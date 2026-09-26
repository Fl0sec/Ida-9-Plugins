"""CFS7 rolling catalogue refresh against the active target IDB."""

import json
import os

from . import cfs6
from . import export as _export
from . import promotion
from . import selection
from . import store
from .api_registry import _collect
from .common import get_search_ranges
from .image import describe_image, get_imagebase, open_image_view, detect_build
from .policy import (
    MAX_EXPORTED_CANDIDATES, MAX_GLOBAL_CANDIDATES, MAX_VALUE_CANDIDATES,
)


def _identity(loaded):
    return {
        "image": dict(loaded.image()),
        "build": {"number": loaded.build_number(),
                  "source": (loaded.header.get("build") or {}).get("source", "unknown")},
    }


def _candidate_key(rec):
    return json.dumps({
        "mode": rec.mode, "pattern": rec.pattern, "origin": rec.origin,
        "resolve": rec.resolve,
    }, sort_keys=True, separators=(",", ":"))


def _candidate_provenance(rec, fallback):
    """Keep CFS7's candidate origin; use a CFS6 header only as fallback."""
    return rec.provenance or fallback


def _limit(item):
    if item.kind == cfs6.REC_FUNCTION:
        return MAX_EXPORTED_CANDIDATES
    if item.kind == cfs6.REC_GLOBAL:
        return MAX_GLOBAL_CANDIDATES
    return MAX_VALUE_CANDIDATES


def _write_item(writer, item, candidates):
    if item.kind == cfs6.REC_PATCH:
        iid = writer.write_patch(item.owner, item.name, len(candidates), item.coverage,
            {"expected_instruction": item.expected_instruction,
             "expected_bytes": item.expected_bytes, "patch_size": item.patch_size})
    elif item.kind in (cfs6.REC_FUNCTION, cfs6.REC_GLOBAL):
        iid = writer.write_item(item.kind, item.name, len(candidates), item.coverage)
    elif item.kind == cfs6.REC_DERIVED_VALUE:
        iid = writer.write_derived_value(item.semantic, item.owner, item.name,
                                         len(candidates), item.coverage,
                                         expected_value=item.expected_value)
    else:
        raise ValueError("unsupported item kind %s" % item.kind)
    for rank, (rec, source, provenance) in enumerate(candidates):
        writer.write_revalidated_candidate(iid, rank, rec, source, provenance)
    return iid


def _selected_active_catalogue(destination_path, item_ids, declaration_names,
                               build, ranges):
    """Export exactly caller-selected active evidence into a disposable CFS6 file."""
    if not item_ids and not declaration_names:
        return None, None
    chosen = selection.resolve(store.load_all(), declaration_names=declaration_names,
                               item_ids=item_ids, patches=store.load_patches())
    if chosen["unresolved"] or not chosen["requested"]:
        return None, chosen["unresolved"] or [{
            "kind": "selection", "name": "", "reason": "no active records selected"
        }]
    sites = store.load_sites()
    locators = store.load_locators()
    functions, globals_, function_sites, function_locators, unresolved = _collect(
        chosen["function_names"], chosen["global_names"],
        sites_by_id=sites, locators_by_id=locators,
    )
    if unresolved:
        return None, unresolved
    path = destination_path + ".active.tmp"
    raw = _export.export_to_path(
        path, ranges, function_eas=functions, global_eas=globals_,
        declarations=chosen["declarations"], patches=chosen["patches"],
        build=build, merge=_export.MERGE_OVERWRITE,
        function_sites=function_sites, function_locators=function_locators,
        require_all=True, validate_output=True,
    )
    if raw.get("error") or raw.get("written", 0) != chosen["requested"]:
        return None, raw.get("uncovered", []) or [{
            "kind": "selection", "name": "", "reason": raw.get("error") or "selected export failed"
        }]
    return cfs6.load_cfs6(path), None


def refresh_catalogue(source_path, destination_path, build=None, item_ids=(),
                      declaration_names=()):
    """Revalidate every source record and add exact selected target evidence.

    CFS7 is always a new, atomic destination. CFS6 is accepted as input but
    never rewritten in place by legacy export operations.
    """
    try:
        source = cfs6.load_catalogue(source_path)
    except Exception as exc:
        return {"ok": False, "partial": False, "error": str(exc), "unresolved": []}
    if not destination_path or os.path.abspath(source_path) == os.path.abspath(destination_path):
        return {"ok": False, "partial": False,
                "error": "CFS7 refresh requires a distinct destination path", "unresolved": []}
    ranges = get_search_ranges()
    if not ranges:
        return {"ok": False, "partial": False,
                "error": "no executable/code search ranges found", "unresolved": []}
    if build is None:
        build = detect_build()
    else:
        build = (int(build), "user")
    build_number, build_source = build
    imagebase = get_imagebase()
    view, view_source = open_image_view()
    image, _notes = describe_image(view, view_source)
    active, active_errors = _selected_active_catalogue(
        destination_path, item_ids, declaration_names, build, ranges
    )
    if active_errors:
        return {"ok": False, "partial": False,
                "error": "active selection is not exportable",
                "unresolved": active_errors}

    entries = {}
    unresolved = []
    removed = 0
    sources = [(source, _identity(source), False)]
    if active is not None:
        sources.append((active, {"image": dict(image), "build": {
            "number": build_number, "source": build_source}}, True))
    for loaded, provenance, is_active in sources:
        for item in loaded.items:
            entry = entries.setdefault(item.id, {"item": item, "records": [], "active": is_active})
            if is_active:
                # Active selected evidence provides current expected values and
                # target-only type payloads for this item.
                entry["item"] = item
                entry["active"] = True
            for rec in item.candidates:
                resolved, error = promotion._validate(item, rec, ranges, imagebase)
                if error:
                    if not is_active:
                        removed += 1
                    continue
                # A CFS7 input already carries immutable per-candidate origin.
                # CFS6 has no such field, so its singular header is the origin.
                record_provenance = _candidate_provenance(rec, provenance)
                entry["records"].append((rec, resolved[1], record_provenance))

    planned = []
    for iid, entry in sorted(entries.items()):
        item = entry["item"]
        records = {}
        for rec, diagnostics, provenance in entry["records"]:
            key = _candidate_key(rec)
            old = records.get(key)
            if old is None or (rec.score, key) < (old[0].score, key):
                records[key] = (rec, diagnostics, provenance)
        candidates = sorted(records.values(), key=lambda value: (
            value[0].score, _candidate_key(value[0])
        ))[:_limit(item)]
        if item.kind == cfs6.REC_DERIVED_VALUE:
            values = {promotion._validate(item, rec, ranges, imagebase)[0][2]
                      for rec, _diag, _prov in candidates}
            if len(values) > 1:
                candidates = []
                unresolved.append({"kind": item.semantic, "name": item.qualified_name,
                                   "reason": "target candidate value conflict"})
        if not candidates:
            removed += 1
            if not any(row.get("name") == item.name for row in unresolved):
                unresolved.append({"kind": item.kind, "name": item.name,
                                   "reason": "no candidate uniquely matched target"})
            continue
        planned.append((item, candidates, entry["active"]))

    tmp = destination_path + ".tmp"
    active_tmp = destination_path + ".active.tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs7Writer(handle, imagebase=imagebase)
            writer.write_header(image, build_number, build_source)
            active_ids = set()
            for item, candidates, is_active in planned:
                iid = _write_item(writer, item, candidates)
                if is_active:
                    active_ids.add(iid)
            # Type records are emitted only from the current-target selected export.
            if active is not None:
                for iid in sorted(active_ids):
                    meta = active.item_meta.get(iid)
                    if meta is not None and meta.type_blob is not None:
                        writer.write_item_type(iid, meta.name, meta.quality,
                            (meta.type_blob, meta.fields_blob, meta.fldcmts_blob),
                            meta.dependencies, is_global=meta.is_global)
                for name in sorted(active.type_records):
                    record = active.type_records[name]
                    writer.write_local_type(record.name, record.kind,
                        (record.type_blob, record.fields_blob, record.fldcmts_blob))
        checked = cfs6.load_catalogue(tmp)
        if checked.parse_errors:
            raise ValueError("generated CFS7 has %d parse errors" % checked.parse_errors)
        os.replace(tmp, destination_path)
    except Exception as exc:
        return {"ok": False, "partial": bool(planned), "error": str(exc),
                "unresolved": unresolved}
    finally:
        for path in (tmp, active_tmp):
            if os.path.exists(path):
                os.remove(path)
    return {
        "ok": not unresolved, "partial": bool(unresolved), "error": None,
        "unresolved": unresolved, "path": destination_path,
        "target": {"image": image, "build": {"number": build_number,
                   "source": build_source}},
        "retained": len(planned), "removed": removed,
        "added": 0 if active is None else len(active.items),
    }
