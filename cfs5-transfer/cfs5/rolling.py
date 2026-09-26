"""CFS7 rolling catalogue refresh against the active target IDB."""

import json
import os

from . import cfs6
from . import export as _export
from . import promotion
from . import selection
from . import store
from . import members
from .api_registry import _collect
from .common import get_search_ranges
from .image import BodyOwnership, describe_image, get_imagebase, open_image_view, detect_build
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


def _active_counts(source_items, emitted_active_ids):
    """Report only selected active records that actually reached the output."""
    source_ids = {item.id for item in source_items}
    emitted = set(emitted_active_ids)
    return {
        "added": len(emitted - source_ids),
        "refreshed": len(emitted & source_ids),
    }


def _is_same_target_cfs7(loaded, image, build_number):
    """Whether ``loaded`` is a target-local CFS7 stage we may carry types from.

    CFS6 type blobs belong to its source IDB and are never portable evidence.
    A CFS7 stage made for this exact image, however, already contains types
    freshly exported from this target.  Refresh jobs deliberately feed such a
    stage into the next bounded step, so dropping its metadata would make the
    last step silently win.
    """
    return (
        loaded.header.get("version") == cfs6.CFS7_FORMAT_VERSION
        and loaded.image() == image
        and loaded.build_number() == build_number
    )


def _target_type_payloads(source, active, output_ids, image, build_number):
    """Merge target-local item metadata and its complete local-type closure.

    ``active`` is the newly exported selection for this step.  It supersedes
    same-item and same-name records from a same-target CFS7 stage; CFS6 source
    payloads are intentionally excluded because they describe an older IDB.
    """
    metas = {}
    local_types = {}
    if _is_same_target_cfs7(source, image, build_number):
        metas.update({
            iid: meta for iid, meta in source.item_meta.items()
            if iid in output_ids and meta.type_blob is not None
        })
        local_types.update(source.type_records)

    if active is not None:
        active_ids = {item.id for item in active.items}
        # A selected current-target item replaces its old target payload even
        # when it no longer has an exportable type.
        for iid in active_ids:
            metas.pop(iid, None)
        for iid, meta in active.item_meta.items():
            if iid in output_ids and meta.type_blob is not None:
                metas[iid] = meta
        local_types.update(active.type_records)

    needed = {
        dependency for meta in metas.values() for dependency in meta.dependencies
    }
    missing = sorted(needed - set(local_types))
    if missing:
        raise ValueError(
            "target type closure is incomplete: missing local type(s) %s"
            % ", ".join(missing)
        )
    return metas, {name: local_types[name] for name in sorted(needed)}


def _type_counts(metas, local_types):
    return {
        "function_types": sum(1 for meta in metas.values() if not meta.is_global),
        "global_types": sum(1 for meta in metas.values() if meta.is_global),
        "local_types": len(local_types),
    }


def _limit(item):
    if item.kind == cfs6.REC_FUNCTION:
        return MAX_EXPORTED_CANDIDATES
    if item.kind == cfs6.REC_GLOBAL:
        return MAX_GLOBAL_CANDIDATES
    return MAX_VALUE_CANDIDATES


def revalidate_item(item, provenance, ranges, imagebase, ownership):
    """Validate one item's candidates once for a resumable refresh job.

    The returned values are retained for derived-value agreement checks.  A
    job must not rescan the image merely to repeat that check at finalization.
    """
    records = {}
    for rec in item.candidates:
        resolved, error = promotion._validate(
            item, rec, ranges, imagebase, ownership=ownership,
        )
        if error:
            continue
        key = _candidate_key(rec)
        value = resolved[2]
        old = records.get(key)
        if old is None or (rec.score, key) < (old[0].score, key):
            records[key] = (rec, resolved[1], _candidate_provenance(rec, provenance),
                            value)
    ranked = sorted(records.items(), key=lambda row: (
        row[1][0].score, row[0],
    ))[:_limit(item)]
    if not ranked:
        return [], {}, "no candidate uniquely matched target"
    candidates = [(rec, source, candidate_provenance)
                  for _key, (rec, source, candidate_provenance, _value) in ranked]
    values = {key: value for key, (_rec, _source, _provenance, value) in ranked}
    if item.kind == cfs6.REC_DERIVED_VALUE and len(set(values.values())) > 1:
        return [], values, "target candidate value conflict"
    return candidates, values, None


def _write_item(writer, item, candidates, active=False):
    if item.kind == cfs6.REC_PATCH:
        iid = writer.write_patch(item.owner, item.name, len(candidates), item.coverage,
            {"expected_instruction": item.expected_instruction,
             "expected_bytes": item.expected_bytes, "patch_size": item.patch_size})
    elif item.kind in (cfs6.REC_FUNCTION, cfs6.REC_GLOBAL):
        iid = writer.write_item(item.kind, item.name, len(candidates), item.coverage)
    elif item.kind == cfs6.REC_DERIVED_VALUE:
        schema = item.portable_member_schema
        # Schema semantics come from the exact source-side member, while the
        # candidate independently proves the target offset.  Do not require
        # the historical evidence operand to retain an IDA stroff annotation:
        # refresh has already revalidated the stored candidate above.
        if item.semantic == cfs6.SEM_MEMBER_OFFSET:
            live_schema = members.portable_member_schema(
                item.owner, item.name, expected_offset=item.expected_value
            )
            if live_schema is not None:
                schema = live_schema
        iid = writer.write_derived_value(item.semantic, item.owner, item.name,
                                         len(candidates), item.coverage,
                                         expected_value=item.expected_value,
                                         portable_member_schema=schema)
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
    ownership = BodyOwnership.for_current_idb(view, imagebase)
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
            entry = entries.setdefault(item.id, {
                "item": item, "records": [], "active": is_active,
            })
            if is_active:
                # Active selected evidence provides current expected values and
                # target-only type payloads for this item.
                entry["item"] = item
                entry["active"] = True
            for rec in item.candidates:
                resolved, error = promotion._validate(
                    item, rec, ranges, imagebase, ownership=ownership,
                )
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
            values = {promotion._validate(
                item, rec, ranges, imagebase, ownership=ownership,
            )[0][2] for rec, _diag, _prov in candidates}
            if len(values) > 1:
                candidates = []
                unresolved.append({"kind": item.semantic, "name": item.qualified_name,
                                   "reason": "target candidate value conflict"})
        if not candidates:
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
                iid = _write_item(writer, item, candidates, active=is_active)
                if is_active:
                    active_ids.add(iid)
            output_ids = {item.id for item, _candidates, _active in planned}
            metas, local_types = _target_type_payloads(
                source, active, output_ids, image, build_number,
            )
            for iid in sorted(metas):
                meta = metas[iid]
                writer.write_item_type(iid, meta.name, meta.quality,
                    (meta.type_blob, meta.fields_blob, meta.fldcmts_blob),
                    meta.dependencies, is_global=meta.is_global)
            for name in sorted(local_types):
                record = local_types[name]
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
    counts = _active_counts(source.items, active_ids)
    return {
        "ok": not unresolved, "partial": bool(unresolved), "error": None,
        "unresolved": unresolved, "path": destination_path,
        "target": {"image": image, "build": {"number": build_number,
                   "source": build_source}},
        "retained": len(planned), "removed": removed,
        **_type_counts(metas, local_types),
        **counts,
    }
