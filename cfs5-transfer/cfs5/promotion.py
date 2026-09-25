"""Cross-build CFS6 catalogue promotion.

Promotion is deliberately a fresh, target-build rewrite, never an append to a
foreign header.  The implementation is built around revalidating loaded
records before emitting them with rebased diagnostic RVAs.
"""

import os

import ida_bytes
import ida_funcs
import ida_ua

from . import cfs6
from . import importer
from .common import find_up_to_two, get_search_ranges
from .image import describe_image, get_imagebase, open_image_view


def _unique_match(rec, ranges):
    matches = find_up_to_two(rec.pattern, ranges)
    if not matches:
        return None, "not-found"
    if len(matches) != 1:
        return None, "ambiguous"
    return matches[0], None


def _rebased_source(rec, match_ea, imagebase):
    """Rebase target diagnostics; never retain stale source function RVAs."""
    source = {key: value for key, value in rec.source.items()
              if key not in ("anchor_rva", "function_rva", "function_size",
                             "target_rva")}
    source["anchor_rva"] = int(match_ea) - int(imagebase)
    func = ida_funcs.get_func(match_ea)
    if func is not None:
        source["function_rva"] = int(func.start_ea) - int(imagebase)
        source["function_size"] = int(func.end_ea - func.start_ea)
    return source


def _validate(item, rec, ranges, imagebase):
    match, error = _unique_match(rec, ranges)
    if error:
        return None, error
    if item.kind in (cfs6.REC_FUNCTION, cfs6.REC_GLOBAL):
        status, target, detail = importer.resolve_candidate(rec, match)
        if status != "ok":
            return None, detail
        source = _rebased_source(rec, match, imagebase)
        if item.kind == cfs6.REC_GLOBAL:
            source.pop("function_rva", None)
            source.pop("function_size", None)
            source["target_rva"] = target - imagebase
        else:
            source["function_rva"] = target - imagebase
        return (rec, source, target), None
    if item.kind == cfs6.REC_DERIVED_VALUE:
        value, _site, _recipe, error = importer._resolve_value_at_match(rec, match)
        if error:
            return None, error
        return (rec, _rebased_source(rec, match, imagebase), value), None
    if item.kind == cfs6.REC_PATCH:
        site = match + rec.instruction_offset
        insn = ida_ua.insn_t()
        raw = ida_bytes.get_bytes(site, item.patch_size)
        if (ida_ua.decode_insn(insn, site) <= 0 or insn.size <= 0 or
                item.patch_size < insn.size or raw is None or
                not raw.startswith(bytes.fromhex(item.expected_bytes))):
            return None, "patch opcode or span mismatch"
        if (ida_ua.print_insn_mnem(site) or "").lower() != item.expected_instruction:
            return None, "patch mnemonic mismatch"
        return (rec, _rebased_source(rec, match, imagebase), site), None
    return None, "unsupported item kind"


def promote_catalogue(source_path, destination_path, build=None, item_ids=(),
                      declaration_names=(), preserve_validated=False):
    """Promote selected uniquely-matching records into a target-build CFS6 file.

    This initial engine deliberately refuses unselected carry-over: a new
    header may contain only records that were revalidated in this target.
    """
    try:
        loaded = cfs6.load_cfs6(source_path)
    except Exception as exc:
        return {"ok": False, "partial": False, "error": str(exc), "unresolved": []}
    wanted = {str(value) for value in item_ids or ()}
    by_name = {}
    for item in loaded.items:
        name = item.qualified_name if hasattr(item, "qualified_name") else item.name
        by_name.setdefault(name, []).append(item.id)
    unresolved = []
    for name in declaration_names or ():
        matches = by_name.get(str(name), ())
        if len(matches) != 1:
            unresolved.append({"kind": "declaration", "name": str(name),
                               "reason": "not in source catalogue" if not matches
                               else "ambiguous declaration name"})
        else:
            wanted.add(matches[0])
    if preserve_validated:
        wanted.update(item.id for item in loaded.items)
    if not wanted:
        return {"ok": False, "partial": False,
                "error": "promotion requires an exact selection", "unresolved": unresolved}
    items = [item for item in loaded.items if item.id in wanted]
    missing = sorted(wanted - {item.id for item in items})
    if missing or unresolved:
        return {"ok": False, "partial": False,
                "error": "promotion selection is not exact",
                "unresolved": unresolved + [{"kind": "item", "name": iid,
                                "reason": "not in source catalogue"} for iid in missing]}
    ranges = get_search_ranges()
    imagebase = get_imagebase()
    view, source = open_image_view()
    image, _notes = describe_image(view, source)
    unresolved, planned = [], []
    for item in items:
        kept, failures = [], []
        for rec in item.candidates:
            resolved, error = _validate(item, rec, ranges, imagebase)
            if error:
                failures.append("rank%d: %s" % (rec.rank, error))
                continue
            kept.append(resolved)
        if not kept:
            unresolved.append({"kind": item.kind, "name": item.name,
                               "reason": "no candidate uniquely matched target"})
        else:
            values = {entry[2] for entry in kept}
            if item.kind == cfs6.REC_DERIVED_VALUE and len(values) != 1:
                unresolved.append({"kind": item.semantic, "name": item.qualified_name,
                                   "reason": "target candidate value conflict"})
            else:
                planned.append((item, kept))
    if unresolved and not preserve_validated:
        return {"ok": False, "partial": bool(planned),
                "error": "promotion refused; source file left untouched",
                "unresolved": unresolved}
    tmp = destination_path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs6Writer(handle, imagebase=imagebase)
            writer.write_header(image, build, "user")
            for item, candidates in planned:
                if item.kind == cfs6.REC_PATCH:
                    iid = writer.write_patch(item.owner, item.name, len(candidates),
                                             item.coverage, {"expected_instruction": item.expected_instruction,
                                                             "expected_bytes": item.expected_bytes,
                                                             "patch_size": item.patch_size})
                elif item.kind in (cfs6.REC_FUNCTION, cfs6.REC_GLOBAL):
                    iid = writer.write_item(item.kind, item.name, len(candidates), item.coverage)
                elif item.kind == cfs6.REC_DERIVED_VALUE:
                    iid = writer.write_derived_value(item.semantic, item.owner, item.name,
                                                     len(candidates), item.coverage,
                                                     expected_value=candidates[0][2])
                else:
                    raise ValueError("unsupported item kind %s" % item.kind)
                for rank, (rec, rebased, _value) in enumerate(candidates):
                    writer.write_revalidated_candidate(iid, rank, rec, rebased)
        cfs6.load_cfs6(tmp)
        os.replace(tmp, destination_path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return {"ok": not unresolved, "partial": bool(unresolved), "error": None,
            "unresolved": unresolved, "path": destination_path,
            "promoted": len(planned), "build": build}
