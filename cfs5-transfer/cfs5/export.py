"""The export engine: turn a set of items into a CFS6 file.

Lives in the package rather than in the exporter entry file because it now has
two callers -- the UI actions and `cfs5/api.py` -- and a second copy of it
would drift from the first. Everything interactive stays in the entry file:
this module never prompts, never pops up, and returns its outcome as data.

`export_to_path` is the single writer. It takes an explicit destination, build
and merge mode, so the caller decides where those come from (a dialog, or an
agent's arguments) without this module knowing which.
"""

import os

import ida_kernwin
import ida_name
import ida_ua

from . import cfs6
from . import members
from .common import UA_MAXOP, ea_str, msg, safe_name
from .disasm import (
    infer_displacement_field, infer_immediate_field, signed_le,
)
from .image import (
    BodyOwnership, describe_image, get_imagebase, open_image_view,
)
from .members import decode_at
from .policy import (
    AXIS_STRING_REL, AXIS_VTABLE, WHY_NOT_ATTEMPTED, WHY_NOT_DECLARED,
    WHY_SELECTED,
)
from .sigs import (
    choose_function_candidates, choose_global_candidates,
    choose_value_candidates,
)
from .typeio import (
    build_local_type_index,
    export_type_payload,
    function_type_quality,
    get_function_export_tinfo,
    get_global_export_tinfo,
    global_type_quality,
)

PROGRESS_EVERY = 10

MERGE_APPEND = "append"
MERGE_OVERWRITE = "replace"
MERGE_MODES = (MERGE_APPEND, MERGE_OVERWRITE)

_SIBLING_CACHE = {}


def clear_caches():
    """Drop per-session caches. Call when the IDB's types may have changed."""
    _SIBLING_CACHE.clear()


def sibling_offsets(owner):
    """Every member offset of `owner`, for co-occurrence ranking.

    Cached because an export walks many declarations of the same structure and
    re-reading the type each time is pure overhead. This only steers *which*
    functions get decompiled -- it never widens what a candidate may be.
    """
    if owner not in _SIBLING_CACHE:
        _SIBLING_CACHE[owner] = [
            r.byte_offset for r in members.iter_members(owner)
        ]
    return _SIBLING_CACHE[owner]


class ExportState:
    """Shared accumulators + counters for one export run."""

    def __init__(self):
        self.local_type_index = {}
        self.closure_cache = {}
        self.exported_types = {}

        self.functions = 0
        self.function_candidates = 0
        self.function_prototypes = 0
        self.globals = 0
        self.global_candidates = 0
        self.global_types = 0
        self.member_values = 0
        self.member_candidates = 0
        # Declarations whose IDA member no longer exists.
        self.member_unresolved = 0
        # Candidates dropped for not reproducing the IDA-known offset.
        self.member_disagreements = 0
        self.no_candidate = 0
        self.failures = 0
        self.user_prototypes = 0
        self.guessed_prototypes = 0
        self.mode_counts = {"ENTRY": 0, "BODY": 0, "REL": 0,
                            cfs6.MODE_VTABLE: 0, cfs6.MODE_STRING_REL: 0}
        # How many items got 1, 2, 3, 4 candidates -- the diversity metric.
        self.candidate_counts = {}
        # BODY candidates a .pdata-based consumer cannot resolve.
        self.ida_only_bodies = 0
        self.ownership = None
        # Per-item reasons, so a caller can act on what was missed instead of
        # inferring it from a count. This is the whole difference between an
        # export an agent can trust and one it has to assume worked.
        self.uncovered = []
        # Findings that are not failures: an anchor that exists but could not
        # be exported, a site the caller named that did not hold up. Separate
        # from `uncovered` because an item can be fully exported and still
        # have something worth saying about it.
        self.advisory = []
        # {func_ea: [site_ea, ...]} supplied by the caller.
        self.function_sites = {}
        # {func_ea: [locator, ...]} -- structural declarations the caller made.
        self.function_locators = {}

    def _miss(self, kind, name, reason, ea=None, diagnosis=None):
        entry = {"kind": kind, "name": name, "reason": reason}
        if ea is not None:
            entry["ea"] = ea_str(ea)
        if diagnosis:
            entry["diagnosis"] = diagnosis
        self.uncovered.append(entry)

    def _advise(self, kind, name, search, ea=None):
        """Record what a search noticed but could not act on."""
        notes = []
        for near in search.near_misses:
            notes.append({
                "note": "unique anchor exists but is not exportable",
                "axis": near.get("axis"),
                "offset": near.get("offset"),
                "ea": near.get("ea"),
                "ownership": near.get("ownership"),
                "signature": near.get("signature"),
            })
        for bad in search.site_rejections:
            notes.append({
                "note": "explicit site rejected",
                "ea": bad.get("ea"),
                "reason": bad.get("reason"),
            })
        # A declared locator that did not hold up is advisory, not a failure:
        # the item may still be fully covered by patterns. But it must be said
        # out loud, because the caller asserted something the database
        # disagrees with, and silence would read as acceptance.
        vtable = search.diagnosis.get(AXIS_VTABLE)
        if vtable and vtable["reason"] not in (WHY_SELECTED, WHY_NOT_DECLARED,
                                               WHY_NOT_ATTEMPTED):
            notes.append({
                "note": "declared vtable locator rejected",
                "axis": AXIS_VTABLE,
                "reason": vtable["reason"],
                "detail": vtable.get("detail", ""),
            })
        string_rel = search.diagnosis.get(AXIS_STRING_REL)
        if string_rel and string_rel["reason"] not in (
            WHY_SELECTED, WHY_NOT_DECLARED, WHY_NOT_ATTEMPTED
        ):
            notes.append({
                "note": "declared anchor_string locator rejected",
                "axis": AXIS_STRING_REL,
                "reason": string_rel["reason"],
                "detail": string_rel.get("detail", ""),
            })
        for note in notes:
            entry = {"kind": kind, "name": name}
            if ea is not None:
                entry["ea"] = ea_str(ea)
            entry.update(note)
            self.advisory.append(entry)


def write_function(writer, state, func_ea, ranges):
    name = safe_name(ida_name.get_name(func_ea) or "")
    if not name:
        state.failures += 1
        state._miss("function", "", "address has no name", func_ea)
        return None

    try:
        search = choose_function_candidates(
            func_ea, ranges, ownership=state.ownership,
            sites=state.function_sites.get(func_ea, ()),
            locators=state.function_locators.get(func_ea, ()),
        )
    except Exception as exc:
        state.failures += 1
        msg("FAIL %-45s @ %s error=%s" % (name, ea_str(func_ea), exc))
        state._miss("function", name, "exception: %s" % exc, func_ea)
        return None

    candidates = search.candidates
    coverage = search.coverage
    xref_count, xrefs_tested = search.total_xrefs, search.searched_xrefs
    state._advise("function", name, search, func_ea)

    if not candidates:
        state.no_candidate += 1
        msg("NO_UNIQUE_CANDIDATE %-31s @ %s" % (name, ea_str(func_ea)))
        explanation = search.explain()
        if explanation:
            msg(explanation)
        state._miss("function", name, search.failure_reason(), func_ea,
                    diagnosis=search.diagnosis)
        return None

    item_id = writer.write_item(
        cfs6.REC_FUNCTION, name, len(candidates), coverage
    )
    for rank, cand in enumerate(candidates):
        writer.write_candidate(item_id, rank, cand)
        state.function_candidates += 1
        state.mode_counts[cand.mode] = state.mode_counts.get(cand.mode, 0) + 1
        if cand.mode == "BODY" and cand.ownership != "pdata":
            state.ida_only_bodies += 1
    state.candidate_counts[len(candidates)] = (
        state.candidate_counts.get(len(candidates), 0) + 1
    )

    quality, prototype_raw, deps = "NONE", None, []
    try:
        tif, explicit = get_function_export_tinfo(func_ea)
        if tif is not None:
            prototype_raw, deps = export_type_payload(
                tif, state.local_type_index, state.closure_cache,
                state.exported_types
            )
            quality = function_type_quality(func_ea, explicit)
            if prototype_raw is None:
                quality = "NONE"
    except Exception as exc:
        quality, prototype_raw, deps = "NONE", None, []
        msg("TYPE_EXPORT_FAIL %-36s @ %s error=%s"
            % (name, ea_str(func_ea), exc))

    if prototype_raw is not None:
        writer.write_item_type(
            item_id, name, quality, prototype_raw, deps, is_global=False
        )
        state.function_prototypes += 1
        if quality == "USER":
            state.user_prototypes += 1
        elif quality == "GUESSED":
            state.guessed_prototypes += 1

    primary = candidates[0]
    xref_note = (
        " xrefs=%d tested=%d" % (xref_count, xrefs_tested) if xref_count else ""
    )
    type_note = (
        " type=%s deps=%d" % (quality, len(deps))
        if prototype_raw is not None else ""
    )
    msg(
        "EXPORTED %-39s n=%d modes=%s bytes=%d exact=%d%s%s"
        % (name, len(candidates), "/".join(c.mode for c in candidates),
           primary.byte_len, primary.exact, xref_note, type_note)
    )
    state.functions += 1
    return name


def write_global(writer, state, global_ea, ranges):
    name = safe_name(ida_name.get_name(global_ea) or "")
    if not name:
        state.failures += 1
        state._miss("global", "", "address has no name", global_ea)
        return None

    try:
        search = choose_global_candidates(global_ea, ranges)
    except Exception as exc:
        state.failures += 1
        msg("GLOB_FAIL %-40s @ %s error=%s" % (name, ea_str(global_ea), exc))
        state._miss("global", name, "exception: %s" % exc, global_ea)
        return None

    candidates = search.candidates
    coverage = search.coverage
    xref_count, xrefs_tested = search.total_xrefs, search.searched_xrefs

    if not candidates:
        state.no_candidate += 1
        msg("GLOB_NO_XREF_ANCHOR %-31s @ %s" % (name, ea_str(global_ea)))
        state._miss("global", name, search.failure_reason(), global_ea,
                    diagnosis=search.diagnosis)
        return None

    item_id = writer.write_item(cfs6.REC_GLOBAL, name, len(candidates), coverage)
    for rank, cand in enumerate(candidates):
        writer.write_candidate(item_id, rank, cand)
        state.global_candidates += 1
        state.mode_counts[cand.mode] = state.mode_counts.get(cand.mode, 0) + 1

    quality, type_raw, deps = "NONE", None, []
    try:
        tif, explicit = get_global_export_tinfo(global_ea)
        if tif is not None:
            type_raw, deps = export_type_payload(
                tif, state.local_type_index, state.closure_cache,
                state.exported_types
            )
            quality = global_type_quality(global_ea, explicit)
            if type_raw is None:
                quality = "NONE"
    except Exception as exc:
        quality, type_raw, deps = "NONE", None, []
        msg("GLOB_TYPE_FAIL %-35s @ %s error=%s"
            % (name, ea_str(global_ea), exc))

    if type_raw is not None:
        writer.write_item_type(
            item_id, name, quality, type_raw, deps, is_global=True
        )
        state.global_types += 1

    primary = candidates[0]
    xref_note = (
        " xrefs=%d tested=%d" % (xref_count, xrefs_tested) if xref_count else ""
    )
    type_note = (
        " type=%s deps=%d" % (quality, len(deps)) if type_raw is not None else ""
    )
    msg(
        "GLOB_EXPORTED %-34s n=%d bytes=%d exact=%d%s%s"
        % (name, len(candidates), primary.byte_len, primary.exact,
           xref_note, type_note)
    )
    state.globals += 1
    return name


def _contradicting_sites(decl, expected):
    """[(ea, decoded)] for declared sites that encode a *different* number.

    Deliberately separate from "this site produced no candidate". A site that
    cannot yield a unique pattern is merely unusable -- short instructions
    fall below the VALUE exact-byte floor all the time -- and must not condemn
    a declaration its other sites support. A site that decodes a *different*
    value is evidence against the claim itself, which is a different thing and
    is fatal.
    """
    out = []
    for site_ea, site_op in decl.sites:
        insn = decode_at(site_ea)
        if insn is None:
            continue
        if infer_displacement_field(insn, expected) is not None:
            continue
        if infer_immediate_field(insn, expected) is not None:
            continue

        # Nothing at this site encodes the expected number. Report what it
        # does hold, when the operand the caller named can say.
        found = "nothing"
        try:
            if 0 <= site_op < UA_MAXOP:
                op = insn.ops[site_op]
                if op.type == ida_ua.o_imm:
                    found = str(int(op.value))
                elif op.type == ida_ua.o_displ:
                    found = str(signed_le(int(op.addr), 8))
        except Exception:
            pass
        out.append((site_ea, found))
    return out


def write_member(writer, state, decl, ranges):
    """Emit one declared derived value as an item plus its candidates.

    Two gates, both hard:

    * a `member_offset` must still name a live IDA member. If the field was
      renamed or deleted, the offset we would export has no backing and the
      item is skipped loudly rather than exported as a guess. A semantic with
      no backing field asserts its value instead, which is a weaker claim --
      so it is gated on every one of its sites decoding that same number.
    * every candidate must reproduce the expected value. Candidates are built
      by searching for exactly that value, so a disagreement means something
      is wrong with the extraction rather than with the build -- it is
      dropped, never ranked.
    """
    ref = None
    if decl.needs_ida_member:
        ref = members.lookup_member(decl.owner, decl.member)
        if ref is None:
            state.member_unresolved += 1
            msg(
                "MEMBER_NO_FIELD %-30s -- %s.%s is not in this database; "
                "re-declare or restore the type"
                % (decl.qualified, decl.owner, decl.member)
            )
            state._miss("member", decl.qualified, "no live IDA field")
            return None
        encoded = ref.byte_offset
    else:
        # No field to read, so the declaration's own number is the claim; the
        # sites below are what has to substantiate it.
        encoded = decl.asserted_value

    expected = encoded + decl.value_adjust

    try:
        candidates, coverage, sites, searched = choose_value_candidates(
            encoded, ranges, selected_sites=decl.sites, ref=ref,
            allow_scan=decl.scan_allowed, value_adjust=decl.value_adjust,
            sibling_offsets=sibling_offsets(ref.owner) if ref is not None else None,
        )
    except Exception as exc:
        state.failures += 1
        msg("MEMBER_FAIL %-33s error=%s" % (decl.qualified, exc))
        state._miss("member", decl.qualified, "exception: %s" % exc)
        return None

    agreed = [c for c in candidates if c.value == expected]
    if len(agreed) != len(candidates):
        state.member_disagreements += len(candidates) - len(agreed)
        msg("MEMBER_DISAGREE %-29s dropped %d candidate(s) that did not "
            "reproduce 0x%X"
            % (decl.qualified, len(candidates) - len(agreed), expected))

    # An asserted value has no database behind it, so the sites are the only
    # thing substantiating it. A site that decodes a *different* number means
    # the assertion or the site is wrong, and exporting the rest would publish
    # a number two of its own witnesses disagree with -- reject the whole
    # declaration rather than quietly keep the agreeing half.
    if not decl.needs_ida_member:
        contradicted = _contradicting_sites(decl, encoded)
        if contradicted:
            state.member_disagreements += len(contradicted)
            detail = ", ".join(
                "%s encodes %s" % (ea_str(ea), found) for ea, found in contradicted
            )
            msg("STRIDE_CONTRADICTED %-25s asserted %d but %s"
                % (decl.qualified, encoded, detail))
            state._miss("member", decl.qualified,
                        "asserted value %d contradicted by %s"
                        % (encoded, detail))
            return None

    if not agreed:
        state.no_candidate += 1
        msg("MEMBER_NO_CANDIDATE %-25s value=0x%X sites=%d"
            % (decl.qualified, expected, sites))
        state._miss("member", decl.qualified,
                    "no candidate reproduced value 0x%X" % expected)
        return None

    item_id = writer.write_derived_value(
        decl.semantic, decl.owner, decl.name, len(agreed), coverage,
        expected_value=expected,
    )
    for rank, cand in enumerate(agreed):
        writer.write_candidate(item_id, rank, cand)
        state.member_candidates += 1
        state.mode_counts[cand.mode] = state.mode_counts.get(cand.mode, 0) + 1

    primary = agreed[0]
    msg(
        "MEMBER_EXPORTED %-29s offset=0x%X n=%d bytes=%d exact=%d sites=%d "
        "tested=%d origins=%s"
        % (decl.qualified, expected, len(agreed), primary.byte_len,
           primary.exact, sites, searched,
           "/".join(sorted(set(c.origin for c in agreed))))
    )
    state.member_values += 1
    return decl.id


def discard_temp(tmp_path):
    try:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    except OSError as exc:
        msg("TEMP_CLEANUP_FAILED %s: %s" % (tmp_path, exc))


def resolve_merge(path, mode, image, build_number):
    """(mode, loaded_or_None, error_or_None) for a non-interactive caller.

    Appending is refused unless the existing header describes the same image
    and build: one header cannot honestly describe two images, and silently
    overwriting a good file is worse than refusing.
    """
    if mode not in MERGE_MODES:
        return None, None, "merge must be one of %s" % ", ".join(MERGE_MODES)
    if mode == MERGE_OVERWRITE or not os.path.exists(path):
        return MERGE_OVERWRITE, None, None

    try:
        loaded = cfs6.load_cfs6(path, log=lambda t: msg("MERGE_READ: %s" % t))
    except Exception as exc:
        return None, None, "existing file is unreadable (%s); refusing to " \
                           "overwrite it -- move it aside or pass " \
                           "merge='replace'" % exc

    conflicts = cfs6.merge_conflicts(loaded.header, image, build_number)
    if conflicts:
        return None, None, "cannot append: %s" % "; ".join(conflicts)
    return MERGE_APPEND, loaded, None


def summarize(state, path, build_number, build_source, merged=None):
    """Human-readable outcome. The UI shows it; the API logs it."""
    spread = " ".join(
        "%dx%d" % (count, n)
        for n, count in sorted(state.candidate_counts.items())
    ) or "none"

    merge_note = (
        "\nMerged into the existing file: %s\n" % merged.describe()
        if merged is not None else ""
    )

    return (
        "CFS6 export complete\n\n"
        "Functions exported: %d\n"
        "Function candidates: %d\n"
        "  Candidates per function: %s\n"
        "Function prototypes: %d\n"
        "  User prototypes: %d\n"
        "  Guessed prototypes: %d\n"
        "Globals exported: %d\n"
        "Global candidates: %d\n"
        "Global types: %d\n"
        "Declared members exported: %d\n"
        "  Member candidates: %d\n"
        "  Declarations with no live IDA field: %d\n"
        "  Candidates dropped for disagreeing with IDA: %d\n"
        "Local type definitions: %d\n"
        "ENTRY / BODY / REL / VALUE candidates: %d / %d / %d / %d\n"
        "  BODY not resolvable from .pdata (IDA-only): %d\n"
        "Structural locators (VTABLE / STRING_REL): %d / %d\n"
        "No unique candidate / no anchor: %d\n"
        "Failures: %d\n"
        "Build: %s (%s)\n"
        "%s\n"
        "%s"
        % (
            state.functions, state.function_candidates, spread,
            state.function_prototypes,
            state.user_prototypes, state.guessed_prototypes,
            state.globals, state.global_candidates, state.global_types,
            state.member_values, state.member_candidates,
            state.member_unresolved, state.member_disagreements,
            len(state.exported_types),
            state.mode_counts.get("ENTRY", 0), state.mode_counts.get("BODY", 0),
            state.mode_counts.get("REL", 0), state.mode_counts.get("VALUE", 0),
            state.ida_only_bodies,
            state.mode_counts.get(cfs6.MODE_VTABLE, 0),
            state.mode_counts.get(cfs6.MODE_STRING_REL, 0),
            state.no_candidate, state.failures,
            "unknown" if build_number is None else build_number, build_source,
            merge_note,
            path,
        )
    )


def export_to_path(path, ranges, function_eas=(), global_eas=(),
                   declarations=(), build=(None, "unknown"),
                   merge=MERGE_APPEND, function_sites=None,
                   function_locators=None):
    """Write a CFS6 file. Returns a result dict; never prompts, never pops up.

    `build` is (number_or_None, source) -- resolved by the caller, because the
    UI confirms it with the user and an agent passes it outright.

    `function_sites` is {func_ea: [site_ea, ...]}: anchors the caller located
    itself, verified against the database before use.
    """
    function_eas = sorted(set(function_eas or []))
    global_eas = sorted(set(global_eas or []))
    declarations = sorted(declarations or [], key=lambda d: d.id)

    result = {
        "ok": False, "path": path, "written": 0, "cancelled": False,
        "uncovered": [], "advisory": [], "error": None, "summary": "",
    }

    if not function_eas and not global_eas and not declarations:
        result["error"] = "nothing to export"
        return result
    if not ranges:
        result["error"] = "no executable/code search ranges found"
        return result

    build_number, build_source = build

    # Open the PE view once: the header identity and the .pdata ownership
    # index both come from it, so they can never describe different images.
    imagebase = get_imagebase()
    view, view_source = open_image_view()
    image, image_notes = describe_image(view, view_source)
    for note in image_notes:
        msg("IMAGE_NOTE: %s" % note)

    msg(
        "SOURCE image=%s arch=%s size=%s build=%s (%s) imagebase=%s headers=%s"
        % (image.get("name"), image.get("architecture"),
           image.get("size_of_image"),
           "unknown" if build_number is None else build_number,
           build_source, ea_str(imagebase), view_source)
    )

    mode, merge_from, merge_error = resolve_merge(
        path, merge, image, build_number
    )
    if merge_error is not None:
        result["error"] = merge_error
        return result
    if merge_from is not None:
        msg("MERGE: appending to %s (%s)"
            % (path, merge_from.describe_contents()))

    state = ExportState()
    state.function_sites = {
        int(ea): list(sites) for ea, sites in (function_sites or {}).items()
    }
    state.function_locators = {
        int(ea): list(entries)
        for ea, entries in (function_locators or {}).items()
    }
    state.ownership = BodyOwnership.for_current_idb(view, imagebase)
    if state.ownership.available:
        msg("PDATA: %d runtime functions (source=%s)"
            % (state.ownership.index.count, state.ownership.source))
    try:
        state.local_type_index = build_local_type_index()
    except Exception as exc:
        msg("TYPE_INDEX_WARN: %s" % exc)
        state.local_type_index = {}

    # One work list instead of a loop per item kind: the progress, cancel and
    # error handling are identical, and a third copy of them would drift.
    work = (
        [(write_function, ea) for ea in function_eas]
        + [(write_global, ea) for ea in global_eas]
        + [(write_member, decl) for decl in declarations]
    )
    total = len(work)

    ida_kernwin.clr_cancelled()
    ida_kernwin.show_wait_box(
        "NODELAY\nBuilding optimized CFS6 signatures + binary types...\n"
        "Press Cancel to stop."
    )

    # Build beside the destination and rename over it only once the export is
    # complete, so a cancel, an exception or a full disk leaves any existing
    # file exactly as it was.
    tmp_path = path + ".tmp"
    merged = None

    try:
        with open(tmp_path, "w", encoding="utf-8", newline="") as f:
            writer = cfs6.Cfs6Writer(f, imagebase=imagebase)
            writer.write_header(image, build_number, build_source)

            done = 0
            cancelled = False
            for handler, payload in work:
                if ida_kernwin.user_cancelled():
                    cancelled = True
                    break
                done += 1
                if done == 1 or done == total or done % PROGRESS_EVERY == 0:
                    ida_kernwin.replace_wait_box(
                        "Building CFS6 signatures + types...\n%d / %d\n"
                        "Functions: %d  Globals: %d  Members: %d  Types: %d\n"
                        "No anchor: %d"
                        % (done, total, state.functions, state.globals,
                           state.member_values, len(state.exported_types),
                           state.no_candidate)
                    )
                handler(writer, state, payload, ranges)

            if cancelled:
                # A half-built export is not a usable file and, on append,
                # would replace a good one with less than it had. Discard.
                msg("Export cancelled after %d/%d items; nothing written, %s "
                    "left untouched." % (done - 1, total, path))
                result["cancelled"] = True
                result["error"] = "cancelled after %d/%d items" % (done - 1, total)
                return result

            # Emit each referenced local type exactly once (shared dedup across
            # functions and globals). Order is irrelevant: the importer performs
            # safe multi-pass registration.
            for type_name in sorted(state.exported_types):
                info = state.exported_types[type_name]
                writer.write_local_type(info["name"], info["kind"], info["raw"])

            # Last, so the records this run produced win over their older
            # namesakes in the file being merged into.
            if merge_from is not None:
                ida_kernwin.replace_wait_box("Merging with the existing file...")
                merged = cfs6.carry_over(writer, merge_from)
                msg("MERGE: %s" % merged.describe())

        os.replace(tmp_path, path)

    except OSError as exc:
        result["error"] = "unable to write CFS6 file: %s" % exc
        return result
    finally:
        ida_kernwin.hide_wait_box()
        ida_kernwin.clr_cancelled()
        discard_temp(tmp_path)

    written = state.functions + state.globals + state.member_values
    result.update({
        "ok": written > 0,
        "written": written,
        "functions": state.functions,
        "globals": state.globals,
        "members": state.member_values,
        "types": len(state.exported_types),
        "merged": merged.describe() if merged is not None else None,
        "mode": mode,
        "uncovered": list(state.uncovered),
        "advisory": list(state.advisory),
        "summary": summarize(state, path, build_number, build_source, merged),
    })
    msg(result["summary"].replace("\n", " | "))
    return result
