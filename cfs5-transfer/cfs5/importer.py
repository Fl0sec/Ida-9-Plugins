# Reusable CFS6 importer service for IDA Professional 9.4 / IDAPython 9.4.
#
# Imports a .cfs file into the current IDB:
#   * resolves each function via its ranked ENTRY/BODY/REL signatures, renames
#     it (never clobbering a real destination name) and merges its prototype;
#   * resolves each user global via its REL data-anchor signature, renames it
#     and applies its transported type;
#   * registers missing named Local Types (multi-pass, non-destructive).
#
# Reads CFS6 (UTF-8 JSONL) only; pre-CFS6 CSV files are rejected with a clear
# re-export message. Every candidate of an item is evaluated, not just the
# first that resolves: agreement is evidence and disagreement is a conflict.
# This module contains resolution and application only.  The plugin entry owns
# file pickers, popups, actions and every other interactive concern.
#
# Target: IDA Professional 9.4 / Python 3.12.

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_nalt
import ida_segment
import ida_typeinf
import ida_ua

from . import VERSION
from . import cfs6
from . import declare
from . import leachain
from . import members
from . import patchdecl
from . import registry
from . import store
from .common import BADADDR, ea_str, find_up_to_two, get_search_ranges, msg
from .image import describe_image
from .typeio import (
    deserialize_binary_tinfo,
    function_tinfo_from_meta,
    get_function_tinfo,
    global_tinfo_from_meta,
    merge_function_tinfos,
    named_type_present,
    register_missing_types,
    type_specificity,
)


CREATE_MISSING_FUNCTIONS = True
PROGRESS_EVERY = 10


class Stats:
    def __init__(self):
        # Functions.
        self.groups = 0
        self.processed = 0
        self.renamed = 0
        self.already_named_global = 0
        self.already_same = 0
        self.skipped_named = 0
        self.name_conflicts = 0
        self.not_found = 0
        self.ambiguous = 0
        self.unsafe = 0
        self.created_functions = 0
        self.fallback_used = 0
        # Independent candidates disagreed, or two items wanted one address.
        self.conflicts = 0
        # Two or more independent candidates agreed on the same target.
        self.confirmed = 0

        # Globals.
        self.glob_groups = 0
        self.glob_processed = 0
        self.glob_renamed = 0
        self.glob_already_named = 0
        self.glob_already_same = 0
        self.glob_skipped_named = 0
        self.glob_name_conflicts = 0
        self.glob_not_found = 0
        self.glob_ambiguous = 0
        self.glob_unsafe = 0
        self.glob_conflicts = 0
        self.glob_confirmed = 0

        # Types.
        self.types_total = 0
        self.types_existing = 0
        self.types_registered = 0
        self.types_failed = 0

        # Function prototypes.
        self.func_types_present = 0
        self.func_types_applied = 0
        self.func_types_unchanged = 0
        self.func_types_failed = 0
        self.args_source_used = 0
        self.args_destination_kept = 0
        self.returns_source_used = 0
        self.returns_destination_kept = 0

        # Global types.
        self.glob_types_present = 0
        self.glob_types_applied = 0
        self.glob_types_unchanged = 0
        self.glob_types_failed = 0

        self.parse_errors = 0
        self.failures = 0
        self.cancelled = False

    def summary(self):
        return (
            "CFS6 import summary\n\n"
            "== Functions ==\n"
            "Processed: %d / %d\n"
            "Renamed: %d\n"
            "Already exists globally: %d\n"
            "Already same destination: %d\n"
            "Skipped destination already-named: %d\n"
            "Name conflicts: %d\n"
            "Not found: %d\n"
            "Ambiguous: %d\n"
            "Unsafe/unresolvable: %d\n"
            "Candidate CONFLICTS (not applied): %d\n"
            "Confirmed by 2+ candidates: %d\n"
            "Functions created: %d\n"
            "Fallback candidate used: %d\n\n"
            "== Globals ==\n"
            "Processed: %d / %d\n"
            "Renamed: %d\n"
            "Already exists globally: %d\n"
            "Already same destination: %d\n"
            "Skipped destination already-named: %d\n"
            "Name conflicts: %d\n"
            "Not found: %d\n"
            "Ambiguous: %d\n"
            "Unsafe/unresolvable: %d\n"
            "Candidate CONFLICTS (not applied): %d\n"
            "Confirmed by 2+ candidates: %d\n\n"
            "== Types ==\n"
            "Transported named types: %d\n"
            "Types already present (kept): %d\n"
            "Types registered: %d\n"
            "Types failed: %d\n\n"
            "== Function prototypes ==\n"
            "Present: %d  Applied: %d  Unchanged/skipped: %d  Failed: %d\n"
            "Arg components src/dst: %d / %d\n"
            "Return component src/dst: %d / %d\n\n"
            "== Global types ==\n"
            "Present: %d  Applied: %d  Unchanged/skipped: %d  Failed: %d\n\n"
            "Parse errors: %d\n"
            "Other failures: %d\n"
            "Cancelled: %s"
            % (
                self.processed, self.groups, self.renamed,
                self.already_named_global, self.already_same,
                self.skipped_named, self.name_conflicts, self.not_found,
                self.ambiguous, self.unsafe, self.conflicts, self.confirmed,
                self.created_functions, self.fallback_used,
                self.glob_processed, self.glob_groups, self.glob_renamed,
                self.glob_already_named, self.glob_already_same,
                self.glob_skipped_named, self.glob_name_conflicts,
                self.glob_not_found, self.glob_ambiguous, self.glob_unsafe,
                self.glob_conflicts, self.glob_confirmed,
                self.types_total, self.types_existing,
                self.types_registered, self.types_failed,
                self.func_types_present, self.func_types_applied,
                self.func_types_unchanged, self.func_types_failed,
                self.args_source_used, self.args_destination_kept,
                self.returns_source_used, self.returns_destination_kept,
                self.glob_types_present, self.glob_types_applied,
                self.glob_types_unchanged, self.glob_types_failed,
                self.parse_errors, self.failures,
                "yes" if self.cancelled else "no",
            )
        )


# ---------------------------------------------------------------------------
# Address resolution
# ---------------------------------------------------------------------------

def _name_state(ea):
    current = ida_name.get_name(ea) or ""
    flags = ida_bytes.get_full_flags(ea)
    user = ida_bytes.has_user_name(flags)
    auto = ida_bytes.has_auto_name(flags)
    dummy = ida_bytes.has_dummy_name(flags)
    protected = bool(current and (user or (not auto and not dummy)))
    return current, protected


def _global_name_ea(name):
    try:
        return ida_name.get_name_ea(BADADDR, name)
    except Exception:
        return BADADDR


def _read_signed(ea, width):
    data = ida_bytes.get_bytes(ea, width)
    if data is None or len(data) != width:
        return None
    return int.from_bytes(data, byteorder="little", signed=True)


def _target_is_mapped_codeish(ea):
    if ea == BADADDR or not ida_bytes.is_mapped(ea):
        return False
    seg = ida_segment.getseg(ea)
    if seg is None:
        return False
    return bool(seg.perm & ida_segment.SEGPERM_EXEC) or seg.type == ida_segment.SEG_CODE


def _target_is_mapped_data(ea):
    if ea == BADADDR or not ida_bytes.is_mapped(ea):
        return False
    return ida_segment.getseg(ea) is not None


def resolve_candidate(rec, match_ea):
    """Return (status, target_ea, detail): 'ok' or 'unsafe'.

    REL targets are re-validated against the live instruction. A global record
    (rec.is_data) accepts any mapped data target; a function record requires a
    mapped executable/code target.
    """
    if rec.mode == "ENTRY":
        return "ok", match_ea + rec.target_delta, "entry"

    if rec.mode == "BODY":
        owner = ida_funcs.get_func(match_ea)
        if owner is None:
            return "unsafe", BADADDR, "BODY match is not inside an IDA function"
        # Mirror the ownership rule a non-IDA consumer applies against .pdata:
        # the recorded body_offset must land exactly on the owning function's
        # start, so a hit that drifted into a neighbouring function is rejected
        # rather than silently attributed to it.
        expected_start = match_ea - rec.body_offset
        if owner.start_ea != expected_start:
            return (
                "unsafe", BADADDR,
                "BODY owner mismatch (body_offset implies %s, IDA owner starts "
                "at %s)" % (ea_str(expected_start), ea_str(owner.start_ea))
            )
        return "ok", owner.start_ea, "body-owner"

    if rec.mode == "REL":
        insn_ea = match_ea + rec.instruction_offset
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, insn_ea) <= 0 or insn.size <= 0:
            return "unsafe", BADADDR, "REL xref instruction does not decode"

        expected_end = match_ea + rec.base_offset
        if insn_ea + insn.size != expected_end:
            return (
                "unsafe", BADADDR,
                "REL instruction length changed (expected end %s, got %s)"
                % (ea_str(expected_end), ea_str(insn_ea + insn.size))
            )

        field_ea = match_ea + rec.displacement_offset
        width = rec.displacement_size
        if not (insn_ea <= field_ea and field_ea + width <= insn_ea + insn.size):
            return "unsafe", BADADDR, "REL field lies outside decoded instruction"

        disp = _read_signed(field_ea, width)
        if disp is None:
            return "unsafe", BADADDR, "REL displacement bytes unavailable"

        target = match_ea + rec.base_offset + disp + rec.target_delta
        if rec.is_data:
            if not _target_is_mapped_data(target):
                return "unsafe", BADADDR, "REL target %s is not mapped data" % ea_str(target)
        else:
            if not _target_is_mapped_codeish(target):
                return "unsafe", BADADDR, "REL target %s is not mapped code" % ea_str(target)

        return "ok", target, "rel%d" % (width * 8)

    return "unsafe", BADADDR, "unsupported mode %s" % rec.mode


def _ensure_function_start(target_ea, allow_create=True):
    """Return (status, function_start, created): 'ok'/'interior'/'failed'."""
    f = ida_funcs.get_func(target_ea)
    if f is not None:
        if f.start_ea != target_ea:
            return "interior", f.start_ea, False
        return "ok", f.start_ea, False

    if not allow_create or not CREATE_MISSING_FUNCTIONS:
        return "failed", BADADDR, False

    flags = ida_bytes.get_full_flags(target_ea)
    if not ida_bytes.is_code(flags):
        if ida_ua.create_insn(target_ea) <= 0:
            return "failed", BADADDR, False

    if not ida_funcs.add_func(target_ea):
        return "failed", BADADDR, False

    f = ida_funcs.get_func(target_ea)
    if f is None or f.start_ea != target_ea:
        return "failed", BADADDR, False

    return "ok", f.start_ea, True


def _find_unique_target(rec, ranges, match_cache):
    """Resolve one record to (status, target_ea, detail). status in
    {'ok','not-found','ambiguous','unsafe'}."""
    matches = match_cache.get(rec.pattern)
    if matches is None:
        matches = find_up_to_two(rec.pattern, ranges)
        match_cache[rec.pattern] = matches

    if len(matches) == 0:
        return "not-found", BADADDR, "no match"
    if len(matches) > 1:
        return "ambiguous", BADADDR, "%s,%s" % (ea_str(matches[0]), ea_str(matches[1]))

    return resolve_candidate(rec, matches[0])


def _find_unique_match(rec, ranges, match_cache):
    matches = match_cache.get(rec.pattern)
    if matches is None:
        matches = find_up_to_two(rec.pattern, ranges)
        match_cache[rec.pattern] = matches
    if not matches:
        return None, "not-found"
    if len(matches) != 1:
        return None, "ambiguous"
    return matches[0], None


def _resolve_value_at_match(rec, match_ea):
    """Return ``(value, site_spec, recipe, error)`` for producer migration."""
    try:
        if rec.op == cfs6.OP_CONST:
            value = cfs6.evaluate_value_recipe(0, rec.resolve)
            site_ea = match_ea + rec.instruction_offset
            return value, {"ea": site_ea, "op": rec.operand_index}, {}, None

        if rec.op == cfs6.OP_LEA_SCALE_CHAIN:
            decoded = []
            steps = []
            for step in rec.resolve.get("steps", ()):
                ea = match_ea + int(step["instruction_offset"])
                size = int(step["instruction_size"])
                raw = ida_bytes.get_bytes(ea, size)
                if raw is None or len(raw) != size:
                    return None, None, None, "LEA step bytes unavailable"
                decoded.append(leachain.decode_lea(raw))
                steps.append({"ea": ea, "op": int(step["operand_index"])})
            value = leachain.fold_coefficients(decoded)
            recipe = {"op": cfs6.OP_LEA_SCALE_CHAIN, "steps": steps}
            return value, steps[0], recipe, None

        insn_ea = match_ea + rec.instruction_offset
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, insn_ea) <= 0 or insn.size <= 0:
            return None, None, None, "VALUE instruction does not decode"
        field_ea = match_ea + rec.field_offset
        if not (insn_ea <= field_ea and
                field_ea + rec.field_size <= insn_ea + insn.size):
            return None, None, None, "VALUE field lies outside instruction"
        if rec.operand_index < 0 or rec.operand_index >= len(insn.ops):
            return None, None, None, "VALUE operand index is invalid"
        raw = ida_bytes.get_bytes(field_ea, rec.field_size)
        if raw is None or len(raw) != rec.field_size:
            return None, None, None, "VALUE field bytes unavailable"
        encoded = int.from_bytes(raw, "little", signed=rec.field_signed)
        value = cfs6.evaluate_value_recipe(encoded, rec.resolve)
        site = {"ea": insn_ea, "op": rec.operand_index}
        if rec.op == cfs6.OP_DISP_PLUS_WIDTH:
            site["access_width"] = rec.access_width
            site["alignment"] = rec.alignment
        return value, site, {}, None
    except (KeyError, TypeError, ValueError, leachain.LeaChainError) as exc:
        return None, None, None, str(exc)


# ---------------------------------------------------------------------------
# Type application
# ---------------------------------------------------------------------------

def apply_function_type_safe(ea, meta, stats):
    if meta is None or not meta.has_prototype() or meta.quality == "NONE":
        return "no-meta"

    stats.func_types_present += 1

    unresolved = [d for d in meta.dependencies if d and not named_type_present(d)]
    if unresolved:
        stats.func_types_failed += 1
        msg(
            "TYPE_FUNC_DEP_MISSING %-26s @ %s deps=%s"
            % (meta.name, ea_str(ea),
               ",".join(unresolved[:8]) + ("..." if len(unresolved) > 8 else ""))
        )
        return "dependency-missing"

    src_tif = function_tinfo_from_meta(meta)
    if src_tif is None:
        stats.func_types_failed += 1
        msg("TYPE_FUNC_DECODE_FAIL %-30s @ %s" % (meta.name, ea_str(ea)))
        return "parse-failed"

    dst_tif, dst_explicit, dst_user = get_function_tinfo(ea, allow_guess=True)

    try:
        new_tif, changed = merge_function_tinfos(
            src_tif, dst_tif, meta.quality, dst_user, stats
        )
    except Exception as exc:
        stats.func_types_failed += 1
        msg("TYPE_FUNC_MERGE_FAIL %-30s @ %s error=%s" % (meta.name, ea_str(ea), exc))
        return "merge-failed"

    if new_tif is None:
        stats.func_types_failed += 1
        msg("TYPE_FUNC_BUILD_FAIL %-30s @ %s" % (meta.name, ea_str(ea)))
        return "build-failed"

    if not dst_explicit and meta.quality in ("USER", "EXPLICIT"):
        changed = True

    if not changed:
        stats.func_types_unchanged += 1
        msg("TYPE_FUNC_UNCHANGED %-30s @ %s" % (meta.name, ea_str(ea)))
        return "unchanged"

    try:
        ok = ida_typeinf.apply_tinfo(ea, new_tif, ida_typeinf.TINFO_DEFINITE)
    except Exception as exc:
        ok = False
        msg("TYPE_FUNC_APPLY_EXCEPTION %-25s @ %s error=%s" % (meta.name, ea_str(ea), exc))

    if not ok:
        stats.func_types_failed += 1
        msg("TYPE_FUNC_APPLY_FAIL %-30s @ %s" % (meta.name, ea_str(ea)))
        return "apply-failed"

    if meta.quality == "USER":
        try:
            ida_nalt.set_userti(ea)
        except Exception:
            pass

    stats.func_types_applied += 1
    msg("TYPE_FUNC_APPLIED %-32s @ %s quality=%s" % (meta.name, ea_str(ea), meta.quality))
    return "applied"


def apply_global_type_safe(ea, meta, stats):
    """Apply a transported global type conservatively.

    A same-named destination type that the user set is never clobbered by a
    non-USER incoming type; a specific destination type is never downgraded to
    a generic incoming one.
    """
    if meta is None or not meta.has_prototype() or meta.quality == "NONE":
        return "no-meta"

    stats.glob_types_present += 1

    unresolved = [d for d in meta.dependencies if d and not named_type_present(d)]
    if unresolved:
        stats.glob_types_failed += 1
        msg(
            "GLOB_TYPE_DEP_MISSING %-26s @ %s deps=%s"
            % (meta.name, ea_str(ea),
               ",".join(unresolved[:8]) + ("..." if len(unresolved) > 8 else ""))
        )
        return "dependency-missing"

    src_tif = global_tinfo_from_meta(meta)
    if src_tif is None:
        stats.glob_types_failed += 1
        msg("GLOB_TYPE_DECODE_FAIL %-30s @ %s" % (meta.name, ea_str(ea)))
        return "parse-failed"

    dst_tif = ida_typeinf.tinfo_t()
    try:
        dst_has_type = bool(ida_nalt.get_tinfo(dst_tif, ea))
    except Exception:
        dst_has_type = False
    try:
        dst_user = bool(ida_nalt.is_userti(ea))
    except Exception:
        dst_user = False

    if dst_has_type:
        # Never downgrade a specific/user destination type.
        if dst_user and meta.quality != "USER":
            stats.glob_types_unchanged += 1
            msg("GLOB_TYPE_KEEP_USER %-28s @ %s" % (meta.name, ea_str(ea)))
            return "unchanged"
        if type_specificity(dst_tif) >= 80 and type_specificity(src_tif) <= type_specificity(dst_tif):
            stats.glob_types_unchanged += 1
            msg("GLOB_TYPE_KEEP_SPECIFIC %-24s @ %s" % (meta.name, ea_str(ea)))
            return "unchanged"

    try:
        ok = ida_typeinf.apply_tinfo(ea, src_tif, ida_typeinf.TINFO_DEFINITE)
    except Exception as exc:
        ok = False
        msg("GLOB_TYPE_APPLY_EXCEPTION %-25s @ %s error=%s" % (meta.name, ea_str(ea), exc))

    if not ok:
        stats.glob_types_failed += 1
        msg("GLOB_TYPE_APPLY_FAIL %-30s @ %s" % (meta.name, ea_str(ea)))
        return "apply-failed"

    if meta.quality == "USER":
        try:
            ida_nalt.set_userti(ea)
        except Exception:
            pass

    stats.glob_types_applied += 1
    msg("GLOB_TYPE_APPLIED %-32s @ %s quality=%s" % (meta.name, ea_str(ea), meta.quality))
    return "applied"


# ---------------------------------------------------------------------------
# Group resolution + rename
# ---------------------------------------------------------------------------

def _evaluate_candidates(name, records, ranges, match_cache, prefix):
    """Resolve **every** candidate of one item, not just the first that works.

    Independent candidates are the whole point of the format: agreement between
    them is evidence, and disagreement is a conflict that must be surfaced
    rather than silently decided by rank order.

    Returns ``(resolved, saw, outcomes)``.  ``outcomes`` deliberately retains
    every rejected candidate: reducing an item to merely ``unsafe`` throws
    away the one fact an operator needs to repair a stale catalogue.
    """
    resolved = []
    saw = {"not-found": False, "ambiguous": False, "unsafe": False}
    outcomes = []

    for rec in records:
        if rec.is_locator:
            # Structural modes are export-only. Their pattern is a bounded
            # confirm signature, not an image-wide locator, so searching it
            # here would be both wasteful and semantically wrong.
            saw["unsafe"] = True
            outcomes.append({"rank": rec.rank, "origin": rec.origin,
                             "mode": rec.mode, "status": "unsafe",
                             "reason": "export-only structural locator"})
            msg("%s_SKIPPED %-33s rank=%d mode=%s export-only locator"
                % (prefix, name, rec.rank, rec.mode))
            continue
        status, target_ea, detail = _find_unique_target(rec, ranges, match_cache)
        if status == "ok":
            resolved.append((rec, target_ea, detail))
            outcomes.append({"rank": rec.rank, "origin": rec.origin,
                             "mode": rec.mode, "status": "resolved",
                             "target": target_ea, "detail": detail})
            continue

        saw[status] = True
        outcomes.append({"rank": rec.rank, "origin": rec.origin,
                         "mode": rec.mode, "status": status,
                         "reason": detail})
        if status == "not-found":
            msg("%s_NOT_FOUND %-30s rank=%d mode=%s origin=%s"
                % (prefix, name, rec.rank, rec.mode, rec.origin))
        elif status == "ambiguous":
            msg("%s_AMBIGUOUS %-31s rank=%d mode=%s hits=%s"
                % (prefix, name, rec.rank, rec.mode, detail))
        else:
            msg("%s_UNSAFE %-34s rank=%d mode=%s %s"
                % (prefix, name, rec.rank, rec.mode, detail))

    return resolved, saw, outcomes


def _report_conflict(name, resolved, prefix):
    """Log and return True when independent candidates disagree on the target."""
    targets = {target_ea for _rec, target_ea, _detail in resolved}
    if len(targets) <= 1:
        return False

    detail = "  ".join(
        "rank%d/%s/%s=%s" % (rec.rank, rec.mode, rec.origin, ea_str(target_ea))
        for rec, target_ea, _detail in resolved
    )
    msg("%s_CONFLICT %-33s %d distinct targets: %s"
        % (prefix, name, len(targets), detail))
    return True


def _set_candidate_outcome(outcomes, rec, status, reason):
    """Replace a preliminary resolution after a later ownership check fails."""
    for row in outcomes:
        if row["rank"] == rec.rank:
            row.pop("target", None)
            row.pop("detail", None)
            row.update(status=status, reason=reason)
            return


def _candidate_group_failure(resolved, saw, candidate_outcomes):
    """Return a terminal validation failure, or ``None`` when one agrees."""
    targets = {target for _rec, target, _detail in resolved}
    if len(targets) > 1:
        return "conflict", "candidates resolved to different targets"
    if targets:
        return None
    if saw["unsafe"]:
        reasons = [row["reason"] for row in candidate_outcomes
                   if row["status"] == "unsafe"]
        return "unsafe", "; ".join(reasons)
    if saw["ambiguous"]:
        return "ambiguous", "multiple matches"
    return "not-found", "no candidate matched"


def _rename_target(name, func_ea, rec, candidate_index, stats):
    """Shared name-protection + rename for a resolved target. Returns a status
    string; on success performs the rename and returns 'renamed'/'already-same'.
    """
    current, protected = _name_state(func_ea)

    if current == name:
        if candidate_index > 0:
            stats.fallback_used += 1
        return "already-same"

    if protected:
        msg("SKIP_NAMED %-42s @ %s current=%s" % (name, ea_str(func_ea), current))
        return "skip-named"

    conflict = _global_name_ea(name)
    if conflict != BADADDR and conflict != func_ea:
        msg("NAME_CONFLICT %-39s target=%s existing=%s"
            % (name, ea_str(func_ea), ea_str(conflict)))
        return "name-conflict"

    flags = ida_name.SN_CHECK | ida_name.SN_NOWARN | ida_name.SN_NON_AUTO
    if not ida_name.set_name(func_ea, name, flags):
        msg("FAIL_RENAME %-42s @ %s" % (name, ea_str(func_ea)))
        return "failure"

    try:
        ida_name.make_name_user(func_ea)
    except Exception:
        pass

    if (ida_name.get_name(func_ea) or "") != name:
        msg("FAIL_VERIFY %-42s @ %s" % (name, ea_str(func_ea)))
        return "failure"

    return "renamed"


def try_apply_function_group(name, records, ranges, match_cache, stats,
                             claimed, meta=None):
    """Resolve one function group, rename it, then merge its prototype."""
    existing_global = _global_name_ea(name)
    resolved, saw, candidate_outcomes = _evaluate_candidates(
        name, records, ranges, match_cache, "CANDIDATE"
    )
    # Structural locators are confirmation evidence, not image-wide searches.
    # An already-correct function name establishes such a record by contract.
    if existing_global != BADADDR and records and all(rec.is_locator for rec in records):
        for row in candidate_outcomes:
            row.update(status="established", reason="established by existing name")
        stats.already_named_global += 1
        f = ida_funcs.get_func(existing_global)
        if f is not None and f.start_ea == existing_global:
            apply_function_type_safe(existing_global, meta, stats)
        return "already-global", candidate_outcomes, None
    terminal = _candidate_group_failure(resolved, saw, candidate_outcomes)
    if terminal is not None:
        status, reason = terminal
        if status == "conflict":
            stats.conflicts += 1
        elif status == "unsafe":
            stats.unsafe += 1
        elif status == "ambiguous":
            stats.ambiguous += 1
        else:
            stats.not_found += 1
        return status, candidate_outcomes, reason

    if existing_global != BADADDR:
        stats.already_named_global += 1
        f = ida_funcs.get_func(existing_global)
        if f is not None and f.start_ea == existing_global:
            msg("SKIP_NAME_EXISTS %-37s @ %s; merging type only"
                % (name, ea_str(existing_global)))
            apply_function_type_safe(existing_global, meta, stats)
        else:
            msg("SKIP_NAME_EXISTS %-37s @ %s (not a function start)"
                % (name, ea_str(existing_global)))
        return "already-global", candidate_outcomes, None

    for rec, target_ea, _detail in resolved:
        allow_create = rec.mode != "BODY"
        fstatus, func_ea, created = _ensure_function_start(
            target_ea, allow_create=allow_create
        )

        if fstatus == "interior":
            saw["unsafe"] = True
            _set_candidate_outcome(candidate_outcomes, rec, "unsafe",
                                   "target is inside existing function %s"
                                   % ea_str(func_ea))
            msg("CANDIDATE_INTERIOR %-33s rank=%d mode=%s target=%s owner=%s"
                % (name, rec.rank, rec.mode, ea_str(target_ea), ea_str(func_ea)))
            continue
        if fstatus != "ok":
            saw["unsafe"] = True
            _set_candidate_outcome(candidate_outcomes, rec, "unsafe",
                                   "destination is not a function start")
            msg("CANDIDATE_NOFUNC %-35s rank=%d mode=%s target=%s"
                % (name, rec.rank, rec.mode, ea_str(target_ea)))
            continue

        owner = claimed.get(func_ea)
        if owner is not None and owner != name:
            stats.conflicts += 1
            msg("FUNC_TARGET_CLASH %-34s @ %s already claimed by %s"
                % (name, ea_str(func_ea), owner))
            return "conflict", candidate_outcomes, "destination target claimed by %s" % owner

        if created:
            stats.created_functions += 1
            msg("CREATED_FUNC %-42s @ %s" % (name, ea_str(func_ea)))

        agreed = len(resolved)
        if agreed > 1:
            stats.confirmed += 1
        confirm = " confirmed-by=%d" % agreed if agreed > 1 else ""

        outcome = _rename_target(name, func_ea, rec, rec.rank, stats)

        if outcome == "already-same":
            stats.already_same += 1
            claimed[func_ea] = name
            msg("ALREADY_SAME %-41s @ %s via=%s rank=%d%s"
                % (name, ea_str(func_ea), rec.mode, rec.rank, confirm))
            apply_function_type_safe(func_ea, meta, stats)
            return "already-same", candidate_outcomes, None
        if outcome == "skip-named":
            stats.skipped_named += 1
            return "skip-named", candidate_outcomes, "destination has a protected name"
        if outcome == "name-conflict":
            stats.name_conflicts += 1
            return "name-conflict", candidate_outcomes, "requested name exists elsewhere"
        if outcome == "failure":
            stats.failures += 1
            return "failure", candidate_outcomes, "IDA refused or did not retain rename"

        stats.renamed += 1
        if rec.rank > 0:
            stats.fallback_used += 1
        claimed[func_ea] = name
        msg("RENAMED %-46s @ %s via=%s/%s rank=%d%s%s"
            % (name, ea_str(func_ea), rec.mode, rec.origin, rec.rank,
               " FALLBACK" if rec.rank > 0 else "", confirm))
        apply_function_type_safe(func_ea, meta, stats)
        return "renamed", candidate_outcomes, None

    if saw["unsafe"]:
        stats.unsafe += 1
        msg("UNRESOLVED_UNSAFE %-36s" % name)
        reasons = [row["reason"] for row in candidate_outcomes
                   if row["status"] == "unsafe"]
        return "unsafe", candidate_outcomes, "; ".join(reasons)
    if saw["ambiguous"]:
        stats.ambiguous += 1
        msg("UNRESOLVED_AMBIGUOUS %-33s" % name)
        return "ambiguous", candidate_outcomes, "multiple matches"
    stats.not_found += 1
    msg("NOT_FOUND %-44s" % name)
    return "not-found", candidate_outcomes, "no candidate matched"


def try_apply_global_group(name, records, ranges, match_cache, stats,
                           claimed, meta=None):
    """Resolve one global group by its REL data-anchor(s), rename, apply type."""
    resolved, saw, candidate_outcomes = _evaluate_candidates(
        name, records, ranges, match_cache, "GLOB_CAND"
    )
    terminal = _candidate_group_failure(resolved, saw, candidate_outcomes)
    if terminal is not None:
        status, reason = terminal
        if status == "conflict":
            stats.glob_conflicts += 1
        elif status == "unsafe":
            stats.glob_unsafe += 1
        elif status == "ambiguous":
            stats.glob_ambiguous += 1
        else:
            stats.glob_not_found += 1
        return status, candidate_outcomes, reason

    existing_global = _global_name_ea(name)
    if existing_global != BADADDR:
        stats.glob_already_named += 1
        msg("GLOB_SKIP_NAME_EXISTS %-32s @ %s; applying type only"
            % (name, ea_str(existing_global)))
        apply_global_type_safe(existing_global, meta, stats)
        return "already-global", candidate_outcomes, None

    for rec, target_ea, _detail in resolved:
        owner = claimed.get(target_ea)
        if owner is not None and owner != name:
            stats.glob_conflicts += 1
            msg("GLOB_TARGET_CLASH %-34s @ %s already claimed by %s"
                % (name, ea_str(target_ea), owner))
            return "conflict", candidate_outcomes, "destination target claimed by %s" % owner

        agreed = len(resolved)
        if agreed > 1:
            stats.glob_confirmed += 1
        confirm = " confirmed-by=%d" % agreed if agreed > 1 else ""

        outcome = _rename_target(name, target_ea, rec, rec.rank, stats)

        if outcome == "already-same":
            stats.glob_already_same += 1
            claimed[target_ea] = name
            msg("GLOB_ALREADY_SAME %-36s @ %s%s"
                % (name, ea_str(target_ea), confirm))
            apply_global_type_safe(target_ea, meta, stats)
            return "already-same", candidate_outcomes, None
        if outcome == "skip-named":
            stats.glob_skipped_named += 1
            return "skip-named", candidate_outcomes, "destination has a protected name"
        if outcome == "name-conflict":
            stats.glob_name_conflicts += 1
            return "name-conflict", candidate_outcomes, "requested name exists elsewhere"
        if outcome == "failure":
            stats.failures += 1
            return "failure", candidate_outcomes, "IDA refused or did not retain rename"

        stats.glob_renamed += 1
        claimed[target_ea] = name
        msg("GLOB_RENAMED %-41s @ %s rank=%d%s%s"
            % (name, ea_str(target_ea), rec.rank,
               " FALLBACK" if rec.rank > 0 else "", confirm))
        apply_global_type_safe(target_ea, meta, stats)
        return "renamed", candidate_outcomes, None

    if saw["unsafe"]:
        stats.glob_unsafe += 1
        msg("GLOB_UNRESOLVED_UNSAFE %-31s" % name)
        reasons = [row["reason"] for row in candidate_outcomes
                   if row["status"] == "unsafe"]
        return "unsafe", candidate_outcomes, "; ".join(reasons)
    if saw["ambiguous"]:
        stats.glob_ambiguous += 1
        msg("GLOB_UNRESOLVED_AMBIGUOUS %-28s" % name)
        return "ambiguous", candidate_outcomes, "multiple matches"
    stats.glob_not_found += 1
    msg("GLOB_NOT_FOUND %-39s" % name)
    return "not-found", candidate_outcomes, "no candidate matched"


# ---------------------------------------------------------------------------
# Import driver
# ---------------------------------------------------------------------------

def _warn_on_image_mismatch(loaded):
    """Report, never block, when the file came from a different image.

    A CFS6 file is meant to be applied across builds, so a mismatch is the
    normal case; the point is that the user sees which image produced it.
    """
    image = loaded.image()
    try:
        current = describe_image()[0]
    except Exception:
        return

    if image.get("sha256") and image.get("sha256") == current.get("sha256"):
        msg("IMAGE_MATCH: exported from this exact image.")
        return

    msg(
        "IMAGE_DIFFERS: file=%s/%s current=%s/%s -- expected when transferring "
        "across builds; source RVAs in the file are diagnostics only."
        % (image.get("name"), image.get("size_of_image"),
           current.get("name"), current.get("size_of_image"))
    )


def _result(ok=False, partial=False, error=None, unresolved=None, **extra):
    result = {
        "ok": bool(ok), "partial": bool(partial), "error": error,
        "unresolved": list(unresolved or []),
    }
    result.update(extra)
    return result


def import_catalogue(path, show_progress=False, transport_types=False,
                     return_member_baseline=False):
    """Resolve and apply one catalogue without prompts or modal UI.

    The return value is JSON-serializable and follows the agent API's strict
    outcome contract: any unresolved requested item makes ``ok`` false.
    ``show_progress`` enables cancellable wait boxes for the interactive
    plugin wrapper; service callers leave it false.
    """
    stats = Stats()

    try:
        loaded = cfs6.load_catalogue(path, log=msg)
    except cfs6.Cfs6Error as exc:
        return _result(error=str(exc), path=path)
    except Exception as exc:
        return _result(error="could not read CFS catalogue: %s" % exc, path=path)

    stats.parse_errors = loaded.parse_errors
    func_groups = loaded.functions()
    glob_groups = loaded.globals()
    stats.groups = len(func_groups)
    stats.glob_groups = len(glob_groups)

    derived = loaded.derived_values()
    patches = loaded.patches()
    if not func_groups and not glob_groups and not derived and not patches:
        return _result(error="no CFS item records found", path=path)

    ranges = get_search_ranges()
    if not ranges:
        return _result(error="no executable/code search ranges found", path=path)

    func_sigs = sum(len(i.candidates) for i in func_groups)
    glob_sigs = sum(len(i.candidates) for i in glob_groups)

    msg("=" * 72)
    msg("CFS Importer %s" % VERSION)
    msg("File: %s" % path)
    msg("Source: %s" % loaded.describe_source())
    _warn_on_image_mismatch(loaded)
    msg(
        "Functions: %d  Function sigs: %d  Globals: %d  Global sigs: %d  "
        "Types: %d  Parse errors: %d  Skipped records: %d"
        % (len(func_groups), func_sigs, len(glob_groups), glob_sigs,
           len(loaded.type_records), loaded.parse_errors, loaded.skipped_records)
    )
    msg("Search ranges: %s"
        % ", ".join("%s[%s-%s]" % (name, ea_str(a), ea_str(b)) for a, b, name in ranges))
    msg("=" * 72)

    # Snapshot before optional type transport: imported layouts are bootstrap
    # material, never independent proof for a migrated member declaration.
    member_baseline = _capture_destination_members(derived)

    # Ordinary catalogue import never manufactures member-layout evidence from
    # the catalogue.  Explicit import-and-migrate opts into type transport.
    if transport_types:
        if show_progress:
            ida_kernwin.show_wait_box("NODELAY\nRegistering missing CFS6 local types...")
        try:
            type_state = register_missing_types(loaded.type_records, stats)
        except Exception as exc:
            type_state = {"preexisting": set(), "registered": set(),
                          "failed": set(loaded.type_records)}
            stats.types_total = len(loaded.type_records)
            stats.types_failed = len(loaded.type_records)
            msg("TYPE_REGISTRATION_FATAL: %s" % exc)
        finally:
            if show_progress:
                ida_kernwin.hide_wait_box()
    else:
        preexisting = {name for name in loaded.type_records if named_type_present(name)}
        type_state = {"preexisting": preexisting, "registered": set(),
                      "failed": set()}
        stats.types_total = len(loaded.type_records)
        stats.types_existing = len(preexisting)

    msg("Types: %d kept-existing, %d registered, %d failed"
        % (len(type_state["preexisting"]), len(type_state["registered"]),
           len(type_state["failed"])))

    match_cache = {}
    total = len(func_groups) + len(glob_groups)
    outcomes = []

    # VALUE and SITE records are intentionally validation-only here.  Importing
    # a catalogue must expose stale dumper inputs, but it must never apply a
    # patch or reconstruct producer state; that remains migrate_state's job.
    for item in derived:
        evidence, error, candidates = _resolve_declaration_evidence(
            item, ranges, match_cache
        )
        row = {"kind": item.semantic, "id": item.id,
               "name": item.qualified_name, "candidates": candidates}
        if error:
            row.update(status="unsafe", reason=error)
        else:
            row.update(status="validated", value=evidence["value"],
                       evidence=evidence["evidence"])
            if item.semantic == cfs6.SEM_MEMBER_OFFSET:
                observed = member_baseline[item.id]
                if observed is None:
                    row.update(status="destination-unverified", destination={
                        "status": "unavailable", "member": item.qualified_name,
                    })
                elif observed != evidence["value"]:
                    row.update(status="destination-disagrees", reason=(
                        "destination IDA field disagrees: type=0x%X code=0x%X; "
                        "update the type from independent evidence"
                        % (observed, evidence["value"])
                    ), destination={"status": "disagrees", "offset": observed})
                else:
                    row.update(status="destination-agrees", destination={
                        "status": "agrees", "offset": observed,
                    })
            if item.expected_value is not None and item.expected_value != evidence["value"]:
                row["drift"] = {"source": item.expected_value,
                                "destination": evidence["value"]}
        outcomes.append(row)

    for item in patches:
        planned, error, candidates = _validate_patch(item, ranges, match_cache)
        row = {"kind": "patch", "id": item.id,
               "name": item.qualified_name, "candidates": candidates}
        if error:
            row.update(status="unsafe", reason=error)
        else:
            row.update(status="validated", site=planned["site"],
                       evidence=planned["evidence"])
        outcomes.append(row)

    if show_progress:
        ida_kernwin.clr_cancelled()
        ida_kernwin.show_wait_box(
            "NODELAY\nImporting CFS6 signatures + prototypes...\nPress Cancel to stop."
        )

    # Reverse map so two different items resolving to one address is caught.
    claimed = {}
    try:
        done = 0
        cancelled = False

        for item in func_groups:
            if show_progress and ida_kernwin.user_cancelled():
                cancelled = True
                break
            done += 1
            if show_progress and (done == 1 or done == total or
                                  done % PROGRESS_EVERY == 0):
                ida_kernwin.replace_wait_box(
                    "Functions...\n%d / %d\nRenamed: %d  Missing: %d  "
                    "Ambiguous: %d  Conflicts: %d\nTypes applied: %d  "
                    "Registered UDTs: %d\nCurrent: %s"
                    % (done, total, stats.renamed, stats.not_found, stats.ambiguous,
                       stats.conflicts, stats.func_types_applied,
                       stats.types_registered, item.name)
                )
            try:
                status, candidates, reason = try_apply_function_group(
                    item.name, item.candidates, ranges, match_cache, stats,
                    claimed, meta=loaded.item_meta.get(item.id),
                )
                row = {"kind": "function", "id": item.id,
                       "name": item.name, "status": status,
                       "candidates": candidates}
                if reason:
                    row["reason"] = reason
                outcomes.append(row)
            except Exception as exc:
                stats.failures += 1
                msg("FAIL_EXCEPTION %-39s error=%s" % (item.name, exc))
                outcomes.append({"kind": "function", "id": item.id,
                                 "name": item.name, "status": "exception",
                                 "reason": str(exc)})
            stats.processed += 1

        if not cancelled:
            for item in glob_groups:
                if show_progress and ida_kernwin.user_cancelled():
                    cancelled = True
                    break
                done += 1
                if show_progress and (done == 1 or done == total or
                                      done % PROGRESS_EVERY == 0):
                    ida_kernwin.replace_wait_box(
                        "Globals...\n%d / %d\nRenamed: %d  Missing: %d  "
                        "Ambiguous: %d  Conflicts: %d\nTypes applied: %d\nCurrent: %s"
                        % (done, total, stats.glob_renamed, stats.glob_not_found,
                           stats.glob_ambiguous, stats.glob_conflicts,
                           stats.glob_types_applied, item.name)
                    )
                try:
                    status, candidates, reason = try_apply_global_group(
                        item.name, item.candidates, ranges, match_cache, stats,
                        claimed, meta=loaded.item_meta.get(item.id),
                    )
                    row = {"kind": "global", "id": item.id,
                           "name": item.name, "status": status,
                           "candidates": candidates}
                    if reason:
                        row["reason"] = reason
                    outcomes.append(row)
                except Exception as exc:
                    stats.failures += 1
                    msg("GLOB_FAIL_EXCEPTION %-34s error=%s" % (item.name, exc))
                    outcomes.append({"kind": "global", "id": item.id,
                                     "name": item.name, "status": "exception",
                                     "reason": str(exc)})
                stats.glob_processed += 1

        if cancelled:
            stats.cancelled = True
            msg("CANCELLED after %d/%d items." % (done - 1, total))

    finally:
        if show_progress:
            ida_kernwin.hide_wait_box()
            ida_kernwin.clr_cancelled()

    msg("-" * 72)
    for line in stats.summary().splitlines():
        msg(line)
    msg("-" * 72)

    good = {"renamed", "already-same", "already-global", "validated",
            "destination-agrees", "destination-unverified"}
    unresolved = [
        {"kind": row["kind"], "name": row["name"],
         "reason": row.get("reason", row["status"])}
        for row in outcomes if row["status"] not in good
    ]
    succeeded = len(outcomes) - len(unresolved)
    ok = not unresolved and not stats.cancelled and stats.parse_errors == 0 \
        and stats.failures == 0
    result = _result(
        ok=ok, partial=(not ok and succeeded > 0), unresolved=unresolved,
        error="cancelled" if stats.cancelled else None,
        path=path, requested=len(func_groups) + len(glob_groups) + len(derived) + len(patches),
        applied=succeeded, outcomes=outcomes, summary=stats.summary(),
        source=loaded.describe_source(), parse_errors=stats.parse_errors,
        skipped_records=loaded.skipped_records,
        derived_values=len(derived), patches=len(patches),
        warnings=[row for row in outcomes
                  if row["status"] == "destination-unverified"],
        type_transport=bool(transport_types),
        types={"preexisting": len(type_state["preexisting"]),
               "registered": len(type_state["registered"]),
               "failed": len(type_state["failed"])},
    )
    if return_member_baseline:
        result["member_baseline"] = member_baseline
    return result


def _snapshot_state():
    return {
        "registry": store.load_registry(),
        "sites": store.load_sites(),
        "locators": store.load_locators(),
        "declarations": [d.to_dict() for d in store.load_all()],
        "patches": [p.to_dict() for p in store.load_patches()],
    }


def _restore_state(snapshot):
    ok = store.save_registry(snapshot["registry"])
    ok = store.save_sites(snapshot["sites"]) and ok
    ok = store.save_locators(snapshot["locators"]) and ok
    for current in store.load_all():
        ok = store.delete(current.id) and ok
    for current in store.load_patches():
        ok = store.delete_patch(current.id) and ok
    for data in snapshot["declarations"]:
        try:
            ok = store.save(declare.from_dict(data)) and ok
        except Exception as exc:
            msg("MIGRATE_ROLLBACK_DECL_FAIL: %s" % exc)
            ok = False
    for data in snapshot["patches"]:
        try:
            ok = store.save_patch(patchdecl.from_dict(data)) and ok
        except Exception as exc:
            msg("MIGRATE_ROLLBACK_PATCH_FAIL: %s" % exc)
            ok = False
    return ok


def _capture_destination_members(items):
    """Snapshot independent member evidence before any optional type transport."""
    out = {}
    for item in items:
        if item.semantic != cfs6.SEM_MEMBER_OFFSET:
            continue
        ref = members.lookup_member(item.owner, item.name)
        out[item.id] = None if ref is None else int(ref.byte_offset)
    return out


def _resolve_declaration_evidence(item, ranges, match_cache):
    """Resolve VALUE candidates without consulting or changing destination types."""
    resolved = []
    failures = []
    recipes = []
    candidate_outcomes = []
    for rec in item.candidates:
        match_ea, error = _find_unique_match(rec, ranges, match_cache)
        if error:
            failures.append("rank%d/%s: %s" % (rec.rank, rec.origin, error))
            candidate_outcomes.append({"rank": rec.rank, "origin": rec.origin,
                                       "mode": rec.mode, "status": error,
                                       "reason": error})
            continue
        value, site, recipe, error = _resolve_value_at_match(rec, match_ea)
        if error:
            failures.append("rank%d/%s: %s" % (rec.rank, rec.origin, error))
            candidate_outcomes.append({"rank": rec.rank, "origin": rec.origin,
                                       "mode": rec.mode, "status": "unsafe",
                                       "reason": error})
            continue
        resolved.append((rec, value, site))
        candidate_outcomes.append({"rank": rec.rank, "origin": rec.origin,
                                   "mode": rec.mode, "status": "resolved",
                                   "value": value, "site": site["ea"]})
        if recipe:
            recipes.append(recipe)
    values = {value for _rec, value, _site in resolved}
    if not resolved:
        return None, "no candidate resolved (%s)" % "; ".join(failures), candidate_outcomes
    if len(values) != 1:
        return None, "candidate conflict: %s" % ", ".join(
            "rank%d=%s" % (rec.rank, value) for rec, value, _site in resolved
        ), candidate_outcomes
    value = next(iter(values))
    sites = []
    seen = set()
    for _rec, _value, site in resolved:
        key = (site["ea"], site["op"])
        if key not in seen:
            seen.add(key)
            sites.append(site)
    adjustments = {rec.value_adjust for rec, _value, _site in resolved}
    if len(adjustments) != 1:
        return None, "candidate value_adjust conflict", candidate_outcomes
    adjust = next(iter(adjustments))

    return {"value": value, "sites": sites, "adjust": adjust,
            "recipes": recipes, "evidence": len(resolved),
            "failures": failures, "candidates": candidate_outcomes}, None, candidate_outcomes


def _plan_declaration(item, ranges, match_cache, member_baseline=None):
    """Make a migration declaration only after independent type agreement."""
    evidence, error, candidate_outcomes = _resolve_declaration_evidence(
        item, ranges, match_cache
    )
    if error:
        return None, error, candidate_outcomes
    value = evidence["value"]
    try:
        if item.semantic == cfs6.SEM_MEMBER_OFFSET:
            if member_baseline is None:
                ref = members.lookup_member(item.owner, item.name)
                observed = None if ref is None else int(ref.byte_offset)
            else:
                observed = member_baseline.get(item.id)
            if observed is None:
                return None, "destination has no independent IDA field %s.%s" % (
                    item.owner, item.name
                ), candidate_outcomes
            if observed != value:
                return None, (
                    "destination IDA field is stale or disagrees: type=0x%X "
                    "code=0x%X; update the type from independent evidence"
                    % (observed, value)
                ), candidate_outcomes
            decl = declare.make_member(
                item.owner, item.name, sites=evidence["sites"],
                discovery=declare.DISCOVER_SITES_ONLY,
                value_adjust=evidence["adjust"],
            )
        elif item.semantic == cfs6.SEM_ELEMENT_STRIDE:
            decl = declare.make_stride(
                item.owner, item.name, value, evidence["sites"],
                value_adjust=evidence["adjust"],
                recipe=evidence["recipes"][0] if evidence["recipes"] else None,
            )
        elif item.semantic == cfs6.SEM_CONSTANT:
            decl = declare.make_constant(
                item.owner, item.name, value, evidence["sites"],
                value_adjust=evidence["adjust"],
            )
        elif item.semantic == cfs6.SEM_OBJECT_EXTENT:
            decl = declare.make_extent(item.owner, item.name, value,
                                       evidence["sites"])
        else:
            return None, "unsupported semantic %s" % item.semantic, candidate_outcomes
    except declare.DeclarationError as exc:
        return None, str(exc), candidate_outcomes
    drift = None
    if item.expected_value is not None and item.expected_value != value:
        drift = {"source": item.expected_value, "destination": value}
    evidence.update(declaration=decl, drift=drift)
    return evidence, None, candidate_outcomes


def _validate_patch(item, ranges, match_cache):
    """Validate one patch record without modifying destination bytes or state."""
    resolved = []
    candidates = []
    failures = []
    expected = bytes.fromhex(item.expected_bytes)
    for rec in item.candidates:
        match_ea, error = _find_unique_match(rec, ranges, match_cache)
        if error:
            failures.append("rank%d/%s: %s" % (rec.rank, rec.origin, error))
            candidates.append({"rank": rec.rank, "origin": rec.origin,
                               "mode": rec.mode, "status": error,
                               "reason": error})
            continue
        site_ea = match_ea + rec.instruction_offset
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, site_ea) <= 0 or insn.size <= 0:
            failures.append("rank%d/%s: patch instruction does not decode"
                            % (rec.rank, rec.origin))
            candidates.append({"rank": rec.rank, "origin": rec.origin,
                               "mode": rec.mode, "status": "unsafe",
                               "reason": "patch instruction does not decode"})
            continue
        if item.patch_size < insn.size:
            failures.append("rank%d/%s: patch span cuts through decoded instruction"
                            % (rec.rank, rec.origin))
            candidates.append({"rank": rec.rank, "origin": rec.origin,
                               "mode": rec.mode, "status": "unsafe",
                               "reason": "patch span cuts through decoded instruction"})
            continue
        raw = ida_bytes.get_bytes(site_ea, item.patch_size)
        if raw is None or len(raw) != item.patch_size or not raw.startswith(expected):
            failures.append("rank%d/%s: original opcode bytes or patch span differ"
                            % (rec.rank, rec.origin))
            candidates.append({"rank": rec.rank, "origin": rec.origin,
                               "mode": rec.mode, "status": "unsafe",
                               "reason": "original opcode bytes or patch span differ"})
            continue
        mnemonic = (ida_ua.print_insn_mnem(site_ea) or "").lower()
        if mnemonic != item.expected_instruction:
            failures.append("rank%d/%s: expected instruction %s, decoded %s"
                            % (rec.rank, rec.origin, item.expected_instruction,
                               mnemonic or "?"))
            candidates.append({"rank": rec.rank, "origin": rec.origin,
                               "mode": rec.mode, "status": "unsafe",
                               "reason": "expected instruction %s, decoded %s"
                               % (item.expected_instruction, mnemonic or "?")})
            continue
        resolved.append(site_ea)
        candidates.append({"rank": rec.rank, "origin": rec.origin,
                           "mode": rec.mode, "status": "resolved",
                           "site": site_ea})
    if not resolved:
        return None, "no candidate resolved (%s)" % "; ".join(failures), candidates
    if len(set(resolved)) != 1:
        return None, "candidate conflict: %s" % ", ".join(
            ea_str(ea) for ea in sorted(set(resolved))), candidates
    return {"site": resolved[0], "evidence": len(resolved),
            "candidates": candidates}, None, candidates


def migrate_producer_state(path, require_all=False, member_baseline=None):
    """Rebuild portable exporter state from a CFS catalogue transactionally.

    Absolute source addresses are never copied.  Declarations and patch sites
    are reconstructed only from candidates that uniquely resolve in the
    destination image. Existing producer records are never overwritten with a
    different definition.
    """
    try:
        loaded = cfs6.load_catalogue(path, log=msg)
    except Exception as exc:
        return _result(error="could not read CFS catalogue: %s" % exc, path=path)
    ranges = get_search_ranges()
    if not ranges:
        return _result(error="no executable/code search ranges found", path=path)

    match_cache = {}
    planned_registry = []
    planned_locators = {}
    planned_declarations = []
    planned_patches = []
    unresolved = []
    notices = []

    for item in loaded.functions() + loaded.globals():
        ea = _global_name_ea(item.name)
        if ea == BADADDR:
            unresolved.append({"kind": item.kind, "name": item.name,
                               "reason": "catalogue item is not applied in destination IDB"})
            continue
        planned_registry.append(item.id)
        if item.kind == cfs6.REC_FUNCTION:
            locators = []
            for rec in item.candidates:
                if rec.mode == cfs6.MODE_VTABLE:
                    locators.append({
                        "kind": registry.LOCATOR_VTABLE,
                        "type": rec.type_descriptor, "slot": rec.slot,
                        "subobject_offset": rec.subobject_offset,
                    })
                elif rec.mode == cfs6.MODE_STRING_REL:
                    locators.append({"kind": registry.LOCATOR_ANCHOR_STRING,
                                     "string": rec.anchor_string})
            if locators:
                planned_locators[item.id] = locators

    for item in loaded.derived_values():
        planned, error, _candidates = _plan_declaration(
            item, ranges, match_cache, member_baseline=member_baseline
        )
        if error:
            unresolved.append({"kind": item.semantic,
                               "name": item.qualified_name, "reason": error})
            continue
        planned_declarations.append(planned["declaration"])
        if planned["drift"]:
            notices.append({"kind": item.semantic, "name": item.qualified_name,
                            "notice": "value drift", **planned["drift"]})
        for failure in planned["failures"]:
            notices.append({"kind": item.semantic, "name": item.qualified_name,
                            "notice": "candidate not portable", "reason": failure})

    for item in loaded.patches():
        resolved = []
        reasons = []
        for rec in item.candidates:
            match_ea, error = _find_unique_match(rec, ranges, match_cache)
            if error:
                reasons.append("rank%d: %s" % (rec.rank, error))
                continue
            site_ea = match_ea + rec.instruction_offset
            raw = ida_bytes.get_bytes(site_ea, item.patch_size)
            expected = bytes.fromhex(item.expected_bytes)
            if raw is None or not raw.startswith(expected):
                reasons.append("rank%d: original opcode/span mismatch" % rec.rank)
                continue
            mnemonic = (ida_ua.print_insn_mnem(site_ea) or "").lower()
            if mnemonic != item.expected_instruction:
                reasons.append(
                    "rank%d: expected instruction %s, decoded %s"
                    % (rec.rank, item.expected_instruction, mnemonic or "?")
                )
                continue
            resolved.append(site_ea)
        if not resolved:
            unresolved.append({"kind": "patch", "name": item.qualified_name,
                               "reason": "; ".join(reasons)})
        elif len(set(resolved)) != 1:
            unresolved.append({"kind": "patch", "name": item.qualified_name,
                               "reason": "candidate conflict"})
        else:
            try:
                planned_patches.append(patchdecl.PatchDeclaration(
                    item.owner, item.name, {
                        "ea": resolved[0],
                        "expected_instruction": item.expected_instruction,
                        "expected_bytes": item.expected_bytes,
                        "patch_size": item.patch_size,
                    }
                ))
            except declare.DeclarationError as exc:
                unresolved.append({"kind": "patch", "name": item.qualified_name,
                                   "reason": str(exc)})

    existing_decls = {d.id: d for d in store.load_all()}
    existing_patches = {p.id: p for p in store.load_patches()}
    for decl in planned_declarations:
        old = existing_decls.get(decl.id)
        if old is not None and old.to_dict() != decl.to_dict():
            unresolved.append({"kind": "declaration", "name": decl.qualified,
                               "reason": "existing producer declaration differs"})
    for patch in planned_patches:
        old = existing_patches.get(patch.id)
        if old is not None and old.to_dict() != patch.to_dict():
            unresolved.append({"kind": "patch", "name": patch.qualified,
                               "reason": "existing producer patch differs"})

    requested = len(loaded.functions()) + len(loaded.globals()) \
        + len(loaded.derived_values()) + len(loaded.patches())
    planned = len(planned_registry) + len(planned_declarations) + len(planned_patches)
    if unresolved and require_all:
        return _result(
            error="producer-state migration refused; no state was written",
            unresolved=unresolved, path=path, requested=requested,
            migrated=0, notices=notices,
        )

    snapshot = _snapshot_state()
    try:
        merged_registry = sorted(set(snapshot["registry"] + planned_registry))
        if not store.save_registry(merged_registry):
            raise RuntimeError("registry write failed")
        merged_locators = dict(snapshot["locators"])
        for iid, values in planned_locators.items():
            merged_locators[iid] = values
        if not store.save_locators(merged_locators):
            raise RuntimeError("locator write failed")
        for decl in planned_declarations:
            if decl.id not in existing_decls and not store.save(decl):
                raise RuntimeError("declaration write failed: %s" % decl.id)
        for patch in planned_patches:
            if patch.id not in existing_patches and not store.save_patch(patch):
                raise RuntimeError("patch write failed: %s" % patch.id)
    except Exception as exc:
        restored = _restore_state(snapshot)
        return _result(
            error="producer-state commit failed and rollback %s: %s" % (
                "succeeded" if restored else "FAILED", exc
            ), unresolved=unresolved, path=path, requested=requested,
            migrated=0, notices=notices,
        )

    ok = not unresolved
    return _result(
        ok=ok, partial=(not ok and planned > 0), unresolved=unresolved,
        path=path, requested=requested, migrated=planned, notices=notices,
        registry=len(planned_registry), declarations=len(planned_declarations),
        patches=len(planned_patches), transactional=True,
    )


def import_and_migrate(path, require_all_state=False, show_progress=False):
    """Apply a catalogue, then transactionally reconstruct producer state."""
    catalogue = import_catalogue(
        path, show_progress=show_progress, transport_types=True,
        return_member_baseline=True,
    )
    member_baseline = catalogue.pop("member_baseline", None)
    state = migrate_producer_state(
        path, require_all=require_all_state,
        member_baseline=member_baseline,
    )
    ok = bool(catalogue.get("ok") and state.get("ok"))
    combined = []
    seen = set()
    for entry in catalogue.get("unresolved", []) + state.get("unresolved", []):
        key = (entry.get("kind"), entry.get("name"), entry.get("reason"))
        if key not in seen:
            seen.add(key)
            combined.append(entry)
    return _result(
        ok=ok, partial=(not ok and (catalogue.get("partial") or state.get("partial"))),
        error=state.get("error") or catalogue.get("error"),
        unresolved=combined,
        path=path, catalogue=catalogue, state=state,
    )
