# CFS5 Importer for IDA Pro 9.0 / IDAPython 9.0
#
# Imports a .cfs file into the current IDB:
#   * resolves each function via its ranked ENTRY/BODY/REL signatures, renames
#     it (never clobbering a real destination name) and merges its prototype;
#   * resolves each user global via its REL data-anchor signature, renames it
#     and applies its transported type;
#   * registers missing named Local Types (multi-pass, non-destructive).
#
# Accepts CFS5, CFS4, CFS3, CFS2 and legacy Cra0 rows. Shared machinery lives
# in the importable `cfs5` package; this file is resolution/apply orchestration
# and the IDA plugin/UI glue.
#
# Target: IDA Professional 9.0 / Python 3.12.

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
for _modname in [n for n in list(sys.modules) if n == "cfs5" or n.startswith("cfs5.")]:
    del sys.modules[_modname]

import idaapi
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_nalt
import ida_segment
import ida_typeinf
import ida_ua

from cfs5 import VERSION
from cfs5 import cfsfile
from cfs5.common import BADADDR, ea_str, find_up_to_two, get_search_ranges, msg
from cfs5.typeio import (
    deserialize_binary_tinfo,
    function_tinfo_from_meta,
    get_function_tinfo,
    global_tinfo_from_meta,
    merge_function_tinfos,
    named_type_present,
    register_missing_types,
    type_specificity,
)


PLUGIN_NAME = "CFS5 Importer (IDA 9)"
PLUGIN_HOTKEY = "Ctrl+Shift+I"
ACTION_ID = "cfs5:import_file"
ACTION_LABEL = "CFS5 / CFS File..."

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
            "CFS5 import summary\n\n"
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
            "Unsafe/unresolvable: %d\n\n"
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
                self.ambiguous, self.unsafe, self.created_functions,
                self.fallback_used,
                self.glob_processed, self.glob_groups, self.glob_renamed,
                self.glob_already_named, self.glob_already_same,
                self.glob_skipped_named, self.glob_name_conflicts,
                self.glob_not_found, self.glob_ambiguous, self.glob_unsafe,
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
        return "ok", owner.start_ea, "body-owner"

    if rec.mode == "REL":
        insn_ea = match_ea + rec.insn_offset
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

        field_ea = match_ea + rec.rel_offset
        if not (insn_ea <= field_ea and field_ea + rec.rel_size <= insn_ea + insn.size):
            return "unsafe", BADADDR, "REL field lies outside decoded instruction"

        disp = _read_signed(field_ea, rec.rel_size)
        if disp is None:
            return "unsafe", BADADDR, "REL displacement bytes unavailable"

        target = match_ea + rec.base_offset + disp + rec.target_delta
        if rec.is_data:
            if not _target_is_mapped_data(target):
                return "unsafe", BADADDR, "REL target %s is not mapped data" % ea_str(target)
        else:
            if not _target_is_mapped_codeish(target):
                return "unsafe", BADADDR, "REL target %s is not mapped code" % ea_str(target)

        return "ok", target, "rel%d" % (rec.rel_size * 8)

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
    matches = match_cache.get(rec.signature)
    if matches is None:
        matches = find_up_to_two(rec.signature, ranges)
        match_cache[rec.signature] = matches

    if len(matches) == 0:
        return "not-found", BADADDR, "no match"
    if len(matches) > 1:
        return "ambiguous", BADADDR, "%s,%s" % (ea_str(matches[0]), ea_str(matches[1]))

    return resolve_candidate(rec, matches[0])


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


def try_apply_function_group(name, records, ranges, match_cache, stats, meta=None):
    """Resolve one function group, rename it, then merge its prototype."""
    existing_global = _global_name_ea(name)
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
        return "already-global"

    saw_not_found = saw_ambiguous = saw_unsafe = False

    for candidate_index, rec in enumerate(records):
        rstatus, target_ea, detail = _find_unique_target(rec, ranges, match_cache)
        if rstatus == "not-found":
            saw_not_found = True
            msg("CANDIDATE_NOT_FOUND %-32s rank=%d mode=%s" % (name, rec.rank, rec.mode))
            continue
        if rstatus == "ambiguous":
            saw_ambiguous = True
            msg("CANDIDATE_AMBIGUOUS %-32s rank=%d mode=%s hits=%s"
                % (name, rec.rank, rec.mode, detail))
            continue
        if rstatus != "ok":
            saw_unsafe = True
            msg("CANDIDATE_UNSAFE %-35s rank=%d mode=%s %s"
                % (name, rec.rank, rec.mode, detail))
            continue

        allow_create = rec.mode != "BODY"
        fstatus, func_ea, created = _ensure_function_start(target_ea, allow_create=allow_create)

        if fstatus == "interior":
            saw_unsafe = True
            msg("CANDIDATE_INTERIOR %-33s rank=%d mode=%s target=%s owner=%s"
                % (name, rec.rank, rec.mode, ea_str(target_ea), ea_str(func_ea)))
            continue
        if fstatus != "ok":
            saw_unsafe = True
            msg("CANDIDATE_NOFUNC %-35s rank=%d mode=%s target=%s"
                % (name, rec.rank, rec.mode, ea_str(target_ea)))
            continue

        if created:
            stats.created_functions += 1
            msg("CREATED_FUNC %-42s @ %s" % (name, ea_str(func_ea)))

        outcome = _rename_target(name, func_ea, rec, candidate_index, stats)

        if outcome == "already-same":
            stats.already_same += 1
            msg("ALREADY_SAME %-41s @ %s via=%s rank=%d"
                % (name, ea_str(func_ea), rec.mode, rec.rank))
            apply_function_type_safe(func_ea, meta, stats)
            return "already-same"
        if outcome == "skip-named":
            stats.skipped_named += 1
            return "skip-named"
        if outcome == "name-conflict":
            stats.name_conflicts += 1
            return "name-conflict"
        if outcome == "failure":
            stats.failures += 1
            return "failure"

        stats.renamed += 1
        if candidate_index > 0:
            stats.fallback_used += 1
        msg("RENAMED %-46s @ %s via=%s rank=%d%s"
            % (name, ea_str(func_ea), rec.mode, rec.rank,
               " FALLBACK" if candidate_index > 0 else ""))
        apply_function_type_safe(func_ea, meta, stats)
        return "renamed"

    if saw_unsafe:
        stats.unsafe += 1
        msg("UNRESOLVED_UNSAFE %-36s" % name)
        return "unsafe"
    if saw_ambiguous:
        stats.ambiguous += 1
        msg("UNRESOLVED_AMBIGUOUS %-33s" % name)
        return "ambiguous"
    stats.not_found += 1
    msg("NOT_FOUND %-44s" % name)
    return "not-found"


def try_apply_global_group(name, records, ranges, match_cache, stats, meta=None):
    """Resolve one global group by its REL data-anchor(s), rename, apply type."""
    existing_global = _global_name_ea(name)
    if existing_global != BADADDR:
        stats.glob_already_named += 1
        msg("GLOB_SKIP_NAME_EXISTS %-32s @ %s; applying type only"
            % (name, ea_str(existing_global)))
        apply_global_type_safe(existing_global, meta, stats)
        return "already-global"

    saw_not_found = saw_ambiguous = saw_unsafe = False

    for candidate_index, rec in enumerate(records):
        rstatus, target_ea, detail = _find_unique_target(rec, ranges, match_cache)
        if rstatus == "not-found":
            saw_not_found = True
            msg("GLOB_CAND_NOT_FOUND %-32s rank=%d" % (name, rec.rank))
            continue
        if rstatus == "ambiguous":
            saw_ambiguous = True
            msg("GLOB_CAND_AMBIGUOUS %-32s rank=%d hits=%s" % (name, rec.rank, detail))
            continue
        if rstatus != "ok":
            saw_unsafe = True
            msg("GLOB_CAND_UNSAFE %-35s rank=%d %s" % (name, rec.rank, detail))
            continue

        outcome = _rename_target(name, target_ea, rec, candidate_index, stats)

        if outcome == "already-same":
            stats.glob_already_same += 1
            msg("GLOB_ALREADY_SAME %-36s @ %s" % (name, ea_str(target_ea)))
            apply_global_type_safe(target_ea, meta, stats)
            return "already-same"
        if outcome == "skip-named":
            stats.glob_skipped_named += 1
            return "skip-named"
        if outcome == "name-conflict":
            stats.glob_name_conflicts += 1
            return "name-conflict"
        if outcome == "failure":
            stats.failures += 1
            return "failure"

        stats.glob_renamed += 1
        msg("GLOB_RENAMED %-41s @ %s rank=%d%s"
            % (name, ea_str(target_ea), rec.rank,
               " FALLBACK" if candidate_index > 0 else ""))
        apply_global_type_safe(target_ea, meta, stats)
        return "renamed"

    if saw_unsafe:
        stats.glob_unsafe += 1
        msg("GLOB_UNRESOLVED_UNSAFE %-31s" % name)
        return "unsafe"
    if saw_ambiguous:
        stats.glob_ambiguous += 1
        msg("GLOB_UNRESOLVED_AMBIGUOUS %-28s" % name)
        return "ambiguous"
    stats.glob_not_found += 1
    msg("GLOB_NOT_FOUND %-39s" % name)
    return "not-found"


# ---------------------------------------------------------------------------
# Import driver
# ---------------------------------------------------------------------------

def import_file(path):
    stats = Stats()

    try:
        loaded = cfsfile.load_records(path)
    except Exception as exc:
        ida_kernwin.warning("Could not read CFS/CFS2/CFS3/CFS4/CFS5 file:\n%s" % exc)
        return False

    stats.parse_errors = loaded.parse_errors
    func_groups = cfsfile.group_records(loaded.func_records)
    glob_groups = cfsfile.group_records(loaded.glob_records)
    stats.groups = len(func_groups)
    stats.glob_groups = len(glob_groups)

    if not func_groups and not glob_groups:
        ida_kernwin.warning("No valid CFS signature records found.")
        return False

    ranges = get_search_ranges()
    if not ranges:
        ida_kernwin.warning("No executable/code search ranges found.")
        return False

    msg("=" * 72)
    msg("CFS5 Importer %s" % VERSION)
    msg("File: %s" % path)
    msg(
        "Functions: %d  Function sigs: %d  Globals: %d  Global sigs: %d  "
        "Types: %d  Parse errors: %d"
        % (len(func_groups), len(loaded.func_records),
           len(glob_groups), len(loaded.glob_records),
           len(loaded.type_records), loaded.parse_errors)
    )
    msg("Search ranges: %s"
        % ", ".join("%s[%s-%s]" % (name, ea_str(a), ea_str(b)) for a, b, name in ranges))
    msg("=" * 72)

    # Register missing local types once, before any prototype/type application.
    ida_kernwin.show_wait_box("NODELAY\nRegistering missing CFS5 local types...")
    try:
        type_state = register_missing_types(loaded.type_records, stats)
    except Exception as exc:
        type_state = {"preexisting": set(), "registered": set(),
                      "failed": set(loaded.type_records)}
        stats.types_total = len(loaded.type_records)
        stats.types_failed = len(loaded.type_records)
        msg("TYPE_REGISTRATION_FATAL: %s" % exc)
    finally:
        ida_kernwin.hide_wait_box()

    msg("Types: %d kept-existing, %d registered, %d failed"
        % (len(type_state["preexisting"]), len(type_state["registered"]),
           len(type_state["failed"])))

    match_cache = {}
    total = len(func_groups) + len(glob_groups)

    ida_kernwin.clr_cancelled()
    ida_kernwin.show_wait_box(
        "NODELAY\nImporting CFS5 signatures + prototypes...\nPress Cancel to stop."
    )

    try:
        done = 0
        cancelled = False

        for (group_id, name), candidates in func_groups:
            if ida_kernwin.user_cancelled():
                cancelled = True
                break
            done += 1
            if done == 1 or done == total or done % PROGRESS_EVERY == 0:
                ida_kernwin.replace_wait_box(
                    "Functions...\n%d / %d\nRenamed: %d  Missing: %d  "
                    "Ambiguous: %d\nTypes applied: %d  Registered UDTs: %d\nCurrent: %s"
                    % (done, total, stats.renamed, stats.not_found, stats.ambiguous,
                       stats.func_types_applied, stats.types_registered, name)
                )
            meta = loaded.func_meta.get((group_id, name))
            try:
                try_apply_function_group(name, candidates, ranges, match_cache, stats, meta=meta)
            except Exception as exc:
                stats.failures += 1
                msg("FAIL_EXCEPTION %-39s error=%s" % (name, exc))
            stats.processed += 1

        if not cancelled:
            for (group_id, name), candidates in glob_groups:
                if ida_kernwin.user_cancelled():
                    cancelled = True
                    break
                done += 1
                if done == 1 or done == total or done % PROGRESS_EVERY == 0:
                    ida_kernwin.replace_wait_box(
                        "Globals...\n%d / %d\nRenamed: %d  Missing: %d  "
                        "Ambiguous: %d\nTypes applied: %d\nCurrent: %s"
                        % (done, total, stats.glob_renamed, stats.glob_not_found,
                           stats.glob_ambiguous, stats.glob_types_applied, name)
                    )
                meta = loaded.glob_meta.get((group_id, name))
                try:
                    try_apply_global_group(name, candidates, ranges, match_cache, stats, meta=meta)
                except Exception as exc:
                    stats.failures += 1
                    msg("GLOB_FAIL_EXCEPTION %-34s error=%s" % (name, exc))
                stats.glob_processed += 1

        if cancelled:
            stats.cancelled = True
            msg("CANCELLED after %d/%d items." % (done - 1, total))

    finally:
        ida_kernwin.hide_wait_box()
        ida_kernwin.clr_cancelled()

    msg("-" * 72)
    for line in stats.summary().splitlines():
        msg(line)
    msg("-" * 72)

    ida_kernwin.info(stats.summary())
    return stats.failures == 0


def choose_and_import():
    path = ida_kernwin.ask_file(False, "*.cfs", "Select CFS5 / CFS signature file to import")
    if not path:
        msg("Import cancelled.")
        return False
    path = os.path.abspath(path)
    msg("Selected: %s" % path)
    return import_file(path)


# ---------------------------------------------------------------------------
# IDA plugin / UI glue
# ---------------------------------------------------------------------------

class ImportHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        choose_and_import()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class CFS5ImporterPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Optimized CFS5 signature + type importer for IDA 9 (functions + globals)"
    help = (
        "Imports CFS5 signatures, transported local types, function prototypes "
        "and global types, plus CFS4/CFS3/CFS2 and legacy CFS. Destination "
        "names/types are protected."
    )
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        self.handler = ImportHandler()

        try:
            ida_kernwin.detach_action_from_menu("File/Load file/", ACTION_ID)
        except Exception:
            pass
        ida_kernwin.unregister_action(ACTION_ID)

        ok = ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_ID, ACTION_LABEL, self.handler, None,
                "Import CFS5 signatures/types (functions + globals) or legacy CFS", -1,
            )
        )

        if ok:
            if not ida_kernwin.attach_action_to_menu(
                "File/Load file/", ACTION_ID, ida_kernwin.SETMENU_APP
            ):
                msg("File menu attachment failed; plugin hotkey still works.")
        else:
            msg("WARNING: importer menu action registration failed.")

        msg("%s initialized on IDA %s. Hotkey: %s"
            % (VERSION, ida_kernwin.get_kernel_version(), PLUGIN_HOTKEY))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        choose_and_import()

    def term(self):
        try:
            ida_kernwin.detach_action_from_menu("File/Load file/", ACTION_ID)
        except Exception:
            pass
        ida_kernwin.unregister_action(ACTION_ID)


def PLUGIN_ENTRY():
    return CFS5ImporterPlugin()
