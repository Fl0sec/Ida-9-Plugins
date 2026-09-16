# CFS6 Exporter for IDA Pro 9.0 / IDAPython 9.0
#
# Fast name/type-transfer signatures for large binaries. Exports user-named
# functions AND user-named global variables to a portable .cfs file:
#   * short unique ENTRY / BODY / REL byte signatures per function,
#   * caller-side REL signatures per global (resolved via signed PC-relative
#     displacement), and
#   * function/global prototypes plus their dependent named Local Types,
#     transported as serialized binary tinfo_t.
#
# All shared machinery lives in the importable `cfs5` package; this file is
# only discovery, orchestration and the IDA plugin/UI glue.
#
# Target: IDA Professional 9.0 / Python 3.12.

import os
import sys

# Make the sibling `cfs5` package importable regardless of IDA's sys.path, and
# force a fresh import on every (re)load so edits to the package take effect.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
for _modname in [n for n in list(sys.modules) if n == "cfs5" or n.startswith("cfs5.")]:
    del sys.modules[_modname]

import re

import idaapi
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import idautils

from cfs5 import VERSION
from cfs5 import cfs6
from cfs5.common import BADADDR, ea_str, get_search_ranges, msg, safe_name
from cfs5.image import (
    BodyOwnership, describe_image, detect_build, get_imagebase, open_image_view,
)
from cfs5.sigs import choose_function_candidates, choose_global_candidates
from cfs5.typeio import (
    build_local_type_index,
    export_type_payload,
    function_type_quality,
    get_function_export_tinfo,
    get_global_export_tinfo,
    global_type_quality,
)


PLUGIN_NAME = "CFS6 Exporter (IDA 9)"
# Functions window actions.
ACTION_SEL_FUNCS = "cfs5:export_sel_funcs"
ACTION_ALL_FUNCS = "cfs5:export_all_funcs"
ACTION_ALL_BOTH = "cfs5:export_all_both"
# Names window actions.
ACTION_SEL_GLOBALS = "cfs5:export_sel_globals"
ACTION_ALL_GLOBALS = "cfs5:export_all_globals"
SELECTED_HOTKEY = "Ctrl+Shift+E"
PROGRESS_EVERY = 10

# Globals named g_* are almost always deliberate even if the user-name flag is
# not set; whitelist that prefix in addition to the has_user_name gate.
_GLOBAL_PREFIX_RE = re.compile(r"^g_")

# A human's interactive rename is a plain C identifier. Compiler/tool-emitted
# names are not: MSVC RTTI/vftable/method symbols carry `?@` (e.g.
# `??_7CNetMessage@@6B@`), and demangled forms carry `:`/`<`/`(`/spaces.
_HUMAN_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Exclusion regex (matches names to KEEP): reject the sub_/j_/_ prefixes and the
# nullsub / std:: / unknown_libname / Concurrency substrings that IDA, PDB and
# FLIRT emit, plus any raw MSVC mangling metacharacter `?` `@` `$` (e.g.
# `?ToString@Value@v8@@...` or template `?$Local@...`). The plain-identifier
# gate below already rejects those metacharacters, so this clause is
# defense-in-depth that also makes the regex correct if used standalone.
_KEEP_RE = re.compile(
    r"^(?!sub_|j_|_)(?!.*nullsub)(?!.*std::)(?!.*unknown_libname)"
    r"(?!.*Concurrency)(?!.*[?@$]).*"
)


def _is_mangled(name):
    """True if `name` is a mangled compiler symbol (MSVC or Itanium)."""
    try:
        return ida_name.demangle_name(name, ida_name.MNG_NODEFINIT) is not None
    except Exception:
        return False


def _is_human_named(name):
    """Distinguish a human rename from a tool/loader/auto-generated symbol.

    `ida_bytes.has_user_name` (FF_NAME) is far too broad: PDB, ClassInformer
    RTTI/vftables, FLIRT and even some auto stubs (`nullsub_N`) all set it. A
    name is kept only if it is a plain C identifier (rejects MSVC `??_7...@@`
    mangled/`::`-demangled shapes), passes the exclusion regex (rejects sub_/j_/_
    prefixes and nullsub/std/unknown_libname/Concurrency), and does not demangle
    (a backstop for identifier-shaped Itanium `_Z...` names).
    """
    if not name or not _HUMAN_NAME_RE.match(name):
        return False
    if not _KEEP_RE.match(name):
        return False
    if _is_mangled(name):
        return False
    return True


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _selected_indices(ctx):
    sel = getattr(ctx, "chooser_selection", None)
    if sel is None:
        return []
    try:
        return [int(x) for x in sel]
    except Exception:
        pass
    try:
        return [int(sel.at(i)) for i in range(sel.size())]
    except Exception:
        return []


def _get_function_start(ea):
    if ea == BADADDR:
        return BADADDR
    f = ida_funcs.get_func(ea)
    return BADADDR if f is None else f.start_ea


def get_selected_function_eas(ctx):
    if ctx is None or getattr(ctx, "widget_type", None) != ida_kernwin.BWN_FUNCS:
        return []

    eas = []
    chooser = getattr(ctx, "chooser", None)
    if chooser is not None:
        for row in _selected_indices(ctx):
            try:
                start = _get_function_start(chooser.get_ea(row))
            except Exception as exc:
                msg("Could not read chooser row %d: %s" % (row, exc))
                continue
            if start != BADADDR:
                eas.append(start)

    if not eas:
        start = _get_function_start(getattr(ctx, "cur_ea", BADADDR))
        if start != BADADDR:
            eas.append(start)

    return sorted(set(eas))


def get_all_user_named_function_eas():
    """Human-renamed function starts: user name, plain identifier, not a FLIRT
    library match, not a compiler/RTTI symbol."""
    result = []
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if f is None or f.start_ea != ea:
            continue
        # FLIRT library match or a thunk (j_*): not a genuine rename, and a
        # thunk's lone jmp makes a poor signature anyway.
        if f.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
            continue
        flags = ida_bytes.get_full_flags(ea)
        if not ida_bytes.has_user_name(flags):
            continue
        if _is_human_named(ida_name.get_name(ea)):
            result.append(ea)
    return result


def get_user_global_eas():
    """Human-named (or g_*) data globals: not code, not a function, not a tail,
    and a plain identifier rather than a compiler/RTTI/vftable symbol."""
    result = []
    for ea, name in idautils.Names():
        if not name:
            continue
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_code(flags) or ida_bytes.is_tail(flags):
            continue
        if ida_funcs.get_func(ea) is not None:
            continue
        if not (ida_bytes.has_user_name(flags) or _GLOBAL_PREFIX_RE.match(name)):
            continue
        if not _is_human_named(name):
            continue
        result.append(ea)
    return sorted(set(result))


def _chooser_ea(ctx, row):
    """Map a chooser row to an address. Prefers the chooser's own mapping (so
    UI sorting is honored); falls back to the name list that backs the Names
    window."""
    ch = getattr(ctx, "chooser", None)
    if ch is not None:
        try:
            ea = ch.get_ea(row)
            if ea is not None and ea != BADADDR:
                return ea
        except Exception:
            pass
    try:
        if 0 <= row < ida_name.get_nlist_size():
            return ida_name.get_nlist_ea(row)
    except Exception:
        pass
    return BADADDR


def get_selected_global_eas(ctx):
    """Globals selected in the Names window. The user picked these explicitly,
    so the human-name heuristic is NOT applied; we only drop code/functions/
    tails so a stray selected function isn't mistaken for a global."""
    if ctx is None or getattr(ctx, "widget_type", None) != ida_kernwin.BWN_NAMES:
        return []

    eas = []
    for row in _selected_indices(ctx):
        ea = _chooser_ea(ctx, row)
        if ea != BADADDR:
            eas.append(ea)

    if not eas:
        cur = getattr(ctx, "cur_ea", BADADDR)
        if cur != BADADDR:
            eas.append(cur)

    out = []
    for ea in eas:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_code(flags) or ida_bytes.is_tail(flags):
            continue
        if ida_funcs.get_func(ea) is not None:
            continue
        out.append(ea)
    return sorted(set(out))


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

class _ExportState:
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
        self.no_candidate = 0
        self.failures = 0
        self.user_prototypes = 0
        self.guessed_prototypes = 0
        self.mode_counts = {"ENTRY": 0, "BODY": 0, "REL": 0}
        # How many items got 1, 2, 3, 4 candidates -- the diversity metric.
        self.candidate_counts = {}
        # BODY candidates a .pdata-based consumer cannot resolve.
        self.ida_only_bodies = 0
        self.ownership = None


def _write_function(writer, state, func_ea, ranges):
    name = safe_name(ida_name.get_name(func_ea) or "")
    if not name:
        state.failures += 1
        return None

    try:
        candidates, coverage, xref_count, xrefs_tested = choose_function_candidates(
            func_ea, ranges, ownership=state.ownership
        )
    except Exception as exc:
        state.failures += 1
        msg("FAIL %-45s @ %s error=%s" % (name, ea_str(func_ea), exc))
        return None

    if not candidates:
        state.no_candidate += 1
        msg("NO_UNIQUE_CANDIDATE %-31s @ %s" % (name, ea_str(func_ea)))
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
                tif, state.local_type_index, state.closure_cache, state.exported_types
            )
            quality = function_type_quality(func_ea, explicit)
            if prototype_raw is None:
                quality = "NONE"
    except Exception as exc:
        quality, prototype_raw, deps = "NONE", None, []
        msg("TYPE_EXPORT_FAIL %-36s @ %s error=%s" % (name, ea_str(func_ea), exc))

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
    xref_note = " xrefs=%d tested=%d" % (xref_count, xrefs_tested) if xref_count else ""
    type_note = " type=%s deps=%d" % (quality, len(deps)) if prototype_raw is not None else ""
    msg(
        "EXPORTED %-39s n=%d modes=%s bytes=%d exact=%d%s%s"
        % (name, len(candidates), "/".join(c.mode for c in candidates),
           primary.byte_len, primary.exact, xref_note, type_note)
    )
    state.functions += 1
    return name


def _write_global(writer, state, global_ea, ranges):
    name = safe_name(ida_name.get_name(global_ea) or "")
    if not name:
        state.failures += 1
        return None

    try:
        candidates, coverage, xref_count, xrefs_tested = choose_global_candidates(
            global_ea, ranges
        )
    except Exception as exc:
        state.failures += 1
        msg("GLOB_FAIL %-40s @ %s error=%s" % (name, ea_str(global_ea), exc))
        return None

    if not candidates:
        state.no_candidate += 1
        msg("GLOB_NO_XREF_ANCHOR %-31s @ %s" % (name, ea_str(global_ea)))
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
                tif, state.local_type_index, state.closure_cache, state.exported_types
            )
            quality = global_type_quality(global_ea, explicit)
            if type_raw is None:
                quality = "NONE"
    except Exception as exc:
        quality, type_raw, deps = "NONE", None, []
        msg("GLOB_TYPE_FAIL %-35s @ %s error=%s" % (name, ea_str(global_ea), exc))

    if type_raw is not None:
        writer.write_item_type(
            item_id, name, quality, type_raw, deps, is_global=True
        )
        state.global_types += 1

    primary = candidates[0]
    xref_note = " xrefs=%d tested=%d" % (xref_count, xrefs_tested) if xref_count else ""
    type_note = " type=%s deps=%d" % (quality, len(deps)) if type_raw is not None else ""
    msg(
        "GLOB_EXPORTED %-34s n=%d bytes=%d exact=%d%s%s"
        % (name, len(candidates), primary.byte_len, primary.exact,
           xref_note, type_note)
    )
    state.globals += 1
    return name


# Remembered for the rest of the session so a multi-part export of one IDB
# cannot end up with disagreeing build numbers across its files.
_CONFIRMED_BUILD = {"number": None, "source": None}


def _ask_build_number():
    """(number_or_None, source) -- detected from the path, confirmed by the user.

    A build number is never invented: an unparseable or empty answer is stored
    as null with source "unknown".
    """
    if _CONFIRMED_BUILD["source"] is not None:
        return _CONFIRMED_BUILD["number"], _CONFIRMED_BUILD["source"]

    detected, detected_source = detect_build()
    default = "" if detected is None else str(detected)
    answer = ida_kernwin.ask_str(
        default, 0,
        "Build number for this image (blank = unknown):"
    )

    if answer is None:
        # Cancelled prompt: fall back to whatever the path said, if anything.
        number, source = detected, detected_source
    else:
        answer = answer.strip()
        if not answer:
            number, source = None, "unknown"
        elif answer.isdigit():
            number = int(answer)
            source = (
                "path-confirmed"
                if detected is not None and number == detected else "user"
            )
        else:
            msg("BUILD_IGNORED: %r is not a number; recording build as unknown"
                % answer)
            number, source = None, "unknown"

    _CONFIRMED_BUILD["number"] = number
    _CONFIRMED_BUILD["source"] = source
    return number, source


def export_items(function_eas, global_eas, title):
    function_eas = sorted(set(function_eas or []))
    global_eas = sorted(set(global_eas or []))

    if not function_eas and not global_eas:
        ida_kernwin.warning("Nothing to export (no functions and no globals).")
        return False

    path = ida_kernwin.ask_file(True, "*.cfs", title)
    if not path:
        msg("Export cancelled.")
        return False
    if not path.lower().endswith(".cfs"):
        path += ".cfs"

    # Open the PE view once: the header identity and the .pdata ownership
    # index both come from it, so they can never describe different images.
    imagebase = get_imagebase()
    view, view_source = open_image_view()
    image, image_notes = describe_image(view, view_source)
    for note in image_notes:
        msg("IMAGE_NOTE: %s" % note)

    build_number, build_source = _ask_build_number()
    msg(
        "SOURCE image=%s arch=%s size=%s build=%s (%s) imagebase=%s headers=%s"
        % (image.get("name"), image.get("architecture"),
           image.get("size_of_image"),
           "unknown" if build_number is None else build_number,
           build_source, ea_str(imagebase), view_source)
    )

    ranges = get_search_ranges()
    if not ranges:
        ida_kernwin.warning("No executable/code search ranges found.")
        return False

    state = _ExportState()
    state.ownership = BodyOwnership.for_current_idb(view, imagebase)
    if state.ownership.available:
        msg("PDATA: %d runtime functions (source=%s)"
            % (state.ownership.index.count, state.ownership.source))
    try:
        state.local_type_index = build_local_type_index()
    except Exception as exc:
        msg("TYPE_INDEX_WARN: %s" % exc)
        state.local_type_index = {}

    total = len(function_eas) + len(global_eas)

    ida_kernwin.clr_cancelled()
    ida_kernwin.show_wait_box(
        "NODELAY\nBuilding optimized CFS6 signatures + binary types...\n"
        "Press Cancel to stop."
    )

    try:
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = cfs6.Cfs6Writer(f, imagebase=imagebase)
            writer.write_header(image, build_number, build_source)

            done = 0
            cancelled = False
            for func_ea in function_eas:
                if ida_kernwin.user_cancelled():
                    cancelled = True
                    break
                done += 1
                if done == 1 or done == total or done % PROGRESS_EVERY == 0:
                    ida_kernwin.replace_wait_box(
                        "Building CFS6 signatures + types...\n%d / %d\n"
                        "Functions: %d  Globals: %d  Types: %d  No anchor: %d"
                        % (done, total, state.functions, state.globals,
                           len(state.exported_types), state.no_candidate)
                    )
                _write_function(writer, state, func_ea, ranges)

            if not cancelled:
                for global_ea in global_eas:
                    if ida_kernwin.user_cancelled():
                        cancelled = True
                        break
                    done += 1
                    if done == 1 or done == total or done % PROGRESS_EVERY == 0:
                        ida_kernwin.replace_wait_box(
                            "Building CFS6 signatures + types...\n%d / %d\n"
                            "Functions: %d  Globals: %d  Types: %d  No anchor: %d"
                            % (done, total, state.functions, state.globals,
                               len(state.exported_types), state.no_candidate)
                        )
                    _write_global(writer, state, global_ea, ranges)

            if cancelled:
                msg("Export cancelled after %d/%d items." % (done - 1, total))

            # Emit each referenced local type exactly once (shared dedup across
            # functions and globals). Order is irrelevant: the importer performs
            # safe multi-pass registration.
            for type_name in sorted(state.exported_types):
                info = state.exported_types[type_name]
                writer.write_local_type(info["name"], info["kind"], info["raw"])

    except OSError as exc:
        ida_kernwin.warning("Unable to write CFS6 file:\n%s" % exc)
        return False
    finally:
        ida_kernwin.hide_wait_box()
        ida_kernwin.clr_cancelled()

    spread = " ".join(
        "%dx%d" % (count, n)
        for n, count in sorted(state.candidate_counts.items())
    ) or "none"

    summary = (
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
        "Local type definitions: %d\n"
        "ENTRY / BODY / REL candidates: %d / %d / %d\n"
        "  BODY not resolvable from .pdata (IDA-only): %d\n"
        "No unique candidate / no anchor: %d\n"
        "Failures: %d\n"
        "Build: %s (%s)\n\n"
        "%s"
        % (
            state.functions, state.function_candidates, spread,
            state.function_prototypes,
            state.user_prototypes, state.guessed_prototypes,
            state.globals, state.global_candidates, state.global_types,
            len(state.exported_types),
            state.mode_counts.get("ENTRY", 0), state.mode_counts.get("BODY", 0),
            state.mode_counts.get("REL", 0), state.ida_only_bodies,
            state.no_candidate, state.failures,
            "unknown" if build_number is None else build_number, build_source,
            path,
        )
    )
    msg(summary.replace("\n", " | "))
    ida_kernwin.info(summary)
    return (state.functions + state.globals) > 0


# ---------------------------------------------------------------------------
# IDA plugin / UI glue
# ---------------------------------------------------------------------------

def _enable_for(ctx, widget_type):
    if getattr(ctx, "widget_type", None) == widget_type:
        return ida_kernwin.AST_ENABLE_FOR_WIDGET
    return ida_kernwin.AST_DISABLE_FOR_WIDGET


# --- Functions window ---

class ExportSelFuncsHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        eas = get_selected_function_eas(ctx)
        if not eas:
            ida_kernwin.warning("No functions selected.")
            return 1
        export_items(eas, [], "Export selected functions to CFS6")
        return 1

    def update(self, ctx):
        return _enable_for(ctx, ida_kernwin.BWN_FUNCS)


class ExportAllFuncsHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        eas = get_all_user_named_function_eas()
        if not eas:
            ida_kernwin.warning("No user-named functions found.")
            return 1
        if ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            "Export %d user-named functions (no globals) to CFS6?" % len(eas),
        ) != ida_kernwin.ASKBTN_YES:
            return 1
        export_items(eas, [], "Export ALL user-named functions to CFS6")
        return 1

    def update(self, ctx):
        return _enable_for(ctx, ida_kernwin.BWN_FUNCS)


class ExportAllBothHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        funcs = get_all_user_named_function_eas()
        globs = get_user_global_eas()
        if not funcs and not globs:
            ida_kernwin.warning("No user-named functions or globals found.")
            return 1
        if ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            "Export %d user-named functions and %d user-named globals to CFS6?"
            % (len(funcs), len(globs)),
        ) != ida_kernwin.ASKBTN_YES:
            return 1
        export_items(funcs, globs, "Export ALL user functions + globals to CFS6")
        return 1

    def update(self, ctx):
        return _enable_for(ctx, ida_kernwin.BWN_FUNCS)


# --- Names window ---

class ExportSelGlobalsHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        eas = get_selected_global_eas(ctx)
        if not eas:
            ida_kernwin.warning("No data globals selected in the Names window.")
            return 1
        export_items([], eas, "Export selected globals to CFS6")
        return 1

    def update(self, ctx):
        return _enable_for(ctx, ida_kernwin.BWN_NAMES)


class ExportAllGlobalsHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        globs = get_user_global_eas()
        if not globs:
            ida_kernwin.warning("No user-named globals found.")
            return 1
        if ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            "Export %d user-named globals (no functions) to CFS6?" % len(globs),
        ) != ida_kernwin.ASKBTN_YES:
            return 1
        export_items([], globs, "Export ALL user-named globals to CFS6")
        return 1

    def update(self, ctx):
        return _enable_for(ctx, ida_kernwin.BWN_NAMES)


class Hooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        wt = ida_kernwin.get_widget_type(widget)
        if wt == ida_kernwin.BWN_FUNCS:
            for aid in (ACTION_SEL_FUNCS, ACTION_ALL_FUNCS, ACTION_ALL_BOTH):
                ida_kernwin.attach_action_to_popup(widget, popup_handle, aid, "CFS6/")
        elif wt == ida_kernwin.BWN_NAMES:
            for aid in (ACTION_SEL_GLOBALS, ACTION_ALL_GLOBALS):
                ida_kernwin.attach_action_to_popup(widget, popup_handle, aid, "CFS6/")


# (action_id, label, handler_factory, hotkey, tooltip)
_ACTIONS = [
    (ACTION_SEL_FUNCS, "Export selected functions to CFS6",
     ExportSelFuncsHandler, SELECTED_HOTKEY,
     "Export the functions selected in the Functions window"),
    (ACTION_ALL_FUNCS, "Export ALL user-named functions to CFS6",
     ExportAllFuncsHandler, None,
     "Export every user-named function (no globals)"),
    (ACTION_ALL_BOTH, "Export ALL user functions + globals to CFS6",
     ExportAllBothHandler, None,
     "Export every user-named function and global"),
    (ACTION_SEL_GLOBALS, "Export selected globals to CFS6",
     ExportSelGlobalsHandler, None,
     "Export the globals selected in the Names window"),
    (ACTION_ALL_GLOBALS, "Export ALL user-named globals to CFS6",
     ExportAllGlobalsHandler, None,
     "Export every user-named global (no functions)"),
]


class CFS5ExporterPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "CFS6 signature + type exporter for IDA 9 (functions + globals)"
    help = (
        "Functions window -> right click -> CFS6 (functions). "
        "Names window -> right click -> CFS6 (globals). Exports short unique "
        "ENTRY/BODY/REL function signatures, REL-anchored global signatures, "
        "and function/global/local types."
    )
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        self.handlers = []
        self.hooks = Hooks()

        for action_id, label, factory, hotkey, tip in _ACTIONS:
            ida_kernwin.unregister_action(action_id)
            handler = factory()
            self.handlers.append(handler)
            if not ida_kernwin.register_action(
                ida_kernwin.action_desc_t(action_id, label, handler, hotkey, tip, -1)
            ):
                msg("Action registration failed: %s" % action_id)
                return idaapi.PLUGIN_SKIP

        self.hooks.hook()
        msg("%s initialized." % VERSION)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.info(
            "Functions window -> right-click -> CFS6 (functions).\n"
            "Names window -> right-click -> CFS6 (globals)."
        )

    def term(self):
        try:
            self.hooks.unhook()
        except Exception:
            pass
        for action_id, _label, _factory, _hotkey, _tip in _ACTIONS:
            ida_kernwin.unregister_action(action_id)


def PLUGIN_ENTRY():
    return CFS5ExporterPlugin()
