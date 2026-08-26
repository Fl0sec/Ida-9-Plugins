# CFS5 Exporter for IDA Pro 9.0 / IDAPython 9.0
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

import csv
import re

import idaapi
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import idautils

from cfs5 import VERSION
from cfs5 import cfsfile
from cfs5.common import (
    BADADDR, ea_str, get_search_ranges, msg, pack_bytes, pack_json, safe_name,
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


PLUGIN_NAME = "CFS5 Exporter (IDA 9)"
ACTION_SELECTED = "cfs5:export_selected"
ACTION_ALL_USER_NAMED = "cfs5:export_all_user_named"
SELECTED_HOTKEY = "Ctrl+Shift+E"
PROGRESS_EVERY = 10

# Globals named g_* are almost always deliberate even if the user-name flag is
# not set; whitelist that prefix in addition to the has_user_name gate.
_GLOBAL_PREFIX_RE = re.compile(r"^g_")

# A human's interactive rename is a plain C identifier. Compiler/tool-emitted
# names are not: MSVC RTTI/vftable/method symbols carry `?@` (e.g.
# `??_7CNetMessage@@6B@`), and demangled forms carry `:`/`<`/`(`/spaces.
_HUMAN_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# IDA auto-generated name stems that can slip past has_user_name (notably
# empty-stub `nullsub_240`, incl. `_74`/`_0` dedup suffixes and `j_`/`j_j_`
# thunk prefixes). A human never types these. Suffix must be hex-ish so real
# renames like `sub_process` or `Handler_beef` are not caught.
_AUTO_NAME_RE = re.compile(
    r"^(j_)*(sub|nullsub|unknown_libname|loc|locret|off|unk|byte|word|dword|"
    r"qword|tbyte|packreal|flt|dbl|xmmword|ymmword|stru|asc|algn|jpt|def)"
    r"(_[0-9A-Fa-f]+)+$"
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
    RTTI/vftables, FLIRT and even some auto stubs (`nullsub_N`) all set it. We
    additionally require the name to be a plain identifier, to not match an IDA
    auto-name stem, and to not demangle. The identifier test rejects MSVC
    mangled/demangled shapes on its own; the demangle test also rejects Itanium
    `_Z...` names, which are identifier-shaped but still compiler-emitted.
    """
    if not name or not _HUMAN_NAME_RE.match(name):
        return False
    if _AUTO_NAME_RE.match(name):
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


def _write_function(writer, state, func_ea, ranges):
    name = safe_name(ida_name.get_name(func_ea) or "")
    if not name:
        state.failures += 1
        return None

    try:
        candidates, xref_count, xrefs_tested = choose_function_candidates(func_ea, ranges)
    except Exception as exc:
        state.failures += 1
        msg("FAIL %-45s @ %s error=%s" % (name, ea_str(func_ea), exc))
        return None

    if not candidates:
        state.no_candidate += 1
        msg("NO_UNIQUE_CANDIDATE %-31s @ %s" % (name, ea_str(func_ea)))
        return None

    group_id = state.functions

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

    proto = prototype_raw if prototype_raw is not None else (None, None, None)
    writer.writerow(cfsfile.meta_row(
        group_id, name, quality,
        pack_bytes(proto[0]), pack_bytes(proto[1]), pack_bytes(proto[2]),
        pack_json(deps), is_global=False,
    ))
    if prototype_raw is not None:
        state.function_prototypes += 1
        if quality == "USER":
            state.user_prototypes += 1
        elif quality == "GUESSED":
            state.guessed_prototypes += 1

    for rank, c in enumerate(candidates):
        writer.writerow(cfsfile.signature_row(group_id, rank, name, c, is_global=False))
        state.function_candidates += 1
        state.mode_counts[c.mode] = state.mode_counts.get(c.mode, 0) + 1

    primary = candidates[0]
    xref_note = " xrefs=%d tested=%d" % (xref_count, xrefs_tested) if xref_count else ""
    type_note = " type=%s deps=%d" % (quality, len(deps)) if prototype_raw is not None else ""
    msg(
        "EXPORTED %-39s mode=%s bytes=%d exact=%d backup=%d%s%s"
        % (name, primary.mode, primary.byte_len, primary.exact,
           max(0, len(candidates) - 1), xref_note, type_note)
    )
    state.functions += 1
    return name


def _write_global(writer, state, global_ea, ranges):
    name = safe_name(ida_name.get_name(global_ea) or "")
    if not name:
        state.failures += 1
        return None

    try:
        candidates, xref_count, xrefs_tested = choose_global_candidates(global_ea, ranges)
    except Exception as exc:
        state.failures += 1
        msg("GLOB_FAIL %-40s @ %s error=%s" % (name, ea_str(global_ea), exc))
        return None

    if not candidates:
        state.no_candidate += 1
        msg("GLOB_NO_XREF_ANCHOR %-31s @ %s" % (name, ea_str(global_ea)))
        return None

    group_id = state.globals

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

    payload = type_raw if type_raw is not None else (None, None, None)
    writer.writerow(cfsfile.meta_row(
        group_id, name, quality,
        pack_bytes(payload[0]), pack_bytes(payload[1]), pack_bytes(payload[2]),
        pack_json(deps), is_global=True,
    ))
    if type_raw is not None:
        state.global_types += 1

    for rank, c in enumerate(candidates):
        writer.writerow(cfsfile.signature_row(group_id, rank, name, c, is_global=True))
        state.global_candidates += 1

    primary = candidates[0]
    xref_note = " xrefs=%d tested=%d" % (xref_count, xrefs_tested) if xref_count else ""
    type_note = " type=%s deps=%d" % (quality, len(deps)) if type_raw is not None else ""
    msg(
        "GLOB_EXPORTED %-34s bytes=%d exact=%d%s%s"
        % (name, primary.byte_len, primary.exact, xref_note, type_note)
    )
    state.globals += 1
    return name


def export_items(function_eas, title):
    function_eas = sorted(set(function_eas))
    global_eas = get_user_global_eas()

    if not function_eas and not global_eas:
        ida_kernwin.warning("No suitable functions or user-named globals found.")
        return False

    path = ida_kernwin.ask_file(True, "*.cfs", title)
    if not path:
        msg("Export cancelled.")
        return False
    if not path.lower().endswith(".cfs"):
        path += ".cfs"

    ranges = get_search_ranges()
    if not ranges:
        ida_kernwin.warning("No executable/code search ranges found.")
        return False

    state = _ExportState()
    try:
        state.local_type_index = build_local_type_index()
    except Exception as exc:
        msg("TYPE_INDEX_WARN: %s" % exc)
        state.local_type_index = {}

    total = len(function_eas) + len(global_eas)

    ida_kernwin.clr_cancelled()
    ida_kernwin.show_wait_box(
        "NODELAY\nBuilding optimized CFS5 signatures + binary types...\n"
        "Press Cancel to stop."
    )

    try:
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, lineterminator="\n")
            f.write("# CFS5 %s\n" % VERSION)
            f.write("# CFS2 / CFS2G signature rows retained for backwards compatibility.\n")
            f.write("# CFS4FUNC / CFS5GLOB,group_id,name,quality,type,fields,fldcmts,deps\n")
            f.write("# CFS4TYPE,name,kind,type,fields,fldcmts (full materialized bodies)\n")
            f.write("# binary payloads are zlib+base64; deps payload is compressed JSON\n")

            done = 0
            cancelled = False
            for func_ea in function_eas:
                if ida_kernwin.user_cancelled():
                    cancelled = True
                    break
                done += 1
                if done == 1 or done == total or done % PROGRESS_EVERY == 0:
                    ida_kernwin.replace_wait_box(
                        "Functions + globals -> CFS5...\n%d / %d\n"
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
                            "Functions + globals -> CFS5...\n%d / %d\n"
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
                type_blob, fields_blob, cmts_blob = info["raw"]
                writer.writerow(cfsfile.type_row(
                    info["name"], info["kind"],
                    pack_bytes(type_blob), pack_bytes(fields_blob), pack_bytes(cmts_blob),
                ))

    except OSError as exc:
        ida_kernwin.warning("Unable to write CFS5 file:\n%s" % exc)
        return False
    finally:
        ida_kernwin.hide_wait_box()
        ida_kernwin.clr_cancelled()

    summary = (
        "CFS5 export complete\n\n"
        "Functions exported: %d\n"
        "Function candidate rows: %d\n"
        "Function prototypes: %d\n"
        "  User prototypes: %d\n"
        "  Guessed prototypes: %d\n"
        "Globals exported: %d\n"
        "Global candidate rows: %d\n"
        "Global types: %d\n"
        "Local type definitions: %d\n"
        "ENTRY / BODY / REL candidates: %d / %d / %d\n"
        "No unique candidate / no anchor: %d\n"
        "Failures: %d\n\n"
        "%s"
        % (
            state.functions, state.function_candidates, state.function_prototypes,
            state.user_prototypes, state.guessed_prototypes,
            state.globals, state.global_candidates, state.global_types,
            len(state.exported_types),
            state.mode_counts.get("ENTRY", 0), state.mode_counts.get("BODY", 0),
            state.mode_counts.get("REL", 0),
            state.no_candidate, state.failures, path,
        )
    )
    msg(summary.replace("\n", " | "))
    ida_kernwin.info(summary)
    return (state.functions + state.globals) > 0


# ---------------------------------------------------------------------------
# IDA plugin / UI glue
# ---------------------------------------------------------------------------

class ExportSelectedHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        export_items(
            get_selected_function_eas(ctx),
            "Export selected functions (+ user globals) to CFS5",
        )
        return 1

    def update(self, ctx):
        if getattr(ctx, "widget_type", None) == ida_kernwin.BWN_FUNCS:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class ExportAllHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        eas = get_all_user_named_function_eas()
        globals_found = len(get_user_global_eas())
        if not eas and not globals_found:
            ida_kernwin.warning("No user-named functions or globals found.")
            return 1

        if ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            "Export %d user-named functions and %d user-named globals to CFS5?"
            % (len(eas), globals_found),
        ) != ida_kernwin.ASKBTN_YES:
            return 1

        export_items(eas, "Export ALL user-named functions + globals to CFS5")
        return 1

    def update(self, ctx):
        if getattr(ctx, "widget_type", None) == ida_kernwin.BWN_FUNCS:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class Hooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_FUNCS:
            return
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_SELECTED, "CFS5/")
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_ALL_USER_NAMED, "CFS5/")


class CFS5ExporterPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Optimized CFS5 signature + type exporter for IDA 9 (functions + globals)"
    help = (
        "Functions window -> right click -> CFS5. Exports short unique "
        "ENTRY/BODY/REL function signatures, REL-anchored global signatures, "
        "and function/global/local types."
    )
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        self.h1 = ExportSelectedHandler()
        self.h2 = ExportAllHandler()
        self.hooks = Hooks()

        ida_kernwin.unregister_action(ACTION_SELECTED)
        ida_kernwin.unregister_action(ACTION_ALL_USER_NAMED)

        ok1 = ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_SELECTED,
                "Export selected functions (+ globals) to CFS5",
                self.h1, SELECTED_HOTKEY,
                "Export selected functions and all user globals to CFS5", -1,
            )
        )
        ok2 = ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_ALL_USER_NAMED,
                "Export ALL user-named functions + globals to CFS5",
                self.h2, None,
                "Export all user-named functions and globals to CFS5", -1,
            )
        )

        if not ok1 or not ok2:
            msg("Action registration failed.")
            return idaapi.PLUGIN_SKIP

        self.hooks.hook()
        msg("%s initialized." % VERSION)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.info(
            "Open View -> Open subviews -> Functions,\nthen right-click -> CFS5."
        )

    def term(self):
        try:
            self.hooks.unhook()
        except Exception:
            pass
        ida_kernwin.unregister_action(ACTION_SELECTED)
        ida_kernwin.unregister_action(ACTION_ALL_USER_NAMED)


def PLUGIN_ENTRY():
    return CFS5ExporterPlugin()
