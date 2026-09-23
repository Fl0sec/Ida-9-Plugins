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
import ida_nalt
import ida_segment
import ida_typeinf
import idautils

from cfs5 import VERSION
from cfs5 import cfs6
from cfs5 import declare
from cfs5 import export
from cfs5 import members
from cfs5 import store
from cfs5.common import BADADDR, ea_str, get_search_ranges, msg
from cfs5.image import describe_image, detect_build, open_image_view
from cfs5.sigs import choose_member_candidates


PLUGIN_NAME = "CFS6 Exporter (IDA 9)"
# Functions window actions.
ACTION_SEL_FUNCS = "cfs5:export_sel_funcs"
ACTION_ALL_FUNCS = "cfs5:export_all_funcs"
ACTION_ALL_BOTH = "cfs5:export_all_both"
# Names window actions.
ACTION_SEL_GLOBALS = "cfs5:export_sel_globals"
ACTION_ALL_GLOBALS = "cfs5:export_all_globals"
# Disassembly actions: declared members (derived_value items).
ACTION_DECLARE_MEMBER = "cfs5:declare_member"
# The member chooser has no fixed widget type, so the popup hook recognizes it
# by title. Keep the prefix and the title construction together.
MEMBER_CHOOSER_PREFIX = "CFS6 members of "

ACTION_DECLARE_STRUCT = "cfs5:declare_struct"
ACTION_MANAGE_DECLS = "cfs5:manage_declarations"
ACTION_EXPORT_MEMBERS = "cfs5:export_members"
SELECTED_HOTKEY = "Ctrl+Shift+E"
DECLARE_HOTKEY = "Ctrl+Shift+M"
# Opens the dispatcher -- the one shortcut worth remembering.
DISPATCH_HOTKEY = "Ctrl+Shift+C"

# Globals named g_* are almost always deliberate even if the user-name flag is
# not set; whitelist that prefix in addition to the has_user_name gate. It is
# also what rescues the handful of genuine tier0 globals that arrive as imports.
_GLOBAL_PREFIX_RE = re.compile(r"^g_")

# A global worth a byte signature lives in a data segment. `.text` only ever
# yields IDA's own jump tables, and `.pdata`/`.reloc`/`.tls` only loader
# structures. `.idata` is allowed in so a g_* import can still be rescued.
_GLOBAL_SEGMENTS = frozenset((".data", ".rdata", ".bss", ".idata"))

# Analyzer- and loader-produced data names that are shaped like plain C
# identifiers, so the human-name heuristic alone cannot reject them: IDA's jump
# tables and jump-table defaults, its `funcs_<ea>` pointer arrays, and the PE
# directory labels the loader plants.
_AUTO_DATA_RE = re.compile(
    r"^(jpt_|def_|funcs_)|^(TlsDirectory|TlsIndex|ExceptionDir)$"
)

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


def _cell_texts(row):
    """The rendered cells of a chooser_row_info_t, as a list of str."""
    texts = getattr(row, "texts", None)
    if texts is None:
        return []
    try:
        return [str(t) for t in texts]
    except Exception:
        pass
    try:
        return [str(texts.at(i)) for i in range(texts.size())]
    except Exception:
        return []


def _cell_ea(text):
    """A chooser cell that spells an address -> that address, else BADADDR.

    Handles both the bare form and IDA's `.text:0000000180001000`.
    """
    token = str(text).strip().rsplit(":", 1)[-1].replace("`", "")
    if not token or len(token) < 4 or len(token) > 18:
        return BADADDR
    try:
        return int(token, 16)
    except ValueError:
        return BADADDR


def _row_function_ea(texts):
    """Map one rendered chooser row to a function start.

    The name column is tried first (exact and unambiguous), then any cell that
    parses as hex *and* lands on a function start -- which rejects the Length
    and flag columns without having to know the window's column layout.
    """
    for text in texts:
        try:
            ea = ida_name.get_name_ea(BADADDR, str(text).strip())
        except Exception:
            ea = BADADDR
        start = _get_function_start(ea)
        if start != BADADDR:
            return start
    for text in texts:
        start = _get_function_start(_cell_ea(text))
        if start != BADADDR:
            return start
    return BADADDR


def _selected_rows(title):
    """Rendered selected rows of the chooser captioned `title`.

    Reads the *widget* rather than the `chooser` object handed to the action
    context: a built-in window does not necessarily expose one, and when it
    does, its row indices are not necessarily the ones `get_ea` expects (the
    Functions window has folders). This path only depends on what is on
    screen, so it survives that.
    """
    try:
        rows = ida_kernwin.chooser_row_info_vec_t()
        if not ida_kernwin.get_chooser_rows(
            rows, title, ida_kernwin.GCRF_SELECTION
        ):
            return []
        return [_cell_texts(rows.at(i)) for i in range(rows.size())]
    except Exception as exc:
        msg("SELECTION: get_chooser_rows(%r) failed: %s" % (title, exc))
        return []


def get_selected_function_eas(ctx):
    """Function starts selected in the Functions window.

    Three independent sources, because none of them is reliable across IDA
    versions: the action context's chooser object, the rendered selection of
    the widget, and finally the current row. Which one answered is logged --
    "nothing selected" on a window with a visible selection is otherwise
    indistinguishable from "this IDA reports selections differently".
    """
    if ctx is None or getattr(ctx, "widget_type", None) != ida_kernwin.BWN_FUNCS:
        return []

    eas = []
    chooser = getattr(ctx, "chooser", None)
    rows = _selected_indices(ctx)
    if chooser is not None and rows:
        for row in rows:
            try:
                start = _get_function_start(chooser.get_ea(row))
            except Exception as exc:
                msg("Could not read chooser row %d: %s" % (row, exc))
                continue
            if start != BADADDR:
                eas.append(start)
        if eas:
            msg("SELECTION: %d function(s) from the action context chooser."
                % len(set(eas)))

    if not eas:
        texts = _selected_rows(getattr(ctx, "widget_title", "Functions"))
        for cells in texts:
            start = _row_function_ea(cells)
            if start != BADADDR:
                eas.append(start)
            else:
                msg("SELECTION: no function for row %r" % (cells[:3],))
        if eas:
            msg("SELECTION: %d function(s) from the rendered selection "
                "(context chooser gave %d row(s))." % (len(set(eas)), len(rows)))

    if not eas:
        func = getattr(ctx, "cur_func", None)
        start = _get_function_start(getattr(func, "start_ea", BADADDR)
                                    if func is not None else BADADDR)
        if start == BADADDR:
            start = _get_function_start(getattr(ctx, "cur_ea", BADADDR))
        if start != BADADDR:
            eas.append(start)
            msg("SELECTION: falling back to the current row (%s)."
                % ea_str(start))

    return sorted(set(eas))


def prompt_for_function_ea():
    """Ask for a function when the window's selection could not be read.

    A UI action must not dead-end by telling the user to do the thing they
    just did.
    """
    func = ida_kernwin.choose_func(
        "Select a function to export to CFS6", BADADDR
    )
    start = getattr(func, "start_ea", BADADDR) if func is not None else BADADDR
    return _get_function_start(start)


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


def _import_thunk_eas():
    """Every IAT slot address, across all imported modules.

    IDA sets the user-name flag on import thunks, so without this they dominate
    the "all globals" export -- measured at 438 of 560 kept names (78%) on cs2
    client.dll. A byte signature for an import is also strictly worse than the
    import table a consumer can already read by name.
    """
    eas = set()

    def collect(ea, name, ordinal):
        eas.add(ea)
        return True

    try:
        for index in range(ida_nalt.get_import_module_qty()):
            try:
                ida_nalt.enum_import_names(index, collect)
            except Exception as exc:
                msg("IMPORT_ENUM_FAILED module %d: %s" % (index, exc))
    except Exception as exc:
        msg("IMPORT_ENUM_FAILED: %s (imports will not be filtered)" % exc)
    return eas


def _segment_name(ea):
    try:
        seg = ida_segment.getseg(ea)
        if seg is None:
            return ""
        return ida_segment.get_segm_name(seg) or ""
    except Exception:
        return ""


def get_user_global_eas():
    """Human-named (or g_*) data globals worth a byte signature.

    The name-shape heuristic alone is not enough: `RegCloseKey` and
    `jpt_234F55` are both valid plain identifiers and both carry the user-name
    flag. So location and producer are gated too -- the address must sit in a
    data segment, must not be an import thunk (unless it is a g_* tier0 global),
    and must not carry an analyzer/loader-generated data name.
    """
    imports = _import_thunk_eas()

    result = []
    for ea, name in idautils.Names():
        if not name:
            continue
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_code(flags) or ida_bytes.is_tail(flags):
            continue
        if ida_funcs.get_func(ea) is not None:
            continue
        is_prefixed = bool(_GLOBAL_PREFIX_RE.match(name))
        if not (ida_bytes.has_user_name(flags) or is_prefixed):
            continue
        if not _is_human_named(name):
            continue
        if _AUTO_DATA_RE.match(name):
            continue
        if _segment_name(ea) not in _GLOBAL_SEGMENTS:
            continue
        # An import is resolvable by name from the import table; only a
        # deliberately g_*-named one (tier0's exported globals) earns a slot.
        if ea in imports and not is_prefixed:
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
        # Same fallback as the Functions window, for the same reason: the
        # action context does not always carry a usable chooser.
        for cells in _selected_rows(getattr(ctx, "widget_title", "Names")):
            ea = BADADDR
            for text in cells:
                try:
                    ea = ida_name.get_name_ea(BADADDR, str(text).strip())
                except Exception:
                    ea = BADADDR
                if ea != BADADDR:
                    break
                ea = _cell_ea(text)
                if ea != BADADDR and ida_bytes.is_mapped(ea):
                    break
                ea = BADADDR
            if ea != BADADDR:
                eas.append(ea)
        if eas:
            msg("SELECTION: %d name(s) from the rendered selection."
                % len(set(eas)))

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
# Declaring a member from a selected operand
# ---------------------------------------------------------------------------

def _resolve_or_create_member(ea, op_index):
    """The IDA member this operand refers to, creating it if the user agrees.

    A `member_offset` declaration is an assertion that a named field of a
    named type lives at some offset. Without a real IDA member behind it that
    assertion is unverified, `source.expected_value` has nothing to come from,
    and no struct-offset references can ever be found for it -- so this is a
    hard gate, not a warning. When the container is known but the field is
    not, creating the field is offered rather than refusing: that improves the
    database permanently and makes every *other* member of the same struct
    easier to declare next time.

    Returns a members.MemberRef, or None when the user backed out.
    """
    ref = members.member_from_operand(ea, op_index)
    if ref is not None:
        return ref

    insn = members.decode_at(ea)
    if insn is None:
        ida_kernwin.warning("Could not decode the instruction at %s."
                            % ea_str(ea))
        return None

    displacement, width = members.operand_displacement(insn, op_index)
    if displacement is None:
        ida_kernwin.warning(
            "Operand %d at %s is not a memory access, so it cannot name a "
            "structure member." % (op_index, ea_str(ea))
        )
        return None
    if displacement < 0:
        ida_kernwin.warning(
            "Operand %d at %s has a negative displacement (%d); declare it "
            "against the type the register really points at."
            % (op_index, ea_str(ea), displacement)
        )
        return None

    owner = ida_kernwin.ask_str(
        "", 0,
        "This operand is not marked as a struct offset.\n"
        "Container structure type for [reg+0x%X]:" % displacement
    )
    if not owner:
        return None
    owner = owner.strip()

    if members.get_struct_tinfo(owner) is None:
        ida_kernwin.warning(
            "%r is not a structure in this database. Create or import the "
            "type first, then declare the member." % owner
        )
        return None

    ref = members.member_at_offset(owner, displacement)
    if ref is None:
        spanning = members.enclosing_member_name(owner, displacement)
        if spanning is not None:
            ida_kernwin.warning(
                "%s+0x%X is inside the existing field %s, not the start of a "
                "field. Fix the layout first." % (owner, displacement, spanning)
            )
            return None
        if ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            "%s has no field at 0x%X.\nCreate one now?" % (owner, displacement),
        ) != ida_kernwin.ASKBTN_YES:
            return None
        field_name = ida_kernwin.ask_str(
            "field_%X" % displacement, 0,
            "Name for the new %s field at 0x%X (%d bytes):"
            % (owner, displacement, width or 8)
        )
        if not field_name:
            return None
        ref = members.create_member(
            owner, field_name.strip(), displacement, width or 8
        )
        if ref is None:
            ida_kernwin.warning(
                "Could not create %s.%s at 0x%X -- see the Output window."
                % (owner, field_name, displacement)
            )
            return None

    # Mark the operand so IDA indexes it as a reference to this member. That
    # is what lets the *next* export find this site (and others) through
    # member_reference_sites instead of relying on the stored selection alone.
    if not members.apply_stroff(ea, op_index, ref.owner):
        msg("DECLARE: could not mark operand %d at %s as a struct offset; "
            "the declaration still works but will not gain xref candidates"
            % (op_index, ea_str(ea)))

    return ref


def _report_candidate_preview(decl, ref):
    """Build the member's candidates now and tell the user what was found.

    Immediate feedback matters more here than for functions: coverage depends
    on how well the container is typed, so a declaration that can only ever
    produce one candidate should say so while the user is still looking at it.
    """
    ranges = get_search_ranges()
    if not ranges:
        return "no executable search ranges"

    try:
        candidates, _coverage, sites, _searched = choose_member_candidates(
            ref, ranges, selected_sites=decl.sites,
            value_adjust=decl.value_adjust,
            sibling_offsets=export.sibling_offsets(ref.owner),
            allow_scan=decl.scan_allowed,
        )
    except Exception as exc:
        msg("DECLARE: candidate preview failed: %s" % exc)
        return "candidate generation failed: %s" % exc

    if not candidates:
        return (
            "no unique signature yet (%d site(s) tried).\nThe declaration is "
            "stored; type more of the binary and re-export." % sites
        )
    origins = sorted(set(c.origin for c in candidates))
    return "%d candidate(s) from %d site(s): %s" % (
        len(candidates), sites, ", ".join(origins)
    )


def _store_member_declaration(ref, site_ea=None, site_op=None):
    """Persist a declaration for `ref`, asking the user nothing.

    The canonical name is the IDA field name. There is no prompt because there
    is nothing to decide: the database already holds the answer, and asking
    would only invite a typo that silently renames the exported item.

    "No site" must be `None`, not BADADDR/-1: `declare.normalize_sites` drops
    the sentinels, so a site is never stored as a real address, displayed as
    `BADADDR`, and then handed to candidate generation as a
    `selected_operand` -- a provenance claim that is simply false.

    A UI declaration keeps automatic discovery. The user clicked one operand;
    they did not thereby assert that it is the only evidence in the binary,
    and losing the scan would silently narrow every existing declaration. Only
    a caller that explicitly asks for `sites_only` gets it.
    """
    if site_ea in (None, BADADDR) or site_op is None or site_op < 0:
        sites = ()
    else:
        sites = [(site_ea, site_op)]
    try:
        decl = declare.make_member(
            ref.owner, ref.name, member=ref.name, sites=sites,
            discovery=declare.DISCOVER_SITES_PLUS_AUTO,
        )
    except declare.DeclarationError as exc:
        msg("DECLARE: %s.%s rejected: %s" % (ref.owner, ref.name, exc))
        return None
    if not store.save(decl):
        msg("DECLARE: %s.%s could not be stored" % (ref.owner, ref.name))
        return None
    return decl


def declare_member_at(ea, op_index):
    """Full declare-from-operand flow. Returns True when something was stored."""
    if ea == BADADDR:
        ida_kernwin.warning("Place the cursor on an instruction operand first.")
        return False

    ref = _resolve_or_create_member(ea, op_index)
    if ref is None:
        return False

    decl = _store_member_declaration(ref, site_ea=ea, site_op=op_index)
    if decl is None:
        ida_kernwin.warning(
            "The declaration could not be stored -- see the Output window."
        )
        return False

    ida_kernwin.info(
        "Declared %s\n\n"
        "IDA field: %s.%s\n"
        "Offset (expected_value): 0x%X (%d)\n"
        "Site: %s operand %d\n\n"
        "%s"
        % (decl.id, ref.owner, ref.name, ref.byte_offset, ref.byte_offset,
           ea_str(ea), op_index, _report_candidate_preview(decl, ref))
    )
    return True


class MemberChooser(ida_kernwin.Choose):
    """Pick which members of one structure to declare.

    Declaring is deliberately separated from *previewing candidates*. Storing a
    declaration is instant; discovering its sites decompiles functions. Doing
    both at once meant a 200-member structure paid for 200 discovery passes
    nobody asked for, so the scan is on demand (Ctrl+E) over the selected rows
    only.
    """

    def __init__(self, owner):
        # The title is the window's identity (and what the popup hook matches
        # on), so key hints live in the popup and the status column instead of
        # bloating it -- a long title just gets truncated in the tab.
        ida_kernwin.Choose.__init__(
            self,
            MEMBER_CHOOSER_PREFIX + owner,
            [[" ", 2], ["Member", 38], ["Offset", 8], ["Size", 5],
             ["Candidates", 34]],
            flags=(ida_kernwin.Choose.CH_MULTI
                   | ida_kernwin.Choose.CH_CAN_DEL),
        )
        self.owner = owner
        self.refs = members.iter_members(owner)
        # Previews are per session and per member; keeping them means the list
        # still shows what you learned after a refresh.
        self.previews = {}
        # Real named commands in the chooser popup. The built-in Edit action is
        # single-item by nature and has no reliable shortcut, so overloading it
        # for "preview" left the feature unreachable except via a toolbar
        # button.
        self.cmd_declare_only = self.AddCommand(
            "Declare without scanning", shortcut="Ctrl+D"
        )
        self.cmd_preview = self.AddCommand(
            "Preview candidates", shortcut="Ctrl+E"
        )

    def OnCommand(self, n, cmd_id):
        # IDA invokes this once per selected row, so each branch must be safe
        # to repeat; both of these are keyed by a single member.
        if not 0 <= n < len(self.refs):
            return 1
        ref = self.refs[n]
        if cmd_id == self.cmd_declare_only:
            _store_member_declaration(ref)
        elif cmd_id == self.cmd_preview:
            preview_member_candidates(self.owner, [ref], self.previews)
        self.Refresh()
        return 1

    # -- Choose plumbing ---------------------------------------------------

    def OnGetSize(self):
        return len(self.refs)

    def OnGetLine(self, n):
        ref = self.refs[n]
        declared = store.load(declare.member_id(self.owner, ref.name)) is not None
        return [
            "*" if declared else "",
            ref.name,
            "0x%X" % ref.byte_offset,
            "%d" % ref.byte_size,
            self.previews.get(ref.name, "" if declared else "not declared"),
        ]

    def OnRefresh(self, sel):
        self.refs = members.iter_members(self.owner)
        # adjust_last_item takes a single line number. Under CH_MULTI `sel`
        # arrives as a sizevec_t, and comparing that to an int raises, so it is
        # reduced to one line first.
        rows = self._rows(sel)
        return self._result(self.adjust_last_item(rows[0] if rows else 0))

    @staticmethod
    def _rows(sel):
        """`sel` as a plain list of ints.

        Under CH_MULTI IDA hands over a `sizevec_t`; single-select choosers
        pass a bare int. Both shapes reach every callback here.
        """
        if sel is None:
            return []
        if isinstance(sel, int):
            return [sel]
        try:
            return [int(x) for x in sel]
        except TypeError:
            return []

    @staticmethod
    def _result(rows):
        """A Choose callback result: `[change_flag, line, line, ...]`.

        The contract is a **flat** sequence of ints, not `(flag, selection)`.
        Returning the selection as a nested list makes SWIG fail to convert
        item #1, which is silent under single-select (where it happens to be an
        int) and fatal under CH_MULTI.
        """
        return [ida_kernwin.Choose.ALL_CHANGED] + list(rows)

    def _selected_refs(self, sel):
        return [self.refs[i] for i in self._rows(sel) if 0 <= i < len(self.refs)]

    # -- Actions -----------------------------------------------------------

    def OnSelectLine(self, sel):
        # Enter and double-click share this one callback -- IDA does not
        # distinguish them -- so it does the whole job: declare, then show what
        # each declaration can actually prove. Declaring without that is half an
        # action, and the cost stays bounded because only selected rows scan.
        refs = self._declare(sel)
        if refs:
            preview_member_candidates(self.owner, refs, self.previews)
        return self._result(self._rows(sel))

    def _declare(self, sel):
        refs = self._selected_refs(sel)
        stored = [r for r in refs if _store_member_declaration(r) is not None]
        msg("DECLARE: %s -- stored %d of %d selected member(s)"
            % (self.owner, len(stored), len(refs)))
        return stored

    def OnDeleteLine(self, sel):
        removed = 0
        for ref in self._selected_refs(sel):
            if store.delete(declare.member_id(self.owner, ref.name)):
                removed += 1
        msg("DECLARE: %s -- removed %d declaration(s)" % (self.owner, removed))
        # The row list is unchanged -- undeclaring clears a column, it does not
        # remove a member -- so the selection survives as-is.
        return self._result(self._rows(sel))



def preview_member_candidates(owner, refs, out):
    """Run discovery for `refs` and record a one-line verdict per member.

    This is the expensive half of the feature -- it builds the displacement
    index on first use and decompiles candidate functions -- so it is only ever
    invoked for members the user explicitly selected.
    """
    ranges = get_search_ranges()
    if not ranges:
        ida_kernwin.warning("No executable search ranges; cannot build "
                            "signatures.")
        return

    # Every member offset of the type, so the scan can rank functions by
    # co-occurrence rather than sampling a single common displacement.
    siblings = export.sibling_offsets(owner)

    ida_kernwin.show_wait_box("CFS6: scanning %s..." % owner)
    try:
        for i, ref in enumerate(refs):
            if ida_kernwin.user_cancelled():
                msg("DECLARE: preview cancelled after %d member(s)" % i)
                break
            ida_kernwin.replace_wait_box(
                "CFS6: %s (%d/%d) %s" % (owner, i + 1, len(refs), ref.name)
            )
            try:
                cands, _cov, sites, _searched = choose_member_candidates(
                    ref, ranges, sibling_offsets=siblings
                )
            except Exception as exc:
                msg("DECLARE: %s candidates failed: %s" % (ref.fullname, exc))
                out[ref.name] = "scan failed"
                continue
            if cands:
                out[ref.name] = "%d from %s" % (
                    len(cands), ",".join(sorted(set(c.origin for c in cands)))
                )
            else:
                out[ref.name] = "none (%d site(s) tried)" % sites
            msg("  %-40s +0x%-6X %s"
                % (ref.name, ref.byte_offset, out[ref.name]))
    finally:
        ida_kernwin.hide_wait_box()


def _type_name_from_ctx(ctx):
    """Name of the UDT the action context points at, or None.

    `action_ctx_base_t.type_ref` is the channel the Local Types view actually
    populates -- it carries the selected `tinfo_t` outright. Reading chooser
    columns instead was the bug: it depends on column order, on the view
    spelling the name without a `struct` keyword, and silently produced "select
    a structure first" when it failed. The column read survives only as a
    fallback, and now says so when it is the thing that failed.
    """
    try:
        ref = getattr(ctx, "type_ref", None)
        if ref is not None and ref.tif is not None and ref.tif.is_udt():
            name = str(ref.tif.get_type_name() or "").strip()
            if name:
                return name
    except Exception as exc:
        msg("DECLARE: ctx.type_ref unusable: %s" % exc)

    rows = list(getattr(ctx, "chooser_selection", None) or [])
    if not rows:
        msg("DECLARE: no type_ref and no chooser selection "
            "(widget_type=%s title=%r)"
            % (getattr(ctx, "widget_type", "?"),
               str(getattr(ctx, "widget_title", ""))))
        return None

    try:
        data = ida_kernwin.get_chooser_data(str(ctx.widget_title), int(rows[0]))
    except Exception as exc:
        msg("DECLARE: get_chooser_data(%r, %d) failed: %s"
            % (str(getattr(ctx, "widget_title", "")), int(rows[0]), exc))
        return None

    for cell in list(data or []):
        name = members.normalize_type_name(cell)
        if name and members.get_struct_tinfo(name) is not None:
            return name

    msg("DECLARE: no column of row %d resolved to a UDT; row was %r"
        % (int(rows[0]), list(data or [])))
    return None


def _pick_struct_name(ctx=None):
    """The structure to work on: from the context, else ask.

    The action must never dead-end. When the context yields nothing, IDA's own
    type chooser is one extra click, which beats a warning that tells the user
    to do the thing they already did.
    """
    if ctx is not None:
        name = _type_name_from_ctx(ctx)
        if name:
            return name
    try:
        tif = ida_typeinf.tinfo_t()
        if ida_kernwin.choose_struct(tif, "CFS6: choose a structure"):
            picked = str(tif.get_type_name() or "").strip()
            if picked:
                return picked
    except Exception as exc:
        msg("DECLARE: choose_struct failed: %s" % exc)
    return None


class DeclarationChooser(ida_kernwin.Choose):
    """Lists stored declarations; Del removes one, Enter jumps to its site."""

    def __init__(self):
        ida_kernwin.Choose.__init__(
            self, "CFS6 declarations",
            [["Owner", 22], ["Name", 22], ["IDA field", 22],
             ["Offset", 10], ["Site", 14]],
        )
        self.items = []

    def OnInit(self):
        self.items = store.load_all()
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        decl = self.items[n]
        ref = members.lookup_member(decl.owner, decl.member)
        # A missing member is the interesting case: it means the type changed
        # under a declaration and the next export will skip it.
        offset = "0x%X" % ref.byte_offset if ref is not None else "MISSING"
        # Show the count once there is more than one: a declaration whose
        # evidence was supplied by an agent routinely has several.
        if not decl.sites:
            site = "-"
        elif len(decl.sites) == 1:
            site = ea_str(decl.sites[0][0])
        else:
            site = "%s +%d" % (ea_str(decl.sites[0][0]), len(decl.sites) - 1)
        return [decl.owner, decl.name, decl.member, offset, site]

    @staticmethod
    def _row(sel):
        """Chooser callbacks pass an index or a selection sequence; accept both."""
        if isinstance(sel, int):
            return sel
        try:
            rows = [int(x) for x in (sel or [])]
        except TypeError:
            return -1
        return rows[0] if rows else -1

    def OnDeleteLine(self, sel):
        row = self._row(sel)
        if 0 <= row < len(self.items):
            store.delete(self.items[row].id)
            self.items = store.load_all()
        # Flat `[flag, line]`, never `(flag, selection)` -- see
        # MemberChooser._result for why the nested form fails to convert.
        return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(
            max(row, 0)
        )

    def OnSelectLine(self, sel):
        row = self._row(sel)
        if 0 <= row < len(self.items):
            decl = self.items[row]
            if decl.has_site:
                ida_kernwin.jumpto(decl.sites[0][0])
        return [ida_kernwin.Choose.NOTHING_CHANGED, max(row, 0)]


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

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


MERGE_APPEND = export.MERGE_APPEND
MERGE_OVERWRITE = export.MERGE_OVERWRITE


def _ask_yes_no(deflt, text):
    # ask_* take a printf format, so a literal message must escape its percents.
    return ida_kernwin.ask_yn(deflt, text.replace("%", "%%"))


def _ask_merge_mode(path, image, build_number):
    """Decide what to do about an existing destination file.

    Returns (mode, loaded) where mode is MERGE_APPEND / MERGE_OVERWRITE, or
    (None, None) when the user cancelled.
    """
    if not os.path.exists(path):
        return MERGE_OVERWRITE, None

    try:
        loaded = cfs6.load_cfs6(path, log=lambda t: msg("MERGE_READ: %s" % t))
    except Exception as exc:
        # Unreadable is not the same as absent: never silently clobber a file
        # we failed to understand. Say why, and make replacing it a decision.
        msg("MERGE: %s exists but is not readable as CFS6: %s" % (path, exc))
        answer = _ask_yes_no(
            ida_kernwin.ASKBTN_NO,
            "%s already exists but cannot be read as a CFS6 file:\n\n%s\n\n"
            "Overwrite it?" % (os.path.basename(path), exc),
        )
        if answer == ida_kernwin.ASKBTN_YES:
            return MERGE_OVERWRITE, None
        return None, None

    conflicts = cfs6.merge_conflicts(loaded.header, image, build_number)
    if conflicts:
        # Appending here would leave one header describing two images, so the
        # only honest options are replace or stop.
        for reason in conflicts:
            msg("MERGE_CONFLICT: %s" % reason)
        answer = _ask_yes_no(
            ida_kernwin.ASKBTN_NO,
            "%s describes a different image, so this export cannot be added "
            "to it:\n\n  %s\n\nIt currently holds %s.\n\nOverwrite it?"
            % (os.path.basename(path), "\n  ".join(conflicts),
               loaded.describe_contents()),
        )
        if answer == ida_kernwin.ASKBTN_YES:
            return MERGE_OVERWRITE, None
        return None, None

    if loaded.parse_errors:
        msg("MERGE_WARN: %s has %d unusable line(s); they will not be carried "
            "over if you append." % (path, loaded.parse_errors))

    answer = ida_kernwin.ask_buttons(
        "Append", "Overwrite", "Cancel", ida_kernwin.ASKBTN_YES,
        # The file dialog's own "replace?" prompt has already fired by now and
        # deleted nothing, so say so -- otherwise this reads as a second,
        # contradictory question.
        ("%s already exists and holds %s\n(%s).\n\n"
         "Append adds this export and refreshes any item it re-exports;\n"
         "Overwrite discards everything already in the file.\n\n"
         "Nothing has been written yet."
         % (os.path.basename(path), loaded.describe_contents(),
            loaded.describe_source())).replace("%", "%%"),
    )
    if answer == ida_kernwin.ASKBTN_YES:
        return MERGE_APPEND, loaded
    if answer == ida_kernwin.ASKBTN_NO:
        return MERGE_OVERWRITE, None
    return None, None


def export_items(function_eas, global_eas, title, declarations=None):
    """Interactive export: acquire the parameters, then hand off to the engine.

    Everything this function does is ask questions. The writing itself lives in
    `cfs5.export` so the agent API drives exactly the same code path -- see
    docs/agent-api.md.
    """
    function_eas = sorted(set(function_eas or []))
    global_eas = sorted(set(global_eas or []))
    declarations = sorted(declarations or [], key=lambda d: d.id)

    if not function_eas and not global_eas and not declarations:
        ida_kernwin.warning("Nothing to export.")
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

    build_number, build_source = _ask_build_number()

    # Asked before the engine runs: the identity gate on appending needs the
    # image and the confirmed build, and the prompt must not fire mid-export.
    view, view_source = open_image_view()
    image, _notes = describe_image(view, view_source)
    mode, merge_from = _ask_merge_mode(path, image, build_number)
    if mode is None:
        msg("Export cancelled at the existing-file prompt; %s left untouched."
            % path)
        return False

    export.clear_caches()
    result = export.export_to_path(
        path, ranges,
        function_eas=function_eas, global_eas=global_eas,
        declarations=declarations,
        build=(build_number, build_source), merge=mode,
    )

    if result["error"] and not result["cancelled"]:
        ida_kernwin.warning("Export failed:\n%s" % result["error"])
        return False
    if result["cancelled"]:
        return False

    ida_kernwin.info(result["summary"])
    return result["ok"]



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
            # No context is not a reason to send the user back to the window
            # they just used -- offer the picker instead.
            msg("SELECTION: no function came back from the Functions window; "
                "offering the function picker.")
            start = prompt_for_function_ea()
            if start == BADADDR:
                return 1
            eas = [start]
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
        decls = store.load_all()
        if not funcs and not globs and not decls:
            ida_kernwin.warning("No user-named functions, globals or members.")
            return 1
        if ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            "Export %d user-named functions, %d user-named globals and %d "
            "declared members to CFS6?" % (len(funcs), len(globs), len(decls)),
        ) != ida_kernwin.ASKBTN_YES:
            return 1
        export_items(funcs, globs, "Export ALL user items to CFS6",
                     declarations=decls)
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


# --- Disassembly view: declared members ---

class DeclareMemberHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        ea = getattr(ctx, "cur_ea", BADADDR)
        if ea == BADADDR:
            ea = ida_kernwin.get_screen_ea()
        op_index = ida_kernwin.get_opnum()
        if op_index < 0:
            ida_kernwin.warning(
                "Put the cursor on the operand that references the member "
                "(the [reg+offset] part), not on the mnemonic."
            )
            return 1
        declare_member_at(ea, op_index)
        return 1

    def update(self, ctx):
        return _enable_for(ctx, ida_kernwin.BWN_DISASM)


class DeclareStructHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        owner = _pick_struct_name(ctx)
        if not owner:
            return 1
        chooser = MemberChooser(owner)
        if not chooser.refs:
            ida_kernwin.warning(
                "%s has no declarable members.\n\nBase-class fields belong to "
                "the base type -- declare them there." % owner
            )
            return 1
        msg("%s: %d member(s). Enter = declare + scan, Ctrl+D = declare only, "
            "Ctrl+E = scan, Del = undeclare. '*' marks a stored declaration. "
            "Right-click to export." % (owner, len(chooser.refs)))
        chooser.Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class ManageDeclarationsHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        if store.count() == 0:
            ida_kernwin.info(
                "No declarations yet.\n\nIn the disassembly view, put the "
                "cursor on a [reg+offset] operand and press %s."
                % DECLARE_HOTKEY
            )
            return 1
        DeclarationChooser().Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class ExportMembersHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        decls = store.load_all()
        if not decls:
            ida_kernwin.warning("No declarations to export.")
            return 1
        export_items([], [], "Export declared members to CFS6",
                     declarations=decls)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class Hooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        wt = ida_kernwin.get_widget_type(widget)
        # The member chooser: attach here rather than in Choose.OnPopup, which
        # IDA drives from `populating_widget_popup` -- too early for
        # attach_action_to_popup to stick.
        try:
            title = str(ida_kernwin.get_widget_title(widget) or "")
        except Exception:
            title = ""
        if title.startswith(MEMBER_CHOOSER_PREFIX):
            for aid in (ACTION_EXPORT_MEMBERS, ACTION_MANAGE_DECLS):
                ida_kernwin.attach_action_to_popup(
                    widget, popup_handle, aid, "CFS6/"
                )
            return
        if wt == ida_kernwin.BWN_FUNCS:
            for aid in (ACTION_SEL_FUNCS, ACTION_ALL_FUNCS, ACTION_ALL_BOTH):
                ida_kernwin.attach_action_to_popup(widget, popup_handle, aid, "CFS6/")
        elif wt == ida_kernwin.BWN_NAMES:
            for aid in (ACTION_SEL_GLOBALS, ACTION_ALL_GLOBALS):
                ida_kernwin.attach_action_to_popup(widget, popup_handle, aid, "CFS6/")
        elif wt == ida_kernwin.BWN_TILVIEW:
            for aid in (ACTION_DECLARE_STRUCT, ACTION_MANAGE_DECLS,
                        ACTION_EXPORT_MEMBERS):
                ida_kernwin.attach_action_to_popup(widget, popup_handle, aid, "CFS6/")
        elif wt in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            for aid in (ACTION_DECLARE_MEMBER, ACTION_DECLARE_STRUCT,
                        ACTION_MANAGE_DECLS, ACTION_EXPORT_MEMBERS):
                ida_kernwin.attach_action_to_popup(widget, popup_handle, aid, "CFS6/")


# (action_id, label, handler_factory, hotkey, tooltip)
_ACTIONS = [
    (ACTION_SEL_FUNCS, "Export selected functions to CFS6",
     ExportSelFuncsHandler, SELECTED_HOTKEY,
     "Export the functions selected in the Functions window"),
    (ACTION_ALL_FUNCS, "Export ALL user-named functions to CFS6",
     ExportAllFuncsHandler, None,
     "Export every user-named function (no globals)"),
    (ACTION_ALL_BOTH, "Export ALL user functions + globals + members to CFS6",
     ExportAllBothHandler, None,
     "Export every user-named function and global, plus declared members"),
    (ACTION_SEL_GLOBALS, "Export selected globals to CFS6",
     ExportSelGlobalsHandler, None,
     "Export the globals selected in the Names window"),
    (ACTION_ALL_GLOBALS, "Export ALL user-named globals to CFS6",
     ExportAllGlobalsHandler, None,
     "Export every user-named global (no functions)"),
    (ACTION_DECLARE_MEMBER, "Declare member from this operand",
     DeclareMemberHandler, DECLARE_HOTKEY,
     "Record the structure member this operand references as a CFS6 "
     "derived_value"),
    (ACTION_DECLARE_STRUCT, "Declare members of a structure...",
     DeclareStructHandler, None,
     "Pick which members of a structure to record as CFS6 derived_values"),
    (ACTION_MANAGE_DECLS, "Manage CFS6 declarations",
     ManageDeclarationsHandler, None,
     "List, inspect and delete the declarations stored in this IDB"),
    (ACTION_EXPORT_MEMBERS, "Export declared members to CFS6",
     ExportMembersHandler, None,
     "Export every declared member as a derived_value item"),
]


# Always-available entry points, independent of which window has focus.
_MENU_PATH = "Edit/Export/"
_MENU_ACTIONS = (ACTION_DECLARE_STRUCT, ACTION_EXPORT_MEMBERS,
                 ACTION_MANAGE_DECLS)

# The importer is a separate plugin, but registered actions live in one global
# namespace, so the dispatcher can offer it as long as it is loaded.
ACTION_IMPORT = "cfs5:import_file"


class DispatcherChooser(ida_kernwin.Choose):
    """One entry point for everything, so nothing depends on right-clicking.

    Every row runs an already-registered action. That keeps this a menu and not
    a second implementation -- the popups, the main menu and this list all
    trigger exactly the same code.
    """

    _ROWS = [
        ("Declare members of a structure...", "members",
         "Pick which fields to record, then scan for signatures",
         ACTION_DECLARE_STRUCT),
        ("Export declared members only", "members",
         "Write just the derived_value items",
         ACTION_EXPORT_MEMBERS),
        ("Manage declarations", "members",
         "List, inspect and delete what is stored in this IDB",
         ACTION_MANAGE_DECLS),
        ("Export selected functions", "functions",
         "The functions selected in the Functions window",
         ACTION_SEL_FUNCS),
        ("Export ALL user-named functions", "functions",
         "Every user-named function, no globals",
         ACTION_ALL_FUNCS),
        ("Export selected globals", "globals",
         "The globals selected in the Names window",
         ACTION_SEL_GLOBALS),
        ("Export ALL user-named globals", "globals",
         "Every user-named global, no functions",
         ACTION_ALL_GLOBALS),
        ("Export EVERYTHING", "all",
         "Functions + globals + declared members",
         ACTION_ALL_BOTH),
        ("Import a .cfs file...", "import",
         "Runs the CFS6 importer plugin",
         ACTION_IMPORT),
    ]

    def __init__(self):
        ida_kernwin.Choose.__init__(
            self, "CFS6",
            [["Action", 36], ["Kind", 10], ["What it does", 52]],
            flags=ida_kernwin.Choose.CH_MODAL,
        )

    def OnGetSize(self):
        return len(self._ROWS)

    def OnGetLine(self, n):
        label, kind, tip, _action = self._ROWS[n]
        return [label, kind, tip]

    def show(self):
        row = self.Show(modal=True)
        if row < 0:
            return
        label, _kind, _tip, action = self._ROWS[row]
        if not ida_kernwin.process_ui_action(action):
            # The selected-items actions are only enabled while their window
            # has focus, and the importer is a separate plugin that may not be
            # loaded -- say which, rather than failing mutely.
            ida_kernwin.warning(
                "%r could not run.\n\n"
                "Actions on a selection (functions/globals) need that window "
                "focused -- select there first, then right-click -> CFS6.\n"
                "Import needs the CFS6 importer plugin to be loaded."
                % label
            )


class CFS5ExporterPlugin(idaapi.plugin_t):
    # Not PLUGIN_HIDE: run() is a real dispatcher now, so the plugin belongs in
    # the Plugins list where it can be found without knowing a right-click.
    flags = idaapi.PLUGIN_PROC
    comment = "CFS6 signature + type exporter for IDA 9 (functions + globals)"
    help = (
        "Functions window -> right click -> CFS6 (functions). "
        "Names window -> right click -> CFS6 (globals). Exports short unique "
        "ENTRY/BODY/REL function signatures, REL-anchored global signatures, "
        "and function/global/local types."
    )
    wanted_name = PLUGIN_NAME
    wanted_hotkey = DISPATCH_HOTKEY

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

        # A permanent home in the main menu. The popups are context-dependent,
        # and exporting only the declared members should not require finding
        # the right window to right-click in.
        for action_id in _MENU_ACTIONS:
            if not ida_kernwin.attach_action_to_menu(
                _MENU_PATH, action_id, ida_kernwin.SETMENU_APP
            ):
                msg("Could not add %s to %s" % (action_id, _MENU_PATH))

        self.hooks.hook()
        msg("%s initialized." % VERSION)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        DispatcherChooser().show()

    def term(self):
        try:
            self.hooks.unhook()
        except Exception:
            pass
        for action_id in _MENU_ACTIONS:
            try:
                ida_kernwin.detach_action_from_menu(_MENU_PATH, action_id)
            except Exception:
                pass
        for action_id, _label, _factory, _hotkey, _tip in _ACTIONS:
            ida_kernwin.unregister_action(action_id)


def PLUGIN_ENTRY():
    return CFS5ExporterPlugin()
