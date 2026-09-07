# Mermaid Flowchart viewer for IDA Pro 9.0 / IDAPython 9.0.
#
# Attach a hand-written or LLM-generated Mermaid flowchart to a function and
# render it as a native IDA graph. Right-click inside a function (disassembly,
# pseudocode or the Functions window) -> Mermaid -> Show flowchart. If none is
# registered yet you are offered a paste dialog; the source is stored in the
# IDB and comes back when the database is reopened.
#
# Nodes link to addresses two ways: automatically when a node's label is a
# symbol name in this IDB, and explicitly via Mermaid's own `click` directive
# (`click F "0x140003870"`). Double-click a linked node to jump there.
#
# All parsing, storage and rendering live in the sibling `mermaidflow` package;
# this file is only orchestration and IDA plugin/UI glue.
#
# Target: IDA Professional 9.0 / Python 3.12.

import os
import sys

# Make the sibling `mermaidflow` package importable regardless of IDA's
# sys.path, and force a fresh import on every (re)load so edits to the package
# take effect without restarting IDA.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
for _modname in [n for n in list(sys.modules)
                 if n == "mermaidflow" or n.startswith("mermaidflow.")]:
    del sys.modules[_modname]

import idaapi
import ida_funcs
import ida_kernwin

from mermaidflow import VERSION
from mermaidflow import store, view
from mermaidflow.common import BADADDR, ea_str, msg


PLUGIN_NAME = "Mermaid Flowchart (IDA 9)"

ACTION_SHOW = "mermaidflow:show"
ACTION_EDIT = "mermaidflow:edit"
ACTION_DELETE = "mermaidflow:delete"

SHOW_HOTKEY = "Ctrl+Shift+M"
POPUP_PATH = "Mermaid/"

# Windows the actions attach to. A flowchart belongs to a function, and these
# are the three places a function is under the cursor.
TARGET_WIDGETS = (
    ida_kernwin.BWN_DISASM,
    ida_kernwin.BWN_PSEUDOCODE,
    ida_kernwin.BWN_FUNCS,
)

# ask_text needs a cap; a flowchart is text, so be generous rather than clever.
MAX_SOURCE = 1024 * 1024

TEMPLATE = """flowchart TD
    A["step one"] --> B["step two"]
    B --> C{"condition?"}
    C -- Yes --> D["done"]
    C -- No --> E["failed"]
"""

# Graph viewers are kept alive here: IDA holds only a raw pointer, so a
# garbage-collected viewer takes the graph window (and often IDA) with it.
_viewers = {}


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------

def current_func_ea(ctx=None):
    """Start address of the function under the cursor, or BADADDR.

    The Functions window reports its selection through `ctx`, every other
    widget through the screen address.
    """
    if ctx is not None:
        # The Functions chooser selects by row index, not by address.
        for index in getattr(ctx, "chooser_selection", None) or []:
            try:
                func = ida_funcs.getn_func(index)
            except Exception as exc:
                msg("chooser index %s unreadable: %s" % (index, exc))
                continue
            if func is not None:
                return func.start_ea

    try:
        return store.func_key(ida_kernwin.get_screen_ea())
    except Exception as exc:
        msg("cannot determine the current function: %s" % exc)
        return BADADDR


def func_label(func_ea):
    name = ida_funcs.get_func_name(func_ea)
    return "%s (%s)" % (name, ea_str(func_ea)) if name else ea_str(func_ea)


def ask_source(func_ea, existing=None):
    """Prompt for Mermaid source. Returns the text, or None if cancelled."""
    prompt = ("Mermaid flowchart for %s\n\n"
              "Paste a `flowchart TD` graph. Node labels that match a symbol "
              "in this IDB link automatically; use `click ID \"name-or-0xaddr\"` "
              "for the rest." % func_label(func_ea))
    try:
        return ida_kernwin.ask_text(MAX_SOURCE, existing or TEMPLATE, prompt)
    except Exception as exc:
        msg("paste dialog failed: %s" % exc)
        return None


def render(func_ea, source):
    """Show the graph for `source`, keeping the viewer alive."""
    viewer = view.show(source, func_ea)
    if viewer is not None:
        _viewers[func_ea] = viewer
    return viewer


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

def show_flowchart(func_ea):
    source = store.load(func_ea)
    if source is None:
        if ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            "No flowchart is registered for %s.\n\nRegister one now?"
            % func_label(func_ea),
        ) != ida_kernwin.ASKBTN_YES:
            return
        source = ask_source(func_ea)
        if not source:
            return
        if store.save(func_ea, source):
            msg("Registered a flowchart for %s." % func_label(func_ea))
        else:
            ida_kernwin.warning("Could not store the flowchart in the IDB.\n"
                                "It will be shown but not saved.")
    render(func_ea, source)


def edit_flowchart(func_ea):
    existing = store.load(func_ea)
    source = ask_source(func_ea, existing)
    if source is None or source == existing:
        return
    if not source.strip():
        ida_kernwin.warning("Empty source; nothing saved. "
                            "Use 'Delete flowchart' to remove it.")
        return
    if store.save(func_ea, source):
        msg("Updated the flowchart for %s." % func_label(func_ea))
    else:
        ida_kernwin.warning("Could not store the flowchart in the IDB.")
    render(func_ea, source)


def delete_flowchart(func_ea):
    if store.load(func_ea) is None:
        ida_kernwin.warning("No flowchart is registered for %s."
                            % func_label(func_ea))
        return
    if ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_NO,
        "Delete the stored flowchart for %s?" % func_label(func_ea),
    ) != ida_kernwin.ASKBTN_YES:
        return

    if store.delete(func_ea):
        msg("Deleted the flowchart for %s." % func_label(func_ea))
    else:
        msg("Nothing deleted for %s." % func_label(func_ea))

    viewer = _viewers.pop(func_ea, None)
    if viewer is not None:
        try:
            viewer.Close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Actions and UI
# ---------------------------------------------------------------------------

def _enable_for_targets(ctx):
    # `getattr`, not `ctx.widget_type`: the attribute is absent in some action
    # contexts and an AttributeError here breaks the whole popup.
    if getattr(ctx, "widget_type", None) in TARGET_WIDGETS:
        return ida_kernwin.AST_ENABLE_FOR_WIDGET
    return ida_kernwin.AST_DISABLE_FOR_WIDGET


class _FuncActionHandler(ida_kernwin.action_handler_t):
    """Resolves the current function, then defers to `operate`."""

    def activate(self, ctx):
        func_ea = current_func_ea(ctx)
        if func_ea == BADADDR:
            ida_kernwin.warning(
                "Place the cursor inside a function, or select one in the "
                "Functions window."
            )
            return 1
        try:
            self.operate(func_ea)
        except Exception as exc:
            msg("%s failed for %s: %s"
                % (type(self).__name__, ea_str(func_ea), exc))
            ida_kernwin.warning("Operation failed: %s\n\nSee the Output window."
                                % exc)
        return 1

    def update(self, ctx):
        return _enable_for_targets(ctx)

    def operate(self, func_ea):
        raise NotImplementedError


class ShowHandler(_FuncActionHandler):
    def operate(self, func_ea):
        show_flowchart(func_ea)


class EditHandler(_FuncActionHandler):
    def operate(self, func_ea):
        edit_flowchart(func_ea)


class DeleteHandler(_FuncActionHandler):
    def operate(self, func_ea):
        delete_flowchart(func_ea)


class Hooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        if ida_kernwin.get_widget_type(widget) not in TARGET_WIDGETS:
            return
        for action_id in (ACTION_SHOW, ACTION_EDIT, ACTION_DELETE):
            ida_kernwin.attach_action_to_popup(
                widget, popup_handle, action_id, POPUP_PATH
            )


# (action_id, label, handler_factory, hotkey, tooltip)
_ACTIONS = [
    (ACTION_SHOW, "Show flowchart", ShowHandler, SHOW_HOTKEY,
     "Render this function's Mermaid flowchart, or register one"),
    (ACTION_EDIT, "Edit flowchart source...", EditHandler, None,
     "Edit the Mermaid source stored for this function"),
    (ACTION_DELETE, "Delete flowchart", DeleteHandler, None,
     "Remove the flowchart stored for this function"),
]


class MermaidFlowPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Render a pasted Mermaid flowchart as a native IDA graph"
    help = (
        "Right-click inside a function (disassembly, pseudocode or the "
        "Functions window) -> Mermaid -> Show flowchart. The source is stored "
        "per function in the IDB. Double-click a node to jump to its address."
    )
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        # IDA keeps only a raw pointer to each handler; hold Python references
        # or activating an action crashes IDA after a garbage collection.
        self.handlers = []
        self.hooks = Hooks()

        for action_id, label, factory, hotkey, tip in _ACTIONS:
            # Tolerate a plugin reload: re-registering an existing id fails.
            ida_kernwin.unregister_action(action_id)
            handler = factory()
            self.handlers.append(handler)
            if not ida_kernwin.register_action(
                ida_kernwin.action_desc_t(action_id, label, handler, hotkey, tip, -1)
            ):
                msg("Action registration failed: %s" % action_id)
                return idaapi.PLUGIN_SKIP

        self.hooks.hook()
        msg("%s %s initialized." % (PLUGIN_NAME, VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.info(
            "Mermaid Flowchart\n\n"
            "Right-click inside a function (disassembly, pseudocode or the "
            "Functions window) -> Mermaid -> Show flowchart (%s).\n\n"
            "The flowchart is stored per function in the IDB." % SHOW_HOTKEY
        )

    def term(self):
        try:
            self.hooks.unhook()
        except Exception:
            pass
        for viewer in list(_viewers.values()):
            try:
                viewer.Close()
            except Exception:
                pass
        _viewers.clear()
        for action_id, _label, _factory, _hotkey, _tip in _ACTIONS:
            ida_kernwin.unregister_action(action_id)


def PLUGIN_ENTRY():
    return MermaidFlowPlugin()
