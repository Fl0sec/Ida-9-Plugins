# Skeleton plugin for IDA Pro 9.0 / IDAPython 9.0.
#
# A minimal but complete plugin: registers two actions, attaches them to the
# Functions window context menu, and runs a cancellable batch over the selected
# or all functions. Copy this directory, rename it, and replace the body of
# `process_functions`.
#
# All reusable machinery lives in the sibling `skeleton` package; this file is
# only discovery, orchestration and IDA plugin/UI glue.
#
# Target: IDA Professional 9.0 / Python 3.12.

import os
import sys

# Make the sibling `skeleton` package importable regardless of IDA's sys.path,
# and force a fresh import on every (re)load so edits to the package take
# effect without restarting IDA. Rename BOTH occurrences of "skeleton" below
# when you rename the package.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
for _modname in [n for n in list(sys.modules)
                 if n == "skeleton" or n.startswith("skeleton.")]:
    del sys.modules[_modname]

import idaapi
import ida_funcs
import ida_kernwin
import idautils

from skeleton import VERSION
from skeleton.common import ea_str, msg


PLUGIN_NAME = "Skeleton (IDA 9)"
ACTION_SEL = "skeleton:process_selected"
ACTION_ALL = "skeleton:process_all"
SELECTED_HOTKEY = "Ctrl+Shift+K"

# How often the cancellable loop checks for cancellation / repaints progress.
PROGRESS_EVERY = 10


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def get_selected_function_eas(ctx):
    """Function start addresses selected in the Functions window."""
    selection = getattr(ctx, "chooser_selection", None)
    if not selection:
        return []

    eas = []
    for index in selection:
        try:
            # The Functions chooser is 0-based over the function list.
            func = ida_funcs.getn_func(index)
        except Exception as exc:
            msg("chooser index %s unreadable: %s" % (index, exc))
            continue
        if func is not None:
            eas.append(func.start_ea)
    return eas


def get_all_function_eas():
    return list(idautils.Functions())


# ---------------------------------------------------------------------------
# Work
# ---------------------------------------------------------------------------

def process_one(ea):
    """Do the actual per-function work. Return True when something changed."""
    name = ida_funcs.get_func_name(ea)
    msg("%s %s" % (ea_str(ea), name))
    return False


def process_functions(eas, title):
    """Run `process_one` over `eas` with progress and cancellation.

    Every per-item failure is logged and skipped: one raising IDA call must not
    lose the whole batch.
    """
    if not eas:
        ida_kernwin.warning("Nothing to process.")
        return

    changed = 0
    failed = 0
    done = 0

    ida_kernwin.show_wait_box("%s: 0/%d..." % (title, len(eas)))
    try:
        for index, ea in enumerate(eas):
            if index % PROGRESS_EVERY == 0:
                if ida_kernwin.user_cancelled():
                    msg("Cancelled at %d/%d." % (index, len(eas)))
                    break
                ida_kernwin.replace_wait_box(
                    "%s: %d/%d..." % (title, index, len(eas))
                )
            try:
                if process_one(ea):
                    changed += 1
            except Exception as exc:
                failed += 1
                msg("%s failed: %s" % (ea_str(ea), exc))
            done += 1
    finally:
        ida_kernwin.hide_wait_box()

    summary = "%s\n\nprocessed: %d\nchanged: %d\nfailed: %d" % (
        title, done, changed, failed,
    )
    msg(summary.replace("\n\n", " -- ").replace("\n", ", "))
    ida_kernwin.info(summary)


# ---------------------------------------------------------------------------
# Actions and UI
# ---------------------------------------------------------------------------

def _enable_for(ctx, widget_type):
    # `getattr`, not `ctx.widget_type`: the attribute is absent in some action
    # contexts and an AttributeError here breaks the whole popup.
    if getattr(ctx, "widget_type", None) == widget_type:
        return ida_kernwin.AST_ENABLE_FOR_WIDGET
    return ida_kernwin.AST_DISABLE_FOR_WIDGET


class ProcessSelectedHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        eas = get_selected_function_eas(ctx)
        if not eas:
            ida_kernwin.warning("No functions selected in the Functions window.")
            return 1
        process_functions(eas, "Process selected functions")
        return 1

    def update(self, ctx):
        return _enable_for(ctx, ida_kernwin.BWN_FUNCS)


class ProcessAllHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        eas = get_all_function_eas()
        if ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES, "Process all %d functions?" % len(eas)
        ) != ida_kernwin.ASKBTN_YES:
            return 1
        process_functions(eas, "Process ALL functions")
        return 1

    def update(self, ctx):
        return _enable_for(ctx, ida_kernwin.BWN_FUNCS)


class Hooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_FUNCS:
            for action_id in (ACTION_SEL, ACTION_ALL):
                ida_kernwin.attach_action_to_popup(
                    widget, popup_handle, action_id, "Skeleton/"
                )


# (action_id, label, handler_factory, hotkey, tooltip)
_ACTIONS = [
    (ACTION_SEL, "Process selected functions", ProcessSelectedHandler,
     SELECTED_HOTKEY, "Process the functions selected in the Functions window"),
    (ACTION_ALL, "Process ALL functions", ProcessAllHandler, None,
     "Process every function in the database"),
]


class SkeletonPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Skeleton plugin for IDA 9"
    help = "Functions window -> right click -> Skeleton."
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
        ida_kernwin.info("Functions window -> right-click -> Skeleton.")

    def term(self):
        try:
            self.hooks.unhook()
        except Exception:
            pass
        for action_id, _label, _factory, _hotkey, _tip in _ACTIONS:
            ida_kernwin.unregister_action(action_id)


def PLUGIN_ENTRY():
    return SkeletonPlugin()
