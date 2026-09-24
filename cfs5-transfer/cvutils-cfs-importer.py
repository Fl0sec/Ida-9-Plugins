# CFS6 Importer UI entry for IDA Professional 9.4 / IDAPython 9.4.

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
for _modname in [
    n for n in list(sys.modules) if n == "cfs5" or n.startswith("cfs5.")
]:
    del sys.modules[_modname]

import idaapi
import ida_kernwin

from cfs5 import VERSION
from cfs5 import importer
from cfs5.common import msg


PLUGIN_NAME = "CFS6 Importer (IDA 9)"
PLUGIN_HOTKEY = "Ctrl+Shift+I"
ACTION_ID = "cfs5:import_file"
ACTION_LABEL = "CFS6 / CFS File..."


def choose_and_import():
    path = ida_kernwin.ask_file(
        False, "*.cfs", "Select CFS6 signature file (.cfs) to import"
    )
    if not path:
        msg("Import cancelled.")
        return False
    path = os.path.abspath(path)
    msg("Selected: %s" % path)
    result = importer.import_and_migrate(path, show_progress=True)
    if result.get("error") and not result.get("partial"):
        ida_kernwin.warning(result["error"])
    else:
        catalogue = result.get("catalogue", {})
        state = result.get("state", {})
        ida_kernwin.info(
            "%s\n\nProducer state: %d/%d migrated%s"
            % (catalogue.get("summary", "CFS6 import complete"),
               state.get("migrated", 0), state.get("requested", 0),
               " (see Output for unresolved records)"
               if state.get("unresolved") else "")
        )
    return bool(result.get("ok"))


class ImportHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        choose_and_import()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class CFS5ImporterPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "CFS6 signature + type importer for IDA 9 (functions + globals)"
    help = "Imports CFS6 names and types while protecting destination work."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        self.handler = ImportHandler()
        try:
            ida_kernwin.detach_action_from_menu("File/Load file/", ACTION_ID)
        except Exception:
            pass
        ida_kernwin.unregister_action(ACTION_ID)
        ok = ida_kernwin.register_action(ida_kernwin.action_desc_t(
            ACTION_ID, ACTION_LABEL, self.handler, None,
            "Import CFS6 signatures/types (functions + globals)", -1,
        ))
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
