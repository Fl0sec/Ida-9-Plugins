# RTTI Browser for IDA Professional 9.4 / IDAPython 9.4 / Python 3.12.
#
# The entry point owns only plugin lifecycle. Validated MSVC RTTI discovery,
# persistence, and chooser behavior live in the sibling rttibrowser package.

import os
import sys


_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
for _modname in [name for name in list(sys.modules)
                 if name == "rttibrowser" or name.startswith("rttibrowser.")]:
    del sys.modules[_modname]

import idaapi

from rttibrowser import VERSION
from rttibrowser.common import msg
from rttibrowser.controller import RttiController


PLUGIN_NAME = "RTTI Browser (IDA 9.4)"
PLUGIN_HOTKEY = "Ctrl+Shift+3"


class RttiBrowserPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Cached, searchable MSVC RTTI hierarchy and vtable browser"
    help = "Edit -> Plugins -> RTTI Browser, or press Ctrl+Shift+3."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        self.controller = RttiController()
        msg("%s initialized. Hotkey: %s" % (VERSION, PLUGIN_HOTKEY))
        return idaapi.PLUGIN_KEEP

    def run(self, _arg):
        self.controller.open()

    def term(self):
        try:
            self.controller.close_windows()
        except Exception:
            pass


def PLUGIN_ENTRY():
    return RttiBrowserPlugin()
