"""Cross-cutting primitives: logging and address formatting."""

import ida_idaapi
import ida_kernwin


BADADDR = ida_idaapi.BADADDR

LOG_PREFIX = "[MERMAID]"


def msg(text):
    """Print a prefixed line to IDA's Output window."""
    ida_kernwin.msg("%s %s\n" % (LOG_PREFIX, text))


def ea_str(ea):
    """Format an address the one way this plugin ever formats addresses."""
    return "BADADDR" if ea == BADADDR else "0x%X" % ea
