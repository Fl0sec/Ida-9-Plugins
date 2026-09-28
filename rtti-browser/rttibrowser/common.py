"""Logging, address formatting, and cancellation primitives."""

import ida_idaapi
import ida_kernwin


BADADDR = ida_idaapi.BADADDR
LOG_PREFIX = "[RTTI]"


class ScanCancelled(Exception):
    """Raised when the user cancels discovery or validation."""


def msg(text):
    """Print one prefixed line to IDA's Output window."""
    ida_kernwin.msg("%s %s\n" % (LOG_PREFIX, text))


def ea_str(ea):
    return "BADADDR" if ea == BADADDR else "0x%X" % int(ea)
