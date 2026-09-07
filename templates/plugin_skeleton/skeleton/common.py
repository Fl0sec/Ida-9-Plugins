"""Cross-cutting primitives: logging, address formatting, segment ranges.

Nothing here is specific to one entry point; every module in the plugin may
consume it.
"""

import ida_idaapi
import ida_ida
import ida_kernwin
import ida_segment


BADADDR = ida_idaapi.BADADDR

# One bracketed tag per plugin keeps Output-window lines greppable. Rename it
# together with the package.
LOG_PREFIX = "[SKELETON]"


def msg(text):
    """Print a prefixed line to IDA's Output window."""
    ida_kernwin.msg("%s %s\n" % (LOG_PREFIX, text))


def ea_str(ea):
    """Format an address the one way this plugin ever formats addresses."""
    return "BADADDR" if ea == BADADDR else "0x%X" % ea


def get_search_ranges():
    """Executable/code segment ranges as (start, end, name) tuples.

    Falls back to the whole database span when no code segment is found, so a
    caller never has to special-case an unusual IDB layout.
    """
    ranges = []
    seg = ida_segment.get_first_seg()
    while seg is not None:
        if bool(seg.perm & ida_segment.SEGPERM_EXEC) or seg.type == ida_segment.SEG_CODE:
            try:
                name = ida_segment.get_segm_name(seg)
            except Exception:
                name = "segment@%s" % ea_str(seg.start_ea)
            ranges.append((seg.start_ea, seg.end_ea, name))
        seg = ida_segment.get_next_seg(seg.start_ea)

    if not ranges:
        lo = ida_ida.inf_get_min_ea()
        hi = ida_ida.inf_get_max_ea()
        if lo != BADADDR and hi != BADADDR and hi > lo:
            ranges.append((lo, hi, "<whole-idb>"))
    return ranges
