"""Cross-cutting primitives: logging, address search ranges and byte-pattern
search.

None of this is exporter- or importer-specific; both plugins consume it. The
payload codec and pattern normalization live in cfs6.py, beside the format
definition they belong to.
"""

import ida_bytes
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_segment


BADADDR = ida_idaapi.BADADDR
UA_MAXOP = ida_ida.UA_MAXOP

def msg(text):
    """Print a prefixed line to IDA's Output window."""
    ida_kernwin.msg("[CFS6] %s\n" % text)


def ea_str(ea):
    return "BADADDR" if ea == BADADDR else "0x%X" % ea


def safe_name(name):
    """Reject names that cannot round-trip as a clean record name."""
    if not name:
        return None
    if "\n" in name or "\r" in name:
        return None
    return name


def get_search_ranges():
    """Executable/code segment ranges as (start, end, name) tuples.

    Falls back to the whole database span when no code segment is found.
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


def find_up_to_n(signature, ranges, limit):
    """Return at most `limit` match addresses for an IDA byte-pattern signature.

    Stops as soon as `limit` hits are in hand. Accepts ranges as (start, end)
    or (start, end, name).
    """
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
    matches = []
    limit = max(1, int(limit))

    for rng in ranges:
        start, end = rng[0], rng[1]
        cur = start
        while cur < end:
            ea = ida_bytes.find_bytes(
                signature, cur, range_end=end, flags=flags, radix=16
            )
            if ea == BADADDR:
                break
            matches.append(ea)
            if len(matches) >= limit:
                return matches
            cur = ea + 1

    return matches


def find_up_to_two(signature, ranges):
    """At most two matches -- the uniqueness test every finder runs.

    Two is all a uniqueness decision needs, and stopping there is what keeps
    the search cheap on a 40MB image. `find_up_to_n` is for diagnostics, where
    *how many* siblings exist is the answer being looked for.
    """
    return find_up_to_n(signature, ranges, 2)
