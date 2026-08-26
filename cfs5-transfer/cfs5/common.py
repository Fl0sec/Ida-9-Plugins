"""Cross-cutting primitives: logging, address search ranges, byte-pattern
search and the zlib+base64 payload codec used by the .cfs format.

None of this is exporter- or importer-specific; both plugins consume it.
"""

import base64
import csv
import json
import zlib

import ida_bytes
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_segment


BADADDR = ida_idaapi.BADADDR
UA_MAXOP = ida_ida.UA_MAXOP

# .cfs payloads can be large (whole struct bodies); lift the csv field cap once.
try:
    csv.field_size_limit(16 * 1024 * 1024)
except Exception:
    pass


def msg(text):
    """Print a prefixed line to IDA's Output window."""
    ida_kernwin.msg("[CFS5] %s\n" % text)


def ea_str(ea):
    return "BADADDR" if ea == BADADDR else "0x%X" % ea


def safe_name(name):
    """Reject names that would corrupt a CSV row (embedded newlines)."""
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


def find_up_to_two(signature, ranges):
    """Return at most two match addresses for an IDA byte-pattern signature.

    Stops early once a second hit proves the pattern is non-unique. Accepts
    ranges as (start, end) or (start, end, name).
    """
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
    matches = []

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
            if len(matches) >= 2:
                return matches
            cur = ea + 1

    return matches


# ---------------------------------------------------------------------------
# .cfs payload codec (zlib + base64; JSON for dependency lists)
# ---------------------------------------------------------------------------

def pack_bytes(data):
    if data is None:
        return ""
    raw = bytes(data)
    if not raw:
        return ""
    return base64.b64encode(zlib.compress(raw, 9)).decode("ascii")


def pack_json(value):
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(zlib.compress(raw, 9)).decode("ascii")


def unpack_bytes(payload):
    if not payload:
        return None
    raw = base64.b64decode(payload.encode("ascii"), validate=False)
    return zlib.decompress(raw)


def unpack_text(payload):
    if not payload:
        return ""
    raw = base64.b64decode(payload.encode("ascii"), validate=False)
    return zlib.decompress(raw).decode("utf-8")


def unpack_json(payload):
    text = unpack_text(payload)
    if not text:
        return []
    value = json.loads(text)
    return value if isinstance(value, list) else []


def normalize_signature(sig):
    """Strip optional surrounding quotes and collapse whitespace in a pattern."""
    sig = sig.strip()
    if len(sig) >= 2 and sig[0] == '"' and sig[-1] == '"':
        sig = sig[1:-1].strip()
    return " ".join(sig.split())
