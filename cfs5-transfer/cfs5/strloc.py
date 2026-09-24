"""Resolve a function from a unique registration string and nearby LEA.

The string identifies registration-table evidence. Inside the enclosing
`.pdata` chunk, clamped to 128 bytes around each xref, call/jmp boundaries
isolate one table entry; exactly one preceding LEA may point into executable
memory. Its target is the handler. Register names and fixed instruction deltas
are deliberately irrelevant.
"""

import ida_bytes
import ida_segment
import ida_ua
import idautils

from .common import BADADDR, UA_MAXOP, find_up_to_n
from .disasm import decode_chunk, infer_pc_relative_field
from .image import BodyOwnership
from .policy import select_handler_lea


WINDOW_BYTES = 128


class StringLocatorError(Exception):
    """A string locator that cannot be resolved without guessing."""


def _all_mapped_ranges():
    ranges = []
    seg = ida_segment.get_first_seg()
    while seg is not None:
        ranges.append((seg.start_ea, seg.end_ea))
        seg = ida_segment.get_next_seg(seg.start_ea)
    return ranges


def _is_executable(ea):
    seg = ida_segment.getseg(ea)
    return seg is not None and (
        bool(seg.perm & ida_segment.SEGPERM_EXEC)
        or seg.type == ida_segment.SEG_CODE
    )


def _exact_string_eas(text):
    try:
        raw = text.encode("utf-8") + b"\0"
    except Exception as exc:
        raise StringLocatorError("anchor string is not UTF-8 encodable: %s" % exc)
    signature = " ".join("%02X" % byte for byte in raw)
    return find_up_to_n(signature, _all_mapped_ranges(), 8)


def _code_xrefs_to(ea):
    out = []
    for xref in idautils.XrefsTo(ea, 0):
        if _is_executable(xref.frm) and xref.frm not in out:
            out.append(xref.frm)
    return out


def _pc_relative_target(insn):
    for index in range(UA_MAXOP):
        op = insn.ops[index]
        if op.type == ida_ua.o_void:
            break
        target = int(op.addr)
        if target in (0, BADADDR):
            continue
        if infer_pc_relative_field(insn, target) is not None:
            return target
    return None


def resolve_anchor_string(text, ownership=None, window_bytes=WINDOW_BYTES):
    """Evidence dict for `text`, or raise StringLocatorError.

    Each match includes the trailing NUL, so a prefix such as
    `ShowGenericPopupOk` cannot match `ShowGenericPopupOkCancel`. Duplicate
    bytes or references are tolerated only when the structural rule produces
    one distinct handler.
    """
    ownership = ownership or BodyOwnership.for_current_idb()
    if not ownership.available:
        raise StringLocatorError(".pdata is unavailable; no bounded registration window")

    resolved = []
    failures = []
    matches = _exact_string_eas(text)
    for string_ea in matches:
        for xref_ea in _code_xrefs_to(string_ea):
            rva = xref_ea - ownership.imagebase
            chunk = ownership.index.containing(rva)
            if chunk is None:
                failures.append("xref is outside .pdata")
                continue
            chunk_start = chunk[0] + ownership.imagebase
            chunk_end = chunk[1] + ownership.imagebase
            start = max(chunk_start, xref_ea - int(window_bytes))
            end = min(chunk_end, xref_ea + int(window_bytes))

            facts = []
            for item in decode_chunk(chunk_start, chunk_end):
                if item["ea"] < start or item["ea"] >= end or item["insn"] is None:
                    continue
                insn = item["insn"]
                mnemonic = insn.get_canon_mnem() or ""
                target = _pc_relative_target(insn)
                facts.append({
                    "ea": item["ea"], "mnemonic": mnemonic,
                    "terminator": mnemonic.lower() in ("call", "jmp"),
                    "target": target,
                    "target_executable": target is not None and _is_executable(target),
                })

            handler, reason = select_handler_lea(facts, xref_ea)
            if handler is None:
                failures.append(reason)
                continue
            resolved.append({
                "string_ea": string_ea, "xref_ea": xref_ea,
                "handler_lea_ea": handler["ea"],
                "function_ea": handler["target"],
                "window_start": start, "window_end": end,
            })

    handlers = {item["function_ea"] for item in resolved}
    if len(handlers) != 1:
        raise StringLocatorError(
            "NUL-terminated string %r produced %d distinct handlers; %s"
            % (text, len(handlers), "; ".join(failures[:3]))
        )
    chosen = next(item for item in resolved if item["function_ea"] in handlers)
    return chosen
