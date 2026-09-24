"""Confirm signatures: the byte evidence attached to a *structural* locator.

A structural locator (an RTTI vtable slot, a unique string's referencing site)
answers "which address" without any byte pattern at all. That is what makes it
work for functions no pattern can find -- a member of a clone family, or a
handler reachable only through a registration table. But it also means nothing
checks the answer: if a slot is renumbered or a table is reordered, the locator
still resolves, just to the wrong function.

The confirm signature is that check. It is a pattern matched **inside the
already-resolved function**, so unlike every other signature in this codebase
it does not have to be unique across the image -- only over the range the
consumer will scan. Two consequences follow, and both are deliberate:

* It may be tokenized with `disasm.pattern_tokens_for_insn(relax=True)`, giving
  up the immediates and stack displacements that drift between builds.
* The image-wide exact-byte floors (`MIN_EXACT_BYTES`, `value_min_exact`) do
  not apply -- they are calibrated for a risk this pattern is not running.

The relaxation has one real hazard: the bytes it wildcards are exactly the ones
separating a function from its byte-identical siblings, so a relaxed pattern
can match inside a sibling too, and would then *confirm* a locator that had
drifted onto the wrong function. **Both** tokenizations are therefore tried and
every window is counted image-wide, with `policy.rank_confirm_windows`
preferring an image-unique one over a merely tolerant one.

That is not belt-and-braces. Measured on `notify_inventory_has_new_items`
(client.dll 14182), no relaxed window at any anchor or length is image-unique --
every one matches 8+ places -- while the strict 15-byte window at +0x58 is
unique exactly because it pins the stack offsets that distinguish it from its
clone siblings. Offering only relaxed windows would ship an ambiguous confirm
signature for the function this mechanism exists to protect.

When nothing image-unique exists at all, the best available window is still
returned with its match count recorded, never silently dropped -- but the count
is what lets a consumer refuse to treat it as confirmation.

**The scan range is the invariant.** Uniqueness is measured over exactly what
the consumer will scan: the contiguous `.pdata` chain starting at the resolved
function (`peinfo.PdataIndex.chain_end`), with no slack. Measuring over IDA's
extent while the consumer scans the chain is how a signature gets declared
unique here and comes back ambiguous there.
"""

import ida_funcs

from .common import find_up_to_n, find_up_to_two, get_search_ranges
from .disasm import decode_chunk
from .policy import (
    CONFIRM_MATCH_LIMIT,
    CONFIRM_NO_INSTRUCTIONS,
    CONFIRM_NO_SCAN_RANGE,
    CONFIRM_NO_UNIQUE_WINDOW,
    SCAN_BOUND_IDA_EXTENT,
    SCAN_BOUND_PDATA_CHAIN,
    TOKENIZATION_RELAXED,
    TOKENIZATION_STRICT,
    confirm_min_exact,
    rank_confirm_windows,
)
from .sigs import iter_unique_windows, sample_body_indices


class ConfirmSignature:
    """A confirm signature, or the reason there is none.

    One object rather than two return shapes: every caller has to handle the
    refusal, and a half-answer -- a signature built over a range we could not
    establish -- is the thing this module exists to not produce.
    """

    __slots__ = (
        "signature", "offset", "scan_start", "scan_end", "scan_bound",
        "image_matches", "tokenization", "byte_len", "reason",
    )

    def __init__(self, signature=None, offset=0, scan_start=0, scan_end=0,
                 scan_bound=SCAN_BOUND_IDA_EXTENT, image_matches=0,
                 tokenization=TOKENIZATION_STRICT, byte_len=0, reason=None):
        self.signature = signature
        self.offset = int(offset)
        self.scan_start = int(scan_start)
        self.scan_end = int(scan_end)
        self.scan_bound = scan_bound
        self.image_matches = int(image_matches)
        self.tokenization = tokenization
        self.byte_len = int(byte_len)
        self.reason = reason

    def __bool__(self):
        return self.signature is not None

    @property
    def scan_size(self):
        return max(0, self.scan_end - self.scan_start)

    @property
    def image_unique(self):
        return self.image_matches == 1


def scan_range_for(func_ea, ownership=None):
    """(start_ea, end_ea, scan_bound) the consumer will scan, or (None, None, None).

    Prefers the `.pdata` chain because that is what a non-IDA consumer can
    compute for itself. IDA's extent is a documented fallback, labelled
    `ida_extent` so the consumer knows it is scanning from a hint rather than
    from the table.
    """
    func_ea = int(func_ea)

    if ownership is not None:
        span = ownership.chain_span(func_ea)
        if span is not None and span[1] > span[0]:
            return span[0], span[1], SCAN_BOUND_PDATA_CHAIN

    f = ida_funcs.get_func(func_ea)
    if f is not None and f.start_ea == func_ea and f.end_ea > f.start_ea:
        return f.start_ea, f.end_ea, SCAN_BOUND_IDA_EXTENT

    return None, None, None


def build_confirm_signature(func_ea, ownership=None, ranges=None):
    """A ConfirmSignature for `func_ea`, or one carrying a refusal reason.

    `ranges` is the image-wide search space (defaults to the code segments) and
    is used only to count siblings -- the uniqueness *decision* is made over
    the scan range.
    """
    func_ea = int(func_ea)
    start, end, bound = scan_range_for(func_ea, ownership)
    if start is None:
        return ConfirmSignature(reason=CONFIRM_NO_SCAN_RANGE)

    if ranges is None:
        ranges = get_search_ranges()
    scan_ranges = [(start, end)]

    windows = []
    seen = set()
    decoded_any = False
    for tokenization, relax in (
        (TOKENIZATION_RELAXED, True), (TOKENIZATION_STRICT, False)
    ):
        insns = decode_chunk(start, end, relax=relax)
        if not insns:
            continue
        decoded_any = True
        for idx in sample_body_indices(insns):
            for stats in iter_unique_windows(
                insns, idx, scan_ranges, min_exact=confirm_min_exact
            ):
                # The two passes produce identical bytes for an instruction
                # with nothing to wildcard; count such a window once, as the
                # strict one it actually is.
                if stats["signature"] in seen:
                    continue
                seen.add(stats["signature"])
                windows.append({
                    "signature": stats["signature"],
                    "offset": stats["start_ea"] - func_ea,
                    "byte_len": stats["byte_len"],
                    "wildcards": stats["wildcards"],
                    "tokenization": (
                        tokenization if stats["wildcards"] else TOKENIZATION_STRICT
                    ),
                    "image_matches": len(find_up_to_n(
                        stats["signature"], ranges, CONFIRM_MATCH_LIMIT
                    )),
                })

    if not windows:
        return ConfirmSignature(
            scan_start=start, scan_end=end, scan_bound=bound,
            reason=(CONFIRM_NO_UNIQUE_WINDOW if decoded_any
                    else CONFIRM_NO_INSTRUCTIONS),
        )

    best = rank_confirm_windows(windows)[0]
    return ConfirmSignature(
        signature=best["signature"],
        offset=best["offset"],
        scan_start=start,
        scan_end=end,
        scan_bound=bound,
        image_matches=best["image_matches"],
        tokenization=best["tokenization"],
        byte_len=best["byte_len"],
    )


def verify_confirm_signature(signature, func_ea, ownership=None):
    """True when `signature` still matches exactly once inside the function.

    Used to re-check a carried-over signature before it is trusted; kept here
    so the scan-range rule has exactly one implementation.
    """
    start, end, _bound = scan_range_for(func_ea, ownership)
    if start is None or not signature:
        return False
    return len(find_up_to_two(signature, [(start, end)])) == 1
