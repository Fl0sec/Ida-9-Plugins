"""Instruction-window growth: the shared primitive under every finder.

Split out of `sigs.py` because `confirm.py` needs the same sampling and growth
rules over a different search space, and importing them from `sigs` made the
two modules mutually dependent. The rules genuinely are one thing -- which
window lengths are considered, and what a window's statistics are -- so they
get one home rather than two copies that drift.

What differs between callers stays a parameter:

* the **search space** -- the whole image for a locating pattern, a single
  function's `.pdata` chain for a confirm signature,
* the **exact-byte floor** -- `policy.candidate_min_exact` for a pattern that
  must survive image-wide, `policy.confirm_min_exact` (none) for one that is
  matched inside an already-resolved function,
* whether the caller wants the **first** unique window or **every** one.
"""

from .common import find_up_to_two
from .policy import MAX_PATTERN_BYTES, candidate_min_exact


# Window lengths tried, shortest first, until one is unique.
WINDOW_THRESHOLDS = [10, 14, 18, 24, 32, 40, 48]


def window_stats(insns, start_idx, end_idx):
    """Token/length statistics for insns[start_idx:end_idx], or None if empty."""
    tokens = []
    for item in insns[start_idx:end_idx]:
        tokens.extend(item["tokens"])

    if not tokens:
        return None

    wild = sum(1 for t in tokens if t == "?")
    return {
        "tokens": tokens,
        "signature": " ".join(tokens),
        "byte_len": len(tokens),
        "wildcards": wild,
        "exact": len(tokens) - wild,
        "start_ea": insns[start_idx]["ea"],
        "end_ea": insns[end_idx - 1]["ea"] + insns[end_idx - 1]["size"],
    }


def window_ladder(insns, start_idx, min_exact=None):
    """Yield window stats at start_idx, shortest first, along the length ladder.

    One implementation so `unique_window` (first hit) and `iter_unique_windows`
    (all hits) cannot drift apart on which lengths they even consider.
    """
    if start_idx < 0 or start_idx >= len(insns):
        return
    if min_exact is None:
        min_exact = candidate_min_exact

    tried_ends = set()
    for threshold in WINDOW_THRESHOLDS:
        total = 0
        end_idx = start_idx
        while end_idx < len(insns) and total < threshold and total < MAX_PATTERN_BYTES:
            total += insns[end_idx]["size"]
            end_idx += 1

        if end_idx <= start_idx:
            continue

        if total > MAX_PATTERN_BYTES:
            while end_idx > start_idx and (
                insns[end_idx - 1]["ea"] + insns[end_idx - 1]["size"]
                - insns[start_idx]["ea"]
            ) > MAX_PATTERN_BYTES:
                end_idx -= 1

        if end_idx <= start_idx or end_idx in tried_ends:
            continue
        tried_ends.add(end_idx)

        stats = window_stats(insns, start_idx, end_idx)
        if stats is None:
            continue
        if stats["exact"] < min_exact(stats["byte_len"]):
            continue
        yield stats


def unique_window(insns, start_idx, ranges, min_exact=None):
    """Shortest window at start_idx that matches `ranges` exactly once, or None."""
    for stats in window_ladder(insns, start_idx, min_exact):
        if len(find_up_to_two(stats["signature"], ranges)) == 1:
            return stats
    return None


def iter_unique_windows(insns, start_idx, ranges, min_exact=None):
    """Every window at start_idx that matches `ranges` exactly once."""
    for stats in window_ladder(insns, start_idx, min_exact):
        if len(find_up_to_two(stats["signature"], ranges)) == 1:
            yield stats


def sample_body_indices(insns):
    """Early/middle/late instruction indices, never the entry instruction."""
    n = len(insns)
    if n <= 3:
        return []

    raw = [max(1, n // 4), max(1, n // 2), max(1, (3 * n) // 4)]
    out = []
    for idx in raw:
        idx = min(idx, n - 1)
        if idx not in out and idx != 0:
            out.append(idx)
    return out
