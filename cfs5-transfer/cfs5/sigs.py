"""IDA-touching signature finders.

Three resolution modes:
  ENTRY  shortest unique instruction-aligned pattern at a function's start.
  BODY   unique interior pattern; the consumer maps the hit back to the owning
         function (IDA: the containing func; a dumper: the .pdata range).
  REL    pattern at a caller/xref site plus a signed PC-relative displacement
         that resolves the referenced target (a function OR a global).

Every axis is searched **independently and unconditionally**: a function with a
perfectly good prologue still gets a caller-side REL anchor, because the two
fail for unrelated reasons. Scoring, deduplication, ranking and the diversity
policy live in `cfs5/policy.py`, which is IDA-free and unit tested.

The REL machinery is target-agnostic: pass a code-xref collector to anchor a
function, or a data-xref collector to anchor a global.
"""

import ida_funcs
import ida_ua

from .common import find_up_to_two
from .disasm import (
    collect_data_xrefs_to,
    collect_far_xrefs_to,
    decode_chunk,
    infer_pc_relative_field,
    pattern_tokens_for_insn,
)
from .policy import (
    MAX_PATTERN_BYTES,
    MAX_XREFS_TO_SEARCH,
    XREF_EARLY_STOP_AFTER,
    AXIS_BODY,
    AXIS_ENTRY,
    AXIS_EXTERNAL_REL,
    Candidate,
    ORIGIN_DATA_REF,
    ORIGIN_ENTRY,
    ORIGIN_EXTERNAL_CALL,
    ORIGIN_SELF_CALL,
    body_origin_for_position,
    candidate_min_exact,
    coverage_for,
    primary_chunk_limit,
    select_function_candidates,
    select_global_candidates,
)

# Window lengths tried, shortest first, until one is source-unique.
_WINDOW_THRESHOLDS = [10, 14, 18, 24, 32, 40, 48]


def _window_stats(insns, start_idx, end_idx):
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


def _unique_window(insns, start_idx, ranges):
    """Shortest source-unique window starting at start_idx, or None."""
    if start_idx < 0 or start_idx >= len(insns):
        return None

    tried_ends = set()
    for threshold in _WINDOW_THRESHOLDS:
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

        stats = _window_stats(insns, start_idx, end_idx)
        if stats is None:
            continue
        if stats["exact"] < candidate_min_exact(stats["byte_len"]):
            continue

        if len(find_up_to_two(stats["signature"], ranges)) == 1:
            return stats

    return None


def _func_extent(func_ea):
    f = ida_funcs.get_func(func_ea)
    if f is None:
        return None, 0, 0
    return f, f.start_ea, f.end_ea - f.start_ea


# ---------------------------------------------------------------------------
# ENTRY
# ---------------------------------------------------------------------------

def find_entry_candidate(func_ea, ranges):
    """(Candidate or None, decoded instruction list) for a function's start."""
    f, start_ea, func_size = _func_extent(func_ea)
    if f is None:
        return None, []

    insns = decode_chunk(f.start_ea, f.end_ea)
    if not insns:
        return None, []

    stats = _unique_window(insns, 0, ranges)
    if stats is None:
        return None, insns

    return Candidate(
        mode="ENTRY",
        signature=stats["signature"],
        origin=ORIGIN_ENTRY,
        byte_len=stats["byte_len"],
        wildcards=stats["wildcards"],
        exact=stats["exact"],
        anchor_ea=stats["start_ea"],
        func_ea=start_ea,
        func_size=func_size,
    ), insns


# ---------------------------------------------------------------------------
# BODY
# ---------------------------------------------------------------------------

def _sample_body_indices(insns):
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


def find_body_candidates(insns, ranges, func_ea, func_size, ownership=None):
    """Unique interior patterns from structurally distinct regions.

    `ownership` is an image.BodyOwnership (or None): it both biases sampling
    toward the function's own .pdata chunk and labels whether a non-IDA
    consumer could recover func_ea from the resulting hit.
    """
    out = []
    limit = primary_chunk_limit(insns, func_ea, ownership)
    indices = _sample_body_indices(insns[:limit])
    for position, idx in enumerate(indices):
        stats = _unique_window(insns, idx, ranges)
        if stats is None:
            continue
        kind = (
            ownership.classify(func_ea, stats["start_ea"])
            if ownership is not None else "pdata"
        )
        out.append(Candidate(
            ownership=kind,
            mode="BODY",
            signature=stats["signature"],
            origin=body_origin_for_position(position, len(indices)),
            byte_len=stats["byte_len"],
            wildcards=stats["wildcards"],
            exact=stats["exact"],
            anchor_ea=stats["start_ea"],
            func_ea=func_ea,
            func_size=func_size,
            body_offset=stats["start_ea"] - func_ea,
        ))
    return out


# ---------------------------------------------------------------------------
# REL
# ---------------------------------------------------------------------------

def _even_sample(values, limit):
    if len(values) <= limit:
        return list(values)
    if limit <= 1:
        return [values[len(values) // 2]]

    result = []
    n = len(values)
    for i in range(limit):
        idx = round(i * (n - 1) / (limit - 1))
        v = values[idx]
        if v not in result:
            result.append(v)
    return result


def _xref_window_specs(xidx, n):
    specs = [
        (xidx, xidx + 1),
        (xidx - 1, xidx + 1),
        (xidx, xidx + 2),
        (xidx - 1, xidx + 2),
        (xidx - 2, xidx + 2),
        (xidx - 1, xidx + 3),
        (xidx - 2, xidx + 3),
        (xidx - 3, xidx + 4),
    ]
    clean = []
    seen = set()
    for a, b in specs:
        a = max(0, a)
        b = min(n, b)
        if a >= b or not (a <= xidx < b):
            continue
        key = (a, b)
        if key not in seen:
            seen.add(key)
            clean.append(key)
    return clean


def find_rel_candidate_for_xref(
    xref_ea, target_ea, ranges, origin, func_ea=0, func_size=0, is_data=False
):
    """Build a REL Candidate anchored at xref_ea that resolves to target_ea."""
    chunk = ida_funcs.get_fchunk(xref_ea)
    if chunk is None:
        return None

    xinsn = ida_ua.insn_t()
    if ida_ua.decode_insn(xinsn, xref_ea) <= 0 or xinsn.size <= 0:
        return None

    rel = infer_pc_relative_field(xinsn, target_ea)
    if rel is None:
        return None
    rel_off_in_insn, rel_size = rel

    insns = decode_chunk(chunk.start_ea, chunk.end_ea)
    if not insns:
        return None

    xidx = None
    for i, item in enumerate(insns):
        if item["ea"] == xref_ea:
            xidx = i
            break
    if xidx is None:
        return None

    # Force only the validated relative field to be wildcarded in the xref insn.
    insns[xidx]["tokens"] = pattern_tokens_for_insn(
        xinsn, force_rel=(rel_off_in_insn, rel_size)
    )
    insns[xidx]["insn"] = xinsn

    possibilities = []
    for a, b in _xref_window_specs(xidx, len(insns)):
        stats = _window_stats(insns, a, b)
        if stats is None or stats["byte_len"] > MAX_PATTERN_BYTES:
            continue
        if stats["exact"] < candidate_min_exact(stats["byte_len"]):
            continue
        possibilities.append(stats)

    possibilities.sort(key=lambda s: (s["byte_len"], s["wildcards"]))

    for stats in possibilities:
        if len(find_up_to_two(stats["signature"], ranges)) != 1:
            continue

        insn_offset = xref_ea - stats["start_ea"]
        return Candidate(
            mode="REL",
            signature=stats["signature"],
            origin=origin,
            byte_len=stats["byte_len"],
            wildcards=stats["wildcards"],
            exact=stats["exact"],
            anchor_ea=stats["start_ea"],
            func_ea=func_ea,
            func_size=func_size,
            target_ea=target_ea,
            is_data=is_data,
            rel_offset=insn_offset + rel_off_in_insn,
            rel_size=rel_size,
            # End of the *whole* instruction, trailing immediates included.
            base_offset=insn_offset + xinsn.size,
            insn_offset=insn_offset,
        )

    return None


def collect_rel_candidates(
    target_ea, ranges, xref_collector, is_data, func_ea=0, func_size=0
):
    """REL Candidates from a bounded, evenly spread sample of target's xrefs.

    Returns (candidates, total_xrefs, searched). Self-referencing anchors are
    kept but tagged ORIGIN_SELF_CALL so the policy can prefer external callers.
    """
    all_refs = xref_collector(target_ea)
    if not all_refs:
        return [], 0, 0

    sampled = _even_sample(all_refs, MAX_XREFS_TO_SEARCH)
    found = []
    searched = 0

    for xref_ea in sampled:
        searched += 1

        if is_data:
            origin = ORIGIN_DATA_REF
        else:
            owner = ida_funcs.get_func(xref_ea)
            origin = (
                ORIGIN_SELF_CALL
                if owner is not None and owner.start_ea == target_ea
                else ORIGIN_EXTERNAL_CALL
            )

        try:
            cand = find_rel_candidate_for_xref(
                xref_ea, target_ea, ranges, origin,
                func_ea=func_ea, func_size=func_size, is_data=is_data,
            )
        except Exception:
            # One odd instruction must not abort the whole item.
            continue

        if cand is not None:
            found.append(cand)

        external = [c for c in found if c.origin != ORIGIN_SELF_CALL]
        if (
            external
            and searched >= XREF_EARLY_STOP_AFTER
            and min(c.byte_len for c in external) <= 20
        ):
            break

    return found, len(all_refs), searched


# ---------------------------------------------------------------------------
# Item-level policy entry points
# ---------------------------------------------------------------------------

def choose_function_candidates(func_ea, ranges, ownership=None):
    """Ranked, structurally diverse candidates for a function.

    Returns (candidates, coverage, total_xrefs, searched_xrefs).
    """
    entry, insns = find_entry_candidate(func_ea, ranges)
    _f, start_ea, func_size = _func_extent(func_ea)

    candidates = []
    attempted = {AXIS_ENTRY}
    if entry is not None:
        candidates.append(entry)

    # Unconditional: a good prologue says nothing about whether a caller-side
    # anchor will survive the next build, and vice versa.
    rels, total_xrefs, searched = collect_rel_candidates(
        func_ea, ranges, collect_far_xrefs_to, is_data=False,
        func_ea=start_ea, func_size=func_size,
    )
    attempted.add(AXIS_EXTERNAL_REL)
    candidates.extend(rels)

    if insns:
        attempted.add(AXIS_BODY)
        candidates.extend(
            find_body_candidates(
                insns, ranges, start_ea, func_size, ownership=ownership
            )
        )

    selected = select_function_candidates(candidates)
    return selected, coverage_for(selected, attempted), total_xrefs, searched


def choose_global_candidates(global_ea, ranges):
    """Ranked REL candidates for a global via distinct data-xref anchor sites.

    Globals have no instruction body, so REL is the only applicable axis.
    Returns (candidates, coverage, total_xrefs, searched_xrefs).
    """
    rels, total_xrefs, searched = collect_rel_candidates(
        global_ea, ranges, collect_data_xrefs_to, is_data=True,
        func_ea=0, func_size=0,
    )
    selected = select_global_candidates(rels)
    coverage = coverage_for(selected, {AXIS_EXTERNAL_REL})
    return selected, coverage, total_xrefs, searched
