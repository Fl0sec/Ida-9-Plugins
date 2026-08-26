"""Signature candidate model and finders.

Three resolution modes:
  ENTRY  shortest unique instruction-aligned pattern at a function's start.
  BODY   unique interior pattern; importer resolves the owning function.
  REL    pattern at a caller/xref site; importer reads a signed PC-relative
         displacement to resolve the referenced target (a function OR a global).

The REL machinery is target-agnostic: pass a code-xref collector to anchor a
function, or a data-xref collector to anchor a global. Only the importer-side
validation differs (code target vs mapped-data target).
"""

import ida_funcs
import ida_ua

from .common import BADADDR, ea_str, find_up_to_two
from .disasm import (
    collect_data_xrefs_to,
    collect_far_xrefs_to,
    decode_chunk,
    infer_pc_relative_field,
    pattern_tokens_for_insn,
)


# Tuning. Defaults favour speed on very large DLLs.
MAX_PATTERN_BYTES = 48
GOOD_ENTRY_BYTES = 24
BODY_START_SAMPLES = 3
MAX_XREFS_TO_SEARCH = 24
XREF_EARLY_STOP_AFTER = 6
MAX_EXPORTED_CANDIDATES = 2
MIN_EXACT_BYTES = 6
MIN_SHORT_EXACT_BYTES = 4


class Candidate:
    __slots__ = (
        "mode", "signature", "target_delta", "rel_offset", "rel_size",
        "base_offset", "insn_offset", "byte_len", "wildcards", "exact",
        "score", "origin"
    )

    def __init__(
        self, mode, signature, target_delta=0, rel_offset=0, rel_size=0,
        base_offset=0, insn_offset=0, byte_len=0, wildcards=0, exact=0,
        origin=""
    ):
        self.mode = mode
        self.signature = signature
        self.target_delta = int(target_delta)
        self.rel_offset = int(rel_offset)
        self.rel_size = int(rel_size)
        self.base_offset = int(base_offset)
        self.insn_offset = int(insn_offset)
        self.byte_len = int(byte_len)
        self.wildcards = int(wildcards)
        self.exact = int(exact)
        self.origin = origin

        mode_penalty = {"ENTRY": 0, "REL": 12, "BODY": 18}.get(mode, 25)
        # Length dominates: once a pattern is source-unique, shorter is usually
        # less flaky across versions. Wildcards get only a small penalty.
        self.score = self.byte_len * 100 + self.wildcards * 2 + mode_penalty

    def key(self):
        return (
            self.mode, self.signature, self.target_delta, self.rel_offset,
            self.rel_size, self.base_offset, self.insn_offset
        )


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


def _candidate_min_exact(total_bytes):
    return MIN_SHORT_EXACT_BYTES if total_bytes < 10 else MIN_EXACT_BYTES


def _unique_window_candidate(insns, start_idx, mode, ranges, thresholds):
    if start_idx < 0 or start_idx >= len(insns):
        return None

    tried_ends = set()
    for threshold in thresholds:
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
        if stats["exact"] < _candidate_min_exact(stats["byte_len"]):
            continue

        matches = find_up_to_two(stats["signature"], ranges)
        if len(matches) != 1:
            continue

        return Candidate(
            mode=mode,
            signature=stats["signature"],
            byte_len=stats["byte_len"],
            wildcards=stats["wildcards"],
            exact=stats["exact"],
            origin="%s@%s" % (mode.lower(), ea_str(stats["start_ea"])),
        )

    return None


def find_entry_candidate(func_ea, ranges):
    f = ida_funcs.get_func(func_ea)
    if f is None:
        return None, []

    insns = decode_chunk(f.start_ea, f.end_ea)
    if not insns:
        return None, []

    candidate = _unique_window_candidate(
        insns, 0, "ENTRY", ranges, [10, 14, 18, 24, 32, 40, 48]
    )
    return candidate, insns


def _sample_body_indices(insns):
    n = len(insns)
    if n <= 3:
        return []

    raw = [max(1, n // 4), max(1, n // 2), max(1, (3 * n) // 4)]
    out = []
    for idx in raw:
        idx = min(idx, n - 1)
        if idx not in out and idx != 0:
            out.append(idx)
    return out[:BODY_START_SAMPLES]


def find_body_candidates(insns, ranges):
    out = []
    for idx in _sample_body_indices(insns):
        cand = _unique_window_candidate(
            insns, idx, "BODY", ranges, [10, 14, 18, 24, 32, 40, 48]
        )
        if cand is not None:
            out.append(cand)
    return out


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


def find_rel_candidate_for_xref(xref_ea, target_ea, ranges):
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
        if stats["exact"] < _candidate_min_exact(stats["byte_len"]):
            continue

        rel_offset = (xref_ea - stats["start_ea"]) + rel_off_in_insn
        base_offset = (xref_ea - stats["start_ea"]) + xinsn.size
        insn_offset = xref_ea - stats["start_ea"]

        possibilities.append((
            stats["byte_len"], stats["wildcards"], a, b, stats,
            rel_offset, base_offset, insn_offset
        ))

    possibilities.sort(key=lambda x: (x[0], x[1]))

    for (
        _blen, _wild, _a, _b, stats,
        rel_offset, base_offset, insn_offset
    ) in possibilities:
        matches = find_up_to_two(stats["signature"], ranges)
        if len(matches) != 1:
            continue

        return Candidate(
            mode="REL",
            signature=stats["signature"],
            target_delta=0,
            rel_offset=rel_offset,
            rel_size=rel_size,
            base_offset=base_offset,
            insn_offset=insn_offset,
            byte_len=stats["byte_len"],
            wildcards=stats["wildcards"],
            exact=stats["exact"],
            origin="xref@%s" % ea_str(xref_ea),
        )

    return None


def find_best_rel_candidate(
    target_ea, ranges, xref_collector=collect_far_xrefs_to, skip_self=True
):
    """Best REL Candidate for target_ea across a sampling of its xrefs.

    xref_collector selects the xref kind: code refs for functions, data refs
    for globals. Returns (candidate_or_None, total_xrefs, searched).
    """
    all_refs = xref_collector(target_ea)
    if not all_refs:
        return None, 0, 0

    sampled = _even_sample(all_refs, MAX_XREFS_TO_SEARCH)
    best = None
    searched = 0

    for xref_ea in sampled:
        # Recursive/self xrefs can work but external callers are preferable.
        # Meaningless for globals (owner is never the global), hence skip_self.
        if skip_self:
            owner = ida_funcs.get_func(xref_ea)
            if owner is not None and owner.start_ea == target_ea and len(sampled) > 1:
                continue

        searched += 1
        cand = find_rel_candidate_for_xref(xref_ea, target_ea, ranges)
        if cand is not None and (best is None or cand.score < best.score):
            best = cand

        if (
            best is not None
            and searched >= XREF_EARLY_STOP_AFTER
            and best.byte_len <= 20
        ):
            break

    return best, len(all_refs), searched


def _dedup_and_order(candidates):
    unique = {}
    for c in candidates:
        old = unique.get(c.key())
        if old is None or c.score < old.score:
            unique[c.key()] = c
    return sorted(unique.values(), key=lambda c: c.score)


def _select_two(ordered):
    selected = []
    if ordered:
        selected.append(ordered[0])
        # Backup should ideally be a different resolution mode/origin.
        for c in ordered[1:]:
            if len(selected) >= MAX_EXPORTED_CANDIDATES:
                break
            if c.mode != selected[0].mode or c.origin != selected[0].origin:
                selected.append(c)
    return selected


def choose_function_candidates(func_ea, ranges):
    """Up to two ranked candidates for a function (ENTRY/BODY/REL blend)."""
    entry, entry_insns = find_entry_candidate(func_ea, ranges)
    candidates = []
    if entry is not None:
        candidates.append(entry)

    f = ida_funcs.get_func(func_ea)
    func_size = (f.end_ea - f.start_ea) if f is not None else 0

    entry_is_good = (
        entry is not None
        and entry.byte_len <= GOOD_ENTRY_BYTES
        and entry.exact >= MIN_EXACT_BYTES
        and (entry.wildcards / max(1, entry.byte_len)) <= 0.50
    )

    need_rel = (
        func_size < 12
        or entry is None
        or entry.byte_len > GOOD_ENTRY_BYTES
        or (entry.wildcards / max(1, entry.byte_len)) > 0.40
    )

    total_xrefs = 0
    tested_xrefs = 0
    if need_rel:
        rel, total_xrefs, tested_xrefs = find_best_rel_candidate(
            func_ea, ranges, xref_collector=collect_far_xrefs_to, skip_self=True
        )
        if rel is not None:
            candidates.append(rel)

    if not entry_is_good and entry_insns:
        candidates.extend(find_body_candidates(entry_insns, ranges))

    ordered = _dedup_and_order(candidates)

    # Tiny functions are weak anchors even when source-unique. Prefer a
    # validated caller-side REL anchor and keep the tiny one only as fallback.
    if func_size < 12:
        rel_candidates = [c for c in ordered if c.mode == "REL"]
        if rel_candidates:
            rel_best = min(rel_candidates, key=lambda c: c.score)
            ordered = [rel_best] + [c for c in ordered if c is not rel_best]

    return _select_two(ordered), total_xrefs, tested_xrefs


def choose_global_candidates(global_ea, ranges):
    """Up to two ranked REL candidates for a global via its data xrefs.

    Globals have no instruction body, so only caller-side REL anchors apply.
    Returns ([], total, tested) when the global has no usable code reference.
    """
    best, total_xrefs, tested_xrefs = find_best_rel_candidate(
        global_ea, ranges, xref_collector=collect_data_xrefs_to, skip_self=False
    )
    if best is None:
        return [], total_xrefs, tested_xrefs
    return [best], total_xrefs, tested_xrefs
