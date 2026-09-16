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

from . import cfs6
from . import memberscan
from .common import UA_MAXOP, find_up_to_two
from .disasm import (
    collect_data_xrefs_to,
    collect_far_xrefs_to,
    decode_chunk,
    infer_displacement_field,
    infer_pc_relative_field,
    pattern_tokens_for_insn,
)
from .members import decode_at, member_reference_sites, operand_displacement
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
    ORIGIN_HEXRAYS_MEMPTR,
    ORIGIN_SELECTED_OPERAND,
    ORIGIN_SELF_CALL,
    ORIGIN_STROFF_XREF,
    body_origin_for_position,
    candidate_min_exact,
    coverage_for,
    primary_chunk_limit,
    select_function_candidates,
    select_global_candidates,
    select_value_candidates,
    value_coverage,
    value_min_exact,
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


def _unique_window_around(insns, xidx, ranges, min_exact=None):
    """Shortest source-unique window that contains instruction `xidx`.

    Shared by every anchored mode (REL and VALUE): both need the smallest
    pattern that still pins one site, around an instruction whose interesting
    field has already been wildcarded. `min_exact` is the floor to apply --
    REL and VALUE wildcard very different amounts, so they do not share one.
    """
    if min_exact is None:
        min_exact = candidate_min_exact
    possibilities = []
    for a, b in _xref_window_specs(xidx, len(insns)):
        stats = _window_stats(insns, a, b)
        if stats is None or stats["byte_len"] > MAX_PATTERN_BYTES:
            continue
        if stats["exact"] < min_exact(stats["byte_len"]):
            continue
        possibilities.append(stats)

    possibilities.sort(key=lambda s: (s["byte_len"], s["wildcards"]))
    for stats in possibilities:
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
        xinsn, force_wildcard=(rel_off_in_insn, rel_size)
    )
    insns[xidx]["insn"] = xinsn

    stats = _unique_window_around(insns, xidx, ranges)
    if stats is None:
        return None

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
# VALUE -- integers extracted from an instruction field
# ---------------------------------------------------------------------------

def find_value_candidate_for_site(
    site_ea, encoded_value, ranges, origin, op_hint=None, value_adjust=0
):
    """A VALUE Candidate anchored at `site_ea` whose field holds `encoded_value`.

    `encoded_value` is what the instruction must literally encode -- for a
    member, the offset IDA has for the field. The value a consumer reports is
    `encoded_value + value_adjust`, which is how a declaration asks for an
    answer relative to something other than the field's own container.

    The encoded field is located by `infer_displacement_field`, which works
    from the decoder's operand metadata and refuses ambiguity -- so the
    offset, width and operand index written to the file are IDA's answer, not
    a byte search for a matching number. The field itself is then wildcarded
    in the pattern: the whole point is that the value may differ in a later
    build, so a pattern that pinned it would stop matching exactly when the
    answer became interesting.

    `op_hint` is the operand the user actually clicked. When present the
    inferred field must belong to it, otherwise the candidate describes a
    different access than the one that was declared.
    """
    insn = decode_at(site_ea)
    if insn is None:
        return None

    encoded = int(encoded_value)
    field = infer_displacement_field(insn, encoded)
    const_extract = None

    if field is None:
        # No encoded field: the only legitimate reason is an access to offset
        # zero, which encodes nothing at all.
        const_extract = _zero_offset_extract(insn, encoded, op_hint)
        if const_extract is None:
            return None
    elif op_hint is not None and field["operand_index"] != int(op_hint):
        return None

    chunk = ida_funcs.get_fchunk(site_ea)
    if chunk is None:
        return None
    insns = decode_chunk(chunk.start_ea, chunk.end_ea)
    xidx = None
    for i, item in enumerate(insns):
        if item["ea"] == site_ea:
            xidx = i
            break
    if xidx is None:
        return None

    if field is not None:
        # Wildcard exactly the extracted field and nothing else.
        insns[xidx]["tokens"] = pattern_tokens_for_insn(
            insn, force_wildcard=(field["field_offset"], field["field_size"])
        )
        insns[xidx]["insn"] = insn

    stats = _unique_window_around(insns, xidx, ranges, min_exact=value_min_exact)
    if stats is None:
        return None

    insn_offset = site_ea - stats["start_ea"]
    if const_extract is not None:
        extract = dict(const_extract)
        extract["instruction_offset"] = insn_offset
    else:
        extract = {
            "op": cfs6.OP_DISP,
            "instruction_offset": insn_offset,
            "field_offset": insn_offset + field["field_offset"],
            "field_size": field["field_size"],
            "operand_index": field["operand_index"],
            # Displacements are signed: a subobject-relative access is
            # legitimately negative, so the consumer must not read unsigned.
            "signed": True,
        }
    if value_adjust:
        extract["value_adjust"] = int(value_adjust)

    return Candidate(
        mode="VALUE",
        signature=stats["signature"],
        origin=origin,
        byte_len=stats["byte_len"],
        wildcards=stats["wildcards"],
        exact=stats["exact"],
        anchor_ea=stats["start_ea"],
        func_ea=chunk.start_ea,
        func_size=chunk.end_ea - chunk.start_ea,
        insn_offset=insn_offset,
        extract=extract,
        value=encoded + int(value_adjust),
    )


def _zero_offset_extract(insn, encoded, op_hint):
    """CONST recipe for an access to offset zero, or None.

    `mov rax, [rcx]` reaches the field at offset 0 with no encoded
    displacement at all, so there is no field to point a consumer at. The
    recipe is the constant itself -- but only when the instruction really does
    have a register-indirect memory operand with no displacement, which is
    what the caller-supplied or inferred operand is checked for here.
    """
    if encoded != 0:
        return None

    indices = [int(op_hint)] if op_hint is not None else range(UA_MAXOP)
    for i in indices:
        if not 0 <= i < UA_MAXOP:
            continue
        disp, _width = operand_displacement(insn, i)
        if disp == 0 and insn.ops[i].type == ida_ua.o_phrase:
            return {"op": cfs6.OP_CONST, "value": 0, "operand_index": i}
    return None


def choose_member_candidates(ref, ranges, selected_site=None, value_adjust=0,
                             sibling_offsets=None):
    """Ranked VALUE candidates for one structure member.

    Sites come from exactly three producers of a *type-directed* association,
    and a consumer can tell which by the candidate's `origin`:

      * the operand the user explicitly selected when declaring,
      * instructions IDA indexes as struct-offset references to this member,
      * instructions the decompiler resolves to this member (`memberscan`).

    The third exists because IDA 9.0's member xref index misses most accesses
    made through a typed pointer, which is the common case; `cfs5/memberscan.py`
    has the measurements. It is still the decompiler, never the displacement,
    that decides a site belongs to this member -- nothing here accepts an
    instruction merely because it encodes the same number.

    `sibling_offsets` is every member offset of the owning structure. It does
    not widen what is accepted -- only which functions are worth decompiling.
    Without it a common offset like `+0x10` selects tens of thousands of
    functions and the sample never reaches the right ones.

    Returns (candidates, coverage, total_sites, searched_sites).
    """
    sites = []
    seen = set()

    def _add(ea, op_hint, origin):
        ea = int(ea)
        if ea in seen:
            return
        seen.add(ea)
        sites.append((ea, op_hint, origin))

    if selected_site is not None:
        _add(selected_site[0], selected_site[1], ORIGIN_SELECTED_OPERAND)

    # Cheapest first: a stroff site is already IDA-verified and needs no
    # decompilation, so it never costs a pass over the ctree.
    for ea in _even_sample(member_reference_sites(ref), MAX_XREFS_TO_SEARCH):
        _add(ea, None, ORIGIN_STROFF_XREF)

    for ea in memberscan.discover_member_sites(
        ref, exclude=seen, offsets=sibling_offsets
    ):
        _add(ea, None, ORIGIN_HEXRAYS_MEMPTR)

    found = []
    searched = 0
    for site_ea, op_hint, origin in sites:
        searched += 1
        try:
            cand = find_value_candidate_for_site(
                site_ea, ref.byte_offset, ranges, origin,
                op_hint=op_hint, value_adjust=value_adjust,
            )
        except Exception:
            # One odd instruction must not cost the whole member.
            continue
        if cand is not None:
            found.append(cand)

    selected = select_value_candidates(found)
    return selected, value_coverage(selected), len(sites), searched


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
