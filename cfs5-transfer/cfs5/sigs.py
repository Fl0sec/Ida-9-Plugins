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

import ida_bytes
import ida_funcs
import ida_ua

from . import cfs6
from . import confirm
from . import memberscan
from . import leachain
from . import registry
from . import rtti
from . import strloc
from .common import UA_MAXOP, ea_str, find_up_to_n, find_up_to_two, msg
from .disasm import (
    collect_data_xrefs_to,
    collect_far_xrefs_to,
    decode_chunk,
    infer_displacement_field,
    infer_immediate_field,
    infer_pc_relative_field,
    pattern_tokens_for_insn,
    recipe_value,
)
from .members import decode_at, member_reference_sites, operand_displacement
from .policy import (
    CLONE_COUNT_LIMIT,
    MAX_PATTERN_BYTES,
    MAX_UNIQUE_PROBES,
    MAX_XREFS_TO_SEARCH,
    XREF_EARLY_STOP_AFTER,
    AXIS_BODY,
    AXIS_ENTRY,
    AXIS_EXTERNAL_REL,
    AXIS_VTABLE,
    AXIS_STRING_REL,
    Candidate,
    declared_window_specs,
    ENVELOPE_WORTH_PROBES,
    anchored_window_specs,
    FunctionSearch,
    ORIGIN_DATA_REF,
    ORIGIN_ENTRY,
    ORIGIN_EXPLICIT_SITE,
    ORIGIN_EXTERNAL_CALL,
    ORIGIN_HEXRAYS_MEMPTR,
    ORIGIN_SELECTED_OPERAND,
    ORIGIN_RTTI_VTABLE_SLOT,
    ORIGIN_ANCHOR_STRING,
    ORIGIN_SELF_CALL,
    ORIGIN_STROFF_XREF,
    WHY_LOCATOR_MISMATCH,
    WHY_LOCATOR_UNRESOLVED,
    WHY_NO_CONFIRM_SIGNATURE,
    body_origin_for_position,
    candidate_min_exact,
    coverage_for,
    diagnose_function,
    primary_chunk_limit,
    select_function_candidates,
    select_global_candidates,
    select_value_candidates,
    value_coverage,
    value_min_exact,
)
from .windows import (
    sample_body_indices,
    unique_window,
    window_stats,
)

# Why no window around an anchor produced a pattern. Four unrelated situations
# that used to print one sentence. "Nothing was even eligible", "the site is
# genuinely ambiguous", "a unique window exists but is too long to export" and
# "we stopped looking" each need a different response from whoever reads the
# log, and only the last one is a limitation of this code.
WINDOW_BELOW_EXACT_FLOOR = "no_window_cleared_the_exact_byte_floor"
WINDOW_NOT_UNIQUE = "site_is_ambiguous_at_every_window_length"
WINDOW_ABOVE_BYTE_LIMIT = (
    "unique_only_in_a_window_longer_than_%d_bytes" % MAX_PATTERN_BYTES
)
WINDOW_PROBE_LIMIT = "gave_up_after_%d_uniqueness_probes" % MAX_UNIQUE_PROBES


def _unique_window_around(insns, xidx, ranges, min_exact=None, specs=None):
    """(shortest source-unique window containing `xidx`, or None), reason.

    Shared by every anchored mode (REL and VALUE): both need the smallest
    pattern that still pins one site, around an instruction whose interesting
    field has already been wildcarded. `min_exact` is the floor to apply --
    REL and VALUE wildcard very different amounts, so they do not share one.

    `specs` is the set of windows to consider. VALUE passes the byte-bounded
    enumeration; REL keeps its original instruction ladder, because widening it
    would re-pick patterns for every already-exported function -- a large
    unvalidated change to fix a defect that only shows up on short anchors.
    """
    if min_exact is None:
        min_exact = candidate_min_exact
    if specs is None:
        specs = _xref_window_specs(xidx, len(insns))
    if not specs:
        return None, WINDOW_BELOW_EXACT_FLOOR

    possibilities = []
    for a, b in specs:
        stats = window_stats(insns, a, b)
        if stats is None or stats["byte_len"] > MAX_PATTERN_BYTES:
            continue
        if stats["exact"] < min_exact(stats["byte_len"]):
            continue
        possibilities.append(stats)

    if not possibilities:
        return None, WINDOW_BELOW_EXACT_FLOOR

    # Uniqueness is monotone under containment: if a window matches in two
    # places then so does every window inside it, because a shorter pattern
    # matches wherever the longer one does. So one probe of the envelope --
    # the window spanning every candidate, which may itself be too long to
    # export -- either proves the whole site ambiguous or proves a unique
    # window is in there somewhere. That turns the expensive case (a site that
    # cannot be pinned) from one image-wide search per candidate window into
    # exactly one, and upgrades the answer from "we tried and stopped" to a
    # fact.
    # Spending it is only worth it when there are more candidate windows than
    # the envelope probe costs, which is why the modes on the short fixed
    # ladder skip it and keep both their behaviour and their cost unchanged.
    envelope_unique = False
    if len(possibilities) > ENVELOPE_WORTH_PROBES:
        envelope = window_stats(
            insns, min(a for a, _b in specs), max(b for _a, b in specs)
        )
        if envelope is not None:
            if len(find_up_to_two(envelope["signature"], ranges)) != 1:
                return None, WINDOW_NOT_UNIQUE
            envelope_unique = True

    possibilities.sort(key=lambda s: (s["byte_len"], s["wildcards"]))

    probes = 0
    seen_signatures = set()
    for stats in possibilities:
        if stats["signature"] in seen_signatures:
            continue
        seen_signatures.add(stats["signature"])
        if probes >= MAX_UNIQUE_PROBES:
            return None, WINDOW_PROBE_LIMIT
        probes += 1
        if len(find_up_to_two(stats["signature"], ranges)) == 1:
            return stats, None

    # A unique envelope with nothing exportable unique means the evidence
    # exists but only in a pattern longer than a candidate may carry -- a
    # tuning answer (raise MAX_PATTERN_BYTES, or pick a site in a less
    # repetitive function), not an ambiguous site. Without the envelope probe
    # the two are indistinguishable, so say the weaker thing.
    return None, WINDOW_ABOVE_BYTE_LIMIT if envelope_unique else WINDOW_NOT_UNIQUE


def _longest_window_matches(insns, start_idx, ranges):
    """How many places the longest allowed window at start_idx still matches.

    Only ever called once an axis has already failed, so its cost is paid on
    the diagnostic path and never on the happy one. The answer is what tells
    an analyst whether to keep growing the pattern or to stop: a prologue that
    still matches N places at maximum length belongs to a clone family, and no
    longer prefix will ever separate it from its siblings.
    """
    end_idx = start_idx
    total = 0
    while end_idx < len(insns):
        size = insns[end_idx]["size"]
        if total + size > MAX_PATTERN_BYTES:
            break
        total += size
        end_idx += 1

    stats = window_stats(insns, start_idx, end_idx)
    if stats is None:
        return 0
    return len(find_up_to_n(stats["signature"], ranges, CLONE_COUNT_LIMIT))


def _func_extent(func_ea):
    f = ida_funcs.get_func(func_ea)
    if f is None:
        return None, 0, 0
    return f, f.start_ea, f.end_ea - f.start_ea


# ---------------------------------------------------------------------------
# ENTRY
# ---------------------------------------------------------------------------

def find_entry_candidate(func_ea, ranges):
    """(Candidate or None, instructions, match_count) for a function's start.

    `match_count` is 0 unless the search failed, in which case it is how many
    places the longest prologue window still matched -- the clone-family
    signal.
    """
    f, start_ea, func_size = _func_extent(func_ea)
    if f is None:
        return None, [], 0

    insns = decode_chunk(f.start_ea, f.end_ea)
    if not insns:
        return None, [], 0

    stats = unique_window(insns, 0, ranges)
    if stats is None:
        return None, insns, _longest_window_matches(insns, 0, ranges)

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
    ), insns, 0


# ---------------------------------------------------------------------------
# BODY
# ---------------------------------------------------------------------------

def find_body_candidates(insns, ranges, func_ea, func_size, ownership=None):
    """(candidates, near_miss) -- unique interior patterns.

    `ownership` is an image.BodyOwnership (or None): it both biases sampling
    toward the function's own .pdata chunk and labels whether a non-IDA
    consumer could recover func_ea from the resulting hit.

    `near_miss` is advisory only. When sampling is confined to the function's
    .pdata range and finds nothing, the rest of the body is sampled *for
    reporting*: a unique anchor that exists past the range is the difference
    between "this function has no distinguishing bytes" and "its
    distinguishing bytes are somewhere a .pdata consumer cannot follow". The
    first is unsolvable, the second points at a structural anchor. Nothing
    found this way is exported -- an anchor whose owner cannot be recovered
    resolves to nothing.
    """
    out = []
    limit = primary_chunk_limit(insns, func_ea, ownership)
    indices = sample_body_indices(insns[:limit])
    for position, idx in enumerate(indices):
        stats = unique_window(insns, idx, ranges)
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

    near_miss = []
    if not out and limit < len(insns):
        out, near_miss = _sample_whole_body(
            insns, ranges, func_ea, func_size, ownership
        )
    return out, near_miss


def _sample_whole_body(insns, ranges, func_ea, func_size, ownership):
    """(candidates, near_miss) from sampling the entire body.

    Only reached when the .pdata-confined sampling produced nothing. Two
    different things come out of it, and conflating them is what made the
    original failure unreadable:

      * an anchor that still classifies `pdata` is a real candidate the
        confined sampling merely did not land on -- it is exported,
      * an anchor outside the function's own .pdata range is not exportable
        (a consumer could not map a hit back to the function) and is reported
        as a near miss instead.
    """
    candidates, near_miss = [], []
    indices = sample_body_indices(insns)
    for position, idx in enumerate(indices):
        stats = unique_window(insns, idx, ranges)
        if stats is None:
            continue
        kind = (
            ownership.classify(func_ea, stats["start_ea"])
            if ownership is not None else "pdata"
        )
        if kind != "pdata":
            near_miss.append({
                "offset": stats["start_ea"] - func_ea,
                "ea": ea_str(stats["start_ea"]),
                "byte_len": stats["byte_len"],
                "exact": stats["exact"],
                "ownership": kind,
                "signature": stats["signature"],
            })
            continue
        candidates.append(Candidate(
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
    return candidates, near_miss


# ---------------------------------------------------------------------------
# Explicit sites -- evidence the caller located and the exporter verifies
# ---------------------------------------------------------------------------

def find_site_candidate(func_ea, site_ea, ranges, ownership=None):
    """(Candidate or None, reason) for one caller-named site.

    A site is an *address*, and what it means is worked out from the database
    rather than declared, because there are only two things it can honestly
    be:

      * an instruction that references the function -- a `call`, a `jmp` or,
        as with a callback passed to a registrar, a bare `lea`. That becomes a
        REL anchor, with the referenced target re-derived from the decoded
        operand and required to land exactly on `func_ea`.
      * an instruction inside the function -- a BODY anchor at that exact
        position, instead of one of the sampled ones.

    The verification is the point of the whole feature. The caller supplies
    *where to look*; the database still supplies what is there. A site that
    references some other function, or that sits in some other function, is
    refused with a reason rather than exported under this name -- an anchor
    pointing at the wrong target is worse than no anchor at all, because a
    consumer would apply it with full confidence.
    """
    if ida_funcs.get_func(func_ea) is None:
        return None, "%s is not a function" % ea_str(func_ea)

    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, site_ea) <= 0 or insn.size <= 0:
        return None, "%s does not decode as an instruction" % ea_str(site_ea)

    # A reference to the function, whatever instruction form carries it.
    if infer_pc_relative_field(insn, func_ea) is not None:
        _f, start_ea, func_size = _func_extent(func_ea)
        cand = find_rel_candidate_for_xref(
            site_ea, func_ea, ranges, ORIGIN_EXPLICIT_SITE,
            func_ea=start_ea, func_size=func_size, is_data=False,
        )
        if cand is None:
            return None, (
                "%s references the function but no unique pattern could be "
                "built around it" % ea_str(site_ea)
            )
        return cand, None

    owner = ida_funcs.get_func(site_ea)
    if owner is None or owner.start_ea != ida_funcs.get_func(func_ea).start_ea:
        where = (
            "inside %s" % ea_str(owner.start_ea) if owner is not None
            else "outside any function"
        )
        return None, (
            "%s neither references the function nor lies inside it (it is %s)"
            % (ea_str(site_ea), where)
        )

    return _body_candidate_at_site(func_ea, site_ea, ranges, ownership)


def _body_candidate_at_site(func_ea, site_ea, ranges, ownership):
    """A BODY Candidate anchored exactly at `site_ea`, or (None, reason)."""
    f, start_ea, func_size = _func_extent(func_ea)
    insns = decode_chunk(f.start_ea, f.end_ea)
    idx = next((i for i, it in enumerate(insns) if it["ea"] == site_ea), None)
    if idx is None:
        return None, (
            "%s is inside the function but is not an instruction start"
            % ea_str(site_ea)
        )

    stats = unique_window(insns, idx, ranges)
    if stats is None:
        return None, (
            "no unique pattern starts at %s (every window matched elsewhere)"
            % ea_str(site_ea)
        )

    kind = (
        ownership.classify(start_ea, stats["start_ea"])
        if ownership is not None else "pdata"
    )
    if kind != "pdata":
        # Emitting it would be a lie of omission: the file would gain a
        # candidate the consumer that asked for it must skip.
        return None, (
            "the unique pattern at %s sits outside the function's own .pdata "
            "range, so a hit could not be mapped back to the function"
            % ea_str(site_ea)
        )

    return Candidate(
        ownership=kind,
        mode="BODY",
        signature=stats["signature"],
        origin=ORIGIN_EXPLICIT_SITE,
        byte_len=stats["byte_len"],
        wildcards=stats["wildcards"],
        exact=stats["exact"],
        anchor_ea=stats["start_ea"],
        func_ea=start_ea,
        func_size=func_size,
        body_offset=stats["start_ea"] - start_ea,
    ), None


def find_site_candidates(func_ea, site_eas, ranges, ownership=None):
    """(candidates, rejections) for every caller-named site of one function."""
    found, rejected = [], []
    for site_ea in site_eas or ():
        try:
            cand, reason = find_site_candidate(
                func_ea, int(site_ea), ranges, ownership
            )
        except Exception as exc:
            cand, reason = None, "site %s raised: %s" % (ea_str(site_ea), exc)
        if cand is not None:
            found.append(cand)
        else:
            rejected.append({"ea": ea_str(site_ea), "reason": reason})
    return found, rejected


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

    stats, _why = _unique_window_around(insns, xidx, ranges)
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

# Why one site produced no candidate. A caller collects these per site so a
# refusal can say which stage rejected the evidence: "nothing encodes the
# number" and "the pattern was not unique" are completely different problems
# with completely different fixes, and one shared message hides both.
REJECT_NO_DECODE = "site_did_not_decode"
REJECT_NO_FIELD = "no_operand_encodes_the_value"
REJECT_WRONG_OPERAND = "value_is_not_in_the_declared_operand"
REJECT_NO_FUNCTION = "site_is_not_inside_a_function"
# The extraction recipe would not reproduce the declared value. Almost always a
# sign-extended immediate asserted at the operand's width (`0xFFFFFFFF`) where
# the recipe yields the signed reading (`-1`) -- assert the latter.
REJECT_RECIPE_DISAGREES = "extraction_recipe_reproduces_a_different_value"
REJECT_SITE_NOT_IN_CHUNK = "site_is_not_an_instruction_start"
# Fallback only. The window search reports which of its three outcomes fired
# (`WINDOW_*` below) and that reason is used in preference to this one.
REJECT_NO_UNIQUE_WINDOW = "no_unique_pattern_around_the_site"


def find_value_candidate_for_site(
    site_ea, encoded_value, ranges, origin, op_hint=None, value_adjust=0,
    reasons=None, window_start_ea=None, access_width=None, alignment=1,
):
    """A VALUE Candidate anchored at `site_ea` whose field holds `encoded_value`.

    `encoded_value` is what the instruction must literally encode -- for a
    member, the offset IDA has for the field *minus* any `value_adjust`; see
    `declare.Declaration.site_value`, which is the one place that arithmetic
    lives. The value a consumer reports is
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
    def _reject(reason):
        if reasons is not None:
            reasons[int(site_ea)] = reason
        return None

    insn = decode_at(site_ea)
    if insn is None:
        return _reject(REJECT_NO_DECODE)

    encoded = int(encoded_value)
    const_extract = None

    # A displacement first: it is what a member offset is, and it is the
    # stricter of the two inferences. An immediate second, because that is how
    # a stride or a size is normally encoded (`add rax, 0x30`).
    field = infer_displacement_field(insn, encoded)
    field_op = cfs6.OP_DISP
    if field is None:
        field = infer_immediate_field(insn, encoded)
        field_op = cfs6.OP_IMM

    if field is None:
        # No encoded field: the only legitimate reason is an access to offset
        # zero, which encodes nothing at all.
        const_extract = _zero_offset_extract(insn, encoded, op_hint)
        if const_extract is None:
            return _reject(REJECT_NO_FIELD)
    elif op_hint is not None and field["operand_index"] != int(op_hint):
        return _reject(REJECT_WRONG_OPERAND)

    chunk = ida_funcs.get_fchunk(site_ea)
    if chunk is None:
        return _reject(REJECT_NO_FUNCTION)
    insns = decode_chunk(chunk.start_ea, chunk.end_ea)
    xidx = None
    for i, item in enumerate(insns):
        if item["ea"] == site_ea:
            xidx = i
            break
    if xidx is None:
        return _reject(REJECT_SITE_NOT_IN_CHUNK)

    specs = None
    if window_start_ea is not None:
        window_start_ea = int(window_start_ea)
        if not (chunk.start_ea <= window_start_ea <= site_ea < chunk.end_ea):
            return _reject("window_start_is_not_in_the_same_function")
        start_idx = next(
            (i for i, item in enumerate(insns) if item["ea"] == window_start_ea),
            None,
        )
        if start_idx is None:
            return _reject("window_start_is_not_an_instruction_start")
        specs = declared_window_specs(insns, start_idx, xidx)

    # The recipe this candidate will publish has to produce the number the
    # candidate claims. Checked here, before any of the expensive window work:
    # `source.expected_value` comes from the decoder's operand and the consumer
    # computes from the raw bytes, so the two can disagree -- and a
    # disagreement would surface only as permanent phantom drift on the
    # consumer's side, blamed on the image rather than on the export.
    if field is not None and recipe_value(insn, field) != encoded:
        return _reject(REJECT_RECIPE_DISAGREES)

    if field is not None:
        # Wildcard exactly the extracted field and nothing else.
        insns[xidx]["tokens"] = pattern_tokens_for_insn(
            insn, force_wildcard=(field["field_offset"], field["field_size"])
        )
        insns[xidx]["insn"] = insn

    stats, why = _unique_window_around(
        insns, xidx, ranges, min_exact=value_min_exact,
        specs=specs or anchored_window_specs(insns, xidx),
    )
    if stats is None:
        return _reject(why or REJECT_NO_UNIQUE_WINDOW)

    insn_offset = site_ea - stats["start_ea"]
    if const_extract is not None:
        extract = dict(const_extract)
        extract["instruction_offset"] = insn_offset
    else:
        extract = {
            "op": field_op,
            "instruction_offset": insn_offset,
            "field_offset": insn_offset + field["field_offset"],
            "field_size": field["field_size"],
            "operand_index": field["operand_index"],
            # A displacement is always signed -- a subobject-relative access is
            # legitimately negative, so the consumer must not read unsigned. An
            # immediate reports what it actually is: a stride is a magnitude,
            # and reading 0x80 as -128 would be wrong.
            "signed": field.get("signed", True),
        }
        if access_width is not None:
            extract["op"] = cfs6.OP_DISP_PLUS_WIDTH
            extract["access_width"] = int(access_width)
            extract["alignment"] = int(alignment)
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
        value=cfs6.evaluate_value_recipe(encoded, extract),
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


def choose_value_candidates(encoded_value, ranges, selected_sites=(),
                            ref=None, allow_scan=True, value_adjust=0,
                            sibling_offsets=None, reasons=None,
                            site_options=None, extent_value=None):
    """Ranked VALUE candidates for one derived value.

    `encoded_value` is the number the *instruction* must encode, which for a
    non-zero `value_adjust` is not the value that gets exported. Callers must
    go through `declare.Declaration.site_value` rather than passing the IDA
    member offset directly.

    Sites come from exactly three producers of a *type-directed* association,
    and a consumer can tell which by the candidate's `origin`:

      * the operands the caller explicitly selected when declaring,
      * instructions IDA indexes as struct-offset references to this member,
      * instructions the decompiler resolves to this member (`memberscan`).

    The last two need `ref` -- a live IDA member. A semantic with no backing
    field (a stride constant) has no type-directed producer at all, so it
    passes `ref=None` and gets exactly the sites it named. Searching for other
    instructions encoding the same number is *not* a fallback: numeric
    equality does not prove two instructions mean the same thing, and a false
    candidate is worse than a missing one because agreement reads as proof.

    `allow_scan=False` keeps the caller's sites and skips discovery entirely.
    Automatic discovery decompiles, so a caller that already knows where the
    evidence is should not pay for it -- and gets a deterministic export.

    `sibling_offsets` is every member offset of the owning structure. It does
    not widen what is accepted -- only which functions are worth decompiling.
    Without it a common offset like `+0x10` selects tens of thousands of
    functions and the sample never reaches the right ones.

    `reasons` is an optional dict filled with `{site_ea: REJECT_*}` for every
    site that produced nothing, so a caller can report *why* rather than only
    that it found nothing.

    Returns (candidates, coverage, total_sites, searched_sites).
    """
    sites = []
    seen = set()

    site_options = site_options or {}

    def _add(ea, op_hint, origin):
        ea = int(ea)
        if ea in seen:
            return
        seen.add(ea)
        sites.append((ea, op_hint, origin))

    for site_ea, site_op in selected_sites or ():
        _add(site_ea, site_op, ORIGIN_SELECTED_OPERAND)

    if ref is not None and allow_scan:
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
            options = site_options.get((int(site_ea), int(op_hint)), {}) \
                if op_hint is not None else {}
            actual_encoded = encoded_value
            if extent_value is not None:
                insn = decode_at(site_ea)
                if insn is None or op_hint is None:
                    if reasons is not None:
                        reasons[int(site_ea)] = REJECT_NO_DECODE
                    continue
                actual_encoded, _width = operand_displacement(insn, int(op_hint))
                if actual_encoded is None:
                    if reasons is not None:
                        reasons[int(site_ea)] = REJECT_NO_FIELD
                    continue
                access_width = int(options.get("access_width", 0))
                alignment = int(options.get("alignment", 1))
                produced = cfs6.evaluate_value_recipe(actual_encoded, {
                    "op": cfs6.OP_DISP_PLUS_WIDTH,
                    "access_width": access_width,
                    "alignment": alignment,
                })
                if access_width <= 0 or produced != int(extent_value):
                    if reasons is not None:
                        reasons[int(site_ea)] = REJECT_RECIPE_DISAGREES
                    continue
            cand = find_value_candidate_for_site(
                site_ea, actual_encoded, ranges, origin,
                op_hint=op_hint, value_adjust=value_adjust, reasons=reasons,
                window_start_ea=options.get("window_start_ea"),
                access_width=(options.get("access_width")
                              if extent_value is not None else None),
                alignment=options.get("alignment", 1),
            )
        except Exception as exc:
            # One odd instruction must not cost the whole member -- but say so,
            # or an exception here is indistinguishable from a clean refusal.
            if reasons is not None:
                reasons[int(site_ea)] = "exception: %s" % exc
            continue
        if cand is not None:
            found.append(cand)

    selected = select_value_candidates(found)
    return selected, value_coverage(selected), len(sites), searched


def choose_member_candidates(ref, ranges, selected_sites=(), value_adjust=0,
                             sibling_offsets=None, allow_scan=True,
                             reasons=None):
    """VALUE candidates for a structure member, whose value IDA supplies.

    IDA supplies the value a consumer must *report*; what the instruction
    encodes is that minus `value_adjust`, which is what the site search needs.
    """
    return choose_value_candidates(
        ref.byte_offset - int(value_adjust), ranges,
        selected_sites=selected_sites, ref=ref,
        allow_scan=allow_scan, value_adjust=value_adjust,
        sibling_offsets=sibling_offsets, reasons=reasons,
    )


def find_patch_candidate(decl, ranges):
    """A unique SITE candidate after validating opcode and instruction bounds."""
    insn = decode_at(decl.ea)
    if insn is None or (insn.get_canon_mnem() or "").lower() != decl.expected_instruction:
        return None, "declared instruction does not match"
    expected = bytes.fromhex(decl.expected_bytes)
    raw = ida_bytes.get_bytes(decl.ea, decl.patch_size)
    if raw is None or len(raw) != decl.patch_size or not raw.startswith(expected):
        return None, "declared opcode bytes or patch span do not match"
    if decl.patch_size < insn.size:
        return None, "patch_size cuts through the declared instruction"
    chunk = ida_funcs.get_fchunk(decl.ea)
    if chunk is None:
        return None, "patch site is not inside a function"
    insns = decode_chunk(chunk.start_ea, chunk.end_ea)
    xidx = next((i for i, item in enumerate(insns) if item["ea"] == decl.ea), None)
    if xidx is None:
        return None, "patch site is not an instruction start"
    stats, reason = _unique_window_around(
        insns, xidx, ranges, min_exact=candidate_min_exact,
        specs=anchored_window_specs(insns, xidx),
    )
    if stats is None:
        return None, reason
    return Candidate(
        mode=cfs6.MODE_SITE, signature=stats["signature"],
        origin=cfs6.ORIGIN_DECLARED_PATCH_SITE,
        byte_len=stats["byte_len"], wildcards=stats["wildcards"],
        exact=stats["exact"], anchor_ea=stats["start_ea"],
        func_ea=chunk.start_ea, func_size=chunk.end_ea - chunk.start_ea,
        insn_offset=decl.ea - stats["start_ea"],
    ), None


def choose_lea_scale_chain_candidate(decl, ranges, reasons=None):
    """One decoder-validated compound stride candidate."""
    steps = decl.recipe.get("steps", ())
    decoded = []
    chunk = None
    for step in steps:
        ea = int(step["ea"])
        op_index = int(step["op"])
        insn = decode_at(ea)
        if insn is None or (insn.get_canon_mnem() or "").lower() != "lea":
            if reasons is not None:
                reasons[ea] = "LEA_SCALE_CHAIN step is not a LEA"
            return [], value_coverage([]), len(steps), len(decoded) + 1
        if not 0 <= op_index < UA_MAXOP or insn.ops[op_index].type not in (
            ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ,
        ):
            if reasons is not None:
                reasons[ea] = "LEA_SCALE_CHAIN operand is not the memory source"
            return [], value_coverage([]), len(steps), len(decoded) + 1
        current = ida_funcs.get_fchunk(ea)
        if current is None or (chunk is not None and current.start_ea != chunk.start_ea):
            if reasons is not None:
                reasons[ea] = "LEA_SCALE_CHAIN steps are not in one function"
            return [], value_coverage([]), len(steps), len(decoded) + 1
        chunk = current
        raw = ida_bytes.get_bytes(ea, insn.size)
        try:
            decoded.append(leachain.decode_lea(raw))
        except leachain.LeaChainError as exc:
            if reasons is not None:
                reasons[ea] = str(exc)
            return [], value_coverage([]), len(steps), len(decoded)

    try:
        stride = leachain.fold_coefficients(decoded)
    except leachain.LeaChainError as exc:
        if reasons is not None:
            reasons[int(steps[0]["ea"])] = str(exc)
        return [], value_coverage([]), len(steps), len(steps)
    if stride != int(decl.asserted_value):
        if reasons is not None:
            reasons[int(steps[0]["ea"])] = REJECT_RECIPE_DISAGREES
        return [], value_coverage([]), len(steps), len(steps)

    insns = decode_chunk(chunk.start_ea, chunk.end_ea)
    indices = []
    for step in steps:
        idx = next((i for i, item in enumerate(insns)
                    if item["ea"] == int(step["ea"])), None)
        if idx is None:
            return [], value_coverage([]), len(steps), len(steps)
        indices.append(idx)
    specs = declared_window_specs(insns, indices[0], indices[-1])
    stats, why = _unique_window_around(
        insns, indices[-1], ranges, min_exact=value_min_exact, specs=specs,
    )
    if stats is None:
        if reasons is not None:
            reasons[int(steps[0]["ea"])] = why
        return [], value_coverage([]), len(steps), len(steps)

    extract_steps = []
    for step, info in zip(steps, decoded):
        extract_steps.append({
            "instruction_offset": int(step["ea"]) - stats["start_ea"],
            "instruction_size": decode_at(int(step["ea"])).size,
            "operand_index": int(step["op"]),
        })
    cand = Candidate(
        mode="VALUE", signature=stats["signature"],
        origin=ORIGIN_SELECTED_OPERAND, byte_len=stats["byte_len"],
        wildcards=stats["wildcards"], exact=stats["exact"],
        anchor_ea=stats["start_ea"], func_ea=chunk.start_ea,
        func_size=chunk.end_ea - chunk.start_ea,
        extract={"op": cfs6.OP_LEA_SCALE_CHAIN, "steps": extract_steps},
        value=stride,
    )
    return [cand], value_coverage([cand]), len(steps), len(steps)


# ---------------------------------------------------------------------------
# Item-level policy entry points
# ---------------------------------------------------------------------------

def find_vtable_candidate(func_ea, ranges, locator, ownership=None):
    """(Candidate or None, failure or None) for a declared vtable locator.

    Three things must hold before anything is exported, and each is checked
    against the database rather than taken on the caller's word:

    1. the class resolves to exactly one vtable (an ambiguous subobject is
       refused, not guessed),
    2. the declared slot really holds *this* function -- a wrong slot number is
       caught here, while the caller is still looking at it, instead of
       becoming a locator that silently resolves elsewhere,
    3. a confirm signature can be built over the range a consumer will scan.

    The confirm signature is what keeps (2) true on a later build: the slot
    could be renumbered, and then only the bytes can tell.
    """
    type_name = locator.get("type")
    slot = int(locator.get("slot", -1))
    subobject = locator.get("subobject_offset")

    try:
        vtable = rtti.find_vtable(type_name, subobject)
    except rtti.RttiError as exc:
        return None, {"reason": WHY_LOCATOR_UNRESOLVED, "detail": str(exc)}
    except Exception as exc:
        return None, {"reason": WHY_LOCATOR_UNRESOLVED,
                      "detail": "RTTI lookup failed: %s" % exc}

    try:
        slot_func, _slot_ea = rtti.read_slot(vtable, slot)
    except rtti.RttiError as exc:
        return None, {"reason": WHY_LOCATOR_MISMATCH, "detail": str(exc)}
    if slot_func != func_ea:
        return None, {
            "reason": WHY_LOCATOR_MISMATCH,
            "detail": "%s slot %d holds %s, not %s" % (
                vtable.type_descriptor, slot, ea_str(slot_func), ea_str(func_ea)
            ),
        }

    sig = confirm.build_confirm_signature(func_ea, ownership, ranges)
    if not sig:
        return None, {
            "reason": WHY_NO_CONFIRM_SIGNATURE,
            "detail": "the vtable slot resolves, but no window inside the "
                      "function is unique over its scan range (%s), so a "
                      "consumer could not check the slot still holds it"
                      % sig.reason,
        }

    _f, start_ea, func_size = _func_extent(func_ea)
    return Candidate(
        mode=cfs6.MODE_VTABLE,
        signature=sig.signature,
        origin=ORIGIN_RTTI_VTABLE_SLOT,
        byte_len=sig.byte_len,
        wildcards=sig.signature.count("?"),
        exact=sig.byte_len - sig.signature.count("?"),
        anchor_ea=func_ea + sig.offset,
        func_ea=start_ea or func_ea,
        func_size=func_size,
        target_ea=vtable.ea,
        locator={
            "type_descriptor": vtable.type_descriptor,
            "subobject_offset": vtable.subobject_offset,
            "slot": slot,
            "confirm_offset": sig.offset,
            "function_size": func_size,
            "scan_bound": sig.scan_bound,
            "tokenization": sig.tokenization,
            "image_matches": sig.image_matches,
        },
    ), None


def find_string_rel_candidate(func_ea, ranges, locator, ownership=None):
    """(Candidate or None, failure) for a declared unique anchor string."""
    text = locator.get("string", "")
    try:
        evidence = strloc.resolve_anchor_string(text, ownership)
    except strloc.StringLocatorError as exc:
        return None, {"reason": WHY_LOCATOR_UNRESOLVED, "detail": str(exc)}
    except Exception as exc:
        return None, {"reason": WHY_LOCATOR_UNRESOLVED,
                      "detail": "string locator failed: %s" % exc}

    if evidence["function_ea"] != func_ea:
        return None, {
            "reason": WHY_LOCATOR_MISMATCH,
            "detail": "anchor string %r resolves to %s, not %s" % (
                text, ea_str(evidence["function_ea"]), ea_str(func_ea)
            ),
        }

    sig = confirm.build_confirm_signature(func_ea, ownership, ranges)
    if not sig:
        return None, {
            "reason": WHY_NO_CONFIRM_SIGNATURE,
            "detail": "the string locator resolves, but no window inside the "
                      "function is unique over its scan range (%s)" % sig.reason,
        }

    _f, start_ea, func_size = _func_extent(func_ea)
    return Candidate(
        mode=cfs6.MODE_STRING_REL,
        signature=sig.signature,
        origin=ORIGIN_ANCHOR_STRING,
        byte_len=sig.byte_len,
        wildcards=sig.signature.count("?"),
        exact=sig.byte_len - sig.signature.count("?"),
        anchor_ea=func_ea + sig.offset,
        func_ea=start_ea or func_ea,
        func_size=func_size,
        locator={
            "string": text,
            "string_match": cfs6.STRING_MATCH_NUL_EXACT,
            "window_bytes": strloc.WINDOW_BYTES,
            "window_bound": cfs6.WINDOW_BOUND_PDATA_CHUNK,
            "confirm_offset": sig.offset,
            "function_size": func_size,
            "scan_bound": sig.scan_bound,
            "tokenization": sig.tokenization,
            "image_matches": sig.image_matches,
        },
        locator_source=evidence,
    ), None


def choose_function_candidates(func_ea, ranges, ownership=None, sites=(),
                               locators=()):
    """Ranked, structurally diverse candidates for a function.

    `sites` are addresses the caller located itself. They are verified against
    the database and, when they hold up, pinned into the result -- scoring is
    a guess about the next build and must not discard evidence that was
    supplied deliberately.

    `locators` are structural declarations (a vtable slot). They are verified
    the same way and pinned for the same reason, and they are the only axis
    that can cover a function whose prologue, callers and body all fail.

    Returns a FunctionSearch.
    """
    entry, insns, entry_matches = find_entry_candidate(func_ea, ranges)
    _f, start_ea, func_size = _func_extent(func_ea)

    pinned, site_rejections = find_site_candidates(
        start_ea or func_ea, sites, ranges, ownership
    )
    for bad in site_rejections:
        msg("SITE_REJECTED %s: %s" % (bad["ea"], bad["reason"]))

    candidates = []
    attempted = {AXIS_ENTRY}
    if entry is not None:
        candidates.append(entry)

    # A declared locator is pinned like an explicit site: the caller asserted
    # it, and the exporter's job is to verify the claim, not to let scoring
    # rank it out of the file.
    vtable_failure = None
    string_rel_failure = None
    for locator in locators or ():
        kind = locator.get("kind")
        if kind == registry.LOCATOR_VTABLE:
            attempted.add(AXIS_VTABLE)
            cand, failure = find_vtable_candidate(
                start_ea or func_ea, ranges, locator, ownership
            )
        elif kind == registry.LOCATOR_ANCHOR_STRING:
            attempted.add(AXIS_STRING_REL)
            cand, failure = find_string_rel_candidate(
                start_ea or func_ea, ranges, locator, ownership
            )
        else:
            continue
        if cand is not None:
            pinned.append(cand)
        else:
            if kind == registry.LOCATOR_VTABLE:
                vtable_failure = failure
            else:
                string_rel_failure = failure
            msg("LOCATOR_REJECTED %s slot %s: %s"
                % (locator.get("type", locator.get("string")),
                   locator.get("slot", "-"),
                   failure.get("detail", "")))

    # Unconditional: a good prologue says nothing about whether a caller-side
    # anchor will survive the next build, and vice versa.
    rels, total_xrefs, searched = collect_rel_candidates(
        func_ea, ranges, collect_far_xrefs_to, is_data=False,
        func_ea=start_ea, func_size=func_size,
    )
    attempted.add(AXIS_EXTERNAL_REL)
    candidates.extend(rels)

    body_near_miss = []
    if insns:
        attempted.add(AXIS_BODY)
        bodies, body_near_miss = find_body_candidates(
            insns, ranges, start_ea, func_size, ownership=ownership
        )
        candidates.extend(bodies)

    selected = select_function_candidates(candidates, pinned=pinned)
    coverage = coverage_for(selected, attempted)

    # Only when nothing called it: the answer distinguishes "unreferenced" from
    # "referenced by an instruction that takes its address", which are very
    # different problems to go and solve.
    data_xrefs = (
        len(collect_data_xrefs_to(start_ea or func_ea)) if not total_xrefs else 0
    )

    return FunctionSearch(
        candidates=selected,
        coverage=coverage,
        total_xrefs=total_xrefs,
        searched_xrefs=searched,
        diagnosis=diagnose_function(coverage, {
            "entry_matches": entry_matches,
            "xref_count": total_xrefs,
            "data_xref_count": data_xrefs,
            "xrefs_tested": searched,
            "body_near_miss": body_near_miss,
            "vtable_failure": vtable_failure,
            "string_rel_failure": string_rel_failure,
        }),
        site_rejections=site_rejections,
        pinned=len(pinned),
    )


def choose_global_candidates(global_ea, ranges):
    """Ranked REL candidates for a global via distinct data-xref anchor sites.

    Globals have no instruction body, so REL is the only applicable axis.
    Returns a FunctionSearch (only its REL axis is meaningful).
    """
    rels, total_xrefs, searched = collect_rel_candidates(
        global_ea, ranges, collect_data_xrefs_to, is_data=True,
        func_ea=0, func_size=0,
    )
    selected = select_global_candidates(rels)
    coverage = coverage_for(selected, {AXIS_EXTERNAL_REL})
    return FunctionSearch(
        candidates=selected,
        coverage=coverage,
        total_xrefs=total_xrefs,
        searched_xrefs=searched,
        diagnosis=diagnose_function(coverage, {
            "xref_count": total_xrefs, "xrefs_tested": searched,
        }),
    )
