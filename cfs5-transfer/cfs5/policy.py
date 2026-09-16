"""Candidate model, scoring and the diversity-selection policy.

Deliberately **free of any `ida_*` import** so the selection rules can be unit
tested outside IDA. `cfs5/sigs.py` holds the IDA-touching finders that produce
Candidates; everything about how they are scored, deduplicated, ranked and
selected lives here.

Selection aims for *structurally independent* anchors rather than a fixed
candidate count: a volatile prologue can change while a body region or a
caller's call site survives, so three candidates from one region are worth far
less than one each from ENTRY, an external caller and the body.
"""

from . import cfs6


# Tuning. Defaults favour bounded, deterministic work on very large DLLs.
MAX_PATTERN_BYTES = 48
GOOD_ENTRY_BYTES = 24
BODY_START_SAMPLES = 3
MAX_XREFS_TO_SEARCH = 24
XREF_EARLY_STOP_AFTER = 6
MAX_EXPORTED_CANDIDATES = 4
MAX_GLOBAL_CANDIDATES = 3
MAX_VALUE_CANDIDATES = 3
MIN_EXACT_BYTES = 6
MIN_SHORT_EXACT_BYTES = 4
# VALUE wildcards one byte, not a rel32, so it must not inherit the short tier.
VALUE_MIN_EXACT_BYTES = 8

# Origin categories. These are part of the exported contract.
ORIGIN_ENTRY = "function_entry"
ORIGIN_EXTERNAL_CALL = "external_call"
ORIGIN_SELF_CALL = "self_call"
ORIGIN_DATA_REF = "data_reference"
ORIGIN_BODY = ("body_early", "body_middle", "body_late")
# derived_value origins live in cfs6.py beside the format rule that closes the
# set; re-exported here so finders import one module.
ORIGIN_STROFF_XREF = cfs6.ORIGIN_STROFF_XREF
ORIGIN_SELECTED_OPERAND = cfs6.ORIGIN_SELECTED_OPERAND
ORIGIN_HEXRAYS_MEMPTR = cfs6.ORIGIN_HEXRAYS_MEMPTR

# Resolution axes an item can be covered by.
AXIS_ENTRY = "entry"
AXIS_EXTERNAL_REL = "external_rel"
AXIS_SELF_REL = "self_rel"
AXIS_BODY = "body"
AXIS_VALUE = "value"

_MODE_ORDER = {"ENTRY": 0, "REL": 1, "BODY": 2, "VALUE": 3}
_MODE_PENALTY = {"ENTRY": 0, "REL": 12, "BODY": 18, "VALUE": 12}


def candidate_min_exact(total_bytes):
    """Minimum non-wildcard bytes a pattern of this length must carry."""
    return MIN_SHORT_EXACT_BYTES if total_bytes < 10 else MIN_EXACT_BYTES


def value_min_exact(total_bytes):
    """The same floor for VALUE candidates, which needs to be much higher.

    `candidate_min_exact`'s short tier (4 exact bytes under 10 total) is
    calibrated for REL, where a 4-byte rel32 is wildcarded and a 10-byte
    pattern legitimately carries only 4-6 concrete bytes.

    A VALUE candidate wildcards a *single* displacement byte, so the same rule
    lets a lone 5-byte instruction through with 4 exact bytes. That pattern is
    genuinely unique in the image it was built from -- uniqueness is verified,
    not assumed -- but uniqueness in one build says very little about the next
    one, and a pattern that picks up a second match resolves to nothing at all.
    The member would then stop working silently on a rebuild, which is the
    exact failure this format exists to prevent.

    So VALUE is held to a flat, higher floor: expand into the neighbouring
    instructions rather than stop at the first technically-unique window.
    """
    return max(VALUE_MIN_EXACT_BYTES, candidate_min_exact(total_bytes))


def primary_chunk_limit(insns, func_ea, ownership):
    """How many leading instructions stay inside the function's .pdata range.

    IDA's function body routinely spans several RUNTIME_FUNCTION entries, and
    only the one *starting* at the function can be mapped back to it by a
    .pdata consumer. Restricting body samples to this prefix keeps the
    resulting candidates externally resolvable.

    Returns len(insns) when the whole body qualifies, when ownership is
    unknown, or when the prefix is too short to sample distinct regions from --
    in that last case the candidates are simply labelled ida-only, which is
    honest rather than silently dropping the function's only BODY anchors.
    """
    if ownership is None:
        return len(insns)
    span = ownership.primary_span(func_ea)
    if span is None:
        return len(insns)

    limit = 0
    for item in insns:
        if item["ea"] >= span[1]:
            break
        limit += 1
    return limit if limit > BODY_START_SAMPLES else len(insns)


def body_origin_for_position(index, total):
    """Map a body sample position onto an early/middle/late origin category."""
    if total <= 1:
        return ORIGIN_BODY[1]
    third = index / float(total - 1)
    if third < 0.34:
        return ORIGIN_BODY[0]
    if third < 0.67:
        return ORIGIN_BODY[1]
    return ORIGIN_BODY[2]


class Candidate:
    """One signature candidate, before it is ranked or written.

    Addresses are source-image EAs; the exporter converts them to RVAs when
    serializing. They are diagnostics — never resolution inputs.
    """

    __slots__ = (
        "mode", "signature", "origin", "byte_len", "wildcards", "exact",
        "score", "anchor_ea", "func_ea", "func_size", "body_offset",
        "target_ea", "target_delta", "rel_offset", "rel_size", "base_offset",
        "insn_offset", "is_data", "ownership", "extract", "value",
    )

    def __init__(
        self, mode, signature, origin="", byte_len=0, wildcards=0, exact=0,
        anchor_ea=0, func_ea=0, func_size=0, body_offset=0, target_ea=0,
        target_delta=0, rel_offset=0, rel_size=0, base_offset=0,
        insn_offset=0, is_data=False, ownership="pdata", extract=None,
        value=None,
    ):
        self.mode = mode
        self.signature = cfs6.normalize_pattern(signature)
        self.origin = origin
        self.byte_len = int(byte_len)
        self.wildcards = int(wildcards)
        self.exact = int(exact)
        self.anchor_ea = int(anchor_ea)
        self.func_ea = int(func_ea)
        self.func_size = int(func_size)
        self.body_offset = int(body_offset)
        self.target_ea = int(target_ea)
        self.target_delta = int(target_delta)
        self.rel_offset = int(rel_offset)
        self.rel_size = int(rel_size)
        self.base_offset = int(base_offset)
        self.insn_offset = int(insn_offset)
        self.is_data = bool(is_data)
        # BODY only: how a consumer can recover the owning function.
        self.ownership = ownership
        # VALUE only: the extraction recipe, and the integer it produced here.
        # `value` is an export-time check (every candidate of an item must
        # agree with the item's expected_value) and is never serialized per
        # candidate -- the item carries the one authoritative value.
        self.extract = dict(extract or {})
        self.value = value

        # Lower is better. Length dominates: once a pattern is source-unique,
        # shorter is usually less flaky across versions. Wildcards get only a
        # small penalty; the mode penalty breaks ties toward cheaper anchors.
        self.score = (
            self.byte_len * 100
            + self.wildcards * 2
            + _MODE_PENALTY.get(mode, 25)
        )

    @property
    def axis(self):
        if self.mode == "ENTRY":
            return AXIS_ENTRY
        if self.mode == "BODY":
            return AXIS_BODY
        if self.mode == "VALUE":
            return AXIS_VALUE
        if self.origin == ORIGIN_SELF_CALL:
            return AXIS_SELF_REL
        return AXIS_EXTERNAL_REL

    @property
    def span(self):
        """Half-open source-image byte range covered by the pattern."""
        return (self.anchor_ea, self.anchor_ea + self.byte_len)

    def overlaps(self, other):
        a0, a1 = self.span
        b0, b1 = other.span
        return a0 < b1 and b0 < a1

    def sort_key(self):
        """Total order: deterministic regardless of discovery order."""
        return (
            self.score,
            _MODE_ORDER.get(self.mode, 9),
            self.origin,
            self.signature,
            self.anchor_ea,
        )

    # -- serialization helpers (consumed by cfs6.Cfs6Writer) ----------------

    def source_object(self, imagebase=0):
        """Diagnostic provenance, as RVAs relative to `imagebase`."""
        def rva(ea):
            return int(ea) - int(imagebase)

        if self.is_data:
            source = {"target_rva": rva(self.target_ea)}
        else:
            source = {
                "function_rva": rva(self.func_ea),
                "function_size": self.func_size,
            }
        source["anchor_rva"] = rva(self.anchor_ea)
        if self.mode == "BODY":
            source["body_offset"] = self.body_offset
        return source

    def resolve_object(self):
        """The only fields a consumer needs to resolve against a new image."""
        if self.mode == "REL":
            resolve = {
                "instruction_offset": self.insn_offset,
                "displacement_offset": self.rel_offset,
                "displacement_size": self.rel_size,
                "base_offset": self.base_offset,
            }
        elif self.mode == "BODY":
            resolve = {"ownership": self.ownership}
        elif self.mode == "VALUE":
            # Built entirely by the finder from decoded operand metadata; the
            # policy layer never invents or edits an extraction field.
            resolve = dict(self.extract)
        else:
            resolve = {}
        # Optional with a documented default of 0; omit the common case.
        if self.target_delta:
            resolve["target_delta"] = self.target_delta
        return resolve


def dedup_and_order(candidates):
    """Deterministic best-first order with identical patterns collapsed.

    Overlap is *not* resolved here: dropping by score alone would let a short
    BODY window near the prologue evict the ENTRY it overlaps, which trades the
    more valuable anchor (ENTRY needs no .pdata to resolve) for the less
    valuable one. Overlap is settled during selection, where axis priority is
    known.
    """
    ordered = sorted(candidates, key=lambda c: c.sort_key())

    kept = []
    seen_patterns = set()
    for cand in ordered:
        if cand.signature in seen_patterns:
            continue
        seen_patterns.add(cand.signature)
        kept.append(cand)
    return kept


def _best_for_axis(pool, axis, selected=()):
    """Best candidate on `axis` that does not overlap anything already chosen.

    Overlapping candidates are not independent evidence, so the later (lower
    priority) axis yields rather than the earlier one.
    """
    for cand in pool:
        if cand.axis != axis:
            continue
        if any(cand.overlaps(other) for other in selected):
            continue
        return cand
    return None


def select_function_candidates(candidates, max_count=MAX_EXPORTED_CANDIDATES):
    """Pick structurally diverse candidates, best-first.

    One candidate per axis first (ENTRY, external REL, BODY), then fill any
    remaining slot with the best leftover of an origin not already used. Never
    manufactures weak candidates to reach a count.
    """
    pool = dedup_and_order(candidates)

    # Axis order is priority order: ENTRY resolves with no .pdata and no xref,
    # an external REL survives a rewritten prologue, BODY is the fallback.
    selected = []
    for axis in (AXIS_ENTRY, AXIS_EXTERNAL_REL, AXIS_BODY):
        cand = _best_for_axis(pool, axis, selected)
        if cand is not None:
            selected.append(cand)

    # A self-referencing anchor is a weaker REL, so it only earns a slot when
    # no external caller produced one.
    if not any(c.axis == AXIS_EXTERNAL_REL for c in selected):
        cand = _best_for_axis(pool, AXIS_SELF_REL, selected)
        if cand is not None:
            selected.append(cand)

    covered_axes = {c.axis for c in selected}
    used_origins = {c.origin for c in selected}
    for cand in pool:
        if len(selected) >= max_count:
            break
        if cand in selected or cand.origin in used_origins:
            continue
        # A self-referencing anchor adds no independence once a real external
        # caller is already covering the REL axis.
        if cand.axis == AXIS_SELF_REL and AXIS_EXTERNAL_REL in covered_axes:
            continue
        if any(cand.overlaps(other) for other in selected):
            continue
        selected.append(cand)
        used_origins.add(cand.origin)

    selected.sort(key=lambda c: c.sort_key())
    return selected[:max_count]


def select_global_candidates(candidates, max_count=MAX_GLOBAL_CANDIDATES):
    """Globals have only one axis, so take the best distinct anchor sites."""
    selected = []
    for cand in dedup_and_order(candidates):
        if len(selected) >= max_count:
            break
        if any(cand.overlaps(other) for other in selected):
            continue
        selected.append(cand)
    return selected


def select_value_candidates(candidates, max_count=MAX_VALUE_CANDIDATES):
    """Best distinct anchor sites for a derived_value item.

    There is one axis, so this is a straight best-first pick of
    non-overlapping sites -- the same shape as globals. What makes the result
    meaningful is *where* the inputs came from: independent instructions, in
    different functions, that each encode the same number. Two candidates
    carved out of one instruction would be one piece of evidence counted
    twice, which the overlap test rejects.

    A CONST candidate is kept only when it is the sole candidate. CONST
    extracts nothing from the code, so several of them would agree
    unconditionally -- fake confirmation rather than evidence.
    """
    selected = []
    for cand in dedup_and_order(candidates):
        if len(selected) >= max_count:
            break
        if any(cand.overlaps(other) for other in selected):
            continue
        selected.append(cand)

    real = [c for c in selected if c.extract.get("op") != cfs6.OP_CONST]
    if real:
        return real
    # Nothing but CONSTs: keep one. Several would agree unconditionally, which
    # would read as confirmation while proving nothing.
    return selected[:1]


def value_coverage(selected):
    """Coverage for a derived_value item: one axis, honestly reported."""
    return {
        AXIS_VALUE: cfs6.COV_SELECTED if selected else cfs6.COV_NONE_UNIQUE
    }


def coverage_for(selected, attempted_axes):
    """Per-axis coverage for an item record.

    `attempted_axes` is the set of axes the finders actually searched; an axis
    that does not apply (a global has no ENTRY) is reported as not_applicable
    rather than as a failure.
    """
    found = {c.axis for c in selected}
    # A self-call REL still covers the external_rel axis in spirit, but the
    # distinction matters to a consumer, so report it honestly.
    coverage = {}
    for axis in (AXIS_ENTRY, AXIS_EXTERNAL_REL, AXIS_BODY):
        if axis not in attempted_axes:
            coverage[axis] = cfs6.COV_NOT_APPLICABLE
        elif axis in found:
            coverage[axis] = cfs6.COV_SELECTED
        else:
            coverage[axis] = cfs6.COV_NONE_UNIQUE
    if AXIS_SELF_REL in found:
        coverage[AXIS_EXTERNAL_REL] = cfs6.COV_NONE_UNIQUE
        coverage[AXIS_SELF_REL] = cfs6.COV_SELECTED
    return coverage
