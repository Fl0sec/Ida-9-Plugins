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
# Uniqueness probes one anchored site may spend. Each probe is an image-wide
# byte search, and the byte-bounded window enumeration offers many more windows
# than the fixed instruction ladder it replaced, so this is what keeps a hard
# site from costing a scan of the image per candidate window. Shortest-first
# ordering means a site that can be pinned at all is pinned in the first few.
MAX_UNIQUE_PROBES = 48
# Candidate windows above which the envelope shortcut pays for itself. Below
# it, probing the windows directly is cheaper than the extra probe.
ENVELOPE_WORTH_PROBES = 8
MIN_EXACT_BYTES = 6
MIN_SHORT_EXACT_BYTES = 4
# VALUE wildcards one byte, not a rel32, so it must not inherit the short tier.
VALUE_MIN_EXACT_BYTES = 8

# Origin categories. These are part of the exported contract.
ORIGIN_ENTRY = "function_entry"
ORIGIN_EXTERNAL_CALL = "external_call"
# An anchor the caller named outright, rather than one discovery found. It is
# a distinct origin because it carries a different warranty: a human or an
# agent asserted this site is the right evidence, and the exporter's job is to
# verify that claim, not to second-guess where it came from.
ORIGIN_EXPLICIT_SITE = "explicit_site"
ORIGIN_SELF_CALL = "self_call"
ORIGIN_DATA_REF = "data_reference"
ORIGIN_BODY = ("body_early", "body_middle", "body_late")
# derived_value origins live in cfs6.py beside the format rule that closes the
# set; re-exported here so finders import one module.
ORIGIN_STROFF_XREF = cfs6.ORIGIN_STROFF_XREF
ORIGIN_SELECTED_OPERAND = cfs6.ORIGIN_SELECTED_OPERAND
ORIGIN_HEXRAYS_MEMPTR = cfs6.ORIGIN_HEXRAYS_MEMPTR
ORIGIN_RTTI_VTABLE_SLOT = cfs6.ORIGIN_RTTI_VTABLE_SLOT
ORIGIN_ANCHOR_STRING = cfs6.ORIGIN_ANCHOR_STRING

# Resolution axes an item can be covered by.
AXIS_ENTRY = "entry"
AXIS_EXTERNAL_REL = "external_rel"
AXIS_SELF_REL = "self_rel"
AXIS_BODY = "body"
AXIS_VALUE = "value"
# A structural locator is its own axis: it is independent of every pattern
# axis by construction, which is the entire reason it exists. A function whose
# prologue, callers and body all fail can still be covered here.
AXIS_VTABLE = "vtable"
AXIS_STRING_REL = "string_rel"

_MODE_ORDER = {"ENTRY": 0, "REL": 1, "BODY": 2, "VALUE": 3,
               cfs6.MODE_VTABLE: 4, cfs6.MODE_STRING_REL: 5,
               cfs6.MODE_SITE: 6}
# A locator is not scored against patterns -- it does not compete with them,
# it covers a different axis -- but it still needs a defined penalty so the
# total order stays deterministic. It sits last because when a pattern axis
# does work, it needs no RTTI table to resolve.
_MODE_PENALTY = {"ENTRY": 0, "REL": 12, "BODY": 18, "VALUE": 12,
                 cfs6.MODE_VTABLE: 24, cfs6.MODE_STRING_REL: 24}
_MODE_PENALTY[cfs6.MODE_SITE] = 12


def candidate_min_exact(total_bytes):
    """Minimum non-wildcard bytes a pattern of this length must carry."""
    return MIN_SHORT_EXACT_BYTES if total_bytes < 10 else MIN_EXACT_BYTES


def anchored_window_specs(insns, xidx, max_bytes=MAX_PATTERN_BYTES):
    """[(start_idx, end_idx)] for every window containing `xidx`, shortest first.

    The growth rule for an *anchored* pattern -- one that must contain a
    specific instruction, rather than start at one. Bounded in **bytes**, not
    in instruction count, because a count is the wrong bound when the anchor is
    short: `bt eax, 0Bh` is 4 bytes and `shr eax, 6` is 3, so a ladder reaching
    three instructions back gives up around 11 bytes and never sees the 15- and
    20-byte unique windows sitting a few instructions earlier in the same
    function. A member offset rarely hit that, because a displacement-bearing
    `mov`/`lea` is longer and reaches uniqueness in fewer steps.

    Both directions are enumerated per instruction rather than per threshold: a
    window that pins a site may lie entirely *behind* it, which a scheme that
    only grew forward -- or only in balanced steps -- would miss.

    `insns` is the enclosing function chunk, so growth is clamped to the
    function by construction and a window can never reach into padding or a
    neighbouring function however far it grows. `insns` items need only `ea`
    and `size`, which keeps this rule testable without IDA.
    """
    n = len(insns)
    if not 0 <= xidx < n:
        return []

    def span(a, b):
        return insns[b - 1]["ea"] + insns[b - 1]["size"] - insns[a]["ea"]

    specs = []
    a = xidx
    while a >= 0 and span(a, xidx + 1) <= max_bytes:
        b = xidx + 1
        while b <= n and span(a, b) <= max_bytes:
            specs.append((a, b))
            b += 1
        a -= 1

    # Shortest first, so the first unique window found is the smallest one --
    # the same preference `windows.window_ladder` encodes for the modes whose
    # pattern starts at the anchor.
    specs.sort(key=lambda ab: (span(ab[0], ab[1]), ab[0]))
    return specs


def declared_window_specs(insns, start_idx, xidx,
                          max_bytes=MAX_PATTERN_BYTES):
    """Windows beginning exactly where a caller anchored them, containing xidx."""
    if not (0 <= start_idx <= xidx < len(insns)):
        return []
    specs = []
    for end in range(xidx + 1, len(insns) + 1):
        size = insns[end - 1]["ea"] + insns[end - 1]["size"] - insns[start_idx]["ea"]
        if size > max_bytes:
            break
        specs.append((start_idx, end))
    return specs


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


# How many image-wide siblings of a confirm signature we bother counting.
CONFIRM_MATCH_LIMIT = 8

# Closed sets that are part of the exported contract, so they live in cfs6.py
# beside the format rule enforcing them; re-exported here so the finders import
# one module. Same arrangement as the derived_value origins above.
TOKENIZATION_STRICT = cfs6.TOKENIZATION_STRICT
TOKENIZATION_RELAXED = cfs6.TOKENIZATION_RELAXED
TOKENIZATIONS = cfs6.TOKENIZATIONS

# Why a confirm signature could not be built. A closed set, like the axis
# reasons -- a caller branches on it rather than parsing English.
CONFIRM_NO_SCAN_RANGE = "no_scan_range"
CONFIRM_NO_INSTRUCTIONS = "no_instructions"
CONFIRM_NO_UNIQUE_WINDOW = "no_unique_window_in_scan_range"

# Which span export-time uniqueness was measured over. Closed set; the consumer
# needs to know whether it is working from the .pdata table or from a hint.
SCAN_BOUND_PDATA_CHAIN = cfs6.SCAN_BOUND_PDATA_CHAIN
SCAN_BOUND_IDA_EXTENT = cfs6.SCAN_BOUND_IDA_EXTENT
SCAN_BOUNDS = cfs6.SCAN_BOUNDS


def confirm_min_exact(total_bytes):
    """No exact-byte floor applies to a confirm signature.

    `MIN_EXACT_BYTES` and `value_min_exact` exist to keep a pattern that must
    be unique across a 40MB image from collapsing to a coincidence on the next
    build. A confirm signature is not that pattern: the locator (an RTTI slot,
    a string reference) has already produced the function address, and the
    signature is only asked to still match *inside that one function*. Applying
    an image-wide floor to a deliberately bounded pattern would refuse good
    answers for a risk that is not being run.
    """
    return 0


def select_handler_lea(instructions, xref_ea=None):
    """(instruction, reason) under STRING_REL's executable-LEA rule.

    Pure by design: register order, spacing, and whether the table entry ends
    in call or jmp are irrelevant. Only the decoded target classification is
    allowed to choose the handler.
    """
    bounded = list(instructions)
    if xref_ea is not None:
        before = [i for i, item in enumerate(bounded)
                  if item.get("terminator") and item.get("ea", 0) < xref_ea]
        after = [i for i, item in enumerate(bounded)
                 if item.get("terminator") and item.get("ea", 0) >= xref_ea]
        lo = (before[-1] + 1) if before else 0
        hi = (after[0] + 1) if after else len(bounded)
        bounded = bounded[lo:hi]

    matches = [
        item for item in bounded
        if item.get("mnemonic", "").lower() == "lea"
        and item.get("target_executable")
        and (xref_ea is None or item.get("ea", xref_ea) < xref_ea)
    ]
    if not matches:
        return None, "no LEA in the bounded registration entry targets executable memory"
    if len(matches) != 1:
        return None, "%d LEAs in the bounded registration entry target executable memory" % len(matches)
    return matches[0], ""


def rank_confirm_windows(windows):
    """Confirm windows best-first.

    Each window is a plain dict carrying at least `image_matches`, `byte_len`,
    `wildcards`, `offset` and `tokenization`, so the ordering rule stays
    testable without IDA.

    **Image-uniqueness is the first key**, and it is the clone-family defence
    rather than a nicety. The relaxed tokenizer wildcards exactly the stack
    offsets and immediates that distinguish a function from its byte-identical
    siblings. If the locator ever drifts onto a sibling -- a vtable slot that
    shifted, a renumbered table -- a signature that also matches inside that
    sibling would *confirm* the wrong function, which is the precise failure
    this design exists to prevent. A window matching nowhere else in the image
    cannot do that, so it wins over any shorter or more tolerant one.

    Measured on `notify_inventory_has_new_items` (cs2 client.dll 14182), a
    member of exactly such a clone family: **no** relaxed window at any anchor
    or any length is image-unique -- every one matches 8+ places -- while the
    strict 15-byte window at +0x58 is unique precisely because it pins the
    `24 48` / `24 30` stack offsets that separate it from its siblings. So both
    tokenizations must be offered here; ranking only relaxed windows would ship
    an 8-way-ambiguous confirm signature for the function the whole mechanism
    exists to protect.

    Tolerance is the *second* key: among windows that are equally
    discriminating, the relaxed one absorbs more build drift, so it is
    preferred even when longer. Length and wildcard count only break the
    remaining ties.
    """
    return sorted(windows, key=lambda w: (
        0 if int(w.get("image_matches", 0)) == 1 else 1,
        0 if w.get("tokenization") == TOKENIZATION_RELAXED else 1,
        int(w.get("byte_len", 0)),
        int(w.get("wildcards", 0)),
        int(w.get("offset", 0)),
    ))


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
        "insn_offset", "is_data", "ownership", "extract", "value", "locator",
        "locator_source",
    )

    def __init__(
        self, mode, signature, origin="", byte_len=0, wildcards=0, exact=0,
        anchor_ea=0, func_ea=0, func_size=0, body_offset=0, target_ea=0,
        target_delta=0, rel_offset=0, rel_size=0, base_offset=0,
        insn_offset=0, is_data=False, ownership="pdata", extract=None,
        value=None, locator=None, locator_source=None,
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
        # Locator modes only: how to find the function without a unique
        # pattern. Built by the finder from validated RTTI/string evidence;
        # the policy layer never invents or edits a field in it.
        self.locator = dict(locator or {})
        self.locator_source = dict(locator_source or {})

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
        if self.mode == cfs6.MODE_VTABLE:
            return AXIS_VTABLE
        if self.mode == cfs6.MODE_STRING_REL:
            return AXIS_STRING_REL
        if self.origin == ORIGIN_SELF_CALL:
            return AXIS_SELF_REL
        return AXIS_EXTERNAL_REL

    @property
    def is_locator(self):
        return self.mode in cfs6.LOCATOR_MODES

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
        if self.mode == cfs6.MODE_VTABLE and self.target_ea:
            # Diagnostics only, like every other source RVA: a consumer finds
            # the table through RTTI, never at the address it had here.
            source["vtable_rva"] = rva(self.target_ea)
        if self.mode == cfs6.MODE_STRING_REL:
            for key in ("string_ea", "xref_ea", "handler_lea_ea"):
                if key in self.locator_source:
                    source[key.replace("_ea", "_rva")] = rva(
                        self.locator_source[key]
                    )
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
        elif self.mode == cfs6.MODE_SITE:
            resolve = {"instruction_offset": self.insn_offset}
        elif self.is_locator:
            resolve = dict(self.locator)
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


def select_function_candidates(candidates, max_count=MAX_EXPORTED_CANDIDATES,
                               pinned=()):
    """Pick structurally diverse candidates, best-first.

    One candidate per axis first (ENTRY, external REL, BODY), then fill any
    remaining slot with the best leftover of an origin not already used. Never
    manufactures weak candidates to reach a count.

    `pinned` candidates are kept unconditionally and occupy the first slots.
    That is the whole point of an explicitly named site: scoring is a
    heuristic about what will survive the next build, and it must not be
    allowed to discard evidence the caller supplied on purpose. Everything
    else is then selected around them, and may not overlap them.
    """
    pool = dedup_and_order(candidates)

    # Axis order is priority order: ENTRY resolves with no .pdata and no xref,
    # an external REL survives a rewritten prologue, BODY is the fallback.
    selected = list(dedup_and_order(pinned))[:max_count]
    pinned_patterns = {c.signature for c in selected}
    pool = [c for c in pool if c.signature not in pinned_patterns]
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

    # Pinned candidates keep their slots through the truncation: sorting the
    # whole list by score could otherwise rank an explicitly named site out of
    # the file, which is the one outcome the caller asked us to prevent.
    keep = [c for c in selected if c.signature in pinned_patterns]
    rest = [c for c in selected if c.signature not in pinned_patterns]
    rest.sort(key=lambda c: c.sort_key())
    keep.sort(key=lambda c: c.sort_key())
    return (keep + rest)[:max_count]


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


# Why an axis produced nothing. A closed set, because the whole point is that
# a caller can branch on it instead of parsing English.
WHY_SELECTED = "selected"
WHY_NOT_ATTEMPTED = "not_attempted"
WHY_NO_UNIQUE_WINDOW = "no_unique_window"
WHY_CLONE_FAMILY = "clone_family"
WHY_NO_XREFS = "no_xrefs"
WHY_DATA_XREFS_ONLY = "data_xrefs_only"
WHY_XREFS_NOT_UNIQUE = "xrefs_not_unique"
WHY_OUTSIDE_PDATA = "unique_anchor_outside_pdata"
# Structural-locator failures. A locator is only attempted when the caller
# declared one, so these say what went wrong with *that claim* -- never
# "nothing was found", which would blame discovery for a declaration problem.
WHY_NOT_DECLARED = "not_declared"
WHY_LOCATOR_UNRESOLVED = "locator_unresolved"
WHY_LOCATOR_MISMATCH = "locator_mismatch"
WHY_NO_CONFIRM_SIGNATURE = "no_confirm_signature"

# How many identical siblings we bother counting before saying "at least N".
CLONE_COUNT_LIMIT = 8


def diagnose_function(coverage, facts):
    """Per-axis {reason, detail} for one function, from plain facts.

    `facts` is whatever the finders observed, all optional:

        entry_matches   how many times the longest ENTRY window still matched
        xref_count      code/data references to the function that were found
        xrefs_tested    how many of them a REL window was attempted at
        body_near_miss  [{offset, byte_len, ownership}] unique body anchors
                        that exist but were not exported

    Kept here, free of `ida_*`, because "no unique signature" was the whole
    problem: a caller could not tell a function with 40 byte-identical clones
    from one with no callers, and had to re-derive the difference by hand. The
    mapping from facts to reason is a rule, so it is testable like one.
    """
    facts = facts or {}
    out = {}

    for axis, state in (coverage or {}).items():
        if state == cfs6.COV_SELECTED:
            out[axis] = {"reason": WHY_SELECTED, "detail": ""}
            continue
        if state == cfs6.COV_NOT_APPLICABLE:
            out[axis] = {"reason": WHY_NOT_ATTEMPTED, "detail": "axis does not apply"}
            continue
        out[axis] = _diagnose_missing_axis(axis, facts)

    return out


def _diagnose_missing_axis(axis, facts):
    if axis == AXIS_ENTRY:
        matches = facts.get("entry_matches")
        if matches and matches >= 2:
            # The decisive fact: N byte-identical prologues means *no* prefix
            # pattern can ever work, so the answer is a structural anchor, not
            # a longer ENTRY window.
            at_least = "at least " if matches >= CLONE_COUNT_LIMIT else ""
            return {
                "reason": WHY_CLONE_FAMILY,
                "detail": "the longest prologue window still matches %s%d "
                          "places; no entry pattern can be unique"
                          % (at_least, matches),
                "matches": matches,
            }
        return {"reason": WHY_NO_UNIQUE_WINDOW,
                "detail": "no prologue window reached a unique match"}

    if axis in (AXIS_EXTERNAL_REL, AXIS_SELF_REL):
        count = int(facts.get("xref_count") or 0)
        data_count = int(facts.get("data_xref_count") or 0)
        if not count and data_count:
            # The distinction is worth spelling out: the address *is*
            # referenced, just by an instruction that takes it rather than
            # calls it (`lea rdx, [rip+x]` handing a callback to a registrar),
            # and the REL axis searches call/jump sites only.
            return {
                "reason": WHY_DATA_XREFS_ONLY,
                "detail": "no call or jump references it; %d instruction(s) "
                          "take its address instead (a `lea`-passed callback)"
                          % data_count,
                "xref_count": 0,
                "data_xref_count": data_count,
            }
        if not count:
            return {"reason": WHY_NO_XREFS,
                    "detail": "nothing in the image references this address "
                              "from code (a vtable-only callee has no call "
                              "site to anchor on)",
                    "xref_count": 0}
        return {
            "reason": WHY_XREFS_NOT_UNIQUE,
            "detail": "%d reference(s), %d tested, none yielded a unique "
                      "window" % (count, int(facts.get("xrefs_tested") or 0)),
            "xref_count": count,
        }

    if axis == AXIS_VTABLE:
        # The caller either did not declare a locator, or declared one that
        # did not survive verification. Those are very different problems and
        # the detail names which, with the underlying refusal quoted verbatim
        # so the RTTI reason is not paraphrased away.
        failure = facts.get("vtable_failure")
        if not failure:
            return {"reason": WHY_NOT_DECLARED,
                    "detail": "no vtable locator was declared for this function"}
        return {
            "reason": failure.get("reason", WHY_LOCATOR_UNRESOLVED),
            "detail": failure.get("detail", ""),
        }

    if axis == AXIS_STRING_REL:
        failure = facts.get("string_rel_failure")
        if not failure:
            return {"reason": WHY_NOT_DECLARED,
                    "detail": "no anchor_string locator was declared"}
        return {"reason": failure.get("reason", WHY_LOCATOR_UNRESOLVED),
                "detail": failure.get("detail", "")}

    if axis == AXIS_BODY:
        near = facts.get("body_near_miss") or []
        if near:
            return {
                "reason": WHY_OUTSIDE_PDATA,
                "detail": "%d unique body anchor(s) exist but sit outside the "
                          "function's own .pdata range, so a non-IDA consumer "
                          "could not map a hit back to the function"
                          % len(near),
                "near_miss": list(near),
            }
        return {"reason": WHY_NO_UNIQUE_WINDOW,
                "detail": "no unique window inside the function's .pdata range"}

    return {"reason": WHY_NO_UNIQUE_WINDOW, "detail": ""}


class FunctionSearch:
    """Everything one item's search produced, findings and failures alike.

    Returned instead of a tuple because the failure half is now as
    load-bearing as the success half: "no unique signature" was true and
    useless, and the caller had to re-derive the actual cause by hand. An
    object also means a later axis or counter can be added without breaking
    every unpacking site.
    """

    __slots__ = (
        "candidates", "coverage", "total_xrefs", "searched_xrefs",
        "diagnosis", "site_rejections", "pinned",
    )

    def __init__(self, candidates=(), coverage=None, total_xrefs=0,
                 searched_xrefs=0, diagnosis=None, site_rejections=(),
                 pinned=0):
        self.candidates = list(candidates)
        self.coverage = dict(coverage or {})
        self.total_xrefs = int(total_xrefs)
        self.searched_xrefs = int(searched_xrefs)
        self.diagnosis = dict(diagnosis or {})
        self.site_rejections = list(site_rejections)
        self.pinned = int(pinned)

    def __bool__(self):
        return bool(self.candidates)

    def __len__(self):
        return len(self.candidates)

    @property
    def near_misses(self):
        """Advisory anchors that exist but are not exportable."""
        out = []
        for axis, entry in sorted(self.diagnosis.items()):
            for item in entry.get("near_miss", ()):
                record = dict(item)
                record["axis"] = axis
                out.append(record)
        return out

    def failure_reason(self):
        """One line naming *which* axis failed and why, for a miss report."""
        parts = []
        for axis in (AXIS_ENTRY, AXIS_EXTERNAL_REL, AXIS_SELF_REL, AXIS_BODY,
                     AXIS_VTABLE, AXIS_STRING_REL):
            entry = self.diagnosis.get(axis)
            if entry is None or entry["reason"] in (
                WHY_SELECTED, WHY_NOT_ATTEMPTED
            ):
                continue
            parts.append("%s: %s" % (axis, entry["reason"]))
        if not parts:
            return "no unique signature"
        return "no unique signature (%s)" % "; ".join(parts)

    def explain(self):
        """The long form: every failed axis with its full detail."""
        lines = []
        for axis in (AXIS_ENTRY, AXIS_EXTERNAL_REL, AXIS_SELF_REL, AXIS_BODY,
                     AXIS_VTABLE, AXIS_STRING_REL):
            entry = self.diagnosis.get(axis)
            if entry is None or entry["reason"] in (
                WHY_SELECTED, WHY_NOT_ATTEMPTED
            ):
                continue
            lines.append("  %-13s %s -- %s"
                         % (axis, entry["reason"], entry["detail"]))
        return "\n".join(lines)


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
    for axis in (AXIS_ENTRY, AXIS_EXTERNAL_REL, AXIS_BODY, AXIS_VTABLE,
                 AXIS_STRING_REL):
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
