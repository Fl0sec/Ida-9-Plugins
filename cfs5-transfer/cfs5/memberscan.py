"""Member reference discovery that compensates for IDA 9.0's xref gap.

Why this module exists
----------------------

IDA 9.0's structure-member cross-reference index is **incomplete for
pointer-based objects**. It reliably records a member xref when the typed
object has concrete storage the database knows about -- a stack variable, a
directly addressed global. It frequently records nothing when the object is
reached through a typed pointer held in a register, which includes function
parameters and loaded global pointers. Hex-Rays still propagates the type and
prints `pEntitySystem->m_nFoo`, but that interpretation is never written back
as a persistent member xref on the underlying `[reg+disp]` operand. Indexed
forms such as `[rdx+rcx*8+0x10]` almost never receive member metadata.

Measured on cs2 `client.dll` (build 14181), with no changes to the IDB:

  * `CGameTrace::m_flFraction` -- the legacy index yields 29 functions. A
    displacement scan validated by the decompiler yields 13 functions, **7 of
    which the legacy index does not contain**. `CGameTrace__DidHit` @ 0x3516A0
    accesses `trace->m_flFraction` at 0x3516A8 through a correctly typed
    parameter and has no legacy member xref at all.
  * `CGameEntitySystem::m_nEntityListenerCapacity` (+0x20D0) -- the legacy
    index yields nothing usable; the only genuine site is in the constructor,
    reached through a `CGameEntitySystem*` parameter.

So `members.member_reference_sites` alone leaves exactly the members this
feature exists for with zero candidates. Do not "simplify" this module back to
`XrefsTo(udm_tid)`.

How it stays honest
-------------------

The normative rule is that numeric equality must never be the *discriminator*
-- two unrelated classes with a field at 0x10 are not evidence about each
other. That rule is intact here, because the two roles are separate:

  * the displacement scan is a **search-space prefilter**. It reduces millions
    of instructions to a handful. It decides nothing.
  * the decompiler is the **discriminator**. A site survives only when the
    ctree has a `cot_memptr`/`cot_memref` node *at that exact instruction*
    whose member offset matches and whose base expression's type is the owner
    structure. That is a type-directed identification, the same kind of fact a
    stroff annotation encodes, from a better-informed producer.

Validation is deliberately **per instruction**, not per function. Checking
that the member's name appears somewhere in the pseudocode would accept an
unrelated `[reg+0x10]` in a function that happens to touch the member
elsewhere, and would also accept a same-named field on a different structure.
A false candidate is worse than a missing one: agreement between candidates is
read as confirmation, so a wrong site manufactures fake confidence.

Every surviving site is still gated by `disasm.infer_displacement_field` in
`sigs.py` before it becomes a candidate, which independently re-proves that
the bytes at that address encode the offset.

Which functions get decompiled, and why
---------------------------------------

There is no member->function index to consult; that absence is the whole
reason this module exists. So the only way to know whether a function uses a
member is to decompile it and look, and the real problem is choosing which few
hundred of tens of thousands are worth that. Two tiers, best first:

**1. Prototype seeds.** Any function declared `f(CModel *self, ...)` is a
`CModel` function, and the database already says so in its type information --
no decompiling, no displacement, no guessing. These are near-certain hits and
are spent before anything speculative.

**2. Rarity-weighted co-occurrence.** For functions that touch the type
without being typed for it, every member offset is looked up in the
displacement index and each hit is weighted by `1/len(bucket)`: an offset
shared with 11 functions is strong evidence, one shared with 37918 is nearly
none. Summing those weights lets a function that hits the type's *rare*
offsets outrank one that merely hits `+0x10`.

An earlier version scored by counting *distinct* offsets hit. That works on a
type with many rare offsets (`CGameEntitySystem`: 14 members, offsets around
`+0x2090`) and collapses on a small one (`CModel`: 4 members near `+0x70`),
where every candidate ties at 1 and the sample is effectively random -- which
is how a correctly typed `CModel` accessor ended up outside a 150-function
sample of 11480. Rarity weighting fixes the ranking; the prototype tier is
what makes that case not depend on ranking at all.

Neither tier decides anything -- the ctree remains the sole discriminator.

Scanning per structure is also what makes it affordable: one decompile
harvests *every* member of the type that function touches, so a 40-member type
costs about one pass, not forty.

Known limits (documented, not hidden)
-------------------------------------

  * **Offset 0 has no bucket.** `[rcx]` encodes no displacement, so a member
    at offset 0 contributes nothing to the ranking and can only be confirmed
    in a function some *other* member brought in. It is still harvested there.
  * **Only sites that encode the offset literally are reachable.** A
    stack-folded access (`filter.m_mode` compiled to `mov [rbp-68h], 3`) does
    not encode the member offset anywhere, so it is information-theoretically
    unrecoverable. It is correctly absent rather than wrong.
  * **The owner must match by name exactly.** An access typed as a derived
    class is not matched against a base-class owner.
  * **Coverage tracks how well typed the database is.** A member only ever
    reached through untyped `*(_DWORD *)(a1 + 112)` arithmetic cannot be
    confirmed by any amount of searching, because the decompiler is the
    discriminator and it has nothing to say. Type the accessing function and
    rescan; every other member of the type in that function comes along free.
"""

import re

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_nalt
import ida_segment
import ida_typeinf
import ida_ua
import idautils

from .common import BADADDR, UA_MAXOP, ea_str, msg
from .disasm import signed_le


# Budget for one whole-structure pass. It is spent on the best-ranked
# functions, not on the lowest-addressed ones, and it is amortized over every
# member of the type rather than paid per member.
MAX_FUNCS_TO_DECOMPILE = 150
MAX_VALIDATED_SITES = 8

# Marks a prototype-seeded function so the budget logic never treats one as a
# weak single-offset guess. Seeds are certainties, not samples.
_SEED_RANK = 1 << 30


# ---------------------------------------------------------------------------
# The displacement index: one pass, reused by every member
# ---------------------------------------------------------------------------

_index = None
_index_key = None


def _database_key():
    """Something that changes when the open database does."""
    try:
        return str(ida_kernwin.get_kernel_version()), int(
            ida_segment.get_segm_qty()
        )
    except Exception:
        return None


def _code_ranges():
    ranges = []
    try:
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if seg is not None and seg.type == ida_segment.SEG_CODE:
                ranges.append((int(seg.start_ea), int(seg.end_ea)))
    except Exception as exc:
        msg("MEMBERSCAN: segment walk failed: %s" % exc)
    return ranges


def build_displacement_index(force=False):
    """Map every encoded memory displacement to the instructions using it.

    Built once per session and reused: the walk is the expensive part, and
    doing it per member would make declaring a structure unusable. Once built,
    locating the search space for any member is a dict lookup.

    Returns the index, or None if the user cancelled.
    """
    global _index, _index_key

    key = _database_key()
    if _index is not None and _index_key == key and not force:
        return _index

    index = {}
    insn = ida_ua.insn_t()
    ranges = _code_ranges()
    total = sum(end - start for start, end in ranges) or 1
    done = 0
    cancelled = False

    ida_kernwin.show_wait_box("CFS6: indexing displacements...")
    try:
        for start, end in ranges:
            for ea in idautils.Heads(start, end):
                done += 1
                if done % 20000 == 0:
                    if ida_kernwin.user_cancelled():
                        cancelled = True
                        break
                    ida_kernwin.replace_wait_box(
                        "CFS6: indexing displacements (%d%%)"
                        % min(99, (ea - start) * 100 // total)
                    )
                try:
                    if ida_ua.decode_insn(insn, ea) <= 0:
                        continue
                    for i in range(UA_MAXOP):
                        op = insn.ops[i]
                        if op.type == ida_ua.o_void:
                            break
                        if op.type != ida_ua.o_displ:
                            continue
                        disp = signed_le(int(op.addr), 8)
                        if disp:
                            index.setdefault(disp, []).append(ea)
                except Exception:
                    # A single undecodable head must not abort the pass.
                    continue
            if cancelled:
                break
    finally:
        ida_kernwin.hide_wait_box()

    if cancelled:
        msg("MEMBERSCAN: displacement index cancelled; nothing cached")
        return None

    _index = index
    _index_key = key
    msg("MEMBERSCAN: indexed %d instructions, %d distinct displacements"
        % (done, len(index)))
    return _index


def invalidate_index():
    """Drop every cache so the next scan re-reads the database."""
    global _index, _index_key
    _index = None
    _index_key = None
    _struct_cache.clear()


def displacement_sites(value):
    """Instructions encoding `value` as a memory displacement (unvalidated)."""
    index = build_displacement_index()
    if index is None:
        return []
    return list(index.get(int(value), ()))


# ---------------------------------------------------------------------------
# The discriminator: per-instruction ctree validation
# ---------------------------------------------------------------------------

def _base_type_name(expr, through_pointer):
    """Name of the structure `expr` refers to, or ''."""
    try:
        tif = expr.type
        if through_pointer:
            if not tif.is_ptr():
                return ""
            tif = tif.get_pointed_object()
        return str(tif.get_type_name() or "")
    except Exception:
        return ""


class _StructSiteVisitor(ida_hexrays.ctree_visitor_t):
    """Collects, per member offset, the addresses accessing this structure.

    Harvests **every** member of `owner` in one traversal. Decompiling is the
    expensive part of the feature, so extracting a single member per pass and
    discarding the rest is what made scanning a whole type unaffordable.

    `cexpr_t.m` is the member offset **in bytes** and is only meaningful for
    `cot_memptr` / `cot_memref`; the binding returns 0 for every other op, so
    the op check is what keeps offset-0 members from matching everything.
    """

    def __init__(self, owner):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.owner = owner
        self.hits = {}

    def visit_expr(self, e):
        try:
            if e.op == ida_hexrays.cot_memptr:
                through_pointer = True
            elif e.op == ida_hexrays.cot_memref:
                through_pointer = False
            else:
                return 0
            if _base_type_name(e.x, through_pointer) != self.owner:
                return 0
            ea = int(e.ea)
            if ea != BADADDR:
                self.hits.setdefault(int(e.m), set()).add(ea)
        except Exception:
            # Never let one odd ctree node abort the traversal.
            pass
        return 0


def _harvest_struct_in(func_ea, owner):
    """{byte_offset: {ea, ...}} for every `owner` member seen in `func_ea`.

    DECOMP_NO_WAIT is not an optimization, it is required for correctness here.
    By default `decompile()` opens its *own* wait box, which nests on top of
    the scan's: the progress text is hidden for the duration of each function
    (so a slow one looks hung), and -- worse -- a Cancel click is consumed by
    the inner box, so `user_cancelled()` never becomes true and the scan cannot
    be aborted at all.

    The cache is deliberately left on (no DECOMP_NO_CACHE): reusing pseudocode
    already stored in the IDB is most of what makes a 150-function pass viable.
    """
    try:
        cfunc = ida_hexrays.decompile(
            func_ea, None, ida_hexrays.DECOMP_NO_WAIT
        )
    except Exception as exc:
        msg("MEMBERSCAN: decompile %s failed: %s" % (ea_str(func_ea), exc))
        return {}
    if cfunc is None:
        return {}

    visitor = _StructSiteVisitor(owner)
    try:
        visitor.apply_to(cfunc.body, None)
    except Exception as exc:
        msg("MEMBERSCAN: ctree walk of %s failed: %s" % (ea_str(func_ea), exc))
        return {}
    return visitor.hits


def _prototype_seed(owner):
    """Functions whose own prototype names `owner` -- the strongest signal.

    A function declared `f(CModel *self, ...)` is a `CModel` function, and that
    is recorded in the database as type information: no decompiling, no
    guessing, no displacement involved. These are near-certain hits and must be
    spent before any speculative candidate.

    This is the signal the co-occurrence ranking cannot replace. Ranking works
    on a type with many rare offsets (CGameEntitySystem: 14 members, offsets
    like +0x2090), but degenerates on a small type whose offsets are all
    common (CModel: 4 members around +0x70), where every candidate function
    scores identically and the sample is effectively random.

    Matching is on a word boundary so `CModel` does not also select
    `CModelDataBlock`. It only decides where to *look*; the ctree still decides
    what counts.
    """
    pattern = re.compile(r"\b%s\b" % re.escape(owner))
    seeds = []
    tif = ida_typeinf.tinfo_t()
    for func_ea in idautils.Functions():
        try:
            if not ida_nalt.get_tinfo(tif, func_ea):
                continue
            if pattern.search(str(tif)):
                seeds.append(int(func_ea))
        except Exception:
            continue
    return seeds


def _rank_functions(owner, offsets):
    """Candidate functions, best first: prototype seeds, then co-occurrence.

    Tier 1 is every function typed against `owner` (see `_prototype_seed`).

    Tier 2 scores the rest by the displacement index, weighting each offset by
    its **rarity**: a hit on an offset shared by 200 functions is weak, one on
    an offset shared by 11 is strong. Counting distinct offsets instead made
    every function on a small structure tie at 1, which is how a well-typed
    `CModel` accessor ended up outside a 150-function sample of 11480.
    """
    index = build_displacement_index()
    if index is None:
        return [], 0

    seeds = _prototype_seed(owner)
    seeded = set(seeds)

    by_func = {}
    total_sites = 0
    for offset in offsets:
        if offset == 0:
            # No displacement is encoded, so there is no bucket to draw on.
            # Such members are still harvested from functions other members
            # bring in -- they just cannot contribute to the ranking.
            continue
        bucket = index.get(offset, ())
        # Rarity weight: an offset that appears everywhere says almost nothing.
        weight = 1.0 / max(1, len(bucket))
        for ea in bucket:
            func = ida_funcs.get_func(ea)
            if func is None:
                continue
            total_sites += 1
            if int(func.start_ea) in seeded:
                continue
            entry = by_func.setdefault(int(func.start_ea), [set(), 0.0])
            entry[0].add(offset)
            entry[1] += weight

    ranked = sorted(
        by_func.items(),
        key=lambda kv: (kv[1][1], len(kv[1][0]), -kv[0]),
        reverse=True,
    )

    out = [(fn, _SEED_RANK, 0.0) for fn in seeds]
    out.extend((fn, len(hits), score) for fn, (hits, score) in ranked)
    if seeds:
        msg("MEMBERSCAN: %s -- %d function(s) are typed against it; those are "
            "searched first" % (owner, len(seeds)))
    return out, total_sites


# Per-structure results, valid for as long as the displacement index is.
# Only *complete* scans land here. Caching a cancelled or failed one would
# turn a transient problem into a permanent empty answer for the whole session,
# and -- because a cache hit produced no output -- an invisible one.
#
# {(owner, index_key): {"asked": set(offsets), "found": {offset: [ea, ...]}}}
#
# `asked` exists because the key does not carry the offsets. Without it a scan
# for one member answers a later call about a *different* member of the same
# structure with "not confirmed" -- a cached answer to a question that was
# never asked. `found` accumulates: a site confirmed by any pass stays
# confirmed, so a later pass can only ever add evidence, never retract it.
_struct_cache = {}


def _merge_into_cache(key, asked, found):
    entry = _struct_cache.setdefault(key, {"asked": set(), "found": {}})
    entry["asked"].update(asked)
    for offset, eas in found.items():
        merged = set(entry["found"].get(offset, ()))
        merged.update(eas)
        entry["found"][offset] = sorted(merged)
    return entry


def scan_struct(owner, offsets, force=False):
    """{byte_offset: [ea, ...]} confirmed by the decompiler for `owner`.

    One ranked pass over the structure, cached. Every member benefits from
    every decompile, so asking for a second member after the first is free --
    but only for an offset the cached pass actually looked for, which is why
    the cache records what it was asked.
    """
    if not ida_hexrays.init_hexrays_plugin():
        msg("MEMBERSCAN: Hex-Rays unavailable; only legacy xrefs will be used")
        return {}

    wanted = set(int(o) for o in offsets)

    # The index must exist before the cache key does: `_index_key` is None
    # until the first successful build, so keying on it beforehand files the
    # result under a key no later call can ever produce.
    if build_displacement_index() is None:
        msg("MEMBERSCAN: %s -- displacement index unavailable (cancelled?); "
            "nothing cached, retry to scan" % owner)
        return {}

    key = (owner, _index_key)
    cached = _struct_cache.get(key)
    if not force and cached is not None and wanted <= cached["asked"]:
        msg("MEMBERSCAN: %s -- reusing cached scan (%d member(s) confirmed of "
            "%d asked)"
            % (owner, len(cached["found"]), len(cached["asked"])))
        return dict(cached["found"])

    if cached is not None and not force:
        # Some offset in this request was never looked for. Rescan for the
        # union so one pass answers both, rather than reporting "not
        # confirmed" for a member nothing ever searched.
        missing = sorted(wanted - cached["asked"])
        msg("MEMBERSCAN: %s -- cached scan did not cover %d offset(s) "
            "(%s); rescanning for the union"
            % (owner, len(missing),
               ", ".join("+0x%X" % o for o in missing[:8])))
        wanted = wanted | cached["asked"]

    ranked, total_sites = _rank_functions(owner, wanted)
    if not ranked:
        msg("MEMBERSCAN: %s -- nothing is typed against it and no instruction "
            "encodes any of its %d member offset(s)" % (owner, len(wanted)))
        return dict(_merge_into_cache(key, wanted, {})["found"])

    found = {}
    examined = 0
    seeds_done = 0
    cancelled = False
    # Seeds are certainties, so the speculative budget is counted separately --
    # a type with 200 typed functions must not spend its whole allowance before
    # reaching them, and must not be cut short by them either.
    seed_count = sum(1 for _fn, rank, _s in ranked if rank == _SEED_RANK)
    budget = seed_count + min(len(ranked) - seed_count, MAX_FUNCS_TO_DECOMPILE)

    ida_kernwin.show_wait_box("CFS6: scanning %s..." % owner)
    try:
        for func_ea, rank, _score in ranked:
            is_seed = rank == _SEED_RANK
            if not is_seed and (examined - seeds_done) >= MAX_FUNCS_TO_DECOMPILE:
                break
            if ida_kernwin.user_cancelled():
                cancelled = True
                msg("MEMBERSCAN: %s -- cancelled after %d function(s)"
                    % (owner, examined))
                break
            # Naming the function makes a slow one identifiable instead of
            # just looking hung.
            ida_kernwin.replace_wait_box(
                "CFS6: %s -- decompiling %d/%d%s\n%s (%d member(s) covered)"
                % (owner, examined + 1, budget,
                   " [typed]" if is_seed else "", ea_str(func_ea), len(found))
            )
            examined += 1
            if is_seed:
                seeds_done += 1
            for offset, eas in _harvest_struct_in(func_ea, owner).items():
                if offset in wanted:
                    found.setdefault(offset, set()).update(eas)
    finally:
        ida_kernwin.hide_wait_box()

    result = {off: sorted(eas) for off, eas in found.items()}
    msg("MEMBERSCAN: %s -- %d site(s) across %d function(s); decompiled %d "
        "(%d typed), confirmed %d of %d member(s)%s"
        % (owner, total_sites, len(ranked), examined, seeds_done, len(result),
           len(wanted),
           " (CANCELLED -- partial, not cached)" if cancelled else ""))
    if cancelled:
        return result

    # Merge rather than replace. A pass that confirmed fewer sites than an
    # earlier one has not disproved anything -- Hex-Rays results depend on what
    # else has been decompiled -- so the union is the honest answer and it makes
    # a second export at least as complete as the first.
    entry = _merge_into_cache(key, wanted, result)
    return dict(entry["found"])


def discover_member_sites(ref, exclude=(), offsets=None):
    """Instruction addresses where the decompiler confirms `ref` is accessed.

    Candidates come from the displacement index; each is kept only if the
    decompiled function containing it has a member expression *at that address*
    naming this owner and offset. See the module docstring for why both halves
    are necessary and why neither alone would be sound.

    `offsets` is every member offset of the owning structure, used to rank
    which functions are worth decompiling. Without it only this member's own
    offset is available, which for a common offset is no filter at all.
    """
    if ref is None:
        return []

    wanted = set(int(o) for o in (offsets or ()))
    wanted.add(int(ref.byte_offset))

    confirmed = scan_struct(ref.owner, wanted).get(int(ref.byte_offset), [])
    if not confirmed:
        if ref.byte_offset == 0:
            msg("MEMBERSCAN: %s is at offset 0, which encodes no displacement; "
                "it can only be confirmed in a function another member brings "
                "in" % ref.fullname)
        return []

    skip = set(int(ea) for ea in exclude)
    return [ea for ea in confirmed if ea not in skip][:MAX_VALIDATED_SITES]
