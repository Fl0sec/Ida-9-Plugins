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

Why the scan is per *structure*, not per member
-----------------------------------------------

A single displacement is only a useful prefilter when it is **rare**. Measured
on client.dll, `+0x2090` narrows to 11 functions; `+0x10` narrows to 37918 --
which is no narrowing at all, and sampling it in address order decompiles the
lowest-addressed functions in the module, none of which touch the type.

So the prefilter is the whole structure at once. Every member's offset is
looked up, and candidate functions are ranked by **how many distinct members
of this same structure they hit**. A function containing hits for `0x10` *and*
`0x2090` *and* `0x20C0` is overwhelmingly likely to be a `CGameEntitySystem`
function; one with only `0x10` is noise. Co-occurrence carries the information
a common offset cannot, so the rare members effectively rescue the common ones.

This is still only a prefilter -- the ctree remains the sole discriminator.

It is also what makes the feature affordable: one decompile harvests *every*
member of the structure that function touches, so scanning a 40-member type
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
"""

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_segment
import ida_ua
import idautils

from .common import BADADDR, UA_MAXOP, ea_str, msg
from .disasm import signed_le


# Budget for one whole-structure pass. It is spent on the best-ranked
# functions, not on the lowest-addressed ones, and it is amortized over every
# member of the type rather than paid per member.
MAX_FUNCS_TO_DECOMPILE = 150
MAX_VALIDATED_SITES = 8

# A function hitting only one of the structure's offsets is weak evidence. Once
# the ranking has dropped to singletons, keep going only while the budget is
# still mostly unspent -- for a small structure that is the only tier there is.
SINGLE_HIT_BUDGET_FRACTION = 0.5


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
    """{byte_offset: {ea, ...}} for every `owner` member seen in `func_ea`."""
    try:
        cfunc = ida_hexrays.decompile(func_ea)
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


def _rank_functions(offsets):
    """Candidate functions, best first, by co-occurrence of `offsets`.

    The ranking key is how many **distinct** member offsets of the structure a
    function contains, then how many total hits. That is the whole reason a
    common offset like `+0x10` becomes tractable: on its own it selects 37918
    functions, but the ones that also contain the type's rare offsets are the
    ones that actually use the type.
    """
    index = build_displacement_index()
    if index is None:
        return [], 0

    by_func = {}
    total_sites = 0
    for offset in offsets:
        if offset == 0:
            # No displacement is encoded, so there is no bucket to draw on.
            # Such members are still harvested from functions other members
            # bring in -- they just cannot contribute to the ranking.
            continue
        for ea in index.get(offset, ()):
            func = ida_funcs.get_func(ea)
            if func is None:
                continue
            total_sites += 1
            entry = by_func.setdefault(int(func.start_ea), [set(), 0])
            entry[0].add(offset)
            entry[1] += 1

    ranked = sorted(
        by_func.items(),
        key=lambda kv: (len(kv[1][0]), kv[1][1], -kv[0]),
        reverse=True,
    )
    return [(fn, len(hits), total) for fn, (hits, total) in ranked], total_sites


# Per-structure results, valid for as long as the displacement index is.
# Only *complete* scans land here. Caching a cancelled or failed one would
# turn a transient problem into a permanent empty answer for the whole session,
# and -- because a cache hit produced no output -- an invisible one.
_struct_cache = {}


def scan_struct(owner, offsets, force=False):
    """{byte_offset: [ea, ...]} confirmed by the decompiler for `owner`.

    One ranked pass over the structure, cached. Every member benefits from
    every decompile, so asking for a second member after the first is free.
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
    if not force and key in _struct_cache:
        cached = _struct_cache[key]
        msg("MEMBERSCAN: %s -- reusing cached scan (%d member(s) confirmed)"
            % (owner, len(cached)))
        return cached

    ranked, total_sites = _rank_functions(wanted)
    if not ranked:
        msg("MEMBERSCAN: %s -- no instruction in this module encodes any of "
            "its %d member offset(s)" % (owner, len(wanted)))
        _struct_cache[key] = {}
        return {}

    found = {}
    examined = 0
    cancelled = False
    single_hit_limit = int(MAX_FUNCS_TO_DECOMPILE * SINGLE_HIT_BUDGET_FRACTION)
    budget = min(len(ranked), MAX_FUNCS_TO_DECOMPILE)

    ida_kernwin.show_wait_box("CFS6: scanning %s..." % owner)
    try:
        for func_ea, distinct, _total in ranked:
            if examined >= MAX_FUNCS_TO_DECOMPILE:
                break
            if distinct < 2 and examined >= single_hit_limit:
                # Nothing but weak, single-offset matches remain.
                break
            if ida_kernwin.user_cancelled():
                cancelled = True
                msg("MEMBERSCAN: %s -- cancelled after %d function(s)"
                    % (owner, examined))
                break
            ida_kernwin.replace_wait_box(
                "CFS6: %s -- decompiling %d/%d (%d member(s) covered)"
                % (owner, examined + 1, budget, len(found))
            )
            examined += 1
            for offset, eas in _harvest_struct_in(func_ea, owner).items():
                if offset in wanted:
                    found.setdefault(offset, set()).update(eas)
    finally:
        ida_kernwin.hide_wait_box()

    result = {off: sorted(eas) for off, eas in found.items()}
    msg("MEMBERSCAN: %s -- %d site(s) across %d function(s); decompiled %d, "
        "confirmed %d of %d member(s)%s"
        % (owner, total_sites, len(ranked), examined, len(result), len(wanted),
           " (CANCELLED -- partial, not cached)" if cancelled else ""))
    if not cancelled:
        _struct_cache[key] = result
    return result


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
