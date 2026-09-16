"""Structure-member lookup, creation and reference discovery.

This is the IDA-facing half of the `member_offset` derived value. It answers
three questions:

  * which member does this operand refer to (`member_from_operand`)?
  * what does IDA believe that member's offset is (`lookup_member`)?
  * which instructions genuinely reference it (`member_reference_sites`)?

The load-bearing rule of the whole feature is that a reference is only genuine
when something *type-directed* associates the operand with that exact member.
An instruction that merely happens to encode the same number is not a
reference: two unrelated classes both having a field at 0x10 is coincidence,
and treating it as evidence would manufacture agreement between candidates
that describe different things.

`member_reference_sites` below covers one producer of that association --
IDA's own stroff index. It is **not sufficient on its own**: IDA 9.0 fails to
record member xrefs for objects reached through a typed pointer, which is most
of them. `cfs5/memberscan.py` supplies the missing sites using the decompiler
as the discriminator, and carries the measurements. There is still deliberately
no code path anywhere that accepts a site on displacement value alone.

IDA 9.0 notes: `ida_struct` is gone. Structures are `tinfo_t`, members are
`udm_t`, and **udm offsets and sizes are in bits**, so every conversion to a
byte offset is explicit below.
"""

import ida_bytes
import ida_name
import ida_pro
import ida_typeinf
import ida_ua
import idautils

from .common import BADADDR, UA_MAXOP, ea_str, msg
from .disasm import signed_le


# udm_t.offset and udm_t.size are bit quantities; these two helpers are the
# only places that conversion happens.
BITS_PER_BYTE = 8


def _bits(byte_offset):
    return int(byte_offset) * BITS_PER_BYTE


def _bytes_of(bit_value):
    return int(bit_value) // BITS_PER_BYTE


class MemberRef:
    """One structure member, identified the way CFS records it."""

    __slots__ = ("owner", "name", "byte_offset", "byte_size", "tid")

    def __init__(self, owner, name, byte_offset, byte_size=0, tid=BADADDR):
        self.owner = owner
        self.name = name
        self.byte_offset = int(byte_offset)
        self.byte_size = int(byte_size)
        self.tid = tid

    @property
    def fullname(self):
        return "%s.%s" % (self.owner, self.name)

    @property
    def qualified(self):
        return "%s::%s" % (self.owner, self.name)

    def __repr__(self):
        return "<MemberRef %s @ 0x%X>" % (self.fullname, self.byte_offset)


# ---------------------------------------------------------------------------
# Type and member lookup
# ---------------------------------------------------------------------------

_TYPE_KEYWORDS = ("struct ", "class ", "union ")


def normalize_type_name(name):
    """Strip a leading `struct`/`class`/`union` and surrounding punctuation.

    A name reaches us from several places -- a chooser column, a pasted
    declaration, a dialog -- and some of them include the keyword. Rejecting
    `struct CGameTrace` because of the prefix looks exactly like "that type
    does not exist", which is the least useful possible diagnosis.
    """
    text = str(name or "").strip().strip(";").strip()
    lowered = text.lower()
    for keyword in _TYPE_KEYWORDS:
        if lowered.startswith(keyword):
            text = text[len(keyword):].strip()
            break
    return text


def get_struct_tinfo(name):
    """The named type as a tinfo_t if it is a UDT, else None.

    Accepts any user-defined type -- struct, class or union. Asking for
    `BTF_STRUCT` specifically used to reject unions and some class shapes,
    which surfaced as a bogus "not a structure in this database".
    """
    name = normalize_type_name(name)
    if not name:
        return None
    try:
        tif = ida_typeinf.tinfo_t()
        til = ida_typeinf.get_idati()
        if not tif.get_named_type(til, name):
            return None
        if not tif.is_udt():
            return None
        return tif
    except Exception as exc:
        msg("MEMBER: cannot load type %r: %s" % (name, exc))
        return None


def _udm_at(tif, byte_offset):
    """(index, udm) for the member starting exactly at `byte_offset`.

    `get_udm_by_offset` returns whichever member *contains* the offset, so the
    exact-start check is what distinguishes "there is a field here" from
    "this address is somewhere inside a bigger field".
    """
    try:
        idx, udm = tif.get_udm_by_offset(_bits(byte_offset))
    except Exception:
        return -1, None
    if idx == -1 or udm is None:
        return -1, None
    if _bytes_of(udm.offset) != int(byte_offset):
        return -1, None
    return idx, udm


def lookup_member(owner, member_name):
    """MemberRef for `owner.member_name`, or None.

    This is the gate for declaring a `member_offset`: no IDA member, no
    declaration. The offset it returns becomes `source.expected_value`, which
    is only trustworthy because it came from a real typed field.
    """
    tif = get_struct_tinfo(owner)
    if tif is None:
        return None

    try:
        idx, udm = tif.get_udm(member_name)
    except Exception as exc:
        msg("MEMBER: get_udm(%s.%s) failed: %s" % (owner, member_name, exc))
        return None
    if idx == -1 or udm is None:
        return None

    tid = BADADDR
    try:
        tid = tif.get_udm_tid(idx)
    except Exception as exc:
        msg("MEMBER: no tid for %s.%s: %s" % (owner, member_name, exc))

    return MemberRef(
        owner=owner,
        name=str(udm.name),
        byte_offset=_bytes_of(udm.offset),
        byte_size=_bytes_of(udm.size),
        tid=tid,
    )


def member_at_offset(owner, byte_offset):
    """MemberRef for whatever starts exactly at `byte_offset` in `owner`."""
    tif = get_struct_tinfo(owner)
    if tif is None:
        return None
    idx, udm = _udm_at(tif, byte_offset)
    if udm is None:
        return None
    if udm.is_baseclass():
        # The field really belongs to the base class; declaring it against the
        # derived class would record the wrong owner.
        msg(
            "MEMBER: %s+0x%X is base class %s -- declare against the base type"
            % (owner, byte_offset, udm.name)
        )
        return None
    tid = BADADDR
    try:
        tid = tif.get_udm_tid(idx)
    except Exception:
        pass
    return MemberRef(
        owner=owner, name=str(udm.name), byte_offset=_bytes_of(udm.offset),
        byte_size=_bytes_of(udm.size), tid=tid,
    )


def iter_members(owner):
    """Every declarable member of `owner`, in layout order.

    Base classes are skipped: their fields belong to the base type, and
    declaring them against the derived name would record the wrong owner and
    produce a second item for the same field.
    """
    tif = get_struct_tinfo(owner)
    if tif is None:
        return []

    details = ida_typeinf.udt_type_data_t()
    try:
        if not tif.get_udt_details(details):
            return []
    except Exception as exc:
        msg("MEMBER: get_udt_details(%r) failed: %s" % (owner, exc))
        return []

    out = []
    for idx in range(len(details)):
        try:
            udm = details[idx]
            if udm.is_baseclass():
                continue
            tid = BADADDR
            try:
                tid = tif.get_udm_tid(idx)
            except Exception:
                pass
            out.append(MemberRef(
                owner=owner, name=str(udm.name),
                byte_offset=_bytes_of(udm.offset),
                byte_size=_bytes_of(udm.size), tid=tid,
            ))
        except Exception:
            continue
    return out


def enclosing_member_name(owner, byte_offset):
    """Name of the member that *spans* `byte_offset` without starting there.

    Used only for diagnostics: it turns "cannot declare here" into "0x20 is
    inside m_vecOrigin", which tells the user what to fix.
    """
    tif = get_struct_tinfo(owner)
    if tif is None:
        return None
    try:
        idx, udm = tif.get_udm_by_offset(_bits(byte_offset))
    except Exception:
        return None
    if idx == -1 or udm is None:
        return None
    if _bytes_of(udm.offset) == int(byte_offset):
        return None
    return "%s (+0x%X)" % (udm.name, byte_offset - _bytes_of(udm.offset))


# ---------------------------------------------------------------------------
# Operand inspection
# ---------------------------------------------------------------------------

def decode_at(ea):
    """A decoded insn_t at `ea`, or None."""
    try:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0 or insn.size <= 0:
            return None
        return insn
    except Exception as exc:
        msg("MEMBER: decode failed at %s: %s" % (ea_str(ea), exc))
        return None


def operand_displacement(insn, op_index):
    """(displacement, access_width) for a memory operand, or (None, 0).

    A register-indirect operand with no encoded displacement (`o_phrase`,
    e.g. `mov rax, [rcx]`) is a real access to offset 0 and is reported as
    such -- that is the zero-offset member case, not a failure.
    """
    if insn is None or not 0 <= op_index < UA_MAXOP:
        return None, 0
    op = insn.ops[op_index]
    try:
        width = int(ida_ua.get_dtype_size(op.dtype))
    except Exception:
        width = 0

    if op.type == ida_ua.o_displ:
        return signed_le(int(op.addr), 8), width
    if op.type == ida_ua.o_phrase:
        return 0, width
    return None, 0


def member_from_operand(ea, op_index):
    """MemberRef for a struct-offset operand, or None when it is not one.

    Reads IDA's own stroff association rather than inferring anything: the
    path names the structure, and the member is the field starting at
    displacement + delta. `delta` is the gap between the structure base and
    what the register actually points at, so it is added, not ignored.

    Only a single-element path is accepted. A nested path (`a.b.c`) names a
    member of a member, whose full offset is the sum along the path; that is
    not needed for the member_offset slice and guessing at it would produce a
    confidently wrong expected_value.
    """
    try:
        flags = ida_bytes.get_full_flags(ea)
    except Exception as exc:
        msg("MEMBER: cannot read flags at %s: %s" % (ea_str(ea), exc))
        return None

    try:
        if not ida_bytes.is_stroff(flags, op_index):
            return None
    except Exception:
        return None

    try:
        path, delta = ida_bytes.get_stroff_path(ea, op_index)
    except Exception as exc:
        msg("MEMBER: get_stroff_path failed at %s: %s" % (ea_str(ea), exc))
        return None

    if not path:
        return None
    if len(path) > 1:
        msg(
            "MEMBER: operand at %s uses a nested struct path (%d levels); "
            "declare the member on its immediate container instead"
            % (ea_str(ea), len(path))
        )
        return None

    owner = _struct_name_for_tid(path[0])
    if not owner:
        return None

    insn = decode_at(ea)
    disp, _width = operand_displacement(insn, op_index)
    if disp is None:
        return None

    byte_offset = disp + int(delta or 0)
    if byte_offset < 0:
        msg("MEMBER: operand at %s resolves to a negative offset" % ea_str(ea))
        return None
    return member_at_offset(owner, byte_offset)


def _struct_name_for_tid(tid):
    """Name of the structure a stroff path element refers to."""
    try:
        tif = ida_typeinf.tinfo_t()
        if tif.get_type_by_tid(tid) and tif.is_udt():
            return str(tif.get_type_name() or "")
    except Exception:
        pass
    # get_type_by_tid is the typed route; the name table is the fallback for
    # an odd tid shape rather than a reason to fail outright.
    try:
        return str(ida_name.get_name(tid) or "")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Reference discovery -- the only sanctioned source of extra candidates
# ---------------------------------------------------------------------------

def member_reference_sites(ref):
    """Addresses of instructions IDA associates with this exact member.

    These are cross-references to the member's tid, which IDA records when an
    operand is marked as a struct offset. They are trustworthy but incomplete
    -- see `cfs5/memberscan.py` -- so an empty result here means "IDA has no
    index entry", never "this member is unused".
    """
    if ref is None or ref.tid in (None, BADADDR):
        return []

    sites = set()
    try:
        for xref in idautils.XrefsTo(ref.tid):
            frm = int(xref.frm)
            try:
                if ida_bytes.is_code(ida_bytes.get_full_flags(frm)):
                    sites.add(frm)
            except Exception:
                continue
    except Exception as exc:
        msg("MEMBER: xref walk for %s failed: %s" % (ref.fullname, exc))
        return []
    return sorted(sites)


# ---------------------------------------------------------------------------
# Member creation
# ---------------------------------------------------------------------------

_WIDTH_TO_BTF = {
    1: "BTF_UINT8",
    2: "BTF_UINT16",
    4: "BTF_UINT32",
    8: "BTF_UINT64",
}


def _integral_type_for_width(width):
    """An unsigned integer tinfo_t of `width` bytes, defaulting to 8."""
    name = _WIDTH_TO_BTF.get(int(width), "BTF_UINT64")
    return getattr(ida_typeinf, name)


def create_member(owner, name, byte_offset, byte_size):
    """Add `name` to `owner` at `byte_offset`, then prove it is really there.

    The read-back is not ceremony. `add_udm` reports a tinfo_code_t that can
    be success while the type in the til is unchanged (a conflicting field, a
    type that is only a forward declaration), and a declaration built on a
    member that does not exist would export an expected_value of 0.

    Returns the created MemberRef, or None.
    """
    tif = get_struct_tinfo(owner)
    if tif is None:
        msg("MEMBER: %r is not a known structure type" % owner)
        return None

    existing = member_at_offset(owner, byte_offset)
    if existing is not None:
        msg("MEMBER: %s already has %s at 0x%X"
            % (owner, existing.name, byte_offset))
        return existing

    spanning = enclosing_member_name(owner, byte_offset)
    if spanning is not None:
        msg("MEMBER: %s+0x%X falls inside %s" % (owner, byte_offset, spanning))
        return None

    try:
        code = tif.add_udm(
            name, _integral_type_for_width(byte_size), _bits(byte_offset)
        )
    except Exception as exc:
        msg("MEMBER: add_udm(%s.%s) raised: %s" % (owner, name, exc))
        return None
    if code != ida_typeinf.TERR_OK:
        msg("MEMBER: add_udm(%s.%s @ 0x%X) refused: code=%s"
            % (owner, name, byte_offset, code))
        return None

    created = member_at_offset(owner, byte_offset)
    if created is None or created.name != name:
        msg("MEMBER: %s.%s did not survive a read-back at 0x%X"
            % (owner, name, byte_offset))
        return None

    msg("MEMBER: created %s.%s at 0x%X (%d bytes)"
        % (owner, name, byte_offset, byte_size))
    return created


def apply_stroff(ea, op_index, owner, delta=0):
    """Mark an operand as a struct offset into `owner`.

    Applying this is what turns a one-off selected operand into an indexed
    reference, so the *next* export can find this site (and others like it)
    through `member_reference_sites` instead of relying on the stored
    selection. It is the difference between a declaration that stays at one
    candidate forever and one that accumulates evidence as the IDB improves.
    """
    tif = get_struct_tinfo(owner)
    if tif is None:
        msg("MEMBER: cannot mark operand -- %r is not a structure" % owner)
        return False

    try:
        tid = tif.get_tid()
    except Exception as exc:
        msg("MEMBER: get_tid(%r) failed: %s" % (owner, exc))
        return False
    if tid in (None, BADADDR):
        msg("MEMBER: no tid for type %r" % owner)
        return False

    try:
        path = ida_pro.tid_array(1)
        path[0] = tid
        return bool(
            ida_bytes.op_stroff(ea, op_index, path.cast(), 1, int(delta))
        )
    except Exception as exc:
        msg("MEMBER: op_stroff failed at %s: %s" % (ea_str(ea), exc))
        return False
