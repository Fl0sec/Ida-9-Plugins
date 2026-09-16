"""Instruction decoding, operand-aware pattern tokenization and signed
PC-relative field inference.

The tokenizer wildcards address-dependent operand bytes so signatures survive
rebasing. PC-relative inference never assumes rel32-at-offset-3: it decodes the
instruction, then searches operand fields/widths for the one whose signed
displacement, added to the *end of the whole instruction* (trailing immediates
included), lands exactly on the known target. That makes it correct for
`mov [rip+disp32], imm32` and every other rip-relative-plus-immediate form.
"""

import ida_bytes
import ida_ua
import ida_xref

from .common import BADADDR, UA_MAXOP


def iter_fcrefs_from(ea):
    cur = ida_xref.get_first_fcref_from(ea)
    while cur != BADADDR:
        yield cur
        cur = ida_xref.get_next_fcref_from(ea, cur)


def iter_drefs_from(ea):
    cur = ida_xref.get_first_dref_from(ea)
    while cur != BADADDR:
        yield cur
        cur = ida_xref.get_next_dref_from(ea, cur)


def has_far_reference(ea):
    return (
        ida_xref.get_first_fcref_from(ea) != BADADDR
        or ida_xref.get_first_dref_from(ea) != BADADDR
    )


def collect_far_xrefs_to(target_ea):
    """Code (call/jump) references to target_ea, deduplicated and sorted."""
    refs = []
    cur = ida_xref.get_first_fcref_to(target_ea)
    while cur != BADADDR:
        refs.append(cur)
        cur = ida_xref.get_next_fcref_to(target_ea, cur)
    return sorted(set(refs))


def collect_data_xrefs_to(target_ea):
    """Data references to target_ea that live inside code (usable as anchors).

    A global can also be referenced from another data blob (a pointer table);
    those are skipped because they cannot form an instruction signature.
    """
    refs = []
    cur = ida_xref.get_first_dref_to(target_ea)
    while cur != BADADDR:
        try:
            if ida_bytes.is_code(ida_bytes.get_full_flags(cur)):
                refs.append(cur)
        except Exception:
            pass
        cur = ida_xref.get_next_dref_to(target_ea, cur)
    return sorted(set(refs))


def operand_encoded_ranges(insn):
    """Return [(operand_index, offb, end_off, optype), ...] for encoded fields."""
    entries = []
    for i in range(UA_MAXOP):
        op = insn.ops[i]
        if op.type == ida_ua.o_void:
            break
        offb = int(op.offb)
        if 0 < offb < insn.size:
            entries.append((i, offb, op.type))

    unique_offsets = sorted(set(off for _i, off, _t in entries))
    result = []
    for i, offb, optype in entries:
        later = [x for x in unique_offsets if x > offb]
        end_off = min(later) if later else insn.size
        if end_off <= offb:
            end_off = insn.size
        result.append((i, offb, end_off, optype))
    return result


def field_span_for_offb(insn, offb):
    offsets = sorted(
        set(x[1] for x in operand_encoded_ranges(insn) if x[1] >= offb)
    )
    later = [x for x in offsets if x > offb]
    end = min(later) if later else insn.size
    return max(0, end - offb)


def pattern_tokens_for_insn(insn, force_wildcard=None):
    """Exact instruction bytes with address-dependent operand bytes wildcarded.

    force_wildcard=(offb, width) additionally wildcards one validated field --
    a REL displacement, or the field a VALUE candidate extracts -- guaranteeing
    those bytes become `?` even if IDA's operand metadata is odd for that
    instruction. Both callers rely on it for the same reason: the field is
    expected to differ in another build, so pinning it would defeat the
    pattern.
    """
    raw = ida_bytes.get_bytes(insn.ea, insn.size)
    if raw is None or len(raw) != insn.size:
        raw = bytes(ida_bytes.get_byte(insn.ea + i) for i in range(insn.size))

    tokens = ["%02X" % b for b in raw]
    wildcard = set()

    if has_far_reference(insn.ea):
        address_like = {
            ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem,
            ida_ua.o_displ, ida_ua.o_imm
        }
        for _idx, offb, end_off, optype in operand_encoded_ranges(insn):
            if optype in address_like:
                for j in range(offb, min(end_off, insn.size)):
                    wildcard.add(j)

    if force_wildcard is not None:
        offb, width = force_wildcard
        for j in range(offb, min(offb + width, insn.size)):
            wildcard.add(j)

    for j in wildcard:
        tokens[j] = "?"

    return tokens


def decode_chunk(start_ea, end_ea):
    """Decode one contiguous chunk without crossing its boundary.

    Returns a list of {ea, size, tokens, insn} dicts; undecodable bytes become
    1-byte pseudo-instructions so window math stays contiguous.
    """
    insns = []
    ea = start_ea
    while ea < end_ea:
        insn = ida_ua.insn_t()
        n = ida_ua.decode_insn(insn, ea)
        if n <= 0 or insn.size <= 0 or ea + insn.size > end_ea:
            raw = ida_bytes.get_byte(ea)
            insns.append({
                "ea": ea, "size": 1, "tokens": ["%02X" % raw], "insn": None
            })
            ea += 1
            continue

        insns.append({
            "ea": ea,
            "size": int(insn.size),
            "tokens": pattern_tokens_for_insn(insn),
            "insn": insn,
        })
        ea += insn.size

    return insns


def signed_le(value, nbytes):
    """Reinterpret the low `nbytes` of `value` as a signed little-endian int."""
    bits = nbytes * 8
    value &= (1 << bits) - 1
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


def displacement_operands(insn):
    """Operand indices of `insn` that carry a memory displacement."""
    out = []
    for i in range(UA_MAXOP):
        op = insn.ops[i]
        if op.type == ida_ua.o_void:
            break
        if op.type == ida_ua.o_displ:
            out.append(i)
    return out


def infer_displacement_field(insn, expected_value):
    """Locate the encoded displacement field whose value is `expected_value`.

    The derived_value analogue of `infer_pc_relative_field`, and deliberately
    stricter. It does **not** search instruction bytes for a matching number:
    it walks the operands the decoder reported, takes each one's own
    displacement (`op.addr`), and only then confirms that the byte span the
    decoder assigned to that operand reproduces the same value when read as a
    signed little-endian integer. Both halves must agree, so the offset and
    width written into the file are the decoder's, never a guess -- and a
    consumer reading those bytes is guaranteed to get what we saw.

    Ambiguity is failure: if two operands could both be meant, there is no
    candidate. Returns a dict with operand_index / field_offset (relative to
    the instruction) / field_size, or None.
    """
    raw = ida_bytes.get_bytes(insn.ea, insn.size)
    if raw is None or len(raw) != insn.size:
        return None

    expected = int(expected_value)
    matches = []

    for i in displacement_operands(insn):
        op = insn.ops[i]
        # op.addr is unsigned 64-bit; a negative displacement arrives as its
        # two's-complement, so compare after sign extension.
        if signed_le(int(op.addr), 8) != expected:
            continue

        offb = int(op.offb)
        # offb == 0 means the decoder did not record a position (byte 0 is the
        # opcode), so there is nothing a consumer could read.
        if not 0 < offb < insn.size:
            continue

        size = field_span_for_offb(insn, offb)
        if size not in (1, 2, 4, 8) or offb + size > insn.size:
            continue

        field = int.from_bytes(raw[offb:offb + size], byteorder="little")
        if signed_le(field, size) != expected:
            continue

        matches.append({
            "operand_index": i,
            "field_offset": offb,
            "field_size": size,
        })

    if len(matches) != 1:
        return None
    return matches[0]


def infer_pc_relative_field(insn, target_ea):
    """Find the encoded signed displacement that resolves to target_ea.

    Returns (offb, width) with width in {1,2,4,8}, or None. Anchored on
    insn.ea + insn.size, so trailing immediates never skew the base.
    """
    raw_insn = ida_bytes.get_bytes(insn.ea, insn.size)
    if raw_insn is None or len(raw_insn) != insn.size:
        return None

    for _idx, offb, _end, _type in operand_encoded_ranges(insn):
        span = field_span_for_offb(insn, offb)
        widths = []
        for w in (span, 4, 1, 2, 8):
            if w in (1, 2, 4, 8) and w not in widths:
                widths.append(w)

        for width in widths:
            if offb + width > insn.size:
                continue
            data = raw_insn[offb:offb + width]
            disp = int.from_bytes(data, byteorder="little", signed=True)
            resolved = insn.ea + insn.size + disp
            if resolved == target_ea:
                return offb, width

    return None
