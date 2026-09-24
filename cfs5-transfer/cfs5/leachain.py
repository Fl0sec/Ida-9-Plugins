"""Minimal x86-64 LEA decoding and coefficient folding for stride recipes."""


class LeaChainError(ValueError):
    pass


def decode_lea(raw):
    """Return dst/base/index/scale for one x86-64 LEA encoding."""
    raw = bytes(raw)
    i = 0
    rex = 0
    while i < len(raw):
        byte = raw[i]
        if 0x40 <= byte <= 0x4F:
            rex = byte
            i += 1
            continue
        if byte in (0x66, 0x67, 0xF2, 0xF3):
            i += 1
            continue
        break
    if i >= len(raw) or raw[i] != 0x8D:
        raise LeaChainError("step is not an encoded LEA")
    i += 1
    if i >= len(raw):
        raise LeaChainError("LEA has no ModRM")
    modrm = raw[i]
    i += 1
    mod = modrm >> 6
    if mod == 3:
        raise LeaChainError("LEA source is not memory")
    dst = ((modrm >> 3) & 7) | (((rex >> 2) & 1) << 3)
    rm = modrm & 7
    base = None
    index = None
    scale = 1
    if rm == 4:
        if i >= len(raw):
            raise LeaChainError("LEA has no SIB")
        sib = raw[i]
        scale = 1 << (sib >> 6)
        raw_index = (sib >> 3) & 7
        raw_base = sib & 7
        if not (raw_index == 4 and not (rex & 2)):
            index = raw_index | (((rex >> 1) & 1) << 3)
        if not (mod == 0 and raw_base == 5):
            base = raw_base | ((rex & 1) << 3)
    elif not (mod == 0 and rm == 5):
        base = rm | ((rex & 1) << 3)
    return {"dst": dst, "base": base, "index": index, "scale": scale}


def fold_coefficients(decoded_steps):
    """Fold index coefficients, treating unknown external bases as additive."""
    coefficients = {}
    for position, step in enumerate(decoded_steps):
        dst = step["dst"]
        base = step.get("base")
        index = step.get("index")
        if position == 0 and dst not in coefficients:
            # The first in-place LEA consumes the unit index established by
            # the preceding movsxd. Other unknown registers are external bases.
            coefficients[dst] = 1
        base_coeff = coefficients.get(base, 0) if base is not None else 0
        index_coeff = coefficients.get(index, 0) if index is not None else 0
        coefficients[dst] = base_coeff + index_coeff * int(step.get("scale", 1))
    if not decoded_steps:
        raise LeaChainError("LEA chain is empty")
    return coefficients[decoded_steps[-1]["dst"]]
