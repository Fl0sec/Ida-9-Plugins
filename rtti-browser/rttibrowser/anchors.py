"""IDA-free byte search that locates MSVC RTTI anchors in raw image chunks.

The scan works RTTI-first instead of probing every pointer slot from Python:
type-descriptor names are found with one regex pass, then COLs that reference
those descriptors, then vtable slots that reference those COLs. Every pass is
a C-speed ``re`` sweep over large ``bytes`` buffers; Python only touches the
few hits. Results are *candidates* — the scanner still validates each one.

A chunk is ``(start_ea, data)``. Chunks may overlap (the reader overlaps them
so a pattern spanning a boundary is not lost); results are sets, so overlap
only costs duplicate hits.
"""

import re


TYPE_NAME_RE = re.compile(rb"\.\?A[UVT]")
COL_TD_FIELD = 12


def _byte_class(values):
    return b"[" + b"".join(b"\\x%02x" % value for value in sorted(values)) + b"]"


def key_pattern(keys, width):
    """Compile an overlapping-match regex that pre-filters ``width``-byte keys.

    Each byte position becomes a character class of the bytes seen at that
    position across all keys. That is a superset filter (callers re-check the
    exact value), but RTTI addresses share their high bytes, so it is highly
    selective and runs entirely inside ``re``.
    """
    encoded = [int(key).to_bytes(width, "little") for key in keys]
    if not encoded:
        return None
    classes = b"".join(
        _byte_class({raw[index] for raw in encoded}) for index in range(width)
    )
    return re.compile(b"(?=" + classes + b")")


def find_keys(chunks, keys, width, align, cancelled=None):
    """Yield ``(ea, key)`` for every aligned ``width``-byte occurrence of a key."""
    keys = {int(key) for key in keys}
    pattern = key_pattern(keys, width)
    if pattern is None:
        return
    for start_ea, data in chunks:
        if cancelled is not None:
            cancelled()
        for match in pattern.finditer(data):
            offset = match.start()
            ea = start_ea + offset
            if ea % align:
                continue
            value = int.from_bytes(data[offset:offset + width], "little")
            if value in keys:
                yield ea, value


def find_type_descriptors(chunks, pointer_size, cancelled=None):
    """Return candidate TypeDescriptor addresses (name string at +2 pointers)."""
    result = set()
    for start_ea, data in chunks:
        if cancelled is not None:
            cancelled()
        for match in TYPE_NAME_RE.finditer(data):
            td = start_ea + match.start() - pointer_size * 2
            if td % pointer_size == 0:
                result.add(td)
    return result


def find_cols(chunks, type_descriptors, pointer_size, image_base, cancelled=None):
    """Return candidate COL addresses whose TD field names a known descriptor.

    x86 COLs hold an absolute TD pointer; x64 COLs hold an image RVA.
    """
    if pointer_size == 8:
        keys = {td - image_base for td in type_descriptors
                if 0 <= td - image_base < 1 << 32}
    else:
        keys = {td for td in type_descriptors if 0 <= td < 1 << 32}
    return {ea - COL_TD_FIELD
            for ea, _ in find_keys(chunks, keys, 4, 4, cancelled)}


def find_vtable_slots(chunks, cols, pointer_size, cancelled=None):
    """Return addresses of pointer slots that hold a COL (vtable minus one slot)."""
    return {ea for ea, _ in find_keys(
        chunks, cols, pointer_size, pointer_size, cancelled,
    )}
