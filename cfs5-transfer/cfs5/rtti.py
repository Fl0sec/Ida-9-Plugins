"""Targeted MSVC RTTI lookup: a class name and a slot to a function address.

Ported, deliberately, rather than imported. The equivalent logic in
`ida-pro-mcp/src/ida_pro_mcp/ida_mcp/api_rtti.py` is already debugged against
this exact binary, but every public function there is wrapped in `@tool` /
`@idasync` from that package's `.rpc` / `.sync`, so importing it would drag the
MCP server runtime into an IDA plugin -- and it lives in a git-ignored upstream
checkout this repo must never depend on.

Two deliberate differences from the original:

* **The raw type descriptor is returned, never a demangled name.** The upstream
  `_type_name` runs `demangle_name` and strips `class `/`struct `, producing
  `CCSPlayerInventory` -- an IDA-side rendering a non-IDA dumper cannot
  reproduce. What goes in the file is `.?AVCCSPlayerInventory@@`, the bytes
  that are actually in the image.
* **C strings are cut at the NUL here, not read with
  `ida_bytes.get_strlit_contents`.** Measured on client.dll 14182, that call
  returns `.?AVCCSPlayerInventory@@H` for a descriptor whose bytes are
  `.?AVCCSPlayerInventory@@\\0` -- it honours IDA's string-item length rather
  than the terminator, appending a byte that is not part of the name. Writing
  that into a record would produce a descriptor no consumer could ever match.

Lookup is targeted, never an image-wide scan: the `??_R4` symbol IDA's own RTTI
analysis already created, its data xrefs, and a validated COL. A whole-image
vtable enumeration is exactly the kind of sweep that makes this unusable on a
40MB DLL.
"""

import ida_bytes
import ida_idaapi
import ida_name
import ida_segment
import ida_xref
import idautils

from .common import BADADDR, ea_str, msg


_MAX_METHODS = 4096
_MAX_BASES = 4096

# The COL symbol IDA's RTTI analysis emits, and the separator that ends the
# class name inside it: `??_R4CCSPlayerInventory@@6B@`.
_COL_PREFIX = "??_R4"
_COL_SEPARATOR = "@@6B"

# Type-descriptor prefixes for a class and a struct respectively.
_DESCRIPTOR_PREFIXES = (".?AV", ".?AU")


class RttiError(Exception):
    """A lookup that could not be completed honestly."""


class VtableInfo:
    """One validated RTTI vtable."""

    __slots__ = (
        "ea", "col_ea", "type_descriptor", "subobject_offset", "method_count",
    )

    def __init__(self, ea, col_ea, type_descriptor, subobject_offset,
                 method_count):
        self.ea = int(ea)
        self.col_ea = int(col_ea)
        self.type_descriptor = type_descriptor
        self.subobject_offset = int(subobject_offset)
        self.method_count = int(method_count)

    def __repr__(self):
        return "VtableInfo(%s, %s, +%d, %d slots)" % (
            ea_str(self.ea), self.type_descriptor,
            self.subobject_offset, self.method_count,
        )


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def _ptr_size():
    # This format is x64 PE only; the 32-bit RTTI layout stores absolute
    # pointers instead of image-relative offsets and is not supported.
    return 8


def _read_u32(ea):
    data = ida_bytes.get_bytes(ea, 4)
    return int.from_bytes(data, "little") if data and len(data) == 4 else None


def _signed32(value):
    return value - 0x100000000 if value & 0x80000000 else value


def _read_ptr(ea):
    size = _ptr_size()
    data = ida_bytes.get_bytes(ea, size)
    return int.from_bytes(data, "little") if data and len(data) == size else None


def _mapped(ea, size=1):
    try:
        return (
            ea != BADADDR
            and ida_bytes.is_mapped(ea)
            and ida_bytes.is_mapped(ea + size - 1)
        )
    except Exception:
        return False


def _relative_or_pointer(field_ea, image_base):
    """An image-relative RTTI field resolved to an address."""
    value = _read_u32(field_ea)
    return image_base + _signed32(value) if value is not None else None


def _read_c_string(ea, limit=2048):
    """The NUL-terminated string at `ea`, cut at the terminator.

    Deliberately not `ida_bytes.get_strlit_contents`: see the module docstring
    for the measured case where that returns a trailing byte past the NUL.
    """
    raw = ida_bytes.get_bytes(ea, limit)
    if not raw:
        return None
    end = raw.find(b"\0")
    if end < 0:
        return None
    try:
        return raw[:end].decode("ascii")
    except Exception:
        return None


def _descriptor_name(type_descriptor_ea):
    """The raw mangled descriptor, e.g. `.?AVCCSPlayerInventory@@`."""
    raw = _read_c_string(type_descriptor_ea + (_ptr_size() * 2))
    if not raw or not raw.startswith(".?"):
        return None
    return raw


def _is_code(ea):
    try:
        seg = ida_segment.getseg(ea)
    except Exception:
        return False
    return seg is not None and seg.type == ida_segment.SEG_CODE


def _has_data_xref(ea):
    return ida_xref.get_first_dref_to(ea) != BADADDR


# ---------------------------------------------------------------------------
# Structure validation (ported; this is the part already debugged upstream)
# ---------------------------------------------------------------------------

def _valid_type_descriptor(ea):
    if not _mapped(ea, (_ptr_size() * 2) + 5):
        return False
    vfptr = _read_ptr(ea)
    spare = _read_ptr(ea + _ptr_size())
    return bool(vfptr and _mapped(vfptr) and spare == 0 and _descriptor_name(ea))


def _valid_bcd(ea, image_base):
    if not _mapped(ea, 24):
        return False
    attributes = _read_u32(ea + 20)
    td = _relative_or_pointer(ea, image_base)
    return (
        attributes is not None
        and not attributes & 0xFFFFFF00
        and td is not None
        and _valid_type_descriptor(td)
    )


def _valid_chd(ea, image_base):
    if not _mapped(ea, 16):
        return False
    signature = _read_u32(ea)
    attributes = _read_u32(ea + 4)
    count = _read_u32(ea + 8)
    bca = _relative_or_pointer(ea + 12, image_base)
    if signature != 0 or attributes is None or attributes & ~0x0F:
        return False
    if count is None or not 1 <= count <= _MAX_BASES:
        return False
    if bca is None or not _mapped(bca, 4):
        return False
    first_bcd = _relative_or_pointer(bca, image_base)
    return first_bcd is not None and _valid_bcd(first_bcd, image_base)


def _parse_col(ea):
    """(image_base, object_offset, type_descriptor_ea) for a valid COL, or None."""
    if not _mapped(ea, 24):
        return None
    signature = _read_u32(ea)
    offset = _read_u32(ea + 4)
    if signature != 1 or offset is None:
        return None
    object_base = _read_u32(ea + 20)
    if object_base is None:
        return None
    image_base = ea - _signed32(object_base)
    type_descriptor = _relative_or_pointer(ea + 12, image_base)
    hierarchy = _relative_or_pointer(ea + 16, image_base)
    if type_descriptor is None or hierarchy is None:
        return None
    if not _valid_type_descriptor(type_descriptor):
        return None
    if not _valid_chd(hierarchy, image_base):
        return None
    return image_base, offset, type_descriptor


def _method_count(vtable_ea):
    """How many consecutive code pointers form the table.

    Stops at the first non-code pointer, and at any later entry that is itself
    referenced from data -- that is the next table beginning.
    """
    size = _ptr_size()
    count = 0
    for slot in range(_MAX_METHODS):
        entry = vtable_ea + slot * size
        target = _read_ptr(entry)
        if not target or not _is_code(target):
            break
        if slot and _has_data_xref(entry):
            break
        count += 1
    return count


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------

def class_name_of(target):
    """The bare class name from a raw descriptor or a plain name."""
    text = str(target or "").strip()
    if not text:
        return ""
    for prefix in _DESCRIPTOR_PREFIXES:
        if text.startswith(prefix):
            body = text[len(prefix):]
            return body[:-2] if body.endswith("@@") else body
    return text


def _col_symbol(name):
    """IDA's exact Complete Object Locator symbol for a class name."""
    return "%s%s%s@" % (_COL_PREFIX, name, _COL_SEPARATOR)


def _vtable_from_col_pointer(pointer_ea):
    """A VtableInfo for a `[col_ptr][slot0...]` pair, or None.

    The validity test is what rejects the decoys: a COL is also referenced from
    inside the RTTI structures themselves, and following one of those yields a
    "vtable" whose first slot is not code. Measured on client.dll 14182,
    `??_R4CCSPlayerInventory@@6B@` has exactly two data xrefs and only one of
    them is the real table.
    """
    col_ea = _read_ptr(pointer_ea)
    if col_ea is None:
        return None
    parsed = _parse_col(col_ea)
    if parsed is None:
        return None
    _image_base, offset, type_descriptor = parsed

    vtable_ea = pointer_ea + _ptr_size()
    count = _method_count(vtable_ea)
    if not count:
        return None
    descriptor = _descriptor_name(type_descriptor)
    if not descriptor:
        return None
    return VtableInfo(vtable_ea, col_ea, descriptor, offset, count)


def find_vtables(target):
    """Every validated vtable for `target`, a class name or raw descriptor."""
    wanted = class_name_of(target)
    if not wanted:
        raise RttiError("no class name given")

    symbol = _col_symbol(wanted)
    col_ea = ida_name.get_name_ea(BADADDR, symbol)
    if col_ea == BADADDR:
        return []

    found = []
    seen = set()
    for pointer_ea in idautils.DataRefsTo(col_ea):
        try:
            info = _vtable_from_col_pointer(pointer_ea)
        except Exception as exc:
            msg("RTTI_NOTE: %s unusable as a vtable pointer (%s)"
                % (ea_str(pointer_ea), exc))
            continue
        if info is not None and info.ea not in seen:
            seen.add(info.ea)
            found.append(info)

    found.sort(key=lambda v: (v.subobject_offset, v.ea))
    return found


def find_vtable(target, subobject_offset=None):
    """The single vtable for `target`, or RttiError naming the ambiguity.

    A class with multiple inheritance has one vtable per subobject, and they
    are different tables with different slot numbering. Picking one silently
    would produce a locator that resolves to a plausible wrong function, so an
    ambiguous request is refused with the offsets that *are* available.
    """
    matches = find_vtables(target)
    if not matches:
        raise RttiError(
            "no MSVC RTTI vtable for %r (looked for a %s%s%s symbol)"
            % (target, _COL_PREFIX, class_name_of(target), _COL_SEPARATOR)
        )

    if subobject_offset is not None:
        wanted = int(subobject_offset)
        exact = [v for v in matches if v.subobject_offset == wanted]
        if not exact:
            raise RttiError(
                "%r has no subobject at offset %d; available: %s"
                % (target, wanted,
                   ", ".join(str(v.subobject_offset) for v in matches))
            )
        if len(exact) > 1:
            raise RttiError(
                "%r has %d vtables at subobject offset %d; this is ambiguous"
                % (target, len(exact), wanted)
            )
        return exact[0]

    if len(matches) > 1:
        raise RttiError(
            "%r has %d subobject vtables (offsets %s); pass subobject_offset "
            "to choose one" % (
                target, len(matches),
                ", ".join(str(v.subobject_offset) for v in matches),
            )
        )
    return matches[0]


def read_slot(vtable, slot):
    """The function address in `slot`, bounds-checked against the method count.

    `vtable` is a VtableInfo or a raw address; a raw address is re-validated
    rather than trusted.
    """
    if not isinstance(vtable, VtableInfo):
        info = _vtable_from_col_pointer(int(vtable) - _ptr_size())
        if info is None:
            raise RttiError("no validated RTTI vtable at %s" % ea_str(vtable))
        vtable = info

    slot = int(slot)
    if slot < 0 or slot >= vtable.method_count:
        raise RttiError(
            "slot %d is outside the vtable's %d slot(s)"
            % (slot, vtable.method_count)
        )

    entry = vtable.ea + slot * _ptr_size()
    target = _read_ptr(entry)
    if target is None or not _is_code(target):
        raise RttiError("vtable slot %d does not hold a code pointer" % slot)
    return target, entry


def verify_slot(target, slot, expected_func_ea, subobject_offset=None):
    """(ok, reason) -- does `target` slot `slot` really hold `expected_func_ea`?

    The declaration-time check behind a VTABLE locator. It exists so a wrong
    slot number is refused while the caller is still looking at it, rather than
    silently exporting a locator that resolves to a different function.
    """
    try:
        vtable = find_vtable(target, subobject_offset)
    except RttiError as exc:
        return False, str(exc)

    try:
        func_ea, _entry = read_slot(vtable, slot)
    except RttiError as exc:
        return False, str(exc)

    if int(func_ea) != int(expected_func_ea):
        return False, (
            "%s slot %d holds %s, not %s"
            % (vtable.type_descriptor, slot, ea_str(func_ea),
               ea_str(expected_func_ea))
        )
    return True, ""
