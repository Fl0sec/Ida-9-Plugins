"""Validated MSVC RTTI discovery extracted from the proven MCP/CFS layer.

This module deliberately contains no MCP decorators, pagination, type creation,
or CFS policy. Its contract ends at validated COL/CHD/BCD/vtable records and
live virtual-slot reads.
"""

from dataclasses import dataclass

import ida_auto
import ida_bytes
import ida_ida
import ida_idaapi
import ida_name
import ida_nalt
import ida_segment
import ida_xref
import idautils

from .common import ScanCancelled, msg
from .model import (
    BaseRecord, MAX_BASES, MAX_METHODS, Snapshot, VtableRecord,
    class_sort_key,
)
from .presentation import descriptor_fallback


@dataclass(frozen=True)
class _Col:
    ea: int
    image_base: int
    offset: int
    cd_offset: int
    type_descriptor: int
    hierarchy_descriptor: int


@dataclass(frozen=True)
class _ParsedVtable:
    ea: int
    col: _Col
    class_name: str
    subobject: str
    bases: tuple
    attributes: int
    method_count: int


class RttiScanner:
    """Read and validate MSVC RTTI in the current IDB."""

    def __init__(self, cancelled=None, progress=None, diagnostic=None):
        self.cancelled = cancelled or (lambda: False)
        self.progress = progress or (lambda _stage, _current, _total: None)
        self.diagnostic = diagnostic or msg
        self.image_base = int(ida_nalt.get_imagebase())
        self.pointer_size = 8 if ida_ida.inf_is_64bit() else 4
        self._ticks = 0

    def _check_cancelled(self, force=False):
        self._ticks += 1
        if (force or self._ticks % 1024 == 0) and self.cancelled():
            raise ScanCancelled("RTTI scan cancelled")

    def _read_u32(self, ea):
        data = ida_bytes.get_bytes(ea, 4)
        return int.from_bytes(data, "little") if data and len(data) == 4 else None

    @staticmethod
    def _signed32(value):
        return value - 0x100000000 if value & 0x80000000 else value

    def _read_ptr(self, ea):
        data = ida_bytes.get_bytes(ea, self.pointer_size)
        if not data or len(data) != self.pointer_size:
            return None
        return int.from_bytes(data, "little")

    @staticmethod
    def _mapped(ea, size=1):
        try:
            return (
                ea != ida_idaapi.BADADDR
                and ida_bytes.is_mapped(ea)
                and ida_bytes.is_mapped(ea + size - 1)
            )
        except Exception:
            return False

    def _relative_or_pointer(self, field_ea, image_base):
        if self.pointer_size == 8:
            value = self._read_u32(field_ea)
            return (image_base + self._signed32(value)
                    if value is not None else None)
        return self._read_ptr(field_ea)

    def _read_c_string(self, ea, limit=2048):
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

    def _type_name(self, type_descriptor):
        raw = self._read_c_string(type_descriptor + (self.pointer_size * 2))
        if not raw or not raw.startswith(".?"):
            return None
        decorated = raw[1:]
        demangled = ida_name.demangle_name(decorated, ida_name.MNG_SHORT_FORM)
        if demangled:
            for prefix in ("class ", "struct ", "union "):
                if demangled.startswith(prefix):
                    return demangled[len(prefix):]
            return demangled
        # Replacing every '@' with '::' only works for simple descriptors. In
        # template/lambda encodings it produces enormous, misleading strings
        # such as ``?$...::::``. The fallback preserves those decorated names
        # honestly so the chooser can hide them only in its relevant view.
        return descriptor_fallback(raw)

    def _valid_type_descriptor(self, ea):
        if not self._mapped(ea, (self.pointer_size * 2) + 5):
            return False
        vfptr = self._read_ptr(ea)
        spare = self._read_ptr(ea + self.pointer_size)
        return bool(vfptr and self._mapped(vfptr) and spare == 0
                    and self._type_name(ea))

    def _valid_bcd(self, ea, image_base):
        if not self._mapped(ea, 24):
            return False
        attributes = self._read_u32(ea + 20)
        td = self._relative_or_pointer(ea, image_base)
        return (
            attributes is not None
            and not attributes & 0xFFFFFF00
            and td is not None
            and self._valid_type_descriptor(td)
        )

    def _valid_chd(self, ea, image_base):
        if not self._mapped(ea, 16):
            return False
        signature = self._read_u32(ea)
        attributes = self._read_u32(ea + 4)
        count = self._read_u32(ea + 8)
        bca = self._relative_or_pointer(ea + 12, image_base)
        if signature != 0 or attributes is None or attributes & ~0x0F:
            return False
        if count is None or not 1 <= count <= MAX_BASES:
            return False
        if bca is None or not self._mapped(bca, 4):
            return False
        first = self._relative_or_pointer(bca, image_base)
        return first is not None and self._valid_bcd(first, image_base)

    def _parse_col(self, ea):
        size = 24 if self.pointer_size == 8 else 20
        if not self._mapped(ea, size):
            return None
        signature = self._read_u32(ea)
        offset = self._read_u32(ea + 4)
        cd_offset = self._read_u32(ea + 8)
        if None in (signature, offset, cd_offset):
            return None
        if self.pointer_size == 8:
            if signature != 1:
                return None
            object_base = self._read_u32(ea + 20)
            if object_base is None:
                return None
            image_base = ea - self._signed32(object_base)
        else:
            if signature != 0:
                return None
            image_base = 0
        td = self._relative_or_pointer(ea + 12, image_base)
        chd = self._relative_or_pointer(ea + 16, image_base)
        if td is None or chd is None:
            return None
        if not self._valid_type_descriptor(td) or not self._valid_chd(chd, image_base):
            return None
        return _Col(ea, image_base, offset, cd_offset, td, chd)

    def _parse_bases(self, col):
        count = self._read_u32(col.hierarchy_descriptor + 8)
        bca = self._relative_or_pointer(
            col.hierarchy_descriptor + 12, col.image_base,
        )
        if count is None or bca is None or not 1 <= count <= MAX_BASES:
            return None
        result = []
        for index in range(count):
            self._check_cancelled()
            bcd = self._relative_or_pointer(bca + index * 4, col.image_base)
            if bcd is None or not self._valid_bcd(bcd, col.image_base):
                return None
            td = self._relative_or_pointer(bcd, col.image_base)
            values = [self._read_u32(bcd + offset)
                      for offset in (4, 8, 12, 16, 20)]
            if td is None or any(value is None for value in values):
                return None
            name = self._type_name(td)
            if not name:
                return None
            contained, mdisp, pdisp, vdisp, attributes = values
            result.append((
                name, bcd, td, contained, self._signed32(mdisp),
                self._signed32(pdisp), self._signed32(vdisp), attributes,
            ))
        return tuple(result)

    @staticmethod
    def _is_code(ea):
        try:
            segment = ida_segment.getseg(ea)
        except Exception:
            return False
        return segment is not None and segment.type == ida_segment.SEG_CODE

    @staticmethod
    def _has_data_xref(ea):
        return ida_xref.get_first_dref_to(ea) != ida_idaapi.BADADDR

    def _method_count(self, vtable_ea):
        count = 0
        for slot in range(MAX_METHODS):
            self._check_cancelled()
            entry = vtable_ea + slot * self.pointer_size
            target = self._read_ptr(entry)
            if not target or not self._is_code(target):
                break
            if slot and self._has_data_xref(entry):
                break
            count += 1
        return count

    def _parse_vtable_pointer(self, pointer_ea):
        col_ea = self._read_ptr(pointer_ea)
        if col_ea is None:
            return None
        col = self._parse_col(col_ea)
        if col is None:
            return None
        vtable_ea = pointer_ea + self.pointer_size
        first = self._read_ptr(vtable_ea)
        if not first or not self._is_code(first):
            return None
        bases = self._parse_bases(col)
        class_name = self._type_name(col.type_descriptor)
        attributes = self._read_u32(col.hierarchy_descriptor + 4)
        count = self._method_count(vtable_ea)
        if bases is None or not class_name or attributes is None or not count:
            return None
        subobject = class_name
        if col.offset:
            for base in bases:
                if base[4] == col.offset:
                    subobject = base[0]
                    break
        return _ParsedVtable(
            vtable_ea, col, class_name, subobject, bases, attributes, count,
        )

    def _candidate_pointers(self, deep_scan):
        candidates = set()
        names = list(idautils.Names())
        for index, (ea, name) in enumerate(names):
            self._check_cancelled()
            if index % 4096 == 0:
                self.progress("IDA RTTI names", index, len(names))
            if name.startswith("??_R4"):
                for xref in idautils.DataRefsTo(ea):
                    candidates.add(int(xref))

        if not deep_scan:
            return candidates

        segments = []
        total = 0
        for index in range(ida_segment.get_segm_qty()):
            segment = ida_segment.getnseg(index)
            if segment is None or segment.type != ida_segment.SEG_DATA:
                continue
            start = ((segment.start_ea + self.pointer_size - 1)
                     & ~(self.pointer_size - 1))
            slots = max(0, (segment.end_ea - start) // self.pointer_size)
            segments.append((start, segment.end_ea, slots))
            total += slots

        visited = 0
        for start, end, slots in segments:
            stop = end - (self.pointer_size * 2) + 1
            for pointer_ea in range(start, max(start, stop), self.pointer_size):
                self._check_cancelled()
                if visited % 32768 == 0:
                    self.progress("Deep RTTI candidates", visited, total)
                visited += 1
                col_ea = self._read_ptr(pointer_ea)
                slot_zero = self._read_ptr(pointer_ea + self.pointer_size)
                if (col_ea and self._mapped(col_ea, 20)
                        and slot_zero and self._is_code(slot_zero)):
                    candidates.add(pointer_ea)
            visited += max(0, slots - max(0, (stop - start) // self.pointer_size))
        return candidates

    def scan(self, identity, deep_scan=True):
        """Return one validated, RVA-based snapshot for the current IDB."""
        ida_auto.auto_wait()
        candidates = sorted(self._candidate_pointers(deep_scan))
        found = []
        seen = set()
        for index, pointer_ea in enumerate(candidates):
            self._check_cancelled()
            if index % 64 == 0:
                self.progress("Validating RTTI", index, len(candidates))
            try:
                parsed = self._parse_vtable_pointer(pointer_ea)
            except ScanCancelled:
                raise
            except Exception as exc:
                self.diagnostic("candidate 0x%X failed: %s" % (pointer_ea, exc))
                continue
            if parsed is None or parsed.ea in seen:
                continue
            seen.add(parsed.ea)
            found.append(self._record(parsed))
        self.progress("Validating RTTI", len(candidates), len(candidates))
        return Snapshot(identity, tuple(sorted(found, key=class_sort_key)))

    def _record(self, parsed):
        def rva(ea):
            return int(ea) - self.image_base

        bases = tuple(BaseRecord(
            name, rva(bcd), rva(td), contained, mdisp, pdisp, vdisp, attrs,
        ) for name, bcd, td, contained, mdisp, pdisp, vdisp, attrs
                      in parsed.bases)
        return VtableRecord(
            rva(parsed.ea), rva(parsed.col.ea),
            rva(parsed.col.type_descriptor),
            rva(parsed.col.hierarchy_descriptor), parsed.class_name,
            parsed.subobject, parsed.col.offset, parsed.col.cd_offset,
            parsed.attributes, parsed.method_count, bases,
        )

    def validate_anchor(self, record):
        """Fast O(1)-per-vtable validation for persisted class metadata."""
        vtable_ea = self.image_base + record.vtable_rva
        col_ea = self._read_ptr(vtable_ea - self.pointer_size)
        parsed = self._parse_col(col_ea) if col_ea is not None else None
        if parsed is None:
            return False, "COL pointer is no longer valid"
        if (
            parsed.ea - self.image_base != record.col_rva
            or parsed.type_descriptor - self.image_base
            != record.type_descriptor_rva
            or parsed.hierarchy_descriptor - self.image_base
            != record.hierarchy_descriptor_rva
            or parsed.offset != record.object_offset
            or self._type_name(parsed.type_descriptor) != record.class_name
        ):
            return False, "RTTI anchor identity changed"
        attributes = self._read_u32(parsed.hierarchy_descriptor + 4)
        bases = self._parse_bases(parsed)
        if attributes != record.attributes or bases is None:
            return False, "RTTI hierarchy changed"
        live_bases = tuple(
            (base[0], base[4], base[5], base[6], base[7]) for base in bases
        )
        cached_bases = tuple(
            (base.name, base.mdisp, base.pdisp, base.vdisp, base.attributes)
            for base in record.bases
        )
        if live_bases != cached_bases:
            return False, "RTTI base hierarchy changed"
        subobject = record.class_name
        if record.object_offset:
            for base in bases:
                if base[4] == record.object_offset:
                    subobject = base[0]
                    break
        if subobject != record.subobject:
            return False, "RTTI subobject identity changed"
        first = self._read_ptr(vtable_ea)
        last_ea = vtable_ea + (record.method_count - 1) * self.pointer_size
        last = self._read_ptr(last_ea)
        if not first or not last or not self._is_code(first) or not self._is_code(last):
            return False, "cached method bounds no longer point to code"
        if record.method_count < MAX_METHODS:
            boundary_ea = vtable_ea + record.method_count * self.pointer_size
            boundary = self._read_ptr(boundary_ea)
            if boundary and self._is_code(boundary) and not self._has_data_xref(boundary_ea):
                return False, "vtable method boundary changed"
        return True, ""

    def method(self, record, slot):
        """Read one live method after bounds and code-target validation."""
        if not 0 <= slot < record.method_count:
            raise ValueError("slot %d is outside the cached vtable" % slot)
        vtable_ea = self.image_base + record.vtable_rva
        entry_ea = vtable_ea + slot * self.pointer_size
        target_ea = self._read_ptr(entry_ea)
        if target_ea is None or not self._is_code(target_ea):
            raise ValueError("slot %d no longer points to code" % slot)
        if slot and self._has_data_xref(entry_ea):
            raise ValueError("slot %d is now a vtable boundary" % slot)
        return entry_ea, target_ea, ida_name.get_name(target_ea) or ""
