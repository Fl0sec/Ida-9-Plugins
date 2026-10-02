"""Tests for the IDA-free RTTI anchor byte search."""

import struct
import unittest

from rttibrowser import anchors


def _image(pointer_size, base):
    """Build one synthetic chunk: TD, COL, vtable, plus decoys."""
    data = bytearray(0x400)
    td = base + 0x100
    col = base + 0x200
    slot = base + 0x300
    fmt = "<Q" if pointer_size == 8 else "<I"
    # TD: vfptr, spare, name.
    data[0x100:0x100 + pointer_size] = struct.pack(fmt, base + 0x10)
    name_at = 0x100 + pointer_size * 2
    data[name_at:name_at + 13] = b".?AVWidget@@\0"
    # COL: signature, offset, cd_offset, td, chd[, self].
    td_field = td - base if pointer_size == 8 else td
    struct.pack_into("<IIII", data, 0x200, 1 if pointer_size == 8 else 0, 0, 0,
                     td_field)
    # Decoy: TD value at a misaligned position must not produce a COL.
    struct.pack_into("<I", data, 0x281, td_field)
    # Vtable slot holding the COL, and a misaligned decoy copy.
    data[0x300:0x300 + pointer_size] = struct.pack(fmt, col)
    data[0x3A1:0x3A1 + pointer_size] = struct.pack(fmt, col)
    return [(base, bytes(data))], td, col, slot


class AnchorTests(unittest.TestCase):
    def _chain(self, pointer_size, base):
        chunks, td, col, slot = _image(pointer_size, base)
        tds = anchors.find_type_descriptors(chunks, pointer_size)
        self.assertEqual(tds, {td})
        cols = anchors.find_cols(chunks, tds, pointer_size, base)
        self.assertEqual(cols, {col})
        self.assertEqual(
            anchors.find_vtable_slots(chunks, cols, pointer_size), {slot})

    def test_x86_chain(self):
        self._chain(4, 0x400000)

    def test_x64_chain(self):
        self._chain(8, 0x140000000)

    def test_overlapping_matches_are_not_swallowed(self):
        key = 0x01010101
        data = b"\x01" * 3 + struct.pack("<I", key)
        hits = {ea for ea, _ in anchors.find_keys([(0x1000, data)], {key}, 4, 4)}
        self.assertEqual(hits, {0x1000})
        hits = {ea for ea, _ in anchors.find_keys(
            [(0x1000, data + b"\x01")], {key}, 4, 4)}
        self.assertEqual(hits, {0x1000, 0x1004})

    def test_superset_class_rejects_non_keys(self):
        keys = {0x00A01234, 0x00B05678}
        data = struct.pack("<II", 0x00A05678, 0x00B01234)
        self.assertEqual(list(anchors.find_keys([(0, data)], keys, 4, 4)), [])

    def test_chunk_offset_is_applied(self):
        chunks, td, _, _ = _image(4, 0x400000)
        shifted = [(0x400000, b"")] + chunks
        self.assertEqual(anchors.find_type_descriptors(shifted, 4), {td})

    def test_empty_keys(self):
        self.assertEqual(list(anchors.find_keys([(0, b"abcd")], set(), 4, 4)), [])


if __name__ == "__main__":
    unittest.main()
