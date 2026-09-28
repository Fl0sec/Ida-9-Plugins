"""Tests for the snapshot commit marker and checksum envelope."""

import unittest

from rttibrowser.model import BaseRecord, Snapshot, VtableRecord
from rttibrowser.snapshot_codec import (
    SnapshotCodecError, decode, encode, writing_marker,
)


def snapshot():
    identity = {
        "sha256": "1" * 64,
        "md5": "2" * 32,
        "processor": "metapc",
        "bitness": 64,
        "pointer_size": 8,
        "file_type": "Portable executable",
        "segments": [[0, 0x1000, 2, 5]],
    }
    base = BaseRecord("Widget", 0x200, 0x300, 0, 0, -1, 0, 0)
    table = VtableRecord(
        0x500, 0x480, 0x300, 0x400, "Widget", "Widget", 0, 0, 0,
        2, (base,),
    )
    return Snapshot(identity, (table,))


class SnapshotCodecTests(unittest.TestCase):
    def test_complete_snapshot_round_trip(self):
        original = snapshot()
        raw, marker = encode(original)
        self.assertEqual(decode(raw, marker), original)

    def test_incomplete_marker_is_rejected(self):
        raw, _marker = encode(snapshot())
        with self.assertRaisesRegex(SnapshotCodecError, "incomplete"):
            decode(raw, writing_marker())

    def test_truncated_or_modified_payload_is_rejected(self):
        raw, marker = encode(snapshot())
        with self.assertRaisesRegex(SnapshotCodecError, "checksum"):
            decode(raw[:-1], marker)
        changed = bytearray(raw)
        changed[len(changed) // 2] ^= 1
        with self.assertRaisesRegex(SnapshotCodecError, "checksum"):
            decode(bytes(changed), marker)

    def test_missing_payload_is_rejected(self):
        _raw, marker = encode(snapshot())
        with self.assertRaisesRegex(SnapshotCodecError, "missing"):
            decode(None, marker)


if __name__ == "__main__":
    unittest.main()
