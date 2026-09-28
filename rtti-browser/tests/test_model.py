"""Tests for IDA-free RTTI records and ordering."""

import unittest

from rttibrowser.model import (
    BaseRecord, Snapshot, SnapshotError, VtableRecord, class_sort_key,
    method_sort_key,
)


def identity():
    return {
        "sha256": "a" * 64,
        "md5": "b" * 32,
        "processor": "metapc",
        "bitness": 64,
        "pointer_size": 8,
        "file_type": "Portable executable",
        "segments": [[0x1000, 0x2000, 2, 5]],
    }


def record(name="Derived", offset=0x10, vtable=0x3000):
    bases = (
        BaseRecord("Derived", 0x4100, 0x4200, 1, 0, -1, 0, 0),
        BaseRecord("Base", 0x4300, 0x4400, 0, 0x10, -1, 0, 0),
    )
    return VtableRecord(
        vtable, 0x4000, 0x4200, 0x4500, name, "Base", offset, 0,
        1, 3, bases,
    )


class ModelTests(unittest.TestCase):
    def test_round_trip_preserves_signed_displacements_and_ownership(self):
        original = Snapshot(identity(), (record(),))
        loaded = Snapshot.from_dict(original.to_dict())
        self.assertEqual(loaded, original)
        self.assertEqual(
            loaded.records[0].ownership_prefix,
            ("Derived", 0x10, 0x3000),
        )

    def test_records_sort_by_class_then_subobject_offset(self):
        records = [record("zeta", 0), record("Alpha", 0x20), record("alpha", 0)]
        records.sort(key=class_sort_key)
        self.assertEqual([item.object_offset for item in records], [0, 0x20, 0])
        self.assertEqual(records[-1].class_name, "zeta")

    def test_method_sort_puts_named_rows_first_then_owner_and_slot(self):
        rows = [
            {"name": "", "owner": "A", "object_offset": 0, "slot": 0,
             "target_ea": 3},
            {"name": "tick", "owner": "B", "object_offset": 0, "slot": 1,
             "target_ea": 2},
            {"name": "Tick", "owner": "A", "object_offset": 0, "slot": 2,
             "target_ea": 1},
        ]
        rows.sort(key=method_sort_key)
        self.assertEqual([row["owner"] for row in rows], ["A", "B", "A"])

    def test_rejects_incompatible_schema_and_oversized_method_count(self):
        value = Snapshot(identity(), (record(),)).to_dict()
        value["snapshot_schema_version"] = 99
        with self.assertRaises(SnapshotError):
            Snapshot.from_dict(value)
        value = Snapshot(identity(), (record(),)).to_dict()
        value["records"][0]["method_count"] = 4097
        with self.assertRaises(SnapshotError):
            Snapshot.from_dict(value)

    def test_rejects_malformed_segment_layout(self):
        value = Snapshot(identity(), (record(),)).to_dict()
        value["identity"]["segments"] = [[0x2000, 0x1000, 2, 5]]
        with self.assertRaises(SnapshotError):
            Snapshot.from_dict(value)


if __name__ == "__main__":
    unittest.main()
