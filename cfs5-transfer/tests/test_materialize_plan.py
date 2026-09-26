"""Offline regression tests for sparse portable-member batch planning."""

import unittest

import _support  # noqa: F401

from cfs5 import materialize_plan


def _row(item_id, offset, width=1, owner="BulletHitRecord"):
    return {"id": item_id, "owner": owner, "member": item_id.rsplit("::", 1)[-1],
            "action": "create", "resolved_offset": offset,
            "field_schema": {"kind": "integer", "width": width, "signed": False}}


class MaterializePlanTests(unittest.TestCase):
    def test_sparse_owner_rows_are_committed_in_offset_order(self):
        rows = [
            _row("member:BulletHitRecord::m_nHitKind", 0x33),
            _row("member:BulletHitRecord::m_hEntity", 0x2C, 4),
            _row("member:BulletHitRecord::m_nSurfaceProps", 0x30, 2),
        ]
        batches, conflicts = materialize_plan.create_batches(rows)
        self.assertEqual([], conflicts)
        self.assertEqual([
            "member:BulletHitRecord::m_hEntity",
            "member:BulletHitRecord::m_nSurfaceProps",
            "member:BulletHitRecord::m_nHitKind",
        ], [row["id"] for row in batches["BulletHitRecord"]])

    def test_selected_overlap_is_rejected_before_any_owner_write(self):
        batches, conflicts = materialize_plan.create_batches([
            _row("member:Owner::first", 0x20, 4, owner="Owner"),
            _row("member:Owner::second", 0x22, 4, owner="Owner"),
        ])
        self.assertEqual(2, len(batches["Owner"]))
        self.assertEqual("member:Owner::second", conflicts[0]["id"])
        self.assertEqual("selected member ranges overlap", conflicts[0]["reason"])


if __name__ == "__main__":
    unittest.main()
