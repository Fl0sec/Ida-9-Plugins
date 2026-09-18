"""Merging a fresh export into an existing CFS6 file.

A merge is a rewrite, not a text append: the header is singular and must come
first, and a re-exported item would otherwise collide with its own previous
`id`. These tests pin the two rules that make it safe -- new records supersede
their namesakes, and two different images never share a file.
"""

import os
import tempfile
import unittest

from _support import (
    cfs6, entry_candidate, rel_candidate, sample_image, write_cfs6,
)


def merge(path, build_fresh, image=None, build_number=14177):
    """Rewrite `path` with whatever `build_fresh(writer)` emits, merged in."""
    loaded = cfs6.load_cfs6(path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as handle:
        writer = cfs6.Cfs6Writer(handle)
        writer.write_header(image or sample_image(), build_number, "user")
        build_fresh(writer)
        stats = cfs6.carry_over(writer, loaded)
    os.replace(tmp, path)
    return stats, cfs6.load_cfs6(path)


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cfs6merge")
        self.path = os.path.join(self.dir, "t.cfs")

    def tearDown(self):
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def _seed(self):
        return write_cfs6(self.path, [
            (cfs6.REC_FUNCTION, "Old", [entry_candidate("48 89 5C 24 08")]),
            (cfs6.REC_GLOBAL, "g_old", [
                rel_candidate("48 8B 05 ? ? ? ?", 0x2000, 0, 3, 4, 7,
                              is_data=True),
            ]),
        ])

    def test_new_items_are_added_and_old_ones_kept(self):
        self._seed()

        def fresh(writer):
            iid = writer.write_item(cfs6.REC_FUNCTION, "New", 1, {})
            writer.write_candidate(iid, 0, entry_candidate("40 53 48 83 EC 20"))

        stats, loaded = merge(self.path, fresh)

        self.assertEqual(stats.items, 2)
        self.assertEqual(stats.replaced_items, 0)
        self.assertEqual(loaded.parse_errors, 0)
        self.assertEqual(
            sorted(i.name for i in loaded.items), ["New", "Old", "g_old"]
        )
        # Exactly one header, still on the first line.
        self.assertEqual(
            sum(1 for line in loaded.lines if '"record":"header"' in line), 1
        )

    def test_reexported_item_supersedes_the_old_one(self):
        self._seed()

        def fresh(writer):
            iid = writer.write_item(cfs6.REC_FUNCTION, "Old", 1, {})
            writer.write_candidate(iid, 0, entry_candidate("CC CC CC CC CC CC"))

        stats, loaded = merge(self.path, fresh)

        self.assertEqual(stats.replaced_items, 1)
        # The superseded item line and its candidate line are replaced, not
        # "unparsable" -- reporting them as damage sends a reader bug-hunting.
        self.assertEqual(stats.replaced_lines, 2)
        self.assertEqual(stats.dropped_lines, 0)
        self.assertEqual(loaded.parse_errors, 0)
        olds = [i for i in loaded.items if i.name == "Old"]
        self.assertEqual(len(olds), 1)
        self.assertEqual(olds[0].candidates[0].pattern, "CC CC CC CC CC CC")

    def test_local_types_dedup_by_name(self):
        with open(self.path, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs6Writer(handle)
            writer.write_header(sample_image(), 14177, "user")
            writer.write_local_type("CFoo", "STRUCT", (b"old", b"", b""))
            writer.write_local_type("CBar", "STRUCT", (b"bar", b"", b""))

        def fresh(writer):
            writer.write_local_type("CFoo", "STRUCT", (b"new", b"", b""))

        stats, loaded = merge(self.path, fresh)

        self.assertEqual(stats.replaced_types, 1)
        self.assertEqual(stats.types, 1)
        self.assertEqual(sorted(loaded.type_records), ["CBar", "CFoo"])
        self.assertEqual(loaded.type_records["CFoo"].type_blob, b"new")

    def test_unparsable_lines_are_not_carried_over(self):
        self._seed()
        with open(self.path, "a", encoding="utf-8", newline="") as handle:
            handle.write("{ this is not json\n")

        stats, loaded = merge(self.path, lambda writer: None)

        self.assertEqual(stats.dropped_lines, 1)
        self.assertEqual(stats.replaced_lines, 0)
        self.assertEqual(loaded.parse_errors, 0)

    def test_carried_lines_are_byte_identical(self):
        self._seed()
        before = [
            line for line in cfs6.load_cfs6(self.path).lines
            if line and '"record":"header"' not in line
        ]

        merge(self.path, lambda writer: None)

        after = [
            line for line in cfs6.load_cfs6(self.path).lines
            if line and '"record":"header"' not in line
        ]
        self.assertEqual(before, after)


class MergeConflictTests(unittest.TestCase):
    def test_same_image_has_no_conflicts(self):
        header = {"image": sample_image(), "build": {"number": 14177}}
        self.assertEqual(
            cfs6.merge_conflicts(header, sample_image(), 14177), []
        )

    def test_a_different_image_conflicts(self):
        header = {"image": sample_image("client.dll"), "build": {}}
        other = sample_image("server.dll")
        other["sha256"] = "11" * 32
        reasons = cfs6.merge_conflicts(header, other, 14177)
        self.assertEqual(len(reasons), 2)
        self.assertTrue(any("image name" in r for r in reasons))
        self.assertTrue(any("sha256" in r for r in reasons))

    def test_a_different_build_conflicts(self):
        header = {"image": sample_image(), "build": {"number": 14177}}
        reasons = cfs6.merge_conflicts(header, sample_image(), 14201)
        self.assertEqual(len(reasons), 1)
        self.assertIn("build", reasons[0])

    def test_the_path_a_name_was_recorded_with_is_not_identity(self):
        header = {"image": sample_image(r"C:\games\csgo\client.dll"),
                  "build": {}}
        self.assertEqual(
            cfs6.merge_conflicts(header, sample_image("client.dll"), None), []
        )

    def test_unknown_fields_are_not_evidence_of_a_mismatch(self):
        degraded = sample_image()
        degraded["architecture"] = None
        degraded["size_of_image"] = None
        header = {"image": degraded, "build": {"number": None}}
        self.assertEqual(
            cfs6.merge_conflicts(header, sample_image(), 14177), []
        )


if __name__ == "__main__":
    unittest.main()
