"""CFS7 rolling catalogue serialization and CFS6 compatibility."""

import json
import os
import tempfile
import unittest

from cfs5 import cfs6


class TestCfs7Format(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.temp.name, "rolling.cfs")

    def tearDown(self):
        self.temp.cleanup()

    def _write(self):
        with open(self.path, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs7Writer(handle)
            image = {"name": "client.dll", "architecture": "x86_64",
                     "size_of_image": 123, "sha256": "ab"}
            writer.write_header(image, 14185, "user")
            iid = writer.write_item(cfs6.REC_FUNCTION, "refresh_me", 1, {})
            rec = cfs6.CandidateRecord(2, iid, 0, "ENTRY", "90 90 90 90 90 90",
                                       origin="function_entry", score=9)
            writer.write_revalidated_candidate(iid, 0, rec, {"anchor_rva": 7}, {
                "image": dict(image), "build": {"number": 14182, "source": "user"},
            })

    def test_target_and_candidate_provenance_round_trip(self):
        self._write()
        loaded = cfs6.load_catalogue(self.path)
        self.assertEqual(loaded.header["version"], 7)
        self.assertEqual(loaded.header["target"]["build"]["number"], 14185)
        self.assertEqual(loaded.functions()[0].candidates[0].provenance["build"]["number"], 14182)

    def test_cfs6_reader_remains_strict_and_generic_loader_accepts_both(self):
        self._write()
        with self.assertRaises(cfs6.Cfs6Error):
            cfs6.load_cfs6(self.path)
        self.assertEqual(cfs6.load_catalogue(self.path).build_number(), 14185)

    def test_cfs7_candidate_without_provenance_is_rejected_per_record(self):
        self._write()
        with open(self.path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        candidate = json.loads(lines[2])
        candidate.pop("provenance")
        lines[2] = json.dumps(candidate)
        with open(self.path, "w", encoding="utf-8", newline="") as handle:
            handle.write("\n".join(lines) + "\n")
        loaded = cfs6.load_catalogue(self.path)
        self.assertEqual(loaded.parse_errors, 1)
        self.assertEqual(loaded.functions()[0].candidates, [])
