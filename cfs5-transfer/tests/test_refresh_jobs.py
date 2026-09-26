"""Offline regressions for bounded CFS7 refresh-job v2 work accounting."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

import _support
from check import _StubFinder

import sys
sys.meta_path.insert(0, _StubFinder())

from cfs5 import cfs6, refresh_jobs, rolling  # noqa: E402


class RefreshJobV2Tests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="cfs-refresh-v2-")
        self.source = os.path.join(self.directory, "source.cfs")
        self.destination = os.path.join(self.directory, "result.cfs")
        self.image = _support.sample_image()

    def tearDown(self):
        shutil.rmtree(self.directory)

    def _source(self, count):
        with open(self.source, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs6Writer(handle)
            writer.write_header(self.image, 14182, "test")
            for index in range(count):
                iid = writer.write_item(cfs6.REC_FUNCTION, "fn_%03d" % index, 1, {})
                writer.write_candidate(iid, 0, _support.entry_candidate(
                    "40 53 48 83 EC 20", anchor=0x1000 + index,
                    func=0x1000 + index,
                ))

    def _begin(self):
        with mock.patch.object(refresh_jobs, "open_image_view", return_value=(None, "test")), \
             mock.patch.object(refresh_jobs, "describe_image", return_value=(self.image, [])), \
             mock.patch.object(refresh_jobs, "detect_build", return_value=(14185, "test")):
            return refresh_jobs.begin_refresh(self.source, self.destination, build=14185)

    def test_source_candidates_are_validated_once_not_once_per_active_unit(self):
        """155 source items must produce 155 validations and one final assembly."""
        self._source(155)
        begun = self._begin()
        self.assertTrue(begun["ok"])
        job_path = begun["job_path"]
        self.assertIn("max_items=1", refresh_jobs.refresh_step(job_path, 2)["error"])

        def validate_once(item, provenance, _ranges, _base, _ownership):
            rec = item.candidates[0]
            return [(rec, dict(rec.source), provenance)], {}, None

        binding = (None, (None, self.image))
        with mock.patch.object(refresh_jobs, "_job_binding", return_value=binding), \
             mock.patch.object(refresh_jobs, "_validation_context", return_value=([], 0, None)), \
             mock.patch.object(rolling, "revalidate_item", side_effect=validate_once) as validated:
            for _index in range(155):
                stepped = refresh_jobs.refresh_step(job_path)
                self.assertTrue(stepped["ok"])
            self.assertEqual(validated.call_count, 155)
            finished = refresh_jobs.finalize_refresh(job_path)

        self.assertTrue(finished["ok"])
        self.assertEqual(finished["items"], 155)
        self.assertEqual(cfs6.load_catalogue(self.destination).parse_errors, 0)

    def test_v1_job_is_refused_but_can_be_discarded(self):
        path = self.destination + ".refresh-job.json"
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write('{"version":1,"stage_path":""}\n')
        status = refresh_jobs.refresh_status(path)
        self.assertIn("obsolete_job", status["error"])
        discarded = refresh_jobs.discard_refresh(path)
        self.assertTrue(discarded["ok"])
        self.assertFalse(os.path.exists(path))

    def test_budgeted_driver_advances_many_units_in_one_request(self):
        self._source(12)
        begun = self._begin()
        job_path = begun["job_path"]
        self.assertIn("between 10 and 90", refresh_jobs.refresh_run(job_path, 9)["error"])

        def validate_once(item, provenance, _ranges, _base, _ownership):
            rec = item.candidates[0]
            return [(rec, dict(rec.source), provenance)], {}, None

        binding = (None, (None, self.image))
        with mock.patch.object(refresh_jobs, "_job_binding", return_value=binding), \
             mock.patch.object(refresh_jobs, "_validation_context", return_value=([], 0, None)), \
             mock.patch.object(rolling, "revalidate_item", side_effect=validate_once) as validated:
            driven = refresh_jobs.refresh_run(job_path, 10)

        self.assertTrue(driven["ok"])
        self.assertEqual(driven["units_processed"], 12)
        self.assertTrue(driven["ready_to_finalize"])
        self.assertEqual(validated.call_count, 12)
