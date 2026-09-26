"""CFS7 revision-4 portable member-schema contract tests."""

import json
import os
import tempfile
import unittest

import _support  # noqa: F401

from cfs5 import cfs6


class PortableMemberSchemaTests(unittest.TestCase):
    def _path(self):
        handle = tempfile.NamedTemporaryFile(suffix=".cfs", delete=False)
        handle.close()
        self.addCleanup(lambda: os.path.exists(handle.name) and os.unlink(handle.name))
        return handle.name

    def test_cfs7_round_trips_integer_schema(self):
        path = self._path()
        with open(path, "w", encoding="utf-8") as handle:
            writer = cfs6.Cfs7Writer(handle)
            writer.write_header({"name": "x"}, 1, "test")
            writer.write_derived_value(cfs6.SEM_MEMBER_OFFSET, "Owner", "field", 0, {},
                                       expected_value=4,
                                       portable_member_schema={"kind": "integer", "width": 4,
                                                               "signed": True})
        loaded = cfs6.load_catalogue(path)
        item = loaded.derived_values()[0]
        self.assertEqual({"kind": "integer", "width": 4, "signed": True},
                         item.portable_member_schema)
        self.assertEqual(4, loaded.header["schema_revision"])

    def test_rejects_schema_on_non_member_item(self):
        path = self._path()
        header = {"record": "header", "format": "CFS", "version": 7,
                  "schema_revision": 4, "generator": {},
                  "target": {"image": {}, "build": {"number": 1, "source": "test"}}}
        value = {"record": "derived_value", "id": "const:A::x", "name": "x",
                 "owner": "A", "semantic": "constant", "candidate_count": 0,
                 "coverage": {}, "portable_member_schema": {"kind": "integer", "width": 4,
                                                               "signed": True}}
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(header) + "\n" + json.dumps(value) + "\n")
        loaded = cfs6.load_catalogue(path)
        self.assertEqual(1, loaded.parse_errors)
        self.assertEqual([], loaded.derived_values())


if __name__ == "__main__":
    unittest.main()
