"""CFS6 serialization, parsing and validation rules."""

import json
import os
import tempfile
import unittest

import _support
from _support import (
    body_candidate, entry_candidate, header_line, rel_candidate, write_cfs6,
    vtable_candidate, write_lines,
)

from cfs5 import cfs6


class Cfs6TempFileCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "t.cfs")
        self.logged = []

    def tearDown(self):
        self.dir.cleanup()

    def load(self):
        return cfs6.load_cfs6(self.path, log=self.logged.append)


class TestRoundTrip(Cfs6TempFileCase):
    def test_vtable_candidate_round_trip(self):
        cand = vtable_candidate()
        write_cfs6(self.path, [(cfs6.REC_FUNCTION, "notify", [cand])])
        loaded = self.load()
        self.assertEqual(loaded.parse_errors, 0)
        got = loaded.functions()[0].candidates[0]
        self.assertEqual(got.mode, cfs6.MODE_VTABLE)
        self.assertEqual(got.type_descriptor, ".?AVCCSPlayerInventory@@")
        self.assertEqual(got.slot, 19)
        self.assertEqual(got.confirm_offset, 0x58)
        self.assertEqual(got.scan_bound, cfs6.SCAN_BOUND_PDATA_CHAIN)
        self.assertEqual(got.tokenization, cfs6.TOKENIZATION_STRICT)
        self.assertEqual(got.image_matches, 1)

    def test_function_and_global_round_trip(self):
        entry = entry_candidate("40 53 48 83 EC ? 48 8B D9")
        body = body_candidate("48 8B 43 ? F3 0F 10 40 ?", anchor=0x1041)
        rel = rel_candidate(
            "0F 28 F0 E8 ? ? ? ? 48 8B 6C 24 50",
            anchor=0x5000, insn_offset=3, disp_offset=4, disp_size=4,
            base_offset=8,
        )
        glob = rel_candidate(
            "4C 8B 1D ? ? ? ? 48 8B D8", anchor=0x6000, insn_offset=0,
            disp_offset=3, disp_size=4, base_offset=7,
            origin="data_reference", is_data=True, target=0x9000,
        )

        write_cfs6(self.path, [
            (cfs6.REC_FUNCTION, "ConVarRef_GetFloat", [rel, entry, body]),
            (cfs6.REC_GLOBAL, "g_pCSGameRules", [glob]),
        ])

        loaded = self.load()
        self.assertEqual(loaded.parse_errors, 0)
        self.assertEqual(len(loaded.functions()), 1)
        self.assertEqual(len(loaded.globals()), 1)
        self.assertEqual(loaded.build_number(), 14177)
        self.assertEqual(loaded.header["version"], 6)

        fn = loaded.functions()[0]
        self.assertEqual(fn.id, "fn:ConVarRef_GetFloat")
        self.assertEqual([c.mode for c in fn.candidates], ["REL", "ENTRY", "BODY"])
        self.assertEqual([c.rank for c in fn.candidates], [0, 1, 2])

        first = fn.candidates[0]
        self.assertEqual(first.pattern, "0F 28 F0 E8 ? ? ? ? 48 8B 6C 24 50")
        self.assertEqual(first.instruction_offset, 3)
        self.assertEqual(first.displacement_offset, 4)
        self.assertEqual(first.displacement_size, 4)
        self.assertEqual(first.base_offset, 8)
        self.assertEqual(first.target_delta, 0)
        self.assertFalse(first.is_data)

        self.assertEqual(fn.candidates[2].body_offset, 0x41)
        self.assertTrue(loaded.globals()[0].candidates[0].is_data)

    def test_target_delta_omitted_when_zero_and_applied_when_set(self):
        cand = entry_candidate("90 90 90 90 90 90")
        write_cfs6(self.path, [(cfs6.REC_FUNCTION, "a", [cand])])
        with open(self.path, encoding="utf-8") as handle:
            raw = handle.read().splitlines()[2]
        self.assertNotIn("target_delta", raw)

        cand.target_delta = 16
        write_cfs6(self.path, [(cfs6.REC_FUNCTION, "a", [cand])])
        self.assertEqual(self.load().functions()[0].candidates[0].target_delta, 16)

    def test_file_is_utf8_without_bom_and_newline_terminated(self):
        write_cfs6(self.path, [
            (cfs6.REC_FUNCTION, "a", [entry_candidate("90 90 90 90 90 90")]),
        ])
        with open(self.path, "rb") as handle:
            raw = handle.read()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b"\r\n", raw)
        for line in raw.decode("utf-8").splitlines():
            json.loads(line)

    def test_local_type_and_item_type_records(self):
        with open(self.path, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs6Writer(handle)
            writer.write_header(_support.sample_image(), None, "unknown")
            iid = writer.write_item(cfs6.REC_FUNCTION, "f", 1, {})
            writer.write_candidate(iid, 0, entry_candidate("90 90 90 90 90 90"))
            writer.write_item_type(
                iid, "f", "USER", (b"typeblob", b"fields", b""), ["Dep"],
            )
            writer.write_local_type("Dep", "STRUCT", (b"body", None, None))

        loaded = self.load()
        meta = loaded.item_meta["fn:f"]
        self.assertEqual(meta.type_blob, b"typeblob")
        self.assertEqual(meta.dependencies, ["Dep"])
        self.assertTrue(meta.has_prototype())
        self.assertEqual(loaded.type_records["Dep"].type_blob, b"body")
        self.assertIsNone(loaded.build_number())


class TestRejection(Cfs6TempFileCase):
    def test_rejects_legacy_csv(self):
        write_lines(self.path, [
            "# CFS5 5.0",
            "CFS2,4,0,ConVarRef_GetFloat,REL,0F 28 F0 E8 ? ? ? ?,0,4,4,8,3,1320",
        ])
        with self.assertRaises(cfs6.Cfs6Error) as ctx:
            self.load()
        self.assertIn("re-export", str(ctx.exception))

    def test_rejects_empty_file(self):
        write_lines(self.path, [])
        with self.assertRaises(cfs6.Cfs6Error):
            self.load()

    def test_rejects_unsupported_major_version(self):
        write_lines(self.path, [header_line(version=7)])
        with self.assertRaises(cfs6.Cfs6Error) as ctx:
            self.load()
        self.assertIn("version", str(ctx.exception))

    def test_rejects_header_without_image(self):
        write_lines(self.path, [
            '{"record":"header","format":"CFS","version":6,"build":{}}'
        ])
        with self.assertRaises(cfs6.Cfs6Error):
            self.load()

    def test_unknown_schema_revision_is_accepted(self):
        line = header_line().replace('"schema_revision":0', '"schema_revision":99')
        write_lines(self.path, [line])
        self.assertEqual(self.load().header["schema_revision"], 99)


class TestValidation(Cfs6TempFileCase):
    def _item_and(self, *candidate_lines):
        write_lines(self.path, [
            header_line(),
            '{"record":"function","id":"fn:a","name":"a","candidate_count":1,'
            '"coverage":{}}',
        ] + list(candidate_lines))
        return self.load()

    def test_unknown_record_kind_is_skipped_not_fatal(self):
        loaded = self._item_and(
            '{"record":"future_thing","hello":"world"}',
            '{"record":"candidate","item":"fn:a","rank":0,"mode":"ENTRY",'
            '"pattern":"90 90 90 90 90 90","resolve":{}}',
        )
        self.assertEqual(loaded.skipped_records, 1)
        self.assertEqual(loaded.parse_errors, 0)
        self.assertEqual(len(loaded.functions()[0].candidates), 1)

    def test_unknown_fields_are_ignored(self):
        loaded = self._item_and(
            '{"record":"candidate","item":"fn:a","rank":0,"mode":"ENTRY",'
            '"pattern":"90 90 90 90 90 90","resolve":{},"future":{"x":1}}'
        )
        self.assertEqual(loaded.parse_errors, 0)
        self.assertEqual(len(loaded.functions()[0].candidates), 1)

    def test_duplicate_item_id_is_an_error(self):
        write_lines(self.path, [
            header_line(),
            '{"record":"function","id":"fn:a","name":"a"}',
            '{"record":"function","id":"fn:a","name":"a"}',
        ])
        loaded = self.load()
        self.assertEqual(loaded.parse_errors, 1)
        self.assertEqual(len(loaded.functions()), 1)
        self.assertIn("duplicate item id", " ".join(self.logged))

    def test_duplicate_rank_is_an_error(self):
        loaded = self._item_and(
            '{"record":"candidate","item":"fn:a","rank":0,"mode":"ENTRY",'
            '"pattern":"90 90 90 90 90 90","resolve":{}}',
            '{"record":"candidate","item":"fn:a","rank":0,"mode":"ENTRY",'
            '"pattern":"91 91 91 91 91 91","resolve":{}}',
        )
        self.assertEqual(loaded.parse_errors, 1)
        self.assertEqual(len(loaded.functions()[0].candidates), 1)
        self.assertIn("duplicate rank", " ".join(self.logged))

    def test_non_contiguous_ranks_are_an_error(self):
        loaded = self._item_and(
            '{"record":"candidate","item":"fn:a","rank":0,"mode":"ENTRY",'
            '"pattern":"90 90 90 90 90 90","resolve":{}}',
            '{"record":"candidate","item":"fn:a","rank":5,"mode":"ENTRY",'
            '"pattern":"91 91 91 91 91 91","resolve":{}}',
        )
        self.assertEqual(loaded.parse_errors, 1)
        self.assertIn("non-contiguous", " ".join(self.logged))

    def test_orphan_candidate_is_an_error(self):
        write_lines(self.path, [
            header_line(),
            '{"record":"candidate","item":"fn:missing","rank":0,"mode":"ENTRY",'
            '"pattern":"90 90 90 90 90 90","resolve":{}}',
        ])
        loaded = self.load()
        self.assertEqual(loaded.parse_errors, 1)
        self.assertIn("unknown item", " ".join(self.logged))

    def test_bad_json_line_is_recoverable(self):
        loaded = self._item_and(
            "{not json at all",
            '{"record":"candidate","item":"fn:a","rank":0,"mode":"ENTRY",'
            '"pattern":"90 90 90 90 90 90","resolve":{}}',
        )
        self.assertEqual(loaded.parse_errors, 1)
        self.assertEqual(len(loaded.functions()[0].candidates), 1)

    def test_rel_displacement_width_must_be_valid(self):
        loaded = self._item_and(
            '{"record":"candidate","item":"fn:a","rank":0,"mode":"REL",'
            '"pattern":"E8 ? ? ? ? 90","resolve":{"instruction_offset":0,'
            '"displacement_offset":1,"displacement_size":3,"base_offset":5}}'
        )
        self.assertEqual(loaded.parse_errors, 1)
        self.assertIn("displacement_size", " ".join(self.logged))

    def test_rel_field_must_lie_inside_the_anchor_instruction(self):
        # base_offset 3 ends the instruction before the 4-byte field does.
        loaded = self._item_and(
            '{"record":"candidate","item":"fn:a","rank":0,"mode":"REL",'
            '"pattern":"E8 ? ? ? ? 90","resolve":{"instruction_offset":0,'
            '"displacement_offset":1,"displacement_size":4,"base_offset":3}}'
        )
        self.assertEqual(loaded.parse_errors, 1)
        self.assertIn("not inside the anchor", " ".join(self.logged))

    def test_rel_field_must_not_run_past_the_pattern(self):
        loaded = self._item_and(
            '{"record":"candidate","item":"fn:a","rank":0,"mode":"REL",'
            '"pattern":"E8 ? ?","resolve":{"instruction_offset":0,'
            '"displacement_offset":1,"displacement_size":4,"base_offset":5}}'
        )
        self.assertEqual(loaded.parse_errors, 1)

    def test_body_requires_body_offset(self):
        loaded = self._item_and(
            '{"record":"candidate","item":"fn:a","rank":0,"mode":"BODY",'
            '"pattern":"90 90 90 90 90 90","source":{},"resolve":{}}'
        )
        self.assertEqual(loaded.parse_errors, 1)
        self.assertIn("body_offset", " ".join(self.logged))

    def test_unsupported_mode_is_skipped_not_an_error(self):
        # Revision 2 contract: a newer producer adding a resolution mode must
        # not make the file unreadable. The candidate is dropped and reported,
        # exactly like an unknown record kind; the item survives with one
        # fewer candidate, and only an item left with *none* actually fails.
        loaded = self._item_and(
            '{"record":"candidate","item":"fn:a","rank":0,"mode":"MAGIC",'
            '"pattern":"90 90 90 90 90 90","resolve":{}}'
        )
        self.assertEqual(loaded.parse_errors, 0)
        self.assertEqual(loaded.skipped_records, 1)
        self.assertIn("MAGIC", " ".join(self.logged))
        self.assertEqual(loaded.functions()[0].candidates, [])

    def test_supported_candidate_survives_rank_gap_from_unknown_mode(self):
        loaded = self._item_and(
            '{"record":"candidate","item":"fn:a","rank":0,"mode":"MAGIC",'
            '"pattern":"90","resolve":{}}',
            '{"record":"candidate","item":"fn:a","rank":1,"mode":"ENTRY",'
            '"pattern":"90 90 90 90 90 90","resolve":{}}',
        )
        self.assertEqual(loaded.parse_errors, 0)
        self.assertEqual(loaded.skipped_records, 1)
        self.assertEqual([c.rank for c in loaded.functions()[0].candidates], [1])

    def test_vtable_validation_and_item_kind(self):
        base = ('{"record":"candidate","item":"fn:a","rank":0,'
                '"mode":"VTABLE","pattern":"90","origin":"rtti_vtable_slot",'
                '"resolve":%s}')
        valid = {
            "type_descriptor": ".?AVC@@", "subobject_offset": 0, "slot": 0,
            "confirm_offset": 0, "function_size": 1,
            "scan_bound": "pdata_chain", "tokenization": "strict",
            "image_matches": 1,
        }
        for field, value, needle in (
            ("slot", -1, "slot"),
            ("type_descriptor", "", "type_descriptor"),
            ("scan_bound", "future_bound", "scan_bound"),
        ):
            resolve = dict(valid)
            resolve[field] = value
            loaded = self._item_and(base % json.dumps(resolve))
            self.assertEqual(loaded.parse_errors, 1)
            self.assertIn(needle, " ".join(self.logged))
            self.logged.clear()

        write_lines(self.path, [
            header_line(),
            '{"record":"derived_value","id":"member:C::x","name":"x",'
            '"owner":"C","semantic":"member_offset","source":{"expected_value":0}}',
            (base % json.dumps(valid)).replace('"item":"fn:a"',
                                                '"item":"member:C::x"'),
        ])
        loaded = self.load()
        self.assertEqual(loaded.parse_errors, 1)
        self.assertIn("cannot belong", " ".join(self.logged))

    def test_pattern_is_normalized(self):
        loaded = self._item_and(
            '{"record":"candidate","item":"fn:a","rank":0,"mode":"ENTRY",'
            '"pattern":"48  8b\\tc0 ?  90 90","resolve":{}}'
        )
        self.assertEqual(
            loaded.functions()[0].candidates[0].pattern, "48 8B C0 ? 90 90"
        )


class TestCodec(unittest.TestCase):
    def test_blob_round_trip(self):
        data = b"\x00\x01binary\xff" * 100
        self.assertEqual(cfs6.unpack_bytes(cfs6.pack_bytes(data)), data)
        self.assertIsNone(cfs6.unpack_bytes(cfs6.pack_bytes(None)))
        self.assertIsNone(cfs6.unpack_bytes(""))

    def test_json_round_trip(self):
        deps = ["A", "B", "Ünïcode"]
        self.assertEqual(cfs6.unpack_json(cfs6.pack_json(deps)), deps)
        self.assertEqual(cfs6.unpack_json(""), [])

    def test_item_id(self):
        self.assertEqual(cfs6.item_id(cfs6.REC_FUNCTION, "f"), "fn:f")
        self.assertEqual(cfs6.item_id(cfs6.REC_GLOBAL, "g"), "global:g")


if __name__ == "__main__":
    unittest.main()
