"""Object-extent declarations, alternate windows, and patch records."""

import os
import tempfile
import unittest

from _support import cfs6, sample_image, site_candidate, value_candidate
from cfs5 import declare, patchdecl, policy
import cfs6_resolve


class _Image:
    def __init__(self, data):
        self.data = data

    def offset_to_rva(self, offset):
        return offset

    def is_executable_rva(self, _rva):
        return True

    def read(self, rva, size):
        data = self.data[rva:rva + size]
        return data if len(data) == size else None


class ExtentDeclarationTests(unittest.TestCase):
    def test_extent_preserves_recipe_inputs(self):
        decl = declare.make_extent("TraceFilter", "kSize", 0x40, [{
            "ea": 0x1234, "op": 0, "access_width": 1, "alignment": 8,
            "window_start_ea": 0x1228,
        }])
        self.assertEqual(decl.semantic, cfs6.SEM_OBJECT_EXTENT)
        self.assertEqual(decl.asserted_value, 0x40)
        self.assertEqual(decl.site_options[(0x1234, 0)]["access_width"], 1)
        back = declare.from_dict(decl.to_dict())
        self.assertEqual(back.site_options, decl.site_options)

    def test_extent_requires_access_width_and_never_zero_falls_back(self):
        with self.assertRaises(declare.DeclarationError):
            declare.make_extent("T", "kSize", 64, [{"ea": 1, "op": 0}])
        with self.assertRaises(declare.DeclarationError):
            declare.make_extent("T", "kSize", 64, [{
                "ea": 1, "op": 0, "access_width": 0,
            }])

    def test_declared_window_must_start_at_or_before_extraction(self):
        insns = [{"ea": 0x1000 + i * 4, "size": 4} for i in range(6)]
        self.assertEqual(policy.declared_window_specs(insns, 3, 2), [])
        specs = policy.declared_window_specs(insns, 1, 3)
        self.assertTrue(specs)
        self.assertTrue(all(a == 1 and b > 3 for a, b in specs))

    def test_extent_record_requires_expected_value_and_keeps_recipe(self):
        path = os.path.join(tempfile.gettempdir(), "cfs6_extent_test.cfs")
        try:
            cand = value_candidate(
                "48 8D 41 ? 90 90 90 90", field_offset=3, field_size=1,
                op=cfs6.OP_DISP_PLUS_WIDTH, value=0x40,
                extra={"access_width": 1, "alignment": 8},
            )
            with open(path, "w", encoding="utf-8", newline="") as handle:
                writer = cfs6.Cfs6Writer(handle)
                writer.write_header(sample_image(), 14182, "user")
                iid = writer.write_derived_value(
                    cfs6.SEM_OBJECT_EXTENT, "TraceFilter", "kSize", 1, {},
                    expected_value=0x40,
                )
                writer.write_candidate(iid, 0, cand)
            item = cfs6.load_cfs6(path).derived_values()[0]
            self.assertEqual(item.expected_value, 0x40)
            self.assertEqual(item.candidates[0].access_width, 1)
            self.assertEqual(item.candidates[0].alignment, 8)
        finally:
            if os.path.exists(path):
                os.unlink(path)


class PatchModelTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "p.cfs")

    def tearDown(self):
        self.dir.cleanup()

    def test_patch_declaration_and_record_round_trip(self):
        decl = patchdecl.PatchDeclaration("spotted", "PlayerGate", {
            "ea": 0xEB8B9E, "expected_instruction": "jz",
            "expected_bytes": "0F 84", "patch_size": 6,
        })
        self.assertEqual(decl.id, "patch:spotted::PlayerGate")
        self.assertEqual(decl.expected_bytes, "0F84")

        with open(self.path, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs6Writer(handle)
            writer.write_header(sample_image(), 14182, "user")
            iid = writer.write_patch(decl.owner, decl.name, 1, {"site": "selected"}, {
                "expected_instruction": decl.expected_instruction,
                "expected_bytes": decl.expected_bytes,
                "patch_size": decl.patch_size,
            })
            writer.write_candidate(iid, 0, site_candidate(instruction_offset=2))

        loaded = cfs6.load_cfs6(self.path)
        self.assertEqual(loaded.parse_errors, 0)
        patch = loaded.patches()[0]
        self.assertEqual(patch.expected_instruction, "jz")
        self.assertEqual(patch.expected_bytes, "0F84")
        self.assertEqual(patch.patch_size, 6)
        self.assertEqual(patch.candidates[0].instruction_offset, 2)

    def test_site_candidate_is_patch_only(self):
        with open(self.path, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs6Writer(handle)
            writer.write_header(sample_image(), 14182, "user")
            iid = writer.write_item(cfs6.REC_FUNCTION, "f", 1, {})
            writer.write_candidate(iid, 0, site_candidate())
        loaded = cfs6.load_cfs6(self.path)
        self.assertEqual(loaded.parse_errors, 1)

    def test_reference_loader_checks_original_patch_bytes(self):
        item = cfs6.PatchRecord(
            1, "patch:spotted::Gate", "Gate", "spotted",
            {"expected_instruction": "jz", "expected_bytes": "7480",
             "patch_size": 2}, candidate_count=1,
        )
        item.candidates.append(cfs6.CandidateRecord(
            2, item.id, 0, cfs6.MODE_SITE, "90 74 80 CC",
            cfs6.ORIGIN_DECLARED_PATCH_SITE,
            resolve={"instruction_offset": 1},
        ))
        target, status, _ = cfs6_resolve.resolve_item(
            _Image(bytes.fromhex("90 74 80 CC")), item
        )
        self.assertEqual((target, status), (1, "ok"))

        item.expected_bytes = "7500"
        target, status, details = cfs6_resolve.resolve_item(
            _Image(bytes.fromhex("90 74 80 CC")), item
        )
        self.assertIsNone(target)
        self.assertEqual(status, "unresolved")
        self.assertIn("opcode", " ".join(details))


if __name__ == "__main__":
    unittest.main()
