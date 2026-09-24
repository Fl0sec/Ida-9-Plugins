"""The `constant` semantic: a number that exists only in the code.

A bit position tested by `bt reg, 0xB`, or a sentinel compared against a field,
is structurally a `member_offset` -- a constant decoded from a matched
instruction and verified against a declared value -- minus the one thing that
makes a member offset strong: an owning IDA field to source the value from.

So it claims less, and the model has to make that visible rather than letting
it pass as an offset: the caller asserts the value, must supply the evidence,
and gets no discovery. These are the rules that keep it honest.
"""

import os
import tempfile
import unittest

from _support import sample_image, value_candidate

from cfs5 import cfs6, declare


SITES = [{"ea": 0x140001000, "op": 1}]


class ConstantDeclarationTests(unittest.TestCase):
    def test_a_constant_asserts_its_value_and_keeps_its_sites(self):
        decl = declare.make_constant(
            "CEntityIdentityFlags", "kModelChangeBlockedBit", 0x6, SITES
        )
        self.assertEqual(decl.semantic, cfs6.SEM_CONSTANT)
        self.assertEqual(decl.asserted_value, 0x6)
        self.assertEqual(decl.sites, [(0x140001000, 1)])
        # The id prefix is the semantic's short form, so a constant and a
        # member of the same name never collide in the shared id namespace.
        self.assertEqual(decl.id, "const:CEntityIdentityFlags::"
                                  "kModelChangeBlockedBit")

    def test_a_constant_has_no_backing_ida_member(self):
        """Which is the whole reason it exists as a separate semantic."""
        decl = declare.make_constant("SosConstants", "kDisableStartTime",
                                     -1, SITES)
        self.assertFalse(decl.needs_ida_member)
        self.assertEqual(decl.asserted_value, -1)

    def test_a_constant_is_never_discovered(self):
        """Nothing in the database associates an instruction with a constant.

        Finding other instructions holding the same number would be numeric
        coincidence, and agreement between coincidences reads as confirmation --
        the one thing the candidate rules forbid.
        """
        decl = declare.make_constant("T", "kBit", 0xB, SITES)
        self.assertEqual(decl.discovery, declare.DISCOVER_SITES_ONLY)
        self.assertFalse(decl.scan_allowed)

    def test_a_constant_without_a_site_is_refused(self):
        with self.assertRaises(declare.DeclarationError):
            declare.make_constant("T", "kBit", 0xB, ())

    def test_a_constant_without_a_value_is_refused(self):
        with self.assertRaises(declare.DeclarationError):
            declare.make_constant("T", "kBit", None, SITES)

    def test_a_member_offset_still_may_not_assert_a_value(self):
        """The new semantic must not become a way in for a hand-counted offset."""
        with self.assertRaises(declare.DeclarationError):
            declare.Declaration(
                cfs6.SEM_MEMBER_OFFSET, "T", "f", sites=SITES,
                asserted_value=0x10,
            )

    def test_a_constant_survives_storage(self):
        decl = declare.make_constant("T", "kBit", 0xB, SITES, value_adjust=2)
        back = declare.from_dict(decl.to_dict())
        self.assertEqual(back.semantic, cfs6.SEM_CONSTANT)
        self.assertEqual(back.asserted_value, 0xB)
        self.assertEqual(back.value_adjust, 2)
        self.assertEqual(back.id, decl.id)


class ConstantFormatTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cfs6const")

    def tearDown(self):
        for name in os.listdir(self.dir):
            os.unlink(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def test_a_constant_item_round_trips_with_its_candidate(self):
        path = os.path.join(self.dir, "c.cfs")
        # `bt ecx, 0xB` -- a bit position is an immediate, not a displacement.
        cand = value_candidate(
            "0F BA E1 ?", anchor=0x3000, field_size=1,
            op=cfs6.OP_IMM, value=0xB,
        )
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs6Writer(handle)
            writer.write_header(sample_image(), 14182, "user")
            iid = writer.write_derived_value(
                cfs6.SEM_CONSTANT, "CEntityIdentityFlags",
                "kModelChangeUseExplicitBit", 1, {}, expected_value=0xB,
            )
            writer.write_candidate(iid, 0, cand)

        errors = []
        loaded = cfs6.load_cfs6(path, log=errors.append)
        self.assertEqual(errors, [])
        self.assertEqual(loaded.parse_errors, 0)

        constants = loaded.derived_values(cfs6.SEM_CONSTANT)
        self.assertEqual(len(constants), 1)
        item = constants[0]
        self.assertEqual(item.semantic, cfs6.SEM_CONSTANT)
        self.assertEqual(item.expected_value, 0xB)
        self.assertEqual(
            item.qualified_name,
            "CEntityIdentityFlags::kModelChangeUseExplicitBit",
        )
        self.assertEqual(len(item.candidates), 1)
        self.assertEqual(item.candidates[0].op, cfs6.OP_IMM)

    def test_negative_expected_value_round_trips_as_signed_json(self):
        path = os.path.join(self.dir, "negative.cfs")
        cand = value_candidate(
            "41 83 F8 ?", anchor=0x3AE51F, field_size=1,
            op=cfs6.OP_IMM, value=-1,
        )
        cand.extract["signed"] = True
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs6Writer(handle)
            writer.write_header(sample_image(), 14182, "user")
            iid = writer.write_derived_value(
                cfs6.SEM_CONSTANT, "SosConstants", "kDisableStartTime",
                1, {}, expected_value=-1,
            )
            writer.write_candidate(iid, 0, cand)

        with open(path, encoding="utf-8") as handle:
            raw = handle.read()
        self.assertIn('"expected_value":-1', raw)

        loaded = cfs6.load_cfs6(path)
        item = loaded.derived_values(cfs6.SEM_CONSTANT)[0]
        self.assertEqual(item.expected_value, -1)
        self.assertTrue(item.candidates[0].field_signed)


if __name__ == "__main__":
    unittest.main()
