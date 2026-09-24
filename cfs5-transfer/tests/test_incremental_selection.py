"""Exact, IDA-free selection rules for incremental export."""

import unittest

from cfs5 import declare, patchdecl, selection


SITE = [{"ea": 0x1000, "op": 1}]


class IncrementalSelectionTests(unittest.TestCase):
    def setUp(self):
        self.a = declare.make_constant("Flags", "kA", 1, SITE)
        self.b = declare.make_constant("Flags", "kB", 2, SITE)

    def test_one_qualified_name_selects_only_that_declaration(self):
        got = selection.resolve([self.a, self.b], ["Flags::kA"])
        self.assertEqual(got["ids"], [self.a.id])
        self.assertEqual(got["declarations"], [self.a])
        self.assertEqual(got["requested"], 1)
        self.assertEqual(got["unresolved"], [])

    def test_two_declarations_share_one_selection_pass(self):
        got = selection.resolve(
            [self.a, self.b], ["Flags::kA", "Flags::kB"]
        )
        self.assertEqual(got["declarations"], [self.a, self.b])
        self.assertEqual(got["requested"], 2)

    def test_exact_function_global_and_derived_ids(self):
        got = selection.resolve(
            [self.a], item_ids=["fn:f", "global:g", self.a.id]
        )
        self.assertEqual(got["function_names"], ["f"])
        self.assertEqual(got["global_names"], ["g"])
        self.assertEqual(got["declarations"], [self.a])
        self.assertEqual(got["unresolved"], [])

    def test_missing_and_malformed_inputs_are_refused(self):
        got = selection.resolve(
            [self.a], declaration_names=["Flags::missing"],
            item_ids=["not-an-id"],
        )
        self.assertEqual(got["requested"], 2)
        self.assertEqual(len(got["unresolved"]), 2)
        self.assertEqual(got["ids"], [])

    def test_ambiguous_qualified_name_requires_an_exact_id(self):
        stride = declare.make_stride("Flags", "kA", 1, SITE)
        got = selection.resolve([self.a, stride], ["Flags::kA"])
        self.assertEqual(got["ids"], [])
        self.assertEqual(got["unresolved"][0]["reason"],
                         "ambiguous declaration name")

        exact = selection.resolve([self.a, stride], item_ids=[self.a.id])
        self.assertEqual(exact["declarations"], [self.a])

    def test_patch_id_selects_only_that_patch(self):
        patch = patchdecl.PatchDeclaration("spotted", "Gate", {
            "ea": 0x2000, "expected_instruction": "jz",
            "expected_bytes": "74", "patch_size": 2,
        })
        got = selection.resolve([], item_ids=[patch.id], patches=[patch])
        self.assertEqual(got["patches"], [patch])
        self.assertEqual(got["unresolved"], [])


if __name__ == "__main__":
    unittest.main()
