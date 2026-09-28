"""Tests for compact, low-noise RTTI chooser presentation."""

import unittest

from rttibrowser.presentation import (
    compact, descriptor_fallback, hierarchy_summary, is_compiler_generated,
)


class PresentationTests(unittest.TestCase):
    def test_complex_descriptor_is_not_fake_namespace_text(self):
        raw = ".?AV?$CParallelLambdaJob@V<lambda_1>@@@"
        result = descriptor_fallback(raw)
        self.assertEqual(result, "?AV?$CParallelLambdaJob@V<lambda_1>@@@")
        self.assertNotIn("::::", result)

    def test_simple_descriptor_fallback_keeps_bare_name(self):
        self.assertEqual(descriptor_fallback(".?AVWidget@@"), "Widget")

    def test_compiler_generated_names_are_hidden_by_default(self):
        self.assertTrue(is_compiler_generated("?$CParallelLambdaJob@V<lambda_1>"))
        self.assertTrue(is_compiler_generated("Worker::<lambda_2>"))
        self.assertTrue(is_compiler_generated("`anonymous namespace'::Helper"))
        self.assertFalse(is_compiler_generated("C_CSGO_PreviewModel"))
        self.assertFalse(is_compiler_generated("CUtlVector<CEntityHandle>"))

    def test_compact_preserves_both_ends(self):
        value = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        result = compact(value, 20)
        self.assertEqual(len(result), 20)
        self.assertTrue(result.startswith("ABCDEFGHIJKL"))
        self.assertTrue(result.endswith("56789"))

    def test_hierarchy_reports_omitted_base_count(self):
        names = ["Base%d" % index for index in range(9)]
        result = hierarchy_summary(names, limit=200, maximum_bases=4)
        self.assertIn("Base0 : Base1 : Base2 : Base3", result)
        self.assertIn("(+5 bases)", result)

    def test_short_hierarchy_is_unchanged(self):
        self.assertEqual(
            hierarchy_summary(["Derived", "Base"], limit=200),
            "Derived : Base",
        )


if __name__ == "__main__":
    unittest.main()
