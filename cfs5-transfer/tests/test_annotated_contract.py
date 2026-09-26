"""Offline contract regressions for the annotated snapshot surface."""

import ast
import hashlib
import json
import os
import unittest

import _support  # noqa: F401

from cfs5 import annotated_export_policy


class AnnotatedContractTests(unittest.TestCase):
    def test_safe_no_candidate_is_a_durable_exclusion_not_a_job_error(self):
        issue = annotated_export_policy.unexportable_issue(
            {"kind": "function", "name": "GetResourceManifestCount"},
            {"written": 0, "uncovered": [{
                "reason": "no unique signature (entry: clone_family)",
                "diagnosis": {"entry": {"matches": 8}},
            }]},
        )
        self.assertEqual("function", issue["kind"])
        self.assertEqual("GetResourceManifestCount", issue["name"])
        self.assertIn("clone_family", issue["reason"])
        self.assertEqual(8, issue["diagnosis"]["entry"]["matches"])

    def test_engine_errors_remain_fatal_not_exclusions(self):
        self.assertIsNone(annotated_export_policy.unexportable_issue(
            {"kind": "global", "name": "g_bad"},
            {"written": 0, "error": "disk full"},
        ))
    def test_digest_is_stable_and_binds_the_reviewed_selection(self):
        selection = {"functions": [("alpha", 0x1000)], "globals": [("g_beta", 0x2000)]}
        payload = {
            "functions": selection["functions"], "globals": selection["globals"],
            "image": {"name": "client.dll"}, "build": {"number": 14185, "source": "user"},
            "generator_version": "6.4.0", "schema_revision": 3,
            "policy": "human_user_names_plus_g_prefixed_data_globals_v1",
        }
        expected = hashlib.sha256(json.dumps(payload, sort_keys=True,
            separators=(",", ":")).encode("utf-8")).hexdigest()
        path = os.path.join(_support.PLUGIN_DIR, "cfs5", "annotated.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        digest = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                      and node.name == "digest")
        self.assertTrue(any(isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "sha256"
                            for node in ast.walk(digest)))
        self.assertEqual(64, len(expected))

    def test_job_uses_one_final_composition_not_per_item_catalogue_rewrites(self):
        path = os.path.join(_support.PLUGIN_DIR, "cfs5", "annotated_export_jobs.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name == "run_annotated_export")
        calls = [getattr(node.func, "id", "") for node in ast.walk(run)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertIn("_step", calls)
        self.assertIn("_compose", calls)
        self.assertEqual(1, calls.count("_compose"))


if __name__ == "__main__":
    unittest.main()
