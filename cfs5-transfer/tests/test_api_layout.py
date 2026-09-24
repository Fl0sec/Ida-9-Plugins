"""Pins the stable facade while implementations remain independently readable."""

import ast
import os
import unittest

import _support  # noqa: F401

from cfs5.api_result import result


PUBLIC = {
    "clear", "declare_constants", "declare_extents", "declare_members",
    "declare_patches", "declare_strides", "declarations", "export",
    "export_list", "export_selected", "import_and_migrate",
    "import_catalogue", "migrate_state", "register", "registered",
    "undeclare", "unregister",
}


class ApiLayoutTests(unittest.TestCase):
    def _tree(self, name):
        path = os.path.join(_support.PLUGIN_DIR, "cfs5", name)
        with open(path, "r", encoding="utf-8") as handle:
            return ast.parse(handle.read(), filename=path)

    def test_facade_defines_no_competing_implementation(self):
        tree = self._tree("api.py")
        functions = {node.name for node in tree.body
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.assertEqual(set(), functions)
        exports = None
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "__all__"
                for target in node.targets
            ):
                exports = set(ast.literal_eval(node.value))
        self.assertEqual(PUBLIC, exports)

    def test_each_public_call_has_one_implementation(self):
        found = {}
        for filename in (
            "api_registry.py", "api_declarations.py", "api_export.py",
            "api_import.py",
        ):
            for node in self._tree(filename).body:
                if isinstance(node, ast.FunctionDef) and node.name in PUBLIC:
                    found.setdefault(node.name, []).append(filename)
        self.assertEqual(PUBLIC, set(found))
        self.assertTrue(all(len(files) == 1 for files in found.values()), found)

    def test_result_envelope_is_strict_and_extensible(self):
        value = result(partial=True, unresolved=[{"name": "x"}], count=1)
        self.assertEqual(
            {"ok": False, "partial": True, "error": None,
             "unresolved": [{"name": "x"}], "count": 1},
            value,
        )


if __name__ == "__main__":
    unittest.main()
