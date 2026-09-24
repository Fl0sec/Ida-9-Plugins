"""Headless smoke test for catalogue application and producer-state migration."""

import json
import os
import sys
import traceback

import ida_auto
import ida_loader
import ida_pro


PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)
for module_name in [
    name for name in list(sys.modules)
    if name == "cfs5" or name.startswith("cfs5.")
]:
    del sys.modules[module_name]

from cfs5 import importer  # noqa: E402


def main():
    output = os.environ["CFS_MIGRATION_RESULT"]
    try:
        ida_auto.auto_wait()
        result = importer.import_and_migrate(
            os.environ["CFS_MIGRATION_CATALOGUE"],
            require_all_state=os.environ.get("CFS_MIGRATION_REQUIRE_ALL", "1") == "1",
            show_progress=False,
        )
        saved = ida_loader.save_database()
        payload = {"result": result, "saved": bool(saved)}
        code = 0 if result.get("ok") else 2
    except Exception as exc:
        payload = {"exception": str(exc), "traceback": traceback.format_exc()}
        code = 1
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    ida_pro.qexit(code)


if __name__ == "__main__":
    main()
