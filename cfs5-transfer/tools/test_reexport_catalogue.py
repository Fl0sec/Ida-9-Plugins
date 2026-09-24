"""Headless helper that re-exports the current IDB's persisted CFS state."""

import json
import os
import sys
import traceback

import ida_auto
import ida_pro


PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)
for module_name in [
    name for name in list(sys.modules)
    if name == "cfs5" or name.startswith("cfs5.")
]:
    del sys.modules[module_name]

from cfs5 import api  # noqa: E402


def main():
    result_path = os.environ["CFS_REEXPORT_RESULT"]
    try:
        ida_auto.auto_wait()
        result = api.export(
            os.environ["CFS_REEXPORT_CATALOGUE"], merge="replace",
            build=int(os.environ["CFS_REEXPORT_BUILD"]), include_members=True,
        )
        payload = {"result": result}
        code = 0 if result.get("ok") else 2
    except Exception as exc:
        payload = {"exception": str(exc), "traceback": traceback.format_exc()}
        code = 1
    with open(result_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    ida_pro.qexit(code)


if __name__ == "__main__":
    main()
