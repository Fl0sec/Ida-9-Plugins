# plugin_skeleton

Starting point for a new IDA Pro 9.0 plugin. Copy the whole directory, then
follow the checklist in [`docs/workflow.md`](../../docs/workflow.md).

```
plugin_skeleton/
  skeleton_plugin.py   # entry file: PLUGIN_ENTRY, actions, orchestration
  skeleton/            # importable package: all reusable logic
    __init__.py        # docstring + VERSION
    common.py          # msg(), ea_str(), get_search_ranges()
  ida-plugin.json      # IDA 9 plugin manifest
```

What it demonstrates:

- the `sys.path` + `sys.modules` reload shim every entry file needs,
- two actions registered from a single `_ACTIONS` table, with symmetric
  `init()` / `term()`,
- a Functions-window context submenu via `UI_Hooks`,
- a cancellable batch loop with progress, per-item error isolation, and a
  summary to both the Output window and a popup.

Replace the body of `process_one` with the real work.
