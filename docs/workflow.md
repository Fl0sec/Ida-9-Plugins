# Workflow

## Starting a new plugin

```bash
cp -r templates/plugin_skeleton my-plugin
```

Then, in order:

1. Rename the entry file (`skeleton_plugin.py` -> `my-plugin.py`) and the
   package directory (`skeleton/` -> `myplugin/`).
2. Update the reload shim's package name — **both** occurrences in the
   `sys.modules` purge. A stale name there means edits silently don't take
   effect, which is a miserable bug to chase.
3. Set `PLUGIN_NAME`, the `ACTION_*` ids (`"myplugin:..."`), the hotkey, the
   `msg()` tag in `myplugin/common.py`, and `VERSION` in `myplugin/__init__.py`.
4. Rename the `plugin_t` subclass. That name plus the action ids are the
   plugin's identity — settle on them now, don't churn them later.
5. `python tools/check.py my-plugin` — the skeleton passes clean, so any
   failure is from your edit.
6. Write a `README.md` for the plugin: what it does, install, and each UI
   action.

Consider a per-plugin `CLAUDE.md` once the plugin has non-obvious invariants
(the file format, the signature model, why a heuristic exists) — see
`cfs5-transfer/CLAUDE.md`. The root `CLAUDE.md` stays the authority for shared
rules; the local one only covers that plugin's internals.

## The edit loop

```bash
python tools/check.py my-plugin          # after every non-trivial edit
pwsh tools/deploy.ps1 my-plugin          # -WhatIf to preview
```

Then in IDA: restart (or reload the plugin) and exercise the actions against a
real IDB, watching the Output window.

`deploy.ps1` copies top-level `.py` entry files plus any package directory,
strips `__pycache__`, and refuses to run if the source or plugins directory is
missing. Target: `%APPDATA%\Hex-Rays\IDA Pro\plugins`.

## What "verified" means

Be precise about this in reports — the gap between the two is where bugs live.

| Claim | Backed by |
|---|---|
| "it compiles / imports / uses real 9.0 APIs" | `tools/check.py` |
| "the pure-logic layer round-trips" | direct Python execution of the IDA-free modules |
| "the API behaves this way on a real IDB" | an `ida-pro-mcp` probe against an actual IDB |
| "the plugin works in IDA" | **only** a human running it in IDA |

Never report the last row on the strength of the first. Say what you ran and
what remains unverified.

## Debugging inside IDA

- The Output window is the only log. `msg()` generously; a per-item line in
  batch loops turns "it didn't work" into a location.
- **Stale `__pycache__` is the classic phantom bug**: IDA runs old bytecode
  while you read new source. The reload shim and `deploy.ps1`'s pycache strip
  both exist for this; if behaviour contradicts the source, suspect it first.
- A modal wait box with no way out means an exception escaped past
  `hide_wait_box()`. Always `finally`.
- If an action doesn't appear in a context menu, check `update()`'s widget-type
  gate before anything else.
- If IDA crashes on activating an action, the handler was garbage-collected —
  the `plugin_t` must hold a reference to every handler instance.

## Using ida-pro-mcp during development

The `ida-pro-mcp` MCP server is available in this environment and is the
fastest way to answer "what does this API actually return here?".

- Load the `ida-pro-mcp:idapython` skill before the first IDA action.
- Prefer typed MCP tools (`decompile`, `xrefs_to`, `set_type`, `rename`, ...)
  over raw `py_eval`; drop to `py_eval` to probe an API shape you are about to
  depend on in plugin code.
- Probe read-only first, on a scratch IDB, before anything that mutates.
- `tools/check.py` proves a symbol *exists*; an MCP probe proves it *behaves*.
  Use both.

## Committing

- Run `python tools/check.py` (whole repo) before committing.
- Commit only when asked. Keep changes to one plugin per commit where possible.
- Never commit into `ida-pro-mcp/` or `reference/`; never commit IDBs.
