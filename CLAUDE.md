# CLAUDE.md

Guidance for agents working in this repository. **Read this before writing or
editing any IDA plugin code here.**

## Hard constraints (non-negotiable)

1. **Target is IDA Professional 9.0 / IDAPython 9.0 / Python 3.12 ONLY.**
   IDA 9.0 removed and moved a large amount of API surface. Do not write
   `ida_*` calls from memory of IDA 7.x/8.x or from generic "IDAPython"
   recall — a call that looks right and does not exist in 9.0 fails only when
   the plugin is loaded into IDA, where nothing catches it for you.
2. **Verify every `ida_*` symbol before relying on it.** The ground truth is
   the local stub tree, not your memory:
   `C:\Program Files\IDA Professional 9.0\python\ida_*.py`.
   `python tools/check.py <plugin-dir>` does this mechanically for the whole
   file — run it, don't eyeball it. See [docs/ida9-api.md](docs/ida9-api.md)
   for the known 9.0 deltas and the grep recipes.
3. **If you cannot verify a symbol exists in 9.0, do not use it.** Find the
   9.0 replacement, or say the approach is unverified — never guess.
4. **Use modern `ida_*` modules, never `idc`.** `idc` is a legacy compatibility
   shim; its behaviour and return conventions are inconsistent. `idautils` is
   fine for iteration (`Functions()`, `XrefsTo()`, `Heads()`, `Strings()`).
5. **These are plugins, not scripts.** There is no test harness inside IDA.
   "Running it" means deploying to IDA's `plugins/` directory and exercising
   the UI against a real IDB. Everything you can check offline, you must check
   offline — see [Verification](#verification-what-you-can-prove-offline).
6. **Never edit the deployed copy under
   `%APPDATA%\Hex-Rays\IDA Pro\plugins`.** Edit here, then `tools/deploy.ps1`.
   Editing the deployed copy silently diverges from the repo.

## Repo layout

```
ida-9-plugins/
  CLAUDE.md            # this file (AGENTS.md points here)
  docs/                # the detail these rules point at
    ida9-api.md        # IDA 9.0 API deltas + how to verify a symbol
    plugin-anatomy.md  # the canonical plugin skeleton and UI patterns
    python-style.md    # the house Python style
    workflow.md        # new-plugin checklist, deploy, debug
  templates/
    plugin_skeleton/   # copy this to start a new plugin
  tools/
    check.py           # offline gate: compile + API existence + stub-import
    ida_api_lint.py    # the API-existence pass on its own
    deploy.ps1         # copy a plugin into IDA's user plugins dir
  cfs5-transfer/       # CFS5 signature/type transfer plugins (has its own CLAUDE.md)
  ida-pro-mcp/         # separate upstream checkout, git-ignored, DO NOT EDIT from here
  reference/           # third-party plugin sources for reading only, git-excluded
```

`cfs5-transfer/CLAUDE.md` is the authority for that plugin's internals; this
file is the authority for everything shared. `ida-pro-mcp/` and `reference/`
are **read-only references** — never commit changes into them from this repo.

## One plugin, one directory

A plugin lives in its own top-level directory:

```
my-plugin/
  my-plugin.py       # entry file: PLUGIN_ENTRY, UI glue, orchestration only
  myplugin/          # importable package: all real logic
    __init__.py      # docstring + VERSION
    ...
  README.md          # what it does, how to install, what the UI actions are
```

Rules that make this work:

- **The entry file holds no reusable logic.** Discovery, orchestration, action
  handlers, `plugin_t`. Everything else goes in the package, so a second plugin
  can import it instead of copying it.
- **Every entry file starts with the sys.path + reload shim** (see
  [docs/plugin-anatomy.md](docs/plugin-anatomy.md)). It makes the sibling
  package importable regardless of IDA's `sys.path`, and purges the package
  from `sys.modules` so an edit is picked up on the next plugin load instead of
  requiring an IDA restart. Keep it at the very top, above all other imports.
- **Import-time work must be trivial** — imports, constants, class definitions.
  Anything touching the IDB happens in `init()` or later. This is what lets
  `tools/check.py` import the module outside IDA.
- Plugin/class identities (`register_action` ids, hotkeys, the `plugin_t`
  subclass name) are the plugin's public surface. Don't rename them casually.

## Python style (summary — full rules in docs/python-style.md)

- Python 3.12, 4-space indent, ~88 column soft limit, stdlib only (IDA's
  interpreter has no third-party packages you can rely on).
- Import order: stdlib, blank line, `ida_*`/`idaapi`/`idautils`, blank line,
  local package. Import specific `ida_*` modules; never `from idaapi import *`.
- `snake_case` for functions/variables, `CapWords` for classes, `UPPER_SNAKE`
  for module constants. A leading `_` marks module-private.
- **Wrap IDA calls in `try/except` with a diagnostic.** IDA's Python bindings
  raise inconsistently across type shapes and IDB states; one unhandled
  exception aborts a whole batch loop. Catch, log via the plugin's `msg()`,
  continue.
- **Every long loop is cancellable**: `show_wait_box` / `replace_wait_box` /
  `user_cancelled` / `hide_wait_box` in a `finally`.
- Docstrings on modules and on any function whose contract is not obvious from
  its name. Comments explain **why**, never what the line already says.
- Diagnostics go to the Output window through a single prefixed `msg()` helper
  (`[MYPLUGIN] ...`). With no in-IDA test harness these are the primary
  debugging channel — be generous and specific with them.

## UI, caching and sentinels — read before touching a `Choose` or an action

These are the repo's scar tissue. Each one fails *silently* or blames the wrong
thing, so re-deriving them costs an in-IDA debugging round trip every time. Full
detail with the stub evidence is in
[docs/ida9-api.md](docs/ida9-api.md#ui-traps-that-cost-real-debugging-time).

- **`Choose` callbacks return a flat `[flag, line, ...]`, not `(flag, selection)`** —
  despite what the stub docstrings say. Nesting the selection raises
  `ValueError: Sequence item #1 cannot be converted`, and it only shows up once
  you add `CH_MULTI`. Same for `adjust_last_item(n)`: pass one line number.
- **Custom chooser actions go through `AddCommand` + `OnCommand`**, never by
  hijacking `CH_CAN_EDIT`. `OnCommand` fires **once per selected row**, so
  whole-selection work does not belong in it.
- **Attach actions in `UI_Hooks.finish_populating_widget_popup`**, not in
  `Choose.OnPopup` (which IDA drives too early for them to stick).
- **A UI action must never dead-end.** No context → open a picker, don't warn
  the user to do what they just did. And when a lookup can fail three ways, say
  *which* — one generic message hides the other two causes.
- **Never cache a cancelled or failed scan**, build the value *before* computing
  its cache key (or the key is stale on the very first call), and **log cache
  hits** so a hit is distinguishable from "never ran".
- **`BADADDR`/`-1` are values, not `None`.** Normalize sentinels to `None` in the
  model's constructor so already-stored records repair themselves on load.

## Verification: what you can prove offline

Run before every commit, and after every non-trivial edit:

```bash
python tools/check.py my-plugin
```

Three passes, all of which catch real bugs without IDA:

| Pass | Catches |
|------|---------|
| compile | syntax errors in every `.py` |
| api | `ida_*` symbols that don't exist in IDA 9.0 |
| import | broken cross-module wiring, import-time crashes (IDA stubbed out) |

What it **cannot** prove: that a call does the right thing on a real IDB. Pure
logic (parsers, encoders, format layers) should be written so it is testable
without IDA — keep it free of `ida_*` imports and exercise it directly.

State plainly in your report which of these you ran, and that in-IDA behaviour
is unverified unless the user confirms it.

## Deploying and testing in IDA

```powershell
pwsh tools/deploy.ps1 my-plugin        # add -WhatIf to preview
```

Copies entry `.py` files plus package directories into
`%APPDATA%\Hex-Rays\IDA Pro\plugins`, stripping `__pycache__` (a stale one
shadowing an edited module is a classic phantom bug). Then restart IDA or
reload the plugin. Full loop in [docs/workflow.md](docs/workflow.md).

## Using the ida-pro-mcp tooling

The `ida-pro-mcp` MCP server and its `idapython` skill are available in this
environment and are the fastest way to check API behaviour against a live IDB.

- Load the `ida-pro-mcp:idapython` skill before the first IDA action.
- Prefer typed MCP tools (`rename`, `set_type`, `decompile`, `xrefs_to`, ...)
  over raw `py_eval`; use `py_eval` to probe an API shape you are about to
  depend on in plugin code. A probe against a real IDB beats reasoning.
- MCP verifies *behaviour*; `tools/check.py` verifies *existence*. Neither
  replaces the other.

## Git

- Work on `main` unless the user asks otherwise; commit only when asked.
- Never commit into `ida-pro-mcp/` (git-ignored) or `reference/` (excluded via
  `.git/info/exclude`) — they are upstream checkouts.
- Never commit IDBs or IDA artifacts (`*.i64`, `*.idb`, `*.til`, ...) —
  `.gitignore` covers these; don't force-add past it.
- Author identity for this repo is `fl0sec`.
