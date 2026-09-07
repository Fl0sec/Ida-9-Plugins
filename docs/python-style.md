# Python style

Python 3.12 (IDA 9.0's interpreter). PEP 8 with the deviations and additions
below. Existing code in `cfs5-transfer/` is the reference implementation — when
this document and that code disagree, the code wins and this document is wrong.

## Formatting

- 4-space indent, no tabs. Soft limit ~88 columns; wrap rather than run long.
- Two blank lines between top-level defs/classes, one between methods.
- Section banners for long modules, sparingly:

  ```python
  # ---------------------------------------------------------------------------
  # Discovery
  # ---------------------------------------------------------------------------
  ```

- **`%`-formatting for messages**, matching the existing code:
  `msg("Exported %d functions." % count)`. f-strings are fine in new pure-Python
  helpers; don't churn existing lines to convert them.
- ASCII in source. Non-ASCII in strings only when it is actually data.

## Imports

Three groups, blank line between:

```python
import os
import sys

import idaapi
import ida_bytes
import ida_funcs
import ida_kernwin
import idautils

from myplugin.common import msg, ea_str
```

- Import specific `ida_*` modules. Never `from idaapi import *` — it drags in
  ~48 modules' worth of names and makes it impossible to tell where a symbol
  came from (or whether it still exists in 9.0).
- `idaapi` only for `plugin_t` and the `PLUGIN_*` flags; use the specific
  module for everything else.
- **Stdlib only.** IDA's interpreter has no third-party packages you can rely
  on being present on another machine.
- The entry-file `sys.path`/reload shim is the one exception to import
  ordering: it sits above everything except `os` and `sys`.

## Naming

| Kind | Convention | Example |
|---|---|---|
| function, variable | `snake_case` | `get_user_global_eas` |
| class | `CapWords` | `ExportSelFuncsHandler` |
| module constant | `UPPER_SNAKE` | `PROGRESS_EVERY`, `ACTION_ALL_FUNCS` |
| module-private | leading `_` | `_HERE`, `_is_human_named`, `_ACTIONS` |
| compiled regex constant | `_NAME_RE` | `_HUMAN_NAME_RE` |

- Address variables are `ea` / `eas` / `*_ea`. Say what an address *is*
  (`func_ea`, `target_ea`), not just `addr`.
- Action ids are namespaced strings: `"myplugin:export_selected"`.

## Docstrings and comments

- Module docstring on every package module: what it holds and who consumes it.
- Docstring on any function whose contract is not obvious from the signature —
  especially anything with a non-trivial return shape or an invariant.
- **Comments explain why.** A comment restating the code is noise; a comment
  recording *which IDA behaviour forced this shape* is the most valuable thing
  in the file. Compare:

  ```python
  # BAD:  bump the csv field limit
  # GOOD: .cfs payloads can be large (whole struct bodies); lift the csv field
  #       cap once.
  ```

- When a heuristic exists because an IDA API is untrustworthy, say so and name
  the API (`has_user_name` / FF_NAME is far too broad because ...).

## Error handling

- **Wrap IDA calls in `try/except` with a diagnostic.** Not defensive
  programming for its own sake: the SWIG bindings raise inconsistently across
  argument types and IDB states, and one unhandled exception in a batch loop
  loses the entire run.

  ```python
  try:
      name = ida_segment.get_segm_name(seg)
  except Exception:
      name = "segment@%s" % ea_str(seg.start_ea)
  ```

- Bare `except Exception:` is acceptable here — the bindings do not raise a
  documented, stable exception hierarchy. `except:` (bare) is not: it swallows
  `KeyboardInterrupt` and cancellation.
- Never swallow silently inside a loop over user data. Either recover with a
  sensible default (as above) or `msg()` the failure and skip the item.
- Teardown paths (`term()`, `finally`) may swallow — nothing useful can be done
  there and raising during unload destabilises IDA.

## Diagnostics

Exactly one prefixed logging helper per plugin, in the shared package:

```python
def msg(text):
    """Print a prefixed line to IDA's Output window."""
    ida_kernwin.msg("[MYPLUGIN] %s\n" % text)
```

- Every plugin gets its own bracketed tag so Output-window lines are greppable.
- Address formatting goes through one helper too
  (`ea_str(ea)` -> `"0x401000"` / `"BADADDR"`), so addresses are never printed
  two different ways.
- There is no in-IDA test harness. These lines *are* the debugger — log
  per-item outcomes in batch operations, not just the summary.

## Structure

- Entry file: shim, imports, constants, discovery/orchestration, handlers,
  hooks, action table, `plugin_t`, `PLUGIN_ENTRY`. Nothing reusable.
- Package: one module per concern, each with a docstring saying what it owns.
- **A format or protocol has exactly one definition site.** Row layouts, tags,
  and their readers/writers live in one module; no other file hand-formats a
  row. `cfs5/cfsfile.py` is the model.
- Keep IDA-free logic IDA-free. Anything that does not import `ida_*` can be
  tested directly with plain Python, which is the only real test you get.
