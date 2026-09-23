# Agent API (`cfs5/api.py`) — rules

Programmatic export for an agent driving IDA. Drive it with `py_eval`:
`from cfs5 import api; api.register(functions=[...])`.

## Surface

| Call | Does |
|---|---|
| `register(functions=[], globals=[])` | add names to this IDB's export set |
| `unregister(functions=[], globals=[])` | remove names |
| `clear()` | empty the set |
| `registered()` | the set + anything that no longer resolves |
| `export(path, merge="append", build=None, include_members=True)` | write the set |
| `export_now(path, functions=[], globals=[], ...)` | one-shot, ignores the set |

`merge`: `"append"` refreshes re-exported items and keeps the rest;
`"replace"` discards the file. Append is refused across a different image or
build — that is an error, not something to retry.

## Rules for anything added here

1. **No blocking UI.** No `ask_*`, `info`, `warning`, `Choose`. A prompt inside
   an agent call is a hang. Interactive code belongs in the entry file.
2. **Batch in, data out.** Take lists; return a JSON-serializable dict. Never
   return prose, never print instead of returning.
3. **Idempotent.** Re-register is `already`; unregister-absent is a no-op.
4. **A bad entry never fails the batch.** Validate per item, collect into
   `rejected`/`uncovered` with a `reason`, keep the rest.
5. **Always report what was not covered.** Every call that can partially
   succeed returns `uncovered`. Silent partial success is the failure this
   module exists to prevent.
6. **Store names, not addresses** (`registry.py`). Resolve at export time.
7. **No new resolution semantics.** Phase 1 writes the same CFS6 records the UI
   writes. Custom signatures, py_eval solvers and new `origin` values are
   format changes: they need a schema revision and a non-IDA consumer story
   (`docs/cfs6-format.md`), not an API argument.
8. **py_eval may find things, never resolve them.** Arbitrary code can decide
   *what* to export; only verified patterns describe *how to find it later*.
   The cs2 dumper cannot run Python.

## Layout

`registry.py` ida-free identity + validation (unit tested) · `store.py`
netnode persistence, write-back verified · `export.py` the engine, never
prompts · `api.py` the facade.

The UI actions call `export.export_to_path` too. Fix bugs there, not in a
second copy.
