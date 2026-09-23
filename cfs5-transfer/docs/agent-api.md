# Agent API (`cfs5/api.py`) — rules

Programmatic export for an agent driving IDA. Drive it with `py_eval`:

```python
import sys; sys.path.insert(0, r"%APPDATA%\Hex-Rays\IDA Pro\plugins")
from cfs5 import api
```

## Surface

| Call | Does |
|---|---|
| `register(function_names=[], global_names=[])` | add names to this IDB's export set |
| `unregister(function_names=[], global_names=[])` | remove names |
| `clear()` | empty the set |
| `registered()` | the set + anything that no longer resolves |
| `export(path, merge="append", build=None, include_members=True)` | write the set |
| `export_list(path, function_names=[], global_names=[], ...)` | explicit list, ignores the set |
| `declare_members(members_=[], discovery="sites_only")` | declare `member_offset` values |
| `declare_strides(strides=[])` | declare `element_stride` constants |
| `undeclare(names=[])` | remove declarations by `"Owner::name"` |
| `declarations()` | every declaration + how it resolves now |

## Members and strides

```python
api.declare_members([
    "CSceneObject::m_hOwnerEntity",                      # scan for sites
    {"owner": "CModel", "member": "m_nBoneCount",
     "sites": [{"ea": 0x1234, "op": 1}]},                # or name them
])
api.declare_strides([
    {"owner": "CMeshDrawPrimitive", "name": "kStride", "value": 0x30,
     "sites": [{"ea": 0x5678, "op": 1}]},
])
```

**Sites are evidence locations, never values.** You say where to look; the
database says what the answer is. A site that decodes a different number is
dropped, not trusted.

Sites exist because **correct pointer typing does not guarantee IDA member
xrefs** — a heap-backed object can yield none however well typed it is, so
automatic discovery can legitimately find nothing.

| | `member_offset` | `element_stride` |
|---|---|---|
| value from | the IDA field | you assert it |
| sites | optional | **required** |
| discovery | `sites_only` (default) / `sites_plus_auto` / `auto` | never |
| a site decoding another value | that candidate is dropped | **whole declaration rejected** |

`element_stride` is weaker on purpose: nothing in the database associates an
instruction with "the stride of this array", so the sites are the only
evidence and a contradiction among them is fatal. `owner` is a namespace
there, not a claim that the type has such a field.

`merge`: `"append"` refreshes re-exported items and keeps the rest;
`"replace"` discards the file. Append is refused across a different image or
build — that is an error, not something to retry.

## Every call returns these four keys

| Key | Meaning |
|---|---|
| `ok` | everything asked for succeeded |
| `partial` | some succeeded, some did not — `ok` is False |
| `error` | the whole call failed and nothing happened, else `None` |
| `unresolved` | `[{kind, name, reason}]` for every input that did not make it |

`ok` is **not** "something worked". 51 of 52 exported is `ok=False,
partial=True`. Check `ok`; when it is False read `unresolved`.

## Rules for anything added here

1. **No blocking UI.** No `ask_*`, `info`, `warning`, `Choose`. A prompt inside
   an agent call is a hang. Interactive code belongs in the entry file.
2. **Batch in, data out.** Take lists; return a JSON-serializable dict. Never
   return prose, never print instead of returning.
3. **Return the four keys above**, via `_result()`. One vocabulary for failure:
   `unresolved`, never a third synonym.
4. **Idempotent.** Re-register is `already`; unregister-absent is a no-op.
5. **A bad entry never fails the batch.** Validate per item, collect into
   `unresolved` with a `reason`, keep the rest.
6. **Partial success is never `ok`.** Silent attrition is the failure this
   module exists to prevent (docs/signature-durability.md).
7. **Store names, not addresses** (`registry.py`). Resolve at export time.
8. **No new resolution semantics.** This layer writes the same CFS6 records the
   UI writes. Custom signatures, py_eval solvers and new `origin` values are
   format changes: they need a schema revision and a non-IDA consumer story
   (`docs/cfs6-format.md`), not an API argument.
9. **py_eval may find things, never resolve them.** Arbitrary code can decide
   *what* to export; only verified patterns describe *how to find it later*.
   The cs2 dumper cannot run Python.

## Layout

`registry.py` ida-free identity + validation (unit tested) · `store.py`
netnode persistence, write-back verified · `export.py` the engine, never
prompts · `api.py` the facade.

The UI actions call `export.export_to_path` too. Fix bugs there, not in a
second copy.
