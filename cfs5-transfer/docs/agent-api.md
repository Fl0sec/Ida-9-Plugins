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

## Explicit anchor sites for functions

A function entry is a name, or an object carrying sites:

```python
api.register(function_names=[
    "CCSPlayer_Think",
    {"name": "ui_toolkit_show_generic_popup_ok", "sites": [0x108C545]},
])
```

A site is an address you determined identifies the function — an instruction
that **references** it (`call`, `jmp`, or the `lea` that hands it to a
registrar), or an instruction **inside** it to anchor a body pattern on. Which
one it is is worked out from the database, not declared.

This exists because discovery legitimately runs out of options: a function
reached only through a vtable has no call site, and one in a family of
byte-identical clones has no unique prologue. When that happens the address you
found by hand is the only evidence left, and there has to be a way to hand it
over.

**A site is not a signature.** The exporter re-decodes it, re-derives what it
references, and refuses it when that is not this function; only then does it
build a pattern and hold it to the same uniqueness rule as a discovered anchor.
You supply *where to look*; the database still supplies the answer. This is the
same contract as a member declaration's `sites`.

A site that holds up is **pinned**: it occupies a candidate slot unconditionally
and is never scored out of the file. Scoring is a guess about which pattern
survives the next build, and it must not discard evidence supplied on purpose.

A refused site appears in the export's `advisory` list with the reason. Sites
are stored per entry and removed with `unregister`. A site on a *global* is
rejected — a global is anchored from its data references.

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

### What a failure says

An `unresolved` entry from an export carries a `reason` that names **which axis
failed and why**, plus a `diagnosis` object keyed by axis:

```
no unique signature (entry: clone_family; external_rel: data_xrefs_only;
                     body: unique_anchor_outside_pdata)
```

| Reason | Means |
|---|---|
| `clone_family` | N byte-identical prologues exist — **no** entry pattern can ever be unique; look for a structural anchor |
| `no_unique_window` | every window tried still matched elsewhere |
| `no_xrefs` | nothing references the address from code |
| `data_xrefs_only` | no call/jump, but N instructions take its address (a `lea`-passed callback) |
| `xrefs_not_unique` | references exist; no window around one was unique |
| `unique_anchor_outside_pdata` | a unique body anchor **does** exist, but outside the function's own `.pdata` range, so a hit could not be mapped back to it |

`export` also returns `advisory`: findings that are not failures — near-miss
anchors (with their offset and pattern, so you can judge them yourself) and
rejected sites. An item can be fully exported and still have something here.

These distinctions are the difference between "this function has no
distinguishing bytes" (unsolvable) and "its distinguishing bytes are somewhere
the resolver cannot follow" (solvable, differently).

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
