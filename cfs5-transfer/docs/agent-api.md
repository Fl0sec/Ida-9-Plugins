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
| `export_selected(path, declaration_names=[], item_ids=[], build=None)` | atomically refresh only named items in an existing file |
| `declare_members(members_=[], discovery="sites_only")` | declare `member_offset` values |
| `declare_strides(strides=[])` | declare `element_stride` constants |
| `declare_constants(constants=[])` | declare `constant` values (bit positions, sentinels) |
| `declare_extents(extents=[])` | declare `object_extent` recipes |
| `declare_patches(patches=[])` | declare validated instruction patch sites |
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

## Vtable locators for functions

A registered function may declare an MSVC RTTI vtable slot:

```python
api.register(function_names=[
    {"name": "notify_inventory_has_new_items",
     "vtable": {"type": "CCSPlayerInventory", "slot": 19}},
])
```

`subobject_offset` may be supplied when multiple-inheritance RTTI exposes more
than one vtable. Without it, an ambiguous class is refused and the available
offsets are reported. Registration resolves RTTI immediately and requires the
slot to hold the named function. Export verifies it again, builds a bounded
confirm signature inside the function, and pins the resulting `VTABLE`
candidate like an explicit site. The record stores the raw MSVC descriptor
read from the image, never IDA's demangled rendering.

These locators are export-only. The IDA importer skips them; a non-IDA consumer
implements the revision-2 algorithm in `cfs6-format.md`.

## String-relative locators for functions

```python
api.register(function_names=[
    {"name": "ui_toolkit_show_generic_popup_ok",
     "anchor_string": "ShowGenericPopupOk"},
])
```

The string is matched as exact UTF-8 bytes including its trailing NUL. The
exporter examines only code references in bounded `.pdata` registration
entries and accepts one structurally unique executable-targeting handler LEA;
it never relies on a register or fixed name-to-handler distance. Registration
verifies that handler is the named function, and export pins a `STRING_REL`
candidate carrying the function's confirm signature. Prefix strings, unrelated
unreferenced copies, inverted argument registers, and tail-call table entries
are handled by the same rule.

## Members, strides and constants

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
api.declare_constants([
    {"owner": "CEntityIdentityFlags", "name": "kModelChangeBlockedBit",
     "value": 0x6, "sites": [{"ea": 0x9ABC, "op": 1}]},
    {"owner": "SosConstants", "name": "kDisableStartTime",
     "value": -1, "sites": [{"ea": 0x3AE51F, "op": 1}]},
])
```

**Sites are evidence locations, never values.** You say where to look; the
database says what the answer is. A site that decodes a different number is
dropped, not trusted.

Sites exist because **correct pointer typing does not guarantee IDA member
xrefs** — a heap-backed object can yield none however well typed it is, so
automatic discovery can legitimately find nothing.

| | `member_offset` | `element_stride` / `constant` |
|---|---|---|
| value from | the IDA field | you assert it |
| sites | optional | **required** |
| discovery | `sites_only` (default) / `sites_plus_auto` / `auto` | never |
| a site decoding another value | that candidate is dropped | **whole declaration rejected** |

`element_stride` and `constant` are weaker on purpose: nothing in the database
associates an instruction with "the stride of this array" or "this bit
position", so the sites are the only evidence and a contradiction among them is
fatal. `owner` is a namespace there, not a claim that the type has such a
field. The two differ only in what a consumer does with the number — use
`constant` for a value that is not a size or a stride, such as a bit position
tested by `bt reg, 6` or a sentinel compared against a field.

Use the semantic signed value for a sign-extended sentinel. An imm8 `FF` that
the consumer reads with `signed: true` is `-1`, not `0xFF` or `0xFFFFFFFF`;
the same signed value is written to `source.expected_value`.

Object extents require explicit recipe inputs:

```python
api.declare_extents([{
    "owner": "TraceFilter", "name": "kSize", "value": 0x40,
    "sites": [{"ea": 0x1234, "op": 0,
               "access_width": 1, "alignment": 8}],
}])
```

The consumer computes `align_up(displacement + access_width, alignment)`.
Every site must independently reproduce the asserted extent; no zero fallback
is emitted. Any VALUE site may additionally name `window_start_ea`. It must be
an instruction start in the same function, at or before the extraction
instruction; the exporter grows only windows starting there and still requires
image-wide uniqueness.

A compound stride whose value is encoded only by a bounded LEA chain uses a
closed recipe rather than an expression or caller-provided bytes:

```python
api.declare_strides([{
    "owner": "CModelHitboxSet", "name": "kStride", "value": 0x48,
    "recipe": {"op": "LEA_SCALE_CHAIN", "steps": [
        {"ea": 0x1000, "op": 1},
        {"ea": 0x1004, "op": 1},
        {"ea": 0x1008, "op": 1},
    ]},
}])
```

The exporter requires every step to decode as LEA in one function, derives
base/index scale coefficients from instruction bytes, ignores additive
base/displacement terms, and requires the folded coefficient to reproduce the
asserted stride. The file carries only instruction offsets, sizes, and operand
indices; consumers independently decode and fold the same chain.

Patch sites are instruction locations, not functions or values:

```python
api.declare_patches([{
    "owner": "spotted", "name": "PlayerGate",
    "site": {"ea": 0xEB8B9E, "expected_instruction": "jz",
             "expected_bytes": "0F 84", "patch_size": 6},
}])
```

Export decodes the site, verifies mnemonic, opcode prefix, full mapped patch
span and instruction boundary, then emits a unique `SITE` candidate resolving
to the instruction start. The patch item carries the expected original bytes
and span so a consumer can retain its runtime original-byte check.

### `value_adjust`

`value_adjust` is what a consumer **adds** to the number the instruction
encodes, for a site that reaches the field through a subobject base:

```
reported = encoded_at_site + value_adjust
```

So the exporter looks for `reported - value_adjust` at the site, where
`reported` is the IDA member offset (or the asserted value). Declare the
adjustment that makes that true and nothing else — for `lea rdi, [rcx+8]`
reaching a member IDA places at `0x10`, `value_adjust` is `+8`.

### What value to assert

**The asserted value is what the extraction recipe produces**, which is the
field read at its encoded width with the candidate's `signed` flag — not
necessarily what IDA prints for the operand. The two differ for a
sign-extended immediate:

| site | encodes | IDA shows | assert |
|---|---|---|---|
| `cmp r8d, 0FFFFFFFFh` (`41 83 F8 FF`) | one byte, `FF` | `0xFFFFFFFF` | `-1` |
| `add rax, 30h` (`48 83 C0 30`) | one byte, `30` | `0x30` | `0x30` |
| `bt eax, 0Bh` (`0F BA E0 0B`) | one byte, `0B` | `0xB` | `0xB` |

Only the first is ambiguous, and both spellings describe the same 32 bits —
but only the signed reading is what a consumer computes, so asserting
`0xFFFFFFFF` is refused with `extraction_recipe_reproduces_a_different_value`
rather than exported. Exporting it would publish an `expected_value` the
consumer can never reproduce, and it would read as image drift forever, on the
image it was built from.

### When a derived value is not exported

Four distinct refusals, never one shared sentence — the one you get tells you
which thing to fix:

| Message | Meaning |
|---|---|
| `MEMBER_NO_FIELD` | the declaration names a field this database no longer has |
| `MEMBER_NO_SITE` | nothing produced a site: none declared, none discovered |
| `MEMBER_NO_PATTERN` | sites were tested and none yielded a candidate; each site's reason is listed |
| ↳ `site_is_ambiguous_at_every_window_length` | proven, not assumed: even the widest window matches twice. Pick another site |
| ↳ `unique_only_in_a_window_longer_than_48_bytes` | the evidence is there but not exportable — raise `MAX_PATTERN_BYTES` or pick a site in a less repetitive function |
| ↳ `no_window_cleared_the_exact_byte_floor` | too few concrete bytes around the site (`VALUE_MIN_EXACT_BYTES`) |
| ↳ `gave_up_after_48_uniqueness_probes` | the only one of the four that is a limitation of the exporter |
| ↳ `extraction_recipe_reproduces_a_different_value` | see *What value to assert* above |
| `MEMBER_DISCARDED` | candidates existed and every one decoded a different value, each listed |

`MEMBER_FLAKY_FIRST_PASS` is not a refusal: the first generation pass produced
no candidate and an identical second one did. The item **is** exported. It means
the first answer was wrong, not the declaration — report it rather than
re-declaring anything.

`merge`: `"append"` refreshes re-exported items and keeps the rest;
`"replace"` discards the file. Append is refused across a different image or
build — that is an error, not something to retry.

## Incremental refresh

Use `export_selected` after changing one or a few declarations:

```python
api.export_selected(
    r"C:\exports\client.cfs",
    declaration_names=[
        "CEntityIdentityFlags::kModelChangeUseExplicitBit",
        "CEntityIdentityFlags::kModelChangeBlockedBit",
    ],
    build=14182,
)
```

Qualified names select derived-value declarations. Exact `item_ids` may select
functions, globals, or derived values. An ambiguous qualified name must be
replaced with its exact id, for example `const:Owner::name`.

The destination must already exist. Selection is resolved completely before
generation; an unknown name/id refuses the call and never falls back to a full
export. Only selected items run candidate generation. Their parent records,
candidates, coverage, item type payloads and directly required local types are
replaced; unrelated records are carried over from the existing file. Image and
build compatibility is enforced before generation.

The update is transactional. Every selected item must generate successfully,
and the complete temporary CFS file must parse cleanly, before the destination
is replaced. A failed item therefore leaves its old file intact rather than
silently retaining the stale record. Results report `requested`, `refreshed`,
`preserved`, `removed_records`, `unresolved`, and `advisory`. Use full `export`
when creating a file, intentionally refreshing the whole registered set, or
rebuilding every transported type after broad type-library changes.

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
