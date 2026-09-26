# Programmatic CFS API

`cfs5.api` is the stable, non-interactive facade. Calls accept plain Python
data and return JSON-serializable dictionaries. Implementation lives in the
focused `api_registry`, `api_declarations`, `api_export`, and `api_import`
modules; callers import only the facade.

```python
from cfs5 import api
```

## Result contract

Every call returns:

| Field | Meaning |
|---|---|
| `ok` | everything requested succeeded |
| `partial` | some work succeeded and some did not; `ok` is false |
| `error` | operation-level failure, otherwise `None` |
| `unresolved` | per-item failures with `kind`, `name`, and `reason` |

Import results additionally contain `outcomes`: one row for every catalogue
record, with its candidate-level resolution results. Derived values and patches
are resolved and checked during `import_catalogue()`, but never applied there;
patching and producer-state writes remain exclusive to migration/export flows.
For member values, `destination-unverified` is advisory: code candidates
validated but the destination had no independently existing field. Ordinary
import does not transport local type/member layouts; `import_and_migrate()` is
the explicit type/state reconstruction operation.

Check `ok`. When false, inspect both `error` and every `unresolved` entry.
Partial success is deliberately not success.

Service calls never prompt, display popups, or return IDA objects. UI belongs
in the two plugin entry files.

## Transfer a catalogue to a new build

```python
result = api.import_and_migrate(r"C:\catalogues\client.cfs")
```

This API accepts one explicit `.cfs` file. It does not implement catalogue-root
discovery, recursive loading, or active-catalogue selection; those are caller
or consumer responsibilities and must be inspected in that component before
being described as CFS API behavior.

This first applies resolvable names and types, then transactionally reconstructs
producer state from destination-build evidence. The normal policy commits the
valid subset and reports every non-portable record.

Use strict producer-state migration when any missing record must block all
state writes:

```python
result = api.import_and_migrate(
    r"C:\catalogues\client.cfs",
    require_all_state=True,
)
```

The two phases are independently available:

```python
catalogue = api.import_catalogue(path)
state = api.migrate_state(path, require_all=False)
```

See [import-migration.md](import-migration.md) for portability, provenance,
and transaction rules.

## Build the persistent export set

Register functions and globals by their destination IDB names:

```python
result = api.register(
    function_names=["trace_shape", "trace_ray"],
    global_names=["g_p_panorama_ui_engine"],
)
```

Registration stores identity, not an address. Re-registering is idempotent.
Inspect or edit the set with:

```python
api.registered()
api.unregister(function_names=["trace_ray"])
api.clear()
```

A function may carry explicit evidence or a structural locator:

```python
api.register(function_names=[
    {"name": "callback", "sites": [0x108C545]},
    {"name": "virtual_method",
     "vtable": {"type": "CCSPlayerInventory", "slot": 19}},
    {"name": "popup_handler", "anchor_string": "ShowGenericPopupOk"},
])
```

An explicit site says where evidence exists. The producer re-decodes and
verifies it; callers do not provide signature bytes. Vtable and string locators
are verified at registration and again at export.

## Declare derived values

Member offsets take their value from the named IDA field:

```python
api.declare_members([
    "CSceneObject::m_hOwnerEntity",
    {"owner": "CModel", "member": "m_nBoneCount",
     "sites": [{"ea": 0x1234, "op": 1}]},
])
```

Discovery modes are `sites_only` (default), `sites_plus_auto`, and `auto`.
Explicit sites are recommended when pointer-backed objects have no IDA field
xrefs. A selected member site must still prove the declared owner and member:
either IDA associates that operand with the member, or Hex-Rays resolves an
exact member expression at that instruction. A matching displacement alone is
rejected.

Strides and constants assert values and require evidence sites:

```python
api.declare_strides([{
    "owner": "CMeshDrawPrimitive", "name": "kStride", "value": 0x30,
    "sites": [{"ea": 0x5678, "op": 1}],
}])

api.declare_constants([{
    "owner": "SosConstants", "name": "kDisableStartTime", "value": -1,
    "sites": [{"ea": 0x3AE51F, "op": 1}],
}])
```

Use the recipe's signed value. For a signed imm8 `FF`, assert `-1`.

Object extents require width and alignment:

```python
api.declare_extents([{
    "owner": "TraceFilter", "name": "kSize", "value": 0x48,
    "sites": [{"ea": 0x1234, "op": 0,
               "access_width": 1, "alignment": 8}],
}])
```

Compound LEA strides use the closed recipe:

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

Patch declarations name an instruction and its original bytes:

```python
api.declare_patches([{
    "owner": "spotted", "name": "PlayerGate",
    "site": {"ea": 0xEB8B9E, "expected_instruction": "jz",
             "expected_bytes": "0F 84", "patch_size": 6},
}])
```

Manage declarations with `api.declarations()` and
`api.undeclare(names=["Owner::name"])`.

For evidence, arithmetic, refusal stages, and candidate policy, read
[producer-invariants.md](producer-invariants.md).

## Export

Export the persistent registry plus declarations and patches:

```python
result = api.export(
    r"C:\catalogues\client.cfs",
    merge="append",
    build=14183,
    include_members=True,
)
```

`append` refreshes the registered set and carries unrelated compatible records;
`replace` starts a new catalogue. Append refuses a different image or build.

Export an explicit one-shot list without changing storage:

```python
api.export_list(
    path,
    function_names=["trace_shape"],
    global_names=["g_p_panorama_ui_engine"],
    merge="replace",
)
```

Refresh only selected existing records:

```python
api.export_selected(
    path,
    declaration_names=["TraceShape::m_nKind", "spotted::PlayerGate"],
    item_ids=["fn:trace_shape"],
    build=14183,
)
```

`export_selected` requires an existing compatible catalogue, resolves the
complete selection before generation, and replaces the file only when every
selected item regenerates and the result parses cleanly. `declaration_names`
accepts derived declarations and patch declarations; use an exact item ID when
the same qualified name exists in both groups.

## Promote selected records across builds

`append` and `export_selected` never cross a header build boundary. Use
promotion to make a new target-build catalogue from explicitly selected,
revalidated source records:

```python
api.promote_catalogue(
    source_path=r"C:\catalogues\client-14182.cfs",
    destination_path=r"C:\catalogues\client-14184.cfs",
    declaration_names=["spotted::PlantedC4Gate"],
    build=14184,
)
```

Promotion does not copy records blindly. Every retained candidate must match
uniquely in the target; failed candidates are dropped, ranks are compacted,
derived values are recomputed, and patches must still pass opcode, mnemonic,
and span checks. The output has a fresh target header and rebased diagnostic
RVAs. It intentionally does not carry type payloads or unrelated records:
those require their own target validation before a later full-catalogue mode.
Pass `preserve_validated=True` to revalidate every source item and retain only
the target-valid subset; the result is partial when any item cannot promote.

## Refresh a rolling CFS7 catalogue

CFS6 remains the strict, single-source format. Use CFS7 when one catalogue
must retain independently validated evidence from more than one build:

```python
api.refresh_catalogue(
    source_path=r"C:\catalogues\client-14182.cfs",
    destination_path=r"C:\catalogues\client-14185.cfs",
    build=14185,
    declaration_names=["spotted::DroppedC4Gate"],
)
```

Refresh revalidates every source candidate against the active target. It keeps
only uniquely resolving, semantically valid candidates, records each retained
candidate's immutable origin image/build, and writes a CFS7 header identifying
the complete catalogue's validation target. Older candidates are not removed
because of their age; they are removed only after target validation fails.

`item_ids` and `declaration_names` add exact active-IDB evidence. Those records
are freshly exported from the target and therefore carry target provenance.
The selection is all-or-nothing. Type payloads are included only for those
fresh target records; refresh never carries type payloads from an older build.

## Public surface

| Branch | Calls |
|---|---|
| Registry | `register`, `unregister`, `clear`, `registered` |
| Declarations | `declare_members`, `declare_strides`, `declare_constants`, `declare_extents`, `declare_patches`, `undeclare`, `declarations` |
| Export | `export`, `export_list`, `export_selected` |
| Import | `import_catalogue`, `migrate_state`, `import_and_migrate`, `promote_catalogue`, `refresh_catalogue` |

Adding a public call requires one implementation branch, a facade re-export,
the shared result envelope, an API layout test update, and documentation here.
Resolution semantics belong in the CFS format and engines, not in facade-only
arguments.
