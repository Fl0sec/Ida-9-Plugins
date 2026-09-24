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

Check `ok`. When false, inspect both `error` and every `unresolved` entry.
Partial success is deliberately not success.

Service calls never prompt, display popups, or return IDA objects. UI belongs
in the two plugin entry files.

## Transfer a catalogue to a new build

```python
result = api.import_and_migrate(r"C:\catalogues\client.cfs")
```

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
xrefs.

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
    declaration_names=["TraceShape::m_nKind"],
    item_ids=["fn:trace_shape"],
    build=14183,
)
```

`export_selected` requires an existing compatible catalogue, resolves the
complete selection before generation, and replaces the file only when every
selected item regenerates and the result parses cleanly.

## Public surface

| Branch | Calls |
|---|---|
| Registry | `register`, `unregister`, `clear`, `registered` |
| Declarations | `declare_members`, `declare_strides`, `declare_constants`, `declare_extents`, `declare_patches`, `undeclare`, `declarations` |
| Export | `export`, `export_list`, `export_selected` |
| Import | `import_catalogue`, `migrate_state`, `import_and_migrate` |

Adding a public call requires one implementation branch, a facade re-export,
the shared result envelope, an API layout test update, and documentation here.
Resolution semantics belong in the CFS format and engines, not in facade-only
arguments.
