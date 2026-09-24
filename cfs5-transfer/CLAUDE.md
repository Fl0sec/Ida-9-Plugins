# CFS6 development routing

Read this file before changing `cfs5-transfer`. Follow the branch pointer for
the code you will touch; completion requires satisfying that branch's checks.

## Target and hard gates

- Target IDA Professional 9.4, IDAPython 9.4, Python 3.12 only. IDA 9.0 is
  historical context, not a validation target.
- Verify every new or changed `ida_*` symbol against
  `C:\Program Files\IDA Professional 9.4\python\ida_*.py`.
- Use modern `ida_*` modules. `idautils` is allowed for iteration; `idc` is not.
- Keep IDB work out of import time. Entry files are UI glue; reusable behavior
  belongs in `cfs5/`.
- Preserve user work: names, complete destination types, catalogues, and
  producer state are non-destructive unless the caller explicitly selects a
  replacing operation.

## Branch router

| Change | Read before editing |
|---|---|
| Public calls, result fields, examples | [docs/agent-api.md](docs/agent-api.md) |
| Candidate generation, declarations, append/selected export, type payloads | [docs/producer-invariants.md](docs/producer-invariants.md) |
| Catalogue application or producer-state migration | [docs/import-migration.md](docs/import-migration.md) |
| Record vocabulary or resolver arithmetic | [docs/cfs6-format.md](docs/cfs6-format.md) |
| Pattern durability or coverage policy | [docs/signature-durability.md](docs/signature-durability.md) |
| IDA API compatibility | [../docs/ida9-api.md](../docs/ida9-api.md) |

Read every referenced document for each branch you touch. A cross-branch change
must satisfy every applicable branch.

## Architecture

```text
cvutils-cfs-exporter.py   interactive export UI
cvutils-cfs-importer.py   interactive import UI
cfs5/api.py               stable public facade; no implementation
cfs5/api_registry.py      persistent function/global export set
cfs5/api_declarations.py  derived-value and patch declarations
cfs5/api_export.py        full/list/selected export orchestration
cfs5/api_import.py        catalogue/migration facade
cfs5/api_result.py        shared result envelope
cfs5/export.py            producer engine; never prompts
cfs5/importer.py          reusable apply/migrate engine; never prompts
cfs5/cfs6.py              IDA-free format reader/writer
cfs5/policy.py            IDA-free candidate selection
cfs5/declare.py           IDA-free declaration model
cfs5/registry.py          IDA-free registry identity
cfs5/store.py             verified IDB netnode persistence
```

`api.py` is a compatibility surface. Put new behavior in the responsible
module and re-export only intentional public calls from the facade.

## Global invariants

- Evidence beats coincidence. A matching number alone never associates an
  instruction with a member or declaration.
- Source RVAs are diagnostics. Resolve patterns against the destination image.
- Evaluate every independent candidate. Agreement confirms; disagreement is a
  conflict and applies nothing for that item.
- Public service calls take batches, return JSON-serializable dictionaries,
  and never show dialogs. Interactive wrappers own prompts and popups.
- Every public result contains `ok`, `partial`, `error`, and `unresolved`.
  Partial success is never `ok=True`.
- Long IDA loops are cancellable. Catch IDA exceptions per item, diagnose, and
  continue where the operation's transaction policy permits.
- Writes to catalogues and producer state are transactional and verified.

## Verification

From `cfs5-transfer`:

```powershell
python -m unittest discover -s tests -t tests
python ..\tools\check.py .
```

Both commands must pass. `check.py` proves syntax, 9.4 symbol existence, and
stubbed imports; it does not prove behavior in a live IDB. For importer,
migration, decoder, or storage changes, use disposable IDB copies and report
the exact live result. Never test mutations against the only copy of an IDB.

## Repository boundaries

- Edit on `main`; commit only when authorized.
- `ida-pro-mcp/` and `reference/` are read-only upstream/reference trees.
- Never commit IDBs or IDA sidecar files.
- Plugin identities (`CFS5ExporterPlugin`, `CFS5ImporterPlugin`, `cfs5:*`, and
  package name `cfs5`) are stable public surface.
