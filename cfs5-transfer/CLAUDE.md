# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Hard constraints (read first)

- **Target is IDA Pro 9.0 / IDAPython 9.0 / Python 3.12 ONLY.** Do not assume API shapes from IDA 7.x/8.x or from generic "IDAPython" memory — those APIs changed. Every `ida_*` call, constant, and signature you add or edit must be **verified against IDA 9.0** before you rely on it. If you cannot verify a symbol exists in 9.0, do not use it.
- Use the `ida-pro-mcp:idapython` skill to check API surface, and treat the modules already imported in `cfs5/` as the known-good ground truth for this codebase.
- These are IDA **plugins**, not standalone scripts. There is no build/test harness inside IDA. "Running" means loading the two entry `.py` files (with the `cfs5/` package beside them) into IDA's `plugins/` directory and exercising the UI actions against a real IDB. You cannot fully validate behavior outside IDA.
- You *can* cheaply catch syntax + cross-module wiring errors outside IDA: `python -m py_compile` every file, and import-test the package with the IDA modules stubbed (any attribute → `object`). The format layer (`cfs5/cfsfile.py` + the codec in `cfs5/common.py`) is pure Python and round-trip-testable without IDA.

## What this repo is

Plugins that transfer names, prototypes and types between IDBs of the same/related binaries using short unique byte signatures instead of raw addresses. The interchange format is a CSV-based `.cfs` file (current version: **CFS5**). It covers **functions and user-named global variables**.

## Layout

```
cfs5-transfer/
  cvutils-cfs-exporter.py   # exporter plugin entry: discovery + orchestration + UI
  cvutils-cfs-importer.py   # importer plugin entry: resolve/apply + UI
  cfs5/                     # shared importable core (no duplication across plugins)
    common.py   # constants, msg/ea_str, search ranges, byte search, zlib+b64 codec
    disasm.py   # insn decode, operand-aware tokenizer, PC-relative inference, xref iters
    sigs.py     # Candidate + ENTRY/BODY/REL finders + selection policy (fn + global)
    typeio.py   # binary tinfo transport: materialize/serialize/deserialize, register, merge
    cfsfile.py  # THE format: row tags, record classes, load_records, row builders
```

Both entry files begin with a shim that (1) adds their own dir to `sys.path` so `import cfs5` resolves regardless of IDA's path, and (2) purges `cfs5*` from `sys.modules` so an edit to the package is picked up on the next plugin (re)load. Keep that shim intact and at the very top.

Internal plugin/class identities are `CFS5ExporterPlugin` / `CFS5ImporterPlugin`. Don't rename the registered actions/hotkeys casually — they're the plugin identities.

## The `.cfs` format (the contract) — single source: `cfs5/cfsfile.py`

Row layouts live in exactly one place: `cfsfile.py` defines the tag constants, the `signature_row`/`meta_row`/`type_row` **builders** (writer side) and `load_records` (reader side). Change a column layout **there**, and both plugins follow. Never hand-format a row in an entry file.

| Tag | Cols | Meaning |
|-----|------|---------|
| `CFS2` | 12 | function signature candidate (frozen layout) |
| `CFS2G` | 12 | global signature candidate; REL target is **data** (`is_data=True`) |
| `CFS4FUNC` | 8 | function prototype as serialized `tinfo_t` |
| `CFS5GLOB` | 8 | global type as serialized `tinfo_t` |
| `CFS4TYPE` | 6 | one referenced named local type, full body |

Legacy accepted on read: `CFS3TYPE`/`CFS3FUNC` (text), bare 3-col Cra0 rows (→ ENTRY). Binary payloads are `zlib`+`base64`; dependency lists are compressed JSON. Function and global signature/meta records live in **separate group namespaces** (`func_records`/`func_meta` vs `glob_records`/`glob_meta` on `LoadedCfs`), joined by `(group_id, name)` — so function and global group ids may both start at 0 without colliding.

## Signature model — `cfs5/sigs.py`

`Candidate.score` ranks by length (dominant), then wildcards, then a mode penalty (ENTRY<REL<BODY). Modes:

- `ENTRY` / `BODY` — function-only; patterns never extend past the function body.
- `REL` — a pattern at a code site that references the target, plus a signed PC-relative field. **Target-agnostic**: `find_best_rel_candidate(target, ranges, xref_collector, skip_self)` anchors a function (code xrefs, `skip_self=True`) or a global (data xrefs, `skip_self=False`) with the *same* machinery. `choose_function_candidates` blends ENTRY/BODY/REL; `choose_global_candidates` is REL-only.

REL formula (identical in exporter and importer — `resolve_candidate`):
```
disp   = signed_le(match + rel_offset, rel_size)   # rel_size ∈ {1,2,4,8}
target = match + base_offset + disp + target_delta  # base_offset = end of xref insn
```
PC-relative inference (`disasm.infer_pc_relative_field`) anchors on `insn.ea + insn.size` — the end of the **whole** instruction, trailing immediates included — and *searches* operand fields/widths for the one that resolves to IDA's known target. So `mov [rip+disp32], imm32` and every rel8/16/32 form work without assuming rel32-at-offset-3. The importer re-validates every REL match (re-decode, unchanged length, field in-bounds, target mapped) before use; function targets must be mapped code, global targets mapped data. Don't weaken these checks.

## Type transport — `cfs5/typeio.py`

Types move as **binary `tinfo_t`**, never C source.
- Export: `build_local_type_index` → `export_type_payload(tif, …)` walks referenced ordinals, computes the transitive closure, `materialize_full_definition` (typeref → concrete detached UDT/enum via `get_*_details` + `create_*`), rewrites ordinals→names (`replace_ordinal_typerefs`), `serialize(SUDT_FAST)`. `export_type_payload` is shared by functions (`get_function_export_tinfo`) and globals (`get_global_export_tinfo`); the shared `exported_types` dict dedups across both. Invariant: a real struct exports its **full body**, not `struct Foo;`.
- Import: `register_missing_types` is non-destructive/multi-pass — existing full type immutable, existing forward upgradable, missing type gets a forward placeholder then its body. Function prototype merge (`merge_function_tinfos`/`type_specificity`) is field-by-field; global types are applied unless the destination already has a user/more-specific type.

## Conventions

- Nearly every IDA call is wrapped in `try/except` with an `msg(...)` diagnostic — IDA's Python bindings raise inconsistently across type shapes. Match this; one unhandled exception aborts a whole export/import loop.
- Long loops use `show_wait_box`/`replace_wait_box`/`user_cancelled`; keep new long work cancellable.
- `msg` prints to the Output window prefixed `[CFS5]`; the final summary also goes to an `info` popup. With no in-IDA test harness, these diagnostics are the primary debugging channel.
