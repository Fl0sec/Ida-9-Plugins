# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Hard constraints (read first)

- **Target is IDA Pro 9.0 / IDAPython 9.0 / Python 3.12 ONLY.** Do not assume API shapes from IDA 7.x/8.x or from generic "IDAPython" memory — those APIs changed. Every `ida_*` call, constant, and signature you add or edit must be **verified against IDA 9.0** before you rely on it. If you cannot verify a symbol exists in 9.0, do not use it.
- Use the `ida-pro-mcp:idapython` skill to check API surface, and treat the modules already imported in `cfs5/` as the known-good ground truth for this codebase.
- These are IDA **plugins**, not standalone scripts. There is no build/test harness inside IDA. "Running" means loading the two entry `.py` files (with the `cfs5/` package beside them) into IDA's `plugins/` directory and exercising the UI actions against a real IDB. You cannot fully validate behavior outside IDA.
- You *can* cheaply catch syntax + cross-module wiring errors outside IDA: `python tools/check.py cfs5-transfer` (compile + IDA-9.0 symbol existence + stubbed import).
- **Five modules are deliberately free of any `ida_*` import and are unit tested**: `cfs5/cfs6.py` (the format), `cfs5/policy.py` (scoring + selection), `cfs5/declare.py` (the declaration model), `cfs5/peinfo.py` (PE/RVA/.pdata) and `tools/cfs6_resolve.py` (the reference resolver). Keep them that way — `cd cfs5-transfer && python -m unittest discover -s tests -t tests` is the only real test harness this repo has. Anything needing IDA goes in the adapter layer (`sigs.py`, `image.py`, `members.py`, `store.py`, the two entry files).

## What this repo is

Plugins that transfer names, prototypes and types between IDBs of the same/related binaries using short unique byte signatures instead of raw addresses. The interchange format is a **UTF-8 JSONL `.cfs` file, version CFS6**, designed to be consumed **without IDA** (a companion cs2 dumper reads it directly). It covers **functions and user-named global variables**.

## Layout

```
cfs5-transfer/
  cvutils-cfs-exporter.py   # exporter plugin entry: discovery + orchestration + UI
  cvutils-cfs-importer.py   # importer plugin entry: resolve/apply + UI
  cfs5/                     # shared importable core (no duplication across plugins)
    cfs6.py     # THE format: records, reader, writer, codec        [no ida_*]
    policy.py   # Candidate, score, dedup, diversity selection       [no ida_*]
    peinfo.py   # PE identity, RVA mapping, .pdata runtime functions [no ida_*]
    image.py    # image identity + build detection + .pdata ownership (IDB-first)
    declare.py  # user-declaration model for derived values              [no ida_*]
    members.py  # struct-member lookup/creation/enumeration + stroff xrefs
    memberscan.py # displacement index + Hex-Rays ctree member-site discovery
    store.py    # declaration persistence in the IDB (one netnode each)
    common.py   # constants, msg/ea_str, search ranges, byte search
    disasm.py   # insn decode, operand-aware tokenizer, PC-relative + displacement
                # field inference, xref iters
    sigs.py     # IDA-touching ENTRY/BODY/REL finders (rules live in policy.py)
    typeio.py   # binary tinfo transport: materialize/serialize/deserialize, register, merge
  docs/cfs6-format.md     # AUTHORITATIVE format spec -- update it with any change
  tests/                  # stdlib unittest over the ida-free modules
../tools/cfs6_resolve.py  # reference CFS6 resolver, no IDA         [no ida_*]
```

Both entry files begin with a shim that (1) adds their own dir to `sys.path` so `import cfs5` resolves regardless of IDA's path, and (2) purges `cfs5*` from `sys.modules` so an edit to the package is picked up on the next plugin (re)load. Keep that shim intact and at the very top.

Internal plugin/class identities are `CFS5ExporterPlugin` / `CFS5ImporterPlugin`. Don't rename the registered actions/hotkeys casually — they're the plugin identities.

## The `.cfs` format (the contract) — single source: `cfs5/cfs6.py`

**[docs/cfs6-format.md](docs/cfs6-format.md) is the authoritative specification.** Change the format there *and* in `cfs6.py`, never by hand-formatting a record in an entry file.

UTF-8 JSONL, no BOM, one JSON object per line. Exactly one `header` record, on the first non-empty line; a file that does not start with one is rejected outright ("not a CFS6 file; re-export"). Record kinds: `header`, `function`, `global`, `derived_value`, `candidate`, plus the optional IDA-specific `function_type` / `global_type` / `local_type` (independently skippable — resolution never decodes them). Unknown record kinds are reported and skipped; unknown fields are ignored; `version != 6` is fatal. Items carry an `id` (`fn:Name` / `global:Name` / `member:Owner::Name`) and candidates reference it via `item`, so all item kinds share one namespace without colliding.

**Two families of item.** `function`/`global` answer *where is this* — a candidate resolves to an address. `derived_value` answers *what integer does this code encode* — a candidate resolves to a number. Same pattern search, same uniqueness rule, same agreement/conflict semantics; only the final arithmetic differs. A `VALUE` candidate may only belong to a `derived_value` and vice versa; the reader enforces it.

Invariants you must not break:

- All `resolve.*` offsets are relative to the **pattern-match start**.
- `resolve.base_offset` is the end of the **whole** anchor instruction and is **stored, never inferred** — inferring it breaks `mov [rip+disp32], imm32`.
- `source.*` values are historical RVAs, **diagnostics only**.
- `rank` is authoritative; `score` is diagnostic and **lower is better**.
- `target_delta` is optional with a documented default of `0`.
- BODY carries `source.body_offset`; ownership requires `match - body_offset` to be a function start *exactly* (a `.pdata` begin for a non-IDA consumer). `function_size` is diagnostic and must never reject a hit.
- BODY also carries `resolve.ownership`: `"pdata"` or `"ida-only"`. **IDA's function extents and the PE's RUNTIME_FUNCTION table disagree for chunked/outlined functions** — their IDA start is not the `.pdata` begin the body sits in — so such candidates are labelled `ida-only` and a non-IDA consumer must skip them. The exporter classifies this via `image.BodyOwnership`; never emit a bare `"pdata"` without checking.
- A pattern matching zero or 2+ times never resolves.

## Derived values (`derived_value` + `VALUE`, schema revision 1)

`member_offset` is the only semantic produced today; `element_stride`, `object_extent` and `constant` are reserved. `semantic`, extraction `op` (`CONST`/`DISP`/`IMM`/`SCALE`/`DISP_PLUS_WIDTH`) and `VALUE` `origin` are **closed sets** — a consumer rejects an unknown value rather than interpreting it. No expression strings, ever.

Non-negotiable rules for this family:

- **A `member_offset` requires a real IDA type and member.** No member, no declaration — the semantic is an assertion, and without a backing field it is unverified and produces no `expected_value`. When the container is typed but the field is missing, `_resolve_or_create_member` offers to create it (and then `op_stroff`s the operand so the site is indexed next time). If a container genuinely cannot be typed, the answer is a semantic that claims less, never a weakened `member_offset`.
- **Candidates come only from `stroff_xref`, `selected_operand` or `hexrays_memptr`.** Every one names a *type-directed* producer of the instruction↔member association. Never accept a site because it encodes the same number: numeric equality does not prove two accesses refer to the same member, and a false candidate is worse than a missing one because agreement would read it as *confirmation*. The reader rejects any other origin, which is what makes the rule checkable rather than a promise.
- **`hexrays_memptr` compensates for a real IDA 9.0 defect, and is not a loophole.** IDA 9.0 does not record member xrefs for objects reached through a typed pointer (parameters, loaded global pointers), so `stroff_xref` alone leaves most members with zero candidates — see the measurements in `cfs5/memberscan.py`. There, a displacement scan is only a **search-space prefilter**; the discriminator is a `cot_memptr`/`cot_memref` node matched **per instruction** against both the member offset and the owner type name. Do not weaken that to a per-function check (e.g. "the member name appears in the pseudocode") — that accepts unrelated accesses in the same function and same-named fields on other structs.
- **The displacement index is built once per session** (`memberscan.build_displacement_index`), not per member. Per-member rebuilding makes declaring a whole structure unusable.
- **Extraction metadata is decoder-derived, never user-entered.** `disasm.infer_displacement_field` walks the operands IDA reported, takes each one's own `op.addr`, and only accepts a field when the byte span the decoder assigned reproduces the same value. Ambiguity → no candidate. This is the member analogue of `infer_pc_relative_field`; keep them symmetrical.
- **The extracted field is wildcarded in the pattern.** The value is expected to change between builds — pinning it would break the pattern exactly when the answer became interesting.
- **`source.expected_value` is a hard gate at export, a drift signal at resolution.** `_write_member` drops any candidate that does not reproduce the IDA-known offset. A consumer that extracts a different value on a newer image has found drift, not a failure, and must resolve to the new value. It lives on the item and is never duplicated per candidate.
- **VALUE patterns have their own exact-byte floor** (`policy.value_min_exact`, 8). `candidate_min_exact`'s short tier (4 exact under 10 bytes) is calibrated for REL, where a 4-byte rel32 is wildcarded. VALUE wildcards a *single* byte, so that tier let a lone 5-byte instruction through with 4 exact bytes — genuinely unique in its own build, but very likely to collide in the next one, and a pattern with 2+ matches resolves to nothing. Don't merge the two floors back together.
- **A `CONST` candidate is kept only when it is the sole candidate** (`policy.select_value_candidates`). CONST extracts nothing, so several would agree unconditionally — fake confirmation.
- `declare.Declaration` stores identity only (semantic, owner, canonical name, IDA field name, the selected site). **Never store the offset**: re-deriving it is what makes a better-typed IDB produce a better export, and what makes a moved field visible instead of silently carried forward. `name` and `member` are separate so a project naming convention does not force a rename in the database.
- Declarations persist in the IDB via `store.py` (one netnode each, blob at index 0, plus an index node), every write read-back-verified.

**Appending is a rewrite, never a text append** (`cfs6.merge_conflicts` +
`cfs6.carry_over`, prompted by `_ask_merge_mode` in the exporter). The header is
singular and first, and a re-exported item would collide with its own `id`, so
the exporter writes the new records into `<path>.cfs.tmp`, carries over the old
records they do not supersede *verbatim* (by line, so a record this build does
not fully model survives), then `os.replace`s into place. Three rules hold it
up: a merge is refused unless both headers describe the same image **and**
build — one header cannot honestly describe two images; a new item id or
local-type name replaces the old record and everything attached to it (its
candidates, its type payload), which is what makes "append" also mean "refresh";
and a cancel or any error writes nothing, leaving the existing file untouched.
Do not "optimize" the carry-over into re-serializing parsed records — a
round-trip through this build's model silently drops fields it does not know.

**No backward compatibility.** The CSV era (`CFS2`/`CFS2G`/`CFS3*`/`CFS4*`/`CFS5GLOB`, legacy Cra0 rows) is deleted, not deprecated. Do not reintroduce it.

## Signature model — `cfs5/sigs.py` (finders) + `cfs5/policy.py` (rules)

`policy.Candidate.score` ranks by length (dominant), then wildcards, then a mode penalty (ENTRY<REL<BODY). **Lower is better.** Modes:

- `ENTRY` / `BODY` — function-only; patterns never extend past the function body.
- `REL` — a pattern at a code site that references the target, plus a signed PC-relative field. **Target-agnostic**: `collect_rel_candidates(target, ranges, xref_collector, is_data, …)` anchors a function (code xrefs) or a global (data xrefs) with the *same* machinery.

**Every axis is searched unconditionally.** A good ENTRY does not suppress the REL search — that gate was the bug that left `CCSGOInput_CreateMove` with a single candidate. `policy.select_function_candidates` then picks best-ENTRY + best-external-REL + best-non-overlapping-BODY (cap 4); `select_global_candidates` takes up to 3 distinct REL anchor sites. Overlapping or duplicate-pattern candidates are dropped — they are not independent evidence. **Never relax uniqueness or `MIN_EXACT_BYTES` to produce more candidates.** A self-referencing (`self_call`) anchor is kept only when no external caller yields one.

REL formula (identical in exporter, importer and `tools/cfs6_resolve.py`):
```
disp   = signed_le(match + displacement_offset, displacement_size)  # width ∈ {1,2,4,8}
target = match + base_offset + disp + target_delta  # base_offset = end of anchor insn
```
PC-relative inference (`disasm.infer_pc_relative_field`) anchors on `insn.ea + insn.size` — the end of the **whole** instruction, trailing immediates included — and *searches* operand fields/widths for the one that resolves to IDA's known target. So `mov [rip+disp32], imm32` and every rel8/16/32 form work without assuming rel32-at-offset-3. The importer re-validates every REL match (re-decode, unchanged length, field in-bounds, target mapped) before use; function targets must be mapped code, global targets mapped data. Don't weaken these checks.

## Type transport — `cfs5/typeio.py`

Types move as **binary `tinfo_t`**, never C source.
- Export: `build_local_type_index` → `export_type_payload(tif, …)` walks referenced ordinals, computes the transitive closure, `materialize_full_definition` (typeref → concrete detached UDT/enum via `get_*_details` + `create_*`), rewrites ordinals→names (`replace_ordinal_typerefs`), `serialize(SUDT_FAST)`. `export_type_payload` is shared by functions (`get_function_export_tinfo`) and globals (`get_global_export_tinfo`); the shared `exported_types` dict dedups across both. Invariant: a real struct exports its **full body**, not `struct Foo;`.
- Import: `register_missing_types` is non-destructive/multi-pass — existing full type immutable, existing forward upgradable, missing type gets a forward placeholder then its body. Function prototype merge (`merge_function_tinfos`/`type_specificity`) is field-by-field; global types are applied unless the destination already has a user/more-specific type.

## Global discovery is gated on location, not just name shape

`get_user_global_eas()` cannot rely on `has_user_name` + a plain-identifier
test: IDA sets that flag on **import thunks** and on its own **`jpt_*` jump
tables**, and `RegCloseKey` / `jpt_234F55` are both valid C identifiers. Measured
on cs2 `client.dll`, the name-shape filter alone kept 560 addresses of which 438
(78%) were `.idata` IAT slots and 69 were jump tables — 8% signal. So the
predicate also requires a data segment (`_GLOBAL_SEGMENTS`), rejects import
thunks unless the name is `g_*` (tier0 exports its globals), and rejects
analyzer/loader data names (`_AUTO_DATA_RE`). That yields 47, all genuine. Do
not loosen these back to a pure name test. The *selected*-globals action
deliberately bypasses the whole heuristic — the user picked those explicitly.

## Conventions

- Nearly every IDA call is wrapped in `try/except` with an `msg(...)` diagnostic — IDA's Python bindings raise inconsistently across type shapes. Match this; one unhandled exception aborts a whole export/import loop.
- Long loops use `show_wait_box`/`replace_wait_box`/`user_cancelled`; keep new long work cancellable.
- **`Choose` callbacks return a flat `[change_flag, line, line, ...]`, not `(flag, selection)`.** The docstrings say "a tuple (changed, selection)" but the marshaller wants ints all the way down — returning the selection nested raises `ValueError: Sequence item #1 cannot be converted`. This is invisible in a single-select chooser (where `sel` is an int and happens to convert) and fatal the moment you add `CH_MULTI`, where `sel` is a `sizevec_t`. Same trap in `adjust_last_item(n)`: it compares `n >= cnt`, so pass one line number, never the selection. `MemberChooser._rows` / `._result` are the normalizers — use them.
- `msg` prints to the Output window prefixed `[CFS6]`; the final summary also goes to an `info` popup. With no in-IDA test harness, these diagnostics are the primary debugging channel.
- **Multi-candidate semantics (importer).** Every candidate of an item is evaluated, not just the first that resolves. Agreement between independent candidates is confirmation and is reported (`confirmed-by=N`); candidates resolving to *different* addresses is a **conflict** — apply nothing and say so loudly. Two items resolving to one address is also a conflict. Never let rank 0 silently win a disagreement.
- Plugin/class identities (`CFS5ExporterPlugin`, `CFS5ImporterPlugin`, the `cfs5:*` action ids, the `cfs5` package name) are deliberately **unchanged** across the CFS6 format switch — they are the plugin's registered surface, not the format version.
- **Read the image from the IDB, not from disk.** `image.open_image_view()` builds a `PeImage` over IDA's mapped `HEADER` segment via an RVA reader, so header identity and `.pdata` come from the database and work regardless of whether the original file still exists. The on-disk path is a fallback only. `peinfo.PeImage` supports both through one parser (`from_path` vs `from_rva_reader`) — don't fork that logic.
