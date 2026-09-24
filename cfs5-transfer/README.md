# cfs5-transfer

CFS6 signature/type transfer plugins for IDA Professional 9.4 (IDAPython 9.4 / Python 3.12).

Transfer function names, **global-variable names**, prototypes, global types and
local types between two IDBs of the same or related binaries, using short unique
byte signatures instead of raw addresses.

## Layout

```
cfs5-transfer/
  cvutils-cfs-exporter.py   # exporter plugin entry (PLUGIN_ENTRY)
  cvutils-cfs-importer.py   # importer plugin entry (PLUGIN_ENTRY)
  cfs5/                     # shared, importable core package
    cfs6.py     # THE format: records, reader, writer (no ida_* imports)
    policy.py   # Candidate, scoring, dedup, diversity selection (no ida_*)
    peinfo.py   # PE identity, RVA mapping, .pdata (no ida_*)
    image.py    # source-image identity via ida_nalt
    declare.py  # the user-declaration model (no ida_*)
    members.py  # structure-member lookup, creation, reference discovery
    store.py    # declaration persistence in the IDB (netnodes)
    api.py      # stable public facade
    api_registry.py api_declarations.py api_export.py api_import.py
    importer.py # reusable catalogue apply + producer-state migration
    common.py   disasm.py   sigs.py   typeio.py
  docs/agent-api.md          # public calls and workflows
  docs/producer-invariants.md # export/declaration implementation rules
  docs/import-migration.md   # import and state portability rules
  docs/cfs6-format.md        # authoritative format specification
  tests/                # python -m unittest discover -s tests -t tests
```

Both entry files add their own directory to `sys.path` and force-reload the
`cfs5` package on load, so editing anything under `cfs5/` takes effect the next
time IDA loads the plugin.

## Install

Copy **all three** items — the two `.py` entry files *and* the `cfs5/` folder,
kept side by side — into your IDA `plugins/` directory (or point IDA's plugin
loader at them). The package must remain a sibling of the entry files.

## Plugins

### `cvutils-cfs-exporter.py` — CFS6 Exporter

Exports functions **and** user-named globals to a `.cfs` file: signatures +
prototypes/types + dependent local types.

**Usage** — functions and globals are controlled independently.

*Functions* window (View → Open subviews → Functions) → right-click → **CFS6/**:
- *Export selected functions* (`Ctrl+Shift+E`) — only the rows you selected.
- *Export ALL user-named functions* — every user function, **no globals**.
- *Export ALL user functions + globals* — the full transfer set.

*Names* window (Shift+F4) → right-click → **CFS6/**:
- *Export selected globals* — only the data globals you selected (pick them in
  the Names window). Explicitly selected items skip the human-name heuristic.
- *Export ALL user-named globals* — every user global, **no functions**.

*Disassembly* view → right-click → **CFS6/**:
- *Declare member from this operand* (`Ctrl+Shift+M`) — see
  [Declared members](#declared-members-derived-values) below.
- *Manage CFS6 declarations* — list, jump to, or delete stored declarations.
- *Export declared members* — write every declaration as a `derived_value`.

### Appending to an existing file

Every export action asks for a destination. **Pick a file that already exists
and the plugin offers Append / Overwrite / Cancel**, so functions, globals and
declared members can accumulate in one `.cfs` instead of one file per action.

- *Append* adds this export and **refreshes** anything it re-exports: a
  function, global, member or local type written now replaces its older record
  (and that record's candidates and type payload) rather than duplicating it.
  Re-export a function you just improved and the file simply gets the better
  version.
- Appending is refused when the file describes a **different image or build** —
  a `.cfs` states one image identity in its single header, and mixing two makes
  the provenance of half its records wrong. The plugin says which field differs
  and offers Overwrite / Cancel.
- A file that exists but does not parse as CFS6 is never silently clobbered:
  you get the parse error and an explicit overwrite question.
- The export is built in a `.cfs.tmp` beside the destination and renamed over it
  only on success. **Cancelling (or any error) writes nothing** and leaves the
  existing file exactly as it was.
- Note that the file dialog's own "replace?" prompt fires first and deletes
  nothing; the Append/Overwrite question is the one that decides.

"User global" is gated on location as well as name shape, because IDA sets the
user-name flag on import thunks and on its own jump tables, and both are shaped
like plain C identifiers. A global must sit in a data segment, must not be an
import thunk (unless it is `g_*`, which rescues tier0's exported globals), and
must not carry an analyzer/loader name (`jpt_`, `def_`, `funcs_`,
`TlsDirectory`, `TlsIndex`, `ExceptionDir`). On cs2 `client.dll` this is the
difference between 560 candidates (78% of them IAT slots) and 47 real globals.

Each action asks for an output `.cfs` path. So you can export functions only,
globals only, a hand-picked subset of either, or everything.

**Features**
- Function signatures in three modes, each searched **independently**:
  - `ENTRY` — at function start.
  - `BODY` — at an interior offset, carrying `body_offset` so a consumer can map
    the hit back to the owning function (IDA: containing func; non-IDA: `.pdata`).
  - `REL` — at a caller/xref instruction, resolving the target via its signed
    PC-relative displacement.
- **Structural diversity, not candidate count.** Best ENTRY + best external REL +
  best non-overlapping BODY, up to 4. A strong prologue no longer suppresses the
  caller-side anchor — the two fail for unrelated reasons, which is the whole
  point. Overlapping or duplicate patterns are dropped rather than exported as
  false redundancy, and weak candidates are never manufactured to hit a count.
- Global signatures: `REL`-only, up to 3 anchors from distinct call sites, so
  globals get cross-validation too. Globals with no usable code reference are
  skipped (no reliable anchor).
- A provenance header: image name/arch/timestamp/size/SHA-256, and a build number
  detected from the input path and confirmed in a prompt (unknown stays `null`).
  The PE headers are read from **IDA's mapped `HEADER` segment**, so this works
  whether or not the original input file is still on disk.
- `BODY` candidates are labelled `pdata` or `ida-only` against the real `.pdata`
  table: a chunked/outlined function's IDA start is not a `RUNTIME_FUNCTION`
  begin, so a non-IDA consumer must skip those rather than mis-resolve them.
  IDA-to-IDA import still uses them.
- Exports each function prototype / global type as a portable binary `tinfo_t`,
  tagged `USER` / `EXPLICIT` / `GUESSED`.
- Transitively exports dependent named local types (structs/unions/enums/
  typedefs), deduplicated across functions and globals, with full member bodies.

**Which names are "user" names?** `has_user_name` (IDA's `FF_NAME`) is not
enough: PDB imports, ClassInformer RTTI/vftables (`??_7…@@6B@`), FLIRT library
matches and even empty-stub `nullsub_N` all set it. So the *auto-discovery*
passes additionally require the name to:

- be a **plain C identifier** (rejects MSVC `??_7…@@` / `::`-demangled shapes),
- pass an **exclusion regex** that drops `sub_` / `j_` / `_` prefixes and any
  `nullsub` / `std::` / `unknown_libname` / `Concurrency` substring, and
- **not demangle** (backstop for identifier-shaped Itanium `_Z…` names).

Functions flagged `FUNC_LIB` or `FUNC_THUNK` are also skipped. A global is
auto-discovered when it is a data item (not code/function/tail) that passes this
filter and is either user-named or starts with `g_`. This keeps hand-renamed
items and drops the thousands of tool-emitted symbols. **Manual selections in
the Names window bypass this filter** — if you pick it, it exports.

### Declared members (derived values)

Functions and globals answer *where is this*. A **declared member** answers
*what integer does this code encode* — the byte offset of a structure field,
recovered from the instructions that access it. A consumer (a dumper with no
IDB) resolves it the same way it resolves anything else: find the unique
pattern, extract, and require independent candidates to agree.

**Declaring them.** *CFS6 → Declare members of a structure…* — from the Local
Types window (the selected type is used) or from anywhere else (you pick one).
A list of that type's members opens:

| key | does |
|---|---|
| `Enter` | declare the selected rows |
| `Del` | undeclare them |
| `Ctrl+E` | preview candidates for the selected rows |

Multi-select works, so "all of them" is just select-all. Nothing else is asked —
the exported name is the IDA field name.

Declaring is instant. **Previewing is the expensive part** (it builds the
displacement index on first use, then decompiles), which is why it is a separate
key over the rows you chose rather than something every declaration pays for.

A member with no candidates is stored, not lost. Type more of the binary and
re-export.

You can still declare a single member from a `[reg+offset]` operand with
`Ctrl+Shift+M`; that path additionally marks the operand as a struct offset so
IDA indexes it from then on.

**A real IDA type and member is required.** `member_offset` is an assertion
that a named field of a named type lives at an offset; without a member behind
it that assertion is unverified, there is no trustworthy offset to export, and
no references can ever be found for it. So this is a hard gate, not a warning.
If a container genuinely cannot be typed, the honest declaration is a different
semantic that claims less — not a weakened `member_offset`.

**Declarations live in the IDB**, not only in an exported file. Candidate
quality improves as you type more of the binary, so re-exporting later picks up
better evidence without re-declaring anything.

**Where candidates come from** — exactly three places, and nowhere else:

- `stroff_xref` — instructions IDA associates with *that exact member*.
- `selected_operand` — the operand you explicitly picked.
- `hexrays_memptr` — instructions the decompiler resolves to that member.

The third exists because **IDA 9.0's member xref index is incomplete**. It
records member xrefs for objects with concrete storage (a stack variable, a
directly addressed global) but usually not for objects reached through a typed
pointer — a function parameter, a loaded global pointer. Hex-Rays still prints
`pFoo->m_x` correctly; that interpretation just never becomes an xref on the
underlying `[reg+disp]` operand. Measured on cs2 `client.dll`:
`CGameTrace::m_flFraction` gains 7 functions the index does not contain, and
`CGameTrace__DidHit` accesses the member through a correctly typed parameter
with no index entry at all.

There is still deliberately **no acceptance on displacement value alone**. A
displacement scan only narrows *where to look*; the decompiler, matched **per
instruction**, is what decides. Two unrelated classes both having a field at
`0x10` is coincidence, and a candidate manufactured that way would be read as
*confirmation* of a value it knows nothing about — worse than no candidate.

Two cases stay out of reach and are reported rather than guessed: a member at
**offset 0** encodes no displacement to scan for, and a **stack-folded** access
(`filter.m_mode` compiled to `mov [rbp-68h], 3`) does not encode the member
offset anywhere at all.

**Extraction metadata is derived, never typed in.** The field offset, width and
operand index come from IDA's decoded operand (`infer_displacement_field`, the
member analogue of the PC-relative inference used for `REL`), and are only
accepted when the byte span the decoder assigned reproduces the same value.
Ambiguity means no candidate. If you ever find yourself typing a hex offset into
a dialog, something has gone wrong.

**`expected_value`.** Every declared member carries the offset IDA held at
export time. At export it is a hard gate — a candidate that does not reproduce
it is dropped rather than ranked. At resolution it is diagnostic: a newer build
moving a field is **drift**, reported and resolved to the new value, not a
failure. Nothing like this is expressible in a hand-written signature table.

Expect uneven coverage at first. A well-typed container yields three
independent candidates; a member you just spotted in one function yields one.
That is honest, and it is reported per item rather than hidden.

### `cvutils-cfs-importer.py` — CFS6 Importer

Imports a `.cfs` file into the current IDB: renames matched functions and
globals, registers missing local types, merges prototypes, applies global
types, then reconstructs portable producer state from destination-build proof.

**Usage**
- File → Load file → **CFS6 / CFS File...** (`Ctrl+Shift+I`).
- Pick a `.cfs` file. **CFS6 only** — older CSV `.cfs` files are rejected with a
  "not a CFS6 file; re-export" message.

**Features**
- Evaluates **every** candidate, not just the first that resolves. Independent
  candidates agreeing is confirmation (reported as `confirmed-by=N`); candidates
  resolving to **different** addresses is a **conflict** — nothing is applied and
  the disagreement is reported. Two items resolving to one address is likewise a
  conflict.
- `REL` targets are re-validated (instruction re-decodes, length unchanged,
  displacement re-read) before use. Function REL targets must be mapped code;
  global REL targets must be mapped data.
- `BODY` matches are validated by ownership: `match - body_offset` must equal the
  owning function's start, mirroring the `.pdata` rule a non-IDA consumer applies.
- Creates a function at a resolved function target if none exists yet.
- Never overwrites a destination function/global that already has a real
  user-given name; never overwrites a fully-defined destination type with a
  same-named incoming one (only upgrades forward declarations).
- Merges function prototypes field-by-field: a specific destination named/UDT/
  enum type wins over a generic incoming scalar; a specific incoming type can
  fill a generic/guessed destination hole. Global types are applied unless the
  destination already carries a user/more-specific type.
- Registers missing local types (multi-pass, dependency-order aware) without
  touching pre-existing definitions.
- Reconstructs the export registry, derived-value declarations, patch sites,
  and structural locators only from records that resolve in the destination
  image. Source RVAs are never copied. The accepted subset is committed as one
  verified transaction; non-portable records remain explicit failures.
- Member-owner types travel with the catalogue. A reconstructed member is
  persisted only when that destination type agrees with the value independently
  decoded from destination code; stale layouts are reported, never self-validated.
- Shows a detailed import summary (functions/globals renamed / created / skipped
  / ambiguous / types registered / prototypes applied, …) in the Output window
  and a popup.

## File format

**UTF-8 JSONL, one self-describing record per line.** Full normative spec:
[docs/cfs6-format.md](docs/cfs6-format.md). Single source of truth in code:
`cfs5/cfs6.py`.

| `record`        | Meaning                                              |
|-----------------|------------------------------------------------------|
| `header`        | format version + source image identity (first line)  |
| `function`      | a function item                                      |
| `global`        | a global-variable item                               |
| `derived_value` | an item whose value is an integer extracted from code |
| `candidate`     | one signature candidate, referencing its item by id  |
| `function_type` | optional IDA `tinfo_t` prototype payload             |
| `global_type`   | optional IDA `tinfo_t` type payload                  |
| `local_type`    | optional IDA `tinfo_t` named local type payload      |

The three `*_type` records are IDA-specific and independently skippable — a
non-IDA consumer ignores them and still resolves every signature.

Key contract points:

- `rank` is authoritative for resolution order. `score` is **diagnostic**, and
  **lower is better**.
- All offsets in `resolve` are relative to the **pattern-match start**; all
  `source.*` RVAs are **diagnostics only** and must never be trusted as current
  addresses.
- `base_offset` (end of the whole anchor instruction) is **stored, not inferred**.
- A pattern that does not match exactly once never resolves.
- `semantic`, extraction `op` and `VALUE` `origin` are **closed sets**: a
  consumer rejects a value it does not know rather than guessing.
- `source.expected_value` is a hard gate at export and a drift signal at
  resolution — never a reason to reject a resolution.

`derived_value` / `VALUE` arrived in **schema revision 1**. The addition is
purely additive: a revision-0 reader skips them as unknown record kinds, which
is why `version` stays `6`.

Filenames carry no meaning: `f.cfs` / `g.cfs` / `all.cfs` are cosmetic and every
file is fully self-describing.

## Compatibility

**CFS6 is a clean break.** Pre-CFS6 CSV files (`CFS2`/`CFS3`/`CFS4`/`CFS5` rows
and legacy Cra0 rows) are no longer read — re-export instead. This removed the
whole legacy parsing path in exchange for a format an external consumer can
implement from the spec alone.

## Testing

```bash
python tools/check.py cfs5-transfer                  # compile + IDA 9.4 API + import
cd cfs5-transfer && python -m unittest discover -s tests -t tests
python tools/cfs6_resolve.py <file.cfs> <image.dll>  # resolve without IDA
```

`tools/cfs6_resolve.py` is the **reference resolver**: a stdlib-only
implementation of CFS6 resolution against a PE, including `.pdata` ownership for
`BODY`. It is what an external consumer should be checked against.

## Author

fl0sec
