# cfs5-transfer

CFS6 signature/type transfer plugins for IDA Pro 9.0 (IDAPython 9.0 / Python 3.12).

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
    common.py   disasm.py   sigs.py   typeio.py
  docs/cfs6-format.md   # the authoritative format specification
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

### `cvutils-cfs-importer.py` — CFS6 Importer

Imports a `.cfs` file into the current IDB: renames matched functions and
globals, registers missing local types, merges prototypes, applies global types.

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

Filenames carry no meaning: `f.cfs` / `g.cfs` / `all.cfs` are cosmetic and every
file is fully self-describing.

## Compatibility

**CFS6 is a clean break.** Pre-CFS6 CSV files (`CFS2`/`CFS3`/`CFS4`/`CFS5` rows
and legacy Cra0 rows) are no longer read — re-export instead. This removed the
whole legacy parsing path in exchange for a format an external consumer can
implement from the spec alone.

## Testing

```bash
python tools/check.py cfs5-transfer                  # compile + IDA 9.0 API + import
cd cfs5-transfer && python -m unittest discover -s tests -t tests
python tools/cfs6_resolve.py <file.cfs> <image.dll>  # resolve without IDA
```

`tools/cfs6_resolve.py` is the **reference resolver**: a stdlib-only
implementation of CFS6 resolution against a PE, including `.pdata` ownership for
`BODY`. It is what an external consumer should be checked against.

## Author

fl0sec
