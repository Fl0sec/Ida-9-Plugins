# cfs5-transfer

CFS5 signature/type transfer plugins for IDA Pro 9.0 (IDAPython 9.0 / Python 3.12).

Transfer function names, **global-variable names**, prototypes, global types and
local types between two IDBs of the same or related binaries, using short unique
byte signatures instead of raw addresses.

## Layout

```
cfs5-transfer/
  cvutils-cfs-exporter.py   # exporter plugin entry (PLUGIN_ENTRY)
  cvutils-cfs-importer.py   # importer plugin entry (PLUGIN_ENTRY)
  cfs5/                     # shared, importable core package
    common.py   disasm.py   sigs.py   typeio.py   cfsfile.py
```

Both entry files add their own directory to `sys.path` and force-reload the
`cfs5` package on load, so editing anything under `cfs5/` takes effect the next
time IDA loads the plugin.

## Install

Copy **all three** items — the two `.py` entry files *and* the `cfs5/` folder,
kept side by side — into your IDA `plugins/` directory (or point IDA's plugin
loader at them). The package must remain a sibling of the entry files.

## Plugins

### `cvutils-cfs-exporter.py` — CFS5 Exporter

Exports functions **and** user-named globals to a `.cfs` file: signatures +
prototypes/types + dependent local types.

**Usage** — functions and globals are controlled independently.

*Functions* window (View → Open subviews → Functions) → right-click → **CFS5/**:
- *Export selected functions* (`Ctrl+Shift+E`) — only the rows you selected.
- *Export ALL user-named functions* — every user function, **no globals**.
- *Export ALL user functions + globals* — the full transfer set.

*Names* window (Shift+F4) → right-click → **CFS5/**:
- *Export selected globals* — only the data globals you selected (pick them in
  the Names window). Explicitly selected items skip the human-name heuristic.
- *Export ALL user-named globals* — every user global, **no functions**.

Each action asks for an output `.cfs` path. So you can export functions only,
globals only, a hand-picked subset of either, or everything.

**Features**
- Function signatures in three modes, shortest-unique first:
  - `ENTRY` — at function start.
  - `BODY` — at an interior offset (importer resolves the owning function).
  - `REL` — at a caller/xref instruction, resolving the target via its signed
    PC-relative displacement.
- Global signatures: `REL`-only, anchored on a code instruction that references
  the global (via a data xref). Globals with no usable code reference are
  skipped (no reliable anchor).
- Up to 2 ranked candidates per item.
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

### `cvutils-cfs-importer.py` — CFS5 Importer

Imports a `.cfs` file into the current IDB: renames matched functions and
globals, registers missing local types, merges prototypes, applies global types.

**Usage**
- File → Load file → **CFS5 / CFS File...** (`Ctrl+Shift+I`).
- Pick a `.cfs` file (also accepts CFS4/CFS3/CFS2 and legacy Cra0-style files).

**Features**
- Resolves each item via its signature(s) in ranked order, falling back to the
  backup candidate if the primary is missing/ambiguous.
- `REL` targets are re-validated (instruction re-decodes, length unchanged,
  displacement re-read) before use. Function REL targets must be mapped code;
  global REL targets must be mapped data.
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

CSV with a leading tag column (see `cfs5/cfsfile.py` for the authoritative
layout):

| Tag        | Meaning                                             |
|------------|-----------------------------------------------------|
| `CFS2`     | function signature candidate (12 cols)              |
| `CFS2G`    | global signature candidate (12 cols, data target)   |
| `CFS4FUNC` | function prototype tinfo (8 cols)                   |
| `CFS5GLOB` | global type tinfo (8 cols)                          |
| `CFS4TYPE` | one named local type, full body (6 cols)            |

Binary payloads are `zlib`+`base64`; dependency lists are compressed JSON. The
`CFS2` layout is frozen for backward compatibility.

## Compatibility

Both plugins accept older `CFS`, `CFS2`, `CFS3`, and `CFS4` rows for import;
export always writes CFS5. Global rows (`CFS2G` / `CFS5GLOB`) are additive, so
older signature-only tooling ignores them.

## Author

fl0sec
