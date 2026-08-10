# ida-9-plugins

CFS5 signature/type transfer plugins for IDA Pro 9.0 (IDAPython 9.0 / Python 3.12).

Transfer function names, prototypes, and local types between two IDBs of the same or related binaries, using short, unique byte signatures instead of raw addresses.

## Plugins

### `cvutils-cfs-exporter.py` — CFS5 Exporter

Exports selected/user-named functions to a `.cfs` file: signatures + prototypes + dependent local types.

**Usage**
- Open the *Functions* window (View → Open subviews → Functions).
- Right-click → **CFS5** → *Export selected optimized signatures* (`Ctrl+Shift+E`), or *Export ALL user-named optimized signatures*.
- Choose an output `.cfs` path.

**Features**
- Builds the shortest unique signature per function in three modes:
  - `ENTRY` — signature at function start.
  - `BODY` — signature at an interior offset (importer resolves the owning function).
  - `REL` — signature at a caller/xref instruction, resolving the target via its signed PC-relative displacement.
- Exports up to 2 candidates per function (primary + a different-mode backup).
- Exports each function's prototype (return type + arguments) as a portable binary `tinfo_t`, tagged `USER` / `EXPLICIT` / `GUESSED` by origin.
- Transitively exports dependent local types (structs/unions/enums/typedefs) referenced by exported prototypes, deduplicated, with full member bodies (not just forward declarations).
- Output stays CFS2-row compatible for backward-compatible signature-only tooling.

### `cvutils-cfs-importer.py` — CFS5 Importer

Imports a `.cfs` file into the current IDB: renames matched functions, registers missing local types, and merges prototypes.

**Usage**
- File → Load file → **CFS5 / CFS File...** (`Ctrl+Shift+I`).
- Pick a `.cfs` file (also accepts CFS4/CFS3/CFS2 and legacy Cra0-style 3-column CFS files).

**Features**
- Resolves each function via its signature(s) in ranked order, falling back to the backup candidate if the primary is missing/ambiguous.
- `REL` targets are re-validated (instruction re-decodes, displacement re-read, target must be mapped code) before use.
- Creates a function at the resolved address if none exists yet.
- Never overwrites a destination function that already has a real user-given name; never overwrites a fully-defined destination type with a same-named incoming one (only upgrades forward declarations).
- Merges prototypes field-by-field: a specific destination named/UDT/enum type always wins over a generic incoming scalar; a specific incoming type can fill a generic/guessed destination hole.
- Registers missing local types (multi-pass, dependency-order aware) without touching pre-existing definitions.
- Shows a detailed import summary (renamed / created / skipped / ambiguous / types registered / prototypes applied, etc.) in the Output window and a popup.

## Compatibility

Both plugins accept older `CFS`, `CFS2`, `CFS3`, and `CFS4` row formats for import; export always writes CFS5.

## Author

NtTilt
