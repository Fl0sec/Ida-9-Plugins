# mermaid-flow

Attach a Mermaid flowchart to a function and render it as a **native IDA
graph**, for IDA Pro 9.0 (IDAPython 9.0 / Python 3.12).

Write (or generate) a high-level flowchart of what a function actually does,
paste it in once, and get it back as a real IDA graph tab every time you open
the database — with nodes that jump to the code they describe. IDA's own graph
view shows basic blocks; this shows the story you reconstructed.

## Layout

```
mermaid-flow/
  cvutils-mermaid-flow.py   # plugin entry (PLUGIN_ENTRY): actions + orchestration
  mermaidflow/              # shared, importable core
    parser.py   # Mermaid subset -> node/edge model  (no ida_* imports)
    store.py    # per-function persistence in the IDB (netnode blobs)
    view.py     # GraphViewer, colours, address resolution
    common.py   # msg(), ea_str()
  tests/
    test_parser.py          # runs outside IDA: python mermaid-flow/tests/test_parser.py
    example_driver.mmd
```

## Install

Copy **both** `cvutils-mermaid-flow.py` and the `mermaidflow/` folder, kept side
by side, into your IDA `plugins/` directory:

```powershell
pwsh tools/deploy.ps1 mermaid-flow
```

## Usage

Right-click inside a function — **disassembly**, **pseudocode**, or the
**Functions** window — and use the **Mermaid** submenu:

| Action | |
|---|---|
| **Show flowchart** (`Ctrl+Shift+M`) | render the stored chart; offers a paste dialog if there is none yet |
| **Edit flowchart source...** | reopen the paste dialog prefilled with what is stored |
| **Delete flowchart** | remove it from the IDB |

The source is stored per function in the IDB, so it survives closing the
database. **Double-click a node** to jump to its address.

## Linking nodes to code

Two mechanisms, no custom syntax:

1. **Automatic.** A node whose label matches a symbol name in the IDB links
   itself. Since generated flowcharts usually label steps with the real callee
   names, most nodes link with no annotation at all.
2. **Explicit**, via Mermaid's own `click` directive — so the source still
   renders unchanged in mermaid.live or any Markdown viewer:

   ```
   click F "0x140003870"
   click D "InitializeTextIntegrityBaseline"
   ```

A **name is preferred over a raw address**: an address dies the moment the IDB
is rebased, whereas a name that stops resolving simply leaves the node
unlinked, which is a visible signal rather than a silent wrong jump.

Linked nodes are tinted green and carry their address as a second line.

## Supported syntax

| Mermaid | Handled as |
|---|---|
| `flowchart TD` / `graph LR` | parsed; **direction is ignored** (IDA always lays out top-down) |
| `A["text"]` | node, `<br/>` becomes a real line break |
| `A(round)` `A((circle))` `A[[sub]]` `A[(db)]` `A([stadium])` | node, shape recorded |
| `A{"cond?"}` / `A{{hex}}` | **decision** node — tinted amber, prefixed `<>` |
| `A --> B`, `A --- B` | edge |
| `A -- Yes --> B`, `A -->|Yes| B` | labelled edge |
| `A -. "text" .-> B` | dotted edge |
| `A == text ==> B` | thick edge |
| `click A "target"` | node jump target |
| `subgraph` / `end` | **flattened** with a warning — nodes and edges kept |
| `classDef` `class` `style` `linkStyle` `%%` | ignored |

Unknown constructs produce a warning in the Output window, never an exception.

## Two IDA limitations worth knowing

Both were verified against the IDA 9.0 SDK, and neither has a workaround:

- **Edge labels cannot be drawn.** `edge_info_t` carries colour, width and
  layout but no text. So `-- Yes -->` is conveyed three other ways instead:
  the edge is coloured (green *yes*, red *no*, grey *dotted*), the label shows
  as `[Yes]` on the node it leads into, and hovering the edge shows it
  verbatim.
- **Every node is a rectangle.** There is no shape control in IDA's graph
  renderer, so a Mermaid diamond becomes an amber node marked `<>`.

Node colours: green = links to an address, amber = decision, blue-ish = reached
only by a failure branch, grey = terminal (no outgoing edge).

## Tests

The parser is deliberately free of `ida_*` imports, so it is the one layer that
can really be tested:

```bash
python mermaid-flow/tests/test_parser.py
python tools/check.py mermaid-flow
```

`example_driver.mmd` is a real generated driver-initialisation flowchart, kept
as a regression fixture because it exercises the three constructs that break a
naive parser: a node referenced before it is labelled, `<br/>` inside labels,
and a duplicate edge pair (`K --> L` plus `K -. "failure is non-fatal" .-> L`)
that must merge rather than draw twice.
