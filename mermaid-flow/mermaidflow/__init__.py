"""Shared core for the Mermaid flowchart viewer IDA 9.0 plugin.

Renders a pasted Mermaid flowchart as a native IDA graph attached to a
function, with node-to-address navigation and per-function persistence in the
IDB.

Layering, deliberately:
  parser.py  pure Python, no `ida_*` -- the only testable layer (tests/)
  store.py   IDB persistence (netnode blobs)
  view.py    the GraphViewer and everything visual

Target: IDA Professional 9.0 / IDAPython 9.0 / Python 3.12.
"""

VERSION = "1.0.0-ida9"
