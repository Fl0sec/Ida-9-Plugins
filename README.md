# ida-9-plugins

IDA Pro 9.0 plugins (IDAPython 9.0 / Python 3.12), plus the shared tooling and
conventions they are written against.

## Contents

| Path | What it is |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | the rules for writing plugins here — read first |
| [`docs/`](docs/) | IDA 9.0 API deltas, plugin anatomy, Python style, workflow |
| [`templates/plugin_skeleton/`](templates/plugin_skeleton/) | copy this to start a new plugin |
| [`tools/`](tools/) | offline check gate and the deploy script |
| [`cfs5-transfer/`](cfs5-transfer/) | CFS5 signature/type transfer plugins |
| `ida-pro-mcp/` | upstream MCP server checkout — read-only, git-ignored |
| `reference/` | third-party plugin sources for reading — git-excluded |

## Quick start

```bash
cp -r templates/plugin_skeleton my-plugin      # then follow docs/workflow.md
python tools/check.py my-plugin                # compile + IDA 9.0 API + import
```

```powershell
pwsh tools/deploy.ps1 my-plugin                # -> %APPDATA%\Hex-Rays\IDA Pro\plugins
```

Then restart IDA and exercise the plugin against a real IDB.

## `tools/check.py`

The only automated verification available for IDA plugins outside IDA. Three
passes:

- **compile** — syntax errors in every `.py`.
- **api** — every `ida_*` symbol checked against the IDAPython stubs in the
  local IDA 9.0 install, so 8.x-era calls (`get_inf_structure`, `ida_struct`,
  `find_binary`, ...) are caught before load time rather than inside IDA.
- **import** — each module imported with the IDA modules stubbed out, catching
  broken cross-module wiring and import-time crashes.

Override the stub location with `IDA_PYTHON_DIR` if IDA is installed elsewhere.

It cannot prove behaviour against a real IDB; only a human running the plugin
in IDA can.

## Requirements

- IDA Professional 9.0 (`C:\Program Files\IDA Professional 9.0`)
- Python 3.12 (matches IDA 9.0's bundled interpreter)
- No third-party Python packages — plugins are stdlib-only by policy

## Author

fl0sec
