# IDA 9.0 API: what changed, and how to verify a symbol

IDA 9.0 is not a drop-in continuation of the 8.x IDAPython surface. Whole
modules were deleted and their functionality folded into `ida_typeinf`, and a
number of long-standing helpers were removed. Code written from 7.x/8.x memory
compiles fine and fails at load time inside IDA.

**Every claim below was verified against the local install**
(`C:\Program Files\IDA Professional 9.0\python`) — reverify rather than trusting
this file if the install is ever upgraded.

## Verification: the ground truth is on disk

The IDAPython stubs shipped with IDA are the authoritative list of what exists.
They cannot be imported outside IDA (they load native `_ida_*` extensions), but
they can be read and parsed.

**Mechanical, whole-file (preferred):**

```bash
python tools/ida_api_lint.py my-plugin      # or: python tools/check.py my-plugin
```

It parses every stub, resolves `from ida_x import *` re-exports transitively
(that is how `idaapi` gets its surface), and reports every `mod.attr` and
`from mod import name` in your sources that IDA 9.0 does not define.

**Ad hoc, one symbol:**

```bash
grep -n "def bin_search" "/c/Program Files/IDA Professional 9.0/python/ida_bytes.py"
grep -rn "def get_inf_structure" "/c/Program Files/IDA Professional 9.0/python/"*.py
ls "/c/Program Files/IDA Professional 9.0/python/" | grep ida_struct
```

An empty result is a definitive answer: it does not exist in 9.0.

**Behaviour, not just existence:** the `ida-pro-mcp` MCP server can run a probe
against a real IDB (`py_eval`). Use it when the signature is present but you are
unsure what the call returns for a given IDB state.

Also available: `ida-pro-mcp/skills/idapython/docs/ida_*.md` — per-module
reference docs checked into the sibling repo.

## Removed in 9.0 — the ones that bite

| Removed / gone | Use instead |
|---|---|
| `ida_struct` (whole module) | `ida_typeinf` — `tinfo_t`, `udt_type_data_t`, `udm_t` |
| `ida_enum` (whole module) | `ida_typeinf` — `tinfo_t` enum details |
| `idaapi.get_inf_structure()` | `ida_ida.inf_get_*()` (75 accessors: `inf_get_min_ea`, `inf_get_max_ea`, `inf_is_64bit`, ...) |
| `ida_search.find_binary()` | `ida_bytes.bin_search()` with `parse_binpat_str` / `compiled_binpat_vec_t` |
| struct-based stack frame access | `ida_frame.add_frame_member`, `set_frame_member_type`, `define_stkvar` (all take `tinfo_t`) |

`ida_search` still exists in 9.0, but only for the `find_code` / `find_data` /
`find_text` / `find_imm` family — **not** for byte-pattern search.

## The modules you will actually use

| Task | Module | Key items |
|---|---|---|
| Plugin/actions/UI | `ida_kernwin` | `action_handler_t`, `action_desc_t`, `register_action`, `attach_action_to_popup`, `UI_Hooks`, `show_wait_box`, `user_cancelled`, `ask_yn`, `info`, `warning`, `msg` |
| Plugin base | `idaapi` / `ida_idaapi` | `plugin_t`, `plugmod_t`, `PLUGIN_*` flags, `BADADDR` |
| Bytes / patching | `ida_bytes` | `get_bytes`, `patch_bytes`, `get_flags`, `bin_search`, `parse_binpat_str`, `create_*`, `has_user_name` |
| Functions | `ida_funcs` | `func_t`, `get_func`, `add_func`, `get_func_name`, `FUNC_LIB`, `FUNC_THUNK` |
| Names | `ida_name` | `set_name`, `get_name`, `demangle_name` |
| Types | `ida_typeinf` | `tinfo_t`, `apply_tinfo`, `parse_decl`, `get_idati`, `udm_t`, `udt_type_data_t` |
| Decompiler | `ida_hexrays` | `decompile`, `cfunc_t`, `lvar_t`, ctree visitors |
| Segments | `ida_segment` | `segment_t`, `getseg`, `get_first_seg`, `get_next_seg`, `SEGPERM_EXEC` |
| Xrefs | `ida_xref` | `xrefblk_t`, `add_cref`, `add_dref` |
| Instructions | `ida_ua` | `insn_t`, `op_t`, `decode_insn` |
| Stack frames | `ida_frame` | `add_frame_member`, `set_frame_member_type`, `define_stkvar`, `build_stkvar_xrefs` |
| Database info | `ida_ida` | `inf_get_min_ea`, `inf_get_max_ea`, `UA_MAXOP`, ... |
| Iteration | `idautils` | `Functions()`, `Heads()`, `XrefsTo()`, `Strings()` |

## Threading

**Every IDA SDK call must run on IDA's main thread.** Action handlers, `run()`,
`init()` and UI hooks are already on it. Anything you start yourself (a worker
thread, a timer callback, an MCP/RPC handler) is not — marshal it with
`ida_kernwin.execute_sync(callable, ida_kernwin.MFF_WRITE)` (`MFF_READ` for
read-only work, `MFF_FAST` when no IDB access is involved).

Getting this wrong does not raise a clean Python exception — it corrupts the
IDB or crashes IDA.

## Robustness rules that come from the bindings, not from taste

- **Wrap IDA calls in `try/except`.** The SWIG bindings raise inconsistently
  depending on the argument type and IDB state; the same call that returns
  `None` on one item throws on the next. In a batch loop, one unhandled
  exception loses the whole run.
- **Addresses are 64-bit.** Compare against `ida_idaapi.BADADDR`, never `-1`
  or `0xFFFFFFFF`.
- **Wait for auto-analysis** before reading analysis results
  (`ida_auto.auto_wait()`), especially right after creating a function or
  patching bytes.
- **`ida_bytes.has_user_name` (FF_NAME) is far too broad** to mean "a human
  named this". PDB imports, ClassInformer RTTI/vftables, FLIRT library matches
  and even `nullsub_N` stubs all set it. If you need real user renames, filter
  further — `cfs5-transfer/cvutils-cfs-exporter.py` has a worked example
  (plain-C-identifier gate + exclusion regex + demangle backstop).
