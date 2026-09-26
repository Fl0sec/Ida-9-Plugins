"""Read-only discovery of the human-curated IDB surface for CFS snapshots.

The exporter UI and MCP API share this module so their definition of an
"annotated" function/global cannot drift.  It deliberately discovers only
addresses and names: candidate generation and type transport stay on the
bounded export-job side of the API.
"""

import hashlib
import json
import re

import ida_bytes
import ida_funcs
import ida_nalt
import ida_name
import ida_segment
import idautils


_GLOBAL_PREFIX_RE = re.compile(r"^g_")
_AUTO_DATA_RE = re.compile(r"^(jpt_|def_|funcs_)|^(TlsDirectory|TlsIndex|ExceptionDir)$")
_HUMAN_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_KEEP_RE = re.compile(
    r"^(?!sub_|j_|_)(?!.*nullsub)(?!.*std::)(?!.*unknown_libname)"
    r"(?!.*Concurrency)(?!.*[?@$]).*"
)
_GLOBAL_SEGMENTS = frozenset((".data", ".rdata", ".bss", ".idata"))


def _is_human_named(name):
    """Apply the conservative UI name policy to one candidate name."""
    if not name or not _HUMAN_NAME_RE.match(name) or not _KEEP_RE.match(name):
        return False
    try:
        return ida_name.demangle_name(name, ida_name.MNG_NODEFINIT) is None
    except Exception:
        return False


def _segment_name(ea):
    try:
        segment = ida_segment.getseg(ea)
        return ida_segment.get_segm_name(segment) if segment is not None else ""
    except Exception:
        return ""


def _import_thunks():
    result = set()

    def collect(ea, _name, _ordinal):
        result.add(ea)
        return True

    try:
        for index in range(ida_nalt.get_import_module_qty()):
            ida_nalt.enum_import_names(index, collect)
    except Exception:
        # A failed import walk must not turn imports into export candidates.
        return result
    return result


def discover():
    """Return stable function/global selections and compact exclusion counts.

    No IDB state is changed.  Exclusions are intentionally aggregate-only so
    a large IDB cannot turn a dry-run response into an oversized MCP payload.
    """
    functions, globals_ = [], []
    excluded = {"functions": {}, "globals": {}}

    def reject(kind, reason):
        bucket = excluded[kind]
        bucket[reason] = bucket.get(reason, 0) + 1

    for ea in idautils.Functions():
        function = ida_funcs.get_func(ea)
        if function is None or function.start_ea != ea:
            reject("functions", "invalid_function")
            continue
        if function.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
            reject("functions", "library_or_thunk")
            continue
        if not ida_bytes.has_user_name(ida_bytes.get_full_flags(ea)):
            reject("functions", "not_user_named")
            continue
        name = ida_name.get_name(ea) or ""
        if not _is_human_named(name):
            reject("functions", "non_human_name")
            continue
        functions.append((name, int(ea)))

    imports = _import_thunks()
    for ea, name in idautils.Names():
        flags = ida_bytes.get_full_flags(ea)
        if not name or ida_bytes.is_code(flags) or ida_bytes.is_tail(flags):
            continue
        if ida_funcs.get_func(ea) is not None:
            continue
        prefixed = bool(_GLOBAL_PREFIX_RE.match(name))
        if not (ida_bytes.has_user_name(flags) or prefixed):
            reject("globals", "not_user_named")
            continue
        if not _is_human_named(name) or _AUTO_DATA_RE.match(name):
            reject("globals", "non_human_name")
            continue
        if _segment_name(ea) not in _GLOBAL_SEGMENTS:
            reject("globals", "not_data_segment")
            continue
        if ea in imports and not prefixed:
            reject("globals", "import_thunk")
            continue
        globals_.append((name, int(ea)))

    return {
        "functions": sorted(functions), "globals": sorted(globals_),
        "excluded": excluded,
    }


def digest(selection, image, build, generator_version, schema_revision):
    """Bind a reviewed selection to the target and output format contract."""
    payload = {
        "functions": selection["functions"], "globals": selection["globals"],
        "image": image, "build": build,
        "generator_version": generator_version, "schema_revision": schema_revision,
        "policy": "human_user_names_plus_g_prefixed_data_globals_v1",
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
