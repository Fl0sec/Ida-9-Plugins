"""Programmatic CFS6 export, for an agent driving IDA.

The UI answers "export what I have selected right now". This answers "export
the set I have been building up", which is the workflow an agent actually has:
it discovers items over many steps and wants one export at the end.

Contract, and the reason for each part:

- **Every function takes and returns plain data.** No dialogs, no popups, no
  `ask_*`. A blocking prompt inside an agent call is a hang, not a question.
- **Everything is batched.** Registering fifty names is one call.
- **Everything is idempotent.** Re-registering is `already`, not an error;
  unregistering something absent is a no-op. Agents retry.
- **A bad entry never fails the batch.** Fifty names with two typos register
  forty-eight and report two, because losing the other forty-eight to a
  validation error is the more expensive outcome.
- **`export` reports what it could not cover.** `uncovered` names every item
  that produced no signature, with a reason. Silent partial success is the
  failure mode this whole module exists to prevent.

Registration stores *names*, resolved to addresses only at export time -- see
`registry.py` for why.
"""

import ida_funcs
import ida_name

from . import export as _export
from . import registry
from . import store
from .common import BADADDR, ea_str, get_search_ranges, msg
from .image import detect_build


def _resolve(kind, name):
    """(ea, error) for a registered name in the current IDB."""
    ea = ida_name.get_name_ea(BADADDR, name)
    if ea == BADADDR:
        return None, "no such name in this IDB"

    if kind == registry.KIND_FUNCTION:
        func = ida_funcs.get_func(ea)
        if func is None:
            return None, "name exists but is not a function"
        if func.start_ea != ea:
            # Registering a name that sits mid-function would export the
            # containing function under the wrong name.
            return None, "name is inside %s, not a function start" % ea_str(
                func.start_ea
            )
        return func.start_ea, None

    if ida_funcs.get_func(ea) is not None:
        return None, "name is code, not a global variable"
    return ea, None


def register(functions=(), globals=()):
    """Add names to this IDB's export set. Returns counts plus rejections.

    Names are validated for shape and checked against the database now, so a
    typo is reported at registration instead of silently producing nothing at
    export time. Registration itself does no analysis and is cheap.
    """
    existing = set(store.load_registry())
    added, already, rejected = [], [], []

    for kind, names in (
        (registry.KIND_FUNCTION, functions),
        (registry.KIND_GLOBAL, globals),
    ):
        ids, bad = registry.normalize(kind, names)
        rejected.extend(bad)
        for iid in ids:
            _kind, name = registry.parse_entry_id(iid)
            ea, error = _resolve(kind, name)
            if error is not None:
                rejected.append({"name": name, "kind": kind, "reason": error})
                continue
            if iid in existing:
                already.append(name)
                continue
            existing.add(iid)
            added.append(name)

    if not store.save_registry(existing):
        return {"ok": False, "added": 0, "already": 0,
                "rejected": rejected,
                "error": "could not persist the export set to the IDB"}

    msg("API: registered %d, already present %d, rejected %d"
        % (len(added), len(already), len(rejected)))
    return {
        "ok": True,
        "added": len(added), "added_names": sorted(added),
        "already": len(already),
        "rejected": rejected,
        "total": len(existing),
    }


def unregister(functions=(), globals=()):
    """Remove names from the export set. Absent names are not an error."""
    existing = set(store.load_registry())
    removed = []

    for kind, names in (
        (registry.KIND_FUNCTION, functions),
        (registry.KIND_GLOBAL, globals),
    ):
        ids, _bad = registry.normalize(kind, names)
        for iid in ids:
            if iid in existing:
                existing.discard(iid)
                removed.append(registry.parse_entry_id(iid)[1])

    if not store.save_registry(existing):
        return {"ok": False, "removed": 0,
                "error": "could not persist the export set to the IDB"}
    return {"ok": True, "removed": len(removed),
            "removed_names": sorted(removed), "total": len(existing)}


def clear():
    """Empty the export set."""
    if not store.save_registry([]):
        return {"ok": False, "error": "could not persist the export set"}
    return {"ok": True, "total": 0}


def registered():
    """The current export set, plus how each entry resolves right now.

    `unresolved` is the actionable part: a name that has since been renamed or
    deleted is reported here rather than quietly contributing nothing.
    """
    ids = store.load_registry()
    by_kind = registry.split_by_kind(ids)
    unresolved = []

    for kind, names in by_kind.items():
        for name in names:
            _ea, error = _resolve(kind, name)
            if error is not None:
                unresolved.append(
                    {"kind": kind, "name": name, "reason": error}
                )

    return {
        "ok": True,
        "functions": by_kind[registry.KIND_FUNCTION],
        "globals": by_kind[registry.KIND_GLOBAL],
        "declared_members": [d.qualified for d in store.load_all()],
        "counts": {
            "functions": len(by_kind[registry.KIND_FUNCTION]),
            "globals": len(by_kind[registry.KIND_GLOBAL]),
            "members": store.count(),
        },
        "unresolved": unresolved,
    }


def export(path, merge=_export.MERGE_APPEND, build=None, include_members=True):
    """Export the registered set to `path`.

    `merge="append"` refreshes items already in the file and keeps the rest;
    `merge="replace"` discards what is there. Appending is refused when the
    existing file describes a different image or build -- that is reported as
    an error rather than resolved by guessing.

    `build` is an explicit build number; omitted, it is detected from the IDB
    path and never invented (an undetectable build is recorded as unknown).
    """
    if not isinstance(path, str) or not path:
        return {"ok": False, "error": "path is required"}
    if not path.lower().endswith(".cfs"):
        path += ".cfs"

    ids = store.load_registry()
    by_kind = registry.split_by_kind(ids)

    function_eas, global_eas, unresolved = [], [], []
    for kind, bucket in (
        (registry.KIND_FUNCTION, function_eas),
        (registry.KIND_GLOBAL, global_eas),
    ):
        for name in by_kind[kind]:
            ea, error = _resolve(kind, name)
            if error is not None:
                unresolved.append(
                    {"kind": kind, "name": name, "reason": error}
                )
                continue
            bucket.append(ea)

    declarations = store.load_all() if include_members else []

    if not function_eas and not global_eas and not declarations:
        return {"ok": False, "error": "export set is empty",
                "uncovered": unresolved}

    if build is None:
        build_number, build_source = detect_build()
    else:
        build_number, build_source = int(build), "user"

    # Types may have changed since the last export in this session.
    _export.clear_caches()

    result = _export.export_to_path(
        path, get_search_ranges(),
        function_eas=function_eas, global_eas=global_eas,
        declarations=declarations,
        build=(build_number, build_source), merge=merge,
    )
    # A name that no longer resolves never reached the engine, so it has to be
    # merged in here or it would vanish from the report entirely.
    result["uncovered"] = unresolved + list(result.get("uncovered", ()))
    result["requested"] = len(function_eas) + len(global_eas) + len(declarations)
    return result


def export_now(path, functions=(), globals=(), merge=_export.MERGE_APPEND,
               build=None, include_members=False):
    """One-shot export of an explicit list, without touching the export set.

    For the case where the agent already knows the whole list and has no use
    for persistence.
    """
    function_eas, global_eas, unresolved = [], [], []

    for kind, names, bucket in (
        (registry.KIND_FUNCTION, functions, function_eas),
        (registry.KIND_GLOBAL, globals, global_eas),
    ):
        ids, bad = registry.normalize(kind, names)
        unresolved.extend(bad)
        for iid in ids:
            name = registry.parse_entry_id(iid)[1]
            ea, error = _resolve(kind, name)
            if error is not None:
                unresolved.append({"kind": kind, "name": name, "reason": error})
                continue
            bucket.append(ea)

    if not isinstance(path, str) or not path:
        return {"ok": False, "error": "path is required"}
    if not path.lower().endswith(".cfs"):
        path += ".cfs"

    declarations = store.load_all() if include_members else []
    if not function_eas and not global_eas and not declarations:
        return {"ok": False, "error": "nothing resolved to export",
                "uncovered": unresolved}

    if build is None:
        build_number, build_source = detect_build()
    else:
        build_number, build_source = int(build), "user"

    _export.clear_caches()
    result = _export.export_to_path(
        path, get_search_ranges(),
        function_eas=function_eas, global_eas=global_eas,
        declarations=declarations,
        build=(build_number, build_source), merge=merge,
    )
    result["uncovered"] = unresolved + list(result.get("uncovered", ()))
    result["requested"] = len(function_eas) + len(global_eas) + len(declarations)
    return result
