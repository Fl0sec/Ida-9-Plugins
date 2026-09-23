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

Every call returns the same four keys, so a caller never has to remember which
verb reports failure under which name:

    ok          everything asked for succeeded
    partial     some of it succeeded and some did not -- `ok` is False
    error       the whole call failed and nothing happened, else None
    unresolved  [{kind, name, reason}] for every input that did not make it

`ok` is deliberately **not** "something worked". An export that writes 51 of 52
items is `ok=False, partial=True`: an agent that checks `ok` and moves on must
not sail past a missing item, which is exactly how silent attrition goes
unnoticed (see docs/signature-durability.md).

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


def _result(ok=False, partial=False, error=None, unresolved=(), **extra):
    """The four keys every call shares, plus whatever the verb adds."""
    out = {
        "ok": bool(ok),
        "partial": bool(partial),
        "error": error,
        "unresolved": list(unresolved),
    }
    out.update(extra)
    return out


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


def _collect(function_names, global_names, check_db=True):
    """([function_ea], [global_ea], unresolved) for two batches of names."""
    function_eas, global_eas, unresolved = [], [], []

    for kind, names, bucket in (
        (registry.KIND_FUNCTION, function_names, function_eas),
        (registry.KIND_GLOBAL, global_names, global_eas),
    ):
        ids, bad = registry.normalize(kind, names)
        unresolved.extend(bad)
        for iid in ids:
            name = registry.parse_entry_id(iid)[1]
            if not check_db:
                bucket.append(name)
                continue
            ea, error = _resolve(kind, name)
            if error is not None:
                unresolved.append({"kind": kind, "name": name, "reason": error})
                continue
            bucket.append(ea)

    return function_eas, global_eas, unresolved


def register(function_names=(), global_names=()):
    """Add names to this IDB's export set.

    Names are validated for shape and checked against the database now, so a
    typo is reported at registration instead of silently producing nothing at
    export time. Registration itself does no analysis and is cheap.
    """
    existing = set(store.load_registry())
    added, already, unresolved = [], [], []

    for kind, names in (
        (registry.KIND_FUNCTION, function_names),
        (registry.KIND_GLOBAL, global_names),
    ):
        ids, bad = registry.normalize(kind, names)
        unresolved.extend(bad)
        for iid in ids:
            name = registry.parse_entry_id(iid)[1]
            _ea, error = _resolve(kind, name)
            if error is not None:
                unresolved.append({"kind": kind, "name": name, "reason": error})
                continue
            if iid in existing:
                already.append(name)
                continue
            existing.add(iid)
            added.append(name)

    if not store.save_registry(existing):
        return _result(error="could not persist the export set to the IDB",
                       unresolved=unresolved, added=0, already=0, total=0)

    accepted = len(added) + len(already)
    ok, partial = registry.outcome(accepted + len(unresolved), accepted,
                                   unresolved)
    msg("API: registered %d, already present %d, unresolved %d"
        % (len(added), len(already), len(unresolved)))
    return _result(
        ok=ok, partial=partial,
        unresolved=unresolved,
        added=len(added), added_names=sorted(added),
        already=len(already),
        total=len(existing),
    )


def unregister(function_names=(), global_names=()):
    """Remove names from the export set. Absent names are not an error."""
    existing = set(store.load_registry())
    removed = []

    for kind, names in (
        (registry.KIND_FUNCTION, function_names),
        (registry.KIND_GLOBAL, global_names),
    ):
        ids, _bad = registry.normalize(kind, names)
        for iid in ids:
            if iid in existing:
                existing.discard(iid)
                removed.append(registry.parse_entry_id(iid)[1])

    if not store.save_registry(existing):
        return _result(error="could not persist the export set to the IDB",
                       removed=0, total=0)
    return _result(ok=True, removed=len(removed),
                   removed_names=sorted(removed), total=len(existing))


def clear():
    """Empty the export set."""
    if not store.save_registry([]):
        return _result(error="could not persist the export set")
    return _result(ok=True, total=0)


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
                unresolved.append({"kind": kind, "name": name, "reason": error})

    resolved = len(ids) - len(unresolved)
    ok, partial = registry.outcome(len(ids), resolved, unresolved)
    return _result(
        ok=ok, partial=partial,
        unresolved=unresolved,
        functions=by_kind[registry.KIND_FUNCTION],
        globals=by_kind[registry.KIND_GLOBAL],
        declared_members=[d.qualified for d in store.load_all()],
        counts={
            "functions": len(by_kind[registry.KIND_FUNCTION]),
            "globals": len(by_kind[registry.KIND_GLOBAL]),
            "members": store.count(),
        },
    )


def _run_export(path, function_eas, global_eas, unresolved, merge, build,
                include_members):
    """Shared tail of `export` and `export_list`."""
    if not isinstance(path, str) or not path:
        return _result(error="path is required", unresolved=unresolved)
    if not path.lower().endswith(".cfs"):
        path += ".cfs"

    declarations = store.load_all() if include_members else []
    requested = len(function_eas) + len(global_eas) + len(declarations)
    if not requested:
        return _result(error="nothing resolved to export", unresolved=unresolved)

    if build is None:
        build_number, build_source = detect_build()
    else:
        build_number, build_source = int(build), "user"

    # Types may have changed since the last export in this session.
    _export.clear_caches()

    raw = _export.export_to_path(
        path, get_search_ranges(),
        function_eas=function_eas, global_eas=global_eas,
        declarations=declarations,
        build=(build_number, build_source), merge=merge,
    )

    # Names that never resolved never reached the engine, so they have to be
    # merged in here or they would vanish from the report entirely.
    missed = list(unresolved) + list(raw.get("uncovered", ()))
    written = raw.get("written", 0)
    # `requested` counts only what got as far as the engine; anything rejected
    # earlier was still asked for, so it belongs in the denominator.
    asked = requested + len(unresolved)

    if raw.get("error") and written == 0:
        return _result(error=raw["error"], unresolved=missed,
                       cancelled=raw.get("cancelled", False),
                       path=raw.get("path", path), requested=asked, written=0)

    ok, partial = registry.outcome(asked, written, missed)
    return _result(
        ok=ok, partial=partial,
        error=raw.get("error"),
        unresolved=missed,
        path=raw.get("path", path),
        requested=asked,
        written=written,
        functions=raw.get("functions", 0),
        globals=raw.get("globals", 0),
        members=raw.get("members", 0),
        types=raw.get("types", 0),
        merged=raw.get("merged"),
        mode=raw.get("mode"),
        cancelled=raw.get("cancelled", False),
        summary=raw.get("summary", ""),
    )


def export(path, merge=_export.MERGE_APPEND, build=None, include_members=True):
    """Export the registered set to `path`.

    `merge="append"` refreshes items already in the file and keeps the rest;
    `merge="replace"` discards what is there. Appending is refused when the
    existing file describes a different image or build -- that is reported as
    an error rather than resolved by guessing.

    `build` is an explicit build number; omitted, it is detected from the IDB
    path and never invented (an undetectable build is recorded as unknown).
    """
    by_kind = registry.split_by_kind(store.load_registry())
    function_eas, global_eas, unresolved = _collect(
        by_kind[registry.KIND_FUNCTION], by_kind[registry.KIND_GLOBAL]
    )
    return _run_export(path, function_eas, global_eas, unresolved,
                       merge, build, include_members)


def export_list(path, function_names=(), global_names=(),
                merge=_export.MERGE_APPEND, build=None, include_members=False):
    """Export an explicit list, ignoring the registered set entirely.

    For the case where the agent already knows the whole list and has no use
    for persistence. Nothing here reads or writes the export set.
    """
    function_eas, global_eas, unresolved = _collect(function_names, global_names)
    return _run_export(path, function_eas, global_eas, unresolved,
                       merge, build, include_members)
