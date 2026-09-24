"""IDA-free selection rules for incremental CFS6 export."""

from . import registry


def resolve(declarations, declaration_names=(), item_ids=()):
    """Return an exact incremental-export selection without guessing.

    The result has `function_names`, `global_names`, `declarations`, `ids`, and
    `unresolved`. Qualified names may be ambiguous across derived semantics;
    callers must use an exact item id in that case.
    """
    decl_by_id = {decl.id: decl for decl in declarations or ()}
    decl_by_name = {}
    for decl in declarations or ():
        decl_by_name.setdefault(decl.qualified, []).append(decl)

    ids = []
    unresolved = []
    for name in declaration_names or ():
        text = str(name)
        matches = decl_by_name.get(text, ())
        if len(matches) != 1:
            unresolved.append({
                "kind": "declaration", "name": text,
                "reason": "not declared" if not matches
                          else "ambiguous declaration name",
            })
            continue
        if matches[0].id not in ids:
            ids.append(matches[0].id)

    function_names = []
    global_names = []
    for value in item_ids or ():
        iid = str(value)
        if iid in decl_by_id:
            if iid not in ids:
                ids.append(iid)
            continue
        try:
            kind, name = registry.parse_entry_id(iid)
        except registry.RegistryError:
            unresolved.append({"kind": "item", "name": iid,
                               "reason": "unknown item id"})
            continue
        bucket = function_names if kind == registry.KIND_FUNCTION else global_names
        if name not in bucket:
            bucket.append(name)
        if iid not in ids:
            ids.append(iid)

    return {
        "ids": ids,
        "function_names": function_names,
        "global_names": global_names,
        "declarations": [decl_by_id[iid] for iid in ids if iid in decl_by_id],
        "unresolved": unresolved,
        "requested": len(ids) + len(unresolved),
    }
