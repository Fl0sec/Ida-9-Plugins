"""Persistent function/global registry and address collection."""

import ida_funcs
import ida_name

from . import registry
from . import rtti
from . import strloc
from . import store
from .api_result import result as _result
from .common import BADADDR, ea_str, msg


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


def _collect(function_names, global_names, sites_by_id=None,
             locators_by_id=None):
    """([function_ea], [global_ea], sites_by_ea, locators_by_ea, unresolved)."""
    function_eas, global_eas, unresolved = [], [], []
    sites_by_id = sites_by_id or {}
    locators_by_id = locators_by_id or {}
    sites_by_ea = {}
    locators_by_ea = {}

    for kind, names, bucket in (
        (registry.KIND_FUNCTION, function_names, function_eas),
        (registry.KIND_GLOBAL, global_names, global_eas),
    ):
        ids, entry_sites, entry_locators, bad = registry.normalize_entries(
            kind, names
        )
        unresolved.extend(bad)
        for iid in ids:
            name = registry.parse_entry_id(iid)[1]
            ea, error = _resolve(kind, name)
            if error is not None:
                unresolved.append({"kind": kind, "name": name, "reason": error})
                continue
            bucket.append(ea)
            # Sites given in this call and sites stored at registration are
            # the same kind of evidence; use both.
            merged = list(sites_by_id.get(iid, ()))
            merged.extend(s for s in entry_sites.get(iid, ()) if s not in merged)
            if merged and kind == registry.KIND_FUNCTION:
                sites_by_ea[ea] = merged

            # A locator named in this call overrides a stored one of the same
            # kind: it is a correction, not extra evidence.
            declared = list(locators_by_id.get(iid, ()))
            for locator in entry_locators.get(iid, ()):
                declared = [x for x in declared if x["kind"] != locator["kind"]]
                declared.append(locator)
            if declared and kind == registry.KIND_FUNCTION:
                locators_by_ea[ea] = declared

    return function_eas, global_eas, sites_by_ea, locators_by_ea, unresolved


def _verify_locators(locators, func_ea):
    """[(locator, reason_or_None), ...] -- does each claim hold in this IDB?

    Verified at registration rather than at export because a wrong slot number
    is a mistake the caller can still fix while they have the context in front
    of them. It also means the stored declaration is one that was true at least
    once, so a later export failure is drift rather than a typo.
    """
    out = []
    for locator in locators or ():
        if locator.get("kind") == registry.LOCATOR_ANCHOR_STRING:
            try:
                evidence = strloc.resolve_anchor_string(locator["string"])
            except Exception as exc:
                out.append((locator, "anchor string lookup failed: %s" % exc))
                continue
            if evidence["function_ea"] != func_ea:
                out.append((locator, "anchor string resolves to %s, not %s" % (
                    ea_str(evidence["function_ea"]), ea_str(func_ea)
                )))
            else:
                out.append((locator, None))
            continue
        if locator.get("kind") != registry.LOCATOR_VTABLE:
            out.append((locator, "unknown locator kind %r" % locator.get("kind")))
            continue
        try:
            ok, reason = rtti.verify_slot(
                locator["type"], locator["slot"], func_ea,
                locator.get("subobject_offset"),
            )
        except Exception as exc:
            out.append((locator, "vtable lookup failed: %s" % exc))
            continue
        out.append((locator, None if ok else reason))
    return out


def register(function_names=(), global_names=()):
    """Add names to this IDB's export set.

    An entry is a name, or an object carrying anchor sites:

        register(function_names=[
            "CCSPlayer_Think",
            {"name": "ui_toolkit_show_generic_popup_ok",
             "sites": [0x108C545]},
        ])

    A site is an address you have already determined identifies the function:
    an instruction that references it (a `call`, a `jmp`, or the `lea` that
    passes it to a registrar), or an instruction inside it to anchor a body
    pattern on. It exists because automatic discovery legitimately runs out of
    options -- a function whose only reference is from a vtable has no call
    site, and one belonging to a family of byte-identical clones has no unique
    prologue -- and when it does, the address you found by hand is the only
    evidence left.

    What a site is **not** is a signature. The exporter re-decodes it, re-
    derives what it references, and refuses it if that is not this function;
    then it builds and uniqueness-checks a pattern exactly as it would for a
    discovered anchor. You supply where to look; the database supplies the
    answer. A refused site is reported in `unresolved` and in the export's
    `advisory` list -- it never silently exports something else.

    Names are validated for shape and checked against the database now, so a
    typo is reported at registration instead of silently producing nothing at
    export time. Registration itself does no analysis and is cheap.
    """
    existing = set(store.load_registry())
    stored_sites = store.load_sites()
    stored_locators = store.load_locators()
    added, already, unresolved = [], [], []
    site_count = 0
    locator_count = 0

    for kind, names in (
        (registry.KIND_FUNCTION, function_names),
        (registry.KIND_GLOBAL, global_names),
    ):
        ids, entry_sites, entry_locators, bad = registry.normalize_entries(
            kind, names
        )
        unresolved.extend(bad)
        for iid in ids:
            name = registry.parse_entry_id(iid)[1]
            ea, error = _resolve(kind, name)
            if error is not None:
                unresolved.append({"kind": kind, "name": name, "reason": error})
                continue

            sites = entry_sites.get(iid, ())
            if sites and kind != registry.KIND_FUNCTION:
                unresolved.append({
                    "kind": kind, "name": name,
                    "reason": "sites apply to functions only; a global is "
                              "anchored from its data references",
                })
            elif sites:
                merged = list(stored_sites.get(iid, ()))
                merged.extend(s for s in sites if s not in merged)
                stored_sites[iid] = merged
                site_count += len(sites)

            # A locator is verified *now*, against the RTTI in this database,
            # so a wrong slot number is a registration error the caller sees
            # while they are still looking at it -- not a silently useless
            # export later, and never a locator that resolves to a different
            # function than the one being registered.
            for locator, reason in _verify_locators(
                entry_locators.get(iid, ()), ea
            ):
                if reason is not None:
                    unresolved.append({
                        "kind": kind, "name": name, "reason": reason,
                    })
                    continue
                kept = [
                    x for x in stored_locators.get(iid, ())
                    if x["kind"] != locator["kind"]
                ]
                kept.append(locator)
                stored_locators[iid] = kept
                locator_count += 1

            if iid in existing:
                already.append(name)
                continue
            existing.add(iid)
            added.append(name)

    if not store.save_registry(existing):
        return _result(error="could not persist the export set to the IDB",
                       unresolved=unresolved, added=0, already=0, total=0)
    if site_count and not store.save_sites(stored_sites):
        # The names are in; saying the sites are too would be a lie the
        # caller only discovers as a mysteriously unanchored export.
        unresolved.append({
            "kind": registry.KIND_FUNCTION, "name": "<sites>",
            "reason": "the export set was saved but its anchor sites were not",
        })
    if locator_count and not store.save_locators(stored_locators):
        unresolved.append({
            "kind": registry.KIND_FUNCTION, "name": "<locators>",
            "reason": "the export set was saved but its structural locators "
                      "were not",
        })

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
        sites=site_count,
        locators=locator_count,
        total=len(existing),
    )


def unregister(function_names=(), global_names=()):
    """Remove names from the export set. Absent names are not an error."""
    existing = set(store.load_registry())
    stored_sites = store.load_sites()
    stored_locators = store.load_locators()
    removed = []

    for kind, names in (
        (registry.KIND_FUNCTION, function_names),
        (registry.KIND_GLOBAL, global_names),
    ):
        ids, _bad = registry.normalize(kind, names)
        for iid in ids:
            # Sites and locators go with the entry: leaving them behind would
            # silently re-attach them if the same name were registered again
            # later, with evidence the caller believes they removed.
            stored_sites.pop(iid, None)
            stored_locators.pop(iid, None)
            if iid in existing:
                existing.discard(iid)
                removed.append(registry.parse_entry_id(iid)[1])

    if not store.save_registry(existing):
        return _result(error="could not persist the export set to the IDB",
                       removed=0, total=0)
    store.save_sites(stored_sites)
    store.save_locators(stored_locators)
    return _result(ok=True, removed=len(removed),
                   removed_names=sorted(removed), total=len(existing))


def clear():
    """Empty the export set."""
    if not store.save_registry([]):
        return _result(error="could not persist the export set")
    store.save_sites({})
    store.save_locators({})
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

    sites = {}
    for iid, eas in store.load_sites().items():
        try:
            sites[registry.parse_entry_id(iid)[1]] = [ea_str(ea) for ea in eas]
        except registry.RegistryError:
            continue

    locators = {}
    for iid, entries in store.load_locators().items():
        try:
            locators[registry.parse_entry_id(iid)[1]] = list(entries)
        except registry.RegistryError:
            continue

    resolved = len(ids) - len(unresolved)
    ok, partial = registry.outcome(len(ids), resolved, unresolved)
    return _result(
        ok=ok, partial=partial,
        unresolved=unresolved,
        functions=by_kind[registry.KIND_FUNCTION],
        globals=by_kind[registry.KIND_GLOBAL],
        sites=sites,
        locators=locators,
        declared_members=[d.qualified for d in store.load_all()],
        counts={
            "functions": len(by_kind[registry.KIND_FUNCTION]),
            "globals": len(by_kind[registry.KIND_GLOBAL]),
            "members": store.count(),
        },
    )

