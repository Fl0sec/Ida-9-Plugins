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

from . import declare
from . import export as _export
from . import members as _members
from . import registry
from . import rtti
from . import strloc
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


def _split_qualified(entry, key):
    """(owner, name) from "Owner::name" or from explicit dict keys."""
    if isinstance(entry, str):
        owner, sep, name = entry.partition("::")
        if not sep:
            raise declare.DeclarationError(
                "%r is not qualified; write \"Owner::%s\"" % (entry, key)
            )
        return owner.strip(), name.strip()
    if not isinstance(entry, dict):
        raise declare.DeclarationError("%r is not a string or an object" % (entry,))
    owner = entry.get("owner")
    name = entry.get(key) or entry.get("name")
    if not owner or not name:
        raise declare.DeclarationError(
            "an object entry needs 'owner' and '%s'" % key
        )
    return owner, name


def declare_members(members_=(), discovery=declare.DISCOVER_SITES_ONLY):
    """Declare `member_offset` values, with explicit evidence sites.

    Each entry is either `"Owner::field"` or a dict:

        {"owner": "CModel", "member": "m_nBoneCount",
         "name": "bone_count",                 # optional export name
         "sites": [{"ea": 0x1234, "op": 1}],   # instruction + operand
         "value_adjust": 0}

    The sites are where *you* know the field is touched. They exist because
    IDA's member xref index is incomplete: correct pointer typing does not
    guarantee xrefs for a heap-backed object, so automatic discovery can
    legitimately find nothing however well typed the database is.

    What a site is **not** is a value. The offset still comes from the IDA
    member, and a site that decodes a different number is dropped. You supply
    where to look; the database supplies the answer.

    `discovery="sites_plus_auto"` keeps automatic scanning as well, which buys
    independent candidates at the cost of decompiling. The default uses only
    the sites given: deterministic, and fast.
    """
    stored, unresolved = [], []

    for entry in members_ or ():
        try:
            owner, member = _split_qualified(entry, "member")
            extra = entry if isinstance(entry, dict) else {}
            ref = _members.lookup_member(owner, member)
            if ref is None:
                raise declare.DeclarationError(
                    "%s::%s is not a field in this database -- a member_offset "
                    "requires a real IDA type and member" % (owner, member)
                )
            decl = declare.make_member(
                owner, extra.get("name") or member, member=member,
                sites=extra.get("sites", ()),
                discovery=extra.get("discovery", discovery),
                value_adjust=extra.get("value_adjust", 0),
            )
        except declare.DeclarationError as exc:
            unresolved.append({"kind": "member", "name": str(entry),
                               "reason": str(exc)})
            continue

        if not store.save(decl):
            unresolved.append({"kind": "member", "name": decl.qualified,
                               "reason": "could not be stored in the IDB"})
            continue
        stored.append(decl.qualified)

    ok, partial = registry.outcome(
        len(stored) + len(unresolved), len(stored), unresolved
    )
    msg("API: declared %d member(s), %d unresolved"
        % (len(stored), len(unresolved)))
    return _result(ok=ok, partial=partial, unresolved=unresolved,
                   declared=len(stored), declared_names=sorted(stored))


def declare_strides(strides=()):
    """Declare `element_stride` values: a constant encoded in code.

    Each entry is a dict, because a stride cannot be written as a bare name:

        {"owner": "CMeshDrawPrimitive", "name": "kStride", "value": 0x30,
         "sites": [{"ea": 0x1234, "op": 1}, ...]}

    Unlike a member offset there is no field in the database to read, so two
    things differ and both are deliberate. You assert the value, and every
    site you give must decode exactly it -- one that decodes something else
    rejects the whole declaration rather than exporting a number its own
    witnesses contradict. And there is no automatic discovery: nothing in the
    database associates an instruction with "the stride of this array", and
    finding other instructions holding the same number would be coincidence,
    not evidence.

    `owner` is a namespace here, not a claim that the type has such a field.
    """
    return _declare_asserted(strides, "stride", declare.make_stride)


def declare_constants(constants=()):
    """Declare `constant` values: a number that exists only in the code.

    Each entry is a dict, same shape as a stride:

        {"owner": "CEntityIdentityFlags", "name": "kModelChangeBlockedBit",
         "value": 0x6, "sites": [{"ea": 0x1234, "op": 1}, ...]}

    For a number that is not an offset and has no owning IDA field: a bit
    position tested by `bt reg, 6`, a sentinel compared against a field. The
    gate is the same as a stride's -- you assert the value, every site must
    decode exactly it, and there is no discovery, because nothing in the
    database associates an instruction with "this constant" and another
    instruction holding the same number would be coincidence, not evidence.

    A small immediate is more likely than a member offset to sit in an
    instruction whose surrounding bytes are not unique, and that refusal is
    kept: a non-unique pattern resolves to nothing on the consumer's side, so
    exporting it would publish a signature that cannot be used.

    `owner` is a namespace here, not a claim that the type has such a field.
    """
    return _declare_asserted(constants, "constant", declare.make_constant)


def _declare_asserted(entries, kind, make):
    """Shared body for the semantics whose value the caller asserts.

    A stride and a constant differ only in what a consumer does with the
    number: same entry shape, same validation, same export gate. One
    implementation keeps them from drifting apart for no reason.
    """
    stored, unresolved = [], []

    for entry in entries or ():
        try:
            owner, name = _split_qualified(entry, "name")
            if not isinstance(entry, dict):
                raise declare.DeclarationError(
                    "a %s needs a value and at least one site, so it cannot "
                    "be declared by name alone" % kind
                )
            if entry.get("value") is None:
                raise declare.DeclarationError(
                    "a %s must assert a 'value'" % kind
                )
            decl = make(
                owner, name, entry["value"], entry.get("sites", ()),
                value_adjust=entry.get("value_adjust", 0),
            )
        except declare.DeclarationError as exc:
            unresolved.append({"kind": kind, "name": str(entry),
                               "reason": str(exc)})
            continue

        if not store.save(decl):
            unresolved.append({"kind": kind, "name": decl.qualified,
                               "reason": "could not be stored in the IDB"})
            continue
        stored.append(decl.qualified)

    ok, partial = registry.outcome(
        len(stored) + len(unresolved), len(stored), unresolved
    )
    msg("API: declared %d %s(s), %d unresolved"
        % (len(stored), kind, len(unresolved)))
    return _result(ok=ok, partial=partial, unresolved=unresolved,
                   declared=len(stored), declared_names=sorted(stored))


def undeclare(names=()):
    """Remove declarations by qualified name (`"Owner::name"`) or stored id."""
    by_qualified = {d.qualified: d.id for d in store.load_all()}
    removed, unresolved = [], []

    for name in names or ():
        decl_id = by_qualified.get(name, name if str(name).count(":") else None)
        if decl_id is None:
            unresolved.append({"kind": "declaration", "name": str(name),
                               "reason": "not declared"})
            continue
        if store.delete(decl_id):
            removed.append(str(name))
        else:
            unresolved.append({"kind": "declaration", "name": str(name),
                               "reason": "could not be removed"})

    ok, partial = registry.outcome(
        len(removed) + len(unresolved), len(removed), unresolved
    )
    return _result(ok=ok, partial=partial, unresolved=unresolved,
                   removed=len(removed), removed_names=sorted(removed))


def declarations():
    """Every stored declaration, with how it resolves right now."""
    out, unresolved = [], []
    for decl in store.load_all():
        entry = {
            "id": decl.id,
            "semantic": decl.semantic,
            "qualified": decl.qualified,
            "member": decl.member,
            "sites": [{"ea": ea_str(ea), "op": op} for ea, op in decl.sites],
            "discovery": decl.discovery,
            "asserted_value": decl.asserted_value,
            "value_adjust": decl.value_adjust,
        }
        if decl.needs_ida_member:
            ref = _members.lookup_member(decl.owner, decl.member)
            if ref is None:
                entry["offset"] = None
                unresolved.append({
                    "kind": "member", "name": decl.qualified,
                    "reason": "no live IDA field; the type changed under it",
                })
            else:
                entry["offset"] = ref.byte_offset
        out.append(entry)

    ok, partial = registry.outcome(len(out), len(out) - len(unresolved),
                                   unresolved)
    return _result(ok=ok, partial=partial, unresolved=unresolved,
                   declarations=out, count=len(out))


def _run_export(path, function_eas, global_eas, unresolved, merge, build,
                include_members, function_sites=None, function_locators=None):
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
        function_sites=function_sites,
        function_locators=function_locators,
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
        # Not failures: anchors that exist but could not be exported, and
        # sites that did not survive verification. An item can be exported
        # and still have something here worth reading.
        advisory=raw.get("advisory", []),
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
    function_eas, global_eas, sites, locators, unresolved = _collect(
        by_kind[registry.KIND_FUNCTION], by_kind[registry.KIND_GLOBAL],
        sites_by_id=store.load_sites(),
        locators_by_id=store.load_locators(),
    )
    return _run_export(path, function_eas, global_eas, unresolved,
                       merge, build, include_members, function_sites=sites,
                       function_locators=locators)


def export_list(path, function_names=(), global_names=(),
                merge=_export.MERGE_APPEND, build=None, include_members=False):
    """Export an explicit list, ignoring the registered set entirely.

    For the case where the agent already knows the whole list and has no use
    for persistence. Nothing here reads or writes the export set.

    Entries may carry `sites` or a `vtable` locator exactly as in `register`,
    so a one-shot export can hand over evidence without registering anything
    first.
    """
    function_eas, global_eas, sites, locators, unresolved = _collect(
        function_names, global_names
    )
    return _run_export(path, function_eas, global_eas, unresolved,
                       merge, build, include_members, function_sites=sites,
                       function_locators=locators)
