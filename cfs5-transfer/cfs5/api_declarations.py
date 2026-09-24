"""Programmatic declaration storage and inspection."""

from . import declare
from . import members as _members
from . import patchdecl
from . import registry
from . import store
from .common import ea_str
from .api_result import result as _result

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


def declare_extents(extents=()):
    """Declare object extents derived from displacement + access width.

    Every site requires positive `access_width`; `alignment` defaults to 1.
    The exported consumer recipe is DISP_PLUS_WIDTH followed by align-up.
    """
    return _declare_asserted(extents, "extent", declare.make_extent)


def declare_patches(patches=()):
    """Declare instruction patch locations with validated original bytes."""
    stored, unresolved = [], []
    for entry in patches or ():
        try:
            if not isinstance(entry, dict):
                raise declare.DeclarationError("a patch declaration must be an object")
            decl = patchdecl.PatchDeclaration(
                entry.get("owner"), entry.get("name"), entry.get("site")
            )
        except (declare.DeclarationError, TypeError, ValueError) as exc:
            unresolved.append({"kind": "patch", "name": str(entry),
                               "reason": str(exc)})
            continue
        if not store.save_patch(decl):
            unresolved.append({"kind": "patch", "name": decl.qualified,
                               "reason": "could not be stored in the IDB"})
            continue
        stored.append(decl.qualified)
    ok, partial = registry.outcome(len(stored) + len(unresolved), len(stored), unresolved)
    return _result(ok=ok, partial=partial, unresolved=unresolved,
                   declared=len(stored), declared_names=sorted(stored))


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
            kwargs = {"value_adjust": entry.get("value_adjust", 0)}
            if kind == "stride":
                kwargs["recipe"] = entry.get("recipe")
            decl = make(owner, name, entry["value"], entry.get("sites", ()),
                        **kwargs)
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
    patch_ids = {d.qualified: d.id for d in store.load_patches()}
    by_qualified.update(patch_ids)
    removed, unresolved = [], []

    for name in names or ():
        decl_id = by_qualified.get(name, name if str(name).count(":") else None)
        if decl_id is None:
            unresolved.append({"kind": "declaration", "name": str(name),
                               "reason": "not declared"})
            continue
        delete = store.delete_patch if str(decl_id).startswith("patch:") else store.delete
        if delete(decl_id):
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
            "sites": [dict({"ea": ea_str(ea), "op": op},
                           **decl.site_options.get((ea, op), {}))
                      for ea, op in decl.sites],
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

    for decl in store.load_patches():
        out.append({
            "id": decl.id, "semantic": "patch", "qualified": decl.qualified,
            "site": {"ea": ea_str(decl.ea),
                     "expected_instruction": decl.expected_instruction,
                     "expected_bytes": decl.expected_bytes,
                     "patch_size": decl.patch_size},
        })

    ok, partial = registry.outcome(len(out), len(out) - len(unresolved),
                                   unresolved)
    return _result(ok=ok, partial=partial, unresolved=unresolved,
                   declarations=out, count=len(out))

