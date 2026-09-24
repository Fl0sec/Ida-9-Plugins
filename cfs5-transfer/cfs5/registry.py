"""The export set: which functions and globals the next export should cover.

Deliberately **free of any `ida_*` import** so the identity rules are unit
tested outside IDA, the same split `declare.py` uses for member declarations.

Two rules carry the design:

- **Entries store a name, never an address.** Re-deriving the address at export
  time is what lets a re-analysed or improved IDB produce a better export, and
  what makes a name that no longer exists *visible* instead of silently
  exporting whatever now sits at a remembered address. `declare.py` stores
  member identity for the same reason.
- **Ids share the CFS6 item namespace** (`cfs6.item_id`), so a registry entry
  and the record it eventually produces are the same string. Nothing has to
  translate between two naming schemes.

Members are not registered here: a member already has a richer persistent
declaration (`declare.py` + `store.py`), and an export takes every declaration
that exists.
"""

import re

from . import cfs6

KIND_FUNCTION = cfs6.REC_FUNCTION
KIND_GLOBAL = cfs6.REC_GLOBAL
VALID_KINDS = (KIND_FUNCTION, KIND_GLOBAL)

# The same shape the exporter's discovery heuristics already demand of a
# human-chosen name: a plain C identifier. Anything else is a mangled symbol,
# a demangled signature or an analyzer artifact, none of which an agent should
# be registering by hand.
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_PREFIX = {KIND_FUNCTION: "fn:", KIND_GLOBAL: "global:"}

# Locator kinds a caller may declare. Closed, and separate from the format's
# candidate modes: this names what the *caller asked for*, which the exporter
# must verify before it becomes a VTABLE candidate.
LOCATOR_VTABLE = "vtable"
VALID_LOCATOR_KINDS = (LOCATOR_VTABLE,)


class RegistryError(ValueError):
    """An entry that cannot be stored as written."""


def entry_id(kind, name):
    """The CFS6 item id this entry will produce. Raises on bad input."""
    if kind not in VALID_KINDS:
        raise RegistryError("unknown kind %r (expected one of %s)"
                            % (kind, ", ".join(VALID_KINDS)))
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise RegistryError(
            "%r is not a plain C identifier; register the name IDA shows, "
            "not a mangled or demangled symbol" % (name,)
        )
    return cfs6.item_id(kind, name)


def parse_entry_id(value):
    """(kind, name) for a stored id, or raise."""
    if isinstance(value, str):
        for kind, prefix in _PREFIX.items():
            if value.startswith(prefix):
                name = value[len(prefix):]
                if name:
                    return kind, name
    raise RegistryError("%r is not a registry entry id" % (value,))


# A site is an address in the current image, so unlike a name it cannot be
# re-derived later -- it is stored as given and re-verified at export time.
_NO_EA = 0xFFFFFFFFFFFFFFFF


def normalize_entry(kind, entry):
    """(id, sites, locators) for one entry, which may be a name or an object.

    An entry is either `"Name"` or an object carrying `sites` and/or locator
    declarations. Both object forms exist for the case discovery cannot serve:
    when no prologue, call site or body window is unique, the only thing left
    is evidence the caller found for itself, and there has to be a way to hand
    it over.

    `sites` and a locator answer different questions, which is why they are
    separate keys rather than one. A site says *where a pattern may be
    anchored* -- discovery still builds the signature. A locator says *how the
    function is found without a pattern at all*, which is the only thing that
    works for a member of a clone family.
    """
    if isinstance(entry, dict):
        name = entry.get("name")
        sites = normalize_sites(entry.get("sites", ()))
        locators = normalize_locators(entry)
    else:
        name, sites, locators = entry, [], []
    iid = entry_id(kind, name)
    if locators and kind != KIND_FUNCTION:
        raise RegistryError(
            "a structural locator names a function; %r is a %s" % (name, kind)
        )
    return iid, sites, locators


def normalize_locators(entry):
    """[locator, ...] declared on one entry. Raises on a malformed one.

    Declared through `register`, not a `declare_*` call, because `declare_*`
    takes an owner and produces a value; these produce a function address, so
    they belong beside `sites`.
    """
    out = []
    vtable = entry.get("vtable")
    if vtable is not None:
        out.append(normalize_vtable_locator(vtable))
    return out


def normalize_vtable_locator(spec):
    """A validated `{"type": ..., "slot": N}` declaration.

    `type` may be a plain class name or a raw MSVC descriptor; which one the
    caller passes is a convenience, and the exporter stores the raw descriptor
    it reads out of the image either way. Nothing here touches IDA -- this
    validates the *shape* of the claim, and `cfs5/sigs.py` verifies the claim
    itself against the RTTI table before anything is exported.
    """
    if not isinstance(spec, dict):
        raise RegistryError(
            "a vtable locator must be an object like "
            '{"type": "CCSPlayerInventory", "slot": 19}, got %r' % (spec,)
        )

    type_name = spec.get("type")
    if not isinstance(type_name, str) or not type_name.strip():
        raise RegistryError("a vtable locator needs a non-empty 'type'")

    if "slot" not in spec:
        raise RegistryError("a vtable locator needs a 'slot'")
    try:
        slot = int(spec["slot"])
    except (TypeError, ValueError):
        raise RegistryError("vtable slot %r is not an integer" % (spec["slot"],))
    if slot < 0:
        raise RegistryError("vtable slot must be >= 0, got %d" % slot)

    subobject = spec.get("subobject_offset")
    if subobject is not None:
        try:
            subobject = int(subobject)
        except (TypeError, ValueError):
            raise RegistryError(
                "subobject_offset %r is not an integer" % (subobject,)
            )
        if subobject < 0:
            raise RegistryError(
                "subobject_offset must be >= 0, got %d" % subobject
            )

    return {
        "kind": LOCATOR_VTABLE,
        "type": type_name.strip(),
        "slot": slot,
        "subobject_offset": subobject,
    }


def normalize_sites(sites):
    """[ea, ...] deduplicated and order-stable. Raises on anything else.

    Accepts a bare integer or `{"ea": ...}` so a caller can pass what it
    already has. Zero and BADADDR are dropped rather than stored: they are how
    "no address" arrives from IDA, and an export would otherwise try to decode
    an instruction at address zero and report a confusing rejection.
    """
    out = []
    seen = set()
    for site in sites or ():
        if isinstance(site, dict):
            value = site.get("ea")
        else:
            value = site
        if value is None:
            continue
        try:
            ea = int(value)
        except (TypeError, ValueError):
            raise RegistryError("site %r is not an address" % (site,))
        if ea == 0 or ea == _NO_EA:
            continue
        if ea not in seen:
            seen.add(ea)
            out.append(ea)
    return out


def normalize_entries(kind, entries):
    """(ids, sites_by_id, locators_by_id, rejected) for a batch.

    Order-stable and deduplicated. Never raises on a bad member of the batch:
    an agent registering fifty names should learn which two were wrong and keep
    the other forty-eight, not lose the call. Rejections carry a reason for the
    same reason.
    """
    ids = []
    seen = set()
    sites_by_id = {}
    locators_by_id = {}
    rejected = []

    for entry in entries or ():
        try:
            iid, sites, locators = normalize_entry(kind, entry)
        except RegistryError as exc:
            name = entry.get("name") if isinstance(entry, dict) else entry
            rejected.append({"name": name, "kind": kind, "reason": str(exc)})
            continue
        if iid not in seen:
            seen.add(iid)
            ids.append(iid)
        if sites:
            # Re-registering with more sites adds to them rather than
            # replacing: an agent that finds a second anchor should not have
            # to repeat the first one.
            merged = sites_by_id.setdefault(iid, [])
            merged.extend(s for s in sites if s not in merged)
        for locator in locators:
            # A re-declared locator of the same kind *replaces* the old one,
            # unlike sites. Two sites are two pieces of evidence; two vtable
            # slots for one function are a contradiction, and keeping both
            # would export a candidate the caller has just corrected.
            merged = locators_by_id.setdefault(iid, [])
            merged[:] = [x for x in merged if x["kind"] != locator["kind"]]
            merged.append(locator)

    return ids, sites_by_id, locators_by_id, rejected


def normalize(kind, names):
    """(ids, rejected) for a batch, ignoring sites and locators."""
    ids, _sites, _locators, rejected = normalize_entries(kind, names)
    return ids, rejected


def outcome(asked, succeeded, missed):
    """(ok, partial) for a batch, the one place that decides what `ok` means.

    `ok` is "everything asked for succeeded", never "something worked". An
    export that writes 51 of 52 items is not ok: an agent that checks `ok` and
    moves on would sail straight past the missing one, which is exactly how a
    silent attrition goes unnoticed. It is `partial` instead, and the caller
    has to look at what was missed to clear it.

    Lives here, ida-free, because it is the rule most worth pinning with a
    test -- the arithmetic is easy to get subtly wrong when it is inlined at
    four call sites.
    """
    asked, succeeded = int(asked), int(succeeded)
    missed_count = len(missed) if missed is not None else 0

    ok = succeeded == asked and missed_count == 0
    partial = (not ok) and succeeded > 0
    return ok, partial


def split_by_kind(ids):
    """{kind: [name, ...]} for stored ids, ignoring anything unparseable."""
    out = {kind: [] for kind in VALID_KINDS}
    for value in ids or ():
        try:
            kind, name = parse_entry_id(value)
        except RegistryError:
            continue
        out[kind].append(name)
    for names in out.values():
        names.sort()
    return out
