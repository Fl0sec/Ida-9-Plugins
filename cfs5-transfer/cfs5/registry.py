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
    """(id, sites) for one entry, which may be a name or an object.

    An entry is either `"Name"` or `{"name": "Name", "sites": [...]}`. The
    object form exists for the case discovery cannot serve: when no prologue,
    call site or body window is unique, the only thing left is the anchor the
    caller found for itself, and there has to be a way to hand it over.
    """
    if isinstance(entry, dict):
        name = entry.get("name")
        sites = normalize_sites(entry.get("sites", ()))
    else:
        name, sites = entry, []
    return entry_id(kind, name), sites


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
    """(ids, sites_by_id, rejected) for a batch, order-stable, deduplicated.

    Never raises on a bad member of the batch: an agent registering fifty
    names should learn which two were wrong and keep the other forty-eight,
    not lose the call. Rejections carry a reason for the same reason.
    """
    ids = []
    seen = set()
    sites_by_id = {}
    rejected = []

    for entry in entries or ():
        try:
            iid, sites = normalize_entry(kind, entry)
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

    return ids, sites_by_id, rejected


def normalize(kind, names):
    """(ids, rejected) for a batch, ignoring any sites the entries carry."""
    ids, _sites, rejected = normalize_entries(kind, names)
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
