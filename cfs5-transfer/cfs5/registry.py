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


def normalize(kind, names):
    """(ids, rejected) for a batch, order-stable and deduplicated.

    Never raises on a bad member of the batch: an agent registering fifty
    names should learn which two were wrong and keep the other forty-eight,
    not lose the call. Rejections carry a reason for the same reason.
    """
    ids = []
    seen = set()
    rejected = []

    for name in names or ():
        try:
            iid = entry_id(kind, name)
        except RegistryError as exc:
            rejected.append({"name": name, "kind": kind, "reason": str(exc)})
            continue
        if iid not in seen:
            seen.add(iid)
            ids.append(iid)

    return ids, rejected


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
