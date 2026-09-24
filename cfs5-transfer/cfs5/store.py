"""Persistence for declarations, in the IDB.

Declarations live in the database, not only in an exported file. A member's
candidate quality improves as more of the binary gets typed, so an export is a
*view* of the declarations at a moment in time; re-exporting a week later
should pick up the better evidence without the user re-declaring anything.

Layout: one netnode per declaration, holding its JSON in the blob at index 0,
plus one index netnode holding the list of declaration ids so they can be
enumerated. The blob-at-index-0-of-its-own-node shape is not a stylistic
choice -- it is the one that was measured to work in IDA 9.0, where
`setblob_ea` reports success and then reads back empty (see
`mermaid-flow/mermaidflow/store.py` for the full account).

Every write is verified by reading it back. A declaration that silently failed
to store would show up much later as a member missing from an export, with
nothing to point at.
"""

import json

import ida_netnode

from .common import msg
from .declare import DeclarationError, from_dict
from .patchdecl import from_dict as patch_from_dict


# "$ " is the documented prefix for private plugin netnodes: it cannot collide
# with an identifier-shaped name in the database.
_NODE_PREFIX = "$ cfs6 declaration "
_INDEX_NODE = "$ cfs6 declarations"
_PATCH_INDEX_NODE = "$ cfs6 patches"
# The export set (registry.py entry ids). One node holding one JSON list --
# it is pure identity, so unlike a declaration there is nothing to shard.
_REGISTRY_NODE = "$ cfs6 export set"
# Explicit anchor sites for registered functions: {entry_id: [ea, ...]}. Kept
# in a separate node from the export set so a plugin that does not know about
# sites still reads and writes the set correctly.
_SITES_NODE = "$ cfs6 export sites"
# Structural locator declarations: {entry_id: [locator, ...]}. Its own node for
# the same reason as the sites node -- a build that does not know about
# locators still reads and writes the export set correctly.
_LOCATORS_NODE = "$ cfs6 export locators"

_BLOB_TAG = "D"
_BLOB_INDEX = 0
_ENCODING = "utf-8"


def _open(name):
    try:
        node = ida_netnode.netnode()
        node.create(name)
        return node
    except Exception as exc:
        msg("STORE: cannot open netnode %r: %s" % (name, exc))
        return None


def _exists(name):
    try:
        return ida_netnode.netnode.exist(name)
    except Exception as exc:
        msg("STORE: exist(%r) failed: %s" % (name, exc))
        return False


def _read_json(name):
    if not _exists(name):
        return None
    node = _open(name)
    if node is None:
        return None
    try:
        blob = node.getblob(_BLOB_INDEX, _BLOB_TAG)
    except Exception as exc:
        msg("STORE: getblob(%r) failed: %s" % (name, exc))
        return None
    if not blob:
        return None
    try:
        return json.loads(blob.decode(_ENCODING))
    except Exception as exc:
        msg("STORE: blob of %r is not valid JSON: %s" % (name, exc))
        return None


def _write_json(name, value):
    node = _open(name)
    if node is None:
        return False
    raw = json.dumps(value, separators=(",", ":")).encode(_ENCODING)
    try:
        node.setblob(raw, _BLOB_INDEX, _BLOB_TAG)
    except Exception as exc:
        msg("STORE: setblob(%r) raised: %s" % (name, exc))
        return False
    if _read_json(name) != value:
        msg("STORE: write to %r did not survive a read-back" % name)
        return False
    return True


def _node_name(decl_id):
    return _NODE_PREFIX + decl_id


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------

def _load_index():
    value = _read_json(_INDEX_NODE)
    if not isinstance(value, list):
        return []
    return [x for x in value if isinstance(x, str) and x]


def _save_index(ids):
    return _write_json(_INDEX_NODE, sorted(set(ids)))


# ---------------------------------------------------------------------------
# The export set
# ---------------------------------------------------------------------------

def load_registry():
    """Registered entry ids, sorted. Never raises -- absent reads as empty."""
    value = _read_json(_REGISTRY_NODE)
    if not isinstance(value, list):
        return []
    return sorted({x for x in value if isinstance(x, str) and x})


def save_registry(entry_ids):
    """Replace the export set. Returns True only if the read-back agrees.

    Callers treat a False as "nothing was registered", so the verification is
    not optional: an agent that is told it registered fifty items and finds
    none of them at export time has no way to tell which step lied.
    """
    wanted = sorted({x for x in entry_ids or () if isinstance(x, str) and x})
    if not _write_json(_REGISTRY_NODE, wanted):
        return False
    if load_registry() != wanted:
        msg("STORE: export set write-back verification failed")
        return False
    return True


def load_sites():
    """{entry_id: [ea, ...]} for registered entries. Absent reads as empty."""
    value = _read_json(_SITES_NODE)
    if not isinstance(value, dict):
        return {}
    out = {}
    for key, eas in value.items():
        if not isinstance(key, str) or not isinstance(eas, list):
            continue
        clean = [int(x) for x in eas if isinstance(x, int)]
        if clean:
            out[key] = clean
    return out


def save_sites(mapping):
    """Replace the stored sites. Verified by read-back, like the export set."""
    wanted = {
        str(k): sorted({int(x) for x in v})
        for k, v in (mapping or {}).items() if v
    }
    if not _write_json(_SITES_NODE, wanted):
        return False
    if load_sites() != wanted:
        msg("STORE: export-site write-back verification failed")
        return False
    return True


def load_locators():
    """{entry_id: [locator, ...]} for registered functions. Absent reads empty.

    Each locator is the dict `registry.normalize_vtable_locator` produced, so
    what comes back out is what the caller declared -- never a re-derived
    approximation of it.
    """
    value = _read_json(_LOCATORS_NODE)
    if not isinstance(value, dict):
        return {}
    out = {}
    for key, entries in value.items():
        if not isinstance(key, str) or not isinstance(entries, list):
            continue
        clean = [x for x in entries if isinstance(x, dict) and x.get("kind")]
        if clean:
            out[key] = clean
    return out


def save_locators(mapping):
    """Replace the stored locators. Verified by read-back, like the sites."""
    wanted = {}
    for key, entries in (mapping or {}).items():
        clean = [x for x in (entries or ()) if isinstance(x, dict) and x.get("kind")]
        if clean:
            wanted[str(key)] = clean
    if not _write_json(_LOCATORS_NODE, wanted):
        return False
    if load_locators() != wanted:
        msg("STORE: export-locator write-back verification failed")
        return False
    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def save(decl):
    """Store a declaration, adding it to the index. Returns True on success.

    Re-declaring the same id overwrites: the id is owner + name, so the user
    is editing the same thing, not creating a second one.
    """
    decl_id = decl.id
    if not _write_json(_node_name(decl_id), decl.to_dict()):
        return False
    if not _save_index(_load_index() + [decl_id]):
        msg("STORE: %s was written but the index update failed" % decl_id)
        return False
    msg("STORE: saved declaration %s" % decl_id)
    return True


def load(decl_id):
    """One declaration by id, or None (with a diagnostic) if unreadable."""
    data = _read_json(_node_name(decl_id))
    if data is None:
        return None
    try:
        return from_dict(data)
    except DeclarationError as exc:
        msg("STORE: declaration %s is unusable: %s" % (decl_id, exc))
        return None


def load_all():
    """Every stored declaration, id order.

    Ids whose node has gone missing are pruned from the index rather than
    reported forever: the node is the record, the index is a convenience.
    """
    ids = _load_index()
    out = []
    alive = []
    for decl_id in ids:
        decl = load(decl_id)
        if decl is None:
            msg("STORE: dropping stale index entry %s" % decl_id)
            continue
        alive.append(decl_id)
        out.append(decl)
    if alive != ids:
        _save_index(alive)
    return out


def save_patch(decl):
    if not _write_json(_node_name(decl.id), decl.to_dict()):
        return False
    return _write_json(_PATCH_INDEX_NODE, sorted(set(
        (_read_json(_PATCH_INDEX_NODE) or []) + [decl.id]
    )))


def load_patches():
    ids = _read_json(_PATCH_INDEX_NODE) or []
    out = []
    for iid in ids:
        data = _read_json(_node_name(iid))
        if data is None:
            continue
        try:
            out.append(patch_from_dict(data))
        except DeclarationError as exc:
            msg("STORE: patch %s is unusable: %s" % (iid, exc))
    return out


def delete_patch(patch_id):
    name = _node_name(patch_id)
    if _exists(name):
        node = _open(name)
        if node is not None:
            try:
                node.kill()
            except Exception as exc:
                msg("STORE: kill(%r) failed: %s" % (name, exc))
                return False
    ids = [i for i in (_read_json(_PATCH_INDEX_NODE) or []) if i != patch_id]
    return _write_json(_PATCH_INDEX_NODE, ids)


def delete(decl_id):
    """Remove a declaration and its index entry."""
    name = _node_name(decl_id)
    if _exists(name):
        node = _open(name)
        if node is not None:
            try:
                node.kill()
            except Exception as exc:
                msg("STORE: kill(%r) failed: %s" % (name, exc))
                return False
    _save_index([i for i in _load_index() if i != decl_id])
    msg("STORE: deleted declaration %s" % decl_id)
    return True


def count():
    return len(_load_index())
