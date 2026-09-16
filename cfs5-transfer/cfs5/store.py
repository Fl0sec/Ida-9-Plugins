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


# "$ " is the documented prefix for private plugin netnodes: it cannot collide
# with an identifier-shaped name in the database.
_NODE_PREFIX = "$ cfs6 declaration "
_INDEX_NODE = "$ cfs6 declarations"

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
