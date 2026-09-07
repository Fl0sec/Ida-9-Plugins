"""Per-function persistence of Mermaid source in the IDB.

One flowchart per function, keyed by the function's start address, stored as a
netnode blob so it travels with the IDB and comes back when the database is
reopened.

Deliberately the simplest thing that works. If this ever needs to grow into a
named graph library (several graphs per function, or graphs that belong to the
whole binary rather than one function), the shape to move to is a second
netnode holding `name -> source` with an optional function anchor, leaving this
one as the per-function index. Nothing here needs to change until that is
actually wanted.
"""

import ida_funcs
import ida_netnode

from .common import BADADDR, ea_str, msg


# `$ ` prefixed names are the convention for private plugin netnodes.
NETNODE_NAME = "$ mermaid flowcharts"

# Blob tag. One character, ours alone within this netnode.
BLOB_TAG = "M"

ENCODING = "utf-8"


def _node(create=False):
    """Open the plugin's netnode, creating it only when about to write."""
    try:
        return ida_netnode.netnode(NETNODE_NAME, 0, create)
    except Exception as exc:
        msg("netnode unavailable: %s" % exc)
        return None


def func_key(ea):
    """Normalise any address inside a function to that function's start_ea.

    Returns BADADDR when `ea` is not inside a function, so callers can give a
    precise diagnostic instead of silently storing against a stray address.
    """
    try:
        func = ida_funcs.get_func(ea)
    except Exception as exc:
        msg("get_func(%s) failed: %s" % (ea_str(ea), exc))
        return BADADDR
    return BADADDR if func is None else func.start_ea


def load(func_ea):
    """Return the stored Mermaid source for a function, or None."""
    node = _node()
    if node is None:
        return None
    try:
        blob = node.getblob_ea(func_ea, BLOB_TAG)
    except Exception as exc:
        msg("read failed for %s: %s" % (ea_str(func_ea), exc))
        return None
    if not blob:
        return None
    try:
        return blob.decode(ENCODING)
    except Exception as exc:
        msg("stored flowchart for %s is not valid %s: %s"
            % (ea_str(func_ea), ENCODING, exc))
        return None


def save(func_ea, source):
    """Store (or replace) the Mermaid source for a function. True on success."""
    node = _node(create=True)
    if node is None:
        return False
    try:
        return bool(node.setblob_ea(source.encode(ENCODING), func_ea, BLOB_TAG))
    except Exception as exc:
        msg("write failed for %s: %s" % (ea_str(func_ea), exc))
        return False


def delete(func_ea):
    """Remove the stored flowchart for a function. True if something went."""
    node = _node()
    if node is None:
        return False
    try:
        return bool(node.delblob_ea(func_ea, BLOB_TAG))
    except Exception as exc:
        msg("delete failed for %s: %s" % (ea_str(func_ea), exc))
        return False


def has(func_ea):
    return load(func_ea) is not None
