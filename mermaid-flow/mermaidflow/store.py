"""Per-function persistence of Mermaid source in the IDB.

One flowchart per function, stored as the blob of a netnode named after the
function's start address, so it travels with the IDB and comes back when the
database is reopened.

**Why one netnode per function, with the blob at index 0.** The obvious design
-- a single shared netnode with `setblob_ea(source, func_ea, tag)` -- does not
work in IDA 9.0. It was measured, not assumed: `setblob_ea` returns True while
the matching `getblob_ea` returns nothing, for payloads as small as 21 bytes,
with the tag passed as a str and as an int alike, and a plain `getblob` at the
same raw index is empty too. The netnode itself is valid. Whatever `setblob_ea`
writes, it is not where the address says it is.

So this follows the shape IDA's own shipped example uses and proves works
(`python/examples/decompiler/vds3.py`): construct an unnamed netnode, `create`
it by name, and read and write the blob at **index 0**.

Keeping the blob at index 0 of a private node also avoids a collision the
address-indexed design carried: a blob spans *consecutive* supval indices from
its start, MAXSPECSIZE (1024) bytes each, so a 1581-byte chart stored "at"
0x4160 also claimed the slot for 0x4161.

If this ever needs to become a named graph library (several charts per
function, or charts belonging to the whole binary), add an index netnode
listing the members and give each chart its own node as here. Nothing below
needs to change for that.
"""

import ida_funcs
import ida_netnode

from .common import BADADDR, ea_str, msg


# Per-function netnode name. The "$ " prefix is the documented convention for
# private plugin netnodes -- it cannot collide with an identifier-shaped name.
NODE_PREFIX = "$ mermaid flowchart "

# Blob tag. One of the 256 supval arrays a netnode may carry; ours alone.
BLOB_TAG = "M"

# The blob always lives at index 0 of its own netnode. Never an address: see
# the module docstring.
BLOB_INDEX = 0

ENCODING = "utf-8"


def node_name(func_ea):
    return "%s0x%X" % (NODE_PREFIX, func_ea)


def _open(func_ea):
    """Bind a netnode for this function, creating it if needed.

    Mirrors the vds3.py idiom: `create` returns False when the node already
    existed, but the object is bound either way, which is all we need.
    """
    try:
        node = ida_netnode.netnode()
        node.create(node_name(func_ea))
        return node
    except Exception as exc:
        msg("storage: cannot open netnode for %s: %s" % (ea_str(func_ea), exc))
        return None


def _exists(func_ea):
    try:
        return ida_netnode.netnode.exist(node_name(func_ea))
    except Exception as exc:
        msg("storage: exist() failed for %s: %s" % (ea_str(func_ea), exc))
        return False


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
    if not _exists(func_ea):
        return None

    node = _open(func_ea)
    if node is None:
        return None

    try:
        blob = node.getblob(BLOB_INDEX, BLOB_TAG)
    except Exception as exc:
        msg("storage: getblob failed for %s: %s" % (ea_str(func_ea), exc))
        return None

    if not blob:
        msg("storage: netnode %r exists but its blob is empty."
            % node_name(func_ea))
        return None

    try:
        return blob.decode(ENCODING)
    except Exception as exc:
        msg("storage: blob for %s is not valid %s: %s"
            % (ea_str(func_ea), ENCODING, exc))
        return None


def save(func_ea, source):
    """Store the Mermaid source for a function, verifying the read-back.

    Returns True only when a subsequent `load` will actually find the data.
    The verification is not paranoia: `setblob` returning True is exactly what
    the broken address-indexed scheme did while storing nothing retrievable.
    """
    node = _open(func_ea)
    if node is None:
        return False

    data = source.encode(ENCODING)
    try:
        node.setblob(data, BLOB_INDEX, BLOB_TAG)
    except Exception as exc:
        msg("storage: setblob raised for %s: %s" % (ea_str(func_ea), exc))
        return False

    if load(func_ea) == source:
        msg("storage: stored %d bytes for %s (verified)."
            % (len(data), ea_str(func_ea)))
        return True

    msg("storage: write to %r did not survive a read-back."
        % node_name(func_ea))
    return False


def delete(func_ea):
    """Remove the stored flowchart for a function."""
    if not _exists(func_ea):
        return False
    node = _open(func_ea)
    if node is None:
        return False
    try:
        node.kill()          # drops the netnode and everything attached
        return True
    except Exception as exc:
        msg("storage: kill failed for %s: %s" % (ea_str(func_ea), exc))
        return False


def has(func_ea):
    return load(func_ea) is not None
