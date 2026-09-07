"""Per-function persistence of Mermaid source in the IDB.

One flowchart per function, stored as the blob of a netnode named after the
function's start address, so it travels with the IDB and comes back when the
database is reopened.

**Why one netnode per function, with the blob at index 0.** The obvious design
-- a single shared netnode with `setblob_ea(source, func_ea, tag)` -- does not
work in IDA 9.0. `setblob_ea` returns True and the matching `getblob_ea`
returns nothing, for payloads as small as 21 bytes, with the tag passed either
as a str or as an int; a plain `getblob` at the same raw index is empty too, so
the data is not where the address says it should be. That was measured, not
guessed (see `diagnose`, which still checks both shapes side by side).

So this follows the shape IDA's own shipped example uses and proves works
(`python/examples/decompiler/vds3.py`): construct an unnamed netnode, `create`
it by name, and read and write the blob at **index 0**. That also removes a
latent collision the address-indexed design had -- a blob spans *consecutive*
supval indices from its start, MAXSPECSIZE (1024) bytes each, so a 1581-byte
chart stored "at" 0x4160 also claimed the slot for 0x4161.

Nothing was ever successfully stored by the old scheme, so there is nothing to
migrate.

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

# Legacy shared netnode, kept only so `diagnose` can keep proving the old
# scheme fails. Never written to.
LEGACY_NODE_NAME = "$ mermaid flowcharts"


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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

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

    Returns True only when a subsequent `load` will actually find the data --
    `setblob` returning True is not, on its own, evidence that it did.
    """
    node = _open(func_ea)
    if node is None:
        return False

    data = source.encode(ENCODING)
    try:
        wrote = bool(node.setblob(data, BLOB_INDEX, BLOB_TAG))
    except Exception as exc:
        msg("storage: setblob raised for %s: %s" % (ea_str(func_ea), exc))
        return False

    echo = load(func_ea)
    if echo == source:
        msg("storage: stored %d bytes for %s in %r (verified)."
            % (len(data), ea_str(func_ea), node_name(func_ea)))
        return True

    msg("storage: write to %r reported %s but read back %s. "
        "Run Mermaid -> Diagnose flowchart storage."
        % (node_name(func_ea), wrote,
           "nothing" if echo is None else "%d chars" % len(echo)))
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


# ---------------------------------------------------------------------------
# Diagnosis
# ---------------------------------------------------------------------------

def diagnose(func_ea):
    """Probe both storage shapes and report which one actually round-trips."""
    lines = []
    add = lines.append
    probe = b"mermaid-storage-probe"

    add("function key: %s" % ea_str(func_ea))
    add("")
    add("A. per-function netnode, blob at index 0 (current scheme)")
    add("   name: %r" % node_name(func_ea))
    try:
        add("   exists before: %s" % _exists(func_ea))
    except Exception as exc:
        add("   exist() raised: %s" % exc)

    node = _open(func_ea)
    if node is None:
        add("   VERDICT: cannot open the netnode at all.")
        return lines

    add("   index: %s" % _index_str(node))
    preserved = None
    try:
        preserved = node.getblob(BLOB_INDEX, BLOB_TAG)
    except Exception:
        pass

    try:
        wrote = node.setblob(probe, BLOB_INDEX, BLOB_TAG)
        echo = node.getblob(BLOB_INDEX, BLOB_TAG)
        add("   setblob=%s, read back %s" % (wrote, _describe(echo)))
        scheme_a = echo == probe
    except Exception as exc:
        add("   raised: %s" % exc)
        scheme_a = False

    # Put back whatever was there, so diagnosing never costs a flowchart.
    try:
        if preserved:
            node.setblob(preserved, BLOB_INDEX, BLOB_TAG)
        else:
            node.delblob(BLOB_INDEX, BLOB_TAG)
    except Exception:
        pass

    add("")
    add("B. shared netnode, blob keyed by address (old scheme, for contrast)")
    scheme_b = False
    try:
        legacy = ida_netnode.netnode(LEGACY_NODE_NAME, 0, True)
        add("   index: %s" % _index_str(legacy))
        wrote = legacy.setblob_ea(probe, func_ea, BLOB_TAG)
        echo = legacy.getblob_ea(func_ea, BLOB_TAG)
        add("   setblob_ea=%s, getblob_ea %s" % (wrote, _describe(echo)))
        raw = legacy.getblob(func_ea, BLOB_TAG)
        add("   getblob at raw index %s: %s" % (ea_str(func_ea), _describe(raw)))
        scheme_b = echo == probe
        legacy.delblob_ea(func_ea, BLOB_TAG)
    except Exception as exc:
        add("   raised: %s" % exc)

    add("")
    if scheme_a:
        add("VERDICT: scheme A works. Flowcharts persist.")
    elif scheme_b:
        add("VERDICT: scheme A fails but B works -- revert to the shared node.")
    else:
        add("VERDICT: neither blob scheme round-trips here. Next step is to")
        add("chunk the source across supvals (setblob is then not involved).")
    return lines


def _index_str(node):
    try:
        return "0x%X" % node.index()
    except Exception as exc:
        return "unavailable (%s)" % exc


def _describe(blob):
    if blob is None:
        return "None"
    if not blob:
        return "empty"
    return "%d bytes" % len(blob)
