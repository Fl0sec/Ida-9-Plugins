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

**Read-after-write, always.** `setblob_ea` returning True is not proof that
anything was stored: the SDK types its tag as `uchar` while `getblob_ea` types
its own as `char`, so the two SWIG typemaps need not agree on what the Python
value "M" means, and a write can land in a tag space the read never looks at.
Rather than guess which form is correct, every write is read straight back and
the tag pairings are tried until one genuinely round-trips. The winner is
cached and logged, so a storage problem announces itself in one line instead of
appearing later as "my flowchart vanished".
"""

import ida_funcs
import ida_netnode

from .common import BADADDR, ea_str, msg


# `$ `-prefixed names are the convention for private plugin netnodes.
NETNODE_NAME = "$ mermaid flowcharts"

# Blob tag. One character, ours alone within this netnode.
BLOB_TAG = "M"

ENCODING = "utf-8"

# The two ways the tag argument can plausibly be expressed.
_TAG_FORMS = (("str", BLOB_TAG), ("int", ord(BLOB_TAG)))

# (write form name, read form name) proven to round-trip in this session.
_known_forms = None


def _node(create=False):
    """Open the plugin's netnode, creating it only when about to write."""
    try:
        return ida_netnode.netnode(NETNODE_NAME, 0, create)
    except Exception as exc:
        msg("storage: netnode unavailable: %s" % exc)
        return None


def _node_index(node):
    try:
        return node.index()
    except Exception:
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


# ---------------------------------------------------------------------------
# Raw blob access
# ---------------------------------------------------------------------------

def _write(node, func_ea, data, tag):
    try:
        return bool(node.setblob_ea(data, func_ea, tag))
    except Exception as exc:
        msg("storage: setblob_ea(%s, tag=%r) raised: %s"
            % (ea_str(func_ea), tag, exc))
        return False


def _read(node, func_ea, tag):
    try:
        return node.getblob_ea(func_ea, tag)
    except Exception as exc:
        msg("storage: getblob_ea(%s, tag=%r) raised: %s"
            % (ea_str(func_ea), tag, exc))
        return None


def _write_read_pairs():
    """Every (write, read) tag pairing, the one known to work first."""
    pairs = [(wn, wt, rn, rt) for wn, wt in _TAG_FORMS for rn, rt in _TAG_FORMS]
    if _known_forms is not None:
        pairs.sort(key=lambda pair: (pair[0], pair[2]) != _known_forms)
    return pairs


def _read_forms():
    """Read tag forms, the one known to work first."""
    forms = list(_TAG_FORMS)
    if _known_forms is not None:
        forms.sort(key=lambda form: form[0] != _known_forms[1])
    return forms


def _remember(write_name, read_name, func_ea, size):
    global _known_forms
    pairing = (write_name, read_name)
    if _known_forms != pairing:
        _known_forms = pairing
        msg("storage: using %s-tag writes and %s-tag reads." % pairing)
    msg("storage: stored %d bytes for %s (verified by read-back)."
        % (size, ea_str(func_ea)))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load(func_ea):
    """Return the stored Mermaid source for a function, or None."""
    node = _node()
    if node is None:
        return None

    index = _node_index(node)
    if index is None or index == BADADDR:
        msg("storage: netnode %r does not exist yet (index=%s)."
            % (NETNODE_NAME, index if index is None else ea_str(index)))
        return None

    for read_name, read_tag in _read_forms():
        blob = _read(node, func_ea, read_tag)
        if not blob:
            continue
        if _known_forms is not None and read_name != _known_forms[1]:
            msg("storage: read succeeded with the %s tag form, not the "
                "expected %s." % (read_name, _known_forms[1]))
        try:
            return blob.decode(ENCODING)
        except Exception as exc:
            msg("storage: blob for %s is not valid %s: %s"
                % (ea_str(func_ea), ENCODING, exc))
            return None

    return None


def save(func_ea, source):
    """Store the Mermaid source for a function, verifying it can be read back.

    Returns True only when a subsequent `load` will actually find the data.
    """
    node = _node(create=True)
    if node is None:
        return False

    index = _node_index(node)
    if index is None or index == BADADDR:
        msg("storage: could not create netnode %r (index=%s)."
            % (NETNODE_NAME, index))
        return False

    data = source.encode(ENCODING)
    for write_name, write_tag, read_name, read_tag in _write_read_pairs():
        if not _write(node, func_ea, data, write_tag):
            continue
        echo = _read(node, func_ea, read_tag)
        if echo == data:
            _remember(write_name, read_name, func_ea, len(data))
            return True
        if echo:
            msg("storage: %s-write/%s-read returned %d bytes, expected %d."
                % (write_name, read_name, len(echo), len(data)))

    msg("storage: NO tag form round-tripped for %s (%d bytes). "
        "Run Mermaid -> Diagnose flowchart storage."
        % (ea_str(func_ea), len(data)))
    return False


def delete(func_ea):
    """Remove the stored flowchart for a function, in every tag form."""
    node = _node()
    if node is None:
        return False

    removed = False
    for _name, tag in _TAG_FORMS:
        try:
            if node.delblob_ea(func_ea, tag):
                removed = True
        except Exception as exc:
            msg("storage: delblob_ea(%s, tag=%r) raised: %s"
                % (ea_str(func_ea), tag, exc))
    return removed


def has(func_ea):
    return load(func_ea) is not None


# ---------------------------------------------------------------------------
# Diagnosis
# ---------------------------------------------------------------------------

def diagnose(func_ea):
    """Probe every part of the storage path and return report lines.

    Written to answer one question without a debugger: when a flowchart does
    not come back, is the netnode missing, is the tag pairing wrong, is the
    blob empty, or is the address different from the one it was stored under?
    """
    lines = []
    add = lines.append

    add("netnode name: %r" % NETNODE_NAME)
    add("function key: %s" % ea_str(func_ea))
    try:
        add("netnode.exist: %s" % ida_netnode.netnode.exist(NETNODE_NAME))
    except Exception as exc:
        add("netnode.exist raised: %s" % exc)

    reader = _node()
    add("index (create=False): %s"
        % (None if reader is None else _node_index(reader)))
    writer = _node(create=True)
    add("index (create=True):  %s"
        % (None if writer is None else _node_index(writer)))

    if writer is None:
        add("VERDICT: the netnode cannot be opened at all.")
        return lines

    probe = b"mermaid-storage-probe"
    add("")
    add("write/read matrix (probe of %d bytes):" % len(probe))
    working = []
    for write_name, write_tag, read_name, read_tag in _write_read_pairs():
        wrote = _write(writer, func_ea, probe, write_tag)
        echo = _read(writer, func_ea, read_tag)
        state = "MATCH" if echo == probe else (
            "%d bytes" % len(echo) if echo else "empty")
        add("  write %-3s -> read %-3s : setblob=%s, got %s"
            % (write_name, read_name, wrote, state))
        if echo == probe:
            working.append((write_name, read_name))

    # getblob (raw index) as a cross-check on the ea -> node index conversion.
    add("")
    for name, tag in _TAG_FORMS:
        try:
            raw = writer.getblob(func_ea, tag)
        except Exception as exc:
            raw = "raised: %s" % exc
        add("  getblob(index=%s, tag %s): %s"
            % (ea_str(func_ea), name,
               ("%d bytes" % len(raw)) if isinstance(raw, bytes) else raw))

    for _name, tag in _TAG_FORMS:
        try:
            writer.delblob_ea(func_ea, tag)
        except Exception:
            pass

    add("")
    if working:
        add("VERDICT: storage works with %s."
            % ", ".join("%s-write/%s-read" % pair for pair in working))
        add("If a real flowchart still does not come back, the address it was")
        add("stored under differs from %s." % ea_str(func_ea))
    else:
        add("VERDICT: no tag pairing round-trips. Blob storage is unusable")
        add("here; the source must move to supvals or a hash node instead.")
    return lines
