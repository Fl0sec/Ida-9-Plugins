"""Versioned, checksummed RTTI snapshots stored in one private netnode.

Netnodes do not provide transactions. The state blob is therefore a commit
marker: readers accept the snapshot only after a verified payload write is
followed by a verified ``complete`` marker.
"""

import json

import ida_ida
import ida_loader
import ida_nalt
import ida_netnode
import ida_segment

from .common import msg
from .snapshot_codec import (
    SnapshotCodecError, decode, encode, writing_marker,
)


_NODE_NAME = "$ rtti browser snapshot"
_STATE_TAG = "M"
_SNAPSHOT_TAG = "S"
_BLOB_INDEX = 0
_ENCODING = "utf-8"


def _open():
    try:
        node = ida_netnode.netnode()
        node.create(_NODE_NAME)
        return node
    except Exception as exc:
        msg("CACHE: cannot open netnode: %s" % exc)
        return None


def _read_blob(tag):
    try:
        if not ida_netnode.netnode.exist(_NODE_NAME):
            return None
        node = _open()
        return None if node is None else node.getblob(_BLOB_INDEX, tag)
    except Exception as exc:
        msg("CACHE: read %s failed: %s" % (tag, exc))
        return None


def _write_blob(tag, raw):
    node = _open()
    if node is None:
        return False
    try:
        node.setblob(raw, _BLOB_INDEX, tag)
    except Exception as exc:
        msg("CACHE: write %s failed: %s" % (tag, exc))
        return False
    if _read_blob(tag) != raw:
        msg("CACHE: write %s did not survive read-back" % tag)
        return False
    return True


def current_identity():
    """Return a rebase-independent identity for the current input and layout."""
    sha256 = ida_nalt.retrieve_input_file_sha256()
    md5 = ida_nalt.retrieve_input_file_md5()
    segments = []
    image_base = int(ida_nalt.get_imagebase())
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        if segment is None:
            continue
        segments.append([
            int(segment.start_ea) - image_base,
            int(segment.end_ea) - image_base,
            int(segment.type),
            int(segment.perm),
        ])
    return {
        "sha256": sha256.hex() if sha256 else "",
        "md5": md5.hex() if md5 else "",
        "processor": ida_ida.inf_get_procname() or "",
        "bitness": 64 if ida_ida.inf_is_64bit() else 32,
        "pointer_size": 8 if ida_ida.inf_is_64bit() else 4,
        "file_type": ida_loader.get_file_type_name() or "",
        "segments": segments,
    }


def can_persist(identity):
    return bool(identity.get("sha256") or identity.get("md5"))


def save(snapshot):
    """Commit a snapshot after verified marker, payload, and checksum writes."""
    if not can_persist(snapshot.identity):
        return False, "IDA has no stored input hash; keeping a session cache only"

    writing = writing_marker()
    if not _write_blob(_STATE_TAG, writing):
        return False, "could not write the incomplete-cache marker"

    raw, complete = encode(snapshot)
    if not _write_blob(_SNAPSHOT_TAG, raw):
        return False, "could not write and verify the snapshot"

    if not _write_blob(_STATE_TAG, complete):
        return False, "snapshot was written but could not be committed"
    state = json.loads(complete.decode(_ENCODING))
    checksum = state["sha256"]
    msg("CACHE: committed %d vtable(s), %d bytes, sha256=%s"
        % (len(snapshot.records), len(raw), checksum[:12]))
    return True, ""


def load(identity):
    """Return ``(snapshot, reason)``; never expose incomplete or stale data."""
    marker = _read_blob(_STATE_TAG)
    raw = _read_blob(_SNAPSHOT_TAG)
    try:
        snapshot = decode(raw, marker)
    except SnapshotCodecError as exc:
        return None, str(exc)
    if snapshot.identity != identity:
        return None, "input identity or segment layout changed"
    return snapshot, ""


def delete():
    """Delete a persisted snapshot after an explicit rescan request."""
    try:
        if not ida_netnode.netnode.exist(_NODE_NAME):
            return True
        node = _open()
        if node is None:
            return False
        node.kill()
        return True
    except Exception as exc:
        msg("CACHE: delete failed: %s" % exc)
        return False
