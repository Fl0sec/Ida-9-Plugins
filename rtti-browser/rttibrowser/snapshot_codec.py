"""IDA-free snapshot encoding and commit-marker verification."""

import hashlib
import json

from .model import Snapshot, SnapshotError


class SnapshotCodecError(ValueError):
    """Snapshot bytes or their commit marker cannot be trusted."""


def json_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")


def writing_marker():
    return json_bytes({"state": "writing"})


def encode(snapshot):
    raw = json_bytes(snapshot.to_dict())
    checksum = hashlib.sha256(raw).hexdigest()
    marker = json_bytes({"state": "complete", "sha256": checksum})
    return raw, marker


def decode(raw, marker_raw):
    if not raw or not marker_raw:
        raise SnapshotCodecError("snapshot marker or payload is missing")
    try:
        marker = json.loads(marker_raw.decode("utf-8"))
    except Exception as exc:
        raise SnapshotCodecError("snapshot marker is not valid JSON") from exc
    if not isinstance(marker, dict) or marker.get("state") != "complete":
        raise SnapshotCodecError("snapshot commit is incomplete")
    checksum = marker.get("sha256")
    if not isinstance(checksum, str):
        raise SnapshotCodecError("snapshot checksum is missing")
    if hashlib.sha256(raw).hexdigest() != checksum:
        raise SnapshotCodecError("snapshot checksum mismatch")
    try:
        value = json.loads(raw.decode("utf-8"))
        return Snapshot.from_dict(value)
    except (SnapshotError, ValueError, UnicodeDecodeError) as exc:
        raise SnapshotCodecError("snapshot payload is unusable: %s" % exc) from exc
