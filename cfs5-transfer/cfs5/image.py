"""Source-image identity and .pdata ownership, read from the IDB itself.

The IDB is the source of truth. When the PE headers are mapped (IDA's `HEADER`
segment, which is present for a normal PE load), both the header identity and
the `.pdata` runtime-function table are read straight out of the database: no
dependency on the original file still sitting on disk, and what we record is
exactly what is loaded. Reading the file from disk is only a fallback for an
IDB whose headers were not mapped.

Everything here is diagnostics except the `.pdata` ownership classification,
which decides whether a BODY candidate is resolvable by a non-IDA consumer.
"""

import os

import ida_bytes
import ida_nalt
import ida_segment

from .common import msg
from .peinfo import PdataIndex, PeImage, detect_build_from_path


# IDA names the mapped PE header segment "HEADER" for a PE load.
_HEADER_SEGMENT = "HEADER"
_PDATA_SEGMENT = ".pdata"

# Distinguishes "caller did not pass a view" from "there is no view".
_UNSET = object()


def get_imagebase():
    """The IDB's load base. EA - imagebase == RVA."""
    try:
        return int(ida_nalt.get_imagebase())
    except Exception as exc:
        msg("IMAGE_BASE_FAILED: %s (assuming 0)" % exc)
        return 0


def get_input_path():
    try:
        return ida_nalt.get_input_file_path() or ""
    except Exception:
        return ""


def get_input_name():
    path = get_input_path()
    if path:
        return os.path.basename(path)
    try:
        return ida_nalt.get_root_filename() or "unknown"
    except Exception:
        return "unknown"


def idb_sha256():
    """The input file's digest as recorded by IDA at load time."""
    try:
        raw = ida_nalt.retrieve_input_file_sha256()
    except Exception:
        return None
    if not raw:
        return None
    try:
        return bytes(raw).hex()
    except Exception:
        return None


def _headers_are_mapped(imagebase):
    """True when the PE headers are readable at the image base."""
    try:
        if ida_segment.get_segm_by_name(_HEADER_SEGMENT) is not None:
            return True
    except Exception:
        pass
    # Some loaders name it differently; fall back to probing for "MZ".
    try:
        return ida_bytes.get_bytes(imagebase, 2) == b"MZ"
    except Exception:
        return False


def _idb_reader(imagebase):
    """An RVA-addressed reader over the loaded image."""
    def read(rva, size):
        if size <= 0:
            return b""
        try:
            return ida_bytes.get_bytes(imagebase + rva, size)
        except Exception:
            return None
    return read


def open_image_view():
    """(PeImage or None, source_label).

    Prefers the IDB's mapped headers; falls back to the input file on disk.
    """
    imagebase = get_imagebase()

    if _headers_are_mapped(imagebase):
        try:
            view = PeImage.from_rva_reader(
                _idb_reader(imagebase), name=get_input_name()
            )
            return view, "idb"
        except Exception as exc:
            msg("IMAGE_NOTE: mapped headers unusable (%s); trying the input "
                "file on disk" % exc)

    path = get_input_path()
    if path and os.path.isfile(path):
        try:
            return PeImage.from_path(path), "file"
        except Exception as exc:
            msg("IMAGE_NOTE: could not parse %s (%s)" % (path, exc))
    else:
        # Name the path that was tried -- IDA records the path the binary was
        # loaded from, which is often not where it lives now.
        msg("IMAGE_NOTE: no mapped %s segment, and the recorded input path is "
            "unavailable (%s)"
            % (_HEADER_SEGMENT, path or "<none recorded>"))

    return None, "none"


def open_pdata_index(view=_UNSET, imagebase=None):
    """(PdataIndex, source_label).

    The RUNTIME_FUNCTION table does not need the PE headers: when they are not
    mapped, IDA usually still exposes a `.pdata` segment, which is the table
    verbatim. That path keeps BODY candidates resolvable for a non-IDA consumer
    on IDBs loaded without headers.
    """
    if view is _UNSET:
        view, _source = open_image_view()

    if view is not None:
        try:
            index = view.pdata_index
            if index.count:
                return index, "headers"
        except Exception as exc:
            msg("PDATA_NOTE: header-directed .pdata unreadable (%s)" % exc)

    if imagebase is None:
        imagebase = get_imagebase()

    try:
        seg = ida_segment.get_segm_by_name(_PDATA_SEGMENT)
        if seg is not None and seg.end_ea > seg.start_ea:
            raw = ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
            if raw:
                # Segment content is RVA-relative like the directory table.
                index = PdataIndex.from_bytes(raw)
                if index.count:
                    return index, "segment"
    except Exception as exc:
        msg("PDATA_NOTE: %s segment unreadable (%s)" % (_PDATA_SEGMENT, exc))

    return PdataIndex(), "none"


def describe_image(view=_UNSET, source=None):
    """(image_object, notes) for the CFS6 header."""
    if view is _UNSET:
        view, source = open_image_view()

    name = get_input_name()
    sha = idb_sha256()

    if view is not None:
        # A mapped image has no file bytes to hash, so use the IDB's record;
        # for a file view prefer its own digest and fall back to the IDB's.
        digest = sha if view.virtual else (view.sha256() or sha)
        return view.identity(name=name, sha256=digest), []

    # Degraded but still self-describing. Explicit nulls beat invented numbers.
    return {
        "name": name,
        "format": "PE",
        "architecture": None,
        "timestamp": None,
        "size_of_image": None,
        "sha256": sha,
    }, ["PE headers unavailable; recorded IDB metadata only"]


def detect_build():
    """(number_or_None, source) guessed from the input file's path."""
    return detect_build_from_path(get_input_path())


class BodyOwnership:
    """Classifies whether a BODY anchor is resolvable from `.pdata` alone.

    IDA's idea of a function's extent and the PE's RUNTIME_FUNCTION table do
    not always agree: a chunked/outlined function spans several .pdata entries,
    so its IDA start is not the .pdata begin the body actually lives in. A
    non-IDA consumer resolves BODY purely from .pdata, so a candidate it could
    never resolve must be labelled `ida-only` rather than claiming `pdata` and
    failing silently downstream.
    """

    def __init__(self, index=None, imagebase=0, source="none"):
        self.index = index if index is not None else PdataIndex()
        self.imagebase = int(imagebase)
        self.source = source
        self.available = self.index.count > 0
        if not self.available:
            msg("PDATA_UNAVAILABLE: BODY candidates will be labelled ida-only "
                "(a .pdata-based consumer cannot resolve them)")

    @classmethod
    def for_current_idb(cls, view=_UNSET, imagebase=None):
        if imagebase is None:
            imagebase = get_imagebase()
        index, source = open_pdata_index(view, imagebase)
        return cls(index, imagebase, source)

    def primary_span(self, func_ea):
        """(start_ea, end_ea) of the .pdata range that begins at func_ea.

        IDA's function body routinely spans several RUNTIME_FUNCTION entries
        (the compiler splits unwind ranges), and only the one *starting* at the
        function can be resolved back to it by a .pdata consumer. Body anchors
        picked inside this span stay externally resolvable.
        """
        if not self.available:
            return None
        try:
            start_rva = int(func_ea) - self.imagebase
            owning = self.index.containing(start_rva)
            if owning is None or owning[0] != start_rva:
                return None
            return (owning[0] + self.imagebase, owning[1] + self.imagebase)
        except Exception:
            return None

    def classify(self, func_ea, anchor_ea):
        """'pdata' when an external consumer can recover func_ea from a hit."""
        if not self.available:
            return "ida-only"
        try:
            start_rva = int(func_ea) - self.imagebase
            anchor_rva = int(anchor_ea) - self.imagebase
            if not self.index.is_start(start_rva):
                return "ida-only"
            owning = self.index.containing(anchor_rva)
            if owning is None or owning[0] != start_rva:
                return "ida-only"
            return "pdata"
        except Exception:
            return "ida-only"
