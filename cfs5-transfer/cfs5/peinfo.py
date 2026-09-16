"""Minimal, dependency-free PE reader: image identity, RVA mapping and .pdata.

Pure stdlib and **free of any `ida_*` import**. It backs three things:
the exporter's provenance header, the CFS6 reference resolver in
`tools/cfs6_resolve.py`, and the offline tests. Keeping one implementation
means the IDA side and the non-IDA side cannot disagree about what an RVA is.
"""

import bisect
import hashlib
import os
import re
import struct


_MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x86_64",
    0xAA64: "arm64",
    0x01C4: "arm",
}

# A build directory component: purely numeric and long enough not to be a
# version fragment or a disc number.
_BUILD_COMPONENT_RE = re.compile(r"^[0-9]{4,7}$")


class PeError(Exception):
    pass


class PdataIndex:
    """Sorted RUNTIME_FUNCTION ranges, queryable by RVA.

    Kept separate from `PeImage` because the table can be recovered without the
    PE headers -- an IDB may expose a `.pdata` segment while its `HEADER`
    segment was never mapped.
    """

    def __init__(self, entries=()):
        pairs = sorted(
            (int(b), int(e)) for b, e in entries if int(e) > int(b)
        )
        self._starts = [b for b, _e in pairs]
        self._ranges = pairs

    @classmethod
    def from_bytes(cls, table):
        """Parse a packed RUNTIME_FUNCTION array (12 bytes per entry)."""
        if not table:
            return cls()
        entries = []
        for i in range(len(table) // 12):
            begin, end, _unwind = struct.unpack_from("<III", table, i * 12)
            entries.append((begin, end))
        return cls(entries)

    def __len__(self):
        return len(self._starts)

    @property
    def count(self):
        return len(self._starts)

    def containing(self, rva):
        """The single range covering rva, or None.

        A gap between two functions belongs to neither -- it is never
        attributed to the preceding one.
        """
        if not self._starts:
            return None
        idx = bisect.bisect_right(self._starts, rva) - 1
        if idx < 0:
            return None
        begin, end = self._ranges[idx]
        return (begin, end) if begin <= rva < end else None

    def is_start(self, rva):
        idx = bisect.bisect_left(self._starts, rva)
        return idx < len(self._starts) and self._starts[idx] == rva


class PeImage:
    """A parsed PE, addressed by RVA.

    Two sources, one parser:

    * `from_path` / `from_bytes` -- a flat on-disk file. RVAs are translated to
      file offsets through the section table.
    * `from_rva_reader` -- an already-mapped image (IDA's IDB, where the PE
      headers live in the `HEADER` segment). RVAs are read directly, so no
      section translation is needed and nothing has to exist on disk.

    The header region is the same in both: a PE's headers sit at file offset 0
    and map to RVA 0, so header parsing is offset/RVA agnostic.
    """

    def __init__(self, data=None, name="", reader=None, header_size=0x1000):
        if reader is None and data is None:
            raise PeError("PeImage needs either data or a reader")
        self.data = data
        self.name = name
        self._reader = reader
        self.virtual = reader is not None
        if self.virtual:
            header = reader(0, header_size)
            if header is None:
                raise PeError("could not read the PE headers from the image")
            self._header = header
        else:
            self._header = data
        self._parse()

    @classmethod
    def from_path(cls, path):
        with open(path, "rb") as handle:
            return cls(handle.read(), name=os.path.basename(path))

    @classmethod
    def from_rva_reader(cls, reader, name="", header_size=0x1000):
        """`reader(rva, size) -> bytes|None` over a mapped image."""
        return cls(reader=reader, name=name, header_size=header_size)

    def _parse(self):
        data = self._header
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PeError("not a PE image (missing MZ signature)")

        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
            raise PeError("not a PE image (missing PE signature)")

        machine, nsections, timestamp = struct.unpack_from("<HHI", data, pe + 4)
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24

        magic = struct.unpack_from("<H", data, opt)[0]
        if magic == 0x20B:
            self.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
            dir_off = opt + 112
        elif magic == 0x10B:
            self.image_base = struct.unpack_from("<I", data, opt + 28)[0]
            dir_off = opt + 96
        else:
            raise PeError("unknown optional header magic 0x%X" % magic)

        self.machine = machine
        self.architecture = _MACHINE_NAMES.get(machine, "0x%04X" % machine)
        self.timestamp = timestamp
        self.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]

        self.sections = []
        sec_off = opt + opt_size
        for i in range(nsections):
            base = sec_off + i * 40
            if base + 40 > len(data):
                break
            raw = data[base:base + 40]
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", raw, 8)
            self.sections.append({
                "name": raw[:8].rstrip(b"\0").decode("ascii", "replace"),
                "vaddr": vaddr,
                "vsize": vsize,
                "rawptr": rawptr,
                "rawsize": rawsize,
                "characteristics": struct.unpack_from("<I", raw, 36)[0],
            })

        self._pdata_dir = struct.unpack_from("<II", data, dir_off + 3 * 8)
        self._pdata_index = None

    # -- address mapping ---------------------------------------------------

    def rva_to_offset(self, rva):
        """File offset for an RVA. Identity for a mapped (virtual) image."""
        if self.virtual:
            return rva
        for sec in self.sections:
            span = max(sec["vsize"], sec["rawsize"])
            if sec["vaddr"] <= rva < sec["vaddr"] + span:
                delta = rva - sec["vaddr"]
                if delta >= sec["rawsize"]:
                    return None
                return sec["rawptr"] + delta
        return None

    def offset_to_rva(self, offset):
        if self.virtual:
            return offset
        for sec in self.sections:
            if sec["rawsize"] and sec["rawptr"] <= offset < sec["rawptr"] + sec["rawsize"]:
                return sec["vaddr"] + (offset - sec["rawptr"])
        return None

    def is_executable_rva(self, rva):
        for sec in self.sections:
            span = max(sec["vsize"], sec["rawsize"])
            if sec["vaddr"] <= rva < sec["vaddr"] + span:
                return bool(sec["characteristics"] & 0x20000000)  # MEM_EXECUTE
        return False

    def read(self, rva, size):
        if self.virtual:
            return self._reader(rva, size)
        offset = self.rva_to_offset(rva)
        if offset is None or offset + size > len(self.data):
            return None
        return self.data[offset:offset + size]

    # -- .pdata ------------------------------------------------------------

    @property
    def pdata_index(self):
        if self._pdata_index is None:
            rva, size = self._pdata_dir
            # Read through self.read so a mapped image and a file behave alike.
            table = self.read(rva, size) if rva and size else None
            self._pdata_index = PdataIndex.from_bytes(table)
        return self._pdata_index

    @property
    def runtime_function_count(self):
        return self.pdata_index.count

    def runtime_function_containing(self, rva):
        return self.pdata_index.containing(rva)

    def is_runtime_function_start(self, rva):
        return self.pdata_index.is_start(rva)

    # -- identity ----------------------------------------------------------

    def sha256(self):
        """Digest of the input file. None for a mapped image (no file bytes)."""
        if self.virtual or self.data is None:
            return None
        return hashlib.sha256(self.data).hexdigest()

    def identity(self, name=None, sha256=None):
        """The CFS6 header `image` object.

        `sha256` overrides the computed digest -- a mapped image has no file
        bytes to hash, so the caller supplies the one the IDB recorded.
        """
        return {
            "name": name or self.name,
            "format": "PE",
            "architecture": self.architecture,
            "timestamp": self.timestamp,
            "size_of_image": self.size_of_image,
            "sha256": sha256 if sha256 is not None else self.sha256(),
        }


def detect_build_from_path(path):
    """(build_number, source) from an unambiguous numeric path component.

    Only a wholly numeric directory component counts, and only when exactly one
    such component exists -- a build number is never invented or guessed from a
    filename.
    """
    if not path:
        return None, "unknown"

    parts = [p for p in re.split(r"[\\/]+", str(path)) if p]
    # The filename itself is not a build directory.
    candidates = [p for p in parts[:-1] if _BUILD_COMPONENT_RE.match(p)]
    if len(candidates) != 1:
        return None, "unknown"
    return int(candidates[0]), "path-detected"
