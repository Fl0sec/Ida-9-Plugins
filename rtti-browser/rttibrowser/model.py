"""IDA-free RTTI records, snapshot schema, sorting, and ownership identity."""

from dataclasses import dataclass


SNAPSHOT_SCHEMA_VERSION = 1
PARSER_VERSION = 2
VALIDATION_RULES_VERSION = 1
MAX_BASES = 4096
MAX_METHODS = 4096
MAX_VTABLES = 1_000_000


class SnapshotError(ValueError):
    """A persisted snapshot is malformed or incompatible."""


def _integer(value, name, minimum=0, maximum=None):
    if not isinstance(value, int) or isinstance(value, bool):
        raise SnapshotError("%s must be an integer" % name)
    if value < minimum or (maximum is not None and value > maximum):
        raise SnapshotError("%s is outside the supported range" % name)
    return value


def _text(value, name):
    if not isinstance(value, str) or not value:
        raise SnapshotError("%s must be a non-empty string" % name)
    return value


@dataclass(frozen=True)
class BaseRecord:
    name: str
    descriptor_rva: int
    type_descriptor_rva: int
    num_contained_bases: int
    mdisp: int
    pdisp: int
    vdisp: int
    attributes: int

    def to_dict(self):
        return {
            "name": self.name,
            "descriptor_rva": self.descriptor_rva,
            "type_descriptor_rva": self.type_descriptor_rva,
            "num_contained_bases": self.num_contained_bases,
            "mdisp": self.mdisp,
            "pdisp": self.pdisp,
            "vdisp": self.vdisp,
            "attributes": self.attributes,
        }

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise SnapshotError("base record must be an object")
        return cls(
            _text(value.get("name"), "base.name"),
            _integer(value.get("descriptor_rva"), "base.descriptor_rva"),
            _integer(value.get("type_descriptor_rva"),
                     "base.type_descriptor_rva"),
            _integer(value.get("num_contained_bases"),
                     "base.num_contained_bases", maximum=MAX_BASES),
            _integer(value.get("mdisp"), "base.mdisp", minimum=-(1 << 31),
                     maximum=(1 << 31) - 1),
            _integer(value.get("pdisp"), "base.pdisp", minimum=-(1 << 31),
                     maximum=(1 << 31) - 1),
            _integer(value.get("vdisp"), "base.vdisp", minimum=-(1 << 31),
                     maximum=(1 << 31) - 1),
            _integer(value.get("attributes"), "base.attributes",
                     maximum=0xFF),
        )


@dataclass(frozen=True)
class VtableRecord:
    vtable_rva: int
    col_rva: int
    type_descriptor_rva: int
    hierarchy_descriptor_rva: int
    class_name: str
    subobject: str
    object_offset: int
    constructor_displacement: int
    attributes: int
    method_count: int
    bases: tuple

    @property
    def ownership_prefix(self):
        return (self.class_name, self.object_offset, self.vtable_rva)

    def owner_label(self):
        if self.subobject == self.class_name and not self.object_offset:
            return self.class_name
        return "%s / %s +0x%X" % (
            self.class_name, self.subobject, self.object_offset,
        )

    def to_dict(self):
        return {
            "vtable_rva": self.vtable_rva,
            "col_rva": self.col_rva,
            "type_descriptor_rva": self.type_descriptor_rva,
            "hierarchy_descriptor_rva": self.hierarchy_descriptor_rva,
            "class_name": self.class_name,
            "subobject": self.subobject,
            "object_offset": self.object_offset,
            "constructor_displacement": self.constructor_displacement,
            "attributes": self.attributes,
            "method_count": self.method_count,
            "bases": [base.to_dict() for base in self.bases],
        }

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise SnapshotError("vtable record must be an object")
        bases = value.get("bases")
        if not isinstance(bases, list) or not 1 <= len(bases) <= MAX_BASES:
            raise SnapshotError("vtable bases must contain 1..%d items"
                                % MAX_BASES)
        return cls(
            _integer(value.get("vtable_rva"), "vtable_rva"),
            _integer(value.get("col_rva"), "col_rva"),
            _integer(value.get("type_descriptor_rva"),
                     "type_descriptor_rva"),
            _integer(value.get("hierarchy_descriptor_rva"),
                     "hierarchy_descriptor_rva"),
            _text(value.get("class_name"), "class_name"),
            _text(value.get("subobject"), "subobject"),
            _integer(value.get("object_offset"), "object_offset",
                     maximum=0xFFFFFFFF),
            _integer(value.get("constructor_displacement"),
                     "constructor_displacement", maximum=0xFFFFFFFF),
            _integer(value.get("attributes"), "attributes", maximum=0x0F),
            _integer(value.get("method_count"), "method_count", minimum=1,
                     maximum=MAX_METHODS),
            tuple(BaseRecord.from_dict(item) for item in bases),
        )


@dataclass(frozen=True)
class Snapshot:
    identity: dict
    records: tuple

    def to_dict(self):
        return {
            "snapshot_schema_version": SNAPSHOT_SCHEMA_VERSION,
            "parser_version": PARSER_VERSION,
            "validation_rules_version": VALIDATION_RULES_VERSION,
            "identity": self.identity,
            "records": [record.to_dict() for record in self.records],
        }

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise SnapshotError("snapshot must be an object")
        expected = (
            ("snapshot_schema_version", SNAPSHOT_SCHEMA_VERSION),
            ("parser_version", PARSER_VERSION),
            ("validation_rules_version", VALIDATION_RULES_VERSION),
        )
        for key, wanted in expected:
            if value.get(key) != wanted:
                raise SnapshotError("unsupported %s" % key)
        identity = value.get("identity")
        records = value.get("records")
        identity = _parse_identity(identity)
        if not isinstance(records, list) or len(records) > MAX_VTABLES:
            raise SnapshotError("snapshot record count is invalid")
        parsed = tuple(VtableRecord.from_dict(item) for item in records)
        return cls(identity, tuple(sorted(parsed, key=class_sort_key)))


def _parse_identity(value):
    if not isinstance(value, dict):
        raise SnapshotError("snapshot identity must be an object")
    for key in ("sha256", "md5", "processor", "file_type"):
        if not isinstance(value.get(key), str):
            raise SnapshotError("identity.%s must be a string" % key)
    if value.get("bitness") not in (32, 64):
        raise SnapshotError("identity.bitness must be 32 or 64")
    if value.get("pointer_size") not in (4, 8):
        raise SnapshotError("identity.pointer_size must be 4 or 8")
    segments = value.get("segments")
    if not isinstance(segments, list) or len(segments) > 65536:
        raise SnapshotError("identity.segments is invalid")
    clean_segments = []
    for segment in segments:
        if not isinstance(segment, list) or len(segment) != 4:
            raise SnapshotError("identity segment must have four integers")
        start, end, segment_type, permissions = segment
        start = _integer(start, "segment.start")
        end = _integer(end, "segment.end", minimum=start)
        clean_segments.append([
            start, end,
            _integer(segment_type, "segment.type"),
            _integer(permissions, "segment.permissions"),
        ])
    clean = dict(value)
    clean["segments"] = clean_segments
    return clean


def class_sort_key(record):
    return (
        record.class_name.casefold(), record.object_offset,
        record.subobject.casefold(), record.vtable_rva,
    )


def method_sort_key(row):
    name = row.get("name", "")
    return (
        0 if name else 1, name.casefold(), row["owner"].casefold(),
        row["object_offset"], row["slot"], row["target_ea"],
    )
