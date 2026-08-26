"""The .cfs file format: row tags, record dataclasses, the reader and the row
builders. This is the single source of truth for column layouts, so exporter
and importer can never drift apart.

Row tags
  CFS2       function signature candidate (12 cols, frozen for compatibility)
  CFS2G      global-variable signature candidate (same 12 cols, target is data)
  CFS4FUNC   function prototype as serialized tinfo (8 cols)
  CFS5GLOB   global-variable type as serialized tinfo (8 cols)
  CFS4TYPE   one referenced named Local Type, full body (6 cols)
Legacy accepted on read: CFS3TYPE, CFS3FUNC, and bare 3-col Cra0 rows.
"""

import csv

from .common import (
    normalize_signature,
    unpack_bytes,
    unpack_json,
    unpack_text,
)


TAG_SIG = "CFS2"
TAG_SIG_GLOBAL = "CFS2G"
TAG_FUNC = "CFS4FUNC"
TAG_GLOB = "CFS5GLOB"
TAG_TYPE = "CFS4TYPE"

_VALID_QUALITIES = ("USER", "EXPLICIT", "GUESSED", "NONE")


class Record:
    """One signature candidate. is_data marks a global (CFS2G) whose REL target
    is a mapped data address rather than a function start."""

    __slots__ = (
        "line_no", "group_id", "rank", "name", "mode", "signature",
        "target_delta", "rel_offset", "rel_size", "base_offset",
        "insn_offset", "score", "legacy", "is_data"
    )

    def __init__(
        self, line_no, group_id, rank, name, mode, signature,
        target_delta=0, rel_offset=0, rel_size=0, base_offset=0,
        insn_offset=0, score=0, legacy=False, is_data=False
    ):
        self.line_no = line_no
        self.group_id = int(group_id)
        self.rank = int(rank)
        self.name = name
        self.mode = mode.upper()
        self.signature = signature
        self.target_delta = int(target_delta)
        self.rel_offset = int(rel_offset)
        self.rel_size = int(rel_size)
        self.base_offset = int(base_offset)
        self.insn_offset = int(insn_offset)
        self.score = int(score)
        self.legacy = bool(legacy)
        self.is_data = bool(is_data)


class TypeRecord:
    __slots__ = (
        "line_no", "name", "kind", "type_blob", "fields_blob",
        "fldcmts_blob", "declaration", "binary"
    )

    def __init__(
        self, line_no, name, kind,
        type_blob=None, fields_blob=None, fldcmts_blob=None,
        declaration="", binary=False
    ):
        self.line_no = int(line_no)
        self.name = name
        self.kind = (kind or "TYPE").upper()
        self.type_blob = type_blob
        self.fields_blob = fields_blob
        self.fldcmts_blob = fldcmts_blob
        self.declaration = declaration or ""
        self.binary = bool(binary)


class ItemMeta:
    """Prototype/type metadata for a function (CFS4FUNC) or global (CFS5GLOB)."""

    __slots__ = (
        "line_no", "group_id", "name", "quality", "type_blob",
        "fields_blob", "fldcmts_blob", "prototype", "dependencies",
        "binary", "is_global"
    )

    def __init__(
        self, line_no, group_id, name, quality,
        type_blob=None, fields_blob=None, fldcmts_blob=None,
        prototype="", dependencies=None, binary=False, is_global=False
    ):
        self.line_no = int(line_no)
        self.group_id = int(group_id)
        self.name = name
        self.quality = (quality or "NONE").upper()
        self.type_blob = type_blob
        self.fields_blob = fields_blob
        self.fldcmts_blob = fldcmts_blob
        self.prototype = prototype or ""
        self.dependencies = list(dependencies or [])
        self.binary = bool(binary)
        self.is_global = bool(is_global)

    def has_prototype(self):
        if self.binary:
            return self.type_blob is not None
        return bool(self.prototype)


class LoadedCfs:
    __slots__ = (
        "func_records", "glob_records", "type_records",
        "func_meta", "glob_meta", "parse_errors"
    )

    def __init__(self):
        self.func_records = []
        self.glob_records = []
        self.type_records = {}
        self.func_meta = {}
        self.glob_meta = {}
        self.parse_errors = 0


# ---------------------------------------------------------------------------
# Row builders (writer side)
# ---------------------------------------------------------------------------

def signature_row(group_id, rank, name, cand, is_global=False):
    return [
        TAG_SIG_GLOBAL if is_global else TAG_SIG,
        group_id, rank, name, cand.mode, cand.signature,
        cand.target_delta, cand.rel_offset, cand.rel_size,
        cand.base_offset, cand.insn_offset, cand.score,
    ]


def meta_row(group_id, name, quality, packed_type, packed_fields,
             packed_cmts, packed_deps, is_global=False):
    return [
        TAG_GLOB if is_global else TAG_FUNC,
        group_id, name, quality,
        packed_type, packed_fields, packed_cmts, packed_deps,
    ]


def type_row(name, kind, packed_type, packed_fields, packed_cmts):
    return [TAG_TYPE, name, kind, packed_type, packed_fields, packed_cmts]


def _clean_deps(dependencies):
    clean = []
    for dep in dependencies:
        if isinstance(dep, str) and dep and dep not in clean:
            clean.append(dep)
    return clean


def _parse_signature_row(row, line_no, is_data):
    rec = Record(
        line_no=line_no,
        group_id=int(row[1].strip(), 0),
        rank=int(row[2].strip(), 0),
        name=row[3].strip(),
        mode=row[4].strip(),
        signature=normalize_signature(row[5]),
        target_delta=int(row[6].strip(), 0),
        rel_offset=int(row[7].strip(), 0),
        rel_size=int(row[8].strip(), 0),
        base_offset=int(row[9].strip(), 0),
        insn_offset=int(row[10].strip(), 0),
        score=int(row[11].strip(), 0),
        legacy=False,
        is_data=is_data,
    )
    if rec.mode not in ("ENTRY", "BODY", "REL"):
        raise ValueError("unsupported mode %r" % rec.mode)
    if not rec.name or not rec.signature:
        raise ValueError("empty name/signature")
    if rec.mode == "REL":
        if rec.rel_size not in (1, 2, 4, 8):
            raise ValueError("REL width must be 1/2/4/8, got %d" % rec.rel_size)
        if rec.rel_offset < 0 or rec.base_offset <= 0:
            raise ValueError("invalid REL offsets")
    return rec


def _parse_meta_row(row, line_no, is_global):
    group_id = int(row[1].strip(), 0)
    name = row[2].strip()
    quality = row[3].strip().upper() or "NONE"
    type_blob = unpack_bytes(row[4].strip())
    fields_blob = unpack_bytes(row[5].strip())
    cmts_blob = unpack_bytes(row[6].strip())
    dependencies = unpack_json(row[7].strip())
    if not name:
        raise ValueError("empty meta name")
    if quality not in _VALID_QUALITIES:
        quality = "EXPLICIT"
    return ItemMeta(
        line_no, group_id, name, quality,
        type_blob=type_blob, fields_blob=fields_blob, fldcmts_blob=cmts_blob,
        dependencies=_clean_deps(dependencies), binary=True, is_global=is_global,
    )


def load_records(path):
    """Parse a .cfs file into a LoadedCfs. Accepts every historical row tag."""
    loaded = LoadedCfs()
    legacy_group = 0

    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        for line_no, row in enumerate(reader, 1):
            if not row:
                continue

            first = row[0].strip()
            if not first or first.startswith("#") or first.startswith("//"):
                continue

            try:
                tag = first.upper()

                if tag == TAG_TYPE:
                    if len(row) < 6:
                        raise ValueError(
                            "CFS4TYPE row needs 6 columns, got %d" % len(row)
                        )
                    name = row[1].strip()
                    kind = row[2].strip().upper() or "TYPE"
                    type_blob = unpack_bytes(row[3].strip())
                    fields_blob = unpack_bytes(row[4].strip())
                    cmts_blob = unpack_bytes(row[5].strip())
                    if not name or type_blob is None:
                        raise ValueError("empty CFS4TYPE name/type blob")
                    if name not in loaded.type_records:
                        loaded.type_records[name] = TypeRecord(
                            line_no, name, kind,
                            type_blob=type_blob, fields_blob=fields_blob,
                            fldcmts_blob=cmts_blob, binary=True,
                        )
                    continue

                if tag == TAG_FUNC:
                    if len(row) < 8:
                        raise ValueError(
                            "CFS4FUNC row needs 8 columns, got %d" % len(row)
                        )
                    meta = _parse_meta_row(row, line_no, is_global=False)
                    loaded.func_meta[(meta.group_id, meta.name)] = meta
                    continue

                if tag == TAG_GLOB:
                    if len(row) < 8:
                        raise ValueError(
                            "CFS5GLOB row needs 8 columns, got %d" % len(row)
                        )
                    meta = _parse_meta_row(row, line_no, is_global=True)
                    loaded.glob_meta[(meta.group_id, meta.name)] = meta
                    continue

                if tag == "CFS3TYPE":
                    if len(row) < 4:
                        raise ValueError(
                            "CFS3TYPE row needs 4 columns, got %d" % len(row)
                        )
                    name = row[1].strip()
                    kind = row[2].strip().upper() or "TYPE"
                    declaration = unpack_text(row[3].strip())
                    if not name or not declaration:
                        raise ValueError("empty CFS3TYPE name/declaration")
                    if name not in loaded.type_records:
                        loaded.type_records[name] = TypeRecord(
                            line_no, name, kind, declaration=declaration, binary=False
                        )
                    continue

                if tag == "CFS3FUNC":
                    if len(row) < 6:
                        raise ValueError(
                            "CFS3FUNC row needs 6 columns, got %d" % len(row)
                        )
                    group_id = int(row[1].strip(), 0)
                    name = row[2].strip()
                    quality = row[3].strip().upper() or "NONE"
                    prototype = unpack_text(row[4].strip())
                    dependencies = unpack_json(row[5].strip())
                    if not name:
                        raise ValueError("empty CFS3FUNC name")
                    if quality not in _VALID_QUALITIES:
                        quality = "EXPLICIT"
                    loaded.func_meta[(group_id, name)] = ItemMeta(
                        line_no, group_id, name, quality,
                        prototype=prototype, dependencies=_clean_deps(dependencies),
                        binary=False, is_global=False,
                    )
                    continue

                if tag == TAG_SIG:
                    if len(row) < 12:
                        raise ValueError(
                            "CFS2 row needs 12 columns, got %d" % len(row)
                        )
                    loaded.func_records.append(
                        _parse_signature_row(row, line_no, is_data=False)
                    )
                    continue

                if tag == TAG_SIG_GLOBAL:
                    if len(row) < 12:
                        raise ValueError(
                            "CFS2G row needs 12 columns, got %d" % len(row)
                        )
                    loaded.glob_records.append(
                        _parse_signature_row(row, line_no, is_data=True)
                    )
                    continue

                # Backward-compatible legacy Cra0 row: index,"name","pattern"
                if len(row) < 3:
                    raise ValueError("legacy row needs at least 3 columns")

                _old_index = int(first, 0)
                name = row[1].strip()
                signature = normalize_signature(",".join(row[2:]))
                if not name or not signature:
                    raise ValueError("empty legacy name/signature")

                loaded.func_records.append(
                    Record(
                        line_no=line_no, group_id=legacy_group, rank=0,
                        name=name, mode="ENTRY", signature=signature, legacy=True,
                    )
                )
                legacy_group += 1

            except Exception as exc:
                loaded.parse_errors += 1
                # Deferred import to avoid a cycle at module load time.
                from .common import msg
                msg("PARSE_ERROR line %d: %s" % (line_no, exc))

    return loaded


def group_records(records):
    """Group signature records by (group_id, name), ranked best-first."""
    groups = {}
    order = []
    for rec in records:
        key = (rec.group_id, rec.name)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(rec)

    result = []
    for key in order:
        items = sorted(groups[key], key=lambda r: (r.rank, r.score, r.line_no))
        result.append((key, items))
    return result
