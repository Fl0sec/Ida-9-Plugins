"""The CFS6 file format: UTF-8 JSONL, one self-describing record per line.

This module is the single source of truth for the contract and is deliberately
**free of any `ida_*` import**, so it can be unit-tested (and read by non-IDA
consumers) outside IDA. See docs/cfs6-format.md for the normative spec.

Record kinds
  header         exactly one, first non-empty line, identifies format + image
  function       a function item; candidates reference it by `id`
  global         a global-variable item
  candidate      one signature candidate belonging to an item
  function_type  optional IDA tinfo payload for a function prototype
  global_type    optional IDA tinfo payload for a global's type
  local_type     optional IDA tinfo payload for one named local type

The `*_type` records are IDA-specific and independently skippable: resolution
never depends on decoding them.

Conventions
  - All offsets and RVAs are decimal JSON integers.
  - Candidate offsets are relative to the **pattern-match start**.
  - `source.*` values are RVAs in the source image and are diagnostics only.
  - `rank` is authoritative for resolution order; `score` is advisory and
    **lower is better**.
"""

import base64
import json
import zlib


FORMAT_NAME = "CFS"
FORMAT_VERSION = 6
SCHEMA_REVISION = 0
GENERATOR_NAME = "cfs5-transfer"
GENERATOR_VERSION = "6.0.0"

REC_HEADER = "header"
REC_FUNCTION = "function"
REC_GLOBAL = "global"
REC_CANDIDATE = "candidate"
REC_FUNC_TYPE = "function_type"
REC_GLOB_TYPE = "global_type"
REC_LOCAL_TYPE = "local_type"

ITEM_KINDS = (REC_FUNCTION, REC_GLOBAL)
MODES = ("ENTRY", "BODY", "REL")
VALID_REL_WIDTHS = (1, 2, 4, 8)

BLOB_ENCODING = "zlib+base64"
BLOB_PRODUCER = "ida-9.0-tinfo"

_VALID_QUALITIES = ("USER", "EXPLICIT", "GUESSED", "NONE")

# Per-axis coverage states reported on an item record.
COV_SELECTED = "selected"
COV_NONE_UNIQUE = "none_unique"
COV_NOT_APPLICABLE = "not_applicable"


class Cfs6Error(Exception):
    """Fatal problem that makes a whole file unusable."""


# ---------------------------------------------------------------------------
# Payload codec (zlib + base64). Part of the format, hence it lives here.
# ---------------------------------------------------------------------------

def pack_bytes(data):
    if data is None:
        return ""
    raw = bytes(data)
    if not raw:
        return ""
    return base64.b64encode(zlib.compress(raw, 9)).decode("ascii")


def pack_json(value):
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(zlib.compress(raw, 9)).decode("ascii")


def unpack_bytes(payload):
    if not payload:
        return None
    return zlib.decompress(base64.b64decode(payload.encode("ascii"), validate=False))


def unpack_text(payload):
    raw = unpack_bytes(payload)
    return raw.decode("utf-8") if raw else ""


def unpack_json(payload):
    text = unpack_text(payload)
    if not text:
        return []
    value = json.loads(text)
    return value if isinstance(value, list) else []


def normalize_pattern(pattern):
    """Collapse whitespace and upper-case an IDA-style byte pattern."""
    return " ".join(str(pattern).split()).upper()


def item_id(kind, name):
    """Stable item identifier. `kind` is REC_FUNCTION or REC_GLOBAL."""
    return ("fn:" if kind == REC_FUNCTION else "global:") + name


# ---------------------------------------------------------------------------
# Reader-side record objects
# ---------------------------------------------------------------------------

class CandidateRecord:
    """One signature candidate as loaded from a file.

    `is_data` is inherited from the owning item (a global's REL target is a
    mapped data address rather than a function start) and is filled in by the
    loader once the item is known.
    """

    __slots__ = (
        "line_no", "item", "rank", "mode", "pattern", "origin", "score",
        "source", "resolve", "is_data",
    )

    def __init__(self, line_no, item, rank, mode, pattern, origin="",
                 score=0, source=None, resolve=None, is_data=False):
        self.line_no = int(line_no)
        self.item = item
        self.rank = int(rank)
        self.mode = mode
        self.pattern = pattern
        self.origin = origin or ""
        self.score = int(score)
        self.source = dict(source or {})
        self.resolve = dict(resolve or {})
        self.is_data = bool(is_data)

    # Resolve-time accessors. Every offset is relative to the match start.
    @property
    def instruction_offset(self):
        return int(self.resolve.get("instruction_offset", 0))

    @property
    def displacement_offset(self):
        return int(self.resolve.get("displacement_offset", 0))

    @property
    def displacement_size(self):
        return int(self.resolve.get("displacement_size", 0))

    @property
    def base_offset(self):
        return int(self.resolve.get("base_offset", 0))

    @property
    def target_delta(self):
        return int(self.resolve.get("target_delta", 0))

    @property
    def body_offset(self):
        return int(self.source.get("body_offset", 0))

    def describe(self):
        return "%s/%s rank=%d" % (self.mode, self.origin or "?", self.rank)


class ItemRecord:
    __slots__ = (
        "line_no", "kind", "id", "name", "coverage", "candidate_count",
        "candidates",
    )

    def __init__(self, line_no, kind, id, name, coverage=None,
                 candidate_count=0):
        self.line_no = int(line_no)
        self.kind = kind
        self.id = id
        self.name = name
        self.coverage = dict(coverage or {})
        self.candidate_count = int(candidate_count)
        self.candidates = []

    @property
    def is_global(self):
        return self.kind == REC_GLOBAL


class ItemMeta:
    """Optional prototype/type payload for a function or global."""

    __slots__ = (
        "line_no", "item", "name", "quality", "type_blob", "fields_blob",
        "fldcmts_blob", "dependencies", "is_global",
    )

    def __init__(self, line_no, item, name, quality, type_blob=None,
                 fields_blob=None, fldcmts_blob=None, dependencies=None,
                 is_global=False):
        self.line_no = int(line_no)
        self.item = item
        self.name = name
        self.quality = (quality or "NONE").upper()
        if self.quality not in _VALID_QUALITIES:
            self.quality = "EXPLICIT"
        self.type_blob = type_blob
        self.fields_blob = fields_blob
        self.fldcmts_blob = fldcmts_blob
        self.dependencies = list(dependencies or [])
        self.is_global = bool(is_global)

    def has_prototype(self):
        return self.type_blob is not None


class TypeRecord:
    __slots__ = (
        "line_no", "name", "kind", "type_blob", "fields_blob", "fldcmts_blob",
    )

    def __init__(self, line_no, name, kind, type_blob=None, fields_blob=None,
                 fldcmts_blob=None):
        self.line_no = int(line_no)
        self.name = name
        self.kind = (kind or "TYPE").upper()
        self.type_blob = type_blob
        self.fields_blob = fields_blob
        self.fldcmts_blob = fldcmts_blob


class LoadedCfs:
    __slots__ = (
        "header", "items", "type_records", "item_meta", "parse_errors",
        "skipped_records",
    )

    def __init__(self, header=None):
        self.header = header or {}
        self.items = []          # ItemRecord, file order
        self.type_records = {}   # name -> TypeRecord
        self.item_meta = {}      # item id -> ItemMeta
        self.parse_errors = 0
        self.skipped_records = 0

    def functions(self):
        return [i for i in self.items if i.kind == REC_FUNCTION]

    def globals(self):
        return [i for i in self.items if i.kind == REC_GLOBAL]

    def build_number(self):
        build = self.header.get("build") or {}
        return build.get("number")

    def image(self):
        return self.header.get("image") or {}

    def describe_source(self):
        img = self.image()
        build = self.build_number()
        return "image=%s size=%s build=%s sha256=%s" % (
            img.get("name", "?"),
            img.get("size_of_image", "?"),
            "unknown" if build is None else build,
            (img.get("sha256") or "?")[:16],
        )


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

def _dumps(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


class Cfs6Writer:
    """Streams CFS6 records to an already-open text handle.

    Open the handle with encoding="utf-8" and newline="" so no BOM is written
    and line endings stay "\\n".
    """

    def __init__(self, handle, imagebase=0):
        self.handle = handle
        # Source EAs are converted to RVAs on the way out, so a rebased IDB
        # still produces image-relative provenance.
        self.imagebase = int(imagebase)
        self.items = 0
        self.candidates = 0

    def _emit(self, obj):
        self.handle.write(_dumps(obj))
        self.handle.write("\n")

    def write_header(self, image, build_number=None, build_source="unknown"):
        self._emit({
            "record": REC_HEADER,
            "format": FORMAT_NAME,
            "version": FORMAT_VERSION,
            "schema_revision": SCHEMA_REVISION,
            "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
            "image": image,
            "build": {"number": build_number, "source": build_source},
            "scoring": {"direction": "lower-is-better"},
        })

    def write_item(self, kind, name, candidate_count, coverage):
        iid = item_id(kind, name)
        self._emit({
            "record": kind,
            "id": iid,
            "name": name,
            "candidate_count": int(candidate_count),
            "coverage": coverage,
        })
        self.items += 1
        return iid

    def write_candidate(self, iid, rank, cand):
        """Serialize a policy.Candidate under item `iid` at `rank`."""
        obj = {
            "record": REC_CANDIDATE,
            "item": iid,
            "rank": int(rank),
            "mode": cand.mode,
            "pattern": cand.signature,
            "origin": cand.origin,
            "score": int(cand.score),
            "source": cand.source_object(self.imagebase),
            "resolve": cand.resolve_object(),
        }
        self._emit(obj)
        self.candidates += 1

    def write_item_type(self, iid, name, quality, blobs, dependencies,
                        is_global=False):
        self._emit({
            "record": REC_GLOB_TYPE if is_global else REC_FUNC_TYPE,
            "item": iid,
            "name": name,
            "quality": quality,
            "encoding": BLOB_ENCODING,
            "producer": BLOB_PRODUCER,
            "type": pack_bytes(blobs[0]),
            "fields": pack_bytes(blobs[1]),
            "field_comments": pack_bytes(blobs[2]),
            "dependencies": pack_json(dependencies),
        })

    def write_local_type(self, name, kind, blobs):
        self._emit({
            "record": REC_LOCAL_TYPE,
            "name": name,
            "kind": kind,
            "encoding": BLOB_ENCODING,
            "producer": BLOB_PRODUCER,
            "type": pack_bytes(blobs[0]),
            "fields": pack_bytes(blobs[1]),
            "field_comments": pack_bytes(blobs[2]),
        })


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

_NOT_CFS6 = (
    "not a CFS6 file (expected a JSON header object on the first line); "
    "re-export with the CFS6 exporter"
)


def _require_int(obj, key, line_no, minimum=None):
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("line %d: %r must be an integer" % (line_no, key))
    if minimum is not None and value < minimum:
        raise ValueError("line %d: %r must be >= %d" % (line_no, key, minimum))
    return value


def _parse_header(obj, line_no):
    if obj.get("record") != REC_HEADER or obj.get("format") != FORMAT_NAME:
        raise Cfs6Error(_NOT_CFS6)
    version = obj.get("version")
    if version != FORMAT_VERSION:
        raise Cfs6Error(
            "unsupported CFS format version %r (this build reads version %d); "
            "re-export" % (version, FORMAT_VERSION)
        )
    if not isinstance(obj.get("image"), dict):
        raise Cfs6Error("CFS6 header is missing its 'image' object")
    return obj


def _parse_candidate(obj, line_no):
    mode = str(obj.get("mode", "")).upper()
    if mode not in MODES:
        raise ValueError("line %d: unsupported mode %r" % (line_no, mode))

    pattern = normalize_pattern(obj.get("pattern", ""))
    if not pattern:
        raise ValueError("line %d: empty pattern" % line_no)

    item = obj.get("item")
    if not isinstance(item, str) or not item:
        raise ValueError("line %d: candidate is missing 'item'" % line_no)

    source = obj.get("source") or {}
    resolve = obj.get("resolve") or {}
    if not isinstance(source, dict) or not isinstance(resolve, dict):
        raise ValueError("line %d: 'source'/'resolve' must be objects" % line_no)

    rec = CandidateRecord(
        line_no=line_no,
        item=item,
        rank=_require_int(obj, "rank", line_no, minimum=0),
        mode=mode,
        pattern=pattern,
        origin=str(obj.get("origin", "")),
        score=int(obj.get("score", 0)),
        source=source,
        resolve=resolve,
    )

    pattern_len = len(pattern.split())

    if mode == "REL":
        width = rec.displacement_size
        if width not in VALID_REL_WIDTHS:
            raise ValueError(
                "line %d: displacement_size must be one of %r, got %r"
                % (line_no, list(VALID_REL_WIDTHS), width)
            )
        if rec.displacement_offset < 0 or rec.instruction_offset < 0:
            raise ValueError("line %d: negative REL offset" % line_no)
        if rec.base_offset <= 0:
            raise ValueError("line %d: REL base_offset must be positive" % line_no)
        if rec.displacement_offset + width > pattern_len:
            raise ValueError(
                "line %d: REL displacement field runs past the pattern" % line_no
            )
        if rec.base_offset > pattern_len:
            raise ValueError(
                "line %d: REL base_offset runs past the pattern" % line_no
            )
        if not (rec.instruction_offset <= rec.displacement_offset
                and rec.displacement_offset + width <= rec.base_offset):
            raise ValueError(
                "line %d: REL displacement field is not inside the anchor "
                "instruction" % line_no
            )
    elif mode == "BODY":
        if "body_offset" not in source:
            raise ValueError("line %d: BODY candidate needs source.body_offset" % line_no)
        if rec.body_offset < 0:
            raise ValueError("line %d: body_offset must be >= 0" % line_no)

    return rec


def _parse_item(obj, kind, line_no):
    iid = obj.get("id")
    name = obj.get("name")
    if not isinstance(iid, str) or not iid:
        raise ValueError("line %d: item is missing 'id'" % line_no)
    if not isinstance(name, str) or not name:
        raise ValueError("line %d: item is missing 'name'" % line_no)
    return ItemRecord(
        line_no=line_no, kind=kind, id=iid, name=name,
        coverage=obj.get("coverage") or {},
        candidate_count=int(obj.get("candidate_count", 0)),
    )


def _parse_item_meta(obj, line_no, is_global):
    name = obj.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("line %d: type record is missing 'name'" % line_no)
    return ItemMeta(
        line_no=line_no,
        item=obj.get("item") or item_id(
            REC_GLOBAL if is_global else REC_FUNCTION, name
        ),
        name=name,
        quality=obj.get("quality", "NONE"),
        type_blob=unpack_bytes(obj.get("type", "")),
        fields_blob=unpack_bytes(obj.get("fields", "")),
        fldcmts_blob=unpack_bytes(obj.get("field_comments", "")),
        dependencies=[
            d for d in unpack_json(obj.get("dependencies", ""))
            if isinstance(d, str) and d
        ],
        is_global=is_global,
    )


def load_cfs6(path, log=None):
    """Parse a CFS6 file. Raises Cfs6Error when the file is unusable.

    Recoverable per-line problems are counted in `parse_errors` and reported
    through `log` (a one-argument callable); unknown record kinds are skipped.
    """
    def report(text):
        if log is not None:
            log(text)

    with open(path, "r", encoding="utf-8", newline="") as handle:
        lines = handle.read().splitlines()

    loaded = None
    by_id = {}
    seen_ranks = {}
    pending = []

    for line_no, raw in enumerate(lines, 1):
        text = raw.strip()
        # A UTF-8 BOM would otherwise make the first line fail to parse.
        if line_no == 1:
            text = text.lstrip("﻿")
        if not text:
            continue

        try:
            obj = json.loads(text)
        except Exception as exc:
            if loaded is None:
                raise Cfs6Error(_NOT_CFS6)
            loaded.parse_errors += 1
            report("PARSE_ERROR line %d: %s" % (line_no, exc))
            continue

        if not isinstance(obj, dict):
            if loaded is None:
                raise Cfs6Error(_NOT_CFS6)
            loaded.parse_errors += 1
            report("PARSE_ERROR line %d: record is not a JSON object" % line_no)
            continue

        kind = obj.get("record")

        if loaded is None:
            loaded = LoadedCfs(_parse_header(obj, line_no))
            continue

        if kind == REC_HEADER:
            loaded.parse_errors += 1
            report("PARSE_ERROR line %d: duplicate header record" % line_no)
            continue

        try:
            if kind in ITEM_KINDS:
                item = _parse_item(obj, kind, line_no)
                if item.id in by_id:
                    raise ValueError(
                        "line %d: duplicate item id %r (first seen on line %d)"
                        % (line_no, item.id, by_id[item.id].line_no)
                    )
                by_id[item.id] = item
                loaded.items.append(item)

            elif kind == REC_CANDIDATE:
                pending.append(_parse_candidate(obj, line_no))

            elif kind in (REC_FUNC_TYPE, REC_GLOB_TYPE):
                meta = _parse_item_meta(
                    obj, line_no, is_global=(kind == REC_GLOB_TYPE)
                )
                loaded.item_meta[meta.item] = meta

            elif kind == REC_LOCAL_TYPE:
                name = obj.get("name")
                type_blob = unpack_bytes(obj.get("type", ""))
                if not name or type_blob is None:
                    raise ValueError(
                        "line %d: local_type needs a name and a type blob" % line_no
                    )
                if name not in loaded.type_records:
                    loaded.type_records[name] = TypeRecord(
                        line_no, name, obj.get("kind", "TYPE"),
                        type_blob=type_blob,
                        fields_blob=unpack_bytes(obj.get("fields", "")),
                        fldcmts_blob=unpack_bytes(obj.get("field_comments", "")),
                    )

            else:
                # Forward compatibility: a newer producer may add record kinds.
                loaded.skipped_records += 1
                report("SKIPPED line %d: unknown record kind %r" % (line_no, kind))

        except Cfs6Error:
            raise
        except Exception as exc:
            loaded.parse_errors += 1
            report("PARSE_ERROR line %d: %s" % (line_no, exc))

    if loaded is None:
        raise Cfs6Error(_NOT_CFS6)

    _attach_candidates(loaded, by_id, pending, seen_ranks, report)
    return loaded


def _attach_candidates(loaded, by_id, pending, seen_ranks, report):
    for cand in pending:
        item = by_id.get(cand.item)
        if item is None:
            loaded.parse_errors += 1
            report(
                "PARSE_ERROR line %d: candidate references unknown item %r"
                % (cand.line_no, cand.item)
            )
            continue

        key = (cand.item, cand.rank)
        if key in seen_ranks:
            loaded.parse_errors += 1
            report(
                "PARSE_ERROR line %d: duplicate rank %d for item %r "
                "(first seen on line %d)"
                % (cand.line_no, cand.rank, cand.item, seen_ranks[key])
            )
            continue
        seen_ranks[key] = cand.line_no

        cand.is_data = item.is_global
        item.candidates.append(cand)

    for item in loaded.items:
        item.candidates.sort(key=lambda c: (c.rank, c.score, c.line_no))
        ranks = [c.rank for c in item.candidates]
        if ranks and ranks != list(range(len(ranks))):
            loaded.parse_errors += 1
            report(
                "PARSE_ERROR line %d: item %r has non-contiguous ranks %r"
                % (item.line_no, item.id, ranks)
            )
