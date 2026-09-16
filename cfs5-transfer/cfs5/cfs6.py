"""The CFS6 file format: UTF-8 JSONL, one self-describing record per line.

This module is the single source of truth for the contract and is deliberately
**free of any `ida_*` import**, so it can be unit-tested (and read by non-IDA
consumers) outside IDA. See docs/cfs6-format.md for the normative spec.

Record kinds
  header         exactly one, first non-empty line, identifies format + image
  function       a function item; candidates reference it by `id`
  global         a global-variable item
  derived_value  an item whose value is an integer extracted from code
  candidate      one signature candidate belonging to an item
  function_type  optional IDA tinfo payload for a function prototype
  global_type    optional IDA tinfo payload for a global's type
  local_type     optional IDA tinfo payload for one named local type

The `*_type` records are IDA-specific and independently skippable: resolution
never depends on decoding them.

Two families of item
  `function` / `global` answer *where is this* -- a candidate resolves to an
  address. `derived_value` answers *what integer does this code encode* -- a
  candidate resolves to a number (a member offset, an element stride, an
  object extent). Both use the same pattern search and the same
  agreement-between-candidates rule; only the final arithmetic differs.

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
# Revision 1 adds the `derived_value` item kind and the VALUE candidate mode.
# Additive only: a revision-0 reader skips both as unknown record kinds.
SCHEMA_REVISION = 1
GENERATOR_NAME = "cfs5-transfer"
GENERATOR_VERSION = "6.1.0"

REC_HEADER = "header"
REC_FUNCTION = "function"
REC_GLOBAL = "global"
REC_DERIVED_VALUE = "derived_value"
REC_CANDIDATE = "candidate"
REC_FUNC_TYPE = "function_type"
REC_GLOB_TYPE = "global_type"
REC_LOCAL_TYPE = "local_type"

ITEM_KINDS = (REC_FUNCTION, REC_GLOBAL, REC_DERIVED_VALUE)
ADDRESS_ITEM_KINDS = (REC_FUNCTION, REC_GLOBAL)
MODES = ("ENTRY", "BODY", "REL", "VALUE")
VALID_REL_WIDTHS = (1, 2, 4, 8)

# ---------------------------------------------------------------------------
# derived_value vocabulary. All three sets are CLOSED: a consumer must reject
# a value it does not know rather than guess at its meaning.
# ---------------------------------------------------------------------------

# What the recovered integer *means*. Only `member_offset` is produced today;
# the rest are reserved so a consumer written now stays correct later.
SEM_MEMBER_OFFSET = "member_offset"
SEM_ELEMENT_STRIDE = "element_stride"
SEM_OBJECT_EXTENT = "object_extent"
SEM_CONSTANT = "constant"
VALID_SEMANTICS = (
    SEM_MEMBER_OFFSET, SEM_ELEMENT_STRIDE, SEM_OBJECT_EXTENT, SEM_CONSTANT,
)

# How the integer is recovered from the matched instruction.
OP_CONST = "CONST"                      # no field; resolve.value is the answer
OP_DISP = "DISP"                        # signed memory displacement
OP_IMM = "IMM"                          # instruction immediate
OP_SCALE = "SCALE"                      # SIB index scale factor
OP_DISP_PLUS_WIDTH = "DISP_PLUS_WIDTH"  # displacement + width of the access
VALID_OPS = (OP_CONST, OP_DISP, OP_IMM, OP_SCALE, OP_DISP_PLUS_WIDTH)
VALID_FIELD_SIZES = (1, 2, 4, 8)

# Where a derived_value candidate may come from. NORMATIVE: nothing else is
# permitted, and in particular a producer must never treat "some other
# instruction encodes the same number" as a candidate. Numeric equality does
# not prove two accesses refer to the same member, and a false candidate is
# worse than a missing one because it manufactures fake agreement.
#
# Each origin names the producer of a *type-directed* association between an
# instruction and a member. `hexrays_memptr` exists because IDA 9.0's member
# xref index is incomplete for objects reached through a typed pointer; the
# decompiler knows the association even when the index does not. It is not a
# relaxation of the rule: the displacement only narrows where to look, and the
# decompiler's `cot_memptr`/`cot_memref` node at that exact instruction is
# what decides. See cfs5/memberscan.py for the measurements.
ORIGIN_STROFF_XREF = "stroff_xref"
ORIGIN_SELECTED_OPERAND = "selected_operand"
ORIGIN_HEXRAYS_MEMPTR = "hexrays_memptr"
VALID_VALUE_ORIGINS = (ORIGIN_STROFF_XREF, ORIGIN_SELECTED_OPERAND,
                       ORIGIN_HEXRAYS_MEMPTR)

# Item-id prefix per semantic, so derived values share the item namespace with
# functions and globals without colliding.
_SEMANTIC_PREFIX = {
    SEM_MEMBER_OFFSET: "member",
    SEM_ELEMENT_STRIDE: "stride",
    SEM_OBJECT_EXTENT: "extent",
    SEM_CONSTANT: "const",
}

# Highest operand index an x86 instruction can carry in IDA's model.
MAX_OPERANDS = 8

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


def derived_item_id(semantic, owner, name):
    """Stable identifier for a derived_value item: `<prefix>:<owner>::<name>`.

    An unqualified member name is not unique across a binary -- every class has
    an `m_pNext` -- so the owner is part of the identity, not decoration.
    """
    prefix = _SEMANTIC_PREFIX.get(semantic)
    if prefix is None:
        raise ValueError("unknown semantic %r" % (semantic,))
    if not owner:
        raise ValueError("a derived_value needs an owner")
    return "%s:%s::%s" % (prefix, owner, name)


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

    # -- VALUE accessors ----------------------------------------------------

    @property
    def op(self):
        return str(self.resolve.get("op", ""))

    @property
    def field_offset(self):
        return int(self.resolve.get("field_offset", 0))

    @property
    def field_size(self):
        return int(self.resolve.get("field_size", 0))

    @property
    def operand_index(self):
        """Which decoded operand the field belongs to.

        Redundant with field_offset/field_size by design: a consumer that
        decodes the instruction can check the field it is about to read really
        is part of the operand the exporter meant, and refuse otherwise.
        """
        return int(self.resolve.get("operand_index", -1))

    @property
    def field_signed(self):
        return bool(self.resolve.get("signed", True))

    @property
    def const_value(self):
        return int(self.resolve.get("value", 0))

    @property
    def value_adjust(self):
        return int(self.resolve.get("value_adjust", 0))

    @property
    def access_width(self):
        return int(self.resolve.get("access_width", 0))

    @property
    def alignment(self):
        return int(self.resolve.get("alignment", 1))

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


class DerivedValueRecord(ItemRecord):
    """An item whose candidates resolve to an integer rather than an address.

    `expected_value` is the value the *source* IDB knew when the file was
    written (for a member offset: the offset IDA has for that field). It is
    diagnostic at resolution time -- a newer build legitimately moving a field
    is drift to be reported, not a failure -- but it is a hard gate at export
    time: a candidate that does not reproduce it is wrong and is not written.

    It is optional because not every semantic has an IDA-known truth to
    compare against; `member_offset` always does.
    """

    __slots__ = ("semantic", "owner", "expected_value")

    def __init__(self, line_no, id, name, semantic, owner, coverage=None,
                 candidate_count=0, expected_value=None):
        ItemRecord.__init__(
            self, line_no, REC_DERIVED_VALUE, id, name,
            coverage=coverage, candidate_count=candidate_count,
        )
        self.semantic = semantic
        self.owner = owner or ""
        self.expected_value = expected_value

    @property
    def qualified_name(self):
        return "%s::%s" % (self.owner, self.name) if self.owner else self.name


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

    def derived_values(self, semantic=None):
        out = [i for i in self.items if i.kind == REC_DERIVED_VALUE]
        if semantic is not None:
            out = [i for i in out if i.semantic == semantic]
        return out

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

    def write_derived_value(self, semantic, owner, name, candidate_count,
                            coverage, expected_value=None):
        """Emit a derived_value item. Returns its id."""
        if semantic not in VALID_SEMANTICS:
            raise ValueError("unsupported semantic %r" % (semantic,))
        iid = derived_item_id(semantic, owner, name)
        obj = {
            "record": REC_DERIVED_VALUE,
            "id": iid,
            "name": name,
            "owner": owner,
            "semantic": semantic,
            "candidate_count": int(candidate_count),
            "coverage": coverage,
        }
        # Carried on the item, never duplicated per candidate: candidates of
        # one item must never intentionally represent different values.
        if expected_value is not None:
            obj["source"] = {"expected_value": int(expected_value)}
        self._emit(obj)
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

    elif mode == "VALUE":
        _validate_value_candidate(rec, pattern_len, line_no)

    return rec


def _validate_value_candidate(rec, pattern_len, line_no):
    """Structural checks for a VALUE candidate.

    The origin check is the important one: it is what makes the
    "never search by numeric equality" rule enforceable by a reader rather
    than a promise made by the producer.
    """
    if rec.origin not in VALID_VALUE_ORIGINS:
        raise ValueError(
            "line %d: VALUE candidate has origin %r, expected one of %r"
            % (line_no, rec.origin, list(VALID_VALUE_ORIGINS))
        )

    op = rec.op
    if op not in VALID_OPS:
        raise ValueError(
            "line %d: unsupported extraction op %r" % (line_no, op)
        )
    if rec.instruction_offset < 0 or rec.instruction_offset >= pattern_len:
        raise ValueError(
            "line %d: instruction_offset is outside the pattern" % line_no
        )
    if rec.alignment < 1:
        raise ValueError("line %d: alignment must be >= 1" % line_no)
    if rec.access_width < 0:
        raise ValueError("line %d: access_width must be >= 0" % line_no)

    if op == OP_CONST:
        if "value" not in rec.resolve:
            raise ValueError("line %d: CONST needs resolve.value" % line_no)
        return

    size = rec.field_size
    if size not in VALID_FIELD_SIZES:
        raise ValueError(
            "line %d: field_size must be one of %r, got %r"
            % (line_no, list(VALID_FIELD_SIZES), size)
        )
    if rec.field_offset < rec.instruction_offset:
        raise ValueError(
            "line %d: the field starts before its own instruction" % line_no
        )
    if rec.field_offset + size > pattern_len:
        raise ValueError("line %d: the field runs past the pattern" % line_no)
    if not 0 <= rec.operand_index < MAX_OPERANDS:
        raise ValueError(
            "line %d: operand_index %d is out of range"
            % (line_no, rec.operand_index)
        )
    if op == OP_DISP_PLUS_WIDTH and rec.access_width <= 0:
        raise ValueError(
            "line %d: DISP_PLUS_WIDTH needs a positive access_width" % line_no
        )


def _parse_derived_value(obj, line_no):
    iid = obj.get("id")
    name = obj.get("name")
    if not isinstance(iid, str) or not iid:
        raise ValueError("line %d: derived_value is missing 'id'" % line_no)
    if not isinstance(name, str) or not name:
        raise ValueError("line %d: derived_value is missing 'name'" % line_no)

    semantic = obj.get("semantic")
    # Closed set: an unknown semantic is rejected, never interpreted as if it
    # were one we do understand.
    if semantic not in VALID_SEMANTICS:
        raise ValueError(
            "line %d: unsupported derived_value semantic %r (this build knows %r)"
            % (line_no, semantic, list(VALID_SEMANTICS))
        )

    owner = obj.get("owner") or ""
    if not isinstance(owner, str):
        raise ValueError("line %d: derived_value 'owner' must be a string" % line_no)

    source = obj.get("source") or {}
    if not isinstance(source, dict):
        raise ValueError("line %d: derived_value 'source' must be an object" % line_no)
    expected = source.get("expected_value")
    if expected is not None:
        if isinstance(expected, bool) or not isinstance(expected, int):
            raise ValueError(
                "line %d: source.expected_value must be an integer" % line_no
            )
    if semantic == SEM_MEMBER_OFFSET and expected is None:
        raise ValueError(
            "line %d: a member_offset must carry source.expected_value" % line_no
        )

    return DerivedValueRecord(
        line_no=line_no, id=iid, name=name, semantic=semantic, owner=owner,
        coverage=obj.get("coverage") or {},
        candidate_count=int(obj.get("candidate_count", 0)),
        expected_value=expected,
    )


def _parse_item(obj, kind, line_no):
    if kind == REC_DERIVED_VALUE:
        return _parse_derived_value(obj, line_no)

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

        # A VALUE candidate produces an integer and an address candidate an
        # address; pairing one with the wrong item kind would silently feed a
        # consumer the wrong sort of answer.
        is_value_item = item.kind == REC_DERIVED_VALUE
        if (cand.mode == "VALUE") != is_value_item:
            loaded.parse_errors += 1
            report(
                "PARSE_ERROR line %d: %s candidate cannot belong to a %s item"
                % (cand.line_no, cand.mode, item.kind)
            )
            continue

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
