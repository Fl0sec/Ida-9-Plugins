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
#
# Revision 2 adds *structural locator* modes -- VTABLE, and STRING_REL --
# which resolve a function by where it sits in the image's own structures
# rather than by a byte pattern, for functions no pattern can distinguish.
# Also additive, and made safely so: an unrecognised `mode` is now
# skip-with-report rather than a parse error, matching how unknown record
# kinds already behave. An item fails only when no candidate survives, which
# was always the semantics, so an older reader degrades to "this item has
# fewer candidates" instead of "this file is broken".
SCHEMA_REVISION = 3
GENERATOR_NAME = "cfs5-transfer"
GENERATOR_VERSION = "6.3.0"

REC_HEADER = "header"
REC_FUNCTION = "function"
REC_GLOBAL = "global"
REC_DERIVED_VALUE = "derived_value"
REC_PATCH = "patch"
REC_CANDIDATE = "candidate"
REC_FUNC_TYPE = "function_type"
REC_GLOB_TYPE = "global_type"
REC_LOCAL_TYPE = "local_type"

ITEM_KINDS = (REC_FUNCTION, REC_GLOBAL, REC_DERIVED_VALUE, REC_PATCH)
ADDRESS_ITEM_KINDS = (REC_FUNCTION, REC_GLOBAL)
MODE_VTABLE = "VTABLE"
MODE_STRING_REL = "STRING_REL"
MODE_SITE = "SITE"
MODES = ("ENTRY", "BODY", "REL", "VALUE", MODE_VTABLE, MODE_STRING_REL,
         MODE_SITE)
# Modes that locate a function structurally instead of by a unique pattern.
# Their `pattern` is a *confirm* signature: it is matched only inside the
# already-located function, so it is not required to be image-unique.
LOCATOR_MODES = (MODE_VTABLE, MODE_STRING_REL)
VALID_REL_WIDTHS = (1, 2, 4, 8)

# ---------------------------------------------------------------------------
# Structural locator vocabulary (revision 2). Closed sets, like every other
# vocabulary here: a consumer rejects a value it does not know.
# ---------------------------------------------------------------------------

# Which span the producer measured the confirm signature's uniqueness over, and
# which span a consumer must therefore scan. `pdata_chain` is the contiguous
# run of RUNTIME_FUNCTION entries beginning at the resolved function -- what a
# non-IDA consumer can compute for itself. `ida_extent` means the producer had
# no .pdata and fell back to IDA's idea of the function, so the bound is a hint
# rather than a table.
SCAN_BOUND_PDATA_CHAIN = "pdata_chain"
SCAN_BOUND_IDA_EXTENT = "ida_extent"
SCAN_BOUNDS = (SCAN_BOUND_PDATA_CHAIN, SCAN_BOUND_IDA_EXTENT)

# How the confirm signature was tokenized. `relaxed` wildcards every encoded
# immediate and displacement, including stack-relative ones, so it absorbs more
# build drift; `strict` keeps them, which is sometimes the only way to tell a
# function from its byte-identical clone siblings. A consumer needs to know
# which it got in order to weigh a failure to match.
TOKENIZATION_STRICT = "strict"
TOKENIZATION_RELAXED = "relaxed"
TOKENIZATIONS = (TOKENIZATION_STRICT, TOKENIZATION_RELAXED)

# Where a VTABLE candidate came from.
ORIGIN_RTTI_VTABLE_SLOT = "rtti_vtable_slot"
VALID_VTABLE_ORIGINS = (ORIGIN_RTTI_VTABLE_SLOT,)
ORIGIN_ANCHOR_STRING = "anchor_string"
VALID_STRING_REL_ORIGINS = (ORIGIN_ANCHOR_STRING,)
STRING_MATCH_NUL_EXACT = "nul_terminated_exact"
WINDOW_BOUND_PDATA_CHUNK = "pdata_chunk"
ORIGIN_DECLARED_PATCH_SITE = "declared_patch_site"

# A raw MSVC type descriptor, never a demangled name: `.?AVCCSPlayerInventory@@`
# is in the image, `CCSPlayerInventory` is IDA's rendering of it.
_DESCRIPTOR_PREFIX = ".?"

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
    """Stable address/patch item identifier."""
    prefix = {REC_FUNCTION: "fn:", REC_GLOBAL: "global:", REC_PATCH: "patch:"}
    if kind not in prefix:
        raise ValueError("unsupported item kind %r" % kind)
    return prefix[kind] + name


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

    # -- structural locator accessors --------------------------------------

    @property
    def is_locator(self):
        return self.mode in LOCATOR_MODES

    @property
    def type_descriptor(self):
        return str(self.resolve.get("type_descriptor", ""))

    @property
    def subobject_offset(self):
        return int(self.resolve.get("subobject_offset", 0))

    @property
    def slot(self):
        return int(self.resolve.get("slot", -1))

    @property
    def confirm_offset(self):
        """Where the confirm signature sat in the source build.

        A **hint for bounding the scan, never a correctness input.** If the
        function grew or was rearranged, the offset drifts and the signature is
        still the right evidence -- only its absence is fatal.
        """
        return int(self.resolve.get("confirm_offset", 0))

    @property
    def scan_bound(self):
        return str(self.resolve.get("scan_bound", SCAN_BOUND_IDA_EXTENT))

    @property
    def tokenization(self):
        return str(self.resolve.get("tokenization", TOKENIZATION_STRICT))

    @property
    def image_matches(self):
        """How many places the confirm signature matched image-wide at export.

        1 means it could also stand alone as a BODY anchor; more means it is
        confirm-only. **Not** a resolution input: a consumer refuses on 0 or 2+
        matches *within the scan range*, which is a different number entirely.
        """
        return int(self.resolve.get("image_matches", 0))

    @property
    def anchor_string(self):
        return str(self.resolve.get("string", ""))

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


class PatchRecord(ItemRecord):
    __slots__ = ("owner", "expected_instruction", "expected_bytes", "patch_size")

    def __init__(self, line_no, id, name, owner, source=None, coverage=None,
                 candidate_count=0):
        ItemRecord.__init__(self, line_no, REC_PATCH, id, name, coverage,
                            candidate_count)
        source = source or {}
        self.owner = owner
        self.expected_instruction = source.get("expected_instruction", "")
        self.expected_bytes = source.get("expected_bytes", "")
        self.patch_size = int(source.get("patch_size", 0))

    @property
    def qualified_name(self):
        return "%s::%s" % (self.owner, self.name)


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
        "skipped_records", "lines", "header_line",
    )

    def __init__(self, header=None):
        self.header = header or {}
        self.items = []          # ItemRecord, file order
        self.type_records = {}   # name -> TypeRecord
        self.item_meta = {}      # item id -> ItemMeta
        self.parse_errors = 0
        self.skipped_records = 0
        # Raw source lines, 0-based, kept so a merge can carry a record over
        # byte-for-byte instead of re-serializing a parsed approximation of it.
        self.lines = []
        self.header_line = 1

    def functions(self):
        return [i for i in self.items if i.kind == REC_FUNCTION]

    def globals(self):
        return [i for i in self.items if i.kind == REC_GLOBAL]

    def derived_values(self, semantic=None):
        out = [i for i in self.items if i.kind == REC_DERIVED_VALUE]
        if semantic is not None:
            out = [i for i in out if i.semantic == semantic]
        return out

    def patches(self):
        return [i for i in self.items if i.kind == REC_PATCH]

    def build_number(self):
        build = self.header.get("build") or {}
        return build.get("number")

    def image(self):
        return self.header.get("image") or {}

    def describe_contents(self):
        """One-line inventory, for a merge prompt."""
        return (
            "%d functions, %d globals, %d derived values, %d patches, %d local types"
            % (len(self.functions()), len(self.globals()),
               len(self.derived_values()), len(self.patches()),
               len(self.type_records))
        )

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
        # What this run has written, so `carry_over` knows which records of a
        # file being merged into are superseded by a fresher export.
        self.item_ids = set()
        self.type_names = set()

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
        self.item_ids.add(iid)
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
        self.item_ids.add(iid)
        return iid

    def write_patch(self, owner, name, candidate_count, coverage, source):
        iid = "patch:%s::%s" % (owner, name)
        self._emit({
            "record": REC_PATCH, "id": iid, "owner": owner, "name": name,
            "candidate_count": int(candidate_count), "coverage": coverage,
            "source": dict(source),
        })
        self.items += 1
        self.item_ids.add(iid)
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
        self.type_names.add(name)
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
# Merging an export into an existing file
#
# A CFS6 file cannot be appended to as raw text: the header is singular and
# must be first, and a re-exported item would collide with its own previous
# `id`. So a merge is a rewrite -- write the new export, then carry over the
# records of the old file that it does not supersede.
# ---------------------------------------------------------------------------

# Header/image fields that must agree before two exports may share a file.
# Everything downstream (source RVAs, coverage, the single build number) is
# stated relative to one image; mixing two makes the header lie about half the
# records. Fields absent on either side are not evidence of a mismatch.
_IDENTITY_FIELDS = (
    ("name", "image name"),
    ("architecture", "architecture"),
    ("size_of_image", "size_of_image"),
    ("sha256", "sha256"),
)


class MergeStats:
    """What `carry_over` kept and what the new export replaced."""

    __slots__ = ("items", "candidates", "types", "metas",
                 "replaced_items", "replaced_types", "replaced_lines",
                 "dropped_lines")

    def __init__(self):
        self.items = 0
        self.candidates = 0
        self.types = 0
        self.metas = 0
        self.replaced_items = 0
        self.replaced_types = 0
        # Lines the fresh export superseded, kept apart from the unparsable
        # ones: conflating them reads as a corrupt file when nothing is wrong.
        self.replaced_lines = 0
        self.dropped_lines = 0

    def describe(self):
        return (
            "carried %d items (%d candidates, %d type payloads, %d local "
            "types); replaced %d items and %d local types (%d lines); "
            "dropped %d unparsable lines"
            % (self.items, self.candidates, self.metas, self.types,
               self.replaced_items, self.replaced_types, self.replaced_lines,
               self.dropped_lines)
        )


def merge_conflicts(header, image, build_number=None):
    """Reasons `header`'s file must not be merged with this image; [] if OK."""
    old = header.get("image") or {}
    new = image or {}
    reasons = []

    for key, label in _IDENTITY_FIELDS:
        a, b = old.get(key), new.get(key)
        if a is None or b is None or a == "" or b == "":
            continue
        if key == "name":
            a, b = str(a).replace("\\", "/").rsplit("/", 1)[-1].casefold(), \
                str(b).replace("\\", "/").rsplit("/", 1)[-1].casefold()
        if a != b:
            reasons.append("%s: file has %r, this IDB has %r"
                           % (label, old.get(key), new.get(key)))

    old_build = (header.get("build") or {}).get("number")
    if old_build is not None and build_number is not None \
            and int(old_build) != int(build_number):
        reasons.append("build: file has %d, this IDB is %d"
                       % (int(old_build), int(build_number)))
    return reasons


def carry_over(writer, loaded):
    """Append the records of `loaded` that `writer` has not superseded.

    Lines are copied verbatim, so a record this build does not fully model
    survives a merge unchanged. Anything the reader could not parse, and any
    record belonging to an item this export rewrote, is dropped.
    """
    stats = MergeStats()
    live_ids = {item.id for item in loaded.items}
    keep = set()
    replaced = set()

    for item in loaded.items:
        if item.id in writer.item_ids:
            stats.replaced_items += 1
            # A superseded item takes its candidates with it: they describe
            # where the *old* export found it.
            replaced.add(item.line_no)
            replaced.update(c.line_no for c in item.candidates)
            continue
        keep.add(item.line_no)
        stats.items += 1
        for cand in item.candidates:
            keep.add(cand.line_no)
            stats.candidates += 1

    for iid, meta in loaded.item_meta.items():
        # An orphaned payload (its item is gone) is dead weight, not a record.
        if iid in writer.item_ids or iid not in live_ids:
            replaced.add(meta.line_no)
            continue
        keep.add(meta.line_no)
        stats.metas += 1

    for name, rec in loaded.type_records.items():
        if name in writer.type_names:
            stats.replaced_types += 1
            replaced.add(rec.line_no)
            continue
        keep.add(rec.line_no)
        stats.types += 1

    for line_no, raw in enumerate(loaded.lines, 1):
        text = raw.strip()
        if not text:
            continue
        # The old header is intentionally gone: the merged file gets a fresh
        # one from this run, so it is not an "unusable" line.
        if line_no == loaded.header_line:
            continue
        if line_no not in keep:
            if line_no in replaced:
                stats.replaced_lines += 1
            else:
                stats.dropped_lines += 1
            continue
        writer.handle.write(text)
        writer.handle.write("\n")

    # The merged file is the union, so the writer's counters must reflect it.
    writer.items += stats.items
    writer.candidates += stats.candidates
    return stats


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


class UnknownMode(Exception):
    """A candidate mode this build does not model.

    Distinct from a parse error on purpose. A newer producer adding a
    resolution mode must not make the file unreadable: the item simply has one
    fewer candidate, and an item fails only when *no* candidate survives, which
    is already the semantics. The loader reports it as a skip.
    """

    def __init__(self, message, item="", rank=-1, line_no=0):
        super().__init__(message)
        self.item = item
        self.rank = rank
        self.line_no = line_no


def _parse_candidate(obj, line_no):
    mode = str(obj.get("mode", "")).upper()
    if mode not in MODES:
        raise UnknownMode(
            "line %d: candidate mode %r is not supported by this build"
            % (line_no, mode),
            item=str(obj.get("item", "")), rank=int(obj.get("rank", -1)),
            line_no=line_no,
        )

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

    elif mode == MODE_VTABLE:
        _validate_vtable_candidate(rec, line_no)

    elif mode == MODE_STRING_REL:
        _validate_string_rel_candidate(rec, line_no)

    elif mode == MODE_SITE:
        if rec.origin != ORIGIN_DECLARED_PATCH_SITE:
            raise ValueError("line %d: SITE candidate has invalid origin" % line_no)
        if rec.instruction_offset < 0 or rec.instruction_offset >= pattern_len:
            raise ValueError("line %d: SITE instruction_offset is outside pattern"
                             % line_no)

    return rec


def _validate_vtable_candidate(rec, line_no):
    """Structural checks for a VTABLE locator.

    Note what is *not* checked: the confirm signature's length, exact-byte
    count and image-wide match count are all unconstrained. Those floors exist
    to keep an image-wide pattern from collapsing to a coincidence, and this
    pattern is matched only inside a function the locator already resolved.
    Applying them here would reject good bounded evidence.
    """
    if rec.origin not in VALID_VTABLE_ORIGINS:
        raise ValueError(
            "line %d: VTABLE candidate has origin %r, expected one of %r"
            % (line_no, rec.origin, list(VALID_VTABLE_ORIGINS))
        )

    descriptor = rec.type_descriptor
    if not descriptor:
        raise ValueError("line %d: VTABLE needs resolve.type_descriptor" % line_no)
    if not descriptor.startswith(_DESCRIPTOR_PREFIX):
        # A demangled name would be an IDA rendering no other consumer can
        # reproduce; the raw descriptor is what is actually in the image.
        raise ValueError(
            "line %d: type_descriptor %r is not a raw MSVC descriptor "
            "(expected a %r prefix)" % (line_no, descriptor, _DESCRIPTOR_PREFIX)
        )

    if "slot" not in rec.resolve:
        raise ValueError("line %d: VTABLE needs resolve.slot" % line_no)
    if rec.slot < 0:
        raise ValueError("line %d: slot must be >= 0, got %d" % (line_no, rec.slot))
    if rec.subobject_offset < 0:
        raise ValueError(
            "line %d: subobject_offset must be >= 0, got %d"
            % (line_no, rec.subobject_offset)
        )
    if rec.confirm_offset < 0:
        raise ValueError(
            "line %d: confirm_offset must be >= 0, got %d"
            % (line_no, rec.confirm_offset)
        )
    if rec.scan_bound not in SCAN_BOUNDS:
        raise ValueError(
            "line %d: scan_bound %r is not one of %r"
            % (line_no, rec.scan_bound, list(SCAN_BOUNDS))
        )
    if rec.tokenization not in TOKENIZATIONS:
        raise ValueError(
            "line %d: tokenization %r is not one of %r"
            % (line_no, rec.tokenization, list(TOKENIZATIONS))
        )
    if rec.image_matches < 1:
        raise ValueError(
            "line %d: image_matches must be >= 1 (the signature matched at "
            "least where it was built), got %d" % (line_no, rec.image_matches)
        )


def _validate_confirm_fields(rec, line_no):
    if rec.confirm_offset < 0:
        raise ValueError(
            "line %d: confirm_offset must be >= 0, got %d"
            % (line_no, rec.confirm_offset)
        )
    if rec.scan_bound not in SCAN_BOUNDS:
        raise ValueError(
            "line %d: scan_bound %r is not one of %r"
            % (line_no, rec.scan_bound, list(SCAN_BOUNDS))
        )
    if rec.tokenization not in TOKENIZATIONS:
        raise ValueError(
            "line %d: tokenization %r is not one of %r"
            % (line_no, rec.tokenization, list(TOKENIZATIONS))
        )
    if rec.image_matches < 1:
        raise ValueError(
            "line %d: image_matches must be >= 1 (the signature matched at "
            "least where it was built), got %d" % (line_no, rec.image_matches)
        )


def _validate_string_rel_candidate(rec, line_no):
    if rec.origin not in VALID_STRING_REL_ORIGINS:
        raise ValueError("line %d: STRING_REL candidate has invalid origin %r"
                         % (line_no, rec.origin))
    if not rec.anchor_string:
        raise ValueError("line %d: STRING_REL needs resolve.string" % line_no)
    if rec.resolve.get("string_match") != STRING_MATCH_NUL_EXACT:
        raise ValueError("line %d: STRING_REL needs nul_terminated_exact matching"
                         % line_no)
    if int(rec.resolve.get("window_bytes", 0)) != 128:
        raise ValueError("line %d: STRING_REL window_bytes must be 128" % line_no)
    if rec.resolve.get("window_bound") != WINDOW_BOUND_PDATA_CHUNK:
        raise ValueError("line %d: STRING_REL window_bound must be pdata_chunk"
                         % line_no)
    _validate_confirm_fields(rec, line_no)


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
    if semantic in (SEM_MEMBER_OFFSET, SEM_OBJECT_EXTENT) and expected is None:
        raise ValueError(
            "line %d: %s must carry source.expected_value" % (line_no, semantic)
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
    if kind == REC_PATCH:
        iid = obj.get("id")
        owner = obj.get("owner")
        name = obj.get("name")
        source = obj.get("source") or {}
        if not all(isinstance(x, str) and x for x in (iid, owner, name)):
            raise ValueError("line %d: patch needs id, owner and name" % line_no)
        if source.get("expected_instruction") in (None, ""):
            raise ValueError("line %d: patch needs expected_instruction" % line_no)
        expected = str(source.get("expected_bytes", "")).replace(" ", "").upper()
        if not expected or len(expected) % 2:
            raise ValueError("line %d: patch expected_bytes is invalid" % line_no)
        try:
            bytes.fromhex(expected)
        except ValueError:
            raise ValueError("line %d: patch expected_bytes is invalid" % line_no)
        source["expected_bytes"] = expected
        if int(source.get("patch_size", 0)) <= 0:
            raise ValueError("line %d: patch_size must be positive" % line_no)
        if int(source["patch_size"]) < len(bytes.fromhex(expected)):
            raise ValueError("line %d: patch_size is smaller than expected_bytes"
                             % line_no)
        return PatchRecord(line_no, iid, name, owner, source,
                           obj.get("coverage") or {},
                           int(obj.get("candidate_count", 0)))

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
    skipped_ranks = {}

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
            loaded.lines = lines
            loaded.header_line = line_no
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
        except UnknownMode as exc:
            # Forward compatibility, the same contract as an unknown record
            # kind: drop the candidate, keep the file.
            loaded.skipped_records += 1
            if exc.item and exc.rank >= 0:
                skipped_ranks.setdefault(exc.item, {})[exc.rank] = exc.line_no
            report("SKIPPED %s" % exc)
        except Exception as exc:
            loaded.parse_errors += 1
            report("PARSE_ERROR line %d: %s" % (line_no, exc))

    if loaded is None:
        raise Cfs6Error(_NOT_CFS6)

    _attach_candidates(loaded, by_id, pending, seen_ranks, skipped_ranks, report)
    return loaded


def _attach_candidates(loaded, by_id, pending, seen_ranks, skipped_ranks, report):
    for item, ranks in skipped_ranks.items():
        for rank, line_no in ranks.items():
            seen_ranks[(item, rank)] = line_no
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

        is_patch_item = item.kind == REC_PATCH
        if (cand.mode == MODE_SITE) != is_patch_item:
            loaded.parse_errors += 1
            report(
                "PARSE_ERROR line %d: %s candidate cannot belong to a %s item"
                % (cand.line_no, cand.mode, item.kind)
            )
            continue

        # A structural locator names a *function* -- an RTTI slot and a string
        # registration both hand back code. Attaching one to a global would
        # claim evidence the mode cannot produce.
        if cand.is_locator and item.kind != REC_FUNCTION:
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
        ranks = sorted(
            rank for (iid, rank), _line in seen_ranks.items() if iid == item.id
        )
        if ranks and ranks != list(range(len(ranks))):
            loaded.parse_errors += 1
            report(
                "PARSE_ERROR line %d: item %r has non-contiguous ranks %r"
                % (item.line_no, item.id, ranks)
            )
