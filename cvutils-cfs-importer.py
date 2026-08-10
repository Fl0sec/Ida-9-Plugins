# CFS5 Importer for IDA Pro 9.0 / IDAPython 9.0
#
# Supports:
#   - CFS3 transported Local Types + per-function prototype metadata.
#   - CFS2 optimized ENTRY / BODY / REL signature records.
#   - Legacy Cra0-style 3-column CFS rows as ENTRY records.
#   - Ranked signature fallback and signed PC-relative REL resolution.
#   - Missing type registration without overwriting same-named destination types.
#   - Per-argument/return prototype merge: destination specific named types win.
#   - Conservative destination naming: never overwrites meaningful names.
#
# CFS2 REL formula:
#   disp   = signed_le(match + rel_offset, rel_size)
#   target = match + base_offset + disp + target_delta
#
# Target: IDA Professional 9.0 / Python 3.12.

VERSION = "6.0.0-ida9"
PLUGIN_NAME = "CFS5 Importer (IDA 9)"
PLUGIN_HOTKEY = "Ctrl+Shift+I"
ACTION_ID = "cfs5:import_file"
ACTION_LABEL = "CFS5 / CFS File..."

CREATE_MISSING_FUNCTIONS = True
PROGRESS_EVERY = 10

import base64
import csv
import json
import os
import re
import zlib

import idc

import idaapi
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_name
import ida_nalt
import ida_segment
import ida_ua
import ida_typeinf


BADADDR = ida_idaapi.BADADDR
try:
    csv.field_size_limit(16 * 1024 * 1024)
except Exception:
    pass


def _msg(text):
    ida_kernwin.msg("[CFS5] %s\n" % text)


def _ea(ea):
    return "BADADDR" if ea == BADADDR else "0x%X" % ea


class Record:
    __slots__ = (
        "line_no", "group_id", "rank", "name", "mode", "signature",
        "target_delta", "rel_offset", "rel_size", "base_offset",
        "insn_offset", "score", "legacy"
    )

    def __init__(
        self, line_no, group_id, rank, name, mode, signature,
        target_delta=0, rel_offset=0, rel_size=0, base_offset=0,
        insn_offset=0, score=0, legacy=False
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


class FuncMeta:
    __slots__ = (
        "line_no", "group_id", "name", "quality", "type_blob",
        "fields_blob", "fldcmts_blob", "prototype", "dependencies", "binary"
    )

    def __init__(
        self, line_no, group_id, name, quality,
        type_blob=None, fields_blob=None, fldcmts_blob=None,
        prototype="", dependencies=None, binary=False
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

    def has_prototype(self):
        if self.binary:
            return self.type_blob is not None
        return bool(self.prototype)


class Stats:
    def __init__(self):
        self.groups = 0
        self.processed = 0
        self.renamed = 0
        self.already_named_global = 0
        self.already_same = 0
        self.skipped_named = 0
        self.name_conflicts = 0
        self.not_found = 0
        self.ambiguous = 0
        self.unsafe = 0
        self.created_functions = 0
        self.fallback_used = 0

        self.types_total = 0
        self.types_existing = 0
        self.types_registered = 0
        self.types_failed = 0

        self.func_types_present = 0
        self.func_types_applied = 0
        self.func_types_unchanged = 0
        self.func_types_failed = 0
        self.args_source_used = 0
        self.args_destination_kept = 0
        self.returns_source_used = 0
        self.returns_destination_kept = 0

        self.parse_errors = 0
        self.failures = 0
        self.cancelled = False

    def summary(self):
        return (
            "CFS5 import summary\n\n"
            "Processed functions: %d / %d\n"
            "Renamed: %d\n"
            "Already exists globally: %d\n"
            "Already same destination: %d\n"
            "Skipped destination already-named: %d\n"
            "Name conflicts: %d\n"
            "Not found: %d\n"
            "Ambiguous: %d\n"
            "Unsafe/unresolvable: %d\n"
            "Functions created: %d\n"
            "Fallback candidate used: %d\n\n"
            "Transported named types: %d\n"
            "Types already present (kept): %d\n"
            "Types registered: %d\n"
            "Types failed: %d\n\n"
            "Function prototypes present: %d\n"
            "Function types applied: %d\n"
            "Function types unchanged/skipped: %d\n"
            "Function type failures: %d\n"
            "Argument components selected from source: %d\n"
            "Destination argument components kept: %d\n"
            "Return component selected from source: %d\n"
            "Destination return component kept: %d\n\n"
            "Parse errors: %d\n"
            "Other failures: %d\n"
            "Cancelled: %s"
            % (
                self.processed, self.groups, self.renamed,
                self.already_named_global, self.already_same,
                self.skipped_named, self.name_conflicts, self.not_found,
                self.ambiguous, self.unsafe, self.created_functions,
                self.fallback_used,
                self.types_total, self.types_existing,
                self.types_registered, self.types_failed,
                self.func_types_present, self.func_types_applied,
                self.func_types_unchanged, self.func_types_failed,
                self.args_source_used, self.args_destination_kept,
                self.returns_source_used, self.returns_destination_kept,
                self.parse_errors, self.failures,
                "yes" if self.cancelled else "no",
            )
        )

def _normalize_signature(sig):
    sig = sig.strip()
    if len(sig) >= 2 and sig[0] == '"' and sig[-1] == '"':
        sig = sig[1:-1].strip()
    return " ".join(sig.split())


def _unpack_text(payload):
    if not payload:
        return ""
    raw = base64.b64decode(payload.encode("ascii"), validate=False)
    return zlib.decompress(raw).decode("utf-8")


def _unpack_bytes(payload):
    if not payload:
        return None
    raw = base64.b64decode(payload.encode("ascii"), validate=False)
    return zlib.decompress(raw)


def _unpack_json(payload):
    text = _unpack_text(payload)
    if not text:
        return []
    value = json.loads(text)
    return value if isinstance(value, list) else []


def load_records(path):
    """
    Return:
      signature_records, type_records, function_metadata, parse_error_count

    CFS4 adds binary tinfo records; CFS3 text records remain legacy-compatible.

    CFS2 and legacy 3-column CFS signature rows remain accepted.
    """
    records = []
    type_records = {}
    func_meta = {}
    errors = 0
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

                if tag == "CFS4TYPE":
                    if len(row) < 6:
                        raise ValueError(
                            "CFS4TYPE row needs 6 columns, got %d" % len(row)
                        )
                    name = row[1].strip()
                    kind = row[2].strip().upper() or "TYPE"
                    type_blob = _unpack_bytes(row[3].strip())
                    fields_blob = _unpack_bytes(row[4].strip())
                    cmts_blob = _unpack_bytes(row[5].strip())
                    if not name or type_blob is None:
                        raise ValueError("empty CFS4TYPE name/type blob")
                    if name not in type_records:
                        type_records[name] = TypeRecord(
                            line_no, name, kind,
                            type_blob=type_blob,
                            fields_blob=fields_blob,
                            fldcmts_blob=cmts_blob,
                            binary=True,
                        )
                    continue

                if tag == "CFS4FUNC":
                    if len(row) < 8:
                        raise ValueError(
                            "CFS4FUNC row needs 8 columns, got %d" % len(row)
                        )
                    group_id = int(row[1].strip(), 0)
                    name = row[2].strip()
                    quality = row[3].strip().upper() or "NONE"
                    type_blob = _unpack_bytes(row[4].strip())
                    fields_blob = _unpack_bytes(row[5].strip())
                    cmts_blob = _unpack_bytes(row[6].strip())
                    dependencies = _unpack_json(row[7].strip())
                    if not name:
                        raise ValueError("empty CFS4FUNC name")
                    if quality not in ("USER", "EXPLICIT", "GUESSED", "NONE"):
                        quality = "EXPLICIT"
                    clean_deps = []
                    for dep in dependencies:
                        if isinstance(dep, str) and dep and dep not in clean_deps:
                            clean_deps.append(dep)
                    func_meta[(group_id, name)] = FuncMeta(
                        line_no, group_id, name, quality,
                        type_blob=type_blob,
                        fields_blob=fields_blob,
                        fldcmts_blob=cmts_blob,
                        dependencies=clean_deps,
                        binary=True,
                    )
                    continue

                if tag == "CFS3TYPE":
                    if len(row) < 4:
                        raise ValueError(
                            "CFS3TYPE row needs 4 columns, got %d" % len(row)
                        )

                    name = row[1].strip()
                    kind = row[2].strip().upper() or "TYPE"
                    declaration = _unpack_text(row[3].strip())

                    if not name or not declaration:
                        raise ValueError("empty CFS3TYPE name/declaration")

                    # First definition wins. Exporter deduplicates, but this
                    # also makes hand-edited or concatenated files deterministic.
                    if name not in type_records:
                        type_records[name] = TypeRecord(
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
                    prototype = _unpack_text(row[4].strip())
                    dependencies = _unpack_json(row[5].strip())

                    if not name:
                        raise ValueError("empty CFS3FUNC name")
                    if quality not in ("USER", "EXPLICIT", "GUESSED", "NONE"):
                        quality = "EXPLICIT"

                    clean_deps = []
                    for dep in dependencies:
                        if isinstance(dep, str) and dep and dep not in clean_deps:
                            clean_deps.append(dep)

                    func_meta[(group_id, name)] = FuncMeta(
                        line_no, group_id, name, quality,
                        prototype=prototype, dependencies=clean_deps, binary=False
                    )
                    continue

                if tag == "CFS2":
                    if len(row) < 12:
                        raise ValueError(
                            "CFS2 row needs 12 columns, got %d" % len(row)
                        )

                    rec = Record(
                        line_no=line_no,
                        group_id=int(row[1].strip(), 0),
                        rank=int(row[2].strip(), 0),
                        name=row[3].strip(),
                        mode=row[4].strip(),
                        signature=_normalize_signature(row[5]),
                        target_delta=int(row[6].strip(), 0),
                        rel_offset=int(row[7].strip(), 0),
                        rel_size=int(row[8].strip(), 0),
                        base_offset=int(row[9].strip(), 0),
                        insn_offset=int(row[10].strip(), 0),
                        score=int(row[11].strip(), 0),
                        legacy=False,
                    )

                    if rec.mode not in ("ENTRY", "BODY", "REL"):
                        raise ValueError("unsupported mode %r" % rec.mode)
                    if not rec.name or not rec.signature:
                        raise ValueError("empty name/signature")
                    if rec.mode == "REL":
                        if rec.rel_size not in (1, 2, 4, 8):
                            raise ValueError(
                                "REL width must be 1/2/4/8, got %d"
                                % rec.rel_size
                            )
                        if rec.rel_offset < 0 or rec.base_offset <= 0:
                            raise ValueError("invalid REL offsets")

                    records.append(rec)
                    continue

                # Backward-compatible legacy Cra0 row:
                # index,"name","pattern"
                if len(row) < 3:
                    raise ValueError("legacy row needs at least 3 columns")

                _old_index = int(first, 0)
                name = row[1].strip()
                signature = _normalize_signature(",".join(row[2:]))
                if not name or not signature:
                    raise ValueError("empty legacy name/signature")

                records.append(
                    Record(
                        line_no=line_no,
                        group_id=legacy_group,
                        rank=0,
                        name=name,
                        mode="ENTRY",
                        signature=signature,
                        legacy=True,
                    )
                )
                legacy_group += 1

            except Exception as exc:
                errors += 1
                _msg("PARSE_ERROR line %d: %s" % (line_no, exc))

    return records, type_records, func_meta, errors

def group_records(records):
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


def get_search_ranges():
    ranges = []
    seg = ida_segment.get_first_seg()
    while seg is not None:
        if bool(seg.perm & ida_segment.SEGPERM_EXEC) or seg.type == ida_segment.SEG_CODE:
            try:
                name = ida_segment.get_segm_name(seg)
            except Exception:
                name = "segment@%s" % _ea(seg.start_ea)
            ranges.append((seg.start_ea, seg.end_ea, name))
        seg = ida_segment.get_next_seg(seg.start_ea)

    if not ranges:
        lo = ida_ida.inf_get_min_ea()
        hi = ida_ida.inf_get_max_ea()
        if lo != BADADDR and hi != BADADDR and hi > lo:
            ranges.append((lo, hi, "<whole-idb>"))
    return ranges


def find_up_to_two(signature, ranges):
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
    matches = []

    for start, end, _name in ranges:
        cur = start
        while cur < end:
            ea = ida_bytes.find_bytes(
                signature, cur, range_end=end, flags=flags, radix=16
            )
            if ea == BADADDR:
                break
            matches.append(ea)
            if len(matches) >= 2:
                return matches
            cur = ea + 1
    return matches


def _name_state(ea):
    current = ida_name.get_name(ea) or ""
    flags = ida_bytes.get_full_flags(ea)
    user = ida_bytes.has_user_name(flags)
    auto = ida_bytes.has_auto_name(flags)
    dummy = ida_bytes.has_dummy_name(flags)

    protected = bool(current and (user or (not auto and not dummy)))
    return current, protected


def _global_name_ea(name):
    try:
        return ida_name.get_name_ea(BADADDR, name)
    except Exception:
        return BADADDR


def _read_signed(ea, width):
    data = ida_bytes.get_bytes(ea, width)
    if data is None or len(data) != width:
        return None
    return int.from_bytes(data, byteorder="little", signed=True)


def _target_is_mapped_codeish(ea):
    if ea == BADADDR or not ida_bytes.is_mapped(ea):
        return False

    seg = ida_segment.getseg(ea)
    if seg is None:
        return False

    return bool(seg.perm & ida_segment.SEGPERM_EXEC) or seg.type == ida_segment.SEG_CODE


def resolve_candidate(rec, match_ea):
    """
    Returns (status, target_ea, detail)
      ok       -> safe target address
      unsafe   -> unique signature but target resolution cannot be trusted
    """
    if rec.mode == "ENTRY":
        target = match_ea + rec.target_delta
        return "ok", target, "entry"

    if rec.mode == "BODY":
        owner = ida_funcs.get_func(match_ea)
        if owner is None:
            return "unsafe", BADADDR, "BODY match is not inside an IDA function"
        return "ok", owner.start_ea, "body-owner"

    if rec.mode == "REL":
        insn_ea = match_ea + rec.insn_offset
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, insn_ea) <= 0 or insn.size <= 0:
            return "unsafe", BADADDR, "REL xref instruction does not decode"

        expected_end = match_ea + rec.base_offset
        if insn_ea + insn.size != expected_end:
            return (
                "unsafe", BADADDR,
                "REL instruction length changed (expected end %s, got %s)"
                % (_ea(expected_end), _ea(insn_ea + insn.size))
            )

        field_ea = match_ea + rec.rel_offset
        if not (insn_ea <= field_ea and field_ea + rec.rel_size <= insn_ea + insn.size):
            return "unsafe", BADADDR, "REL field lies outside decoded instruction"

        disp = _read_signed(field_ea, rec.rel_size)
        if disp is None:
            return "unsafe", BADADDR, "REL displacement bytes unavailable"

        target = match_ea + rec.base_offset + disp + rec.target_delta
        if not _target_is_mapped_codeish(target):
            return (
                "unsafe", BADADDR,
                "REL target %s is not mapped executable/code" % _ea(target)
            )

        return "ok", target, "rel%d" % (rec.rel_size * 8)

    return "unsafe", BADADDR, "unsupported mode %s" % rec.mode


def _ensure_function_start(target_ea, allow_create=True):
    """
    Returns (status, function_start, created)
      ok       target is/was made a function start
      interior target lies inside an existing function but is not its start
      failed   could not safely create/locate a function
    """
    f = ida_funcs.get_func(target_ea)
    if f is not None:
        if f.start_ea != target_ea:
            return "interior", f.start_ea, False
        return "ok", f.start_ea, False

    if not allow_create or not CREATE_MISSING_FUNCTIONS:
        return "failed", BADADDR, False

    flags = ida_bytes.get_full_flags(target_ea)
    if not ida_bytes.is_code(flags):
        if ida_ua.create_insn(target_ea) <= 0:
            return "failed", BADADDR, False

    if not ida_funcs.add_func(target_ea):
        return "failed", BADADDR, False

    f = ida_funcs.get_func(target_ea)
    if f is None or f.start_ea != target_ea:
        return "failed", BADADDR, False

    return "ok", f.start_ea, True



# ---------------------------------------------------------------------------
# CFS4 type registration + conservative function-prototype merge
# ---------------------------------------------------------------------------

def _named_type_tinfo(name):
    """
    Resolve a named type through the destination IDB's Local Types and all base
    TILs. This makes "Vector3 already exists" protection explicit instead of
    depending on implicit base-library lookup behavior.
    """
    if not name:
        return None

    root = ida_typeinf.get_idati()
    seen = set()

    def visit(til):
        if til is None:
            return None

        try:
            key = (str(getattr(til, "name", "")), id(til))
        except Exception:
            key = id(til)

        if key in seen:
            return None
        seen.add(key)

        try:
            tif = til.get_named_type(name)
        except Exception:
            tif = None

        if tif is not None:
            return tif

        try:
            nbases = int(til.nbases)
        except Exception:
            nbases = 0

        for i in range(nbases):
            try:
                base = til.base(i)
            except Exception:
                base = None
            found = visit(base)
            if found is not None:
                return found

        return None

    found = visit(root)
    if found is not None:
        return found

    # Last fallback through the tinfo constructor. This is useful for some
    # compiler-provided built-in typedefs that aren't exposed as a normal
    # named-type entry of the enumerated TIL tree.
    try:
        return ida_typeinf.tinfo_t(name=name, til=root)
    except Exception:
        return None

def _named_type_present(name):
    return _named_type_tinfo(name) is not None


def _named_type_is_forward(name):
    tif = _named_type_tinfo(name)
    if tif is None:
        return False
    try:
        return bool(tif.is_forward_decl())
    except Exception:
        return False


def _named_type_well_defined(name):
    tif = _named_type_tinfo(name)
    if tif is None:
        return False

    # CFS4's bug was here: a mere `struct Foo;` could pass presence/
    # is_well_defined checks and be reported as successfully registered.
    try:
        if tif.is_forward_decl():
            return False
    except Exception:
        pass

    try:
        return bool(tif.is_well_defined())
    except Exception:
        return True


def _incoming_is_forward(rec):
    if rec is None or not rec.binary or rec.type_blob is None:
        return False
    tif = _deserialize_binary_tinfo(
        rec.type_blob, rec.fields_blob, rec.fldcmts_blob
    )
    if tif is None:
        return False
    try:
        return bool(tif.is_forward_decl())
    except Exception:
        return False


def _named_type_shape(name):
    """Human-readable post-import diagnostic."""
    tif = _named_type_tinfo(name)
    if tif is None:
        return "missing"

    try:
        if tif.is_forward_decl():
            return "forward"
    except Exception:
        pass

    try:
        udt = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt, ida_typeinf.GTD_CALC_LAYOUT):
            return "%s members=%d size=0x%X" % (
                "union" if bool(udt.is_union) else "struct",
                len(udt),
                int(udt.total_size),
            )
    except Exception:
        pass

    try:
        ei = ida_typeinf.enum_type_data_t()
        if tif.get_enum_details(ei):
            return "enum members=%d" % len(ei)
    except Exception:
        pass

    return "defined"


def _forward_decl_btf(kind):
    kind = (kind or "").upper()
    if kind == "STRUCT":
        return ida_typeinf.BTF_STRUCT
    if kind == "UNION":
        return ida_typeinf.BTF_UNION
    if kind == "ENUM":
        return ida_typeinf.BTF_ENUM
    return None


def _deserialize_binary_tinfo(type_blob, fields_blob=None, fldcmts_blob=None):
    if type_blob is None:
        return None
    tif = ida_typeinf.tinfo_t()
    try:
        ok = tif.deserialize(
            ida_typeinf.get_idati(),
            type_blob,
            fields_blob,
            fldcmts_blob,
        )
    except Exception as exc:
        _msg("TYPE_DESERIALIZE_EXCEPTION %s" % exc)
        ok = False
    return tif if ok else None


def register_missing_types(type_records, stats):
    """
    CFS5 registration is binary and non-destructive.

    Destination policy:
      * existing FULL same-named type -> immutable, keep destination
      * existing FORWARD same-named type -> incomplete, may be upgraded
      * missing type -> create forward placeholder when needed, then full body

    Incoming policy:
      * full transported UDT/enum must become a non-forward destination type
      * a source type that was genuinely forward/opaque may remain forward
    """
    stats.types_total = len(type_records)
    if not type_records:
        return {"preexisting": set(), "registered": set(), "failed": set()}

    idati = ida_typeinf.get_idati()
    preexisting = set()
    pending_binary = {}
    pending_text = {}
    replaceable_forwards = set()

    for name, rec in type_records.items():
        existing = _named_type_tinfo(name)

        if existing is not None:
            is_fwd = False
            try:
                is_fwd = bool(existing.is_forward_decl())
            except Exception:
                pass

            incoming_fwd = _incoming_is_forward(rec) if rec.binary else False

            if not is_fwd:
                preexisting.add(name)
                stats.types_existing += 1
                _msg(
                    "TYPE_KEEP_EXISTING %-35s kind=%s shape=%s"
                    % (name, rec.kind, _named_type_shape(name))
                )
                continue

            if incoming_fwd:
                # Both sides are intentionally opaque/forward. Nothing useful
                # can be added and there is no reason to replace it.
                preexisting.add(name)
                stats.types_existing += 1
                _msg(
                    "TYPE_KEEP_FORWARD %-36s kind=%s"
                    % (name, rec.kind)
                )
                continue

            # Important CFS5 behavior: a previous CFS4-created forward is not a
            # protected user definition. Upgrade it to the transported body.
            replaceable_forwards.add(name)
            _msg(
                "TYPE_UPGRADE_FORWARD %-33s kind=%s"
                % (name, rec.kind)
            )

        if rec.binary:
            pending_binary[name] = rec
        else:
            pending_text[name] = rec

    registered = set()
    created_forwards = set(replaceable_forwards)

    # Phase 1: create placeholders for missing recursive UDT/enum names.
    for name, rec in list(pending_binary.items()):
        if name in replaceable_forwards:
            continue

        btf = _forward_decl_btf(rec.kind)
        if btf is None:
            continue

        # If incoming itself is only a forward declaration, this placeholder is
        # the final legitimate representation.
        incoming_forward = _incoming_is_forward(rec)

        try:
            fwd = ida_typeinf.tinfo_t()
            rc = fwd.create_forward_decl(idati, btf, name, 0)
        except Exception as exc:
            rc = None
            _msg("TYPE_FORWARD_EXCEPTION %-27s error=%s" % (name, exc))

        if rc == ida_typeinf.TERR_OK or _named_type_present(name):
            created_forwards.add(name)
            _msg("TYPE_FORWARD %-37s kind=%s" % (name, rec.kind))

            if incoming_forward:
                registered.add(name)
                stats.types_registered += 1
                del pending_binary[name]
                _msg(
                    "TYPE_REGISTERED_FORWARD %-26s kind=%s"
                    % (name, rec.kind)
                )

    # Phase 2: deserialize and replace our placeholders with complete bodies.
    max_passes = min(16, max(2, len(pending_binary) + 1))
    for pass_no in range(1, max_passes + 1):
        if not pending_binary:
            break
        progress = False

        names = sorted(
            pending_binary,
            key=lambda n: (
                0 if pending_binary[n].kind in ("STRUCT", "UNION", "ENUM") else 1,
                n,
            ),
        )

        for name in names:
            rec = pending_binary.get(name)
            if rec is None:
                continue

            tif = _deserialize_binary_tinfo(
                rec.type_blob, rec.fields_blob, rec.fldcmts_blob
            )
            if tif is None:
                continue

            try:
                incoming_forward = bool(tif.is_forward_decl())
            except Exception:
                incoming_forward = False

            ntf = ida_typeinf.NTF_REPLACE if name in created_forwards else 0

            try:
                rc = tif.set_named_type(idati, name, ntf)
            except Exception as exc:
                rc = None
                if pass_no == max_passes:
                    _msg("TYPE_SAVE_EXCEPTION %-31s error=%s" % (name, exc))

            # Full incoming records MUST result in a non-forward destination.
            if rc == ida_typeinf.TERR_OK:
                if incoming_forward:
                    success = _named_type_present(name)
                else:
                    success = _named_type_well_defined(name)
            else:
                success = False

            if success:
                registered.add(name)
                stats.types_registered += 1
                del pending_binary[name]
                progress = True
                _msg(
                    "TYPE_REGISTERED %-35s kind=%s pass=%d shape=%s"
                    % (name, rec.kind, pass_no, _named_type_shape(name))
                )

        if not progress:
            break

    # Legacy textual CFS3 fallback only.
    if pending_text:
        parse_flags = (
            ida_typeinf.HTI_NWR
            | ida_typeinf.HTI_HIGH
            | ida_typeinf.HTI_RELAXED
        )
        max_text_passes = min(8, max(2, len(pending_text) + 1))
        for pass_no in range(1, max_text_passes + 1):
            if not pending_text:
                break
            progress = False

            for name in list(pending_text.keys()):
                rec = pending_text[name]
                try:
                    errors = ida_typeinf.parse_decls(
                        idati, rec.declaration, None, parse_flags
                    )
                except Exception:
                    errors = 1

                if errors == 0 and _named_type_well_defined(name):
                    registered.add(name)
                    stats.types_registered += 1
                    del pending_text[name]
                    progress = True
                    _msg(
                        "TYPE_REGISTERED_LEGACY %-28s shape=%s"
                        % (name, _named_type_shape(name))
                    )

            if not progress:
                break

    failed = set(pending_binary) | set(pending_text)
    for name in sorted(failed):
        stats.types_failed += 1
        rec = type_records[name]
        _msg(
            "TYPE_FAILED %-39s kind=%s line=%d format=%s shape=%s"
            % (
                name,
                rec.kind,
                rec.line_no,
                "BIN" if rec.binary else "TEXT",
                _named_type_shape(name),
            )
        )

    return {
        "preexisting": preexisting,
        "registered": registered,
        "failed": failed,
    }


def _parse_function_prototype(declaration):
    """Legacy CFS3 textual-prototype fallback."""
    if not declaration:
        return None
    idati = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    flags = (
        ida_typeinf.PT_TYP
        | ida_typeinf.PT_SIL
        | ida_typeinf.PT_HIGH
        | ida_typeinf.PT_RELAXED
    )
    try:
        ok = ida_typeinf.parse_decl(tif, idati, declaration, flags)
    except Exception:
        ok = False
    if not ok:
        return None
    try:
        if tif.is_funcptr():
            tif = tif.get_pointed_object()
    except Exception:
        pass
    try:
        return tif if tif.is_func() else None
    except Exception:
        return None


def _function_tinfo_from_meta(meta):
    if meta is None:
        return None
    if meta.binary:
        tif = _deserialize_binary_tinfo(
            meta.type_blob, meta.fields_blob, meta.fldcmts_blob
        )
    else:
        tif = _parse_function_prototype(meta.prototype)
    if tif is None:
        return None
    try:
        if tif.is_funcptr():
            tif = tif.get_pointed_object()
    except Exception:
        pass
    try:
        return tif if tif.is_func() else None
    except Exception:
        return None


def _get_function_tinfo(ea, allow_guess=True):
    """
    Return (tinfo_or_None, explicit, user_type).

    Guessed type is used only as merge context. It is never treated as stronger
    than a destination-specific named type.
    """
    tif = ida_typeinf.tinfo_t()
    explicit = False
    user_type = False

    try:
        explicit = bool(ida_nalt.get_tinfo(tif, ea))
    except Exception:
        explicit = False

    try:
        user_type = bool(ida_nalt.is_userti(ea))
    except Exception:
        user_type = False

    if not explicit and allow_guess:
        guessed = ida_typeinf.tinfo_t()
        try:
            rc = ida_typeinf.guess_tinfo(guessed, ea)
        except Exception:
            rc = ida_typeinf.GUESS_FUNC_FAILED

        if rc != ida_typeinf.GUESS_FUNC_FAILED:
            tif = guessed
        else:
            return None, False, user_type

    try:
        if tif.is_funcptr():
            tif = tif.get_pointed_object()
    except Exception:
        pass

    try:
        if not tif.is_func():
            return None, explicit, user_type
    except Exception:
        return None, explicit, user_type

    return tif, explicit, user_type


def _type_specificity(tif, depth=0):
    """
    Heuristic information score for one argument/return type.

    Named typedef/UDT/enum types score much higher than generic machine-width
    scalars such as __int64. Pointers/arrays inherit their pointee specificity.
    """
    if tif is None or depth > 12:
        return 0

    try:
        if tif.empty() or tif.is_unknown():
            return 0
    except Exception:
        pass

    name = ""
    try:
        maybe_name = tif.get_type_name()
        if isinstance(maybe_name, str):
            name = maybe_name
    except Exception:
        pass

    try:
        if tif.is_typeref():
            # Local named types are the strongest signal. A type coming from a
            # base TIL (e.g. a standard/compiler typedef) is useful, but should
            # not automatically outrank an old Local-Type such as Vector3.
            try:
                from_base_til = bool(tif.is_from_subtil())
            except Exception:
                from_base_til = False

            if from_base_til:
                return 70 if name and not name.startswith("#") else 60

            return 125 if name and not name.startswith("#") else 110
    except Exception:
        pass

    try:
        if tif.is_udt():
            return 120
    except Exception:
        pass

    try:
        if tif.is_enum():
            return 115
    except Exception:
        pass

    try:
        if tif.is_funcptr():
            return 100
    except Exception:
        pass

    try:
        if tif.is_func():
            return 95
    except Exception:
        pass

    try:
        if tif.is_ptr_or_array():
            child = tif.get_ptrarr_object()
            child_score = _type_specificity(child, depth + 1)
            # void*/char* and generic scalar pointers remain below a pointer to
            # Vector3 / user typedef / enum.
            return 30 + min(100, child_score)
    except Exception:
        pass

    try:
        if tif.is_void():
            return 2
    except Exception:
        pass

    try:
        if tif.is_bool():
            return 18
    except Exception:
        pass

    try:
        if tif.is_floating():
            return 16
    except Exception:
        pass

    try:
        if tif.is_integral() or tif.is_arithmetic():
            return 14
    except Exception:
        pass

    # Unknown complex/custom forms are still more informative than an empty type.
    return 25


def _type_is_specific(tif):
    return _type_specificity(tif) >= 80


def _choose_component_type(
    dst_type,
    src_type,
    src_quality,
    dst_function_user_typed,
):
    """
    Return (chosen_tinfo, source_won).

    Rules:
      * destination specific named/UDT/enum type always wins;
      * source specific type can replace generic destination __int64/int/etc;
      * if both are generic and destination function is user-typed, keep dst;
      * if both are generic and destination isn't user-typed, prefer source
        when source is USER/EXPLICIT, not merely GUESSED.
    """
    if src_type is None:
        return (dst_type.copy() if dst_type is not None else None), False

    if dst_type is None:
        return src_type.copy(), True

    dst_score = _type_specificity(dst_type)
    src_score = _type_specificity(src_type)

    if dst_score >= 80:
        return dst_type.copy(), False

    if src_score >= 80 and src_score > dst_score:
        return src_type.copy(), True

    if dst_function_user_typed:
        return dst_type.copy(), False

    if src_quality in ("USER", "EXPLICIT") and src_score >= dst_score:
        return src_type.copy(), True

    if src_quality == "GUESSED":
        # Guessed source info should only fill a substantially weaker hole.
        if src_score > dst_score + 20:
            return src_type.copy(), True
        return dst_type.copy(), False

    return dst_type.copy(), False


def _new_funcarg(name, tif, cmt="", flags=0, argloc=None):
    """
    Build funcarg_t using the documented IDAPython 9 constructor.

    funcarg_t(name, type, argloc) requires a non-empty constructor name, so
    unnamed arguments use a temporary placeholder that is cleared afterwards.
    """
    loc = ida_typeinf.argloc_t()
    ctor_name = name or "__cfs_arg"

    try:
        arg = ida_typeinf.funcarg_t(ctor_name, tif.copy(), loc)
    except Exception:
        # Some wrappers are happier if the temporary name is plain/alphanumeric.
        arg = ida_typeinf.funcarg_t("a", tif.copy(), loc)

    try:
        arg.name = name or ""
    except Exception:
        pass

    if argloc is not None:
        try:
            arg.argloc = argloc
        except Exception:
            pass

    try:
        arg.cmt = cmt or ""
    except Exception:
        pass
    try:
        arg.flags = int(flags)
    except Exception:
        pass
    return arg

def _copy_arg_text(src_arg, dst_arg, prefer_dst):
    src_name = getattr(src_arg, "name", "") if src_arg is not None else ""
    dst_name = getattr(dst_arg, "name", "") if dst_arg is not None else ""

    if prefer_dst and dst_name:
        name = dst_name
    else:
        name = dst_name or src_name

    src_cmt = getattr(src_arg, "cmt", "") if src_arg is not None else ""
    dst_cmt = getattr(dst_arg, "cmt", "") if dst_arg is not None else ""
    cmt = dst_cmt or src_cmt

    try:
        flags = int(getattr(dst_arg if prefer_dst else src_arg, "flags", 0))
    except Exception:
        flags = 0

    return name, cmt, flags


def _merge_function_tinfos(
    src_tif,
    dst_tif,
    src_quality,
    dst_function_user_typed,
    stats,
):
    src = ida_typeinf.func_type_data_t()
    if not src_tif.get_func_details(src):
        return None, False

    dst = ida_typeinf.func_type_data_t()
    have_dst = bool(dst_tif is not None and dst_tif.get_func_details(dst))

    # Preserve the destination skeleton not only when IDA marks the whole
    # function type as user-owned, but also when any destination component is
    # already a specific named/UDT/enum type. That is a strong signal that the
    # newer IDB carries deliberate/newer prototype knowledge.
    dst_has_specific = False
    if have_dst:
        try:
            dst_has_specific = _type_is_specific(dst.rettype)
        except Exception:
            dst_has_specific = False

        if not dst_has_specific:
            for _arg in dst:
                if _type_is_specific(_arg.type):
                    dst_has_specific = True
                    break

    use_dst_skeleton = have_dst and (
        dst_function_user_typed or dst_has_specific
    )
    base = dst if use_dst_skeleton else src

    try:
        user_cc = bool(ida_typeinf.is_user_cc(base.cc))
    except Exception:
        user_cc = False

    merged = ida_typeinf.func_type_data_t()
    try:
        merged.cc = base.cc
    except Exception:
        pass
    try:
        merged.flags = base.flags
    except Exception:
        pass

    # Custom/user calling conventions carry explicit register/stack locations.
    # Preserve those from the selected skeleton. For normal conventions, empty
    # locations let IDA recompute ABI locations for the merged types.
    if user_cc:
        for attr in ("retloc", "stkargs", "spoiled"):
            try:
                setattr(merged, attr, getattr(base, attr))
            except Exception:
                pass

    # Return type: same information-strength rule as arguments.
    dst_ret = dst.rettype if have_dst else None
    chosen_ret, source_won = _choose_component_type(
        dst_ret,
        src.rettype,
        src_quality,
        dst_function_user_typed,
    )
    if chosen_ret is None:
        chosen_ret = src.rettype.copy()

    merged.rettype = chosen_ret
    if source_won:
        stats.returns_source_used += 1
    elif have_dst:
        stats.returns_destination_kept += 1

    src_count = len(src)
    dst_count = len(dst) if have_dst else 0
    arg_count = dst_count if use_dst_skeleton else src_count

    for i in range(arg_count):
        src_arg = src[i] if i < src_count else None
        dst_arg = dst[i] if i < dst_count else None

        src_type = src_arg.type if src_arg is not None else None
        dst_type = dst_arg.type if dst_arg is not None else None

        chosen, source_won = _choose_component_type(
            dst_type,
            src_type,
            src_quality,
            dst_function_user_typed,
        )

        if chosen is None:
            continue

        if source_won:
            stats.args_source_used += 1
        elif dst_arg is not None:
            stats.args_destination_kept += 1

        name, cmt, arg_flags = _copy_arg_text(
            src_arg,
            dst_arg,
            prefer_dst=bool(dst_arg is not None and dst_function_user_typed),
        )

        base_arg = dst_arg if use_dst_skeleton else src_arg
        base_argloc = None
        if user_cc and base_arg is not None:
            try:
                base_argloc = base_arg.argloc
            except Exception:
                base_argloc = None

        merged.push_back(
            _new_funcarg(
                name,
                chosen,
                cmt,
                arg_flags,
                argloc=base_argloc,
            )
        )

    new_tif = ida_typeinf.tinfo_t()
    if not new_tif.create_func(merged):
        return None, False

    changed = True
    if dst_tif is not None:
        try:
            changed = not (new_tif == dst_tif)
        except Exception:
            changed = True

    return new_tif, changed


def apply_function_type_safe(ea, meta, stats):
    """
    Merge and apply a transported function prototype.

    This function never edits the definitions of same-named destination UDTs.
    The prototype was exported with ordinal references converted to names, so
    parsing here naturally resolves Vector3/etc. to the destination definition.
    """
    if meta is None or not meta.has_prototype() or meta.quality == "NONE":
        return "no-meta"

    stats.func_types_present += 1

    unresolved_deps = [
        dep for dep in meta.dependencies
        if dep and not _named_type_present(dep)
    ]
    if unresolved_deps:
        stats.func_types_failed += 1
        _msg(
            "TYPE_FUNC_DEP_MISSING %-26s @ %s deps=%s"
            % (
                meta.name,
                _ea(ea),
                ",".join(unresolved_deps[:8])
                + ("..." if len(unresolved_deps) > 8 else ""),
            )
        )
        return "dependency-missing"

    src_tif = _function_tinfo_from_meta(meta)
    if src_tif is None:
        stats.func_types_failed += 1
        _msg(
            "TYPE_FUNC_DECODE_FAIL %-30s @ %s"
            % (meta.name, _ea(ea))
        )
        return "parse-failed"

    dst_tif, dst_explicit, dst_user = _get_function_tinfo(
        ea, allow_guess=True
    )

    try:
        new_tif, changed = _merge_function_tinfos(
            src_tif,
            dst_tif,
            meta.quality,
            dst_user,
            stats,
        )
    except Exception as exc:
        stats.func_types_failed += 1
        _msg(
            "TYPE_FUNC_MERGE_FAIL %-30s @ %s error=%s"
            % (meta.name, _ea(ea), exc)
        )
        return "merge-failed"

    if new_tif is None:
        stats.func_types_failed += 1
        _msg(
            "TYPE_FUNC_BUILD_FAIL %-30s @ %s"
            % (meta.name, _ea(ea))
        )
        return "build-failed"

    # If source carried a deliberate prototype but destination only had a
    # guessed equivalent, still apply it so the type becomes definite.
    if (
        not dst_explicit
        and meta.quality in ("USER", "EXPLICIT")
    ):
        changed = True

    if not changed:
        stats.func_types_unchanged += 1
        _msg(
            "TYPE_FUNC_UNCHANGED %-30s @ %s"
            % (meta.name, _ea(ea))
        )
        return "unchanged"

    try:
        ok = ida_typeinf.apply_tinfo(
            ea,
            new_tif,
            ida_typeinf.TINFO_DEFINITE,
        )
    except Exception as exc:
        ok = False
        _msg(
            "TYPE_FUNC_APPLY_EXCEPTION %-25s @ %s error=%s"
            % (meta.name, _ea(ea), exc)
        )

    if not ok:
        stats.func_types_failed += 1
        _msg(
            "TYPE_FUNC_APPLY_FAIL %-30s @ %s"
            % (meta.name, _ea(ea))
        )
        return "apply-failed"

    # Preserve the semantic distinction exported by IDA: only a source type
    # that was actually marked user-owned gets the destination user-type bit.
    if meta.quality == "USER":
        try:
            ida_nalt.set_userti(ea)
        except Exception:
            pass

    stats.func_types_applied += 1
    _msg(
        "TYPE_FUNC_APPLIED %-32s @ %s quality=%s"
        % (meta.name, _ea(ea), meta.quality)
    )
    return "applied"


def try_apply_group(name, records, ranges, match_cache, stats, meta=None):
    """
    Resolve one function group and then merge its CFS4 prototype.

    A safe name match is always established first. If a different meaningful
    destination name already owns the matched function, both rename and type
    import are skipped to respect newer/manual destination work.
    """
    existing_global = _global_name_ea(name)
    if existing_global != BADADDR:
        stats.already_named_global += 1

        f = ida_funcs.get_func(existing_global)
        if f is not None and f.start_ea == existing_global:
            _msg(
                "SKIP_NAME_EXISTS %-37s @ %s; merging type only"
                % (name, _ea(existing_global))
            )
            apply_function_type_safe(existing_global, meta, stats)
        else:
            _msg(
                "SKIP_NAME_EXISTS %-37s @ %s (not a function start)"
                % (name, _ea(existing_global))
            )

        return "already-global"

    saw_not_found = False
    saw_ambiguous = False
    saw_unsafe = False

    for candidate_index, rec in enumerate(records):
        matches = match_cache.get(rec.signature)
        if matches is None:
            matches = find_up_to_two(rec.signature, ranges)
            match_cache[rec.signature] = matches

        if len(matches) == 0:
            saw_not_found = True
            _msg(
                "CANDIDATE_NOT_FOUND %-32s rank=%d mode=%s"
                % (name, rec.rank, rec.mode)
            )
            continue

        if len(matches) > 1:
            saw_ambiguous = True
            _msg(
                "CANDIDATE_AMBIGUOUS %-32s rank=%d mode=%s hits=%s,%s"
                % (
                    name,
                    rec.rank,
                    rec.mode,
                    _ea(matches[0]),
                    _ea(matches[1]),
                )
            )
            continue

        match_ea = matches[0]
        rstatus, target_ea, detail = resolve_candidate(rec, match_ea)
        if rstatus != "ok":
            saw_unsafe = True
            _msg(
                "CANDIDATE_UNSAFE %-35s rank=%d mode=%s match=%s %s"
                % (name, rec.rank, rec.mode, _ea(match_ea), detail)
            )
            continue

        # BODY deliberately resolves an interior match to the owning function.
        # ENTRY/REL require the resolved target itself to be a function start.
        allow_create = rec.mode != "BODY"
        fstatus, func_ea, created = _ensure_function_start(
            target_ea,
            allow_create=allow_create,
        )

        if fstatus == "interior":
            saw_unsafe = True
            _msg(
                "CANDIDATE_INTERIOR %-33s rank=%d mode=%s target=%s owner=%s"
                % (
                    name,
                    rec.rank,
                    rec.mode,
                    _ea(target_ea),
                    _ea(func_ea),
                )
            )
            continue

        if fstatus != "ok":
            saw_unsafe = True
            _msg(
                "CANDIDATE_NOFUNC %-35s rank=%d mode=%s target=%s"
                % (name, rec.rank, rec.mode, _ea(target_ea))
            )
            continue

        if created:
            stats.created_functions += 1
            _msg("CREATED_FUNC %-42s @ %s" % (name, _ea(func_ea)))

        current, protected = _name_state(func_ea)

        if current == name:
            stats.already_same += 1
            if candidate_index > 0:
                stats.fallback_used += 1

            _msg(
                "ALREADY_SAME %-41s @ %s via=%s rank=%d"
                % (name, _ea(func_ea), rec.mode, rec.rank)
            )
            apply_function_type_safe(func_ea, meta, stats)
            return "already-same"

        if protected:
            stats.skipped_named += 1
            _msg(
                "SKIP_NAMED %-42s @ %s current=%s; type untouched"
                % (name, _ea(func_ea), current)
            )
            return "skip-named"

        conflict = _global_name_ea(name)
        if conflict != BADADDR and conflict != func_ea:
            stats.name_conflicts += 1
            _msg(
                "NAME_CONFLICT %-39s target=%s existing=%s"
                % (name, _ea(func_ea), _ea(conflict))
            )
            return "name-conflict"

        flags = ida_name.SN_CHECK | ida_name.SN_NOWARN | ida_name.SN_NON_AUTO
        if not ida_name.set_name(func_ea, name, flags):
            stats.failures += 1
            _msg(
                "FAIL_RENAME %-42s @ %s via=%s rank=%d"
                % (name, _ea(func_ea), rec.mode, rec.rank)
            )
            return "failure"

        try:
            ida_name.make_name_user(func_ea)
        except Exception:
            pass

        if (ida_name.get_name(func_ea) or "") != name:
            stats.failures += 1
            _msg("FAIL_VERIFY %-42s @ %s" % (name, _ea(func_ea)))
            return "failure"

        stats.renamed += 1
        if candidate_index > 0:
            stats.fallback_used += 1

        _msg(
            "RENAMED %-46s @ %s via=%s rank=%d%s"
            % (
                name,
                _ea(func_ea),
                rec.mode,
                rec.rank,
                " FALLBACK" if candidate_index > 0 else "",
            )
        )

        # Type import is deliberately after the name resolution succeeds.
        apply_function_type_safe(func_ea, meta, stats)
        return "renamed"

    # No candidate produced a safe unique target.
    if saw_unsafe:
        stats.unsafe += 1
        _msg("UNRESOLVED_UNSAFE %-36s" % name)
        return "unsafe"

    if saw_ambiguous:
        stats.ambiguous += 1
        _msg("UNRESOLVED_AMBIGUOUS %-33s" % name)
        return "ambiguous"

    stats.not_found += 1
    _msg("NOT_FOUND %-44s" % name)
    return "not-found"

def import_file(path):
    stats = Stats()

    try:
        records, type_records, func_meta, parse_errors = load_records(path)
    except Exception as exc:
        ida_kernwin.warning(
            "Could not read CFS/CFS2/CFS3/CFS4/CFS5/CFS5/CFS4 file:\n%s" % exc
        )
        return False

    stats.parse_errors = parse_errors
    groups = group_records(records)
    stats.groups = len(groups)

    if not groups:
        ida_kernwin.warning("No valid CFS/CFS2/CFS3/CFS4/CFS5/CFS5 signature records found.")
        return False

    ranges = get_search_ranges()
    if not ranges:
        ida_kernwin.warning("No executable/code search ranges found.")
        return False

    _msg("=" * 72)
    _msg("CFS5 Importer %s" % VERSION)
    _msg("File: %s" % path)
    _msg(
        "Functions: %d  Candidate rows: %d  Type records: %d  "
        "Prototype records: %d  Parse errors: %d"
        % (
            len(groups),
            len(records),
            len(type_records),
            len(func_meta),
            parse_errors,
        )
    )
    _msg(
        "Search ranges: %s"
        % ", ".join(
            "%s[%s-%s]" % (name, _ea(a), _ea(b))
            for a, b, name in ranges
        )
    )
    _msg(
        "Type policy: same-named destination types are immutable; "
        "specific destination argument types win."
    )
    _msg("=" * 72)

    # Register missing local types once, before any prototype parsing. A failed
    # type registration never prevents the signature/name transfer.
    ida_kernwin.show_wait_box(
        "NODELAY\nRegistering missing CFS3 local types..."
    )
    try:
        type_state = register_missing_types(type_records, stats)
    except Exception as exc:
        type_state = {
            "preexisting": set(),
            "registered": set(),
            "failed": set(type_records),
        }
        stats.types_total = len(type_records)
        stats.types_failed = len(type_records)
        _msg("TYPE_REGISTRATION_FATAL: %s" % exc)
    finally:
        ida_kernwin.hide_wait_box()

    _msg(
        "Types: %d kept-existing, %d registered, %d failed"
        % (
            len(type_state["preexisting"]),
            len(type_state["registered"]),
            len(type_state["failed"]),
        )
    )

    match_cache = {}

    ida_kernwin.clr_cancelled()
    ida_kernwin.show_wait_box(
        "NODELAY\nImporting CFS3 signatures + prototypes...\n"
        "Press Cancel to stop."
    )

    try:
        for pos, ((group_id, name), candidates) in enumerate(groups, 1):
            if ida_kernwin.user_cancelled():
                stats.cancelled = True
                _msg(
                    "CANCELLED after %d/%d functions."
                    % (pos - 1, len(groups))
                )
                break

            if (
                pos == 1
                or pos == len(groups)
                or pos % PROGRESS_EVERY == 0
            ):
                ida_kernwin.replace_wait_box(
                    "Importing CFS3 signatures + prototypes...\n"
                    "%d / %d\n"
                    "Renamed: %d  Missing: %d  Ambiguous: %d\n"
                    "Types applied: %d  Registered UDTs: %d\n"
                    "Current: %s"
                    % (
                        pos,
                        len(groups),
                        stats.renamed,
                        stats.not_found,
                        stats.ambiguous,
                        stats.func_types_applied,
                        stats.types_registered,
                        name,
                    )
                )

            meta = func_meta.get((group_id, name))

            try:
                try_apply_group(
                    name,
                    candidates,
                    ranges,
                    match_cache,
                    stats,
                    meta=meta,
                )
            except Exception as exc:
                stats.failures += 1
                _msg(
                    "FAIL_EXCEPTION %-39s error=%s"
                    % (name, exc)
                )

            stats.processed += 1

    finally:
        ida_kernwin.hide_wait_box()
        ida_kernwin.clr_cancelled()

    _msg("-" * 72)
    for line in stats.summary().splitlines():
        _msg(line)
    _msg("-" * 72)

    ida_kernwin.info(stats.summary())
    return stats.failures == 0

def choose_and_import():
    path = ida_kernwin.ask_file(
        False,
        "*.cfs",
        "Select CFS3 / CFS2 / CFS signature file to import",
    )
    if not path:
        _msg("Import cancelled.")
        return False

    path = os.path.abspath(path)
    _msg("Selected: %s" % path)
    return import_file(path)


class ImportHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        choose_and_import()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class CFS3ImporterPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Optimized CFS3 signature + type importer for IDA 9"
    help = (
        "Imports CFS3 signatures, transported local types/function prototypes, "
        "plus CFS2 and legacy CFS. Destination names/types are protected."
    )
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        self.handler = ImportHandler()

        try:
            ida_kernwin.detach_action_from_menu("File/Load file/", ACTION_ID)
        except Exception:
            pass
        ida_kernwin.unregister_action(ACTION_ID)

        ok = ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_ID,
                ACTION_LABEL,
                self.handler,
                None,
                "Import CFS3 signatures/types or CFS2/legacy CFS signatures",
                -1,
            )
        )

        if ok:
            if not ida_kernwin.attach_action_to_menu(
                "File/Load file/", ACTION_ID, ida_kernwin.SETMENU_APP
            ):
                _msg(
                    "File menu attachment failed; plugin hotkey still works."
                )
        else:
            _msg("WARNING: importer menu action registration failed.")

        _msg(
            "%s initialized on IDA %s. Hotkey: %s"
            % (VERSION, ida_kernwin.get_kernel_version(), PLUGIN_HOTKEY)
        )
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        choose_and_import()

    def term(self):
        try:
            ida_kernwin.detach_action_from_menu("File/Load file/", ACTION_ID)
        except Exception:
            pass
        ida_kernwin.unregister_action(ACTION_ID)


def PLUGIN_ENTRY():
    return CFS3ImporterPlugin()