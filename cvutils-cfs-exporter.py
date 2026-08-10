# CFS5 Exporter for IDA Pro 9.0 / IDAPython 9.0
#
# Fast name-transfer signatures for large binaries.
#
# CFS5 combines optimized name signatures with conservative type transport:
#   1) ENTRY: shortest unique instruction-aligned signature at function entry.
#   2) BODY:  shortest unique interior signature; importer resolves containing function.
#   3) REL:   short caller/xref signature; importer reads signed PC-relative
#             byte/word/dword/qword and resolves the referenced function.
#   4) FUNC:  function prototype detached from old Local-Type ordinals.
#   5) TYPE:  deduplicated named Local-Type definitions used by prototypes.
#
# It never extends a short function signature past the function body.
# Instead, short/unstable functions prefer REL xref anchors.
#
# Signature rows retain the CFS2 layout:
# CFS2,index,rank,"name","mode","signature",
#      target_delta,rel_offset,rel_size,base_offset,insn_offset,score
#
# CFS4FUNC links a prototype to the same group id.
# CFS4TYPE stores each referenced named Local Type once per file.
#
# REL formula:
#   disp   = signed_le(match + rel_offset, rel_size)
#   target = match + base_offset + disp + target_delta
#
# base_offset points to the end of the xref instruction.
#
# Target: IDA Professional 9.0 / Python 3.12.

VERSION = "6.0.0-ida9"
PLUGIN_NAME = "CFS5 Exporter (IDA 9)"
ACTION_SELECTED = "cfs5:export_selected"
ACTION_ALL_USER_NAMED = "cfs5:export_all_user_named"
SELECTED_HOTKEY = "Ctrl+Shift+E"

# Tuning. These defaults favor speed on very large DLLs.
MAX_PATTERN_BYTES = 48
GOOD_ENTRY_BYTES = 24
BODY_START_SAMPLES = 3
MAX_XREFS_TO_SEARCH = 24
XREF_EARLY_STOP_AFTER = 6
MAX_EXPORTED_CANDIDATES = 2
MIN_EXACT_BYTES = 6
MIN_SHORT_EXACT_BYTES = 4
PROGRESS_EVERY = 10

import base64
import csv
import json
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
import ida_xref
import idautils


BADADDR = ida_idaapi.BADADDR
UA_MAXOP = ida_ida.UA_MAXOP


def _msg(text):
    ida_kernwin.msg("[CFS5] %s\n" % text)


def _ea(ea):
    return "BADADDR" if ea == BADADDR else "0x%X" % ea


class Candidate:
    __slots__ = (
        "mode", "signature", "target_delta", "rel_offset", "rel_size",
        "base_offset", "insn_offset", "byte_len", "wildcards", "exact",
        "score", "origin"
    )

    def __init__(
        self, mode, signature, target_delta=0, rel_offset=0, rel_size=0,
        base_offset=0, insn_offset=0, byte_len=0, wildcards=0, exact=0,
        origin=""
    ):
        self.mode = mode
        self.signature = signature
        self.target_delta = int(target_delta)
        self.rel_offset = int(rel_offset)
        self.rel_size = int(rel_size)
        self.base_offset = int(base_offset)
        self.insn_offset = int(insn_offset)
        self.byte_len = int(byte_len)
        self.wildcards = int(wildcards)
        self.exact = int(exact)
        self.origin = origin

        mode_penalty = {"ENTRY": 0, "REL": 12, "BODY": 18}.get(mode, 25)
        # Length dominates: once a pattern is source-unique, shorter is usually
        # less flaky across versions. Wildcards get only a small penalty.
        self.score = self.byte_len * 100 + self.wildcards * 2 + mode_penalty

    def key(self):
        return (
            self.mode, self.signature, self.target_delta, self.rel_offset,
            self.rel_size, self.base_offset, self.insn_offset
        )


def _selected_indices(ctx):
    sel = getattr(ctx, "chooser_selection", None)
    if sel is None:
        return []
    try:
        return [int(x) for x in sel]
    except Exception:
        pass
    try:
        return [int(sel.at(i)) for i in range(sel.size())]
    except Exception:
        return []


def _get_function_start(ea):
    if ea == BADADDR:
        return BADADDR
    f = ida_funcs.get_func(ea)
    return BADADDR if f is None else f.start_ea


def get_selected_function_eas(ctx):
    if ctx is None or getattr(ctx, "widget_type", None) != ida_kernwin.BWN_FUNCS:
        return []

    eas = []
    chooser = getattr(ctx, "chooser", None)
    if chooser is not None:
        for row in _selected_indices(ctx):
            try:
                start = _get_function_start(chooser.get_ea(row))
            except Exception as exc:
                _msg("Could not read chooser row %d: %s" % (row, exc))
                continue
            if start != BADADDR:
                eas.append(start)

    if not eas:
        start = _get_function_start(getattr(ctx, "cur_ea", BADADDR))
        if start != BADADDR:
            eas.append(start)

    return sorted(set(eas))


def get_all_user_named_function_eas():
    result = []
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if f is None or f.start_ea != ea:
            continue
        flags = ida_bytes.get_full_flags(ea)
        if not ida_bytes.has_user_name(flags):
            continue
        if ida_name.get_name(ea):
            result.append(ea)
    return result


def get_search_ranges():
    ranges = []
    seg = ida_segment.get_first_seg()
    while seg is not None:
        if bool(seg.perm & ida_segment.SEGPERM_EXEC) or seg.type == ida_segment.SEG_CODE:
            ranges.append((seg.start_ea, seg.end_ea))
        seg = ida_segment.get_next_seg(seg.start_ea)

    if not ranges:
        lo = ida_ida.inf_get_min_ea()
        hi = ida_ida.inf_get_max_ea()
        if lo != BADADDR and hi != BADADDR and hi > lo:
            ranges.append((lo, hi))
    return ranges


def find_up_to_two(signature, ranges):
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
    matches = []

    for start, end in ranges:
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


def _iter_fcrefs_from(ea):
    cur = ida_xref.get_first_fcref_from(ea)
    while cur != BADADDR:
        yield cur
        cur = ida_xref.get_next_fcref_from(ea, cur)


def _iter_drefs_from(ea):
    cur = ida_xref.get_first_dref_from(ea)
    while cur != BADADDR:
        yield cur
        cur = ida_xref.get_next_dref_from(ea, cur)


def _has_far_reference(ea):
    return (
        ida_xref.get_first_fcref_from(ea) != BADADDR
        or ida_xref.get_first_dref_from(ea) != BADADDR
    )


def _operand_encoded_ranges(insn):
    """Return [(operand_index, offb, end_off), ...] for encoded operand fields."""
    entries = []
    for i in range(UA_MAXOP):
        op = insn.ops[i]
        if op.type == ida_ua.o_void:
            break
        offb = int(op.offb)
        if 0 < offb < insn.size:
            entries.append((i, offb, op.type))

    unique_offsets = sorted(set(off for _i, off, _t in entries))
    result = []
    for i, offb, optype in entries:
        later = [x for x in unique_offsets if x > offb]
        end_off = min(later) if later else insn.size
        if end_off <= offb:
            end_off = insn.size
        result.append((i, offb, end_off, optype))
    return result


def _pattern_tokens_for_insn(insn, force_rel=None):
    """
    Exact instruction bytes with address-dependent encoded operands wildcarded.

    force_rel=(offb,width) is used for the actual REL field and guarantees that
    exact displacement bytes are wildcarded even if IDA's xref metadata is odd.
    """
    raw = ida_bytes.get_bytes(insn.ea, insn.size)
    if raw is None or len(raw) != insn.size:
        raw = bytes(ida_bytes.get_byte(insn.ea + i) for i in range(insn.size))

    tokens = ["%02X" % b for b in raw]
    wildcard = set()

    if _has_far_reference(insn.ea):
        address_like = {
            ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem,
            ida_ua.o_displ, ida_ua.o_imm
        }
        for _idx, offb, end_off, optype in _operand_encoded_ranges(insn):
            if optype in address_like:
                for j in range(offb, min(end_off, insn.size)):
                    wildcard.add(j)

    if force_rel is not None:
        offb, width = force_rel
        for j in range(offb, min(offb + width, insn.size)):
            wildcard.add(j)

    for j in wildcard:
        tokens[j] = "?"

    return tokens


def decode_chunk(start_ea, end_ea):
    """Decode one contiguous IDA function chunk without crossing its boundary."""
    insns = []
    ea = start_ea
    while ea < end_ea:
        insn = ida_ua.insn_t()
        n = ida_ua.decode_insn(insn, ea)
        if n <= 0 or insn.size <= 0 or ea + insn.size > end_ea:
            # Preserve an undecodable byte as a 1-byte pseudo-instruction.
            raw = ida_bytes.get_byte(ea)
            insns.append({
                "ea": ea, "size": 1, "tokens": ["%02X" % raw], "insn": None
            })
            ea += 1
            continue

        insns.append({
            "ea": ea,
            "size": int(insn.size),
            "tokens": _pattern_tokens_for_insn(insn),
            "insn": insn,
        })
        ea += insn.size

    return insns


def _window_stats(insns, start_idx, end_idx):
    tokens = []
    for item in insns[start_idx:end_idx]:
        tokens.extend(item["tokens"])

    if not tokens:
        return None

    wild = sum(1 for t in tokens if t == "?")
    return {
        "tokens": tokens,
        "signature": " ".join(tokens),
        "byte_len": len(tokens),
        "wildcards": wild,
        "exact": len(tokens) - wild,
        "start_ea": insns[start_idx]["ea"],
        "end_ea": insns[end_idx - 1]["ea"] + insns[end_idx - 1]["size"],
    }


def _candidate_min_exact(total_bytes):
    return MIN_SHORT_EXACT_BYTES if total_bytes < 10 else MIN_EXACT_BYTES


def _unique_window_candidate(insns, start_idx, mode, ranges, thresholds):
    if start_idx < 0 or start_idx >= len(insns):
        return None

    tried_ends = set()
    for threshold in thresholds:
        total = 0
        end_idx = start_idx
        while end_idx < len(insns) and total < threshold and total < MAX_PATTERN_BYTES:
            total += insns[end_idx]["size"]
            end_idx += 1

        if end_idx <= start_idx:
            continue

        if total > MAX_PATTERN_BYTES:
            while end_idx > start_idx and (
                insns[end_idx - 1]["ea"] + insns[end_idx - 1]["size"]
                - insns[start_idx]["ea"]
            ) > MAX_PATTERN_BYTES:
                end_idx -= 1

        if end_idx <= start_idx or end_idx in tried_ends:
            continue
        tried_ends.add(end_idx)

        stats = _window_stats(insns, start_idx, end_idx)
        if stats is None:
            continue
        if stats["exact"] < _candidate_min_exact(stats["byte_len"]):
            continue

        matches = find_up_to_two(stats["signature"], ranges)
        if len(matches) != 1:
            continue

        return Candidate(
            mode=mode,
            signature=stats["signature"],
            byte_len=stats["byte_len"],
            wildcards=stats["wildcards"],
            exact=stats["exact"],
            origin="%s@%s" % (mode.lower(), _ea(stats["start_ea"])),
        )

    return None


def find_entry_candidate(func_ea, ranges):
    f = ida_funcs.get_func(func_ea)
    if f is None:
        return None, []

    insns = decode_chunk(f.start_ea, f.end_ea)
    if not insns:
        return None, []

    candidate = _unique_window_candidate(
        insns, 0, "ENTRY", ranges, [10, 14, 18, 24, 32, 40, 48]
    )
    return candidate, insns


def _sample_body_indices(insns):
    n = len(insns)
    if n <= 3:
        return []

    raw = [max(1, n // 4), max(1, n // 2), max(1, (3 * n) // 4)]
    out = []
    for idx in raw:
        idx = min(idx, n - 1)
        if idx not in out and idx != 0:
            out.append(idx)
    return out[:BODY_START_SAMPLES]


def find_body_candidates(insns, ranges):
    out = []
    for idx in _sample_body_indices(insns):
        cand = _unique_window_candidate(
            insns, idx, "BODY", ranges, [10, 14, 18, 24, 32, 40, 48]
        )
        if cand is not None:
            out.append(cand)
    return out


def _field_span_for_offb(insn, offb):
    offsets = sorted(
        set(x[1] for x in _operand_encoded_ranges(insn) if x[1] >= offb)
    )
    later = [x for x in offsets if x > offb]
    end = min(later) if later else insn.size
    return max(0, end - offb)


def infer_pc_relative_field(insn, target_ea):
    """
    Find an encoded signed displacement that resolves from instruction_end
    exactly to target_ea. This validates width rather than assuming rel32.
    """
    raw_insn = ida_bytes.get_bytes(insn.ea, insn.size)
    if raw_insn is None or len(raw_insn) != insn.size:
        return None

    for _idx, offb, _end, _type in _operand_encoded_ranges(insn):
        span = _field_span_for_offb(insn, offb)
        widths = []
        for w in (span, 4, 1, 2, 8):
            if w in (1, 2, 4, 8) and w not in widths:
                widths.append(w)

        for width in widths:
            if offb + width > insn.size:
                continue
            data = raw_insn[offb:offb + width]
            disp = int.from_bytes(data, byteorder="little", signed=True)
            resolved = insn.ea + insn.size + disp
            if resolved == target_ea:
                return offb, width

    return None


def collect_far_xrefs_to(target_ea):
    refs = []
    cur = ida_xref.get_first_fcref_to(target_ea)
    while cur != BADADDR:
        refs.append(cur)
        cur = ida_xref.get_next_fcref_to(target_ea, cur)
    return sorted(set(refs))


def _even_sample(values, limit):
    if len(values) <= limit:
        return list(values)
    if limit <= 1:
        return [values[len(values) // 2]]

    result = []
    n = len(values)
    for i in range(limit):
        idx = round(i * (n - 1) / (limit - 1))
        v = values[idx]
        if v not in result:
            result.append(v)
    return result


def _xref_window_specs(xidx, n):
    specs = [
        (xidx, xidx + 1),
        (xidx - 1, xidx + 1),
        (xidx, xidx + 2),
        (xidx - 1, xidx + 2),
        (xidx - 2, xidx + 2),
        (xidx - 1, xidx + 3),
        (xidx - 2, xidx + 3),
        (xidx - 3, xidx + 4),
    ]
    clean = []
    seen = set()
    for a, b in specs:
        a = max(0, a)
        b = min(n, b)
        if a >= b or not (a <= xidx < b):
            continue
        key = (a, b)
        if key not in seen:
            seen.add(key)
            clean.append(key)
    return clean


def find_rel_candidate_for_xref(xref_ea, target_ea, ranges):
    chunk = ida_funcs.get_fchunk(xref_ea)
    if chunk is None:
        return None

    xinsn = ida_ua.insn_t()
    if ida_ua.decode_insn(xinsn, xref_ea) <= 0 or xinsn.size <= 0:
        return None

    rel = infer_pc_relative_field(xinsn, target_ea)
    if rel is None:
        return None
    rel_off_in_insn, rel_size = rel

    insns = decode_chunk(chunk.start_ea, chunk.end_ea)
    if not insns:
        return None

    xidx = None
    for i, item in enumerate(insns):
        if item["ea"] == xref_ea:
            xidx = i
            break
    if xidx is None:
        return None

    # Force only the validated relative field to be wildcarded in xref insn.
    insns[xidx]["tokens"] = _pattern_tokens_for_insn(
        xinsn, force_rel=(rel_off_in_insn, rel_size)
    )
    insns[xidx]["insn"] = xinsn

    possibilities = []
    for a, b in _xref_window_specs(xidx, len(insns)):
        stats = _window_stats(insns, a, b)
        if stats is None or stats["byte_len"] > MAX_PATTERN_BYTES:
            continue
        if stats["exact"] < _candidate_min_exact(stats["byte_len"]):
            continue

        rel_offset = (xref_ea - stats["start_ea"]) + rel_off_in_insn
        base_offset = (xref_ea - stats["start_ea"]) + xinsn.size
        insn_offset = xref_ea - stats["start_ea"]

        possibilities.append((
            stats["byte_len"], stats["wildcards"], a, b, stats,
            rel_offset, base_offset, insn_offset
        ))

    possibilities.sort(key=lambda x: (x[0], x[1]))

    for (
        _blen, _wild, _a, _b, stats,
        rel_offset, base_offset, insn_offset
    ) in possibilities:
        matches = find_up_to_two(stats["signature"], ranges)
        if len(matches) != 1:
            continue

        return Candidate(
            mode="REL",
            signature=stats["signature"],
            target_delta=0,
            rel_offset=rel_offset,
            rel_size=rel_size,
            base_offset=base_offset,
            insn_offset=insn_offset,
            byte_len=stats["byte_len"],
            wildcards=stats["wildcards"],
            exact=stats["exact"],
            origin="xref@%s" % _ea(xref_ea),
        )

    return None


def find_best_rel_candidate(func_ea, ranges):
    all_refs = collect_far_xrefs_to(func_ea)
    if not all_refs:
        return None, 0, 0

    sampled = _even_sample(all_refs, MAX_XREFS_TO_SEARCH)
    best = None
    searched = 0

    for xref_ea in sampled:
        # Recursive xrefs can work, but external callers are preferable.
        owner = ida_funcs.get_func(xref_ea)
        if owner is not None and owner.start_ea == func_ea and len(sampled) > 1:
            continue

        searched += 1
        cand = find_rel_candidate_for_xref(xref_ea, func_ea, ranges)
        if cand is not None and (best is None or cand.score < best.score):
            best = cand

        if (
            best is not None
            and searched >= XREF_EARLY_STOP_AFTER
            and best.byte_len <= 20
        ):
            break

    return best, len(all_refs), searched


def choose_candidates(func_ea, ranges):
    entry, entry_insns = find_entry_candidate(func_ea, ranges)
    candidates = []
    if entry is not None:
        candidates.append(entry)

    f = ida_funcs.get_func(func_ea)
    func_size = (f.end_ea - f.start_ea) if f is not None else 0

    entry_is_good = (
        entry is not None
        and entry.byte_len <= GOOD_ENTRY_BYTES
        and entry.exact >= MIN_EXACT_BYTES
        and (entry.wildcards / max(1, entry.byte_len)) <= 0.50
    )

    # REL is most valuable for very short functions, missing entry matches,
    # or when the entry signature had to become long/wildcard-heavy.
    need_rel = (
        func_size < 12
        or entry is None
        or entry.byte_len > GOOD_ENTRY_BYTES
        or (entry.wildcards / max(1, entry.byte_len)) > 0.40
    )

    rel = None
    total_xrefs = 0
    tested_xrefs = 0
    if need_rel:
        rel, total_xrefs, tested_xrefs = find_best_rel_candidate(func_ea, ranges)
        if rel is not None:
            candidates.append(rel)

    # Interior BODY signatures are a final non-xref option. They never need a
    # fixed delta: importer resolves the IDA function containing the match.
    if not entry_is_good and entry_insns:
        candidates.extend(find_body_candidates(entry_insns, ranges))

    # De-duplicate and sort by quality.
    unique = {}
    for c in candidates:
        old = unique.get(c.key())
        if old is None or c.score < old.score:
            unique[c.key()] = c
    ordered = sorted(unique.values(), key=lambda c: c.score)

    # Tiny functions are inherently weak anchors even when their few bytes are
    # source-unique. Prefer a validated caller-side REL anchor when available,
    # and retain the tiny ENTRY/BODY candidate only as a fallback.
    if func_size < 12:
        rel_candidates = [c for c in ordered if c.mode == "REL"]
        if rel_candidates:
            rel_best = min(rel_candidates, key=lambda c: c.score)
            ordered = [rel_best] + [c for c in ordered if c is not rel_best]

    selected = []
    if ordered:
        selected.append(ordered[0])

        # Backup should ideally be a different resolution mode/origin.
        for c in ordered[1:]:
            if len(selected) >= MAX_EXPORTED_CANDIDATES:
                break
            if c.mode != selected[0].mode or c.origin != selected[0].origin:
                selected.append(c)

    return selected, total_xrefs, tested_xrefs


def _safe_name(name):
    if not name:
        return None
    if "\n" in name or "\r" in name:
        return None
    return name



# ---------------------------------------------------------------------------
# CFS4 binary type transport
# ---------------------------------------------------------------------------

# CFS4 deliberately does NOT round-trip UDTs through C syntax.
# IDAPython 9 exposes tinfo_t.serialize() -> (type, fields, field_cmts), and
# tinfo_t.deserialize() consumes that representation directly. We detach a
# named root definition, replace source-IDB ordinal references with names, and
# serialize the resulting portable tinfo.


def _pack_bytes(data):
    if data is None:
        return ""
    raw = bytes(data)
    if not raw:
        return ""
    return base64.b64encode(zlib.compress(raw, 9)).decode("ascii")


def _pack_json(value):
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(zlib.compress(raw, 9)).decode("ascii")



def _resolved_definition_kind(tif):
    """
    Determine the actual resolved Local-Type kind.

    A numbered/named tinfo_t is commonly a typeref wrapper. Querying the
    resolved detail containers is more reliable than looking only at the
    wrapper's declared type.
    """
    if tif is None:
        return "TYPE"

    try:
        if tif.is_forward_struct():
            return "STRUCT"
        if tif.is_forward_union():
            return "UNION"
        if tif.is_forward_enum():
            return "ENUM"
    except Exception:
        pass

    try:
        udt = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt, ida_typeinf.GTD_CALC_LAYOUT):
            return "UNION" if bool(udt.is_union) else "STRUCT"
    except Exception:
        pass

    try:
        ei = ida_typeinf.enum_type_data_t()
        if tif.get_enum_details(ei):
            return "ENUM"
    except Exception:
        pass

    try:
        if tif.is_typedef():
            return "TYPEDEF"
    except Exception:
        pass

    return "TYPE"


def _materialize_full_definition(source_tif):
    """
    Turn a Local-Type typeref into a detached, concrete definition.

    This is the key CFS5 fix.

    get_numbered_type()/get_named_type() create a tinfo_t that *links* to a
    named/numbered type. detach() alone can still leave a reference-shaped
    object. For UDTs/enums we explicitly extract the resolved detail container
    and rebuild a brand-new detached tinfo_t with create_udt()/create_enum().

    Returns (materialized_tinfo, kind, member_count_or_-1).
    """
    if source_tif is None:
        return None, "TYPE", -1

    # A true source forward declaration has no body to materialize.
    try:
        if source_tif.is_forward_decl():
            fwd = source_tif.copy()
            try:
                fwd.detach()
            except Exception:
                pass
            return fwd, _resolved_definition_kind(source_tif), 0
    except Exception:
        pass

    # Force resolution of the reference before asking for details.
    try:
        source_tif.get_realtype(True)
    except Exception:
        pass

    # Full structure/union body.
    try:
        udt = ida_typeinf.udt_type_data_t()
        if source_tif.get_udt_details(udt, ida_typeinf.GTD_CALC_LAYOUT):
            member_count = len(udt)
            kind = "UNION" if bool(udt.is_union) else "STRUCT"

            full = ida_typeinf.tinfo_t()
            decl_type = (
                ida_typeinf.BTF_UNION
                if bool(udt.is_union)
                else ida_typeinf.BTF_STRUCT
            )

            # create_udt() consumes the detail vector and creates a detached
            # unique type containing the real members/layout.
            if full.create_udt(udt, decl_type):
                return full, kind, member_count
    except Exception as exc:
        _msg("TYPE_MATERIALIZE_UDT_WARN: %s" % exc)

    # Full enum body.
    try:
        ei = ida_typeinf.enum_type_data_t()
        if source_tif.get_enum_details(ei):
            member_count = len(ei)
            full = ida_typeinf.tinfo_t()
            if full.create_enum(ei, ida_typeinf.BTF_ENUM):
                return full, "ENUM", member_count
    except Exception as exc:
        _msg("TYPE_MATERIALIZE_ENUM_WARN: %s" % exc)

    # Typedef/simple/opaque fallback. For a genuine opaque source type there
    # simply is no UDT body to transport.
    fallback = source_tif.copy()
    try:
        fallback.detach()
    except Exception:
        pass
    return fallback, _resolved_definition_kind(source_tif), -1


def _local_type_kind(tif):
    return _resolved_definition_kind(tif)

def _build_local_type_index():
    """Return {ordinal: (name, tinfo)} for named Local Types."""
    idati = ida_typeinf.get_idati()
    result = {}
    try:
        limit = int(ida_typeinf.get_ordinal_limit(idati))
    except Exception:
        limit = 0

    for ordinal in range(1, max(1, limit)):
        try:
            name = ida_typeinf.get_numbered_type_name(idati, ordinal)
        except Exception:
            name = None

        if not name or str(name).startswith("#"):
            continue

        try:
            tif = idati.get_numbered_type(ordinal)
        except Exception:
            tif = None

        if tif is None:
            continue

        result[int(ordinal)] = (str(name), tif)

    return result


def _collect_direct_local_ordinals(tif, out, depth=0):
    """Collect local-type ordinal references contained in a tinfo tree."""
    if tif is None or depth > 64:
        return

    try:
        if tif.empty():
            return
    except Exception:
        return

    try:
        ordinal = int(tif.get_ordinal())
    except Exception:
        ordinal = 0

    if ordinal > 0:
        out.add(ordinal)
        return

    try:
        if tif.is_typeref():
            name = tif.get_type_name()
            if isinstance(name, str) and name:
                try:
                    ord2 = int(ida_typeinf.get_type_ordinal(ida_typeinf.get_idati(), name))
                except Exception:
                    ord2 = 0
                if ord2 > 0:
                    out.add(ord2)
            return
    except Exception:
        pass

    try:
        if tif.is_ptr_or_array():
            _collect_direct_local_ordinals(tif.get_ptrarr_object(), out, depth + 1)
            return
    except Exception:
        pass

    try:
        if tif.is_func():
            _collect_direct_local_ordinals(tif.get_rettype(), out, depth + 1)
            fti = ida_typeinf.func_type_data_t()
            if tif.get_func_details(fti):
                for arg in fti:
                    _collect_direct_local_ordinals(arg.type, out, depth + 1)
            return
    except Exception:
        pass

    try:
        if tif.is_udt():
            for udm in tif.iter_udt():
                _collect_direct_local_ordinals(udm.type, out, depth + 1)
    except Exception:
        pass


def _dependency_closure_for_root(root_ordinal, local_index, cache):
    """
    Resolve transitive dependencies by walking IDA's tinfo graph directly.

    CFS3 used print_decls()+regex for this. That can expose compiler/parser
    helper names and is unnecessary. Here we detach each named definition and
    inspect its actual member types instead.
    """
    root_ordinal = int(root_ordinal)
    if root_ordinal in cache:
        return set(cache[root_ordinal])

    closure = set()
    visiting = set()

    def visit(ordinal):
        ordinal = int(ordinal)
        if ordinal <= 0 or ordinal in closure or ordinal in visiting:
            return
        visiting.add(ordinal)
        closure.add(ordinal)

        info = local_index.get(ordinal)
        if info is not None:
            _name, source_tif = info
            body, _kind, _count = _materialize_full_definition(source_tif)
            if body is None:
                body = source_tif

            refs = set()
            _collect_direct_local_ordinals(body, refs)
            for dep in refs:
                if int(dep) != ordinal:
                    visit(dep)

        visiting.discard(ordinal)

    visit(root_ordinal)
    cache[root_ordinal] = set(closure)
    return closure


def _portable_serialize_tinfo(source_tif, detach_root=False):
    """
    Return (type_bytes, fields_bytes_or_None, field_cmts_bytes_or_None).

    For function/member types, ordinal typerefs are converted to name refs.

    For a named Local Type (detach_root=True), CFS5 first materializes the
    resolved full UDT/enum definition with get_*_details()+create_*().
    This prevents exporting only `struct Foo;` when the source actually
    contains a complete Foo body.
    """
    if detach_root:
        portable, _kind, _count = _materialize_full_definition(source_tif)
        if portable is None:
            return None
    else:
        portable = source_tif.copy()

    try:
        replaced = ida_typeinf.replace_ordinal_typerefs(
            ida_typeinf.get_idati(), portable
        )
    except Exception:
        replaced = -1

    if replaced == -1:
        return None

    try:
        raw = portable.serialize(ida_typeinf.SUDT_FAST)
    except Exception:
        raw = None

    if not isinstance(raw, tuple) or len(raw) != 3 or raw[0] is None:
        return None

    out = []
    for part in raw:
        if part is None:
            out.append(None)
        else:
            out.append(bytes(part))
    return tuple(out)


def _function_type_quality(ea, explicit_type):
    try:
        if ida_nalt.is_userti(ea):
            return "USER"
    except Exception:
        pass

    try:
        if (
            ida_nalt.is_type_guessed_by_ida(ea)
            or ida_nalt.is_func_guessed_by_hexrays(ea)
            or ida_nalt.is_type_guessed_by_hexrays(ea)
        ):
            return "GUESSED"
    except Exception:
        pass

    return "EXPLICIT" if explicit_type else "GUESSED"


def _export_function_type_metadata(ea, local_index, closure_cache, exported_types):
    """Return (quality, serialized_function_tinfo_or_None, dependency_names)."""
    tif = ida_typeinf.tinfo_t()
    explicit = False

    try:
        explicit = bool(ida_nalt.get_tinfo(tif, ea))
    except Exception:
        explicit = False

    if not explicit:
        guessed = ida_typeinf.tinfo_t()
        try:
            rc = ida_typeinf.guess_tinfo(guessed, ea)
        except Exception:
            rc = ida_typeinf.GUESS_FUNC_FAILED

        if rc == ida_typeinf.GUESS_FUNC_FAILED:
            return "NONE", None, []
        tif = guessed

    try:
        if tif.is_funcptr():
            tif = tif.get_pointed_object()
    except Exception:
        pass

    try:
        if not tif.is_func():
            return "NONE", None, []
    except Exception:
        return "NONE", None, []

    roots = set()
    _collect_direct_local_ordinals(tif, roots)

    dependency_ordinals = set()
    for root in roots:
        dependency_ordinals.update(
            _dependency_closure_for_root(root, local_index, closure_cache)
        )

    dependency_names = []
    for ordinal in sorted(dependency_ordinals):
        info = local_index.get(ordinal)
        if info is None:
            continue

        name, dep_tif = info
        serialized = _portable_serialize_tinfo(dep_tif, detach_root=True)
        if serialized is None:
            _msg(
                "TYPE_EXPORT_SKIP %s ordinal=%d: binary serialization failed"
                % (name, ordinal)
            )
            continue

        dependency_names.append(name)
        if name not in exported_types:
            _body, resolved_kind, body_count = _materialize_full_definition(dep_tif)
            exported_types[name] = {
                "name": name,
                "kind": resolved_kind,
                "raw": serialized,
                "body_count": body_count,
            }
            if resolved_kind in ("STRUCT", "UNION", "ENUM"):
                _msg(
                    "TYPE_BODY_EXPORTED %-34s kind=%s items=%d"
                    % (name, resolved_kind, body_count)
                )

    func_raw = _portable_serialize_tinfo(tif, detach_root=False)
    if func_raw is None:
        return "NONE", None, sorted(set(dependency_names))

    return (
        _function_type_quality(ea, explicit),
        func_raw,
        sorted(set(dependency_names)),
    )


def export_function_eas(function_eas, title):
    function_eas = sorted(set(function_eas))
    if not function_eas:
        ida_kernwin.warning("No suitable functions selected/found.")
        return False

    path = ida_kernwin.ask_file(True, "*.cfs", title)
    if not path:
        _msg("Export cancelled.")
        return False
    if not path.lower().endswith(".cfs"):
        path += ".cfs"

    ranges = get_search_ranges()
    if not ranges:
        ida_kernwin.warning("No executable/code search ranges found.")
        return False

    # Local type discovery is done once. Actual definitions are emitted only
    # when an exported function prototype references them.
    try:
        local_type_index = _build_local_type_index()
    except Exception as exc:
        _msg("TYPE_INDEX_WARN: %s" % exc)
        local_type_index = {}

    closure_cache = {}
    exported_types = {}

    exported_functions = 0
    exported_candidates = 0
    exported_prototypes = 0
    user_prototypes = 0
    guessed_prototypes = 0
    no_candidate = 0
    failures = 0
    mode_counts = {"ENTRY": 0, "BODY": 0, "REL": 0}
    total = len(function_eas)

    ida_kernwin.clr_cancelled()
    ida_kernwin.show_wait_box(
        "NODELAY\nBuilding optimized CFS5 signatures + binary types...\n"
        "Press Cancel to stop."
    )

    try:
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, lineterminator="\n")
            f.write("# CFS5 %s\n" % VERSION)
            f.write(
                "# CFS2 signature row is retained for backwards compatibility.\n"
            )
            f.write(
                "# CFS4FUNC,group_id,name,quality,type_payload,fields_payload,fldcmts_payload,deps_payload\n"
            )
            f.write(
                "# CFS4TYPE,name,kind,type_payload,fields_payload,fldcmts_payload (CFS5 exporter materializes full bodies)\n"
            )
            f.write(
                "# binary payloads are zlib+base64; deps payload is compressed JSON\n"
            )

            for pos, func_ea in enumerate(function_eas, 1):
                if ida_kernwin.user_cancelled():
                    _msg(
                        "Export cancelled after %d/%d functions."
                        % (pos - 1, total)
                    )
                    break

                name = _safe_name(ida_name.get_name(func_ea) or "")
                if not name:
                    failures += 1
                    continue

                if pos == 1 or pos == total or pos % PROGRESS_EVERY == 0:
                    ida_kernwin.replace_wait_box(
                        "Building optimized CFS5 signatures + binary types...\n"
                        "%d / %d\nCurrent: %s\n"
                        "Exported: %d  Types: %d  No candidate: %d"
                        % (
                            pos,
                            total,
                            name,
                            exported_functions,
                            len(exported_types),
                            no_candidate,
                        )
                    )

                try:
                    candidates, xref_count, xrefs_tested = choose_candidates(
                        func_ea, ranges
                    )
                except Exception as exc:
                    failures += 1
                    _msg(
                        "FAIL %-45s @ %s error=%s"
                        % (name, _ea(func_ea), exc)
                    )
                    continue

                if not candidates:
                    no_candidate += 1
                    _msg(
                        "NO_UNIQUE_CANDIDATE %-31s @ %s"
                        % (name, _ea(func_ea))
                    )
                    continue

                # The same group id ties signatures and prototype metadata
                # together. Types are de-duplicated globally by local type name.
                group_id = exported_functions

                try:
                    quality, prototype_raw, deps = _export_function_type_metadata(
                        func_ea,
                        local_type_index,
                        closure_cache,
                        exported_types,
                    )
                except Exception as exc:
                    quality, prototype_raw, deps = "NONE", None, []
                    _msg(
                        "TYPE_EXPORT_FAIL %-36s @ %s error=%s"
                        % (name, _ea(func_ea), exc)
                    )

                if prototype_raw is None:
                    proto_type = proto_fields = proto_cmts = None
                else:
                    proto_type, proto_fields, proto_cmts = prototype_raw

                writer.writerow([
                    "CFS4FUNC",
                    group_id,
                    name,
                    quality,
                    _pack_bytes(proto_type),
                    _pack_bytes(proto_fields),
                    _pack_bytes(proto_cmts),
                    _pack_json(deps),
                ])

                if prototype_raw is not None:
                    exported_prototypes += 1
                    if quality == "USER":
                        user_prototypes += 1
                    elif quality == "GUESSED":
                        guessed_prototypes += 1

                for rank, c in enumerate(candidates):
                    writer.writerow([
                        "CFS2",
                        group_id,
                        rank,
                        name,
                        c.mode,
                        c.signature,
                        c.target_delta,
                        c.rel_offset,
                        c.rel_size,
                        c.base_offset,
                        c.insn_offset,
                        c.score,
                    ])
                    exported_candidates += 1
                    mode_counts[c.mode] = mode_counts.get(c.mode, 0) + 1

                primary = candidates[0]
                xref_note = ""
                if xref_count:
                    xref_note = (
                        " xrefs=%d tested=%d" % (xref_count, xrefs_tested)
                    )

                type_note = ""
                if prototype_raw is not None:
                    type_note = " type=%s deps=%d" % (quality, len(deps))

                _msg(
                    "EXPORTED %-39s mode=%s bytes=%d exact=%d "
                    "backup=%d%s%s"
                    % (
                        name,
                        primary.mode,
                        primary.byte_len,
                        primary.exact,
                        max(0, len(candidates) - 1),
                        xref_note,
                        type_note,
                    )
                )
                exported_functions += 1

            # Emit each referenced local type exactly once. Their order is not
            # semantically important because the importer performs safe
            # multi-pass registration and never overwrites pre-existing names.
            for type_name in sorted(exported_types):
                info = exported_types[type_name]
                type_blob, fields_blob, cmts_blob = info["raw"]
                writer.writerow([
                    "CFS4TYPE",
                    info["name"],
                    info["kind"],
                    _pack_bytes(type_blob),
                    _pack_bytes(fields_blob),
                    _pack_bytes(cmts_blob),
                ])

    except OSError as exc:
        ida_kernwin.warning("Unable to write CFS4 file:\n%s" % exc)
        return False
    finally:
        ida_kernwin.hide_wait_box()
        ida_kernwin.clr_cancelled()

    summary = (
        "CFS5 export complete\n\n"
        "Functions exported: %d\n"
        "Candidate rows: %d\n"
        "Function prototypes: %d\n"
        "  User prototypes: %d\n"
        "  Guessed prototypes: %d\n"
        "Local type definitions: %d\n"
        "ENTRY candidates: %d\n"
        "BODY candidates: %d\n"
        "REL candidates: %d\n"
        "No unique candidate: %d\n"
        "Failures: %d\n\n"
        "%s"
        % (
            exported_functions,
            exported_candidates,
            exported_prototypes,
            user_prototypes,
            guessed_prototypes,
            len(exported_types),
            mode_counts.get("ENTRY", 0),
            mode_counts.get("BODY", 0),
            mode_counts.get("REL", 0),
            no_candidate,
            failures,
            path,
        )
    )
    _msg(summary.replace("\n", " | "))
    ida_kernwin.info(summary)
    return exported_functions > 0


class ExportSelectedHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        export_function_eas(
            get_selected_function_eas(ctx),
            "Export selected optimized CFS5 signatures + binary types",
        )
        return 1

    def update(self, ctx):
        if getattr(ctx, "widget_type", None) == ida_kernwin.BWN_FUNCS:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class ExportAllHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        eas = get_all_user_named_function_eas()
        if not eas:
            ida_kernwin.warning("No user-named functions found.")
            return 1

        if ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            "Export %d user-named functions with optimized CFS2 signatures?"
            % len(eas),
        ) != ida_kernwin.ASKBTN_YES:
            return 1

        export_function_eas(
            eas,
            "Export ALL user-named optimized CFS5 signatures + binary types",
        )
        return 1

    def update(self, ctx):
        if getattr(ctx, "widget_type", None) == ida_kernwin.BWN_FUNCS:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class Hooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_FUNCS:
            return
        ida_kernwin.attach_action_to_popup(
            widget, popup_handle, ACTION_SELECTED, "CFS5/"
        )
        ida_kernwin.attach_action_to_popup(
            widget, popup_handle, ACTION_ALL_USER_NAMED, "CFS5/"
        )


class CFS3ExporterPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Optimized CFS5 signature + type exporter for IDA 9"
    help = (
         "Functions window -> right click -> CFS3. "
        "Uses short unique ENTRY/BODY/REL signatures and transports function/local types."
    )
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        self.h1 = ExportSelectedHandler()
        self.h2 = ExportAllHandler()
        self.hooks = Hooks()

        ida_kernwin.unregister_action(ACTION_SELECTED)
        ida_kernwin.unregister_action(ACTION_ALL_USER_NAMED)

        ok1 = ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_SELECTED,
                "Export selected optimized signatures",
                self.h1,
                SELECTED_HOTKEY,
                "Export selected functions to optimized CFS5 + types",
                -1,
            )
        )
        ok2 = ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_ALL_USER_NAMED,
                "Export ALL user-named optimized signatures",
                self.h2,
                None,
                "Export user-named functions to optimized CFS5 + types",
                -1,
            )
        )

        if not ok1 or not ok2:
            _msg("Action registration failed.")
            return idaapi.PLUGIN_SKIP

        self.hooks.hook()
        _msg("%s initialized." % VERSION)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.info(
            "Open View -> Open subviews -> Functions,\n"
            "then right-click -> CFS3."
        )

    def term(self):
        try:
            self.hooks.unhook()
        except Exception:
            pass
        ida_kernwin.unregister_action(ACTION_SELECTED)
        ida_kernwin.unregister_action(ACTION_ALL_USER_NAMED)


def PLUGIN_ENTRY():
    return CFS3ExporterPlugin()