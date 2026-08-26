"""Binary Local-Type transport shared by both plugins.

Types move as serialized tinfo_t (never round-tripped through C syntax):
  * export: materialize a named Local Type into a concrete detached UDT/enum
    body, rewrite source ordinal typerefs as name refs, then serialize.
  * import: multi-pass, non-destructive registration that upgrades forward
    declarations but never overwrites a fully-defined same-named destination.
  * prototype merge: field-by-field, where a specific destination named/UDT/
    enum type wins over a generic incoming scalar and vice-versa.
"""

import ida_nalt
import ida_typeinf

from .common import msg


# ---------------------------------------------------------------------------
# Kind resolution + full-body materialization (export side)
# ---------------------------------------------------------------------------

def resolved_definition_kind(tif):
    """The actual resolved Local-Type kind behind a possible typeref wrapper."""
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


def materialize_full_definition(source_tif):
    """Turn a Local-Type typeref into a detached, concrete definition.

    get_numbered_type()/get_named_type() return a tinfo_t that *links* to a
    named/numbered type; detach() alone can leave a reference-shaped object.
    For UDTs/enums we extract the resolved detail container and rebuild a fresh
    detached tinfo_t via create_udt()/create_enum() so the full body travels,
    not just `struct Foo;`.

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
            return fwd, resolved_definition_kind(source_tif), 0
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
            if full.create_udt(udt, decl_type):
                return full, kind, member_count
    except Exception as exc:
        msg("TYPE_MATERIALIZE_UDT_WARN: %s" % exc)

    # Full enum body.
    try:
        ei = ida_typeinf.enum_type_data_t()
        if source_tif.get_enum_details(ei):
            member_count = len(ei)
            full = ida_typeinf.tinfo_t()
            if full.create_enum(ei, ida_typeinf.BTF_ENUM):
                return full, "ENUM", member_count
    except Exception as exc:
        msg("TYPE_MATERIALIZE_ENUM_WARN: %s" % exc)

    # Typedef/simple/opaque fallback.
    fallback = source_tif.copy()
    try:
        fallback.detach()
    except Exception:
        pass
    return fallback, resolved_definition_kind(source_tif), -1


# ---------------------------------------------------------------------------
# Local-type discovery + dependency closure (export side)
# ---------------------------------------------------------------------------

def build_local_type_index():
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
    """Transitive local-type dependencies, walking IDA's tinfo graph directly."""
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
            body, _kind, _count = materialize_full_definition(source_tif)
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
    """Return (type_bytes, fields_bytes_or_None, field_cmts_bytes_or_None).

    Ordinal typerefs are converted to name refs. For a named Local Type
    (detach_root=True) the resolved full UDT/enum body is materialized first.
    """
    if detach_root:
        portable, _kind, _count = materialize_full_definition(source_tif)
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
        out.append(None if part is None else bytes(part))
    return tuple(out)


def export_type_payload(tif, local_index, closure_cache, exported_types):
    """Serialize a prototype/global tinfo and record its dependent Local Types.

    Returns (serialized_raw_or_None, sorted_dependency_names). exported_types is
    a shared {name: {...}} dict deduplicated across every exported item.
    """
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
            msg(
                "TYPE_EXPORT_SKIP %s ordinal=%d: binary serialization failed"
                % (name, ordinal)
            )
            continue

        dependency_names.append(name)
        if name not in exported_types:
            _body, resolved_kind, body_count = materialize_full_definition(dep_tif)
            exported_types[name] = {
                "name": name,
                "kind": resolved_kind,
                "raw": serialized,
                "body_count": body_count,
            }
            if resolved_kind in ("STRUCT", "UNION", "ENUM"):
                msg(
                    "TYPE_BODY_EXPORTED %-34s kind=%s items=%d"
                    % (name, resolved_kind, body_count)
                )

    raw = _portable_serialize_tinfo(tif, detach_root=False)
    return raw, sorted(set(dependency_names))


# ---------------------------------------------------------------------------
# Export-side tinfo acquisition + quality tagging
# ---------------------------------------------------------------------------

def get_function_export_tinfo(ea):
    """(func_tinfo_or_None, explicit) for a function, guessing when needed."""
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
            return None, False
        tif = guessed

    try:
        if tif.is_funcptr():
            tif = tif.get_pointed_object()
    except Exception:
        pass
    try:
        if not tif.is_func():
            return None, False
    except Exception:
        return None, False

    return tif, explicit


def get_global_export_tinfo(ea):
    """(data_tinfo_or_None, explicit) for a global. Only explicit types export."""
    tif = ida_typeinf.tinfo_t()
    try:
        ok = bool(ida_nalt.get_tinfo(tif, ea))
    except Exception:
        ok = False
    if not ok:
        return None, False
    try:
        if tif.empty():
            return None, False
    except Exception:
        pass
    return tif, True


def function_type_quality(ea, explicit_type):
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


def global_type_quality(ea, explicit_type):
    try:
        if ida_nalt.is_userti(ea):
            return "USER"
    except Exception:
        pass
    try:
        if ida_nalt.is_type_guessed_by_ida(ea):
            return "GUESSED"
    except Exception:
        pass
    return "EXPLICIT" if explicit_type else "NONE"


# ---------------------------------------------------------------------------
# Import-side named-type resolution
# ---------------------------------------------------------------------------

def named_type_tinfo(name):
    """Resolve a named type through the destination IDB's Local Types + TILs."""
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

    try:
        return ida_typeinf.tinfo_t(name=name, til=root)
    except Exception:
        return None


def named_type_present(name):
    return named_type_tinfo(name) is not None


def _named_type_well_defined(name):
    tif = named_type_tinfo(name)
    if tif is None:
        return False
    try:
        if tif.is_forward_decl():
            return False
    except Exception:
        pass
    try:
        return bool(tif.is_well_defined())
    except Exception:
        return True


def _named_type_shape(name):
    tif = named_type_tinfo(name)
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


def deserialize_binary_tinfo(type_blob, fields_blob=None, fldcmts_blob=None):
    if type_blob is None:
        return None
    tif = ida_typeinf.tinfo_t()
    try:
        ok = tif.deserialize(
            ida_typeinf.get_idati(), type_blob, fields_blob, fldcmts_blob
        )
    except Exception as exc:
        msg("TYPE_DESERIALIZE_EXCEPTION %s" % exc)
        ok = False
    return tif if ok else None


def _incoming_is_forward(rec):
    if rec is None or not rec.binary or rec.type_blob is None:
        return False
    tif = deserialize_binary_tinfo(rec.type_blob, rec.fields_blob, rec.fldcmts_blob)
    if tif is None:
        return False
    try:
        return bool(tif.is_forward_decl())
    except Exception:
        return False


def register_missing_types(type_records, stats):
    """Binary, non-destructive multi-pass Local-Type registration.

    Existing fully-defined types are immutable; existing forwards may be
    upgraded to a transported body; missing types get a forward placeholder
    then their full body.
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
        existing = named_type_tinfo(name)

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
                msg(
                    "TYPE_KEEP_EXISTING %-35s kind=%s shape=%s"
                    % (name, rec.kind, _named_type_shape(name))
                )
                continue

            if incoming_fwd:
                preexisting.add(name)
                stats.types_existing += 1
                msg("TYPE_KEEP_FORWARD %-36s kind=%s" % (name, rec.kind))
                continue

            replaceable_forwards.add(name)
            msg("TYPE_UPGRADE_FORWARD %-33s kind=%s" % (name, rec.kind))

        if rec.binary:
            pending_binary[name] = rec
        else:
            pending_text[name] = rec

    registered = set()
    created_forwards = set(replaceable_forwards)

    # Phase 1: placeholders for missing recursive UDT/enum names.
    for name, rec in list(pending_binary.items()):
        if name in replaceable_forwards:
            continue

        btf = _forward_decl_btf(rec.kind)
        if btf is None:
            continue

        incoming_forward = _incoming_is_forward(rec)

        try:
            fwd = ida_typeinf.tinfo_t()
            rc = fwd.create_forward_decl(idati, btf, name, 0)
        except Exception as exc:
            rc = None
            msg("TYPE_FORWARD_EXCEPTION %-27s error=%s" % (name, exc))

        if rc == ida_typeinf.TERR_OK or named_type_present(name):
            created_forwards.add(name)
            msg("TYPE_FORWARD %-37s kind=%s" % (name, rec.kind))

            if incoming_forward:
                registered.add(name)
                stats.types_registered += 1
                del pending_binary[name]
                msg("TYPE_REGISTERED_FORWARD %-26s kind=%s" % (name, rec.kind))

    # Phase 2: deserialize + replace placeholders with complete bodies.
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

            tif = deserialize_binary_tinfo(
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
                    msg("TYPE_SAVE_EXCEPTION %-31s error=%s" % (name, exc))

            if rc == ida_typeinf.TERR_OK:
                if incoming_forward:
                    success = named_type_present(name)
                else:
                    success = _named_type_well_defined(name)
            else:
                success = False

            if success:
                registered.add(name)
                stats.types_registered += 1
                del pending_binary[name]
                progress = True
                msg(
                    "TYPE_REGISTERED %-35s kind=%s pass=%d shape=%s"
                    % (name, rec.kind, pass_no, _named_type_shape(name))
                )

        if not progress:
            break

    # Legacy textual CFS3 fallback only.
    if pending_text:
        parse_flags = (
            ida_typeinf.HTI_NWR | ida_typeinf.HTI_HIGH | ida_typeinf.HTI_RELAXED
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
                    msg(
                        "TYPE_REGISTERED_LEGACY %-28s shape=%s"
                        % (name, _named_type_shape(name))
                    )

            if not progress:
                break

    failed = set(pending_binary) | set(pending_text)
    for name in sorted(failed):
        stats.types_failed += 1
        rec = type_records[name]
        msg(
            "TYPE_FAILED %-39s kind=%s line=%d format=%s shape=%s"
            % (
                name, rec.kind, rec.line_no,
                "BIN" if rec.binary else "TEXT", _named_type_shape(name),
            )
        )

    return {"preexisting": preexisting, "registered": registered, "failed": failed}


# ---------------------------------------------------------------------------
# Prototype acquisition + conservative merge (import side)
# ---------------------------------------------------------------------------

def _parse_function_prototype(declaration):
    """Legacy CFS3 textual-prototype fallback."""
    if not declaration:
        return None
    idati = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    flags = (
        ida_typeinf.PT_TYP | ida_typeinf.PT_SIL
        | ida_typeinf.PT_HIGH | ida_typeinf.PT_RELAXED
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


def function_tinfo_from_meta(meta):
    if meta is None:
        return None
    if meta.binary:
        tif = deserialize_binary_tinfo(
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


def global_tinfo_from_meta(meta):
    """Data tinfo transported for a global (no function-shape requirement)."""
    if meta is None or not meta.binary:
        return None
    return deserialize_binary_tinfo(
        meta.type_blob, meta.fields_blob, meta.fldcmts_blob
    )


def get_function_tinfo(ea, allow_guess=True):
    """(tinfo_or_None, explicit, user_type) for a destination function."""
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


def type_specificity(tif, depth=0):
    """Information score for one argument/return/global type."""
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
            child_score = type_specificity(child, depth + 1)
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

    return 25


def _type_is_specific(tif):
    return type_specificity(tif) >= 80


def _choose_component_type(dst_type, src_type, src_quality, dst_function_user_typed):
    """Return (chosen_tinfo, source_won) for one return/argument component."""
    if src_type is None:
        return (dst_type.copy() if dst_type is not None else None), False
    if dst_type is None:
        return src_type.copy(), True

    dst_score = type_specificity(dst_type)
    src_score = type_specificity(src_type)

    if dst_score >= 80:
        return dst_type.copy(), False
    if src_score >= 80 and src_score > dst_score:
        return src_type.copy(), True
    if dst_function_user_typed:
        return dst_type.copy(), False
    if src_quality in ("USER", "EXPLICIT") and src_score >= dst_score:
        return src_type.copy(), True
    if src_quality == "GUESSED":
        if src_score > dst_score + 20:
            return src_type.copy(), True
        return dst_type.copy(), False

    return dst_type.copy(), False


def _new_funcarg(name, tif, cmt="", flags=0, argloc=None):
    """Build funcarg_t via the documented IDAPython 9 constructor."""
    loc = ida_typeinf.argloc_t()
    ctor_name = name or "__cfs_arg"

    try:
        arg = ida_typeinf.funcarg_t(ctor_name, tif.copy(), loc)
    except Exception:
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


def merge_function_tinfos(src_tif, dst_tif, src_quality, dst_function_user_typed, stats):
    """Merge transported prototype into destination, component by component."""
    src = ida_typeinf.func_type_data_t()
    if not src_tif.get_func_details(src):
        return None, False

    dst = ida_typeinf.func_type_data_t()
    have_dst = bool(dst_tif is not None and dst_tif.get_func_details(dst))

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

    use_dst_skeleton = have_dst and (dst_function_user_typed or dst_has_specific)
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

    if user_cc:
        for attr in ("retloc", "stkargs", "spoiled"):
            try:
                setattr(merged, attr, getattr(base, attr))
            except Exception:
                pass

    dst_ret = dst.rettype if have_dst else None
    chosen_ret, source_won = _choose_component_type(
        dst_ret, src.rettype, src_quality, dst_function_user_typed
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
            dst_type, src_type, src_quality, dst_function_user_typed
        )
        if chosen is None:
            continue

        if source_won:
            stats.args_source_used += 1
        elif dst_arg is not None:
            stats.args_destination_kept += 1

        name, cmt, arg_flags = _copy_arg_text(
            src_arg, dst_arg,
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
            _new_funcarg(name, chosen, cmt, arg_flags, argloc=base_argloc)
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
