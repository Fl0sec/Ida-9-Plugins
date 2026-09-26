"""Target-side, evidence-bound materialization of portable CFS7 members."""

import hashlib
import json
import os

import ida_typeinf

from . import cfs6, importer, materialize_plan, members
from .api_result import result
from .common import get_search_ranges
from .image import describe_image, open_image_view


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _owner_layout(owner):
    return [(ref.name, ref.byte_offset, ref.byte_size)
            for ref in members.iter_members(owner)]


def _plan_digest(loaded, catalogue_path, image, rows):
    binding = {
        "catalogue_sha256": _file_hash(catalogue_path),
        "generator": loaded.header.get("generator", {}),
        "schema_revision": loaded.header.get("schema_revision"),
        "target": image,
        "rows": [{"id": row["id"], "action": row["action"],
                  "schema": row.get("field_schema"),
                  "offset": row.get("resolved_offset"),
                  "owner_action": row.get("owner_action"),
                  "owner_layout": row.get("owner_layout", [])}
                 for row in rows],
    }
    return hashlib.sha256(_canonical(binding).encode("utf-8")).hexdigest()


def _snapshot_layout(snapshot):
    """Comparable read-back layout for an owner snapshot."""
    details = ida_typeinf.udt_type_data_t()
    try:
        if not snapshot.get_udt_details(details):
            return None
    except Exception:
        return None
    return [(str(member.name), int(member.offset), int(member.size))
            for member in details]


def _restore_owner(owner, snapshot):
    """Restore one owner and prove its pre-apply state is back."""
    status = {"owner": owner, "attempted": True, "verified": False, "error": None}
    try:
        if snapshot is None:
            ida_typeinf.del_named_type(
                ida_typeinf.get_idati(), owner, ida_typeinf.NTF_TYPE
            )
            probe = ida_typeinf.tinfo_t()
            absent = not probe.get_named_type(ida_typeinf.get_idati(), owner)
            status.update(action="delete_created_shell", verified=bool(absent))
            if not status["verified"]:
                status["error"] = "created owner still exists after deletion"
            return status
        code = snapshot.set_named_type(ida_typeinf.get_idati(), owner, ida_typeinf.NTF_REPLACE)
        restored = members.get_struct_tinfo(owner)
        status.update(action="restore_snapshot",
                      verified=(code == ida_typeinf.TERR_OK and restored is not None and
                                _snapshot_layout(snapshot) == _snapshot_layout(restored)))
        if not status["verified"]:
            status["error"] = "owner layout did not match its snapshot after restoration"
    except Exception as exc:
        status["error"] = str(exc)
    return status


def _classify(item, evidence):
    schema = item.portable_member_schema
    row = {"id": item.id, "owner": item.owner, "member": item.name,
           "resolved_offset": None, "field_schema": schema,
           "evidence": {"candidate_outcomes": evidence.get("candidates", []),
                        "successful_candidates": evidence.get("evidence", 0)},
           "conflicts": [], "owner_layout": _owner_layout(item.owner)}
    if schema is None:
        row.update(action="blocked_insufficient_evidence", reason="catalogue has no portable member schema")
        return row
    owner_action, owner = members.owner_shell_state(item.owner)
    row["owner_action"] = owner_action
    if owner_action.startswith("blocked"):
        row.update(action=owner_action, reason="destination owner type is incompatible")
        return row
    offset = int(evidence["value"])
    row["resolved_offset"] = offset
    named = members.lookup_member(item.owner, item.name)
    at = members.member_at_offset(item.owner, offset)
    spanning = members.enclosing_member_name(item.owner, offset)
    if named is not None and named.byte_offset == offset and named.byte_size == int(schema["width"]):
        row.update(action="already_exact")
    elif named is not None:
        row.update(action="relocate", reason="named destination member exists at another offset")
    elif at is not None or spanning is not None:
        row.update(action="blocked_overlap", reason="destination range is occupied")
    else:
        row.update(action="create")
    return row


def plan_type_materialization(catalogue_path, item_ids=(), mode="missing_only"):
    """Plan portable member creates without changing the active IDB."""
    if mode != "missing_only":
        return result(error="only missing_only is implemented", mode=mode)
    try:
        loaded = cfs6.load_catalogue(catalogue_path)
    except Exception as exc:
        return result(error=str(exc))
    if (loaded.header.get("version") != cfs6.CFS7_FORMAT_VERSION or
            int(loaded.header.get("schema_revision", 0)) < 4):
        return result(partial=True, unresolved=[], rows=[],
                      plan_digest=None, reason="materialization requires CFS7 revision 4")
    requested = set(item_ids or ())
    ranges = get_search_ranges()
    cache = {}
    rows, unresolved = [], []
    for item in loaded.derived_values(cfs6.SEM_MEMBER_OFFSET):
        if requested and item.id not in requested:
            continue
        evidence, error, candidates = importer._resolve_declaration_evidence(item, ranges, cache)
        if error:
            row = {"id": item.id, "owner": item.owner, "member": item.name,
                   "resolved_offset": None, "field_schema": item.portable_member_schema,
                   "action": "blocked_ambiguous", "reason": error,
                   "evidence": {"candidate_outcomes": candidates}, "conflicts": [],
                   "owner_layout": _owner_layout(item.owner)}
        else:
            row = _classify(item, evidence)
        rows.append(row)
        if row["action"].startswith("blocked") or row["action"] in ("relocate", "rename_existing", "type_existing"):
            unresolved.append({"kind": "member", "name": "%s::%s" % (item.owner, item.name),
                               "reason": row.get("reason", row["action"])})
    view, source = open_image_view()
    image, _notes = describe_image(view, source)
    digest = _plan_digest(loaded, catalogue_path, image, rows)
    return result(ok=not unresolved, partial=bool(unresolved), unresolved=unresolved,
                  rows=rows, plan_digest=digest, mode=mode, target=image)


def apply_type_materialization(catalogue_path, item_ids, expected_plan_digest,
                               mode="missing_only"):
    """Replan, bind to a reviewed digest, then create selected safe fields."""
    if not item_ids:
        return result(error="item_ids must explicitly select one or more planned members")
    planned = plan_type_materialization(catalogue_path, item_ids=item_ids, mode=mode)
    if planned.get("plan_digest") != expected_plan_digest:
        return result(error="plan digest no longer matches the active target or catalogue",
                      plan_digest=planned.get("plan_digest"))
    selected = [row for row in planned["rows"] if row["id"] in set(item_ids)]
    unsafe = [row for row in selected if row["action"] not in ("create", "already_exact")]
    if unsafe:
        return result(partial=True, unresolved=[{"kind": "member", "name": row["id"],
                                                  "reason": row["action"]} for row in unsafe],
                      rows=selected, plan_digest=planned["plan_digest"])
    batches, conflicts = materialize_plan.create_batches(selected)
    if conflicts:
        return result(partial=True, rows=selected,
                      unresolved=[{"kind": "member", "name": item["id"],
                                   "reason": item["reason"]} for item in conflicts],
                      plan_digest=planned["plan_digest"])
    snapshots = {}
    for row in selected:
        if row["action"] == "create" and row["owner"] not in snapshots:
            _state, tif = members.owner_shell_state(row["owner"])
            snapshots[row["owner"]] = None if tif is None else tif.copy()
    created = []
    committed_owners = []
    for owner, batch in batches.items():
        state, _tif = members.owner_shell_state(owner)
        committed = members.replace_portable_members(
            owner, batch, create_owner=(state == "create_owner_shell")
        )
        if not committed["ok"]:
            # A failed batch may have committed its replacement before a
            # read-back failure, so restore its snapshot as well.
            rollback_owners = [owner] + list(reversed(committed_owners))
            statuses = [_restore_owner(changed_owner, snapshots[changed_owner])
                        for changed_owner in rollback_owners]
            rollback_verified = all(status["verified"] for status in statuses)
            failed_id = committed.get("failed_item_id")
            return result(partial=not rollback_verified,
                          error="materialization failed; rollback %s" %
                                ("verified" if rollback_verified else "FAILED"),
                          rows=selected, failed_item_id=failed_id,
                          failure={"owner": owner, "reason": committed.get("reason")},
                          rollback={"attempted": bool(statuses),
                                    "verified": rollback_verified, "owners": statuses})
        committed_owners.append(owner)
        created.extend(committed["created"])
    return result(ok=True, rows=selected, created=created,
                  already_exact=[row["id"] for row in selected if row["action"] == "already_exact"],
                  owner_shells=[owner for owner in committed_owners
                                if snapshots[owner] is None],
                  plan_digest=planned["plan_digest"])
