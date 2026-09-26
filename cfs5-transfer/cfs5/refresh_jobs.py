"""Restart-resumable CFS7 refresh jobs with bounded, non-repeating work.

Version 1 repeatedly invoked the whole rolling refresh for every selected
record.  Version 2 persists one revalidated source fragment or one active
export fragment per step, then composes the complete CFS7 once at finalization.
"""

import hashlib
import json
import os
import shutil
import tempfile
import time

from . import cfs6, rolling
from .api_result import result
from .image import BodyOwnership, describe_image, detect_build, get_imagebase, open_image_view
from .common import get_search_ranges


JOB_VERSION = 2
LEGACY_MAX_SELECTION = 8


def _hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stat(path):
    value = os.stat(path)
    return {"size": int(value.st_size), "mtime_ns": int(value.st_mtime_ns)}


def _atomic_json(path, value):
    directory = os.path.dirname(path) or "."
    fd, temporary = tempfile.mkstemp(prefix=".cfs-refresh-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.replace(temporary, path)
    except Exception:
        if os.path.exists(temporary):
            os.remove(temporary)
        raise


def _load_raw_job(job_path):
    try:
        with open(job_path, "r", encoding="utf-8") as handle:
            return json.load(handle), None
    except Exception as exc:
        return None, "invalid_job: %s" % exc


def _load_job(job_path):
    job, error = _load_raw_job(job_path)
    if error:
        return None, error
    if job.get("version") != JOB_VERSION:
        return None, "obsolete_job: discard and begin a v2 refresh job"
    required = {"version", "source", "destination_path", "work_dir", "target",
                "source_units", "active_units", "source_cursor", "active_cursor",
                "build", "status"}
    if not required <= set(job):
        return None, "invalid_job: malformed refresh job"
    if os.path.abspath(job["work_dir"]) != _work_dir(job["destination_path"]):
        return None, "invalid_job: unexpected refresh work directory"
    return job, None


def _job_path(destination_path):
    return os.path.abspath(destination_path) + ".refresh-job.json"


def _work_dir(destination_path):
    return os.path.abspath(destination_path) + ".refresh-job"


def _unit_path(job, phase, index):
    return os.path.join(job["work_dir"], phase, "%06d.cfs" % int(index))


def _outcome_path(job, phase, index):
    return os.path.join(job["work_dir"], phase, "%06d.json" % int(index))


def _write_fragment(path, image, build, item, candidates, item_meta=None,
                    local_types=None):
    """Atomically write one private CFS7 fragment without touching the IDB."""
    temporary = path + ".tmp"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(temporary, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs7Writer(handle, imagebase=0)
            writer.write_header(image, build["number"], build["source"])
            if item.kind == cfs6.REC_PATCH:
                iid = writer.write_patch(item.owner, item.name, len(candidates), item.coverage,
                    {"expected_instruction": item.expected_instruction,
                     "expected_bytes": item.expected_bytes, "patch_size": item.patch_size})
            elif item.kind in (cfs6.REC_FUNCTION, cfs6.REC_GLOBAL):
                iid = writer.write_item(item.kind, item.name, len(candidates), item.coverage)
            elif item.kind == cfs6.REC_DERIVED_VALUE:
                iid = writer.write_derived_value(
                    item.semantic, item.owner, item.name, len(candidates), item.coverage,
                    expected_value=item.expected_value,
                    portable_member_schema=item.portable_member_schema,
                )
            else:
                raise ValueError("unsupported item kind %s" % item.kind)
            for rank, (rec, source, provenance) in enumerate(candidates):
                writer.write_revalidated_candidate(iid, rank, rec, source, provenance)
            if item_meta is not None and item_meta.type_blob is not None:
                writer.write_item_type(
                    iid, item_meta.name, item_meta.quality,
                    (item_meta.type_blob, item_meta.fields_blob, item_meta.fldcmts_blob),
                    item_meta.dependencies, is_global=item_meta.is_global,
                )
            for name in sorted(local_types or {}):
                record = local_types[name]
                writer.write_local_type(record.name, record.kind,
                    (record.type_blob, record.fields_blob, record.fldcmts_blob))
        checked = cfs6.load_catalogue(temporary)
        if checked.parse_errors or len(checked.items) != 1:
            raise ValueError("invalid refresh fragment")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


def _source_fragment(path, loaded, item):
    """Write a one-item input fragment once, avoiding full-source reparsing."""
    provenance = rolling._identity(loaded)
    candidates = [
        (rec, dict(rec.source), rolling._candidate_provenance(rec, provenance))
        for rec in item.candidates
    ]
    _write_fragment(path, loaded.image(), provenance["build"], item, candidates)


def _job_binding(job, force_hash=False):
    source = job["source"]
    path = source["path"]
    if not os.path.isfile(path):
        return "stale_job: source catalogue no longer exists", None
    now = _stat(path)
    if force_hash or now != source["stat"]:
        if _hash(path) != source["sha256"]:
            return "stale_job: source catalogue hash changed", None
        source["stat"] = now
    view, source_label = open_image_view()
    image, _notes = describe_image(view, source_label)
    if image != job["target"]:
        return "stale_job: active target identity changed", None
    return None, (view, image)


def _type_expectations(loaded, item_ids):
    return sorted(iid for iid in item_ids
                  if loaded.item_meta.get(iid) is not None
                  and loaded.item_meta[iid].type_blob is not None)


def begin_refresh(source_path, destination_path, build=None, item_ids=(),
                  declaration_names=()):
    """Create a v2 job and immutable one-item source inputs; publish nothing."""
    source_path = os.path.abspath(source_path)
    destination_path = os.path.abspath(destination_path)
    if not destination_path or source_path == destination_path:
        return result(error="refresh job requires a distinct destination path")
    try:
        loaded = cfs6.load_catalogue(source_path)
    except Exception as exc:
        return result(error=str(exc))
    job_path = _job_path(destination_path)
    work_dir = _work_dir(destination_path)
    if os.path.exists(job_path) or os.path.exists(work_dir):
        return result(error="refresh job already exists", job_path=job_path)
    view, source_label = open_image_view()
    image, _notes = describe_image(view, source_label)
    if build is None:
        number, build_source = detect_build()
    else:
        number, build_source = int(build), "user"
    active_units = ([{"item_ids": [str(item)], "declaration_names": []}
                     for item in item_ids] +
                    [{"item_ids": [], "declaration_names": [str(name)]}
                     for name in declaration_names])
    source_units = [{"id": item.id} for item in loaded.items]
    job = {
        "version": JOB_VERSION, "status": "active", "source": {
            "path": source_path, "sha256": _hash(source_path), "stat": _stat(source_path),
        },
        "destination_path": destination_path, "work_dir": work_dir, "target": image,
        "build": {"number": number, "source": build_source},
        "source_units": source_units, "active_units": active_units,
        "source_cursor": 0, "active_cursor": 0,
        "type_expectations": _type_expectations(loaded, item_ids),
        "created_at": time.time(), "last_error": None,
    }
    try:
        os.makedirs(os.path.join(work_dir, "input"), exist_ok=False)
        os.makedirs(os.path.join(work_dir, "source"), exist_ok=False)
        os.makedirs(os.path.join(work_dir, "active"), exist_ok=False)
        for index, item in enumerate(loaded.items):
            _source_fragment(os.path.join(work_dir, "input", "%06d.cfs" % index),
                             loaded, item)
        _atomic_json(job_path, job)
    except Exception as exc:
        if os.path.isdir(work_dir):
            shutil.rmtree(work_dir)
        return result(error="unable to create refresh job: %s" % exc)
    return result(ok=True, job_path=job_path, phase="validate_source",
                  source_total=len(source_units), active_total=len(active_units),
                  target=image)


def refresh_status(job_path):
    """Return durable v2 progress without opening the IDB."""
    job, error = _load_job(job_path)
    if error:
        return result(error=error)
    phase = ("validate_source" if job["source_cursor"] < len(job["source_units"])
             else "export_active" if job["active_cursor"] < len(job["active_units"])
             else "ready_to_finalize")
    return result(ok=True, job_path=os.path.abspath(job_path), status=job["status"],
                  phase=phase, source_total=len(job["source_units"]),
                  source_completed=job["source_cursor"], active_total=len(job["active_units"]),
                  active_completed=job["active_cursor"], last_error=job.get("last_error"))


def _validation_context(view, image):
    ranges = get_search_ranges()
    if not ranges:
        raise ValueError("no executable/code search ranges found")
    imagebase = get_imagebase()
    return ranges, imagebase, BodyOwnership.for_current_idb(view, imagebase)


def _write_outcome(job, phase, index, item, reason, values, elapsed):
    value_rows = [[key, value] for key, value in sorted(values.items())]
    _atomic_json(_outcome_path(job, phase, index), {
        "id": item.id, "kind": item.kind,
        "name": getattr(item, "qualified_name", item.name),
        "reason": reason, "values": value_rows, "elapsed_ms": int(elapsed * 1000),
    })


def _step_source(job, index, view, image):
    loaded = cfs6.load_catalogue(os.path.join(job["work_dir"], "input", "%06d.cfs" % index))
    item = loaded.items[0]
    started = time.monotonic()
    ranges, imagebase, ownership = _validation_context(view, image)
    candidates, values, reason = rolling.revalidate_item(
        item, rolling._identity(loaded), ranges, imagebase, ownership,
    )
    elapsed = time.monotonic() - started
    if candidates:
        _write_fragment(_unit_path(job, "source", index), image, job["build"], item, candidates)
    _write_outcome(job, "source", index, item, reason, values, elapsed)
    return item, reason, elapsed


def _step_active(job, index, view, image):
    unit = job["active_units"][index]
    destination = _unit_path(job, "active", index)
    started = time.monotonic()
    ranges, imagebase, ownership = _validation_context(view, image)
    active, errors = rolling._selected_active_catalogue(
        destination, unit["item_ids"], unit["declaration_names"],
        (job["build"]["number"], job["build"]["source"]), ranges,
    )
    active_tmp = destination + ".active.tmp"
    if os.path.exists(active_tmp):
        os.remove(active_tmp)
    if errors or active is None or len(active.items) != 1:
        raise ValueError("active selection is not exportable: %s" % (errors or "unexpected item count"))
    item = active.items[0]
    candidates, values, reason = rolling.revalidate_item(
        item, {"image": image, "build": job["build"]}, ranges, imagebase, ownership,
    )
    if reason:
        raise ValueError("active selection did not validate: %s" % reason)
    meta = active.item_meta.get(item.id)
    if item.id in job["type_expectations"] and (meta is None or meta.type_blob is None):
        raise ValueError("required target type payload was not exported for %s" % item.id)
    _write_fragment(destination, image, job["build"], item, candidates, meta,
                    active.type_records)
    elapsed = time.monotonic() - started
    _write_outcome(job, "active", index, item, None, values, elapsed)
    return item, elapsed


def refresh_step(job_path, max_items=1):
    """Advance exactly one bounded source-validation or active-export unit."""
    job, error = _load_job(job_path)
    if error:
        return result(error=error)
    if job["status"] != "active":
        return result(error="invalid_job: refresh job is not active", job_path=job_path)
    try:
        one_item = int(max_items) == 1
    except (TypeError, ValueError):
        one_item = False
    if not one_item:
        return result(error="refresh job v2 requires max_items=1", job_path=job_path)
    binding_error, context = _job_binding(job)
    if binding_error:
        job["status"] = "stale"
        job["last_error"] = binding_error
        _atomic_json(job_path, job)
        return result(error=binding_error, job_path=job_path)
    view, image = context
    try:
        if job["source_cursor"] < len(job["source_units"]):
            index = job["source_cursor"]
            item, reason, elapsed = _step_source(job, index, view, image)
            job["source_cursor"] += 1
            phase = "validate_source"
            unresolved = ([] if reason is None else [{"kind": item.kind, "name": item.name,
                                                       "reason": reason}])
        elif job["active_cursor"] < len(job["active_units"]):
            index = job["active_cursor"]
            item, elapsed = _step_active(job, index, view, image)
            job["active_cursor"] += 1
            phase = "export_active"
            unresolved = []
        else:
            return result(error="invalid_job: refresh job is already complete", job_path=job_path)
    except Exception as exc:
        job["last_error"] = str(exc)
        _atomic_json(job_path, job)
        return result(partial=bool(job["source_cursor"] or job["active_cursor"]),
                      error=str(exc), job_path=job_path)
    job["last_error"] = None
    _atomic_json(job_path, job)
    return result(ok=not unresolved, partial=bool(unresolved), error=None,
                  unresolved=unresolved, job_path=job_path, phase=phase,
                  item_id=item.id, elapsed_ms=int(elapsed * 1000),
                  source_completed=job["source_cursor"], source_total=len(job["source_units"]),
                  active_completed=job["active_cursor"], active_total=len(job["active_units"]),
                  ready_to_finalize=(job["source_cursor"] == len(job["source_units"])
                                     and job["active_cursor"] == len(job["active_units"])))


def _outcome(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _add_fragment(entries, values, loaded, outcome, active=False):
    item = loaded.items[0]
    entry = entries.setdefault(item.id, {"item": item, "records": []})
    if active:
        entry["item"] = item
    for rec in item.candidates:
        entry["records"].append((rec, dict(rec.source), dict(rec.provenance or {})))
    for key, value in outcome.get("values", []):
        values.setdefault(item.id, {})[key] = value


def _compose(job, image):
    """Compose validated fragments without any IDA calls or image searches."""
    entries, values, unresolved = {}, {}, []
    for index in range(len(job["source_units"])):
        outcome = _outcome(_outcome_path(job, "source", index))
        path = _unit_path(job, "source", index)
        if not os.path.exists(path):
            unresolved.append({"kind": outcome["kind"], "name": outcome["name"],
                               "reason": outcome["reason"] or "no validated candidate"})
            continue
        _add_fragment(entries, values, cfs6.load_catalogue(path), outcome)
    active = cfs6.LoadedCfs({"version": cfs6.CFS7_FORMAT_VERSION, "image": image,
                              "build": dict(job["build"])})
    for index in range(len(job["active_units"])):
        outcome = _outcome(_outcome_path(job, "active", index))
        loaded = cfs6.load_catalogue(_unit_path(job, "active", index))
        _add_fragment(entries, values, loaded, outcome, active=True)
        active.items.extend(loaded.items)
        active.item_meta.update(loaded.item_meta)
        active.type_records.update(loaded.type_records)

    planned = []
    for iid, entry in sorted(entries.items()):
        item = entry["item"]
        unique = {}
        for rec, source, provenance in entry["records"]:
            key = rolling._candidate_key(rec)
            old = unique.get(key)
            if old is None or (rec.score, key) < (old[0].score, key):
                unique[key] = (rec, source, provenance)
        candidates = sorted(unique.values(), key=lambda row: (row[0].score,
            rolling._candidate_key(row[0])))[:rolling._limit(item)]
        if item.kind == cfs6.REC_DERIVED_VALUE:
            item_values = values.get(iid, {})
            selected_values = {item_values.get(rolling._candidate_key(row[0]))
                               for row in candidates}
            if None in selected_values or len(selected_values) != 1:
                unresolved.append({"kind": item.semantic, "name": item.qualified_name,
                                   "reason": "target candidate value conflict"})
                continue
        if candidates:
            planned.append((item, candidates))
    source = cfs6.load_catalogue(job["source"]["path"])
    output_ids = {item.id for item, _candidates in planned}
    metas, local_types = rolling._target_type_payloads(
        source, active, output_ids, image, job["build"]["number"],
    )
    return planned, metas, local_types, unresolved


def finalize_refresh(job_path):
    """Compose once, validate once, and atomically publish a completed v2 job."""
    job, error = _load_job(job_path)
    if error:
        return result(error=error)
    if job["status"] != "active" or job["source_cursor"] != len(job["source_units"]) \
            or job["active_cursor"] != len(job["active_units"]):
        return result(error="invalid_job: refresh job is incomplete", job_path=job_path)
    binding_error, context = _job_binding(job, force_hash=True)
    if binding_error:
        return result(error=binding_error, job_path=job_path)
    _view, image = context
    started = time.monotonic()
    temporary = job["destination_path"] + ".tmp"
    try:
        planned, metas, local_types, unresolved = _compose(job, image)
        with open(temporary, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs7Writer(handle, imagebase=0)
            writer.write_header(image, job["build"]["number"], job["build"]["source"])
            for item, candidates in planned:
                _write_fragment_item(writer, item, candidates)
            for iid in sorted(metas):
                meta = metas[iid]
                writer.write_item_type(iid, meta.name, meta.quality,
                    (meta.type_blob, meta.fields_blob, meta.fldcmts_blob),
                    meta.dependencies, is_global=meta.is_global)
            for name in sorted(local_types):
                record = local_types[name]
                writer.write_local_type(record.name, record.kind,
                    (record.type_blob, record.fields_blob, record.fldcmts_blob))
        checked = cfs6.load_catalogue(temporary)
        if checked.parse_errors:
            raise ValueError("generated CFS7 has %d parse errors" % checked.parse_errors)
        os.replace(temporary, job["destination_path"])
    except Exception as exc:
        return result(error="finalize failed: %s" % exc, job_path=job_path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)
    job["status"] = "finalized"
    job["output_sha256"] = _hash(job["destination_path"])
    _atomic_json(job_path, job)
    counts = rolling._type_counts(metas, local_types)
    return result(ok=not unresolved, partial=bool(unresolved), error=None,
                  unresolved=unresolved, job_path=job_path, path=job["destination_path"],
                  output_sha256=job["output_sha256"], items=len(checked.items),
                  elapsed_ms=int((time.monotonic() - started) * 1000), **counts)


def _write_fragment_item(writer, item, candidates):
    """The fragment writer's item emission, shared by final composition."""
    if item.kind == cfs6.REC_PATCH:
        iid = writer.write_patch(item.owner, item.name, len(candidates), item.coverage,
            {"expected_instruction": item.expected_instruction,
             "expected_bytes": item.expected_bytes, "patch_size": item.patch_size})
    elif item.kind in (cfs6.REC_FUNCTION, cfs6.REC_GLOBAL):
        iid = writer.write_item(item.kind, item.name, len(candidates), item.coverage)
    else:
        iid = writer.write_derived_value(item.semantic, item.owner, item.name,
            len(candidates), item.coverage, expected_value=item.expected_value,
            portable_member_schema=item.portable_member_schema)
    for rank, (rec, source, provenance) in enumerate(candidates):
        writer.write_revalidated_candidate(iid, rank, rec, source, provenance)
    return iid


def discard_refresh(job_path):
    """Discard only the exact private artifacts for a v1 or v2 refresh job."""
    raw, error = _load_raw_job(job_path)
    if error:
        return result(error=error)
    paths = [job_path]
    if raw.get("version") == JOB_VERSION:
        work_dir = raw.get("work_dir")
        if work_dir == _work_dir(raw.get("destination_path", "")) and os.path.isdir(work_dir):
            shutil.rmtree(work_dir)
    elif raw.get("version") == 1:
        for path in (raw.get("stage_path"), str(raw.get("stage_path", "")) + ".next"):
            if path and os.path.isfile(path):
                os.remove(path)
    else:
        return result(error="invalid_job: unknown refresh job version")
    if os.path.isfile(job_path):
        os.remove(job_path)
    return result(ok=True, discarded_job_path=os.path.abspath(job_path))
