"""Bounded, restart-resumable CFS6 exports of the annotated IDB surface."""

import json
import os
import shutil
import tempfile
import time

from . import annotated, annotated_export_policy, cfs6, export
from .api_result import result
from .common import get_search_ranges
from .image import describe_image, detect_build, get_imagebase, open_image_view
from .refresh_jobs import RUN_DEFAULT_BUDGET_SEC, RUN_MAX_BUDGET_SEC, RUN_MIN_BUDGET_SEC


JOB_VERSION = 1


def _job_path(destination):
    return os.path.abspath(destination) + ".annotated-export-job.json"


def _work_dir(destination):
    return os.path.abspath(destination) + ".annotated-export-job"


def _atomic_json(path, value):
    directory = os.path.dirname(path) or "."
    fd, temporary = tempfile.mkstemp(prefix=".cfs-annotated-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


def _load(job_path):
    try:
        with open(job_path, "r", encoding="utf-8") as handle:
            job = json.load(handle)
    except Exception as exc:
        return None, "invalid_job: %s" % exc
    required = {"version", "destination_path", "work_dir", "target", "build",
                "selection_digest", "units", "cursor", "status"}
    if job.get("version") != JOB_VERSION or not required <= set(job):
        return None, "invalid_job: malformed annotated export job"
    if os.path.abspath(job["work_dir"]) != _work_dir(job["destination_path"]):
        return None, "invalid_job: unexpected annotated export work directory"
    # Version 1 initially stopped on a safe no-candidate result.  Treat old
    # manifests as having no exclusions so they resume without recreation.
    job.setdefault("skipped", [])
    return job, None


def _binding(job):
    view, label = open_image_view()
    image, _notes = describe_image(view, label)
    if image != job["target"]:
        return None, "stale_job: active target identity changed"
    return image, None


def plan_annotated_export(build=None):
    """Preview a snapshot selection without generating candidates or files."""
    view, label = open_image_view()
    image, _notes = describe_image(view, label)
    number, source = detect_build() if build is None else (int(build), "user")
    selection = annotated.discover()
    digest = annotated.digest(selection, image, {"number": number, "source": source},
                              cfs6.GENERATOR_VERSION, cfs6.SCHEMA_REVISION)
    return result(ok=True, dry_run=True, selection_digest=digest, target=image,
                  build={"number": number, "source": source},
                  functions=len(selection["functions"]), globals=len(selection["globals"]),
                  excluded=selection["excluded"],
                  function_samples=[name for name, _ea in selection["functions"][:100]],
                  global_samples=[name for name, _ea in selection["globals"][:100]],
                  samples_truncated=(len(selection["functions"]) > 100 or len(selection["globals"]) > 100),
                  type_mode="transitive_from_exported_functions_and_globals")


def begin_annotated_export(destination_path, expected_selection_digest, build=None):
    """Freeze a reviewed selection into durable per-item export units."""
    if not isinstance(destination_path, str) or not destination_path:
        return result(error="destination_path is required")
    if not destination_path.lower().endswith(".cfs"):
        destination_path += ".cfs"
    destination_path = os.path.abspath(destination_path)
    if not isinstance(expected_selection_digest, str) or not expected_selection_digest:
        return result(error="expected_selection_digest is required")
    job_path, work_dir = _job_path(destination_path), _work_dir(destination_path)
    if os.path.exists(job_path) or os.path.exists(work_dir):
        return result(error="annotated export job already exists", job_path=job_path)
    preview = plan_annotated_export(build)
    if preview["selection_digest"] != expected_selection_digest:
        return result(error="selection changed since dry-run; plan again",
                      selection_digest=preview["selection_digest"])
    selection = annotated.discover()
    actual_digest = annotated.digest(
        selection, preview["target"], preview["build"],
        cfs6.GENERATOR_VERSION, cfs6.SCHEMA_REVISION,
    )
    if actual_digest != expected_selection_digest:
        return result(error="selection changed while creating job; plan again",
                      selection_digest=actual_digest)
    units = ([{"kind": "function", "name": name, "ea": ea}
              for name, ea in selection["functions"]] +
             [{"kind": "global", "name": name, "ea": ea}
              for name, ea in selection["globals"]])
    if not units:
        return result(error="nothing annotated to export")
    job = {"version": JOB_VERSION, "status": "active", "destination_path": destination_path,
           "work_dir": work_dir, "target": preview["target"], "build": preview["build"],
           "selection_digest": expected_selection_digest, "units": units, "cursor": 0,
           "skipped": [],
           "created_at": time.time(), "last_error": None}
    try:
        os.makedirs(os.path.join(work_dir, "fragments"), exist_ok=False)
        _atomic_json(job_path, job)
    except Exception as exc:
        if os.path.isdir(work_dir):
            shutil.rmtree(work_dir)
        return result(error="unable to create annotated export job: %s" % exc)
    return result(ok=True, job_path=job_path, total=len(units), target=preview["target"],
                  selection_digest=expected_selection_digest)


def annotated_export_status(job_path):
    job, error = _load(job_path)
    if error:
        return result(error=error)
    return result(ok=True, job_path=os.path.abspath(job_path), status=job["status"],
                  completed=job["cursor"], total=len(job["units"]),
                  skipped=len(job["skipped"]), unresolved=list(job["skipped"]),
                  last_error=job["last_error"])


def _fragment_path(job, index):
    return os.path.join(job["work_dir"], "fragments", "%06d.cfs" % index)


def _step(job, index, ranges):
    unit = job["units"][index]
    fragment = _fragment_path(job, index)
    raw = export.export_to_path(
        fragment, ranges,
        function_eas=[unit["ea"]] if unit["kind"] == "function" else [],
        global_eas=[unit["ea"]] if unit["kind"] == "global" else [],
        build=(job["build"]["number"], job["build"]["source"]),
        merge=export.MERGE_OVERWRITE, validate_output=True,
    )
    if raw.get("error"):
        raise ValueError("%s %s was not exportable: %s" % (
            unit["kind"], unit["name"], raw["error"]))
    issue = annotated_export_policy.unexportable_issue(unit, raw)
    if issue is not None:
        if os.path.exists(fragment):
            os.remove(fragment)
        return unit, issue
    return unit, None


def _compose(job):
    temporary = job["destination_path"] + ".tmp"
    local_types = {}
    items, metas = [], {}
    try:
        skipped = {int(entry["index"]) for entry in job["skipped"]}
        for index in range(len(job["units"])):
            if index in skipped:
                continue
            loaded = cfs6.load_catalogue(_fragment_path(job, index))
            if loaded.parse_errors or len(loaded.items) != 1:
                raise ValueError("invalid annotated export fragment %d" % index)
            item = loaded.items[0]
            items.append(item)
            metas.update(loaded.item_meta)
            for name, record in loaded.type_records.items():
                old = local_types.get(name)
                if old is not None and (old.type_blob, old.fields_blob, old.fldcmts_blob) != (
                        record.type_blob, record.fields_blob, record.fldcmts_blob):
                    raise ValueError("conflicting local type payload for %s" % name)
                local_types[name] = record
        with open(temporary, "w", encoding="utf-8", newline="") as handle:
            writer = cfs6.Cfs6Writer(handle, imagebase=0)
            writer.write_header(job["target"], job["build"]["number"], job["build"]["source"])
            for item in items:
                iid = writer.write_item(item.kind, item.name, len(item.candidates), item.coverage)
                for rank, candidate in enumerate(item.candidates):
                    writer.write_revalidated_candidate(iid, rank, candidate, candidate.source)
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
        if checked.parse_errors or len(checked.items) != len(items):
            raise ValueError("generated annotated snapshot did not validate")
        os.replace(temporary, job["destination_path"])
        return checked, len(metas), len(local_types)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


def run_annotated_export(job_path, budget_seconds=RUN_DEFAULT_BUDGET_SEC):
    """Drive many units internally; callers must not loop one item at a time."""
    try:
        budget = int(budget_seconds)
    except (TypeError, ValueError):
        return result(error="budget_seconds must be an integer")
    if not RUN_MIN_BUDGET_SEC <= budget <= RUN_MAX_BUDGET_SEC:
        return result(error="budget_seconds must be between %d and %d" % (RUN_MIN_BUDGET_SEC, RUN_MAX_BUDGET_SEC))
    job, error = _load(job_path)
    if error:
        return result(error=error)
    if job["status"] == "finalized":
        partial = bool(job["skipped"])
        return result(ok=not partial, partial=partial, unresolved=list(job["skipped"]),
                      job_path=job_path, path=job["destination_path"],
                      completed=len(job["units"]), total=len(job["units"]))
    if job["status"] != "active":
        return result(error="invalid_job: annotated export job is not active", job_path=job_path)
    _image, binding_error = _binding(job)
    if binding_error:
        job["status"], job["last_error"] = "stale", binding_error
        _atomic_json(job_path, job)
        return result(error=binding_error, job_path=job_path)
    ranges = get_search_ranges()
    if not ranges:
        return result(error="no executable/code search ranges found", job_path=job_path)
    started, deadline, units = time.monotonic(), time.monotonic() + budget, 0
    while job["cursor"] < len(job["units"]):
        # Keep a conservative reserve: an individual signature export may scan
        # the complete executable image, so never start one at the deadline.
        if units and deadline - time.monotonic() < 30.0:
            break
        try:
            index = job["cursor"]
            unit, issue = _step(job, index, ranges)
        except Exception as exc:
            job["last_error"] = str(exc)
            _atomic_json(job_path, job)
            return result(partial=bool(job["cursor"]), error=str(exc), job_path=job_path,
                          completed=job["cursor"], total=len(job["units"]), units_processed=units)
        job["cursor"] += 1
        if issue is not None:
            issue["index"] = index
            job["skipped"].append(issue)
        job["last_error"] = None
        _atomic_json(job_path, job)
        units += 1
    extra = {}
    if job["cursor"] == len(job["units"]):
        try:
            checked, type_count, local_type_count = _compose(job)
            job["status"] = "finalized"
            _atomic_json(job_path, job)
            extra = {"path": job["destination_path"], "items": len(checked.items),
                     "types": type_count, "local_types": local_type_count}
        except Exception as exc:
            job["last_error"] = "finalize failed: %s" % exc
            _atomic_json(job_path, job)
            return result(partial=True, error=job["last_error"], job_path=job_path,
                          completed=job["cursor"], total=len(job["units"]),
                          unresolved=list(job["skipped"]))
    partial = bool(job["skipped"])
    return result(ok=job["status"] == "finalized" and not partial, partial=partial,
                  unresolved=list(job["skipped"]), job_path=job_path,
                  completed=job["cursor"], total=len(job["units"]), units_processed=units,
                  elapsed_ms=int((time.monotonic() - started) * 1000),
                  finalized=job["status"] == "finalized", **extra)


def discard_annotated_export(job_path):
    job, error = _load(job_path)
    if error:
        return result(error=error)
    if os.path.isdir(job["work_dir"]):
        shutil.rmtree(job["work_dir"])
    if os.path.isfile(job_path):
        os.remove(job_path)
    return result(ok=True, discarded_job_path=os.path.abspath(job_path))
