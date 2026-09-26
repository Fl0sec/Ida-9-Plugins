"""Durable, bounded application of large CFS catalogues.

This deliberately reuses the importer for one immutable catalogue item at a
time.  It trades a little setup I/O for a hard synchronization boundary: no
MCP request owns an unbounded whole-image candidate scan.
"""

import json
import os
import shutil
import tempfile
import time

from . import cfs6, importer
from .api_result import result
from .image import describe_image, open_image_view
from .refresh_jobs import RUN_DEFAULT_BUDGET_SEC, RUN_MAX_BUDGET_SEC, RUN_MIN_BUDGET_SEC
from .typeio import register_missing_types


JOB_VERSION = 1
MAX_DIRECT_ITEMS = 8
OPERATIONS = ("catalogue", "migrate", "import_and_migrate")


def item_count(path):
    """Return the address/declaration item count, or ``None`` if unreadable."""
    try:
        return len(cfs6.load_catalogue(path).items)
    except Exception:
        return None


def direct_required(path, operation, require_all_state=False):
    count = item_count(path)
    if count is None or count <= MAX_DIRECT_ITEMS:
        return None
    return result(error="resumable_job_required: %d catalogue items exceed the direct limit of %d" %
                  (count, MAX_DIRECT_ITEMS), recommended={
                      "catalogue_path": path, "operation": operation,
                      "require_all_state": bool(require_all_state),
                  }, item_count=count)


def _job_path(path, operation):
    return os.path.abspath(path) + ".%s-import-job.json" % operation


def _work_dir(path, operation):
    return os.path.abspath(path) + ".%s-import-job" % operation


def _atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".cfs-import-", suffix=".json", dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


def _hash(path):
    import hashlib
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load(job_path):
    try:
        with open(job_path, "r", encoding="utf-8") as handle:
            job = json.load(handle)
    except Exception as exc:
        return None, "invalid_job: %s" % exc
    required = {"version", "catalogue_path", "catalogue_sha256", "operation",
                "work_dir", "target", "units", "cursor", "status", "outcomes"}
    if job.get("version") != JOB_VERSION or not required <= set(job):
        return None, "invalid_job: malformed import job"
    if job["operation"] not in OPERATIONS or os.path.abspath(job["work_dir"]) != _work_dir(job["catalogue_path"], job["operation"]):
        return None, "invalid_job: unexpected import job binding"
    return job, None


def _binding(job):
    if not os.path.isfile(job["catalogue_path"]) or _hash(job["catalogue_path"]) != job["catalogue_sha256"]:
        return "stale_job: catalogue changed"
    view, source = open_image_view()
    image, _notes = describe_image(view, source)
    return None if image == job["target"] else "stale_job: active target identity changed"


def _write_fragment(path, loaded, item):
    """Write a one-item CFS6 input retaining its item type, not all local types."""
    with open(path + ".tmp", "w", encoding="utf-8", newline="") as handle:
        writer = cfs6.Cfs6Writer(handle, imagebase=0)
        header = loaded.header
        writer.write_header(loaded.image(), header["build"].get("number"), header["build"].get("source", "unknown"))
        if item.kind in (cfs6.REC_FUNCTION, cfs6.REC_GLOBAL):
            iid = writer.write_item(item.kind, item.name, len(item.candidates), item.coverage)
        elif item.kind == cfs6.REC_DERIVED_VALUE:
            iid = writer.write_derived_value(item.semantic, item.owner, item.name, len(item.candidates), item.coverage,
                                             expected_value=item.expected_value, portable_member_schema=item.portable_member_schema)
        else:
            iid = writer.write_patch(item.owner, item.name, len(item.candidates), item.coverage,
                                     {"expected_instruction": item.expected_instruction, "expected_bytes": item.expected_bytes, "patch_size": item.patch_size})
        for rank, rec in enumerate(item.candidates):
            writer.write_revalidated_candidate(iid, rank, rec, rec.source)
        meta = loaded.item_meta.get(item.id)
        if meta is not None and meta.type_blob is not None:
            writer.write_item_type(iid, meta.name, meta.quality,
                                   (meta.type_blob, meta.fields_blob, meta.fldcmts_blob), meta.dependencies, meta.is_global)
    os.replace(path + ".tmp", path)


def begin_import_job(catalogue_path, operation="import_and_migrate", require_all_state=False, job_path=None):
    if operation not in OPERATIONS:
        return result(error="operation must be one of %s" % ", ".join(OPERATIONS))
    try:
        loaded = cfs6.load_catalogue(catalogue_path)
    except Exception as exc:
        return result(error=str(exc))
    catalogue_path = os.path.abspath(catalogue_path)
    job_path = os.path.abspath(job_path or _job_path(catalogue_path, operation))
    work_dir = _work_dir(catalogue_path, operation)
    if os.path.exists(job_path) or os.path.exists(work_dir):
        return result(error="import job already exists", job_path=job_path)
    view, source = open_image_view()
    target, _notes = describe_image(view, source)
    units = [] if operation == "migrate" else [
        {"id": item.id, "kind": item.kind,
         "name": getattr(item, "qualified_name", item.name)}
        for item in loaded.items
    ]
    job = {"version": JOB_VERSION, "catalogue_path": catalogue_path,
           "catalogue_sha256": _hash(catalogue_path), "operation": operation,
           "require_all_state": bool(require_all_state), "work_dir": work_dir,
           "target": target, "units": units,
           "cursor": 0, "status": "types" if operation == "import_and_migrate" else "importing",
           "outcomes": [], "type_state": None, "last_error": None}
    try:
        os.makedirs(os.path.join(work_dir, "items"), exist_ok=False)
        for index, item in enumerate(loaded.items):
            _write_fragment(os.path.join(work_dir, "items", "%06d.cfs" % index), loaded, item)
        _atomic_json(job_path, job)
    except Exception as exc:
        if os.path.isdir(work_dir):
            shutil.rmtree(work_dir)
        return result(error="unable to create import job: %s" % exc)
    return result(ok=True, job_path=job_path, operation=operation, total=len(loaded.items), target=target)


def import_job_status(job_path):
    job, error = _load(job_path)
    if error:
        return result(error=error)
    unresolved = [row for row in job["outcomes"] if row.get("status") not in ("renamed", "already-same", "already-global", "validated", "destination-agrees", "destination-unverified")]
    migration = job.get("migration") or {}
    migration_unresolved = list(migration.get("unresolved", ()))
    compact = [{"kind": row["kind"], "name": row["name"], "reason": row.get("reason", row.get("status", "failed"))} for row in unresolved]
    compact.extend(migration_unresolved)
    return result(ok=job["status"] == "finalized" and not compact, partial=bool(compact),
                  unresolved=compact,
                  job_path=os.path.abspath(job_path), status=job["status"], completed=job["cursor"], total=len(job["units"]), last_error=job.get("last_error"))


def import_job_outcomes(job_path, offset=0, limit=100):
    job, error = _load(job_path)
    if error:
        return result(error=error)
    try:
        offset, limit = max(0, int(offset)), max(1, min(500, int(limit)))
    except (TypeError, ValueError):
        return result(error="offset and limit must be integers")
    return result(ok=True, job_path=os.path.abspath(job_path), outcomes=job["outcomes"][offset:offset + limit],
                  offset=offset, next_offset=(offset + limit if offset + limit < len(job["outcomes"]) else None), total_outcomes=len(job["outcomes"]))


def _run_types(job):
    loaded = cfs6.load_catalogue(job["catalogue_path"])
    stats = importer.Stats()
    state = register_missing_types(loaded.type_records, stats)
    job["type_state"] = {key: sorted(value) for key, value in state.items()}
    job["status"] = "importing"


def run_import_job(job_path, budget_seconds=RUN_DEFAULT_BUDGET_SEC):
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
        return import_job_status(job_path)
    binding = _binding(job)
    if binding:
        job["status"], job["last_error"] = "stale", binding
        _atomic_json(job_path, job)
        return result(error=binding, job_path=job_path)
    started, deadline, units = time.monotonic(), time.monotonic() + budget, 0
    try:
        if job["status"] == "types":
            _run_types(job)
            _atomic_json(job_path, job)
        while job["cursor"] < len(job["units"]):
            if units and deadline - time.monotonic() < 30.0:
                break
            index = job["cursor"]
            fragment = os.path.join(job["work_dir"], "items", "%06d.cfs" % index)
            raw = importer.import_catalogue(fragment, show_progress=False, transport_types=False)
            job["outcomes"].extend(raw.get("outcomes", []))
            job["cursor"] += 1
            units += 1
            _atomic_json(job_path, job)
        if job["cursor"] == len(job["units"]):
            if job["operation"] in ("migrate", "import_and_migrate"):
                state = importer.migrate_producer_state(job["catalogue_path"], require_all=job["require_all_state"])
                job["migration"] = state
            job["status"] = "finalized"
            _atomic_json(job_path, job)
    except Exception as exc:
        job["last_error"] = str(exc)
        _atomic_json(job_path, job)
        return result(partial=bool(job["cursor"]), error=str(exc), job_path=job_path, completed=job["cursor"], total=len(job["units"]))
    status = import_job_status(job_path)
    status.update(units_processed=units, elapsed_ms=int((time.monotonic() - started) * 1000), finalized=job["status"] == "finalized")
    return status


def discard_import_job(job_path):
    job, error = _load(job_path)
    if error:
        return result(error=error)
    if os.path.isdir(job["work_dir"]):
        shutil.rmtree(job["work_dir"])
    if os.path.isfile(job_path):
        os.remove(job_path)
    return result(ok=True, discarded_job_path=os.path.abspath(job_path))
