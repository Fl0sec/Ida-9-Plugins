"""Restart-resumable, bounded CFS7 refresh jobs.

The rolling engine remains the single source of refresh semantics.  A job
advances it one explicitly selected active record at a time into a private
stage catalogue, making every IDA callback short and leaving publication to an
explicit finalization step.
"""

import hashlib
import json
import os
import shutil
import tempfile
import time

from . import cfs6, rolling
from .api_result import result
from .image import describe_image, open_image_view, detect_build


JOB_VERSION = 1
LEGACY_MAX_SELECTION = 8


def _hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _load_job(job_path):
    try:
        with open(job_path, "r", encoding="utf-8") as handle:
            job = json.load(handle)
    except Exception as exc:
        return None, "invalid_job: %s" % exc
    required = {"version", "source_path", "source_sha256", "destination_path",
                "stage_path", "target", "units", "cursor", "build"}
    if job.get("version") != JOB_VERSION or not required <= set(job):
        return None, "invalid_job: malformed refresh job"
    return job, None


def _job_binding(job):
    if not os.path.isfile(job["source_path"]):
        return "stale_job: source catalogue no longer exists"
    if _hash(job["source_path"]) != job["source_sha256"]:
        return "stale_job: source catalogue hash changed"
    view, source = open_image_view()
    image, _notes = describe_image(view, source)
    if image != job["target"]:
        return "stale_job: active target identity changed"
    return None


def _job_path(destination_path):
    return os.path.abspath(destination_path) + ".refresh-job.json"


def _stage_path(destination_path):
    return os.path.abspath(destination_path) + ".refresh-job.stage.cfs"


def begin_refresh(source_path, destination_path, build=None, item_ids=(),
                  declaration_names=()):
    """Create a durable refresh plan; no catalogue is published or changed."""
    source_path = os.path.abspath(source_path)
    destination_path = os.path.abspath(destination_path)
    if not destination_path or source_path == destination_path:
        return result(error="refresh job requires a distinct destination path")
    try:
        cfs6.load_catalogue(source_path)
    except Exception as exc:
        return result(error=str(exc))
    job_path = _job_path(destination_path)
    if os.path.exists(job_path):
        return result(error="refresh job already exists", job_path=job_path)
    view, source = open_image_view()
    image, _notes = describe_image(view, source)
    if build is None:
        number, build_source = detect_build()
    else:
        number, build_source = int(build), "user"
    units = ([{"item_ids": [str(item)], "declaration_names": []}
              for item in item_ids] +
             [{"item_ids": [], "declaration_names": [str(name)]}
              for name in declaration_names])
    if not units:
        # A source-only rolling refresh is still one bounded, publishable unit.
        units.append({"item_ids": [], "declaration_names": []})
    job = {
        "version": JOB_VERSION, "status": "active", "source_path": source_path,
        "source_sha256": _hash(source_path), "destination_path": destination_path,
        "stage_path": _stage_path(destination_path), "target": image,
        "build": {"number": number, "source": build_source}, "units": units,
        "cursor": 0, "created_at": time.time(), "last_error": None,
    }
    _atomic_json(job_path, job)
    return result(ok=True, job_path=job_path, total_units=len(units),
                  completed_units=0, target=image)


def refresh_status(job_path):
    """Return durable job progress without touching the IDB."""
    job, error = _load_job(job_path)
    if error:
        return result(error=error)
    return result(ok=True, job_path=os.path.abspath(job_path), status=job["status"],
                  total_units=len(job["units"]), completed_units=job["cursor"],
                  remaining_units=len(job["units"]) - job["cursor"],
                  stage_path=job["stage_path"], last_error=job.get("last_error"))


def refresh_step(job_path, max_items=1):
    """Advance at most ``max_items`` selected records into the private stage."""
    job, error = _load_job(job_path)
    if error:
        return result(error=error)
    if job["status"] != "active":
        return result(error="invalid_job: refresh job is not active", job_path=job_path)
    binding_error = _job_binding(job)
    if binding_error:
        job["status"] = "stale"
        job["last_error"] = binding_error
        _atomic_json(job_path, job)
        return result(error=binding_error, job_path=job_path)
    try:
        limit = max(1, min(int(max_items), 4))
    except (TypeError, ValueError):
        return result(error="max_items must be an integer")
    completed_now = 0
    while completed_now < limit and job["cursor"] < len(job["units"]):
        unit = job["units"][job["cursor"]]
        source = job["stage_path"] if job["cursor"] else job["source_path"]
        next_stage = job["stage_path"] + ".next"
        raw = rolling.refresh_catalogue(
            source, next_stage, build=job["build"]["number"],
            item_ids=unit["item_ids"], declaration_names=unit["declaration_names"],
        )
        if raw.get("error"):
            if os.path.exists(next_stage):
                os.remove(next_stage)
            job["last_error"] = raw["error"]
            _atomic_json(job_path, job)
            return result(partial=bool(job["cursor"]), error=raw["error"],
                          unresolved=raw.get("unresolved", []), job_path=job_path,
                          completed_units=job["cursor"], total_units=len(job["units"]))
        os.replace(next_stage, job["stage_path"])
        job["cursor"] += 1
        completed_now += 1
        job["last_error"] = None
        _atomic_json(job_path, job)
    return result(ok=True, job_path=job_path, completed_now=completed_now,
                  completed_units=job["cursor"], total_units=len(job["units"]),
                  ready_to_finalize=(job["cursor"] == len(job["units"])))


def finalize_refresh(job_path):
    """Validate the completed private stage and atomically publish it."""
    job, error = _load_job(job_path)
    if error:
        return result(error=error)
    if job["status"] != "active" or job["cursor"] != len(job["units"]):
        return result(error="invalid_job: refresh job is incomplete", job_path=job_path,
                      completed_units=job["cursor"], total_units=len(job["units"]))
    binding_error = _job_binding(job)
    if binding_error:
        return result(error=binding_error, job_path=job_path)
    try:
        checked = cfs6.load_catalogue(job["stage_path"])
        if checked.parse_errors:
            raise ValueError("staged CFS7 has %d parse errors" % checked.parse_errors)
        temporary = job["destination_path"] + ".tmp"
        shutil.copyfile(job["stage_path"], temporary)
        cfs6.load_catalogue(temporary)
        os.replace(temporary, job["destination_path"])
    except Exception as exc:
        return result(error="finalize failed: %s" % exc, job_path=job_path)
    job["status"] = "finalized"
    job["output_sha256"] = _hash(job["destination_path"])
    _atomic_json(job_path, job)
    return result(ok=True, job_path=job_path, path=job["destination_path"],
                  output_sha256=job["output_sha256"], items=len(checked.items))


def discard_refresh(job_path):
    """Discard only a job's private stage and durable manifest."""
    job, error = _load_job(job_path)
    if error:
        return result(error=error)
    for path in (job["stage_path"], job["stage_path"] + ".next", job_path):
        if os.path.exists(path):
            os.remove(path)
    return result(ok=True, discarded_job_path=os.path.abspath(job_path))
