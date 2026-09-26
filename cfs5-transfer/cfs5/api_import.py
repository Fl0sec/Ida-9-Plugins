"""Programmatic catalogue application and producer-state migration."""

from . import importer as _importer
from . import promotion as _promotion
from . import rolling as _rolling
from . import refresh_jobs as _refresh_jobs
from . import import_jobs as _import_jobs


def import_catalogue(path):
    """Apply names and types from a CFS6 catalogue without interactive UI."""
    routed = _import_jobs.direct_required(path, "catalogue")
    if routed is not None:
        return routed
    return _importer.import_catalogue(path, show_progress=False)


def migrate_state(path, require_all=False):
    """Transactionally reconstruct portable producer state from a catalogue."""
    routed = _import_jobs.direct_required(path, "migrate", require_all)
    if routed is not None:
        return routed
    return _importer.migrate_producer_state(path, require_all=require_all)


def import_and_migrate(path, require_all_state=False):
    """Apply a catalogue, then reconstruct producer state from resolved proof."""
    routed = _import_jobs.direct_required(path, "import_and_migrate", require_all_state)
    if routed is not None:
        return routed
    return _importer.import_and_migrate(
        path, require_all_state=require_all_state, show_progress=False
    )


def begin_import_job(catalogue_path, operation="import_and_migrate",
                     require_all_state=False, job_path=None):
    return _import_jobs.begin_import_job(catalogue_path, operation,
                                         require_all_state, job_path)


def run_import_job(job_path, budget_seconds=90):
    return _import_jobs.run_import_job(job_path, budget_seconds)


def import_job_status(job_path):
    return _import_jobs.import_job_status(job_path)


def import_job_outcomes(job_path, offset=0, limit=100):
    return _import_jobs.import_job_outcomes(job_path, offset, limit)


def discard_import_job(job_path):
    return _import_jobs.discard_import_job(job_path)


def promote_catalogue(source_path, destination_path, build=None, item_ids=(),
                      declaration_names=(), preserve_validated=False):
    """Revalidate selected records and write a fresh target-build catalogue."""
    return _promotion.promote_catalogue(
        source_path, destination_path, build=build, item_ids=item_ids,
        declaration_names=declaration_names, preserve_validated=preserve_validated,
    )


def refresh_catalogue(source_path, destination_path, build=None, item_ids=(),
                      declaration_names=()):
    """Write a rolling CFS7 catalogue validated against the active target."""
    if len(item_ids) + len(declaration_names) > _refresh_jobs.LEGACY_MAX_SELECTION:
        return {
            "ok": False, "partial": False, "error": "resumable_refresh_required: "
            "large selections must use begin_refresh/refresh_step/finalize_refresh",
            "unresolved": [], "recommended": {"source_path": source_path,
            "destination_path": destination_path, "build": build,
            "item_ids": list(item_ids), "declaration_names": list(declaration_names)},
        }
    return _rolling.refresh_catalogue(
        source_path, destination_path, build=build, item_ids=item_ids,
        declaration_names=declaration_names,
    )


def begin_refresh(source_path, destination_path, build=None, item_ids=(), declaration_names=()):
    return _refresh_jobs.begin_refresh(source_path, destination_path, build, item_ids, declaration_names)


def refresh_step(job_path, max_items=1):
    return _refresh_jobs.refresh_step(job_path, max_items)


def refresh_run(job_path, budget_seconds=90):
    """Drive a resumable refresh for a bounded 10-90 second MCP budget."""
    return _refresh_jobs.refresh_run(job_path, budget_seconds)


def refresh_status(job_path):
    return _refresh_jobs.refresh_status(job_path)


def finalize_refresh(job_path):
    return _refresh_jobs.finalize_refresh(job_path)


def discard_refresh(job_path):
    return _refresh_jobs.discard_refresh(job_path)
