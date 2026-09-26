"""Programmatic catalogue application and producer-state migration."""

from . import importer as _importer
from . import promotion as _promotion
from . import rolling as _rolling
from . import refresh_jobs as _refresh_jobs


def import_catalogue(path):
    """Apply names and types from a CFS6 catalogue without interactive UI."""
    return _importer.import_catalogue(path, show_progress=False)


def migrate_state(path, require_all=False):
    """Transactionally reconstruct portable producer state from a catalogue."""
    return _importer.migrate_producer_state(path, require_all=require_all)


def import_and_migrate(path, require_all_state=False):
    """Apply a catalogue, then reconstruct producer state from resolved proof."""
    return _importer.import_and_migrate(
        path, require_all_state=require_all_state, show_progress=False
    )


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


def refresh_status(job_path):
    return _refresh_jobs.refresh_status(job_path)


def finalize_refresh(job_path):
    return _refresh_jobs.finalize_refresh(job_path)


def discard_refresh(job_path):
    return _refresh_jobs.discard_refresh(job_path)
