"""Programmatic catalogue application and producer-state migration."""

from . import importer as _importer
from . import promotion as _promotion
from . import rolling as _rolling


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
    return _rolling.refresh_catalogue(
        source_path, destination_path, build=build, item_ids=item_ids,
        declaration_names=declaration_names,
    )
