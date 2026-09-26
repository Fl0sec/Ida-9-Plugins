"""Programmatic full, explicit-list, and selected CFS exports."""

import os

from . import export as _export
from . import annotated_export_jobs
from . import registry
from . import selection
from . import store
from .common import get_search_ranges
from .image import detect_build
from .api_registry import _collect
from .api_result import result as _result

def _run_export(path, function_eas, global_eas, unresolved, merge, build,
                include_members, function_sites=None, function_locators=None):
    """Shared tail of `export` and `export_list`."""
    if not isinstance(path, str) or not path:
        return _result(error="path is required", unresolved=unresolved)
    if not path.lower().endswith(".cfs"):
        path += ".cfs"

    declarations = store.load_all() if include_members else []
    patches = store.load_patches() if include_members else []
    requested = (len(function_eas) + len(global_eas) + len(declarations)
                 + len(patches))
    if not requested:
        return _result(error="nothing resolved to export", unresolved=unresolved)

    if build is None:
        build_number, build_source = detect_build()
    else:
        build_number, build_source = int(build), "user"

    # Types may have changed since the last export in this session.
    _export.clear_caches()

    raw = _export.export_to_path(
        path, get_search_ranges(),
        function_eas=function_eas, global_eas=global_eas,
        declarations=declarations,
        patches=patches,
        build=(build_number, build_source), merge=merge,
        function_sites=function_sites,
        function_locators=function_locators,
    )

    # Names that never resolved never reached the engine, so they have to be
    # merged in here or they would vanish from the report entirely.
    missed = list(unresolved) + list(raw.get("uncovered", ()))
    written = raw.get("written", 0)
    # `requested` counts only what got as far as the engine; anything rejected
    # earlier was still asked for, so it belongs in the denominator.
    asked = requested + len(unresolved)

    if raw.get("error") and written == 0:
        return _result(error=raw["error"], unresolved=missed,
                       cancelled=raw.get("cancelled", False),
                       path=raw.get("path", path), requested=asked, written=0)

    ok, partial = registry.outcome(asked, written, missed)
    return _result(
        ok=ok, partial=partial,
        error=raw.get("error"),
        unresolved=missed,
        path=raw.get("path", path),
        requested=asked,
        written=written,
        functions=raw.get("functions", 0),
        globals=raw.get("globals", 0),
        members=raw.get("members", 0),
        patches=raw.get("patches", 0),
        types=raw.get("types", 0),
        merged=raw.get("merged"),
        mode=raw.get("mode"),
        cancelled=raw.get("cancelled", False),
        # Not failures: anchors that exist but could not be exported, and
        # sites that did not survive verification. An item can be exported
        # and still have something here worth reading.
        advisory=raw.get("advisory", []),
        summary=raw.get("summary", ""),
    )


def export(path, merge=_export.MERGE_APPEND, build=None, include_members=True):
    """Export the registered set, preserving compatible existing records."""
    by_kind = registry.split_by_kind(store.load_registry())
    function_eas, global_eas, sites, locators, unresolved = _collect(
        by_kind[registry.KIND_FUNCTION], by_kind[registry.KIND_GLOBAL],
        sites_by_id=store.load_sites(),
        locators_by_id=store.load_locators(),
    )
    return _run_export(path, function_eas, global_eas, unresolved,
                       merge, build, include_members, function_sites=sites,
                       function_locators=locators)


def export_list(path, function_names=(), global_names=(),
                merge=_export.MERGE_APPEND, build=None, include_members=False):
    """Export an explicit list without reading or changing the registry."""
    function_eas, global_eas, sites, locators, unresolved = _collect(
        function_names, global_names
    )
    return _run_export(path, function_eas, global_eas, unresolved,
                       merge, build, include_members, function_sites=sites,
                       function_locators=locators)


def plan_annotated_export(build=None):
    """Preview the human-curated function/global snapshot without writes."""
    return annotated_export_jobs.plan_annotated_export(build)


def begin_annotated_export(destination_path, expected_selection_digest,
                           build=None):
    """Freeze a reviewed annotated selection into a durable export job."""
    return annotated_export_jobs.begin_annotated_export(
        destination_path, expected_selection_digest, build
    )


def run_annotated_export(job_path, budget_seconds=90):
    """Advance a bounded annotated export job without a per-item caller loop."""
    return annotated_export_jobs.run_annotated_export(job_path, budget_seconds)


def annotated_export_status(job_path):
    """Report durable annotated export progress without exporting an item."""
    return annotated_export_jobs.annotated_export_status(job_path)


def discard_annotated_export(job_path):
    """Discard only private files owned by one annotated export job."""
    return annotated_export_jobs.discard_annotated_export(job_path)


def export_selected(path, declaration_names=(), item_ids=(), build=None):
    """Atomically refresh only explicitly selected items in an existing file."""
    if not isinstance(path, str) or not path:
        return _result(error="path is required", requested=0, refreshed=0)
    if not path.lower().endswith(".cfs"):
        path += ".cfs"
    if not os.path.isfile(path):
        return _result(
            error="selected export requires an existing CFS6 file; run a full "
                  "export first",
            path=path, requested=0, refreshed=0,
        )

    chosen = selection.resolve(
        store.load_all(), declaration_names=declaration_names, item_ids=item_ids,
        patches=store.load_patches(),
    )
    unresolved = chosen["unresolved"]
    requested = chosen["requested"]
    if unresolved:
        return _result(
            error="selected export refused because the selection is not exact",
            unresolved=unresolved, path=path, requested=requested, refreshed=0,
            preserved=0, removed_records=0,
        )
    if not requested:
        return _result(error="no items selected", path=path,
                       requested=0, refreshed=0, preserved=0,
                       removed_records=0)

    sites_by_id = store.load_sites()
    locators_by_id = store.load_locators()
    function_eas, global_eas, sites, locators, resolve_errors = _collect(
        chosen["function_names"], chosen["global_names"],
        sites_by_id=sites_by_id, locators_by_id=locators_by_id,
    )
    if resolve_errors:
        return _result(
            error="selected export refused because an item does not resolve",
            unresolved=resolve_errors, path=path, requested=requested,
            refreshed=0, preserved=0, removed_records=0,
        )

    if build is None:
        build_number, build_source = detect_build()
    else:
        build_number, build_source = int(build), "user"

    _export.clear_caches()
    raw = _export.export_to_path(
        path, get_search_ranges(),
        function_eas=function_eas, global_eas=global_eas,
        declarations=chosen["declarations"],
        patches=chosen["patches"],
        build=(build_number, build_source), merge=_export.MERGE_APPEND,
        function_sites=sites, function_locators=locators,
        require_all=True, validate_output=True,
    )
    missed = list(raw.get("uncovered", ()))
    if raw.get("error") or raw.get("written", 0) != requested or missed:
        return _result(
            error=raw.get("error") or "one or more selected items failed",
            unresolved=missed, path=path, requested=requested, refreshed=0,
            preserved=0, removed_records=0,
            advisory=raw.get("advisory", []),
        )

    stats = raw.get("merge_stats") or {}
    return _result(
        ok=True, path=path, requested=requested, refreshed=raw["written"],
        preserved=stats.get("preserved_records", 0),
        preserved_items=stats.get("preserved_items", 0),
        removed_records=stats.get("removed_records", 0),
        dropped_records=stats.get("dropped_records", 0),
        functions=raw.get("functions", 0), globals=raw.get("globals", 0),
        declarations=raw.get("members", 0), types=raw.get("types", 0),
        patches=raw.get("patches", 0),
        advisory=raw.get("advisory", []), summary=raw.get("summary", ""),
    )
