"""Public non-interactive facade for safe portable member materialization."""

from . import materialize


def plan_type_materialization(catalogue_path, item_ids=(), mode="missing_only"):
    """Return target-side member actions without changing the active IDB."""
    return materialize.plan_type_materialization(catalogue_path, item_ids, mode)


def apply_type_materialization(catalogue_path, item_ids, expected_plan_digest,
                               mode="missing_only"):
    """Apply explicitly selected safe creates bound to a reviewed plan digest."""
    return materialize.apply_type_materialization(
        catalogue_path, item_ids, expected_plan_digest, mode
    )
