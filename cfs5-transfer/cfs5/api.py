"""Stable, non-interactive CFS API facade.

Implementation is split by responsibility so callers keep one import while
maintainers and agents can inspect only the branch they are changing.
"""

from .api_declarations import (
    declare_constants,
    declare_extents,
    declare_members,
    declare_patches,
    declare_strides,
    declarations,
    undeclare,
)
from .api_export import (
    annotated_export_status, begin_annotated_export, discard_annotated_export,
    export, export_list, export_selected, plan_annotated_export,
    run_annotated_export,
)
from .api_import import (
    import_and_migrate, import_catalogue, migrate_state, promote_catalogue,
    refresh_catalogue, begin_refresh, refresh_step, refresh_run, refresh_status, finalize_refresh,
    discard_refresh,
    begin_import_job, run_import_job, import_job_status, import_job_outcomes,
    discard_import_job,
)
from .api_materialize import apply_type_materialization, plan_type_materialization
from .api_registry import clear, register, registered, unregister


__all__ = (
    "clear", "declare_constants", "declare_extents", "declare_members",
    "declare_patches", "declare_strides", "declarations", "export",
    "export_list", "export_selected", "plan_annotated_export",
    "begin_annotated_export", "run_annotated_export", "annotated_export_status",
    "discard_annotated_export", "import_and_migrate",
    "begin_import_job", "run_import_job", "import_job_status",
    "import_job_outcomes", "discard_import_job",
    "import_catalogue", "migrate_state", "promote_catalogue", "refresh_catalogue",
    "begin_refresh", "refresh_step", "refresh_run", "refresh_status", "finalize_refresh", "discard_refresh",
    "apply_type_materialization", "plan_type_materialization",
    "register", "registered",
    "undeclare", "unregister",
)
