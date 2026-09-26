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
from .api_export import export, export_list, export_selected
from .api_import import (
    import_and_migrate, import_catalogue, migrate_state, promote_catalogue,
    refresh_catalogue, begin_refresh, refresh_step, refresh_run, refresh_status, finalize_refresh,
    discard_refresh,
)
from .api_materialize import apply_type_materialization, plan_type_materialization
from .api_registry import clear, register, registered, unregister


__all__ = (
    "clear", "declare_constants", "declare_extents", "declare_members",
    "declare_patches", "declare_strides", "declarations", "export",
    "export_list", "export_selected", "import_and_migrate",
    "import_catalogue", "migrate_state", "promote_catalogue", "refresh_catalogue",
    "begin_refresh", "refresh_step", "refresh_run", "refresh_status", "finalize_refresh", "discard_refresh",
    "apply_type_materialization", "plan_type_materialization",
    "register", "registered",
    "undeclare", "unregister",
)
