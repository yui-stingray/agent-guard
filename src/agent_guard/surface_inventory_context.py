"""Where: src/agent_guard/surface_inventory_context.py
What: context-file surface projection and complete inventory assembly.
Why: keep the public inventory builder separate from scanner-specific collectors.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from .bounded_repo_reader import DistinctInputBudget
from .context_guard import (
    ERROR_CONTEXT_SCAN_LIMIT,
    ContextInventory,
    collect_context_inventory,
)
from .surface_inventory_core import (
    ERROR_SURFACE_INVENTORY_LIMIT,
    SurfaceInventoryBudget,
    normalize_surface_version,
    schema_for_surface_version,
)
from .surface_inventory_directories import (
    AGENT_COMMAND_DIRS,
    AGENT_PROFILE_DIRS,
    AGENT_SKILL_DIRS,
    collect_directory_surfaces,
    collect_hook_surfaces,
)
from .surface_inventory_mcp import (
    ERROR_MCP_CONFIG_LIMIT,
    collect_mcp_config_surfaces,
)
from .surface_inventory_metadata import (
    collect_committed_evidence_surfaces,
    collect_documented_guard_surfaces,
    collect_policy_surfaces,
)
from .surface_inventory_workflow import collect_workflow_surfaces


def summarize_surfaces(surfaces: list[dict[str, object]]) -> dict[str, object]:
    by_surface: dict[str, int] = {}
    for item in surfaces:
        surface = str(item.get("surface", "unknown"))
        by_surface[surface] = by_surface.get(surface, 0) + 1
    return {
        "surface_count": len(surfaces),
        "by_surface": dict(sorted(by_surface.items())),
    }


def collect_agent_surface_inventory(
    *,
    root: Path,
    context_policy: dict[str, object],
    schema_version: str = "v1",
    opaque_directories: Sequence[str] = (),
    include_empty_directory_surfaces: bool = True,
    _context_input_budget: DistinctInputBudget | None = None,
    _mcp_input_budget: DistinctInputBudget | None = None,
    _context_inventory: ContextInventory | None = None,
    _mcp_surfaces: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    root = root.resolve()
    version = normalize_surface_version(schema_version)
    # Preserve a caller's prior context-policy charge while using one budget for
    # every collector invoked by this inventory assembly.
    budget = SurfaceInventoryBudget(
        _input_budget=_context_input_budget or _mcp_input_budget
    )
    if _context_inventory is None:
        try:
            context_inventory = collect_context_inventory(
                root=root,
                policy=context_policy,
                opaque_directories=opaque_directories,
                _input_budget=budget.input_budget,
            )
        except ValueError as exc:
            if str(exc) == ERROR_CONTEXT_SCAN_LIMIT:
                raise ValueError(ERROR_SURFACE_INVENTORY_LIMIT) from None
            raise
    else:
        context_inventory = _context_inventory
    surfaces: list[dict[str, object]] = []

    def append_surface(item: dict[str, object]) -> None:
        budget.add_result(item)
        surfaces.append(item)

    for item in context_inventory.context_files:
        budget.charge_selected(root / item.path)
        append_surface(
            {
                "surface": "agent_context",
                "path": item.path,
                "kind": item.kind,
                "status": item.read_status,
                "size_bytes": item.size_bytes,
                **({"line_count": item.line_count} if item.line_count is not None else {}),
            }
        )
    surfaces.extend(
        collect_policy_surfaces(
            root,
            opaque_directories=opaque_directories,
            _budget=budget,
        )
    )
    budget.check_deadline()
    surfaces.extend(
        collect_workflow_surfaces(
            root,
            include_artifacts=version == "v2",
            opaque_directories=opaque_directories,
            _budget=budget,
        )
    )
    budget.check_deadline()
    if version == "v2":
        surfaces.extend(
            collect_documented_guard_surfaces(
                root,
                opaque_directories=opaque_directories,
                _budget=budget,
            )
        )
        budget.check_deadline()
        surfaces.extend(
            collect_committed_evidence_surfaces(
                root,
                opaque_directories=opaque_directories,
                _budget=budget,
            )
        )
        budget.check_deadline()
        surfaces.extend(
            collect_directory_surfaces(
                root,
                AGENT_SKILL_DIRS,
                surface="agent_skill",
                opaque_directories=opaque_directories,
                include_empty_containers=include_empty_directory_surfaces,
                _budget=budget,
            )
        )
        budget.check_deadline()
        surfaces.extend(
            collect_directory_surfaces(
                root,
                AGENT_PROFILE_DIRS,
                surface="agent_profile",
                opaque_directories=opaque_directories,
                include_empty_containers=include_empty_directory_surfaces,
                _budget=budget,
            )
        )
        budget.check_deadline()
        surfaces.extend(
            collect_directory_surfaces(
                root,
                AGENT_COMMAND_DIRS,
                surface="agent_command",
                opaque_directories=opaque_directories,
                include_empty_containers=include_empty_directory_surfaces,
                _budget=budget,
            )
        )
        budget.check_deadline()
        surfaces.extend(
            collect_hook_surfaces(
                root,
                opaque_directories=opaque_directories,
                _budget=budget,
            )
        )
        budget.check_deadline()
        if _mcp_surfaces is None:
            try:
                mcp_surfaces = collect_mcp_config_surfaces(
                    root,
                    opaque_directories=opaque_directories,
                    _budget=budget,
                )
            except ValueError as exc:
                if str(exc) == ERROR_MCP_CONFIG_LIMIT:
                    raise ValueError(ERROR_SURFACE_INVENTORY_LIMIT) from None
                raise
        else:
            mcp_surfaces = _mcp_surfaces
        if _mcp_surfaces is None:
            # The MCP collector already charged the shared budget while it
            # enumerated and projected these entries.
            surfaces.extend(mcp_surfaces)
        else:
            for item in mcp_surfaces:
                path = item.get("path")
                if isinstance(path, str) and path:
                    budget.charge_selected(root / path)
                append_surface(item)
    directory_surfaces = {"agent_skill", "agent_profile", "agent_command"}
    filtered_surfaces = []
    for item in surfaces:
        path = str(item.get("path", ""))
        containing_opaque = next(
            (
                opaque
                for opaque in opaque_directories
                if path == opaque or path.startswith(f"{opaque.rstrip('/')}/")
            ),
            None,
        )
        if containing_opaque is None or (
            path == containing_opaque and item.get("surface") in directory_surfaces
        ):
            filtered_surfaces.append(item)
    budget.check_deadline()
    surfaces = sorted(
        filtered_surfaces,
        key=lambda item: (str(item.get("path", "")), str(item.get("surface", ""))),
    )
    return {
        "schema_version": schema_for_surface_version(version),
        "summary": summarize_surfaces(surfaces),
        "surfaces": surfaces,
    }


def public_safe_surface_text(payload: dict[str, object]) -> str:
    """Return serialized inventory text for tests and downstream safety checks."""

    import json

    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
    )
