"""Where: src/agent_guard/surface_inventory_context.py
What: context-file surface projection and complete inventory assembly.
Why: keep the public inventory builder separate from scanner-specific collectors.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from .context_guard import collect_context_inventory
from .surface_inventory_core import normalize_surface_version, schema_for_surface_version
from .surface_inventory_directories import (
    AGENT_COMMAND_DIRS,
    AGENT_PROFILE_DIRS,
    AGENT_SKILL_DIRS,
    collect_directory_surfaces,
    collect_hook_surfaces,
)
from .surface_inventory_mcp import collect_mcp_config_surfaces
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
) -> dict[str, object]:
    root = root.resolve()
    version = normalize_surface_version(schema_version)
    context_inventory = collect_context_inventory(
        root=root,
        policy=context_policy,
        opaque_directories=opaque_directories,
    )
    surfaces: list[dict[str, object]] = []
    for item in context_inventory.context_files:
        surfaces.append(
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
        )
    )
    surfaces.extend(
        collect_workflow_surfaces(
            root,
            include_artifacts=version == "v2",
            opaque_directories=opaque_directories,
        )
    )
    if version == "v2":
        surfaces.extend(
            collect_documented_guard_surfaces(
                root,
                opaque_directories=opaque_directories,
            )
        )
        surfaces.extend(
            collect_committed_evidence_surfaces(
                root,
                opaque_directories=opaque_directories,
            )
        )
        surfaces.extend(
            collect_directory_surfaces(
                root,
                AGENT_SKILL_DIRS,
                surface="agent_skill",
                opaque_directories=opaque_directories,
                include_empty_containers=include_empty_directory_surfaces,
            )
        )
        surfaces.extend(
            collect_directory_surfaces(
                root,
                AGENT_PROFILE_DIRS,
                surface="agent_profile",
                opaque_directories=opaque_directories,
                include_empty_containers=include_empty_directory_surfaces,
            )
        )
        surfaces.extend(
            collect_directory_surfaces(
                root,
                AGENT_COMMAND_DIRS,
                surface="agent_command",
                opaque_directories=opaque_directories,
                include_empty_containers=include_empty_directory_surfaces,
            )
        )
        surfaces.extend(
            collect_hook_surfaces(
                root,
                opaque_directories=opaque_directories,
            )
        )
        surfaces.extend(
            collect_mcp_config_surfaces(
                root,
                opaque_directories=opaque_directories,
            )
        )
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

    return json.dumps(payload, ensure_ascii=False, sort_keys=True)
