"""Where: src/agent_guard/surface_inventory_directories.py
What: agent skill, profile, command, and hook surface collection.
Why: separate filesystem surface discovery from context, workflow, and MCP parsing.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from .surface_inventory_core import (
    ERROR_SURFACE_INVENTORY_INPUT,
    SurfaceInventoryBudget,
    is_in_opaque_directory,
    is_repo_bound_path,
    read_surface_file,
    rel_path,
    repo_bound_glob,
)


AGENT_SKILL_DIRS = (
    (".github/skills", "github_copilot_skill"),
    (".agents/skills", "github_copilot_skill"),
    (".claude/skills", "claude_skill"),
    (".codex/skills", "codex_skill"),
    (".cursor/skills", "cursor_skill"),
    (".gemini/skills", "gemini_skill"),
)
AGENT_PROFILE_DIRS = (
    (".github/agents", "github_copilot_agent"),
    (".claude/agents", "claude_agent"),
    (".codex/agents", "codex_agent"),
    (".cursor/agents", "cursor_agent"),
)
AGENT_COMMAND_DIRS = (
    (".claude/commands", "claude_command"),
    (".cursor/commands", "cursor_command"),
    (".gemini/commands", "gemini_command"),
)
AGENT_HOOK_FILES = (
    (".github/hooks/*.json", "github_hook_config"),
    (".cursor/hooks.json", "cursor_hook_config"),
)
MAX_SURFACE_TREE_FILES = 1000


def count_tree_files(
    base: Path,
    *,
    root: Path | None = None,
    cap: int = MAX_SURFACE_TREE_FILES,
    opaque_directories: Sequence[str] = (),
    _budget: SurfaceInventoryBudget | None = None,
) -> tuple[int, bool]:
    """Count repo-bound files without repeatedly traversing symlink cycles."""

    root = base if root is None else root
    budget = _budget or SurfaceInventoryBudget()
    if is_in_opaque_directory(
        base,
        root=root,
        opaque_directories=opaque_directories,
    ):
        return 0, False
    if not is_repo_bound_path(base, root):
        return 0, False
    if base.is_file():
        budget.charge_selected(base)
        return 1, False
    count = 0
    pending = [base]
    visited: set[Path] = set()
    while pending:
        budget.check_deadline()
        current = pending.pop()
        try:
            resolved_current = current.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved_current in visited:
            continue
        visited.add(resolved_current)
        try:
            children = os.scandir(current)
        except OSError:
            raise ValueError(ERROR_SURFACE_INVENTORY_INPUT) from None
        try:
            with children as entries:
                for entry in entries:
                    budget.charge_traversal()
                    item = current / entry.name
                    if is_in_opaque_directory(
                        item,
                        root=root,
                        opaque_directories=opaque_directories,
                    ):
                        continue
                    if not is_repo_bound_path(item, root):
                        continue
                    if item.is_file():
                        budget.charge_selected(item)
                        count += 1
                        if count >= cap:
                            return count, True
                    elif item.is_dir():
                        pending.append(item)
        except OSError:
            raise ValueError(ERROR_SURFACE_INVENTORY_INPUT) from None
    return count, False


def collect_directory_surfaces(
    root: Path,
    entries: tuple[tuple[str, str], ...],
    *,
    surface: str,
    opaque_directories: Sequence[str] = (),
    include_empty_containers: bool = True,
    _budget: SurfaceInventoryBudget | None = None,
) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    budget = _budget or SurfaceInventoryBudget()
    for rel_base, kind in entries:
        base = root / rel_base
        if not is_repo_bound_path(base, root):
            continue
        if not base.is_dir():
            continue
        base_is_opaque = is_in_opaque_directory(
            base,
            root=root,
            opaque_directories=opaque_directories,
        )
        children: list[Path] = []
        had_raw_children = False
        if not base_is_opaque:
            try:
                raw_children = os.scandir(base)
            except OSError:
                raise ValueError(ERROR_SURFACE_INVENTORY_INPUT) from None
            try:
                with raw_children as discovered:
                    for entry in discovered:
                        budget.charge_traversal()
                        had_raw_children = True
                        item = base / entry.name
                        if not is_repo_bound_path(item, root) or not (
                            item.is_dir() or item.is_file()
                        ):
                            continue
                        budget.charge_selected(item)
                        children.append(item)
            except OSError:
                raise ValueError(ERROR_SURFACE_INVENTORY_INPUT) from None
        children.sort()
        if not children:
            if had_raw_children:
                continue
            if not base_is_opaque and not include_empty_containers:
                continue
            file_count, truncated = count_tree_files(
                base,
                root=root,
                opaque_directories=opaque_directories,
                _budget=budget,
            )
            item = {
                "surface": surface,
                "path": rel_path(base, root),
                "kind": kind,
                "status": "present",
                "file_count": file_count,
                **({"truncated": True} if truncated else {}),
            }
            budget.add_result(item)
            surfaces.append(item)
            continue
        for child in children:
            file_count, truncated = count_tree_files(
                child,
                root=root,
                opaque_directories=opaque_directories,
                _budget=budget,
            )
            item = {
                "surface": surface,
                "path": rel_path(child, root),
                "kind": kind,
                "status": "present",
                "file_count": file_count,
                **({"truncated": True} if truncated else {}),
            }
            budget.add_result(item)
            surfaces.append(item)
    return surfaces


def collect_hook_surfaces(
    root: Path,
    *,
    opaque_directories: Sequence[str] = (),
    _budget: SurfaceInventoryBudget | None = None,
) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    budget = _budget or SurfaceInventoryBudget()
    for pattern, kind in AGENT_HOOK_FILES:
        for path in sorted(
            repo_bound_glob(
                root,
                pattern,
                opaque_directories=opaque_directories,
                _budget=budget,
            )
        ):
            if not path.is_file():
                continue
            opened = read_surface_file(path, root, budget=budget)
            item = {
                "surface": "agent_hook_config",
                "path": opened.relative_path,
                "kind": kind,
                "status": "present",
                "size_bytes": len(opened.data),
            }
            budget.add_result(item)
            surfaces.append(item)
    return surfaces
