"""Where: src/agent_guard/surface_inventory_directories.py
What: agent skill, profile, command, and hook surface collection.
Why: separate filesystem surface discovery from context, workflow, and MCP parsing.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from .surface_inventory_core import (
    is_in_opaque_directory,
    is_repo_bound_path,
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
) -> tuple[int, bool]:
    """Count repo-bound files without repeatedly traversing symlink cycles."""

    root = base if root is None else root
    if is_in_opaque_directory(
        base,
        root=root,
        opaque_directories=opaque_directories,
    ):
        return 0, False
    if not is_repo_bound_path(base, root):
        return 0, False
    if base.is_file():
        return 1, False
    count = 0
    pending = [base]
    visited: set[Path] = set()
    while pending:
        current = pending.pop()
        try:
            resolved_current = current.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved_current in visited:
            continue
        visited.add(resolved_current)
        try:
            children = sorted(current.iterdir())
        except OSError:
            continue
        for item in children:
            if is_in_opaque_directory(
                item,
                root=root,
                opaque_directories=opaque_directories,
            ):
                continue
            if not is_repo_bound_path(item, root):
                continue
            if item.is_file():
                count += 1
                if count >= cap:
                    return count, True
            elif item.is_dir():
                pending.append(item)
    return count, False


def collect_directory_surfaces(
    root: Path,
    entries: tuple[tuple[str, str], ...],
    *,
    surface: str,
    opaque_directories: Sequence[str] = (),
    include_empty_containers: bool = True,
) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
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
        raw_children = [] if base_is_opaque else list(base.iterdir())
        children = sorted(
            item
            for item in raw_children
            if is_repo_bound_path(item, root) and (item.is_dir() or item.is_file())
        )
        if not children:
            if raw_children:
                continue
            if not base_is_opaque and not include_empty_containers:
                continue
            file_count, truncated = count_tree_files(
                base,
                root=root,
                opaque_directories=opaque_directories,
            )
            surfaces.append(
                {
                    "surface": surface,
                    "path": rel_path(base, root),
                    "kind": kind,
                    "status": "present",
                    "file_count": file_count,
                    **({"truncated": True} if truncated else {}),
                }
            )
            continue
        for child in children:
            file_count, truncated = count_tree_files(
                child,
                root=root,
                opaque_directories=opaque_directories,
            )
            surfaces.append(
                {
                    "surface": surface,
                    "path": rel_path(child, root),
                    "kind": kind,
                    "status": "present",
                    "file_count": file_count,
                    **({"truncated": True} if truncated else {}),
                }
            )
    return surfaces


def collect_hook_surfaces(
    root: Path,
    *,
    opaque_directories: Sequence[str] = (),
) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    for pattern, kind in AGENT_HOOK_FILES:
        for path in sorted(
            repo_bound_glob(
                root,
                pattern,
                opaque_directories=opaque_directories,
            )
        ):
            if not path.is_file():
                continue
            surfaces.append(
                {
                    "surface": "agent_hook_config",
                    "path": rel_path(path, root),
                    "kind": kind,
                    "status": "present",
                    "size_bytes": path.stat().st_size,
                }
            )
    return surfaces
