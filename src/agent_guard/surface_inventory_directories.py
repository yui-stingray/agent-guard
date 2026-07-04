"""Where: src/agent_guard/surface_inventory_directories.py
What: agent skill, profile, command, and hook surface collection.
Why: separate filesystem surface discovery from context, workflow, and MCP parsing.
"""

from __future__ import annotations

from pathlib import Path

from .surface_inventory_core import rel_path


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


def count_tree_files(base: Path, *, cap: int = MAX_SURFACE_TREE_FILES) -> tuple[int, bool]:
    if base.is_file():
        return 1, False
    count = 0
    for item in base.rglob("*"):
        if not item.is_file():
            continue
        count += 1
        if count >= cap:
            return count, True
    return count, False


def collect_directory_surfaces(
    root: Path,
    entries: tuple[tuple[str, str], ...],
    *,
    surface: str,
) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    for rel_base, kind in entries:
        base = root / rel_base
        if not base.is_dir():
            continue
        children = sorted(item for item in base.iterdir() if item.is_dir() or item.is_file())
        if not children:
            file_count, truncated = count_tree_files(base)
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
            file_count, truncated = count_tree_files(child)
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


def collect_hook_surfaces(root: Path) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    for pattern, kind in AGENT_HOOK_FILES:
        for path in sorted(root.glob(pattern)):
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
