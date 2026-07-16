"""Where: src/agent_guard/surface_inventory_core.py
What: shared constants and sanitizers for agent surface inventory modules.
Why: keep surface scanners deterministic while splitting scanner-specific logic.
"""

from __future__ import annotations

import re
from glob import has_magic
from pathlib import Path, PureWindowsPath
from typing import Literal

from .cli_registry import is_agent_guard_cli_command


AGENT_SURFACE_SCHEMA_VERSION_V1 = "agent-guard.agent_surface_inventory.v1"
AGENT_SURFACE_SCHEMA_VERSION_V2 = "agent-guard.agent_surface_inventory.v2"
AGENT_SURFACE_SCHEMA_VERSION = AGENT_SURFACE_SCHEMA_VERSION_V1
SurfaceVersion = Literal["v1", "v2"]


def is_repo_bound_path(path: Path, root: Path) -> bool:
    """Return whether an existing path resolves inside the repository root."""

    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        resolved_path.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def repo_bound_glob(root: Path, pattern: str) -> list[Path]:
    """Glob only when the fixed parent and each result remain repo-bound."""

    fixed_parts: list[str] = []
    for part in Path(pattern).parts:
        if has_magic(part):
            break
        fixed_parts.append(part)
    base = root.joinpath(*fixed_parts) if fixed_parts else root
    if not is_repo_bound_path(base, root):
        return []
    return [path for path in root.glob(pattern) if is_repo_bound_path(path, root)]


def rel_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def parse_agent_guard_command(command: str) -> dict[str, object] | None:
    match = re.search(
        r"(?:^|\s)(?:python(?:3(?:\.\d+)?)?\s+-m\s+agent_guard\.cli|agent-guard)\s+([a-z][a-z-]*)(?:\s+([a-z][a-z-]*))?",
        command,
    )
    if not match:
        return None
    scanner = match.group(1)
    command = match.group(2) or ""
    if not is_agent_guard_cli_command(scanner, command):
        return None
    return {
        "scanner": scanner,
        "command": command,
    }


def normalize_surface_version(version: str) -> SurfaceVersion:
    if version in {"v1", AGENT_SURFACE_SCHEMA_VERSION_V1}:
        return "v1"
    if version in {"v2", AGENT_SURFACE_SCHEMA_VERSION_V2}:
        return "v2"
    raise ValueError("surface inventory schema version must be v1 or v2")


def schema_for_surface_version(version: SurfaceVersion) -> str:
    return AGENT_SURFACE_SCHEMA_VERSION_V1 if version == "v1" else AGENT_SURFACE_SCHEMA_VERSION_V2


def safe_metadata_path(raw_path: str) -> str:
    text = str(raw_path).strip().strip("'\"")
    if not text:
        return ""
    windows_path = PureWindowsPath(text)
    if windows_path.is_absolute() or windows_path.drive or text.startswith("\\\\"):
        return windows_path.name or "<external-path>"
    path = Path(text)
    if path.is_absolute() or ".." in path.parts:
        return path.name or "<external-path>"
    return path.as_posix()
