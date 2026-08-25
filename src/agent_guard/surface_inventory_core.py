"""Where: src/agent_guard/surface_inventory_core.py
What: shared constants and sanitizers for agent surface inventory modules.
Why: keep surface scanners deterministic while splitting scanner-specific logic.
"""

from __future__ import annotations

import fnmatch
import os
import re
import time
from collections.abc import Sequence
from pathlib import Path, PureWindowsPath
from typing import Literal

from .bounded_repo_reader import (
    BoundedRepoContainmentError,
    BoundedRepoFile,
    BoundedRepoFileNotFoundError,
    BoundedRepoLimitError,
    BoundedRepoReadError,
    DistinctInputBudget,
    read_repo_bound_bytes,
)
from .cli_registry import is_agent_guard_cli_command
from .content_guard import CONTENT_TRAVERSAL_TIMEOUT_SECONDS
from .context_guard import (
    MAX_CONTEXT_DISTINCT_INPUT_BYTES,
    MAX_CONTEXT_FILE_BYTES,
    MAX_CONTEXT_SCAN_FILES,
)
from .workflow_guard import MAX_WORKFLOW_POLICY_BYTES, MAX_WORKFLOW_TRAVERSAL


AGENT_SURFACE_SCHEMA_VERSION_V1 = "agent-guard.agent_surface_inventory.v1"
AGENT_SURFACE_SCHEMA_VERSION_V2 = "agent-guard.agent_surface_inventory.v2"
AGENT_SURFACE_SCHEMA_VERSION = AGENT_SURFACE_SCHEMA_VERSION_V1
SurfaceVersion = Literal["v1", "v2"]
ERROR_SURFACE_INVENTORY_INPUT = "surface inventory repository input could not be verified"
ERROR_SURFACE_INVENTORY_LIMIT = "surface inventory exceeds configured limits"
# Match established repository scanner ceilings instead of creating a separate
# policy for inventory: 10,000 selected files, 32,768 traversal units, 1 MiB
# per file, 16 MiB distinct input, and the shared five-second walk deadline.
MAX_SURFACE_INVENTORY_FILES = MAX_CONTEXT_SCAN_FILES
MAX_SURFACE_INVENTORY_TRAVERSAL = MAX_WORKFLOW_TRAVERSAL
MAX_SURFACE_INVENTORY_FILE_BYTES = MAX_CONTEXT_FILE_BYTES
MAX_SURFACE_INVENTORY_POLICY_BYTES = MAX_WORKFLOW_POLICY_BYTES
MAX_SURFACE_INVENTORY_DISTINCT_INPUT_BYTES = MAX_CONTEXT_DISTINCT_INPUT_BYTES
SURFACE_INVENTORY_TRAVERSAL_TIMEOUT_SECONDS = CONTENT_TRAVERSAL_TIMEOUT_SECONDS


class SurfaceInventoryBudget:
    """Share bounded enumeration and descriptor-read work inside one collector."""

    def __init__(
        self,
        *,
        _input_budget: DistinctInputBudget | None = None,
    ) -> None:
        self.deadline = (
            time.monotonic() + SURFACE_INVENTORY_TRAVERSAL_TIMEOUT_SECONDS
        )
        self.traversed = 0
        self.selected: set[str] = set()
        self.input_budget = _input_budget or DistinctInputBudget(
            max_bytes=MAX_SURFACE_INVENTORY_DISTINCT_INPUT_BYTES
        )

    def check_deadline(self) -> None:
        if time.monotonic() >= self.deadline:
            raise ValueError(ERROR_SURFACE_INVENTORY_LIMIT)

    def charge_traversal(self) -> None:
        self.check_deadline()
        self.traversed += 1
        if self.traversed > MAX_SURFACE_INVENTORY_TRAVERSAL:
            raise ValueError(ERROR_SURFACE_INVENTORY_LIMIT)

    def charge_selected(self, path: Path) -> None:
        self.check_deadline()
        identity = os.path.normcase(os.path.normpath(str(path)))
        self.selected.add(identity)
        if len(self.selected) > MAX_SURFACE_INVENTORY_FILES:
            raise ValueError(ERROR_SURFACE_INVENTORY_LIMIT)


def read_surface_file(
    path: Path,
    root: Path,
    *,
    budget: SurfaceInventoryBudget,
    max_bytes: int = MAX_SURFACE_INVENTORY_FILE_BYTES,
) -> BoundedRepoFile:
    """Read one stable regular repository file and charge shared input limits."""

    budget.charge_selected(path)
    try:
        opened = read_repo_bound_bytes(path, root, max_bytes=max_bytes)
    except BoundedRepoLimitError:
        raise ValueError(ERROR_SURFACE_INVENTORY_LIMIT) from None
    except (
        BoundedRepoContainmentError,
        BoundedRepoFileNotFoundError,
        BoundedRepoReadError,
    ):
        raise ValueError(ERROR_SURFACE_INVENTORY_INPUT) from None
    try:
        budget.input_budget.charge(opened)
    except BoundedRepoLimitError:
        raise ValueError(ERROR_SURFACE_INVENTORY_LIMIT) from None
    except BoundedRepoReadError:
        raise ValueError(ERROR_SURFACE_INVENTORY_INPUT) from None
    return opened


def has_glob_magic(part: str) -> bool:
    """Return whether one path component contains stdlib-glob magic."""

    return any(char in part for char in "*?[")


def is_repo_bound_path(path: Path, root: Path) -> bool:
    """Return whether an existing path resolves inside the repository root."""

    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        resolved_path.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def is_in_opaque_directory(
    path: Path,
    *,
    root: Path,
    opaque_directories: Sequence[str],
) -> bool:
    def matches(relative: str) -> bool:
        return any(
            relative == opaque or relative.startswith(f"{opaque.rstrip('/')}/")
            for opaque in opaque_directories
        )

    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = ""
    if relative and matches(relative):
        return True

    try:
        resolved_root = root.resolve(strict=True)
        resolved_relative = path.resolve(strict=True).relative_to(resolved_root).as_posix()
    except (OSError, RuntimeError, ValueError):
        return False
    return matches(resolved_relative)


def repo_bound_glob(
    root: Path,
    pattern: str,
    *,
    opaque_directories: Sequence[str] = (),
    _budget: SurfaceInventoryBudget | None = None,
) -> list[Path]:
    """Enumerate glob matches incrementally inside shared traversal bounds."""

    budget = _budget or SurfaceInventoryBudget()
    pattern_path = Path(pattern)
    if pattern_path.is_absolute() or ".." in pattern_path.parts:
        raise ValueError(ERROR_SURFACE_INVENTORY_INPUT)

    candidates = [root]
    for part in pattern_path.parts:
        if part == "**":
            raise ValueError(ERROR_SURFACE_INVENTORY_LIMIT)
        next_candidates: list[Path] = []
        for parent in candidates:
            budget.check_deadline()
            if is_in_opaque_directory(
                parent,
                root=root,
                opaque_directories=opaque_directories,
            ) or not is_repo_bound_path(parent, root):
                continue
            if not has_glob_magic(part):
                candidate = parent / part
                if not is_in_opaque_directory(
                    candidate,
                    root=root,
                    opaque_directories=opaque_directories,
                ) and is_repo_bound_path(candidate, root):
                    next_candidates.append(candidate)
                continue

            try:
                with os.scandir(parent) as entries:
                    for entry in entries:
                        budget.charge_traversal()
                        name = entry.name
                        candidate_name = name.casefold() if os.name == "nt" else name
                        match_pattern = part.casefold() if os.name == "nt" else part
                        if not fnmatch.fnmatchcase(candidate_name, match_pattern):
                            continue
                        candidate = parent / name
                        if is_in_opaque_directory(
                            candidate,
                            root=root,
                            opaque_directories=opaque_directories,
                        ) or not is_repo_bound_path(candidate, root):
                            continue
                        next_candidates.append(candidate)
            except OSError:
                raise ValueError(ERROR_SURFACE_INVENTORY_INPUT) from None
        candidates = next_candidates

    for candidate in candidates:
        budget.charge_selected(candidate)
    return candidates


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
