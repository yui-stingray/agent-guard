"""Where: src/agent_guard/surface_inventory_metadata.py
What: documented command, committed evidence, and policy file surfaces.
Why: keep repository metadata discovery separate from workflow and MCP scanners.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from pathlib import Path

from .bounded_git import (
    UNTRUSTED_GIT_ENVIRONMENT_VARIABLES,
    BoundedGitOutputLimitError,
    BoundedGitProcessError,
    run_bounded_git,
    sanitized_git_environment,
)
from .surface_inventory_core import (
    MAX_SURFACE_INVENTORY_POLICY_BYTES,
    SurfaceInventoryBudget,
    is_in_opaque_directory,
    is_repo_bound_path,
    parse_agent_guard_command,
    read_surface_file,
    rel_path,
    repo_bound_glob,
)


DOC_GLOBS = ("README.md", "docs/*.md")
EVIDENCE_INDEX_PATHS = (".agent-guard/evidence", "docs/evidence-samples")
ERROR_EVIDENCE_INDEX = "committed evidence metadata could not be verified"
GIT_METADATA_TIMEOUT_SECONDS = 5.0
MAX_EVIDENCE_INDEX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_ARTIFACT_FILES = 10_000
MAX_EVIDENCE_INDEX_ENTRIES = MAX_EVIDENCE_ARTIFACT_FILES
_REGULAR_FILE_MODES = frozenset({"100644", "100755"})
_GIT_METADATA_ROUTING_ENVIRONMENT_VARIABLES = (
    UNTRUSTED_GIT_ENVIRONMENT_VARIABLES
)
_GENERATED_EVIDENCE_NAMES = frozenset(
    {
        "agent-guard-report.json",
        "agent-guard-report.md",
        "agent-guard-results.sarif",
        "agent-guard-annotations.txt",
        "agent-guard-conformance.json",
        "agent-guard-evidence-pack.json",
        "agent-surface-inventory.json",
    }
)


def _git_metadata_environment() -> dict[str, str]:
    """Return the shared configuration-isolated Git environment."""

    return sanitized_git_environment()


def _run_git_metadata(
    root: Path,
    args: list[str],
    *,
    input_data: bytes | None = None,
    _budget: SurfaceInventoryBudget | None = None,
) -> subprocess.CompletedProcess[bytes]:
    timeout_seconds = GIT_METADATA_TIMEOUT_SECONDS
    if _budget is not None:
        timeout_seconds = min(timeout_seconds, _budget.remaining_timeout())
    try:
        return run_bounded_git(
            root,
            args,
            timeout_seconds=timeout_seconds,
            max_output_bytes=MAX_EVIDENCE_INDEX_OUTPUT_BYTES,
            input_data=input_data,
        )
    except (BoundedGitOutputLimitError, BoundedGitProcessError):
        raise ValueError(ERROR_EVIDENCE_INDEX) from None


def _has_valid_git_marker(
    root: Path,
    *,
    _budget: SurfaceInventoryBudget | None = None,
) -> bool:
    for candidate in (root, *root.parents):
        marker = candidate / ".git"
        if not marker.exists():
            continue
        try:
            resolved = _run_git_metadata(
                root,
                ["rev-parse", "--resolve-git-dir", str(marker)],
                _budget=_budget,
            )
        except ValueError:
            if candidate == root or _looks_like_git_marker(marker):
                return True
            continue
        if resolved.returncode == 0:
            return True
        if candidate == root or _looks_like_git_marker(marker):
            return True
    return False


def _looks_like_git_marker(marker: Path) -> bool:
    if marker.is_dir():
        return (marker / "HEAD").is_file()
    if not marker.is_file():
        return False
    try:
        with marker.open("rb") as handle:
            prefix = handle.read(4_097)
    except OSError:
        return False
    return len(prefix) <= 4_096 and prefix.lstrip().startswith(b"gitdir:")


def _is_git_worktree(
    root: Path,
    *,
    _budget: SurfaceInventoryBudget | None = None,
) -> bool:
    try:
        probe = _run_git_metadata(
            root,
            ["rev-parse", "--is-inside-work-tree"],
            _budget=_budget,
        )
    except ValueError:
        if _has_valid_git_marker(root, _budget=_budget):
            raise
        return False
    if probe.returncode == 0 and probe.stdout.strip() == b"true":
        return True
    if _has_valid_git_marker(root, _budget=_budget):
        raise ValueError(ERROR_EVIDENCE_INDEX)
    return False


def policy_kind(path: str) -> str:
    name = Path(path).name
    if name == "context-policy.yaml":
        return "context_policy"
    if name == "path-policy.yaml":
        return "path_policy"
    if name == "content-policy.yaml":
        return "content_policy"
    if name == "workflow-policy.yaml":
        return "workflow_policy"
    if "digest" in name:
        return "digest_policy"
    return "agent_guard_policy"


def collect_documented_guard_surfaces(
    root: Path,
    *,
    opaque_directories: Sequence[str] = (),
    _budget: SurfaceInventoryBudget | None = None,
) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    budget = _budget or SurfaceInventoryBudget()
    doc_files: list[Path] = []
    for pattern in DOC_GLOBS:
        doc_files.extend(
            repo_bound_glob(
                root,
                pattern,
                opaque_directories=opaque_directories,
                _budget=budget,
            )
        )
    for doc_file in sorted(
        path for path in doc_files if is_repo_bound_path(path, root) and path.is_file()
    ):
        try:
            opened = read_surface_file(doc_file, root, budget=budget)
            lines = opened.data.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        doc_path = opened.relative_path
        for lineno, line in enumerate(lines, start=1):
            command = parse_agent_guard_command(line)
            if command is None:
                continue
            item = {
                "surface": "documented_guard_command",
                "path": doc_path,
                "kind": "documentation_recipe",
                "status": "documented",
                "line": lineno,
                "command": command,
            }
            budget.add_result(item)
            surfaces.append(item)
    return surfaces


def collect_committed_evidence_surfaces(
    root: Path,
    *,
    opaque_directories: Sequence[str] = (),
    _budget: SurfaceInventoryBudget | None = None,
) -> list[dict[str, object]]:
    """Return regular evidence files proven by the repository's Git index.

    Reading paths and blob sizes from the index keeps generated Action outputs
    and modified working-tree copies from feeding back into their own report.
    A non-Git materialization cannot prove index membership, so the fallback
    keeps review samples and nonstandard evidence files while excluding every
    official generated output name.
    """

    budget = _budget or SurfaceInventoryBudget()
    budget.check_deadline()
    if not _is_git_worktree(root, _budget=budget):
        return _collect_materialized_evidence_surfaces(
            root,
            opaque_directories=opaque_directories,
            _budget=budget,
        )
    budget.check_deadline()
    indexed = _run_git_metadata(
        root,
        [
            "ls-files",
            "--cached",
            "--stage",
            "-z",
            "--",
            *EVIDENCE_INDEX_PATHS,
        ],
        _budget=budget,
    )
    budget.check_deadline()
    if indexed.returncode != 0:
        raise ValueError(ERROR_EVIDENCE_INDEX)

    entries: list[tuple[str, str]] = []
    for raw_entry in indexed.stdout.split(b"\0"):
        budget.check_deadline()
        if not raw_entry:
            continue
        metadata, separator, raw_path = raw_entry.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise ValueError(ERROR_EVIDENCE_INDEX)
        try:
            mode = fields[0].decode("ascii")
            object_id = fields[1].decode("ascii")
            stage = fields[2].decode("ascii")
            display = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(ERROR_EVIDENCE_INDEX) from None
        path = Path(display)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(ERROR_EVIDENCE_INDEX)
        if not any(
            display.startswith(f"{base}/")
            for base in EVIDENCE_INDEX_PATHS
        ):
            raise ValueError(ERROR_EVIDENCE_INDEX)
        if stage != "0":
            raise ValueError(ERROR_EVIDENCE_INDEX)
        if mode not in _REGULAR_FILE_MODES:
            continue
        if is_in_opaque_directory(
            root / path,
            root=root,
            opaque_directories=opaque_directories,
        ):
            continue
        entries.append((display, object_id))
        if len(entries) > MAX_EVIDENCE_INDEX_ENTRIES:
            raise ValueError(ERROR_EVIDENCE_INDEX)

    if not entries:
        return []

    budget.check_deadline()
    object_ids = sorted({object_id for _display, object_id in entries})
    object_metadata = _run_git_metadata(
        root,
        ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        input_data="".join(f"{object_id}\n" for object_id in object_ids).encode("ascii"),
        _budget=budget,
    )
    budget.check_deadline()
    if object_metadata.returncode != 0:
        raise ValueError(ERROR_EVIDENCE_INDEX)

    blob_sizes: dict[str, int] = {}
    for raw_line in object_metadata.stdout.splitlines():
        budget.check_deadline()
        try:
            line = raw_line.decode("ascii")
        except UnicodeDecodeError:
            raise ValueError(ERROR_EVIDENCE_INDEX) from None
        fields = line.split()
        if len(fields) != 3 or fields[1] != "blob":
            raise ValueError(ERROR_EVIDENCE_INDEX)
        try:
            blob_sizes[fields[0]] = int(fields[2])
        except ValueError:
            raise ValueError(ERROR_EVIDENCE_INDEX) from None

    surfaces: list[dict[str, object]] = []
    for display, object_id in sorted(entries):
        budget.check_deadline()
        size_bytes = blob_sizes.get(object_id)
        if size_bytes is None:
            raise ValueError(ERROR_EVIDENCE_INDEX)
        budget.charge_selected(root / display)
        item = {
            "surface": "evidence_artifact",
            "path": display,
            "kind": (
                "committed_evidence_sample"
                if display.startswith("docs/evidence-samples/")
                else "repo_evidence_file"
            ),
            "status": "present",
            "size_bytes": size_bytes,
        }
        budget.add_result(item)
        surfaces.append(item)
    return surfaces


def _collect_materialized_evidence_surfaces(
    root: Path,
    *,
    opaque_directories: Sequence[str] = (),
    _budget: SurfaceInventoryBudget | None = None,
) -> list[dict[str, object]]:
    """Collect bounded non-Git evidence without admitting official outputs.

    Candidate enumeration is capped before validation and sorting so a hostile
    directory cannot force an unbounded intermediate collection.
    """

    budget = _budget or SurfaceInventoryBudget()
    candidates: list[tuple[str, Path]] = []
    for rel_base in EVIDENCE_INDEX_PATHS:
        budget.check_deadline()
        base = root / rel_base
        if is_in_opaque_directory(
            base,
            root=root,
            opaque_directories=opaque_directories,
        ) or not is_repo_bound_path(base, root):
            continue
        if not base.is_dir():
            continue
        try:
            with os.scandir(base) as entries:
                for entry in entries:
                    budget.charge_traversal()
                    if len(candidates) >= MAX_EVIDENCE_ARTIFACT_FILES:
                        raise ValueError(ERROR_EVIDENCE_INDEX)
                    candidates.append((rel_base, base / entry.name))
        except OSError:
            raise ValueError(ERROR_EVIDENCE_INDEX) from None

    surfaces: list[dict[str, object]] = []
    for rel_base, path in sorted(candidates):
        budget.check_deadline()
        if is_in_opaque_directory(
            path,
            root=root,
            opaque_directories=opaque_directories,
        ) or not is_repo_bound_path(path, root):
            continue
        if not path.is_file():
            continue
        if rel_base == ".agent-guard/evidence" and path.name in _GENERATED_EVIDENCE_NAMES:
            continue
        try:
            size_bytes = path.stat().st_size
        except OSError:
            raise ValueError(ERROR_EVIDENCE_INDEX) from None
        budget.charge_selected(path)
        item = {
            "surface": "evidence_artifact",
            "path": rel_path(path, root),
            "kind": (
                "committed_evidence_sample"
                if rel_base == "docs/evidence-samples"
                else "repo_evidence_file"
            ),
            "status": "present",
            "size_bytes": size_bytes,
        }
        budget.add_result(item)
        surfaces.append(item)
    return surfaces


def collect_policy_surfaces(
    root: Path,
    *,
    opaque_directories: Sequence[str] = (),
    _budget: SurfaceInventoryBudget | None = None,
) -> list[dict[str, object]]:
    policy_dir = root / ".agent-guard"
    if not is_repo_bound_path(policy_dir, root):
        return []
    if not policy_dir.is_dir():
        return []
    surfaces: list[dict[str, object]] = []
    budget = _budget or SurfaceInventoryBudget()
    for path in sorted(
        repo_bound_glob(
            root,
            ".agent-guard/*.yaml",
            opaque_directories=opaque_directories,
            _budget=budget,
        )
    ):
        if not path.is_file():
            continue
        opened = read_surface_file(
            path,
            root,
            budget=budget,
            max_bytes=MAX_SURFACE_INVENTORY_POLICY_BYTES,
        )
        display = opened.relative_path
        item = {
            "surface": "policy_file",
            "path": display,
            "kind": policy_kind(display),
            "status": "present",
            "size_bytes": len(opened.data),
        }
        budget.add_result(item)
        surfaces.append(item)
    return surfaces
