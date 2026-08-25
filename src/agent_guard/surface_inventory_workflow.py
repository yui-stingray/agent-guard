"""Where: src/agent_guard/surface_inventory_workflow.py
What: GitHub Actions workflow references to agent-guard commands and artifacts.
Why: keep workflow parsing separate from context, repository metadata, and MCP scanners.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

import yaml

from .bounded_yaml import (
    BoundedYamlInvalidError,
    BoundedYamlLimitError,
    load_bounded_yaml,
)
from .surface_inventory_core import (
    ERROR_SURFACE_INVENTORY_LIMIT,
    MAX_SURFACE_INVENTORY_FILE_BYTES,
    SurfaceInventoryBudget,
    is_repo_bound_path,
    parse_agent_guard_command,
    rel_path,
    repo_bound_glob,
    read_surface_file,
    safe_metadata_path,
)
from .workflow_guard import collect_run_lines


WORKFLOW_GLOBS = ("*.yml", "*.yaml")


def parse_output_artifact(command: str) -> str:
    match = re.search(r"(?:^|\s)--output(?:=|\s+)([^\s]+)", command)
    if not match:
        return ""
    return safe_metadata_path(match.group(1))


def iter_workflow_files(
    root: Path,
    *,
    opaque_directories: Sequence[str] = (),
    _budget: SurfaceInventoryBudget | None = None,
) -> list[Path]:
    budget = _budget or SurfaceInventoryBudget()
    workflow_dir = root / ".github" / "workflows"
    if not is_repo_bound_path(workflow_dir, root):
        return []
    if not workflow_dir.is_dir():
        return []
    files: list[Path] = []
    for pattern in WORKFLOW_GLOBS:
        files.extend(
            repo_bound_glob(
                root,
                f".github/workflows/{pattern}",
                opaque_directories=opaque_directories,
                _budget=budget,
            )
        )
    return sorted(path for path in files if is_repo_bound_path(path, root) and path.is_file())


def collect_workflow_artifact_surfaces(workflow: dict[str, object], *, workflow_path: str) -> list[dict[str, object]]:
    raw_jobs = workflow.get("jobs", {})
    if not isinstance(raw_jobs, dict):
        return []
    surfaces: list[dict[str, object]] = []
    for raw_job_id, raw_job in raw_jobs.items():
        if not isinstance(raw_job, dict):
            continue
        raw_steps = raw_job.get("steps", [])
        if not isinstance(raw_steps, list):
            continue
        for step_index, raw_step in enumerate(raw_steps, start=1):
            if not isinstance(raw_step, dict):
                continue
            uses = str(raw_step.get("uses", ""))
            with_cfg = raw_step.get("with", {})
            if "upload-artifact" in uses and isinstance(with_cfg, dict):
                artifact_path = safe_metadata_path(str(with_cfg.get("path", "")))
                if artifact_path:
                    surfaces.append(
                        {
                            "surface": "evidence_artifact_reference",
                            "path": workflow_path,
                            "kind": "github_artifact",
                            "status": "referenced",
                            "job_id": str(raw_job_id),
                            "step_index": step_index,
                            "artifact_path": artifact_path,
                        }
                    )
    return surfaces


def collect_workflow_surfaces(
    root: Path,
    *,
    include_artifacts: bool = False,
    opaque_directories: Sequence[str] = (),
) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    budget = SurfaceInventoryBudget()
    for workflow_file in iter_workflow_files(
        root,
        opaque_directories=opaque_directories,
        _budget=budget,
    ):
        if not is_repo_bound_path(workflow_file, root):
            continue
        workflow_path = rel_path(workflow_file, root)
        try:
            opened = read_surface_file(workflow_file, root, budget=budget)
            workflow_path = opened.relative_path
            text = opened.data.decode("utf-8")
            loaded = load_bounded_yaml(
                text,
                construct=yaml.safe_load,
                max_expanded_bytes=MAX_SURFACE_INVENTORY_FILE_BYTES,
            ) or {}
        except BoundedYamlLimitError:
            raise ValueError(ERROR_SURFACE_INVENTORY_LIMIT) from None
        except (BoundedYamlInvalidError, UnicodeDecodeError):
            surfaces.append(
                {
                    "surface": "workflow_file",
                    "path": workflow_path,
                    "kind": "github_actions",
                    "status": "parse_error",
                }
            )
            continue
        if not isinstance(loaded, dict):
            surfaces.append(
                {
                    "surface": "workflow_file",
                    "path": workflow_path,
                    "kind": "github_actions",
                    "status": "not_object",
                }
            )
            continue
        surfaces.append(
            {
                "surface": "workflow_file",
                "path": workflow_path,
                "kind": "github_actions",
                "status": "scanned",
            }
        )
        for line in collect_run_lines(loaded, workflow_path=workflow_path):
            command = parse_agent_guard_command(line.command)
            if command is None:
                continue
            surfaces.append(
                {
                    "surface": "workflow_reference",
                    "path": workflow_path,
                    "kind": "agent_guard_command",
                    "status": "referenced",
                    "job_id": line.job_id,
                    "step_index": line.step_index,
                    "command": command,
                }
            )
            if include_artifacts:
                artifact_path = parse_output_artifact(line.command)
                if artifact_path:
                    surfaces.append(
                        {
                            "surface": "evidence_artifact_reference",
                            "path": workflow_path,
                            "kind": "agent_guard_output",
                            "status": "referenced",
                            "job_id": line.job_id,
                            "step_index": line.step_index,
                            "artifact_path": artifact_path,
                            "command": command,
                        }
                    )
        if include_artifacts:
            surfaces.extend(collect_workflow_artifact_surfaces(loaded, workflow_path=workflow_path))
    return surfaces
