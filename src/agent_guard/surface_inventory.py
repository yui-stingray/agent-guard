"""Where: src/agent_guard/surface_inventory.py
What: repo-local agent surface inventory without raw instruction or command text.
Why: maintainers need to know which agent-facing surfaces exist before review.
"""

from __future__ import annotations

import re
from pathlib import Path, PureWindowsPath
from typing import Literal

import yaml

from .context_guard import collect_context_inventory
from .workflow_guard import collect_run_lines


AGENT_SURFACE_SCHEMA_VERSION_V1 = "agent-guard.agent_surface_inventory.v1"
AGENT_SURFACE_SCHEMA_VERSION_V2 = "agent-guard.agent_surface_inventory.v2"
AGENT_SURFACE_SCHEMA_VERSION = AGENT_SURFACE_SCHEMA_VERSION_V1
WORKFLOW_GLOBS = ("*.yml", "*.yaml")
DOC_GLOBS = ("README.md", "docs/*.md")
SurfaceVersion = Literal["v1", "v2"]


def rel_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


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


def parse_agent_guard_command(command: str) -> dict[str, object] | None:
    match = re.search(
        r"(?:^|\s)(?:python\s+-m\s+agent_guard\.cli|agent-guard)\s+([a-z][a-z-]*)(?:\s+([a-z][a-z-]*))?",
        command,
    )
    if not match:
        return None
    return {
        "scanner": match.group(1),
        "command": match.group(2) or "",
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


def parse_output_artifact(command: str) -> str:
    match = re.search(r"(?:^|\s)--output(?:=|\s+)([^\s]+)", command)
    if not match:
        return ""
    return safe_metadata_path(match.group(1))


def iter_workflow_files(root: Path) -> list[Path]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []
    files: list[Path] = []
    for pattern in WORKFLOW_GLOBS:
        files.extend(workflow_dir.glob(pattern))
    return sorted(path for path in files if path.is_file())


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


def collect_workflow_surfaces(root: Path, *, include_artifacts: bool = False) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    for workflow_file in iter_workflow_files(root):
        workflow_path = rel_path(workflow_file, root)
        try:
            loaded = yaml.safe_load(workflow_file.read_text(encoding="utf-8")) or {}
        except Exception:
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


def collect_documented_guard_surfaces(root: Path) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    doc_files: list[Path] = []
    for pattern in DOC_GLOBS:
        doc_files.extend(root.glob(pattern))
    for doc_file in sorted(path for path in doc_files if path.is_file()):
        doc_path = rel_path(doc_file, root)
        try:
            lines = doc_file.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for lineno, line in enumerate(lines, start=1):
            command = parse_agent_guard_command(line)
            if command is None:
                continue
            surfaces.append(
                {
                    "surface": "documented_guard_command",
                    "path": doc_path,
                    "kind": "documentation_recipe",
                    "status": "documented",
                    "line": lineno,
                    "command": command,
                }
            )
    return surfaces


def collect_committed_evidence_surfaces(root: Path) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    for base in (root / ".agent-guard" / "evidence", root / "docs" / "evidence-samples"):
        if not base.is_dir():
            continue
        for path in sorted(base.glob("*")):
            if not path.is_file():
                continue
            surfaces.append(
                {
                    "surface": "evidence_artifact",
                    "path": rel_path(path, root),
                    "kind": "committed_evidence_sample" if "docs" in path.parts else "repo_evidence_file",
                    "status": "present",
                    "size_bytes": path.stat().st_size,
                }
            )
    return surfaces


def collect_policy_surfaces(root: Path) -> list[dict[str, object]]:
    policy_dir = root / ".agent-guard"
    if not policy_dir.is_dir():
        return []
    surfaces: list[dict[str, object]] = []
    for path in sorted(policy_dir.glob("*.yaml")):
        if not path.is_file():
            continue
        display = rel_path(path, root)
        surfaces.append(
            {
                "surface": "policy_file",
                "path": display,
                "kind": policy_kind(display),
                "status": "present",
                "size_bytes": path.stat().st_size,
            }
        )
    return surfaces


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
) -> dict[str, object]:
    root = root.resolve()
    version = normalize_surface_version(schema_version)
    context_inventory = collect_context_inventory(root=root, policy=context_policy)
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
    surfaces.extend(collect_policy_surfaces(root))
    surfaces.extend(collect_workflow_surfaces(root, include_artifacts=version == "v2"))
    if version == "v2":
        surfaces.extend(collect_documented_guard_surfaces(root))
        surfaces.extend(collect_committed_evidence_surfaces(root))
    surfaces = sorted(surfaces, key=lambda item: (str(item.get("path", "")), str(item.get("surface", ""))))
    return {
        "schema_version": schema_for_surface_version(version),
        "summary": summarize_surfaces(surfaces),
        "surfaces": surfaces,
    }


def public_safe_surface_text(payload: dict[str, object]) -> str:
    """Return serialized inventory text for tests and downstream safety checks."""

    import json

    return json.dumps(payload, ensure_ascii=False, sort_keys=True)
