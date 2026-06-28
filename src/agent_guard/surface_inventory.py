"""Where: src/agent_guard/surface_inventory.py
What: repo-local agent surface inventory without raw instruction or command text.
Why: maintainers need to know which agent-facing surfaces exist before review.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .context_guard import collect_context_inventory
from .workflow_guard import collect_run_lines


AGENT_SURFACE_SCHEMA_VERSION = "agent-guard.agent_surface_inventory.v1"
WORKFLOW_GLOBS = ("*.yml", "*.yaml")


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


def iter_workflow_files(root: Path) -> list[Path]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []
    files: list[Path] = []
    for pattern in WORKFLOW_GLOBS:
        files.extend(workflow_dir.glob(pattern))
    return sorted(path for path in files if path.is_file())


def collect_workflow_surfaces(root: Path) -> list[dict[str, object]]:
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


def collect_agent_surface_inventory(*, root: Path, context_policy: dict[str, object]) -> dict[str, object]:
    root = root.resolve()
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
    surfaces.extend(collect_workflow_surfaces(root))
    surfaces = sorted(surfaces, key=lambda item: (str(item.get("path", "")), str(item.get("surface", ""))))
    return {
        "schema_version": AGENT_SURFACE_SCHEMA_VERSION,
        "summary": summarize_surfaces(surfaces),
        "surfaces": surfaces,
    }


def public_safe_surface_text(payload: dict[str, object]) -> str:
    """Return serialized inventory text for tests and downstream safety checks."""

    import json

    return json.dumps(payload, ensure_ascii=False, sort_keys=True)
