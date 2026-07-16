"""Where: src/agent_guard/surface_inventory_metadata.py
What: documented command, committed evidence, and policy file surfaces.
Why: keep repository metadata discovery separate from workflow and MCP scanners.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from .surface_inventory_core import (
    is_repo_bound_path,
    parse_agent_guard_command,
    rel_path,
    repo_bound_glob,
)


DOC_GLOBS = ("README.md", "docs/*.md")


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
) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    doc_files: list[Path] = []
    for pattern in DOC_GLOBS:
        doc_files.extend(
            repo_bound_glob(
                root,
                pattern,
                opaque_directories=opaque_directories,
            )
        )
    for doc_file in sorted(
        path for path in doc_files if is_repo_bound_path(path, root) and path.is_file()
    ):
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


def collect_committed_evidence_surfaces(
    root: Path,
    *,
    opaque_directories: Sequence[str] = (),
) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    for rel_base in (".agent-guard/evidence", "docs/evidence-samples"):
        base = root / rel_base
        if not is_repo_bound_path(base, root):
            continue
        if not base.is_dir():
            continue
        for path in sorted(
            repo_bound_glob(
                root,
                f"{rel_base}/*",
                opaque_directories=opaque_directories,
            )
        ):
            if not is_repo_bound_path(path, root):
                continue
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


def collect_policy_surfaces(
    root: Path,
    *,
    opaque_directories: Sequence[str] = (),
) -> list[dict[str, object]]:
    policy_dir = root / ".agent-guard"
    if not is_repo_bound_path(policy_dir, root):
        return []
    if not policy_dir.is_dir():
        return []
    surfaces: list[dict[str, object]] = []
    for path in sorted(
        repo_bound_glob(
            root,
            ".agent-guard/*.yaml",
            opaque_directories=opaque_directories,
        )
    ):
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
