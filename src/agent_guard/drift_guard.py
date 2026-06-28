"""Where: src/agent_guard/drift_guard.py
What: small policy/spec drift checks for the repo's own guard setup.
Why: keep README guidance, workflow policy, and guard files aligned.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .context_guard import collect_context_inventory, load_context_policy
from .profiles import normalize_profile_name, profile_requirements
from .workflow_guard import load_workflow_policy, scan_workflow_policy


POLICY_SPEC_DRIFT_SCHEMA_VERSION_V1 = "agent-guard.policy_spec_drift.v1"
POLICY_SPEC_DRIFT_SCHEMA_VERSION_V2 = "agent-guard.policy_spec_drift.v2"
README_COMMANDS = (
    (
        "readme_surface_inventory",
        "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml",
    ),
    (
        "readme_context_guard",
        "agent-guard context check --root . --policy .agent-guard/context-policy.yaml",
    ),
    (
        "readme_context_lock_coverage",
        "agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml",
    ),
    (
        "readme_workflow_guard",
        "agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml",
    ),
    (
        "readme_drift_guard",
        "agent-guard drift check --root .",
    ),
)

REQUIRED_AGENT_GUARD_FILES = (
    ".agent-guard/context-policy.yaml",
    ".agent-guard/path-policy.yaml",
    ".agent-guard/content-policy.yaml",
    ".agent-guard/workflow-policy.yaml",
)


@dataclass(frozen=True)
class DriftFinding:
    rule_id: str
    severity: str
    file: str
    message: str
    reason: str
    requirement_id: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "message": self.message,
            "reason": self.reason,
            "requirement_id": self.requirement_id,
        }


def normalize_drift_schema_version(version: str) -> str:
    if version in {"v1", POLICY_SPEC_DRIFT_SCHEMA_VERSION_V1}:
        return "v1"
    if version in {"v2", POLICY_SPEC_DRIFT_SCHEMA_VERSION_V2}:
        return "v2"
    raise ValueError("drift schema version must be v1 or v2")


def drift_schema_id(version: str) -> str:
    return POLICY_SPEC_DRIFT_SCHEMA_VERSION_V1 if version == "v1" else POLICY_SPEC_DRIFT_SCHEMA_VERSION_V2


def profile_readme_commands(profile: str) -> tuple[tuple[str, str], ...]:
    requirements = profile_requirements(profile)
    return tuple((str(item[0]), str(item[1])) for item in requirements["readme_commands"])


def profile_required_files(profile: str) -> tuple[str, ...]:
    requirements = profile_requirements(profile)
    return tuple(str(item) for item in requirements["policy_files"])


def read_optional_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def workflow_policy_required_paths(root: Path) -> set[str]:
    policy_path = root / ".agent-guard" / "workflow-policy.yaml"
    try:
        loaded = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return set()
    if not isinstance(loaded, dict):
        return set()
    raw_files = loaded.get("required_files", [])
    if not isinstance(raw_files, list):
        return set()
    paths: set[str] = set()
    for item in raw_files:
        if isinstance(item, str):
            paths.add(item)
        elif isinstance(item, dict) and isinstance(item.get("path"), str):
            paths.add(str(item["path"]))
    return paths


def scan_context_boundary_drift(*, root: Path, profile: str) -> tuple[list[DriftFinding], int]:
    context_policy_path = root / ".agent-guard" / "context-policy.yaml"
    if not context_policy_path.is_file():
        return [], 0
    findings: list[DriftFinding] = []
    checked_count = 0
    required_boundaries = profile_requirements(profile)["boundary_categories"]
    inventory = collect_context_inventory(root=root, policy=load_context_policy(context_policy_path))
    boundary_status = {
        str(item.get("category", "")): str(item.get("status", "missing"))
        for item in inventory.permission_boundaries
    }
    for category in required_boundaries:
        checked_count += 1
        category_name = str(category)
        if boundary_status.get(category_name) == "present":
            continue
        findings.append(
            DriftFinding(
                rule_id="context_boundary_missing",
                severity="medium",
                file="AGENTS.md",
                message="agent context is missing a required safety boundary category",
                reason="missing_required_context_boundary",
                requirement_id=category_name,
            )
        )
    return findings, checked_count


def scan_policy_spec_drift(
    *,
    root: Path,
    profile: str = "recommended",
    schema_version: str = "v1",
) -> tuple[list[DriftFinding], int]:
    root = root.resolve()
    version = normalize_drift_schema_version(schema_version)
    profile_name = normalize_profile_name(profile)
    readme_commands = README_COMMANDS if version == "v1" else profile_readme_commands(profile_name)
    required_files = REQUIRED_AGENT_GUARD_FILES if version == "v1" else profile_required_files(profile_name)
    findings: list[DriftFinding] = []
    checked_count = 0

    readme = root / "README.md"
    readme_text = read_optional_text(readme)
    for requirement_id, command in readme_commands:
        checked_count += 1
        if command in readme_text:
            continue
        findings.append(
            DriftFinding(
                rule_id="readme_guard_command_missing",
                severity="medium",
                file="README.md",
                message="README is missing a recommended guard command",
                reason="missing_readme_guard_command",
                requirement_id=requirement_id,
            )
        )

    for rel_path in required_files:
        checked_count += 1
        if (root / rel_path).is_file():
            continue
        findings.append(
            DriftFinding(
                rule_id="agent_guard_policy_missing",
                severity="high",
                file=rel_path,
                message="required .agent-guard policy file is missing",
                reason="missing_agent_guard_policy",
                requirement_id=Path(rel_path).name,
            )
        )

    required_paths = workflow_policy_required_paths(root)
    for rel_path in required_files:
        checked_count += 1
        if rel_path in required_paths:
            continue
        findings.append(
            DriftFinding(
                rule_id="workflow_policy_required_file_missing",
                severity="medium",
                file=".agent-guard/workflow-policy.yaml",
                message="workflow policy does not require a core .agent-guard policy file",
                reason="missing_required_file_entry",
                requirement_id=Path(rel_path).name,
            )
        )

    workflow_policy_path = root / ".agent-guard" / "workflow-policy.yaml"
    if workflow_policy_path.is_file():
        try:
            workflow_findings, workflow_checked = scan_workflow_policy(
                root=root,
                policy=load_workflow_policy(workflow_policy_path),
            )
            checked_count += workflow_checked
            for item in workflow_findings:
                findings.append(
                    DriftFinding(
                        rule_id=item.rule_id,
                        severity=item.severity,
                        file=item.file,
                        message=item.message,
                        reason=item.reason,
                        requirement_id=item.requirement_id or item.workflow_id or item.rule_id,
                    )
                )
        except Exception:
            findings.append(
                DriftFinding(
                    rule_id="workflow_policy_invalid",
                    severity="high",
                    file=".agent-guard/workflow-policy.yaml",
                    message="workflow policy could not be evaluated",
                    reason="invalid_workflow_policy",
                    requirement_id="workflow_policy",
                )
            )
            checked_count += 1

    if version == "v2":
        boundary_findings, boundary_checked = scan_context_boundary_drift(root=root, profile=profile_name)
        checked_count += boundary_checked
        findings.extend(boundary_findings)

    return findings, checked_count


def build_policy_spec_drift_report(
    *,
    root: Path,
    profile: str = "recommended",
    schema_version: str = "v1",
) -> dict[str, object]:
    version = normalize_drift_schema_version(schema_version)
    profile_name = normalize_profile_name(profile)
    findings, checked_count = scan_policy_spec_drift(
        root=root,
        profile=profile_name,
        schema_version=version,
    )
    return {
        "schema_version": drift_schema_id(version),
        "profile": profile_name,
        "status": "ok" if not findings else "violation",
        "checked_count": checked_count,
        "finding_count": len(findings),
        "findings": [item.to_dict() for item in findings],
    }
