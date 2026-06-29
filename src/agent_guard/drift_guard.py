"""Where: src/agent_guard/drift_guard.py
What: small policy/spec drift checks for the repo's own guard setup.
Why: keep README guidance, workflow policy, and guard files aligned.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml

from .context_guard import collect_context_inventory, load_context_policy, scan_context_files
from .context_lock import check_context_digest_coverage
from .digest_guard import load_digest_policy
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

CONTEXT_RULE_CLASSIFICATIONS = {
    "approval_bypass": "permission_boundary_weakened",
    "disable_safety_tools": "permission_boundary_weakened",
    "force_merge_without_review": "permission_boundary_weakened",
    "policy_self_modification": "permission_boundary_weakened",
    "sandbox_escape": "permission_boundary_weakened",
    "permission_self_escalation": "permission_boundary_weakened",
    "skip_verification": "verification_removed",
    "ignore_test_failures": "verification_removed",
    "unsafe_release_publication": "verification_removed",
    "secret_prompt": "private_data_exposure",
    "credential_persistence": "private_data_exposure",
    "private_data_exfiltration": "private_data_exposure",
    "raw_evidence_publication": "raw_evidence_publication",
    "untrusted_instruction_priority": "untrusted_instruction_priority",
    "unrestricted_network": "unrestricted_external_access",
    "hidden_action": "auditability_weakened",
    "audit_trail_removal": "auditability_weakened",
    "user_impersonation": "auditability_weakened",
    "destructive_command": "destructive_action_boundary_weakened",
}

CONTEXT_LOCK_CLASSIFICATIONS = {
    "missing": "context_file_unpinned",
    "partial": "context_file_partially_pinned",
    "mismatch": "context_file_digest_drift",
}

BASELINE_TRUST_EXTRA_PATHS = (
    ".agent-guard/context-digest-policy.yaml",
    ".github/workflows",
    "action.yml",
    ".pre-commit-hooks.yaml",
)


@dataclass(frozen=True)
class BaselineTrustSummary:
    status: str
    protected_path_count: int
    changed_count: int
    finding_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": "git_diff",
            "base_ref": "provided",
            "status": self.status,
            "protected_path_count": self.protected_path_count,
            "changed_count": self.changed_count,
            "finding_count": self.finding_count,
        }


@dataclass(frozen=True)
class PolicySpecDriftScan:
    findings: list["DriftFinding"]
    checked_count: int
    baseline_trust: BaselineTrustSummary | None = None


@dataclass(frozen=True)
class DriftFinding:
    rule_id: str
    severity: str
    file: str
    message: str
    reason: str
    requirement_id: str
    classification: str = ""
    source_rule_id: str = ""
    line: int | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "message": self.message,
            "reason": self.reason,
            "requirement_id": self.requirement_id,
        }
        if self.classification:
            payload["classification"] = self.classification
        if self.source_rule_id:
            payload["source_rule_id"] = self.source_rule_id
        if self.line is not None:
            payload["line"] = self.line
        return payload


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


def baseline_trust_paths(profile: str) -> tuple[str, ...]:
    paths = {*profile_required_files(profile), *BASELINE_TRUST_EXTRA_PATHS}
    return tuple(sorted(paths))


def classify_baseline_trust_path(path: str) -> str:
    if path == ".agent-guard/context-digest-policy.yaml" or "digest" in Path(path).name:
        return "digest_policy_changed"
    if path.startswith(".agent-guard/"):
        return "guard_policy_changed"
    if path.startswith(".github/workflows/") or path == "action.yml":
        return "guard_workflow_changed"
    if path == ".pre-commit-hooks.yaml":
        return "guard_hook_changed"
    return "baseline_guard_surface_changed"


def build_baseline_unproven_finding(reason: str) -> DriftFinding:
    return DriftFinding(
        rule_id="baseline_trust_unproven",
        severity="high",
        file=".",
        message="baseline-sensitive guard changes could not be compared to the provided base ref",
        reason=reason,
        requirement_id="baseline_ref",
        classification="baseline_review_required",
    )


def is_safe_base_ref_arg(base_ref: str) -> bool:
    return bool(base_ref) and not base_ref.startswith("-") and not any(char in base_ref for char in "\x00\r\n")


def run_git_command(root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def scan_baseline_trust_drift(
    *,
    root: Path,
    base_ref: str,
    profile: str,
) -> tuple[list[DriftFinding], int, BaselineTrustSummary]:
    protected_paths = baseline_trust_paths(profile)
    if not is_safe_base_ref_arg(base_ref):
        finding = build_baseline_unproven_finding("base_ref_unavailable")
        return [finding], 1, BaselineTrustSummary(
            status="unproven",
            protected_path_count=len(protected_paths),
            changed_count=0,
            finding_count=1,
        )
    try:
        probe = run_git_command(root, ["rev-parse", "--is-inside-work-tree"])
    except FileNotFoundError:
        finding = build_baseline_unproven_finding("git_unavailable")
        return [finding], 1, BaselineTrustSummary(
            status="unproven",
            protected_path_count=len(protected_paths),
            changed_count=0,
            finding_count=1,
        )
    if probe.returncode != 0 or probe.stdout.strip() != "true":
        finding = build_baseline_unproven_finding("not_git_repository")
        return [finding], 1, BaselineTrustSummary(
            status="unproven",
            protected_path_count=len(protected_paths),
            changed_count=0,
            finding_count=1,
        )

    try:
        diff = run_git_command(
            root,
            [
                "diff",
                "--relative",
                "--name-only",
                "--diff-filter=AMDR",
                f"{base_ref}...HEAD",
                "--",
                *protected_paths,
            ],
        )
    except FileNotFoundError:
        finding = build_baseline_unproven_finding("git_unavailable")
        return [finding], 1, BaselineTrustSummary(
            status="unproven",
            protected_path_count=len(protected_paths),
            changed_count=0,
            finding_count=1,
        )
    if diff.returncode != 0:
        finding = build_baseline_unproven_finding("base_ref_unavailable")
        return [finding], 1, BaselineTrustSummary(
            status="unproven",
            protected_path_count=len(protected_paths),
            changed_count=0,
            finding_count=1,
        )

    changed_paths = sorted({line.strip() for line in diff.stdout.splitlines() if line.strip()})
    findings = [
        DriftFinding(
            rule_id="baseline_trust_change",
            severity="high",
            file=path,
            message="baseline-sensitive guard surface changed relative to the provided base ref",
            reason=classify_baseline_trust_path(path),
            requirement_id=Path(path).name or path,
            classification="baseline_review_required",
        )
        for path in changed_paths
    ]
    return findings, len(protected_paths), BaselineTrustSummary(
        status="ok" if not findings else "review_required",
        protected_path_count=len(protected_paths),
        changed_count=len(changed_paths),
        finding_count=len(findings),
    )


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


def scan_context_instruction_drift(*, root: Path) -> tuple[list[DriftFinding], int]:
    context_policy_path = root / ".agent-guard" / "context-policy.yaml"
    if not context_policy_path.is_file():
        return [], 0

    policy = load_context_policy(context_policy_path)
    context_findings, scanned_count = scan_context_files(root=root, policy=policy)
    findings: list[DriftFinding] = []
    for item in context_findings:
        classification = CONTEXT_RULE_CLASSIFICATIONS.get(item.rule_id, "unsafe_context_instruction")
        findings.append(
            DriftFinding(
                rule_id="context_instruction_drift",
                severity=item.severity,
                file=item.file,
                message="agent context contains a classified unsafe instruction",
                reason=classification,
                requirement_id=item.rule_id,
                classification=classification,
                source_rule_id=item.rule_id,
                line=item.line,
            )
        )
    return findings, scanned_count


def scan_context_lock_drift(*, root: Path) -> tuple[list[DriftFinding], int]:
    context_policy_path = root / ".agent-guard" / "context-policy.yaml"
    digest_policy_path = root / ".agent-guard" / "context-digest-policy.yaml"
    if not context_policy_path.is_file() or not digest_policy_path.is_file():
        return [], 0

    inventory = collect_context_inventory(root=root, policy=load_context_policy(context_policy_path))
    if not inventory.context_files:
        return [], 0
    coverage = check_context_digest_coverage(
        root=root,
        inventory=inventory,
        digest_policy=load_digest_policy(digest_policy_path),
    )
    raw_findings = coverage.get("findings", [])
    findings: list[DriftFinding] = []
    for item in raw_findings if isinstance(raw_findings, list) else []:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", ""))
        classification = CONTEXT_LOCK_CLASSIFICATIONS.get(status, "context_lock_drift")
        findings.append(
            DriftFinding(
                rule_id="context_lock_drift",
                severity=str(item.get("severity", "high")),
                file=str(item.get("path", "AGENTS.md")),
                message="agent context digest coverage changed",
                reason=classification,
                requirement_id=str(item.get("check_id") or item.get("path") or "context_lock"),
                classification=classification,
                source_rule_id=str(item.get("rule_id", "")),
            )
        )
    return findings, int(coverage.get("context_file_count", 0))


def scan_policy_spec_drift(
    *,
    root: Path,
    profile: str = "recommended",
    schema_version: str = "v1",
    base_ref: str = "",
) -> tuple[list[DriftFinding], int]:
    scan = build_policy_spec_drift_scan(
        root=root,
        profile=profile,
        schema_version=schema_version,
        base_ref=base_ref,
    )
    return scan.findings, scan.checked_count


def build_policy_spec_drift_scan(
    *,
    root: Path,
    profile: str = "recommended",
    schema_version: str = "v1",
    base_ref: str = "",
) -> PolicySpecDriftScan:
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
        context_findings, context_checked = scan_context_instruction_drift(root=root)
        checked_count += context_checked
        findings.extend(context_findings)
        context_lock_findings, context_lock_checked = scan_context_lock_drift(root=root)
        checked_count += context_lock_checked
        findings.extend(context_lock_findings)

    baseline_trust: BaselineTrustSummary | None = None
    baseline_ref = str(base_ref).strip()
    if baseline_ref:
        baseline_findings, baseline_checked, baseline_trust = scan_baseline_trust_drift(
            root=root,
            base_ref=baseline_ref,
            profile=profile_name,
        )
        checked_count += baseline_checked
        findings.extend(baseline_findings)

    return PolicySpecDriftScan(
        findings=findings,
        checked_count=checked_count,
        baseline_trust=baseline_trust,
    )


def build_policy_spec_drift_report(
    *,
    root: Path,
    profile: str = "recommended",
    schema_version: str = "v1",
    base_ref: str = "",
) -> dict[str, object]:
    version = normalize_drift_schema_version(schema_version)
    profile_name = normalize_profile_name(profile)
    scan = build_policy_spec_drift_scan(
        root=root,
        profile=profile_name,
        schema_version=version,
        base_ref=base_ref,
    )
    payload: dict[str, object] = {
        "schema_version": drift_schema_id(version),
        "profile": profile_name,
        "status": "ok" if not scan.findings else "violation",
        "checked_count": scan.checked_count,
        "finding_count": len(scan.findings),
        "findings": [item.to_dict() for item in scan.findings],
    }
    if scan.baseline_trust is not None:
        payload["baseline_trust"] = scan.baseline_trust.to_dict()
    return payload
