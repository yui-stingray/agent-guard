"""Where: src/agent_guard/context_lock.py
What: build digest policy checks from discovered agent context files.
Why: connect context inventory to digest drift checks without emitting raw context content.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .context_guard import ContextInventory
from .digest_guard import DigestCheck, normalize_checks


CONTEXT_LOCK_COVERAGE_SCHEMA_VERSION = "agent-guard.context_lock_coverage.v1"


@dataclass(frozen=True)
class ContextLockCoverageFinding:
    rule_id: str
    severity: str
    path: str
    status: str
    check_id: str
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "path": self.path,
            "status": self.status,
            "check_id": self.check_id,
            "message": self.message,
        }


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def context_lock_check_id(path: str, used_ids: set[str]) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")
    base = f"context_{slug}" if slug else "context_file"
    candidate = base
    suffix = 2
    while candidate in used_ids:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used_ids.add(candidate)
    return candidate


def build_context_digest_policy(*, root: Path, inventory: ContextInventory) -> dict[str, Any]:
    root = root.resolve()
    used_ids: set[str] = set()
    checks: list[dict[str, str]] = []

    if not inventory.context_files:
        raise ValueError("no agent context files discovered")

    for entry in inventory.context_files:
        target = (root / entry.path).resolve()
        try:
            relative_path = target.relative_to(root).as_posix()
        except ValueError:
            raise ValueError(f"context file path escapes root: {entry.path}") from None

        if not target.is_file():
            raise FileNotFoundError(f"context file not found: {entry.path}")

        checks.append(
            {
                "id": context_lock_check_id(relative_path, used_ids),
                "path": relative_path,
                "sha256": sha256_file(target),
            }
        )

    return {"checks": checks}


def dump_digest_policy_yaml(policy: dict[str, Any]) -> str:
    return yaml.safe_dump(policy, sort_keys=False)


def digest_check_repo_path(*, root: Path, check: DigestCheck) -> str:
    target = (root / check.path).resolve()
    try:
        return target.relative_to(root).as_posix()
    except ValueError:
        raise ValueError(f"{check.check_id}: path escapes root: {check.path}") from None


def check_context_digest_coverage(
    *,
    root: Path,
    inventory: ContextInventory,
    digest_policy: dict[str, Any],
) -> dict[str, Any]:
    root = root.resolve()
    if not inventory.context_files:
        raise ValueError("no agent context files discovered")

    checks_by_path: dict[str, list[DigestCheck]] = {}
    for check in normalize_checks(digest_policy.get("checks", [])):
        rel_path = digest_check_repo_path(root=root, check=check)
        checks_by_path.setdefault(rel_path, []).append(check)

    findings: list[ContextLockCoverageFinding] = []
    covered_count = 0
    for entry in inventory.context_files:
        target = (root / entry.path).resolve()
        try:
            rel_path = target.relative_to(root).as_posix()
        except ValueError:
            raise ValueError(f"context file path escapes root: {entry.path}") from None

        checks = checks_by_path.get(rel_path, [])
        full_file_checks = [check for check in checks if check.start_line == 1]
        if not checks:
            findings.append(
                ContextLockCoverageFinding(
                    rule_id="context_lock_missing",
                    severity="high",
                    path=rel_path,
                    status="missing",
                    check_id="",
                    message="context file is not pinned by digest policy",
                )
            )
            continue
        if not full_file_checks:
            findings.append(
                ContextLockCoverageFinding(
                    rule_id="context_lock_partial",
                    severity="high",
                    path=rel_path,
                    status="partial",
                    check_id=checks[0].check_id,
                    message="context file is only partially pinned by digest policy",
                )
            )
            continue
        if not target.is_file():
            findings.append(
                ContextLockCoverageFinding(
                    rule_id="context_lock_file_missing",
                    severity="high",
                    path=rel_path,
                    status="missing",
                    check_id=full_file_checks[0].check_id,
                    message="context file is missing",
                )
            )
            continue

        actual_sha256 = sha256_file(target)
        if any(check.expected_sha256 == actual_sha256 for check in full_file_checks):
            covered_count += 1
            continue
        findings.append(
            ContextLockCoverageFinding(
                rule_id="context_lock_mismatch",
                severity="high",
                path=rel_path,
                status="mismatch",
                check_id=full_file_checks[0].check_id,
                message="context file digest does not match digest policy",
            )
        )

    return {
        "schema_version": CONTEXT_LOCK_COVERAGE_SCHEMA_VERSION,
        "status": "ok" if not findings else "violation",
        "context_file_count": len(inventory.context_files),
        "covered_count": covered_count,
        "finding_count": len(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
