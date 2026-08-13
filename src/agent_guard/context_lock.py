"""Where: src/agent_guard/context_lock.py
What: build digest policy checks from discovered agent context files.
Why: connect context inventory to digest drift checks without emitting raw context content.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .bounded_repo_reader import (
    BoundedRepoReceipt,
    BoundedRepoContainmentError,
    BoundedRepoFileNotFoundError,
    BoundedRepoLimitError,
    BoundedRepoReadError,
    DistinctInputBudget,
    read_repo_bound_bytes,
)
from .context_guard import (
    ERROR_CONTEXT_SCAN_LIMIT,
    ERROR_CONTEXT_SCAN_TARGET,
    MAX_CONTEXT_DISTINCT_INPUT_BYTES,
    MAX_CONTEXT_FILE_BYTES,
    ContextInventory,
)
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


def _snapshot_inputs(
    inventory: ContextInventory,
) -> dict[str, tuple[BoundedRepoReceipt, str]]:
    receipts = inventory._input_receipts
    alias_pairs = inventory._input_aliases
    aliases = dict(inventory._input_aliases)
    receipt_paths = [receipt.relative_path for receipt in receipts]
    if (
        len(receipts) != len(inventory.context_files)
        or len(alias_pairs) != len(receipts)
        or len(aliases) != len(alias_pairs)
        or len(set(receipt_paths)) != len(receipt_paths)
        or set(aliases) != set(receipt_paths)
    ):
        raise ValueError(ERROR_CONTEXT_SCAN_TARGET)
    return {
        receipt.relative_path: (receipt, aliases[receipt.relative_path])
        for receipt in receipts
    }


def _context_file_receipt(
    *,
    root: Path,
    relative_path: str,
    input_budget: DistinctInputBudget,
) -> BoundedRepoReceipt | None:
    try:
        opened = read_repo_bound_bytes(
            root / relative_path,
            root,
            max_bytes=MAX_CONTEXT_FILE_BYTES,
        )
    except BoundedRepoFileNotFoundError:
        return None
    except BoundedRepoLimitError:
        raise ValueError(ERROR_CONTEXT_SCAN_LIMIT) from None
    except (BoundedRepoContainmentError, BoundedRepoReadError):
        raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
    try:
        input_budget.charge(opened)
    except BoundedRepoLimitError:
        raise ValueError(ERROR_CONTEXT_SCAN_LIMIT) from None
    except BoundedRepoReadError:
        raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
    return opened.receipt()


def _receipt_matches_snapshot(
    current: BoundedRepoReceipt,
    snapshot: BoundedRepoReceipt,
) -> bool:
    return (
        current.relative_path == snapshot.relative_path
        and current.identity == snapshot.identity
        and current.size_bytes == snapshot.size_bytes
        and current.sha256 == snapshot.sha256
    )


def _context_relative_path(*, root: Path, raw_path: str) -> str:
    target = Path(os.path.abspath(root / raw_path))
    try:
        return target.relative_to(root).as_posix()
    except ValueError:
        raise ValueError(f"context file path escapes root: {raw_path}") from None


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


def build_context_digest_policy(
    *,
    root: Path,
    inventory: ContextInventory,
    _input_budget: DistinctInputBudget | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    input_budget = _input_budget or DistinctInputBudget(
        max_bytes=MAX_CONTEXT_DISTINCT_INPUT_BYTES
    )
    snapshot_inputs = _snapshot_inputs(inventory)
    used_ids: set[str] = set()
    checks: list[dict[str, str]] = []

    if not inventory.context_files:
        raise ValueError("no agent context files discovered")

    for entry in inventory.context_files:
        relative_path = _context_relative_path(root=root, raw_path=entry.path)
        snapshot_input = snapshot_inputs.get(relative_path)
        if snapshot_input is None:
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET)
        reopen_path = snapshot_input[1]
        current_receipt = _context_file_receipt(
            root=root,
            relative_path=reopen_path,
            input_budget=input_budget,
        )
        if current_receipt is None:
            raise FileNotFoundError(f"context file not found: {entry.path}")
        snapshot_receipt = snapshot_input[0]
        if not _receipt_matches_snapshot(
            current_receipt,
            snapshot_receipt,
        ):
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET)
        checked_digest = snapshot_receipt.sha256.hex()

        checks.append(
            {
                "id": context_lock_check_id(relative_path, used_ids),
                "path": relative_path,
                "sha256": checked_digest,
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
    _input_budget: DistinctInputBudget | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    input_budget = _input_budget or DistinctInputBudget(
        max_bytes=MAX_CONTEXT_DISTINCT_INPUT_BYTES
    )
    snapshot_inputs = _snapshot_inputs(inventory)
    if not inventory.context_files:
        raise ValueError("no agent context files discovered")

    checks_by_path: dict[str, list[DigestCheck]] = {}
    for check in normalize_checks(digest_policy.get("checks", [])):
        rel_path = digest_check_repo_path(root=root, check=check)
        checks_by_path.setdefault(rel_path, []).append(check)

    findings: list[ContextLockCoverageFinding] = []
    covered: list[dict[str, object]] = []
    covered_count = 0
    for entry in inventory.context_files:
        rel_path = _context_relative_path(root=root, raw_path=entry.path)
        snapshot_input = snapshot_inputs.get(rel_path)
        if snapshot_input is None:
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET)

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
        reopen_path = snapshot_input[1]
        current_receipt = _context_file_receipt(
            root=root,
            relative_path=reopen_path,
            input_budget=input_budget,
        )
        if current_receipt is None:
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
        snapshot_receipt = snapshot_input[0]
        if not _receipt_matches_snapshot(
            current_receipt,
            snapshot_receipt,
        ):
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET)
        checked_digest = snapshot_receipt.sha256.hex()
        matching_check = next(
            (check for check in full_file_checks if check.expected_sha256 == checked_digest),
            None,
        )
        if matching_check is not None:
            covered_count += 1
            covered.append(
                {
                    "path": rel_path,
                    "kind": entry.kind,
                    "status": "covered",
                    "check_id": matching_check.check_id,
                }
            )
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
        "covered": covered,
        "finding_count": len(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
