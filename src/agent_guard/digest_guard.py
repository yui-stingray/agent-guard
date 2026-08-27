"""Where: src/agent_guard/digest_guard.py
What: static SHA-256 pin verifier for repository files.
Why: catch drift in governance docs or safety-critical scripts before publication.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bounded_scan import MAX_ISOLATED_MESSAGE_BYTES
from .bounded_repo_reader import (
    BoundedRepoContainmentError,
    BoundedRepoFileNotFoundError,
    BoundedRepoLimitError,
    BoundedRepoReadError,
    DistinctInputBudget,
    read_bounded_bytes,
    read_repo_bound_bytes,
)
from .bounded_yaml import (
    BoundedYamlInvalidError,
    BoundedYamlLimitError,
    load_bounded_yaml,
)


ERROR_DIGEST_POLICY_INVALID = "digest policy YAML is not parseable"
ERROR_DIGEST_POLICY_LIMIT = "digest policy exceeds configured limits"
ERROR_DIGEST_SCAN_LIMIT = "digest scan exceeds configured limits"
ERROR_DIGEST_SCAN_TARGET = "digest scan target must stay under repo root"
MAX_DIGEST_POLICY_BYTES = 256 * 1024
MAX_DIGEST_CHECKS = 10_000
MAX_DIGEST_FILE_BYTES = 1_048_576
MAX_DIGEST_DISTINCT_INPUT_BYTES = 16 * 1024 * 1024
MAX_DIGEST_AGGREGATE_RESULT_BYTES = MAX_ISOLATED_MESSAGE_BYTES // 2


@dataclass(frozen=True)
class DigestCheck:
    check_id: str
    path: str
    expected_sha256: str
    start_line: int


@dataclass(frozen=True)
class DigestGuardFinding:
    check_id: str
    path: str
    expected_sha256: str
    actual_sha256: str | None
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "path": self.path,
            "expected_sha256": self.expected_sha256,
            "actual_sha256": self.actual_sha256,
            "message": self.message,
        }


def _canonical_json_size(value: object) -> int:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return len(rendered.encode("utf-8", errors="surrogatepass"))
    except (MemoryError, OverflowError, RecursionError, TypeError, ValueError):
        raise ValueError(ERROR_DIGEST_SCAN_LIMIT) from None


class _DigestFindingResultBudget:
    def __init__(self) -> None:
        self.used = _canonical_json_size([])
        self.count = 0
        if self.used > MAX_DIGEST_AGGREGATE_RESULT_BYTES:
            raise ValueError(ERROR_DIGEST_SCAN_LIMIT)

    def add(self, finding: DigestGuardFinding) -> None:
        amount = _canonical_json_size(finding.to_dict()) + (1 if self.count else 0)
        if amount > MAX_DIGEST_AGGREGATE_RESULT_BYTES - self.used:
            raise ValueError(ERROR_DIGEST_SCAN_LIMIT)
        self.used += amount
        self.count += 1


def load_digest_policy(
    path: Path,
    *,
    _input_budget: DistinctInputBudget | None = None,
) -> dict[str, Any]:
    try:
        opened = read_bounded_bytes(path, max_bytes=MAX_DIGEST_POLICY_BYTES)
        if _input_budget is not None:
            _input_budget.charge(opened)
        text = opened.data.decode("utf-8")
    except BoundedRepoFileNotFoundError:
        raise FileNotFoundError(f"policy file not found: {path}") from None
    except BoundedRepoLimitError:
        raise ValueError(ERROR_DIGEST_POLICY_LIMIT) from None
    except (BoundedRepoContainmentError, BoundedRepoReadError, UnicodeDecodeError):
        raise ValueError(ERROR_DIGEST_POLICY_INVALID) from None
    try:
        loaded = load_bounded_yaml(text) or {}
    except BoundedYamlLimitError:
        raise ValueError(ERROR_DIGEST_POLICY_LIMIT) from None
    except BoundedYamlInvalidError:
        raise ValueError(ERROR_DIGEST_POLICY_INVALID) from None
    if not isinstance(loaded, dict):
        raise ValueError(f"policy file must be YAML object: {path}")
    return loaded


def normalize_checks(raw: Any) -> list[DigestCheck]:
    if not isinstance(raw, list):
        raise ValueError("checks must be a list")
    if len(raw) > MAX_DIGEST_CHECKS:
        raise ValueError(ERROR_DIGEST_SCAN_LIMIT)

    checks: list[DigestCheck] = []
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"checks[{idx}] must be an object")

        check_id = str(item.get("id", f"digest_check_{idx}")).strip() or f"digest_check_{idx}"
        path = str(item.get("path", "")).strip()
        expected_sha256 = str(item.get("sha256", "")).strip().lower()
        start_line = int(item.get("start_line", 1))

        if not path:
            raise ValueError(f"{check_id}: path is required")
        if len(expected_sha256) != 64 or any(char not in "0123456789abcdef" for char in expected_sha256):
            raise ValueError(f"{check_id}: sha256 must be 64 lowercase hex characters")
        if start_line < 1:
            raise ValueError(f"{check_id}: start_line must be >= 1")

        checks.append(
            DigestCheck(
                check_id=check_id,
                path=path,
                expected_sha256=expected_sha256,
                start_line=start_line,
            )
        )
    return checks


def content_for_digest(
    path: Path,
    start_line: int,
    *,
    root: Path | None = None,
    max_bytes: int = MAX_DIGEST_FILE_BYTES,
    _input_budget: DistinctInputBudget | None = None,
) -> bytes:
    allowed_root = path.parent if root is None else root
    opened = read_repo_bound_bytes(path, allowed_root, max_bytes=max_bytes)
    if _input_budget is not None:
        _input_budget.charge(opened)
    data = opened.data
    if start_line == 1:
        return data

    lines = data.splitlines(keepends=True)
    return b"".join(lines[start_line - 1 :])


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def scan_digests(
    *,
    root: Path,
    policy: dict[str, Any],
    _input_budget: DistinctInputBudget | None = None,
) -> tuple[list[DigestGuardFinding], int]:
    try:
        root = root.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError(ERROR_DIGEST_SCAN_TARGET) from None
    checks = normalize_checks(policy.get("checks", []))
    input_budget = _input_budget or DistinctInputBudget(
        max_bytes=MAX_DIGEST_DISTINCT_INPUT_BYTES
    )

    findings: list[DigestGuardFinding] = []
    result_budget = _DigestFindingResultBudget()
    for check in checks:
        target = Path(os.path.abspath(root / check.path))
        try:
            rel = target.relative_to(root)
        except ValueError:
            raise ValueError(f"{check.check_id}: path escapes root: {check.path}") from None
        try:
            content = content_for_digest(
                target,
                check.start_line,
                root=root,
                _input_budget=input_budget,
            )
        except BoundedRepoFileNotFoundError:
            finding = DigestGuardFinding(
                check_id=check.check_id,
                path=rel.as_posix(),
                expected_sha256=check.expected_sha256,
                actual_sha256=None,
                message="pinned file is missing",
            )
            result_budget.add(finding)
            findings.append(finding)
            continue
        except BoundedRepoContainmentError:
            raise ValueError(f"{check.check_id}: path escapes root: {check.path}") from None
        except BoundedRepoLimitError:
            raise ValueError(ERROR_DIGEST_SCAN_LIMIT) from None
        except BoundedRepoReadError:
            raise ValueError(ERROR_DIGEST_SCAN_TARGET) from None

        actual = sha256_hex(content)
        if actual != check.expected_sha256:
            finding = DigestGuardFinding(
                check_id=check.check_id,
                path=rel.as_posix(),
                expected_sha256=check.expected_sha256,
                actual_sha256=actual,
                message="sha256 digest mismatch",
            )
            result_budget.add(finding)
            findings.append(finding)
    return findings, len(checks)
