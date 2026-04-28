"""Where: src/agent_guard/digest_guard.py
What: static SHA-256 pin verifier for repository files.
Why: catch drift in governance docs or safety-critical scripts before publication.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


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


def load_digest_policy(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")

    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"policy file must be YAML object: {path}")
    return loaded


def normalize_checks(raw: Any) -> list[DigestCheck]:
    if not isinstance(raw, list):
        raise ValueError("checks must be a list")

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


def content_for_digest(path: Path, start_line: int) -> bytes:
    data = path.read_bytes()
    if start_line == 1:
        return data

    lines = data.splitlines(keepends=True)
    return b"".join(lines[start_line - 1 :])


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def scan_digests(*, root: Path, policy: dict[str, Any]) -> tuple[list[DigestGuardFinding], int]:
    root = root.resolve()
    checks = normalize_checks(policy.get("checks", []))

    findings: list[DigestGuardFinding] = []
    for check in checks:
        target = (root / check.path).resolve()
        try:
            rel = target.relative_to(root)
        except ValueError:
            raise ValueError(f"{check.check_id}: path escapes root: {check.path}") from None

        if not target.is_file():
            findings.append(
                DigestGuardFinding(
                    check_id=check.check_id,
                    path=rel.as_posix(),
                    expected_sha256=check.expected_sha256,
                    actual_sha256=None,
                    message="pinned file is missing",
                )
            )
            continue

        actual = sha256_hex(content_for_digest(target, check.start_line))
        if actual != check.expected_sha256:
            findings.append(
                DigestGuardFinding(
                    check_id=check.check_id,
                    path=rel.as_posix(),
                    expected_sha256=check.expected_sha256,
                    actual_sha256=actual,
                    message="sha256 digest mismatch",
                )
            )
    return findings, len(checks)
