"""Where: tests/test_digest_guard.py
What: behavior tests for SHA-256 digest pin verification.
Why: preserve B9-style static integrity checks as a reusable guard scanner.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from agent_guard.digest_guard import DigestGuardFinding, load_digest_policy, scan_digests


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def policy_file(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "digest_policy.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def test_digest_guard_accepts_matching_full_file_digest(tmp_path: Path) -> None:
    write(tmp_path / "constitution.md", "front\nbody\n")
    policy = load_digest_policy(
        policy_file(
            tmp_path,
            {
                "checks": [
                    {
                        "id": "constitution_full",
                        "path": "constitution.md",
                        "sha256": sha256_text("front\nbody\n"),
                    }
                ]
            },
        )
    )

    findings, checked = scan_digests(root=tmp_path, policy=policy)

    assert checked == 1
    assert findings == []


def test_digest_guard_reports_mismatch(tmp_path: Path) -> None:
    write(tmp_path / "constitution.md", "changed\n")
    expected = sha256_text("original\n")
    policy = load_digest_policy(
        policy_file(
            tmp_path,
            {"checks": [{"id": "constitution_full", "path": "constitution.md", "sha256": expected}]},
        )
    )

    findings, checked = scan_digests(root=tmp_path, policy=policy)

    assert checked == 1
    assert findings == [
        DigestGuardFinding(
            check_id="constitution_full",
            path="constitution.md",
            expected_sha256=expected,
            actual_sha256=sha256_text("changed\n"),
            message="sha256 digest mismatch",
        )
    ]


def test_digest_guard_supports_content_digest_from_start_line(tmp_path: Path) -> None:
    write(tmp_path / "constitution.md", "---\nstatus: draft\n---\nbody\n")
    policy = load_digest_policy(
        policy_file(
            tmp_path,
            {
                "checks": [
                    {
                        "id": "constitution_content",
                        "path": "constitution.md",
                        "sha256": sha256_text("body\n"),
                        "start_line": 4,
                    }
                ]
            },
        )
    )

    findings, checked = scan_digests(root=tmp_path, policy=policy)

    assert checked == 1
    assert findings == []


def test_digest_guard_reports_missing_file(tmp_path: Path) -> None:
    expected = "0" * 64
    policy = load_digest_policy(
        policy_file(
            tmp_path,
            {"checks": [{"id": "missing_pin", "path": "missing.md", "sha256": expected}]},
        )
    )

    findings, _ = scan_digests(root=tmp_path, policy=policy)

    assert findings == [
        DigestGuardFinding(
            check_id="missing_pin",
            path="missing.md",
            expected_sha256=expected,
            actual_sha256=None,
            message="pinned file is missing",
        )
    ]


def test_digest_guard_rejects_path_escape(tmp_path: Path) -> None:
    policy = load_digest_policy(
        policy_file(
            tmp_path,
            {"checks": [{"id": "escape", "path": "../outside.md", "sha256": "0" * 64}]},
        )
    )

    with pytest.raises(ValueError, match="path escapes root"):
        scan_digests(root=tmp_path, policy=policy)


def test_digest_guard_rejects_malformed_policy(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- not-a-mapping\n", encoding="utf-8")

    with pytest.raises(ValueError, match="policy file must be YAML object"):
        load_digest_policy(bad)
