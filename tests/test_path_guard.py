"""Where: tests/test_path_guard.py
What: behavior tests for repository path-name guardrails.
Why: catch private artifacts and env-file leaks before content scanning is possible.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agent_guard.path_guard import PathGuardFinding, load_path_policy, scan_paths


def write(path: Path, text: str = "x\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def policy_file(tmp_path: Path) -> Path:
    payload = {
        "scan": {"include": ["."], "exclude": []},
        "policy": {
            "allowed_path_patterns": [r"(^|/)\.env\.example$"],
            "forbidden_path_patterns": [
                {
                    "id": "private_artifacts",
                    "severity": "high",
                    "pattern": r"(^|/)artifacts/private(/|$)",
                    "message": "private artifact directory must stay outside published/tracked paths",
                },
                {
                    "id": "bypass_corpus",
                    "severity": "high",
                    "pattern": r"(^|/)bypass[^/]*\.(jsonl|json|txt)$",
                    "message": "bypass corpus material must not be placed in repository paths",
                },
                {
                    "id": "red_session_log",
                    "severity": "high",
                    "pattern": r"(^|/)red_session_[^/]+",
                    "message": "red-team session logs must not be placed in repository paths",
                },
                {
                    "id": "env_file",
                    "severity": "high",
                    "pattern": r"(^|/)\.env(\..+)?$",
                    "message": "env files are forbidden except .env.example",
                },
            ],
        },
    }
    path = tmp_path / "path_policy.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def test_path_guard_blocks_private_artifacts_and_sensitive_names(tmp_path: Path) -> None:
    policy = load_path_policy(policy_file(tmp_path))
    write(tmp_path / "artifacts" / "private" / "bypass_cases.jsonl")
    write(tmp_path / "logs" / "red_session_001.txt")
    write(tmp_path / ".env.evil")
    write(tmp_path / ".env.example")

    findings, scanned = scan_paths(root=tmp_path, policy=policy)

    assert scanned >= 5
    assert {(item.path, item.rule_id) for item in findings} == {
        (".env.evil", "env_file"),
        ("artifacts/private", "private_artifacts"),
        ("artifacts/private/bypass_cases.jsonl", "private_artifacts"),
        ("logs/red_session_001.txt", "red_session_log"),
    }


def test_path_guard_allowlist_runs_before_deny_patterns(tmp_path: Path) -> None:
    policy = load_path_policy(policy_file(tmp_path))
    write(tmp_path / ".env.example")
    write(tmp_path / "nested" / ".env.example")

    findings, _ = scan_paths(root=tmp_path, policy=policy)

    assert findings == []


def test_path_guard_blocks_root_env_file(tmp_path: Path) -> None:
    policy = load_path_policy(policy_file(tmp_path))
    write(tmp_path / ".env")

    findings, _ = scan_paths(root=tmp_path, policy=policy)

    assert findings == [
        PathGuardFinding(
            path=".env",
            rule_id="env_file",
            severity="high",
            message="env files are forbidden except .env.example",
            matched_pattern=r"(^|/)\.env(\..+)?$",
        )
    ]


def test_path_guard_checks_symlink_name_without_following_target(tmp_path: Path) -> None:
    policy = load_path_policy(policy_file(tmp_path))
    outside = tmp_path.parent / "outside-private-target"
    outside.mkdir(exist_ok=True)
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts" / "private").symlink_to(outside, target_is_directory=True)

    findings, _ = scan_paths(root=tmp_path, policy=policy)

    assert any(item.path == "artifacts/private" for item in findings)


def test_malformed_path_policy_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- not-a-mapping\n", encoding="utf-8")

    with pytest.raises(ValueError):
        load_path_policy(bad)
