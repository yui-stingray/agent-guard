"""Where: tests/test_api_guard.py
What: behavior tests for the extracted API surface guard.
Why: preserve ai-company's architecture_guard semantics during extraction.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agent_guard.api_guard import ApiGuardFinding, load_yaml_policy, scan_urls


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def policy_file(tmp_path: Path, *, include: list[str], exclude: list[str], allowed: list[str], forbidden: list[str]) -> Path:
    payload = {
        "scan": {"include": include, "exclude": exclude},
        "policy": {
            "allowed_api_patterns": allowed,
            "forbidden_api_patterns": forbidden,
        },
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def basic_policy(tmp_path: Path) -> Path:
    return policy_file(
        tmp_path,
        include=["src", "scripts"],
        exclude=[],
        allowed=[r"^https://ntfy\.sh/"],
        forbidden=[r"^https://api\.openai\.com/", r"^https://api\.anthropic\.com/"],
    )


def test_allowed_url_passes(tmp_path: Path) -> None:
    policy_path = basic_policy(tmp_path)
    write(tmp_path / "src" / "ok.py", 'URL = "https://ntfy.sh/example"\n')

    findings = scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert findings == []


def test_forbidden_url_fails(tmp_path: Path) -> None:
    policy_path = basic_policy(tmp_path)
    write(tmp_path / "src" / "bad.py", 'URL = "https://api.openai.com/v1/responses"\n')

    findings = scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert findings == [
        ApiGuardFinding(
            path="src/bad.py",
            line=1,
            url="https://api.openai.com/v1/responses",
            matched_forbidden_pattern=r"^https://api\.openai\.com/",
        )
    ]


def test_allowed_rule_wins_over_broader_forbidden_prefix(tmp_path: Path) -> None:
    policy_path = policy_file(
        tmp_path,
        include=["src"],
        exclude=[],
        allowed=[r"^https://api\.anthropic\.com/api/oauth/usage$"],
        forbidden=[r"^https://api\.anthropic\.com/"],
    )
    write(tmp_path / "src" / "usage.py", 'URL = "https://api.anthropic.com/api/oauth/usage"\n')

    findings = scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert findings == []


def test_include_exclude_paths_are_honored(tmp_path: Path) -> None:
    policy_path = policy_file(
        tmp_path,
        include=["src", "scripts"],
        exclude=["scripts/generated"],
        allowed=[],
        forbidden=[r"^https://api\.openai\.com/"],
    )
    write(tmp_path / "src" / "bad.py", 'URL = "https://api.openai.com/v1/responses"\n')
    write(tmp_path / "scripts" / "generated" / "skip.py", 'URL = "https://api.openai.com/v1/responses"\n')

    findings = scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert [finding.path for finding in findings] == ["src/bad.py"]


def test_binary_file_is_skipped(tmp_path: Path) -> None:
    policy_path = basic_policy(tmp_path)
    binary_path = tmp_path / "src" / "blob.bin"
    binary_path.parent.mkdir(parents=True, exist_ok=True)
    binary_path.write_bytes(b"\x00\xff\x00https://api.openai.com/")

    findings = scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert findings == []


def test_missing_policy_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_yaml_policy(tmp_path / "missing.yaml")


def test_malformed_policy_object_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- not-a-mapping\n", encoding="utf-8")

    with pytest.raises(ValueError):
        load_yaml_policy(bad)
