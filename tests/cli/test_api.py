# Where: tests/cli/test_api.py
# What: focused subprocess tests for the api CLI group.
# Why: keep extracted API subcommand coverage close to its module.

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import agent_guard.cli.api as api_cli
from agent_guard.api_guard import ApiGuardFinding

from tests.cli.helpers import assert_shared_envelope, run_cli, run_cli_from, write


def test_api_cli_json_ok(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "scan:\n  include:\n    - src\n  exclude: []\npolicy:\n  allowed_api_patterns: []\n  forbidden_api_patterns:\n    - '^https://api\\.openai\\.com/'\n",
        encoding="utf-8",
    )
    write(tmp_path / "src" / "ok.py", 'URL = "https://example.com"\n')

    result = run_cli("api", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="api",
        status="ok",
        exit_code=0,
        finding_count=0,
        scanned_count=1,
        scanned_unit="files",
    )
    assert payload["policy"] == {"path": "policy.yaml"}
    assert payload["findings"] == []

def test_api_cli_json_violation(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "scan:\n  include:\n    - src\n  exclude: []\npolicy:\n  allowed_api_patterns: []\n  forbidden_api_patterns:\n    - '^https://api\\.openai\\.com/'\n",
        encoding="utf-8",
    )
    write(tmp_path / "src" / "bad.py", 'URL = "https://api.openai.com/v1/responses"\n')

    result = run_cli("api", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="api",
        status="violation",
        exit_code=1,
        finding_count=1,
        scanned_count=1,
        scanned_unit="files",
    )
    assert payload["status"] == "violation"
    assert payload["scanner"] == "api"
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["path"] == "src/bad.py"

def test_api_cli_uses_count_from_the_single_scan_operation(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "scan:\n  include:\n    - src\n  exclude: []\npolicy:\n  allowed_api_patterns: []\n  forbidden_api_patterns: []\n",
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    operation_calls = 0

    def fake_scan_urls_with_count(*, root: Path, policy: dict[str, object]):
        nonlocal operation_calls
        operation_calls += 1
        assert root == tmp_path.resolve()
        assert policy["scan"] == {"include": ["src"], "exclude": []}
        return (
            [
                ApiGuardFinding(
                    path="src/bad.py",
                    line=1,
                    url="https://api.openai.com/v1/responses",
                    matched_forbidden_pattern=r"^https://api\.openai\.com/",
                )
            ],
            7,
        )

    def fail_outside_operation_walk(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("API CLI must not walk outside the isolated scan operation")

    monkeypatch.setattr(api_cli, "scan_urls_with_count", fake_scan_urls_with_count)
    monkeypatch.setattr(Path, "rglob", fail_outside_operation_walk)

    exit_code = api_cli.run_api_check(
        argparse.Namespace(
            root=str(tmp_path),
            policy=str(policy),
            json=True,
        )
    )

    assert exit_code == 1
    assert operation_calls == 1
    payload = json.loads(capsys.readouterr().out)
    assert_shared_envelope(
        payload,
        scanner="api",
        status="violation",
        exit_code=1,
        finding_count=1,
        scanned_count=7,
        scanned_unit="files",
    )
    assert payload["findings"][0]["path"] == "src/bad.py"

@pytest.mark.parametrize(
    ("url", "forbidden_pattern"),
    [
        ("https://api.openai.com/v1/responses", r"^https://api\.openai\.com/"),
        ("http://api.openai.com/v1/responses", r"^https?://api\.openai\.com/"),
    ],
    ids=["https", "http"],
)
def test_api_cli_outputs_public_safe_findings(
    tmp_path: Path,
    url: str,
    forbidden_pattern: str,
) -> None:
    secret_like = "sk-" + ("a" * 24)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "scan:\n"
        "  include:\n"
        "    - src\n"
        "  exclude: []\n"
        "policy:\n"
        "  allowed_api_patterns: []\n"
        "  forbidden_api_patterns:\n"
        f"    - '{forbidden_pattern}'\n",
        encoding="utf-8",
    )
    write(
        tmp_path / "src" / secret_like / "bad.py",
        f'URL = "{url}?key={secret_like}"\n',
    )

    json_result = run_cli("api", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")
    text_result = run_cli("api", "check", "--root", str(tmp_path), "--policy", str(policy))

    assert json_result.returncode == 1
    assert text_result.returncode == 1
    payload = json.loads(json_result.stdout)
    assert payload["findings"][0]["path"] == "src/<redacted>/bad.py"
    assert payload["findings"][0]["line"] == 1
    assert payload["findings"][0]["category"] == "forbidden_api"
    assert "url" not in payload["findings"][0]
    assert "matched_forbidden_pattern" not in payload["findings"][0]
    for output in (
        json_result.stdout,
        json_result.stderr,
        text_result.stdout,
        text_result.stderr,
    ):
        assert secret_like not in output
        assert "matched_forbidden_pattern" not in output
        assert "api.openai.com" not in output

def test_api_cli_json_error(tmp_path: Path) -> None:
    result = run_cli("api", "check", "--root", str(tmp_path), "--policy", str(tmp_path / "missing.yaml"), "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="api", status="error", exit_code=2, finding_count=0)
    assert payload["status"] == "error"
    assert payload["scanner"] == "api"
    assert str(tmp_path) not in payload["error"]
    assert payload["policy"] == {"path": "missing.yaml"}


def test_api_cli_rejects_yaml_merge_with_sanitized_policy_limit(
    tmp_path: Path,
) -> None:
    sentinel = "synthetic-api-cli-yaml-sentinel"
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        f"base: &base {{marker: {sentinel}}}\n"
        "scan:\n"
        "  <<: *base\n",
        encoding="utf-8",
    )

    result = run_cli(
        "api",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(policy),
        "--json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="api",
        status="error",
        exit_code=2,
        finding_count=0,
    )
    assert payload["error"] == "api policy exceeds configured limits"
    assert sentinel not in result.stdout
    assert str(tmp_path) not in payload["error"]

def test_api_cli_json_error_scrubs_windows_policy_path(tmp_path: Path) -> None:
    windows_policy = r"C:\Users\maintainer\secret\policy.yaml"

    result = run_cli("api", "check", "--root", str(tmp_path), "--policy", windows_policy, "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="api", status="error", exit_code=2, finding_count=0)
    assert payload["policy"] == {"path": "<external-policy>"}
    assert "C:\\Users" not in payload["error"]
    assert "maintainer" not in payload["error"]

def test_api_cli_json_error_scrubs_external_include_path_with_spaces(tmp_path: Path) -> None:
    sentinel = "sk-" + ("a" * 24)
    outside = tmp_path.parent / f"{tmp_path.name}-{sentinel}-external-include"
    write(outside / "bad.py", 'URL = "https://api.openai.com/v1/responses"\n')
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "scan:\n"
        "  include:\n"
        f"    - {str(outside / 'bad.py')!r}\n"
        "  exclude: []\n"
        "policy:\n"
        "  allowed_api_patterns: []\n"
        "  forbidden_api_patterns:\n"
        "    - '^https://api\\.openai\\.com/'\n",
        encoding="utf-8",
    )

    json_result = run_cli("api", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")
    text_result = run_cli("api", "check", "--root", str(tmp_path), "--policy", str(policy))

    assert json_result.returncode == 2
    assert text_result.returncode == 2
    payload = json.loads(json_result.stdout)
    assert_shared_envelope(payload, scanner="api", status="error", exit_code=2, finding_count=0)
    assert payload["error"] == "api scan target must stay under repo root"
    assert text_result.stdout.strip() == "ERROR: api scan target must stay under repo root"
    for result in (json_result, text_result):
        for output in (result.stdout, result.stderr):
            assert sentinel not in output
            assert str(outside) not in output

def test_api_cli_policy_path_is_root_relative_from_external_cwd(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    cwd = tmp_path / "cwd"
    policy_arg = ".agent-guard/api-policy.yaml"
    write(
        repo / policy_arg,
        "scan:\n"
        "  include:\n"
        "    - src\n"
        "  exclude: []\n"
        "policy:\n"
        "  allowed_api_patterns: []\n"
        "  forbidden_api_patterns:\n"
        "    - '^https://api\\.openai\\.com/'\n",
    )
    write(repo / "src" / "ok.py", 'URL = "https://example.com"\n')
    write(cwd / policy_arg, "not: [valid\n")

    result = run_cli_from(cwd, "api", "check", "--root", str(repo), "--policy", policy_arg, "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="api",
        status="ok",
        exit_code=0,
        finding_count=0,
        scanned_count=1,
        scanned_unit="files",
    )
    assert payload["policy"] == {"path": policy_arg}
    assert str(tmp_path) not in result.stdout
