# Where: tests/cli/test_path.py
# What: focused subprocess tests for the path CLI group.
# Why: keep extracted path subcommand coverage close to its module.

from __future__ import annotations

import json
from pathlib import Path

from tests.cli.helpers import ROOT, assert_shared_envelope, run_cli, run_cli_from, write


def test_repo_root_path_policies_match_ci_self_dogfood() -> None:
    for policy_arg in (
        ".agent-guard/path-policy.yaml",
        "examples/ai_resilience_path_policy.yaml",
    ):
        result = run_cli("path", "check", "--root", str(ROOT), "--policy", policy_arg, "--json")

        assert result.returncode == 0, result.stdout + result.stderr
        payload = json.loads(result.stdout)
        assert_shared_envelope(
            payload,
            scanner="path",
            status="ok",
            exit_code=0,
            finding_count=0,
            scanned_unit="paths",
        )
        assert payload["findings"] == []
        assert payload["scanned_paths"] == payload["summary"]["scanned_count"]


def test_path_cli_json_violation(tmp_path: Path) -> None:
    policy = tmp_path / "path_policy.yaml"
    policy.write_text(
        "scan:\n"
        "  include:\n"
        "    - .\n"
        "  exclude: []\n"
        "policy:\n"
        "  allowed_path_patterns:\n"
        "    - '(^|/)\\.env\\.example$'\n"
        "  forbidden_path_patterns:\n"
        "    - id: env_file\n"
        "      severity: high\n"
        "      pattern: '(^|/)\\.env(\\..+)?$'\n"
        "      message: 'env files are forbidden except .env.example'\n",
        encoding="utf-8",
    )
    write(tmp_path / ".env.evil", "TOKEN=x\n")
    write(tmp_path / ".env.example", "TOKEN=\n")

    result = run_cli("path", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="path",
        status="violation",
        exit_code=1,
        finding_count=1,
        scanned_unit="paths",
    )
    assert payload["status"] == "violation"
    assert payload["scanner"] == "path"
    assert payload["finding_count"] == 1
    assert payload["scanned_paths"] == payload["summary"]["scanned_count"]
    assert payload["findings"][0]["path"] == ".env.evil"

def test_path_cli_json_ok(tmp_path: Path) -> None:
    policy = tmp_path / "path_policy.yaml"
    policy.write_text(
        "scan:\n  include:\n    - .\n  exclude: []\npolicy:\n  forbidden_path_patterns: []\n",
        encoding="utf-8",
    )
    write(tmp_path / "README.md", "safe\n")

    result = run_cli("path", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="path", status="ok", exit_code=0, finding_count=0, scanned_unit="paths")
    assert payload["policy"] == {"path": "path_policy.yaml"}
    assert payload["findings"] == []

def test_path_cli_policy_path_is_root_relative_from_external_cwd(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    cwd = tmp_path / "cwd"
    policy_arg = ".agent-guard/path-policy.yaml"
    write(
        repo / policy_arg,
        "scan:\n"
        "  include:\n"
        "    - .\n"
        "  exclude: []\n"
        "policy:\n"
        "  forbidden_path_patterns: []\n",
    )
    write(repo / "README.md", "safe\n")
    write(cwd / policy_arg, "not: [valid\n")

    result = run_cli_from(cwd, "path", "check", "--root", str(repo), "--policy", policy_arg, "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="path", status="ok", exit_code=0, finding_count=0, scanned_unit="paths")
    assert payload["policy"] == {"path": policy_arg}
    assert str(tmp_path) not in result.stdout

def test_path_cli_json_error(tmp_path: Path) -> None:
    result = run_cli("path", "check", "--root", str(tmp_path), "--policy", str(tmp_path / "missing.yaml"), "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="path", status="error", exit_code=2, finding_count=0)
    assert str(tmp_path) not in payload["error"]
    assert payload["policy"] == {"path": "missing.yaml"}


def test_path_cli_rejects_yaml_merge_with_sanitized_policy_limit(
    tmp_path: Path,
) -> None:
    sentinel = "synthetic-path-cli-yaml-sentinel"
    policy = tmp_path / "path_policy.yaml"
    policy.write_text(
        f"base: &base {{marker: {sentinel}}}\n"
        "policy:\n"
        "  <<: *base\n",
        encoding="utf-8",
    )

    result = run_cli(
        "path",
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
        scanner="path",
        status="error",
        exit_code=2,
        finding_count=0,
    )
    assert payload["error"] == "path policy exceeds configured limits"
    assert sentinel not in result.stdout
    assert str(tmp_path) not in payload["error"]


def test_path_cli_rejects_external_include_without_leaking_target(tmp_path: Path) -> None:
    sentinel = "sk-" + ("h" * 24)
    outside = tmp_path.parent / f"{tmp_path.name}-{sentinel}-outside"
    write(outside / "synthetic-marker.txt", "safe\n")
    policy = tmp_path / "path_policy.yaml"
    policy.write_text(
        "scan:\n"
        "  include:\n"
        f"    - {str(outside)!r}\n"
        "  exclude: []\n"
        "policy:\n"
        "  allowed_path_patterns: []\n"
        "  forbidden_path_patterns: []\n",
        encoding="utf-8",
    )

    json_result = run_cli("path", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")
    text_result = run_cli("path", "check", "--root", str(tmp_path), "--policy", str(policy))

    for result in (json_result, text_result):
        assert result.returncode == 2
        for output in (result.stdout, result.stderr):
            assert sentinel not in output
            assert str(outside) not in output
    payload = json.loads(json_result.stdout)
    assert payload["error"] == "path scan target must stay under repo root"
    assert text_result.stdout.strip() == "ERROR: path scan target must stay under repo root"
