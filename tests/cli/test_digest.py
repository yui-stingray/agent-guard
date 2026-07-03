# Where: tests/cli/test_digest.py
# What: focused subprocess tests for the digest CLI group.
# Why: keep extracted digest subcommand coverage close to its module.

from __future__ import annotations

import json
from pathlib import Path

from tests.cli.helpers import assert_shared_envelope, run_cli, run_cli_from, sha256_text, write

def test_digest_cli_json_violation(tmp_path: Path) -> None:
    policy = tmp_path / "digest_policy.yaml"
    policy.write_text(
        "checks:\n"
        "  - id: readme_pin\n"
        "    path: README.md\n"
        "    sha256: '0000000000000000000000000000000000000000000000000000000000000000'\n",
        encoding="utf-8",
    )
    write(tmp_path / "README.md", "changed\n")

    result = run_cli("digest", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="digest",
        status="violation",
        exit_code=1,
        finding_count=1,
        scanned_count=1,
        scanned_unit="files",
    )
    assert payload["status"] == "violation"
    assert payload["scanner"] == "digest"
    assert payload["checked_files"] == 1
    assert payload["findings"][0]["check_id"] == "readme_pin"

def test_digest_cli_json_ok(tmp_path: Path) -> None:
    policy = tmp_path / "digest_policy.yaml"
    policy.write_text(
        "checks:\n"
        "  - id: readme_pin\n"
        "    path: README.md\n"
        "    sha256: '93d868f3b59590f611d7646894ce8def1cea5ad63a9af0d9ccc56e9bc6968c11'\n",
        encoding="utf-8",
    )
    write(tmp_path / "README.md", "safe\n")

    result = run_cli("digest", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="digest",
        status="ok",
        exit_code=0,
        finding_count=0,
        scanned_count=1,
        scanned_unit="files",
    )
    assert payload["checked_files"] == 1
    assert payload["policy"] == {"path": "digest_policy.yaml"}
    assert payload["findings"] == []

def test_digest_cli_policy_path_is_root_relative_from_external_cwd(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    cwd = tmp_path / "cwd"
    policy_arg = ".agent-guard/digest-policy.yaml"
    content = "safe\n"
    write(repo / "README.md", content)
    write(
        repo / policy_arg,
        "checks:\n"
        "  - id: readme_pin\n"
        "    path: README.md\n"
        f"    sha256: '{sha256_text(content)}'\n",
    )
    write(cwd / policy_arg, "not: [valid\n")

    result = run_cli_from(cwd, "digest", "check", "--root", str(repo), "--policy", policy_arg, "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="digest",
        status="ok",
        exit_code=0,
        finding_count=0,
        scanned_count=1,
        scanned_unit="files",
    )
    assert payload["policy"] == {"path": policy_arg}
    assert str(tmp_path) not in result.stdout

def test_digest_cli_json_error(tmp_path: Path) -> None:
    result = run_cli("digest", "check", "--root", str(tmp_path), "--policy", str(tmp_path / "missing.yaml"), "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="digest", status="error", exit_code=2, finding_count=0)
    assert str(tmp_path) not in payload["error"]
    assert payload["policy"] == {"path": "missing.yaml"}
