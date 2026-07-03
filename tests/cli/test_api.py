# Where: tests/cli/test_api.py
# What: focused subprocess tests for the api CLI group.
# Why: keep extracted API subcommand coverage close to its module.

from __future__ import annotations

import json
from pathlib import Path

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

def test_api_cli_outputs_public_safe_findings(tmp_path: Path) -> None:
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
        "    - '^https://api\\.openai\\.com/'\n",
        encoding="utf-8",
    )
    write(
        tmp_path / "src" / secret_like / "bad.py",
        f'URL = "https://api.openai.com/v1/responses?key={secret_like}"\n',
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
    for output in (json_result.stdout, text_result.stdout):
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
    outside = tmp_path.parent / f"{tmp_path.name} external include"
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

    result = run_cli("api", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="api", status="error", exit_code=2, finding_count=0)
    assert str(outside) not in payload["error"]
    assert payload["error"].count("<absolute-path>") >= 1

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
