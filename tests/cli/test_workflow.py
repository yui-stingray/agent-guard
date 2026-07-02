# Where: tests/cli/test_workflow.py
# What: focused subprocess tests for the workflow CLI group.
# Why: keep extracted workflow subcommand coverage close to its module.

from __future__ import annotations

import json
from pathlib import Path

from tests.cli.helpers import assert_shared_envelope, run_cli, run_cli_from, write

def test_workflow_cli_json_ok(tmp_path: Path) -> None:
    write(tmp_path / ".agent-guard" / "context-policy.yaml", "{}\n")
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        """
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Run CLI smoke tests
        run: |
          python -m agent_guard.cli context check --root . --policy .agent-guard/context-policy.yaml --json
""",
    )
    policy = tmp_path / "workflow-policy.yaml"
    policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - id: context_policy\n"
        "    path: .agent-guard/context-policy.yaml\n"
        "workflow_checks:\n"
        "  - id: ci_smoke\n"
        "    path: .github/workflows/ci.yml\n"
        "    required_commands:\n"
        "      - id: context_guard\n"
        "        command: python -m agent_guard.cli context check\n",
        encoding="utf-8",
    )

    result = run_cli("workflow", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="workflow",
        status="ok",
        exit_code=0,
        finding_count=0,
        scanned_count=2,
        scanned_unit="checks",
    )
    assert payload["checked_items"] == 2
    assert payload["policy"] == {"path": "workflow-policy.yaml"}
    assert payload["findings"] == []

def test_workflow_cli_policy_path_is_root_relative_from_external_cwd(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    cwd = tmp_path / "cwd"
    policy_arg = ".agent-guard/workflow-policy.yaml"
    write(repo / ".agent-guard" / "context-policy.yaml", "{}\n")
    write(
        repo / ".github" / "workflows" / "ci.yml",
        """
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: python -m agent_guard.cli context check --root . --policy .agent-guard/context-policy.yaml --json
""",
    )
    write(
        repo / policy_arg,
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - id: context_policy\n"
        "    path: .agent-guard/context-policy.yaml\n"
        "workflow_checks:\n"
        "  - id: ci_smoke\n"
        "    path: .github/workflows/ci.yml\n"
        "    required_commands:\n"
        "      - id: context_guard\n"
        "        command: python -m agent_guard.cli context check\n",
    )
    write(cwd / policy_arg, "not: [valid\n")

    result = run_cli_from(cwd, "workflow", "check", "--root", str(repo), "--policy", policy_arg, "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="workflow",
        status="ok",
        exit_code=0,
        finding_count=0,
        scanned_count=2,
        scanned_unit="checks",
    )
    assert payload["policy"] == {"path": policy_arg}
    assert str(tmp_path) not in result.stdout

def test_workflow_cli_json_missing_required_file(tmp_path: Path) -> None:
    policy = tmp_path / "workflow-policy.yaml"
    policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - id: context_policy\n"
        "    path: .agent-guard/context-policy.yaml\n",
        encoding="utf-8",
    )

    result = run_cli("workflow", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="workflow",
        status="violation",
        exit_code=1,
        finding_count=1,
        scanned_count=1,
        scanned_unit="checks",
    )
    assert payload["findings"][0]["reason"] == "missing_required_file"
    assert payload["findings"][0]["file"] == ".agent-guard/context-policy.yaml"

def test_workflow_cli_json_missing_command_rejects_comment_echo_and_heredoc(tmp_path: Path) -> None:
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        """
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          # python -m agent_guard.cli digest check --root . --policy digest.yaml --json
          echo "python -m agent_guard.cli digest check --root . --policy digest.yaml --json"
          python - <<'PY'
          print("python -m agent_guard.cli digest check --root . --policy digest.yaml --json")
          PY
""",
    )
    policy = tmp_path / "workflow-policy.yaml"
    policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "workflow_checks:\n"
        "  - id: ci_smoke\n"
        "    path: .github/workflows/ci.yml\n"
        "    required_commands:\n"
        "      - id: digest_guard\n"
        "        command: python -m agent_guard.cli digest check\n",
        encoding="utf-8",
    )

    result = run_cli("workflow", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="workflow",
        status="violation",
        exit_code=1,
        finding_count=1,
        scanned_count=1,
        scanned_unit="checks",
    )
    finding_text = json.dumps(payload["findings"])
    assert payload["findings"][0]["reason"] == "missing_required_workflow_command"
    assert "python -m agent_guard.cli digest check" not in finding_text

def test_workflow_cli_json_malformed_workflow_yaml(tmp_path: Path) -> None:
    write(tmp_path / ".github" / "workflows" / "ci.yml", "jobs: [\n")
    policy = tmp_path / "workflow-policy.yaml"
    policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "workflow_checks:\n"
        "  - id: ci_smoke\n"
        "    path: .github/workflows/ci.yml\n"
        "    required_commands:\n"
        "      - python -m agent_guard.cli context check\n",
        encoding="utf-8",
    )

    result = run_cli("workflow", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="workflow", status="error", exit_code=2, finding_count=0)
    assert str(tmp_path) not in payload["error"]
    assert "workflow YAML is invalid" in payload["error"]

def test_workflow_cli_json_rejects_repo_escape(tmp_path: Path) -> None:
    policy = tmp_path / "workflow-policy.yaml"
    policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - id: outside\n"
        "    path: ../outside.yaml\n",
        encoding="utf-8",
    )

    result = run_cli("workflow", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="workflow", status="error", exit_code=2, finding_count=0)
    assert str(tmp_path) not in payload["error"]
    assert "path must not contain" in payload["error"]

def test_workflow_cli_json_empty_policy_is_error(tmp_path: Path) -> None:
    policy = tmp_path / "workflow-policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")

    result = run_cli("workflow", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="workflow", status="error", exit_code=2, finding_count=0)
    assert "schema_version" in payload["error"]

def test_workflow_cli_json_null_path_is_error(tmp_path: Path) -> None:
    policy = tmp_path / "workflow-policy.yaml"
    policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - id: context_policy\n"
        "    path:\n",
        encoding="utf-8",
    )

    result = run_cli("workflow", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="workflow", status="error", exit_code=2, finding_count=0)
    assert "must be a string" in payload["error"]
    assert "None" not in json.dumps(payload["findings"])

def test_workflow_cli_json_workflow_check_without_commands_is_error(tmp_path: Path) -> None:
    policy = tmp_path / "workflow-policy.yaml"
    policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "workflow_checks:\n"
        "  - id: ci_smoke\n"
        "    path: .github/workflows/ci.yml\n",
        encoding="utf-8",
    )

    result = run_cli("workflow", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="workflow", status="error", exit_code=2, finding_count=0)
    assert "required_commands must contain" in payload["error"]

def test_workflow_cli_json_error_scrubs_windows_policy_path(tmp_path: Path) -> None:
    windows_policy = r"C:\Users\maintainer\secret\workflow-policy.yaml"

    result = run_cli("workflow", "check", "--root", str(tmp_path), "--policy", windows_policy, "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="workflow", status="error", exit_code=2, finding_count=0)
    assert payload["policy"] == {"path": "<external-policy>"}
    assert "C:\\Users" not in payload["error"]
    assert "maintainer" not in payload["error"]
