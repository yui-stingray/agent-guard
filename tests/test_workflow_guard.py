"""Where: tests/test_workflow_guard.py
What: unit tests for workflow drift guard parsing and matching.
Why: keep workflow evidence deterministic without shell execution or raw log output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_guard.workflow_guard import command_line_matches_required, scan_workflow_policy


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_scan_workflow_policy_ok_with_multiline_run(tmp_path: Path) -> None:
    write(tmp_path / ".agent-guard" / "context-policy.yaml", "{}\n")
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        """
name: ci
on: [push]
jobs:
  test:
    name: pytest
    runs-on: ubuntu-latest
    steps:
      - name: Run CLI smoke tests
        run: |
          # documented but ignored
          echo "python -m agent_guard.cli digest check"
          python - <<'PY'
          print("python -m agent_guard.cli path check")
          PY
          python -m agent_guard.cli context check --root . --policy .agent-guard/context-policy.yaml --json
          python -m agent_guard.cli path check --root . --policy examples/path-policy.yaml --json
""",
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "required_files": [
            {"id": "context_policy", "path": ".agent-guard/context-policy.yaml"},
        ],
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": [
                    {"id": "context_guard", "command": "python -m agent_guard.cli context check"},
                    {"id": "path_guard", "command": "python -m agent_guard.cli path check"},
                ],
            }
        ],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert findings == []
    assert checked_items == 3


def test_scan_workflow_policy_rejects_echo_comment_and_heredoc_false_positives(tmp_path: Path) -> None:
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
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": [
                    {"id": "digest_guard", "command": "python -m agent_guard.cli digest check"},
                ],
            }
        ],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert checked_items == 1
    assert len(findings) == 1
    assert findings[0].reason == "missing_required_workflow_command"
    assert findings[0].to_dict() == {
        "rule_id": "digest_guard",
        "severity": "high",
        "file": ".github/workflows/ci.yml",
        "message": "required workflow command is missing",
        "reason": "missing_required_workflow_command",
        "workflow_id": "ci_smoke",
        "requirement_id": "digest_guard",
    }


def test_scan_workflow_policy_finds_commands_inside_parallel_steps(tmp_path: Path) -> None:
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        """
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Independent guard checks
        parallel:
          - name: Context guard
            run: python -m agent_guard.cli context check --root . --policy .agent-guard/context-policy.yaml --json
          - name: Surface inventory
            run: python -m agent_guard.cli surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json
      - name: Final report
        run: python -m agent_guard.cli report --root . --context-policy .agent-guard/context-policy.yaml --format json
""",
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": [
                    {"id": "context_guard", "command": "python -m agent_guard.cli context check"},
                    {"id": "surface_inventory", "command": "python -m agent_guard.cli surface inventory"},
                    {"id": "report", "command": "python -m agent_guard.cli report"},
                ],
            }
        ],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert findings == []
    assert checked_items == 3


def test_context_lock_coverage_requirement_needs_digest_policy_option(tmp_path: Path) -> None:
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        """
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: python -m agent_guard.cli context lock --root . --policy .agent-guard/context-policy.yaml --check --json
""",
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_self_dogfood",
                "path": ".github/workflows/ci.yml",
                "required_commands": [
                    {
                        "id": "context_lock_coverage",
                        "command": (
                            "python -m agent_guard.cli context lock --root . "
                            "--policy .agent-guard/context-policy.yaml --check "
                            "--digest-policy .agent-guard/context-digest-policy.yaml"
                        ),
                    },
                ],
            },
        ],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert checked_items == 1
    assert len(findings) == 1
    assert findings[0].to_dict() == {
        "rule_id": "context_lock_coverage",
        "severity": "high",
        "file": ".github/workflows/ci.yml",
        "message": "required workflow command is missing",
        "reason": "missing_required_workflow_command",
        "workflow_id": "ci_self_dogfood",
        "requirement_id": "context_lock_coverage",
    }


def test_command_match_requires_command_segment_start() -> None:
    assert command_line_matches_required(
        "python -m agent_guard.cli context check --root . --json",
        "python -m agent_guard.cli context check",
    )
    assert command_line_matches_required(
        "python -m agent_guard.cli path check --json && python -m agent_guard.cli digest check --json",
        "python -m agent_guard.cli digest check",
    )
    assert not command_line_matches_required(
        "echo python -m agent_guard.cli context check",
        "python -m agent_guard.cli context check",
    )
    assert not command_line_matches_required(
        "python -m agent_guard.cli context check --help",
        "python -m agent_guard.cli context check",
    )
    assert not command_line_matches_required(
        "python -m agent_guard.cli context check --root . --policy p.yaml --json || true",
        "python -m agent_guard.cli context check",
    )
    assert not command_line_matches_required(
        "python -m agent_guard.cli context check --root . --policy p.yaml --json && echo ok || true",
        "python -m agent_guard.cli context check",
    )
    assert not command_line_matches_required(
        "python -m agent_guard.cli context checker",
        "python -m agent_guard.cli context check",
    )


def test_scan_workflow_policy_reports_missing_required_file(tmp_path: Path) -> None:
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "required_files": [{"id": "context_policy", "path": ".agent-guard/context-policy.yaml"}],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert checked_items == 1
    assert len(findings) == 1
    assert findings[0].to_dict()["reason"] == "missing_required_file"
    assert findings[0].to_dict()["file"] == ".agent-guard/context-policy.yaml"


def test_scan_workflow_policy_rejects_repo_escape(tmp_path: Path) -> None:
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "required_files": [{"id": "outside", "path": "../outside.yaml"}],
    }

    with pytest.raises(ValueError, match="path must not contain"):
        scan_workflow_policy(root=tmp_path, policy=policy)


def test_scan_workflow_policy_rejects_empty_policy() -> None:
    with pytest.raises(ValueError, match="schema_version"):
        scan_workflow_policy(root=Path("."), policy={})

    with pytest.raises(ValueError, match="at least one"):
        scan_workflow_policy(
            root=Path("."),
            policy={"schema_version": "agent-guard.workflow_policy.v1"},
        )


def test_scan_workflow_policy_rejects_null_path(tmp_path: Path) -> None:
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "required_files": [{"id": "context_policy", "path": None}],
    }

    with pytest.raises(ValueError, match="path.*must be a string"):
        scan_workflow_policy(root=tmp_path, policy=policy)


def test_scan_workflow_policy_rejects_workflow_check_without_commands(tmp_path: Path) -> None:
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [{"id": "ci_smoke", "path": ".github/workflows/ci.yml"}],
    }

    with pytest.raises(ValueError, match="required_commands must contain"):
        scan_workflow_policy(root=tmp_path, policy=policy)


def test_scan_workflow_policy_missing_configured_workflow_is_error(tmp_path: Path) -> None:
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": ["python -m agent_guard.cli context check"],
            }
        ]
    }

    with pytest.raises(FileNotFoundError, match="workflow file not found"):
        scan_workflow_policy(root=tmp_path, policy=policy)
