# Where: tests/cli/test_drift_baseline.py
# What: focused subprocess tests for drift baseline-ref handling.
# Why: keep git-backed drift tests separate from lighter drift CLI checks.

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from agent_guard import drift_guard
from tests.cli.helpers import run_cli, run_git, sha256_text, write, write_baseline_ready_repo


def test_drift_cli_base_ref_flags_baseline_sensitive_changes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    write_baseline_ready_repo(repo)
    run_git(repo, "init")
    run_git(repo, "config", "user.email", "agent-guard@example.invalid")
    run_git(repo, "config", "user.name", "agent guard tests")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "base")

    write(repo / ".agent-guard" / "context-policy.yaml", "scan:\n  include:\n    - AGENTS.md\n")
    write(
        repo / ".agent-guard" / "context-digest-policy.yaml",
        "checks:\n"
        "  - id: root_agents_md\n"
        "    path: AGENTS.md\n"
        f"    sha256: '{sha256_text((repo / 'AGENTS.md').read_text(encoding='utf-8'))}'\n",
    )
    write(
        repo / ".github" / "workflows" / "agent-guard.yml",
        "name: agent-guard\n"
        "on: [push]\n"
        "jobs:\n"
        "  guard:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: Guard checks\n"
        "        run: |\n"
        "          agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json\n"
        "          agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json\n"
        "          agent-guard drift check --root . --profile recommended --schema-version v2 --base-ref HEAD~1 --json\n",
    )
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "change baseline surfaces")

    result = run_cli(
        "drift",
        "check",
        "--root",
        str(repo),
        "--profile",
        "recommended",
        "--schema-version",
        "v2",
        "--base-ref",
        "HEAD~1",
        "--json",
    )

    assert result.returncode == 1, result.stdout
    payload = json.loads(result.stdout)
    baseline = payload["policy_spec_drift"]["baseline_trust"]
    assert baseline["status"] == "review_required"
    assert baseline["base_ref"] == "provided"
    assert baseline["changed_count"] == 3
    flagged = {(item["file"], item["reason"], item.get("classification")) for item in payload["findings"]}
    assert (
        ".agent-guard/context-policy.yaml",
        "guard_policy_changed",
        "baseline_review_required",
    ) in flagged
    assert (
        ".agent-guard/context-digest-policy.yaml",
        "digest_policy_changed",
        "baseline_review_required",
    ) in flagged
    assert (
        ".github/workflows/agent-guard.yml",
        "guard_workflow_changed",
        "baseline_review_required",
    ) in flagged
    assert str(tmp_path) not in result.stdout
    assert "sha256" not in result.stdout
    assert "agent-guard context check" not in result.stdout


def test_drift_cli_base_ref_unavailable_is_sanitized(tmp_path: Path) -> None:
    write_baseline_ready_repo(tmp_path)

    result = run_cli(
        "drift",
        "check",
        "--root",
        str(tmp_path),
        "--profile",
        "recommended",
        "--schema-version",
        "v2",
        "--base-ref",
        "origin/main",
        "--json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    baseline_findings = [
        item for item in payload["findings"] if item["rule_id"] == "baseline_trust_unproven"
    ]
    assert baseline_findings == [
        {
            "rule_id": "baseline_trust_unproven",
            "severity": "high",
            "file": ".",
            "message": "baseline-sensitive guard changes could not be compared to the provided base ref",
            "reason": "not_git_repository",
            "requirement_id": "baseline_ref",
            "classification": "baseline_review_required",
        }
    ]
    assert payload["policy_spec_drift"]["baseline_trust"]["status"] == "unproven"
    assert str(tmp_path) not in result.stdout
    assert "origin/main" not in result.stdout


def test_drift_cli_rejects_unsafe_base_ref_without_echoing_it(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    write_baseline_ready_repo(repo)
    run_git(repo, "init")
    run_git(repo, "config", "user.email", "agent-guard@example.invalid")
    run_git(repo, "config", "user.name", "agent guard tests")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "base")

    unsafe_ref = "--output=/tmp/agent-guard-leak"
    result = run_cli(
        "drift",
        "check",
        "--root",
        str(repo),
        "--profile",
        "recommended",
        "--schema-version",
        "v2",
        f"--base-ref={unsafe_ref}",
        "--json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert any(
        item["rule_id"] == "baseline_trust_unproven" and item["reason"] == "base_ref_unavailable"
        for item in payload["findings"]
    )
    assert unsafe_ref not in result.stdout
    assert str(tmp_path) not in result.stdout


def test_drift_cli_ignores_hostile_git_routing_and_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    hostile = tmp_path / "hostile"
    repo.mkdir()
    hostile.mkdir()
    write_baseline_ready_repo(repo)
    run_git(repo, "init")
    run_git(repo, "config", "user.email", "agent-guard@example.invalid")
    run_git(repo, "config", "user.name", "agent guard tests")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "base")
    write(repo / ".agent-guard" / "context-policy.yaml", "scan:\n  include: [AGENTS.md]\n")
    run_git(repo, "add", ".agent-guard/context-policy.yaml")
    run_git(repo, "commit", "-m", "change protected path")
    run_git(hostile, "init")

    hostile_config = tmp_path / "hostile.gitconfig"
    write(hostile_config, "[core]\n\tfsmonitor = synthetic-hostile-helper\n")
    hostile_environment = {
        "GIT_DIR": str(hostile / ".git"),
        "GIT_WORK_TREE": str(hostile),
        "GIT_CONFIG_GLOBAL": str(hostile_config),
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "synthetic-hostile-helper",
        "GIT_CONFIG_PARAMETERS": "'core.fsmonitor=synthetic-hostile-parameter'",
        "GIT_NO_LAZY_FETCH": "0",
        "GIT_NO_REPLACE_OBJECTS": "0",
    }
    for key, value in hostile_environment.items():
        monkeypatch.setenv(key, value)

    result = run_cli(
        "drift",
        "check",
        "--root",
        str(repo),
        "--profile",
        "recommended",
        "--schema-version",
        "v2",
        "--base-ref",
        "HEAD~1",
        "--json",
    )

    assert result.returncode == 1, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    baseline = payload["policy_spec_drift"]["baseline_trust"]
    assert baseline["status"] == "review_required"
    assert any(
        item["file"] == ".agent-guard/context-policy.yaml"
        for item in payload["findings"]
    )
    assert "synthetic-hostile" not in result.stdout + result.stderr
    assert str(hostile) not in result.stdout + result.stderr


def test_drift_git_query_uses_bounded_runner_and_sanitizes_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def run_git(root: Path, args: list[str], **kwargs: object):
        captured["root"] = root
        captured["args"] = args
        captured.update(kwargs)
        return subprocess.CompletedProcess(args, 0, b"true\n")

    monkeypatch.setattr(drift_guard, "run_bounded_git", run_git)
    result = drift_guard.run_git_command(
        tmp_path,
        ["rev-parse", "--is-inside-work-tree"],
    )

    assert result.stdout == "true\n"
    assert captured["timeout_seconds"] == drift_guard.GIT_DRIFT_TIMEOUT_SECONDS
    assert captured["max_output_bytes"] == drift_guard.MAX_GIT_DRIFT_OUTPUT_BYTES

    marker = "sensitive bounded git detail"

    def fail_git(*_args: object, **_kwargs: object) -> None:
        raise drift_guard.BoundedGitProcessError(marker)

    monkeypatch.setattr(drift_guard, "run_bounded_git", fail_git)
    findings, _, summary = drift_guard.scan_baseline_trust_drift(
        root=tmp_path,
        base_ref="HEAD~1",
        profile="recommended",
    )

    assert summary.status == "unproven"
    assert findings[0].reason == "git_unavailable"
    assert marker not in str(findings[0].to_dict())


def test_drift_cli_rejects_oversized_readme_with_sanitized_limit(tmp_path: Path) -> None:
    write_baseline_ready_repo(tmp_path)
    (tmp_path / "README.md").write_bytes(
        b"x" * (drift_guard.MAX_CONTEXT_FILE_BYTES + 1)
    )

    result = run_cli("drift", "check", "--root", str(tmp_path), "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["error"] == drift_guard.ERROR_POLICY_SPEC_DRIFT_LIMIT
    assert str(tmp_path) not in result.stdout


def test_drift_rejects_bounded_workflow_yaml_merge_expansion(tmp_path: Path) -> None:
    write(tmp_path / "README.md", "agent-guard drift check --root .\n")
    write(
        tmp_path / ".agent-guard" / "workflow-policy.yaml",
        "defaults: &defaults\n"
        "  path: .agent-guard/context-policy.yaml\n"
        "required_files:\n"
        "  - <<: *defaults\n"
        "    id: context_policy\n",
    )

    with pytest.raises(ValueError) as raised:
        drift_guard.build_policy_spec_drift_scan(root=tmp_path)

    assert str(raised.value) == drift_guard.ERROR_POLICY_SPEC_DRIFT_LIMIT


def test_drift_enforces_aggregate_distinct_input_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write(tmp_path / "README.md", "12345678")
    write(tmp_path / ".agent-guard" / "workflow-policy.yaml", "{}\n     ")
    monkeypatch.setattr(drift_guard, "MAX_CONTEXT_FILE_BYTES", 8)
    monkeypatch.setattr(drift_guard, "MAX_WORKFLOW_POLICY_BYTES", 8)
    monkeypatch.setattr(drift_guard, "MAX_CONTEXT_DISTINCT_INPUT_BYTES", 15)

    with pytest.raises(ValueError) as raised:
        drift_guard.build_policy_spec_drift_scan(root=tmp_path)

    assert str(raised.value) == drift_guard.ERROR_POLICY_SPEC_DRIFT_LIMIT


def test_drift_readme_fails_closed_on_external_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    readme = root / "README.md"
    outside = tmp_path / "outside.md"
    write(readme, "safe\n")
    write(outside, "outside-private-marker\n")
    probe = root / "symlink-probe"
    try:
        probe.symlink_to(outside)
        probe.unlink()
    except OSError:
        pytest.skip("symlink creation is unavailable")

    original_read = drift_guard.read_repo_bound_bytes
    swapped = False

    def swap_before_open(path: Path, repo_root: Path, *, max_bytes: int):
        nonlocal swapped
        if path == readme and not swapped:
            path.unlink()
            path.symlink_to(outside)
            swapped = True
        return original_read(path, repo_root, max_bytes=max_bytes)

    monkeypatch.setattr(drift_guard, "read_repo_bound_bytes", swap_before_open)

    with pytest.raises(ValueError) as raised:
        drift_guard.read_optional_text(readme, root=root)

    assert swapped
    assert str(raised.value) == drift_guard.ERROR_POLICY_SPEC_DRIFT_INPUT
    assert "outside-private-marker" not in str(raised.value)
