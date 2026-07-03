# Where: tests/cli/test_drift_baseline.py
# What: focused subprocess tests for drift baseline-ref handling.
# Why: keep git-backed drift tests separate from lighter drift CLI checks.

from __future__ import annotations

import json
from pathlib import Path

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
