"""Where: tests/test_cli.py
What: subprocess tests for the agent-guard CLI.
Why: pin the shared exit-code and JSON envelope contract for wrappers and CI.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_guard.cli import safe_policy_path

from tests.cli.helpers import assert_shared_envelope, run_cli, run_cli_from, write


def test_init_cli_json_is_review_first_and_does_not_write(tmp_path: Path) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "agent-guard.init_plan.v1"
    assert payload["mode"] == "print"
    files = payload["files"]
    assert [item["path"] for item in files] == [
        ".agent-guard/context-policy.yaml",
        ".agent-guard/path-policy.yaml",
        ".agent-guard/content-policy.yaml",
        ".agent-guard/mcp-policy.yaml",
        ".agent-guard/workflow-policy.yaml",
        ".github/workflows/agent-guard.yml",
    ]
    assert all(item["status"] == "create" for item in files)
    contents = {item["path"]: item["content"] for item in files}
    workflow = contents[".github/workflows/agent-guard.yml"]
    mcp_policy = contents[".agent-guard/mcp-policy.yaml"]
    workflow_policy = contents[".agent-guard/workflow-policy.yaml"]
    assert "schema_version: agent-guard.mcp_policy.v1" in mcp_policy
    assert "forbidden_risky_patterns:" in mcp_policy
    assert "agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json" in workflow
    assert (
        "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml "
        "--schema-version v2 --json"
        in workflow
    )
    assert "agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json" in workflow
    assert "agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json" in workflow
    assert "agent-guard drift check --root . --profile recommended --schema-version v2 --json" in workflow
    assert (
        "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml "
        "--evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json"
        in workflow
    )
    report_lines = [line.strip() for line in workflow.splitlines() if line.strip().startswith("agent-guard report")]
    assert report_lines == [
        "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml "
        "--evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json"
    ]
    assert "render_report_output" not in workflow
    assert (
        "agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json "
        "--format markdown --output .agent-guard/evidence/agent-guard-report.md"
        in workflow
    )
    assert (
        "agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json "
        "--format sarif --output .agent-guard/evidence/agent-guard-results.sarif"
        in workflow
    )
    assert (
        "agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json "
        "--format github-annotations"
        in workflow
    )
    assert "agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json --profile recommended --json" in workflow
    assert "agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json" in workflow
    raw_scanner_lines = [
        line.strip()
        for line in workflow.splitlines()
        if line.strip().startswith("agent-guard ")
        and "--json" in line
        and any(
            command in line
            for command in (
                "context check",
                "path check",
                "content check",
                "mcp check",
                "workflow check",
                "drift check",
            )
        )
    ]
    assert raw_scanner_lines
    assert "raw_dir=\"$(mktemp -d \"$raw_parent/agent-guard-raw.XXXXXX\")\"" in workflow
    assert all('> "$raw_dir/' in line for line in raw_scanner_lines)
    assert (
        "agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json "
        "--profile recommended --json > .agent-guard/evidence/agent-guard-conformance.json"
        in workflow
    )
    assert (
        "agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json "
        "--artifact .agent-guard/evidence/agent-guard-report.json --json > .agent-guard/evidence/agent-guard-evidence-pack.json"
        in workflow
    )
    assert "workflow_checks:" in workflow_policy
    assert "path: .agent-guard/mcp-policy.yaml" in workflow_policy
    assert "command: agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml" in workflow_policy
    assert "command: agent-guard drift check --root . --profile recommended --schema-version v2" in workflow_policy
    assert (
        "command: agent-guard report --root . --context-policy .agent-guard/context-policy.yaml "
        "--evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml"
        in workflow_policy
    )
    next_steps = "\n".join(payload["next_steps"])
    assert "raw per-scanner JSON as local or CI-internal" in next_steps
    assert "publish only the sanitized report, render-report, or evidence-pack outputs" in next_steps
    assert "runtime MCP validation, live OAuth validation, or MCP tool-poisoning detection" in next_steps
    assert not (tmp_path / ".agent-guard").exists()
    serialized = json.dumps(payload, sort_keys=True)
    assert str(tmp_path) not in serialized


def test_init_cli_written_workflow_policy_checks_generated_workflow(tmp_path: Path) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--write", "--json")
    assert result.returncode == 0

    result = run_cli(
        "workflow",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / ".agent-guard" / "workflow-policy.yaml"),
        "--json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="workflow",
        status="ok",
        exit_code=0,
        finding_count=0,
        scanned_unit="checks",
    )


def test_init_cli_workflow_policy_detects_removed_drift_gate(tmp_path: Path) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--write", "--json")
    assert result.returncode == 0

    workflow = tmp_path / ".github" / "workflows" / "agent-guard.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            '          agent-guard drift check --root . --profile recommended --schema-version v2 --json > "$raw_dir/drift.json"\n',
            "",
        ),
        encoding="utf-8",
    )

    result = run_cli(
        "workflow",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / ".agent-guard" / "workflow-policy.yaml"),
        "--json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="workflow",
        status="violation",
        exit_code=1,
        finding_count=1,
        scanned_unit="checks",
    )
    assert payload["findings"][0]["requirement_id"] == "drift_guard"


def test_init_cli_workflow_policy_detects_report_without_recommended_preset(tmp_path: Path) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--write", "--json")
    assert result.returncode == 0

    workflow = tmp_path / ".github" / "workflows" / "agent-guard.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(" --evidence-preset recommended", ""),
        encoding="utf-8",
    )

    result = run_cli(
        "workflow",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / ".agent-guard" / "workflow-policy.yaml"),
        "--json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="workflow",
        status="violation",
        exit_code=1,
        finding_count=1,
        scanned_unit="checks",
    )
    assert payload["findings"][0]["requirement_id"] == "evidence_report_with_drift"


def test_init_cli_write_refuses_existing_files(tmp_path: Path) -> None:
    write(tmp_path / ".agent-guard" / "context-policy.yaml", "existing\n")

    result = run_cli("init", "--root", str(tmp_path), "--write", "--json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["mode"] == "write"
    assert payload["status"] == "blocked"
    statuses = {item["path"]: item["status"] for item in payload["files"]}
    assert statuses[".agent-guard/context-policy.yaml"] == "exists"
    assert (tmp_path / ".agent-guard" / "context-policy.yaml").read_text(encoding="utf-8") == "existing\n"


def test_init_cli_rejects_print_and_write_together(tmp_path: Path) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--print", "--write", "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "agent-guard.init_plan.v1"
    assert payload["status"] == "error"
    assert payload["error"] == "init --print cannot be combined with --write"
    assert not (tmp_path / ".agent-guard").exists()


def test_direct_cli_text_errors_scrub_policy_paths_from_external_cwd(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    cwd = tmp_path / "cwd"
    repo.mkdir()
    cwd.mkdir()
    missing_policy = ".agent-guard/missing-policy.yaml"
    commands = [
        ("api", "check", "--root", str(repo), "--policy", missing_policy),
        (
            "content",
            "check",
            "--repo-root",
            str(repo),
            "--policy",
            missing_policy,
            "--mode",
            "registered",
            "--scan-dir",
            ".",
        ),
        ("context", "check", "--root", str(repo), "--policy", missing_policy),
        ("path", "check", "--root", str(repo), "--policy", missing_policy),
        ("digest", "check", "--root", str(repo), "--policy", missing_policy),
        ("workflow", "check", "--root", str(repo), "--policy", missing_policy),
    ]

    for command in commands:
        result = run_cli_from(cwd, *command)
        combined = result.stdout + result.stderr

        assert result.returncode == 2, command
        assert "ERROR:" in combined
        assert str(tmp_path) not in combined
        assert missing_policy in combined


def test_safe_policy_path_treats_url_like_policy_as_external(tmp_path: Path) -> None:
    url_policy = "https://policy.example.invalid/reviewed/policy.yaml"

    assert safe_policy_path(url_policy, tmp_path) == "<external-policy>"


