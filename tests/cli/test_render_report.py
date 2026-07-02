# Where: tests/cli/test_render_report.py
# What: focused subprocess tests for render-report behavior.
# Why: keep extracted render-report command coverage close to its module.

from __future__ import annotations

import json
from pathlib import Path

from tests.cli.helpers import ROOT, create_report_violation_fixture_repo, read_report_fixture, run_cli

def test_render_report_cli_renders_markdown_from_sanitized_json(tmp_path: Path) -> None:
    policy = create_report_violation_fixture_repo(tmp_path)
    report_json = tmp_path / "evidence" / "agent-guard-report.json"

    report_result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(policy),
        "--format",
        "json",
        "--output",
        str(report_json),
    )
    assert report_result.returncode == 1

    result = run_cli(
        "render-report",
        "--root",
        str(tmp_path),
        "--input",
        str(report_json),
        "--format",
        "markdown",
    )

    assert result.returncode == 1
    assert "Agent Guard Evidence Report" in result.stdout
    assert "| high | approval_bypass | ASI01 Agent Goal Hijack; ASI09 Human-Agent Trust Exploitation | AGENTS.md | 1 |" in result.stdout
    assert "Ignore approval checks" not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_render_report_cli_redacts_secret_shaped_existing_payload_paths(tmp_path: Path) -> None:
    secret_like = "sk-" + ("a" * 24)
    sample = ROOT / "docs" / "evidence-samples" / "agent-guard-report.json"
    payload = json.loads(sample.read_text(encoding="utf-8"))
    payload["surface_inventory"]["surfaces"][0]["path"] = f"docs/{secret_like}/policy.md"
    report_json = tmp_path / "agent-guard-report.json"
    report_json.write_text(json.dumps(payload), encoding="utf-8")

    result = run_cli(
        "render-report",
        "--root",
        str(tmp_path),
        "--input",
        str(report_json),
        "--format",
        "json",
    )

    assert result.returncode == 0
    assert secret_like not in result.stdout
    rendered = json.loads(result.stdout)
    assert rendered["surface_inventory"]["surfaces"][0]["path"] == "docs/<redacted>/policy.md"

def test_render_report_cli_writes_sarif_from_sanitized_json(tmp_path: Path) -> None:
    policy = create_report_violation_fixture_repo(tmp_path)
    report_json = tmp_path / "evidence" / "agent-guard-report.json"
    report_sarif = tmp_path / "evidence" / "agent-guard-results.sarif"

    report_result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(policy),
        "--format",
        "json",
        "--output",
        str(report_json),
    )
    assert report_result.returncode == 1

    result = run_cli(
        "render-report",
        "--root",
        str(tmp_path),
        "--input",
        str(report_json),
        "--format",
        "sarif",
        "--output",
        str(report_sarif),
    )

    assert result.returncode == 1
    assert result.stdout == ""
    payload = json.loads(report_sarif.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "AGENTS.md"
    assert str(tmp_path) not in report_sarif.read_text(encoding="utf-8")
    assert "Ignore approval checks" not in report_sarif.read_text(encoding="utf-8")

def test_render_report_cli_github_annotations_from_sanitized_json(tmp_path: Path) -> None:
    policy = create_report_violation_fixture_repo(tmp_path)
    report_json = tmp_path / "evidence" / "agent-guard-report.json"

    report_result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(policy),
        "--format",
        "json",
        "--output",
        str(report_json),
    )
    assert report_result.returncode == 1

    result = run_cli(
        "render-report",
        "--root",
        str(tmp_path),
        "--input",
        str(report_json),
        "--format",
        "github-annotations",
    )

    assert result.returncode == 1
    assert result.stdout == read_report_fixture("context_violation.github-annotations.golden")
    assert str(tmp_path) not in result.stdout

def test_render_report_cli_missing_input_error_is_sanitized(tmp_path: Path) -> None:
    missing_report = tmp_path / "missing-report.json"

    result = run_cli(
        "render-report",
        "--root",
        str(tmp_path),
        "--input",
        str(missing_report),
        "--format",
        "json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["command"] == "render-report"
    assert payload["status"] == "error"
    assert payload["policy"] == {"path": "missing-report.json"}
    assert "missing-report.json" in payload["error"]
    assert str(tmp_path) not in result.stdout

def test_render_report_cli_rejects_non_object_json(tmp_path: Path) -> None:
    report_json = tmp_path / "report.json"
    report_json.write_text("[]\n", encoding="utf-8")

    result = run_cli(
        "render-report",
        "--root",
        str(tmp_path),
        "--input",
        str(report_json),
        "--format",
        "json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["error"] == "report JSON root must be an object"
    assert str(tmp_path) not in result.stdout
