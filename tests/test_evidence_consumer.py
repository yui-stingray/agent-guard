"""Where: tests/test_evidence_consumer.py
What: contract tests for the downstream evidence consumer example.
Why: keep the copyable consumer aligned with packaged report schemas.
"""

from __future__ import annotations

import json
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

from agent_guard.consumer import load_payload, load_report_schema, main as packaged_consumer_main, validate_report


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
SCRIPT = REPO_ROOT / "examples" / "evidence_consumer.py"
SAMPLE = REPO_ROOT / "docs" / "evidence-samples" / "agent-guard-report.json"


def run_consumer(path: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{SRC}{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else str(SRC)
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_evidence_consumer_accepts_public_sample() -> None:
    result = run_consumer(SAMPLE)

    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 0
    assert payload["report_schema_version"] == "agent-guard.report_evidence.v1"
    assert payload["schema_version"] == "agent-guard.result.v1"
    assert payload["status"] == "ok"
    assert payload["surface_count"] >= 1
    assert payload["enabled_gate_count"] >= 2
    assert payload["missing_gate_count"] >= 0


def test_packaged_consumer_accepts_public_sample_directly() -> None:
    summary = validate_report(load_payload(SAMPLE), load_report_schema())

    assert summary["status"] == "ok"
    assert summary["report_schema_version"] == "agent-guard.report_evidence.v1"


def test_evidence_consumer_example_shim_exports_packaged_main() -> None:
    spec = importlib.util.spec_from_file_location("evidence_consumer_shim", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    spec.loader.exec_module(module)

    assert module.main is packaged_consumer_main


def test_evidence_consumer_accepts_schema_valid_error_report(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "schema_version": "agent-guard.result.v1",
                "tool": {"name": "agent-guard", "version": "0.1.15"},
                "scanner": "context",
                "status": "error",
                "exit_code": 2,
                "policy": {"path": "nonexistent"},
                "summary": {"finding_count": 0},
                "finding_count": 0,
                "findings": [],
                "command": "report",
                "report": {
                    "schema_version": "agent-guard.report_evidence.v1",
                    "format": "json",
                    "scope": "context",
                    "sanitized": True,
                },
                "error": "policy file not found: nonexistent",
            }
        ),
        encoding="utf-8",
    )

    result = run_consumer(report)

    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert payload["finding_count"] == 0
    assert payload["surface_count"] == 0
    assert payload["enabled_gate_count"] == 0


def test_evidence_consumer_fails_closed_on_schema_drift(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["report"]["schema_version"] = "agent-guard.report_evidence.v2"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.report.schema_version must equal" in result.stderr


def test_evidence_consumer_rejects_invalid_conformance_profile(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["conformance"]["profile"] = "experimental"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.conformance.profile must be one of" in result.stderr


def test_evidence_consumer_rejects_unsanitized_fragments(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["findings"] = [{"file": "/home/example/private.txt"}]
    payload["finding_count"] = 1
    payload["summary"]["finding_count"] = 1
    del payload["evidence_pack_manifest"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "contains a raw local path" in result.stderr


def test_evidence_consumer_rejects_secret_and_hash_shaped_values(tmp_path: Path) -> None:
    cases = [
        ("openai_key", "sk-" + ("a" * 24), "secret-shaped value"),
        ("github_token", "ghp_" + ("a" * 36), "secret-shaped value"),
        ("aws_access_key_id", "AKIA" + ("A" * 16), "secret-shaped value"),
        ("aws_temporary_access_key_id", "ASIA" + ("B" * 16), "secret-shaped value"),
        ("sha256_value", "a" * 64, "raw sha256-shaped value"),
        ("raw_url", "http" + "s://example.com/private", "raw URL"),
        ("private_key", "-----BEGIN " + "PRIVATE KEY-----", "secret-shaped value"),
    ]

    for name, value, expected in cases:
        payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
        payload["tool"]["version"] = value
        report = tmp_path / f"{name}.json"
        report.write_text(json.dumps(payload), encoding="utf-8")

        result = run_consumer(report)

        assert result.returncode == 1, name
        assert expected in result.stderr
        assert value not in result.stderr


def test_evidence_consumer_rejects_secret_shaped_keys(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    secret_like_key = "sk-" + ("a" * 24)
    payload[secret_like_key] = "redacted"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "secret-shaped value" in result.stderr
    assert secret_like_key not in result.stderr


def test_evidence_consumer_rejects_nested_secret_shaped_extra_keys_without_leak(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    secret_like_key = "sk-" + ("a" * 24)
    payload["report"][secret_like_key] = "redacted"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.report has 1 extra properties" in result.stderr
    assert secret_like_key not in result.stderr


def test_evidence_consumer_rejects_forbidden_raw_evidence_keys(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["surface_inventory"]["surfaces"][0]["raw_regex"] = "^sk-.+"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "forbidden raw evidence key" in result.stderr
    assert "^sk-.+" not in result.stderr


def test_evidence_consumer_allows_benign_token_substrings(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["surface_inventory"]["surfaces"][0]["path"] = "docs/tokenizer.md"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 0, result.stdout + result.stderr


def test_evidence_consumer_rejects_missing_conditional_inventory(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    del payload["inventory"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.inventory is required" in result.stderr


def test_evidence_consumer_rejects_missing_surface_inventory(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    del payload["surface_inventory"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.surface_inventory is required" in result.stderr


def test_evidence_consumer_rejects_missing_evidence_coverage(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    del payload["evidence_coverage"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_coverage is required" in result.stderr


def test_evidence_consumer_accepts_v2_inventory_and_manifest(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["surface_inventory"]["schema_version"] = "agent-guard.agent_surface_inventory.v2"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads(result.stdout)
    assert summary["conformance_status"] == "ok"


def test_evidence_consumer_rejects_inconsistent_conformance_counts(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.conformance.finding_count must match findings length" in result.stderr


def test_evidence_consumer_rejects_ok_conformance_with_findings(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["conformance"]["finding_count"] = 1
    payload["conformance"]["findings"] = [
        {
            "rule_id": "required_gate_missing",
            "severity": "high",
            "requirement_id": "workflow",
            "message": "required evidence gate is missing",
            "reason": "missing_required_gate",
        }
    ]
    payload["evidence_pack_manifest"]["report"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.conformance.finding_count must be 0 when conformance status is ok" in result.stderr


def test_evidence_consumer_rejects_empty_violation_conformance(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["status"] = "violation"
    payload["exit_code"] = 1
    payload["conformance"]["status"] = "violation"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.conformance.finding_count must be non-zero when conformance status is violation" in result.stderr


def test_evidence_consumer_rejects_ok_report_with_violation_conformance(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["conformance"]["status"] = "violation"
    payload["conformance"]["finding_count"] = 1
    payload["conformance"]["findings"] = [
        {
            "rule_id": "required_gate_missing",
            "severity": "high",
            "requirement_id": "workflow",
            "message": "required evidence gate is missing",
            "reason": "missing_required_gate",
        }
    ]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.status must be violation when conformance status is violation" in result.stderr


def test_evidence_consumer_rejects_ok_recommended_conformance_with_external_mcp_policy(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["mcp_config"]["policy"]["path"] = "<external-policy>"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.mcp_config.policy.path must be the reviewed repo MCP policy" in result.stderr


def test_evidence_consumer_rejects_ok_recommended_conformance_with_weakened_mcp_policy(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["mcp_config"]["policy"]["forbidden_risky_patterns"] = ["inline_authorization_value"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.mcp_config.policy.forbidden_risky_patterns must include the default MCP risk labels" in result.stderr


def test_evidence_consumer_summarizes_mcp_policy_conformance_rules(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["status"] = "violation"
    payload["exit_code"] = 1
    payload["mcp_config"]["policy"]["forbidden_risky_patterns"] = ["inline_authorization_value"]
    payload["conformance"]["status"] = "violation"
    payload["conformance"]["finding_count"] = 1
    payload["conformance"]["findings"] = [
        {
            "rule_id": "mcp_policy_weakened",
            "severity": "high",
            "requirement_id": "mcp_config_policy_default_patterns",
            "message": "reviewed MCP policy omits required default risk labels",
            "reason": "missing_default_risky_patterns",
        }
    ]
    payload["evidence_pack_manifest"]["report"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads(result.stdout)
    assert summary["conformance_status"] == "violation"
    assert summary["mcp_policy_conformance_rules"] == ["mcp_policy_weakened"]


def test_evidence_consumer_rejects_untracked_external_mcp_policy_violation(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["status"] = "violation"
    payload["exit_code"] = 1
    payload["mcp_config"]["policy"]["path"] = "<external-policy>"
    payload["conformance"]["status"] = "violation"
    payload["conformance"]["finding_count"] = 1
    payload["conformance"]["findings"] = [
        {
            "rule_id": "required_gate_missing",
            "severity": "high",
            "requirement_id": "workflow",
            "message": "required evidence gate is missing",
            "reason": "missing_required_gate",
        }
    ]
    payload["evidence_pack_manifest"]["report"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "must include required_mcp_policy_not_reviewed" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_evidence_consumer_rejects_untracked_weakened_mcp_policy_violation(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["status"] = "violation"
    payload["exit_code"] = 1
    payload["mcp_config"]["policy"]["forbidden_risky_patterns"] = ["inline_authorization_value"]
    payload["conformance"]["status"] = "violation"
    payload["conformance"]["finding_count"] = 1
    payload["conformance"]["findings"] = [
        {
            "rule_id": "required_gate_missing",
            "severity": "high",
            "requirement_id": "workflow",
            "message": "required evidence gate is missing",
            "reason": "missing_required_gate",
        }
    ]
    payload["evidence_pack_manifest"]["report"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "must include mcp_policy_weakened" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_evidence_consumer_rejects_stale_mcp_policy_weakened_violation(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["status"] = "violation"
    payload["exit_code"] = 1
    payload["conformance"]["status"] = "violation"
    payload["conformance"]["finding_count"] = 1
    payload["conformance"]["findings"] = [
        {
            "rule_id": "mcp_policy_weakened",
            "severity": "high",
            "requirement_id": "mcp_config_policy_default_patterns",
            "message": "reviewed MCP policy omits required default risk labels",
            "reason": "missing_default_risky_patterns",
        }
    ]
    payload["evidence_pack_manifest"]["report"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "must not report mcp_policy_weakened" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_evidence_consumer_rejects_missing_report_scope(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    del payload["report"]["scope"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.report.scope is required" in result.stderr


def test_evidence_consumer_rejects_extra_report_property(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["report"]["extra"] = "not-in-schema"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.report has 1 extra properties" in result.stderr


def test_evidence_consumer_rejects_inconsistent_evidence_coverage_counts(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_coverage"]["failing_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_coverage.failing_count must match gate statuses" in result.stderr


def test_evidence_consumer_rejects_inconsistent_evidence_pack_manifest_counts(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_pack_manifest"]["summary"]["gate_count"] += 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.summary.gate_count must match gates length" in result.stderr


def test_evidence_consumer_rejects_inconsistent_manifest_gate_status_counts(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_pack_manifest"]["gates"][0]["status"] = "violation"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.summary.failing_gate_count must match gate statuses" in result.stderr


def test_evidence_consumer_rejects_inconsistent_manifest_conformance_summary(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_pack_manifest"]["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.conformance.finding_count must match $.conformance.finding_count" in result.stderr


def test_evidence_consumer_rejects_manifest_report_mismatch(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_pack_manifest"]["report"]["status"] = "violation"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.report.status must match $.status" in result.stderr


def test_evidence_consumer_rejects_manifest_gate_mismatch_with_evidence_coverage(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_pack_manifest"]["gates"] = payload["evidence_pack_manifest"]["gates"][:-1]
    payload["evidence_pack_manifest"]["summary"]["gate_count"] -= 1
    payload["evidence_pack_manifest"]["summary"]["enabled_gate_count"] -= 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.gates must match $.evidence_coverage.gates" in result.stderr


def test_evidence_consumer_rejects_manifest_gate_status_mismatch_without_gate_name_leak(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    secret_like_gate = "sk-" + ("a" * 24)
    payload["evidence_coverage"]["gates"][0]["gate"] = secret_like_gate
    payload["evidence_pack_manifest"]["gates"][0]["gate"] = secret_like_gate
    payload["evidence_pack_manifest"]["gates"][0]["status"] = "violation"
    payload["evidence_pack_manifest"]["summary"]["failing_gate_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.gates[0].status must match $.evidence_coverage.gates" in result.stderr
    assert secret_like_gate not in result.stderr


def test_evidence_consumer_rejects_missing_manifest_conformance_when_report_has_conformance(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    del payload["evidence_pack_manifest"]["conformance"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.conformance is required when $.conformance is present" in result.stderr


def test_evidence_consumer_rejects_ok_report_with_top_level_findings(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["finding_count"] = 1
    payload["summary"]["finding_count"] = 1
    payload["findings"] = [
        {
            "file": "AGENTS.md",
            "line": 1,
            "rule_id": "approval_bypass",
            "severity": "high",
        }
    ]
    del payload["evidence_pack_manifest"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.finding_count must be 0 when status is ok" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_evidence_consumer_rejects_unexplained_violation_report(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["status"] = "violation"
    payload["exit_code"] = 1
    del payload["evidence_pack_manifest"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.status violation must be explained by findings, failing gates, or conformance findings" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_evidence_consumer_rejects_ok_report_with_failing_gate(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_coverage"]["gates"][0]["status"] = "violation"
    payload["evidence_coverage"]["failing_count"] = 1
    payload["evidence_pack_manifest"]["gates"][0]["status"] = "violation"
    payload["evidence_pack_manifest"]["summary"]["failing_gate_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_coverage.failing_count must be 0 when report status is ok" in result.stderr


def test_evidence_consumer_rejects_inconsistent_surface_count(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["surface_inventory"]["summary"]["surface_count"] += 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.surface_inventory.summary.surface_count must match surfaces length" in result.stderr
