# Where: tests/cli/test_conformance_strict.py
# What: focused subprocess tests for strict conformance checks.
# Why: keep strict profile edge cases out of the legacy CLI test file.

from __future__ import annotations

import json
from pathlib import Path

from tests.cli.helpers import DEFAULT_FORBIDDEN_RISKY_PATTERNS, policy_file_surfaces, run_cli

def test_conformance_cli_strict_requires_sanitized_evidence_pack_report_artifact(tmp_path: Path) -> None:
    base_payload = {
        "evidence_coverage": {
            "gates": [
                {"gate": gate, "status": "ok", "checked_count": 1, "finding_count": 0}
                for gate in (
                    "context",
                    "surface_inventory",
                    "path",
                    "content",
                    "mcp_config",
                    "context_lock",
                    "digest",
                    "workflow",
                    "policy_spec_drift",
                )
            ]
        },
        "surface_inventory": {
            "summary": {
                "by_surface": {
                    "agent_context": 1,
                    "policy_file": 6,
                    "workflow_file": 1,
                    "workflow_reference": 8,
                    "documented_guard_command": 4,
                    "evidence_artifact_reference": 1,
                }
            },
            "surfaces": policy_file_surfaces(
                ".agent-guard/context-policy.yaml",
                ".agent-guard/path-policy.yaml",
                ".agent-guard/content-policy.yaml",
                ".agent-guard/context-digest-policy.yaml",
                ".agent-guard/mcp-policy.yaml",
                ".agent-guard/workflow-policy.yaml",
            ),
        },
        "mcp_config": {
            "policy": {
                "path": ".agent-guard/mcp-policy.yaml",
                "forbidden_risky_patterns": sorted(DEFAULT_FORBIDDEN_RISKY_PATTERNS),
            }
        },
    }
    report = tmp_path / "report.json"
    report.write_text(json.dumps(base_payload), encoding="utf-8")

    missing_manifest = run_cli("conformance", "check", "--evidence", str(report), "--profile", "strict", "--json")

    assert missing_manifest.returncode == 1
    missing_payload = json.loads(missing_manifest.stdout)
    assert any(item["rule_id"] == "required_report_section_missing" for item in missing_payload["findings"])

    base_payload["evidence_pack_manifest"] = {
        "schema_version": "agent-guard.evidence_pack_manifest.v1",
        "sanitized": True,
        "artifacts": [{"path": ".agent-guard/evidence/agent-guard-report.json", "role": "report"}],
    }
    report.write_text(json.dumps(base_payload), encoding="utf-8")
    strict = run_cli("conformance", "check", "--evidence", str(report), "--profile", "strict", "--json")

    assert strict.returncode == 0
    payload = json.loads(strict.stdout)
    assert payload["conformance"]["status"] == "ok"
    assert payload["conformance"]["required_report_sections"] == ["evidence_pack_manifest"]
    assert payload["conformance"]["required_artifact_roles"] == ["report"]

def test_conformance_cli_strict_flags_mcp_risky_patterns(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "evidence_coverage": {
                    "gates": [
                        {"gate": gate, "status": "ok", "checked_count": 1, "finding_count": 0}
                        for gate in (
                            "context",
                            "surface_inventory",
                            "path",
                            "content",
                            "mcp_config",
                            "context_lock",
                            "digest",
                            "workflow",
                            "policy_spec_drift",
                        )
                    ]
                },
                "surface_inventory": {
                    "summary": {
                        "by_surface": {
                            "agent_context": 1,
                            "policy_file": 6,
                            "workflow_file": 1,
                            "workflow_reference": 8,
                            "documented_guard_command": 4,
                            "evidence_artifact_reference": 1,
                            "mcp_config": 1,
                            "mcp_server_reference": 1,
                        }
                    },
                    "surfaces": [
                        *policy_file_surfaces(
                            ".agent-guard/context-policy.yaml",
                            ".agent-guard/path-policy.yaml",
                            ".agent-guard/content-policy.yaml",
                            ".agent-guard/context-digest-policy.yaml",
                            ".agent-guard/mcp-policy.yaml",
                            ".agent-guard/workflow-policy.yaml",
                        ),
                        {
                            "surface": "mcp_server_reference",
                            "path": ".mcp.json",
                            "kind": "mcp_config",
                            "status": "referenced",
                            "server_name": "browser",
                            "risky_patterns": ["secret_shaped_inline_value", "unpinned_package"],
                        }
                    ],
                },
                "mcp_config": {
                    "policy": {
                        "path": ".agent-guard/mcp-policy.yaml",
                        "forbidden_risky_patterns": sorted(DEFAULT_FORBIDDEN_RISKY_PATTERNS),
                    }
                },
                "evidence_pack_manifest": {
                    "schema_version": "agent-guard.evidence_pack_manifest.v1",
                    "sanitized": True,
                    "artifacts": [{"path": ".agent-guard/evidence/agent-guard-report.json", "role": "report"}],
                },
            }
        ),
        encoding="utf-8",
    )

    strict = run_cli("conformance", "check", "--evidence", str(report), "--profile", "strict", "--json")

    assert strict.returncode == 1
    payload = json.loads(strict.stdout)
    findings = payload["conformance"]["findings"]
    assert [item["reason"] for item in findings] == ["secret_shaped_inline_value", "unpinned_package"]
    assert findings[0]["severity"] == "high"
    assert findings[0]["owasp_agentic_risk_themes"] == [{"id": "ASI03", "name": "Identity and Privilege Abuse"}]
    assert findings[1]["owasp_agentic_risk_themes"] == [
        {"id": "ASI04", "name": "Agentic Supply Chain Vulnerabilities"}
    ]
    assert str(tmp_path) not in strict.stdout

def test_conformance_cli_strict_flags_mcp_config_parse_errors(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "evidence_coverage": {
                    "gates": [
                        {"gate": gate, "status": "ok", "checked_count": 1, "finding_count": 0}
                        for gate in (
                            "context",
                            "surface_inventory",
                            "path",
                            "content",
                            "mcp_config",
                            "context_lock",
                            "digest",
                            "workflow",
                            "policy_spec_drift",
                        )
                    ]
                },
                "surface_inventory": {
                    "summary": {
                        "by_surface": {
                            "agent_context": 1,
                            "policy_file": 6,
                            "workflow_file": 1,
                            "workflow_reference": 8,
                            "documented_guard_command": 4,
                            "evidence_artifact_reference": 1,
                            "mcp_config": 1,
                        }
                    },
                    "surfaces": [
                        *policy_file_surfaces(
                            ".agent-guard/context-policy.yaml",
                            ".agent-guard/path-policy.yaml",
                            ".agent-guard/content-policy.yaml",
                            ".agent-guard/context-digest-policy.yaml",
                            ".agent-guard/mcp-policy.yaml",
                            ".agent-guard/workflow-policy.yaml",
                        ),
                        {
                            "surface": "mcp_config",
                            "path": ".mcp.json",
                            "kind": "mcp_config",
                            "status": "parse_error",
                        }
                    ],
                },
                "mcp_config": {
                    "policy": {
                        "path": ".agent-guard/mcp-policy.yaml",
                        "forbidden_risky_patterns": sorted(DEFAULT_FORBIDDEN_RISKY_PATTERNS),
                    }
                },
                "evidence_pack_manifest": {
                    "schema_version": "agent-guard.evidence_pack_manifest.v1",
                    "sanitized": True,
                    "artifacts": [{"path": ".agent-guard/evidence/agent-guard-report.json", "role": "report"}],
                },
            }
        ),
        encoding="utf-8",
    )

    strict = run_cli("conformance", "check", "--evidence", str(report), "--profile", "strict", "--json")

    assert strict.returncode == 1
    payload = json.loads(strict.stdout)
    finding = payload["conformance"]["findings"][0]
    assert finding["rule_id"] == "mcp_config_risky_pattern"
    assert finding["reason"] == "parse_error"
    assert finding["surface"] == "mcp_config"
    assert finding["owasp_agentic_risk_themes"] == [
        {"id": "ASI04", "name": "Agentic Supply Chain Vulnerabilities"}
    ]
    assert str(tmp_path) not in strict.stdout
