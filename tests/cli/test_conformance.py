# Where: tests/cli/test_conformance.py
# What: focused subprocess tests for conformance profile checks.
# Why: keep extracted conformance subcommand coverage close to its module.

from __future__ import annotations

import json
from pathlib import Path

from tests.cli.helpers import DEFAULT_FORBIDDEN_RISKY_PATTERNS, policy_file_surfaces, run_cli

def test_conformance_cli_checks_report_profile_requirements(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "evidence_coverage": {
                    "gates": [
                        {"gate": "context", "status": "ok", "checked_count": 1, "finding_count": 0},
                        {"gate": "surface_inventory", "status": "ok", "checked_count": 1, "finding_count": 0},
                    ]
                },
                "surface_inventory": {"summary": {"by_surface": {"agent_context": 1}}},
            }
        ),
        encoding="utf-8",
    )
    report_payload = json.loads(report.read_text(encoding="utf-8"))
    report_payload["surface_inventory"] = {
        "summary": {"by_surface": {"agent_context": 1, "policy_file": 2}},
        "surfaces": policy_file_surfaces(".agent-guard/context-policy.yaml", ".agent-guard/workflow-policy.yaml"),
    }
    report.write_text(json.dumps(report_payload), encoding="utf-8")

    minimal = run_cli("conformance", "check", "--evidence", str(report), "--profile", "minimal", "--json")
    assert minimal.returncode == 0
    assert json.loads(minimal.stdout)["conformance"]["status"] == "ok"

    recommended = run_cli("conformance", "check", "--evidence", str(report), "--profile", "recommended", "--json")
    assert recommended.returncode == 1
    payload = json.loads(recommended.stdout)
    assert payload["conformance"]["status"] == "violation"
    assert any(item["rule_id"] == "required_gate_missing" for item in payload["findings"])
    assert str(tmp_path) not in recommended.stdout

def test_conformance_cli_recommended_requires_reviewed_mcp_policy_and_full_default_set(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
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
                    "workflow",
                    "policy_spec_drift",
                )
            ]
        },
        "surface_inventory": {
            "summary": {
                "by_surface": {
                    "agent_context": 1,
                    "policy_file": 5,
                    "workflow_file": 1,
                    "workflow_reference": 1,
                }
            },
            "surfaces": policy_file_surfaces(
                ".agent-guard/context-policy.yaml",
                ".agent-guard/path-policy.yaml",
                ".agent-guard/content-policy.yaml",
                ".agent-guard/mcp-policy.yaml",
                ".agent-guard/workflow-policy.yaml",
            ),
        },
        "mcp_config": {
            "policy": {
                "path": "<external-policy>",
                "forbidden_risky_patterns": sorted(DEFAULT_FORBIDDEN_RISKY_PATTERNS),
            }
        },
    }
    report.write_text(json.dumps(base_payload), encoding="utf-8")

    external = run_cli("conformance", "check", "--evidence", str(report), "--profile", "recommended", "--json")

    assert external.returncode == 1
    external_payload = json.loads(external.stdout)
    assert any(item["rule_id"] == "required_mcp_policy_not_reviewed" for item in external_payload["findings"])
    assert str(tmp_path) not in external.stdout

    base_payload["mcp_config"] = {
        "policy": {
            "path": ".agent-guard/mcp-policy.yaml",
            "forbidden_risky_patterns": ["inline_authorization_value"],
        }
    }
    report.write_text(json.dumps(base_payload), encoding="utf-8")
    weakened = run_cli("conformance", "check", "--evidence", str(report), "--profile", "recommended", "--json")

    assert weakened.returncode == 1
    weakened_payload = json.loads(weakened.stdout)
    assert any(item["rule_id"] == "mcp_policy_weakened" for item in weakened_payload["findings"])

    base_payload["mcp_config"] = {
        "policy": {
            "path": ".agent-guard/mcp-policy.yaml",
            "forbidden_risky_patterns": [],
        }
    }
    report.write_text(json.dumps(base_payload), encoding="utf-8")
    empty = run_cli("conformance", "check", "--evidence", str(report), "--profile", "recommended", "--json")

    assert empty.returncode == 1
    empty_payload = json.loads(empty.stdout)
    empty_finding = next(item for item in empty_payload["findings"] if item["rule_id"] == "mcp_policy_weakened")
    assert empty_finding["reason"] == "missing_default_risky_patterns"
    assert empty_finding["missing_patterns"] == sorted(DEFAULT_FORBIDDEN_RISKY_PATTERNS)
    assert str(tmp_path) not in empty.stdout

    base_payload["mcp_config"] = {
        "policy": {
            "path": ".agent-guard/mcp-policy.yaml",
            "forbidden_risky_patterns": sorted(DEFAULT_FORBIDDEN_RISKY_PATTERNS),
        }
    }
    report.write_text(json.dumps(base_payload), encoding="utf-8")
    full = run_cli("conformance", "check", "--evidence", str(report), "--profile", "recommended", "--json")

    assert full.returncode == 0, full.stdout
    assert json.loads(full.stdout)["conformance"]["required_policy_files"] == [
        ".agent-guard/context-policy.yaml",
        ".agent-guard/path-policy.yaml",
        ".agent-guard/content-policy.yaml",
        ".agent-guard/mcp-policy.yaml",
        ".agent-guard/workflow-policy.yaml",
    ]

def test_conformance_cli_rejects_malformed_surface_counts_without_raw_path(tmp_path: Path) -> None:
    for index, malformed_value in enumerate(("not-a-number", "1", True, -1, 1.5), start=1):
        report = tmp_path / f"malformed-report-{index}.json"
        report.write_text(
            json.dumps(
                {
                    "evidence_coverage": {
                        "gates": [
                            {"gate": "context", "status": "ok", "checked_count": 1, "finding_count": 0},
                            {"gate": "surface_inventory", "status": "ok", "checked_count": 1, "finding_count": 0},
                        ]
                    },
                    "surface_inventory": {"summary": {"by_surface": {"agent_context": malformed_value}}},
                }
            ),
            encoding="utf-8",
        )

        result = run_cli("conformance", "check", "--evidence", str(report), "--profile", "minimal", "--json")

        assert result.returncode == 2
        payload = json.loads(result.stdout)
        assert payload["status"] == "error"
        assert payload["exit_code"] == 2
        assert payload["scanner"] == "conformance"
        assert payload["policy"]["path"] == "<external-policy>"
        assert str(tmp_path) not in result.stdout
