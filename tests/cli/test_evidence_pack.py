# Where: tests/cli/test_evidence_pack.py
# What: focused subprocess tests for evidence-pack manifest emission.
# Why: keep extracted evidence-pack subcommand coverage close to its module.

from __future__ import annotations

import json
from pathlib import Path

from tests.cli.helpers import run_cli

def test_evidence_pack_manifest_cli_is_sanitized(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "tool": {"name": "agent-guard", "version": "0.1.7"},
                "status": "ok",
                "finding_count": 0,
                "summary": {"surface_count": 2},
                "report": {
                    "schema_version": "agent-guard.report_evidence.v1",
                    "format": "json",
                    "scope": "context",
                },
                "evidence_coverage": {
                    "gate_count": 1,
                    "enabled_count": 1,
                    "missing_count": 0,
                    "failing_count": 0,
                    "gates": [{"gate": "context", "status": "ok", "finding_count": 0}],
                },
            }
        ),
        encoding="utf-8",
    )

    result = run_cli(
        "evidence-pack",
        "manifest",
        "--root",
        str(tmp_path),
        "--report",
        str(report),
        "--artifact",
        str(tmp_path / ".agent-guard" / "evidence" / "report.json"),
        "--artifact",
        str(tmp_path.parent / "outside-report.json"),
        "--artifact",
        r"C:\Users\alice\secret\agent-guard-report.json",
        "--artifact",
        r"\\server\share\agent-guard-report.json",
        "--agent-policy-audit-event",
        str(tmp_path / ".agent-guard" / "evidence" / "policy-admission-event.json"),
        "--json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    manifest = payload["evidence_pack_manifest"]
    assert manifest["schema_version"] == "agent-guard.evidence_pack_manifest.v1"
    assert manifest["sanitized"] is True
    assert manifest["artifacts"] == [
        {"path": ".agent-guard/evidence/report.json", "role": "report"},
        {"path": "outside-report.json", "role": "report"},
        {"path": "agent-guard-report.json", "role": "report"},
        {"path": "agent-guard-report.json", "role": "report"},
        {"path": ".agent-guard/evidence/policy-admission-event.json", "role": "agent-policy-audit-event"},
    ]
    assert str(tmp_path) not in result.stdout
    assert r"C:\Users\alice" not in result.stdout
    assert r"\\server\share" not in result.stdout
