"""Where: tests/test_evidence_consumer.py
What: contract tests for the downstream evidence consumer example.
Why: keep the copyable consumer aligned with packaged report schemas.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


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


def test_evidence_consumer_fails_closed_on_schema_drift(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["report"]["schema_version"] = "agent-guard.report_evidence.v2"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.report.schema_version must equal" in result.stderr


def test_evidence_consumer_rejects_unsanitized_fragments(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["findings"] = [{"file": "/home/example/private.txt"}]
    payload["finding_count"] = 1
    payload["summary"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "forbidden public-evidence fragment" in result.stderr


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
    payload["conformance"] = {
        "schema_version": "agent-guard.conformance.v1",
        "profile": "recommended",
        "status": "ok",
        "checked_count": 1,
        "finding_count": 0,
        "findings": [],
    }
    payload["evidence_pack_manifest"] = {
        "schema_version": "agent-guard.evidence_pack_manifest.v1",
        "sanitized": True,
        "report": {
            "schema_version": "agent-guard.report_evidence.v1",
            "format": "json",
            "scope": "context",
            "status": "ok",
            "finding_count": 0,
        },
        "summary": {
            "gate_count": 1,
            "enabled_gate_count": 1,
            "missing_gate_count": 0,
            "failing_gate_count": 0,
            "surface_count": 1,
        },
        "gates": [{"gate": "context", "status": "ok", "finding_count": 0}],
        "artifacts": [],
    }
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads(result.stdout)
    assert summary["conformance_status"] == "ok"


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
    assert "$.report has extra properties" in result.stderr
