"""Where: tests/test_evidence_runner.py
What: unit tests for the evidence integrity benchmark runner.
Why: keep determinism, redaction, schema, and compat checks stable.
"""

from __future__ import annotations

import json
from pathlib import Path

from bench.evidence import run as evidence_run


def test_normalize_for_determinism_removes_volatile_keys_only() -> None:
    payload = {
        "generated_at": "2026-07-02T00:00:00Z",
        "stable": {"generated_at": "later", "value": 3},
        "items": [{"generated_at": "nested", "name": "kept"}],
    }

    assert evidence_run.normalize_for_determinism(payload) == {
        "stable": {"value": 3},
        "items": [{"name": "kept"}],
    }


def test_find_seed_hits_reports_exact_secret_values(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text('{"token": "ghp_FAKE000000000000000000000000000000"}', encoding="utf-8")

    hits = evidence_run.find_seed_hits(
        [report],
        ["ghp_FAKE000000000000000000000000000000", "sk-FAKE000000000000000000000000000000"],
    )

    assert hits == {"ghp_FAKE000000000000000000000000000000": ["report.json"]}


def test_validate_schema_accepts_minimal_result_payload() -> None:
    schema = {
        "type": "object",
        "required": ["schema_version", "status"],
        "properties": {
            "schema_version": {"const": "agent-guard.result.v1"},
            "status": {"enum": ["ok", "violation", "error"]},
        },
        "additionalProperties": False,
    }

    evidence_run.validate_schema(
        schema,
        {"schema_version": "agent-guard.result.v1", "status": "ok"},
        label="result",
    )


def test_build_results_writes_status_payload(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(evidence_run, "run_determinism_check", lambda repo_root, work_root: evidence_run.CheckResult("determinism", True, "ok"))
    monkeypatch.setattr(evidence_run, "run_redaction_check", lambda repo_root, work_root: evidence_run.CheckResult("redaction", True, "ok"))
    monkeypatch.setattr(evidence_run, "run_schema_check", lambda repo_root, work_root: evidence_run.CheckResult("schema_validation", True, "ok"))
    monkeypatch.setattr(evidence_run, "run_backward_compat_check", lambda repo_root, work_root: evidence_run.CheckResult("backward_compat", True, "ok"))
    out_path = tmp_path / "evidence.json"

    payload = evidence_run.build_results(tmp_path, tmp_path / "work", out_path=out_path)

    assert payload["status"] == "ok"
    assert payload["summary"] == {"passed": 4, "failed": 0}
    assert json.loads(out_path.read_text(encoding="utf-8"))["schema_version"] == "agent-guard.evidence_results.v1"
