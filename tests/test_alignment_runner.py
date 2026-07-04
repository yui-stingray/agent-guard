"""Where: tests/test_alignment_runner.py
What: tests for ASI taxonomy completeness alignment checks.
Why: unmapped emitted guard IDs should fail before release evidence drifts.
"""

from __future__ import annotations

from bench.alignment.run import build_alignment_result
from agent_guard.context_guard import DEFAULT_FORBIDDEN_PATTERNS


def test_alignment_runner_has_no_unmapped_asi_ids() -> None:
    result = build_alignment_result()

    assert result["status"] == "ok"
    assert result["summary"]["missing_count"] == 0
    check_names = {check["name"] for check in result["checks"]}
    assert "sarif_official_schema_validation" in check_names


def test_context_rule_classifications_cover_default_context_rules() -> None:
    result = build_alignment_result()
    checks = {check["name"]: check for check in result["checks"]}

    check = checks["drift_context_rule_classifications"]
    assert check["emitted_count"] == len(DEFAULT_FORBIDDEN_PATTERNS)
    assert check["missing"] == []


def test_alignment_runner_validates_sarif_with_official_schema() -> None:
    result = build_alignment_result()
    checks = {check["name"]: check for check in result["checks"]}

    check = checks["sarif_official_schema_validation"]
    assert check["status"] == "ok"
    assert check["missing"] == []
