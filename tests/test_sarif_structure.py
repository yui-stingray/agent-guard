# Where: tests/test_sarif_structure.py
# What: official SARIF 2.1.0 schema checks for rendered agent-guard reports.
# Why: catch SARIF drift offline before code-scanning consumers see it.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bench.alignment.run import official_sarif_schema_errors
from tests.cli.helpers import create_report_violation_fixture_repo, run_cli


def test_report_sarif_validates_against_official_2_1_0_schema(tmp_path: Path) -> None:
    policy = create_report_violation_fixture_repo(tmp_path)

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(policy),
        "--format",
        "sarif",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert official_sarif_schema_errors(payload) == []
    assert payload["version"] == "2.1.0"
    assert isinstance(payload["runs"], list)
    assert payload["runs"]

    run = payload["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "agent-guard"
    assert isinstance(driver["rules"], list)
    assert driver["rules"]

    declared_rule_ids = {rule["id"] for rule in driver["rules"]}
    assert all(isinstance(rule_id, str) and rule_id for rule_id in declared_rule_ids)
    assert isinstance(run["results"], list)
    assert run["results"]

    for item in run["results"]:
        result_item = item if isinstance(item, dict) else {}
        _assert_result_references_declared_rule(result_item, declared_rule_ids)


def _assert_result_references_declared_rule(result_item: dict[str, Any], declared_rule_ids: set[str]) -> None:
    assert result_item["ruleId"] in declared_rule_ids
    assert result_item["message"]["text"]
    locations = result_item["locations"]
    assert isinstance(locations, list)
    assert locations
    physical_location = locations[0]["physicalLocation"]
    assert physical_location["artifactLocation"]["uri"]
    assert physical_location["region"]["startLine"] >= 1
