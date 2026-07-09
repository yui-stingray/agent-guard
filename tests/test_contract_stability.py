# Where: tests/test_contract_stability.py
# What: freeze tests for public evidence contracts and stability docs.
# Why: accidental schema or release-discipline drift should fail before release.

from __future__ import annotations

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = REPO_ROOT / "src" / "agent_guard" / "schemas"
COMPATIBILITY_DOC = REPO_ROOT / "docs" / "compatibility.md"
RELEASE_CRITERIA_DOC = REPO_ROOT / "docs" / "release-criteria.md"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"

FROZEN_SCHEMA_CONTRACTS = {
    "agent-guard.conformance.v1.schema.json": (
        "https://github.com/yui-stingray/agent-guard/schemas/agent-guard.conformance.v1.schema.json",
        {"schema_version": "agent-guard.conformance.v1"},
    ),
    "agent-guard.context_inventory.v1.schema.json": (
        "https://github.com/yui-stingray/agent-guard/schemas/agent-guard.context_inventory.v1.schema.json",
        {"schema_version": "agent-guard.context_inventory.v1"},
    ),
    "agent-guard.context_lock_coverage.v1.schema.json": (
        "https://github.com/yui-stingray/agent-guard/schemas/agent-guard.context_lock_coverage.v1.schema.json",
        {"schema_version": "agent-guard.context_lock_coverage.v1"},
    ),
    "agent-guard.evidence_pack_manifest.v1.schema.json": (
        "https://github.com/yui-stingray/agent-guard/schemas/agent-guard.evidence_pack_manifest.v1.schema.json",
        {"schema_version": "agent-guard.evidence_pack_manifest.v1"},
    ),
    "agent-guard.report_evidence.v1.schema.json": (
        "https://github.com/yui-stingray/agent-guard/schemas/agent-guard.report_evidence.v1.schema.json",
        {
            "schema_version": "agent-guard.result.v1",
            "report.schema_version": "agent-guard.report_evidence.v1",
        },
    ),
    "agent-guard.result.v1.schema.json": (
        "https://github.com/yui-stingray/agent-guard/schemas/agent-guard.result.v1.schema.json",
        {"schema_version": "agent-guard.result.v1"},
    ),
}

DOCUMENTED_ARTIFACTS = (
    "agent-guard.result.v1",
    "agent-guard.context_inventory.v1",
    "agent-guard.context_lock_coverage.v1",
    "agent-guard.report_evidence.v1",
    "agent-guard.conformance.v1",
    "agent-guard.evidence_pack_manifest.v1",
    "agent-guard.agb_results.v1",
    "agent-guard.evidence_results.v1",
    "agent-guard.alignment.v1",
    "agent-guard.ttfe_results.v1",
)


def load_schema(name: str) -> dict[str, object]:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def test_packaged_schema_contracts_are_frozen() -> None:
    assert {path.name for path in SCHEMA_DIR.glob("*.schema.json")} == set(FROZEN_SCHEMA_CONTRACTS)
    for name, (schema_id, constants) in FROZEN_SCHEMA_CONTRACTS.items():
        schema = load_schema(name)
        assert schema["$id"] == schema_id
        properties = schema["properties"]
        for dotted_key, value in constants.items():
            node = properties
            for part in dotted_key.split("."):
                node = node[part]  # type: ignore[index]
                if part != dotted_key.split(".")[-1]:
                    node = node["properties"]  # type: ignore[index]
            assert node["const"] == value  # type: ignore[index]


def test_compatibility_doc_freezes_emitted_artifacts_and_volatile_fields() -> None:
    docs = COMPATIBILITY_DOC.read_text(encoding="utf-8")
    docs_single_line = " ".join(docs.split())

    for artifact in DOCUMENTED_ARTIFACTS:
        assert artifact in docs
    assert "v1 consumers keep working across 0.x releases" in docs_single_line
    assert "Volatile fields" in docs
    assert "`generated_at`" in docs
    assert "schema version will not change without a new schema identifier" in docs_single_line


def test_release_criteria_use_batched_contract_stability_cadence() -> None:
    docs = RELEASE_CRITERIA_DOC.read_text(encoding="utf-8")

    assert "Batched Release Cadence" in docs
    assert "weekly" in docs
    assert "P0 fix" in docs
    assert "Do not cut a patch release for every qualifying change" in docs
    assert "schema/contract stability" in docs


def test_changelog_records_024_patch_release_entry() -> None:
    changelog = CHANGELOG.read_text(encoding="utf-8")

    assert "## 0.2.4 - 2026-07-09" in changelog
    assert "external risk-reference currentness" in changelog
    assert "Japanese-language skip-verification" in changelog
    assert "MCP metadata-poisoning label" in changelog
    assert "split-token approval-bypass context detection" in changelog
