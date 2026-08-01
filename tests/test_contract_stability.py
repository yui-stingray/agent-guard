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
CONTRIBUTING = REPO_ROOT / "CONTRIBUTING.md"

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
    "agent-guard.surface_delta.v1.schema.json": (
        "https://github.com/yui-stingray/agent-guard/schemas/agent-guard.surface_delta.v1.schema.json",
        {"schema_version": "agent-guard.surface_delta.v1"},
    ),
}

DOCUMENTED_ARTIFACTS = (
    "agent-guard.result.v1",
    "agent-guard.context_inventory.v1",
    "agent-guard.context_lock_coverage.v1",
    "agent-guard.report_evidence.v1",
    "agent-guard.conformance.v1",
    "agent-guard.evidence_pack_manifest.v1",
    "agent-guard.surface_delta.v1",
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
    assert "unreleased source only" not in docs_single_line
    assert "not present in the published" not in docs_single_line
    assert "| Surface delta evidence | `agent-guard.surface_delta.v1`" in docs


def test_release_criteria_use_batched_contract_stability_cadence() -> None:
    docs = RELEASE_CRITERIA_DOC.read_text(encoding="utf-8")

    assert "Batched Release Cadence" in docs
    assert "weekly" in docs
    assert "P0 fix" in docs
    assert "one-sentence, public-safe rationale" in docs
    assert "release-preparation pull request or that release's CHANGELOG entry" in docs
    assert "embargoed vulnerability details" in docs
    assert "Do not cut a patch release for every qualifying change" in docs
    assert "schema/contract stability" in docs


def test_contributing_keeps_runtime_expansion_out_of_scope() -> None:
    docs = CONTRIBUTING.read_text(encoding="utf-8")

    assert "runtime MCP execution" in docs
    assert "live OAuth validation" in docs
    assert "generic credential" in docs
    assert "LLM review" in docs
    assert "raw local paths" in docs
    assert "private command transcripts" in docs


def test_changelog_records_latest_release_entry() -> None:
    changelog = CHANGELOG.read_text(encoding="utf-8")
    headings = [line for line in changelog.splitlines() if line.startswith("## ")]
    unreleased = changelog.split("## Unreleased", maxsplit=1)[1].split(
        "## 0.3.4 - 2026-07-31", maxsplit=1
    )[0]
    latest_release = changelog.split("## 0.3.4 - 2026-07-31", maxsplit=1)[1].split(
        "## 0.3.3 - 2026-07-27", maxsplit=1
    )[0]
    previous_release = changelog.split("## 0.3.3 - 2026-07-27", maxsplit=1)[1].split(
        "## 0.3.2 - 2026-07-19", maxsplit=1
    )[0]
    earlier_release = changelog.split("## 0.3.2 - 2026-07-19", maxsplit=1)[1].split(
        "## 0.3.1 - 2026-07-17", maxsplit=1
    )[0]
    older_release = changelog.split("## 0.3.1 - 2026-07-17", maxsplit=1)[1].split(
        "## 0.3.0 - 2026-07-17", maxsplit=1
    )[0]
    normalized_latest = " ".join(latest_release.split())
    normalized_previous = " ".join(previous_release.split())
    normalized_earlier = " ".join(earlier_release.split())
    normalized_older = " ".join(older_release.split())
    normalized_unreleased = " ".join(unreleased.split())

    assert headings[:6] == [
        "## Unreleased",
        "## 0.3.4 - 2026-07-31",
        "## 0.3.3 - 2026-07-27",
        "## 0.3.2 - 2026-07-19",
        "## 0.3.1 - 2026-07-17",
        "## 0.3.0 - 2026-07-17",
    ]
    assert normalized_unreleased == ""
    assert "Bound API, content, and path policy inputs and scan work" in normalized_latest
    assert "bounded packaged public-bundle consumer mode" in normalized_latest
    assert "fresh runner-temporary staging" in normalized_latest
    assert "bounded P0 public-artifact hygiene patch" in normalized_previous
    assert "standalone evidence-pack command recursively sanitizes" in normalized_previous
    assert "recognized HTTP(S)- or file-scheme artifact inputs" in normalized_previous
    assert "mixed-case URLs" in normalized_previous
    assert "mapping-key collisions fail closed" in normalized_previous
    assert "explicit repository-root commands" in normalized_previous
    assert "Released ahead of the default batch" in normalized_earlier
    assert "repository-root containment fixes" in normalized_earlier
    assert "Agent-Guard Bench fail closed on guard runner errors" in normalized_earlier
    assert "top-level `--version` command" in normalized_earlier
    assert "write-capable GitHub Release job" in normalized_earlier
    assert "credentials in its working copy" in normalized_earlier
    assert "dedicated least-privilege job" in normalized_earlier
    assert "Hardened the packaged evidence consumer" in normalized_older
    assert "AWS access-key-ID-shaped" in normalized_older
    assert "lower-bound token" in normalized_older
    assert "WSL-mounted Windows user paths" in normalized_older
    assert "minimum supported Python version from 3.11 to 3.11.4" in changelog
    assert "surface delta --base-ref <ref>" in changelog
    assert "Recursively sanitized standalone Surface Inventory output" in changelog
    assert "## 0.2.4 - 2026-07-09" in changelog
    assert "external risk-reference currentness" in changelog
    assert "Japanese-language skip-verification" in changelog
    assert "MCP metadata-poisoning label" in changelog
    assert "split-token approval-bypass context detection" in changelog
