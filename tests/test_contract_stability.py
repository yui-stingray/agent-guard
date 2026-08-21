# Where: tests/test_contract_stability.py
# What: freeze tests for public evidence contracts and stability docs.
# Why: accidental schema or release-discipline drift should fail before release.

from __future__ import annotations

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = REPO_ROOT / "src" / "agent_guard" / "schemas"
COMPATIBILITY_DOC = REPO_ROOT / "docs" / "compatibility.md"
EVIDENCE_CONTRACTS_DOC = REPO_ROOT / "docs" / "evidence-contracts.md"
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
    "agent-guard.evidence_pack_manifest.v2.schema.json": (
        "https://github.com/yui-stingray/agent-guard/schemas/agent-guard.evidence_pack_manifest.v2.schema.json",
        {"schema_version": "agent-guard.evidence_pack_manifest.v2"},
    ),
    "agent-guard.report_evidence.v1.schema.json": (
        "https://github.com/yui-stingray/agent-guard/schemas/agent-guard.report_evidence.v1.schema.json",
        {
            "schema_version": "agent-guard.result.v1",
            "report.schema_version": "agent-guard.report_evidence.v1",
        },
    ),
    "agent-guard.report_evidence.v2.schema.json": (
        "https://github.com/yui-stingray/agent-guard/schemas/agent-guard.report_evidence.v2.schema.json",
        {
            "schema_version": "agent-guard.result.v1",
            "report.schema_version": "agent-guard.report_evidence.v2",
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
    "agent-guard.report_evidence.v2",
    "agent-guard.conformance.v1",
    "agent-guard.evidence_pack_manifest.v1",
    "agent-guard.evidence_pack_manifest.v2",
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


def test_evidence_contracts_freeze_mcp_package_pin_grammar() -> None:
    docs = " ".join(EVIDENCE_CONTRACTS_DOC.read_text(encoding="utf-8").split())

    assert (
        "For JavaScript launchers (`npx`, `npm exec`/`npm x`, `pnpm dlx`, `yarn dlx`, "
        "`bun x`, and direct `bunx`), every eligible package operand or selector must use "
        "an npm-compatible full SemVer: its total version text is at most 256 characters and "
        "each numeric core identifier is no greater than `Number.MAX_SAFE_INTEGER`."
    ) in docs
    assert (
        "Synthetic package-attached `sha256` selectors are not supported by these launcher "
        "grammars and are not treated as pins."
    ) in docs
    assert (
        "`version_pinned` and `latest_package` consume only explicit recognized launcher option "
        "and alias arities; unsupported or ambiguous layouts do not inspect arbitrary arguments "
        "as package operands."
    ) in docs
    assert "For `uvx`, every selected requirement must use an exact `name[extras]==version` form" in docs
    assert "package-attached `sha256` value with 64 hexadecimal digits" not in docs


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
        "## 0.3.5 - 2026-08-13", maxsplit=1
    )[0]
    latest_release = changelog.split("## 0.3.5 - 2026-08-13", maxsplit=1)[1].split(
        "## 0.3.4 - 2026-08-01", maxsplit=1
    )[0]
    previous_release = changelog.split("## 0.3.4 - 2026-08-01", maxsplit=1)[1].split(
        "## 0.3.3 - 2026-07-27", maxsplit=1
    )[0]
    earlier_release = changelog.split("## 0.3.3 - 2026-07-27", maxsplit=1)[1].split(
        "## 0.3.2 - 2026-07-19", maxsplit=1
    )[0]
    older_release = changelog.split("## 0.3.2 - 2026-07-19", maxsplit=1)[1].split(
        "## 0.3.1 - 2026-07-17", maxsplit=1
    )[0]
    oldest_release = changelog.split("## 0.3.1 - 2026-07-17", maxsplit=1)[1].split(
        "## 0.3.0 - 2026-07-17", maxsplit=1
    )[0]
    normalized_latest = " ".join(latest_release.split())
    normalized_previous = " ".join(previous_release.split())
    normalized_earlier = " ".join(earlier_release.split())
    normalized_older = " ".join(older_release.split())
    normalized_oldest = " ".join(oldest_release.split())
    normalized_unreleased = " ".join(unreleased.split())

    assert headings[:7] == [
        "## Unreleased",
        "## 0.3.5 - 2026-08-13",
        "## 0.3.4 - 2026-08-01",
        "## 0.3.3 - 2026-07-27",
        "## 0.3.2 - 2026-07-19",
        "## 0.3.1 - 2026-07-17",
        "## 0.3.0 - 2026-07-17",
    ]
    assert normalized_unreleased == ""
    assert normalized_latest == " ".join(
        [
            "- The published 0.3.4 context scanner can be made unavailable by adversarial repository-controlled regex, and this patch bounds that matching.",
            "- Corrected `bun x` and direct `bunx` pin inference to evaluate only the package operand (optionally preceded by `--bun`). Bun global `--cwd` and `--shell` are consumed only before `x`; version-dependent post-`x` selectors such as `--package` fail closed as unpinned metadata.",
            "- Made static MCP package pin and latest-tag inference inspect recognized package-manager operands and selectors instead of arbitrary command arguments. JavaScript launchers require npm-compatible full SemVer (total version text at most 256 characters and core numeric identifiers at most `Number.MAX_SAFE_INTEGER`) and do not treat synthetic package-attached SHA-256 selectors as pins; exact `uvx` requirements and uv's exact-only positional `name@version` syntax remain eligible. Both labels use bounded, explicit launcher option and alias arities; unsupported or ambiguous layouts fail closed without treating arbitrary arguments as package operands. Trailing executed-command arguments are excluded after the package operand, and recognized Windows launcher suffixes are normalized internally without changing the public command basename. Ranges, npm-style major/minor-only versions, digest selectors, option values, and ambiguous layouts fail closed as unpinned metadata.",
            "- Bounded context inventory, digest, and MCP configuration inputs by file size, file count, aggregate distinct bytes, structured-object depth, and public result size. Repository containment is bound to the opened regular file, and resource or race failures remain deterministic sanitized errors without raw policy, context, command, URL, or local-path content.",
            "- Isolated repository-controlled context-policy regular-expression matching behind the existing bounded scanner worker and added fixed pattern-count and pattern-length limits. Timeout and limit failures remain deterministic, sanitized configuration errors; no raw pattern or context text is emitted.",
            "- Tuned narrow English negation handling for built-in context rules so safe prohibitions do not become findings, while custom regular expressions, mixed unsafe clauses, double negation, and verification-skip instructions retain deterministic fail-closed behavior.",
            "- Content-bound optional `agent-policy` audit-event references with a canonical-JSON, profile-bound, public-safe digest. Producers require a caller-designated repo-local JSON event and the recognized `agent-policy.audit_event.v1.1` profile. Producers and consumers validate that profile's published event shape and reject unsupported profiles, malformed events, or replaced content. Maintainer review remains external. Audit-event binding uses report and manifest v2; the released v1 schemas remain unchanged and their path-and-role references remain readable as explicitly unbound legacy metadata. The event body remains outside the fixed seven-file public bundle.",
            "- Defined a bounded demand-validation window through 2026-09-20 and froze feature releases pending an explicit maintainer decision after the 2026-09-21 review. Marketplace publication remains separately prohibited without explicit authorization.",
            "- Locked the release build toolchain, pinned copyable GitHub Action examples to the immutable v0.3.4 release commit, and documented the post-release pin refresh contract.",
            "- Simplified reviewed bootstrap and monorepo onboarding, added explicit Python interpreter checks, and tightened guidance for copying public-safe evidence.",
            "- Hardened the documented PyPI provenance flow with isolated temporary downloads, request timeouts, exact artifact checks, redirect-final HTTPS host validation, exclusive file creation, and cleanup on success or failure.",
            "- Aligned self-dogfood CI with the canonical public evidence filenames and required fail-closed bundle validation before artifact upload.",
        ]
    )
    assert "Bound API, content, and path policy inputs and scan work" in normalized_previous
    assert "bounded packaged public-bundle consumer mode" in normalized_previous
    assert "fresh runner-temporary staging" in normalized_previous
    assert "bounded P0 public-artifact hygiene patch" in normalized_earlier
    assert "standalone evidence-pack command recursively sanitizes" in normalized_earlier
    assert "recognized HTTP(S)- or file-scheme artifact inputs" in normalized_earlier
    assert "mixed-case URLs" in normalized_earlier
    assert "mapping-key collisions fail closed" in normalized_earlier
    assert "explicit repository-root commands" in normalized_earlier
    assert "Released ahead of the default batch" in normalized_older
    assert "repository-root containment fixes" in normalized_older
    assert "Agent-Guard Bench fail closed on guard runner errors" in normalized_older
    assert "top-level `--version` command" in normalized_older
    assert "write-capable GitHub Release job" in normalized_older
    assert "credentials in its working copy" in normalized_older
    assert "dedicated least-privilege job" in normalized_older
    assert "Hardened the packaged evidence consumer" in normalized_oldest
    assert "AWS access-key-ID-shaped" in normalized_oldest
    assert "lower-bound token" in normalized_oldest
    assert "WSL-mounted Windows user paths" in normalized_oldest
    assert "minimum supported Python version from 3.11 to 3.11.4" in changelog
    assert "surface delta --base-ref <ref>" in changelog
    assert "Recursively sanitized standalone Surface Inventory output" in changelog
    assert "## 0.2.4 - 2026-07-09" in changelog
    assert "external risk-reference currentness" in changelog
    assert "Japanese-language skip-verification" in changelog
    assert "MCP metadata-poisoning label" in changelog
    assert "split-token approval-bypass context detection" in changelog
