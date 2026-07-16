"""Where: tests/test_docs_contract.py
What: README, quickstart, release, and positioning documentation contracts.
Why: keep public docs aligned with the package contract and static-evidence boundary.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
README = REPO_ROOT / "README.md"
EVIDENCE_CONTRACTS_DOC = REPO_ROOT / "docs" / "evidence-contracts.md"
EVIDENCE_SAMPLE_REPORT = REPO_ROOT / "docs" / "evidence-samples" / "agent-guard-report.json"
EXISTING_REPO_QUICKSTART = REPO_ROOT / "docs" / "quickstart-existing-repo.md"
GITHUB_ACTIONS_EVIDENCE_DOC = REPO_ROOT / "docs" / "github-actions-evidence.md"
RELEASE_CRITERIA_DOC = REPO_ROOT / "docs" / "release-criteria.md"
POSITIONING_DOC = REPO_ROOT / "docs" / "positioning.md"
THREAT_MODEL_DOC = REPO_ROOT / "docs" / "threat-model.md"
SECURITY_POLICY = REPO_ROOT / "SECURITY.md"


def pyproject_version() -> str:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_readme_status_matches_pyproject_version() -> None:
    assert f"**Status**: `{pyproject_version()}` alpha." in README.read_text(encoding="utf-8")


def test_readme_documents_python_patch_floor() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "Python 3.11.4+" in readme
    assert "Requires Python 3.11.4+." in readme


def test_onboarding_commands_pin_the_current_package_version() -> None:
    version = pyproject_version()
    readme = README.read_text(encoding="utf-8")
    quickstart = EXISTING_REPO_QUICKSTART.read_text(encoding="utf-8")

    assert f"python -m pip install yui-agent-guard=={version}" in readme
    assert f"--from yui-agent-guard=={version}" in readme
    assert f"--from yui-agent-guard=={version}" in quickstart
    assert f"python -m pip install yui-agent-guard=={version}" in quickstart

    bootstrap = readme[readme.index("## Start with a reviewed bootstrap") : readme.index("## Why")]
    assert bootstrap.index("agent-guard init --root . --json") < bootstrap.index(
        "agent-guard init --root . --write"
    )


def test_readme_opening_states_the_bounded_value_contract() -> None:
    readme = README.read_text(encoding="utf-8")
    opening = readme[: readme.index("## Why")]

    assert "Deterministic static evidence for repositories maintained with coding agents." in opening
    assert "Which agent-facing surfaces are present" in opening
    assert "without executing agents" in opening
    assert "MCP servers" in opening
    assert "- **Inventory**" in opening
    assert "- **Check**" in opening
    assert "- **Emit**" in opening
    assert "sanitized report JSON" in opening
    assert "SARIF derived from the report payload" in opening
    assert "sanitized JSON, Markdown, and SARIF outputs" not in opening
    assert "Raw per-scanner JSON remains a" in opening
    assert "local/CI-internal surface unless a maintainer reviews it" in opening
    assert "It is **not** an authorship detector" in opening
    assert re.search(r"It is \*\*not\*\*[^.]{0,180}\bprovenance system\b", opening, re.IGNORECASE)
    assert not re.search(
        r"\b(SBOM|DCO|ISO|NIST|compliance|certification|attestation)\b",
        opening,
        re.IGNORECASE,
    )


def test_quickstart_documents_windows_without_activation() -> None:
    version = pyproject_version()
    readme = README.read_text(encoding="utf-8")
    quickstart = EXISTING_REPO_QUICKSTART.read_text(encoding="utf-8")

    assert "Windows PowerShell users" in readme
    assert "avoid activation and execution-policy friction" in quickstart
    assert rf".\.venv\Scripts\python.exe -m pip install yui-agent-guard=={version}" in quickstart
    assert r".\.venv\Scripts\agent-guard.exe init --root . --json" in quickstart
    assert r".\.venv\Scripts\agent-guard.exe init --root . --write" in quickstart
    assert r".\.venv\Scripts\agent-guard.exe report --root ." in quickstart


def test_security_policy_tracks_the_current_alpha_series() -> None:
    security = SECURITY_POLICY.read_text(encoding="utf-8")

    assert "latest published `0.x` release is supported" in security
    assert "latest published `0.1.x` release" not in security


def test_readme_documents_ci_gate_recipe() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "## CI gate recipe" in readme
    assert "agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json" in readme
    assert "agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json" in readme
    assert (
        "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml "
        "--schema-version v2 --json"
        in readme
    )
    assert (
        "agent-guard context lock --root . --policy .agent-guard/context-policy.yaml "
        "--check --digest-policy .agent-guard/context-digest-policy.yaml --json"
        in readme
    )
    assert "agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml --json" in readme
    assert (
        "agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml "
        "--mode registered --scan-dir . --json"
        in readme
    )
    assert "agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json" in readme
    assert "agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json" in readme
    assert "agent-guard drift check --root . --profile recommended --schema-version v2 --json" in readme
    assert "--evidence-preset recommended" in readme
    assert "--conformance-profile recommended" in readme
    assert "--evidence-pack-manifest" in readme
    assert "--agent-policy-audit-event .agent-guard/evidence/policy-admission-event.json" in readme
    assert (
        "agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json "
        "--profile recommended --json"
        in readme
    )
    assert "agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json" in readme


def test_readme_documents_agent_policy_companion_boundary() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "Runtime admission belongs to" in readme
    assert "shows the two layers together" in readme
    assert "| Runtime admission | `agent-policy` |" in readme
    assert "| Static repository gate | `agent-guard` |" in readme
    assert "It does **not** route models, score model quality, run LLM review" in readme
    assert "does not execute MCP servers, validate" in readme
    assert "live OAuth flows" in readme
    assert "replace dedicated secret scanners" in readme


def test_readme_uses_audience_facing_ci_and_example_language() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "ai-resilience-style repositories" not in readme
    assert "ready-to-run ai-resilience-style copy" not in readme
    assert "For repositories that publish artifacts or accept changes" in readme
    assert "A ready-to-run example policy lives in" in readme
    assert "examples/ai_resilience_path_policy.yaml" in readme


def test_readme_documents_report_evidence_contract() -> None:
    readme = README.read_text(encoding="utf-8")
    readme_single_line = " ".join(readme.split())

    assert "docs/evidence-contracts.md" in readme
    assert "docs/threat-model.md" in readme
    assert "docs/quickstart-existing-repo.md" in readme
    assert "docs/github-actions-evidence.md" in readme
    assert "docs/release-criteria.md" in readme
    assert "docs/positioning.md" in readme
    assert "agent-guard.report_evidence.v1" in readme
    assert "agent-guard.result.v1" in readme
    assert "--format <markdown|json|github-annotations|sarif>" in readme
    assert "--output <path>" in readme
    assert "Use `--format json`" in readme
    assert "Packaged JSON schemas" in readme
    assert "agent-guard.context_inventory.v1.schema.json" in readme
    assert "agent-guard.context_lock_coverage.v1.schema.json" in readme
    assert "agent-guard.conformance.v1.schema.json" in readme
    assert "agent-guard.evidence_pack_manifest.v1.schema.json" in readme
    assert "Context Lock Coverage Evidence" in readme
    assert "Evidence Coverage" in readme
    assert "Agent Surface Inventory" in readme
    assert "Conformance Evidence" in readme
    assert "Evidence Pack Manifest" in readme
    assert "does not emit context text" in readme
    assert "raw repository/content/digest hash values" in readme
    assert "SARIF is a thin adapter" in readme
    assert "Raw scanner JSON is for local automation and CI internals" in readme
    assert "Public-safe evidence" in readme
    assert "apply to `agent-guard report`" in readme
    assert "URL/API endpoint references" in readme
    assert "MCP configuration metadata" in readme
    assert "--mcp-config-check" in readme
    assert "--mcp-policy" in readme
    cli_reference = readme[readme.index("## CLI") : readme.index("## Releases")]
    assert (
        "agent-guard surface delta --root <repo> --context-policy <yaml> --base-ref <ref> "
        "[--schema-version <v1>] [--json]"
        in cli_reference
    )
    assert "[--surface-delta-base-ref <ref>]" in cli_reference
    assert "env values" in readme
    assert "owasp_agentic_risk_themes" in readme
    assert "not runtime vulnerability detection" in readme
    assert "live OAuth validation" in readme
    assert "SLSA/provenance verification" in readme
    assert "MCP runtime security validator" in readme
    assert "they do not prove" in readme
    assert "live OAuth flow is correctly implemented" in readme
    assert "Read `recommended` as the reviewed static evidence baseline" in readme
    assert "recommended conformance does not require those gates" in readme_single_line
    assert "Use `strict` when context-lock coverage, digest drift" in readme_single_line


def test_evidence_contract_docs_cover_adoption_and_non_goals() -> None:
    docs = EVIDENCE_CONTRACTS_DOC.read_text(encoding="utf-8")
    docs_single_line = " ".join(docs.split())

    assert EVIDENCE_SAMPLE_REPORT.is_file()
    assert "generated from the current package version" in docs
    assert "Adoption Path: Minimal First, Then Recommended" in docs
    assert "| `minimal` |" in docs
    assert "| `recommended` |" in docs
    assert "| `strict` |" in docs
    assert "Choose the smallest profile that matches the review decision you need" in docs
    assert "Context policy, workflow policy, and surface inventory evidence." in docs
    assert "Minimal first pass" in docs
    assert "Move to recommended evidence" in docs
    assert "CI artifact" in docs
    assert "agent-policy" in docs
    assert "agent-policy-audit-event" in docs
    assert "examples/evidence_consumer.py" in docs
    assert "SARIF Thin Adapter" in docs
    assert "LLM reviewer" in docs
    assert "model router" in docs
    assert "large governance framework" in docs
    assert "Public Artifact Boundary" in docs
    assert "Raw per-scanner JSON" in docs
    assert "Do not" in docs
    assert "upload raw scanner JSON as a public artifact" in docs
    assert "owasp_agentic_risk_themes" in docs
    assert "runtime prompt/tool poisoning detection" in docs
    assert "live OAuth validation" in docs
    assert "generic secret scanning" in docs
    assert "SLSA/provenance verification" in docs
    assert "MCP security validation" in docs
    assert "live OAuth validator" in docs
    assert "they do not prove" in docs
    assert "live OAuth flow is correctly implemented" in docs
    assert "docs/threat-model.md" in docs
    assert "static evidence boundary" in docs
    assert "Review the `init --json` plan before" in docs
    assert "agent-guard init --root . --write" in docs
    assert (
        "agent-guard context lock --root . --policy .agent-guard/context-policy.yaml "
        "> .agent-guard/context-digest-policy.yaml"
        in docs
    )
    assert "Recommended is the reviewed static evidence baseline" in docs
    assert "does not require repository-specific digest or context-lock gates" in docs_single_line
    assert "mcp_config` records `mcp_policy_missing" in docs
    assert "`mcp_policy_weakened`" in docs
    assert "do not dump raw YAML content" in docs
    assert "raw repository/content/digest hash values" in docs_single_line
    assert "`partialFingerprints` are deterministic hashes of sanitized" in docs_single_line


def test_existing_repo_quickstart_and_github_docs_are_copyable() -> None:
    readme = README.read_text(encoding="utf-8")
    quickstart = EXISTING_REPO_QUICKSTART.read_text(encoding="utf-8")
    quickstart_single_line = " ".join(quickstart.split())
    actions = GITHUB_ACTIONS_EVIDENCE_DOC.read_text(encoding="utf-8")
    actions_single_line = " ".join(actions.split())

    assert "python3 -m venv .venv" in quickstart
    assert ".agent-guard/context-policy.yaml" in quickstart
    assert "agent-guard context inventory --root ." in quickstart
    assert "agent-guard mcp check --root ." in quickstart
    assert "--policy .agent-guard/mcp-policy.yaml" in quickstart
    assert "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2" in quickstart
    assert "agent-guard init --root . --json" in quickstart
    assert "agent-guard context lock --root ." in quickstart
    assert ".agent-guard/context-digest-policy.yaml" in quickstart
    assert "agent-guard report --root ." in quickstart
    assert "agent-guard render-report --root ." in quickstart
    assert "--evidence-preset recommended" in quickstart
    assert (
        "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml "
        "--evidence-preset recommended --format json"
        in readme
    )
    assert (
        "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml "
        "--evidence-preset recommended"
        in quickstart_single_line
    )
    assert "--agent-policy-audit-event .agent-guard/evidence/policy-admission-event.json" in quickstart
    assert "agent-guard conformance check --root ." in quickstart
    assert "agent-guard evidence-pack manifest --root ." in quickstart
    assert "LLM reviewer" in quickstart
    assert "MoA orchestrator" in quickstart
    assert "Raw scanner JSON" in quickstart
    assert "agent execution UI" in quickstart
    assert "MCP server names" in quickstart
    assert "MCP runtime" in quickstart
    assert "MCP tool-poisoning detector" in quickstart
    assert "validate live OAuth flows" in quickstart
    assert "Consume Evidence Safely" in quickstart
    assert "examples/evidence_consumer.py" in quickstart
    assert "docs/threat-model.md" in quickstart
    assert "Monorepos and Subdirectories" in quickstart
    assert "root: services/api" in quickstart
    assert "selected root" in quickstart
    assert "policy paths relative to that root" in quickstart
    assert "--root services/api" in quickstart
    assert "--output services/api/.agent-guard/evidence/agent-guard-report.json" in quickstart
    assert "repo-external policy files do not satisfy recommended or strict" in quickstart_single_line
    assert "Common rule ids map to these first checks" in quickstart
    assert "`mcp_policy_missing`" in quickstart
    assert "`required_mcp_policy_not_reviewed`" in quickstart
    assert "`mcp_policy_weakened`" in quickstart
    assert "`required_policy_file_missing`" in quickstart
    assert "`policy_spec_drift` findings" in quickstart
    assert "minimal-to-recommended path and monorepo/subdirectory roots" in readme
    assert "--conformance-profile strict" in quickstart
    assert "MCP runtime security validator" in quickstart
    assert "uses: actions/upload-artifact@v7" in actions
    assert f"uses: yui-stingray/agent-guard@v{pyproject_version()}" in actions
    assert "Recommended Action Workflow" in actions
    assert "root: services/api" in actions
    assert "Policy and evidence paths are" in actions
    assert "resolved relative to that root" in actions
    assert "conformance-profile: recommended" in actions
    assert "conformance-profile: strict" in actions
    assert "packaged action always generates the recommended evidence preset" in actions_single_line
    assert "${{ steps.agent-guard.outputs.evidence-dir }}" in actions
    assert "status=0" in actions
    assert "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2" in actions
    assert "agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml" in actions
    assert "mcp-policy" in actions
    assert "agent-guard drift check --root . --profile recommended --schema-version v2" in actions
    assert "--evidence-preset recommended" in actions
    assert "--agent-policy-audit-event .agent-guard/evidence/policy-admission-event.json" in actions
    assert "agent-guard conformance check --root ." in actions
    assert "agent-guard evidence-pack manifest --root ." in actions
    assert 'exit "$status"' in actions
    assert "if: always()" in actions
    assert "Recommended evidence is the default reviewed static baseline" in actions
    assert "use `conformance-profile: strict` when digest/context-lock" in actions
    assert "recommended static baseline after `agent-guard init --root . --write`" in actions
    assert "add `--digest-policy .agent-guard/context-digest-policy.yaml` only after generating" in actions_single_line
    assert (
        "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml "
        "--evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml "
        "--conformance-profile recommended --format json"
        in actions_single_line
    )
    assert "If the reviewed MCP policy is missing" in actions
    assert "`required_mcp_policy_not_reviewed`" in actions
    assert "not by pointing recommended evidence at an external policy file" in actions_single_line
    assert (
        "agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json "
        "--format github-annotations"
        in actions
    )
    assert "does not post pull request comments" in actions
    assert "examples/evidence_consumer.py" in actions
    assert "docs/threat-model.md" in actions
    assert "fail closed on schema drift" in actions
    assert "raw context text" in actions
    assert "raw repository/content/digest hashes" in actions
    assert "SARIF `partialFingerprints` derived only" in actions
    assert "OWASP risk-theme labels" in actions
    assert "live OAuth validator" in actions
    assert "scanner-specific metadata" in actions
    assert "workflow logs" in actions
    assert "Raw" in actions
    assert "scanner JSON may include scanner-specific metadata" in actions
    assert "do not upload it publicly" in actions
    assert "unless a maintainer has reviewed" in actions_single_line
    raw_json_doc_lines = [
        line.strip()
        for line in actions.splitlines()
        if line.strip().startswith("agent-guard ")
        and "--json" in line
        and any(
            command in line
            for command in (
                "context check",
                "workflow check",
                "drift check",
                "conformance check",
                "evidence-pack manifest",
            )
        )
    ]
    assert raw_json_doc_lines
    assert all(">" in line for line in raw_json_doc_lines)
    assert "Parallel Step Support" not in actions
    assert "step-level `parallel`" not in actions


def test_marketplace_readiness_stays_manual_and_static_only() -> None:
    readme = README.read_text(encoding="utf-8")
    release_criteria = RELEASE_CRITERIA_DOC.read_text(encoding="utf-8")

    assert "packaged alpha GitHub Action" in readme
    assert "The action generates static evidence only" in readme
    assert "Marketplace publication is not part of the automated release workflows" in release_criteria
    assert "`agent-guard static evidence`" in release_criteria
    assert "`Security` as the primary category" in release_criteria
    assert "`Code quality` as the secondary" in release_criteria
    assert "do not select `Code Scanning Ready`" in release_criteria
    assert "do not create a moving\n  `v0` alias" in release_criteria
    assert "explicit maintainer approval" in release_criteria


def test_positioning_doc_keeps_public_scope_narrow() -> None:
    docs = POSITIONING_DOC.read_text(encoding="utf-8")
    docs_single_line = " ".join(docs.split())

    assert "Static evidence contracts for AI-agent-maintained repositories." in docs
    assert "CONTINUE-NARROW" in docs
    assert "Python/PyPI static evidence package" in docs_single_line
    assert "init -> report -> upload evidence" in docs_single_line
    assert "demand signals" in docs
    assert "rename work" in docs
    assert "does not route" in docs
    assert "run LLM review" in docs
    assert "validate live OAuth flows" in docs
    assert "replace dedicated secret scanners" in docs
    assert "review metadata" in docs
    assert "related independent work" in docs


def test_threat_model_doc_keeps_static_boundary() -> None:
    docs = THREAT_MODEL_DOC.read_text(encoding="utf-8")
    docs_single_line = " ".join(docs.split())

    assert "deterministic static evidence gate" in docs
    assert "Public evidence must not disclose" in docs
    assert "raw evidence URLs" in docs
    assert "raw repository/content/digest hash values" in docs_single_line
    assert "Standard SARIF schema/tool URIs" in docs
    assert "`partialFingerprints` derived only from sanitized" in docs_single_line
    assert "What It Can Catch" in docs
    assert "What It Cannot Prove" in docs
    assert "MCP-Specific Boundary" in docs
    assert "Evidence Consumer Expectations" in docs
    assert "API keys, access tokens, passwords, private keys" in docs
    assert "runtime prompt injection" in docs
    assert "MCP tool poisoning" in docs
    assert "live OAuth validation" in docs
    assert "generic secret scanner" not in docs
    assert "does not execute MCP servers" in docs_single_line
    assert "do not satisfy reviewed-policy conformance" in docs_single_line
    assert "examples/evidence_consumer.py" in docs
    assert "agent-guard.report_evidence.v1" in docs
    assert "not as runtime safety guarantees" in docs_single_line
    assert "Reference snapshot: verified on 2026-07-09" in docs
    assert "MCP 2025-11-25 latest specification family" in docs
    assert "non-final MCP 2026-07-28 release candidate" in docs_single_line
    assert "OWASP Top 10 for Agentic Applications 2026" in docs_single_line
    assert "published 2025-12-09" in docs
    assert "OWASP Agentic Skills Top 10 Incubator/Public review (v1) material" in docs_single_line
    assert "SLSA v1.2 Approved specification" in docs_single_line
    assert "NIST AI 600-1 Generative AI Profile" in docs_single_line
    assert "NIST SSDF SP 800-218 v1.1 Final" in docs_single_line
    assert "May 2025 v1.0 joint AI Data Security guidance" in docs_single_line
    assert "2026 Five Eyes careful-adoption guidance for agentic AI services" in docs_single_line
    assert "must not be described as certification, compliance" in docs_single_line
    assert "live OAuth validation, or runtime MCP/tool-poisoning detection" in docs_single_line


def test_release_criteria_keep_patch_releases_bounded() -> None:
    docs = RELEASE_CRITERIA_DOC.read_text(encoding="utf-8")

    assert "Batched Release Cadence" in docs
    assert "weekly" in docs
    assert "P0 fix" in docs
    assert "Do not cut a patch release for every qualifying change" in docs
    assert "Docs-only changes under `docs/` do not need an immediate release" in docs
    assert "packaged JSON Schema" in docs
    assert "schema/contract stability" in docs
    assert "wheel contract check" in docs
    assert "LLM review" in docs
    assert "model routing" in docs
    assert "live OAuth validation" in docs
    assert "security/compliance certification" in docs


def test_readme_documents_operational_example_policy_coverage() -> None:
    readme = README.read_text(encoding="utf-8")

    assert '- "**/*.yaml"' in readme
    assert '- "**/*.sh"' in readme
    assert "destructive_rm_root" in readme
    assert "local_artifacts" in readme


def test_readme_documents_surface_delta_evidence() -> None:
    readme = README.read_text(encoding="utf-8")
    readme_single_line = " ".join(readme.split())

    assert "### Surface delta evidence" in readme
    assert "agent-guard surface delta --root . --context-policy <policy> --base-ref <ref>" in readme
    assert "agent-guard.surface_delta.v1.schema.json" in readme
    assert "--surface-delta-base-ref <ref>" in readme
    assert "## Surface Delta Evidence" in readme
    assert '`changed_fields: ["content"]`' in readme
    assert "existing file-backed context, policy, workflow, evidence artifact" in readme_single_line
    assert "neither content nor a content fingerprint value is published" in readme_single_line
    assert (
        "agent-guard surface delta --root . --context-policy .agent-guard/context-policy.yaml "
        "--base-ref <base-ref> --json"
        in readme
    )


def test_evidence_contract_docs_cover_surface_delta() -> None:
    docs = EVIDENCE_CONTRACTS_DOC.read_text(encoding="utf-8")
    docs_single_line = " ".join(docs.split())

    assert "agent-guard.surface_delta.v1.schema.json" in docs
    assert "controlled-vocabulary `changed_fields` names" in docs_single_line
    assert "It is review evidence, not a gate" in docs_single_line
    assert "never emitted to SARIF" in docs_single_line
    assert "tar extraction filter available from Python 3.11.4" in docs_single_line
    assert "there is no unfiltered fallback" in docs_single_line
    assert "controlled field name `content`" in docs_single_line
    assert "existing file-backed context, policy, workflow, evidence artifact" in docs_single_line
    assert "never emits the instruction body or an internal content fingerprint value" in docs_single_line
    assert "Policy is always read from the current working tree, never from the base" in docs_single_line


def test_github_actions_evidence_doc_covers_surface_delta_recipe() -> None:
    actions = GITHUB_ACTIONS_EVIDENCE_DOC.read_text(encoding="utf-8")
    surface_delta_section = actions.split("## Surface Delta Evidence On Pull Requests", 1)[1].split(
        "## Expanded Workflow Step", 1
    )[0]

    assert "## Surface Delta Evidence On Pull Requests" in actions
    assert "surface-delta-base-ref: origin/${{ github.base_ref }}" in actions
    assert "${{ github.event.pull_request.base.sha }}" in actions
    assert "fetch-depth: 0" in actions
    assert "never emitted to SARIF" in actions or "never SARIF" in actions
    assert "currently unreleased" in surface_delta_section
    assert "yui-stingray/agent-guard@<release-tag-with-surface-delta>" in surface_delta_section
    assert "yui-stingray/agent-guard@v0.2.4" not in surface_delta_section
