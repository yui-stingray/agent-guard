"""Where: tests/test_docs_contract.py
What: README, quickstart, release, and positioning documentation contracts.
Why: keep public docs aligned with the package contract and static-evidence boundary.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import yaml

from agent_guard.init_guard import (
    GITHUB_WORKFLOW,
    PUBLISHED_CONTEXT_POLICY_PREFLIGHT,
    PUBLISHED_PACKAGE_VERSION,
)
from agent_guard.profiles import profile_requirements
from agent_guard.surface_inventory_metadata import collect_documented_guard_surfaces
from agent_guard.surface_inventory_workflow import collect_workflow_surfaces


REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
README = REPO_ROOT / "README.md"
CONTRIBUTING = REPO_ROOT / "CONTRIBUTING.md"
EVIDENCE_CONTRACTS_DOC = REPO_ROOT / "docs" / "evidence-contracts.md"
EVIDENCE_CONSUMER_CONTRACTS_DOC = REPO_ROOT / "docs" / "evidence-consumer-contracts.md"
EVIDENCE_SAMPLE_REPORT = REPO_ROOT / "docs" / "evidence-samples" / "agent-guard-report.json"
EXISTING_REPO_QUICKSTART = REPO_ROOT / "docs" / "quickstart-existing-repo.md"
GITHUB_ACTIONS_EVIDENCE_DOC = REPO_ROOT / "docs" / "github-actions-evidence.md"
ACTION_METADATA = REPO_ROOT / "action.yml"
RELEASE_CRITERIA_DOC = REPO_ROOT / "docs" / "release-criteria.md"
POSITIONING_DOC = REPO_ROOT / "docs" / "positioning.md"
DEMAND_VALIDATION_DOC = REPO_ROOT / "docs" / "demand-validation.md"
THREAT_MODEL_DOC = REPO_ROOT / "docs" / "threat-model.md"
COMPATIBILITY_DOC = REPO_ROOT / "docs" / "compatibility.md"
COMPARISON_DOC = REPO_ROOT / "docs" / "comparison.md"
SECURITY_POLICY = REPO_ROOT / "SECURITY.md"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
ACTION_RELEASE_VERSION = "0.3.7"
ACTION_RELEASE_COMMIT = "67d8828ccf5b199d0cf9e99007de53436ac47f7a"
PACKAGE_RELEASE_VERSION = "0.3.7"


def pyproject_version() -> str:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_readme_matches_release_package_identity() -> None:
    readme = README.read_text(encoding="utf-8")

    assert pyproject_version() == PACKAGE_RELEASE_VERSION
    assert f"**Status**: `{PACKAGE_RELEASE_VERSION}` alpha." in readme


def test_release_identity_contains_the_executable_change_notes() -> None:
    changelog = CHANGELOG.read_text(encoding="utf-8")
    release_notes = changelog.split("## 0.3.7 - 2026-08-24", maxsplit=1)[1].split(
        "## 0.3.6 - 2026-08-23", maxsplit=1
    )[0]

    assert pyproject_version() == PACKAGE_RELEASE_VERSION
    assert PUBLISHED_PACKAGE_VERSION == PACKAGE_RELEASE_VERSION
    assert "PyPI-specific long description" in release_notes
    assert "self-Action pin" in release_notes


def test_copyable_action_snippets_use_one_immutable_release_pin() -> None:
    assert re.fullmatch(r"[0-9a-f]{40}", ACTION_RELEASE_COMMIT)

    docs = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            README,
            EXISTING_REPO_QUICKSTART,
            GITHUB_ACTIONS_EVIDENCE_DOC,
            EVIDENCE_CONSUMER_CONTRACTS_DOC,
        )
    )
    action_reference_lines = [
        line for line in docs.splitlines() if "yui-stingray/agent-guard@" in line
    ]
    pins = set(re.findall(r"yui-stingray/agent-guard@([^\s]+)", docs))
    referenced_outputs = set(
        re.findall(r"steps\.agent-guard\.outputs\.([A-Za-z0-9-]+)", docs)
    )
    action = yaml.safe_load(ACTION_METADATA.read_text(encoding="utf-8"))

    expected_reference = (
        f"yui-stingray/agent-guard@{ACTION_RELEASE_COMMIT} "
        f"# v{ACTION_RELEASE_VERSION}"
    )
    assert action_reference_lines
    assert all(expected_reference in line for line in action_reference_lines)
    assert pins == {ACTION_RELEASE_COMMIT}
    assert re.search(r"yui-stingray/agent-guard@v\d", docs) is None

    yaml_blocks = re.findall(r"```yaml\n(.*?)\n```", docs, flags=re.DOTALL)
    complete_workflows = [
        yaml.safe_load(block)
        for block in yaml_blocks
        if "yui-stingray/agent-guard@" in block and "jobs:" in block
    ]
    assert len(complete_workflows) == 3
    for workflow in complete_workflows:
        assert isinstance(workflow, dict)
        assert workflow.get("on", workflow.get(True)) == ["push", "pull_request"]
        job = workflow["jobs"]["agent-guard"]
        steps = job["steps"]
        checkout = next(
            step
            for step in steps
            if str(step.get("uses", "")).startswith("actions/checkout@")
        )
        preflight = next(
            step
            for step in steps
            if step.get("name") == "Reject unreviewed context policy changes"
        )
        action_step = next(
            step
            for step in steps
            if str(step.get("uses", "")).startswith("yui-stingray/agent-guard@")
        )

        assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}
        assert preflight["if"] == "github.event_name == 'pull_request'"
        action_inputs = action_step.get("with", {})
        assert preflight["env"] == {
            "AGENT_GUARD_PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
            "AGENT_GUARD_ROOT": action_inputs.get("root", "."),
            "AGENT_GUARD_CONTEXT_POLICY": action_inputs.get(
                "context-policy", ".agent-guard/context-policy.yaml"
            ),
        }
        assert preflight["run"].rstrip() == PUBLISHED_CONTEXT_POLICY_PREFLIGHT
        assert "git diff --exit-code" not in preflight["run"]
        assert action_step["timeout-minutes"] == 1

    for block in yaml_blocks:
        if "yui-stingray/agent-guard@" in block:
            assert block.count("timeout-minutes: 1") == block.count(
                "yui-stingray/agent-guard@"
            )
    assert referenced_outputs
    assert referenced_outputs <= set(action["outputs"])


def test_documented_workflow_steps_are_executable() -> None:
    documents = (README, EXISTING_REPO_QUICKSTART, GITHUB_ACTIONS_EVIDENCE_DOC)
    step_lists: list[list[dict[str, object]]] = []

    for document in documents:
        blocks = re.findall(
            r"```yaml\n(.*?)\n```",
            document.read_text(encoding="utf-8"),
            flags=re.DOTALL,
        )
        for block in blocks:
            parsed = yaml.safe_load(block)
            if isinstance(parsed, list) and any(
                isinstance(item, dict) and ({"run", "uses"} & set(item))
                for item in parsed
            ):
                step_lists.append(parsed)
            elif isinstance(parsed, dict) and isinstance(parsed.get("steps"), list):
                step_lists.append(parsed["steps"])
            elif isinstance(parsed, dict) and isinstance(parsed.get("jobs"), dict):
                for job in parsed["jobs"].values():
                    if isinstance(job, dict) and isinstance(job.get("steps"), list):
                        step_lists.append(job["steps"])

    assert step_lists
    for steps in step_lists:
        for step in steps:
            assert isinstance(step, dict)
            assert "run" in step or "uses" in step


def test_generated_workflow_uses_the_release_package_and_bounded_action_step() -> None:
    readme = README.read_text(encoding="utf-8")
    quickstart = EXISTING_REPO_QUICKSTART.read_text(encoding="utf-8")

    assert PUBLISHED_PACKAGE_VERSION == PACKAGE_RELEASE_VERSION
    assert f"yui-agent-guard=={PACKAGE_RELEASE_VERSION}" in GITHUB_WORKFLOW
    assert "Reject unreviewed context policy changes" in GITHUB_WORKFLOW
    assert "context policy preflight rejected a pull-request change" in GITHUB_WORKFLOW
    assert "published agent-guard 0.3.4 cannot evaluate a context policy changed by a pull request" not in GITHUB_WORKFLOW
    assert "timeout-minutes: 1" in GITHUB_WORKFLOW
    assert "workflow generated by published `0.3.4` predates" not in readme
    assert "workflow generated by published `0.3.4` predates" not in quickstart


def test_copyable_workflows_pin_third_party_actions_like_generated_workflow() -> None:
    public_docs = [README, *sorted((REPO_ROOT / "docs").glob("*.md"))]

    for action_name in ("checkout", "setup-python", "upload-artifact"):
        generated = re.search(
            rf"actions/{re.escape(action_name)}@[0-9a-f]{{40}} # v[^\s]+",
            GITHUB_WORKFLOW,
        )
        assert generated is not None
        expected = generated.group(0)
        references = [
            line.strip()
            for path in public_docs
            for line in path.read_text(encoding="utf-8").splitlines()
            if f"uses: actions/{action_name}@" in line
        ]
        assert references
        assert all(expected in line for line in references)


def test_copyable_workflows_pin_every_external_action_to_a_commit() -> None:
    public_docs = [README, *sorted((REPO_ROOT / "docs").glob("*.md"))]
    references = [
        match.group(1)
        for path in public_docs
        for match in re.finditer(
            r"^\s*(?:-\s*)?uses:\s*([^\s#]+)",
            path.read_text(encoding="utf-8"),
            flags=re.MULTILINE,
        )
    ]

    assert references
    for reference in references:
        if reference.startswith("./"):
            continue
        assert re.fullmatch(
            r"[^/@\s]+/[^/@\s]+(?:/[^@\s]+)*@[0-9a-f]{40}",
            reference,
        ), reference


def test_readme_yaml_examples_parse() -> None:
    blocks = re.findall(
        r"```yaml\n(.*?)\n```",
        README.read_text(encoding="utf-8"),
        flags=re.DOTALL,
    )

    assert blocks
    for block in blocks:
        yaml.safe_load(block)


def test_readme_documents_python_patch_floor() -> None:
    readme = README.read_text(encoding="utf-8")
    contributing = CONTRIBUTING.read_text(encoding="utf-8")

    assert "Python 3.11.4+" in readme
    assert "Requires Python 3.11.4+." in readme
    assert "Use Python 3.11.4 or newer." in contributing


def test_unreleased_v2_path_contract_is_consistent_in_public_docs() -> None:
    documents = (
        README.read_text(encoding="utf-8"),
        EVIDENCE_CONTRACTS_DOC.read_text(encoding="utf-8"),
        COMPATIBILITY_DOC.read_text(encoding="utf-8"),
    )

    for document in documents:
        normalized = " ".join(document.split())
        assert "printable ASCII" in normalized
        assert "secret-shaped" in normalized
        assert "64-hex" in normalized
        assert (
            "not generic secret scanning" in normalized
            or "not a generic secret scanner" in normalized
        )


def test_evidence_sample_documented_commands_match_current_docs() -> None:
    payload = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))
    sample_surfaces = [
        item
        for item in payload["surface_inventory"]["surfaces"]
        if item.get("surface") == "documented_guard_command"
    ]

    current_surfaces = collect_documented_guard_surfaces(REPO_ROOT)
    assert [
        {key: value for key, value in item.items() if key != "line"}
        for item in sample_surfaces
    ] == [
        {key: value for key, value in item.items() if key != "line"}
        for item in current_surfaces
    ]


def test_evidence_sample_workflow_surfaces_match_current_workflows() -> None:
    payload = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))
    workflow_surface_names = {
        "evidence_artifact_reference",
        "workflow_file",
        "workflow_reference",
    }
    sample_surfaces = [
        item
        for item in payload["surface_inventory"]["surfaces"]
        if item.get("surface") in workflow_surface_names
    ]

    expected_surfaces = sorted(
        collect_workflow_surfaces(REPO_ROOT, include_artifacts=True),
        key=lambda item: (str(item.get("path", "")), str(item.get("surface", ""))),
    )
    assert sample_surfaces == expected_surfaces


def test_evidence_sample_tool_versions_match_published_package() -> None:
    payload = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))
    version = PACKAGE_RELEASE_VERSION

    assert payload["tool"] == {"name": "agent-guard", "version": version}
    assert payload["evidence_pack_manifest"]["tool"] == {
        "name": "agent-guard",
        "version": version,
    }


def test_evidence_sample_uses_the_tracked_release_tree_path_count() -> None:
    payload = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))

    # Measured by regenerating the sample in a tracked-only temporary worktree.
    assert payload["path"]["checked_count"] == 328
    assert payload["summary"]["path_checked_count"] == 328


def test_evidence_sample_only_describes_committed_evidence_artifacts() -> None:
    payload = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))
    evidence_artifacts = [
        item
        for item in payload["surface_inventory"]["surfaces"]
        if item.get("surface") == "evidence_artifact"
    ]

    assert evidence_artifacts == [
        {
            "kind": "committed_evidence_sample",
            "path": "docs/evidence-samples/agent-guard-report.json",
            "size_bytes": EVIDENCE_SAMPLE_REPORT.stat().st_size,
            "status": "present",
            "surface": "evidence_artifact",
        }
    ]


def test_onboarding_commands_pin_the_published_package_version() -> None:
    version = PACKAGE_RELEASE_VERSION
    readme = README.read_text(encoding="utf-8")
    quickstart = EXISTING_REPO_QUICKSTART.read_text(encoding="utf-8")
    consumer_contracts = EVIDENCE_CONSUMER_CONTRACTS_DOC.read_text(encoding="utf-8")

    assert f"python -m pip install yui-agent-guard=={version}" in readme
    assert f"--from yui-agent-guard=={version}" in readme
    assert f"--from yui-agent-guard=={version}" in quickstart
    assert f"python -m pip install yui-agent-guard=={version}" in quickstart
    assert consumer_contracts.count(
        f"python -m pip install yui-agent-guard=={version}"
    ) == 2
    assert re.search(r"pip install yui-agent-guard(?:\s|$)", consumer_contracts) is None

    bootstrap = readme[readme.index("## Start with a reviewed bootstrap") : readme.index("## Why")]
    trial = bootstrap[
        bootstrap.index("### Preview without target-repository writes") : bootstrap.index(
            "### Adopt after review"
        )
    ]
    adoption = bootstrap[bootstrap.index("### Adopt after review") :]
    trial_single_line = " ".join(trial.split())
    adoption_single_line = " ".join(adoption.split())
    preview_command = (
        f"uvx --python 3.12 --from yui-agent-guard=={version} "
        "agent-guard init --root . --print"
    )

    assert preview_command in trial
    assert "without a persistent install" in trial
    assert "target-repository writes" in trial
    assert "not a scan or evidence result" in trial
    assert "may populate caches outside the repository" in trial_single_line
    assert (
        "does not write the proposed policies or workflow into the selected root"
        in trial_single_line
    )
    assert "agent-guard init --root . --write" not in trial
    assert "--force" not in bootstrap
    assert "--skip-existing" not in bootstrap
    assert f"python -m pip install yui-agent-guard=={version}" in adoption
    adoption_markers = [
        "agent-guard init --root . --print",
        "Review the proposed policies and workflow before the write step",
        "agent-guard init --root . --write",
        "Inspect the generated files before running the first local diagnostic",
        "agent-guard report --root .",
        "Review and commit the starter policies and replacement workflow",
        "Keep reports uncommitted unless curated as sanitized samples",
        "successful default-branch run",
    ]
    marker_positions = [adoption_single_line.index(marker) for marker in adoption_markers]
    assert marker_positions == sorted(marker_positions)
    assert "commit the generated files" not in adoption_single_line
    assert sum(
        line.strip() == "agent-guard init --root . --print" for line in readme.splitlines()
    ) == 1
    assert sum(line.strip() == preview_command for line in readme.splitlines()) == 1
    assert "## Adoption and CI reference" in readme


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
    assert "Other raw per-scanner JSON remains a" in opening
    assert "local/CI-internal surface unless a maintainer reviews it" in opening
    assert "standalone `agent-guard surface inventory`" in opening
    assert "It is **not** an authorship detector" in opening
    assert re.search(r"It is \*\*not\*\*[^.]{0,180}\bprovenance system\b", opening, re.IGNORECASE)
    assert not re.search(
        r"\b(SBOM|DCO|ISO|NIST|compliance|certification|attestation)\b",
        opening,
        re.IGNORECASE,
    )


def test_quickstart_documents_windows_without_activation() -> None:
    version = PACKAGE_RELEASE_VERSION
    readme = README.read_text(encoding="utf-8")
    quickstart = EXISTING_REPO_QUICKSTART.read_text(encoding="utf-8")

    assert "Windows PowerShell users" in readme
    assert "avoid activation and execution-policy friction" in quickstart
    assert rf".\.venv\Scripts\python.exe -m pip install yui-agent-guard=={version}" in quickstart
    assert r".\.venv\Scripts\agent-guard.exe init --root . --print" in quickstart
    assert r".\.venv\Scripts\agent-guard.exe init --root . --write" in quickstart
    assert r".\.venv\Scripts\agent-guard.exe report --root ." in quickstart


def test_security_policy_tracks_the_current_alpha_series() -> None:
    security = SECURITY_POLICY.read_text(encoding="utf-8")

    assert "latest published `0.x` release is supported" in security
    assert "latest published `0.1.x` release" not in security


def test_public_docs_align_release_package_features_and_action_pin() -> None:
    readme = README.read_text(encoding="utf-8")
    security = SECURITY_POLICY.read_text(encoding="utf-8")
    evidence_contracts = EVIDENCE_CONTRACTS_DOC.read_text(encoding="utf-8")
    compatibility = COMPATIBILITY_DOC.read_text(encoding="utf-8")
    quickstart = EXISTING_REPO_QUICKSTART.read_text(encoding="utf-8")

    assert "immutable\n`0.3.7` Action" in readme
    assert "unreviewed" in readme
    assert "context" in readme
    assert "defense in depth" in readme
    assert ACTION_RELEASE_VERSION in readme
    assert "Published `0.3.4`" in security
    assert "unreviewed" in security
    assert "context" in security
    assert "regular expression" in security
    assert "0.3.5" in security
    for docs in (evidence_contracts, compatibility, quickstart):
        normalized = " ".join(docs.split())
        assert "Version gate" in docs
        assert "agent-guard.public_agent_policy_audit_event.v1" in docs
        assert PACKAGE_RELEASE_VERSION in docs
        assert "Action" in docs
        assert (
            f"immutable `{ACTION_RELEASE_VERSION}` release commit" in normalized
        )
    assert re.findall(r"published `([^`]+)` Action", quickstart) == [
        ACTION_RELEASE_VERSION
    ]
    for docs in (evidence_contracts, quickstart):
        normalized = " ".join(docs.split())
        assert "The Action does not expose audit-event inputs" in normalized
        assert "its generated report and manifest remain v1" in normalized
        assert "requires consumer `--repo-root`" in normalized
    for docs in (evidence_contracts, compatibility):
        normalized = " ".join(docs.split())
        assert "public-safe subset" in normalized
        assert "underlying" in normalized
    assert PACKAGE_RELEASE_VERSION in readme
    assert "does not claim validation against the generic" in " ".join(
        compatibility.split()
    )


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
    assert "--agent-policy-audit-event" in readme
    assert ".agent-guard/evidence/policy-admission-event.json" not in readme
    assert (
        "agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json "
        "--profile recommended --json"
        in readme
    )
    assert "agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json" in readme
    assert (
        "agent-guard context lock --root . --policy .agent-guard/context-policy.yaml "
        "> .agent-guard/context-digest-policy.yaml"
        in readme
    )
    assert "> .agent-guard/context-lock.yaml" not in readme


def test_readme_documents_agent_policy_companion_boundary() -> None:
    readme = README.read_text(encoding="utf-8")
    normalized = " ".join(readme.split())

    assert "standalone public entry" in normalized
    assert "optional advanced runtime companion" in normalized
    assert "standalone static publication gate" in normalized
    assert "if a repository also needs runtime admission" in normalized.lower()
    assert "reference implementation" in normalized
    assert "one half of a small agent safety toolkit" not in readme
    assert "| Optional runtime admission | `agent-policy` |" in readme
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
    assert "--stderr-summary" in readme
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
    assert "controlled-field/controlled-pattern contract" in readme
    assert "not a generic guarantee that an artifact contains no secrets or PII" in readme_single_line
    assert "does not replace a dedicated secret scanner" in readme_single_line
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
    assert "Unreleased source-only CLI additions" not in cli_reference
    assert "agent-guard init --root <repo> [--print] [--write] [--skip-existing] [--force] [--json]" in cli_reference
    assert "[--output <path>] [--stderr-summary]" in cli_reference
    assert "--surface-delta-base-ref <ref>" in cli_reference
    assert "env values" in readme
    assert "owasp_agentic_risk_themes" in readme
    assert "not runtime vulnerability detection" in readme
    assert "live OAuth validation" in readme
    assert "SLSA/provenance verification" in readme
    assert "MCP runtime security validator" in readme
    assert "they do not prove" in readme
    assert "live OAuth flow is correctly implemented" in readme
    assert "2026-07-28 protocol/runtime/OAuth changes do not justify" in readme
    assert "No changelog item directly invalidates the current static committed-config labels" in readme_single_line
    assert "Read `recommended` as the reviewed static evidence baseline" in readme
    assert "recommended conformance does not require those gates" in readme_single_line
    assert "Use `strict` when context-lock coverage, digest drift" in readme_single_line


def test_evidence_contract_docs_cover_adoption_and_non_goals() -> None:
    docs = EVIDENCE_CONTRACTS_DOC.read_text(encoding="utf-8")
    docs_single_line = " ".join(docs.split())

    assert EVIDENCE_SAMPLE_REPORT.is_file()
    assert "generated from the latest published package version" in docs_single_line
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
    assert "controlled-field/controlled-pattern contract" in docs
    assert "not a generic secret/PII absence guarantee" in docs_single_line
    assert "dedicated secret scanners" in docs
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
    assert "2026-07-28 protocol/runtime/OAuth changes do not expand this" in docs
    assert "No changelog item directly invalidates the current committed-config labels" in docs_single_line
    assert "docs/threat-model.md" in docs
    assert "static evidence boundary" in docs
    assert "Review the `init --print` plan before" in docs
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
    assert "`report.scope` is a compatibility-preserved, coarse scanner summary" in docs
    assert "the released shorthand names `mcp` and `drift`" in docs_single_line
    assert "must use `evidence_coverage.gates`" in docs_single_line
    assert "`mcp_config`, `policy_spec_drift`, `surface_inventory`, and `context_lock`" in docs_single_line
    assert "do not dump raw YAML content" in docs
    assert "raw repository/content/digest hash values" in docs_single_line
    assert "`partialFingerprints` are deterministic hashes of sanitized" in docs_single_line
    assert "replaced as a whole" in docs_single_line
    assert "mapping keys become identical after sanitization" in docs_single_line
    assert "fails closed with a generic error" in docs_single_line


def test_optional_agent_policy_event_stays_outside_public_bundle() -> None:
    documents = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (README, EXISTING_REPO_QUICKSTART, EVIDENCE_CONTRACTS_DOC)
    )
    single_line = " ".join(documents.split())

    assert ".agent-guard/evidence/policy-admission-event.json" not in documents
    assert "outside `.agent-guard/evidence`" in single_line
    assert "profile-bound" in single_line
    assert "reads and canonicalizes" in single_line
    assert "never embeds the event body" in single_line
    assert "requires the event separately" in single_line
    assert "both the `report`" in single_line
    assert "manifest embedded in the report" in single_line


def test_quickstart_strict_prerequisites_match_profile_requirements() -> None:
    quickstart = " ".join(
        EXISTING_REPO_QUICKSTART.read_text(encoding="utf-8").split()
    )
    recommended = profile_requirements("recommended")
    strict = profile_requirements("strict")

    assert set(strict["gates"]) - set(recommended["gates"]) == {
        "context_lock",
        "digest",
    }
    assert strict["report_sections"] == ("evidence_pack_manifest",)
    assert strict["artifact_roles"] == ("report",)
    strict_only_surfaces = set(strict["surfaces"]) - set(recommended["surfaces"])
    strict_only_boundaries = set(strict["boundary_categories"]) - set(
        recommended["boundary_categories"]
    )
    assert strict_only_surfaces == {
        "documented_guard_command",
        "evidence_artifact_reference",
    }
    assert strict_only_boundaries == {
        "tool_permission_boundary",
        "network_boundary",
        "destructive_action_boundary",
    }
    for phrase in (
        "context-lock and digest gates",
        "sanitized evidence-pack manifest with the report artifact role",
        "v2 MCP risk-label requirements",
    ):
        assert phrase in quickstart
    for requirement in sorted(strict_only_surfaces | strict_only_boundaries):
        assert f"`{requirement}`" in quickstart


def test_existing_repo_quickstart_and_github_docs_are_copyable() -> None:
    readme = README.read_text(encoding="utf-8")
    quickstart = EXISTING_REPO_QUICKSTART.read_text(encoding="utf-8")
    quickstart_single_line = " ".join(quickstart.split())
    actions = GITHUB_ACTIONS_EVIDENCE_DOC.read_text(encoding="utf-8")
    actions_single_line = " ".join(actions.split())

    assert quickstart.index("## 4. Optional Review Commands") < quickstart.index(
        "## 5. Consume Evidence Safely"
    ) < quickstart.index("## 6. Reading Exit Codes")

    def fenced_code_blocks(document: str) -> list[list[str]]:
        blocks: list[list[str]] = []
        block: list[str] | None = None
        fence: str | None = None

        for line in document.splitlines():
            stripped = line.lstrip()
            if block is None:
                match = re.match(r"(`{3,}|~{3,})", stripped)
                if match:
                    fence = match.group(1)
                    block = []
            elif fence is not None and re.fullmatch(
                rf"{re.escape(fence[0])}{{{len(fence)},}}\s*", stripped
            ):
                blocks.append(block)
                block = None
                fence = None
            else:
                block.append(line)

        return blocks

    consumer_blocks = [
        block
        for block in fenced_code_blocks(quickstart)
        if "sh examples/evidence_contracts_ci.sh consume" in block
    ]
    assert len(consumer_blocks) == 1
    consumer_block = consumer_blocks[0]

    def shell_assignment_value(name: str) -> str:
        prefix = f"{name}="
        assignment_lines = [
            line.lstrip()
            for line in consumer_block
            if line.lstrip().startswith(prefix)
        ]
        assert len(assignment_lines) == 1
        assignment = assignment_lines[0]
        assert assignment.endswith("\\")
        return assignment.removeprefix(prefix).removesuffix("\\").rstrip()

    consumer_environment = {
        "root": shell_assignment_value("AGENT_GUARD_ROOT"),
        "evidence_dir": shell_assignment_value("AGENT_GUARD_EVIDENCE_DIR"),
        "report_json": shell_assignment_value("AGENT_GUARD_REPORT_JSON"),
    }
    assert consumer_environment == {
        "root": "services/api",
        "evidence_dir": ".agent-guard/evidence",
        "report_json": "services/api/.agent-guard/evidence/agent-guard-report.json",
    }
    resolved_evidence_dir = (
        REPO_ROOT / consumer_environment["root"] / consumer_environment["evidence_dir"]
    ).resolve()
    assert (REPO_ROOT / consumer_environment["report_json"]).resolve() == (
        resolved_evidence_dir / "agent-guard-report.json"
    )

    assert "python3 -m venv .venv" in quickstart
    assert "Use Python 3.11.4+ as the `agent-guard` tool interpreter" in quickstart
    assert "`python3` must resolve to Python 3.11.4+" in quickstart
    python_version_check = (
        "python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11, 4) "
        'else "agent-guard requires Python 3.11.4+")\''
    )
    venv_command = "python3 -m venv .venv"
    guarded_venv_sequence = f"{python_version_check} && \\\n{venv_command}"
    assert quickstart.count(guarded_venv_sequence) == quickstart.count(venv_command) > 0
    assert "TTFE benchmark" not in quickstart
    assert quickstart.count("# Review the proposed starter policies and workflow") == 2
    assert quickstart.count("# Inspect the generated starter files") == 2
    assert ".agent-guard/context-policy.yaml" in quickstart
    assert "agent-guard context inventory --root ." in quickstart
    assert "agent-guard mcp check --root ." in quickstart
    assert "--policy .agent-guard/mcp-policy.yaml" in quickstart
    assert "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2" in quickstart
    assert "agent-guard init --root . --print" in quickstart
    assert "agent-guard init --root . --write --skip-existing" in quickstart
    assert "does not mean those preserved files are trusted" in quickstart_single_line
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
    assert "--stderr-summary" in quickstart
    assert "`--output` creates parent directories" in quickstart
    assert "Exit `1` from this first `report` command is a diagnostic success" in quickstart_single_line
    assert "Exit `>=2` is a" in quickstart
    assert "Python 3.11.4+ requirement applies to the tool environment" in quickstart
    assert "The packaged GitHub Action provisions its own Python" in quickstart
    assert (
        "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml "
        "--evidence-preset recommended"
        in quickstart_single_line
    )
    assert "--agent-policy-audit-event" in quickstart
    assert ".agent-guard/evidence/policy-admission-event.json" not in quickstart
    assert "agent-guard conformance check --root ." in quickstart
    assert "agent-guard evidence-pack manifest --root ." in quickstart
    assert "LLM reviewer" in quickstart
    assert "MoA orchestrator" in quickstart
    assert "Raw scanner JSON" in quickstart
    assert "standalone surface inventory, conformance, and evidence-pack" in quickstart
    assert "recursively sanitized" in quickstart
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
    assert "golden path moves directly to `recommended`" in quickstart_single_line
    assert "evidence-contracts.md#adoption-path-minimal-first-then-recommended" in quickstart
    assert "--conformance-profile strict" in quickstart
    assert "MCP runtime security validator" in quickstart
    assert "uses: actions/upload-artifact@" in actions
    assert (
        f"uses: yui-stingray/agent-guard@{ACTION_RELEASE_COMMIT} "
        f"# v{ACTION_RELEASE_VERSION}"
        in actions
    )
    assert "Recommended Action Workflow" in actions
    assert "root: services/api" in actions
    assert "Policy and evidence paths are" in actions
    assert "resolved relative to that root" in actions_single_line
    assert "conformance-profile: recommended" in actions
    assert "conformance-profile: strict" in actions
    assert "packaged action always generates the recommended evidence preset" in actions_single_line
    assert "${{ steps.agent-guard.outputs.evidence-dir }}" in actions
    recommended_yaml = actions.split("## Recommended Action Workflow", 1)[1].split(
        "```yaml", 1
    )[1].split("```", 1)[0]
    recommended_workflow = yaml.safe_load(recommended_yaml)
    recommended_checkout = recommended_workflow["jobs"]["agent-guard"]["steps"][0]
    assert recommended_checkout["with"]["persist-credentials"] is False
    action_lines = actions.splitlines()
    checkout_lines = [
        index
        for index, line in enumerate(action_lines)
        if line.strip().startswith("- uses: actions/checkout@")
    ]
    assert checkout_lines
    assert all(
        "persist-credentials: false" in "\n".join(action_lines[index : index + 6])
        for index in checkout_lines
    )
    recommended_upload = next(
        step
        for step in recommended_workflow["jobs"]["agent-guard"]["steps"]
        if isinstance(step, dict) and step.get("name") == "Upload evidence"
    )
    assert recommended_upload["if"] == (
        "always() && steps.agent-guard.outputs.ready == 'true' && "
        "(steps.agent-guard.outputs.status == '0' || "
        "steps.agent-guard.outputs.status == '1')"
    )
    assert recommended_upload["with"]["path"].splitlines() == [
        "${{ steps.agent-guard.outputs.report-json }}",
        "${{ steps.agent-guard.outputs.report-markdown }}",
        "${{ steps.agent-guard.outputs.report-sarif }}",
        "${{ steps.agent-guard.outputs.evidence-dir }}/agent-guard-conformance.json",
        "${{ steps.agent-guard.outputs.evidence-dir }}/agent-guard-evidence-pack.json",
        "${{ steps.agent-guard.outputs.evidence-dir }}/agent-surface-inventory.json",
    ]
    expanded = actions.split("## Expanded Workflow Step", 1)[1].split("## Optional SARIF Upload", 1)[0]
    expanded_single_line = " ".join(expanded.split())
    assert "agent-guard init --root . --print" in expanded
    assert "agent-guard init --root . --write" in expanded
    assert "separate fresh directories under `RUNNER_TEMP`" in expanded_single_line
    assert "prior checkout `.agent-guard/evidence`" in expanded_single_line
    assert "regular non-symlink file" in expanded_single_line
    assert "python -I -m agent_guard.consumer --evidence-dir" in expanded
    assert (
        "`evidence-dir` step output, sets `evidence_ready=true`, and writes "
        "`ready=true` last"
        in expanded_single_line
    )
    assert "if: always() && steps.generate-evidence.outputs.ready == 'true'" in expanded
    assert "Fatal setup/runtime errors (`>=2`)" in actions
    assert (
        "before `evidence-dir` is recorded, cleanup removes incomplete public staging"
        in expanded_single_line
    )
    assert "After that output is recorded and `evidence_ready=true`" in expanded_single_line
    assert "ready-gated upload cannot publish it" in expanded_single_line
    assert "mcp-policy" in actions
    assert "--evidence-preset recommended" in actions
    assert "if: always()" in actions
    assert "Recommended evidence is the default reviewed static baseline" in actions
    assert "use `conformance-profile: strict` when digest/context-lock" in actions
    assert "generated `.github/workflows/agent-guard.yml` is the canonical expanded form" in actions_single_line
    assert "Add `--digest-policy .agent-guard/context-digest-policy.yaml` to the report command" in actions_single_line
    assert "If the reviewed MCP policy is missing" in actions
    assert "`required_mcp_policy_not_reviewed`" in actions
    assert "not by pointing recommended evidence at an external policy file" in actions_single_line
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
    assert "recursively sanitized surface inventory" in actions
    assert "do not upload it publicly" in actions
    assert "unless a maintainer has reviewed" in actions_single_line
    assert "controlled-field/controlled-pattern contract" in actions_single_line
    assert "not a generic secret/PII absence guarantee" in actions_single_line
    assert "secret-shaped values covered by the controlled public-artifact contract" in actions_single_line
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
    assert raw_json_doc_lines == []
    assert "Parallel Step Support" not in actions
    assert "step-level `parallel`" not in actions


def test_evidence_consumer_docs_describe_directory_transaction_boundary() -> None:
    docs = EVIDENCE_CONSUMER_CONTRACTS_DOC.read_text(encoding="utf-8")
    docs_single_line = " ".join(docs.split())

    assert "fixed seven-name public-artifact allow-list" in docs_single_line
    assert "same-device backup outside the selected scan root" in docs_single_line
    assert "does not copy the consumed report" in docs
    assert "temporarily absent or hold regenerated or partial evidence" in docs_single_line
    assert "catchable `HUP`, `INT`, or `TERM` signals" in docs
    assert "SIGKILL" in docs
    assert "static evidence consumers" in docs


def test_marketplace_readiness_stays_inactive_and_static_only() -> None:
    readme = README.read_text(encoding="utf-8")
    release_criteria = RELEASE_CRITERIA_DOC.read_text(encoding="utf-8")

    assert "packaged alpha GitHub Action" in readme
    assert "The action generates static evidence only" in readme
    assert "Marketplace publication is not part of the automated release workflows" in release_criteria
    assert "Manual and automated publication are both out of scope" in release_criteria
    assert "new explicit maintainer instruction" in release_criteria
    assert "Demand-gate success does not grant that authorization" in release_criteria
    assert "`agent-guard static evidence`" in release_criteria
    assert "`Security` as the primary category" in release_criteria
    assert "`Code quality` as the secondary" in release_criteria
    assert "do not select `Code Scanning Ready`" in release_criteria
    assert "do not create a moving\n  `v0` alias" in release_criteria
    assert "do not open or submit the release form" in release_criteria


def test_positioning_doc_keeps_public_scope_narrow() -> None:
    docs = POSITIONING_DOC.read_text(encoding="utf-8")
    docs_single_line = " ".join(docs.split())

    assert "Static evidence contracts for AI-agent-maintained repositories." in docs
    assert "VALIDATE-NARROW" in docs
    assert "Python/PyPI static evidence package" in docs_single_line
    assert "init -> report -> upload evidence" in docs_single_line
    assert "Demand signals" in docs
    assert "rename work" in docs
    assert "does not route" in docs
    assert "run LLM review" in docs
    assert "validate live OAuth flows" in docs_single_line
    assert "replace dedicated secret scanners" in docs
    assert "review metadata" in docs
    assert "related independent work" in docs
    assert "unvalidated project hypothesis" in docs_single_line
    assert "quickstart-existing-repo.md" in docs


def test_comparison_does_not_claim_scanner_output_ingestion() -> None:
    docs = COMPARISON_DOC.read_text(encoding="utf-8")

    assert "downstream workflow may reference a separately reviewed artifact" in docs
    assert "does not parse or validate `agent-audit` output" in docs
    assert "May consume or package detection outputs" not in docs


def test_demand_validation_defines_qualified_matured_signals_and_stop_rule() -> None:
    docs = DEMAND_VALIDATION_DOC.read_text(encoding="utf-8")
    docs_single_line = " ".join(docs.split())

    assert "2026-08-10 through 2026-09-20" in docs
    assert "2026-09-21" in docs
    assert "maximum of four hours per week" in docs_single_line
    assert "Qualified exposure" in docs
    assert "Deduplicate this denominator by person, organization, and proposal" in docs_single_line
    assert (
        "repository not owned or controlled by the `agent-guard` project owner. "
        "Forks, project-owned repositories, and the public demo are excluded."
        in docs_single_line
    )
    assert (
        "adopts `agent-guard` configuration or workflow on an owner-external "
        "repository's default branch, and a qualifying CI run or documented "
        "reproduction succeeds from that branch"
        in docs_single_line
    )
    assert "Count at most one activation per organization" in docs
    assert "exact published package version or immutable release Action pin" in docs_single_line
    assert "identified default-branch revision" in docs_single_line
    assert "diagnostic finding status does not count as success" in docs_single_line
    assert "dated private measurement record" in docs_single_line
    assert (
        "at least 14 days after activation, the adopted configuration remains "
        "on the default branch and a qualifying run after that 14-day point succeeds"
        in docs_single_line
    )
    assert "no later than 2026-09-06" in docs
    assert "Count at most one retained result per activation" in docs
    assert "cannot count toward retention in this validation window" in docs_single_line
    assert "Deduplicate by person, organization, and topic" in docs
    assert "activations are at least 3" in docs
    assert "retained activations are at least 2" in docs
    assert (
        "at least 2 external people have supplied at least 3 specific feedback items"
        in docs_single_line
    )
    assert "not statistical validation or product-market-fit evidence" in docs_single_line
    assert "unmet or cannot be measured" in docs
    assert "NO-GO" in docs
    assert 'Do not post "just checking in" comments' in docs
    assert "limited to one per person or organization" in docs_single_line
    assert "Across all proposals in this window" in docs_single_line
    assert "unless the recipient reinitiates" in docs_single_line
    assert "Comments, open pull requests, and pull-request-branch CI never count" in docs_single_line
    assert "Outreach and measurement stop on 2026-09-20" in docs_single_line
    assert "new period, budget, and hypothesis" in docs_single_line
    assert "whether manual or automated, is out of scope" in docs_single_line
    assert "Meeting the continuation gate does not authorize publication" in docs_single_line


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
    assert "MCP 2026-07-28 changelog" in docs
    assert "was verified on 2026-07-31" in docs
    assert "current MCP 2026-07-28 specification" in docs
    assert "MCP 2025-11-25 latest specification family" not in docs
    assert "non-final MCP 2026-07-28 release candidate" not in docs_single_line
    assert "controlled-field/controlled-pattern contract" in docs
    assert "not a generic secret or PII absence guarantee" in docs_single_line
    assert "dedicated secret scanners" in docs
    assert "2026-07-28 protocol/runtime/OAuth changes do not justify" in docs
    assert "No changelog item directly invalidates the current static committed-config labels" in docs_single_line
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


def test_compatibility_doc_keeps_public_safe_contract_bounded() -> None:
    docs = COMPATIBILITY_DOC.read_text(encoding="utf-8")

    assert "bounded sanitization contract over declared controlled fields" in docs
    assert "not a generic guarantee that an artifact contains" in docs
    assert "no secrets or PII" in docs
    assert "does not replace dedicated secret scanners" in docs
    assert "fixed seven-name public bundle" in docs
    assert "without a new bundle version or explicit" in docs
    assert "`agent-guard.result.v1` outer envelope" in docs
    assert "nested `conformance` and `evidence_pack_manifest`" in " ".join(docs.split())
    assert "requires at least one bound `agent-policy` audit-event artifact" in docs


def test_release_criteria_keep_patch_releases_bounded() -> None:
    docs = RELEASE_CRITERIA_DOC.read_text(encoding="utf-8")
    docs_single_line = " ".join(docs.split())

    assert "Batched Release Cadence" in docs
    assert "weekly" in docs
    assert "P0 fix" in docs
    assert "Do not cut a patch release for every qualifying change" in docs_single_line
    assert "reproducible severe issue in a published version" in docs
    assert "Speculative hardening, defense in depth" in docs
    assert "explicit maintainer approval before release" in docs
    assert "frozen until a separate explicit maintainer decision" in docs_single_line
    assert "Docs-only changes under `docs/` do not need an immediate release" in docs
    assert "packaged JSON Schema" in docs
    assert "schema/contract stability" in docs
    assert "wheel contract check" in docs
    assert "LLM review" in docs
    assert "model routing" in docs
    assert "live OAuth validation" in docs
    assert "security/compliance certification" in docs


def test_release_criteria_require_post_release_action_pin_refresh() -> None:
    docs = RELEASE_CRITERIA_DOC.read_text(encoding="utf-8")
    _, readiness_marker, remainder = docs.partition("## Release Readiness")
    readiness, marketplace_marker, _ = remainder.partition(
        "## GitHub Marketplace Readiness Record"
    )

    assert readiness_marker
    assert marketplace_marker
    readiness_single_line = " ".join(readiness.split())
    ordered_steps = (
        "After a release is published",
        "separate documentation follow-up pull request",
        "limited to public docs and documentation contract tests",
        "resolve the new release tag to its immutable 40-character commit SHA",
        "refresh the Action release version and commit constants",
        "every copyable Action example",
        "rerun the documentation contract tests",
    )
    positions = []
    for step in ordered_steps:
        assert step in readiness_single_line
        positions.append(readiness_single_line.index(step))
    assert positions == sorted(positions)
    assert "cannot contain its own final SHA" in readiness_single_line
    assert (
        "During release preparation, examples therefore pin the latest "
        "already-published release" in readiness_single_line
    )
    assert (
        "may differ from the next `pyproject.toml` version" in readiness_single_line
    )
    assert (
        "After publication, they temporarily lag the newly published release until "
        "the follow-up merges" in readiness_single_line
    )


def test_release_readiness_separates_pre_tag_and_published_state() -> None:
    docs = RELEASE_CRITERIA_DOC.read_text(encoding="utf-8")
    pre_tag = docs.split("### Pre-tag checks", 1)[1].split(
        "### Post-tag and publication checks", 1
    )[0]
    post_tag = docs.split("### Post-tag and publication checks", 1)[1].split(
        "The release workflow remains tag-driven", 1
    )[0]

    assert "exact candidate version is absent from PyPI" in pre_tag
    assert "local clean build contains exactly the current wheel and sdist" in pre_tag
    assert "exact-version PyPI metadata exposes" not in pre_tag
    assert "release workflow succeeds" in post_tag
    assert "exact-version PyPI metadata exposes" in post_tag
    assert "provenance attestations" in post_tag


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
    assert "Surface Delta evidence is available in `0.3.0`." in readme
    assert "unreleased source behavior" not in readme
    assert "not available in the published `0.3.0` package" not in readme
    assert "not part of the published `0.3.0` package" not in readme
    assert "Unreleased source-only CLI additions" not in readme
    assert "agent-guard surface delta --root . --context-policy <policy> --base-ref <ref>" in readme
    assert "agent-guard.surface_delta.v1.schema.json" in readme
    assert "Installed wheels also include `agent-guard.surface_delta.v1.schema.json`" in readme
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
    assert "Installed wheels also include `agent-guard.surface_delta.v1.schema.json`" in docs_single_line
    assert "controlled-vocabulary `changed_fields` names" in docs_single_line
    assert "It is review evidence, not a gate" in docs_single_line
    assert "never emitted to SARIF" in docs_single_line
    assert "tar extraction filter available from Python 3.11.4" in docs_single_line
    assert "there is no unfiltered fallback" in docs_single_line
    assert "controlled field name `content`" in docs_single_line
    assert "existing file-backed context, policy, workflow, evidence artifact" in docs_single_line
    assert "never emits the instruction body or an internal content fingerprint value" in docs_single_line
    assert "Policy is always read from the current working tree, never from the base" in docs_single_line
    assert "raw Git tree/blob objects" in docs_single_line
    assert "export-ignore" in docs_single_line
    assert "clean/process/smudge filters are not executed" in docs_single_line
    assert "filtered against the requested repository root and inventory patterns" in docs_single_line
    assert "context `scan.exclude`" in docs_single_line
    assert "unrelated tracked blobs are not materialized" in docs_single_line
    assert "Repository-external symlink targets are not followed" in docs_single_line
    assert "git merge-base <base-ref> HEAD" in docs_single_line
    assert "repository-relative alias paths and resolved in-repo target paths" in docs_single_line
    assert "before expansion through context-selected symlinks" in docs_single_line
    assert "Target values are never published" in docs_single_line


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
    assert "currently unreleased" not in surface_delta_section
    assert "yui-stingray/agent-guard@<release-tag-with-surface-delta>" not in surface_delta_section
    assert "complete workflow" in surface_delta_section
    assert "yui-stingray/agent-guard@" not in surface_delta_section
