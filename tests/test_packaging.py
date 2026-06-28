"""Where: tests/test_packaging.py
What: packaging invariants for the extracted guard package.
Why: keep version drift and typed-package regressions out of the release path.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import agent_guard
from agent_guard.context_guard import collect_context_inventory, load_context_policy, scan_context_files
from agent_guard.context_lock import check_context_digest_coverage
from agent_guard.content_guard import build_rules, collect_registered_targets, load_content_policy
from agent_guard.content_guard import scan_paths as scan_content_paths
from agent_guard.digest_guard import load_digest_policy, scan_digests
from agent_guard.path_guard import load_path_policy, scan_paths as scan_repo_paths
from agent_guard.workflow_guard import load_workflow_policy, scan_workflow_policy


REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
README = REPO_ROOT / "README.md"
EVIDENCE_CONTRACTS_DOC = REPO_ROOT / "docs" / "evidence-contracts.md"
EVIDENCE_SAMPLE_REPORT = REPO_ROOT / "docs" / "evidence-samples" / "agent-guard-report.json"
EXISTING_REPO_QUICKSTART = REPO_ROOT / "docs" / "quickstart-existing-repo.md"
GITHUB_ACTIONS_EVIDENCE_DOC = REPO_ROOT / "docs" / "github-actions-evidence.md"
RELEASE_CRITERIA_DOC = REPO_ROOT / "docs" / "release-criteria.md"
PACKAGE_DIR = REPO_ROOT / "src" / "agent_guard"
SCHEMA_DIR = PACKAGE_DIR / "schemas"
SELF_PATH_POLICY = REPO_ROOT / ".agent-guard" / "path-policy.yaml"
SELF_CONTEXT_POLICY = REPO_ROOT / ".agent-guard" / "context-policy.yaml"
SELF_CONTENT_POLICY = REPO_ROOT / ".agent-guard" / "content-policy.yaml"
SELF_DIGEST_POLICY = REPO_ROOT / ".agent-guard" / "context-digest-policy.yaml"
SELF_WORKFLOW_POLICY = REPO_ROOT / ".agent-guard" / "workflow-policy.yaml"


def pyproject_version() -> str:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_package_version_matches_pyproject() -> None:
    assert agent_guard.__version__ == pyproject_version()


def test_readme_status_matches_pyproject_version() -> None:
    assert f"**Status**: `{pyproject_version()}` alpha." in README.read_text(encoding="utf-8")


def test_readme_documents_ai_resilience_ci_gate_recipe() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "## CI gate recipe" in readme
    assert "agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json" in readme
    assert "agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json" in readme
    assert "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --json" in readme
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
    assert "agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json" in readme
    assert "agent-guard drift check --root . --json" in readme


def test_readme_documents_agent_policy_companion_boundary() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "`agent-policy` decides whether an agent should do something." in readme
    assert "`agent-guard` checks whether the repository content still obeys the rules." in readme
    assert "| Runtime admission | `agent-policy` |" in readme
    assert "| Static repository gate | `agent-guard` |" in readme
    assert "It does **not** route models, score model quality, run LLM review" in readme


def test_readme_documents_report_evidence_contract() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "docs/evidence-contracts.md" in readme
    assert "docs/quickstart-existing-repo.md" in readme
    assert "docs/github-actions-evidence.md" in readme
    assert "docs/release-criteria.md" in readme
    assert "agent-guard.report_evidence.v1" in readme
    assert "agent-guard.result.v1" in readme
    assert "--format <markdown|json|github-annotations>" in readme
    assert "--output <path>" in readme
    assert "Use `--format json`" in readme
    assert "Packaged JSON schemas" in readme
    assert "agent-guard.context_inventory.v1.schema.json" in readme
    assert "agent-guard.context_lock_coverage.v1.schema.json" in readme
    assert "Context Lock Coverage Evidence" in readme
    assert "Evidence Coverage" in readme
    assert "Agent Surface Inventory" in readme
    assert "does not emit context text" in readme
    assert "hash values" in readme
    assert "SARIF is intentionally" in readme


def test_evidence_contract_docs_cover_adoption_and_non_goals() -> None:
    docs = EVIDENCE_CONTRACTS_DOC.read_text(encoding="utf-8")

    assert EVIDENCE_SAMPLE_REPORT.is_file()
    assert "Minimal Adoption Path" in docs
    assert "CI artifact" in docs
    assert "agent-policy" in docs
    assert "examples/evidence_consumer.py" in docs
    assert "SARIF is intentionally deferred" in docs
    assert "LLM reviewer" in docs
    assert "model router" in docs
    assert "large governance framework" in docs


def test_existing_repo_quickstart_and_github_docs_are_copyable() -> None:
    quickstart = EXISTING_REPO_QUICKSTART.read_text(encoding="utf-8")
    actions = GITHUB_ACTIONS_EVIDENCE_DOC.read_text(encoding="utf-8")

    assert "python3 -m venv .venv" in quickstart
    assert ".agent-guard/context-policy.yaml" in quickstart
    assert "agent-guard context inventory --root ." in quickstart
    assert "agent-guard surface inventory --root ." in quickstart
    assert "agent-guard init --root . --json" in quickstart
    assert "agent-guard context lock --root ." in quickstart
    assert ".agent-guard/context-digest-policy.yaml" in quickstart
    assert "agent-guard report --root ." in quickstart
    assert "--drift-check" in quickstart
    assert "LLM reviewer" in quickstart
    assert "MoA orchestrator" in quickstart
    assert "uses: actions/upload-artifact@v7" in actions
    assert "status=0" in actions
    assert "agent-guard surface inventory --root ." in actions
    assert "agent-guard drift check --root ." in actions
    assert 'exit "$status"' in actions
    assert "if: always()" in actions
    assert "--format github-annotations" in actions
    assert "does not post pull request comments" in actions
    assert "raw context text" in actions


def test_release_criteria_keep_patch_releases_bounded() -> None:
    docs = RELEASE_CRITERIA_DOC.read_text(encoding="utf-8")

    assert "Patch Release Candidates" in docs
    assert "Docs-only changes under `docs/` do not need an immediate release" in docs
    assert "packaged JSON Schema" in docs
    assert "wheel contract check" in docs
    assert "LLM review" in docs
    assert "model routing" in docs


def test_readme_documents_operational_example_policy_coverage() -> None:
    readme = README.read_text(encoding="utf-8")

    assert '- "**/*.yaml"' in readme
    assert '- "**/*.sh"' in readme
    assert "destructive_rm_root" in readme
    assert "local_artifacts" in readme


def test_self_dogfood_guard_policies_are_present_and_clean() -> None:
    assert (REPO_ROOT / "AGENTS.md").is_file()
    assert SELF_PATH_POLICY.is_file()
    assert SELF_CONTEXT_POLICY.is_file()
    assert SELF_CONTENT_POLICY.is_file()
    assert SELF_DIGEST_POLICY.is_file()
    assert SELF_WORKFLOW_POLICY.is_file()

    path_findings, scanned_paths = scan_repo_paths(
        root=REPO_ROOT,
        policy=load_path_policy(SELF_PATH_POLICY),
    )
    assert scanned_paths >= 1
    assert path_findings == []

    context_policy = load_context_policy(SELF_CONTEXT_POLICY)
    context_findings, scanned_files = scan_context_files(root=REPO_ROOT, policy=context_policy)
    assert scanned_files >= 1
    assert context_findings == []

    inventory = collect_context_inventory(root=REPO_ROOT, policy=context_policy)
    context_paths = {entry.path for entry in inventory.context_files}
    assert "AGENTS.md" in context_paths
    assert all(item["status"] == "present" for item in inventory.permission_boundaries)

    content_policy = load_content_policy(SELF_CONTENT_POLICY)
    file_globs = content_policy.get("file_globs", [])
    exclude_globs = content_policy.get("exclude_globs", [])
    assert isinstance(file_globs, list)
    assert isinstance(exclude_globs, list)
    content_paths = collect_registered_targets(REPO_ROOT, Path("."), file_globs, exclude_globs)
    relative_content_paths = [path.relative_to(REPO_ROOT).as_posix() for path in content_paths]
    excluded_prefixes = (".venv/", ".venv312/", ".venv-py312/", ".pytest_cache/")
    assert not any(path.startswith(excluded_prefixes) for path in relative_content_paths)
    content_findings = scan_content_paths(content_paths, build_rules(content_policy), REPO_ROOT)
    assert len(content_paths) >= 1
    assert content_findings == []

    digest_findings, digest_checked = scan_digests(
        root=REPO_ROOT,
        policy=load_digest_policy(SELF_DIGEST_POLICY),
    )
    assert digest_checked == 5
    assert digest_findings == []
    coverage = check_context_digest_coverage(
        root=REPO_ROOT,
        inventory=inventory,
        digest_policy=load_digest_policy(SELF_DIGEST_POLICY),
    )
    assert coverage["status"] == "ok"
    assert coverage["covered_count"] == coverage["context_file_count"]
    assert coverage["covered"] == [
        {
            "path": "AGENTS.md",
            "kind": "agents_md",
            "status": "covered",
            "check_id": "root_agents_md",
        }
    ]
    assert coverage["findings"] == []

    workflow_findings, workflow_checked = scan_workflow_policy(
        root=REPO_ROOT,
        policy=load_workflow_policy(SELF_WORKFLOW_POLICY),
    )
    assert workflow_checked == 17
    assert workflow_findings == []


def test_schema_resources_are_present_in_package_tree() -> None:
    expected = {
        "agent-guard.result.v1.schema.json",
        "agent-guard.context_inventory.v1.schema.json",
        "agent-guard.context_lock_coverage.v1.schema.json",
        "agent-guard.report_evidence.v1.schema.json",
    }

    assert SCHEMA_DIR.is_dir()
    assert {path.name for path in SCHEMA_DIR.glob("*.schema.json")} == expected


def test_py_typed_marker_is_present() -> None:
    marker = PACKAGE_DIR / "py.typed"
    assert marker.is_file()
    assert marker.stat().st_size == 0
