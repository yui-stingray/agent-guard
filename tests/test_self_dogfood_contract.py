"""Where: tests/test_self_dogfood_contract.py
What: repository self-dogfood policy contract tests.
Why: keep this repository covered by the same static guard policies it ships.
"""

from __future__ import annotations

from pathlib import Path

from agent_guard.context_guard import collect_context_inventory, load_context_policy, scan_context_files
from agent_guard.context_lock import check_context_digest_coverage
from agent_guard.content_guard import build_rules, collect_registered_targets, load_content_policy
from agent_guard.content_guard import scan_paths as scan_content_paths
from agent_guard.digest_guard import load_digest_policy, scan_digests
from agent_guard.path_guard import load_path_policy, scan_paths as scan_repo_paths
from agent_guard.workflow_guard import load_workflow_policy, scan_workflow_policy


REPO_ROOT = Path(__file__).resolve().parents[1]
SELF_PATH_POLICY = REPO_ROOT / ".agent-guard" / "path-policy.yaml"
SELF_CONTEXT_POLICY = REPO_ROOT / ".agent-guard" / "context-policy.yaml"
SELF_CONTENT_POLICY = REPO_ROOT / ".agent-guard" / "content-policy.yaml"
SELF_DIGEST_POLICY = REPO_ROOT / ".agent-guard" / "context-digest-policy.yaml"
SELF_WORKFLOW_POLICY = REPO_ROOT / ".agent-guard" / "workflow-policy.yaml"


def test_self_dogfood_guard_policies_are_present_and_clean() -> None:
    assert (REPO_ROOT / "AGENTS.md").is_file()
    agent_instructions = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "python -m agent_guard.cli" not in agent_instructions
    assert "python -I -m agent_guard.cli" in agent_instructions
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
    assert digest_checked == 6
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
    assert workflow_checked == 25
    assert workflow_findings == []
