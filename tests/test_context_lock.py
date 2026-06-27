"""Where: tests/test_context_lock.py
What: behavior tests for generating digest pins from agent context inventory.
Why: keep context lock output deterministic and safe to feed into digest guard.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
import pytest

from agent_guard.context_guard import collect_context_inventory, load_context_policy
from agent_guard.context_lock import (
    build_context_digest_policy,
    check_context_digest_coverage,
    context_lock_check_id,
    dump_digest_policy_yaml,
)
from agent_guard.digest_guard import load_digest_policy, scan_digests


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def policy_file(tmp_path: Path, payload: dict[str, object] | None = None) -> Path:
    path = tmp_path / "context_policy.yaml"
    path.write_text(yaml.safe_dump(payload or {}, sort_keys=False), encoding="utf-8")
    return path


def test_context_lock_generates_digest_policy_for_discovered_context_files(
    tmp_path: Path,
) -> None:
    agents = "Require approval before shell writes.\n"
    claude = b"\xff\xfeapproval"
    write(tmp_path / "AGENTS.md", agents)
    (tmp_path / "CLAUDE.md").write_bytes(claude)

    inventory = collect_context_inventory(root=tmp_path, policy=load_context_policy(policy_file(tmp_path)))
    digest_policy = build_context_digest_policy(root=tmp_path, inventory=inventory)

    assert digest_policy == {
        "checks": [
            {
                "id": "context_agents_md",
                "path": "AGENTS.md",
                "sha256": sha256_bytes(agents.encode("utf-8")),
            },
            {
                "id": "context_claude_md",
                "path": "CLAUDE.md",
                "sha256": sha256_bytes(claude),
            },
        ]
    }
    findings, checked = scan_digests(root=tmp_path, policy=digest_policy)
    assert checked == 2
    assert findings == []


def test_context_lock_yaml_output_can_feed_digest_guard(tmp_path: Path) -> None:
    write(tmp_path / "AGENTS.md", "Run local tests before reporting completion.\n")
    inventory = collect_context_inventory(root=tmp_path, policy=load_context_policy(policy_file(tmp_path)))
    digest_policy = yaml.safe_load(
        dump_digest_policy_yaml(build_context_digest_policy(root=tmp_path, inventory=inventory))
    )
    digest_policy_path = tmp_path / "context-digest-policy.yaml"
    digest_policy_path.write_text(yaml.safe_dump(digest_policy, sort_keys=False), encoding="utf-8")

    findings, checked = scan_digests(
        root=tmp_path,
        policy=load_digest_policy(digest_policy_path),
    )

    assert checked == 1
    assert findings == []


def test_context_lock_check_ids_are_stable_and_unique() -> None:
    used_ids: set[str] = set()

    assert context_lock_check_id(".github/copilot-instructions.md", used_ids) == (
        "context_github_copilot_instructions_md"
    )
    assert context_lock_check_id("a-b.md", used_ids) == "context_a_b_md"
    assert context_lock_check_id("a_b.md", used_ids) == "context_a_b_md_2"


def test_context_lock_rejects_empty_inventory(tmp_path: Path) -> None:
    inventory = collect_context_inventory(root=tmp_path, policy=load_context_policy(policy_file(tmp_path)))

    with pytest.raises(ValueError, match="no agent context files discovered"):
        build_context_digest_policy(root=tmp_path, inventory=inventory)


def test_context_lock_coverage_accepts_full_digest_pin(tmp_path: Path) -> None:
    context = "Require approval before shell writes.\n"
    write(tmp_path / "AGENTS.md", context)
    inventory = collect_context_inventory(root=tmp_path, policy=load_context_policy(policy_file(tmp_path)))

    coverage = check_context_digest_coverage(
        root=tmp_path,
        inventory=inventory,
        digest_policy={
            "checks": [
                {
                    "id": "root_agents_md",
                    "path": "AGENTS.md",
                    "sha256": sha256_bytes(context.encode("utf-8")),
                }
            ]
        },
    )

    assert coverage == {
        "schema_version": "agent-guard.context_lock_coverage.v1",
        "status": "ok",
        "context_file_count": 1,
        "covered_count": 1,
        "covered": [
            {
                "path": "AGENTS.md",
                "kind": "agents_md",
                "status": "covered",
                "check_id": "root_agents_md",
            }
        ],
        "finding_count": 0,
        "findings": [],
    }


def test_context_lock_coverage_fails_on_missing_pin(tmp_path: Path) -> None:
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    write(tmp_path / "CLAUDE.md", "Run tests before reporting completion.\n")
    inventory = collect_context_inventory(root=tmp_path, policy=load_context_policy(policy_file(tmp_path)))

    coverage = check_context_digest_coverage(
        root=tmp_path,
        inventory=inventory,
        digest_policy={
            "checks": [
                {
                    "id": "root_agents_md",
                    "path": "AGENTS.md",
                    "sha256": sha256_bytes((tmp_path / "AGENTS.md").read_bytes()),
                }
            ]
        },
    )

    assert coverage["status"] == "violation"
    assert coverage["covered_count"] == 1
    assert coverage["finding_count"] == 1
    assert coverage["findings"] == [
        {
            "rule_id": "context_lock_missing",
            "severity": "high",
            "path": "CLAUDE.md",
            "status": "missing",
            "check_id": "",
            "message": "context file is not pinned by digest policy",
        }
    ]


def test_context_lock_coverage_fails_on_partial_or_mismatched_pin(tmp_path: Path) -> None:
    write(tmp_path / "AGENTS.md", "line 1\nline 2\n")
    write(tmp_path / "CLAUDE.md", "Run tests before reporting completion.\n")
    inventory = collect_context_inventory(root=tmp_path, policy=load_context_policy(policy_file(tmp_path)))

    coverage = check_context_digest_coverage(
        root=tmp_path,
        inventory=inventory,
        digest_policy={
            "checks": [
                {
                    "id": "partial_agents_md",
                    "path": "AGENTS.md",
                    "sha256": sha256_bytes(b"line 2\n"),
                    "start_line": 2,
                },
                {
                    "id": "stale_claude_md",
                    "path": "CLAUDE.md",
                    "sha256": "0" * 64,
                },
            ]
        },
    )

    assert coverage["status"] == "violation"
    assert coverage["covered_count"] == 0
    assert coverage["finding_count"] == 2
    assert coverage["findings"] == [
        {
            "rule_id": "context_lock_partial",
            "severity": "high",
            "path": "AGENTS.md",
            "status": "partial",
            "check_id": "partial_agents_md",
            "message": "context file is only partially pinned by digest policy",
        },
        {
            "rule_id": "context_lock_mismatch",
            "severity": "high",
            "path": "CLAUDE.md",
            "status": "mismatch",
            "check_id": "stale_claude_md",
            "message": "context file digest does not match digest policy",
        },
    ]
