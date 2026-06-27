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
