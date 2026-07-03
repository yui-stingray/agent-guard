# Where: tests/cli/test_context_inventory.py
# What: focused subprocess tests for context inventory behavior.
# Why: keep extracted context inventory coverage close to its module.

from __future__ import annotations

import json
from pathlib import Path

from tests.cli.helpers import assert_shared_envelope, run_cli, write

def test_context_inventory_cli_json_redacted_payload(tmp_path: Path) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    content_marker = "fixture marker alpha"
    write(
        tmp_path / "AGENTS.md",
        "Require approval before shell writes.\n"
        f"Never paste token or {content_marker}.\n"
        "Run pytest before reporting completion.\n",
    )
    write(tmp_path / ".cursor" / "rules" / "review.md", "Network access requires permission.\n")
    (tmp_path / "CLAUDE.md").write_bytes(b"\x00approval")

    result = run_cli("context", "inventory", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="context",
        status="ok",
        exit_code=0,
        finding_count=0,
        scanned_count=3,
        scanned_unit="files",
    )
    assert payload["command"] == "inventory"
    assert payload["scanned_files"] == 3
    assert payload["summary"]["evidence_count"] >= 4
    assert payload["findings"] == []
    assert payload["inventory"]["schema_version"] == "agent-guard.context_inventory.v1"
    paths = [item["path"] for item in payload["inventory"]["context_files"]]
    assert paths == [".cursor/rules/review.md", "AGENTS.md", "CLAUDE.md"]
    entries = {item["path"]: item for item in payload["inventory"]["context_files"]}
    assert entries[".cursor/rules/review.md"]["kind"] == "cursor"
    assert entries["AGENTS.md"]["kind"] == "agents_md"
    assert entries["CLAUDE.md"]["kind"] == "claude"
    assert entries["CLAUDE.md"]["read_status"] == "binary"
    assert str(tmp_path) not in result.stdout
    assert content_marker not in result.stdout
    assert "Require approval" not in result.stdout
    assert "Never paste token" not in result.stdout
    assert "snippet" not in result.stdout
    assert "matched_text" not in result.stdout

def test_context_inventory_cli_json_error_uses_shared_envelope(tmp_path: Path) -> None:
    result = run_cli(
        "context",
        "inventory",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / "missing.yaml"),
        "--json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert_shared_envelope(payload, scanner="context", status="error", exit_code=2, finding_count=0)
    assert payload["command"] == "inventory"
    assert payload["policy"] == {"path": "missing.yaml"}
    assert str(tmp_path) not in payload["error"]
