"""Exercise native Windows final-handle containment for repository readers."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from agent_guard import api_guard, content_guard, evidence_pack, workflow_guard
from agent_guard.consumer import validate_agent_policy_audit_event_files


pytestmark = pytest.mark.skipif(os.name != "nt", reason="requires native Windows handles")
AUDIT_EVENT_PROFILE = "agent-policy.audit_event.v1.1"


def test_windows_repo_bound_readers_accept_in_root_regular_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    api_path = repo / "src" / "api.py"
    content_path = repo / "docs" / "note.md"
    workflow_path = repo / ".github" / "workflows" / "ci.yml"
    audit_event_path = repo / "reviewed" / "policy-admission-event.json"
    for path, text in (
        (api_path, "def handler():\n    return 'ok'\n"),
        (content_path, "Reviewed documentation.\n"),
        (workflow_path, "name: ci\njobs: {}\n"),
        (audit_event_path, '{"status":"reviewed"}\n'),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))

    api_text, api_relative = api_guard._read_repo_text(api_path, repo)
    assert api_text == "def handler():\n    return 'ok'\n"
    assert api_relative == "src/api.py"
    assert content_guard._read_scan_text(content_path, repo) == "Reviewed documentation.\n"
    assert workflow_guard._read_repo_bound_bytes(
        workflow_path,
        repo,
        max_bytes=1024,
    ) == b"name: ci\njobs: {}\n"
    artifacts = evidence_pack.build_agent_policy_audit_event_artifacts(
        ["reviewed/policy-admission-event.json"],
        event_profile=AUDIT_EVENT_PROFILE,
        root=repo,
    )
    validate_agent_policy_audit_event_files(
        {
            "evidence_pack_manifest": {
                "schema_version": "agent-guard.evidence_pack_manifest.v2",
                "artifacts": artifacts,
            }
        },
        (audit_event_path,),
        event_profile=AUDIT_EVENT_PROFILE,
    )


def test_windows_repo_bound_readers_reject_outside_junction(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    (outside / "payload.txt").write_text("synthetic external payload\n", encoding="utf-8")
    junction = repo / "linked"
    created = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        text=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.fail("Windows junction setup failed")

    linked = junction / "payload.txt"
    resolved_root = repo.resolve(strict=True)
    try:
        with pytest.raises(ValueError, match="^api scan target must stay under repo root$"):
            api_guard._read_repo_text(linked, repo)
        with pytest.raises(ValueError, match="^content scan target must stay under repo root$"):
            content_guard._read_scan_text(linked, repo)
        with pytest.raises(ValueError, match="^workflow scan target must stay under repo root$"):
            workflow_guard._read_repo_bound_bytes(linked, repo, max_bytes=1024)
        with pytest.raises(
            ValueError,
            match="^agent-policy audit event must be a repository file$",
        ):
            evidence_pack.build_agent_policy_audit_event_binding(
                linked,
                event_profile=AUDIT_EVENT_PROFILE,
                repo_root=repo,
            )

        # The final-handle check also rejects an already-external path passed
        # directly to the opener, independently of caller-side resolution.
        with pytest.raises(ValueError, match="^api scan target must stay under repo root$"):
            api_guard._open_repo_file_windows(resolved_root, linked)
        with pytest.raises(ValueError, match="^content scan target must stay under repo root$"):
            content_guard._open_repo_file_windows(resolved_root, linked)
        with pytest.raises(ValueError, match="^workflow scan target must stay under repo root$"):
            workflow_guard._open_repo_file_windows(resolved_root, linked)
    finally:
        junction.rmdir()
