# Where: tests/cli/test_evidence_pack.py
# What: focused subprocess tests for evidence-pack manifest emission.
# Why: keep extracted evidence-pack subcommand coverage close to its module.

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agent_guard import evidence_pack
from agent_guard.consumer import validate_public_evidence_shape
from agent_guard.evidence_pack import (
    build_agent_policy_audit_event_artifacts,
    build_agent_policy_audit_event_binding,
)
from tests.cli.helpers import run_cli

AUDIT_EVENT_PROFILE = "agent-policy.audit_event.v1.1"


def test_evidence_pack_manifest_cli_is_sanitized(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "tool": {"name": "agent-guard", "version": "0.1.7"},
                "status": "ok",
                "finding_count": 0,
                "summary": {"surface_count": 2},
                "report": {
                    "schema_version": "agent-guard.report_evidence.v1",
                    "format": "json",
                    "scope": "context",
                },
                "evidence_coverage": {
                    "gate_count": 1,
                    "enabled_count": 1,
                    "missing_count": 0,
                    "failing_count": 0,
                    "gates": [{"gate": "context", "status": "ok", "finding_count": 0}],
                },
            }
        ),
        encoding="utf-8",
    )
    event = tmp_path / ".agent-guard" / "evidence" / "policy-admission-event.json"
    event.parent.mkdir(parents=True)
    event.write_text('{"status":"reviewed"}\n', encoding="utf-8")

    result = run_cli(
        "evidence-pack",
        "manifest",
        "--root",
        str(tmp_path),
        "--report",
        str(report),
        "--artifact",
        str(tmp_path / ".agent-guard" / "evidence" / "report.json"),
        "--artifact",
        str(tmp_path.parent / "outside-report.json"),
        "--artifact",
        r"C:\Users\alice\secret\agent-guard-report.json",
        "--artifact",
        r"\\server\share\agent-guard-report.json",
        "--artifact",
        "file://localhost/home/synthetic/private/report.json",
        "--agent-policy-audit-event",
        str(event),
        "--agent-policy-audit-event-profile",
        AUDIT_EVENT_PROFILE,
        "--json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    manifest = payload["evidence_pack_manifest"]
    assert manifest["schema_version"] == "agent-guard.evidence_pack_manifest.v1"
    assert manifest["sanitized"] is True
    assert manifest["artifacts"][:-1] == [
        {"path": ".agent-guard/evidence/report.json", "role": "report"},
        {"path": "outside-report.json", "role": "report"},
        {"path": "agent-guard-report.json", "role": "report"},
        {"path": "agent-guard-report.json", "role": "report"},
        {"path": "<redacted-url>", "role": "report"},
    ]
    audit_artifact = manifest["artifacts"][-1]
    assert audit_artifact["path"] == ".agent-guard/evidence/policy-admission-event.json"
    assert audit_artifact["role"] == "agent-policy-audit-event"
    binding = audit_artifact["content_binding"]
    assert binding["schema_version"] == "agent-guard.agent_policy_audit_event_binding.v1"
    assert binding["event_profile"] == AUDIT_EVENT_PROFILE
    assert binding["canonicalization"] == "canonical-json-v1"
    assert binding["digest_algorithm"] == "sha256"
    assert binding["digest_encoding"] == "base32-lower-no-padding"
    assert len(binding["digest"]) == 53
    assert binding["digest"].startswith("b")
    assert str(tmp_path) not in result.stdout
    assert r"C:\Users\alice" not in result.stdout
    assert r"\\server\share" not in result.stdout


def test_evidence_pack_manifest_cli_sanitizes_copied_report_metadata(tmp_path: Path) -> None:
    secret_shaped = "AKIA" + ("A" * 16)
    raw_url = "HtTpS:/example.invalid/private's/synthetic-tail"
    local_path = "/home/synthetic/private/repository"
    windows_path = r"D:\synthetic's folder\private\repository name"
    unc_path = r"\\?\UNC\synthetic-host\private`folder\repository name"
    hash_shaped = "a" * 64
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "tool": {
                    "name": unc_path,
                    "version": secret_shaped,
                    "build_path": windows_path,
                },
                "status": "ok",
                "finding_count": 0,
                "summary": {"surface_count": 2},
                "report": {
                    "schema_version": "agent-guard.report_evidence.v1",
                    "format": "json",
                    "scope": local_path,
                },
                "evidence_coverage": {
                    "gate_count": 2,
                    "enabled_count": 2,
                    "missing_count": 0,
                    "failing_count": 0,
                    "gates": [
                        {"gate": raw_url, "status": "ok", "checked_count": 1, "finding_count": 0},
                        {"gate": hash_shaped, "status": "ok", "checked_count": 1, "finding_count": 0},
                    ],
                },
                "conformance": {
                    "schema_version": "agent-guard.conformance.v1",
                    "profile": "recommended",
                    "status": "ok",
                    "finding_count": 0,
                },
            }
        ),
        encoding="utf-8",
    )

    result = run_cli(
        "evidence-pack",
        "manifest",
        "--root",
        str(tmp_path),
        "--report",
        str(report),
        "--artifact",
        raw_url,
        "--json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    manifest = payload["evidence_pack_manifest"]
    assert manifest["sanitized"] is True
    assert manifest["tool"]["name"] == "<absolute-path>"
    assert manifest["tool"]["version"] == "<redacted>"
    assert manifest["tool"]["build_path"] == "<absolute-path>"
    assert manifest["report"]["scope"] == "<absolute-path>"
    assert manifest["gates"][0]["gate"] == "<redacted-url>"
    assert manifest["gates"][1]["gate"] == "<redacted>"
    assert manifest["conformance"]["profile"] == "recommended"
    assert manifest["artifacts"] == [
        {"path": "<redacted-url>", "role": "report"},
    ]
    for value in (secret_shaped, raw_url, local_path, windows_path, unc_path, hash_shaped):
        assert value not in result.stdout
    validate_public_evidence_shape(payload)


def test_evidence_pack_manifest_cli_rejects_unbound_or_external_audit_event(
    tmp_path: Path,
) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "status": "ok",
                "finding_count": 0,
                "report": {
                    "schema_version": "agent-guard.report_evidence.v1",
                    "format": "json",
                    "scope": "context",
                },
                "evidence_coverage": {"gates": []},
            }
        ),
        encoding="utf-8",
    )
    event = tmp_path / "event.json"
    event.write_text("{}\n", encoding="utf-8")

    missing_profile = run_cli(
        "evidence-pack",
        "manifest",
        "--root",
        str(tmp_path),
        "--report",
        str(report),
        "--agent-policy-audit-event",
        str(event),
        "--json",
    )
    external = run_cli(
        "evidence-pack",
        "manifest",
        "--root",
        str(tmp_path),
        "--report",
        str(report),
        "--agent-policy-audit-event",
        str(tmp_path.parent / "outside.json"),
        "--agent-policy-audit-event-profile",
        AUDIT_EVENT_PROFILE,
        "--json",
    )

    assert missing_profile.returncode == 2
    assert external.returncode == 2
    assert AUDIT_EVENT_PROFILE not in external.stdout
    assert str(tmp_path) not in missing_profile.stdout + external.stdout


def test_audit_event_artifacts_preserve_nested_paths_for_duplicate_basenames(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repository"
    first = root / "evidence" / "first" / "policy-admission-event.json"
    second = root / "evidence" / "second" / "policy-admission-event.json"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_text('{"status":"first"}\n', encoding="utf-8")
    second.write_text('{"status":"second"}\n', encoding="utf-8")

    artifacts = build_agent_policy_audit_event_artifacts(
        [
            first.relative_to(root).as_posix(),
            second.relative_to(root).as_posix(),
        ],
        event_profile=AUDIT_EVENT_PROFILE,
        root=root,
    )

    paths = [artifact["path"] for artifact in artifacts]
    assert paths == [
        "evidence/first/policy-admission-event.json",
        "evidence/second/policy-admission-event.json",
    ]
    assert len(set(paths)) == 2


def test_audit_event_binding_is_canonical_and_detects_content_change(tmp_path: Path) -> None:
    event = tmp_path / "event.json"
    event.write_text('{"decision":{"mode":"auto_allow"},"capability":"read"}\n', encoding="utf-8")
    first = build_agent_policy_audit_event_binding(event, event_profile=AUDIT_EVENT_PROFILE)

    event.write_text(
        '{\n  "capability": "read",\n  "decision": {"mode": "auto_allow"}\n}\n',
        encoding="utf-8",
    )
    equivalent = build_agent_policy_audit_event_binding(event, event_profile=AUDIT_EVENT_PROFILE)
    event.write_text('{"capability":"write","decision":{"mode":"auto_allow"}}\n', encoding="utf-8")
    changed = build_agent_policy_audit_event_binding(event, event_profile=AUDIT_EVENT_PROFILE)

    assert equivalent == first
    assert changed["digest"] != first["digest"]


def test_audit_event_binding_preserves_distinct_large_number_lexemes(
    tmp_path: Path,
) -> None:
    event = tmp_path / "event.json"
    event.write_text('{"sequence":9007199254740992.0}\n', encoding="utf-8")
    first = build_agent_policy_audit_event_binding(
        event,
        event_profile=AUDIT_EVENT_PROFILE,
    )

    event.write_text('{"sequence":9007199254740993.0}\n', encoding="utf-8")
    changed = build_agent_policy_audit_event_binding(
        event,
        event_profile=AUDIT_EVENT_PROFILE,
    )

    assert changed["digest"] != first["digest"]


@pytest.mark.parametrize(
    "event_profile",
    (
        "sk-" + ("x" * 16),
        "a" * 64,
    ),
)
def test_audit_event_profile_rejects_public_sanitization_changes_before_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_profile: str,
) -> None:
    event = tmp_path / "event.json"
    event.write_text('{"status":"reviewed"}\n', encoding="utf-8")
    assert evidence_pack._AUDIT_EVENT_PROFILE_RE.fullmatch(event_profile)

    def unexpected_digest(_value: bytes) -> object:
        raise AssertionError("digest computation must not run")

    monkeypatch.setattr(evidence_pack.hashlib, "sha256", unexpected_digest)

    with pytest.raises(
        ValueError,
        match="^agent-policy audit event profile is invalid$",
    ) as exc_info:
        build_agent_policy_audit_event_binding(
            event,
            event_profile=event_profile,
        )

    assert event_profile not in str(exc_info.value)


def test_audit_event_binding_enforces_one_mib_read_bound_before_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = tmp_path / "event.json"
    event.write_bytes(b"x" * (evidence_pack.MAX_AGENT_POLICY_AUDIT_EVENT_BYTES + 1))

    def unexpected_parse(_raw: bytes) -> bytes:
        raise AssertionError("oversized event must not be parsed")

    monkeypatch.setattr(
        evidence_pack,
        "_canonical_agent_policy_audit_event",
        unexpected_parse,
    )

    with pytest.raises(
        ValueError,
        match="^agent-policy audit event is not valid bounded JSON$",
    ):
        build_agent_policy_audit_event_binding(
            event,
            event_profile=AUDIT_EVENT_PROFILE,
        )


@pytest.mark.skipif(os.name != "posix", reason="exercises POSIX descriptor traversal")
def test_audit_event_binding_reads_opened_descriptor_after_final_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    event = root / "reviewed" / "event.json"
    external = tmp_path / "external-event.json"
    event.parent.mkdir(parents=True)
    event.write_text('{"status":"reviewed"}\n', encoding="utf-8")
    external.write_text('{"status":"external"}\n', encoding="utf-8")
    expected = build_agent_policy_audit_event_binding(
        event,
        event_profile=AUDIT_EVENT_PROFILE,
        repo_root=root,
    )
    original_open = evidence_pack._open_agent_policy_audit_event_posix

    def open_then_swap(repo_root: Path, relative_path: Path) -> int:
        file_fd = original_open(repo_root, relative_path)
        event.unlink()
        event.symlink_to(external)
        return file_fd

    monkeypatch.setattr(
        evidence_pack,
        "_open_agent_policy_audit_event_posix",
        open_then_swap,
    )

    artifacts = build_agent_policy_audit_event_artifacts(
        ["reviewed/event.json"],
        event_profile=AUDIT_EVENT_PROFILE,
        root=root,
    )

    assert artifacts == [
        {
            "path": "reviewed/event.json",
            "role": "agent-policy-audit-event",
            "content_binding": expected,
        }
    ]


@pytest.mark.skipif(os.name != "posix", reason="exercises POSIX no-follow traversal")
def test_audit_event_binding_rejects_final_file_symlink_swap_without_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    event = root / "reviewed" / "event.json"
    held = event.with_name("held-event.json")
    external = tmp_path / "external-event.json"
    external_marker = "synthetic-external-event-marker"
    event.parent.mkdir(parents=True)
    event.write_text('{"status":"reviewed"}\n', encoding="utf-8")
    external.write_text(json.dumps({"marker": external_marker}), encoding="utf-8")
    original_open = evidence_pack._open_agent_policy_audit_event_posix

    def swap_before_open(repo_root: Path, relative_path: Path) -> int:
        event.rename(held)
        event.symlink_to(external)
        return original_open(repo_root, relative_path)

    monkeypatch.setattr(
        evidence_pack,
        "_open_agent_policy_audit_event_posix",
        swap_before_open,
    )

    with pytest.raises(
        ValueError,
        match="^agent-policy audit event must be a repository file$",
    ) as exc_info:
        build_agent_policy_audit_event_artifacts(
            ["reviewed/event.json"],
            event_profile=AUDIT_EVENT_PROFILE,
            root=root,
        )

    assert external_marker not in str(exc_info.value)
    assert str(external) not in str(exc_info.value)


@pytest.mark.skipif(os.name != "posix", reason="exercises POSIX no-follow traversal")
def test_audit_event_binding_rejects_ancestor_symlink_swap_without_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    event_dir = root / "reviewed" / "nested"
    event = event_dir / "event.json"
    held = event_dir.with_name("held-nested")
    external_dir = tmp_path / "external"
    external_marker = "synthetic-external-ancestor-marker"
    event_dir.mkdir(parents=True)
    event.write_text('{"status":"reviewed"}\n', encoding="utf-8")
    external_dir.mkdir()
    (external_dir / "event.json").write_text(
        json.dumps({"marker": external_marker}),
        encoding="utf-8",
    )
    original_open = evidence_pack._open_agent_policy_audit_event_posix

    def swap_before_open(repo_root: Path, relative_path: Path) -> int:
        event_dir.rename(held)
        event_dir.symlink_to(external_dir, target_is_directory=True)
        return original_open(repo_root, relative_path)

    monkeypatch.setattr(
        evidence_pack,
        "_open_agent_policy_audit_event_posix",
        swap_before_open,
    )

    with pytest.raises(
        ValueError,
        match="^agent-policy audit event must be a repository file$",
    ) as exc_info:
        build_agent_policy_audit_event_artifacts(
            ["reviewed/nested/event.json"],
            event_profile=AUDIT_EVENT_PROFILE,
            root=root,
        )

    assert external_marker not in str(exc_info.value)
    assert str(external_dir) not in str(exc_info.value)


def test_evidence_pack_manifest_rejects_ambiguous_audit_event_json(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "status": "ok",
                "finding_count": 0,
                "report": {
                    "schema_version": "agent-guard.report_evidence.v1",
                    "format": "json",
                    "scope": "context",
                },
                "evidence_coverage": {"gates": []},
            }
        ),
        encoding="utf-8",
    )
    event = tmp_path / "event.json"
    event.write_text('{"decision":"first","decision":"second"}\n', encoding="utf-8")

    result = run_cli(
        "evidence-pack",
        "manifest",
        "--root",
        str(tmp_path),
        "--report",
        str(report),
        "--agent-policy-audit-event",
        str(event),
        "--agent-policy-audit-event-profile",
        AUDIT_EVENT_PROFILE,
        "--json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["error"] == "agent-policy audit event is not valid bounded JSON"
    assert "first" not in result.stdout + result.stderr
    assert "second" not in result.stdout + result.stderr


def test_evidence_pack_manifest_rejects_non_unicode_audit_event_json(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "status": "ok",
                "finding_count": 0,
                "report": {
                    "schema_version": "agent-guard.report_evidence.v1",
                    "format": "json",
                    "scope": "context",
                },
                "evidence_coverage": {"gates": []},
            }
        ),
        encoding="utf-8",
    )
    event = tmp_path / "event.json"
    event.write_bytes(b'{"value":"\\ud800"}\n')

    result = run_cli(
        "evidence-pack",
        "manifest",
        "--root",
        str(tmp_path),
        "--report",
        str(report),
        "--agent-policy-audit-event",
        str(event),
        "--agent-policy-audit-event-profile",
        AUDIT_EVENT_PROFILE,
        "--json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["error"] == "agent-policy audit event is not valid bounded JSON"
    assert "ud800" not in result.stdout + result.stderr


def test_evidence_pack_manifest_cli_fails_closed_on_sanitized_key_collision(tmp_path: Path) -> None:
    first = "field=https://one.invalid/a alpha"
    second = "field=https://two.invalid/b beta"
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "tool": {first: "one", second: "two"},
                "status": "ok",
                "finding_count": 0,
                "summary": {},
                "report": {
                    "schema_version": "agent-guard.report_evidence.v1",
                    "format": "json",
                    "scope": "context",
                },
                "evidence_coverage": {"gates": []},
            }
        ),
        encoding="utf-8",
    )

    result = run_cli(
        "evidence-pack",
        "manifest",
        "--root",
        str(tmp_path),
        "--report",
        str(report),
        "--json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert payload["error"] == "public sanitization produced duplicate mapping keys"
    for value in (first, second):
        assert value not in result.stdout
        assert value not in result.stderr
