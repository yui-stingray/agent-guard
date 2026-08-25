# Where: tests/cli/test_evidence_pack.py
# What: focused subprocess tests for evidence-pack manifest emission.
# Why: keep extracted evidence-pack subcommand coverage close to its module.

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import pytest

from agent_guard import evidence_pack
import agent_guard.cli.common as cli_common
import agent_guard.cli.evidence_pack as evidence_pack_cli
from agent_guard.consumer import validate_public_evidence_shape
from agent_guard.consumer._schema import (
    MAX_JSON_DEPTH,
    MAX_JSON_ITEMS,
    MAX_REPORT_JSON_BYTES,
)
from agent_guard.evidence_pack import (
    build_agent_policy_audit_event_artifacts,
    build_agent_policy_audit_event_binding,
    build_evidence_pack_manifest,
)
from tests.audit_event_helpers import audit_event_payload, write_audit_event
from tests.cli.helpers import run_cli

AUDIT_EVENT_PROFILE = "agent-guard.public_agent_policy_audit_event.v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_SAMPLE_REPORT = REPO_ROOT / "docs" / "evidence-samples" / "agent-guard-report.json"
V2_REPORT_PAYLOAD = {
    "report": {"schema_version": "agent-guard.report_evidence.v2"},
}


def test_evidence_pack_manifest_cli_rejects_oversized_report_before_decode(
    tmp_path: Path,
) -> None:
    report = tmp_path / "oversized-report.json"
    report.write_bytes(
        b'{"ignored":"' + (b"x" * MAX_REPORT_JSON_BYTES) + b'"}'
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
    assert payload["error"] == "report JSON exceeds configured limits"
    assert result.stderr == ""


def test_evidence_pack_manifest_cli_rejects_excessive_json_items(
    tmp_path: Path,
) -> None:
    report = tmp_path / "wide-report.json"
    report.write_text(
        json.dumps({"ignored": [0] * MAX_JSON_ITEMS}),
        encoding="utf-8",
    )
    assert report.stat().st_size < MAX_REPORT_JSON_BYTES

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
    assert payload["error"] == "report JSON exceeds configured limits"
    assert result.stderr == ""


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_evidence_pack_manifest_cli_rejects_nonfinite_report_json(
    tmp_path: Path,
    constant: str,
) -> None:
    report = tmp_path / "nonfinite-report.json"
    report.write_text(f'{{"metric":{constant}}}\n', encoding="utf-8")

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
    assert payload["error"] == "report JSON is invalid"
    assert constant not in result.stdout + result.stderr


def test_evidence_pack_manifest_cli_fails_closed_on_public_output_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    report = tmp_path / "report.json"
    report.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(cli_common, "MAX_PUBLIC_OUTPUT_BYTES", 1024)
    args = argparse.Namespace(
        root=str(tmp_path),
        report=str(report),
        artifact=["a" * 2048],
        agent_policy_audit_event=[],
        agent_policy_audit_event_profile="",
        json=True,
    )

    exit_code = evidence_pack_cli.run_evidence_pack_manifest(args)
    captured = capfd.readouterr()

    assert exit_code == 2
    payload = json.loads(captured.out)
    assert payload["error"] == "evidence-pack output exceeds configured limits"
    assert captured.err == ""


def test_evidence_pack_manifest_cli_is_sanitized(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    event = tmp_path / ".agent-guard" / "evidence" / "policy-admission-event.json"
    event.parent.mkdir(parents=True)
    write_audit_event(event)
    report_payload = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))
    report_payload["report"]["schema_version"] = "agent-guard.report_evidence.v2"
    embedded_manifest = report_payload["evidence_pack_manifest"]
    embedded_manifest["schema_version"] = "agent-guard.evidence_pack_manifest.v2"
    embedded_manifest["report"]["schema_version"] = "agent-guard.report_evidence.v2"
    embedded_manifest["artifacts"].append(
        {
            "path": ".agent-guard/evidence/policy-admission-event.json",
            "role": "agent-policy-audit-event",
            "content_binding": build_agent_policy_audit_event_binding(
                event,
                event_profile=AUDIT_EVENT_PROFILE,
            ),
        }
    )
    report.write_text(json.dumps(report_payload), encoding="utf-8")

    result = run_cli(
        "evidence-pack",
        "manifest",
        "--root",
        str(tmp_path),
        "--report",
        str(report),
        "--artifact",
        ".agent-guard/evidence/report.json",
        "--agent-policy-audit-event",
        event.relative_to(tmp_path).as_posix(),
        "--agent-policy-audit-event-profile",
        AUDIT_EVENT_PROFILE,
        "--json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    manifest = payload["evidence_pack_manifest"]
    assert manifest["schema_version"] == "agent-guard.evidence_pack_manifest.v2"
    assert manifest["sanitized"] is True
    assert manifest["artifacts"][:-1] == [
        {"path": ".agent-guard/evidence/report.json", "role": "report"},
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


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "../claimed/event.json",
        "/claimed/event.json",
        r"C:\claimed\event.json",
        r"claimed\event.json",
        "https://example.invalid/claimed/event.json",
        "./claimed/event.json",
        "claimed/./event.json",
        "claimed/../event.json",
        " claimed/event.json",
        "claimed/event.json ",
    ),
)
def test_bound_manifest_rejects_unsafe_report_artifact_paths_without_leak(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    event_marker = "synthetic-private-event-body"
    event = tmp_path / "event.json"
    write_audit_event(event, context={"marker": event_marker})
    audit_artifact = {
        "path": "reviewed/event.json",
        "role": "agent-policy-audit-event",
        "content_binding": build_agent_policy_audit_event_binding(
            event,
            event_profile=AUDIT_EVENT_PROFILE,
        ),
    }

    with pytest.raises(
        ValueError,
        match="^evidence-pack artifact path is invalid$",
    ) as exc_info:
        build_evidence_pack_manifest(
            report_payload=V2_REPORT_PAYLOAD,
            artifact_paths=[unsafe_path],
            agent_policy_audit_event_artifacts=[audit_artifact],
            root=tmp_path,
        )

    error = str(exc_info.value)
    assert unsafe_path not in error
    assert str(event) not in error
    assert AUDIT_EVENT_PROFILE not in error
    assert event_marker not in error


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "../claimed/event.json",
        "/claimed/event.json",
        r"C:\claimed\event.json",
        r"claimed\event.json",
        "https://example.invalid/claimed/event.json",
        "./claimed/event.json",
        "claimed/./event.json",
        "claimed/../event.json",
        " claimed/event.json",
        "claimed/event.json ",
    ),
)
def test_bound_manifest_cli_rejects_unsafe_report_artifact_paths_without_leak(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    event_marker = "synthetic-cli-private-event-body"
    event = tmp_path / "reviewed" / "event.json"
    event.parent.mkdir()
    write_audit_event(event, context={"marker": event_marker})
    report_payload = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))
    report_payload["report"]["schema_version"] = "agent-guard.report_evidence.v2"
    embedded_manifest = report_payload["evidence_pack_manifest"]
    embedded_manifest["schema_version"] = "agent-guard.evidence_pack_manifest.v2"
    embedded_manifest["report"]["schema_version"] = "agent-guard.report_evidence.v2"
    embedded_manifest["artifacts"].append(
        {
            "path": "reviewed/event.json",
            "role": "agent-policy-audit-event",
            "content_binding": build_agent_policy_audit_event_binding(
                event,
                event_profile=AUDIT_EVENT_PROFILE,
            ),
        }
    )
    report = tmp_path / "report.json"
    report.write_text(json.dumps(report_payload), encoding="utf-8")

    result = run_cli(
        "evidence-pack",
        "manifest",
        "--root",
        str(tmp_path),
        "--report",
        str(report),
        "--artifact",
        unsafe_path,
        "--agent-policy-audit-event",
        "reviewed/event.json",
        "--agent-policy-audit-event-profile",
        AUDIT_EVENT_PROFILE,
        "--json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["error"] == "evidence-pack artifact path is invalid"
    public_output = result.stdout + result.stderr
    assert unsafe_path not in public_output
    assert str(event) not in public_output
    assert AUDIT_EVENT_PROFILE not in public_output
    assert event_marker not in public_output


def test_evidence_pack_manifest_cli_rejects_unverified_bound_v2_report(
    tmp_path: Path,
) -> None:
    report = tmp_path / "report.json"
    event = tmp_path / "reviewed" / "event.json"
    event.parent.mkdir()
    write_audit_event(event)
    report_payload = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))
    report_payload["report"]["schema_version"] = "agent-guard.report_evidence.v2"
    manifest = report_payload["evidence_pack_manifest"]
    manifest["schema_version"] = "agent-guard.evidence_pack_manifest.v2"
    manifest["report"]["schema_version"] = "agent-guard.report_evidence.v2"
    manifest["artifacts"].append(
        {
            "path": "reviewed/event.json",
            "role": "agent-policy-audit-event",
            "content_binding": build_agent_policy_audit_event_binding(
                event,
                event_profile=AUDIT_EVENT_PROFILE,
            ),
        }
    )
    report.write_text(json.dumps(report_payload), encoding="utf-8")

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
    assert payload["error"] == "agent-policy audit event binding is invalid"
    assert str(event) not in result.stdout + result.stderr
    assert AUDIT_EVENT_PROFILE not in result.stdout + result.stderr


def test_evidence_pack_manifest_cli_rejects_mismatched_bound_v2_event(
    tmp_path: Path,
) -> None:
    report = tmp_path / "report.json"
    event = tmp_path / "reviewed" / "event.json"
    event.parent.mkdir()
    write_audit_event(event)
    report_payload = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))
    report_payload["report"]["schema_version"] = "agent-guard.report_evidence.v2"
    manifest = report_payload["evidence_pack_manifest"]
    manifest["schema_version"] = "agent-guard.evidence_pack_manifest.v2"
    manifest["report"]["schema_version"] = "agent-guard.report_evidence.v2"
    manifest["artifacts"].append(
        {
            "path": "reviewed/event.json",
            "role": "agent-policy-audit-event",
            "content_binding": build_agent_policy_audit_event_binding(
                event,
                event_profile=AUDIT_EVENT_PROFILE,
            ),
        }
    )
    report.write_text(json.dumps(report_payload), encoding="utf-8")
    private_marker = "synthetic-unreviewed-event-body"
    write_audit_event(event, context={"marker": private_marker})

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
    assert payload["error"] == "agent-policy audit event binding is invalid"
    assert private_marker not in result.stdout + result.stderr
    assert str(event) not in result.stdout + result.stderr
    assert AUDIT_EVENT_PROFILE not in result.stdout + result.stderr


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
        "--artifact",
        str(tmp_path.parent / "outside-report.json"),
        "--artifact",
        r"C:\Users\alice\secret\agent-guard-report.json",
        "--artifact",
        r"\\server\share\agent-guard-report.json",
        "--json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    manifest = payload["evidence_pack_manifest"]
    assert manifest["schema_version"] == "agent-guard.evidence_pack_manifest.v1"
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
        {"path": "outside-report.json", "role": "report"},
        {"path": "agent-guard-report.json", "role": "report"},
        {"path": "agent-guard-report.json", "role": "report"},
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
    write_audit_event(event)

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
    write_audit_event(first, context={"status": "first"})
    write_audit_event(second, context={"status": "second"})

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
    payload = audit_event_payload(capability="read")
    event.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    first = build_agent_policy_audit_event_binding(event, event_profile=AUDIT_EVENT_PROFILE)

    event.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    equivalent = build_agent_policy_audit_event_binding(event, event_profile=AUDIT_EVENT_PROFILE)
    write_audit_event(event, capability="write")
    changed = build_agent_policy_audit_event_binding(event, event_profile=AUDIT_EVENT_PROFILE)

    assert equivalent == first
    assert changed["digest"] != first["digest"]


def test_audit_event_binding_preserves_distinct_large_number_lexemes(
    tmp_path: Path,
) -> None:
    event = tmp_path / "event.json"
    event.write_text(
        '{"capability":"read","context":{"sequence":9007199254740992.0},'
        '"decision":{"matched_repo":"example/repo","mode":"auto_allow",'
        '"reason":"repo_policy"},"repo":"example/repo"}\n',
        encoding="utf-8",
    )
    first = build_agent_policy_audit_event_binding(
        event,
        event_profile=AUDIT_EVENT_PROFILE,
    )

    event.write_text(
        '{"capability":"read","context":{"sequence":9007199254740993.0},'
        '"decision":{"matched_repo":"example/repo","mode":"auto_allow",'
        '"reason":"repo_policy"},"repo":"example/repo"}\n',
        encoding="utf-8",
    )
    changed = build_agent_policy_audit_event_binding(
        event,
        event_profile=AUDIT_EVENT_PROFILE,
    )

    assert changed["digest"] != first["digest"]


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_audit_event_binding_rejects_nonfinite_json_constants(
    tmp_path: Path,
    constant: str,
) -> None:
    event = tmp_path / "event.json"
    event.write_text(
        '{"capability":"read","context":{"sequence":'
        + constant
        + '},"decision":{"matched_repo":"example/repo","mode":"auto_allow",'
        '"reason":"repo_policy"},"repo":"example/repo"}\n',
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="^agent-policy audit event is not valid bounded JSON$",
    ) as exc_info:
        build_agent_policy_audit_event_binding(
            event,
            event_profile=AUDIT_EVENT_PROFILE,
        )

    assert constant not in str(exc_info.value)
    assert str(tmp_path) not in str(exc_info.value)


@pytest.mark.parametrize("shape", ["deep", "wide"])
def test_audit_event_binding_rejects_shared_structure_budget_overflow(
    tmp_path: Path,
    shape: str,
) -> None:
    event = tmp_path / "event.json"
    if shape == "deep":
        nested: object = None
        for _ in range(MAX_JSON_DEPTH):
            nested = [nested]
        context = {"nested": nested}
    else:
        context = {"items": [None] * MAX_JSON_ITEMS}
    event.write_text(
        json.dumps(audit_event_payload(context=context)),
        encoding="utf-8",
    )
    assert event.stat().st_size < MAX_REPORT_JSON_BYTES

    with pytest.raises(
        ValueError,
        match="^agent-policy audit event is not valid bounded JSON$",
    ) as exc_info:
        build_agent_policy_audit_event_binding(
            event,
            event_profile=AUDIT_EVENT_PROFILE,
        )

    assert str(tmp_path) not in str(exc_info.value)


@pytest.mark.parametrize(
    "event_path",
    (
        "reviewed/event.json",
        ".agent-guard/reviewed-event.json",
        "reviewed/event-version.json",
    ),
)
def test_audit_event_binding_accepts_sanitized_repository_relative_payload_paths(
    tmp_path: Path,
    event_path: str,
) -> None:
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(audit_event_payload() | {"path": event_path}),
        encoding="utf-8",
    )

    binding = build_agent_policy_audit_event_binding(
        event,
        event_profile=AUDIT_EVENT_PROFILE,
    )

    assert binding["event_profile"] == AUDIT_EVENT_PROFILE


@pytest.mark.parametrize(
    "event_path",
    (
        ".",
        "../synthetic-event.json",
        "reviewed/../synthetic-event.json",
        "reviewed/./synthetic-event.json",
        r"C:\synthetic\event.json",
        r"\\synthetic-host\synthetic-share\event.json",
        r"reviewed\event.json",
        "file://synthetic.invalid/reviewed/event.json",
        "artifact+review:/synthetic/event.json",
        "artifact+review:synthetic-event.json",
        "reviewed/\x01event.json",
        "reviewed/\x7fevent.json",
        "reviewed/\x85event.json",
        "reviewed/\u2028event.json",
        "reviewed/\u2029event.json",
        "reviewed/\u202eevent.json",
        "reviewed/\ud800event.json",
        "reviewed/\U00013438event.json",
        "reviewed/\U00013439event.json",
        "reviewed/\U0001343fevent.json",
        "reviewed/caf\u00e9-\u8a3c\u62e0.json",
        "reviewed/\U00013440event.json",
    ),
)
def test_audit_event_binding_rejects_unsanitized_payload_paths_before_canonicalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_path: str,
) -> None:
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(audit_event_payload() | {"path": event_path}),
        encoding="utf-8",
    )

    def unexpected_canonicalization(_value: object) -> bytes:
        raise AssertionError("unsafe audit-event path must not be canonicalized")

    monkeypatch.setattr(
        evidence_pack,
        "_canonical_json_value",
        unexpected_canonicalization,
    )

    with pytest.raises(
        ValueError,
        match="^agent-policy audit event is not valid bounded JSON$",
    ) as exc_info:
        build_agent_policy_audit_event_binding(
            event,
            event_profile=AUDIT_EVENT_PROFILE,
        )

    assert event_path not in str(exc_info.value)


@pytest.mark.parametrize(
    "payload",
    (
        {"case_id": "not-an-audit-event", "expected_findings": []},
        {
            key: value
            for key, value in audit_event_payload().items()
            if key != "repo"
        },
        audit_event_payload() | {"extra": "not allowed"},
        audit_event_payload() | {"capability": 7},
        audit_event_payload()
        | {
            "decision": {
                "mode": "auto_allow",
                "reason": "repo_policy",
                "matched_repo": "example/repo",
                "extra": True,
            }
        },
        audit_event_payload() | {"path": "/private/repository"},
    ),
)
def test_audit_event_binding_rejects_payloads_outside_recognized_profile_schema(
    tmp_path: Path,
    payload: dict[str, object],
) -> None:
    marker = "not-an-audit-event"
    event = tmp_path / "event.json"
    event.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="^agent-policy audit event is not valid bounded JSON$",
    ) as exc_info:
        build_agent_policy_audit_event_binding(
            event,
            event_profile=AUDIT_EVENT_PROFILE,
        )

    assert marker not in str(exc_info.value)


def test_audit_event_binding_rejects_unsupported_profile_before_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = tmp_path / "event.json"
    write_audit_event(event)

    def unexpected_digest(_value: bytes) -> object:
        raise AssertionError("digest computation must not run")

    monkeypatch.setattr(evidence_pack.hashlib, "sha256", unexpected_digest)

    with pytest.raises(
        ValueError,
        match="^agent-policy audit event profile is invalid$",
    ):
        build_agent_policy_audit_event_binding(
            event,
            event_profile="agent-policy.audit_event.v1.1",
        )


def test_manifest_rejects_extra_fields_in_prebuilt_audit_event_artifact(
    tmp_path: Path,
) -> None:
    marker = "synthetic-private-passphrase"
    event = tmp_path / "event.json"
    write_audit_event(event)
    binding = build_agent_policy_audit_event_binding(
        event,
        event_profile=AUDIT_EVENT_PROFILE,
    )

    with pytest.raises(
        ValueError,
        match="^agent-policy audit event is not valid bounded JSON$",
    ) as exc_info:
        build_evidence_pack_manifest(
            report_payload=V2_REPORT_PAYLOAD,
            agent_policy_audit_event_artifacts=[
                {
                    "path": "reviewed/event.json",
                    "role": "agent-policy-audit-event",
                    "content_binding": binding,
                    "event_body": {"passphrase": marker},
                }
            ],
            root=tmp_path,
        )

    assert marker not in str(exc_info.value)


def test_manifest_rejects_invalid_prebuilt_audit_event_artifact_shape(
    tmp_path: Path,
) -> None:
    event = tmp_path / "event.json"
    write_audit_event(event)
    binding = build_agent_policy_audit_event_binding(
        event,
        event_profile=AUDIT_EVENT_PROFILE,
    )
    valid_artifact: dict[str, object] = {
        "path": "reviewed/event.json",
        "role": "agent-policy-audit-event",
        "content_binding": binding,
    }
    manifest = build_evidence_pack_manifest(
        report_payload=V2_REPORT_PAYLOAD,
        agent_policy_audit_event_artifacts=[valid_artifact],
        root=tmp_path,
    )
    assert manifest["schema_version"] == "agent-guard.evidence_pack_manifest.v2"
    assert manifest["artifacts"] == [valid_artifact]

    invalid_artifacts = [
        valid_artifact | {"role": "report"},
        valid_artifact | {"path": "../outside/event.json"},
        valid_artifact | {"content_binding": binding | {"digest": "invalid"}},
    ]
    for artifact in invalid_artifacts:
        with pytest.raises(
            ValueError,
            match="^agent-policy audit event is not valid bounded JSON$",
        ):
            build_evidence_pack_manifest(
                report_payload=V2_REPORT_PAYLOAD,
                agent_policy_audit_event_artifacts=[artifact],
                root=tmp_path,
            )


def test_bound_manifest_rejects_v1_report_without_leak(tmp_path: Path) -> None:
    event = tmp_path / "event.json"
    write_audit_event(event)
    artifact = {
        "path": "reviewed/event.json",
        "role": "agent-policy-audit-event",
        "content_binding": build_agent_policy_audit_event_binding(
            event,
            event_profile=AUDIT_EVENT_PROFILE,
        ),
    }

    with pytest.raises(
        ValueError,
        match=r"^bound agent-policy audit events require report evidence v2$",
    ) as exc_info:
        build_evidence_pack_manifest(
            report_payload={
                "report": {"schema_version": "agent-guard.report_evidence.v1"},
            },
            agent_policy_audit_event_artifacts=[artifact],
            root=tmp_path,
        )

    assert str(event) not in str(exc_info.value)


def test_manifest_rejects_v2_report_without_bound_audit_event() -> None:
    for prebuilt_artifacts in (None, []):
        with pytest.raises(
            ValueError,
            match=(
                r"^report evidence v2 requires bound agent-policy audit events$"
            ),
        ):
            build_evidence_pack_manifest(
                report_payload=V2_REPORT_PAYLOAD,
                agent_policy_audit_event_artifacts=prebuilt_artifacts,
            )

    manifest = build_evidence_pack_manifest(
        report_payload={
            "report": {"schema_version": "agent-guard.report_evidence.v1"},
        },
        agent_policy_audit_event_artifacts=[],
    )
    assert manifest["schema_version"] == "agent-guard.evidence_pack_manifest.v1"


def test_manifest_rejects_profile_with_explicitly_empty_prebuilt_artifacts() -> None:
    with pytest.raises(
        ValueError,
        match=r"^agent-policy audit event profile is invalid$",
    ):
        build_evidence_pack_manifest(
            report_payload=V2_REPORT_PAYLOAD,
            agent_policy_audit_event_artifacts=[],
            agent_policy_audit_event_profile=AUDIT_EVENT_PROFILE,
        )


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
    write_audit_event(event)
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

    def unexpected_parse(_raw: bytes, *, event_profile: str) -> bytes:
        del event_profile
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
def test_audit_event_binding_rejects_opened_descriptor_after_final_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    event = root / "reviewed" / "event.json"
    external = tmp_path / "external-event.json"
    event.parent.mkdir(parents=True)
    write_audit_event(event)
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

    assert expected["event_profile"] == AUDIT_EVENT_PROFILE
    with pytest.raises(
        ValueError,
        match="^agent-policy audit event must be a repository file$",
    ):
        build_agent_policy_audit_event_artifacts(
            ["reviewed/event.json"],
            event_profile=AUDIT_EVENT_PROFILE,
            root=root,
        )


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
    write_audit_event(event)
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
    write_audit_event(event)
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
    event.write_bytes(
        b'{"repo":"example/repo","capability":"read",'
        b'"context":{"value":"\\ud800"},'
        b'"decision":{"mode":"auto_allow","reason":"repo_policy",'
        b'"matched_repo":"example/repo"}}\n'
    )

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
