"""Where: tests/test_evidence_consumer.py
What: contract tests for the downstream evidence consumer example.
Why: keep the copyable consumer aligned with packaged report schemas.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import agent_guard.consumer._bundle as consumer_bundle
from agent_guard.consumer import (
    LOCAL_PATH_RE,
    RAW_URL_RE,
    load_payload,
    load_report_schema,
    select_report_schema,
    validate_agent_policy_audit_event_files,
    validate_report,
)
from agent_guard.consumer import (
    main as packaged_consumer_main,
)
from agent_guard.consumer._bundle import MAX_MARKDOWN_BYTES
from agent_guard.evidence_pack import build_agent_policy_audit_event_binding
from agent_guard.report_render import emit_report_output, render_report_output

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
SCRIPT = REPO_ROOT / "examples" / "evidence_consumer.py"
SAMPLE = REPO_ROOT / "docs" / "evidence-samples" / "agent-guard-report.json"
AUDIT_EVENT_PROFILE = "agent-policy.audit_event.v1.1"


def _bound_v2_report(event: Path) -> dict[str, object]:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["report"]["schema_version"] = "agent-guard.report_evidence.v2"
    manifest = payload["evidence_pack_manifest"]
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
    return payload


def run_consumer(path: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{SRC}{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else str(SRC)
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def run_packaged_consumer_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{SRC}{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else str(SRC)
    return subprocess.run(
        [sys.executable, "-m", "agent_guard.consumer", *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_packaged_consumer_accepts_legacy_unbound_audit_event_reference(
    tmp_path: Path,
) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_pack_manifest"]["artifacts"].append(
        {
            "path": "reviewed/policy-admission-event.json",
            "role": "agent-policy-audit-event",
        }
    )

    summary = validate_report(payload, load_report_schema())
    validate_agent_policy_audit_event_files(payload, (), event_profile="")

    assert summary["report_schema_version"] == "agent-guard.report_evidence.v1"

    event = tmp_path / "synthetic-legacy-event.json"
    event.write_text('{"status":"reviewed"}\n', encoding="utf-8")
    with pytest.raises(
        ValueError,
        match=r"^agent-policy audit event binding is invalid$",
    ) as exc_info:
        validate_agent_policy_audit_event_files(
            payload,
            (event,),
            event_profile=AUDIT_EVENT_PROFILE,
        )

    assert str(event) not in str(exc_info.value)
    assert AUDIT_EVENT_PROFILE not in str(exc_info.value)


def test_v1_content_binding_field_never_counts_as_bound(tmp_path: Path) -> None:
    event = tmp_path / "synthetic-v1-event.json"
    event.write_text('{"status":"reviewed"}\n', encoding="utf-8")
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_pack_manifest"]["artifacts"].append(
        {
            "path": "reviewed/event.json",
            "role": "agent-policy-audit-event",
            "content_binding": build_agent_policy_audit_event_binding(
                event,
                event_profile=AUDIT_EVENT_PROFILE,
            ),
        }
    )

    validate_report(payload, load_report_schema())
    validate_agent_policy_audit_event_files(payload, (), event_profile="")
    with pytest.raises(
        ValueError,
        match=r"^agent-policy audit event binding is invalid$",
    ):
        validate_agent_policy_audit_event_files(
            payload,
            (event,),
            event_profile=AUDIT_EVENT_PROFILE,
        )


def test_packaged_consumer_rejects_extra_audit_event_artifact_fields_without_leak(
    tmp_path: Path,
) -> None:
    marker = "synthetic-private-passphrase"
    event = tmp_path / "event.json"
    event.write_text('{"status":"reviewed"}\n', encoding="utf-8")
    binding = build_agent_policy_audit_event_binding(
        event,
        event_profile=AUDIT_EVENT_PROFILE,
    )
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["report"]["schema_version"] = "agent-guard.report_evidence.v2"
    payload["evidence_pack_manifest"]["schema_version"] = (
        "agent-guard.evidence_pack_manifest.v2"
    )
    payload["evidence_pack_manifest"]["report"]["schema_version"] = (
        "agent-guard.report_evidence.v2"
    )
    payload["evidence_pack_manifest"]["artifacts"].append(
        {
            "path": "reviewed/event.json",
            "role": "agent-policy-audit-event",
            "content_binding": binding,
            "event_body": {"passphrase": marker},
        }
    )

    with pytest.raises(ValueError, match="invalid fields") as exc_info:
        validate_report(payload, select_report_schema(payload))

    assert marker not in str(exc_info.value)


@pytest.mark.skipif(os.name != "posix", reason="exercises POSIX final-component no-follow")
def test_packaged_consumer_rejects_final_audit_event_symlink_without_leak(
    tmp_path: Path,
) -> None:
    event = tmp_path / "event.json"
    external = tmp_path / "external.json"
    external_marker = "synthetic-consumer-external-marker"
    event.write_text('{"status":"reviewed"}\n', encoding="utf-8")
    report = _bound_v2_report(event)
    external.write_text(json.dumps({"marker": external_marker}), encoding="utf-8")
    event.unlink()
    event.symlink_to(external)

    with pytest.raises(
        ValueError,
        match=r"^agent-policy audit event binding is invalid$",
    ) as exc_info:
        validate_agent_policy_audit_event_files(
            report,
            (event,),
            event_profile=AUDIT_EVENT_PROFILE,
        )

    assert external_marker not in str(exc_info.value)
    assert str(external) not in str(exc_info.value)


def test_packaged_consumer_rejects_large_number_audit_event_substitution(
    tmp_path: Path,
) -> None:
    event = tmp_path / "event.json"
    event.write_text('{"sequence":9007199254740992.0}\n', encoding="utf-8")
    report = _bound_v2_report(event)

    event.write_text('{"sequence":9007199254740993.0}\n', encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"^agent-policy audit event binding is invalid$",
    ):
        validate_agent_policy_audit_event_files(
            report,
            (event,),
            event_profile=AUDIT_EVENT_PROFILE,
        )


def test_current_consumer_accepts_matching_bound_v2_evidence(tmp_path: Path) -> None:
    event = tmp_path / "synthetic-reviewed-event.json"
    event.write_text('{"status":"reviewed","sequence":7}\n', encoding="utf-8")
    payload = _bound_v2_report(event)

    summary = validate_report(payload, select_report_schema(payload))
    validate_agent_policy_audit_event_files(
        payload,
        (event,),
        event_profile=AUDIT_EVENT_PROFILE,
    )

    assert summary["report_schema_version"] == "agent-guard.report_evidence.v2"
    report_path = tmp_path / "synthetic-report.json"
    report_path.write_text(json.dumps(payload), encoding="utf-8")
    result = run_packaged_consumer_cli(
        "--agent-policy-audit-event",
        str(event),
        "--agent-policy-audit-event-profile",
        AUDIT_EVENT_PROFILE,
        str(report_path),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["report_schema_version"] == (
        "agent-guard.report_evidence.v2"
    )


def test_bound_v2_verification_failures_are_sanitized(tmp_path: Path) -> None:
    event_marker = "synthetic-event-body-marker"
    event = tmp_path / "synthetic-sensitive-event-name.json"
    event.write_text(json.dumps({"marker": event_marker}), encoding="utf-8")
    payload = _bound_v2_report(event)
    mismatched_profile = "agent-policy.audit_event.v1.2"

    failures: list[ValueError] = []
    for paths, profile in (
        ((), ""),
        ((event,), mismatched_profile),
    ):
        with pytest.raises(
            ValueError,
            match=r"^agent-policy audit event binding is invalid$",
        ) as exc_info:
            validate_agent_policy_audit_event_files(
                payload,
                paths,
                event_profile=profile,
            )
        failures.append(exc_info.value)

    event.write_text('{"marker":', encoding="utf-8")
    with pytest.raises(
        ValueError,
        match=r"^agent-policy audit event binding is invalid$",
    ) as exc_info:
        validate_agent_policy_audit_event_files(
            payload,
            (event,),
            event_profile=AUDIT_EVENT_PROFILE,
        )
    failures.append(exc_info.value)

    for failure in failures:
        rendered = str(failure)
        assert event_marker not in rendered
        assert str(event) not in rendered
        assert mismatched_profile not in rendered


def test_current_consumer_rejects_mixed_unbound_v2_entries_without_leak(
    tmp_path: Path,
) -> None:
    event = tmp_path / "synthetic-reviewed-event.json"
    event.write_text('{"status":"reviewed"}\n', encoding="utf-8")
    payload = _bound_v2_report(event)
    marker = "synthetic-private-unbound-path.json"
    payload["evidence_pack_manifest"]["artifacts"].append(
        {
            "path": marker,
            "role": "agent-policy-audit-event",
        }
    )

    with pytest.raises(ValueError, match="content_binding is required") as exc_info:
        validate_report(payload, select_report_schema(payload))

    assert marker not in str(exc_info.value)
    assert str(event) not in str(exc_info.value)


def test_current_consumer_rejects_v2_without_bound_audit_event() -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["report"]["schema_version"] = "agent-guard.report_evidence.v2"
    payload["evidence_pack_manifest"]["schema_version"] = (
        "agent-guard.evidence_pack_manifest.v2"
    )
    payload["evidence_pack_manifest"]["report"]["schema_version"] = (
        "agent-guard.report_evidence.v2"
    )

    with pytest.raises(
        ValueError,
        match=r"^\$\.evidence_pack_manifest\.artifacts must include a bound audit event$",
    ):
        validate_report(payload, select_report_schema(payload))
    with pytest.raises(
        ValueError,
        match=r"^agent-policy audit event binding is invalid$",
    ):
        validate_agent_policy_audit_event_files(payload, (), event_profile="")

    payload.pop("evidence_pack_manifest")
    with pytest.raises(
        ValueError,
        match=r"^\$\.evidence_pack_manifest is required$",
    ):
        validate_report(payload, select_report_schema(payload))
    with pytest.raises(
        ValueError,
        match=r"^agent-policy audit event binding is invalid$",
    ):
        validate_agent_policy_audit_event_files(payload, (), event_profile="")


def test_report_schema_loader_is_bounded_and_v1_default_is_preserved() -> None:
    v1_schema = load_report_schema()
    v2_schema = load_report_schema("agent-guard.report_evidence.v2")

    assert v1_schema["$id"].endswith("agent-guard.report_evidence.v1.schema.json")
    assert v2_schema["$id"].endswith("agent-guard.report_evidence.v2.schema.json")
    with pytest.raises(
        ValueError,
        match=r"^report evidence schema version is not supported$",
    ):
        load_report_schema("synthetic-untrusted.schema.json")


def test_v1_schema_consumer_fails_closed_on_v2_report(tmp_path: Path) -> None:
    event = tmp_path / "synthetic-reviewed-event.json"
    event.write_text('{"status":"reviewed"}\n', encoding="utf-8")
    payload = _bound_v2_report(event)

    with pytest.raises(
        ValueError,
        match=r"must equal 'agent-guard\.(?:evidence_pack_manifest|report_evidence)\.v1'",
    ):
        validate_report(payload, load_report_schema())


def _prepend_duplicate_json_member(text: str, *, key: str, value: object) -> str:
    assert text.startswith("{")
    member = f"{json.dumps(key, ensure_ascii=False)}:{json.dumps(value, ensure_ascii=False)}"
    return f"{{{member},{text[1:]}"


def _synthetic_violation_report() -> tuple[dict[str, object], str]:
    marker = "synthetic-conformance-marker"
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    conformance = payload["conformance"]
    manifest = payload["evidence_pack_manifest"]
    assert isinstance(conformance, dict)
    assert isinstance(manifest, dict)
    assert isinstance(manifest["report"], dict)
    assert isinstance(manifest["conformance"], dict)

    payload["status"] = "violation"
    payload["exit_code"] = 1
    conformance["status"] = "violation"
    conformance["checked_count"] = 17
    conformance["finding_count"] = 1
    conformance["findings"] = [
        {
            "rule_id": "synthetic_conformance_rule",
            "severity": "high",
            "requirement_id": "synthetic_requirement",
            "message": marker,
            "reason": "synthetic_reason",
        }
    ]
    manifest["report"]["status"] = "violation"
    manifest["conformance"]["status"] = "violation"
    manifest["conformance"]["finding_count"] = 1
    return payload, marker


def _synthetic_result_envelope(
    *,
    tool: dict[str, object],
    scanner: str,
    command: str,
    status: str,
    exit_code: int,
    policy: dict[str, object],
    findings: list[object],
    summary: dict[str, object],
    section_name: str,
    section: object,
) -> dict[str, object]:
    return {
        "schema_version": "agent-guard.result.v1",
        "tool": tool,
        "scanner": scanner,
        "command": command,
        "status": status,
        "exit_code": exit_code,
        "policy": policy,
        "summary": {"finding_count": len(findings), **summary},
        "finding_count": len(findings),
        "findings": findings,
        section_name: section,
    }


def _canonical_standalone_envelopes(report_payload: dict[str, object]) -> dict[str, dict[str, object]]:
    tool = report_payload["tool"]
    policy = report_payload["policy"]
    conformance = report_payload["conformance"]
    surface_inventory = report_payload["surface_inventory"]
    manifest = report_payload["evidence_pack_manifest"]
    assert isinstance(tool, dict)
    assert isinstance(policy, dict)
    assert isinstance(conformance, dict)
    assert isinstance(surface_inventory, dict)
    assert isinstance(surface_inventory["summary"], dict)
    assert isinstance(manifest, dict)
    assert isinstance(conformance["findings"], list)
    assert isinstance(manifest["gates"], list)
    assert isinstance(manifest["artifacts"], list)

    report_artifacts = [
        artifact
        for artifact in manifest["artifacts"]
        if isinstance(artifact, dict) and artifact.get("role") == "report"
    ]
    assert len(report_artifacts) == 1
    report_artifact_path = report_artifacts[0]["path"]
    assert isinstance(report_artifact_path, str)
    report_artifact_policy = {"path": report_artifact_path}

    conformance_status = str(conformance["status"])
    conformance_findings = conformance["findings"]
    conformance_count = conformance["finding_count"]
    checked_count = conformance["checked_count"]
    profile = conformance["profile"]
    surface_count = surface_inventory["summary"]["surface_count"]
    gates = manifest["gates"]
    assert isinstance(conformance_count, int)
    assert isinstance(checked_count, int)
    assert isinstance(profile, str)
    assert isinstance(surface_count, int)

    return {
        "agent-guard-conformance.json": _synthetic_result_envelope(
            tool=tool,
            scanner="conformance",
            command="check",
            status=conformance_status,
            exit_code=0 if conformance_status == "ok" else 1,
            policy=report_artifact_policy,
            findings=conformance_findings,
            summary={
                "scanned_count": checked_count,
                "scanned_unit": "requirements",
                "profile": profile,
                "conformance_finding_count": conformance_count,
            },
            section_name="conformance",
            section=conformance,
        ),
        "agent-surface-inventory.json": _synthetic_result_envelope(
            tool=tool,
            scanner="surface",
            command="inventory",
            status="ok",
            exit_code=0,
            policy=policy,
            findings=[],
            summary={
                "scanned_count": surface_count,
                "scanned_unit": "surfaces",
                "surface_count": surface_count,
            },
            section_name="surface_inventory",
            section=surface_inventory,
        ),
        "agent-guard-evidence-pack.json": _synthetic_result_envelope(
            tool=tool,
            scanner="evidence-pack",
            command="manifest",
            status="ok",
            exit_code=0,
            policy=report_artifact_policy,
            findings=[],
            summary={"scanned_count": len(gates), "scanned_unit": "gates"},
            section_name="evidence_pack_manifest",
            section=manifest,
        ),
    }


def _mutate_standalone_envelope(
    envelope: dict[str, object],
    *,
    artifact_name: str,
    mutation: str,
    marker: str,
) -> None:
    summary = envelope["summary"]
    assert isinstance(summary, dict)

    if mutation == "status":
        if artifact_name == "agent-guard-conformance.json":
            envelope["status"] = "ok"
            envelope["exit_code"] = 0
        else:
            envelope["status"] = "violation"
            envelope["exit_code"] = 1
    elif mutation == "exit_code":
        envelope["exit_code"] = 2
    elif mutation == "findings":
        findings = [] if artifact_name == "agent-guard-conformance.json" else [{"rule_id": marker}]
        envelope["findings"] = findings
        envelope["finding_count"] = len(findings)
        summary["finding_count"] = len(findings)
    elif mutation == "scanned_count":
        summary["scanned_count"] = int(summary["scanned_count"]) + 1
    elif mutation == "scanned_unit":
        summary["scanned_unit"] = "synthetic-unit"
    elif mutation == "profile":
        summary["profile"] = "minimal"
    elif mutation == "conformance_finding_count":
        summary["conformance_finding_count"] = 0
    elif mutation == "surface_count":
        summary["surface_count"] = int(summary["surface_count"]) + 1
    elif mutation == "manifest_surface_count":
        manifest = envelope["evidence_pack_manifest"]
        assert isinstance(manifest, dict)
        manifest_summary = manifest["summary"]
        assert isinstance(manifest_summary, dict)
        manifest_summary["surface_count"] = int(manifest_summary["surface_count"]) + 1
    elif mutation == "manifest_tool":
        manifest = envelope["evidence_pack_manifest"]
        assert isinstance(manifest, dict)
        manifest["tool"] = {"name": "agent-guard", "version": marker}
    elif mutation == "tool":
        envelope["tool"] = {"name": "agent-guard", "version": marker}
    elif mutation == "policy":
        envelope["policy"] = {"path": marker}
    elif mutation == "external_policy":
        envelope["policy"] = {"path": "<external-policy>"}
    elif mutation == "manifest_artifacts":
        manifest = envelope["evidence_pack_manifest"]
        assert isinstance(manifest, dict)
        manifest["artifacts"] = [{"path": marker, "role": "report"}]
    else:
        raise AssertionError(f"unknown synthetic mutation: {mutation}")


def test_exported_redaction_regexes_keep_legacy_matching_semantics() -> None:
    assert LOCAL_PATH_RE.search("command>/home/synthetic/private.txt")
    assert LOCAL_PATH_RE.search("-L/home/synthetic/lib")
    assert not LOCAL_PATH_RE.search("ratio / denominator and unit / second")
    assert RAW_URL_RE.search("https://example.invalid/private")
    assert not RAW_URL_RE.search("https:example.invalid/private")
    assert not RAW_URL_RE.search("file://localhost/home/synthetic/private")


def test_evidence_consumer_accepts_public_sample() -> None:
    result = run_consumer(SAMPLE)

    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["finding_count"] == 0
    assert payload["report_schema_version"] == "agent-guard.report_evidence.v1"
    assert payload["schema_version"] == "agent-guard.result.v1"
    assert payload["status"] == "ok"
    assert payload["surface_count"] >= 1
    assert payload["enabled_gate_count"] >= 2
    assert payload["missing_gate_count"] >= 0


def test_packaged_consumer_accepts_public_sample_directly() -> None:
    summary = validate_report(load_payload(SAMPLE), load_report_schema())

    assert summary["status"] == "ok"
    assert summary["report_schema_version"] == "agent-guard.report_evidence.v1"


@pytest.mark.parametrize(
    ("container_key", "duplicate_key"),
    (
        (None, "schema_version"),
        ("tool", "version"),
    ),
)
def test_packaged_consumer_report_only_rejects_duplicate_json_keys_without_leak(
    tmp_path: Path,
    container_key: str | None,
    duplicate_key: str,
) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    secret_like_value = "sk-" + ("d" * 24)
    if container_key is None:
        raw = _prepend_duplicate_json_member(raw, key=duplicate_key, value=secret_like_value)
    else:
        object_prefix = f"{json.dumps(container_key)}:{{"
        duplicate_member = (
            f"{json.dumps(duplicate_key)}:{json.dumps(secret_like_value)}"
        )
        assert object_prefix in raw
        raw = raw.replace(object_prefix, f"{object_prefix}{duplicate_member},", 1)
    report = tmp_path / "report.json"
    report.write_bytes((raw + "\n").encode("utf-8"))

    result = run_packaged_consumer_cli(str(report))

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == (
        "agent-guard evidence invalid: public evidence JSON contains duplicate object keys\n"
    )
    assert duplicate_key not in result.stderr
    assert secret_like_value not in result.stderr
    if container_key is not None:
        assert f"$.{container_key}" not in result.stderr
    assert str(tmp_path) not in result.stderr


def test_packaged_consumer_cli_accepts_fixture_bundle(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")

    result = run_packaged_consumer_cli("--evidence-dir", str(evidence_dir), str(report))

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["status"] == "ok"


def test_packaged_consumer_accepts_bound_v2_standalone_manifest_bundle(
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    event = tmp_path / "synthetic-reviewed-event.json"
    event.write_text('{"status":"reviewed"}\n', encoding="utf-8")
    payload = _bound_v2_report(event)
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")
    envelope = _canonical_standalone_envelopes(payload)[
        "agent-guard-evidence-pack.json"
    ]
    (evidence_dir / "agent-guard-evidence-pack.json").write_text(
        json.dumps(envelope),
        encoding="utf-8",
    )

    result = run_packaged_consumer_cli(
        "--evidence-dir",
        str(evidence_dir),
        "--agent-policy-audit-event",
        str(event),
        "--agent-policy-audit-event-profile",
        AUDIT_EVENT_PROFILE,
        str(report),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["report_schema_version"] == (
        "agent-guard.report_evidence.v2"
    )
    assert event.name not in result.stdout + result.stderr


def test_bundle_directory_enumeration_stops_at_configured_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_dir = tmp_path / "evidence"
    entry_cap = consumer_bundle.MAX_EVIDENCE_DIRECTORY_ENTRIES + 1

    class FakeDirEntry:
        def __init__(self, name: str) -> None:
            self.name = name

    class ScandirProbe:
        def __init__(self) -> None:
            self._entries = [FakeDirEntry(f"artifact-{index}") for index in range(entry_cap + 1)]
            self.next_calls = 0
            self.closed = False

        def __enter__(self) -> ScandirProbe:
            return self

        def __exit__(self, *_: object) -> None:
            self.closed = True

        def __iter__(self) -> ScandirProbe:
            return self

        def __next__(self) -> FakeDirEntry:
            if self.next_calls >= entry_cap:
                raise AssertionError("bundle scan consumed an entry beyond its cap")
            entry = self._entries[self.next_calls]
            self.next_calls += 1
            return entry

    probe = ScandirProbe()

    def fake_scandir(path: object) -> ScandirProbe:
        assert os.fspath(path) == os.fspath(evidence_dir)
        return probe

    monkeypatch.setattr(consumer_bundle.os, "scandir", fake_scandir)

    with pytest.raises(ValueError) as exc_info:
        consumer_bundle._read_bundle_entries(evidence_dir)

    assert str(exc_info.value) == consumer_bundle.ERROR_PUBLIC_BUNDLE_LIMIT
    assert probe.next_calls == entry_cap
    assert probe.closed


@pytest.mark.parametrize(
    ("target", "duplicate_key"),
    (
        ("selected-report", "schema_version"),
        ("agent-guard-report.json", "schema_version"),
        ("agent-guard-results.sarif", "version"),
        ("agent-guard-conformance.json", "schema_version"),
        ("agent-guard-evidence-pack.json", "schema_version"),
        ("agent-surface-inventory.json", "schema_version"),
    ),
)
def test_packaged_consumer_rejects_duplicate_keys_before_bundle_semantic_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    duplicate_key: str,
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    selected_report = tmp_path / "selected-report.json"
    canonical_report = render_report_output(payload, "json")
    selected_report.write_bytes(canonical_report.encode("utf-8"))
    secret_like_value = "sk-" + ("b" * 24)

    if target == "selected-report":
        selected_report.write_bytes(
            _prepend_duplicate_json_member(
                canonical_report,
                key=duplicate_key,
                value=secret_like_value,
            ).encode("utf-8")
        )
    elif target == "agent-guard-report.json":
        (evidence_dir / target).write_bytes(
            _prepend_duplicate_json_member(
                canonical_report,
                key=duplicate_key,
                value=secret_like_value,
            ).encode("utf-8")
        )
    elif target == "agent-guard-results.sarif":
        (evidence_dir / target).write_bytes(
            _prepend_duplicate_json_member(
                render_report_output(payload, "sarif"),
                key=duplicate_key,
                value=secret_like_value,
            ).encode("utf-8")
        )
    else:
        envelope = _canonical_standalone_envelopes(payload)[target]
        envelope_json = json.dumps(envelope, ensure_ascii=False, sort_keys=True) + "\n"
        (evidence_dir / target).write_bytes(
            _prepend_duplicate_json_member(
                envelope_json,
                key=duplicate_key,
                value=secret_like_value,
            ).encode("utf-8")
        )

    validation_calls = {"report": 0, "sarif": 0, "envelope": 0}
    original_validate_report = consumer_bundle.validate_report
    original_validate_sarif = consumer_bundle._validate_sarif
    original_validate_envelope = consumer_bundle._validate_result_envelope

    def tracked_validate_report(*args, **kwargs):
        validation_calls["report"] += 1
        return original_validate_report(*args, **kwargs)

    def tracked_validate_sarif(*args, **kwargs):
        validation_calls["sarif"] += 1
        return original_validate_sarif(*args, **kwargs)

    def tracked_validate_envelope(*args, **kwargs):
        validation_calls["envelope"] += 1
        return original_validate_envelope(*args, **kwargs)

    monkeypatch.setattr(consumer_bundle, "validate_report", tracked_validate_report)
    monkeypatch.setattr(consumer_bundle, "_validate_sarif", tracked_validate_sarif)
    monkeypatch.setattr(
        consumer_bundle,
        "_validate_result_envelope",
        tracked_validate_envelope,
    )

    with pytest.raises(ValueError) as exc_info:
        consumer_bundle.validate_evidence_bundle(evidence_dir, selected_report)

    assert str(exc_info.value) == consumer_bundle.ERROR_PUBLIC_BUNDLE_INVALID
    assert validation_calls["report"] == (0 if target == "selected-report" else 1)
    assert validation_calls["sarif"] == 0
    assert validation_calls["envelope"] == 0
    assert duplicate_key not in str(exc_info.value)
    assert secret_like_value not in str(exc_info.value)
    assert str(tmp_path) not in str(exc_info.value)


def test_report_output_files_round_trip_as_utf8_lf_under_windows_text_defaults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    evidence_dir = tmp_path / "evidence"
    rendered_artifacts = {
        "agent-guard-report.json": render_report_output(payload, "json"),
        "agent-guard-report.md": render_report_output(payload, "markdown"),
        "agent-guard-results.sarif": render_report_output(payload, "sarif"),
        "agent-guard-annotations.txt": render_report_output(payload, "github-annotations"),
    }

    def windows_default_write_text(
        path: Path,
        data: str,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> int:
        if newline is None:
            persisted = data.replace("\n", "\r\n")
        elif newline == "":
            persisted = data
        else:
            persisted = data.replace("\n", newline)
        path.write_bytes(persisted.encode(encoding or "utf-8", errors or "strict"))
        return len(data)

    monkeypatch.setattr(Path, "write_text", windows_default_write_text)

    for artifact_name, rendered in rendered_artifacts.items():
        assert "\r" not in rendered
        artifact = evidence_dir / artifact_name
        emit_report_output(rendered, str(artifact))
        assert artifact.read_bytes() == rendered.encode("utf-8")
        assert b"\r\n" not in artifact.read_bytes()

    result = run_packaged_consumer_cli(
        "--evidence-dir",
        str(evidence_dir),
        str(evidence_dir / "agent-guard-report.json"),
    )

    assert result.returncode == 0, result.stdout + result.stderr

    markdown = evidence_dir / "agent-guard-report.md"
    markdown.write_bytes(rendered_artifacts[markdown.name].replace("\n", "\r\n").encode("utf-8"))
    drifted = run_packaged_consumer_cli(
        "--evidence-dir",
        str(evidence_dir),
        str(evidence_dir / "agent-guard-report.json"),
    )
    assert drifted.returncode == 1
    assert drifted.stdout == ""
    assert drifted.stderr == "agent-guard evidence bundle invalid\n"
    assert str(tmp_path) not in drifted.stderr


def test_packaged_consumer_cli_accepts_canonical_standalone_envelopes(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    payload, marker = _synthetic_violation_report()
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    for artifact_name, envelope in _canonical_standalone_envelopes(payload).items():
        (evidence_dir / artifact_name).write_text(json.dumps(envelope), encoding="utf-8")

    result = run_packaged_consumer_cli("--evidence-dir", str(evidence_dir), str(report))

    assert result.returncode == 0
    assert json.loads(result.stdout)["status"] == "violation"
    assert marker not in result.stdout
    assert marker not in result.stderr


@pytest.mark.parametrize(
    "artifact_name",
    ("agent-guard-conformance.json", "agent-guard-evidence-pack.json"),
)
def test_packaged_consumer_cli_accepts_controlled_external_policy_for_relocated_report(
    tmp_path: Path,
    artifact_name: str,
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    staged_dir = tmp_path / "staged"
    staged_dir.mkdir()
    payload, marker = _synthetic_violation_report()
    manifest = payload["evidence_pack_manifest"]
    assert isinstance(manifest, dict)
    manifest["artifacts"] = [{"path": "agent-guard-report.json", "role": "report"}]
    report = staged_dir / "agent-guard-report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")
    envelope = _canonical_standalone_envelopes(payload)[artifact_name]
    envelope["policy"] = {"path": "<external-policy>"}
    (evidence_dir / artifact_name).write_text(json.dumps(envelope), encoding="utf-8")

    result = run_packaged_consumer_cli("--evidence-dir", str(evidence_dir), str(report))

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["status"] == "violation"
    assert marker not in result.stdout
    assert marker not in result.stderr


@pytest.mark.parametrize(
    ("artifact_name", "mutation"),
    (
        ("agent-guard-conformance.json", "status"),
        ("agent-guard-conformance.json", "exit_code"),
        ("agent-guard-conformance.json", "findings"),
        ("agent-guard-conformance.json", "scanned_count"),
        ("agent-guard-conformance.json", "scanned_unit"),
        ("agent-guard-conformance.json", "profile"),
        ("agent-guard-conformance.json", "conformance_finding_count"),
        ("agent-guard-conformance.json", "tool"),
        ("agent-guard-conformance.json", "policy"),
        ("agent-surface-inventory.json", "status"),
        ("agent-surface-inventory.json", "findings"),
        ("agent-surface-inventory.json", "scanned_count"),
        ("agent-surface-inventory.json", "scanned_unit"),
        ("agent-surface-inventory.json", "surface_count"),
        ("agent-surface-inventory.json", "tool"),
        ("agent-surface-inventory.json", "policy"),
        ("agent-surface-inventory.json", "external_policy"),
        ("agent-guard-evidence-pack.json", "status"),
        ("agent-guard-evidence-pack.json", "findings"),
        ("agent-guard-evidence-pack.json", "scanned_count"),
        ("agent-guard-evidence-pack.json", "scanned_unit"),
        ("agent-guard-evidence-pack.json", "manifest_surface_count"),
        ("agent-guard-evidence-pack.json", "manifest_tool"),
        ("agent-guard-evidence-pack.json", "tool"),
        ("agent-guard-evidence-pack.json", "policy"),
        ("agent-guard-evidence-pack.json", "manifest_artifacts"),
    ),
)
def test_packaged_consumer_cli_rejects_inconsistent_standalone_envelopes(
    tmp_path: Path,
    artifact_name: str,
    mutation: str,
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    payload, marker = _synthetic_violation_report()
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")
    envelope = _canonical_standalone_envelopes(payload)[artifact_name]
    _mutate_standalone_envelope(
        envelope,
        artifact_name=artifact_name,
        mutation=mutation,
        marker=marker,
    )
    (evidence_dir / artifact_name).write_text(json.dumps(envelope), encoding="utf-8")

    result = run_packaged_consumer_cli("--evidence-dir", str(evidence_dir), str(report))

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "agent-guard evidence bundle invalid\n"
    assert marker not in result.stderr
    assert str(tmp_path) not in result.stderr


@pytest.mark.parametrize(
    ("artifact_name", "artifacts"),
    (
        ("agent-guard-conformance.json", []),
        (
            "agent-guard-conformance.json",
            [
                {"path": "synthetic-report-one.json", "role": "report"},
                {"path": "synthetic-report-two.json", "role": "report"},
            ],
        ),
        ("agent-guard-evidence-pack.json", []),
        (
            "agent-guard-evidence-pack.json",
            [
                {"path": "synthetic-report-one.json", "role": "report"},
                {"path": "synthetic-report-two.json", "role": "report"},
            ],
        ),
    ),
)
def test_packaged_consumer_cli_rejects_standalone_envelopes_without_unique_report_artifact_claim(
    tmp_path: Path,
    artifact_name: str,
    artifacts: list[dict[str, str]],
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    payload, marker = _synthetic_violation_report()
    envelope = _canonical_standalone_envelopes(payload)[artifact_name]
    envelope["policy"] = {"path": "<external-policy>"}
    manifest = payload["evidence_pack_manifest"]
    assert isinstance(manifest, dict)
    manifest["artifacts"] = artifacts
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")
    (evidence_dir / artifact_name).write_text(json.dumps(envelope), encoding="utf-8")

    result = run_packaged_consumer_cli("--evidence-dir", str(evidence_dir), str(report))

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "agent-guard evidence bundle invalid\n"
    assert marker not in result.stderr
    assert "synthetic-report-one.json" not in result.stderr
    assert "synthetic-report-two.json" not in result.stderr
    assert str(tmp_path) not in result.stderr


def test_packaged_consumer_cli_accepts_canonical_rendered_artifacts(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    payload = json.loads(report.read_text(encoding="utf-8"))

    for artifact_name, output_format in (
        ("agent-guard-report.md", "markdown"),
        ("agent-guard-results.sarif", "sarif"),
        ("agent-guard-annotations.txt", "github-annotations"),
    ):
        (evidence_dir / artifact_name).write_text(
            render_report_output(payload, output_format),
            encoding="utf-8",
        )

    result = run_packaged_consumer_cli("--evidence-dir", str(evidence_dir), str(report))

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["status"] == "ok"


def test_packaged_consumer_cli_annotation_mode_is_quiet_when_optional_artifact_is_absent(
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")

    result = run_packaged_consumer_cli(
        "--evidence-dir",
        str(evidence_dir),
        "--emit-annotations",
        str(report),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == ""
    assert result.stderr == ""


@pytest.mark.parametrize("replacement_kind", ("file", "symlink"))
def test_packaged_consumer_cli_emits_buffered_annotations_without_reopening_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary: pytest.CaptureFixture[bytes],
    replacement_kind: str,
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    payload, _ = _synthetic_violation_report()
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")
    for artifact_name, envelope in _canonical_standalone_envelopes(payload).items():
        (evidence_dir / artifact_name).write_text(json.dumps(envelope), encoding="utf-8")
    for artifact_name, output_format in (
        ("agent-guard-report.md", "markdown"),
        ("agent-guard-results.sarif", "sarif"),
    ):
        (evidence_dir / artifact_name).write_text(
            render_report_output(payload, output_format),
            encoding="utf-8",
        )
    annotations_path = evidence_dir / "agent-guard-annotations.txt"
    expected_annotations = render_report_output(payload, "github-annotations").encode("utf-8")
    assert expected_annotations
    annotations_path.write_bytes(expected_annotations)
    injected = b"::error::" + b"sk-" + (b"a" * 24) + b"\n"
    injected_target = tmp_path / "injected-annotations.txt"
    injected_target.write_bytes(injected)
    render = consumer_bundle.render_report_output

    def replace_annotation_after_read(
        report_payload: dict[str, object],
        output_format: str,
    ) -> str:
        rendered = render(report_payload, output_format)
        if output_format == "github-annotations":
            annotations_path.unlink()
            if replacement_kind == "symlink":
                annotations_path.symlink_to(injected_target)
            else:
                annotations_path.write_bytes(injected)
        return rendered

    monkeypatch.setattr(consumer_bundle, "render_report_output", replace_annotation_after_read)

    return_code = packaged_consumer_main(
        [
            "--evidence-dir",
            str(evidence_dir),
            "--emit-annotations",
            str(report),
        ]
    )
    stdout, stderr = capfdbinary.readouterr()

    assert return_code == 0
    assert stdout == expected_annotations
    assert stderr == b""
    assert injected not in stdout


@pytest.mark.parametrize(
    ("artifact_name", "output_format"),
    (
        ("agent-guard-report.md", "markdown"),
        ("agent-guard-results.sarif", "sarif"),
        ("agent-guard-annotations.txt", "github-annotations"),
    ),
)
def test_packaged_consumer_cli_rejects_sanitized_mismatched_rendered_artifacts(
    tmp_path: Path,
    artifact_name: str,
    output_format: str,
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    payload = json.loads(report.read_text(encoding="utf-8"))
    marker = f"synthetic-{output_format}-artifact-mismatch"
    rendered = render_report_output(payload, output_format)

    if output_format == "sarif":
        sarif = json.loads(rendered)
        sarif["runs"][0]["properties"] = {"synthetic_marker": marker}
        rendered = json.dumps(sarif, ensure_ascii=False, sort_keys=True) + "\n"
    else:
        rendered += f"{marker}\n"
    artifact = evidence_dir / artifact_name
    artifact.write_text(rendered, encoding="utf-8")

    result = run_packaged_consumer_cli("--evidence-dir", str(evidence_dir), str(report))

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "agent-guard evidence bundle invalid\n"
    assert marker not in result.stderr
    assert str(artifact) not in result.stderr
    assert str(tmp_path) not in result.stderr


def test_packaged_consumer_cli_sanitizes_bundle_filename_failure(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    sentinel = "sk-" + ("a" * 24) + ".json"
    (evidence_dir / sentinel).write_text("{}", encoding="utf-8")

    result = run_packaged_consumer_cli("--evidence-dir", str(evidence_dir), str(report))

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "agent-guard evidence bundle invalid\n"
    assert sentinel not in result.stderr
    assert str(tmp_path) not in result.stderr


def test_packaged_consumer_cli_sanitizes_oversized_bundle_artifact_failure(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    sentinel = "oversized-artifact-sentinel"
    oversized = sentinel.encode("utf-8") + (b"x" * (MAX_MARKDOWN_BYTES + 1 - len(sentinel)))
    (evidence_dir / "agent-guard-report.md").write_bytes(oversized)

    result = run_packaged_consumer_cli("--evidence-dir", str(evidence_dir), str(report))

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "agent-guard evidence bundle invalid\n"
    assert sentinel not in result.stderr
    assert str(tmp_path) not in result.stderr


def test_packaged_consumer_cli_rejects_unsafe_annotations_without_echoing_them(
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    sentinel = "sk-" + ("a" * 24)
    (evidence_dir / "agent-guard-annotations.txt").write_text(
        f"::error::{sentinel}\n",
        encoding="utf-8",
    )

    result = run_packaged_consumer_cli("--evidence-dir", str(evidence_dir), str(report))

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "agent-guard evidence bundle invalid\n"
    assert sentinel not in result.stderr
    assert str(tmp_path) not in result.stderr


def test_evidence_consumer_example_shim_exports_packaged_main() -> None:
    spec = importlib.util.spec_from_file_location("evidence_consumer_shim", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    spec.loader.exec_module(module)

    assert module.main is packaged_consumer_main


def test_evidence_consumer_accepts_schema_valid_error_report(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "schema_version": "agent-guard.result.v1",
                "tool": {"name": "agent-guard", "version": "0.1.15"},
                "scanner": "context",
                "status": "error",
                "exit_code": 2,
                "policy": {"path": "nonexistent"},
                "summary": {"finding_count": 0},
                "finding_count": 0,
                "findings": [],
                "command": "report",
                "report": {
                    "schema_version": "agent-guard.report_evidence.v1",
                    "format": "json",
                    "scope": "context",
                    "sanitized": True,
                },
                "error": "policy file not found: nonexistent",
            }
        ),
        encoding="utf-8",
    )

    result = run_consumer(report)

    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert payload["finding_count"] == 0
    assert payload["surface_count"] == 0
    assert payload["enabled_gate_count"] == 0


@pytest.mark.parametrize(
    ("status", "exit_code", "expected_error"),
    [
        ("violation", 2, "$.exit_code must be 1 when status is violation"),
        ("error", 1, "$.exit_code must be 2 when status is error"),
    ],
)
def test_evidence_consumer_rejects_mismatched_status_exit_code(
    tmp_path: Path,
    status: str,
    exit_code: int,
    expected_error: str,
) -> None:
    if status == "violation":
        payload, _ = _synthetic_violation_report()
        payload["exit_code"] = exit_code
    else:
        payload = {
            "schema_version": "agent-guard.result.v1",
            "tool": {"name": "agent-guard", "version": "0.3.4"},
            "scanner": "context",
            "status": "error",
            "exit_code": exit_code,
            "policy": {"path": "nonexistent"},
            "summary": {"finding_count": 0},
            "finding_count": 0,
            "findings": [],
            "command": "report",
            "report": {
                "schema_version": "agent-guard.report_evidence.v1",
                "format": "json",
                "scope": "context",
                "sanitized": True,
            },
            "error": "policy file not found",
        }
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    report_only = run_consumer(report)
    bundle = run_packaged_consumer_cli(
        "--evidence-dir",
        str(evidence_dir),
        str(report),
    )

    assert report_only.returncode == 1
    assert expected_error in report_only.stderr
    assert bundle.returncode == 1
    assert bundle.stderr == "agent-guard evidence bundle invalid\n"
    assert str(tmp_path) not in report_only.stderr
    assert str(tmp_path) not in bundle.stderr


def test_packaged_consumer_report_read_failure_does_not_echo_path(tmp_path: Path) -> None:
    missing = tmp_path / "opaque-sensitive-name.json"

    result = run_packaged_consumer_cli(str(missing))

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "agent-guard evidence invalid: public evidence could not be read\n"
    assert missing.name not in result.stderr
    assert str(tmp_path) not in result.stderr


def test_evidence_consumer_fails_closed_on_schema_drift(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["report"]["schema_version"] = "agent-guard.report_evidence.v3"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "report evidence schema version is not supported" in result.stderr


def test_evidence_consumer_rejects_invalid_conformance_profile(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["conformance"]["profile"] = "experimental"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.conformance.profile must be one of" in result.stderr


def test_evidence_consumer_rejects_unsanitized_fragments(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["findings"] = [{"file": "/home/example/private.txt"}]
    payload["finding_count"] = 1
    payload["summary"]["finding_count"] = 1
    del payload["evidence_pack_manifest"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "contains a raw local path" in result.stderr


def test_evidence_consumer_rejects_secret_and_hash_shaped_values(tmp_path: Path) -> None:
    cases = [
        ("short_openai_key_shape", "sk-" + ("a" * 16), "secret-shaped value"),
        ("openai_key", "sk-" + ("a" * 24), "secret-shaped value"),
        ("github_token", "ghp_" + ("a" * 36), "secret-shaped value"),
        ("aws_access_key_id", "AKIA" + ("A" * 16), "secret-shaped value"),
        ("aws_temporary_access_key_id", "ASIA" + ("B" * 16), "secret-shaped value"),
        ("short_slack_token_shape", "xoxb-" + ("a" * 10), "secret-shaped value"),
        ("sha256_value", "a" * 64, "raw sha256-shaped value"),
        ("raw_url", "http" + "s://example.com/private", "raw URL"),
        ("mixed_case_raw_url", "HtTpS://example.com/private", "raw URL"),
        ("raw_url_with_spaces", "https://example.com/private folder/report", "raw URL"),
        ("malformed_raw_url", "HTTPS:/example.com/private", "raw URL"),
        ("opaque_raw_url", "https:example.com/private", "raw URL"),
        ("local_file_uri", "file://localhost/home/example/private", "raw URL"),
        ("wsl_windows_user_path", "/mnt/c/Users/example/private.txt", "raw local path"),
        ("unix_root_path", "/root/synthetic/private.txt", "raw local path"),
        ("generic_posix_path", "/workspace/synthetic/private.txt", "raw local path"),
        ("space_component_posix_path", "/ synthetic/private.txt", "raw local path"),
        ("single_space_component_posix_path", "/ synthetic", "raw local path"),
        ("redirected_posix_path", "2>/home/synthetic/private.txt", "raw local path"),
        ("attached_redirected_posix_path", "command>/home/synthetic/private.txt", "raw local path"),
        ("attached_fd_redirected_posix_path", "command2>/home/synthetic/private.txt", "raw local path"),
        ("attached_combined_redirected_posix_path", "command&>/home/synthetic/private.txt", "raw local path"),
        ("attached_semicolon_redirected_posix_path", "command;2>/home/synthetic/private.txt", "raw local path"),
        ("compact_pipeline_posix_path", "command|/home/synthetic/private.txt", "raw local path"),
        ("compact_or_posix_path", "command||/home/synthetic/private.txt", "raw local path"),
        ("compact_and_posix_path", "command&&/home/synthetic/private.txt", "raw local path"),
        ("embedded_space_component_posix_path", "artifact=/ synthetic", "raw local path"),
        ("labelled_space_component_posix_path", "path: / synthetic", "raw local path"),
        ("closing_delimiter_space_component_posix_path", "source=${prefix}/ synthetic", "raw local path"),
        ("closing_brace_posix_path", "source=${prefix}/home/synthetic/private.txt", "raw local path"),
        ("closing_parenthesis_posix_path", "source=(prefix)/home/synthetic/private.txt", "raw local path"),
        ("closing_bracket_posix_path", "source=[prefix]/home/synthetic/private.txt", "raw local path"),
        ("input_then_output_redirect_posix_path", "command<input >/home/synthetic/private.txt", "raw local path"),
        ("adjacent_input_output_redirect_posix_path", "command<input>/home/synthetic/private.txt", "raw local path"),
        ("tag_prefixed_posix_path", "<img>/home/synthetic/private.txt", "raw local path"),
        ("nested_tag_prefixed_posix_path", "bang!/<img src=x>/home/synthetic/private.txt", "raw local path"),
        ("response_posix_path", "@/workspace/synthetic/private.txt", "raw local path"),
        ("compiler_posix_path", "-I/home/synthetic/include", "raw local path"),
        ("linker_posix_path", "-L/home/synthetic/lib", "raw local path"),
        ("redirected_compiler_posix_path", "command>-I/home/synthetic/include", "raw local path"),
        ("redirected_linker_posix_path", "command>-L/home/synthetic/lib", "raw local path"),
        ("windows_drive_path", r"D:\synthetic\private\report.json", "raw local path"),
        ("compiler_windows_path", r"-ID:\synthetic\include", "raw local path"),
        ("linker_windows_path", r"-LD:\synthetic\lib", "raw local path"),
        ("attached_redirected_windows_path", r"command>D:\synthetic\private\report.json", "raw local path"),
        ("compact_pipeline_windows_path", r"command|D:\synthetic\private\report.json", "raw local path"),
        ("input_then_output_redirect_windows_path", r"command<input >D:\synthetic\private\report.json", "raw local path"),
        ("adjacent_input_output_redirect_windows_path", r"command<input>D:\synthetic\private\report.json", "raw local path"),
        ("tag_prefixed_windows_path", r"<img>D:\synthetic\private\report.json", "raw local path"),
        ("windows_drive_space_path", r"D:\ synthetic\private\report.json", "raw local path"),
        ("windows_unc_path", r"\\synthetic-host\private\report.json", "raw local path"),
        ("redirected_windows_unc_path", r"command>\\synthetic-host\private\report.json", "raw local path"),
        ("closing_brace_windows_path", r"source=${prefix}D:\synthetic\private\report.json", "raw local path"),
        ("colon_prefixed_windows_path", r":note D:\synthetic\private\report.json", "raw local path"),
        ("private_key", "-----BEGIN " + "PRIVATE KEY-----", "secret-shaped value"),
    ]

    for name, value, expected in cases:
        payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
        payload["tool"]["version"] = value
        report = tmp_path / f"{name}.json"
        report.write_text(json.dumps(payload), encoding="utf-8")

        result = run_consumer(report)

        assert result.returncode == 1, name
        assert expected in result.stderr
        assert value not in result.stderr


def test_evidence_consumer_rejects_secret_shaped_keys(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    secret_like_key = "sk-" + ("a" * 24)
    payload[secret_like_key] = "redacted"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "secret-shaped value" in result.stderr
    assert secret_like_key not in result.stderr


def test_evidence_consumer_rejects_nested_secret_shaped_extra_keys_without_leak(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    secret_like_key = "sk-" + ("a" * 24)
    payload["report"][secret_like_key] = "redacted"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.report has 1 extra properties" in result.stderr
    assert secret_like_key not in result.stderr


def test_evidence_consumer_rejects_forbidden_raw_evidence_keys(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["surface_inventory"]["surfaces"][0]["raw_regex"] = "^sk-.+"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "forbidden raw evidence key" in result.stderr
    assert "^sk-.+" not in result.stderr


@pytest.mark.parametrize(
    "field_name",
    [
        "authorization",
        "scope",
        "arguments",
        "environment",
        "APIKey",
        "apiKey",
        "password",
        "secret",
        "authToken",
        "apiToken",
        "bearerToken",
        "idToken",
        "oauthToken",
        "sessionToken",
    ],
)
def test_evidence_consumer_rejects_structurally_sensitive_mcp_fields_without_leak(
    tmp_path: Path,
    field_name: str,
) -> None:
    opaque_value = "opaque-synthetic-credential-value"
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["mcp_config"][field_name] = opaque_value
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    report = evidence_dir / "agent-guard-report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    report_only = run_consumer(report)
    bundle = run_packaged_consumer_cli(
        "--evidence-dir",
        str(evidence_dir),
        str(report),
    )

    assert report_only.returncode == 1
    assert "forbidden raw evidence key" in report_only.stderr
    assert bundle.returncode == 1
    assert bundle.stderr == "agent-guard evidence bundle invalid\n"
    for output in (report_only.stderr, bundle.stderr):
        assert opaque_value not in output
        assert str(tmp_path) not in output


def test_evidence_consumer_allows_benign_token_substrings(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["surface_inventory"]["surfaces"][0]["path"] = "docs/tokenizer.md"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 0, result.stdout + result.stderr


def test_evidence_consumer_rejects_missing_conditional_inventory(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    del payload["inventory"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.inventory is required" in result.stderr


def test_evidence_consumer_rejects_missing_surface_inventory(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    del payload["surface_inventory"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.surface_inventory is required" in result.stderr


def test_evidence_consumer_rejects_missing_evidence_coverage(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    del payload["evidence_coverage"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_coverage is required" in result.stderr


def test_evidence_consumer_accepts_v2_inventory_and_manifest(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["surface_inventory"]["schema_version"] = "agent-guard.agent_surface_inventory.v2"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads(result.stdout)
    assert summary["conformance_status"] == "ok"


def test_evidence_consumer_rejects_inconsistent_conformance_counts(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.conformance.finding_count must match findings length" in result.stderr


def test_evidence_consumer_rejects_ok_conformance_with_findings(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["conformance"]["finding_count"] = 1
    payload["conformance"]["findings"] = [
        {
            "rule_id": "required_gate_missing",
            "severity": "high",
            "requirement_id": "workflow",
            "message": "required evidence gate is missing",
            "reason": "missing_required_gate",
        }
    ]
    payload["evidence_pack_manifest"]["report"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.conformance.finding_count must be 0 when conformance status is ok" in result.stderr


def test_evidence_consumer_rejects_empty_violation_conformance(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["status"] = "violation"
    payload["exit_code"] = 1
    payload["conformance"]["status"] = "violation"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.conformance.finding_count must be non-zero when conformance status is violation" in result.stderr


def test_evidence_consumer_rejects_ok_report_with_violation_conformance(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["conformance"]["status"] = "violation"
    payload["conformance"]["finding_count"] = 1
    payload["conformance"]["findings"] = [
        {
            "rule_id": "required_gate_missing",
            "severity": "high",
            "requirement_id": "workflow",
            "message": "required evidence gate is missing",
            "reason": "missing_required_gate",
        }
    ]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.status must be violation when conformance status is violation" in result.stderr


def test_evidence_consumer_rejects_ok_recommended_conformance_with_external_mcp_policy(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["mcp_config"]["policy"]["path"] = "<external-policy>"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.mcp_config.policy.path must be the reviewed repo MCP policy" in result.stderr


def test_evidence_consumer_rejects_ok_recommended_conformance_with_weakened_mcp_policy(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["mcp_config"]["policy"]["forbidden_risky_patterns"] = ["inline_authorization_value"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.mcp_config.policy.forbidden_risky_patterns must include the default MCP risk labels" in result.stderr


def test_evidence_consumer_summarizes_mcp_policy_conformance_rules(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["status"] = "violation"
    payload["exit_code"] = 1
    payload["mcp_config"]["policy"]["forbidden_risky_patterns"] = ["inline_authorization_value"]
    payload["conformance"]["status"] = "violation"
    payload["conformance"]["finding_count"] = 1
    payload["conformance"]["findings"] = [
        {
            "rule_id": "mcp_policy_weakened",
            "severity": "high",
            "requirement_id": "mcp_config_policy_default_patterns",
            "message": "reviewed MCP policy omits required default risk labels",
            "reason": "missing_default_risky_patterns",
        }
    ]
    payload["evidence_pack_manifest"]["report"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads(result.stdout)
    assert summary["conformance_status"] == "violation"
    assert summary["mcp_policy_conformance_rules"] == ["mcp_policy_weakened"]


def test_evidence_consumer_rejects_untracked_external_mcp_policy_violation(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["status"] = "violation"
    payload["exit_code"] = 1
    payload["mcp_config"]["policy"]["path"] = "<external-policy>"
    payload["conformance"]["status"] = "violation"
    payload["conformance"]["finding_count"] = 1
    payload["conformance"]["findings"] = [
        {
            "rule_id": "required_gate_missing",
            "severity": "high",
            "requirement_id": "workflow",
            "message": "required evidence gate is missing",
            "reason": "missing_required_gate",
        }
    ]
    payload["evidence_pack_manifest"]["report"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "must include required_mcp_policy_not_reviewed" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_evidence_consumer_rejects_untracked_weakened_mcp_policy_violation(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["status"] = "violation"
    payload["exit_code"] = 1
    payload["mcp_config"]["policy"]["forbidden_risky_patterns"] = ["inline_authorization_value"]
    payload["conformance"]["status"] = "violation"
    payload["conformance"]["finding_count"] = 1
    payload["conformance"]["findings"] = [
        {
            "rule_id": "required_gate_missing",
            "severity": "high",
            "requirement_id": "workflow",
            "message": "required evidence gate is missing",
            "reason": "missing_required_gate",
        }
    ]
    payload["evidence_pack_manifest"]["report"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "must include mcp_policy_weakened" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_evidence_consumer_rejects_stale_mcp_policy_weakened_violation(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["status"] = "violation"
    payload["exit_code"] = 1
    payload["conformance"]["status"] = "violation"
    payload["conformance"]["finding_count"] = 1
    payload["conformance"]["findings"] = [
        {
            "rule_id": "mcp_policy_weakened",
            "severity": "high",
            "requirement_id": "mcp_config_policy_default_patterns",
            "message": "reviewed MCP policy omits required default risk labels",
            "reason": "missing_default_risky_patterns",
        }
    ]
    payload["evidence_pack_manifest"]["report"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["status"] = "violation"
    payload["evidence_pack_manifest"]["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "must not report mcp_policy_weakened" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_evidence_consumer_rejects_missing_report_scope(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    del payload["report"]["scope"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.report.scope is required" in result.stderr


def test_evidence_consumer_rejects_extra_report_property(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["report"]["extra"] = "not-in-schema"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.report has 1 extra properties" in result.stderr


def test_evidence_consumer_rejects_inconsistent_evidence_coverage_counts(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_coverage"]["failing_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_coverage.failing_count must match gate statuses" in result.stderr


def test_evidence_consumer_rejects_inconsistent_evidence_pack_manifest_counts(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_pack_manifest"]["summary"]["gate_count"] += 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.summary.gate_count must match gates length" in result.stderr


def test_evidence_consumer_rejects_inconsistent_manifest_gate_status_counts(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_pack_manifest"]["gates"][0]["status"] = "violation"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.summary.failing_gate_count must match gate statuses" in result.stderr


def test_evidence_consumer_rejects_inconsistent_manifest_conformance_summary(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_pack_manifest"]["conformance"]["finding_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.conformance.finding_count must match $.conformance.finding_count" in result.stderr


def test_evidence_consumer_rejects_manifest_report_mismatch(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_pack_manifest"]["report"]["status"] = "violation"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.report.status must match $.status" in result.stderr


def test_evidence_consumer_rejects_manifest_gate_mismatch_with_evidence_coverage(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_pack_manifest"]["gates"] = payload["evidence_pack_manifest"]["gates"][:-1]
    payload["evidence_pack_manifest"]["summary"]["gate_count"] -= 1
    payload["evidence_pack_manifest"]["summary"]["enabled_gate_count"] -= 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.gates must match $.evidence_coverage.gates" in result.stderr


def test_evidence_consumer_rejects_manifest_gate_status_mismatch_without_gate_name_leak(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    secret_like_gate = "sk-" + ("a" * 24)
    payload["evidence_coverage"]["gates"][0]["gate"] = secret_like_gate
    payload["evidence_pack_manifest"]["gates"][0]["gate"] = secret_like_gate
    payload["evidence_pack_manifest"]["gates"][0]["status"] = "violation"
    payload["evidence_pack_manifest"]["summary"]["failing_gate_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.gates[0].status must match $.evidence_coverage.gates" in result.stderr
    assert secret_like_gate not in result.stderr


def test_evidence_consumer_rejects_missing_manifest_conformance_when_report_has_conformance(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    del payload["evidence_pack_manifest"]["conformance"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_pack_manifest.conformance is required when $.conformance is present" in result.stderr


def test_evidence_consumer_rejects_ok_report_with_top_level_findings(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["finding_count"] = 1
    payload["summary"]["finding_count"] = 1
    payload["findings"] = [
        {
            "file": "AGENTS.md",
            "line": 1,
            "rule_id": "approval_bypass",
            "severity": "high",
        }
    ]
    del payload["evidence_pack_manifest"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.finding_count must be 0 when status is ok" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_evidence_consumer_rejects_unexplained_violation_report(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["status"] = "violation"
    payload["exit_code"] = 1
    del payload["evidence_pack_manifest"]
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.status violation must be explained by findings, failing gates, or conformance findings" in result.stderr
    assert str(tmp_path) not in result.stderr


def test_evidence_consumer_rejects_ok_report_with_failing_gate(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["evidence_coverage"]["gates"][0]["status"] = "violation"
    payload["evidence_coverage"]["failing_count"] = 1
    payload["evidence_pack_manifest"]["gates"][0]["status"] = "violation"
    payload["evidence_pack_manifest"]["summary"]["failing_gate_count"] = 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.evidence_coverage.failing_count must be 0 when report status is ok" in result.stderr


def test_evidence_consumer_rejects_inconsistent_surface_count(tmp_path: Path) -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    payload["surface_inventory"]["summary"]["surface_count"] += 1
    report = tmp_path / "report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    result = run_consumer(report)

    assert result.returncode == 1
    assert "$.surface_inventory.summary.surface_count must match surfaces length" in result.stderr
