"""Where: tests/test_schemas.py
What: schema resource contract tests for agent-guard evidence JSON.
Why: keep downstream CI wrappers from depending on undocumented payload shapes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
SCHEMA_DIR = Path(__file__).resolve().parents[1] / "src" / "agent_guard" / "schemas"
EVIDENCE_SAMPLE_REPORT = REPO_ROOT / "docs" / "evidence-samples" / "agent-guard-report.json"
EXPECTED_SCHEMAS = {
    "agent-guard.conformance.v1.schema.json": "agent-guard.conformance.v1",
    "agent-guard.evidence_pack_manifest.v1.schema.json": "agent-guard.evidence_pack_manifest.v1",
    "agent-guard.evidence_pack_manifest.v2.schema.json": "agent-guard.evidence_pack_manifest.v2",
    "agent-guard.result.v1.schema.json": "agent-guard.result.v1",
    "agent-guard.context_inventory.v1.schema.json": "agent-guard.context_inventory.v1",
    "agent-guard.context_lock_coverage.v1.schema.json": "agent-guard.context_lock_coverage.v1",
    "agent-guard.report_evidence.v1.schema.json": "agent-guard.report_evidence.v1",
    "agent-guard.report_evidence.v2.schema.json": "agent-guard.report_evidence.v2",
    "agent-guard.surface_delta.v1.schema.json": "agent-guard.surface_delta.v1",
}


def run_cli(*args: str, cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{SRC}{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else str(SRC)
    return subprocess.run(
        [sys.executable, "-m", "agent_guard.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def load_schema(name: str) -> dict[str, object]:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def validate_payload(schema_name: str, payload: dict[str, object]) -> None:
    schema = load_schema(schema_name)
    validate_against_local_schema(schema, payload, path="$")


def validate_against_local_schema(schema: Mapping[str, object], value: object, *, path: str) -> None:
    schema_type = schema.get("type")
    if schema_type == "object":
        assert isinstance(value, Mapping), f"{path} must be object"
    elif schema_type == "array":
        assert isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)), f"{path} must be array"
    elif schema_type == "string":
        assert isinstance(value, str), f"{path} must be string"
    elif schema_type == "integer":
        assert isinstance(value, int) and not isinstance(value, bool), f"{path} must be integer"
    elif schema_type == "boolean":
        assert isinstance(value, bool), f"{path} must be boolean"

    if "const" in schema:
        assert value == schema["const"], f"{path} must equal {schema['const']!r}"
    if "enum" in schema:
        assert value in schema["enum"], f"{path} must be one of {schema['enum']!r}"

    for condition in schema.get("allOf", []):
        if isinstance(condition, Mapping) and schema_condition_matches(condition.get("if", {}), value):
            then_schema = condition.get("then")
            if isinstance(then_schema, Mapping):
                validate_against_local_schema(then_schema, value, path=path)

    if (schema_type == "object" or "required" in schema or "properties" in schema) and isinstance(value, Mapping):
        for required in schema.get("required", []):
            assert required in value, f"{path}.{required} is required"
        properties = schema.get("properties", {})
        assert isinstance(properties, Mapping)
        additional = schema.get("additionalProperties", True)
        if additional is False:
            extras = set(value) - set(properties)
            assert not extras, f"{path} has extra properties: {sorted(extras)!r}"
        for key, item in value.items():
            child = properties.get(key)
            if isinstance(child, Mapping):
                validate_against_local_schema(child, item, path=f"{path}.{key}")

    if schema_type == "array" and isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                validate_against_local_schema(item_schema, item, path=f"{path}[{index}]")


def schema_condition_matches(schema: object, value: object) -> bool:
    if not isinstance(schema, Mapping) or not isinstance(value, Mapping):
        return False
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        return False
    for key, child in properties.items():
        if key not in value or not isinstance(child, Mapping):
            return False
        if "const" in child and value[key] != child["const"]:
            return False
        if "enum" in child and value[key] not in child["enum"]:
            return False
    return True


def test_expected_schema_resources_are_present_and_parseable() -> None:
    assert {path.name for path in SCHEMA_DIR.glob("*.schema.json")} == set(EXPECTED_SCHEMAS)
    for name in EXPECTED_SCHEMAS:
        schema = load_schema(name)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert str(schema["$id"]).endswith(f"/{name}")
        assert schema["type"] == "object"
        assert isinstance(schema["title"], str)
        assert isinstance(schema.get("required"), list)


def test_schema_versions_are_pinned() -> None:
    for name, schema_version in EXPECTED_SCHEMAS.items():
        schema = load_schema(name)
        properties = schema["properties"]
        if name.startswith("agent-guard.report_evidence."):
            assert properties["schema_version"]["const"] == "agent-guard.result.v1"
            assert properties["report"]["properties"]["schema_version"]["const"] == schema_version
        else:
            assert properties["schema_version"]["const"] == schema_version


def test_context_lock_coverage_schema_requires_covered_evidence() -> None:
    schema = load_schema("agent-guard.context_lock_coverage.v1.schema.json")
    assert "covered" in schema["required"]
    covered = schema["properties"]["covered"]
    assert covered["items"]["required"] == ["path", "kind", "status", "check_id"]
    assert covered["items"]["properties"]["status"]["const"] == "covered"


def test_report_schema_accepts_context_lock_covered_evidence() -> None:
    schema = load_schema("agent-guard.report_evidence.v1.schema.json")
    context_lock = schema["properties"]["context_lock"]
    assert "covered" in context_lock["properties"]
    assert context_lock["properties"]["covered"]["type"] == "array"


def test_report_schema_requires_surface_inventory_and_coverage_on_success() -> None:
    schema = load_schema("agent-guard.report_evidence.v1.schema.json")
    required_on_success = schema["allOf"][0]["then"]["required"]

    assert "inventory" in required_on_success
    assert "surface_inventory" in required_on_success
    assert "evidence_coverage" in required_on_success
    assert schema["properties"]["surface_inventory"]["properties"]["schema_version"]["enum"] == [
        "agent-guard.agent_surface_inventory.v1",
        "agent-guard.agent_surface_inventory.v2",
    ]
    assert schema["properties"]["evidence_coverage"]["properties"]["schema_version"]["const"] == (
        "agent-guard.evidence_coverage.v1"
    )


def test_report_schema_allows_conformance_and_evidence_pack_manifest() -> None:
    schema = load_schema("agent-guard.report_evidence.v1.schema.json")

    assert schema["properties"]["conformance"]["properties"]["schema_version"]["const"] == "agent-guard.conformance.v1"
    assert schema["properties"]["conformance"]["properties"]["profile"]["enum"] == [
        "minimal",
        "recommended",
        "strict",
    ]
    assert schema["properties"]["conformance"]["properties"]["mcp_config_checked_count"]["minimum"] == 0
    assert schema["properties"]["evidence_pack_manifest"]["properties"]["schema_version"]["const"] == (
        "agent-guard.evidence_pack_manifest.v1"
    )
    artifact_role = (
        schema["properties"]["evidence_pack_manifest"]["properties"]["artifacts"]["items"]["properties"]["role"]
    )
    assert artifact_role["enum"] == ["report", "agent-policy-audit-event"]
    artifact = schema["properties"]["evidence_pack_manifest"]["properties"]["artifacts"]["items"]
    assert "content_binding" not in artifact["properties"]


def test_v1_evidence_schemas_accept_released_unbound_audit_event_references() -> None:
    for schema_name in (
        "agent-guard.evidence_pack_manifest.v1.schema.json",
        "agent-guard.report_evidence.v1.schema.json",
    ):
        report = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))
        value = report["evidence_pack_manifest"] if "manifest" in schema_name else report
        manifest = value if "manifest" in schema_name else value["evidence_pack_manifest"]
        manifest["artifacts"].append(
            {
                "path": "reviewed/event.json",
                "role": "agent-policy-audit-event",
            }
        )

        assert Draft202012Validator(load_schema(schema_name)).is_valid(value)


def test_v2_evidence_schemas_require_exact_bound_audit_event_entries() -> None:
    binding = {
        "schema_version": "agent-guard.agent_policy_audit_event_binding.v1",
        "event_profile": "agent-policy.audit_event.v1.1",
        "canonicalization": "canonical-json-v1",
        "digest_algorithm": "sha256",
        "digest_encoding": "base32-lower-no-padding",
        "digest": "b" + ("a" * 52),
    }
    for schema_name in (
        "agent-guard.evidence_pack_manifest.v2.schema.json",
        "agent-guard.report_evidence.v2.schema.json",
    ):
        report = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))
        report["report"]["schema_version"] = "agent-guard.report_evidence.v2"
        report["evidence_pack_manifest"]["schema_version"] = (
            "agent-guard.evidence_pack_manifest.v2"
        )
        value = report["evidence_pack_manifest"] if "manifest" in schema_name else report
        manifest = value if "manifest" in schema_name else value["evidence_pack_manifest"]
        validator = Draft202012Validator(load_schema(schema_name))

        assert not validator.is_valid(value)
        if schema_name == "agent-guard.report_evidence.v2.schema.json":
            without_manifest = dict(value)
            without_manifest.pop("evidence_pack_manifest")
            assert not validator.is_valid(without_manifest)

        manifest["report"]["schema_version"] = "agent-guard.report_evidence.v1"
        assert not validator.is_valid(value)
        manifest["report"]["schema_version"] = "agent-guard.report_evidence.v2"

        manifest["artifacts"][0]["review_metadata"] = "synthetic-public-metadata"
        assert not validator.is_valid(value)

        manifest["artifacts"].append(
            {
                "path": "reviewed/event.json",
                "role": "agent-policy-audit-event",
            }
        )
        assert not validator.is_valid(value)
        manifest["artifacts"].pop()

        manifest["artifacts"].append(
            {
                "path": "reviewed/event.json",
                "role": "agent-policy-audit-event",
                "content_binding": binding,
            }
        )
        assert validator.is_valid(value)

        manifest["artifacts"][-1]["event_body"] = {
            "passphrase": "synthetic-private-passphrase"
        }
        assert not validator.is_valid(value)

        manifest["artifacts"][-1] = {
            "path": "reviewed/event.json",
            "role": "agent-policy-audit-event",
            "content_binding": binding | {
                "schema_version": "agent-guard.agent_policy_audit_event_binding.v2"
            },
        }
        assert not validator.is_valid(value)


def test_surface_delta_schema_requires_details_only_when_base_resolves() -> None:
    unresolved = {
        "schema_version": "agent-guard.surface_delta.v1",
        "base_resolved": False,
    }
    resolved_without_details = {
        "schema_version": "agent-guard.surface_delta.v1",
        "base_resolved": True,
    }

    validate_payload("agent-guard.surface_delta.v1.schema.json", unresolved)
    with pytest.raises(AssertionError, match=r"\$\.summary is required"):
        validate_payload("agent-guard.surface_delta.v1.schema.json", resolved_without_details)


def test_surface_delta_schema_pins_public_vocabularies() -> None:
    schema = load_schema("agent-guard.surface_delta.v1.schema.json")
    entry = schema["properties"]["entries"]["items"]

    assert schema["additionalProperties"] is False
    assert entry["additionalProperties"] is False
    assert entry["properties"]["changed_fields"]["items"]["enum"] == [
        "artifact_path",
        "command",
        "command_basename",
        "content",
        "env_vars",
        "file_count",
        "filesystem_root",
        "job_id",
        "kind",
        "line_count",
        "package_manager",
        "remote_host",
        "risky_patterns",
        "size_bytes",
        "status",
        "transport",
        "truncated",
        "version_pinned",
    ]
    assert entry["properties"]["risk_labels"]["items"]["enum"] == [
        "broad_authorization_scope",
        "filesystem_root_reference",
        "inline_authorization_value",
        "inline_env_value",
        "instruction_like_description",
        "latest_package",
        "secret_shaped_inline_value",
        "unsafe_url_scheme",
        "unpinned_package",
    ]


def test_report_schema_embeds_surface_delta_contract() -> None:
    report_schema = load_schema("agent-guard.report_evidence.v1.schema.json")
    delta_schema = load_schema("agent-guard.surface_delta.v1.schema.json")
    embedded = report_schema["properties"]["surface_delta"]
    standalone_contract = {
        key: value
        for key, value in delta_schema.items()
        if key not in {"$schema", "$id", "title"}
    }

    assert embedded == standalone_contract


def test_surface_delta_schema_validates_unresolved_report_section(tmp_path: Path) -> None:
    subprocess.run(
        ["git", "init", "--quiet"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    write(tmp_path / "context_policy.yaml", "{}\n")
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        "context_policy.yaml",
        "--surface-delta-base-ref",
        "refs/does-not-exist",
        "--format",
        "json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["surface_delta"]["base_resolved"] is False
    validate_payload("agent-guard.surface_delta.v1.schema.json", payload["surface_delta"])


def test_report_schema_validates_success_cli_payload(tmp_path: Path) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(policy),
        "--format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    validate_payload("agent-guard.report_evidence.v1.schema.json", payload)

    payload["surface_delta"] = {
        "schema_version": "agent-guard.surface_delta.v1",
        "base_resolved": True,
    }
    with pytest.raises(AssertionError, match=r"\$\.surface_delta\.summary is required"):
        validate_payload("agent-guard.report_evidence.v1.schema.json", payload)


def test_report_schema_validates_v2_report_cli_payload(tmp_path: Path) -> None:
    policy = tmp_path / ".agent-guard" / "context-policy.yaml"
    write(policy, "{}\n")
    write(
        tmp_path / ".agent-guard" / "workflow-policy.yaml",
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - id: context_policy\n"
        "    path: .agent-guard/context-policy.yaml\n",
    )
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(policy),
        "--surface-inventory-version",
        "v2",
        "--conformance-profile",
        "minimal",
        "--evidence-pack-manifest",
        "--format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["surface_inventory"]["schema_version"] == "agent-guard.agent_surface_inventory.v2"
    assert payload["conformance"]["schema_version"] == "agent-guard.conformance.v1"
    assert payload["evidence_pack_manifest"]["schema_version"] == "agent-guard.evidence_pack_manifest.v1"
    validate_payload("agent-guard.report_evidence.v1.schema.json", payload)


def test_report_schema_validates_error_cli_payload(tmp_path: Path) -> None:
    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(tmp_path / "missing.yaml"),
        "--format",
        "json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert "inventory" not in payload
    validate_payload("agent-guard.report_evidence.v1.schema.json", payload)


def test_report_schema_validates_mcp_enabled_error_cli_payload(tmp_path: Path) -> None:
    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(tmp_path / "missing.yaml"),
        "--mcp-config-check",
        "--format",
        "json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert "mcp_config" not in payload
    validate_payload("agent-guard.report_evidence.v1.schema.json", payload)


def test_public_sample_report_matches_schema_and_is_sanitized() -> None:
    payload = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))

    validate_payload("agent-guard.report_evidence.v1.schema.json", payload)
    assert payload["conformance"]["profile"] == "recommended"
    assert payload["conformance"]["status"] == "ok"
    gates = {item["gate"]: item["status"] for item in payload["evidence_coverage"]["gates"]}
    for gate in ("context", "surface_inventory", "path", "content", "workflow", "policy_spec_drift"):
        assert gates[gate] == "ok"
    serialized = json.dumps(payload, sort_keys=True)
    forbidden_fragments = (
        "/home/",
        "/Users/",
        "C:\\Users\\",
        "snippet",
        "matched_text",
        "raw_regex",
        "sha256",
        "token",
    )
    for fragment in forbidden_fragments:
        assert fragment not in serialized
