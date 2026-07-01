"""Where: examples/evidence_consumer.py
What: minimal downstream consumer for sanitized agent-guard report evidence.
Why: show wrappers how to load packaged schemas and fail closed on drift without
     adding runtime dependencies to agent-guard itself.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from importlib import resources
import json
import re
import sys
from pathlib import Path
from typing import Any


REPORT_SCHEMA = "agent-guard.report_evidence.v1.schema.json"
REVIEWED_MCP_POLICY_PATH = ".agent-guard/mcp-policy.yaml"
REQUIRED_MCP_RISK_LABELS = frozenset(
    {
        "broad_authorization_scope",
        "filesystem_root_reference",
        "inline_authorization_value",
        "inline_env_value",
        "latest_package",
        "secret_shaped_inline_value",
        "unpinned_package",
        "unsafe_url_scheme",
    }
)
MCP_POLICY_CONFORMANCE_RULES = frozenset({"required_mcp_policy_not_reviewed", "mcp_policy_weakened"})
FORBIDDEN_PUBLIC_KEYS = frozenset({"matched_text", "raw_regex", "snippet"})
LOCAL_PATH_RE = re.compile(r"(?:^|[\s\"'=:])(?:/(?:home|Users)/|[A-Za-z]:[\\/]+Users[\\/]+)")
RAW_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
SHA256_VALUE_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
SECRET_VALUE_RE = re.compile(
    r"(?:"
    r"sk-[A-Za-z0-9_-]{20,}"
    r"|gh[pousr]_[A-Za-z0-9_]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{20,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r")"
)


def load_report_schema() -> dict[str, Any]:
    schema_path = resources.files("agent_guard.schemas").joinpath(REPORT_SCHEMA)
    return json.loads(schema_path.read_text(encoding="utf-8"))


def load_payload(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("report payload must be a JSON object")
    return payload


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def schema_condition_matches(schema: Any, value: Any) -> bool:
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


def validate_against_schema(schema: Mapping[str, Any], value: Any, *, path: str) -> None:
    schema_type = schema.get("type")
    allowed_types = schema_type if isinstance(schema_type, list) else [schema_type]
    if schema_type is not None:
        require(any(value_has_json_type(value, item) for item in allowed_types), f"{path} has wrong type")

    if "const" in schema:
        require(value == schema["const"], f"{path} must equal {schema['const']!r}")
    if "enum" in schema:
        require(value in schema["enum"], f"{path} must be one of {schema['enum']!r}")
    if "minimum" in schema and isinstance(value, (int, float)) and not isinstance(value, bool):
        require(value >= schema["minimum"], f"{path} must be >= {schema['minimum']!r}")

    for condition in schema.get("allOf", []):
        if isinstance(condition, Mapping) and schema_condition_matches(condition.get("if", {}), value):
            then_schema = condition.get("then")
            if isinstance(then_schema, Mapping):
                validate_against_schema(then_schema, value, path=path)

    if (schema_type == "object" or "required" in schema or "properties" in schema) and isinstance(value, Mapping):
        for required in schema.get("required", []):
            require(required in value, f"{path}.{required} is required")
        properties = schema.get("properties", {})
        require(isinstance(properties, Mapping), f"{path}.properties must be an object")
        if schema.get("additionalProperties", True) is False:
            extras = set(value) - set(properties)
            require(not extras, f"{path} has {len(extras)} extra properties")
        for key, item in value.items():
            child = properties.get(key)
            if isinstance(child, Mapping):
                validate_against_schema(child, item, path=f"{path}.{key}")

    if schema_type == "array" and isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                validate_against_schema(item_schema, item, path=f"{path}[{index}]")


def value_has_json_type(value: Any, schema_type: Any) -> bool:
    if schema_type == "object":
        return isinstance(value, Mapping)
    if schema_type == "array":
        return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))
    if schema_type == "string":
        return isinstance(value, str)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "boolean":
        return isinstance(value, bool)
    if schema_type == "null":
        return value is None
    return True


def require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    require(isinstance(value, Mapping), f"{path} must be an object")
    return value


def require_sequence(value: Any, path: str) -> Sequence[Any]:
    require(
        isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)),
        f"{path} must be an array",
    )
    return value


def require_int(value: Any, path: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{path} must be an integer")
    require(value >= 0, f"{path} must be >= 0")
    return value


def validate_gate_counts(evidence_coverage: Mapping[str, Any], *, report_status: str) -> None:
    gates = require_sequence(evidence_coverage.get("gates"), "$.evidence_coverage.gates")
    gate_count = require_int(evidence_coverage.get("gate_count"), "$.evidence_coverage.gate_count")
    enabled_count = require_int(evidence_coverage.get("enabled_count"), "$.evidence_coverage.enabled_count")
    missing_count = require_int(evidence_coverage.get("missing_count"), "$.evidence_coverage.missing_count")
    failing_count = require_int(evidence_coverage.get("failing_count"), "$.evidence_coverage.failing_count")

    require(gate_count == len(gates), "$.evidence_coverage.gate_count must match gates length")
    enabled = 0
    missing = 0
    failing = 0
    names: set[str] = set()
    for index, raw_gate in enumerate(gates):
        gate = require_mapping(raw_gate, f"$.evidence_coverage.gates[{index}]")
        name = str(gate.get("gate", "")).strip()
        require(name, f"$.evidence_coverage.gates[{index}].gate is required")
        require(name not in names, f"$.evidence_coverage.gates[{index}].gate must be unique")
        names.add(name)
        status = str(gate.get("status", ""))
        require(status in {"ok", "violation", "missing", "error"}, f"$.evidence_coverage.gates[{index}].status is invalid")
        require_int(gate.get("checked_count"), f"$.evidence_coverage.gates[{index}].checked_count")
        require_int(gate.get("finding_count"), f"$.evidence_coverage.gates[{index}].finding_count")
        if status == "missing":
            missing += 1
        else:
            enabled += 1
        if status not in {"ok", "missing"}:
            failing += 1

    require(enabled_count == enabled, "$.evidence_coverage.enabled_count must match gate statuses")
    require(missing_count == missing, "$.evidence_coverage.missing_count must match gate statuses")
    require(failing_count == failing, "$.evidence_coverage.failing_count must match gate statuses")
    if report_status == "ok":
        require(failing_count == 0, "$.evidence_coverage.failing_count must be 0 when report status is ok")


def validate_surface_inventory(surface_inventory: Mapping[str, Any]) -> None:
    surfaces = require_sequence(surface_inventory.get("surfaces"), "$.surface_inventory.surfaces")
    summary = require_mapping(surface_inventory.get("summary"), "$.surface_inventory.summary")
    surface_count = summary.get("surface_count")
    if surface_count is not None:
        require_int(surface_count, "$.surface_inventory.summary.surface_count")
        require(surface_count == len(surfaces), "$.surface_inventory.summary.surface_count must match surfaces length")
    for index, raw_surface in enumerate(surfaces):
        surface = require_mapping(raw_surface, f"$.surface_inventory.surfaces[{index}]")
        for key in ("surface", "path", "kind", "status"):
            require(isinstance(surface.get(key), str), f"$.surface_inventory.surfaces[{index}].{key} must be a string")
        raw_patterns = surface.get("risky_patterns")
        if raw_patterns is not None:
            patterns = require_sequence(raw_patterns, f"$.surface_inventory.surfaces[{index}].risky_patterns")
            require(
                all(isinstance(pattern, str) and pattern for pattern in patterns),
                f"$.surface_inventory.surfaces[{index}].risky_patterns must contain non-empty strings",
            )


def validate_conformance(conformance: Mapping[str, Any], payload: Mapping[str, Any]) -> set[str]:
    findings = require_sequence(conformance.get("findings"), "$.conformance.findings")
    finding_count = require_int(conformance.get("finding_count"), "$.conformance.finding_count")
    require(finding_count == len(findings), "$.conformance.finding_count must match findings length")

    status = str(conformance.get("status", ""))
    require(status in {"ok", "violation"}, "$.conformance.status is invalid")
    if status == "ok":
        require(finding_count == 0, "$.conformance.finding_count must be 0 when conformance status is ok")
    if status == "violation":
        require(finding_count > 0, "$.conformance.finding_count must be non-zero when conformance status is violation")

    tracked_rule_ids: set[str] = set()
    for index, raw_finding in enumerate(findings):
        finding = require_mapping(raw_finding, f"$.conformance.findings[{index}]")
        for key in ("rule_id", "severity", "requirement_id", "message", "reason"):
            require(
                isinstance(finding.get(key), str) and bool(str(finding.get(key)).strip()),
                f"$.conformance.findings[{index}].{key} must be a non-empty string",
            )
        rule_id = str(finding.get("rule_id", "")).strip()
        if rule_id in MCP_POLICY_CONFORMANCE_RULES:
            tracked_rule_ids.add(rule_id)

    profile = str(conformance.get("profile", ""))
    if status == "ok" and profile in {"recommended", "strict"}:
        mcp_config = require_mapping(payload.get("mcp_config"), "$.mcp_config")
        policy = require_mapping(mcp_config.get("policy"), "$.mcp_config.policy")
        require(
            policy.get("path") == REVIEWED_MCP_POLICY_PATH,
            "$.mcp_config.policy.path must be the reviewed repo MCP policy when conformance is ok",
        )
        raw_patterns = require_sequence(
            policy.get("forbidden_risky_patterns"),
            "$.mcp_config.policy.forbidden_risky_patterns",
        )
        pattern_set = {str(value).strip() for value in raw_patterns if isinstance(value, str) and str(value).strip()}
        missing = sorted(REQUIRED_MCP_RISK_LABELS - pattern_set)
        require(
            not missing,
            "$.mcp_config.policy.forbidden_risky_patterns must include the default MCP risk labels",
        )

    return tracked_rule_ids


def validate_evidence_pack_manifest(manifest: Mapping[str, Any], payload: Mapping[str, Any]) -> None:
    manifest_report = require_mapping(manifest.get("report"), "$.evidence_pack_manifest.report")
    report = require_mapping(payload.get("report"), "$.report")
    for key in ("schema_version", "format", "scope"):
        require(
            manifest_report.get(key) == report.get(key),
            f"$.evidence_pack_manifest.report.{key} must match $.report.{key}",
        )
    require(
        manifest_report.get("status") == payload.get("status"),
        "$.evidence_pack_manifest.report.status must match $.status",
    )
    require(
        manifest_report.get("finding_count") == payload.get("finding_count"),
        "$.evidence_pack_manifest.report.finding_count must match $.finding_count",
    )

    summary = require_mapping(manifest.get("summary"), "$.evidence_pack_manifest.summary")
    gates = require_sequence(manifest.get("gates"), "$.evidence_pack_manifest.gates")
    gate_count = require_int(summary.get("gate_count"), "$.evidence_pack_manifest.summary.gate_count")
    enabled_count = require_int(
        summary.get("enabled_gate_count"),
        "$.evidence_pack_manifest.summary.enabled_gate_count",
    )
    missing_count = require_int(
        summary.get("missing_gate_count"),
        "$.evidence_pack_manifest.summary.missing_gate_count",
    )
    failing_count = require_int(
        summary.get("failing_gate_count"),
        "$.evidence_pack_manifest.summary.failing_gate_count",
    )

    require(gate_count == len(gates), "$.evidence_pack_manifest.summary.gate_count must match gates length")
    enabled = 0
    missing = 0
    failing = 0
    names: set[str] = set()
    manifest_gates: dict[str, Mapping[str, Any]] = {}
    for index, raw_gate in enumerate(gates):
        gate = require_mapping(raw_gate, f"$.evidence_pack_manifest.gates[{index}]")
        name = str(gate.get("gate", "")).strip()
        require(name, f"$.evidence_pack_manifest.gates[{index}].gate is required")
        require(name not in names, f"$.evidence_pack_manifest.gates[{index}].gate must be unique")
        names.add(name)
        manifest_gates[name] = gate
        status = str(gate.get("status", ""))
        require(
            status in {"ok", "violation", "missing", "error"},
            f"$.evidence_pack_manifest.gates[{index}].status is invalid",
        )
        require_int(gate.get("finding_count"), f"$.evidence_pack_manifest.gates[{index}].finding_count")
        if status == "missing":
            missing += 1
        else:
            enabled += 1
        if status not in {"ok", "missing"}:
            failing += 1

    require(enabled_count == enabled, "$.evidence_pack_manifest.summary.enabled_gate_count must match gate statuses")
    require(missing_count == missing, "$.evidence_pack_manifest.summary.missing_gate_count must match gate statuses")
    require(failing_count == failing, "$.evidence_pack_manifest.summary.failing_gate_count must match gate statuses")

    evidence_coverage = require_mapping(payload.get("evidence_coverage"), "$.evidence_coverage")
    evidence_gates = require_sequence(evidence_coverage.get("gates"), "$.evidence_coverage.gates")
    coverage_gates: dict[str, Mapping[str, Any]] = {}
    for index, raw_gate in enumerate(evidence_gates):
        gate = require_mapping(raw_gate, f"$.evidence_coverage.gates[{index}]")
        name = str(gate.get("gate", "")).strip()
        if name:
            coverage_gates[name] = gate
    require(
        set(manifest_gates) == set(coverage_gates),
        "$.evidence_pack_manifest.gates must match $.evidence_coverage.gates",
    )
    for index, (gate_name, manifest_gate) in enumerate(manifest_gates.items()):
        coverage_gate = coverage_gates[gate_name]
        for key in ("status", "finding_count"):
            require(
                manifest_gate.get(key) == coverage_gate.get(key),
                f"$.evidence_pack_manifest.gates[{index}].{key} must match $.evidence_coverage.gates",
            )

    conformance = manifest.get("conformance")
    payload_conformance = payload.get("conformance")
    require(
        not (payload_conformance is not None and conformance is None),
        "$.evidence_pack_manifest.conformance is required when $.conformance is present",
    )
    if conformance is not None:
        conformance_obj = require_mapping(conformance, "$.evidence_pack_manifest.conformance")
        payload_conformance_obj = require_mapping(payload_conformance, "$.conformance")
        for key in ("schema_version", "profile", "status", "finding_count"):
            require(
                conformance_obj.get(key) == payload_conformance_obj.get(key),
                f"$.evidence_pack_manifest.conformance.{key} must match $.conformance.{key}",
            )
        finding_count = require_int(
            conformance_obj.get("finding_count"),
            "$.evidence_pack_manifest.conformance.finding_count",
        )
        status = str(conformance_obj.get("status", ""))
        require(status in {"ok", "violation"}, "$.evidence_pack_manifest.conformance.status is invalid")
        if status == "ok":
            require(
                finding_count == 0,
                "$.evidence_pack_manifest.conformance.finding_count must be 0 when status is ok",
            )
        if status == "violation":
            require(
                finding_count > 0,
                "$.evidence_pack_manifest.conformance.finding_count must be non-zero when status is violation",
            )


def validate_public_text_shape(text: str, *, path: str) -> None:
    require(not LOCAL_PATH_RE.search(text), f"{path} contains a raw local path")
    require(not RAW_URL_RE.search(text), f"{path} contains a raw URL")
    require(not SHA256_VALUE_RE.search(text), f"{path} contains a raw sha256-shaped value")
    require(not SECRET_VALUE_RE.search(text), f"{path} contains a secret-shaped value")


def validate_public_evidence_shape(value: Any, *, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for index, (key, item) in enumerate(value.items()):
            key_text = str(key)
            key_path = f"{path}.keys[{index}]"
            child_path = f"{path}.values[{index}]"
            require(key_text not in FORBIDDEN_PUBLIC_KEYS, f"{key_path} is a forbidden raw evidence key")
            validate_public_text_shape(key_text, path=key_path)
            validate_public_evidence_shape(item, path=child_path)
        return

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            validate_public_evidence_shape(item, path=f"{path}[{index}]")
        return

    if not isinstance(value, str):
        return

    validate_public_text_shape(value, path=path)


def validate_public_report_consistency(payload: Mapping[str, Any]) -> None:
    status = str(payload.get("status", ""))
    exit_code = payload.get("exit_code")
    if status == "ok":
        require(exit_code == 0, "$.exit_code must be 0 when status is ok")
    if status == "violation":
        require(isinstance(exit_code, int) and exit_code != 0, "$.exit_code must be non-zero when status is violation")
    if status == "error":
        require(isinstance(exit_code, int) and exit_code != 0, "$.exit_code must be non-zero when status is error")
        error = payload.get("error")
        require(isinstance(error, str) and bool(error.strip()), "$.error must be a non-empty string when status is error")

    findings = require_sequence(payload.get("findings"), "$.findings")
    finding_count = require_int(payload.get("finding_count"), "$.finding_count")
    require(finding_count == len(findings), "$.finding_count must match findings length")
    summary = require_mapping(payload.get("summary"), "$.summary")
    require(summary.get("finding_count") == finding_count, "$.summary.finding_count must match finding_count")

    if status == "error":
        return

    surface_inventory = require_mapping(payload.get("surface_inventory"), "$.surface_inventory")
    validate_surface_inventory(surface_inventory)
    evidence_coverage = require_mapping(payload.get("evidence_coverage"), "$.evidence_coverage")
    validate_gate_counts(evidence_coverage, report_status=status)

    drift = payload.get("policy_spec_drift")
    if isinstance(drift, Mapping):
        baseline = drift.get("baseline_trust")
        if baseline is not None:
            baseline_obj = require_mapping(baseline, "$.policy_spec_drift.baseline_trust")
            require(
                baseline_obj.get("status") in {"ok", "review_required", "unproven"},
                "$.policy_spec_drift.baseline_trust.status is invalid",
            )


def validate_report(payload: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    validate_against_schema(schema, payload, path="$")

    required = schema.get("required", [])
    require(isinstance(required, list), "schema.required must be a list")
    for key in required:
        require(key in payload, f"missing required field: {key}")

    properties = schema["properties"]
    require(payload["schema_version"] == properties["schema_version"]["const"], "schema_version mismatch")
    require(payload["scanner"] == properties["scanner"]["const"], "scanner mismatch")
    require(payload["command"] == properties["command"]["const"], "command mismatch")
    require(payload["status"] in properties["status"]["enum"], "status is not allowed")
    require(isinstance(payload["finding_count"], int), "finding_count must be an integer")
    require(isinstance(payload["findings"], list), "findings must be an array")
    status = str(payload["status"])

    report = payload.get("report")
    require(isinstance(report, dict), "report must be an object")
    report_properties = properties["report"]["properties"]
    require(
        report.get("schema_version") == report_properties["schema_version"]["const"],
        "report.schema_version mismatch",
    )
    require(report.get("format") in report_properties["format"]["enum"], "report.format is not allowed")
    require(report.get("sanitized") is True, "report.sanitized must be true")

    surfaces: Sequence[Any] = []
    evidence_coverage: Mapping[str, Any] = {}
    if status in {"ok", "violation"}:
        surface_inventory = payload.get("surface_inventory")
        require(isinstance(surface_inventory, dict), "surface_inventory must be an object")
        surface_schema = properties["surface_inventory"]["properties"]["schema_version"]
        require(
            surface_inventory.get("schema_version") in surface_schema["enum"],
            "surface_inventory.schema_version mismatch",
        )
        raw_surfaces = surface_inventory.get("surfaces")
        require(isinstance(raw_surfaces, list), "surface_inventory.surfaces must be an array")
        surfaces = raw_surfaces

        raw_evidence_coverage = payload.get("evidence_coverage")
        require(isinstance(raw_evidence_coverage, dict), "evidence_coverage must be an object")
        require(
            raw_evidence_coverage.get("schema_version") == "agent-guard.evidence_coverage.v1",
            "evidence_coverage.schema_version mismatch",
        )
        gates = raw_evidence_coverage.get("gates")
        require(isinstance(gates, list), "evidence_coverage.gates must be an array")
        evidence_coverage = raw_evidence_coverage

    conformance = payload.get("conformance")
    tracked_conformance_rules: set[str] = set()
    if conformance is not None:
        require(isinstance(conformance, dict), "conformance must be an object")
        require(conformance.get("schema_version") == "agent-guard.conformance.v1", "conformance.schema_version mismatch")
        tracked_conformance_rules = validate_conformance(conformance, payload)
        if conformance.get("status") == "violation":
            require(status == "violation", "$.status must be violation when conformance status is violation")

    manifest = payload.get("evidence_pack_manifest")
    if manifest is not None:
        require(isinstance(manifest, dict), "evidence_pack_manifest must be an object")
        require(
            manifest.get("schema_version") == "agent-guard.evidence_pack_manifest.v1",
            "evidence_pack_manifest.schema_version mismatch",
        )
        require(manifest.get("sanitized") is True, "evidence_pack_manifest.sanitized must be true")
        validate_evidence_pack_manifest(manifest, payload)

    validate_public_report_consistency(payload)

    validate_public_evidence_shape(payload)

    return {
        "schema_version": payload["schema_version"],
        "report_schema_version": report["schema_version"],
        "status": payload["status"],
        "finding_count": payload["finding_count"],
        "surface_count": len(surfaces),
        "enabled_gate_count": evidence_coverage.get("enabled_count", 0),
        "missing_gate_count": evidence_coverage.get("missing_count", 0),
        **({"conformance_status": conformance.get("status")} if isinstance(conformance, dict) else {}),
        **({"mcp_policy_conformance_rules": sorted(tracked_conformance_rules)} if tracked_conformance_rules else {}),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a sanitized agent-guard report JSON file.")
    parser.add_argument("report", type=Path, help="Path to agent-guard report JSON")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        summary = validate_report(load_payload(args.report), load_report_schema())
    except Exception as exc:
        print(f"agent-guard evidence invalid: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
