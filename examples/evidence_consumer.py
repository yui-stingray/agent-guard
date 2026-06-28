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
import sys
from pathlib import Path
from typing import Any


REPORT_SCHEMA = "agent-guard.report_evidence.v1.schema.json"
FORBIDDEN_FRAGMENTS = (
    "/home/",
    "/Users/",
    "C:\\Users\\",
    "snippet",
    "matched_text",
    "raw_regex",
    "sha256",
    "token",
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
            require(not extras, f"{path} has extra properties: {sorted(extras)!r}")
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

    report = payload.get("report")
    require(isinstance(report, dict), "report must be an object")
    report_properties = properties["report"]["properties"]
    require(
        report.get("schema_version") == report_properties["schema_version"]["const"],
        "report.schema_version mismatch",
    )
    require(report.get("format") in report_properties["format"]["enum"], "report.format is not allowed")
    require(report.get("sanitized") is True, "report.sanitized must be true")

    surface_inventory = payload.get("surface_inventory")
    require(isinstance(surface_inventory, dict), "surface_inventory must be an object")
    surface_schema = properties["surface_inventory"]["properties"]["schema_version"]
    require(
        surface_inventory.get("schema_version") in surface_schema["enum"],
        "surface_inventory.schema_version mismatch",
    )
    surfaces = surface_inventory.get("surfaces")
    require(isinstance(surfaces, list), "surface_inventory.surfaces must be an array")

    evidence_coverage = payload.get("evidence_coverage")
    require(isinstance(evidence_coverage, dict), "evidence_coverage must be an object")
    require(
        evidence_coverage.get("schema_version") == "agent-guard.evidence_coverage.v1",
        "evidence_coverage.schema_version mismatch",
    )
    gates = evidence_coverage.get("gates")
    require(isinstance(gates, list), "evidence_coverage.gates must be an array")

    conformance = payload.get("conformance")
    if conformance is not None:
        require(isinstance(conformance, dict), "conformance must be an object")
        require(conformance.get("schema_version") == "agent-guard.conformance.v1", "conformance.schema_version mismatch")

    manifest = payload.get("evidence_pack_manifest")
    if manifest is not None:
        require(isinstance(manifest, dict), "evidence_pack_manifest must be an object")
        require(
            manifest.get("schema_version") == "agent-guard.evidence_pack_manifest.v1",
            "evidence_pack_manifest.schema_version mismatch",
        )
        require(manifest.get("sanitized") is True, "evidence_pack_manifest.sanitized must be true")

    serialized = json.dumps(payload, sort_keys=True)
    for fragment in FORBIDDEN_FRAGMENTS:
        require(fragment not in serialized, f"forbidden public-evidence fragment found: {fragment}")

    return {
        "schema_version": payload["schema_version"],
        "report_schema_version": report["schema_version"],
        "status": payload["status"],
        "finding_count": payload["finding_count"],
        "surface_count": len(surfaces),
        "enabled_gate_count": evidence_coverage.get("enabled_count", 0),
        "missing_gate_count": evidence_coverage.get("missing_count", 0),
        **({"conformance_status": conformance.get("status")} if isinstance(conformance, dict) else {}),
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
