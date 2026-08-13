"""Where: src/agent_guard/consumer/_report.py
What: top-level sanitized report validator and summary builder.
Why: provide a stable packaged evidence-consumer API for downstream wrappers.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ._redaction import validate_public_evidence_shape
from ._schema import require, validate_against_schema
from ._sections import (
    validate_conformance,
    validate_evidence_pack_manifest,
    validate_public_report_consistency,
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
    require(report.get("schema_version") == report_properties["schema_version"]["const"], "report.schema_version mismatch")
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
        manifest_properties = properties["evidence_pack_manifest"]["properties"]
        require(
            manifest.get("schema_version") == manifest_properties["schema_version"]["const"],
            "evidence_pack_manifest.schema_version mismatch",
        )
        require(manifest.get("sanitized") is True, "evidence_pack_manifest.sanitized must be true")
        validate_evidence_pack_manifest(manifest, payload)

    validate_public_evidence_shape(payload)
    validate_public_report_consistency(payload)

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
