"""Where: src/agent_guard/consumer/_sections.py
What: cross-section consistency checks for sanitized report evidence.
Why: packaged consumers need stronger invariants than schema shape alone provides.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..evidence_pack import validate_agent_policy_audit_event_binding_shape
from ._schema import require, require_int, require_mapping, require_sequence

REVIEWED_MCP_POLICY_PATH = ".agent-guard/mcp-policy.yaml"
REQUIRED_MCP_RISK_LABELS = frozenset(
    {
        "broad_authorization_scope",
        "filesystem_root_reference",
        "inline_authorization_value",
        "inline_env_value",
        "instruction_like_description",
        "latest_package",
        "secret_shaped_inline_value",
        "unpinned_package",
        "unsafe_url_scheme",
    }
)
MCP_POLICY_CONFORMANCE_RULES = frozenset({"required_mcp_policy_not_reviewed", "mcp_policy_weakened"})
EVIDENCE_PACK_SCHEMA_VERSIONS = frozenset(
    {
        "agent-guard.evidence_pack_manifest.v1",
        "agent-guard.evidence_pack_manifest.v2",
    }
)


def validate_gate_counts(evidence_coverage: Mapping[str, Any], *, report_status: str) -> None:
    gates = require_sequence(evidence_coverage.get("gates"), "$.evidence_coverage.gates")
    gate_count = require_int(evidence_coverage.get("gate_count"), "$.evidence_coverage.gate_count")
    enabled_count = require_int(evidence_coverage.get("enabled_count"), "$.evidence_coverage.enabled_count")
    missing_count = require_int(evidence_coverage.get("missing_count"), "$.evidence_coverage.missing_count")
    failing_count = require_int(evidence_coverage.get("failing_count"), "$.evidence_coverage.failing_count")

    require(gate_count == len(gates), "$.evidence_coverage.gate_count must match gates length")
    enabled = missing = failing = 0
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
        missing += int(status == "missing")
        enabled += int(status != "missing")
        failing += int(status not in {"ok", "missing"})

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

    _validate_mcp_policy_conformance(conformance, payload, tracked_rule_ids)
    return tracked_rule_ids


def _validate_mcp_policy_conformance(
    conformance: Mapping[str, Any],
    payload: Mapping[str, Any],
    tracked_rule_ids: set[str],
) -> None:
    profile = str(conformance.get("profile", ""))
    if profile not in {"recommended", "strict"}:
        return

    status = str(conformance.get("status", ""))
    mcp_config = require_mapping(payload.get("mcp_config"), "$.mcp_config")
    policy = require_mapping(mcp_config.get("policy"), "$.mcp_config.policy")
    policy_path = policy.get("path")
    has_reviewed_policy_rule = "required_mcp_policy_not_reviewed" in tracked_rule_ids
    has_weakened_policy_rule = "mcp_policy_weakened" in tracked_rule_ids

    if policy_path == REVIEWED_MCP_POLICY_PATH:
        require(
            not has_reviewed_policy_rule,
            "$.conformance.findings must not report the reviewed MCP policy missing when policy path is reviewed",
        )
    elif status == "ok":
        raise ValueError("$.mcp_config.policy.path must be the reviewed repo MCP policy when conformance is ok")
    else:
        require(
            has_reviewed_policy_rule,
            "$.conformance.findings must include required_mcp_policy_not_reviewed when MCP policy is not reviewed",
        )

    raw_patterns = policy.get("forbidden_risky_patterns")
    if isinstance(raw_patterns, Sequence) and not isinstance(raw_patterns, (str, bytes, bytearray)):
        pattern_set = {str(value).strip() for value in raw_patterns if isinstance(value, str) and str(value).strip()}
        missing = sorted(REQUIRED_MCP_RISK_LABELS - pattern_set)
        if missing:
            if status == "ok":
                raise ValueError("$.mcp_config.policy.forbidden_risky_patterns must include the default MCP risk labels")
            require(
                has_weakened_policy_rule,
                "$.conformance.findings must include mcp_policy_weakened when default MCP risk labels are missing",
            )
        else:
            require(
                not has_weakened_policy_rule,
                "$.conformance.findings must not report mcp_policy_weakened when default MCP risk labels are present",
            )
    elif status == "ok":
        raise ValueError("$.mcp_config.policy.forbidden_risky_patterns must be an array when conformance is ok")
    else:
        require(
            has_weakened_policy_rule,
            "$.conformance.findings must include mcp_policy_weakened when default MCP risk labels are unavailable",
        )


def validate_evidence_pack_manifest(manifest: Mapping[str, Any], payload: Mapping[str, Any]) -> None:
    manifest_version = manifest.get("schema_version")
    require(
        manifest_version in EVIDENCE_PACK_SCHEMA_VERSIONS,
        "$.evidence_pack_manifest.schema_version mismatch",
    )
    manifest_report = require_mapping(manifest.get("report"), "$.evidence_pack_manifest.report")
    report = require_mapping(payload.get("report"), "$.report")
    for key in ("schema_version", "format", "scope"):
        require(manifest_report.get(key) == report.get(key), f"$.evidence_pack_manifest.report.{key} must match $.report.{key}")
    expected_report_version = {
        "agent-guard.evidence_pack_manifest.v1": "agent-guard.report_evidence.v1",
        "agent-guard.evidence_pack_manifest.v2": "agent-guard.report_evidence.v2",
    }[manifest_version]
    require(
        report.get("schema_version") == expected_report_version,
        "$.evidence_pack_manifest.schema_version does not match $.report.schema_version",
    )
    require(manifest_report.get("status") == payload.get("status"), "$.evidence_pack_manifest.report.status must match $.status")
    require(
        manifest_report.get("finding_count") == payload.get("finding_count"),
        "$.evidence_pack_manifest.report.finding_count must match $.finding_count",
    )

    summary = require_mapping(manifest.get("summary"), "$.evidence_pack_manifest.summary")
    gates = require_sequence(manifest.get("gates"), "$.evidence_pack_manifest.gates")
    gate_count = require_int(summary.get("gate_count"), "$.evidence_pack_manifest.summary.gate_count")
    enabled_count = require_int(summary.get("enabled_gate_count"), "$.evidence_pack_manifest.summary.enabled_gate_count")
    missing_count = require_int(summary.get("missing_gate_count"), "$.evidence_pack_manifest.summary.missing_gate_count")
    failing_count = require_int(summary.get("failing_gate_count"), "$.evidence_pack_manifest.summary.failing_gate_count")

    require(gate_count == len(gates), "$.evidence_pack_manifest.summary.gate_count must match gates length")
    manifest_gates, enabled, missing, failing = _manifest_gate_map(gates)
    require(enabled_count == enabled, "$.evidence_pack_manifest.summary.enabled_gate_count must match gate statuses")
    require(missing_count == missing, "$.evidence_pack_manifest.summary.missing_gate_count must match gate statuses")
    require(failing_count == failing, "$.evidence_pack_manifest.summary.failing_gate_count must match gate statuses")
    _validate_manifest_coverage(manifest_gates, payload)
    _validate_manifest_conformance(manifest, payload)
    _validate_manifest_artifacts(manifest)


def _validate_manifest_artifacts(manifest: Mapping[str, Any]) -> None:
    artifacts = require_sequence(manifest.get("artifacts"), "$.evidence_pack_manifest.artifacts")
    audit_event_count = 0
    for index, raw_artifact in enumerate(artifacts):
        artifact = require_mapping(raw_artifact, f"$.evidence_pack_manifest.artifacts[{index}]")
        role = artifact.get("role")
        require(
            role in {"report", "agent-policy-audit-event"},
            f"$.evidence_pack_manifest.artifacts[{index}].role is invalid",
        )
        require(
            isinstance(artifact.get("path"), str) and bool(str(artifact.get("path")).strip()),
            f"$.evidence_pack_manifest.artifacts[{index}].path must be a non-empty string",
        )
        if role != "agent-policy-audit-event":
            continue
        audit_event_count += 1
        if manifest.get("schema_version") == "agent-guard.evidence_pack_manifest.v1":
            continue
        require(
            set(artifact) == {"path", "role", "content_binding"},
            f"$.evidence_pack_manifest.artifacts[{index}] has invalid fields",
        )
        try:
            validate_agent_policy_audit_event_binding_shape(artifact.get("content_binding"))
        except ValueError:
            raise ValueError(
                f"$.evidence_pack_manifest.artifacts[{index}].content_binding is invalid"
            ) from None
    if manifest.get("schema_version") == "agent-guard.evidence_pack_manifest.v2":
        require(
            audit_event_count > 0,
            "$.evidence_pack_manifest.artifacts must include a bound audit event",
        )


def _manifest_gate_map(gates: Sequence[Any]) -> tuple[dict[str, Mapping[str, Any]], int, int, int]:
    enabled = missing = failing = 0
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
        require(status in {"ok", "violation", "missing", "error"}, f"$.evidence_pack_manifest.gates[{index}].status is invalid")
        require_int(gate.get("finding_count"), f"$.evidence_pack_manifest.gates[{index}].finding_count")
        missing += int(status == "missing")
        enabled += int(status != "missing")
        failing += int(status not in {"ok", "missing"})
    return manifest_gates, enabled, missing, failing


def _validate_manifest_coverage(manifest_gates: dict[str, Mapping[str, Any]], payload: Mapping[str, Any]) -> None:
    evidence_coverage = require_mapping(payload.get("evidence_coverage"), "$.evidence_coverage")
    evidence_gates = require_sequence(evidence_coverage.get("gates"), "$.evidence_coverage.gates")
    coverage_gates: dict[str, Mapping[str, Any]] = {}
    for index, raw_gate in enumerate(evidence_gates):
        gate = require_mapping(raw_gate, f"$.evidence_coverage.gates[{index}]")
        name = str(gate.get("gate", "")).strip()
        if name:
            coverage_gates[name] = gate
    require(set(manifest_gates) == set(coverage_gates), "$.evidence_pack_manifest.gates must match $.evidence_coverage.gates")
    for index, (gate_name, manifest_gate) in enumerate(manifest_gates.items()):
        coverage_gate = coverage_gates[gate_name]
        for key in ("status", "finding_count"):
            require(
                manifest_gate.get(key) == coverage_gate.get(key),
                f"$.evidence_pack_manifest.gates[{index}].{key} must match $.evidence_coverage.gates",
            )


def _validate_manifest_conformance(manifest: Mapping[str, Any], payload: Mapping[str, Any]) -> None:
    conformance = manifest.get("conformance")
    payload_conformance = payload.get("conformance")
    require(
        not (payload_conformance is not None and conformance is None),
        "$.evidence_pack_manifest.conformance is required when $.conformance is present",
    )
    if conformance is None:
        return
    conformance_obj = require_mapping(conformance, "$.evidence_pack_manifest.conformance")
    payload_conformance_obj = require_mapping(payload_conformance, "$.conformance")
    for key in ("schema_version", "profile", "status", "finding_count"):
        require(
            conformance_obj.get(key) == payload_conformance_obj.get(key),
            f"$.evidence_pack_manifest.conformance.{key} must match $.conformance.{key}",
        )
    finding_count = require_int(conformance_obj.get("finding_count"), "$.evidence_pack_manifest.conformance.finding_count")
    status = str(conformance_obj.get("status", ""))
    require(status in {"ok", "violation"}, "$.evidence_pack_manifest.conformance.status is invalid")
    if status == "ok":
        require(finding_count == 0, "$.evidence_pack_manifest.conformance.finding_count must be 0 when status is ok")
    if status == "violation":
        require(finding_count > 0, "$.evidence_pack_manifest.conformance.finding_count must be non-zero when status is violation")


def validate_public_report_consistency(payload: Mapping[str, Any]) -> None:
    status = str(payload.get("status", ""))
    exit_code = payload.get("exit_code")
    if status == "ok":
        require(exit_code == 0, "$.exit_code must be 0 when status is ok")
    if status == "violation":
        require(exit_code == 1, "$.exit_code must be 1 when status is violation")
    if status == "error":
        require(exit_code == 2, "$.exit_code must be 2 when status is error")
        error = payload.get("error")
        require(isinstance(error, str) and bool(error.strip()), "$.error must be a non-empty string when status is error")

    findings = require_sequence(payload.get("findings"), "$.findings")
    finding_count = require_int(payload.get("finding_count"), "$.finding_count")
    require(finding_count == len(findings), "$.finding_count must match findings length")
    summary = require_mapping(payload.get("summary"), "$.summary")
    require(summary.get("finding_count") == finding_count, "$.summary.finding_count must match finding_count")
    if status == "ok":
        require(finding_count == 0, "$.finding_count must be 0 when status is ok")
    if status == "error":
        return

    surface_inventory = require_mapping(payload.get("surface_inventory"), "$.surface_inventory")
    validate_surface_inventory(surface_inventory)
    evidence_coverage = require_mapping(payload.get("evidence_coverage"), "$.evidence_coverage")
    validate_gate_counts(evidence_coverage, report_status=status)
    failing_count = require_int(evidence_coverage.get("failing_count"), "$.evidence_coverage.failing_count")
    conformance = payload.get("conformance")
    conformance_finding_count = 0
    if isinstance(conformance, Mapping):
        conformance_finding_count = require_int(conformance.get("finding_count"), "$.conformance.finding_count")
    if status == "violation":
        require(
            finding_count > 0 or failing_count > 0 or conformance_finding_count > 0,
            "$.status violation must be explained by findings, failing gates, or conformance findings",
        )

    drift = payload.get("policy_spec_drift")
    if isinstance(drift, Mapping):
        baseline = drift.get("baseline_trust")
        if baseline is not None:
            baseline_obj = require_mapping(baseline, "$.policy_spec_drift.baseline_trust")
            require(
                baseline_obj.get("status") in {"ok", "review_required", "unproven"},
                "$.policy_spec_drift.baseline_trust.status is invalid",
            )
