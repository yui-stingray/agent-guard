"""Where: src/agent_guard/conformance.py
What: profile-based conformance over sanitized agent-guard evidence.
Why: adopters need a deterministic pass/fail summary without LLM judgment.
"""

from __future__ import annotations

from collections.abc import Mapping

from .mcp_guard import mcp_config_findings_from_surfaces
from .profiles import profile_requirements, normalize_profile_name


CONFORMANCE_SCHEMA_VERSION = "agent-guard.conformance.v1"


def evidence_gate_map(evidence_coverage: dict[str, object]) -> dict[str, dict[str, object]]:
    gates = evidence_coverage.get("gates", [])
    if not isinstance(gates, list):
        return {}
    mapped: dict[str, dict[str, object]] = {}
    for item in gates:
        if not isinstance(item, dict):
            continue
        gate = str(item.get("gate", "")).strip()
        if gate:
            mapped[gate] = item
    return mapped


def surface_counts(surface_inventory: dict[str, object]) -> dict[str, int]:
    summary = surface_inventory.get("summary", {})
    if isinstance(summary, dict):
        by_surface = summary.get("by_surface", {})
        if isinstance(by_surface, dict):
            return {str(key): int(value) for key, value in by_surface.items()}
    counts: dict[str, int] = {}
    surfaces = surface_inventory.get("surfaces", [])
    if isinstance(surfaces, list):
        for item in surfaces:
            if isinstance(item, dict):
                surface = str(item.get("surface", "unknown"))
                counts[surface] = counts.get(surface, 0) + 1
    return counts


def artifact_roles(report_payload: Mapping[str, object]) -> set[str]:
    manifest = report_payload.get("evidence_pack_manifest", {})
    if not isinstance(manifest, Mapping):
        return set()
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        return set()
    roles: set[str] = set()
    for item in artifacts:
        if isinstance(item, Mapping):
            role = str(item.get("role", "")).strip()
            if role:
                roles.add(role)
    return roles


def strict_mcp_risk_findings(surface_inventory: dict[str, object]) -> tuple[list[dict[str, object]], int]:
    return mcp_config_findings_from_surfaces(
        surface_inventory.get("surfaces", []),
        requirement_id="mcp_config_risky_patterns",
    )


def build_conformance_report(
    *,
    profile: str,
    evidence_coverage: dict[str, object],
    surface_inventory: dict[str, object],
    report_payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    profile_name = normalize_profile_name(profile)
    requirements = profile_requirements(profile_name)
    gates = evidence_gate_map(evidence_coverage)
    surfaces = surface_counts(surface_inventory)
    payload = report_payload or {}
    roles = artifact_roles(payload)
    findings: list[dict[str, object]] = []
    checked_count = 0

    for gate in requirements["gates"]:
        checked_count += 1
        gate_name = str(gate)
        item = gates.get(gate_name)
        if item is None:
            findings.append(
                {
                    "rule_id": "required_gate_missing",
                    "severity": "high",
                    "requirement_id": gate_name,
                    "message": "required evidence gate is missing",
                    "reason": "missing_required_gate",
                }
            )
            continue
        status = str(item.get("status", "missing"))
        if status != "ok":
            findings.append(
                {
                    "rule_id": "required_gate_not_ok",
                    "severity": "high",
                    "requirement_id": gate_name,
                    "message": "required evidence gate is not clean",
                    "reason": status,
                }
            )

    for surface in requirements["surfaces"]:
        checked_count += 1
        surface_name = str(surface)
        if surfaces.get(surface_name, 0) > 0:
            continue
        findings.append(
            {
                "rule_id": "required_surface_missing",
                "severity": "medium",
                "requirement_id": surface_name,
                "message": "required agent surface metadata is missing",
                "reason": "missing_required_surface",
            }
        )

    for section in requirements["report_sections"]:
        checked_count += 1
        section_name = str(section)
        item = payload.get(section_name)
        if isinstance(item, Mapping):
            if section_name == "evidence_pack_manifest" and item.get("sanitized") is not True:
                findings.append(
                    {
                        "rule_id": "required_report_section_not_sanitized",
                        "severity": "high",
                        "requirement_id": section_name,
                        "message": "required report section is not marked sanitized",
                        "reason": "not_sanitized",
                    }
                )
            continue
        findings.append(
            {
                "rule_id": "required_report_section_missing",
                "severity": "high",
                "requirement_id": section_name,
                "message": "required report section is missing",
                "reason": "missing_required_report_section",
            }
        )

    for role in requirements["artifact_roles"]:
        checked_count += 1
        role_name = str(role)
        if role_name in roles:
            continue
        findings.append(
            {
                "rule_id": "required_artifact_role_missing",
                "severity": "medium",
                "requirement_id": role_name,
                "message": "required evidence-pack artifact role is missing",
                "reason": "missing_required_artifact_role",
            }
        )

    mcp_checked_count = 0
    if profile_name == "strict":
        mcp_findings, mcp_checked_count = strict_mcp_risk_findings(surface_inventory)
        checked_count += mcp_checked_count
        findings.extend(mcp_findings)

    return {
        "schema_version": CONFORMANCE_SCHEMA_VERSION,
        "profile": profile_name,
        "status": "ok" if not findings else "violation",
        "checked_count": checked_count,
        "finding_count": len(findings),
        "required_gates": list(requirements["gates"]),
        "required_surfaces": list(requirements["surfaces"]),
        "required_report_sections": list(requirements["report_sections"]),
        "required_artifact_roles": list(requirements["artifact_roles"]),
        "mcp_config_checked_count": mcp_checked_count,
        "findings": findings,
    }
