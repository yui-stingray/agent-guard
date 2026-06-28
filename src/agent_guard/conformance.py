"""Where: src/agent_guard/conformance.py
What: profile-based conformance over sanitized agent-guard evidence.
Why: adopters need a deterministic pass/fail summary without LLM judgment.
"""

from __future__ import annotations

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


def build_conformance_report(
    *,
    profile: str,
    evidence_coverage: dict[str, object],
    surface_inventory: dict[str, object],
) -> dict[str, object]:
    profile_name = normalize_profile_name(profile)
    requirements = profile_requirements(profile_name)
    gates = evidence_gate_map(evidence_coverage)
    surfaces = surface_counts(surface_inventory)
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

    return {
        "schema_version": CONFORMANCE_SCHEMA_VERSION,
        "profile": profile_name,
        "status": "ok" if not findings else "violation",
        "checked_count": checked_count,
        "finding_count": len(findings),
        "required_gates": list(requirements["gates"]),
        "required_surfaces": list(requirements["surfaces"]),
        "findings": findings,
    }
