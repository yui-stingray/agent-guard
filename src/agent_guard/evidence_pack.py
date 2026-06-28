"""Where: src/agent_guard/evidence_pack.py
What: sanitized manifest for PR-reviewable agent-guard evidence packs.
Why: reviewers need a compact index of evidence artifacts without raw content.
"""

from __future__ import annotations

from pathlib import Path, PureWindowsPath


EVIDENCE_PACK_MANIFEST_SCHEMA_VERSION = "agent-guard.evidence_pack_manifest.v1"


def safe_artifact_path(path: str, *, root: Path | None = None) -> str:
    text = str(path).strip()
    if not text:
        return ""
    windows_path = PureWindowsPath(text)
    if windows_path.is_absolute() or windows_path.drive or text.startswith("\\\\"):
        return windows_path.name or "<external-artifact>"
    raw = Path(text)
    if raw.is_absolute() and root is not None:
        try:
            return raw.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
        except ValueError:
            pass
    if raw.is_absolute() or ".." in raw.parts:
        return raw.name or "<external-artifact>"
    return raw.as_posix()


def build_evidence_pack_manifest(
    *,
    report_payload: dict[str, object],
    artifact_paths: list[str] | None = None,
    agent_policy_audit_event_paths: list[str] | None = None,
    root: Path | None = None,
) -> dict[str, object]:
    report = report_payload.get("report", {})
    summary = report_payload.get("summary", {})
    evidence_coverage = report_payload.get("evidence_coverage", {})
    conformance = report_payload.get("conformance", {})

    gates: list[dict[str, object]] = []
    if isinstance(evidence_coverage, dict):
        raw_gates = evidence_coverage.get("gates", [])
        if isinstance(raw_gates, list):
            for item in raw_gates:
                if not isinstance(item, dict):
                    continue
                gates.append(
                    {
                        "gate": item.get("gate", ""),
                        "status": item.get("status", ""),
                        "finding_count": item.get("finding_count", 0),
                    }
                )

    artifacts = []
    for path in artifact_paths or []:
        safe_path = safe_artifact_path(path, root=root)
        if safe_path:
            artifacts.append({"path": safe_path, "role": "report"})
    for path in agent_policy_audit_event_paths or []:
        safe_path = safe_artifact_path(path, root=root)
        if safe_path:
            artifacts.append({"path": safe_path, "role": "agent-policy-audit-event"})

    return {
        "schema_version": EVIDENCE_PACK_MANIFEST_SCHEMA_VERSION,
        "tool": report_payload.get("tool", {}),
        "sanitized": True,
        "report": {
            "schema_version": report.get("schema_version", "") if isinstance(report, dict) else "",
            "format": report.get("format", "") if isinstance(report, dict) else "",
            "scope": report.get("scope", "") if isinstance(report, dict) else "",
            "status": report_payload.get("status", ""),
            "finding_count": report_payload.get("finding_count", 0),
        },
        "summary": {
            "gate_count": evidence_coverage.get("gate_count", 0) if isinstance(evidence_coverage, dict) else 0,
            "enabled_gate_count": (
                evidence_coverage.get("enabled_count", 0) if isinstance(evidence_coverage, dict) else 0
            ),
            "missing_gate_count": (
                evidence_coverage.get("missing_count", 0) if isinstance(evidence_coverage, dict) else 0
            ),
            "failing_gate_count": (
                evidence_coverage.get("failing_count", 0) if isinstance(evidence_coverage, dict) else 0
            ),
            "surface_count": summary.get("surface_count", 0) if isinstance(summary, dict) else 0,
        },
        "gates": gates,
        **(
            {
                "conformance": {
                    "schema_version": conformance.get("schema_version", ""),
                    "profile": conformance.get("profile", ""),
                    "status": conformance.get("status", ""),
                    "finding_count": conformance.get("finding_count", 0),
                }
            }
            if isinstance(conformance, dict) and conformance
            else {}
        ),
        "artifacts": artifacts,
    }
