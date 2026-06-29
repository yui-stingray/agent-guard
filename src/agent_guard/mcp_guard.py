"""Where: src/agent_guard/mcp_guard.py
What: static MCP configuration evidence derived from sanitized surface inventory.
Why: expose MCP configuration risk metadata as a first-class deterministic gate.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .surface_inventory import collect_mcp_config_surfaces
from .taxonomy import annotate_finding


def mcp_risk_severity(pattern: str) -> str:
    return "high" if pattern in {"inline_authorization_value", "secret_shaped_inline_value"} else "medium"


def mcp_config_findings_from_surfaces(
    surfaces: object,
    *,
    requirement_id: str = "",
) -> tuple[list[dict[str, object]], int]:
    if not isinstance(surfaces, list):
        return [], 0
    findings: list[dict[str, object]] = []
    checked_count = 0
    for item in surfaces:
        if not isinstance(item, Mapping):
            continue
        surface = str(item.get("surface", ""))
        if surface == "mcp_config":
            checked_count += 1
            if item.get("status") == "parse_error":
                finding = {
                    "rule_id": "mcp_config_risky_pattern",
                    "severity": "medium",
                    "message": "MCP configuration metadata is not parseable",
                    "reason": "parse_error",
                    "surface": "mcp_config",
                    "path": str(item.get("path", "")),
                }
                if requirement_id:
                    finding["requirement_id"] = requirement_id
                findings.append(annotate_finding("mcp_config", finding))
            continue
        if surface != "mcp_server_reference":
            continue
        checked_count += 1
        raw_patterns = item.get("risky_patterns", [])
        if not isinstance(raw_patterns, list):
            continue
        patterns = sorted(value.strip() for value in raw_patterns if isinstance(value, str) and value.strip())
        for pattern in patterns:
            finding = {
                "rule_id": "mcp_config_risky_pattern",
                "severity": mcp_risk_severity(pattern),
                "message": "MCP configuration metadata requires review",
                "reason": pattern,
                "surface": "mcp_server_reference",
                "path": str(item.get("path", "")),
                "server_name": str(item.get("server_name", "")),
            }
            if requirement_id:
                finding["requirement_id"] = requirement_id
            findings.append(annotate_finding("mcp_config", finding))
    return findings, checked_count


def build_mcp_config_report(*, root: Path) -> dict[str, object]:
    surfaces = collect_mcp_config_surfaces(root)
    findings, checked_count = mcp_config_findings_from_surfaces(surfaces)
    return {
        "status": "ok" if not findings else "violation",
        "checked_count": checked_count,
        "finding_count": len(findings),
        "findings": findings,
        "surfaces": surfaces,
    }
