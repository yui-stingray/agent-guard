"""Where: src/agent_guard/mcp_guard.py
What: static MCP configuration evidence derived from sanitized surface inventory.
Why: expose MCP configuration risk metadata as a first-class deterministic gate.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from .surface_inventory import collect_mcp_config_surfaces
from .taxonomy import annotate_finding

MCP_POLICY_SCHEMA_VERSION = "agent-guard.mcp_policy.v1"
DEFAULT_FORBIDDEN_RISKY_PATTERNS = frozenset(
    {
        "broad_authorization_scope",
        "filesystem_root_reference",
        "inline_authorization_value",
        "inline_env_value",
        "latest_package",
        "secret_shaped_inline_value",
        "unsafe_url_scheme",
        "unpinned_package",
    }
)


def load_mcp_policy(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")

    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError("MCP policy YAML is not parseable") from exc
    except UnicodeDecodeError as exc:
        raise ValueError("MCP policy YAML must be UTF-8 text") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"policy file must be YAML object: {path}")
    return loaded


def normalize_mcp_string_list(values: object, *, field: str) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError(f"{field} must be a list")
    out: list[str] = []
    for index, value in enumerate(values, start=1):
        if not isinstance(value, str):
            raise ValueError(f"{field}[{index}] must be a string")
        text = value.strip()
        if not text:
            raise ValueError(f"{field}[{index}] must not be empty")
        out.append(text)
    return out


def normalize_mcp_policy(policy: Mapping[str, object] | None) -> dict[str, object]:
    if policy is None:
        return {
            "fail_on_parse_error": True,
            "forbidden_risky_patterns": None,
        }

    schema_version = policy.get("schema_version")
    if schema_version != MCP_POLICY_SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {MCP_POLICY_SCHEMA_VERSION!r}")

    raw_policy_cfg = policy.get("policy", {})
    if not isinstance(raw_policy_cfg, Mapping):
        raise ValueError("policy must be an object")

    fail_on_parse_error = raw_policy_cfg.get("fail_on_parse_error", True)
    if not isinstance(fail_on_parse_error, bool):
        raise ValueError("policy.fail_on_parse_error must be a boolean")

    forbidden_risky_patterns = normalize_mcp_string_list(
        raw_policy_cfg.get("forbidden_risky_patterns", sorted(DEFAULT_FORBIDDEN_RISKY_PATTERNS)),
        field="policy.forbidden_risky_patterns",
    )
    unknown = sorted(set(forbidden_risky_patterns) - DEFAULT_FORBIDDEN_RISKY_PATTERNS)
    if unknown:
        raise ValueError("policy.forbidden_risky_patterns contains unknown MCP risk pattern values")

    return {
        "fail_on_parse_error": fail_on_parse_error,
        "forbidden_risky_patterns": set(forbidden_risky_patterns),
    }


def mcp_policy_summary(
    *,
    policy: Mapping[str, object] | None,
    policy_path: str,
) -> dict[str, object]:
    policy_cfg = normalize_mcp_policy(policy)
    forbidden_patterns = policy_cfg["forbidden_risky_patterns"]
    summary: dict[str, object] = {
        "path": policy_path,
        "fail_on_parse_error": bool(policy_cfg["fail_on_parse_error"]),
    }
    if forbidden_patterns is None:
        summary["forbidden_risky_patterns"] = sorted(DEFAULT_FORBIDDEN_RISKY_PATTERNS)
        summary["default_enforcement"] = True
    else:
        summary["forbidden_risky_patterns"] = sorted(forbidden_patterns)
    return summary


def mcp_risk_severity(pattern: str) -> str:
    return "high" if pattern in {"inline_authorization_value", "secret_shaped_inline_value"} else "medium"


def mcp_config_findings_from_surfaces(
    surfaces: object,
    *,
    requirement_id: str = "",
    policy: Mapping[str, object] | None = None,
) -> tuple[list[dict[str, object]], int]:
    if not isinstance(surfaces, list):
        return [], 0
    policy_cfg = normalize_mcp_policy(policy)
    fail_on_parse_error = bool(policy_cfg["fail_on_parse_error"])
    forbidden_patterns = policy_cfg["forbidden_risky_patterns"]
    findings: list[dict[str, object]] = []
    checked_count = 0
    for item in surfaces:
        if not isinstance(item, Mapping):
            continue
        surface = str(item.get("surface", ""))
        if surface == "mcp_config":
            checked_count += 1
            if fail_on_parse_error and item.get("status") == "parse_error":
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
            if forbidden_patterns is not None and pattern not in forbidden_patterns:
                continue
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


def build_mcp_config_report(
    *,
    root: Path,
    policy: Mapping[str, object] | None = None,
    policy_path: str = "",
) -> dict[str, object]:
    surfaces = collect_mcp_config_surfaces(root)
    findings, checked_count = mcp_config_findings_from_surfaces(surfaces, policy=policy)
    return {
        "status": "ok" if not findings else "violation",
        "checked_count": checked_count,
        "finding_count": len(findings),
        "findings": findings,
        "surfaces": surfaces,
        **({"policy": mcp_policy_summary(policy=policy, policy_path=policy_path)} if policy_path else {}),
    }
