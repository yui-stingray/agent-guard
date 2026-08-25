"""Where: src/agent_guard/mcp_guard.py
What: static MCP configuration evidence derived from sanitized surface inventory.
Why: expose MCP configuration risk metadata as a first-class deterministic gate.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import yaml

from .bounded_repo_reader import (
    BoundedRepoContainmentError,
    BoundedRepoFileNotFoundError,
    BoundedRepoLimitError,
    BoundedRepoReadError,
    DistinctInputBudget,
    read_bounded_bytes,
)
from .bounded_scan import MAX_ISOLATED_MESSAGE_BYTES
from .bounded_yaml import (
    BoundedYamlInvalidError,
    BoundedYamlLimitError,
    MAX_YAML_GRAPH_TRAVERSAL,
    _validate_object_graph,
    load_bounded_yaml,
)
from .surface_inventory import collect_mcp_config_surfaces
from .surface_inventory_mcp_safety import MCP_RISKY_PATTERNS
from .taxonomy import annotate_finding

MCP_POLICY_SCHEMA_VERSION = "agent-guard.mcp_policy.v1"
DEFAULT_FORBIDDEN_RISKY_PATTERNS = MCP_RISKY_PATTERNS
ERROR_MCP_POLICY_NOT_FOUND = "MCP policy file not found"
ERROR_MCP_POLICY_INVALID = "MCP policy YAML is not parseable"
ERROR_MCP_POLICY_LIMIT = "MCP policy exceeds configured limits"
ERROR_MCP_CONFIG_LIMIT = "MCP configuration exceeds configured limits"
MAX_MCP_POLICY_BYTES = 256 * 1024
# Match MAX_API_POLICY_LIST_ITEMS for policy-controlled public lists.
MAX_MCP_POLICY_LIST_ITEMS = 256
# Match API/content scanner selection; use the same established count for servers.
MAX_MCP_CONFIG_FILES = 10_000
MAX_MCP_SERVERS = 10_000
# Reserve half the isolated transport cap for container/serialization overhead.
MAX_MCP_AGGREGATE_RESULT_BYTES = MAX_ISOLATED_MESSAGE_BYTES // 2


def load_mcp_policy(
    path: Path,
    *,
    _input_budget: DistinctInputBudget | None = None,
) -> dict[str, Any]:
    try:
        opened = read_bounded_bytes(path, max_bytes=MAX_MCP_POLICY_BYTES)
        if _input_budget is not None:
            _input_budget.charge(opened)
        raw = opened.data
    except BoundedRepoFileNotFoundError:
        raise FileNotFoundError(ERROR_MCP_POLICY_NOT_FOUND) from None
    except BoundedRepoLimitError:
        raise ValueError(ERROR_MCP_POLICY_LIMIT) from None
    except (BoundedRepoContainmentError, BoundedRepoReadError):
        raise ValueError(ERROR_MCP_POLICY_INVALID) from None
    try:
        text = raw.decode("utf-8")
        loaded = load_bounded_yaml(text, construct=yaml.safe_load)
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise BoundedYamlInvalidError
    except BoundedYamlLimitError:
        raise ValueError(ERROR_MCP_POLICY_LIMIT) from None
    except BoundedYamlInvalidError:
        raise ValueError(ERROR_MCP_POLICY_INVALID) from None
    except (MemoryError, OverflowError, RecursionError):
        raise ValueError(ERROR_MCP_POLICY_LIMIT) from None
    except UnicodeDecodeError:
        raise ValueError(ERROR_MCP_POLICY_INVALID) from None
    normalize_mcp_policy(loaded)
    return loaded


def normalize_mcp_string_list(values: object, *, field: str) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError(f"{field} must be a list")
    if len(values) > MAX_MCP_POLICY_LIST_ITEMS:
        raise ValueError(ERROR_MCP_POLICY_LIMIT)
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

    try:
        _validate_object_graph(policy)
    except BoundedYamlLimitError:
        raise ValueError(ERROR_MCP_POLICY_LIMIT) from None
    except (MemoryError, OverflowError, RecursionError):
        raise ValueError(ERROR_MCP_POLICY_LIMIT) from None

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
    return (
        "high"
        if pattern in {"inline_authorization_value", "instruction_like_description", "secret_shaped_inline_value"}
        else "medium"
    )


def _canonical_json_size(value: object) -> int:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return len(rendered.encode("utf-8", errors="surrogatepass"))
    except (MemoryError, OverflowError, RecursionError, TypeError, ValueError):
        raise ValueError(ERROR_MCP_CONFIG_LIMIT) from None


def _validate_mcp_surface_counts(surfaces: list[object]) -> int:
    config_count = 0
    server_count = 0
    for item in surfaces:
        if not isinstance(item, Mapping):
            continue
        surface = str(item.get("surface", ""))
        if surface == "mcp_config":
            config_count += 1
            if config_count > MAX_MCP_CONFIG_FILES:
                raise ValueError(ERROR_MCP_CONFIG_LIMIT)
        elif surface == "mcp_server_reference":
            server_count += 1
            if server_count > MAX_MCP_SERVERS:
                raise ValueError(ERROR_MCP_CONFIG_LIMIT)
    return config_count + server_count


class _McpFindingResultBudget:
    def __init__(
        self,
        result_size_check: Callable[[int, int], None] | None = None,
    ) -> None:
        self.used = _canonical_json_size([])
        self.count = 0
        self.result_size_check = result_size_check
        if self.used > MAX_MCP_AGGREGATE_RESULT_BYTES:
            raise ValueError(ERROR_MCP_CONFIG_LIMIT)

    def add(self, finding: dict[str, object]) -> None:
        amount = _canonical_json_size(finding) + (1 if self.count else 0)
        projected = self.used + amount
        projected_count = self.count + 1
        if projected > MAX_MCP_AGGREGATE_RESULT_BYTES:
            raise ValueError(ERROR_MCP_CONFIG_LIMIT)
        if self.result_size_check is not None:
            self.result_size_check(projected, projected_count)
        self.used = projected
        self.count = projected_count


def mcp_config_findings_from_surfaces(
    surfaces: object,
    *,
    requirement_id: str = "",
    policy: Mapping[str, object] | None = None,
    _result_size_check: Callable[[int, int], None] | None = None,
) -> tuple[list[dict[str, object]], int]:
    if not isinstance(surfaces, list):
        return [], 0
    if len(surfaces) > MAX_YAML_GRAPH_TRAVERSAL:
        raise ValueError(ERROR_MCP_CONFIG_LIMIT)
    checked_count = _validate_mcp_surface_counts(surfaces)
    policy_cfg = normalize_mcp_policy(policy)
    fail_on_parse_error = bool(policy_cfg["fail_on_parse_error"])
    forbidden_patterns = policy_cfg["forbidden_risky_patterns"]
    findings: list[dict[str, object]] = []
    result_budget = _McpFindingResultBudget(_result_size_check)
    for item in surfaces:
        if not isinstance(item, Mapping):
            continue
        surface = str(item.get("surface", ""))
        if surface == "mcp_config":
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
                annotated = annotate_finding("mcp_config", finding)
                result_budget.add(annotated)
                findings.append(annotated)
            continue
        if surface != "mcp_server_reference":
            continue
        raw_patterns = item.get("risky_patterns", [])
        if not isinstance(raw_patterns, list):
            continue
        if len(raw_patterns) > len(DEFAULT_FORBIDDEN_RISKY_PATTERNS):
            raise ValueError(ERROR_MCP_CONFIG_LIMIT)
        patterns = sorted(
            value.strip()
            for value in raw_patterns
            if isinstance(value, str) and value.strip() in DEFAULT_FORBIDDEN_RISKY_PATTERNS
        )
        for pattern in patterns:
            if forbidden_patterns is not None and pattern not in forbidden_patterns:
                continue
            rule_id = "mcp_metadata_poisoning" if pattern == "instruction_like_description" else "mcp_config_risky_pattern"
            message = (
                "MCP configuration metadata contains instruction-like description text"
                if pattern == "instruction_like_description"
                else "MCP configuration metadata requires review"
            )
            finding = {
                "rule_id": rule_id,
                "severity": mcp_risk_severity(pattern),
                "message": message,
                "reason": pattern,
                "surface": "mcp_server_reference",
                "path": str(item.get("path", "")),
                "server_name": str(item.get("server_name", "")),
            }
            if requirement_id:
                finding["requirement_id"] = requirement_id
            annotated = annotate_finding("mcp_config", finding)
            result_budget.add(annotated)
            findings.append(annotated)
    return findings, checked_count


def build_mcp_config_report(
    *,
    root: Path,
    policy: Mapping[str, object] | None = None,
    policy_path: str = "",
    _input_budget: DistinctInputBudget | None = None,
    _surfaces: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    surfaces = (
        _surfaces
        if _surfaces is not None
        else collect_mcp_config_surfaces(root, _input_budget=_input_budget)
    )
    checked_count = _validate_mcp_surface_counts(surfaces)
    policy_payload = mcp_policy_summary(policy=policy, policy_path=policy_path) if policy_path else None
    empty_report: dict[str, object] = {
        "status": "ok",
        "checked_count": checked_count,
        "finding_count": 0,
        "findings": [],
        "surfaces": surfaces,
        **({"policy": policy_payload} if policy_payload is not None else {}),
    }
    empty_report_size = _canonical_json_size(empty_report)
    if empty_report_size > MAX_MCP_AGGREGATE_RESULT_BYTES:
        raise ValueError(ERROR_MCP_CONFIG_LIMIT)

    def check_report_size(findings_size: int, finding_count: int) -> None:
        projected = empty_report_size + findings_size - _canonical_json_size([])
        projected += _canonical_json_size("violation") - _canonical_json_size("ok")
        projected += len(str(finding_count)) - len(str(0))
        if projected > MAX_MCP_AGGREGATE_RESULT_BYTES:
            raise ValueError(ERROR_MCP_CONFIG_LIMIT)

    findings, checked_count = mcp_config_findings_from_surfaces(
        surfaces,
        policy=policy,
        _result_size_check=check_report_size,
    )
    report = {
        "status": "ok" if not findings else "violation",
        "checked_count": checked_count,
        "finding_count": len(findings),
        "findings": findings,
        "surfaces": surfaces,
        **({"policy": policy_payload} if policy_payload is not None else {}),
    }
    if _canonical_json_size(report) > MAX_MCP_AGGREGATE_RESULT_BYTES:
        raise ValueError(ERROR_MCP_CONFIG_LIMIT)
    return report
