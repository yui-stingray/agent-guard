# Where: src/agent_guard/cli/mcp.py
# What: MCP configuration CLI parser and runner.
# Why: keep MCP evidence handling out of the legacy CLI module.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..bounded_repo_reader import DistinctInputBudget
from ..mcp_guard import build_mcp_config_report, load_mcp_policy
from ..surface_inventory_mcp import ERROR_MCP_CONFIG_LIMIT, MAX_MCP_DISTINCT_INPUT_BYTES
from ..taxonomy import annotate_finding
from .common import (
    bounded_public_line,
    bounded_public_json,
    emit_public_output,
    require_public_output_budget,
    resolve_policy_arg,
    result_payload,
    safe_resolved_policy_path,
)


def add_mcp_parser(top) -> None:
    mcp = top.add_parser("mcp", help="static MCP configuration evidence")
    mcp_sub = mcp.add_subparsers(dest="command", required=True)
    mcp_check = mcp_sub.add_parser("check", help="scan committed MCP configuration metadata")
    mcp_check.add_argument("--root", default=".", help="repository root path")
    mcp_check.add_argument("--policy", default="", help="optional MCP YAML policy path")
    mcp_check.add_argument("--json", action="store_true", help="emit JSON")


def _emit_mcp_payload(
    *,
    args: argparse.Namespace,
    root: Path,
    policy_arg: str,
    payload: dict[str, object],
    plain_text: str,
) -> bool:
    try:
        raw_output = (
            bounded_public_json(
                payload,
                error=ERROR_MCP_CONFIG_LIMIT,
                sort_keys=True,
            )
            if args.json
            else require_public_output_budget(
                plain_text,
                error=ERROR_MCP_CONFIG_LIMIT,
            )
        )
        rendered = bounded_public_line(
            raw_output,
            error=ERROR_MCP_CONFIG_LIMIT,
        )
    except ValueError:
        fallback = result_payload(
            scanner="mcp",
            status="error",
            exit_code=2,
            policy_arg=policy_arg or ".mcp-config",
            root=root,
            error=ERROR_MCP_CONFIG_LIMIT,
            extra={"command": "check"},
        )
        rendered = (
            json.dumps(fallback, ensure_ascii=False, sort_keys=True)
            if args.json
            else f"ERROR: {ERROR_MCP_CONFIG_LIMIT}"
        )
        emit_public_output(f"{rendered}\n", error=ERROR_MCP_CONFIG_LIMIT)
        return False
    try:
        emit_public_output(rendered, error=ERROR_MCP_CONFIG_LIMIT)
    except ValueError:
        emit_public_output(
            f"ERROR: {ERROR_MCP_CONFIG_LIMIT}\n",
            error=ERROR_MCP_CONFIG_LIMIT,
        )
        return False
    return True


def build_missing_mcp_policy_report(
    *,
    root: Path,
    policy_path: str,
    _input_budget: DistinctInputBudget | None = None,
    _surfaces: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    report = build_mcp_config_report(
        root=root,
        policy=None,
        _input_budget=_input_budget,
        _surfaces=_surfaces,
    )
    existing_findings = report.get("findings", [])
    finding_items = existing_findings if isinstance(existing_findings, list) else []
    missing_policy = annotate_finding(
        "mcp_config",
        {
            "rule_id": "mcp_policy_missing",
            "severity": "high",
            "message": "reviewed MCP policy is required for recommended evidence",
            "reason": "missing_required_policy",
            "surface": "policy_file",
            "path": policy_path,
        },
    )
    report["findings"] = [missing_policy, *[item for item in finding_items if isinstance(item, dict)]]
    report["finding_count"] = len(report["findings"])
    report["status"] = "violation"
    report["policy"] = {"path": policy_path, "required": True}
    return report


def run_mcp_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_arg = str(args.policy).strip()
    policy_abs = resolve_policy_arg(policy_arg, root) if policy_arg else None
    policy_path = safe_resolved_policy_path(policy_abs, root) if policy_abs else ""
    try:
        input_budget = DistinctInputBudget(max_bytes=MAX_MCP_DISTINCT_INPUT_BYTES)
        policy = (
            load_mcp_policy(policy_abs, _input_budget=input_budget)
            if policy_abs
            else None
        )
        report = build_mcp_config_report(
            root=root,
            policy=policy,
            policy_path=policy_path,
            _input_budget=input_budget,
        )
    except Exception as exc:
        payload = result_payload(
            scanner="mcp",
            status="error",
            exit_code=2,
            policy_arg=policy_arg or ".mcp-config",
            root=root,
            error=str(exc),
            extra={"command": "check"},
        )
        _emit_mcp_payload(
            args=args,
            root=root,
            policy_arg=policy_arg,
            payload=payload,
            plain_text=f"ERROR: {payload.get('error', 'unknown error')}",
        )
        return 2

    findings = report.get("findings", [])
    finding_items = findings if isinstance(findings, list) else []
    checked_count = int(report.get("checked_count", 0))
    exit_code = 0 if not finding_items else 1
    payload = result_payload(
        scanner="mcp",
        status="ok" if exit_code == 0 else "violation",
        exit_code=exit_code,
        policy_arg=policy_arg or ".mcp-config",
        root=root,
        findings=[item for item in finding_items if isinstance(item, dict)],
        scanned_count=checked_count,
        scanned_unit="mcp_config_surfaces",
        extra={"command": "check", "mcp_config": report},
    )
    plain_lines = (
        [
            f"mcp-config: NG ({len(finding_items)} findings)",
            *[
                f"- {item.get('severity', 'medium')} {item.get('rule_id', '-')} "
                f"{item.get('path', '-')} {item.get('reason', '-')}"
                for item in finding_items
                if isinstance(item, dict)
            ],
        ]
        if finding_items
        else [f"mcp-config: OK ({checked_count} config surfaces checked)"]
    )
    if not _emit_mcp_payload(
        args=args,
        root=root,
        policy_arg=policy_arg,
        payload=payload,
        plain_text="\n".join(plain_lines),
    ):
        return 2
    return exit_code
