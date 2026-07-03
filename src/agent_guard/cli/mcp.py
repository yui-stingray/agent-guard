# Where: src/agent_guard/cli/mcp.py
# What: MCP configuration CLI parser and runner.
# Why: keep MCP evidence handling out of the legacy CLI module.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..mcp_guard import build_mcp_config_report, load_mcp_policy
from ..taxonomy import annotate_finding
from .common import resolve_policy_arg, result_payload, safe_resolved_policy_path


def add_mcp_parser(top) -> None:
    mcp = top.add_parser("mcp", help="static MCP configuration evidence")
    mcp_sub = mcp.add_subparsers(dest="command", required=True)
    mcp_check = mcp_sub.add_parser("check", help="scan committed MCP configuration metadata")
    mcp_check.add_argument("--root", default=".", help="repository root path")
    mcp_check.add_argument("--policy", default="", help="optional MCP YAML policy path")
    mcp_check.add_argument("--json", action="store_true", help="emit JSON")


def build_missing_mcp_policy_report(*, root: Path, policy_path: str) -> dict[str, object]:
    report = build_mcp_config_report(root=root, policy=None)
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
        policy = load_mcp_policy(policy_abs) if policy_abs else None
        report = build_mcp_config_report(root=root, policy=policy, policy_path=policy_path)
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
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"ERROR: {payload.get('error', 'unknown error')}")
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
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    elif finding_items:
        print(f"mcp-config: NG ({len(finding_items)} findings)")
        for item in finding_items:
            if isinstance(item, dict):
                print(
                    f"- {item.get('severity', 'medium')} {item.get('rule_id', '-')} "
                    f"{item.get('path', '-')} {item.get('reason', '-')}"
                )
    else:
        print(f"mcp-config: OK ({checked_count} config surfaces checked)")
    return exit_code

