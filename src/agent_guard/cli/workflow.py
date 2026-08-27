# Where: src/agent_guard/cli/workflow.py
# What: workflow guard CLI parser and runner.
# Why: isolate workflow drift checks from the legacy CLI module.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..workflow_guard import load_workflow_policy, scan_workflow_policy
from .common import redact_public_text, resolve_policy_arg, result_payload


def add_workflow_parser(top) -> None:
    workflow = top.add_parser("workflow", help="workflow drift guard for declared repository gates")
    workflow_sub = workflow.add_subparsers(dest="command", required=True)
    workflow_check = workflow_sub.add_parser("check", help="verify required files and workflow commands")
    workflow_check.add_argument("--root", default=".", help="repository root path")
    workflow_check.add_argument("--policy", required=True, help="YAML policy path")
    workflow_check.add_argument("--json", action="store_true", help="emit JSON")


def run_workflow_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = resolve_policy_arg(args.policy, root)

    try:
        policy = load_workflow_policy(policy_path)
        findings, checked_items = scan_workflow_policy(root=root, policy=policy)
    except Exception as exc:
        payload = result_payload(
            scanner="workflow",
            status="error",
            exit_code=2,
            policy_arg=args.policy,
            root=root,
            error=str(exc),
        )
        if args.json:
            print(json.dumps(payload, allow_nan=False, ensure_ascii=False))
        else:
            print(f"ERROR: {payload.get('error', 'unknown error')}")
        return 2

    exit_code = 0 if not findings else 1
    payload = result_payload(
        scanner="workflow",
        status="ok" if not findings else "violation",
        exit_code=exit_code,
        policy_arg=args.policy,
        root=root,
        findings=[item.to_dict() for item in findings],
        scanned_count=checked_items,
        scanned_unit="checks",
        extra={"checked_items": checked_items},
    )
    if args.json:
        print(json.dumps(payload, allow_nan=False, ensure_ascii=False))
    elif findings:
        print(f"workflow-guard: NG ({len(findings)} findings)")
        for item in findings:
            print(
                f"- {item.severity} {item.rule_id} "
                f"{redact_public_text(item.file)} {redact_public_text(item.message)}"
            )
    else:
        print(f"workflow-guard: OK ({checked_items} checks)")

    return 0 if not findings else 1

