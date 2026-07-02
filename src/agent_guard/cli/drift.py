# Where: src/agent_guard/cli/drift.py
# What: policy/spec drift CLI parser and runner.
# Why: isolate drift checks from the legacy CLI module.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..drift_guard import build_policy_spec_drift_report
from ..profiles import PROFILE_NAMES
from .common import result_payload


def add_drift_parser(top) -> None:
    drift = top.add_parser("drift", help="small policy/spec drift guard")
    drift_sub = drift.add_subparsers(dest="command", required=True)
    drift_check = drift_sub.add_parser("check", help="verify README, workflow, and .agent-guard policy alignment")
    drift_check.add_argument("--root", default=".", help="repository root path")
    drift_check.add_argument("--profile", choices=PROFILE_NAMES, default="recommended", help="conformance profile")
    drift_check.add_argument("--schema-version", choices=("v1", "v2"), default="v1", help="drift schema version")
    drift_check.add_argument(
        "--base-ref",
        default="",
        help="optional git base ref used to flag baseline-sensitive guard changes",
    )
    drift_check.add_argument("--json", action="store_true", help="emit JSON")


def run_drift_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    try:
        report = build_policy_spec_drift_report(
            root=root,
            profile=args.profile,
            schema_version=args.schema_version,
            base_ref=args.base_ref,
        )
    except Exception as exc:
        payload = result_payload(
            scanner="drift",
            status="error",
            exit_code=2,
            policy_arg=".agent-guard/workflow-policy.yaml",
            root=root,
            error=str(exc),
            extra={"command": "check"},
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            print(f"ERROR: {payload.get('error', 'unknown error')}")
        return 2
    findings = report.get("findings", [])
    finding_items = findings if isinstance(findings, list) else []
    exit_code = 0 if report.get("status") == "ok" else 1
    payload = result_payload(
        scanner="drift",
        status="ok" if exit_code == 0 else "violation",
        exit_code=exit_code,
        policy_arg=".agent-guard/workflow-policy.yaml",
        root=root,
        findings=finding_items,
        scanned_count=int(report.get("checked_count", 0)),
        scanned_unit="checks",
        summary_extra={"drift_finding_count": int(report.get("finding_count", 0))},
        extra={"command": "check", "policy_spec_drift": report},
    )
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    elif exit_code == 0:
        print(f"drift-guard: OK ({report.get('checked_count', 0)} checks)")
    else:
        print(f"drift-guard: NG ({report.get('finding_count', 0)} findings)")
        for item in finding_items:
            finding = item if isinstance(item, dict) else {}
            print(
                f"- {finding.get('severity', 'medium')} {finding.get('rule_id', '-')} "
                f"{finding.get('file', '-')} {finding.get('reason', '-')}"
            )
    return exit_code


