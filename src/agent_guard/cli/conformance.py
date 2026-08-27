# Where: src/agent_guard/cli/conformance.py
# What: conformance CLI parser and runner.
# Why: isolate profile conformance checks from the legacy CLI dispatcher.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..conformance import build_conformance_report
from ..profiles import PROFILE_NAMES
from ..taxonomy import annotate_finding
from .common import load_json_file, result_payload


def add_conformance_parser(top) -> None:
    conformance = top.add_parser("conformance", help="profile conformance over sanitized evidence")
    conformance_sub = conformance.add_subparsers(dest="command", required=True)
    conformance_check = conformance_sub.add_parser("check", help="evaluate an agent-guard report against a profile")
    conformance_check.add_argument("--root", default=".", help="repository root used for display-path scrubbing")
    conformance_check.add_argument("--evidence", required=True, help="agent-guard report JSON path")
    conformance_check.add_argument("--profile", choices=PROFILE_NAMES, default="recommended", help="conformance profile")
    conformance_check.add_argument("--json", action="store_true", help="emit JSON")


def run_conformance_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    evidence_path = Path(args.evidence).resolve()
    try:
        payload = load_json_file(evidence_path)
        conformance = build_conformance_report(
            profile=args.profile,
            evidence_coverage=payload.get("evidence_coverage", {}) if isinstance(payload, dict) else {},
            surface_inventory=payload.get("surface_inventory", {}) if isinstance(payload, dict) else {},
            report_payload=payload,
        )
    except Exception as exc:
        result = result_payload(
            scanner="conformance",
            status="error",
            exit_code=2,
            policy_arg=args.evidence,
            root=root,
            error=str(exc),
            extra={"command": "check"},
        )
        if args.json:
            print(json.dumps(result, allow_nan=False, ensure_ascii=False, sort_keys=True))
        else:
            print(f"ERROR: {result.get('error', 'unknown error')}")
        return 2

    findings = conformance.get("findings", [])
    finding_items = (
        [annotate_finding("conformance", item) for item in findings if isinstance(item, dict)]
        if isinstance(findings, list)
        else []
    )
    conformance["findings"] = finding_items
    conformance["finding_count"] = len(finding_items)
    exit_code = 0 if conformance.get("status") == "ok" else 1
    result = result_payload(
        scanner="conformance",
        status="ok" if exit_code == 0 else "violation",
        exit_code=exit_code,
        policy_arg=args.evidence,
        root=root,
        findings=finding_items,
        scanned_count=int(conformance.get("checked_count", 0)),
        scanned_unit="requirements",
        summary_extra={
            "profile": conformance.get("profile", args.profile),
            "conformance_finding_count": int(conformance.get("finding_count", 0)),
        },
        extra={"command": "check", "conformance": conformance},
    )
    if args.json:
        print(json.dumps(result, allow_nan=False, ensure_ascii=False, sort_keys=True))
    elif exit_code == 0:
        print(f"conformance: OK ({conformance.get('profile', args.profile)})")
    else:
        print(f"conformance: NG ({conformance.get('finding_count', 0)} findings)")
        for item in finding_items:
            finding = item if isinstance(item, dict) else {}
            print(f"- {finding.get('severity', 'medium')} {finding.get('rule_id', '-')} {finding.get('requirement_id', '-')}")
    return exit_code
