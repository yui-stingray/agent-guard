# Where: src/agent_guard/cli/api.py
# What: API surface guard CLI parser and runner.
# Why: isolate API checks from the legacy CLI module.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..api_guard import load_yaml_policy, scan_urls_with_count
from ..taxonomy import annotate_finding
from .common import redact_public_text, resolve_policy_arg, result_payload


def add_api_parser(top) -> None:
    api = top.add_parser("api", help="URL-based API surface guard")
    api_sub = api.add_subparsers(dest="command", required=True)
    api_check = api_sub.add_parser("check", help="scan a repository and fail on forbidden API usage")
    api_check.add_argument("--root", default=".", help="repository root path")
    api_check.add_argument("--policy", required=True, help="YAML policy path")
    api_check.add_argument("--json", action="store_true", help="emit JSON")

def api_finding_payload(finding: object) -> dict[str, object]:
    return annotate_finding(
        "api",
        {
            "path": getattr(finding, "path", ""),
            "line": getattr(finding, "line", 0),
            "category": "forbidden_api",
        },
    )



def run_api_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = resolve_policy_arg(args.policy, root)

    try:
        policy = load_yaml_policy(policy_path)
        findings, scanned_count = scan_urls_with_count(root=root, policy=policy)
    except Exception as exc:
        payload = result_payload(
            scanner="api",
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

    if findings:
        payload = result_payload(
            scanner="api",
            status="violation",
            exit_code=1,
            policy_arg=args.policy,
            root=root,
            findings=[api_finding_payload(finding) for finding in findings],
            scanned_count=scanned_count,
            scanned_unit="files",
        )
        if args.json:
            print(json.dumps(payload, allow_nan=False, ensure_ascii=False))
        else:
            print(f"FAILED: {len(findings)} forbidden API endpoint(s) detected")
            for finding in findings:
                print(f"  - {redact_public_text(finding.path)}:{finding.line} forbidden_api")
        return 1

    payload = result_payload(
        scanner="api",
        status="ok",
        exit_code=0,
        policy_arg=args.policy,
        root=root,
        findings=[],
        scanned_count=scanned_count,
        scanned_unit="files",
    )
    if args.json:
        print(json.dumps(payload, allow_nan=False, ensure_ascii=False))
    else:
        print("OK: API surface guard passed")
    return 0
