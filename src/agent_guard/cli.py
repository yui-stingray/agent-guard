"""Where: src/agent_guard/cli.py
What: command-line interface for the agent-guard MVP.
Why: make the extracted scanner consumable from CI, hooks, and local debugging.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .api_guard import load_yaml_policy, scan_urls


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="static repository guardrails for agent-touched repos")
    top = parser.add_subparsers(dest="scanner", required=True)

    api = top.add_parser("api", help="URL-based API surface guard")
    api_sub = api.add_subparsers(dest="command", required=True)

    check = api_sub.add_parser("check", help="scan a repository and fail on forbidden API usage")
    check.add_argument("--root", default=".", help="repository root path")
    check.add_argument("--policy", required=True, help="YAML policy path")
    check.add_argument("--json", action="store_true", help="emit JSON")

    return parser


def run_api_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = Path(args.policy).resolve()

    try:
        policy = load_yaml_policy(policy_path)
        findings = scan_urls(root=root, policy=policy)
    except Exception as exc:
        payload = {"status": "error", "scanner": "api", "error": str(exc)}
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"ERROR: {exc}")
        return 2

    if findings:
        payload = {
            "status": "violation",
            "scanner": "api",
            "finding_count": len(findings),
            "findings": [finding.to_dict() for finding in findings],
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"FAILED: {len(findings)} forbidden API endpoint(s) detected")
            for finding in findings:
                print(
                    f"  - {finding.path}:{finding.line} {finding.url} "
                    f"(pattern: {finding.matched_forbidden_pattern})"
                )
        return 1

    payload = {"status": "ok", "scanner": "api", "finding_count": 0, "findings": []}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print("OK: API surface guard passed")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.scanner == "api" and args.command == "check":
        return run_api_check(args)

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
