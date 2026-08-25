# Where: src/agent_guard/cli/path.py
# What: path guard CLI parser and runner.
# Why: isolate path-name checks from the legacy CLI module.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..path_guard import load_path_policy, scan_paths as scan_repo_paths
from .common import redact_public_text, resolve_policy_arg, result_payload


def add_path_parser(top) -> None:
    path = top.add_parser("path", help="path-name guard for private artifacts and env-file leaks")
    path_sub = path.add_subparsers(dest="command", required=True)
    path_check = path_sub.add_parser("check", help="scan repository path names and fail on forbidden paths")
    path_check.add_argument("--root", default=".", help="repository root path")
    path_check.add_argument("--policy", required=True, help="YAML policy path")
    path_check.add_argument("--json", action="store_true", help="emit JSON")


def run_path_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = resolve_policy_arg(args.policy, root)

    try:
        policy = load_path_policy(policy_path)
        findings, scanned_paths = scan_repo_paths(root=root, policy=policy)
    except Exception as exc:
        payload = result_payload(
            scanner="path",
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
        scanner="path",
        status="ok" if not findings else "violation",
        exit_code=exit_code,
        policy_arg=args.policy,
        root=root,
        findings=[item.to_dict() for item in findings],
        scanned_count=scanned_paths,
        scanned_unit="paths",
        extra={"scanned_paths": scanned_paths},
    )
    if args.json:
        print(json.dumps(payload, allow_nan=False, ensure_ascii=False))
    elif findings:
        print(f"path-guard: NG ({len(findings)} findings)")
        for item in findings:
            print(
                f"- {item.severity} {item.rule_id} "
                f"{redact_public_text(item.path)} {redact_public_text(item.message)}"
            )
    else:
        print(f"path-guard: OK ({scanned_paths} paths scanned)")

    return 0 if not findings else 1
