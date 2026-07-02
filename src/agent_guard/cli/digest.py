# Where: src/agent_guard/cli/digest.py
# What: digest guard CLI parser and runner.
# Why: isolate digest pin checks from the legacy CLI module.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..digest_guard import load_digest_policy, scan_digests
from .common import redact_public_text, resolve_policy_arg, result_payload


def add_digest_parser(top) -> None:
    digest = top.add_parser("digest", help="SHA-256 pin guard for safety-critical files")
    digest_sub = digest.add_subparsers(dest="command", required=True)
    digest_check = digest_sub.add_parser("check", help="verify pinned SHA-256 digests")
    digest_check.add_argument("--root", default=".", help="repository root path")
    digest_check.add_argument("--policy", required=True, help="YAML policy path")
    digest_check.add_argument("--json", action="store_true", help="emit JSON")


def run_digest_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = resolve_policy_arg(args.policy, root)

    try:
        policy = load_digest_policy(policy_path)
        findings, checked_files = scan_digests(root=root, policy=policy)
    except Exception as exc:
        payload = result_payload(
            scanner="digest",
            status="error",
            exit_code=2,
            policy_arg=args.policy,
            root=root,
            error=str(exc),
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"ERROR: {payload.get('error', 'unknown error')}")
        return 2

    exit_code = 0 if not findings else 1
    payload = result_payload(
        scanner="digest",
        status="ok" if not findings else "violation",
        exit_code=exit_code,
        policy_arg=args.policy,
        root=root,
        findings=[item.to_dict() for item in findings],
        scanned_count=checked_files,
        scanned_unit="files",
        extra={"checked_files": checked_files},
    )
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    elif findings:
        print(f"digest-guard: NG ({len(findings)} findings)")
        for item in findings:
            print(
                f"- {item.check_id} {redact_public_text(item.path)} "
                f"{redact_public_text(item.message)}"
            )
    else:
        print(f"digest-guard: OK ({checked_files} files checked)")

    return 0 if not findings else 1

