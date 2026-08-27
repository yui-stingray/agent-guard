# Where: src/agent_guard/cli/digest.py
# What: digest guard CLI parser and runner.
# Why: isolate digest pin checks from the legacy CLI module.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..bounded_repo_reader import DistinctInputBudget
from ..digest_guard import (
    ERROR_DIGEST_SCAN_LIMIT,
    MAX_DIGEST_DISTINCT_INPUT_BYTES,
    load_digest_policy,
    scan_digests,
)
from .common import (
    bounded_public_json,
    emit_public_output,
    bounded_public_line,
    redact_public_text,
    require_public_output_budget,
    resolve_policy_arg,
    result_payload,
)


def _emit_digest_payload(
    *,
    args: argparse.Namespace,
    root: Path,
    payload: dict[str, object],
    plain_text: str,
) -> bool:
    try:
        raw_output = (
            bounded_public_json(
                payload,
                error=ERROR_DIGEST_SCAN_LIMIT,
            )
            if args.json
            else require_public_output_budget(
                plain_text,
                error=ERROR_DIGEST_SCAN_LIMIT,
            )
        )
        rendered = bounded_public_line(
            raw_output,
            error=ERROR_DIGEST_SCAN_LIMIT,
        )
    except ValueError:
        fallback = result_payload(
            scanner="digest",
            status="error",
            exit_code=2,
            policy_arg=args.policy,
            root=root,
            error=ERROR_DIGEST_SCAN_LIMIT,
        )
        rendered = (
            json.dumps(fallback, allow_nan=False, ensure_ascii=False)
            if args.json
            else f"ERROR: {ERROR_DIGEST_SCAN_LIMIT}"
        )
        try:
            emit_public_output(f"{rendered}\n", error=ERROR_DIGEST_SCAN_LIMIT)
        except ValueError:
            pass
        return False
    try:
        emit_public_output(rendered, error=ERROR_DIGEST_SCAN_LIMIT)
    except ValueError:
        return False
    return True


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
        input_budget = DistinctInputBudget(max_bytes=MAX_DIGEST_DISTINCT_INPUT_BYTES)
        policy = load_digest_policy(policy_path, _input_budget=input_budget)
        findings, checked_files = scan_digests(
            root=root,
            policy=policy,
            _input_budget=input_budget,
        )
    except Exception as exc:
        payload = result_payload(
            scanner="digest",
            status="error",
            exit_code=2,
            policy_arg=args.policy,
            root=root,
            error=str(exc),
        )
        _emit_digest_payload(
            args=args,
            root=root,
            payload=payload,
            plain_text=f"ERROR: {payload.get('error', 'unknown error')}",
        )
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
    if findings:
        plain_lines = [f"digest-guard: NG ({len(findings)} findings)"]
        plain_lines.extend(
            f"- {redact_public_text(item.check_id)} {redact_public_text(item.path)} "
            f"{redact_public_text(item.message)}"
            for item in findings
        )
        plain_text = "\n".join(plain_lines)
    else:
        plain_text = f"digest-guard: OK ({checked_files} files checked)"
    if not _emit_digest_payload(
        args=args,
        root=root,
        payload=payload,
        plain_text=plain_text,
    ):
        return 2
    return exit_code
