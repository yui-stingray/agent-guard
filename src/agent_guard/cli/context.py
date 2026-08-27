# Where: src/agent_guard/cli/context.py
# What: context CLI parser and runners.
# Why: isolate context check, inventory, and lock commands from the legacy CLI module.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..bounded_repo_reader import DistinctInputBudget
from ..context_guard import (
    ERROR_CONTEXT_SCAN_LIMIT,
    MAX_CONTEXT_DISTINCT_INPUT_BYTES,
    collect_context_inventory,
    load_context_policy,
    scan_context_files,
    scan_context_files_with_inventory,
)
from ..context_lock import (
    build_context_digest_policy,
    check_context_digest_coverage,
    dump_digest_policy_yaml,
)
from ..digest_guard import load_digest_policy
from .common import (
    bounded_public_line,
    bounded_public_json,
    emit_public_output,
    redact_public_text,
    require_public_output_budget,
    resolve_policy_arg,
    result_payload,
    safe_policy_path,
)


def add_context_parser(top) -> None:
    context = top.add_parser("context", help="agent context file guard")
    context_sub = context.add_subparsers(dest="command", required=True)
    context_check = context_sub.add_parser("check", help="scan agent instruction files for unsafe directives")
    context_check.add_argument("--root", default=".", help="repository root path")
    context_check.add_argument("--policy", required=True, help="YAML policy path")
    context_check.add_argument("--json", action="store_true", help="emit JSON")
    context_inventory = context_sub.add_parser("inventory", help="emit redacted agent context inventory evidence")
    context_inventory.add_argument("--root", default=".", help="repository root path")
    context_inventory.add_argument("--policy", required=True, help="YAML policy path")
    context_inventory.add_argument("--json", action="store_true", help="emit JSON")
    context_lock = context_sub.add_parser("lock", help="emit digest policy checks for agent context files")
    context_lock.add_argument("--root", default=".", help="repository root path")
    context_lock.add_argument("--policy", required=True, help="agent context YAML policy path")
    context_lock.add_argument(
        "--check",
        action="store_true",
        help="verify discovered context files are covered by --digest-policy instead of emitting YAML",
    )
    context_lock.add_argument("--digest-policy", default="", help="digest YAML policy path for coverage checks")
    context_lock.add_argument("--json", action="store_true", help="emit JSON")


def _emit_context_payload(
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
                error=ERROR_CONTEXT_SCAN_LIMIT,
            )
            if args.json
            else require_public_output_budget(
                plain_text,
                error=ERROR_CONTEXT_SCAN_LIMIT,
            )
        )
        rendered = bounded_public_line(
            raw_output,
            error=ERROR_CONTEXT_SCAN_LIMIT,
        )
    except ValueError:
        command = str(payload.get("command", ""))
        fallback = result_payload(
            scanner="context",
            status="error",
            exit_code=2,
            policy_arg=args.policy,
            root=root,
            error=ERROR_CONTEXT_SCAN_LIMIT,
            extra={"command": command} if command else None,
        )
        rendered = (
            json.dumps(fallback, allow_nan=False, ensure_ascii=False)
            if args.json
            else f"ERROR: {ERROR_CONTEXT_SCAN_LIMIT}"
        )
        try:
            emit_public_output(f"{rendered}\n", error=ERROR_CONTEXT_SCAN_LIMIT)
        except ValueError:
            pass
        return False
    try:
        emit_public_output(rendered, error=ERROR_CONTEXT_SCAN_LIMIT)
    except ValueError:
        return False
    return True


def run_context_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = resolve_policy_arg(args.policy, root)

    try:
        input_budget = DistinctInputBudget(max_bytes=MAX_CONTEXT_DISTINCT_INPUT_BYTES)
        policy = load_context_policy(policy_path, _input_budget=input_budget)
        findings, scanned_files = scan_context_files(
            root=root,
            policy=policy,
            _input_budget=input_budget,
        )
    except Exception as exc:
        payload = result_payload(
            scanner="context",
            status="error",
            exit_code=2,
            policy_arg=args.policy,
            root=root,
            error=str(exc),
        )
        _emit_context_payload(
            args=args,
            root=root,
            payload=payload,
            plain_text=f"ERROR: {payload.get('error', 'unknown error')}",
        )
        return 2

    exit_code = 0 if not findings else 1
    payload = result_payload(
        scanner="context",
        status="ok" if not findings else "violation",
        exit_code=exit_code,
        policy_arg=args.policy,
        root=root,
        findings=[item.to_dict() for item in findings],
        scanned_count=scanned_files,
        scanned_unit="files",
        extra={"scanned_files": scanned_files},
    )
    plain_lines = (
        [
            f"context-guard: NG ({len(findings)} findings)",
            *[
                f"- {item.severity} {item.rule_id} "
                f"{redact_public_text(item.file)}:{item.line} "
                f"{redact_public_text(item.message)}"
                for item in findings
            ],
        ]
        if findings
        else [f"context-guard: OK ({scanned_files} files scanned)"]
    )
    if not _emit_context_payload(
        args=args,
        root=root,
        payload=payload,
        plain_text="\n".join(plain_lines),
    ):
        return 2

    return 0 if not findings else 1



def run_context_inventory(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = resolve_policy_arg(args.policy, root)

    try:
        input_budget = DistinctInputBudget(max_bytes=MAX_CONTEXT_DISTINCT_INPUT_BYTES)
        policy = load_context_policy(policy_path, _input_budget=input_budget)
        inventory = collect_context_inventory(
            root=root,
            policy=policy,
            _input_budget=input_budget,
        )
    except Exception as exc:
        payload = result_payload(
            scanner="context",
            status="error",
            exit_code=2,
            policy_arg=args.policy,
            root=root,
            error=str(exc),
            extra={"command": "inventory"},
        )
        _emit_context_payload(
            args=args,
            root=root,
            payload=payload,
            plain_text=f"ERROR: {payload.get('error', 'unknown error')}",
        )
        return 2

    payload = result_payload(
        scanner="context",
        status="ok",
        exit_code=0,
        policy_arg=args.policy,
        root=root,
        findings=[],
        scanned_count=len(inventory.context_files),
        scanned_unit="files",
        summary_extra={"evidence_count": inventory.evidence_count},
        extra={
            "command": "inventory",
            "scanned_files": len(inventory.context_files),
            "inventory": inventory.to_dict(),
        },
    )
    if not _emit_context_payload(
        args=args,
        root=root,
        payload=payload,
        plain_text=(
            "context-inventory: OK "
            f"({len(inventory.context_files)} files, "
            f"{inventory.evidence_count} evidence records)"
        ),
    ):
        return 2
    return 0



def run_context_lock(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = resolve_policy_arg(args.policy, root)
    digest_policy_arg = str(args.digest_policy).strip()

    try:
        if args.check and not digest_policy_arg:
            raise ValueError("context lock --check requires --digest-policy")
        if digest_policy_arg and not args.check:
            raise ValueError("context lock --digest-policy requires --check")
        input_budget = DistinctInputBudget(max_bytes=MAX_CONTEXT_DISTINCT_INPUT_BYTES)
        policy = load_context_policy(policy_path, _input_budget=input_budget)
        findings, scanned_files, inventory = scan_context_files_with_inventory(
            root=root,
            policy=policy,
            _input_budget=input_budget,
        )
        if findings:
            finding_items = [
                {
                    "file": item.file,
                    "line": item.line,
                    "rule_id": item.rule_id,
                    "severity": item.severity,
                }
                for item in findings
            ]
            payload = result_payload(
                scanner="context",
                status="violation",
                exit_code=1,
                policy_arg=args.policy,
                root=root,
                findings=finding_items,
                scanned_count=scanned_files,
                scanned_unit="files",
                extra={"command": "lock", "scanned_files": scanned_files},
            )
            plain_text = "\n".join(
                [
                    f"context-lock: NG ({len(findings)} findings)",
                    *[
                        f"- {item['severity']} {item['rule_id']} "
                        f"{redact_public_text(str(item['file']))}:{item['line']}"
                        for item in finding_items
                    ],
                ]
            )
            if not _emit_context_payload(
                args=args,
                root=root,
                payload=payload,
                plain_text=plain_text,
            ):
                return 2
            return 1
        lock_input_budget = input_budget.next_read_pass()
        if args.check:
            digest_policy = load_digest_policy(
                resolve_policy_arg(digest_policy_arg, root),
                _input_budget=lock_input_budget,
            )
            coverage = check_context_digest_coverage(
                root=root,
                inventory=inventory,
                digest_policy=digest_policy,
                _input_budget=lock_input_budget,
            )
            coverage_findings = coverage.get("findings", [])
            finding_items = coverage_findings if isinstance(coverage_findings, list) else []
            exit_code = 0 if coverage.get("status") == "ok" else 1
            payload = result_payload(
                scanner="context",
                status="ok" if exit_code == 0 else "violation",
                exit_code=exit_code,
                policy_arg=args.policy,
                root=root,
                findings=finding_items,
                scanned_count=int(coverage.get("context_file_count", len(inventory.context_files))),
                scanned_unit="context_files",
                summary_extra={
                    "covered_count": coverage.get("covered_count", 0),
                    "coverage_finding_count": coverage.get("finding_count", 0),
                },
                extra={
                    "command": "lock",
                    "lock_mode": "coverage",
                    "digest_policy": {"path": safe_policy_path(digest_policy_arg, root)},
                    "coverage": coverage,
                },
            )
            if exit_code == 0:
                plain_text = (
                    "context-lock: OK "
                    f"({coverage.get('covered_count', 0)}/"
                    f"{coverage.get('context_file_count', 0)} context files covered)"
                )
            else:
                plain_text = "\n".join(
                    [
                        (
                            "context-lock: NG "
                            f"({coverage.get('finding_count', 0)} coverage findings)"
                        ),
                        *[
                            f"- {item.get('severity', 'high')} "
                            f"{item.get('rule_id', '-')} "
                            f"{redact_public_text(str(item.get('path', '-')))} "
                            f"{item.get('status', '-')}"
                            for item in finding_items
                        ],
                    ]
                )
            if not _emit_context_payload(
                args=args,
                root=root,
                payload=payload,
                plain_text=plain_text,
            ):
                return 2
            return exit_code
        digest_policy = build_context_digest_policy(
            root=root,
            inventory=inventory,
            _input_budget=lock_input_budget,
        )
    except Exception as exc:
        error_paths = [digest_policy_arg] if digest_policy_arg else []
        payload = result_payload(
            scanner="context",
            status="error",
            exit_code=2,
            policy_arg=args.policy,
            root=root,
            error=str(exc),
            error_paths=error_paths,
            extra={
                "command": "lock",
                **({"lock_mode": "coverage"} if args.check else {}),
                **(
                    {"digest_policy": {"path": safe_policy_path(digest_policy_arg, root)}}
                    if digest_policy_arg
                    else {}
                ),
            },
        )
        _emit_context_payload(
            args=args,
            root=root,
            payload=payload,
            plain_text=f"ERROR: {payload.get('error', 'unknown error')}",
        )
        return 2

    checks = digest_policy.get("checks", [])
    checked_count = len(checks) if isinstance(checks, list) else 0
    payload = result_payload(
        scanner="context",
        status="ok",
        exit_code=0,
        policy_arg=args.policy,
        root=root,
        findings=[],
        scanned_count=checked_count,
        scanned_unit="context_files",
        summary_extra={"context_file_count": len(inventory.context_files)},
        extra={
            "command": "lock",
            "digest_policy": digest_policy,
        },
    )
    if not _emit_context_payload(
        args=args,
        root=root,
        payload=payload,
        plain_text=dump_digest_policy_yaml(digest_policy).rstrip("\n"),
    ):
        return 2
    return 0
