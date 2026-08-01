# Where: src/agent_guard/cli/content.py
# What: content guard CLI parser and runner.
# Why: isolate content checks from the legacy CLI module.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..content_guard import (
    build_rules,
    collect_new_targets,
    collect_preregister_targets,
    collect_registered_targets,
    load_content_policy,
    normalize_patterns,
    scan_paths,
)
from ..taxonomy import annotate_finding
from .common import redact_public_text, resolve_policy_arg, result_payload


def add_content_parser(top) -> None:
    content = top.add_parser("content", help="pattern-based content security guard")
    content_sub = content.add_subparsers(dest="command", required=True)
    content_check = content_sub.add_parser("check", help="scan text content and fail on forbidden patterns")
    content_check.add_argument("--repo-root", default=".", help="repository root path")
    content_check.add_argument("--policy", required=True, help="YAML policy path")
    content_check.add_argument("--mode", choices=("registered", "preregister", "new"), default="registered")
    content_check.add_argument(
        "--scan-dir",
        default="skills",
        help="target directory for registered/new modes; must resolve under --repo-root",
    )
    content_check.add_argument("--targets", nargs="*", default=[], help="target files/dirs for preregister mode")
    content_check.add_argument("--since-ref", default="", help="base ref for new mode diff (e.g. origin/main)")
    content_check.add_argument("--no-untracked", action="store_true", help="exclude untracked files in new mode")
    content_check.add_argument("--json", action="store_true", help="emit JSON")

def print_content_text(*, findings: list, scanned_files: int, mode: str) -> None:
    if not findings:
        print(f"content-security: OK ({scanned_files} files scanned, mode={mode})")
        return

    print(f"content-security: NG ({len(findings)} findings, mode={mode})")
    for item in findings:
        print(f"- {item.severity} {item.rule_id} {redact_public_text(item.file)}:{item.line}")



def content_finding_payload(finding: object) -> dict[str, object]:
    return annotate_finding(
        "content",
        {
            "severity": getattr(finding, "severity", ""),
            "rule_id": getattr(finding, "rule_id", ""),
            "file": getattr(finding, "file", ""),
            "line": getattr(finding, "line", 0),
        },
    )



def run_content_check(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root).resolve()
    policy_path = resolve_policy_arg(args.policy, repo_root)

    try:
        policy = load_content_policy(policy_path)
        rules = build_rules(policy)
        file_globs = normalize_patterns(policy.get("file_globs", [])) or ["**/*.md"]
        exclude_globs = normalize_patterns(policy.get("exclude_globs", []))

        if args.mode == "preregister":
            paths = collect_preregister_targets(args.targets, file_globs, exclude_globs)
        elif args.mode == "new":
            paths = collect_new_targets(
                repo_root,
                Path(args.scan_dir),
                file_globs,
                exclude_globs,
                since_ref=str(args.since_ref),
                include_untracked=not bool(args.no_untracked),
            )
        else:
            paths = collect_registered_targets(repo_root, Path(args.scan_dir), file_globs, exclude_globs)

        findings = scan_paths(paths, rules, repo_root)
    except Exception as exc:
        payload = result_payload(
            scanner="content",
            status="error",
            exit_code=2,
            policy_arg=args.policy,
            root=repo_root,
            error=str(exc),
            error_paths=[str(args.scan_dir), *[str(target) for target in args.targets]],
            extra={"mode": args.mode},
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"ERROR: {payload.get('error', 'unknown error')}")
        return 2

    exit_code = 0 if not findings else 1
    payload = result_payload(
        scanner="content",
        status="ok" if not findings else "violation",
        exit_code=exit_code,
        policy_arg=args.policy,
        root=repo_root,
        findings=[content_finding_payload(item) for item in findings],
        scanned_count=len(paths),
        scanned_unit="files",
        extra={"mode": args.mode, "scanned_files": len(paths)},
    )
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print_content_text(findings=findings, scanned_files=len(paths), mode=args.mode)

    return 0 if not findings else 1
