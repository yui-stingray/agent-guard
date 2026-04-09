"""Where: src/agent_guard/cli.py
What: command-line interface for the agent-guard MVP.
Why: make the extracted scanners consumable from CI, hooks, and local debugging.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .api_guard import load_yaml_policy, scan_urls
from .content_guard import (
    build_rules,
    collect_new_targets,
    collect_preregister_targets,
    collect_registered_targets,
    load_content_policy,
    normalize_patterns,
    scan_paths,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="static repository guardrails for agent-touched repos")
    top = parser.add_subparsers(dest="scanner", required=True)

    api = top.add_parser("api", help="URL-based API surface guard")
    api_sub = api.add_subparsers(dest="command", required=True)
    api_check = api_sub.add_parser("check", help="scan a repository and fail on forbidden API usage")
    api_check.add_argument("--root", default=".", help="repository root path")
    api_check.add_argument("--policy", required=True, help="YAML policy path")
    api_check.add_argument("--json", action="store_true", help="emit JSON")

    content = top.add_parser("content", help="pattern-based content security guard")
    content_sub = content.add_subparsers(dest="command", required=True)
    content_check = content_sub.add_parser("check", help="scan text content and fail on forbidden patterns")
    content_check.add_argument("--repo-root", default=".", help="repository root path")
    content_check.add_argument("--policy", required=True, help="YAML policy path")
    content_check.add_argument("--mode", choices=("registered", "preregister", "new"), default="registered")
    content_check.add_argument("--scan-dir", default="skills", help="target directory for registered/new modes")
    content_check.add_argument("--targets", nargs="*", default=[], help="target files/dirs for preregister mode")
    content_check.add_argument("--since-ref", default="", help="base ref for new mode diff (e.g. origin/main)")
    content_check.add_argument("--no-untracked", action="store_true", help="exclude untracked files in new mode")
    content_check.add_argument("--json", action="store_true", help="emit JSON")

    return parser


def print_content_text(*, findings: list, scanned_files: int, mode: str) -> None:
    if not findings:
        print(f"content-security: OK ({scanned_files} files scanned, mode={mode})")
        return

    print(f"content-security: NG ({len(findings)} findings, mode={mode})")
    for item in findings:
        print(
            f"- {item.severity} {item.rule_id} {item.file}:{item.line} "
            f"{item.message} :: {item.snippet}"
        )


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


def run_content_check(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root).resolve()
    policy_path = Path(args.policy).resolve()

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
                since_ref=str(args.since_ref).strip(),
                include_untracked=not bool(args.no_untracked),
            )
        else:
            paths = collect_registered_targets(repo_root, Path(args.scan_dir), file_globs, exclude_globs)

        findings = scan_paths(paths, rules, repo_root)
    except Exception as exc:
        payload = {"status": "error", "scanner": "content", "error": str(exc)}
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"ERROR: {exc}")
        return 2

    payload = {
        "status": "ok" if not findings else "violation",
        "scanner": "content",
        "mode": args.mode,
        "scanned_files": len(paths),
        "finding_count": len(findings),
        "findings": [item.to_dict() for item in findings],
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print_content_text(findings=findings, scanned_files=len(paths), mode=args.mode)

    return 0 if not findings else 1


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.scanner == "api" and args.command == "check":
        return run_api_check(args)
    if args.scanner == "content" and args.command == "check":
        return run_content_check(args)

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
