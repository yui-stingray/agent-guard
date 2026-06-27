"""Where: src/agent_guard/cli.py
What: command-line interface for the agent-guard MVP.
Why: make the extracted scanners consumable from CI, hooks, and local debugging.
"""

from __future__ import annotations

import argparse
import json
import re
from importlib import metadata
from pathlib import Path, PureWindowsPath
from typing import Iterable

from . import __version__ as PACKAGE_VERSION
from .api_guard import iter_scan_files as iter_api_scan_files
from .api_guard import load_yaml_policy, normalize_string_list as normalize_api_string_list, scan_urls
from .context_guard import collect_context_inventory, load_context_policy, scan_context_files
from .content_guard import (
    build_rules,
    collect_new_targets,
    collect_preregister_targets,
    collect_registered_targets,
    load_content_policy,
    normalize_patterns,
    scan_paths,
)
from .digest_guard import load_digest_policy, scan_digests
from .path_guard import load_path_policy, scan_paths as scan_repo_paths
from .report import render_markdown_evidence_report
from .workflow_guard import load_workflow_policy, scan_workflow_policy

RESULT_SCHEMA_VERSION = "agent-guard.result.v1"
TOOL_NAME = "agent-guard"


def tool_version() -> str:
    if PACKAGE_VERSION:
        return PACKAGE_VERSION
    try:
        return metadata.version("yui-agent-guard")
    except metadata.PackageNotFoundError:
        return "0.0.0+local"


def safe_policy_path(raw_policy: str, root: Path) -> str:
    raw_text = str(raw_policy)
    if is_windows_absolute_path(raw_text):
        return PureWindowsPath(raw_text).name or "<external-policy>"

    raw = Path(str(raw_policy))
    if not raw.is_absolute():
        return raw.as_posix()

    resolved_root = root.resolve()
    resolved_policy = raw.resolve(strict=False)
    try:
        return resolved_policy.relative_to(resolved_root).as_posix()
    except ValueError:
        return resolved_policy.name or "<external-policy>"


def is_windows_absolute_path(raw_path: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:[\\/]", raw_path)) or raw_path.startswith("\\\\")


def scrub_error_path(raw_path: str, *, root: Path, policy_abs: Path, safe_policy: str) -> str:
    if is_windows_absolute_path(raw_path):
        return safe_policy if raw_path == str(policy_abs) else "<absolute-path>"

    path = Path(raw_path)
    if not path.is_absolute():
        return raw_path

    resolved_path = path.resolve(strict=False)
    if resolved_path == policy_abs:
        return safe_policy

    try:
        rel_path = resolved_path.relative_to(root.resolve())
    except ValueError:
        return "<absolute-path>"
    return "." if rel_path.as_posix() == "." else rel_path.as_posix()


def scrub_error_message(
    message: str,
    *,
    root: Path,
    policy_arg: str,
    extra_paths: Iterable[str] = (),
) -> str:
    safe_policy = safe_policy_path(policy_arg, root)
    policy_abs = Path(str(policy_arg)).resolve(strict=False)
    scrubbed = message

    for raw_path in (policy_arg, str(policy_abs), *extra_paths):
        raw_text = str(raw_path)
        if not raw_text:
            continue
        replacement = safe_policy if raw_text in {policy_arg, str(policy_abs)} else scrub_error_path(
            raw_text,
            root=root,
            policy_abs=policy_abs,
            safe_policy=safe_policy,
        )
        scrubbed = scrubbed.replace(raw_text, replacement)

    scrubbed = re.sub(
        r"(['\"])(/[^'\"]+)\1",
        lambda match: scrub_error_path(
            match.group(2),
            root=root,
            policy_abs=policy_abs,
            safe_policy=safe_policy,
        ),
        scrubbed,
    )
    scrubbed = re.sub(
        r"(?<![\w./:-])/(?:[^\s:'\"]+/)*[^\s:'\"]+",
        lambda match: scrub_error_path(
            match.group(0),
            root=root,
            policy_abs=policy_abs,
            safe_policy=safe_policy,
        ),
        scrubbed,
    )
    return re.sub(r"[A-Za-z]:\\(?:[^\\\s:'\"]+\\)*[^\\\s:'\"]*", "<absolute-path>", scrubbed)


def result_payload(
    *,
    scanner: str,
    status: str,
    exit_code: int,
    policy_arg: str,
    root: Path,
    findings: list[dict[str, object]] | None = None,
    scanned_count: int | None = None,
    scanned_unit: str | None = None,
    summary_extra: dict[str, object] | None = None,
    error: str | None = None,
    error_paths: Iterable[str] = (),
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    finding_items = findings or []
    summary: dict[str, object] = {"finding_count": len(finding_items)}
    if scanned_count is not None:
        summary["scanned_count"] = scanned_count
    if scanned_unit:
        summary["scanned_unit"] = scanned_unit
    if summary_extra:
        summary.update(summary_extra)

    payload: dict[str, object] = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": tool_version()},
        "scanner": scanner,
        "status": status,
        "exit_code": exit_code,
        "policy": {"path": safe_policy_path(policy_arg, root)},
        "summary": summary,
        "finding_count": len(finding_items),
        "findings": finding_items,
    }
    if extra:
        payload.update(extra)
    if error is not None:
        payload["error"] = scrub_error_message(error, root=root, policy_arg=policy_arg, extra_paths=error_paths)
    return payload


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

    path = top.add_parser("path", help="path-name guard for private artifacts and env-file leaks")
    path_sub = path.add_subparsers(dest="command", required=True)
    path_check = path_sub.add_parser("check", help="scan repository path names and fail on forbidden paths")
    path_check.add_argument("--root", default=".", help="repository root path")
    path_check.add_argument("--policy", required=True, help="YAML policy path")
    path_check.add_argument("--json", action="store_true", help="emit JSON")

    digest = top.add_parser("digest", help="SHA-256 pin guard for safety-critical files")
    digest_sub = digest.add_subparsers(dest="command", required=True)
    digest_check = digest_sub.add_parser("check", help="verify pinned SHA-256 digests")
    digest_check.add_argument("--root", default=".", help="repository root path")
    digest_check.add_argument("--policy", required=True, help="YAML policy path")
    digest_check.add_argument("--json", action="store_true", help="emit JSON")

    workflow = top.add_parser("workflow", help="workflow drift guard for declared repository gates")
    workflow_sub = workflow.add_subparsers(dest="command", required=True)
    workflow_check = workflow_sub.add_parser("check", help="verify required files and workflow commands")
    workflow_check.add_argument("--root", default=".", help="repository root path")
    workflow_check.add_argument("--policy", required=True, help="YAML policy path")
    workflow_check.add_argument("--json", action="store_true", help="emit JSON")

    report = top.add_parser("report", help="emit sanitized Markdown evidence for reviews")
    report.add_argument("--root", default=".", help="repository root path")
    report.add_argument("--context-policy", required=True, help="agent context YAML policy path")
    report.add_argument("--digest-policy", default="", help="optional digest YAML policy path for drift evidence")
    report.add_argument("--format", choices=("markdown",), default="markdown", help="report output format")

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
        scan_cfg = policy.get("scan", {}) if isinstance(policy.get("scan", {}), dict) else {}
        api_scan_files = list(
            iter_api_scan_files(
                root,
                normalize_api_string_list(scan_cfg.get("include", [])),
                normalize_api_string_list(scan_cfg.get("exclude", [])),
            )
        )
        findings = scan_urls(root=root, policy=policy)
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
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"ERROR: {exc}")
        return 2

    if findings:
        payload = result_payload(
            scanner="api",
            status="violation",
            exit_code=1,
            policy_arg=args.policy,
            root=root,
            findings=[finding.to_dict() for finding in findings],
            scanned_count=len(api_scan_files),
            scanned_unit="files",
        )
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

    payload = result_payload(
        scanner="api",
        status="ok",
        exit_code=0,
        policy_arg=args.policy,
        root=root,
        findings=[],
        scanned_count=len(api_scan_files),
        scanned_unit="files",
    )
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
            print(f"ERROR: {exc}")
        return 2

    exit_code = 0 if not findings else 1
    payload = result_payload(
        scanner="content",
        status="ok" if not findings else "violation",
        exit_code=exit_code,
        policy_arg=args.policy,
        root=repo_root,
        findings=[item.to_dict() for item in findings],
        scanned_count=len(paths),
        scanned_unit="files",
        extra={"mode": args.mode, "scanned_files": len(paths)},
    )
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print_content_text(findings=findings, scanned_files=len(paths), mode=args.mode)

    return 0 if not findings else 1


def run_context_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = Path(args.policy).resolve()

    try:
        policy = load_context_policy(policy_path)
        findings, scanned_files = scan_context_files(root=root, policy=policy)
    except Exception as exc:
        payload = result_payload(
            scanner="context",
            status="error",
            exit_code=2,
            policy_arg=args.policy,
            root=root,
            error=str(exc),
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"ERROR: {exc}")
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
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    elif findings:
        print(f"context-guard: NG ({len(findings)} findings)")
        for item in findings:
            print(f"- {item.severity} {item.rule_id} {item.file}:{item.line} {item.message}")
    else:
        print(f"context-guard: OK ({scanned_files} files scanned)")

    return 0 if not findings else 1


def run_context_inventory(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = Path(args.policy).resolve()

    try:
        policy = load_context_policy(policy_path)
        inventory = collect_context_inventory(root=root, policy=policy)
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
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"ERROR: {exc}")
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
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print(
            "context-inventory: OK "
            f"({len(inventory.context_files)} files, {inventory.evidence_count} evidence records)"
        )
    return 0


def run_report(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = Path(args.context_policy).resolve()
    digest_policy_arg = str(args.digest_policy).strip()

    try:
        policy = load_context_policy(policy_path)
        findings, scanned_files = scan_context_files(root=root, policy=policy)
        inventory = collect_context_inventory(root=root, policy=policy)
        digest_report: dict[str, object] | None = None
        if digest_policy_arg:
            digest_policy = load_digest_policy(Path(digest_policy_arg).resolve())
            digest_findings, checked_files = scan_digests(root=root, policy=digest_policy)
            digest_report = {
                "policy": {"path": safe_policy_path(digest_policy_arg, root)},
                "status": "ok" if not digest_findings else "violation",
                "checked_count": checked_files,
                "finding_count": len(digest_findings),
                "findings": [
                    {
                        "check_id": item.check_id,
                        "path": item.path,
                        "status": "missing" if item.actual_sha256 is None else "mismatch",
                        "message": item.message,
                    }
                    for item in digest_findings
                ],
            }
    except Exception as exc:
        payload = result_payload(
            scanner="context",
            status="error",
            exit_code=2,
            policy_arg=args.context_policy,
            root=root,
            error=str(exc),
            error_paths=[digest_policy_arg] if digest_policy_arg else (),
            extra={
                "command": "report",
                "report": {
                    "format": args.format,
                    "scope": "context+digest" if digest_policy_arg else "context",
                    "sanitized": True,
                },
                **(
                    {"digest": {"policy": {"path": safe_policy_path(digest_policy_arg, root)}}}
                    if digest_policy_arg
                    else {}
                ),
            },
        )
        print(render_markdown_evidence_report(payload), end="")
        return 2

    digest_finding_count = int(digest_report["finding_count"]) if digest_report else 0
    exit_code = 0 if not findings and digest_finding_count == 0 else 1
    payload = result_payload(
        scanner="context",
        status="ok" if exit_code == 0 else "violation",
        exit_code=exit_code,
        policy_arg=args.context_policy,
        root=root,
        findings=[
            {
                "file": item.file,
                "line": item.line,
                "rule_id": item.rule_id,
                "severity": item.severity,
            }
            for item in findings
        ],
        scanned_count=scanned_files,
        scanned_unit="files",
        summary_extra={
            "context_file_count": len(inventory.context_files),
            "evidence_count": inventory.evidence_count,
            **(
                {
                    "digest_checked_count": digest_report["checked_count"],
                    "digest_finding_count": digest_report["finding_count"],
                }
                if digest_report
                else {}
            ),
        },
        extra={
            "command": "report",
            "report": {
                "format": args.format,
                "scope": "context+digest" if digest_report else "context",
                "sanitized": True,
            },
            "scanned_files": scanned_files,
            "inventory": inventory.to_dict(),
            **({"digest": digest_report} if digest_report else {}),
        },
    )
    print(render_markdown_evidence_report(payload), end="")
    return exit_code


def run_path_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = Path(args.policy).resolve()

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
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"ERROR: {exc}")
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
        print(json.dumps(payload, ensure_ascii=False))
    elif findings:
        print(f"path-guard: NG ({len(findings)} findings)")
        for item in findings:
            print(f"- {item.severity} {item.rule_id} {item.path} {item.message}")
    else:
        print(f"path-guard: OK ({scanned_paths} paths scanned)")

    return 0 if not findings else 1


def run_digest_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = Path(args.policy).resolve()

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
            print(f"ERROR: {exc}")
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
            print(f"- {item.check_id} {item.path} {item.message}")
    else:
        print(f"digest-guard: OK ({checked_files} files checked)")

    return 0 if not findings else 1


def run_workflow_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = Path(args.policy).resolve()

    try:
        policy = load_workflow_policy(policy_path)
        findings, checked_items = scan_workflow_policy(root=root, policy=policy)
    except Exception as exc:
        payload = result_payload(
            scanner="workflow",
            status="error",
            exit_code=2,
            policy_arg=args.policy,
            root=root,
            error=str(exc),
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"ERROR: {exc}")
        return 2

    exit_code = 0 if not findings else 1
    payload = result_payload(
        scanner="workflow",
        status="ok" if not findings else "violation",
        exit_code=exit_code,
        policy_arg=args.policy,
        root=root,
        findings=[item.to_dict() for item in findings],
        scanned_count=checked_items,
        scanned_unit="checks",
        extra={"checked_items": checked_items},
    )
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    elif findings:
        print(f"workflow-guard: NG ({len(findings)} findings)")
        for item in findings:
            print(f"- {item.severity} {item.rule_id} {item.file} {item.message}")
    else:
        print(f"workflow-guard: OK ({checked_items} checks)")

    return 0 if not findings else 1


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.scanner == "api" and args.command == "check":
        return run_api_check(args)
    if args.scanner == "content" and args.command == "check":
        return run_content_check(args)
    if args.scanner == "context" and args.command == "check":
        return run_context_check(args)
    if args.scanner == "context" and args.command == "inventory":
        return run_context_inventory(args)
    if args.scanner == "report":
        return run_report(args)
    if args.scanner == "path" and args.command == "check":
        return run_path_check(args)
    if args.scanner == "digest" and args.command == "check":
        return run_digest_check(args)
    if args.scanner == "workflow" and args.command == "check":
        return run_workflow_check(args)

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
