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
from .context_lock import (
    build_context_digest_policy,
    check_context_digest_coverage,
    dump_digest_policy_yaml,
)
from .content_guard import (
    build_rules,
    collect_new_targets,
    collect_preregister_targets,
    collect_registered_targets,
    load_content_policy,
    normalize_patterns,
    scan_paths,
)
from .conformance import build_conformance_report
from .digest_guard import load_digest_policy, scan_digests
from .drift_guard import build_policy_spec_drift_report
from .evidence_pack import build_evidence_pack_manifest
from .init_guard import build_init_plan, render_init_plan_text, write_init_plan
from .path_guard import load_path_policy, scan_paths as scan_repo_paths
from .profiles import PROFILE_NAMES
from .report import render_github_annotations_report, render_markdown_evidence_report
from .surface_inventory import collect_agent_surface_inventory
from .workflow_guard import load_workflow_policy, scan_workflow_policy

RESULT_SCHEMA_VERSION = "agent-guard.result.v1"
REPORT_EVIDENCE_SCHEMA_VERSION = "agent-guard.report_evidence.v1"
TOOL_NAME = "agent-guard"
RECOMMENDED_EVIDENCE_PRESET = "recommended"


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


def scrub_report_error_message(message: str) -> str:
    scrubbed = re.sub(
        r"(?im)^(\s*-?\s*['\"]?run['\"]?\s*:\s*).*$",
        r"\1<workflow-run>",
        message,
    )
    return re.sub(
        r"(invalid [^\n]* regex[^\n]*?: )(['\"])(?:\\.|(?!\2).)*\2(?=:)",
        r"\1<regex>",
        scrubbed,
    )


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

    init = top.add_parser("init", help="print or write review-first starter guard files")
    init.add_argument("--root", default=".", help="repository root path")
    init.add_argument("--print", action="store_true", help="print the planned starter files without writing")
    init.add_argument("--write", action="store_true", help="write starter files; refuses existing files unless --force")
    init.add_argument("--force", action="store_true", help="overwrite existing starter files when used with --write")
    init.add_argument("--json", action="store_true", help="emit JSON")

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

    surface = top.add_parser("surface", help="agent-facing repository surface inventory")
    surface_sub = surface.add_subparsers(dest="command", required=True)
    surface_inventory = surface_sub.add_parser("inventory", help="emit repo-local agent surface metadata")
    surface_inventory.add_argument("--root", default=".", help="repository root path")
    surface_inventory.add_argument("--context-policy", required=True, help="agent context YAML policy path")
    surface_inventory.add_argument("--schema-version", choices=("v1", "v2"), default="v1", help="inventory schema version")
    surface_inventory.add_argument("--json", action="store_true", help="emit JSON")

    drift = top.add_parser("drift", help="small policy/spec drift guard")
    drift_sub = drift.add_subparsers(dest="command", required=True)
    drift_check = drift_sub.add_parser("check", help="verify README, workflow, and .agent-guard policy alignment")
    drift_check.add_argument("--root", default=".", help="repository root path")
    drift_check.add_argument("--profile", choices=PROFILE_NAMES, default="recommended", help="conformance profile")
    drift_check.add_argument("--schema-version", choices=("v1", "v2"), default="v1", help="drift schema version")
    drift_check.add_argument("--json", action="store_true", help="emit JSON")

    conformance = top.add_parser("conformance", help="profile conformance over sanitized evidence")
    conformance_sub = conformance.add_subparsers(dest="command", required=True)
    conformance_check = conformance_sub.add_parser("check", help="evaluate an agent-guard report against a profile")
    conformance_check.add_argument("--root", default=".", help="repository root used for display-path scrubbing")
    conformance_check.add_argument("--evidence", required=True, help="agent-guard report JSON path")
    conformance_check.add_argument("--profile", choices=PROFILE_NAMES, default="recommended", help="conformance profile")
    conformance_check.add_argument("--json", action="store_true", help="emit JSON")

    evidence_pack = top.add_parser("evidence-pack", help="review evidence pack manifest")
    evidence_pack_sub = evidence_pack.add_subparsers(dest="command", required=True)
    evidence_pack_manifest = evidence_pack_sub.add_parser("manifest", help="emit a sanitized evidence pack manifest")
    evidence_pack_manifest.add_argument("--root", default=".", help="repository root used for display-path scrubbing")
    evidence_pack_manifest.add_argument("--report", required=True, help="agent-guard report JSON path")
    evidence_pack_manifest.add_argument("--artifact", action="append", default=[], help="optional repo-relative artifact path")
    evidence_pack_manifest.add_argument(
        "--agent-policy-audit-event",
        action="append",
        default=[],
        help="optional repo-relative agent-policy audit event artifact path",
    )
    evidence_pack_manifest.add_argument("--json", action="store_true", help="emit JSON")

    report = top.add_parser("report", help="emit sanitized evidence for reviews")
    report.add_argument("--root", default=".", help="repository root path")
    report.add_argument("--context-policy", required=True, help="agent context YAML policy path")
    report.add_argument(
        "--evidence-preset",
        choices=(RECOMMENDED_EVIDENCE_PRESET,),
        default="",
        help="expand unset report options for a named adoption preset",
    )
    report.add_argument("--path-policy", default="", help="optional path YAML policy path for path-name evidence")
    report.add_argument("--content-policy", default="", help="optional content YAML policy path for content evidence")
    report.add_argument(
        "--content-scan-dir",
        default=".",
        help="repository-relative directory for content report evidence (registered mode only)",
    )
    report.add_argument("--api-policy", default="", help="optional API YAML policy path for API surface evidence")
    report.add_argument("--digest-policy", default="", help="optional digest YAML policy path for drift evidence")
    report.add_argument("--workflow-policy", default="", help="optional workflow YAML policy path for drift evidence")
    report.add_argument(
        "--drift-check",
        action="store_true",
        help="include policy/spec drift evidence for README, workflow, and guard policy alignment",
    )
    report.add_argument("--drift-profile", choices=PROFILE_NAMES, default="", help="profile for --drift-check")
    report.add_argument("--drift-schema-version", choices=("v1", "v2"), default="", help="drift evidence schema version")
    report.add_argument(
        "--surface-inventory-version",
        choices=("v1", "v2"),
        default="",
        help="surface inventory schema version embedded in the report",
    )
    report.add_argument("--conformance-profile", choices=PROFILE_NAMES, default="", help="embed conformance evidence")
    report.add_argument(
        "--evidence-pack-manifest",
        action="store_true",
        help="embed a sanitized evidence pack manifest for PR review",
    )
    report.add_argument(
        "--agent-policy-audit-event",
        action="append",
        default=[],
        help="optional repo-relative agent-policy audit event artifact path for the embedded evidence-pack manifest",
    )
    report.add_argument(
        "--format",
        choices=("markdown", "json", "github-annotations"),
        default="markdown",
        help="report output format",
    )
    report.add_argument("--output", default="", help="optional output path; stdout when omitted")

    return parser


def render_report_output(payload: dict[str, object], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n"
    if output_format == "github-annotations":
        return render_github_annotations_report(payload)
    return render_markdown_evidence_report(payload)


def emit_report_output(rendered: str, output_path: str) -> None:
    output = str(output_path).strip()
    if not output:
        print(rendered, end="")
        return

    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")


def output_json_or_text(*, payload: dict[str, object], text: str, emit_json: bool) -> None:
    if emit_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(text, end="" if text.endswith("\n") else "\n")


def run_init(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    try:
        if args.print and args.write:
            raise ValueError("init --print cannot be combined with --write")
        if args.write:
            plan, exit_code = write_init_plan(root=root, force=bool(args.force))
            text = render_init_plan_text(plan, include_content=False)
        else:
            plan = build_init_plan(root=root, force=bool(args.force))
            exit_code = 0
            text = render_init_plan_text(plan, include_content=True)
    except Exception as exc:
        payload = {
            "schema_version": "agent-guard.init_plan.v1",
            "mode": "write" if args.write else "print",
            "status": "error",
            "error": scrub_error_message(str(exc), root=root, policy_arg=".agent-guard/init"),
        }
        output_json_or_text(payload=payload, text=f"ERROR: {payload['error']}\n", emit_json=bool(args.json))
        return 2

    output_json_or_text(payload=plan, text=text, emit_json=bool(args.json))
    return exit_code


def run_surface_inventory(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    try:
        policy = load_context_policy(Path(args.context_policy).resolve())
        inventory = collect_agent_surface_inventory(
            root=root,
            context_policy=policy,
            schema_version=args.schema_version,
        )
    except Exception as exc:
        payload = result_payload(
            scanner="surface",
            status="error",
            exit_code=2,
            policy_arg=args.context_policy,
            root=root,
            error=str(exc),
            extra={"command": "inventory"},
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"ERROR: {payload.get('error', 'unknown error')}")
        return 2

    surface_count = int(inventory.get("summary", {}).get("surface_count", 0)) if isinstance(
        inventory.get("summary"), dict
    ) else 0
    payload = result_payload(
        scanner="surface",
        status="ok",
        exit_code=0,
        policy_arg=args.context_policy,
        root=root,
        findings=[],
        scanned_count=surface_count,
        scanned_unit="surfaces",
        summary_extra={"surface_count": surface_count},
        extra={"command": "inventory", "surface_inventory": inventory},
    )
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(f"surface-inventory: OK ({surface_count} surfaces)")
    return 0


def run_drift_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    try:
        report = build_policy_spec_drift_report(
            root=root,
            profile=args.profile,
            schema_version=args.schema_version,
        )
    except Exception as exc:
        payload = result_payload(
            scanner="drift",
            status="error",
            exit_code=2,
            policy_arg=".agent-guard/workflow-policy.yaml",
            root=root,
            error=str(exc),
            extra={"command": "check"},
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            print(f"ERROR: {payload.get('error', 'unknown error')}")
        return 2
    findings = report.get("findings", [])
    finding_items = findings if isinstance(findings, list) else []
    exit_code = 0 if report.get("status") == "ok" else 1
    payload = result_payload(
        scanner="drift",
        status="ok" if exit_code == 0 else "violation",
        exit_code=exit_code,
        policy_arg=".agent-guard/workflow-policy.yaml",
        root=root,
        findings=finding_items,
        scanned_count=int(report.get("checked_count", 0)),
        scanned_unit="checks",
        summary_extra={"drift_finding_count": int(report.get("finding_count", 0))},
        extra={"command": "check", "policy_spec_drift": report},
    )
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    elif exit_code == 0:
        print(f"drift-guard: OK ({report.get('checked_count', 0)} checks)")
    else:
        print(f"drift-guard: NG ({report.get('finding_count', 0)} findings)")
        for item in finding_items:
            finding = item if isinstance(item, dict) else {}
            print(
                f"- {finding.get('severity', 'medium')} {finding.get('rule_id', '-')} "
                f"{finding.get('file', '-')} {finding.get('reason', '-')}"
            )
    return exit_code


def load_json_file(path: Path) -> dict[str, object]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"JSON file must contain an object: {path}")
    return loaded


def run_conformance_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    evidence_path = Path(args.evidence).resolve()
    try:
        payload = load_json_file(evidence_path)
        conformance = build_conformance_report(
            profile=args.profile,
            evidence_coverage=payload.get("evidence_coverage", {}) if isinstance(payload, dict) else {},
            surface_inventory=payload.get("surface_inventory", {}) if isinstance(payload, dict) else {},
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
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        else:
            print(f"ERROR: {result.get('error', 'unknown error')}")
        return 2

    findings = conformance.get("findings", [])
    finding_items = findings if isinstance(findings, list) else []
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
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    elif exit_code == 0:
        print(f"conformance: OK ({conformance.get('profile', args.profile)})")
    else:
        print(f"conformance: NG ({conformance.get('finding_count', 0)} findings)")
        for item in finding_items:
            finding = item if isinstance(item, dict) else {}
            print(f"- {finding.get('severity', 'medium')} {finding.get('rule_id', '-')} {finding.get('requirement_id', '-')}")
    return exit_code


def run_evidence_pack_manifest(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    report_path = Path(args.report).resolve()
    try:
        payload = load_json_file(report_path)
        manifest = build_evidence_pack_manifest(
            report_payload=payload,
            artifact_paths=list(args.artifact or []),
            agent_policy_audit_event_paths=list(args.agent_policy_audit_event or []),
            root=root,
        )
    except Exception as exc:
        result = result_payload(
            scanner="evidence-pack",
            status="error",
            exit_code=2,
            policy_arg=args.report,
            root=root,
            error=str(exc),
            extra={"command": "manifest"},
        )
        if args.json:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        else:
            print(f"ERROR: {result.get('error', 'unknown error')}")
        return 2

    result = result_payload(
        scanner="evidence-pack",
        status="ok",
        exit_code=0,
        policy_arg=args.report,
        root=root,
        findings=[],
        scanned_count=len(manifest.get("gates", [])) if isinstance(manifest.get("gates"), list) else 0,
        scanned_unit="gates",
        extra={"command": "manifest", "evidence_pack_manifest": manifest},
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(json.dumps(manifest, ensure_ascii=False, sort_keys=True))
    return 0


def apply_report_evidence_preset(args: argparse.Namespace) -> None:
    if args.evidence_preset != RECOMMENDED_EVIDENCE_PRESET:
        return
    root = Path(args.root)
    policy_dir = root / ".agent-guard"
    if not str(args.path_policy).strip():
        args.path_policy = str(policy_dir / "path-policy.yaml")
    if not str(args.content_policy).strip():
        args.content_policy = str(policy_dir / "content-policy.yaml")
    if not str(args.workflow_policy).strip():
        args.workflow_policy = str(policy_dir / "workflow-policy.yaml")
    args.drift_check = True
    if not str(args.drift_profile).strip():
        args.drift_profile = RECOMMENDED_EVIDENCE_PRESET
    if not str(args.drift_schema_version).strip():
        args.drift_schema_version = "v2"
    if not str(args.surface_inventory_version).strip():
        args.surface_inventory_version = "v2"
    if not str(args.conformance_profile).strip():
        args.conformance_profile = RECOMMENDED_EVIDENCE_PRESET
    args.evidence_pack_manifest = True


def apply_report_defaults(args: argparse.Namespace) -> None:
    if not str(args.drift_profile).strip():
        args.drift_profile = RECOMMENDED_EVIDENCE_PRESET
    if not str(args.drift_schema_version).strip():
        args.drift_schema_version = "v1"
    if not str(args.surface_inventory_version).strip():
        args.surface_inventory_version = "v1"


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


def run_context_lock(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = Path(args.policy).resolve()
    digest_policy_arg = str(args.digest_policy).strip()

    try:
        if args.check and not digest_policy_arg:
            raise ValueError("context lock --check requires --digest-policy")
        if digest_policy_arg and not args.check:
            raise ValueError("context lock --digest-policy requires --check")
        policy = load_context_policy(policy_path)
        findings, scanned_files = scan_context_files(root=root, policy=policy)
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
            if args.json:
                print(json.dumps(payload, ensure_ascii=False))
            else:
                print(f"context-lock: NG ({len(findings)} findings)")
                for item in finding_items:
                    print(
                        f"- {item['severity']} {item['rule_id']} "
                        f"{item['file']}:{item['line']}"
                    )
            return 1
        inventory = collect_context_inventory(root=root, policy=policy)
        if args.check:
            digest_policy = load_digest_policy(Path(digest_policy_arg).resolve())
            coverage = check_context_digest_coverage(
                root=root,
                inventory=inventory,
                digest_policy=digest_policy,
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
            if args.json:
                print(json.dumps(payload, ensure_ascii=False))
            elif exit_code == 0:
                print(
                    "context-lock: OK "
                    f"({coverage.get('covered_count', 0)}/"
                    f"{coverage.get('context_file_count', 0)} context files covered)"
                )
            else:
                print(
                    "context-lock: NG "
                    f"({coverage.get('finding_count', 0)} coverage findings)"
                )
                for item in finding_items:
                    print(
                        f"- {item.get('severity', 'high')} {item.get('rule_id', '-')} "
                        f"{item.get('path', '-')} {item.get('status', '-')}"
                    )
            return exit_code
        digest_policy = build_context_digest_policy(root=root, inventory=inventory)
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
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"ERROR: {payload.get('error', 'unknown error')}")
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
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print(dump_digest_policy_yaml(digest_policy), end="")
    return 0


def report_scope(
    *,
    path_enabled: bool,
    content_enabled: bool,
    api_enabled: bool,
    digest_enabled: bool,
    workflow_enabled: bool,
    drift_enabled: bool = False,
) -> str:
    parts = ["context"]
    if path_enabled:
        parts.append("path")
    if content_enabled:
        parts.append("content")
    if api_enabled:
        parts.append("api")
    if digest_enabled:
        parts.append("digest")
    if workflow_enabled:
        parts.append("workflow")
    if drift_enabled:
        parts.append("drift")
    return "+".join(parts)


def gate_entry(
    *,
    gate: str,
    status: str,
    checked_count: int = 0,
    finding_count: int = 0,
    policy_path: str = "",
) -> dict[str, object]:
    entry: dict[str, object] = {
        "gate": gate,
        "status": status,
        "checked_count": checked_count,
        "finding_count": finding_count,
    }
    if policy_path:
        entry["policy"] = {"path": policy_path}
    return entry


def report_status(value: object) -> str:
    if isinstance(value, dict):
        return str(value.get("status", "missing"))
    return "missing"


def report_checked_count(value: object) -> int:
    if isinstance(value, dict):
        return int(value.get("checked_count", 0))
    return 0


def report_finding_count(value: object) -> int:
    if isinstance(value, dict):
        return int(value.get("finding_count", 0))
    return 0


def report_policy_path(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    policy = value.get("policy", {})
    if not isinstance(policy, dict):
        return ""
    return str(policy.get("path", ""))


def build_evidence_coverage(
    *,
    context_policy_path: str,
    scanned_files: int,
    context_finding_count: int,
    inventory_surface_count: int,
    path_report: dict[str, object] | None,
    content_report: dict[str, object] | None,
    api_report: dict[str, object] | None,
    context_lock_report: dict[str, object] | None,
    digest_report: dict[str, object] | None,
    workflow_report: dict[str, object] | None,
    drift_report: dict[str, object] | None,
) -> dict[str, object]:
    gates = [
        gate_entry(
            gate="context",
            status="violation" if context_finding_count else "ok",
            checked_count=scanned_files,
            finding_count=context_finding_count,
            policy_path=context_policy_path,
        ),
        gate_entry(
            gate="surface_inventory",
            status="ok",
            checked_count=inventory_surface_count,
            finding_count=0,
            policy_path=context_policy_path,
        ),
    ]
    optional_reports = (
        ("path", path_report),
        ("content", content_report),
        ("api", api_report),
        ("context_lock", context_lock_report),
        ("digest", digest_report),
        ("workflow", workflow_report),
        ("policy_spec_drift", drift_report),
    )
    for gate, report in optional_reports:
        if report is None:
            gates.append(gate_entry(gate=gate, status="missing"))
            continue
        gates.append(
            gate_entry(
                gate=gate,
                status=report_status(report),
                checked_count=report_checked_count(report),
                finding_count=report_finding_count(report),
                policy_path=report_policy_path(report),
            )
        )

    enabled = [item for item in gates if item.get("status") != "missing"]
    failing = [
        item for item in enabled if item.get("status") not in {"ok", "missing"}
    ]
    missing = [item for item in gates if item.get("status") == "missing"]
    return {
        "schema_version": "agent-guard.evidence_coverage.v1",
        "gate_count": len(gates),
        "enabled_count": len(enabled),
        "missing_count": len(missing),
        "failing_count": len(failing),
        "gates": gates,
    }


def build_api_report(*, root: Path, policy_arg: str) -> dict[str, object]:
    policy = load_yaml_policy(Path(policy_arg).resolve())
    scan_cfg = policy.get("scan", {}) if isinstance(policy.get("scan", {}), dict) else {}
    api_scan_files = list(
        iter_api_scan_files(
            root,
            normalize_api_string_list(scan_cfg.get("include", [])),
            normalize_api_string_list(scan_cfg.get("exclude", [])),
        )
    )
    findings = scan_urls(root=root, policy=policy)
    return {
        "policy": {"path": safe_policy_path(policy_arg, root)},
        "status": "ok" if not findings else "violation",
        "checked_count": len(api_scan_files),
        "finding_count": len(findings),
        "findings": [
            {
                "path": item.path,
                "line": item.line,
                "category": "forbidden_api",
            }
            for item in findings
        ],
    }


def build_content_report(*, root: Path, policy_arg: str, scan_dir_arg: str) -> dict[str, object]:
    scan_dir = Path(scan_dir_arg)
    target_root = scan_dir if scan_dir.is_absolute() else root / scan_dir
    target_root = target_root.resolve()
    try:
        relative_scan_dir = target_root.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError("content scan dir must stay under report root") from exc

    policy = load_content_policy(Path(policy_arg).resolve())
    rules = build_rules(policy)
    file_globs = normalize_patterns(policy.get("file_globs", [])) or ["**/*.md"]
    exclude_globs = normalize_patterns(policy.get("exclude_globs", []))
    paths = collect_registered_targets(root, target_root, file_globs, exclude_globs)
    findings = scan_paths(paths, rules, root)
    return {
        "policy": {"path": safe_policy_path(policy_arg, root)},
        "status": "ok" if not findings else "violation",
        "mode": "registered",
        "scan_dir": "." if relative_scan_dir == "." else relative_scan_dir,
        "checked_count": len(paths),
        "finding_count": len(findings),
        "findings": [
            {
                "severity": item.severity,
                "rule_id": item.rule_id,
                "file": item.file,
                "line": item.line,
            }
            for item in findings
        ],
    }


def build_path_report(*, root: Path, policy_arg: str) -> dict[str, object]:
    policy = load_path_policy(Path(policy_arg).resolve())
    findings, scanned_paths = scan_repo_paths(root=root, policy=policy)
    return {
        "policy": {"path": safe_policy_path(policy_arg, root)},
        "status": "ok" if not findings else "violation",
        "checked_count": scanned_paths,
        "finding_count": len(findings),
        "findings": [
            {
                "severity": item.severity,
                "rule_id": item.rule_id,
                "path": item.path,
            }
            for item in findings
        ],
    }


def safe_report_scan_dir(raw_scan_dir: str, root: Path, policy_abs: Path, safe_policy: str) -> str:
    scan_dir = Path(raw_scan_dir)
    if not scan_dir.is_absolute():
        return raw_scan_dir
    return scrub_error_path(
        raw_scan_dir,
        root=root,
        policy_abs=policy_abs,
        safe_policy=safe_policy,
    )


def build_context_lock_report(
    *,
    root: Path,
    inventory: object,
    digest_policy: dict[str, object],
    digest_policy_arg: str,
) -> dict[str, object]:
    coverage = check_context_digest_coverage(
        root=root,
        inventory=inventory,
        digest_policy=digest_policy,
    )
    return {
        "policy": {"path": safe_policy_path(digest_policy_arg, root)},
        "status": coverage["status"],
        "checked_count": coverage["context_file_count"],
        "covered_count": coverage["covered_count"],
        "covered": coverage.get("covered", []),
        "finding_count": coverage["finding_count"],
        "findings": coverage["findings"],
    }


def run_report(args: argparse.Namespace) -> int:
    apply_report_evidence_preset(args)
    apply_report_defaults(args)
    root = Path(args.root).resolve()
    policy_path = Path(args.context_policy).resolve()
    path_policy_arg = str(args.path_policy).strip()
    content_policy_arg = str(args.content_policy).strip()
    content_scan_dir_arg = str(args.content_scan_dir).strip() or "."
    api_policy_arg = str(args.api_policy).strip()
    digest_policy_arg = str(args.digest_policy).strip()
    workflow_policy_arg = str(args.workflow_policy).strip()
    safe_context_policy_path = safe_policy_path(args.context_policy, root)
    surface_inventory_version = args.surface_inventory_version
    scope = report_scope(
        path_enabled=bool(path_policy_arg),
        content_enabled=bool(content_policy_arg),
        api_enabled=bool(api_policy_arg),
        digest_enabled=bool(digest_policy_arg),
        workflow_enabled=bool(workflow_policy_arg),
        drift_enabled=bool(args.drift_check),
    )

    try:
        policy = load_context_policy(policy_path)
        findings, scanned_files = scan_context_files(root=root, policy=policy)
        inventory = collect_context_inventory(root=root, policy=policy)
        surface_inventory = collect_agent_surface_inventory(
            root=root,
            context_policy=policy,
            schema_version=surface_inventory_version,
        )
        path_report = build_path_report(root=root, policy_arg=path_policy_arg) if path_policy_arg else None
        content_report = (
            build_content_report(root=root, policy_arg=content_policy_arg, scan_dir_arg=content_scan_dir_arg)
            if content_policy_arg
            else None
        )
        api_report = build_api_report(root=root, policy_arg=api_policy_arg) if api_policy_arg else None
        context_lock_report: dict[str, object] | None = None
        digest_report: dict[str, object] | None = None
        if digest_policy_arg:
            digest_policy = load_digest_policy(Path(digest_policy_arg).resolve())
            context_lock_report = build_context_lock_report(
                root=root,
                inventory=inventory,
                digest_policy=digest_policy,
                digest_policy_arg=digest_policy_arg,
            )
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
        workflow_report: dict[str, object] | None = None
        if workflow_policy_arg:
            workflow_policy = load_workflow_policy(Path(workflow_policy_arg).resolve())
            workflow_findings, checked_items = scan_workflow_policy(root=root, policy=workflow_policy)
            workflow_report = {
                "policy": {"path": safe_policy_path(workflow_policy_arg, root)},
                "status": "ok" if not workflow_findings else "violation",
                "checked_count": checked_items,
                "finding_count": len(workflow_findings),
                "findings": [
                    {
                        "severity": item.severity,
                        "rule_id": item.rule_id,
                        "file": item.file,
                        "reason": item.reason,
                        "workflow_id": item.workflow_id or "",
                        "requirement_id": item.requirement_id or "",
                    }
                    for item in workflow_findings
                ],
            }
        drift_report: dict[str, object] | None = None
        if args.drift_check:
            drift_report = build_policy_spec_drift_report(
                root=root,
                profile=args.drift_profile,
                schema_version=args.drift_schema_version,
            )
    except Exception as exc:
        payload = result_payload(
            scanner="context",
            status="error",
            exit_code=2,
            policy_arg=args.context_policy,
            root=root,
            error=scrub_report_error_message(str(exc)),
            error_paths=[
                path
                for path in (
                    path_policy_arg,
                    content_policy_arg,
                    *([content_scan_dir_arg] if content_policy_arg else []),
                    api_policy_arg,
                    digest_policy_arg,
                    workflow_policy_arg,
                )
                if path
            ],
            extra={
            "command": "report",
            "report": {
                "schema_version": REPORT_EVIDENCE_SCHEMA_VERSION,
                "format": args.format,
                "scope": scope,
                    "sanitized": True,
                },
                **(
                    {"path": {"policy": {"path": safe_policy_path(path_policy_arg, root)}}}
                    if path_policy_arg
                    else {}
                ),
                **(
                    {
                        "content": {
                            "policy": {"path": safe_policy_path(content_policy_arg, root)},
                            "mode": "registered",
                            "scan_dir": safe_report_scan_dir(
                                content_scan_dir_arg,
                                root,
                                policy_path,
                                safe_context_policy_path,
                            ),
                        }
                    }
                    if content_policy_arg
                    else {}
                ),
                **(
                    {"api": {"policy": {"path": safe_policy_path(api_policy_arg, root)}}}
                    if api_policy_arg
                    else {}
                ),
                **(
                    {"digest": {"policy": {"path": safe_policy_path(digest_policy_arg, root)}}}
                    if digest_policy_arg
                    else {}
                ),
                **(
                    {"workflow": {"policy": {"path": safe_policy_path(workflow_policy_arg, root)}}}
                    if workflow_policy_arg
                    else {}
                ),
                **(
                    {
                        "policy_spec_drift": {
                            "schema_version": "agent-guard.policy_spec_drift.v1",
                            "status": "error",
                        }
                    }
                    if args.drift_check
                    else {}
                ),
            },
        )
        emit_report_output(render_report_output(payload, args.format), args.output)
        return 2

    path_finding_count = int(path_report["finding_count"]) if path_report else 0
    content_finding_count = int(content_report["finding_count"]) if content_report else 0
    api_finding_count = int(api_report["finding_count"]) if api_report else 0
    digest_finding_count = int(digest_report["finding_count"]) if digest_report else 0
    context_lock_finding_count = (
        int(context_lock_report["finding_count"]) if context_lock_report else 0
    )
    workflow_finding_count = int(workflow_report["finding_count"]) if workflow_report else 0
    drift_finding_count = int(drift_report["finding_count"]) if drift_report else 0
    exit_code = (
        0
        if not findings
        and path_finding_count == 0
        and content_finding_count == 0
        and api_finding_count == 0
        and context_lock_finding_count == 0
        and digest_finding_count == 0
        and workflow_finding_count == 0
        and drift_finding_count == 0
        else 1
    )
    surface_summary = surface_inventory.get("summary", {})
    inventory_surface_count = (
        int(surface_summary.get("surface_count", 0))
        if isinstance(surface_summary, dict)
        else 0
    )
    evidence_coverage = build_evidence_coverage(
        context_policy_path=safe_context_policy_path,
        scanned_files=scanned_files,
        context_finding_count=len(findings),
        inventory_surface_count=inventory_surface_count,
        path_report=path_report,
        content_report=content_report,
        api_report=api_report,
        context_lock_report=context_lock_report,
        digest_report=digest_report,
        workflow_report=workflow_report,
        drift_report=drift_report,
    )
    conformance_report: dict[str, object] | None = None
    if args.conformance_profile:
        conformance_report = build_conformance_report(
            profile=args.conformance_profile,
            evidence_coverage=evidence_coverage,
            surface_inventory=surface_inventory,
        )
        if int(conformance_report.get("finding_count", 0)) > 0:
            exit_code = 1
    evidence_pack_manifest: dict[str, object] | None = None
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
            "surface_count": inventory_surface_count,
            "coverage_enabled_count": evidence_coverage["enabled_count"],
            "coverage_missing_count": evidence_coverage["missing_count"],
            "coverage_failing_count": evidence_coverage["failing_count"],
            **(
                {
                    "conformance_checked_count": conformance_report["checked_count"],
                    "conformance_finding_count": conformance_report["finding_count"],
                }
                if conformance_report
                else {}
            ),
            **(
                {
                    "path_checked_count": path_report["checked_count"],
                    "path_finding_count": path_report["finding_count"],
                }
                if path_report
                else {}
            ),
            **(
                {
                    "content_checked_count": content_report["checked_count"],
                    "content_finding_count": content_report["finding_count"],
                }
                if content_report
                else {}
            ),
            **(
                {
                    "api_checked_count": api_report["checked_count"],
                    "api_finding_count": api_report["finding_count"],
                }
                if api_report
                else {}
            ),
            **(
                {
                    "context_lock_checked_count": context_lock_report["checked_count"],
                    "context_lock_covered_count": context_lock_report["covered_count"],
                    "context_lock_finding_count": context_lock_report["finding_count"],
                }
                if context_lock_report
                else {}
            ),
            **(
                {
                    "digest_checked_count": digest_report["checked_count"],
                    "digest_finding_count": digest_report["finding_count"],
                }
                if digest_report
                else {}
            ),
            **(
                {
                    "workflow_checked_count": workflow_report["checked_count"],
                    "workflow_finding_count": workflow_report["finding_count"],
                }
                if workflow_report
                else {}
            ),
            **(
                {
                    "drift_checked_count": drift_report["checked_count"],
                    "drift_finding_count": drift_report["finding_count"],
                }
                if drift_report
                else {}
            ),
        },
        extra={
            "command": "report",
            "report": {
                "schema_version": REPORT_EVIDENCE_SCHEMA_VERSION,
                "format": args.format,
                "scope": report_scope(
                    path_enabled=path_report is not None,
                    content_enabled=content_report is not None,
                    api_enabled=api_report is not None,
                    digest_enabled=digest_report is not None,
                    workflow_enabled=workflow_report is not None,
                    drift_enabled=drift_report is not None,
                ),
                "sanitized": True,
            },
            "scanned_files": scanned_files,
            "inventory": inventory.to_dict(),
            "surface_inventory": surface_inventory,
            "evidence_coverage": evidence_coverage,
            **({"conformance": conformance_report} if conformance_report else {}),
            **({"path": path_report} if path_report else {}),
            **({"content": content_report} if content_report else {}),
            **({"api": api_report} if api_report else {}),
            **({"context_lock": context_lock_report} if context_lock_report else {}),
            **({"digest": digest_report} if digest_report else {}),
            **({"workflow": workflow_report} if workflow_report else {}),
            **({"policy_spec_drift": drift_report} if drift_report else {}),
        },
    )
    if args.evidence_pack_manifest:
        artifact_paths = [str(args.output)] if str(args.output).strip() else None
        evidence_pack_manifest = build_evidence_pack_manifest(
            report_payload=payload,
            artifact_paths=artifact_paths,
            agent_policy_audit_event_paths=list(args.agent_policy_audit_event or []),
            root=root,
        )
        payload["evidence_pack_manifest"] = evidence_pack_manifest
    emit_report_output(render_report_output(payload, args.format), args.output)
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

    if args.scanner == "init":
        return run_init(args)
    if args.scanner == "api" and args.command == "check":
        return run_api_check(args)
    if args.scanner == "content" and args.command == "check":
        return run_content_check(args)
    if args.scanner == "context" and args.command == "check":
        return run_context_check(args)
    if args.scanner == "context" and args.command == "inventory":
        return run_context_inventory(args)
    if args.scanner == "context" and args.command == "lock":
        return run_context_lock(args)
    if args.scanner == "report":
        return run_report(args)
    if args.scanner == "path" and args.command == "check":
        return run_path_check(args)
    if args.scanner == "digest" and args.command == "check":
        return run_digest_check(args)
    if args.scanner == "workflow" and args.command == "check":
        return run_workflow_check(args)
    if args.scanner == "surface" and args.command == "inventory":
        return run_surface_inventory(args)
    if args.scanner == "drift" and args.command == "check":
        return run_drift_check(args)
    if args.scanner == "conformance" and args.command == "check":
        return run_conformance_check(args)
    if args.scanner == "evidence-pack" and args.command == "manifest":
        return run_evidence_pack_manifest(args)

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
