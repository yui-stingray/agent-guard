"""Where: src/agent_guard/cli.py
What: command-line interface for the agent-guard MVP.
Why: make the extracted scanners consumable from CI, hooks, and local debugging.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .api_guard import iter_scan_files as iter_api_scan_files
from .api_guard import load_yaml_policy, normalize_string_list as normalize_api_string_list, scan_urls
from .cli.api import add_api_parser, api_finding_payload, run_api_check
from .cli.content import add_content_parser, content_finding_payload, run_content_check
from .cli.context import add_context_parser, run_context_check, run_context_inventory, run_context_lock
from .cli.common import (
    RECOMMENDED_EVIDENCE_PRESET,
    REPORT_EVIDENCE_SCHEMA_VERSION,
    redact_public_text,
    result_payload,
    resolve_policy_arg,
    safe_policy_path,
    safe_resolved_policy_path,
    sanitize_public_mapping,
    scrub_error_path,
    scrub_report_error_message,
)
from .context_guard import collect_context_inventory, load_context_policy, scan_context_files
from .context_lock import check_context_digest_coverage
from .content_guard import (
    build_rules,
    collect_registered_targets,
    load_content_policy,
    normalize_patterns,
    scan_paths,
)
from .conformance import build_conformance_report
from .digest_guard import load_digest_policy, scan_digests
from .drift_guard import build_policy_spec_drift_report
from .evidence_pack import build_evidence_pack_manifest
from .cli.conformance import add_conformance_parser, run_conformance_check
from .cli.evidence_pack import add_evidence_pack_parser, run_evidence_pack_manifest
from .cli.init import run_init
from .cli.path import add_path_parser, run_path_check
from .cli.digest import add_digest_parser, run_digest_check
from .cli.drift import add_drift_parser, run_drift_check
from .cli.workflow import add_workflow_parser, run_workflow_check
from .cli.mcp import add_mcp_parser, build_missing_mcp_policy_report, run_mcp_check
from .cli.render_report import add_render_report_parser, run_report_render
from .cli.surface import add_surface_parser, run_surface_inventory
from .mcp_guard import build_mcp_config_report, load_mcp_policy
from .path_guard import load_path_policy, scan_paths as scan_repo_paths
from .profiles import PROFILE_NAMES
from .report_render import emit_report_output, render_report_output
from .surface_inventory import collect_agent_surface_inventory
from .taxonomy import annotate_finding
from .workflow_guard import load_workflow_policy, scan_workflow_policy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="static repository guardrails for agent-touched repos")
    top = parser.add_subparsers(dest="scanner", required=True)

    init = top.add_parser("init", help="print or write review-first starter guard files")
    init.add_argument("--root", default=".", help="repository root path")
    init.add_argument("--print", action="store_true", help="print the planned starter files without writing")
    init.add_argument("--write", action="store_true", help="write starter files; refuses existing files unless --force")
    init.add_argument("--force", action="store_true", help="overwrite existing starter files when used with --write")
    init.add_argument("--json", action="store_true", help="emit JSON")

    add_api_parser(top)
    add_content_parser(top)

    add_context_parser(top)
    add_path_parser(top)
    add_digest_parser(top)
    add_workflow_parser(top)
    add_surface_parser(top)
    add_mcp_parser(top)

    add_drift_parser(top)
    add_conformance_parser(top)
    add_evidence_pack_parser(top)

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
        "--drift-base-ref",
        default="",
        help="optional git base ref passed to policy/spec drift evidence",
    )
    report.add_argument(
        "--surface-inventory-version",
        choices=("v1", "v2"),
        default="",
        help="surface inventory schema version embedded in the report",
    )
    report.add_argument(
        "--mcp-config-check",
        action="store_true",
        help="include static MCP configuration evidence derived from committed config metadata",
    )
    report.add_argument(
        "--mcp-policy",
        default="",
        help="optional MCP YAML policy path; implies --mcp-config-check",
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
        choices=("markdown", "json", "github-annotations", "sarif"),
        default="markdown",
        help="report output format",
    )
    report.add_argument("--output", default="", help="optional output path; stdout when omitted")

    add_render_report_parser(top)

    return parser


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
    args.mcp_config_check = True
    if not str(args.mcp_policy).strip():
        args.mcp_policy = ".agent-guard/mcp-policy.yaml"
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


def report_scope(
    *,
    path_enabled: bool,
    content_enabled: bool,
    api_enabled: bool,
    mcp_enabled: bool,
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
    if mcp_enabled:
        parts.append("mcp")
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
    mcp_report: dict[str, object] | None,
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
        ("mcp_config", mcp_report),
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
    policy = load_yaml_policy(resolve_policy_arg(policy_arg, root))
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
            api_finding_payload(item) for item in findings
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

    policy = load_content_policy(resolve_policy_arg(policy_arg, root))
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
            content_finding_payload(item) for item in findings
        ],
    }


def build_path_report(*, root: Path, policy_arg: str) -> dict[str, object]:
    policy = load_path_policy(resolve_policy_arg(policy_arg, root))
    findings, scanned_paths = scan_repo_paths(root=root, policy=policy)
    return {
        "policy": {"path": safe_policy_path(policy_arg, root)},
        "status": "ok" if not findings else "violation",
        "checked_count": scanned_paths,
        "finding_count": len(findings),
        "findings": [
            annotate_finding(
                "path",
                {
                    "severity": item.severity,
                    "rule_id": item.rule_id,
                    "path": redact_public_text(item.path),
                },
            )
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
        "findings": [
            annotate_finding("context_lock", item)
            for item in coverage["findings"]
            if isinstance(item, dict)
        ],
    }


def annotate_report_findings(scanner: str, report: dict[str, object] | None) -> dict[str, object] | None:
    if report is None:
        return None
    findings = report.get("findings")
    if not isinstance(findings, list):
        return report
    report["findings"] = [
        annotate_finding(scanner, item)
        for item in findings
        if isinstance(item, dict)
    ]
    report["finding_count"] = len(report["findings"])
    return report


def run_report(args: argparse.Namespace) -> int:
    explicit_mcp_policy_arg = bool(str(args.mcp_policy).strip())
    apply_report_evidence_preset(args)
    apply_report_defaults(args)
    root = Path(args.root).resolve()
    policy_path = resolve_policy_arg(args.context_policy, root)
    path_policy_arg = str(args.path_policy).strip()
    content_policy_arg = str(args.content_policy).strip()
    content_scan_dir_arg = str(args.content_scan_dir).strip() or "."
    api_policy_arg = str(args.api_policy).strip()
    mcp_policy_arg = str(args.mcp_policy).strip()
    mcp_policy_abs = resolve_policy_arg(mcp_policy_arg, root) if mcp_policy_arg else None
    mcp_policy_path = safe_resolved_policy_path(mcp_policy_abs, root) if mcp_policy_abs else ""
    implicit_recommended_mcp_policy_missing = (
        args.evidence_preset == RECOMMENDED_EVIDENCE_PRESET
        and not explicit_mcp_policy_arg
        and mcp_policy_abs is not None
        and not mcp_policy_abs.is_file()
    )
    if mcp_policy_arg:
        args.mcp_config_check = True
    digest_policy_arg = str(args.digest_policy).strip()
    workflow_policy_arg = str(args.workflow_policy).strip()
    safe_context_policy_path = safe_policy_path(args.context_policy, root)
    surface_inventory_version = args.surface_inventory_version
    scope = report_scope(
        path_enabled=bool(path_policy_arg),
        content_enabled=bool(content_policy_arg),
        api_enabled=bool(api_policy_arg),
        mcp_enabled=bool(args.mcp_config_check),
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
        mcp_policy = (
            None
            if implicit_recommended_mcp_policy_missing or mcp_policy_abs is None
            else load_mcp_policy(mcp_policy_abs)
        )
        mcp_report = (
            build_missing_mcp_policy_report(root=root, policy_path=mcp_policy_path)
            if implicit_recommended_mcp_policy_missing
            else build_mcp_config_report(
                root=root,
                policy=mcp_policy,
                policy_path=mcp_policy_path,
            )
            if args.mcp_config_check
            else None
        )
        context_lock_report: dict[str, object] | None = None
        digest_report: dict[str, object] | None = None
        if digest_policy_arg:
            digest_policy = load_digest_policy(resolve_policy_arg(digest_policy_arg, root))
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
                    annotate_finding(
                        "digest",
                        {
                            "check_id": item.check_id,
                            "path": item.path,
                            "status": "missing" if item.actual_sha256 is None else "mismatch",
                            "message": item.message,
                        },
                    )
                    for item in digest_findings
                ],
            }
        workflow_report: dict[str, object] | None = None
        if workflow_policy_arg:
            workflow_policy = load_workflow_policy(resolve_policy_arg(workflow_policy_arg, root))
            workflow_findings, checked_items = scan_workflow_policy(root=root, policy=workflow_policy)
            workflow_report = {
                "policy": {"path": safe_policy_path(workflow_policy_arg, root)},
                "status": "ok" if not workflow_findings else "violation",
                "checked_count": checked_items,
                "finding_count": len(workflow_findings),
                "findings": [
                    annotate_finding(
                        "workflow",
                        {
                            "severity": item.severity,
                            "rule_id": item.rule_id,
                            "file": item.file,
                            "reason": item.reason,
                            "workflow_id": item.workflow_id or "",
                            "requirement_id": item.requirement_id or "",
                        },
                    )
                    for item in workflow_findings
                ],
            }
        drift_report: dict[str, object] | None = None
        if args.drift_check:
            drift_report = build_policy_spec_drift_report(
                root=root,
                profile=args.drift_profile,
                schema_version=args.drift_schema_version,
                base_ref=args.drift_base_ref,
            )
            annotate_report_findings("policy_spec_drift", drift_report)
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
                    mcp_policy_arg,
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
                    {"mcp_config": {"policy": {"path": safe_policy_path(mcp_policy_arg, root)}}}
                    if mcp_policy_arg
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
    mcp_finding_count = int(mcp_report["finding_count"]) if mcp_report else 0
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
        and mcp_finding_count == 0
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
        mcp_report=mcp_report,
        context_lock_report=context_lock_report,
        digest_report=digest_report,
        workflow_report=workflow_report,
        drift_report=drift_report,
    )
    conformance_report: dict[str, object] | None = None
    payload = result_payload(
        scanner="context",
        status="ok" if exit_code == 0 else "violation",
        exit_code=exit_code,
        policy_arg=args.context_policy,
        root=root,
        findings=[
            annotate_finding(
                "context",
                {
                    "file": item.file,
                    "line": item.line,
                    "rule_id": item.rule_id,
                    "severity": item.severity,
                },
            )
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
                    "mcp_config_checked_count": mcp_report["checked_count"],
                    "mcp_config_finding_count": mcp_report["finding_count"],
                }
                if mcp_report
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
                    mcp_enabled=mcp_report is not None,
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
            **({"path": path_report} if path_report else {}),
            **({"content": content_report} if content_report else {}),
            **({"api": api_report} if api_report else {}),
            **({"mcp_config": mcp_report} if mcp_report else {}),
            **({"context_lock": context_lock_report} if context_lock_report else {}),
            **({"digest": digest_report} if digest_report else {}),
            **({"workflow": workflow_report} if workflow_report else {}),
            **({"policy_spec_drift": drift_report} if drift_report else {}),
        },
    )
    evidence_pack_manifest: dict[str, object] | None = None
    if args.evidence_pack_manifest:
        artifact_paths = [str(args.output)] if str(args.output).strip() else None
        evidence_pack_manifest = build_evidence_pack_manifest(
            report_payload=payload,
            artifact_paths=artifact_paths,
            agent_policy_audit_event_paths=list(args.agent_policy_audit_event or []),
            root=root,
        )
        payload["evidence_pack_manifest"] = evidence_pack_manifest
    if args.conformance_profile:
        conformance_report = build_conformance_report(
            profile=args.conformance_profile,
            evidence_coverage=evidence_coverage,
            surface_inventory=surface_inventory,
            report_payload=payload,
        )
        annotate_report_findings("conformance", conformance_report)
        payload["conformance"] = conformance_report
        summary = payload.get("summary", {})
        if isinstance(summary, dict):
            summary["conformance_checked_count"] = conformance_report["checked_count"]
            summary["conformance_finding_count"] = conformance_report["finding_count"]
        if int(conformance_report.get("finding_count", 0)) > 0:
            exit_code = 1
            payload["exit_code"] = exit_code
            payload["status"] = "violation"
        if args.evidence_pack_manifest:
            artifact_paths = [str(args.output)] if str(args.output).strip() else None
            evidence_pack_manifest = build_evidence_pack_manifest(
                report_payload=payload,
                artifact_paths=artifact_paths,
                agent_policy_audit_event_paths=list(args.agent_policy_audit_event or []),
                root=root,
            )
            payload["evidence_pack_manifest"] = evidence_pack_manifest
    payload = sanitize_public_mapping(payload)
    emit_report_output(render_report_output(payload, args.format), args.output)
    return exit_code


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
    if args.scanner == "render-report":
        return run_report_render(args)
    if args.scanner == "path" and args.command == "check":
        return run_path_check(args)
    if args.scanner == "digest" and args.command == "check":
        return run_digest_check(args)
    if args.scanner == "workflow" and args.command == "check":
        return run_workflow_check(args)
    if args.scanner == "surface" and args.command == "inventory":
        return run_surface_inventory(args)
    if args.scanner == "mcp" and args.command == "check":
        return run_mcp_check(args)
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
