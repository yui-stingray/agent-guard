# Where: src/agent_guard/cli/report_builders.py
# What: helper builders for report CLI evidence sections.
# Why: keep report command orchestration below the file budget without changing scanner behavior.

from __future__ import annotations

from pathlib import Path

from ..api_guard import iter_scan_files as iter_api_scan_files
from ..api_guard import load_yaml_policy, normalize_string_list as normalize_api_string_list, scan_urls
from ..content_guard import (
    build_rules,
    collect_registered_targets,
    load_content_policy,
    normalize_patterns,
    scan_paths,
)
from ..context_lock import check_context_digest_coverage
from ..path_guard import load_path_policy, scan_paths as scan_repo_paths
from ..taxonomy import annotate_finding
from .api import api_finding_payload
from .common import redact_public_text, resolve_policy_arg, safe_policy_path, scrub_error_path
from .content import content_finding_payload


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
