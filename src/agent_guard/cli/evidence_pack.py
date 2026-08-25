# Where: src/agent_guard/cli/evidence_pack.py
# What: evidence-pack CLI parser and runner.
# Why: isolate evidence pack manifest emission from the legacy CLI module.

from __future__ import annotations

import argparse
from pathlib import Path

from ..consumer import (
    select_report_schema,
    validate_agent_policy_audit_event_files,
    validate_report,
)
from ..evidence_pack import (
    build_agent_policy_audit_event_artifacts,
    build_evidence_pack_manifest,
)
from .common import (
    bounded_public_json,
    bounded_public_line,
    emit_public_output,
    load_json_file,
    result_payload,
)


ERROR_EVIDENCE_PACK_OUTPUT_LIMIT = "evidence-pack output exceeds configured limits"


def add_evidence_pack_parser(top) -> None:
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
    evidence_pack_manifest.add_argument(
        "--agent-policy-audit-event-profile",
        default="",
        help="recognized profile agent-guard.public_agent_policy_audit_event.v1 for every attached audit event",
    )
    evidence_pack_manifest.add_argument("--json", action="store_true", help="emit JSON")


def _emit_json_payload(payload: dict[str, object]) -> None:
    rendered = bounded_public_line(
        bounded_public_json(
            payload,
            error=ERROR_EVIDENCE_PACK_OUTPUT_LIMIT,
            sort_keys=True,
        ),
        error=ERROR_EVIDENCE_PACK_OUTPUT_LIMIT,
    )
    emit_public_output(rendered, error=ERROR_EVIDENCE_PACK_OUTPUT_LIMIT)


def _emit_evidence_pack_error(
    args: argparse.Namespace,
    *,
    root: Path,
    error: str,
) -> int:
    result = result_payload(
        scanner="evidence-pack",
        status="error",
        exit_code=2,
        policy_arg=args.report,
        root=root,
        error=error,
        extra={"command": "manifest"},
    )
    try:
        if args.json:
            _emit_json_payload(result)
        else:
            emit_public_output(
                bounded_public_line(
                    f"ERROR: {result.get('error', 'unknown error')}",
                    error=ERROR_EVIDENCE_PACK_OUTPUT_LIMIT,
                ),
                error=ERROR_EVIDENCE_PACK_OUTPUT_LIMIT,
            )
    except ValueError:
        pass
    return 2


def run_evidence_pack_manifest(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    report_path = Path(args.report).resolve()
    try:
        payload = load_json_file(report_path)
        audit_event_paths = list(args.agent_policy_audit_event or [])
        audit_event_artifacts = None
        if audit_event_paths:
            audit_event_artifacts = build_agent_policy_audit_event_artifacts(
                audit_event_paths,
                event_profile=str(args.agent_policy_audit_event_profile),
                root=root,
            )
        report_metadata = payload.get("report")
        is_v2_report = (
            isinstance(report_metadata, dict)
            and report_metadata.get("schema_version")
            == "agent-guard.report_evidence.v2"
        )
        if audit_event_paths or is_v2_report:
            validate_report(payload, select_report_schema(payload))
        if is_v2_report:
            validate_agent_policy_audit_event_files(
                payload,
                tuple(audit_event_paths),
                event_profile=str(args.agent_policy_audit_event_profile),
                repo_root=root,
            )
        manifest = build_evidence_pack_manifest(
            report_payload=payload,
            artifact_paths=list(args.artifact or []),
            agent_policy_audit_event_artifacts=audit_event_artifacts,
            agent_policy_audit_event_profile=str(args.agent_policy_audit_event_profile),
            root=root,
        )
    except Exception as exc:
        return _emit_evidence_pack_error(
            args,
            root=root,
            error=str(exc),
        )

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
    try:
        _emit_json_payload(result if args.json else manifest)
    except ValueError:
        return _emit_evidence_pack_error(
            args,
            root=root,
            error=ERROR_EVIDENCE_PACK_OUTPUT_LIMIT,
        )
    return 0
