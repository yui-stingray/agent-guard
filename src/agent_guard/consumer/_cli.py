"""Where: src/agent_guard/consumer/_cli.py
What: command-line adapter for packaged evidence consumer validation.
Why: keep the example shim thin while preserving the old script behavior.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from ._bindings import validate_agent_policy_audit_event_files
from ._bundle import _validate_evidence_bundle
from ._report import validate_report
from ._schema import load_payload, select_report_schema


BUNDLE_VALIDATION_ERROR = "agent-guard evidence bundle invalid"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a sanitized agent-guard report JSON file.")
    parser.add_argument("report", type=Path, help="Path to agent-guard report JSON")
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="Validate an allowlisted public evidence bundle against the report",
    )
    parser.add_argument(
        "--emit-annotations",
        action="store_true",
        help="Emit only the canonical annotation bytes buffered while validating the bundle",
    )
    parser.add_argument(
        "--agent-policy-audit-event",
        action="append",
        default=[],
        type=Path,
        help="Audit-event file to verify against a bound manifest entry; repeat in manifest order",
    )
    parser.add_argument(
        "--agent-policy-audit-event-profile",
        default="",
        help="Expected recognized profile agent-policy.audit_event.v1.1 for every supplied event",
    )
    args = parser.parse_args(argv)
    if args.emit_annotations and args.evidence_dir is None:
        parser.error("--emit-annotations requires --evidence-dir")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    event_paths = tuple(args.agent_policy_audit_event or ())
    event_profile = str(args.agent_policy_audit_event_profile).strip()
    if args.evidence_dir is not None:
        try:
            summary, annotation_bytes = _validate_evidence_bundle(
                args.evidence_dir,
                args.report,
                agent_policy_audit_event_paths=event_paths,
                agent_policy_audit_event_profile=event_profile,
            )
        except Exception:
            print(BUNDLE_VALIDATION_ERROR, file=sys.stderr)
            return 1
        if args.emit_annotations:
            try:
                if annotation_bytes is not None:
                    sys.stdout.buffer.write(annotation_bytes)
                sys.stdout.buffer.flush()
            except OSError:
                print(BUNDLE_VALIDATION_ERROR, file=sys.stderr)
                return 1
            return 0
        print(json.dumps(summary, sort_keys=True))
        return 0

    try:
        report = load_payload(args.report)
        summary = validate_report(report, select_report_schema(report))
        validate_agent_policy_audit_event_files(
            report,
            event_paths,
            event_profile=event_profile,
        )
    except Exception as exc:
        print(f"agent-guard evidence invalid: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(summary, sort_keys=True))
    return 0
