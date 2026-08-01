"""Where: src/agent_guard/consumer/_cli.py
What: command-line adapter for packaged evidence consumer validation.
Why: keep the example shim thin while preserving the old script behavior.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from ._bundle import _validate_evidence_bundle
from ._report import validate_report
from ._schema import load_payload, load_report_schema


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
    args = parser.parse_args(argv)
    if args.emit_annotations and args.evidence_dir is None:
        parser.error("--emit-annotations requires --evidence-dir")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.evidence_dir is not None:
        try:
            summary, annotation_bytes = _validate_evidence_bundle(args.evidence_dir, args.report)
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
        summary = validate_report(load_payload(args.report), load_report_schema())
    except Exception as exc:
        print(f"agent-guard evidence invalid: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(summary, sort_keys=True))
    return 0
