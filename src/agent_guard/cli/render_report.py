# Where: src/agent_guard/cli/render_report.py
# What: render-report CLI parser and runner.
# Why: isolate sanitized report rendering from the legacy CLI module.

from __future__ import annotations

import argparse
from pathlib import Path

from ..report_render import emit_report_output, render_report_output
from .common import (
    REPORT_EVIDENCE_SCHEMA_VERSION,
    bounded_public_json,
    bounded_public_line,
    load_json_file,
    require_public_output_budget,
    result_payload,
    sanitize_public_mapping,
    scrub_report_error_message,
)


ERROR_REPORT_OUTPUT_LIMIT = "report output exceeds configured limits"


def add_render_report_parser(top) -> None:
    render_report = top.add_parser(
        "render-report",
        help="render an existing sanitized report JSON without rescanning",
    )
    render_report.add_argument("--root", default=".", help="repository root used for display-path scrubbing")
    render_report.add_argument("--input", required=True, help="sanitized agent-guard report JSON path")
    render_report.add_argument(
        "--format",
        choices=("markdown", "json", "github-annotations", "sarif"),
        default="markdown",
        help="rendered output format",
    )
    render_report.add_argument("--output", default="", help="optional output path; stdout when omitted")


def _render_bounded_report(payload: dict[str, object], output_format: str) -> str:
    try:
        if output_format == "json":
            return bounded_public_line(
                bounded_public_json(
                    payload,
                    error=ERROR_REPORT_OUTPUT_LIMIT,
                    sort_keys=True,
                ),
                error=ERROR_REPORT_OUTPUT_LIMIT,
            )
        return require_public_output_budget(
            render_report_output(payload, output_format),
            error=ERROR_REPORT_OUTPUT_LIMIT,
        )
    except (MemoryError, OverflowError, RecursionError, TypeError, ValueError):
        raise ValueError(ERROR_REPORT_OUTPUT_LIMIT) from None


def _emit_report_error(
    args: argparse.Namespace,
    *,
    root: Path,
    input_arg: str,
    error: str,
) -> int:
    payload = result_payload(
        scanner="report",
        status="error",
        exit_code=2,
        policy_arg=input_arg,
        root=root,
        error=error,
        error_paths=[input_arg],
        extra={
            "command": "render-report",
            "report": {
                "schema_version": REPORT_EVIDENCE_SCHEMA_VERSION,
                "format": args.format,
                "sanitized": True,
                "source": "json",
            },
        },
    )
    payload = sanitize_public_mapping(payload)
    emit_report_output(_render_bounded_report(payload, args.format), args.output)
    return 2


def run_report_render(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    input_arg = str(args.input).strip()
    try:
        payload = load_json_file(
            Path(input_arg),
            root_error="report JSON root must be an object",
        )
    except Exception as exc:
        return _emit_report_error(
            args,
            root=root,
            input_arg=input_arg,
            error=scrub_report_error_message(str(exc)),
        )

    try:
        payload = sanitize_public_mapping(payload)
    except ValueError:
        return _emit_report_error(
            args,
            root=root,
            input_arg=input_arg,
            error="public sanitization produced duplicate mapping keys",
        )
    try:
        rendered = _render_bounded_report(payload, args.format)
    except ValueError:
        return _emit_report_error(
            args,
            root=root,
            input_arg=input_arg,
            error=ERROR_REPORT_OUTPUT_LIMIT,
        )
    emit_report_output(rendered, args.output)
    exit_code = payload.get("exit_code", 0)
    return exit_code if isinstance(exit_code, int) and exit_code in {0, 1, 2} else 0
