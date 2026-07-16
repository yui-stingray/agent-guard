"""Where: src/agent_guard/cli.py
What: command-line interface for the agent-guard MVP.
Why: make the extracted scanners consumable from CI, hooks, and local debugging.
"""

from __future__ import annotations

import argparse

from .cli.api import add_api_parser, run_api_check
from .cli.content import add_content_parser, run_content_check
from .cli.context import add_context_parser, run_context_check, run_context_inventory, run_context_lock
from .cli.common import safe_policy_path, scrub_report_error_message
from .cli.conformance import add_conformance_parser, run_conformance_check
from .cli.digest import add_digest_parser, run_digest_check
from .cli.drift import add_drift_parser, run_drift_check
from .cli.evidence_pack import add_evidence_pack_parser, run_evidence_pack_manifest
from .cli.init import run_init
from .cli.mcp import add_mcp_parser, run_mcp_check
from .cli.path import add_path_parser, run_path_check
from .cli.report import add_report_parser, run_report
from .cli.render_report import add_render_report_parser, run_report_render
from .cli.surface import add_surface_parser, run_surface_delta, run_surface_inventory
from .cli.workflow import add_workflow_parser, run_workflow_check


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

    add_report_parser(top)
    add_render_report_parser(top)

    return parser


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
    if args.scanner == "surface" and args.command == "delta":
        return run_surface_delta(args)
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
