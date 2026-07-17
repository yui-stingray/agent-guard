"""Where: src/agent_guard/cli/init.py
What: init subcommand implementation for the CLI package.
Why: begin splitting standalone subcommands out of the legacy CLI module.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..init_guard import build_init_plan, render_init_plan_text, write_init_plan
from .common import scrub_error_message


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
        if args.skip_existing and not args.write:
            raise ValueError("init --skip-existing requires --write")
        if args.skip_existing and args.force:
            raise ValueError("init --skip-existing cannot be combined with --force")
        if args.write:
            plan, exit_code = write_init_plan(
                root=root,
                force=bool(args.force),
                skip_existing=bool(args.skip_existing),
            )
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
