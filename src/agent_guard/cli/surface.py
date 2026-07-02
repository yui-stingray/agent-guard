# Where: src/agent_guard/cli/surface.py
# What: surface inventory CLI parser and runner.
# Why: keep the surface subcommand isolated while preserving legacy CLI behavior.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..context_guard import load_context_policy
from ..surface_inventory import collect_agent_surface_inventory
from .common import resolve_policy_arg, result_payload


def add_surface_parser(top) -> None:
    surface = top.add_parser("surface", help="agent-facing repository surface inventory")
    surface_sub = surface.add_subparsers(dest="command", required=True)
    surface_inventory = surface_sub.add_parser("inventory", help="emit repo-local agent surface metadata")
    surface_inventory.add_argument("--root", default=".", help="repository root path")
    surface_inventory.add_argument("--context-policy", required=True, help="agent context YAML policy path")
    surface_inventory.add_argument("--schema-version", choices=("v1", "v2"), default="v1", help="inventory schema version")
    surface_inventory.add_argument("--json", action="store_true", help="emit JSON")


def run_surface_inventory(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = resolve_policy_arg(args.context_policy, root)
    try:
        policy = load_context_policy(policy_path)
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

