# Where: src/agent_guard/cli/surface.py
# What: surface inventory CLI parser and runner.
# Why: keep the surface subcommand isolated while preserving legacy CLI behavior.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..context_guard import load_context_policy
from ..surface_delta import SurfaceDeltaError, build_surface_delta_report
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

    surface_delta = surface_sub.add_parser(
        "delta", help="sanitized PR base/head agent surface delta evidence"
    )
    surface_delta.add_argument("--root", default=".", help="repository root path")
    surface_delta.add_argument("--context-policy", required=True, help="agent context YAML policy path")
    surface_delta.add_argument(
        "--base-ref",
        required=True,
        help="git ref to diff against the current working tree; fetch it explicitly in CI",
    )
    surface_delta.add_argument(
        "--schema-version", choices=("v1",), default="v1", help="surface delta schema version"
    )
    surface_delta.add_argument("--json", action="store_true", help="emit JSON")


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


def run_surface_delta(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    policy_path = resolve_policy_arg(args.context_policy, root)
    try:
        policy = load_context_policy(policy_path)
        delta = build_surface_delta_report(root=root, context_policy=policy, base_ref=args.base_ref)
    except SurfaceDeltaError as exc:
        return _emit_surface_delta_error(args=args, root=root, message=str(exc))
    except Exception as exc:
        return _emit_surface_delta_error(args=args, root=root, message=str(exc))

    entries = delta.get("entries", [])
    entry_count = len(entries) if isinstance(entries, list) else 0
    summary = delta.get("summary", {}) if isinstance(delta.get("summary"), dict) else {}
    payload = result_payload(
        scanner="surface",
        status="ok",
        exit_code=0,
        policy_arg=args.context_policy,
        root=root,
        findings=[],
        scanned_count=entry_count,
        scanned_unit="delta_entries",
        summary_extra={
            "delta_added_count": summary.get("added", 0),
            "delta_removed_count": summary.get("removed", 0),
            "delta_modified_count": summary.get("modified", 0),
        },
        extra={"command": "delta", "delta": delta},
    )
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(
            "surface-delta: OK "
            f"(added={summary.get('added', 0)} removed={summary.get('removed', 0)} "
            f"modified={summary.get('modified', 0)} unchanged={summary.get('unchanged', 0)})"
        )
    return 0


def _emit_surface_delta_error(*, args: argparse.Namespace, root: Path, message: str) -> int:
    payload = result_payload(
        scanner="surface",
        status="error",
        exit_code=2,
        policy_arg=args.context_policy,
        root=root,
        error=message,
        extra={"command": "delta"},
    )
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(f"ERROR: {payload.get('error', 'unknown error')}")
    return 2

