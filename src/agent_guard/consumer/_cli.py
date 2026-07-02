"""Where: src/agent_guard/consumer/_cli.py
What: command-line adapter for packaged evidence consumer validation.
Why: keep the example shim thin while preserving the old script behavior.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from ._report import validate_report
from ._schema import load_payload, load_report_schema


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a sanitized agent-guard report JSON file.")
    parser.add_argument("report", type=Path, help="Path to agent-guard report JSON")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        summary = validate_report(load_payload(args.report), load_report_schema())
    except Exception as exc:
        print(f"agent-guard evidence invalid: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(summary, sort_keys=True))
    return 0
