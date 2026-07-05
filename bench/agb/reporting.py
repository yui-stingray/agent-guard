"""Where: bench/agb/reporting.py
What: Markdown reporting helpers for Agent-Guard Bench result JSON.
Why: keep public benchmark tables reproducible from deterministic runner output.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


GUARD_LABELS = {
    "content": "Content",
    "context": "Context",
    "digest": "Digest",
    "drift": "Drift",
    "mcp": "MCP",
    "path": "Path",
}


def format_metric(value: object) -> str:
    if not isinstance(value, int | float):
        raise ValueError(f"metric must be numeric: {value!r}")
    if float(value) == 1.0:
        return "1.000000"
    return f"{float(value):.6f}"


def guard_results_table(payload: dict[str, Any]) -> str:
    by_guard = payload.get("by_guard")
    if not isinstance(by_guard, dict):
        raise ValueError("AGB result JSON must include object field: by_guard")

    lines = [
        "| Guard | TP | FP | FN | Precision | Recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for guard, metrics in sorted(by_guard.items()):
        if not isinstance(metrics, dict):
            raise ValueError(f"guard metrics must be an object: {guard}")
        label = GUARD_LABELS.get(str(guard), str(guard))
        lines.append(
            "| {label} | {tp} | {fp} | {fn} | {precision} | {recall} | {f1} |".format(
                label=label,
                tp=int(metrics["tp"]),
                fp=int(metrics["fp"]),
                fn=int(metrics["fn"]),
                precision=format_metric(metrics["precision"]),
                recall=format_metric(metrics["recall"]),
                f1=format_metric(metrics["f1"]),
            )
        )
    return "\n".join(lines)


def load_payload(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("AGB result JSON must be an object")
    return loaded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="render AGB result JSON as Markdown tables")
    parser.add_argument("result_json", help="path to an agent-guard.agb_results.v1 JSON file")
    args = parser.parse_args(argv)
    print(guard_results_table(load_payload(Path(args.result_json))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
