"""Where: bench/ttfe/run.py
What: helpers for the TTFE quickstart replay benchmark.
Why: keep command extraction and result shaping testable outside the shell runner.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "agent-guard.ttfe_results.v1"
PACK_COMMAND_MARKER = "agent-guard evidence-pack manifest"


def extract_bash_commands(markdown: str) -> list[str]:
    commands: list[str] = []
    in_bash = False
    pending = ""
    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if stripped.startswith("```"):
            language = stripped.removeprefix("```").strip().lower()
            if in_bash:
                if pending:
                    commands.append(pending.strip())
                    pending = ""
                in_bash = False
            else:
                in_bash = language in {"bash", "sh", "shell"}
            continue
        if not in_bash or not stripped or stripped.startswith("#"):
            continue
        if pending:
            pending = f"{pending} {stripped}"
        else:
            pending = stripped
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        commands.append(pending)
        pending = ""
    if pending:
        commands.append(pending.strip())
    return commands


def _first_matching(records: list[dict[str, Any]], *, minimum_exit_code: int) -> dict[str, Any] | None:
    for record in records:
        try:
            exit_code = int(record.get("exit_code", 0))
        except (TypeError, ValueError):
            continue
        if exit_code >= minimum_exit_code:
            return {
                "index": record.get("index"),
                "command": record.get("command"),
                "exit_code": exit_code,
            }
    return None


def build_result_payload(
    *,
    source_doc: str,
    commands: list[str],
    records: list[dict[str, Any]],
    elapsed_ms: int,
    setup: dict[str, Any],
) -> dict[str, Any]:
    reached_pack = any(PACK_COMMAND_MARKER in str(record.get("command", "")) for record in records)
    failure_point = _first_matching(records, minimum_exit_code=2)
    first_nonzero = _first_matching(records, minimum_exit_code=1)
    status = "ok" if reached_pack and failure_point is None else "failed"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": status,
        "source_doc": source_doc,
        "command_count": len(records),
        "documented_command_count": len(commands),
        "elapsed_ms": elapsed_ms,
        "reached_recommended_evidence_pack": reached_pack,
        "first_nonzero": first_nonzero,
        "failure_point": failure_point,
        "setup": setup,
        "commands": records,
    }


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--source", required=True)
    result_parser = subparsers.add_parser("result")
    result_parser.add_argument("--source", required=True)
    result_parser.add_argument("--records", required=True)
    result_parser.add_argument("--out", required=True)
    result_parser.add_argument("--elapsed-ms", required=True, type=int)
    result_parser.add_argument("--setup", required=True)
    args = parser.parse_args(argv)

    source = Path(args.source)
    commands = extract_bash_commands(source.read_text(encoding="utf-8"))
    if args.command == "list":
        for command in commands:
            print(command)
        return 0

    setup = json.loads(args.setup)
    payload = build_result_payload(
        source_doc=os.environ.get("AGENT_GUARD_TTFE_SOURCE_LABEL", source.as_posix()),
        commands=commands,
        records=load_jsonl(Path(args.records)),
        elapsed_ms=args.elapsed_ms,
        setup=setup,
    )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
