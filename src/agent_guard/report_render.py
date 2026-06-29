"""Where: src/agent_guard/report_render.py
What: thin render helpers for sanitized agent-guard report payloads.
Why: let CI render Markdown, SARIF, and annotations from one JSON evidence file.
"""

from __future__ import annotations

import json
from pathlib import Path

from .report import render_github_annotations_report, render_markdown_evidence_report, render_sarif_report


def render_report_output(payload: dict[str, object], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n"
    if output_format == "github-annotations":
        return render_github_annotations_report(payload)
    if output_format == "sarif":
        return render_sarif_report(payload)
    return render_markdown_evidence_report(payload)


def emit_report_output(rendered: str, output_path: str) -> None:
    output = str(output_path).strip()
    if not output:
        print(rendered, end="")
        return

    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
