"""Where: src/agent_guard/report.py
What: compatibility facade for sanitized evidence report rendering.
Why: preserve existing imports while renderer implementations live in focused modules.
"""

from __future__ import annotations

from .report_annotations import (
    annotation_level,
    github_annotation,
    render_github_annotations_report,
)
from .report_core import (
    as_mapping,
    as_sequence,
    escape_markdown_text,
    github_command_data,
    github_command_property,
    markdown_cell,
    markdown_table,
    positive_line_number,
    redact_text,
    risk_theme_cell,
    risk_theme_message_suffix,
)
from .report_markdown import render_markdown_evidence_report
from .report_sarif import (
    append_sarif_result,
    render_sarif_report,
    sarif_artifact_uri,
    sarif_fingerprint,
    sarif_level,
    sarif_region,
    sarif_rule_id,
)

__all__ = [
    "annotation_level",
    "append_sarif_result",
    "as_mapping",
    "as_sequence",
    "escape_markdown_text",
    "github_annotation",
    "github_command_data",
    "github_command_property",
    "markdown_cell",
    "markdown_table",
    "positive_line_number",
    "redact_text",
    "render_github_annotations_report",
    "render_markdown_evidence_report",
    "render_sarif_report",
    "risk_theme_cell",
    "risk_theme_message_suffix",
    "sarif_artifact_uri",
    "sarif_fingerprint",
    "sarif_level",
    "sarif_region",
    "sarif_rule_id",
]
