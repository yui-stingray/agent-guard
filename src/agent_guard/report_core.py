"""Where: src/agent_guard/report_core.py
What: shared helpers for sanitized evidence report rendering.
Why: keep renderer-specific modules small without changing report output contracts.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping, Sequence

from .taxonomy import risk_theme_labels, risk_themes_for_finding


def redact_text(value: str) -> str:
    """Redact common secret, URL, hash, and absolute-path shapes before Markdown rendering."""

    redacted = value
    redacted = re.sub(r"github_pat_[A-Za-z0-9_]{20,}", "<secret>", redacted)
    redacted = re.sub(r"gh[pousr]_[A-Za-z0-9_]{20,}", "<secret>", redacted)
    redacted = re.sub(r"sk-[A-Za-z0-9_-]{16,}", "<secret>", redacted)
    redacted = re.sub(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "<secret>", redacted)
    redacted = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "<secret>", redacted)
    redacted = re.sub(r"https?://[^\s|)>\]]+", "<url>", redacted)
    redacted = re.sub(r"\b[a-fA-F0-9]{64}\b", "<sha256>", redacted)
    redacted = re.sub(r"[A-Za-z]:\\(?:[^\\\s|]+\\)*[^\\\s|]+", "<absolute-path>", redacted)
    redacted = re.sub(
        r"(^|[\s('\"\[])(/(?:[^\s|:'\"]+/)*[^\s|:'\"]+)",
        lambda match: f"{match.group(1)}<absolute-path>",
        redacted,
    )
    return redacted


def escape_markdown_text(value: str) -> str:
    escaped = html.escape(value, quote=False)
    escaped = escaped.replace("\\", "\\\\")
    for char in "[]()!`":
        escaped = escaped.replace(char, f"\\{char}")
    return escaped


def markdown_cell(value: object) -> str:
    text = "-" if value is None or value == "" else str(value)
    text = redact_text(text)
    text = text.replace("\r", " ").replace("\n", " ")
    return escape_markdown_text(text).replace("|", r"\|")


def markdown_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> list[str]:
    table = [
        "| " + " | ".join(markdown_cell(header) for header in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    table.extend("| " + " | ".join(markdown_cell(cell) for cell in row) + " |" for row in rows)
    return table


def github_command_data(value: object) -> str:
    text = "-" if value is None or value == "" else str(value)
    text = redact_text(text)
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def github_command_property(value: object) -> str:
    return github_command_data(value).replace(":", "%3A").replace(",", "%2C")


def positive_line_number(value: object) -> str:
    try:
        line = int(str(value))
    except (TypeError, ValueError):
        return ""
    return str(line) if line > 0 else ""


def risk_theme_message_suffix(themes: list[dict[str, str]]) -> str:
    labels = risk_theme_labels(themes)
    return f" (OWASP risk themes: {labels})" if labels else ""


def risk_theme_cell(scanner: str, finding: Mapping[str, object]) -> str:
    return risk_theme_labels(risk_themes_for_finding(scanner, finding)) or "-"


def as_mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def as_sequence(value: object) -> Sequence[object]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return ()
