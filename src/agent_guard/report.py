"""Where: src/agent_guard/report.py
What: sanitized Markdown evidence report rendering.
Why: let maintainers attach deterministic guard evidence to reviews without leaking raw repository content.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping, Sequence


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


def as_mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def as_sequence(value: object) -> Sequence[object]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return ()


def render_markdown_evidence_report(payload: Mapping[str, object]) -> str:
    """Render a sanitized deterministic Markdown report from an internal report payload."""

    tool = as_mapping(payload.get("tool"))
    policy = as_mapping(payload.get("policy"))
    summary = as_mapping(payload.get("summary"))
    report = as_mapping(payload.get("report"))
    digest = as_mapping(payload.get("digest"))
    inventory = as_mapping(payload.get("inventory"))
    context_files = as_sequence(inventory.get("context_files"))
    boundaries = as_sequence(inventory.get("permission_boundaries"))
    findings = as_sequence(payload.get("findings"))
    digest_findings = as_sequence(digest.get("findings"))

    overview_rows: list[tuple[object, object]] = [
        ("Tool", f"{tool.get('name', 'agent-guard')} {tool.get('version', 'unknown')}"),
        ("Scope", report.get("scope", "context")),
        ("Status", payload.get("status", "unknown")),
        ("Exit code", payload.get("exit_code", "-")),
        ("Policy", policy.get("path", "-")),
    ]
    if digest:
        digest_policy = as_mapping(digest.get("policy"))
        overview_rows.append(("Digest policy", digest_policy.get("path", "-")))

    lines: list[str] = [
        "# Agent Guard Evidence Report",
        "",
        *markdown_table(
            ("Field", "Value"),
            overview_rows,
        ),
        "",
    ]

    if payload.get("status") == "error":
        lines.extend(
            [
                "## Error",
                "",
                *markdown_table(("Field", "Value"), (("Error", payload.get("error", "unknown error")),)),
                "",
                "Sanitization: report cells are limited to deterministic metadata; raw source lines, rule patterns, URLs, hashes, secrets, and absolute local paths are omitted or redacted.",
            ]
        )
        return "\n".join(lines) + "\n"

    present_boundaries = sum(
        1 for item in boundaries if as_mapping(item).get("status") == "present"
    )
    missing_boundaries = sum(
        1 for item in boundaries if as_mapping(item).get("status") == "missing"
    )

    summary_rows: list[tuple[object, object]] = [
        ("Context files scanned", summary.get("scanned_count", 0)),
        ("Unsafe context findings", summary.get("finding_count", 0)),
        ("Inventory evidence records", summary.get("evidence_count", 0)),
        ("Permission boundaries present", present_boundaries),
        ("Permission boundaries missing", missing_boundaries),
    ]
    if digest:
        summary_rows.extend(
            [
                ("Digest checks", digest.get("checked_count", 0)),
                ("Digest drift findings", digest.get("finding_count", 0)),
            ]
        )

    lines.extend(
        [
            "## Summary",
            "",
            *markdown_table(("Metric", "Value"), summary_rows),
            "",
            "## Context Check Findings",
            "",
        ]
    )

    if findings:
        finding_rows = []
        for item in findings:
            finding = as_mapping(item)
            finding_rows.append(
                (
                    finding.get("severity", "-"),
                    finding.get("rule_id", "-"),
                    finding.get("file", "-"),
                    finding.get("line", "-"),
                )
            )
        lines.extend(markdown_table(("Severity", "Rule", "File", "Line"), finding_rows))
    else:
        lines.append("No unsafe context findings were detected.")

    if digest:
        lines.extend(["", "## Digest Drift Evidence", ""])
        if digest_findings:
            digest_rows = []
            for item in digest_findings:
                finding = as_mapping(item)
                digest_rows.append(
                    (
                        finding.get("check_id", "-"),
                        finding.get("path", "-"),
                        finding.get("status", "-"),
                        finding.get("message", "-"),
                    )
                )
            lines.extend(markdown_table(("Check", "Path", "Status", "Message"), digest_rows))
        else:
            lines.append("No digest drift was detected.")

    lines.extend(["", "## Context Files", ""])
    if context_files:
        file_rows = []
        for item in context_files:
            entry = as_mapping(item)
            file_rows.append(
                (
                    entry.get("path", "-"),
                    entry.get("kind", "-"),
                    entry.get("read_status", "-"),
                    entry.get("line_count", "-"),
                    len(as_sequence(entry.get("evidence"))),
                )
            )
        lines.extend(markdown_table(("Path", "Kind", "Read status", "Lines", "Evidence records"), file_rows))
    else:
        lines.append("No agent context files were discovered.")

    lines.extend(["", "## Evidence Records", ""])
    evidence_rows = []
    for item in context_files:
        entry = as_mapping(item)
        path = entry.get("path", "-")
        for evidence_item in as_sequence(entry.get("evidence")):
            evidence = as_mapping(evidence_item)
            evidence_rows.append(
                (
                    path,
                    evidence.get("line", "-"),
                    evidence.get("category", "-"),
                    evidence.get("rule_id", "-"),
                )
            )
    if evidence_rows:
        lines.extend(markdown_table(("File", "Line", "Category", "Rule"), evidence_rows))
    else:
        lines.append("No inventory evidence records were detected.")

    lines.extend(["", "## Permission Boundary Evidence", ""])
    if boundaries:
        boundary_rows = []
        for item in boundaries:
            boundary = as_mapping(item)
            boundary_rows.append(
                (
                    boundary.get("category", "-"),
                    boundary.get("status", "-"),
                    len(as_sequence(boundary.get("evidence_ids"))),
                )
            )
        lines.extend(markdown_table(("Category", "Status", "Evidence records"), boundary_rows))
    else:
        lines.append("No permission boundary categories were configured.")

    lines.extend(
        [
            "",
            "Sanitization: report cells are limited to deterministic metadata; raw source lines, rule patterns, URLs, hashes, secrets, and absolute local paths are omitted or redacted.",
        ]
    )
    return "\n".join(lines) + "\n"
