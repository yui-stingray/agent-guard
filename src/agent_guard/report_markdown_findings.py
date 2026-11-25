"""Finding tables for the Markdown evidence report."""

from __future__ import annotations

from collections.abc import Mapping

from .report_core import as_mapping, as_sequence, markdown_table, risk_theme_cell

# A None field renders the scanner's computed risk themes.
_RISK = ("OWASP risk themes", None)
_RULE_COLUMNS = (("Severity", "severity"), ("Rule", "rule_id"), _RISK)
_FILE_LINE = (("File", "file"), ("Line", "line"))
_Columns = tuple[tuple[str, str | None], ...]


_SCANNER_TABLES = (
    (
        "path",
        "Path Guard Evidence",
        "No path guard findings were detected.",
        _RULE_COLUMNS + (("Path", "path"),),
    ),
    (
        "content",
        "Content Guard Evidence",
        "No content guard findings were detected.",
        _RULE_COLUMNS + _FILE_LINE,
    ),
    (
        "api",
        "API Guard Evidence",
        "No API guard findings were detected.",
        (("File", "path"), ("Line", "line"), ("Category", "category"), _RISK),
    ),
    (
        "mcp_config",
        "MCP Configuration Evidence",
        "No MCP configuration findings were detected.",
        _RULE_COLUMNS + (("Path", "path"), ("Server", "server_name"), ("Reason", "reason")),
    ),
    (
        "context_lock",
        "Context Lock Coverage Evidence",
        "All discovered agent context files are fully pinned by the digest policy.",
        _RULE_COLUMNS + (("Path", "path"), ("Status", "status"), ("Check", "check_id")),
    ),
    (
        "digest",
        "Digest Drift Evidence",
        "No digest drift was detected.",
        (
            ("Check", "check_id"),
            ("Path", "path"),
            ("Status", "status"),
            _RISK,
            ("Message", "message"),
        ),
    ),
    (
        "workflow",
        "Workflow Drift Evidence",
        "No workflow drift was detected.",
        _RULE_COLUMNS
        + (
            ("File", "file"),
            ("Reason", "reason"),
            ("Workflow", "workflow_id"),
            ("Requirement", "requirement_id"),
        ),
    ),
    (
        "policy_spec_drift",
        "Policy/Spec Drift Evidence",
        "No policy/spec drift was detected.",
        _RULE_COLUMNS + (("File", "file"), ("Reason", "reason"), ("Requirement", "requirement_id")),
    ),
)


def _finding_table(
    section: Mapping[str, object], scanner: str, columns: _Columns, empty_message: str
) -> list[str]:
    items = as_sequence(section.get("findings"))
    if not items:
        return [empty_message]

    rows = []
    for item in items:
        finding = as_mapping(item)
        rows.append(
            [
                risk_theme_cell(scanner, finding) if field is None else finding.get(field, "-")
                for _, field in columns
            ]
        )
    return markdown_table([heading for heading, _ in columns], rows)


def scanner_evidence(payload: Mapping[str, object]) -> list[str]:
    lines = ["## Context Check Findings", ""]
    lines.extend(
        _finding_table(
            payload,
            "context",
            _RULE_COLUMNS + _FILE_LINE,
            "No unsafe context findings were detected.",
        )
    )
    for scanner, heading, empty_message, columns in _SCANNER_TABLES:
        section = as_mapping(payload.get(scanner))
        if not section:
            continue
        lines.extend(["", f"## {heading}", ""])
        lines.extend(_finding_table(section, scanner, columns, empty_message))
        if scanner == "mcp_config":
            lines.extend(_mcp_surfaces(section))
        elif scanner == "context_lock":
            lines.extend(_covered_context_files(section))
    return lines


def _mcp_surfaces(section: Mapping[str, object]) -> list[str]:
    mcp_surfaces = as_sequence(section.get("surfaces"))
    if not mcp_surfaces:
        return []
    lines = ["", "MCP config surfaces:"]
    surface_rows = []
    for item in mcp_surfaces:
        surface = as_mapping(item)
        risky_patterns = as_sequence(surface.get("risky_patterns"))
        surface_rows.append(
            (
                surface.get("surface", "-"),
                surface.get("kind", "-"),
                surface.get("path", "-"),
                surface.get("status", "-"),
                surface.get("server_name", "-"),
                surface.get("transport", "-"),
                "; ".join(str(pattern) for pattern in risky_patterns) if risky_patterns else "-",
            )
        )
    lines.extend(
        markdown_table(
            ("Surface", "Kind", "Path", "Status", "Server", "Transport", "Risk labels"),
            surface_rows,
        )
    )
    return lines


def _covered_context_files(section: Mapping[str, object]) -> list[str]:
    context_lock_covered = as_sequence(section.get("covered"))
    if not context_lock_covered:
        return []
    lines = ["", "Covered context files:"]
    covered_rows = []
    for item in context_lock_covered:
        covered = as_mapping(item)
        covered_rows.append(
            (
                covered.get("path", "-"),
                covered.get("kind", "-"),
                covered.get("status", "-"),
                covered.get("check_id", "-"),
            )
        )
    lines.extend(markdown_table(("Path", "Kind", "Status", "Check"), covered_rows))
    return lines


def conformance_evidence(section: Mapping[str, object]) -> list[str]:
    columns = _RULE_COLUMNS + (("Requirement", "requirement_id"), ("Reason", "reason"))
    passed = f"Profile `{section.get('profile', '-')}` passed."
    return [
        "",
        "## Conformance Evidence",
        "",
        *_finding_table(section, "conformance", columns, passed),
    ]
