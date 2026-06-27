"""Where: src/agent_guard/report.py
What: sanitized evidence report rendering.
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


def annotation_level(severity: object, *, default: str = "warning") -> str:
    return "error" if str(severity).lower() == "high" else default


def github_annotation(
    *,
    level: str,
    title: object,
    message: object,
    file: object = "",
    line: object = "",
) -> str:
    properties: list[tuple[str, object]] = []
    if file not in (None, "", "-"):
        properties.append(("file", file))
    line_number = positive_line_number(line)
    if line_number:
        properties.append(("line", line_number))
    if title not in (None, ""):
        properties.append(("title", title))

    property_text = ",".join(
        f"{key}={github_command_property(value)}" for key, value in properties
    )
    prefix = f"::{level}"
    if property_text:
        prefix = f"{prefix} {property_text}"
    return f"{prefix}::{github_command_data(message)}"


def as_mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def as_sequence(value: object) -> Sequence[object]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return ()


def render_github_annotations_report(payload: Mapping[str, object]) -> str:
    """Render sanitized GitHub Actions workflow-command annotations."""

    path = as_mapping(payload.get("path"))
    content = as_mapping(payload.get("content"))
    api = as_mapping(payload.get("api"))
    context_lock = as_mapping(payload.get("context_lock"))
    digest = as_mapping(payload.get("digest"))
    workflow = as_mapping(payload.get("workflow"))
    findings = as_sequence(payload.get("findings"))
    path_findings = as_sequence(path.get("findings"))
    content_findings = as_sequence(content.get("findings"))
    api_findings = as_sequence(api.get("findings"))
    context_lock_findings = as_sequence(context_lock.get("findings"))
    digest_findings = as_sequence(digest.get("findings"))
    workflow_findings = as_sequence(workflow.get("findings"))

    lines: list[str] = []
    if payload.get("status") == "error":
        lines.append(
            github_annotation(
                level="error",
                title="agent-guard report",
                message=f"report error: {payload.get('error', 'unknown error')}",
            )
        )
        return "\n".join(lines) + "\n"

    for item in findings:
        finding = as_mapping(item)
        rule_id = finding.get("rule_id", "-")
        lines.append(
            github_annotation(
                level=annotation_level(finding.get("severity")),
                title=f"agent-guard context: {rule_id}",
                message=f"context finding: {rule_id}",
                file=finding.get("file", ""),
                line=finding.get("line", ""),
            )
        )

    for item in path_findings:
        finding = as_mapping(item)
        rule_id = finding.get("rule_id", "-")
        lines.append(
            github_annotation(
                level=annotation_level(finding.get("severity")),
                title=f"agent-guard path: {rule_id}",
                message=f"path guard finding: {rule_id}",
                file=finding.get("path", ""),
            )
        )

    for item in content_findings:
        finding = as_mapping(item)
        rule_id = finding.get("rule_id", "-")
        lines.append(
            github_annotation(
                level=annotation_level(finding.get("severity")),
                title=f"agent-guard content: {rule_id}",
                message=f"content guard finding: {rule_id}",
                file=finding.get("file", ""),
                line=finding.get("line", ""),
            )
        )

    for item in api_findings:
        finding = as_mapping(item)
        category = finding.get("category", "forbidden_api")
        lines.append(
            github_annotation(
                level="error",
                title=f"agent-guard api: {category}",
                message=f"api guard finding: {category}",
                file=finding.get("path", ""),
                line=finding.get("line", ""),
            )
        )

    for item in context_lock_findings:
        finding = as_mapping(item)
        rule_id = finding.get("rule_id", "-")
        status = finding.get("status", "-")
        lines.append(
            github_annotation(
                level=annotation_level(finding.get("severity"), default="error"),
                title=f"agent-guard context lock: {rule_id}",
                message=f"context lock coverage: {status}",
                file=finding.get("path", ""),
            )
        )

    for item in digest_findings:
        finding = as_mapping(item)
        check_id = finding.get("check_id", "-")
        status = finding.get("status", "-")
        lines.append(
            github_annotation(
                level="error",
                title=f"agent-guard digest: {check_id}",
                message=f"digest drift: {check_id} ({status})",
                file=finding.get("path", ""),
            )
        )

    for item in workflow_findings:
        finding = as_mapping(item)
        rule_id = finding.get("rule_id", "-")
        workflow_id = finding.get("workflow_id", "")
        requirement_id = finding.get("requirement_id", "")
        suffix = (
            f" ({workflow_id}/{requirement_id})"
            if workflow_id and requirement_id
            else ""
        )
        lines.append(
            github_annotation(
                level=annotation_level(finding.get("severity")),
                title=f"agent-guard workflow: {rule_id}",
                message=f"workflow drift: {finding.get('reason', '-')}{suffix}",
                file=finding.get("file", ""),
            )
        )

    return "\n".join(lines) + ("\n" if lines else "")


def render_markdown_evidence_report(payload: Mapping[str, object]) -> str:
    """Render a sanitized deterministic Markdown report from an internal report payload."""

    tool = as_mapping(payload.get("tool"))
    policy = as_mapping(payload.get("policy"))
    summary = as_mapping(payload.get("summary"))
    report = as_mapping(payload.get("report"))
    path = as_mapping(payload.get("path"))
    content = as_mapping(payload.get("content"))
    api = as_mapping(payload.get("api"))
    context_lock = as_mapping(payload.get("context_lock"))
    digest = as_mapping(payload.get("digest"))
    workflow = as_mapping(payload.get("workflow"))
    inventory = as_mapping(payload.get("inventory"))
    context_files = as_sequence(inventory.get("context_files"))
    boundaries = as_sequence(inventory.get("permission_boundaries"))
    findings = as_sequence(payload.get("findings"))
    path_findings = as_sequence(path.get("findings"))
    content_findings = as_sequence(content.get("findings"))
    api_findings = as_sequence(api.get("findings"))
    context_lock_findings = as_sequence(context_lock.get("findings"))
    digest_findings = as_sequence(digest.get("findings"))
    workflow_findings = as_sequence(workflow.get("findings"))

    overview_rows: list[tuple[object, object]] = [
        ("Tool", f"{tool.get('name', 'agent-guard')} {tool.get('version', 'unknown')}"),
        ("Scope", report.get("scope", "context")),
        ("Status", payload.get("status", "unknown")),
        ("Exit code", payload.get("exit_code", "-")),
        ("Policy", policy.get("path", "-")),
        ("Evidence contract", report.get("schema_version", "-")),
    ]
    if path:
        path_policy = as_mapping(path.get("policy"))
        overview_rows.append(("Path policy", path_policy.get("path", "-")))
    if content:
        content_policy = as_mapping(content.get("policy"))
        overview_rows.append(("Content policy", content_policy.get("path", "-")))
    if api:
        api_policy = as_mapping(api.get("policy"))
        overview_rows.append(("API policy", api_policy.get("path", "-")))
    if digest:
        digest_policy = as_mapping(digest.get("policy"))
        overview_rows.append(("Digest policy", digest_policy.get("path", "-")))
    if workflow:
        workflow_policy = as_mapping(workflow.get("policy"))
        overview_rows.append(("Workflow policy", workflow_policy.get("path", "-")))

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
                "Sanitization: report cells are limited to deterministic metadata; raw source lines, raw workflow commands, workflow run bodies, rule patterns, URLs, hashes, secrets, and absolute local paths are omitted or redacted.",
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
    if path:
        summary_rows.extend(
            [
                ("Path names scanned", path.get("checked_count", 0)),
                ("Path guard findings", path.get("finding_count", 0)),
            ]
        )
    if content:
        summary_rows.extend(
            [
                ("Content files scanned", content.get("checked_count", 0)),
                ("Content guard findings", content.get("finding_count", 0)),
            ]
        )
    if api:
        summary_rows.extend(
            [
                ("API files scanned", api.get("checked_count", 0)),
                ("API guard findings", api.get("finding_count", 0)),
            ]
        )
    if digest:
        summary_rows.extend(
            [
                ("Context lock checked", context_lock.get("checked_count", 0)),
                ("Context lock covered", context_lock.get("covered_count", 0)),
                ("Context lock coverage findings", context_lock.get("finding_count", 0)),
                ("Digest checks", digest.get("checked_count", 0)),
                ("Digest drift findings", digest.get("finding_count", 0)),
            ]
        )
    if workflow:
        summary_rows.extend(
            [
                ("Workflow checks", workflow.get("checked_count", 0)),
                ("Workflow drift findings", workflow.get("finding_count", 0)),
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

    if path:
        lines.extend(["", "## Path Guard Evidence", ""])
        if path_findings:
            path_rows = []
            for item in path_findings:
                finding = as_mapping(item)
                path_rows.append(
                    (
                        finding.get("severity", "-"),
                        finding.get("rule_id", "-"),
                        finding.get("path", "-"),
                    )
                )
            lines.extend(markdown_table(("Severity", "Rule", "Path"), path_rows))
        else:
            lines.append("No path guard findings were detected.")

    if content:
        lines.extend(["", "## Content Guard Evidence", ""])
        if content_findings:
            content_rows = []
            for item in content_findings:
                finding = as_mapping(item)
                content_rows.append(
                    (
                        finding.get("severity", "-"),
                        finding.get("rule_id", "-"),
                        finding.get("file", "-"),
                        finding.get("line", "-"),
                    )
                )
            lines.extend(markdown_table(("Severity", "Rule", "File", "Line"), content_rows))
        else:
            lines.append("No content guard findings were detected.")

    if api:
        lines.extend(["", "## API Guard Evidence", ""])
        if api_findings:
            api_rows = []
            for item in api_findings:
                finding = as_mapping(item)
                api_rows.append(
                    (
                        finding.get("path", "-"),
                        finding.get("line", "-"),
                        finding.get("category", "-"),
                    )
                )
            lines.extend(markdown_table(("File", "Line", "Category"), api_rows))
        else:
            lines.append("No API guard findings were detected.")

    if context_lock:
        lines.extend(["", "## Context Lock Coverage Evidence", ""])
        if context_lock_findings:
            coverage_rows = []
            for item in context_lock_findings:
                finding = as_mapping(item)
                coverage_rows.append(
                    (
                        finding.get("severity", "-"),
                        finding.get("rule_id", "-"),
                        finding.get("path", "-"),
                        finding.get("status", "-"),
                        finding.get("check_id", "-"),
                    )
                )
            lines.extend(
                markdown_table(
                    ("Severity", "Rule", "Path", "Status", "Check"),
                    coverage_rows,
                )
            )
        else:
            lines.append("All discovered agent context files are fully pinned by the digest policy.")

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

    if workflow:
        lines.extend(["", "## Workflow Drift Evidence", ""])
        if workflow_findings:
            workflow_rows = []
            for item in workflow_findings:
                finding = as_mapping(item)
                workflow_rows.append(
                    (
                        finding.get("severity", "-"),
                        finding.get("rule_id", "-"),
                        finding.get("file", "-"),
                        finding.get("reason", "-"),
                        finding.get("workflow_id", "-"),
                        finding.get("requirement_id", "-"),
                    )
                )
            lines.extend(
                markdown_table(
                    ("Severity", "Rule", "File", "Reason", "Workflow", "Requirement"),
                    workflow_rows,
                )
            )
        else:
            lines.append("No workflow drift was detected.")

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
            "Sanitization: report cells are limited to deterministic metadata; raw source lines, raw workflow commands, workflow run bodies, rule patterns, URLs, hashes, secrets, and absolute local paths are omitted or redacted.",
        ]
    )
    return "\n".join(lines) + "\n"
