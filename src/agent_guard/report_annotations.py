"""Where: src/agent_guard/report_annotations.py
What: GitHub Actions annotation renderer for sanitized evidence reports.
Why: isolate workflow-command rendering from Markdown and SARIF report adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from .report_core import (
    as_mapping,
    as_sequence,
    github_command_data,
    github_command_property,
    positive_line_number,
    risk_theme_message_suffix,
)
from .taxonomy import risk_themes_for_finding


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


def render_github_annotations_report(payload: Mapping[str, object]) -> str:
    """Render sanitized GitHub Actions workflow-command annotations."""

    path = as_mapping(payload.get("path"))
    content = as_mapping(payload.get("content"))
    api = as_mapping(payload.get("api"))
    mcp_config = as_mapping(payload.get("mcp_config"))
    context_lock = as_mapping(payload.get("context_lock"))
    digest = as_mapping(payload.get("digest"))
    workflow = as_mapping(payload.get("workflow"))
    drift = as_mapping(payload.get("policy_spec_drift"))
    conformance = as_mapping(payload.get("conformance"))
    findings = as_sequence(payload.get("findings"))
    path_findings = as_sequence(path.get("findings"))
    content_findings = as_sequence(content.get("findings"))
    api_findings = as_sequence(api.get("findings"))
    mcp_findings = as_sequence(mcp_config.get("findings"))
    context_lock_findings = as_sequence(context_lock.get("findings"))
    digest_findings = as_sequence(digest.get("findings"))
    workflow_findings = as_sequence(workflow.get("findings"))
    drift_findings = as_sequence(drift.get("findings"))
    conformance_findings = as_sequence(conformance.get("findings"))

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
        themes = risk_themes_for_finding("context", finding)
        lines.append(
            github_annotation(
                level=annotation_level(finding.get("severity")),
                title=f"agent-guard context: {rule_id}",
                message=f"context finding: {rule_id}{risk_theme_message_suffix(themes)}",
                file=finding.get("file", ""),
                line=finding.get("line", ""),
            )
        )

    for item in path_findings:
        finding = as_mapping(item)
        rule_id = finding.get("rule_id", "-")
        themes = risk_themes_for_finding("path", finding)
        lines.append(
            github_annotation(
                level=annotation_level(finding.get("severity")),
                title=f"agent-guard path: {rule_id}",
                message=f"path guard finding: {rule_id}{risk_theme_message_suffix(themes)}",
                file=finding.get("path", ""),
            )
        )

    for item in content_findings:
        finding = as_mapping(item)
        rule_id = finding.get("rule_id", "-")
        themes = risk_themes_for_finding("content", finding)
        lines.append(
            github_annotation(
                level=annotation_level(finding.get("severity")),
                title=f"agent-guard content: {rule_id}",
                message=f"content guard finding: {rule_id}{risk_theme_message_suffix(themes)}",
                file=finding.get("file", ""),
                line=finding.get("line", ""),
            )
        )

    for item in api_findings:
        finding = as_mapping(item)
        category = finding.get("category", "forbidden_api")
        themes = risk_themes_for_finding("api", finding)
        lines.append(
            github_annotation(
                level="error",
                title=f"agent-guard api: {category}",
                message=f"api guard finding: {category}{risk_theme_message_suffix(themes)}",
                file=finding.get("path", ""),
                line=finding.get("line", ""),
            )
        )

    for item in mcp_findings:
        finding = as_mapping(item)
        rule_id = finding.get("rule_id", "-")
        themes = risk_themes_for_finding("mcp_config", finding)
        lines.append(
            github_annotation(
                level=annotation_level(finding.get("severity")),
                title=f"agent-guard mcp: {rule_id}",
                message=f"mcp config finding: {finding.get('reason', '-')}{risk_theme_message_suffix(themes)}",
                file=finding.get("path", ""),
            )
        )

    for item in context_lock_findings:
        finding = as_mapping(item)
        rule_id = finding.get("rule_id", "-")
        status = finding.get("status", "-")
        themes = risk_themes_for_finding("context_lock", finding)
        lines.append(
            github_annotation(
                level=annotation_level(finding.get("severity"), default="error"),
                title=f"agent-guard context lock: {rule_id}",
                message=f"context lock coverage: {status}{risk_theme_message_suffix(themes)}",
                file=finding.get("path", ""),
            )
        )

    for item in digest_findings:
        finding = as_mapping(item)
        check_id = finding.get("check_id", "-")
        status = finding.get("status", "-")
        themes = risk_themes_for_finding("digest", finding)
        lines.append(
            github_annotation(
                level="error",
                title=f"agent-guard digest: {check_id}",
                message=f"digest drift: {check_id} ({status}){risk_theme_message_suffix(themes)}",
                file=finding.get("path", ""),
            )
        )

    for item in workflow_findings:
        finding = as_mapping(item)
        rule_id = finding.get("rule_id", "-")
        themes = risk_themes_for_finding("workflow", finding)
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
                message=f"workflow drift: {finding.get('reason', '-')}{suffix}{risk_theme_message_suffix(themes)}",
                file=finding.get("file", ""),
            )
        )

    for item in drift_findings:
        finding = as_mapping(item)
        rule_id = finding.get("rule_id", "-")
        themes = risk_themes_for_finding("policy_spec_drift", finding)
        lines.append(
            github_annotation(
                level=annotation_level(finding.get("severity")),
                title=f"agent-guard drift: {rule_id}",
                message=f"policy/spec drift: {finding.get('reason', '-')}{risk_theme_message_suffix(themes)}",
                file=finding.get("file", ""),
            )
        )

    for item in conformance_findings:
        finding = as_mapping(item)
        rule_id = finding.get("rule_id", "-")
        themes = risk_themes_for_finding("conformance", finding)
        lines.append(
            github_annotation(
                level=annotation_level(finding.get("severity")),
                title=f"agent-guard conformance: {rule_id}",
                message=f"conformance finding: {finding.get('reason', '-')}{risk_theme_message_suffix(themes)}",
            )
        )

    return "\n".join(lines) + ("\n" if lines else "")
