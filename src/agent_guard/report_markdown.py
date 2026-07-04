"""Where: src/agent_guard/report_markdown.py
What: Markdown renderer for sanitized evidence reports.
Why: isolate human-readable report layout from SARIF and annotation adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from .report_core import as_mapping, as_sequence, markdown_table, risk_theme_cell


def render_markdown_evidence_report(payload: Mapping[str, object]) -> str:
    """Render a sanitized deterministic Markdown report from an internal report payload."""

    tool = as_mapping(payload.get("tool"))
    policy = as_mapping(payload.get("policy"))
    summary = as_mapping(payload.get("summary"))
    report = as_mapping(payload.get("report"))
    path = as_mapping(payload.get("path"))
    content = as_mapping(payload.get("content"))
    api = as_mapping(payload.get("api"))
    mcp_config = as_mapping(payload.get("mcp_config"))
    context_lock = as_mapping(payload.get("context_lock"))
    digest = as_mapping(payload.get("digest"))
    workflow = as_mapping(payload.get("workflow"))
    drift = as_mapping(payload.get("policy_spec_drift"))
    conformance = as_mapping(payload.get("conformance"))
    evidence_pack_manifest = as_mapping(payload.get("evidence_pack_manifest"))
    inventory = as_mapping(payload.get("inventory"))
    surface_inventory = as_mapping(payload.get("surface_inventory"))
    evidence_coverage = as_mapping(payload.get("evidence_coverage"))
    context_files = as_sequence(inventory.get("context_files"))
    surfaces = as_sequence(surface_inventory.get("surfaces"))
    coverage_gates = as_sequence(evidence_coverage.get("gates"))
    boundaries = as_sequence(inventory.get("permission_boundaries"))
    findings = as_sequence(payload.get("findings"))
    path_findings = as_sequence(path.get("findings"))
    content_findings = as_sequence(content.get("findings"))
    api_findings = as_sequence(api.get("findings"))
    mcp_findings = as_sequence(mcp_config.get("findings"))
    mcp_surfaces = as_sequence(mcp_config.get("surfaces"))
    context_lock_covered = as_sequence(context_lock.get("covered"))
    context_lock_findings = as_sequence(context_lock.get("findings"))
    digest_findings = as_sequence(digest.get("findings"))
    workflow_findings = as_sequence(workflow.get("findings"))
    drift_findings = as_sequence(drift.get("findings"))
    conformance_findings = as_sequence(conformance.get("findings"))
    manifest_gates = as_sequence(evidence_pack_manifest.get("gates"))

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
    if mcp_config:
        overview_rows.append(("MCP config evidence", mcp_config.get("status", "-")))
    if digest:
        digest_policy = as_mapping(digest.get("policy"))
        overview_rows.append(("Digest policy", digest_policy.get("path", "-")))
    if workflow:
        workflow_policy = as_mapping(workflow.get("policy"))
        overview_rows.append(("Workflow policy", workflow_policy.get("path", "-")))
    if drift:
        overview_rows.append(("Policy/spec drift", drift.get("status", "-")))
    if conformance:
        overview_rows.append(("Conformance profile", conformance.get("profile", "-")))
    if evidence_pack_manifest:
        overview_rows.append(("Evidence pack manifest", evidence_pack_manifest.get("schema_version", "-")))

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
        ("Agent surfaces inventoried", summary.get("surface_count", 0)),
        ("Evidence gates enabled", summary.get("coverage_enabled_count", 0)),
        ("Evidence gates missing", summary.get("coverage_missing_count", 0)),
        ("Evidence gates failing", summary.get("coverage_failing_count", 0)),
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
    if mcp_config:
        summary_rows.extend(
            [
                ("MCP config surfaces checked", mcp_config.get("checked_count", 0)),
                ("MCP config findings", mcp_config.get("finding_count", 0)),
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
    if drift:
        summary_rows.extend(
            [
                ("Policy/spec drift checks", drift.get("checked_count", 0)),
                ("Policy/spec drift findings", drift.get("finding_count", 0)),
            ]
        )
    if conformance:
        summary_rows.extend(
            [
                ("Conformance checks", conformance.get("checked_count", 0)),
                ("Conformance findings", conformance.get("finding_count", 0)),
            ]
        )

    lines.extend(
        [
            "## Summary",
            "",
            *markdown_table(("Metric", "Value"), summary_rows),
            "",
        ]
    )

    if coverage_gates:
        lines.extend(["## Evidence Coverage", ""])
        coverage_rows = []
        for item in coverage_gates:
            gate = as_mapping(item)
            policy = as_mapping(gate.get("policy"))
            coverage_rows.append(
                (
                    gate.get("gate", "-"),
                    gate.get("status", "-"),
                    gate.get("checked_count", 0),
                    gate.get("finding_count", 0),
                    policy.get("path", "-"),
                )
            )
        lines.extend(
            markdown_table(("Gate", "Status", "Checked", "Findings", "Policy"), coverage_rows)
        )
        lines.append("")

    if surfaces:
        lines.extend(["## Agent Surface Inventory", ""])
        surface_rows = []
        for item in surfaces:
            surface = as_mapping(item)
            command = as_mapping(surface.get("command"))
            risky_patterns = as_sequence(surface.get("risky_patterns"))
            surface_rows.append(
                (
                    surface.get("surface", "-"),
                    surface.get("kind", "-"),
                    surface.get("path", "-"),
                    surface.get("status", "-"),
                    command.get("scanner", "-"),
                    command.get("command", "-"),
                    "; ".join(str(pattern) for pattern in risky_patterns) if risky_patterns else "-",
                )
            )
        lines.extend(
            markdown_table(
                ("Surface", "Kind", "Path", "Status", "Scanner", "Command", "Risk labels"),
                surface_rows,
            )
        )
        lines.append("")

    lines.extend(
        [
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
                    risk_theme_cell("context", finding),
                    finding.get("file", "-"),
                    finding.get("line", "-"),
                )
            )
        lines.extend(markdown_table(("Severity", "Rule", "OWASP risk themes", "File", "Line"), finding_rows))
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
                        risk_theme_cell("path", finding),
                        finding.get("path", "-"),
                    )
                )
            lines.extend(markdown_table(("Severity", "Rule", "OWASP risk themes", "Path"), path_rows))
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
                        risk_theme_cell("content", finding),
                        finding.get("file", "-"),
                        finding.get("line", "-"),
                    )
                )
            lines.extend(markdown_table(("Severity", "Rule", "OWASP risk themes", "File", "Line"), content_rows))
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
                        risk_theme_cell("api", finding),
                    )
                )
            lines.extend(markdown_table(("File", "Line", "Category", "OWASP risk themes"), api_rows))
        else:
            lines.append("No API guard findings were detected.")

    if mcp_config:
        lines.extend(["", "## MCP Configuration Evidence", ""])
        if mcp_findings:
            mcp_rows = []
            for item in mcp_findings:
                finding = as_mapping(item)
                mcp_rows.append(
                    (
                        finding.get("severity", "-"),
                        finding.get("rule_id", "-"),
                        risk_theme_cell("mcp_config", finding),
                        finding.get("path", "-"),
                        finding.get("server_name", "-"),
                        finding.get("reason", "-"),
                    )
                )
            lines.extend(
                markdown_table(
                    ("Severity", "Rule", "OWASP risk themes", "Path", "Server", "Reason"),
                    mcp_rows,
                )
            )
        else:
            lines.append("No MCP configuration findings were detected.")
        if mcp_surfaces:
            lines.extend(["", "MCP config surfaces:"])
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
                        risk_theme_cell("context_lock", finding),
                        finding.get("path", "-"),
                        finding.get("status", "-"),
                        finding.get("check_id", "-"),
                    )
                )
            lines.extend(
                markdown_table(
                    ("Severity", "Rule", "OWASP risk themes", "Path", "Status", "Check"),
                    coverage_rows,
                )
            )
        else:
            lines.append("All discovered agent context files are fully pinned by the digest policy.")
        if context_lock_covered:
            lines.extend(["", "Covered context files:"])
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
                        risk_theme_cell("digest", finding),
                        finding.get("message", "-"),
                    )
                )
            lines.extend(markdown_table(("Check", "Path", "Status", "OWASP risk themes", "Message"), digest_rows))
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
                        risk_theme_cell("workflow", finding),
                        finding.get("file", "-"),
                        finding.get("reason", "-"),
                        finding.get("workflow_id", "-"),
                        finding.get("requirement_id", "-"),
                    )
                )
            lines.extend(
                markdown_table(
                    ("Severity", "Rule", "OWASP risk themes", "File", "Reason", "Workflow", "Requirement"),
                    workflow_rows,
                )
            )
        else:
            lines.append("No workflow drift was detected.")

    if drift:
        lines.extend(["", "## Policy/Spec Drift Evidence", ""])
        if drift_findings:
            drift_rows = []
            for item in drift_findings:
                finding = as_mapping(item)
                drift_rows.append(
                    (
                        finding.get("severity", "-"),
                        finding.get("rule_id", "-"),
                        risk_theme_cell("policy_spec_drift", finding),
                        finding.get("file", "-"),
                        finding.get("reason", "-"),
                        finding.get("requirement_id", "-"),
                    )
                )
            lines.extend(
                markdown_table(
                    ("Severity", "Rule", "OWASP risk themes", "File", "Reason", "Requirement"),
                    drift_rows,
                )
            )
        else:
            lines.append("No policy/spec drift was detected.")

    if conformance:
        lines.extend(["", "## Conformance Evidence", ""])
        if conformance_findings:
            conformance_rows = []
            for item in conformance_findings:
                finding = as_mapping(item)
                conformance_rows.append(
                    (
                        finding.get("severity", "-"),
                        finding.get("rule_id", "-"),
                        risk_theme_cell("conformance", finding),
                        finding.get("requirement_id", "-"),
                        finding.get("reason", "-"),
                    )
                )
            lines.extend(
                markdown_table(
                    ("Severity", "Rule", "OWASP risk themes", "Requirement", "Reason"),
                    conformance_rows,
                )
            )
        else:
            lines.append(f"Profile `{conformance.get('profile', '-')}` passed.")

    if evidence_pack_manifest:
        lines.extend(["", "## Evidence Pack Manifest", ""])
        manifest_summary = as_mapping(evidence_pack_manifest.get("summary"))
        manifest_rows = [
            ("Manifest schema", evidence_pack_manifest.get("schema_version", "-")),
            ("Sanitized", evidence_pack_manifest.get("sanitized", "-")),
            ("Enabled gates", manifest_summary.get("enabled_gate_count", 0)),
            ("Missing gates", manifest_summary.get("missing_gate_count", 0)),
            ("Failing gates", manifest_summary.get("failing_gate_count", 0)),
        ]
        lines.extend(markdown_table(("Field", "Value"), manifest_rows))
        if manifest_gates:
            lines.extend(["", "Manifest gates:"])
            gate_rows = []
            for item in manifest_gates:
                gate = as_mapping(item)
                gate_rows.append(
                    (
                        gate.get("gate", "-"),
                        gate.get("status", "-"),
                        gate.get("finding_count", 0),
                    )
                )
            lines.extend(markdown_table(("Gate", "Status", "Findings"), gate_rows))

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
                    risk_theme_cell("inventory", evidence),
                )
            )
    if evidence_rows:
        lines.extend(markdown_table(("File", "Line", "Category", "Rule", "OWASP risk themes"), evidence_rows))
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
