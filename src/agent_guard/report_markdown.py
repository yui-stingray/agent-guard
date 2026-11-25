"""Where: src/agent_guard/report_markdown.py
What: Markdown renderer for sanitized evidence reports.
Why: isolate human-readable report layout from SARIF and annotation adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from .report_core import as_mapping, as_sequence, markdown_table, risk_theme_cell
from .report_markdown_findings import conformance_evidence, scanner_evidence


_SANITIZATION_NOTE = (
    "Sanitization: report cells are limited to deterministic metadata; raw source lines, raw workflow commands, "
    "workflow run bodies, rule patterns, URLs, hashes, secrets, and absolute local paths are omitted or redacted."
)


def _overview(payload: Mapping[str, object]) -> list[str]:
    tool = as_mapping(payload.get("tool"))
    policy = as_mapping(payload.get("policy"))
    report = as_mapping(payload.get("report"))
    overview_rows: list[tuple[object, object]] = [
        ("Tool", f"{tool.get('name', 'agent-guard')} {tool.get('version', 'unknown')}"),
        ("Scope", report.get("scope", "context")),
        ("Status", payload.get("status", "unknown")),
        ("Exit code", payload.get("exit_code", "-")),
        ("Policy", policy.get("path", "-")),
        ("Evidence contract", report.get("schema_version", "-")),
    ]
    for section_name, label, field in (
        ("path", "Path policy", "policy"),
        ("content", "Content policy", "policy"),
        ("api", "API policy", "policy"),
        ("mcp_config", "MCP config evidence", "status"),
        ("digest", "Digest policy", "policy"),
        ("workflow", "Workflow policy", "policy"),
        ("policy_spec_drift", "Policy/spec drift", "status"),
        ("conformance", "Conformance profile", "profile"),
        ("evidence_pack_manifest", "Evidence pack manifest", "schema_version"),
    ):
        section = as_mapping(payload.get(section_name))
        if section:
            value = section.get(field, "-")
            if field == "policy":
                value = as_mapping(value).get("path", "-")
            overview_rows.append((label, value))
    return [
        "# Agent Guard Evidence Report",
        "",
        *markdown_table(("Field", "Value"), overview_rows),
        "",
    ]


def _summary(payload: Mapping[str, object], inventory: Mapping[str, object]) -> list[str]:
    summary = as_mapping(payload.get("summary"))
    boundaries = as_sequence(inventory.get("permission_boundaries"))
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
    for name, checked_label, findings_label in (
        ("path", "Path names scanned", "Path guard findings"),
        ("content", "Content files scanned", "Content guard findings"),
        ("api", "API files scanned", "API guard findings"),
        ("mcp_config", "MCP config surfaces checked", "MCP config findings"),
        ("digest", "Digest checks", "Digest drift findings"),
        ("workflow", "Workflow checks", "Workflow drift findings"),
        ("policy_spec_drift", "Policy/spec drift checks", "Policy/spec drift findings"),
        ("conformance", "Conformance checks", "Conformance findings"),
    ):
        section = as_mapping(payload.get(name))
        if not section:
            continue
        if name == "digest":
            lock = as_mapping(payload.get("context_lock"))
            summary_rows.extend(
                [
                    ("Context lock checked", lock.get("checked_count", 0)),
                    ("Context lock covered", lock.get("covered_count", 0)),
                    ("Context lock coverage findings", lock.get("finding_count", 0)),
                ]
            )
        summary_rows.extend(
            [
                (checked_label, section.get("checked_count", 0)),
                (findings_label, section.get("finding_count", 0)),
            ]
        )
    return ["## Summary", "", *markdown_table(("Metric", "Value"), summary_rows), ""]


def _coverage_and_surfaces(payload: Mapping[str, object]) -> list[str]:
    coverage_gates = as_sequence(as_mapping(payload.get("evidence_coverage")).get("gates"))
    surfaces = as_sequence(as_mapping(payload.get("surface_inventory")).get("surfaces"))
    lines: list[str] = []
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
                    "; ".join(str(pattern) for pattern in risky_patterns)
                    if risky_patterns
                    else "-",
                )
            )
        lines.extend(
            markdown_table(
                ("Surface", "Kind", "Path", "Status", "Scanner", "Command", "Risk labels"),
                surface_rows,
            )
        )
        lines.append("")
    return lines


def _surface_delta(surface_delta: Mapping[str, object]) -> list[str]:
    lines: list[str] = []
    surface_delta_entries = as_sequence(surface_delta.get("entries"))
    lines.extend(["", "## Surface Delta Evidence", ""])
    delta_summary = as_mapping(surface_delta.get("summary"))
    lines.extend(
        markdown_table(
            ("Metric", "Value"),
            (
                ("Added", delta_summary.get("added", 0)),
                ("Removed", delta_summary.get("removed", 0)),
                ("Modified", delta_summary.get("modified", 0)),
                ("Unchanged", delta_summary.get("unchanged", 0)),
            ),
        )
    )
    if surface_delta_entries:
        lines.append("")
        delta_rows = []
        for item in surface_delta_entries:
            entry = as_mapping(item)
            changed_fields = as_sequence(entry.get("changed_fields"))
            risk_labels = as_sequence(entry.get("risk_labels"))
            delta_rows.append(
                (
                    entry.get("kind", "-"),
                    entry.get("path", "-"),
                    entry.get("name", "") or "-",
                    entry.get("status", "-"),
                    "; ".join(str(item) for item in changed_fields) if changed_fields else "-",
                    "; ".join(str(item) for item in risk_labels) if risk_labels else "-",
                )
            )
        lines.extend(
            markdown_table(
                ("Kind", "Path", "Name", "Status", "Changed fields", "Risk labels"),
                delta_rows,
            )
        )
    else:
        lines.append("No agent surface changes were detected relative to the base ref.")
    return lines


def _manifest(evidence_pack_manifest: Mapping[str, object]) -> list[str]:
    lines: list[str] = []
    manifest_gates = as_sequence(evidence_pack_manifest.get("gates"))
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
    return lines


def _context_inventory(inventory: Mapping[str, object]) -> list[str]:
    context_files = as_sequence(inventory.get("context_files"))
    boundaries = as_sequence(inventory.get("permission_boundaries"))
    lines: list[str] = []
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
        lines.extend(
            markdown_table(("Path", "Kind", "Read status", "Lines", "Evidence records"), file_rows)
        )
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
        lines.extend(
            markdown_table(("File", "Line", "Category", "Rule", "OWASP risk themes"), evidence_rows)
        )
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
    return lines


def render_markdown_evidence_report(payload: Mapping[str, object]) -> str:
    """Render a sanitized deterministic Markdown report from an internal report payload."""
    lines = _overview(payload)
    if payload.get("status") == "error":
        error = markdown_table(
            ("Field", "Value"), (("Error", payload.get("error", "unknown error")),)
        )
        lines.extend(["## Error", "", *error])
    else:
        inventory = as_mapping(payload.get("inventory"))
        lines.extend(_summary(payload, inventory))
        lines.extend(_coverage_and_surfaces(payload))
        lines.extend(scanner_evidence(payload))
        delta = as_mapping(payload.get("surface_delta"))
        if delta:
            lines.extend(_surface_delta(delta))
        conformance = as_mapping(payload.get("conformance"))
        if conformance:
            lines.extend(conformance_evidence(conformance))
        manifest = as_mapping(payload.get("evidence_pack_manifest"))
        if manifest:
            lines.extend(_manifest(manifest))
        lines.extend(_context_inventory(inventory))
    lines.extend(["", _SANITIZATION_NOTE])
    return "\n".join(lines) + "\n"
