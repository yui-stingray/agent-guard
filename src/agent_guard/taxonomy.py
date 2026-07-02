"""Where: src/agent_guard/taxonomy.py
What: controlled external risk-theme crosswalks for sanitized evidence.
Why: help reviewers read evidence without claiming runtime vulnerability detection.
"""

from __future__ import annotations

from collections.abc import Mapping


OWASP_AGENTIC_TOP10: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

OWASP_AGENTIC_SKILLS_TOP10: dict[str, str] = {
    "AST01": "Malicious Skills",
    "AST02": "Supply Chain Compromise",
    "AST03": "Over-Privileged Skills",
    "AST04": "Insecure Metadata",
    "AST05": "Untrusted External Instructions",
    "AST06": "Weak Isolation",
    "AST07": "Update Drift",
    "AST08": "Poor Scanning",
    "AST09": "No Governance",
    "AST10": "Cross-Platform Reuse",
}

AGENT_GUARD_AST_CAPABILITY_CROSSWALK: dict[str, tuple[str, ...]] = {
    "context_guard": ("AST05", "AST09"),
    "surface_inventory": ("AST01", "AST04", "AST10"),
    "mcp_config_guard": ("AST02", "AST03", "AST06"),
    "digest_pinning": ("AST02", "AST06", "AST07"),
    "workflow_guard": ("AST07", "AST09"),
    "policy_spec_drift": ("AST07", "AST09"),
    "evidence_pack": ("AST08", "AST09"),
    "conformance": ("AST08", "AST09"),
}

CONTEXT_RULE_THEMES: dict[str, tuple[str, ...]] = {
    "approval_bypass": ("ASI01", "ASI09"),
    "secret_prompt": ("ASI03", "ASI09"),
    "destructive_command": ("ASI05",),
    "hidden_action": ("ASI09",),
    "disable_safety_tools": ("ASI01", "ASI09"),
    "skip_verification": ("ASI08", "ASI09"),
    "ignore_test_failures": ("ASI08", "ASI09"),
    "force_merge_without_review": ("ASI09",),
    "credential_persistence": ("ASI03",),
    "unrestricted_network": ("ASI02",),
    "untrusted_instruction_priority": ("ASI01", "ASI06"),
    "raw_evidence_publication": ("ASI09",),
    "policy_self_modification": ("ASI01", "ASI06"),
    "sandbox_escape": ("ASI05",),
    "permission_self_escalation": ("ASI03",),
    "audit_trail_removal": ("ASI09",),
    "private_data_exfiltration": ("ASI02", "ASI03"),
    "user_impersonation": ("ASI03", "ASI09"),
    "unsafe_release_publication": ("ASI04", "ASI09"),
    "delegate_policy_bypass": ("ASI01", "ASI07"),
    "unsafe_tool_auto_allow": ("ASI02",),
    "unreviewed_agent_output": ("ASI09",),
    "unsafe_background_agent": ("ASI10",),
    "unreviewed_suppression": ("ASI01", "ASI09"),
}

EVIDENCE_CATEGORY_THEMES: dict[str, tuple[str, ...]] = {
    "approval_boundary": ("ASI09",),
    "tool_permission_boundary": ("ASI02",),
    "network_boundary": ("ASI02",),
    "secret_handling": ("ASI03",),
    "destructive_action_boundary": ("ASI05",),
    "local_verification": ("ASI08",),
}

EVIDENCE_RULE_THEMES: dict[str, tuple[str, ...]] = {
    "approval_boundary_mention": ("ASI09",),
    "tool_permission_boundary_mention": ("ASI02",),
    "network_boundary_mention": ("ASI02",),
    "secret_handling_mention": ("ASI03",),
    "destructive_action_boundary_mention": ("ASI05",),
    "local_verification_mention": ("ASI08",),
}

CONTENT_RULE_THEMES: dict[str, tuple[str, ...]] = {
    "pipe_to_shell": ("ASI05",),
    "destructive_rm_root": ("ASI05",),
    "force_history_rewrite": ("ASI05",),
    "encoded_exec": ("ASI05",),
    "powershell_iex_download": ("ASI05",),
    "secret_prompt": ("ASI03",),
    "hardcoded_credential": ("ASI03",),
}

API_CATEGORY_THEMES: dict[str, tuple[str, ...]] = {
    "forbidden_api": ("ASI02",),
}

CONTEXT_LOCK_RULE_THEMES: dict[str, tuple[str, ...]] = {
    "context_lock_missing": ("ASI04", "ASI06"),
    "context_lock_partial": ("ASI04", "ASI06"),
    "context_lock_file_missing": ("ASI04", "ASI06"),
    "context_lock_mismatch": ("ASI04", "ASI06"),
}

DIGEST_STATUS_THEMES: dict[str, tuple[str, ...]] = {
    "missing": ("ASI04", "ASI06"),
    "mismatch": ("ASI04", "ASI06"),
}

WORKFLOW_REASON_THEMES: dict[str, tuple[str, ...]] = {
    "missing_required_file": ("ASI04", "ASI08"),
    "missing_required_workflow_command": ("ASI04", "ASI08"),
}

CONFORMANCE_RULE_THEMES: dict[str, tuple[str, ...]] = {
    "required_gate_missing": ("ASI08",),
    "required_gate_not_ok": ("ASI08",),
    "required_surface_missing": ("ASI04",),
    "required_policy_file_missing": ("ASI04",),
    "required_report_section_not_sanitized": ("ASI09",),
    "required_report_section_missing": ("ASI09",),
    "required_artifact_role_missing": ("ASI04",),
    "required_mcp_policy_not_reviewed": ("ASI04",),
    "mcp_policy_weakened": ("ASI04",),
}

DRIFT_CLASSIFICATION_THEMES: dict[str, tuple[str, ...]] = {
    "baseline_review_required": ("ASI04",),
    "baseline_guard_surface_changed": ("ASI04",),
    "guard_policy_changed": ("ASI04", "ASI06"),
    "digest_policy_changed": ("ASI04", "ASI06"),
    "guard_workflow_changed": ("ASI04", "ASI05"),
    "guard_hook_changed": ("ASI04", "ASI07"),
    "permission_boundary_weakened": ("ASI01", "ASI09"),
    "verification_removed": ("ASI08", "ASI09"),
    "private_data_exposure": ("ASI03",),
    "raw_evidence_publication": ("ASI09",),
    "untrusted_instruction_priority": ("ASI01", "ASI06"),
    "unrestricted_external_access": ("ASI02",),
    "auditability_weakened": ("ASI09",),
    "destructive_action_boundary_weakened": ("ASI05",),
    "context_file_unpinned": ("ASI04", "ASI06"),
    "context_file_partially_pinned": ("ASI04", "ASI06"),
    "context_file_digest_drift": ("ASI04", "ASI06"),
    "context_lock_drift": ("ASI04", "ASI06"),
    "unsafe_context_instruction": ("ASI01", "ASI09"),
    "missing_readme_guard_command": ("ASI08",),
    "missing_agent_guard_policy": ("ASI04",),
    "missing_required_file_entry": ("ASI04", "ASI08"),
    "missing_required_context_boundary": ("ASI09",),
    "invalid_workflow_policy": ("ASI04", "ASI08"),
    "missing_required_file": ("ASI04", "ASI08"),
    "missing_required_workflow_command": ("ASI04", "ASI08"),
}

MCP_RULE_THEMES: dict[str, tuple[str, ...]] = {
    "mcp_config_risky_pattern": ("ASI02", "ASI04"),
    "mcp_policy_missing": ("ASI04",),
}

MCP_RISK_PATTERN_THEMES: dict[str, tuple[str, ...]] = {
    "latest_package": ("ASI04",),
    "unpinned_package": ("ASI04",),
    "filesystem_root_reference": ("ASI02", "ASI05"),
    "secret_shaped_inline_value": ("ASI03",),
    "inline_env_value": ("ASI03",),
    "inline_authorization_value": ("ASI03",),
    "broad_authorization_scope": ("ASI02", "ASI03"),
    "unsafe_url_scheme": ("ASI02", "ASI05"),
    "parse_error": ("ASI04",),
}


def risk_theme(theme_id: str) -> dict[str, str]:
    return {"id": theme_id, "name": OWASP_AGENTIC_TOP10[theme_id]}


def risk_theme_refs(theme_ids: tuple[str, ...]) -> list[dict[str, str]]:
    return [risk_theme(theme_id) for theme_id in theme_ids if theme_id in OWASP_AGENTIC_TOP10]


def risk_theme_labels(themes: object) -> str:
    if not isinstance(themes, list):
        return ""
    labels = []
    for item in themes:
        if not isinstance(item, Mapping):
            continue
        theme_id = str(item.get("id", "")).strip()
        name = str(item.get("name", "")).strip()
        if theme_id and name:
            labels.append(f"{theme_id} {name}")
    return "; ".join(labels)


def existing_risk_themes(finding: Mapping[str, object]) -> list[dict[str, str]]:
    raw = finding.get("owasp_agentic_risk_themes")
    if not isinstance(raw, list):
        return []
    themes: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        theme_id = str(item.get("id", "")).strip()
        name = str(item.get("name", "")).strip()
        if theme_id and name:
            themes.append({"id": theme_id, "name": name})
    return themes


def risk_themes_for_mcp_pattern(pattern: str) -> list[dict[str, str]]:
    return risk_theme_refs(MCP_RISK_PATTERN_THEMES.get(str(pattern), ()))


def risk_themes_for_finding(scanner: str, finding: Mapping[str, object]) -> list[dict[str, str]]:
    existing = existing_risk_themes(finding)
    if existing:
        return existing

    scanner_name = str(scanner).replace("-", "_")
    rule_id = str(finding.get("rule_id") or finding.get("check_id") or finding.get("category") or "")
    reason = str(finding.get("reason") or finding.get("classification") or "")
    category = str(finding.get("category") or "")
    themes: tuple[str, ...] = ()

    if scanner_name == "context":
        themes = CONTEXT_RULE_THEMES.get(rule_id) or EVIDENCE_RULE_THEMES.get(rule_id, ())
    elif scanner_name == "path":
        themes = ("ASI03", "ASI04")
    elif scanner_name == "content":
        themes = CONTENT_RULE_THEMES.get(rule_id, ())
    elif scanner_name == "api":
        themes = API_CATEGORY_THEMES.get(category or rule_id, ("ASI02",))
    elif scanner_name == "context_lock":
        themes = CONTEXT_LOCK_RULE_THEMES.get(rule_id, ("ASI04", "ASI06"))
    elif scanner_name == "digest":
        status = str(finding.get("status") or "")
        themes = DIGEST_STATUS_THEMES.get(status, ("ASI04", "ASI06"))
    elif scanner_name == "workflow":
        themes = WORKFLOW_REASON_THEMES.get(reason, ("ASI04", "ASI08"))
    elif scanner_name == "policy_spec_drift":
        themes = (
            DRIFT_CLASSIFICATION_THEMES.get(reason)
            or DRIFT_CLASSIFICATION_THEMES.get(str(finding.get("classification") or ""))
            or ()
        )
    elif scanner_name == "mcp_config":
        if rule_id == "mcp_config_risky_pattern":
            themes = tuple(theme["id"] for theme in risk_themes_for_mcp_pattern(reason))
        else:
            themes = MCP_RULE_THEMES.get(rule_id, ())
    elif scanner_name == "conformance":
        if rule_id == "mcp_config_risky_pattern":
            themes = tuple(theme["id"] for theme in risk_themes_for_mcp_pattern(reason))
        else:
            themes = CONFORMANCE_RULE_THEMES.get(rule_id, ())

    if not themes and category:
        themes = EVIDENCE_CATEGORY_THEMES.get(category, ())
    return risk_theme_refs(themes)


def annotate_finding(scanner: str, finding: Mapping[str, object]) -> dict[str, object]:
    payload = dict(finding)
    themes = risk_themes_for_finding(scanner, payload)
    if themes:
        payload["owasp_agentic_risk_themes"] = themes
    return payload
