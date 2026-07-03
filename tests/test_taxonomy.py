"""Where: tests/test_taxonomy.py
What: focused tests for finding risk-theme annotation.
Why: keep taxonomy metadata regressions covered without scanner fixture churn.
"""

from __future__ import annotations

from agent_guard.taxonomy import annotate_finding


def content_theme_ids(rule_id: str) -> list[str]:
    finding = annotate_finding("content", {"rule_id": rule_id})
    themes = finding.get("owasp_agentic_risk_themes", [])
    return [str(item["id"]) for item in themes]


def test_content_custom_secret_token_rule_id_uses_keyword_theme() -> None:
    assert content_theme_ids("secret_token_leak") == ["ASI03"]


def test_content_custom_command_exec_rule_id_uses_keyword_theme() -> None:
    assert content_theme_ids("dangerous_command_exec") == ["ASI05"]


def test_content_custom_unknown_rule_id_has_no_theme_metadata() -> None:
    finding = annotate_finding("content", {"rule_id": "style_policy_notice"})

    assert "owasp_agentic_risk_themes" not in finding


def test_content_builtin_pipe_to_shell_uses_exact_theme_table() -> None:
    assert content_theme_ids("pipe_to_shell") == ["ASI05"]
