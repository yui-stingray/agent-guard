# Where: tests/test_ast_crosswalk.py
# What: unit tests for the additive OWASP Agentic Skills Top 10 crosswalk.
# Why: keep optional AST mappings internally consistent as taxonomy names evolve.

from __future__ import annotations

from agent_guard.taxonomy import AGENT_GUARD_AST_CAPABILITY_CROSSWALK, OWASP_AGENTIC_SKILLS_TOP10


def test_ast_taxonomy_table_contains_ast01_through_ast10() -> None:
    assert list(OWASP_AGENTIC_SKILLS_TOP10) == [f"AST{index:02d}" for index in range(1, 11)]
    assert OWASP_AGENTIC_SKILLS_TOP10["AST01"] == "Malicious Skills"
    assert OWASP_AGENTIC_SKILLS_TOP10["AST10"] == "Cross-Platform Reuse"


def test_agent_guard_ast_crosswalk_references_valid_ast_codes() -> None:
    valid_codes = set(OWASP_AGENTIC_SKILLS_TOP10)
    referenced_codes = {
        code
        for codes in AGENT_GUARD_AST_CAPABILITY_CROSSWALK.values()
        for code in codes
    }

    assert referenced_codes
    assert referenced_codes <= valid_codes
