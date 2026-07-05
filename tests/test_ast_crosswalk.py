# Where: tests/test_ast_crosswalk.py
# What: unit tests for the additive OWASP Agentic Skills Top 10 crosswalk.
# Why: keep optional AST mappings internally consistent as taxonomy names evolve.

from __future__ import annotations

from pathlib import Path

from agent_guard.taxonomy import AGENT_GUARD_AST_CAPABILITY_CROSSWALK, OWASP_AGENTIC_SKILLS_TOP10


REPO_ROOT = Path(__file__).resolve().parents[1]
AST_CROSSWALK_DOC = REPO_ROOT / "docs" / "ast-crosswalk.md"


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


def test_ast_crosswalk_documents_currentness_and_non_goals() -> None:
    docs = AST_CROSSWALK_DOC.read_text(encoding="utf-8")
    docs_single_line = " ".join(docs.split())

    assert "Reference snapshot: verified on 2026-07-06" in docs
    assert "OWASP Incubator" in docs
    assert "Public review (v1) draft" in docs
    assert "v0.5 community-review milestone" in docs_single_line
    assert "v1.0 release target" in docs_single_line
    assert "separate from the OWASP Top 10 for Agentic Applications 2026 ASI taxonomy" in docs_single_line
    assert "Neither label set is a vulnerability proof" in docs_single_line
    assert "runtime MCP/OAuth validation" in docs_single_line
    assert "SLSA/provenance verification" in docs_single_line
    assert "compliance attestation" in docs_single_line
