"""Where: tests/test_adoption_boundary_docs.py
What: documentation regression checks for P1/P2 adoption and scope boundaries.
Why: keep monorepo evidence consumption and external-risk crosswalks bounded.
"""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _single_line(path: str) -> str:
    return " ".join((REPO_ROOT / path).read_text(encoding="utf-8").split())


def test_quickstart_documents_per_root_monorepo_evidence_boundaries() -> None:
    text = _single_line("docs/quickstart-existing-repo.md")

    assert "Treat each reviewed project root as its own evidence boundary" in text
    assert "Do not aggregate raw scanner JSON across services" in text
    assert "AGENT_GUARD_ROOT=services/api" in text
    assert "repo-external policy files do not satisfy recommended or strict reviewed-policy conformance" in text


def test_consumer_contracts_keep_monorepo_stale_checks_root_aligned() -> None:
    text = _single_line("docs/evidence-consumer-contracts.md")

    assert "run the consumer per reviewed project root" in text
    assert "same selected root, same reviewed repo-local policies" in text
    assert "should not be consumed as evidence for" in text
    assert "links to per-root sanitized reports" in text


def test_threat_model_keeps_external_risk_updates_out_of_runtime_scope() -> None:
    text = _single_line("docs/threat-model.md")

    assert "update labels, docs, or benchmark notes only after rechecking primary sources" in text
    assert "not by itself a requirement to add a runtime validator" in text
    assert "broad credential-scanning feature" in text
    assert "autonomous enforcement path" in text
    assert "2026-07-28 protocol/runtime/OAuth changes do not justify adding runtime execution" in text
    assert "No changelog item directly invalidates the current static committed-config labels" in text
