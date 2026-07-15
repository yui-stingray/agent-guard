"""Where: tests/test_readme_benchmark_doc_links.py
What: tests for the README.md updates that replaced the inline AGB metric claim
with a pointer to docs/benchmark-results.md and added a pointer to
docs/evidence-consumer-contracts.md.
Why: keep README cross-references pointed at real files and prevent the removed
bare metric claims from silently returning.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"


def test_readme_measured_quality_section_points_to_benchmark_results_doc() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "[`docs/benchmark-results.md`](docs/benchmark-results.md)" in readme
    assert (REPO_ROOT / "docs" / "benchmark-results.md").is_file()

    paragraph_start = readme.index("Agent-Guard Bench (AGB)")
    paragraph_end = readme.index("\n\n## Why", paragraph_start)
    benchmark_paragraph = " ".join(readme[paragraph_start:paragraph_end].split())
    assert "[`docs/benchmark-results.md`](docs/benchmark-results.md)" in benchmark_paragraph
    assert "local deterministic regression evidence" in benchmark_paragraph
    assert "not an independently verified quality benchmark" in benchmark_paragraph


def test_readme_no_longer_states_a_bare_agb_metric_claim() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "F1 `0.959`" not in readme
    assert "precision `0.921`" not in readme
    assert "recall `1.0`" not in readme
    assert "self-authored 40-case corpus" not in readme


def test_readme_points_to_evidence_consumer_contracts_doc() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "[`docs/evidence-consumer-contracts.md`](docs/evidence-consumer-contracts.md)" in readme
    assert (REPO_ROOT / "docs" / "evidence-consumer-contracts.md").is_file()

    single_line = " ".join(readme.split())
    assert (
        "fail-closed missing/invalid/stale checks, public-artifact linting, or "
        "strict release gates" in single_line
    )


def test_readme_evidence_contracts_reference_is_still_present_alongside_consumer_doc() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "[`docs/evidence-contracts.md`](docs/evidence-contracts.md)" in readme
    assert (REPO_ROOT / "docs" / "evidence-contracts.md").is_file()
