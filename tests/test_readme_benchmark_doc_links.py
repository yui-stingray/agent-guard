"""Where: tests/test_readme_benchmark_doc_links.py
What: tests that README.md points to docs/benchmark-results.md instead of an
inline AGB metric claim, and to docs/evidence-consumer-contracts.md.
Why: keep README cross-references pointed at real files and prevent the removed
bare metric claims from silently returning.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"


def test_readme_agb_section_points_to_benchmark_results_doc() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "](docs/benchmark-results.md)" in readme
    assert (REPO_ROOT / "docs" / "benchmark-results.md").is_file()

    # The AGB claim lives in the Documentation list entry that links the results doc.
    entry_start = readme.rindex("\n- ", 0, readme.index("Agent-Guard Bench (AGB)"))
    entry_ends = (readme.find("\n- ", entry_start + 1), readme.find("\n\n", entry_start))
    entry_end = min(end for end in entry_ends if end != -1)
    benchmark_paragraph = " ".join(readme[entry_start:entry_end].split())
    assert "](docs/benchmark-results.md)" in benchmark_paragraph
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

    assert "](docs/evidence-consumer-contracts.md)" in readme
    assert (REPO_ROOT / "docs" / "evidence-consumer-contracts.md").is_file()

    single_line = " ".join(readme.split())
    assert (
        "fail-closed missing/invalid/report-visible drift checks, public-artifact linting, or "
        "strict release gates" in single_line
    )


def test_readme_evidence_contracts_reference_is_still_present_alongside_consumer_doc() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "](docs/evidence-contracts.md)" in readme
    assert (REPO_ROOT / "docs" / "evidence-contracts.md").is_file()
