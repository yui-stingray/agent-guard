"""Where: tests/test_benchmark_reporting_docs.py
What: public documentation checks for Agent-Guard Bench reporting.
Why: prevent context-free benchmark claims from drifting back into docs.
"""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DOCS = [REPO_ROOT / "README.md", *sorted((REPO_ROOT / "docs").glob("*.md"))]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_current_agb_numbers_are_reported_with_population_and_scope() -> None:
    text = read(REPO_ROOT / "docs" / "benchmark-results.md")

    required_fragments = [
        "60 self-authored cases",
        "groups A16/B10/C13/D6/E10/F5",
        "overall F1 `0.935780`",
        "precision `0.944444`",
        "recall `0.927273`",
        "`TP=51`, `FP=3`, `FN=4`",
        "no independent verification yet",
        "Scope limits",
        "`a12`",
        "`a13`",
        "`a14`",
        "`c09`",
        "Next Evaluation Work",
        "third-party or independently reviewed fixture sets",
        "demand signals",
        "Do not use AGB movement as a reason to add runtime MCP execution",
        "| Content | 10 | 2 | 0 | 0.833333 | 1.000000 | 0.909091 |",
        "| Context | 14 | 0 | 3 | 1.000000 | 0.823529 | 0.903226 |",
        "| MCP | 13 | 1 | 1 | 0.928571 | 0.928571 | 0.928571 |",
        "| Path | 7 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |",
    ]
    for fragment in required_fragments:
        assert fragment in text


def test_public_agb_docs_do_not_keep_stale_or_bare_metric_claims() -> None:
    joined = "\n".join(read(path) for path in PUBLIC_DOCS)

    stale_fragments = [
        "self-authored 40-case corpus",
        "AGB F1 0.959",
        "F1 `0.959`",
        "F1 0.91",
        "precision `0.921`",
        "recall `1.0`",
    ]
    for fragment in stale_fragments:
        assert fragment not in joined

    for path in PUBLIC_DOCS:
        if path.name == "benchmark-results.md":
            continue
        text = read(path)
        assert "AGB F1" not in text
        assert "overall F1" not in text
