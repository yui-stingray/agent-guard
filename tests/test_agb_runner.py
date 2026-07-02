"""Where: tests/test_agb_runner.py
What: unit tests for the Agent-Guard Bench runner.
Why: keep benchmark scoring deterministic before adding adversarial fixtures.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from pathlib import Path

from bench.agb import run as agb_run


def write_expected(path: Path, payload: dict[str, object]) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "expected.json").write_text(json.dumps(payload), encoding="utf-8")


def test_evaluate_case_counts_tp_fp_and_fn_by_guard(tmp_path: Path) -> None:
    case_dir = tmp_path / "a01"
    write_expected(
        case_dir,
        {
            "case_id": "a01",
            "guards": ["context", "content"],
            "expected_findings": [
                {"guard": "context", "rule": "approval_bypass", "path": "AGENTS.md"},
                {"guard": "content", "rule": "secret_prompt", "path": "AGENTS.md"},
            ],
            "forbidden_findings": [],
        },
    )
    guard_outputs = {
        "context": {
            "exit_code": 1,
            "findings": [{"rule_id": "approval_bypass", "file": "AGENTS.md"}],
        },
        "content": {
            "exit_code": 1,
            "findings": [{"rule_id": "hardcoded_credential", "file": "secrets.md"}],
        },
    }

    result = agb_run.evaluate_case(case_dir, guard_outputs)

    assert result.counts == {"tp": 1, "fp": 1, "fn": 1}
    assert result.by_guard["context"].counts == {"tp": 1, "fp": 0, "fn": 0}
    assert result.by_guard["content"].counts == {"tp": 0, "fp": 1, "fn": 1}
    assert result.false_negatives[0].rule == "secret_prompt"
    assert result.false_positives[0].rule == "hardcoded_credential"


def test_metrics_handle_zero_denominators() -> None:
    assert agb_run.metrics_from_counts({"tp": 0, "fp": 0, "fn": 0}) == {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    }
    assert agb_run.metrics_from_counts({"tp": 1, "fp": 1, "fn": 1}) == {
        "tp": 1,
        "fp": 1,
        "fn": 1,
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
    }


def test_run_case_uses_declared_guards(tmp_path: Path, monkeypatch) -> None:
    case_dir = tmp_path / "case"
    write_expected(
        case_dir,
        {
            "case_id": "case",
            "guards": ["context"],
            "expected_findings": [
                {"guard": "context", "rule": "approval_bypass", "path": "AGENTS.md"}
            ],
            "forbidden_findings": [],
        },
    )
    calls: list[tuple[str, Path]] = []

    def fake_run_guard(repo_root: Path, case_root: Path, guard: str) -> dict[str, object]:
        calls.append((guard, case_root))
        return {"exit_code": 1, "findings": [{"rule_id": "approval_bypass", "file": "AGENTS.md"}]}

    monkeypatch.setattr(agb_run, "run_guard", fake_run_guard)

    result = agb_run.run_case(tmp_path, case_dir)

    assert calls == [("context", case_dir)]
    assert result.case_id == "case"
    assert result.counts == {"tp": 1, "fp": 0, "fn": 0}


def test_build_results_discovers_cases_and_aggregates(tmp_path: Path, monkeypatch) -> None:
    fixtures = tmp_path / "fixtures"
    write_expected(
        fixtures / "a",
        {
            "case_id": "a",
            "guards": ["context"],
            "expected_findings": [{"guard": "context", "rule": "approval_bypass", "path": "AGENTS.md"}],
            "forbidden_findings": [],
        },
    )
    write_expected(
        fixtures / "e",
        {
            "case_id": "e",
            "guards": ["content"],
            "expected_findings": [],
            "forbidden_findings": [],
        },
    )

    def fake_run_guard(repo_root: Path, case_root: Path, guard: str) -> dict[str, object]:
        if guard == "context":
            return {"exit_code": 1, "findings": [{"rule_id": "approval_bypass", "file": "AGENTS.md"}]}
        return {"exit_code": 1, "findings": [{"rule_id": "pipe_to_shell", "file": "docs/install.md"}]}

    monkeypatch.setattr(agb_run, "run_guard", fake_run_guard)

    payload = agb_run.build_results(tmp_path, fixtures)

    assert payload["schema_version"] == "agent-guard.agb_results.v1"
    assert payload["case_count"] == 2
    assert payload["overall"]["tp"] == 1
    assert payload["overall"]["fp"] == 1
    assert payload["by_guard"]["context"]["f1"] == 1.0
    assert payload["by_guard"]["content"]["precision"] == 0.0


def test_run_guard_returns_runner_error_for_non_json(tmp_path: Path, monkeypatch) -> None:
    case_dir = tmp_path / "case"
    (case_dir / "policies").mkdir(parents=True)

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=2, stdout="not json", stderr="boom")

    monkeypatch.setattr(agb_run.subprocess, "run", fake_run)

    payload = agb_run.run_guard(tmp_path, case_dir, "context")

    assert payload == {"exit_code": 2, "findings": [], "runner_error": "boom"}


def test_main_writes_result_file(tmp_path: Path, monkeypatch) -> None:
    out_path = tmp_path / "result.json"

    def fake_build_results(repo_root: Path, fixtures_root: Path) -> dict[str, object]:
        return {"schema_version": "agent-guard.agb_results.v1", "case_count": 0}

    monkeypatch.setattr(agb_run, "build_results", fake_build_results)

    assert agb_run.main(["--repo-root", str(tmp_path), "--fixtures", "fixtures", "--out", str(out_path)]) == 0
    assert json.loads(out_path.read_text(encoding="utf-8"))["case_count"] == 0
