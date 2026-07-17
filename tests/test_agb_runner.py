"""Where: tests/test_agb_runner.py
What: unit tests for the Agent-Guard Bench runner.
Why: keep benchmark scoring deterministic before adding adversarial fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bench.agb import run as agb_run
from bench.agb import reporting as agb_reporting


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


@pytest.mark.parametrize(
    "item",
    [
        {"rule": "approval_bypass", "path": "AGENTS.md"},
        {"guard": 123, "rule": "approval_bypass", "path": "AGENTS.md"},
        {"guard": " ", "rule": "approval_bypass", "path": "AGENTS.md"},
        {"guard": "unsupported", "rule": "approval_bypass", "path": "AGENTS.md"},
        {"guard": "context", "path": "AGENTS.md"},
        {"guard": "context", "rule": ["approval_bypass"], "path": "AGENTS.md"},
        {"guard": "context", "rule": " ", "path": "AGENTS.md"},
        {"guard": "context", "rule": "approval_bypass"},
        {"guard": "context", "rule": "approval_bypass", "path": {"file": "AGENTS.md"}},
        {"guard": "context", "rule": "approval_bypass", "path": " "},
        {"guard": "context", "rule": "approval_bypass", "path": "AGENTS.md", "reason": 123},
        {"guard": "context", "rule": "approval_bypass", "path": "AGENTS.md", "reason": " "},
    ],
)
def test_spec_from_expected_rejects_malformed_fields(item: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        agb_run.spec_from_expected(item)


@pytest.mark.parametrize(
    "guards",
    [None, "context", [""], [123], ["context", "context"]],
)
def test_declared_guards_rejects_malformed_or_duplicate_entries(guards: object) -> None:
    with pytest.raises(ValueError):
        agb_run.declared_guards(
            {
                "guards": guards,
                "expected_findings": [],
                "forbidden_findings": [],
            }
        )


def test_declared_guards_rejects_expected_guard_that_is_not_declared() -> None:
    with pytest.raises(ValueError, match="must be declared"):
        agb_run.declared_guards(
            {
                "guards": ["context"],
                "expected_findings": [
                    {"guard": "content", "rule": "pipe_to_shell", "path": "docs/install.md"}
                ],
                "forbidden_findings": [],
            }
        )


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


def test_run_guard_returns_sanitized_runner_error_for_non_json(tmp_path: Path, monkeypatch) -> None:
    case_dir = tmp_path / "case"
    (case_dir / "policies").mkdir(parents=True)

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=2, stdout="not json", stderr=f"boom at {tmp_path}")

    monkeypatch.setattr(agb_run.subprocess, "run", fake_run)

    payload = agb_run.run_guard(tmp_path, case_dir, "context")

    assert payload == {"exit_code": 2, "findings": [], "runner_error": "runner_invalid_json"}
    assert str(tmp_path) not in json.dumps(payload)


def test_run_guard_returns_runner_error_for_non_object_json(tmp_path: Path, monkeypatch) -> None:
    case_dir = tmp_path / "case"
    (case_dir / "policies").mkdir(parents=True)

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout='["not", "an", "object"]', stderr="")

    monkeypatch.setattr(agb_run.subprocess, "run", fake_run)

    assert agb_run.run_guard(tmp_path, case_dir, "context") == {
        "exit_code": 0,
        "findings": [],
        "runner_error": "runner_invalid_json_type",
    }


@pytest.mark.parametrize(
    "malformed_findings",
    [
        {"malformed": "not-a-list"},
        ["not-an-object"],
        [{"rule_id": "approval_bypass"}],
        [{"file": "AGENTS.md"}],
        [{"rule_id": 123, "file": "AGENTS.md"}],
        [{"rule_id": ["approval_bypass"], "file": "AGENTS.md"}],
        [{"rule_id": "approval_bypass", "file": 456}],
        [{"rule_id": "approval_bypass", "file": {"path": "AGENTS.md"}}],
        [{"rule_id": "approval_bypass", "file": "AGENTS.md", "reason": 789}],
    ],
)
def test_run_guard_rejects_malformed_findings(
    tmp_path: Path,
    monkeypatch,
    malformed_findings: object,
) -> None:
    case_dir = tmp_path / "case"
    (case_dir / "policies").mkdir(parents=True)

    def fake_run(*args, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"findings": malformed_findings}),
            stderr="",
        )

    monkeypatch.setattr(agb_run.subprocess, "run", fake_run)

    assert agb_run.run_guard(tmp_path, case_dir, "context") == {
        "exit_code": 0,
        "findings": [],
        "runner_error": "runner_invalid_json_type",
    }


def test_run_guard_labels_valid_json_execution_error(tmp_path: Path, monkeypatch) -> None:
    case_dir = tmp_path / "case"
    (case_dir / "policies").mkdir(parents=True)

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=2, stdout='{"findings":[],"error":"raw failure"}', stderr="")

    monkeypatch.setattr(agb_run.subprocess, "run", fake_run)

    payload = agb_run.run_guard(tmp_path, case_dir, "context")

    assert payload["exit_code"] == 2
    assert payload["runner_error"] == "runner_execution_error"
    assert "raw failure" not in json.dumps(payload)


def test_evaluate_case_sanitizes_raw_runner_error(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    write_expected(
        case_dir,
        {
            "case_id": "case",
            "guards": ["context"],
            "expected_findings": [],
            "forbidden_findings": [],
        },
    )

    result = agb_run.evaluate_case(
        case_dir,
        {"context": {"exit_code": 2, "findings": [], "runner_error": f"raw at {tmp_path}"}},
    )

    assert result.errors == {"context": "runner_execution_error"}
    assert str(tmp_path) not in json.dumps(result.to_dict())


def test_public_finding_path_redacts_windows_user_path_on_posix(tmp_path: Path) -> None:
    public_path = agb_run.public_finding_path(r"C:\Users\alice\secrets\policy.yaml", tmp_path)

    assert public_path == "<absolute-path>"
    assert agb_run.public_finding_path(r"D:\work\policy.yaml", tmp_path) == "<absolute-path>"


def test_public_finding_path_redacts_url_and_secret_shaped_relative_paths(tmp_path: Path) -> None:
    raw_hash = "a" * 64

    assert agb_run.public_finding_path("https://example.invalid/path?token=abc", tmp_path) == "<redacted-url>"
    assert agb_run.public_finding_path(f"docs/sk-{'a' * 16}/bad.md", tmp_path) == "docs/<redacted>/bad.md"
    assert agb_run.public_finding_path(f"docs/{raw_hash}/bad.md", tmp_path) == "docs/<redacted>/bad.md"


def test_public_finding_path_redacts_external_posix_absolute_path(tmp_path: Path) -> None:
    public_path = agb_run.public_finding_path("/etc/passwd", tmp_path)

    assert public_path == "<absolute-path>"


def test_evaluate_case_redacts_finding_reason_and_expected_metadata(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    sensitive = (
        f"https://example.invalid/private sk-{'a' * 16} {'b' * 64} "
        "/home/alice/private.txt /tmp/private/policy.yaml"
    )
    write_expected(
        case_dir,
        {
            "case_id": sensitive,
            "guards": ["context"],
            "expected_findings": [
                {"guard": "context", "rule": "unexpected", "path": "AGENTS.md", "reason": sensitive}
            ],
            "forbidden_findings": [],
        },
    )

    result = agb_run.evaluate_case(
        case_dir,
        {
            "context": {
                "findings": [
                    {"rule_id": "unexpected", "file": "AGENTS.md", "reason": sensitive}
                ]
            }
        },
    )

    serialized = json.dumps(result.to_dict(), sort_keys=True)
    assert result.counts == {"tp": 1, "fp": 0, "fn": 0}
    assert "example.invalid" not in serialized
    assert "sk-" not in serialized
    assert "b" * 64 not in serialized
    assert "/home/alice" not in serialized
    assert "/tmp/private" not in serialized


def test_redaction_does_not_collapse_distinct_scoring_values(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    expected_token = f"sk-{'a' * 16}"
    actual_token = f"sk-{'b' * 16}"
    write_expected(
        case_dir,
        {
            "case_id": "case",
            "guards": ["context"],
            "expected_findings": [
                {
                    "guard": "context",
                    "rule": "unexpected",
                    "path": f"docs/{expected_token}/bad.md",
                    "reason": expected_token,
                }
            ],
            "forbidden_findings": [],
        },
    )

    result = agb_run.evaluate_case(
        case_dir,
        {
            "context": {
                "findings": [
                    {
                        "rule_id": "unexpected",
                        "file": f"docs/{actual_token}/bad.md",
                        "reason": actual_token,
                    }
                ]
            }
        },
    )

    public_result = json.dumps(result.to_dict(), sort_keys=True)
    assert result.counts == {"tp": 0, "fp": 1, "fn": 1}
    assert expected_token not in public_result
    assert actual_token not in public_result


def test_run_guard_keeps_findings_exit_code_one_successful(tmp_path: Path, monkeypatch) -> None:
    case_dir = tmp_path / "case"
    write_expected(
        case_dir,
        {
            "case_id": "case",
            "guards": ["context"],
            "expected_findings": [],
            "forbidden_findings": [],
        },
    )
    (case_dir / "policies").mkdir(parents=True, exist_ok=True)
    finding_path = case_dir / "AGENTS.md"

    def fake_run(*args, **kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout=json.dumps({"findings": [{"rule_id": "approval_bypass", "file": str(finding_path)}]}),
            stderr="",
        )

    monkeypatch.setattr(agb_run.subprocess, "run", fake_run)

    payload = agb_run.run_guard(tmp_path, case_dir, "context")
    result = agb_run.evaluate_case(
        case_dir,
        {
            "context": payload,
        },
    )

    assert "runner_error" not in payload
    assert result.false_positives[0].path == "AGENTS.md"
    assert str(tmp_path) not in json.dumps(result.to_dict())


def test_main_writes_result_file(tmp_path: Path, monkeypatch) -> None:
    out_path = tmp_path / "result.json"

    def fake_build_results(repo_root: Path, fixtures_root: Path) -> dict[str, object]:
        return {"schema_version": "agent-guard.agb_results.v1", "case_count": 0}

    monkeypatch.setattr(agb_run, "build_results", fake_build_results)

    assert agb_run.main(["--repo-root", str(tmp_path), "--fixtures", "fixtures", "--out", str(out_path)]) == 0
    assert json.loads(out_path.read_text(encoding="utf-8"))["case_count"] == 0


def test_main_returns_nonzero_and_writes_diagnostics_for_runner_error(tmp_path: Path, monkeypatch, capsys) -> None:
    out_path = tmp_path / "result.json"
    payload = {
        "schema_version": "agent-guard.agb_results.v1",
        "case_count": 1,
        "cases": [{"case_id": "case", "errors": {"context": "runner_invalid_json"}}],
    }

    def fake_build_results(repo_root: Path, fixtures_root: Path) -> dict[str, object]:
        return payload

    monkeypatch.setattr(agb_run, "build_results", fake_build_results)

    assert agb_run.main(["--repo-root", str(tmp_path), "--fixtures", "fixtures", "--out", str(out_path)]) == 2

    written = json.loads(out_path.read_text(encoding="utf-8"))
    printed = json.loads(capsys.readouterr().out)
    assert written["cases"][0]["errors"] == {"context": "runner_invalid_json"}
    assert printed == written


def test_malformed_guard_findings_fail_closed_through_reporting(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    case_dir = tmp_path / "fixtures" / "case"
    write_expected(
        case_dir,
        {
            "case_id": "case",
            "guards": ["context"],
            "expected_findings": [],
            "forbidden_findings": [],
        },
    )

    def fake_run(*args, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"findings": {"malformed": "not-a-list"}}),
            stderr="",
        )

    monkeypatch.setattr(agb_run.subprocess, "run", fake_run)

    assert agb_run.main(["--repo-root", str(tmp_path), "--fixtures", "fixtures"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["cases"][0]["errors"] == {"context": "runner_invalid_json_type"}
    with pytest.raises(agb_reporting.DiagnosticResultError, match="case diagnostics"):
        agb_reporting.guard_results_table(payload)


def test_main_returns_diagnostic_json_for_malformed_expected_without_path_or_traceback(
    tmp_path: Path,
    capsys,
) -> None:
    case_dir = tmp_path / "fixtures" / "case"
    case_dir.mkdir(parents=True)
    (case_dir / "expected.json").write_text("{not json", encoding="utf-8")
    out_path = tmp_path / "result.json"

    assert agb_run.main(["--repo-root", str(tmp_path), "--fixtures", "fixtures", "--out", str(out_path)]) == 2

    captured = capsys.readouterr()
    written = out_path.read_text(encoding="utf-8")
    printed = captured.out
    payload = json.loads(printed)

    assert captured.err == ""
    assert payload["schema_version"] == "agent-guard.agb_results.v1"
    assert payload["case_count"] == 0
    assert payload["overall"] == agb_run.metrics_from_counts({"tp": 0, "fp": 0, "fn": 0})
    assert payload["by_guard"] == {}
    assert payload["cases"] == []
    assert payload["benchmark_error"] == {"type": "benchmark_fixture_error"}
    assert isinstance(payload["generated_at"], str)
    assert json.loads(written) == payload
    combined_output = printed + written
    assert "Traceback" not in combined_output
    assert "JSONDecodeError" not in combined_output
    assert str(tmp_path) not in combined_output


def test_main_rejects_malformed_expected_field_without_disclosing_value(
    tmp_path: Path,
    capsys,
) -> None:
    case_dir = tmp_path / "fixtures" / "case"
    private_value = f"unsupported-{tmp_path}"
    write_expected(
        case_dir,
        {
            "case_id": "case",
            "guards": ["context"],
            "expected_findings": [
                {"guard": private_value, "rule": "approval_bypass", "path": "AGENTS.md"}
            ],
            "forbidden_findings": [],
        },
    )

    assert agb_run.main(["--repo-root", str(tmp_path), "--fixtures", "fixtures"]) == 2

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["benchmark_error"] == {"type": "benchmark_fixture_error"}
    assert private_value not in captured.out
    assert str(tmp_path) not in captured.out
    assert captured.err == ""


def test_has_runner_errors_recognizes_benchmark_error() -> None:
    assert agb_run.has_runner_errors(
        {
            "schema_version": "agent-guard.agb_results.v1",
            "benchmark_error": {"type": "benchmark_fixture_error"},
        }
    )
    assert agb_run.has_runner_errors({"benchmark_error": {}})
    assert agb_run.has_runner_errors({"cases": [{"errors": None}]})


@pytest.mark.parametrize(
    "cases",
    [None, {}, "not-a-list", ["not-an-object"], [{"errors": None}]],
)
def test_has_runner_errors_rejects_malformed_cases(cases: object) -> None:
    assert agb_run.has_runner_errors({"cases": cases})


def test_has_runner_errors_accepts_missing_cases_and_empty_case_errors() -> None:
    assert not agb_run.has_runner_errors({"overall": {}})
    assert not agb_run.has_runner_errors({"cases": [{"errors": {}}]})


def test_guard_command_supports_digest_and_drift(tmp_path: Path) -> None:
    policies = tmp_path / "policies"

    assert agb_run.guard_command(tmp_path, "digest") == [
        "digest",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(policies / "digest-policy.yaml"),
        "--json",
    ]
    assert agb_run.guard_command(tmp_path, "drift") == [
        "drift",
        "check",
        "--root",
        str(tmp_path),
        "--profile",
        "recommended",
        "--schema-version",
        "v2",
        "--json",
    ]


def test_sprint3_fixture_corpus_has_expected_group_counts() -> None:
    fixtures_root = Path(__file__).resolve().parents[1] / "bench" / "agb" / "fixtures"
    group_counts: dict[str, int] = {}
    case_ids: set[str] = set()
    for expected_path in fixtures_root.glob("*/expected.json"):
        payload = json.loads(expected_path.read_text(encoding="utf-8"))
        case_id = str(payload["case_id"])
        assert case_id not in case_ids
        case_ids.add(case_id)
        group = str(payload["group"])
        group_counts[group] = group_counts.get(group, 0) + 1

    assert group_counts == {"A": 16, "B": 10, "C": 13, "D": 6, "E": 10, "F": 5}


def test_guard_results_table_renders_markdown_from_result_payload() -> None:
    payload = {
        "by_guard": {
            "context": {"tp": 16, "fp": 0, "fn": 1, "precision": 1, "recall": 0.941176, "f1": 0.969697},
            "path": {"tp": 7, "fp": 0, "fn": 0, "precision": 1, "recall": 1, "f1": 1},
        }
    }

    table = agb_reporting.guard_results_table(payload)

    assert "| Context | 16 | 0 | 1 | 1.000000 | 0.941176 | 0.969697 |" in table
    assert "| Path | 7 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |" in table


def test_guard_results_table_rejects_benchmark_error_payload() -> None:
    payload = {
        "by_guard": {},
        "cases": [],
        "benchmark_error": {"type": "private diagnostic value"},
    }

    with pytest.raises(agb_reporting.DiagnosticResultError, match="benchmark diagnostics") as error:
        agb_reporting.guard_results_table(payload)

    assert "private diagnostic value" not in str(error.value)


def test_guard_results_table_rejects_case_level_errors() -> None:
    payload = {
        "by_guard": {},
        "cases": [{"case_id": "case", "errors": {"context": "private diagnostic value"}}],
    }

    with pytest.raises(agb_reporting.DiagnosticResultError, match="case diagnostics") as error:
        agb_reporting.guard_results_table(payload)

    assert "private diagnostic value" not in str(error.value)


@pytest.mark.parametrize(
    "cases",
    [None, {}, "not-a-list", ["not-an-object"]],
)
def test_guard_results_table_rejects_malformed_cases(cases: object) -> None:
    payload = {"by_guard": {}, "cases": cases}

    with pytest.raises(agb_reporting.DiagnosticResultError, match="malformed case diagnostics"):
        agb_reporting.guard_results_table(payload)


def test_reporting_main_returns_2_for_diagnostic_result_without_table(
    tmp_path: Path,
    capsys,
) -> None:
    result_path = tmp_path / "result.json"
    result_path.write_text(
        json.dumps(
            {
                "by_guard": {},
                "cases": [],
                "benchmark_error": {"type": "private diagnostic value"},
            }
        ),
        encoding="utf-8",
    )

    assert agb_reporting.main([str(result_path)]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "AGB result contains benchmark diagnostics; refusing to render metrics\n"
    assert "private diagnostic value" not in captured.err


def test_reporting_main_returns_2_for_explicit_null_cases_without_table(
    tmp_path: Path,
    capsys,
) -> None:
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps({"by_guard": {}, "cases": None}), encoding="utf-8")

    assert agb_reporting.main([str(result_path)]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "AGB result contains malformed case diagnostics; refusing to render metrics\n"
