"""Where: tests/test_ttfe_runner.py
What: unit tests for the TTFE quickstart replay helper.
Why: keep the Day 4 onboarding benchmark deterministic and diffable.
"""

from __future__ import annotations

from pathlib import Path

from bench.ttfe import run as ttfe_run

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_extract_bash_commands_skips_yaml_and_preserves_order() -> None:
    markdown = """
```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install yui-agent-guard
```

```yaml
jobs:
  test:
    steps:
      - run: echo not-a-quickstart-command
```

```bash
agent-guard init --root . --print
```
"""

    assert ttfe_run.extract_bash_commands(markdown) == [
        "python3 -m venv .venv",
        ". .venv/bin/activate",
        "python -m pip install yui-agent-guard",
        "agent-guard init --root . --print",
    ]


def test_build_result_payload_records_failure_and_pack_reach() -> None:
    payload = ttfe_run.build_result_payload(
        source_doc="docs/quickstart-existing-repo.md",
        commands=["agent-guard report --format json", "agent-guard evidence-pack manifest --json"],
        records=[
            {"index": 1, "command": "agent-guard report --format json", "exit_code": 1},
            {"index": 2, "command": "agent-guard evidence-pack manifest --json", "exit_code": 0},
        ],
        elapsed_ms=1234,
        setup={"wheelhouse": "skipped"},
    )

    assert payload["schema_version"] == "agent-guard.ttfe_results.v1"
    assert payload["status"] == "ok"
    assert payload["command_count"] == 2
    assert payload["first_nonzero"]["index"] == 1
    assert payload["failure_point"] is None
    assert payload["reached_recommended_evidence_pack"] is True
    assert payload["elapsed_ms"] == 1234


def test_quickstart_golden_path_stays_short_and_fixture_runnable() -> None:
    quickstart = (REPO_ROOT / "docs" / "quickstart-existing-repo.md").read_text(encoding="utf-8")

    commands = ttfe_run.extract_bash_commands(quickstart)

    assert len(commands) <= 4
    assert ttfe_run.reaches_recommended_evidence_pack([{"command": command} for command in commands])
    assert not any("--root services/api" in command for command in commands)


def test_quickstart_splits_diagnostic_and_green_ci_paths() -> None:
    quickstart = (REPO_ROOT / "docs" / "quickstart-existing-repo.md").read_text(encoding="utf-8")
    quickstart_single_line = " ".join(quickstart.split())

    assert "Initial Diagnostic Path" in quickstart
    assert "Green CI Path" in quickstart
    assert "report` or `conformance` exits `1`" in quickstart_single_line
    assert "expected, correct fail-closed behavior" in quickstart_single_line
    assert "everything exits `0`" in quickstart_single_line
    assert "| `0` |" in quickstart
    assert "| `1` |" in quickstart
    assert "| `>=2` |" in quickstart


def test_validate_result_payload_enforces_time_and_completion() -> None:
    payload = ttfe_run.build_result_payload(
        source_doc="docs/quickstart-existing-repo.md",
        commands=["agent-guard evidence-pack manifest --json"],
        records=[
            {
                "index": 1,
                "command": "agent-guard evidence-pack manifest --json",
                "exit_code": 0,
            }
        ],
        elapsed_ms=1_000,
        setup={"status": "local_wheelhouse"},
    )

    assert ttfe_run.validate_result_payload(payload, max_elapsed_ms=900_000) == []

    payload["elapsed_ms"] = 900_001
    payload["failure_point"] = {"index": 1, "exit_code": 2}
    errors = ttfe_run.validate_result_payload(payload, max_elapsed_ms=900_000)

    assert "TTFE replay exceeded the configured time limit" in errors
    assert "TTFE replay encountered a configuration or runtime error" in errors

    payload["setup"] = {"status": "wheelhouse_failed"}
    errors = ttfe_run.validate_result_payload(payload, max_elapsed_ms=900_000)
    assert "TTFE replay did not install the current checkout wheel" in errors
