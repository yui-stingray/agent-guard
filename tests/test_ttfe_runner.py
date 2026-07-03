"""Where: tests/test_ttfe_runner.py
What: unit tests for the TTFE quickstart replay helper.
Why: keep the Day 4 onboarding benchmark deterministic and diffable.
"""

from __future__ import annotations

from bench.ttfe import run as ttfe_run


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
agent-guard init --root . --json
```
"""

    assert ttfe_run.extract_bash_commands(markdown) == [
        "python3 -m venv .venv",
        ". .venv/bin/activate",
        "python -m pip install yui-agent-guard",
        "agent-guard init --root . --json",
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
