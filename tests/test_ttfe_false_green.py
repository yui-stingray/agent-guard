"""TTFE false-green regression cases; legacy results are not install evidence."""
from pathlib import Path
from bench.ttfe import run as ttfe_run

ROOT = Path(__file__).resolve().parents[1]


def legacy_result():
    commands = ttfe_run.extract_bash_commands(
        (ROOT / "docs/quickstart-existing-repo.md").read_text()
    )
    return ttfe_run.build_result_payload(
        source_doc="docs/quickstart-existing-repo.md", commands=commands,
        records=[
            {"index": i, "command": command, "exit_code": 1 if i in (1, 4) else 0,
             "duration_ms": 1}
            for i, command in enumerate(commands, 1)
        ],
        elapsed_ms=20, setup={"status": "local_wheelhouse"},
    )


def test_failed_install_cannot_be_hidden_by_later_commands():
    payload = legacy_result()
    assert payload["status"] == "failed"
    assert ttfe_run.validate_result_payload(payload, max_elapsed_ms=900000)


def test_summary_and_marker_are_not_substitutes_for_records():
    payload = legacy_result()
    payload["status"] = "ok"
    payload["commands"] = []
    assert ttfe_run.validate_result_payload(payload, max_elapsed_ms=900000)
