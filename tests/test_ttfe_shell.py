"""Subprocess boundaries for the local TTFE shell runner and result checker."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


def isolated_env(tmp_path: Path) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("PYTHON", "PIP_")) and key != "VIRTUAL_ENV"}
    env.update(TMPDIR=str(tmp_path), TEMP=str(tmp_path), TMP=str(tmp_path),
               PIP_NO_INDEX="1", PIP_CONFIG_FILE=os.devnull,
               AGENT_GUARD_TTFE_OUT=str(tmp_path / "result.json"))
    return env


def test_explicit_invalid_interpreter_never_falls_back(tmp_path: Path) -> None:
    env = isolated_env(tmp_path)
    env["PYTHON"] = str(tmp_path / "missing-python")
    completed = subprocess.run(
        ["bash", str(ROOT / "bench/ttfe/run.sh")], cwd=ROOT, env=env,
        text=True, capture_output=True, timeout=15,
    )
    assert completed.returncode != 0
    assert not (tmp_path / "result.json").exists()


def test_shell_propagates_interpreter_bootstrap_failure(tmp_path: Path) -> None:
    interpreter = tmp_path / "failed-python"
    interpreter.write_text("#!/bin/sh\nexit 42\n")
    interpreter.chmod(0o755)
    env = isolated_env(tmp_path)
    env["PYTHON"] = str(interpreter)
    completed = subprocess.run(
        ["bash", str(ROOT / "bench/ttfe/run.sh")], cwd=ROOT, env=env,
        text=True, capture_output=True, timeout=15,
    )
    assert completed.returncode == 42
    assert not (tmp_path / "result.json").exists()


@pytest.mark.parametrize("content", [
    "[" * 2000 + "]" * 2000,
    "null", "[]", "false", "0", '""', "{}", "{",
    '{"schema_version":"agent-guard.ttfe_results.v2","elapsed_ms":NaN}',
    '{"schema_version":"agent-guard.ttfe_results.v2","status":"failed","status":"ok"}',
])
def test_check_cli_rejects_invalid_result_json(tmp_path: Path, content: str) -> None:
    artifact = tmp_path / "result.json"
    artifact.write_text(content)
    completed = subprocess.run(
        [sys.executable, "-m", "bench.ttfe.run", "check", "--input", str(artifact)],
        cwd=ROOT, env=isolated_env(tmp_path), text=True, capture_output=True, timeout=15,
    )
    assert completed.returncode != 0
    assert "TTFE gate passed" not in completed.stdout
    assert "Traceback" not in completed.stderr


def test_legacy_success_requires_a_rerun(tmp_path: Path) -> None:
    artifact = tmp_path / "legacy.json"
    artifact.write_text(json.dumps({
        "schema_version": "agent-guard.ttfe_results.v1", "status": "ok",
        "failure_point": None, "reached_recommended_evidence_pack": True,
        "setup": {"status": "local_wheelhouse"}, "elapsed_ms": 20,
        "documented_command_count": 4, "command_count": 4, "commands": [],
    }))
    completed = subprocess.run(
        [sys.executable, "-m", "bench.ttfe.run", "check", "--input", str(artifact)],
        cwd=ROOT, env=isolated_env(tmp_path), text=True, capture_output=True, timeout=15,
    )
    assert completed.returncode != 0
    assert "rerun" in (completed.stdout + completed.stderr).lower()
    assert "TTFE gate passed" not in completed.stdout


def test_result_command_does_not_turn_written_diagnostics_into_success(tmp_path: Path) -> None:
    records = tmp_path / "records.jsonl"
    records.write_text("")
    artifact = tmp_path / "result.json"
    completed = subprocess.run(
        [sys.executable, "-m", "bench.ttfe.run", "result",
         "--source", str(ROOT / "docs/quickstart-existing-repo.md"),
         "--records", str(records), "--out", str(artifact),
         "--elapsed-ms", "10", "--setup", '{"status":"wheelhouse_failed"}'],
        cwd=ROOT, env=isolated_env(tmp_path), text=True, capture_output=True, timeout=15,
    )
    assert completed.returncode != 0
    assert json.loads(artifact.read_text())["status"] == "failed"
    checked = subprocess.run(
        [sys.executable, "-m", "bench.ttfe.run", "check", "--input", str(artifact)],
        cwd=ROOT, env=isolated_env(tmp_path), text=True, capture_output=True, timeout=15,
    )
    assert checked.returncode != 0
