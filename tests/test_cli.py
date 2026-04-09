"""Where: tests/test_cli.py
What: subprocess tests for the agent-guard CLI.
Why: pin the shared exit-code and JSON envelope contract for wrappers and CI.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agent_guard.cli", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_cli_json_ok(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "scan:\n  include:\n    - src\n  exclude: []\npolicy:\n  allowed_api_patterns: []\n  forbidden_api_patterns:\n    - '^https://api\\.openai\\.com/'\n",
        encoding="utf-8",
    )
    write(tmp_path / "src" / "ok.py", 'URL = "https://example.com"\n')

    result = run_cli("api", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload == {"status": "ok", "scanner": "api", "finding_count": 0, "findings": []}


def test_cli_json_violation(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "scan:\n  include:\n    - src\n  exclude: []\npolicy:\n  allowed_api_patterns: []\n  forbidden_api_patterns:\n    - '^https://api\\.openai\\.com/'\n",
        encoding="utf-8",
    )
    write(tmp_path / "src" / "bad.py", 'URL = "https://api.openai.com/v1/responses"\n')

    result = run_cli("api", "check", "--root", str(tmp_path), "--policy", str(policy), "--json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "violation"
    assert payload["scanner"] == "api"
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["path"] == "src/bad.py"


def test_cli_json_error(tmp_path: Path) -> None:
    result = run_cli("api", "check", "--root", str(tmp_path), "--policy", str(tmp_path / "missing.yaml"), "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert payload["scanner"] == "api"
