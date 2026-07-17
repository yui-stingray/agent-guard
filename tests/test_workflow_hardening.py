"""Regression tests for CI and release supply-chain hardening."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from agent_guard.init_guard import GITHUB_WORKFLOW

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_FILES = [
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "release.yml",
    ROOT / ".github" / "workflows" / "github-release.yml",
    ROOT / "action.yml",
]
USES_PATTERN = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)
HARD_ERROR_PRECEDENCE = (
    'if [ "$code" -ge 2 ] || { [ "$code" -ne 0 ] && [ "$status" -eq 0 ]; }; then'
)


def test_executable_action_dependencies_are_pinned_to_full_commit_shas() -> None:
    for path in WORKFLOW_FILES:
        text = path.read_text(encoding="utf-8")
        references = USES_PATTERN.findall(text)
        assert references, path
        for reference in references:
            if reference == "./":
                assert path == ROOT / ".github" / "workflows" / "ci.yml"
                continue
            assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference), (path, reference)


def test_ci_covers_supported_current_python_versions_and_ttfe() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for version in ("3.11.4", "3.12", "3.13", "3.14"):
        assert f"'{version}'" in workflow
    assert "Replay 15-minute onboarding path" in workflow
    assert "--max-elapsed-ms 900000" in workflow


def test_ci_runs_packaged_action_consumer_smoke() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "name: packaged action smoke" in workflow
    assert "uses: ./" in workflow
    assert 'test "$ACTION_STATUS" = "0"' in workflow
    assert 'python -m agent_guard.consumer "$REPORT_JSON"' in workflow


def test_evidence_workflows_preserve_runtime_error_precedence() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    manual_workflow = (ROOT / "docs" / "github-actions-evidence.md").read_text(
        encoding="utf-8"
    )
    for text in (action, GITHUB_WORKFLOW, manual_workflow):
        assert HARD_ERROR_PRECEDENCE in text
        assert 'if [ "$code" -eq 2 ]' not in text

    result = subprocess.run(
        [
            "bash",
            "-c",
            f"""
status=0
record_status() {{
  code="$1"
  {HARD_ERROR_PRECEDENCE}
    status="$code"
  fi
}}
record_status 1
record_status 127
printf '%s\\n' "$status"
""",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout == "127\n"
    assert result.stderr == ""


def test_release_requires_current_master_and_successful_ci() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "actions: read" in workflow
    assert "check_release_source.py" in workflow
    assert '--workflow ci.yml' in workflow
    assert '--branch master' in workflow
    assert '--event push' in workflow
