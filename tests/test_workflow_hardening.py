"""Regression tests for CI and release supply-chain hardening."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_FILES = [
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "release.yml",
    ROOT / ".github" / "workflows" / "github-release.yml",
    ROOT / "action.yml",
]
USES_PATTERN = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)


def test_executable_action_dependencies_are_pinned_to_full_commit_shas() -> None:
    for path in WORKFLOW_FILES:
        text = path.read_text(encoding="utf-8")
        references = USES_PATTERN.findall(text)
        assert references, path
        for reference in references:
            assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference), (path, reference)


def test_ci_covers_supported_current_python_versions_and_ttfe() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for version in ("3.11", "3.12", "3.13", "3.14"):
        assert f"'{version}'" in workflow
    assert "Replay 15-minute onboarding path" in workflow
    assert "--max-elapsed-ms 900000" in workflow


def test_release_requires_current_master_and_successful_ci() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "actions: read" in workflow
    assert "check_release_source.py" in workflow
    assert '--workflow ci.yml' in workflow
    assert '--branch master' in workflow
    assert '--event push' in workflow
