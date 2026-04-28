"""Where: tests/test_check_release_version.py
What: pin the release tag/version consistency guard used by the workflow.
Why: a broken guard would let mismatched tags reach PyPI upload.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_release_version.py"
PYPROJECT = ROOT / "pyproject.toml"


def project_version() -> str:
    """Read the current package version from pyproject.toml."""
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def run_script(tag_name: str) -> subprocess.CompletedProcess[str]:
    """Execute the release-version guard exactly as the workflow does."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), tag_name],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_matching_tag_succeeds() -> None:
    version = project_version()

    result = run_script(f"v{version}")

    assert result.returncode == 0
    assert f"release tag/version match: {version}" in result.stdout


def test_mismatched_tag_fails_early() -> None:
    version = project_version()
    bad_version = "0.0.0" if version != "0.0.0" else "9.9.9"

    result = run_script(f"v{bad_version}")

    assert result.returncode == 1
    assert f"tag={bad_version}" in result.stderr
    assert f"pyproject={version}" in result.stderr
