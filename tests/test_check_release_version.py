"""Where: tests/test_check_release_version.py
What: pin the release tag/version consistency guard used by the workflow.
Why: a broken guard would let mismatched tags reach PyPI upload.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_release_version.py"
PYPROJECT = ROOT / "pyproject.toml"
SPEC = importlib.util.spec_from_file_location("check_release_version", SCRIPT)
assert SPEC is not None
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


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


def test_matching_development_tag_is_not_releasable() -> None:
    version = project_version()

    result = run_script(f"v{version}")

    assert version == "0.3.6.dev0"
    assert MODULE.FINAL_RELEASE_VERSION_RE.fullmatch(version) is None
    assert result.returncode == 1
    assert "release tag must name a final numeric x.y.z version" in result.stderr


def test_final_release_version_grammar_is_bounded() -> None:
    assert MODULE.FINAL_RELEASE_VERSION_RE.fullmatch("0.3.5")
    for value in ("0.3.5.dev0", "0.3.5rc1", "0.3", "v0.3.5", "0.3.5+local"):
        assert MODULE.FINAL_RELEASE_VERSION_RE.fullmatch(value) is None


def test_mismatched_tag_fails_early() -> None:
    version = project_version()
    bad_version = "0.0.0" if version != "0.0.0" else "9.9.9"

    result = run_script(f"v{bad_version}")

    assert result.returncode == 1
    assert f"tag={bad_version}" in result.stderr
    assert f"pyproject={version}" in result.stderr
