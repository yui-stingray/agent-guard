"""Where: tests/test_check_changelog.py
What: pin the changelog readiness guard used by CI and release workflows.
Why: missing release notes should be caught before a version tag is pushed.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_changelog.py"
SPEC = importlib.util.spec_from_file_location("check_changelog", SCRIPT)
assert SPEC is not None
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_changelog_versions_extract_semver_headings(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "# Changelog\n\n"
        "## 0.1.1 - 2026-04-30\n\n"
        "- Current release.\n\n"
        "## Not a version\n\n"
        "## 0.1.0\n",
        encoding="utf-8",
    )

    assert MODULE.changelog_versions(changelog) == ["0.1.1", "0.1.0"]


def test_current_project_version_has_changelog_entry() -> None:
    root = Path(__file__).resolve().parents[1]
    version = MODULE.load_project_version(root / "pyproject.toml")

    assert version in MODULE.changelog_versions(root / "CHANGELOG.md")


def test_extract_release_notes_returns_selected_body(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "# Changelog\n\n"
        "## 0.1.1 - 2026-04-30\n\n"
        "- Current release.\n"
        "- Second item.\n\n"
        "## 0.1.0\n\n"
        "- Older release.\n",
        encoding="utf-8",
    )

    assert MODULE.extract_release_notes(changelog, "0.1.1") == "- Current release.\n- Second item.\n"

