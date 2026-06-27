"""Where: tests/test_packaging.py
What: packaging invariants for the extracted guard package.
Why: keep version drift and typed-package regressions out of the release path.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import agent_guard


REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
README = REPO_ROOT / "README.md"
PACKAGE_DIR = REPO_ROOT / "src" / "agent_guard"


def pyproject_version() -> str:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_package_version_matches_pyproject() -> None:
    assert agent_guard.__version__ == pyproject_version()


def test_readme_status_matches_pyproject_version() -> None:
    assert f"**Status**: `{pyproject_version()}` alpha." in README.read_text(encoding="utf-8")


def test_readme_documents_ai_resilience_ci_gate_recipe() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "## CI gate recipe" in readme
    assert "agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json" in readme
    assert "agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json" in readme
    assert (
        "agent-guard digest check --root . --policy .agent-guard/constitution-digest-policy.yaml --json"
        in readme
    )
    assert (
        "agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml "
        "--mode registered --scan-dir . --json"
        in readme
    )
    assert "agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json" in readme


def test_readme_documents_operational_example_policy_coverage() -> None:
    readme = README.read_text(encoding="utf-8")

    assert '- "**/*.yaml"' in readme
    assert '- "**/*.sh"' in readme
    assert "destructive_rm_root" in readme
    assert "local_artifacts" in readme


def test_py_typed_marker_is_present() -> None:
    marker = PACKAGE_DIR / "py.typed"
    assert marker.is_file()
    assert marker.stat().st_size == 0
