"""Where: tests/test_package_contract.py
What: package metadata, schema resources, and typed package invariants.
Why: keep version drift and typed-package regressions out of the release path.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import agent_guard
import pytest
import scripts.check_wheel_contract as wheel_contract


REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
EVIDENCE_SAMPLE_REPORT = REPO_ROOT / "docs" / "evidence-samples" / "agent-guard-report.json"
PACKAGE_DIR = REPO_ROOT / "src" / "agent_guard"
SCHEMA_DIR = PACKAGE_DIR / "schemas"


def pyproject_version() -> str:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_package_version_matches_pyproject() -> None:
    assert agent_guard.__version__ == pyproject_version()


def test_package_requires_safe_tar_filter_runtime() -> None:
    with PYPROJECT.open("rb") as fh:
        pyproject = tomllib.load(fh)

    assert pyproject["project"]["requires-python"] == ">=3.11.4"


def test_wheel_contract_uses_platform_specific_venv_interpreter() -> None:
    venv_dir = Path("contract-venv")

    assert wheel_contract.venv_python_path(venv_dir, platform_name="posix") == venv_dir / "bin" / "python"
    assert wheel_contract.venv_python_path(venv_dir, platform_name="nt") == venv_dir / "Scripts" / "python.exe"


def test_wheel_contract_requires_exact_current_distribution_set(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    version = "1.2.3"
    dist = tmp_path / "dist"
    monkeypatch.setattr(wheel_contract, "DIST", dist)

    with pytest.raises(RuntimeError, match="directory is missing") as missing:
        wheel_contract.find_release_distributions(version)
    assert str(tmp_path) not in str(missing.value)

    dist.mkdir()
    wheel = dist / f"yui_agent_guard-{version}-py3-none-any.whl"
    sdist = dist / f"yui_agent_guard-{version}.tar.gz"
    wheel.write_bytes(b"wheel")

    with pytest.raises(RuntimeError, match="exactly the current") as incomplete:
        wheel_contract.find_release_distributions(version)
    assert str(tmp_path) not in str(incomplete.value)

    sdist.write_bytes(b"sdist")
    assert wheel_contract.find_release_distributions(version) == (wheel, sdist)

    (dist / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="exactly the current"):
        wheel_contract.find_release_distributions(version)


def test_dev_extra_includes_benchmark_schema_tools() -> None:
    with PYPROJECT.open("rb") as fh:
        pyproject = tomllib.load(fh)

    dev_deps = pyproject["project"]["optional-dependencies"]["dev"]

    assert any(dep.startswith("pytest-cov") for dep in dev_deps)
    assert any(dep.startswith("jsonschema") for dep in dev_deps)


def test_execution_notes_are_not_tracked_or_packaged() -> None:
    with PYPROJECT.open("rb") as fh:
        pyproject = tomllib.load(fh)

    assert not (REPO_ROOT / "execution-notes.md").exists()
    assert "execution-notes.md" in (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "/execution-notes.md" in pyproject["tool"]["hatch"]["build"]["exclude"]


def test_public_sample_report_matches_pyproject_version() -> None:
    payload = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))

    assert payload["tool"]["name"] == "agent-guard"
    assert payload["tool"]["version"] == pyproject_version()


def test_schema_resources_are_present_in_package_tree() -> None:
    expected = {
        "agent-guard.result.v1.schema.json",
        "agent-guard.context_inventory.v1.schema.json",
        "agent-guard.context_lock_coverage.v1.schema.json",
        "agent-guard.report_evidence.v1.schema.json",
        "agent-guard.conformance.v1.schema.json",
        "agent-guard.evidence_pack_manifest.v1.schema.json",
        "agent-guard.surface_delta.v1.schema.json",
    }

    assert SCHEMA_DIR.is_dir()
    assert {path.name for path in SCHEMA_DIR.glob("*.schema.json")} == expected


def test_py_typed_marker_is_present() -> None:
    marker = PACKAGE_DIR / "py.typed"
    assert marker.is_file()
    assert marker.stat().st_size == 0
