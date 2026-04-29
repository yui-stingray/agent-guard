"""Where: tests/test_check_pypi_release_state.py
What: unit tests for the PyPI release-state preflight.
Why: keep immutable-version checks predictable without live network calls.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_pypi_release_state.py"
SPEC = importlib.util.spec_from_file_location("check_pypi_release_state", SCRIPT)
assert SPEC is not None
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
check_release_state = MODULE.check_release_state


def test_missing_project_is_allowed_with_pending_publisher_note() -> None:
    ok, message = check_release_state("yui-agent-guard", "0.1.0", None)

    assert ok is True
    assert "does not exist yet" in message
    assert "Trusted Publisher" in message


def test_existing_version_blocks_release() -> None:
    ok, message = check_release_state(
        "yui-agent-guard",
        "0.1.0",
        {"info": {"version": "0.1.0"}, "releases": {"0.1.0": [{}]}},
    )

    assert ok is False
    assert "already exists" in message


def test_new_version_for_existing_project_is_allowed() -> None:
    ok, message = check_release_state(
        "yui-agent-guard",
        "0.1.1",
        {"info": {"version": "0.1.0"}, "releases": {"0.1.0": [{}]}},
    )

    assert ok is True
    assert "candidate=0.1.1" in message
