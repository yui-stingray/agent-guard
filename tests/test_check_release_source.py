"""Tests for the release source preflight."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_release_source.py"
SPEC = importlib.util.spec_from_file_location("check_release_source", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_release_source_requires_current_master_and_successful_ci() -> None:
    sha = "a" * 40
    assert MODULE.check_release_source(
        tag_sha=sha,
        master_sha=sha,
        ci_conclusions=["failure", "success"],
    ) == (True, "release source is current protected master with successful CI")

    ok, message = MODULE.check_release_source(
        tag_sha=sha,
        master_sha="b" * 40,
        ci_conclusions=["success"],
    )
    assert ok is False
    assert message == "release tag must point at the current origin/master commit"

    ok, message = MODULE.check_release_source(
        tag_sha=sha,
        master_sha=sha,
        ci_conclusions=["failure"],
    )
    assert ok is False
    assert message == "release commit must have a successful completed CI run"
