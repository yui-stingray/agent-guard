"""Where: tests/test_bounded_scan.py
What: portability tests for bounded policy-controlled scan execution.
Why: keep Windows-style spawn behavior compatible with the CLI entry point.
"""

from __future__ import annotations

import multiprocessing
import os

import pytest

from agent_guard import bounded_scan
from agent_guard.bounded_scan import run_isolated_scan


def _return_value(value: str) -> str:
    return value


def _return_repeated_value(size: int) -> str:
    return "x" * size


def _raise_private_resource_limit_error(_max_address_space_bytes: int) -> None:
    raise OSError("synthetic private resource-limit detail")


def test_isolated_scan_supports_spawn_context() -> None:
    result = run_isolated_scan(
        _return_value,
        "ok",
        timeout_error="scan timed out",
        runtime_error="scan failed",
        _context=multiprocessing.get_context("spawn"),
    )

    assert result == "ok"


def test_isolated_scan_rejects_oversized_result_with_sanitized_error() -> None:
    with pytest.raises(ValueError, match="^scan result exceeds configured limits$"):
        run_isolated_scan(
            _return_repeated_value,
            1_024,
            timeout_error="scan timed out",
            runtime_error="scan failed",
            result_limit_error="scan result exceeds configured limits",
            _max_message_bytes=256,
        )


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX RLIMIT_AS")
def test_isolated_scan_sanitizes_address_space_ceiling_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    try:
        import resource
    except ImportError:
        pytest.skip("resource module is unavailable")
    if not hasattr(resource, "RLIMIT_AS"):
        pytest.skip("RLIMIT_AS is unavailable")

    monkeypatch.setattr(
        bounded_scan,
        "_apply_posix_address_space_ceiling",
        _raise_private_resource_limit_error,
    )

    with pytest.raises(RuntimeError, match="^scan failed$") as exc_info:
        run_isolated_scan(
            _return_value,
            "ok",
            timeout_error="scan timed out",
            runtime_error="scan failed",
        )

    assert "synthetic private resource-limit detail" not in str(exc_info.value)
