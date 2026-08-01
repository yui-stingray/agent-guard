"""Where: tests/test_bounded_scan.py
What: portability tests for bounded policy-controlled scan execution.
Why: keep Windows-style spawn behavior compatible with the CLI entry point.
"""

from __future__ import annotations

import _thread
import multiprocessing
import os
import subprocess
import sys
import threading

import pytest

from agent_guard import bounded_scan
from agent_guard.bounded_scan import run_isolated_scan


_PARENT_THREAD_LOCK = threading.Lock()


def _return_value(value: str) -> str:
    return value


def _return_repeated_value(size: int) -> str:
    return "x" * size


def _raise_private_resource_limit_error(_max_address_space_bytes: int) -> None:
    raise OSError("synthetic private resource-limit detail")


def _acquire_parent_thread_lock() -> bool:
    return _PARENT_THREAD_LOCK.acquire(timeout=0.25)


def test_isolated_scan_supports_spawn_context() -> None:
    result = run_isolated_scan(
        _return_value,
        "ok",
        timeout_error="scan timed out",
        runtime_error="scan failed",
        _context=multiprocessing.get_context("spawn"),
    )

    assert result == "ok"


@pytest.mark.skipif(
    os.name != "posix" or "forkserver" not in multiprocessing.get_all_start_methods(),
    reason="requires the POSIX forkserver path",
)
def test_default_isolated_scan_supports_guarded_programmatic_call() -> None:
    script = (
        "from agent_guard.bounded_scan import run_isolated_scan\n"
        "from operator import add\n"
        "if __name__ == '__main__':\n"
        "    print(run_isolated_scan(add, 1, 2, timeout_error='timeout', runtime_error='failed'))\n"
    )

    result = subprocess.run(
        [sys.executable, "-I", "-c", script],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout == "3\n"
    assert result.stderr == ""


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX start methods")
def test_default_isolated_scan_does_not_inherit_parent_thread_locks() -> None:
    held = threading.Event()
    release = threading.Event()

    def hold_lock() -> None:
        with _PARENT_THREAD_LOCK:
            held.set()
            release.wait(timeout=5)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    try:
        assert held.wait(timeout=1)
        result = run_isolated_scan(
            _acquire_parent_thread_lock,
            timeout_error="scan timed out",
            runtime_error="scan failed",
        )
    finally:
        release.set()
        holder.join(timeout=1)

    assert result is True
    assert not holder.is_alive()


@pytest.mark.skipif(
    os.name != "posix"
    or "forkserver" not in multiprocessing.get_all_start_methods(),
    reason="requires POSIX forkserver",
)
def test_default_context_avoids_fork_with_unregistered_low_level_thread() -> None:
    held = threading.Event()
    release = threading.Event()
    stopped = threading.Event()

    def hold_lock() -> None:
        held.set()
        release.wait(timeout=5)
        stopped.set()

    _thread.start_new_thread(hold_lock, ())
    try:
        assert held.wait(timeout=1)
        assert bounded_scan._default_context().get_start_method() == "forkserver"
    finally:
        release.set()
        stopped.wait(timeout=1)

    assert stopped.is_set()


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


@pytest.mark.skipif(
    os.name != "posix" or "fork" not in multiprocessing.get_all_start_methods(),
    reason="requires POSIX RLIMIT_AS and a fork context for monkeypatch propagation",
)
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
            _context=multiprocessing.get_context("fork"),
        )

    assert "synthetic private resource-limit detail" not in str(exc_info.value)
