"""Where: tests/test_bounded_scan.py
What: portability tests for bounded policy-controlled scan execution.
Why: keep package-worker isolation compatible with guarded and unguarded callers.
"""

from __future__ import annotations

import _thread
import multiprocessing
import operator
import os
import pickle
import struct
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pytest

from agent_guard import bounded_scan
from agent_guard.bounded_scan import run_isolated_scan


_PARENT_THREAD_LOCK = threading.Lock()


def _return_value(value: str) -> str:
    return value


def _raise_private_resource_limit_error(_max_address_space_bytes: int) -> None:
    raise OSError("synthetic private resource-limit detail")


def _track_scan_processes(
    monkeypatch: pytest.MonkeyPatch,
) -> list[subprocess.Popen[bytes]]:
    processes: list[subprocess.Popen[bytes]] = []
    original_popen = subprocess.Popen

    def tracked_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = original_popen(*args, **kwargs)  # type: ignore[arg-type]
        processes.append(process)
        return process

    monkeypatch.setattr(bounded_scan.subprocess, "Popen", tracked_popen)
    return processes


def test_isolated_scan_supports_spawn_context() -> None:
    result = run_isolated_scan(
        _return_value,
        "ok",
        timeout_error="scan timed out",
        runtime_error="scan failed",
        _context=multiprocessing.get_context("spawn"),
    )

    assert result == "ok"


@pytest.mark.parametrize("guarded", [False, True], ids=["unguarded", "guarded"])
def test_default_isolated_scan_supports_standalone_programmatic_call(
    tmp_path: Path,
    guarded: bool,
) -> None:
    invocation = (
        "print(run_isolated_scan(add, 1, 2, "
        "timeout_error='timeout', runtime_error='failed'))"
    )
    if guarded:
        invocation = "if __name__ == '__main__':\n    " + invocation
    script = tmp_path / "consumer.py"
    script.write_text(
        "from agent_guard.bounded_scan import run_isolated_scan\n"
        "from operator import add\n"
        f"{invocation}\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, "-I", str(script)],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout == "3\n"
    assert result.stderr == ""


def test_package_worker_handshake_rejects_origin_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        bounded_scan,
        "_package_worker_identity",
        lambda: "0" * 64,
    )

    with pytest.raises(RuntimeError, match="^scan failed$"):
        run_isolated_scan(
            operator.add,
            1,
            2,
            timeout_error="scan timed out",
            runtime_error="scan failed",
        )


def test_default_isolated_scan_runs_while_parent_thread_lock_is_held() -> None:
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
            operator.add,
            1,
            2,
            timeout_error="scan timed out",
            runtime_error="scan failed",
        )
    finally:
        release.set()
        holder.join(timeout=1)

    assert result == 3
    assert not holder.is_alive()


def test_default_isolated_scan_avoids_multiprocessing_with_low_level_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    held = threading.Event()
    release = threading.Event()
    stopped = threading.Event()

    def hold_lock() -> None:
        held.set()
        release.wait(timeout=5)
        stopped.set()

    _thread.start_new_thread(hold_lock, ())
    monkeypatch.setattr(
        bounded_scan,
        "_run_multiprocessing_scan",
        lambda *_args, **_kwargs: pytest.fail(
            "default isolation selected the multiprocessing seam"
        ),
    )
    try:
        assert held.wait(timeout=1)
        assert run_isolated_scan(
            operator.add,
            1,
            2,
            timeout_error="scan timed out",
            runtime_error="scan failed",
        ) == 3
    finally:
        release.set()
        stopped.wait(timeout=1)

    assert stopped.is_set()


def test_isolated_scan_rejects_oversized_result_with_sanitized_error() -> None:
    with pytest.raises(ValueError, match="^scan result exceeds configured limits$"):
        run_isolated_scan(
            operator.mul,
            "x",
            1_024,
            timeout_error="scan timed out",
            runtime_error="scan failed",
            result_limit_error="scan result exceeds configured limits",
            _max_message_bytes=256,
        )


def test_isolated_scan_rejects_oversized_request_before_worker_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_detail = "synthetic-private-request-detail-" + ("x" * 1_024)

    def fail_start(*_args: object, **_kwargs: object) -> None:
        pytest.fail("oversized request started a worker")

    monkeypatch.setattr(bounded_scan.subprocess, "Popen", fail_start)

    with pytest.raises(RuntimeError, match="^scan failed$") as exc_info:
        run_isolated_scan(
            operator.add,
            private_detail,
            "suffix",
            timeout_error="scan timed out",
            runtime_error="scan failed",
            _max_message_bytes=256,
        )

    assert private_detail not in str(exc_info.value)


def test_isolated_scan_timeout_is_bounded_and_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bounded_scan, "ISOLATED_SCAN_TIMEOUT_SECONDS", 0.05)
    started = time.monotonic()

    with pytest.raises(RuntimeError, match="^scan timed out$"):
        run_isolated_scan(
            time.sleep,
            5,
            timeout_error="scan timed out",
            runtime_error="scan failed",
        )

    assert time.monotonic() - started < 2
    assert not any(
        thread.name == "agent-guard-scan-startup" for thread in threading.enumerate()
    )


def test_isolated_scan_startup_timeout_reaps_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processes = _track_scan_processes(monkeypatch)
    monkeypatch.setattr(bounded_scan, "ISOLATED_SCAN_START_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(
        bounded_scan,
        "_ISOLATED_SCAN_BOOTSTRAP",
        "import time; time.sleep(5)",
    )

    with pytest.raises(RuntimeError, match="^scan failed$"):
        run_isolated_scan(
            operator.add,
            1,
            2,
            timeout_error="scan timed out",
            runtime_error="scan failed",
        )

    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert not any(
        thread.name == "agent-guard-scan-startup" for thread in threading.enumerate()
    )


@pytest.mark.parametrize(
    "malformed_result",
    [
        b"\x00\x00",
        struct.pack("!I", 5) + b"abc",
        bounded_scan._framed_message(
            pickle.dumps(("ok", 3), protocol=pickle.HIGHEST_PROTOCOL),
            bounded_scan.MAX_ISOLATED_MESSAGE_BYTES,
        )
        + b"x",
    ],
    ids=["partial-header", "truncated-body", "extra-bytes"],
)
def test_isolated_scan_malformed_worker_result_is_sanitized_and_reaped(
    monkeypatch: pytest.MonkeyPatch,
    malformed_result: bytes,
) -> None:
    worker_identity = "synthetic-worker-origin-identity"
    ready_payload = pickle.dumps(
        ("ready", worker_identity),
        protocol=pickle.HIGHEST_PROTOCOL,
    )
    ready_frame = bounded_scan._framed_message(
        ready_payload,
        bounded_scan.MAX_ISOLATED_MESSAGE_BYTES,
    )
    fake_worker = (
        "import sys;"
        f"sys.stdout.buffer.write({ready_frame!r});"
        "sys.stdout.buffer.flush();"
        "sys.stdin.buffer.read();"
        f"sys.stdout.buffer.write({malformed_result!r});"
        "sys.stdout.buffer.flush()"
    )
    processes = _track_scan_processes(monkeypatch)
    monkeypatch.setattr(
        bounded_scan,
        "_package_worker_identity",
        lambda: worker_identity,
    )
    monkeypatch.setattr(bounded_scan, "_ISOLATED_SCAN_BOOTSTRAP", fake_worker)

    with pytest.raises(RuntimeError, match="^scan failed$"):
        run_isolated_scan(
            operator.add,
            1,
            2,
            timeout_error="scan timed out",
            runtime_error="scan failed",
        )

    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert not any(
        thread.name == "agent-guard-scan-startup" for thread in threading.enumerate()
    )


@pytest.mark.parametrize(
    ("operation", "args", "expected"),
    [
        (print, ("synthetic worker stdout",), None),
        (os.write, (1, b"synthetic worker fd1"), len(b"synthetic worker fd1")),
        (os.write, (2, b"synthetic worker fd2"), len(b"synthetic worker fd2")),
    ],
    ids=["text-stdout", "fd1", "fd2"],
)
def test_isolated_scan_worker_output_cannot_corrupt_protocol(
    capfd: pytest.CaptureFixture[str],
    operation: object,
    args: tuple[object, ...],
    expected: object,
) -> None:
    assert callable(operation)

    result = run_isolated_scan(
        operation,
        *args,
        timeout_error="scan timed out",
        runtime_error="scan failed",
    )

    captured = capfd.readouterr()
    assert result == expected
    assert captured.out == ""
    assert captured.err == ""


def test_isolated_scan_sanitizes_unexpected_operation_error() -> None:
    private_detail = "synthetic-private-worker-detail-does-not-exist"

    with pytest.raises(RuntimeError, match="^scan failed$") as exc_info:
        run_isolated_scan(
            open,
            private_detail,
            "rb",
            timeout_error="scan timed out",
            runtime_error="scan failed",
        )

    assert private_detail not in str(exc_info.value)


def test_isolated_scan_preserves_allowlisted_safe_error() -> None:
    invalid_value = "synthetic-invalid-integer"
    try:
        int(invalid_value)
    except ValueError as exc:
        safe_error = str(exc)
    else:  # pragma: no cover - fixed stdlib behavior
        raise AssertionError("invalid integer unexpectedly parsed")

    with pytest.raises(ValueError, match="^invalid literal") as exc_info:
        run_isolated_scan(
            int,
            invalid_value,
            timeout_error="scan timed out",
            runtime_error="scan failed",
            safe_errors=(safe_error,),
        )

    assert str(exc_info.value) == safe_error


def test_isolated_scan_sanitizes_unexpected_protocol_decode_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_detail = "synthetic private protocol decode detail"

    def fail_decode(_payload: bytes) -> tuple[str, object]:
        raise LookupError(private_detail)

    monkeypatch.setattr(bounded_scan, "_decode_worker_message", fail_decode)

    with pytest.raises(RuntimeError, match="^scan failed$") as exc_info:
        run_isolated_scan(
            operator.add,
            1,
            2,
            timeout_error="scan timed out",
            runtime_error="scan failed",
        )

    assert private_detail not in str(exc_info.value)
    assert not any(
        thread.name == "agent-guard-scan-startup" for thread in threading.enumerate()
    )


def test_isolated_scan_reaps_worker_when_startup_reader_cannot_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_detail = "synthetic private startup-thread detail"
    processes = _track_scan_processes(monkeypatch)

    def fail_thread(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(private_detail)

    monkeypatch.setattr(
        bounded_scan,
        "threading",
        types.SimpleNamespace(Thread=fail_thread),
    )

    with pytest.raises(RuntimeError, match="^scan failed$") as exc_info:
        run_isolated_scan(
            operator.add,
            1,
            2,
            timeout_error="scan timed out",
            runtime_error="scan failed",
        )

    assert private_detail not in str(exc_info.value)
    assert len(processes) == 1
    assert processes[0].poll() is not None


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX RLIMIT_AS")
def test_package_worker_lowers_address_space_ceiling() -> None:
    try:
        import resource
    except ImportError:
        pytest.skip("resource module is unavailable")
    if not hasattr(resource, "RLIMIT_AS"):
        pytest.skip("RLIMIT_AS is unavailable")
    ceiling = 384 * 1024 * 1024

    soft_limit, hard_limit = run_isolated_scan(
        resource.getrlimit,
        resource.RLIMIT_AS,
        timeout_error="scan timed out",
        runtime_error="scan failed",
        _max_address_space_bytes=ceiling,
    )

    assert soft_limit != resource.RLIM_INFINITY
    assert hard_limit != resource.RLIM_INFINITY
    assert 0 < soft_limit <= hard_limit <= ceiling


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
