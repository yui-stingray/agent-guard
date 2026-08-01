"""Where: src/agent_guard/bounded_scan.py
What: bounded subprocess execution for policy-controlled static scans.
Why: stop pathological regular expressions without coupling scanners together.
"""

from __future__ import annotations

import multiprocessing
import os
import pickle
import threading
from collections.abc import Callable, Iterable
from typing import Any, TypeVar


ISOLATED_SCAN_START_TIMEOUT_SECONDS = 5.0
ISOLATED_SCAN_TIMEOUT_SECONDS = 5.0
# Scanners must bound their own result construction. This cap only limits the
# serialized IPC response after an operation has materialized its result.
MAX_ISOLATED_MESSAGE_BYTES = 16 * 1024 * 1024
# Applied in POSIX workers when ``resource.RLIMIT_AS`` is available.
MAX_ISOLATED_ADDRESS_SPACE_BYTES = 512 * 1024 * 1024

ScanResult = TypeVar("ScanResult")


def _lowered_resource_limit(limit: int, ceiling: int, infinity: int) -> int:
    return ceiling if limit == infinity else min(limit, ceiling)


def _apply_posix_address_space_ceiling(max_address_space_bytes: int) -> None:
    """Lower the worker address-space limit where POSIX RLIMIT_AS is available."""
    if os.name != "posix":
        return

    try:
        import resource
    except ImportError:
        # Some POSIX runtimes do not expose the stdlib resource module.
        return
    if not hasattr(resource, "RLIMIT_AS"):
        return

    try:
        if max_address_space_bytes <= 0:
            raise ValueError
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_AS)
        limited_hard = _lowered_resource_limit(
            hard_limit,
            max_address_space_bytes,
            resource.RLIM_INFINITY,
        )
        limited_soft = min(
            _lowered_resource_limit(
                soft_limit,
                max_address_space_bytes,
                resource.RLIM_INFINITY,
            ),
            limited_hard,
        )
        if (limited_soft, limited_hard) != (soft_limit, hard_limit):
            resource.setrlimit(resource.RLIMIT_AS, (limited_soft, limited_hard))
    except Exception:
        # The parent maps this worker failure to its existing sanitized runtime
        # error instead of running an operation without the claimed ceiling.
        raise RuntimeError from None


def _isolated_scan_worker(
    sender: Any,
    operation: Callable[..., object],
    args: tuple[object, ...],
    max_message_bytes: int,
    max_address_space_bytes: int,
) -> None:
    try:
        _apply_posix_address_space_ceiling(max_address_space_bytes)
        sender.send_bytes(pickle.dumps(("ready", None), protocol=pickle.HIGHEST_PROTOCOL))
        result = operation(*args)
        # This transport cap is deliberately post-materialization; operation-side
        # budgets are the primary limit for intermediate and result allocations.
        result_message = pickle.dumps(("ok", result), protocol=pickle.HIGHEST_PROTOCOL)
        if len(result_message) > max_message_bytes:
            result_message = pickle.dumps(("limit", None), protocol=pickle.HIGHEST_PROTOCOL)
        sender.send_bytes(result_message)
    except Exception as exc:
        try:
            error_message = pickle.dumps(("error", str(exc)), protocol=pickle.HIGHEST_PROTOCOL)
            if len(error_message) > max_message_bytes:
                error_message = pickle.dumps(("error", None), protocol=pickle.HIGHEST_PROTOCOL)
            sender.send_bytes(error_message)
        except (BrokenPipeError, OSError, pickle.PickleError):
            pass
    finally:
        sender.close()


def _stop_isolated_process(process: multiprocessing.Process) -> None:
    if process.is_alive():
        process.terminate()
        process.join(timeout=0.1)
    if process.is_alive():
        process.kill()
        process.join(timeout=0.1)


def _default_context() -> Any:
    start_methods = multiprocessing.get_all_start_methods()
    if os.name == "posix":
        if threading.active_count() == 1 and "fork" in start_methods:
            return multiprocessing.get_context("fork")
        if "forkserver" in start_methods:
            return multiprocessing.get_context("forkserver")
    return multiprocessing.get_context("spawn")


def run_isolated_scan(
    operation: Callable[..., ScanResult],
    *args: object,
    timeout_error: str,
    runtime_error: str,
    result_limit_error: str | None = None,
    safe_errors: Iterable[str] = (),
    _context: Any | None = None,
    _max_message_bytes: int = MAX_ISOLATED_MESSAGE_BYTES,
    _max_address_space_bytes: int | None = None,
) -> ScanResult:
    """Run policy-controlled work out of process with bounded startup and execution.

    Operation-side result budgets are the primary protection against oversized
    results. The IPC message cap applies only after a worker has materialized
    and serialized its operation result. On POSIX, supported workers also lower
    their address-space limit before the operation runs; unsupported platforms
    rely on operation budgets and the execution timeout.
    """
    context = _context or _default_context()
    max_address_space_bytes = (
        MAX_ISOLATED_ADDRESS_SPACE_BYTES
        if _max_address_space_bytes is None
        else _max_address_space_bytes
    )
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_isolated_scan_worker,
        args=(
            sender,
            operation,
            args,
            _max_message_bytes,
            max_address_space_bytes,
        ),
    )
    process.daemon = True
    safe_error_messages = set(safe_errors)

    try:
        process.start()
    except (OSError, RuntimeError):
        receiver.close()
        sender.close()
        raise RuntimeError(runtime_error) from None
    sender.close()

    try:
        if not receiver.poll(ISOLATED_SCAN_START_TIMEOUT_SECONDS):
            _stop_isolated_process(process)
            raise RuntimeError(runtime_error)
        try:
            status, payload = pickle.loads(receiver.recv_bytes(maxlength=_max_message_bytes))
        except (EOFError, OSError, pickle.PickleError, ValueError, TypeError):
            raise RuntimeError(runtime_error) from None
        if status != "ready":
            raise RuntimeError(runtime_error)

        if not receiver.poll(ISOLATED_SCAN_TIMEOUT_SECONDS):
            _stop_isolated_process(process)
            raise RuntimeError(timeout_error)
        try:
            status, payload = pickle.loads(receiver.recv_bytes(maxlength=_max_message_bytes))
        except (EOFError, OSError, pickle.PickleError, ValueError, TypeError):
            raise RuntimeError(runtime_error) from None

        process.join(timeout=0.1)
        if process.is_alive():
            _stop_isolated_process(process)

        if status == "ok":
            return payload
        if status == "limit" and result_limit_error is not None:
            raise ValueError(result_limit_error)
        if status == "error" and isinstance(payload, str) and payload in safe_error_messages:
            raise ValueError(payload)
        raise RuntimeError(runtime_error)
    finally:
        receiver.close()
        if process.is_alive():
            _stop_isolated_process(process)
