"""Where: src/agent_guard/bounded_scan.py
What: bounded subprocess execution for policy-controlled static scans.
Why: stop pathological regular expressions without coupling scanners together.
"""

from __future__ import annotations

import hashlib
import multiprocessing
import os
import pickle
import queue
import struct
import subprocess
import sys
import threading
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, BinaryIO, TypeVar


ISOLATED_SCAN_START_TIMEOUT_SECONDS = 5.0
ISOLATED_SCAN_TIMEOUT_SECONDS = 5.0
# Scanners must bound their own result construction. This cap bounds each
# serialized IPC request or response, but only after it has been materialized.
MAX_ISOLATED_MESSAGE_BYTES = 16 * 1024 * 1024
# Applied in POSIX workers when ``resource.RLIMIT_AS`` is available.
MAX_ISOLATED_ADDRESS_SPACE_BYTES = 512 * 1024 * 1024

_ISOLATED_SCAN_PROTOCOL = "agent-guard.bounded-scan.v1"
_ISOLATED_SCAN_WORKER_MODULE = "agent_guard._bounded_scan_worker"
_ISOLATED_SCAN_BOOTSTRAP = (
    "import runpy,sys;"
    "sys.path.insert(0,sys.argv.pop(1));"
    f"runpy.run_module({_ISOLATED_SCAN_WORKER_MODULE!r},run_name='__main__')"
)
_ISOLATED_SCAN_FRAME_HEADER = struct.Struct("!I")
_ISOLATED_PROCESS_TERMINATE_SECONDS = 0.1

ScanResult = TypeVar("ScanResult")


def _lowered_resource_limit(limit: int, ceiling: int, infinity: int) -> int:
    return ceiling if limit == infinity else min(limit, ceiling)


def _package_worker_root() -> str:
    """Return the canonical import root for this exact package checkout/install."""
    return str(Path(__file__).resolve().parents[1])


def _package_worker_identity() -> str:
    """Return an opaque identity for the package origin used by both processes."""
    return hashlib.sha256(os.fsencode(_package_worker_root())).hexdigest()


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
    safe_errors: tuple[str, ...],
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
            try:
                error_text = str(exc)
            except Exception:
                error_text = None
            error_payload = error_text if error_text in safe_errors else None
            error_message = pickle.dumps(
                ("error", error_payload),
                protocol=pickle.HIGHEST_PROTOCOL,
            )
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
        process.join(timeout=_ISOLATED_PROCESS_TERMINATE_SECONDS)
    if process.is_alive():
        process.kill()
        process.join()


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def _read_framed_message(stream: BinaryIO, max_message_bytes: int) -> bytes:
    header = _read_exact(stream, _ISOLATED_SCAN_FRAME_HEADER.size)
    (message_size,) = _ISOLATED_SCAN_FRAME_HEADER.unpack(header)
    if message_size <= 0 or message_size > max_message_bytes:
        raise ValueError
    return _read_exact(stream, message_size)


def _framed_message(payload: bytes, max_message_bytes: int) -> bytes:
    if not payload or len(payload) > max_message_bytes:
        raise ValueError
    return _ISOLATED_SCAN_FRAME_HEADER.pack(len(payload)) + payload


def _write_all(stream: BinaryIO, payload: bytes) -> None:
    payload_view = memoryview(payload)
    offset = 0
    while offset < len(payload):
        written = stream.write(payload_view[offset:])
        if not isinstance(written, int) or written <= 0:
            raise OSError
        offset += written


def _write_framed_message(
    stream: BinaryIO,
    message: object,
    max_message_bytes: int,
) -> None:
    payload = pickle.dumps(message, protocol=pickle.HIGHEST_PROTOCOL)
    _write_all(stream, _framed_message(payload, max_message_bytes))
    stream.flush()


def _read_worker_startup(
    stream: BinaryIO,
    result: queue.Queue[bytes | None],
    max_message_bytes: int,
) -> None:
    try:
        payload = _read_framed_message(stream, max_message_bytes)
    except Exception:
        payload = None
    result.put(payload)


def _stop_isolated_subprocess(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
    except OSError:
        pass
    try:
        process.wait(timeout=_ISOLATED_PROCESS_TERMINATE_SECONDS)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait()
    except OSError:
        pass


def _decode_framed_worker_result(payload: bytes, max_message_bytes: int) -> bytes:
    try:
        if len(payload) < _ISOLATED_SCAN_FRAME_HEADER.size:
            raise ValueError
        (message_size,) = _ISOLATED_SCAN_FRAME_HEADER.unpack_from(payload)
        if (
            message_size <= 0
            or message_size > max_message_bytes
            or len(payload) != _ISOLATED_SCAN_FRAME_HEADER.size + message_size
        ):
            raise ValueError
        return payload[_ISOLATED_SCAN_FRAME_HEADER.size :]
    except Exception:
        raise ValueError from None


def _decode_worker_message(payload: bytes) -> tuple[str, object]:
    try:
        message = pickle.loads(payload)
    except Exception:
        raise ValueError from None
    try:
        if (
            type(message) is not tuple
            or len(message) != 2
            or not isinstance(message[0], str)
        ):
            raise ValueError
        return message
    except Exception:
        raise ValueError from None


def _resolve_worker_result(
    message: tuple[str, object],
    *,
    runtime_error: str,
    result_limit_error: str | None,
    safe_error_messages: set[str],
) -> ScanResult:
    status, payload = message
    if status == "ok":
        return payload  # type: ignore[return-value]
    if status == "limit" and payload is None and result_limit_error is not None:
        raise ValueError(result_limit_error)
    if status == "error" and isinstance(payload, str) and payload in safe_error_messages:
        raise ValueError(payload)
    raise RuntimeError(runtime_error)


def _run_multiprocessing_scan(
    context: Any,
    operation: Callable[..., ScanResult],
    args: tuple[object, ...],
    *,
    timeout_error: str,
    runtime_error: str,
    result_limit_error: str | None,
    safe_error_messages: set[str],
    max_message_bytes: int,
    max_address_space_bytes: int,
) -> ScanResult:
    """Run the private multiprocessing seam used by process fault tests."""
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_isolated_scan_worker,
        args=(
            sender,
            operation,
            args,
            tuple(safe_error_messages),
            max_message_bytes,
            max_address_space_bytes,
        ),
    )
    process.daemon = True

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
            ready = _decode_worker_message(receiver.recv_bytes(maxlength=max_message_bytes))
        except (EOFError, OSError, ValueError, TypeError):
            raise RuntimeError(runtime_error) from None
        if ready != ("ready", None):
            raise RuntimeError(runtime_error)

        if not receiver.poll(ISOLATED_SCAN_TIMEOUT_SECONDS):
            _stop_isolated_process(process)
            raise RuntimeError(timeout_error)
        try:
            result = _decode_worker_message(receiver.recv_bytes(maxlength=max_message_bytes))
        except (EOFError, OSError, ValueError, TypeError):
            raise RuntimeError(runtime_error) from None

        process.join(timeout=_ISOLATED_PROCESS_TERMINATE_SECONDS)
        if process.is_alive():
            _stop_isolated_process(process)
        return _resolve_worker_result(
            result,
            runtime_error=runtime_error,
            result_limit_error=result_limit_error,
            safe_error_messages=safe_error_messages,
        )
    finally:
        receiver.close()
        if process.is_alive():
            _stop_isolated_process(process)


def _run_package_worker_scan(
    operation: Callable[..., ScanResult],
    args: tuple[object, ...],
    *,
    timeout_error: str,
    runtime_error: str,
    result_limit_error: str | None,
    safe_error_messages: set[str],
    max_message_bytes: int,
    max_address_space_bytes: int,
) -> ScanResult:
    worker_root = _package_worker_root()
    expected_worker_identity = _package_worker_identity()
    try:
        request_payload = pickle.dumps(
            (
                _ISOLATED_SCAN_PROTOCOL,
                operation,
                args,
                tuple(safe_error_messages),
            ),
            protocol=pickle.HIGHEST_PROTOCOL,
        )
        request = _framed_message(request_payload, max_message_bytes)
    except Exception:
        raise RuntimeError(runtime_error) from None

    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-c",
                _ISOLATED_SCAN_BOOTSTRAP,
                worker_root,
                str(max_message_bytes),
                str(max_address_space_bytes),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
    except Exception:
        raise RuntimeError(runtime_error) from None

    if process.stdin is None or process.stdout is None:
        _stop_isolated_subprocess(process)
        raise RuntimeError(runtime_error)

    reader: threading.Thread | None = None
    reader_started = False
    try:
        try:
            startup_result: queue.Queue[bytes | None] = queue.Queue(maxsize=1)
            reader = threading.Thread(
                target=_read_worker_startup,
                args=(process.stdout, startup_result, max_message_bytes),
                name="agent-guard-scan-startup",
            )
            reader.start()
            reader_started = True
        except Exception:
            raise RuntimeError(runtime_error) from None
        try:
            ready_payload = startup_result.get(
                timeout=ISOLATED_SCAN_START_TIMEOUT_SECONDS
            )
        except queue.Empty:
            _stop_isolated_subprocess(process)
            reader.join()
            raise RuntimeError(runtime_error) from None
        except Exception:
            raise RuntimeError(runtime_error) from None
        reader.join()
        if ready_payload is None:
            raise RuntimeError(runtime_error)
        try:
            ready = _decode_worker_message(ready_payload)
        except Exception:
            raise RuntimeError(runtime_error) from None
        if ready != ("ready", expected_worker_identity):
            raise RuntimeError(runtime_error)

        try:
            result_output, _ = process.communicate(
                input=request,
                timeout=ISOLATED_SCAN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            _stop_isolated_subprocess(process)
            try:
                process.communicate()
            except Exception:
                pass
            raise RuntimeError(timeout_error) from None
        except Exception:
            _stop_isolated_subprocess(process)
            try:
                process.communicate()
            except Exception:
                pass
            raise RuntimeError(runtime_error) from None
        try:
            result_payload = _decode_framed_worker_result(
                result_output,
                max_message_bytes,
            )
            result = _decode_worker_message(result_payload)
        except Exception:
            raise RuntimeError(runtime_error) from None
        return _resolve_worker_result(
            result,
            runtime_error=runtime_error,
            result_limit_error=result_limit_error,
            safe_error_messages=safe_error_messages,
        )
    finally:
        _stop_isolated_subprocess(process)
        if reader_started and reader is not None:
            reader.join()
        for stream in (process.stdin, process.stdout):
            try:
                stream.close()
            except (OSError, ValueError):
                pass


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
    results. The IPC message cap applies after a request or response has been
    serialized. On POSIX, supported workers also lower their address-space
    limit before the operation runs; unsupported platforms rely on operation
    budgets and the execution timeout.
    """
    max_address_space_bytes = (
        MAX_ISOLATED_ADDRESS_SPACE_BYTES
        if _max_address_space_bytes is None
        else _max_address_space_bytes
    )
    if (
        isinstance(_max_message_bytes, bool)
        or not isinstance(_max_message_bytes, int)
        or _max_message_bytes <= 0
        or _max_message_bytes > MAX_ISOLATED_MESSAGE_BYTES
        or isinstance(max_address_space_bytes, bool)
        or not isinstance(max_address_space_bytes, int)
        or max_address_space_bytes <= 0
        or max_address_space_bytes > MAX_ISOLATED_ADDRESS_SPACE_BYTES
    ):
        raise RuntimeError(runtime_error)
    try:
        safe_error_messages = set(safe_errors)
    except Exception:
        raise RuntimeError(runtime_error) from None
    if not all(isinstance(message, str) for message in safe_error_messages):
        raise RuntimeError(runtime_error)

    if _context is not None:
        return _run_multiprocessing_scan(
            _context,
            operation,
            args,
            timeout_error=timeout_error,
            runtime_error=runtime_error,
            result_limit_error=result_limit_error,
            safe_error_messages=safe_error_messages,
            max_message_bytes=_max_message_bytes,
            max_address_space_bytes=max_address_space_bytes,
        )
    return _run_package_worker_scan(
        operation,
        args,
        timeout_error=timeout_error,
        runtime_error=runtime_error,
        result_limit_error=result_limit_error,
        safe_error_messages=safe_error_messages,
        max_message_bytes=_max_message_bytes,
        max_address_space_bytes=max_address_space_bytes,
    )
