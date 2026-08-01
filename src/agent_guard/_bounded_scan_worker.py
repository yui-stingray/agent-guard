"""Where: src/agent_guard/_bounded_scan_worker.py
What: package-owned interpreter entry point for isolated static scans.
Why: isolate scanner work without importing a consumer's ``__main__`` module.
"""

from __future__ import annotations

import os
import pickle
import sys
from collections.abc import Callable, Sequence
from typing import BinaryIO

from .bounded_scan import (
    MAX_ISOLATED_ADDRESS_SPACE_BYTES,
    MAX_ISOLATED_MESSAGE_BYTES,
    _ISOLATED_SCAN_PROTOCOL,
    _apply_posix_address_space_ceiling,
    _framed_message,
    _package_worker_identity,
    _read_framed_message,
    _write_all,
    _write_framed_message,
)


def _parse_bounded_integer(raw_value: str, maximum: int) -> int:
    if not raw_value.isascii() or not raw_value.isdecimal() or len(raw_value) > 10:
        raise ValueError
    value = int(raw_value)
    if value <= 0 or value > maximum:
        raise ValueError
    return value


def _open_protocol_output() -> BinaryIO:
    protocol_fd = os.dup(sys.stdout.fileno())
    try:
        # Duplicating a standard stream yields an inheritable descriptor on
        # Windows, so make the private protocol pipe explicit on every host.
        os.set_inheritable(protocol_fd, False)
        null_fd = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(null_fd, sys.stdout.fileno())
        finally:
            os.close(null_fd)
        return os.fdopen(protocol_fd, "wb", buffering=0)
    except Exception:
        os.close(protocol_fd)
        raise


def _redirect_standard_input() -> None:
    null_fd = os.open(os.devnull, os.O_RDONLY)
    try:
        os.dup2(null_fd, sys.stdin.fileno())
    finally:
        os.close(null_fd)


def _safe_error_text(exc: Exception, safe_errors: tuple[str, ...]) -> str | None:
    try:
        error_text = str(exc)
    except Exception:
        return None
    return error_text if error_text in safe_errors else None


def _decode_request(
    payload: bytes,
) -> tuple[Callable[..., object], tuple[object, ...], tuple[str, ...]]:
    request = pickle.loads(payload)
    if (
        type(request) is not tuple
        or len(request) != 4
        or request[0] != _ISOLATED_SCAN_PROTOCOL
        or not callable(request[1])
        or not isinstance(request[2], tuple)
        or not isinstance(request[3], tuple)
        or not all(isinstance(message, str) for message in request[3])
    ):
        raise ValueError
    return request[1], request[2], request[3]


def _send_result(
    protocol_output: BinaryIO,
    result: object,
    max_message_bytes: int,
) -> None:
    payload = pickle.dumps(("ok", result), protocol=pickle.HIGHEST_PROTOCOL)
    if len(payload) > max_message_bytes:
        payload = pickle.dumps(("limit", None), protocol=pickle.HIGHEST_PROTOCOL)
    _write_all(protocol_output, _framed_message(payload, max_message_bytes))
    protocol_output.flush()


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2:
        return 2
    try:
        max_message_bytes = _parse_bounded_integer(
            arguments[0],
            MAX_ISOLATED_MESSAGE_BYTES,
        )
        max_address_space_bytes = _parse_bounded_integer(
            arguments[1],
            MAX_ISOLATED_ADDRESS_SPACE_BYTES,
        )
        protocol_output = _open_protocol_output()
    except (OSError, TypeError, ValueError):
        return 2

    safe_errors: tuple[str, ...] = ()
    try:
        _apply_posix_address_space_ceiling(max_address_space_bytes)
        _write_framed_message(
            protocol_output,
            ("ready", _package_worker_identity()),
            max_message_bytes,
        )
        request_payload = _read_framed_message(sys.stdin.buffer, max_message_bytes)
        operation, args, safe_errors = _decode_request(request_payload)
        _redirect_standard_input()
        result = operation(*args)
        _send_result(protocol_output, result, max_message_bytes)
    except Exception as exc:
        try:
            _write_framed_message(
                protocol_output,
                ("error", _safe_error_text(exc, safe_errors)),
                max_message_bytes,
            )
        except Exception:
            pass
    finally:
        try:
            protocol_output.close()
        except (OSError, ValueError):
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
