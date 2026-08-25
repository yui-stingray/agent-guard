"""Where: src/agent_guard/cli/common.py
What: shared CLI constants, redaction, policy-path, and result-envelope helpers.
Why: shrink the legacy CLI module without changing subcommand behavior.
"""

from __future__ import annotations

import json
import os
import re
import sys
from importlib import metadata
from pathlib import Path
from typing import Iterable

from .. import __version__ as PACKAGE_VERSION
from ..bounded_scan import MAX_ISOLATED_MESSAGE_BYTES
from ..consumer._schema import (
    DuplicateJSONKeyError,
    JSONStructureLimitError,
    MAX_REPORT_JSON_BYTES,
    NonFiniteJSONNumberError,
    load_json_text,
    read_limited_bytes,
)
from ..public_redaction import (
    redact_public_text,
    sanitize_public_mapping,
    sanitize_public_value,
)

RESULT_SCHEMA_VERSION = "agent-guard.result.v1"
REPORT_EVIDENCE_SCHEMA_VERSION = "agent-guard.report_evidence.v1"
REPORT_EVIDENCE_SCHEMA_VERSION_V2 = "agent-guard.report_evidence.v2"
TOOL_NAME = "agent-guard"
RECOMMENDED_EVIDENCE_PRESET = "recommended"
URL_LIKE_POLICY_ARG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
# Reuse the scanner result ceiling so final public serialization cannot exceed
# the bounded worker contract after envelope/rendering overhead is added.
MAX_PUBLIC_OUTPUT_BYTES = MAX_ISOLATED_MESSAGE_BYTES // 2
ERROR_REPORT_JSON_INVALID = "report JSON is invalid"
ERROR_REPORT_JSON_LIMIT = "report JSON exceeds configured limits"


def tool_version() -> str:
    if PACKAGE_VERSION:
        return PACKAGE_VERSION
    try:
        return metadata.version("yui-agent-guard")
    except metadata.PackageNotFoundError:
        return "0.0.0+local"


def require_public_output_budget(text: str, *, error: str) -> str:
    try:
        if len(text.encode("utf-8")) > MAX_PUBLIC_OUTPUT_BYTES:
            raise ValueError(error)
    except (MemoryError, OverflowError, UnicodeEncodeError):
        raise ValueError(error) from None
    return text


def _silence_failed_stdout() -> None:
    """Drain pending output into the platform null device before shutdown."""

    stdout = sys.stdout
    try:
        stdout_fd = stdout.fileno()
        null_fd = os.open(
            os.devnull,
            os.O_WRONLY | getattr(os, "O_BINARY", 0),
        )
    except Exception:
        return

    close_null_fd = null_fd != stdout_fd
    try:
        if close_null_fd:
            os.dup2(null_fd, stdout_fd)
    except Exception:
        return
    finally:
        if close_null_fd:
            try:
                os.close(null_fd)
            except OSError:
                pass

    for output in (getattr(stdout, "buffer", None), stdout):
        if output is None:
            continue
        try:
            output.flush()
        except Exception:
            pass


def emit_public_output(text: str, *, error: str) -> None:
    """Write exact UTF-8 bytes without platform newline translation."""

    try:
        data = text.encode("utf-8")
    except (MemoryError, UnicodeEncodeError, UnicodeError):
        raise ValueError(error) from None

    try:
        output = getattr(sys.stdout, "buffer", None)
        if output is None:
            sys.stdout.write(text)
            sys.stdout.flush()
            return
        sys.stdout.flush()
        written = output.write(data)
        if (
            isinstance(written, bool)
            or not isinstance(written, int)
            or written != len(data)
        ):
            raise OSError
        output.flush()
    except (MemoryError, UnicodeEncodeError, UnicodeError):
        raise ValueError(error) from None
    except (OSError, ValueError):
        _silence_failed_stdout()
        raise ValueError(error) from None


def bounded_public_line(text: str, *, error: str) -> str:
    """Return one line only when its emitted terminator also fits the budget."""

    return require_public_output_budget(f"{text}\n", error=error)


def bounded_public_json(
    payload: dict[str, object],
    *,
    error: str,
    sort_keys: bool = False,
) -> str:
    try:
        rendered = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=sort_keys,
        )
    except (MemoryError, OverflowError, RecursionError, TypeError, ValueError):
        raise ValueError(error) from None
    return require_public_output_budget(rendered, error=error)


def safe_policy_path(raw_policy: str, root: Path) -> str:
    raw_text = str(raw_policy).strip()
    if not raw_text:
        return ""
    if is_windows_absolute_path(raw_text) or is_url_like_policy_arg(raw_text):
        return "<external-policy>"

    return redact_public_text(safe_resolved_policy_path(resolve_policy_arg(raw_text, root), root))


def resolve_policy_arg(raw_policy: str, root: Path) -> Path:
    raw_text = str(raw_policy).strip()
    if is_url_like_policy_arg(raw_text):
        return (root / "<external-policy>").resolve(strict=False)
    raw = Path(raw_text)
    if raw.is_absolute() or is_windows_absolute_path(raw_text):
        return raw.resolve(strict=False)
    return (root / raw).resolve(strict=False)


def safe_resolved_policy_path(policy_path: Path, root: Path) -> str:
    resolved_root = root.resolve()
    resolved_policy = policy_path.resolve(strict=False)
    try:
        return redact_public_text(resolved_policy.relative_to(resolved_root).as_posix())
    except ValueError:
        return "<external-policy>"


def is_windows_absolute_path(raw_path: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:[\\/]", raw_path)) or raw_path.startswith("\\\\")


def is_url_like_policy_arg(raw_path: str) -> bool:
    return bool(URL_LIKE_POLICY_ARG_RE.match(raw_path))


def scrub_error_path(raw_path: str, *, root: Path, policy_abs: Path, safe_policy: str) -> str:
    if is_windows_absolute_path(raw_path):
        return safe_policy if raw_path == str(policy_abs) else "<absolute-path>"

    path = Path(raw_path)
    if not path.is_absolute():
        return raw_path

    resolved_path = path.resolve(strict=False)
    if resolved_path == policy_abs:
        return safe_policy

    try:
        rel_path = resolved_path.relative_to(root.resolve())
    except ValueError:
        return "<absolute-path>"
    return "." if rel_path.as_posix() == "." else rel_path.as_posix()


def scrub_error_message(
    message: str,
    *,
    root: Path,
    policy_arg: str,
    extra_paths: Iterable[str] = (),
) -> str:
    safe_policy = safe_policy_path(policy_arg, root)
    policy_abs = resolve_policy_arg(policy_arg, root)
    scrubbed = message

    for raw_path in (policy_arg, str(policy_abs), *extra_paths):
        raw_text = str(raw_path)
        if not raw_text:
            continue
        replacement = safe_policy if raw_text in {policy_arg, str(policy_abs)} else scrub_error_path(
            raw_text,
            root=root,
            policy_abs=policy_abs,
            safe_policy=safe_policy,
        )
        scrubbed = scrubbed.replace(raw_text, replacement)

    scrubbed = re.sub(
        r"(['\"])(/[^'\"]+)\1",
        lambda match: scrub_error_path(
            match.group(2),
            root=root,
            policy_abs=policy_abs,
            safe_policy=safe_policy,
        ),
        scrubbed,
    )
    scrubbed = re.sub(
        r"(?<![\w./:-])/(?:[^\s:'\"]+/)*[^\s:'\"]+",
        lambda match: scrub_error_path(
            match.group(0),
            root=root,
            policy_abs=policy_abs,
            safe_policy=safe_policy,
        ),
        scrubbed,
    )
    scrubbed = re.sub(r"[A-Za-z]:\\(?:[^\\\s:'\"]+\\)*[^\\\s:'\"]*", "<absolute-path>", scrubbed)
    return redact_public_text(scrubbed)


def scrub_report_error_message(message: str) -> str:
    scrubbed = re.sub(
        r"(?im)^(\s*-?\s*['\"]?run['\"]?\s*:\s*).*$",
        r"\1<workflow-run>",
        message,
    )
    return re.sub(
        r"(invalid [^\n]* regex[^\n]*?: )(['\"])(?:\\.|(?!\2).)*\2(?=:)",
        r"\1<regex>",
        scrubbed,
    )


def load_json_file(
    path: Path,
    *,
    root_error: str | None = None,
) -> dict[str, object]:
    raw = read_limited_bytes(
        path,
        limit=MAX_REPORT_JSON_BYTES,
        read_error=f"JSON file could not be read: {path}",
        limit_error=ERROR_REPORT_JSON_LIMIT,
    )
    try:
        text = raw.decode("utf-8")
        loaded = load_json_text(text)
    except JSONStructureLimitError:
        raise ValueError(ERROR_REPORT_JSON_LIMIT) from None
    except (MemoryError, OverflowError, RecursionError):
        raise ValueError(ERROR_REPORT_JSON_LIMIT) from None
    except (
        DuplicateJSONKeyError,
        NonFiniteJSONNumberError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        raise ValueError(ERROR_REPORT_JSON_INVALID) from None
    if not isinstance(loaded, dict):
        raise ValueError(root_error or f"JSON file must contain an object: {path}")
    return loaded


def result_payload(
    *,
    scanner: str,
    status: str,
    exit_code: int,
    policy_arg: str,
    root: Path,
    findings: list[dict[str, object]] | None = None,
    scanned_count: int | None = None,
    scanned_unit: str | None = None,
    summary_extra: dict[str, object] | None = None,
    error: str | None = None,
    error_paths: Iterable[str] = (),
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    finding_items = [
        sanitize_public_mapping(item)
        for item in (findings or [])
    ]
    summary: dict[str, object] = {"finding_count": len(finding_items)}
    if scanned_count is not None:
        summary["scanned_count"] = scanned_count
    if scanned_unit:
        summary["scanned_unit"] = scanned_unit
    if summary_extra:
        summary.update(summary_extra)

    payload: dict[str, object] = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": tool_version()},
        "scanner": scanner,
        "status": status,
        "exit_code": exit_code,
        "policy": {"path": safe_policy_path(policy_arg, root)},
        "summary": summary,
        "finding_count": len(finding_items),
        "findings": finding_items,
    }
    if extra:
        payload.update(extra)
    if error is not None:
        payload["error"] = scrub_error_message(error, root=root, policy_arg=policy_arg, extra_paths=error_paths)
    return payload
