"""Where: src/agent_guard/cli/common.py
What: shared CLI constants, redaction, policy-path, and result-envelope helpers.
Why: shrink the legacy CLI module without changing subcommand behavior.
"""

from __future__ import annotations

import json
import re
from importlib import metadata
from pathlib import Path
from typing import Iterable

from .. import __version__ as PACKAGE_VERSION

RESULT_SCHEMA_VERSION = "agent-guard.result.v1"
REPORT_EVIDENCE_SCHEMA_VERSION = "agent-guard.report_evidence.v1"
TOOL_NAME = "agent-guard"
RECOMMENDED_EVIDENCE_PRESET = "recommended"
SECRET_SHAPED_PUBLIC_TEXT_RE = re.compile(
    r"(sk-[A-Za-z0-9_-]{16,}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"ASIA[0-9A-Z]{16}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"
)
SHA256_PUBLIC_TEXT_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
RAW_URL_PUBLIC_TEXT_RE = re.compile(r"https?://[^\s\"'`<>()]+")
URL_LIKE_POLICY_ARG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
LOCAL_PATH_PUBLIC_TEXT_RE = re.compile(
    r"(?:(?:/home|/mnt/c/Users)/(?:[^\s:'\"]+/)*[^\s:'\"]+|"
    r"[A-Za-z]:[\\/]+Users[\\/]+(?:[^\\/\s:'\"]+[\\/]+)*[^\\/\s:'\"]+)"
)


def tool_version() -> str:
    if PACKAGE_VERSION:
        return PACKAGE_VERSION
    try:
        return metadata.version("yui-agent-guard")
    except metadata.PackageNotFoundError:
        return "0.0.0+local"


def safe_policy_path(raw_policy: str, root: Path) -> str:
    raw_text = str(raw_policy).strip()
    if not raw_text:
        return ""
    if is_windows_absolute_path(raw_text) or is_url_like_policy_arg(raw_text):
        return "<external-policy>"

    return redact_public_text(safe_resolved_policy_path(resolve_policy_arg(raw_text, root), root))


def redact_public_text(text: str) -> str:
    redacted = RAW_URL_PUBLIC_TEXT_RE.sub("<redacted-url>", text)
    redacted = LOCAL_PATH_PUBLIC_TEXT_RE.sub("<absolute-path>", redacted)
    redacted = SECRET_SHAPED_PUBLIC_TEXT_RE.sub("<redacted>", redacted)
    return SHA256_PUBLIC_TEXT_RE.sub("<redacted>", redacted)


def sanitize_public_value(value: object) -> object:
    if isinstance(value, str):
        return redact_public_text(value)
    if isinstance(value, dict):
        return {
            redact_public_text(str(key)): sanitize_public_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_public_value(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_public_value(item) for item in value]
    return value


def sanitize_public_mapping(value: dict[str, object]) -> dict[str, object]:
    sanitized = sanitize_public_value(value)
    return sanitized if isinstance(sanitized, dict) else {}


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


def load_json_file(path: Path) -> dict[str, object]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"JSON file must contain an object: {path}")
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
