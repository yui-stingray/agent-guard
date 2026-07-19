"""Shared redaction helpers for public JSON and text evidence."""

from __future__ import annotations

import re


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
RAW_URL_PUBLIC_TEXT_RE = re.compile(r"https?://[^\s\"'`<>()]+", re.IGNORECASE)
LOCAL_PATH_PUBLIC_TEXT_RE = re.compile(
    r"(?:(?:/home|/mnt/c/Users)/(?:[^/\s:'\"]+/)*[^/\s:'\"]+|"
    r"(?<![A-Za-z0-9+.-])[A-Za-z]:[\\/]+(?:[^\\/\s:'\"]+[\\/]+)*[^\\/\s:'\"]+|"
    r"(?:\\\\|(?<!:)//)[^\\/\s:'\"]+(?:[\\/]+[^\\/\s:'\"]+)+)"
)


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
        return tuple(sanitize_public_value(item) for item in value)
    return value


def sanitize_public_mapping(value: dict[str, object]) -> dict[str, object]:
    sanitized = sanitize_public_value(value)
    return sanitized if isinstance(sanitized, dict) else {}
