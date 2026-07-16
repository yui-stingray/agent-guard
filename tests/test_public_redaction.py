"""Focused tests for public evidence redaction helpers."""

from __future__ import annotations

from agent_guard.public_redaction import redact_public_text, sanitize_public_value


def test_unix_local_path_redaction_uses_non_overlapping_separators() -> None:
    text = "path=/home/alice/private/policy.yaml suffix"

    assert redact_public_text(text) == "path=<absolute-path> suffix"


def test_unix_local_path_redaction_handles_bounded_separator_overlap_input() -> None:
    path = "/home/" + "/".join(f"segment{i}" for i in range(256)) + "/policy.yaml"

    assert redact_public_text(f"before {path} after") == "before <absolute-path> after"


def test_sanitize_public_value_preserves_tuple_type() -> None:
    value = ("safe", "/home/alice/private/policy.yaml", {"key": ("https://example.invalid/path",)})

    sanitized = sanitize_public_value(value)

    assert isinstance(sanitized, tuple)
    assert sanitized == ("safe", "<absolute-path>", {"key": ("<redacted-url>",)})
    assert isinstance(sanitized[2]["key"], tuple)
