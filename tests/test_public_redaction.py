"""Focused tests for public evidence redaction helpers."""

from __future__ import annotations

import pytest

from agent_guard.consumer import validate_public_text_shape
from agent_guard.public_redaction import redact_public_text, sanitize_public_value


def test_unix_local_path_redaction_uses_non_overlapping_separators() -> None:
    text = "path=/home/alice/private/policy.yaml suffix"

    assert redact_public_text(text) == "path=<absolute-path> suffix"


def test_unix_local_path_redaction_handles_bounded_separator_overlap_input() -> None:
    path = "/home/" + "/".join(f"segment{i}" for i in range(256)) + "/policy.yaml"

    assert redact_public_text(f"before {path} after") == "before <absolute-path> after"


def test_aws_access_key_id_shapes_are_redacted_without_leak() -> None:
    values = ("AKIA" + ("A" * 16), "ASIA" + ("B" * 16))

    for value in values:
        redacted = redact_public_text(f"before {value} after")

        assert redacted == "before <redacted> after"
        assert value not in redacted


@pytest.mark.parametrize(
    "value",
    (
        "HTTP://example.invalid/private",
        "HtTpS://example.invalid/private",
    ),
)
def test_url_redaction_and_consumer_validation_are_case_insensitive(value: str) -> None:
    redacted = redact_public_text(f"before {value} after")

    assert redacted == "before <redacted-url> after"
    assert value not in redacted
    with pytest.raises(ValueError, match="raw URL") as exc_info:
        validate_public_text_shape(value, path="$.value")
    assert value not in str(exc_info.value)


@pytest.mark.parametrize(
    "value",
    (
        "sk-" + ("a" * 16),
        "xoxb-" + ("a" * 10),
        "AKIA" + ("A" * 16),
        "ASIA" + ("B" * 16),
    ),
)
def test_consumer_rejects_controlled_secret_shapes_redacted_by_producer(value: str) -> None:
    redacted = redact_public_text(f"before {value} after")

    assert value not in redacted
    with pytest.raises(ValueError, match="secret-shaped value") as exc_info:
        validate_public_text_shape(value, path="$.value")
    assert value not in str(exc_info.value)


def test_consumer_rejects_wsl_user_path_redacted_by_producer() -> None:
    value = "/mnt/c/Users/example/private.txt"
    redacted = redact_public_text(f"before {value} after")

    assert value not in redacted
    with pytest.raises(ValueError, match="raw local path") as exc_info:
        validate_public_text_shape(value, path="$.value")
    assert value not in str(exc_info.value)


@pytest.mark.parametrize(
    "value",
    (
        r"D:\synthetic\private\policy.yaml",
        r"\\synthetic-host\private\policy.yaml",
    ),
)
def test_consumer_rejects_absolute_windows_paths_redacted_by_producer(value: str) -> None:
    redacted = redact_public_text(f"before {value} after")

    assert redacted == "before <absolute-path> after"
    assert value not in redacted
    with pytest.raises(ValueError, match="raw local path") as exc_info:
        validate_public_text_shape(value, path="$.value")
    assert value not in str(exc_info.value)


def test_sanitize_public_value_preserves_tuple_type() -> None:
    value = ("safe", "/home/alice/private/policy.yaml", {"key": ("https://example.invalid/path",)})

    sanitized = sanitize_public_value(value)

    assert isinstance(sanitized, tuple)
    assert sanitized == ("safe", "<absolute-path>", {"key": ("<redacted-url>",)})
    assert isinstance(sanitized[2]["key"], tuple)
