"""Focused tests for public evidence redaction helpers."""

from __future__ import annotations

import pytest

from agent_guard.consumer import validate_public_text_shape
from agent_guard.public_redaction import redact_public_text, sanitize_public_value


def test_unix_local_path_redaction_uses_non_overlapping_separators() -> None:
    text = "path=/home/alice/private/policy.yaml suffix"

    assert redact_public_text(text) == "<absolute-path>"


def test_local_path_redaction_drops_an_ambiguous_status_suffix() -> None:
    text = "path=/home/alice/private/policy.yaml; status=ok"

    assert redact_public_text(text) == "<absolute-path>"


@pytest.mark.parametrize(
    "value",
    (
        r"D:\synthetic; status=private\report.json",
        r"D:\synthetic, code=private\report.json",
    ),
)
def test_path_delimiters_do_not_expose_path_remainders(value: str) -> None:
    redacted = redact_public_text(value)

    assert redacted == "<absolute-path>"
    assert value not in redacted
    validate_public_text_shape(redacted, path="$.value")


def test_unix_local_path_redaction_handles_bounded_separator_overlap_input() -> None:
    path = "/home/" + "/".join(f"segment{i}" for i in range(256)) + "/policy.yaml"

    assert redact_public_text(f"before {path} after") == "<absolute-path>"


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

    assert redacted == "<redacted-url>"
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
        "/root/synthetic/private.txt",
        "/var/root/synthetic/private.txt",
        "/tmp/synthetic/private.txt",
        "/workspace/synthetic/private.txt",
        "path:/home/synthetic/private.txt",
        "/ synthetic/report.json",
        "2>/home/synthetic/private/output.json",
        "command>/home/synthetic/private/output.json",
        "command2>/home/synthetic/private/output.json",
        "command&>/home/synthetic/private/output.json",
        "command;2>/home/synthetic/private/output.json",
        "command|/home/synthetic/private/tool",
        "command||/home/synthetic/private/tool",
        "command&&/home/synthetic/private/tool",
        "artifact=/ synthetic",
        "artifact='/ synthetic'",
        "path: / synthetic",
        "command<input >/home/synthetic/private/output.json",
        "command<input>/home/synthetic/private/output.json",
        "command '<' >/home/synthetic/private/output.json",
        "command>-I/home/synthetic/private/include",
        "command>-L/home/synthetic/private/lib",
        "<img>/home/synthetic/private",
        "bang!/<img src=x>/home/synthetic/private",
        "-I/home/synthetic/private/include",
        "-L/home/synthetic/private/lib",
        "@/workspace/synthetic/private/list.txt",
        r"-ID:\synthetic\private\include",
        r"-LD:\synthetic\private\lib",
        r"command>D:\synthetic\private\output.json",
        r"command|D:\synthetic\private\tool.exe",
        r"command<input >D:\synthetic\private\output.json",
        r"command<input>D:\synthetic\private\output.json",
        r"<img>D:\synthetic\private",
        r"command>\\synthetic-host\private\output.json",
    ),
)
def test_consumer_rejects_common_absolute_posix_paths(value: str) -> None:
    assert redact_public_text(f"before {value} after") == "<absolute-path>"
    with pytest.raises(ValueError, match="raw local path") as exc_info:
        validate_public_text_shape(value, path="$.value")
    assert value not in str(exc_info.value)


def test_value_rooted_single_space_component_path_is_rejected() -> None:
    value = "/ synthetic"

    assert redact_public_text(value) == "<absolute-path>"
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

    assert redacted == "<absolute-path>"
    assert value not in redacted
    with pytest.raises(ValueError, match="raw local path") as exc_info:
        validate_public_text_shape(value, path="$.value")
    assert value not in str(exc_info.value)


@pytest.mark.parametrize(
    "value",
    (
        r"D:\synthetic folder\private\report name.json",
        r"D:\ synthetic folder\private\report name.json",
        r"D:\synthetic's folder\private\report name.json",
        r"D:\synthetic`folder\private\report name.json",
        r"\\synthetic-host\private folder\report name.json",
        r"\\synthetic'host\private folder\report name.json",
        r"\\synthetic`host\private folder\report name.json",
        r"\\?\D:\synthetic folder\private\report name.json",
        r"\\?\UNC\synthetic-host\private folder\report name.json",
    ),
)
def test_windows_path_spaces_and_extended_prefixes_are_fully_redacted(value: str) -> None:
    redacted = redact_public_text(value)

    assert redacted == "<absolute-path>"
    assert value not in redacted
    with pytest.raises(ValueError, match="raw local path") as exc_info:
        validate_public_text_shape(value, path="$.value")
    assert value not in str(exc_info.value)
    validate_public_text_shape(redacted, path="$.value")


def test_quoted_windows_path_redacts_the_entire_value() -> None:
    value = r"D:\synthetic's folder\private\report name.json"

    redacted = redact_public_text(f'before "{value}" after')

    assert redacted == "<absolute-path>"
    assert value not in redacted


@pytest.mark.parametrize(
    ("quote", "value"),
    (
        ("'", r"D:\synthetic's\private\report.json"),
        ("`", r"D:\synthetic`folder\private\report.json"),
    ),
)
def test_quoted_path_with_internal_delimiter_redacts_the_entire_value(quote: str, value: str) -> None:
    redacted = redact_public_text(f"before {quote}{value}{quote} after")

    assert redacted == "<absolute-path>"
    assert value not in redacted


def test_quoted_path_with_later_field_redacts_the_entire_value() -> None:
    value = r"D:\synthetic folder\private\report.json"

    redacted = redact_public_text(f'before "{value}" after "safe text"')

    assert redacted == "<absolute-path>"
    assert value not in redacted


@pytest.mark.parametrize(
    "value",
    (
        "HtTpS://example.invalid/private)synthetic-tail",
        "https://example.invalid/private]synthetic-tail",
        "https://example.invalid/private's/synthetic-tail",
        "https://example.invalid/private`synthetic-tail",
    ),
)
def test_url_delimiter_suffixes_are_fully_redacted(value: str) -> None:
    redacted = redact_public_text(value)

    assert redacted == "<redacted-url>"
    assert value not in redacted
    with pytest.raises(ValueError, match="raw URL") as exc_info:
        validate_public_text_shape(value, path="$.value")
    assert value not in str(exc_info.value)
    validate_public_text_shape(redacted, path="$.value")


@pytest.mark.parametrize(
    "value",
    (
        "HTTPS:/synthetic-host/private/report.json",
        "https:synthetic-host/private/report.json",
        "HtTpS : //synthetic-host/private/report.json",
    ),
)
def test_malformed_http_url_like_values_are_fully_redacted(value: str) -> None:
    assert redact_public_text(value) == "<redacted-url>"
    with pytest.raises(ValueError, match="raw URL") as exc_info:
        validate_public_text_shape(value, path="$.value")
    assert value not in str(exc_info.value)


@pytest.mark.parametrize(
    "value",
    (
        "command|https:synthetic-host/private",
        "command&&https:synthetic-host/private",
        "command>https://synthetic.invalid/private",
        "command>https:synthetic.invalid/private",
    ),
)
def test_compact_shell_boundaries_do_not_hide_url_schemes(value: str) -> None:
    assert redact_public_text(value) == "<redacted-url>"
    with pytest.raises(ValueError, match="raw URL") as exc_info:
        validate_public_text_shape(value, path="$.value")
    assert value not in str(exc_info.value)


def test_local_file_uri_is_fully_redacted() -> None:
    value = "file://localhost/home/synthetic/private/file"

    assert redact_public_text(value) == "<redacted-url>"
    with pytest.raises(ValueError, match="raw URL") as exc_info:
        validate_public_text_shape(value, path="$.value")
    assert value not in str(exc_info.value)


@pytest.mark.parametrize("value", ("file: report.json", "source file: report.json"))
def test_plain_file_labels_are_not_treated_as_file_uris(value: str) -> None:
    assert redact_public_text(value) == value
    validate_public_text_shape(value, path="$.value")


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("u='https://host.invalid/a's/private-tail", "<redacted-url>"),
        (r"p='D:\synthetic's\private\tail", "<absolute-path>"),
    ),
)
def test_unmatched_quote_suffixes_redact_the_entire_value(value: str, expected: str) -> None:
    redacted = redact_public_text(value)

    assert redacted == expected
    assert value not in redacted
    validate_public_text_shape(redacted, path="$.value")


def test_url_with_spaces_is_fully_redacted() -> None:
    value = "https://example.invalid/private folder/report.json"

    redacted = redact_public_text(value)

    assert redacted == "<redacted-url>"
    assert value not in redacted
    validate_public_text_shape(redacted, path="$.value")


def test_quoted_url_with_later_field_redacts_the_entire_value() -> None:
    value = "https://example.invalid/private folder/report.json"

    redacted = redact_public_text(f'before "{value}" after "safe text"')

    assert redacted == "<redacted-url>"
    assert value not in redacted


def test_angle_bracketed_url_and_path_values_use_complete_markers() -> None:
    assert redact_public_text("before <HTTPS://example.invalid/private> after") == "<redacted-url>"
    assert redact_public_text("before </home/synthetic/private> after") == "<absolute-path>"


def test_url_redaction_drops_an_ambiguous_status_suffix() -> None:
    value = "https://example.invalid/private folder/report.json; status=ok"

    assert redact_public_text(value) == "<redacted-url>"


def test_many_same_line_urls_are_redacted_in_one_value_level_match() -> None:
    value = " ".join(
        f"https://example.invalid/private/{index}"
        for index in range(10_000)
    )

    assert redact_public_text(value) == "<redacted-url>"


@pytest.mark.parametrize(
    "value",
    (
        "ratio // denominator and safe suffix",
        "ratio//denominator/scale",
        "ratio / denominator and unit / second",
        "ratio //denominator and unit / second",
        r"prefix \\ suffix",
        "folder,with:colon%/AGENTS.md",
        "bang!/<synthetic>/AGENTS.md",
        "bang!/<x>text>/AGENTS.md",
        "docs//nested/report.json",
        r"docs\\nested\report.json",
        "supports_https: true",
        "docs/http:client.md",
    ),
)
def test_non_path_slash_notation_is_not_redacted(value: str) -> None:
    assert redact_public_text(value) == value
    validate_public_text_shape(value, path="$.value")


def test_large_benign_value_and_late_path_use_the_same_bounded_rules() -> None:
    benign = "ratio//denominator/scale " * 4_000

    assert redact_public_text(benign) == benign
    assert redact_public_text(benign + "/home/synthetic/private/report.json") == "<absolute-path>"


def test_repeated_tag_like_text_remains_benign_with_bounded_scanning() -> None:
    value = "<x>/" * 32_768

    assert redact_public_text(value) == value
    validate_public_text_shape(value, path="$.value")


def test_sanitize_public_value_preserves_tuple_type() -> None:
    value = ("safe", "/home/alice/private/policy.yaml", {"key": ("https://example.invalid/path",)})

    sanitized = sanitize_public_value(value)

    assert isinstance(sanitized, tuple)
    assert sanitized == ("safe", "<absolute-path>", {"key": ("<redacted-url>",)})
    assert isinstance(sanitized[2]["key"], tuple)


def test_sanitize_public_value_rejects_redacted_key_collisions_without_leak() -> None:
    first = "field=https://one.invalid/a alpha"
    second = "field=https://two.invalid/b beta"

    with pytest.raises(ValueError, match="duplicate mapping keys") as exc_info:
        sanitize_public_value({first: 1, second: 2})

    error = str(exc_info.value)
    assert first not in error
    assert second not in error
