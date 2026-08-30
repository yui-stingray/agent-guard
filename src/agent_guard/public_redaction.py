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
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
SHA256_PUBLIC_TEXT_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
LOCAL_PATH_PUBLIC_TEXT_RE = re.compile(
    r"(?:(?:/home|/mnt/c/Users)/(?:[^/\s:'\"]+/)*[^/\s:'\"]+|"
    r"(?<![A-Za-z0-9+.-])[A-Za-z]:[\\/]+(?:[^\\/\s:'\"]+[\\/]+)*[^\\/\s:'\"]+|"
    r"(?:\\\\|(?<!:)//)[^\\/\s:'\"]+(?:[\\/]+[^\\/\s:'\"]+)+)"
)
# URL and absolute-path matches redact the entire containing value. Preserving
# surrounding text makes malformed or quoted values ambiguous and can expose a
# suffix after the recognized prefix.
_PUBLIC_URL_BOUNDARY = r"(?:^|(?<=[\s\"'`=:()\[\]{},;<@|&>]))"
_PUBLIC_PATH_BOUNDARY_CHARS = frozenset("\"'`=:()[],;{}<@|&")
_SPACE_COMPONENT_BOUNDARY_CHARS = frozenset("=:\"'`)]}")
_ABSOLUTE_ROOT_COMPONENTS = frozenset(
    {
        "etc",
        "home",
        "mnt",
        "opt",
        "private",
        "root",
        "tmp",
        "usr",
        "users",
        "var",
        "workspace",
    }
)
RAW_URL_PUBLIC_TEXT_RE = re.compile(
    rf"{_PUBLIC_URL_BOUNDARY}(?:https?\s*:|file\s*:\s*/)",
    re.IGNORECASE,
)


def _has_public_value_boundary(text: str, index: int) -> bool:
    return (
        index == 0
        or text[index - 1].isspace()
        or text[index - 1] in _PUBLIC_PATH_BOUNDARY_CHARS
    )


def _has_unc_share_separator(line: str, start: int) -> bool:
    if start >= len(line) or line[start].isspace():
        return False
    end = start
    while end < len(line) and not line[end].isspace():
        end += 1
    candidate = line[start:end]
    return "/" in candidate[1:] or "\\" in candidate[1:]


def _has_shell_redirect_prefix(line: str, path_start: int) -> bool:
    redirect_end = path_start - 1
    if redirect_end < 0 or line[redirect_end] != ">":
        return False
    index = redirect_end - 1
    while index >= 0 and line[index] not in "/\\":
        index -= 1
    component_start = index + 1
    if line[component_start : component_start + 1] != "<":
        return True
    if line[path_start : path_start + 1] not in {"/", "\\"}:
        return True
    tail_start = path_start + 1
    while tail_start < len(line) and line[tail_start].isspace():
        tail_start += 1
    if line[tail_start : tail_start + 1] == "<":
        return False
    tail_end = tail_start
    while tail_end < len(line) and not line[tail_end].isspace():
        tail_end += 1
    tail = line[tail_start:tail_end]
    first_component = tail.replace("\\", "/").split("/", 1)[0].casefold()
    if first_component in _ABSOLUTE_ROOT_COMPONENTS:
        return True
    if "/" in tail or "\\" in tail:
        return True
    return False


def _line_contains_local_path(line: str) -> bool:
    index = line.find("/")
    while index >= 0:
        boundary = _has_public_value_boundary(line, index)
        if line[index : index + 2] == "//":
            if boundary and _has_unc_share_separator(line, index + 2):
                return True
        elif boundary:
            following = line[index + 1 : index + 2]
            if following and not following.isspace():
                return True
            if following.isspace():
                tail_start = index + 1
                while tail_start < len(line) and line[tail_start].isspace():
                    tail_start += 1
                tail_end = tail_start
                while tail_end < len(line) and not line[tail_end].isspace():
                    tail_end += 1
                prefix = index - 1
                while prefix >= 0 and line[prefix].isspace():
                    prefix -= 1
                if (
                    prefix < 0
                    or line[prefix] in _SPACE_COMPONENT_BOUNDARY_CHARS
                    or "/" in line[tail_start:tail_end]
                ):
                    return True
        if _has_shell_redirect_prefix(line, index):
            return True
        index = line.find("/", index + 1)

    index = line.find("\\")
    while index >= 0:
        if line[index + 1 : index + 2] == "\\":
            boundary = _has_public_value_boundary(line, index)
            if (
                boundary or _has_shell_redirect_prefix(line, index)
            ) and _has_unc_share_separator(line, index + 2):
                return True
        index = line.find("\\", index + 1)

    index = line.find(":")
    while index >= 0:
        if index >= 1:
            drive_start = index - 1
            if (
                line[drive_start].isalpha()
                and line[index + 1 : index + 2] in {"/", "\\"}
                and (
                    _has_public_value_boundary(line, drive_start)
                    or _has_shell_redirect_prefix(line, drive_start)
                )
            ):
                return True
        index = line.find(":", index + 1)

    for option in ("-I", "-L"):
        index = line.find(option)
        while index >= 0:
            if _has_public_value_boundary(line, index) or _has_shell_redirect_prefix(
                line, index
            ):
                target = index + len(option)
                if line[target : target + 1] == "/":
                    return True
                if (
                    line[target : target + 1].isalpha()
                    and line[target + 1 : target + 2] == ":"
                    and line[target + 2 : target + 3] in {"/", "\\"}
                ):
                    return True
            index = line.find(option, index + len(option))
    return False


def contains_raw_url(text: str) -> bool:
    return RAW_URL_PUBLIC_TEXT_RE.search(text) is not None


def contains_local_path(text: str) -> bool:
    return any(_line_contains_local_path(line) for line in text.splitlines() or (text,))


def redact_public_text(text: str) -> str:
    if contains_raw_url(text):
        return "<redacted-url>"
    if contains_local_path(text):
        return "<absolute-path>"
    redacted = SECRET_SHAPED_PUBLIC_TEXT_RE.sub("<redacted>", text)
    return SHA256_PUBLIC_TEXT_RE.sub("<redacted>", redacted)


def sanitize_public_value(value: object) -> object:
    if isinstance(value, str):
        return redact_public_text(value)
    if isinstance(value, dict):
        sanitized: dict[str, object] = {}
        for key, item in value.items():
            sanitized_key = redact_public_text(str(key))
            if sanitized_key in sanitized:
                raise ValueError("public sanitization produced duplicate mapping keys")
            sanitized[sanitized_key] = sanitize_public_value(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_public_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_public_value(item) for item in value)
    return value


def sanitize_public_mapping(value: dict[str, object]) -> dict[str, object]:
    sanitized = sanitize_public_value(value)
    return sanitized if isinstance(sanitized, dict) else {}
