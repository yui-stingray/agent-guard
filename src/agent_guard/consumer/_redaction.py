"""Where: src/agent_guard/consumer/_redaction.py
What: public evidence shape checks that reject raw paths, URLs, hashes, and secrets.
Why: evidence consumers must fail closed before forwarding sanitized reports.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import re
from typing import Any

from ._schema import require


FORBIDDEN_PUBLIC_KEYS = frozenset({"matched_text", "raw_regex", "snippet"})
LOCAL_PATH_RE = re.compile(r"(?:^|[\s\"'=:])(?:/(?:home|Users)/|[A-Za-z]:[\\/]+Users[\\/]+)")
RAW_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
SHA256_VALUE_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
SECRET_VALUE_RE = re.compile(
    r"(?:"
    r"sk-[A-Za-z0-9_-]{20,}"
    r"|gh[pousr]_[A-Za-z0-9_]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|ASIA[0-9A-Z]{16}"
    r"|xox[baprs]-[A-Za-z0-9-]{20,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r")"
)


def validate_public_text_shape(text: str, *, path: str) -> None:
    require(not LOCAL_PATH_RE.search(text), f"{path} contains a raw local path")
    require(not RAW_URL_RE.search(text), f"{path} contains a raw URL")
    require(not SHA256_VALUE_RE.search(text), f"{path} contains a raw sha256-shaped value")
    require(not SECRET_VALUE_RE.search(text), f"{path} contains a secret-shaped value")


def validate_public_evidence_shape(value: Any, *, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for index, (key, item) in enumerate(value.items()):
            key_text = str(key)
            key_path = f"{path}.keys[{index}]"
            child_path = f"{path}.values[{index}]"
            require(key_text not in FORBIDDEN_PUBLIC_KEYS, f"{key_path} is a forbidden raw evidence key")
            validate_public_text_shape(key_text, path=key_path)
            validate_public_evidence_shape(item, path=child_path)
        return

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            validate_public_evidence_shape(item, path=f"{path}[{index}]")
        return

    if isinstance(value, str):
        validate_public_text_shape(value, path=path)
