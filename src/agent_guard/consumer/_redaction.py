"""Where: src/agent_guard/consumer/_redaction.py
What: public evidence shape checks that reject raw paths, URLs, hashes, and secrets.
Why: evidence consumers must fail closed before forwarding sanitized reports.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import re

from ..public_redaction import (
    LOCAL_PATH_PUBLIC_TEXT_RE,
    SECRET_SHAPED_PUBLIC_TEXT_RE,
    contains_local_path,
    contains_raw_url,
)
from ..surface_inventory_mcp_safety import (
    SCOPE_FIELD_NAMES,
    is_authorization_field_name,
    normalized_auth_field_name,
)
from ._schema import require


FORBIDDEN_PUBLIC_KEYS = frozenset({"matched_text", "raw_regex", "snippet"})
SENSITIVE_CONTAINER_FIELD_NAMES = frozenset(
    {
        "args",
        "arguments",
        "credential",
        "credentials",
        "env",
        "environment",
        "headers",
    }
)
ALLOWED_SENSITIVE_KEY_PATHS = frozenset(
    {
        ("report", "scope"),
        ("evidence_pack_manifest", "report", "scope"),
    }
)
# Retained with their 0.3.2 import and matching semantics. Consumer validation
# uses the shared predicates above; these regex helpers are not authoritative.
LOCAL_PATH_RE = re.compile(
    rf"(?:{LOCAL_PATH_PUBLIC_TEXT_RE.pattern}|"
    r"(?:^|[\s\"'=:])(?:/(?:home|Users)/|[A-Za-z]:[\\/]+Users[\\/]+))"
)
RAW_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SHA256_VALUE_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
SECRET_VALUE_RE = re.compile(
    rf"(?:{SECRET_SHAPED_PUBLIC_TEXT_RE.pattern}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def validate_public_text_shape(text: str, *, path: str) -> None:
    require(not contains_raw_url(text), f"{path} contains a raw URL")
    require(not contains_local_path(text), f"{path} contains a raw local path")
    require(not SHA256_VALUE_RE.search(text), f"{path} contains a raw sha256-shaped value")
    require(not SECRET_VALUE_RE.search(text), f"{path} contains a secret-shaped value")


def _is_structurally_sensitive_public_key(key: str) -> bool:
    normalized = normalized_auth_field_name(key)
    return (
        is_authorization_field_name(key)
        or normalized in SCOPE_FIELD_NAMES
        or normalized in SENSITIVE_CONTAINER_FIELD_NAMES
    )


def validate_public_evidence_shape(
    value: object,
    *,
    path: str = "$",
    _field_path: tuple[str, ...] = (),
) -> None:
    if isinstance(value, Mapping):
        for index, (key, item) in enumerate(value.items()):
            key_text = str(key)
            key_path = f"{path}.keys[{index}]"
            child_path = f"{path}.values[{index}]"
            require(key_text not in FORBIDDEN_PUBLIC_KEYS, f"{key_path} is a forbidden raw evidence key")
            field_path = (*_field_path, key_text)
            require(
                not _is_structurally_sensitive_public_key(key_text)
                or field_path in ALLOWED_SENSITIVE_KEY_PATHS,
                f"{key_path} is a forbidden raw evidence key",
            )
            validate_public_text_shape(key_text, path=key_path)
            validate_public_evidence_shape(
                item,
                path=child_path,
                _field_path=field_path,
            )
        return

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            validate_public_evidence_shape(
                item,
                path=f"{path}[{index}]",
                _field_path=_field_path,
            )
        return

    if isinstance(value, str):
        validate_public_text_shape(value, path=path)
