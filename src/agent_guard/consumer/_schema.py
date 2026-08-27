"""Where: src/agent_guard/consumer/_schema.py
What: small JSON-schema subset and report loading helpers for evidence consumers.
Why: keep downstream evidence validation dependency-free inside the package.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from importlib import resources
import json
import math
from pathlib import Path
from typing import Any, NoReturn

from ..bounded_yaml import MAX_YAML_DEPTH, MAX_YAML_NODES


REPORT_SCHEMA_VERSION = "agent-guard.report_evidence.v1"
REPORT_SCHEMA_VERSION_V2 = "agent-guard.report_evidence.v2"
REPORT_SCHEMA = "agent-guard.report_evidence.v1.schema.json"
REPORT_SCHEMA_V2 = "agent-guard.report_evidence.v2.schema.json"
EVIDENCE_PACK_SCHEMA_VERSION = "agent-guard.evidence_pack_manifest.v1"
EVIDENCE_PACK_SCHEMA_VERSION_V2 = "agent-guard.evidence_pack_manifest.v2"
EVIDENCE_PACK_SCHEMA = "agent-guard.evidence_pack_manifest.v1.schema.json"
EVIDENCE_PACK_SCHEMA_V2 = "agent-guard.evidence_pack_manifest.v2.schema.json"
_REPORT_SCHEMAS = {
    REPORT_SCHEMA_VERSION: REPORT_SCHEMA,
    REPORT_SCHEMA_VERSION_V2: REPORT_SCHEMA_V2,
}
_EVIDENCE_PACK_SCHEMAS = {
    EVIDENCE_PACK_SCHEMA_VERSION: EVIDENCE_PACK_SCHEMA,
    EVIDENCE_PACK_SCHEMA_VERSION_V2: EVIDENCE_PACK_SCHEMA_V2,
}
ERROR_DUPLICATE_JSON_KEYS = "public evidence JSON contains duplicate object keys"
ERROR_NONFINITE_JSON_NUMBER = "public evidence JSON contains a non-finite number"
ERROR_PUBLIC_EVIDENCE_INVALID = "public evidence JSON is invalid"
ERROR_PUBLIC_EVIDENCE_READ = "public evidence could not be read"
ERROR_PUBLIC_EVIDENCE_LIMIT = "public evidence exceeds configured limits"
ERROR_REPORT_SCHEMA_UNSUPPORTED = "report evidence schema version is not supported"
ERROR_EVIDENCE_PACK_SCHEMA_UNSUPPORTED = "evidence-pack schema version is not supported"
MAX_REPORT_JSON_BYTES = 1 * 1024 * 1024
MAX_JSON_DEPTH = MAX_YAML_DEPTH
MAX_JSON_ITEMS = MAX_YAML_NODES


class DuplicateJSONKeyError(ValueError):
    """A sanitized duplicate-key failure for untrusted public evidence JSON."""


class NonFiniteJSONNumberError(ValueError):
    """A sanitized non-finite-number failure for untrusted JSON."""


class JSONStructureLimitError(ValueError):
    """Raised when decoded JSON exceeds the shared structured-input budgets."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(ERROR_DUPLICATE_JSON_KEYS)
        result[key] = value
    return result


def _reject_nonfinite_json_number(_value: str) -> NoReturn:
    raise NonFiniteJSONNumberError(ERROR_NONFINITE_JSON_NUMBER)


def _validate_json_structure(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    item_count = 0
    while stack:
        current, depth = stack.pop()
        item_count += 1
        if item_count > MAX_JSON_ITEMS or depth > MAX_JSON_DEPTH:
            raise JSONStructureLimitError(ERROR_PUBLIC_EVIDENCE_LIMIT)
        if isinstance(current, float) and not math.isfinite(current):
            raise NonFiniteJSONNumberError(ERROR_NONFINITE_JSON_NUMBER)
        if isinstance(current, dict):
            item_count += len(current)
            if item_count > MAX_JSON_ITEMS:
                raise JSONStructureLimitError(ERROR_PUBLIC_EVIDENCE_LIMIT)
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def load_json_text(text: str) -> Any:
    payload = json.loads(
        text,
        object_pairs_hook=_object_without_duplicate_keys,
        parse_constant=_reject_nonfinite_json_number,
    )
    _validate_json_structure(payload)
    return payload


def read_limited_bytes(
    path: Path,
    *,
    limit: int,
    read_error: str,
    limit_error: str,
) -> bytes:
    """Read one file through a fixed byte ceiling without exposing its path."""

    try:
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError:
        raise ValueError(read_error) from None
    except (MemoryError, OverflowError):
        raise ValueError(limit_error) from None
    if len(raw) > limit:
        raise ValueError(limit_error)
    return raw


def _load_packaged_schema(name: str) -> dict[str, Any]:
    schema_path = resources.files("agent_guard.schemas").joinpath(name)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    require(isinstance(schema, dict), "packaged schema must be an object")
    return schema


def load_report_schema(
    schema_version: str = REPORT_SCHEMA_VERSION,
) -> dict[str, Any]:
    """Load one of the explicitly supported report schemas; default remains v1."""

    if not isinstance(schema_version, str) or schema_version not in _REPORT_SCHEMAS:
        raise ValueError(ERROR_REPORT_SCHEMA_UNSUPPORTED)
    return _load_packaged_schema(_REPORT_SCHEMAS[schema_version])


def select_report_schema(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Select a packaged report schema from the payload's bounded version marker."""

    report = payload.get("report")
    if not isinstance(report, Mapping) or "schema_version" not in report:
        return load_report_schema()
    version = report.get("schema_version")
    if not isinstance(version, str):
        raise ValueError(ERROR_REPORT_SCHEMA_UNSUPPORTED)
    return load_report_schema(version)


def load_evidence_pack_schema(schema_version: str) -> dict[str, Any]:
    """Load one of the explicitly supported evidence-pack manifest schemas."""

    if not isinstance(schema_version, str) or schema_version not in _EVIDENCE_PACK_SCHEMAS:
        raise ValueError(ERROR_EVIDENCE_PACK_SCHEMA_UNSUPPORTED)
    return _load_packaged_schema(_EVIDENCE_PACK_SCHEMAS[schema_version])


def select_evidence_pack_schema(manifest: Mapping[str, Any]) -> dict[str, Any]:
    version = manifest.get("schema_version")
    if not isinstance(version, str):
        raise ValueError(ERROR_EVIDENCE_PACK_SCHEMA_UNSUPPORTED)
    return load_evidence_pack_schema(version)


def load_payload(path: Path) -> dict[str, Any]:
    try:
        text = read_limited_bytes(
            path,
            limit=MAX_REPORT_JSON_BYTES,
            read_error=ERROR_PUBLIC_EVIDENCE_READ,
            limit_error=ERROR_PUBLIC_EVIDENCE_LIMIT,
        ).decode("utf-8")
    except UnicodeError:
        raise ValueError(ERROR_PUBLIC_EVIDENCE_READ) from None
    try:
        payload = load_json_text(text)
    except DuplicateJSONKeyError:
        raise
    except NonFiniteJSONNumberError:
        raise
    except JSONStructureLimitError:
        raise ValueError(ERROR_PUBLIC_EVIDENCE_LIMIT) from None
    except (MemoryError, OverflowError, RecursionError):
        raise ValueError(ERROR_PUBLIC_EVIDENCE_LIMIT) from None
    except (json.JSONDecodeError, TypeError, ValueError):
        raise ValueError(ERROR_PUBLIC_EVIDENCE_INVALID) from None
    if not isinstance(payload, dict):
        raise ValueError("report payload must be a JSON object")
    return payload


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def schema_condition_matches(schema: Any, value: Any) -> bool:
    if not isinstance(schema, Mapping) or not isinstance(value, Mapping):
        return False
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        return False
    for key, child in properties.items():
        if key not in value or not isinstance(child, Mapping):
            return False
        if "const" in child and value[key] != child["const"]:
            return False
        if "enum" in child and value[key] not in child["enum"]:
            return False
    return True


def value_has_json_type(value: Any, schema_type: Any) -> bool:
    if schema_type == "object":
        return isinstance(value, Mapping)
    if schema_type == "array":
        return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))
    if schema_type == "string":
        return isinstance(value, str)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "boolean":
        return isinstance(value, bool)
    if schema_type == "null":
        return value is None
    return True


def validate_against_schema(schema: Mapping[str, Any], value: Any, *, path: str) -> None:
    schema_type = schema.get("type")
    allowed_types = schema_type if isinstance(schema_type, list) else [schema_type]
    if schema_type is not None:
        require(any(value_has_json_type(value, item) for item in allowed_types), f"{path} has wrong type")

    if "const" in schema:
        require(value == schema["const"], f"{path} must equal {schema['const']!r}")
    if "enum" in schema:
        require(value in schema["enum"], f"{path} must be one of {schema['enum']!r}")
    if "minimum" in schema and isinstance(value, (int, float)) and not isinstance(value, bool):
        require(value >= schema["minimum"], f"{path} must be >= {schema['minimum']!r}")

    for condition in schema.get("allOf", []):
        if isinstance(condition, Mapping) and schema_condition_matches(condition.get("if", {}), value):
            then_schema = condition.get("then")
            if isinstance(then_schema, Mapping):
                validate_against_schema(then_schema, value, path=path)

    if (schema_type == "object" or "required" in schema or "properties" in schema) and isinstance(value, Mapping):
        for required in schema.get("required", []):
            require(required in value, f"{path}.{required} is required")
        properties = schema.get("properties", {})
        require(isinstance(properties, Mapping), f"{path}.properties must be an object")
        if schema.get("additionalProperties", True) is False:
            extras = set(value) - set(properties)
            require(not extras, f"{path} has {len(extras)} extra properties")
        for key, item in value.items():
            child = properties.get(key)
            if isinstance(child, Mapping):
                validate_against_schema(child, item, path=f"{path}.{key}")

    if schema_type == "array" and isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                validate_against_schema(item_schema, item, path=f"{path}[{index}]")


def require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    require(isinstance(value, Mapping), f"{path} must be an object")
    return value


def require_sequence(value: Any, path: str) -> Sequence[Any]:
    require(
        isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)),
        f"{path} must be an array",
    )
    return value


def require_int(value: Any, path: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{path} must be an integer")
    require(value >= 0, f"{path} must be >= 0")
    return value
