"""Where: src/agent_guard/consumer/_schema.py
What: small JSON-schema subset and report loading helpers for evidence consumers.
Why: keep downstream evidence validation dependency-free inside the package.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from importlib import resources
import json
from pathlib import Path
from typing import Any


REPORT_SCHEMA = "agent-guard.report_evidence.v1.schema.json"
ERROR_DUPLICATE_JSON_KEYS = "public evidence JSON contains duplicate object keys"


class DuplicateJSONKeyError(ValueError):
    """A sanitized duplicate-key failure for untrusted public evidence JSON."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(ERROR_DUPLICATE_JSON_KEYS)
        result[key] = value
    return result


def load_json_text(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_object_without_duplicate_keys)


def load_report_schema() -> dict[str, Any]:
    schema_path = resources.files("agent_guard.schemas").joinpath(REPORT_SCHEMA)
    return json.loads(schema_path.read_text(encoding="utf-8"))


def load_payload(path: Path) -> dict[str, Any]:
    payload = load_json_text(path.read_text(encoding="utf-8"))
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
