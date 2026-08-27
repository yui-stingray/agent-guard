"""Where: tests/test_bounded_yaml.py
What: shared YAML alias-expansion tests.
Why: keep aliases bounded before policy normalizers can expand them.
"""

from __future__ import annotations

import pytest

from agent_guard.bounded_yaml import (
    BoundedYamlInvalidError,
    BoundedYamlLimitError,
    MAX_YAML_EXPANDED_BYTES,
    load_bounded_yaml,
)


def _alias_dag(marker: str, *, depth: int) -> str:
    lines = [f"n0: &n0 [{marker}]\n"]
    for index in range(1, depth + 1):
        lines.append(f"n{index}: &n{index} [*n{index - 1}, *n{index - 1}]\n")
    lines.append(f"root: *n{depth}\n")
    return "".join(lines)


def test_bounded_yaml_rejects_alias_dag_expanded_scalar_bytes() -> None:
    marker = "x" * (MAX_YAML_EXPANDED_BYTES // (2**12) + 1)

    with pytest.raises(BoundedYamlLimitError) as exc_info:
        load_bounded_yaml(_alias_dag(marker, depth=12))

    assert marker not in str(exc_info.value)


def test_bounded_yaml_rejects_integer_alias_dag_expanded_scalar_bytes() -> None:
    marker = "9" * 4_000

    with pytest.raises(BoundedYamlLimitError) as exc_info:
        load_bounded_yaml(_alias_dag(marker, depth=7))

    assert marker not in str(exc_info.value)


def test_bounded_yaml_preserves_small_non_merge_aliases() -> None:
    loaded = load_bounded_yaml(
        "shared: &shared [safe]\nfirst: *shared\nsecond: *shared\n",
    )

    assert loaded["first"] is loaded["second"] is loaded["shared"]


@pytest.mark.parametrize(
    "mapping",
    [
        "key: first\nkey: second",
        "1: first\n01: second",
        "true: first\n1: second",
        "null: first\n~: second",
        "1.0: first\n1: second",
    ],
)
def test_bounded_yaml_rejects_duplicate_constructed_keys_at_nested_depth(
    mapping: str,
) -> None:
    nested = "outer:\n  sequence:\n    - mapping:\n" + "\n".join(
        f"        {line}" for line in mapping.splitlines()
    )

    with pytest.raises(BoundedYamlInvalidError):
        load_bounded_yaml(nested)
