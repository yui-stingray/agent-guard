"""Where: src/agent_guard/bounded_yaml.py
What: pre-construction and post-construction bounds for untrusted YAML.
Why: prevent policy aliases, nesting, and object graphs from exhausting scanners.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, NoReturn

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode


MAX_YAML_ALIASES = 128
MAX_YAML_NODES = 50_000
MAX_YAML_DEPTH = 64
MAX_YAML_GRAPH_TRAVERSAL = 100_000
# Shared policy loaders cap their raw YAML input at this size. Keep
# alias-expanded scalar data within the same envelope before callers normalize it.
MAX_YAML_EXPANDED_BYTES = 256 * 1024


class BoundedYamlInvalidError(Exception):
    """YAML syntax or construction was invalid."""


class BoundedYamlLimitError(Exception):
    """YAML exceeded a construction or traversal safety bound."""


class StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader variant that rejects duplicate constructed mapping keys."""

    def construct_mapping(
        self,
        node: yaml.Node,
        deep: bool = False,
    ) -> dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(
                None,
                None,
                "expected a mapping node",
                node.start_mark,
            )
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                hash(key)
            except TypeError:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from None
            if key in mapping:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found a duplicate mapping key",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def strict_safe_load(text: str) -> Any:
    """Safely construct YAML while rejecting duplicate Python mapping keys."""

    return yaml.load(text, Loader=StrictSafeLoader)


def _raise_invalid() -> NoReturn:
    raise BoundedYamlInvalidError from None


def _raise_limit() -> NoReturn:
    raise BoundedYamlLimitError from None


def _preflight_yaml_events(text: str) -> None:
    """Bound syntax and reject merge expansion before object construction."""

    aliases = 0
    nodes = 0
    depth = 0
    node_events = (
        yaml.events.AliasEvent,
        yaml.events.MappingStartEvent,
        yaml.events.ScalarEvent,
        yaml.events.SequenceStartEvent,
    )
    start_events = (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)
    end_events = (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)

    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, node_events):
            nodes += 1
            if nodes > MAX_YAML_NODES:
                _raise_limit()
        if isinstance(event, yaml.events.AliasEvent):
            aliases += 1
            if aliases > MAX_YAML_ALIASES:
                _raise_limit()
        if isinstance(event, start_events):
            depth += 1
            if depth > MAX_YAML_DEPTH:
                _raise_limit()
        elif isinstance(event, end_events):
            depth -= 1
        if isinstance(event, yaml.events.ScalarEvent) and (
            event.tag == "tag:yaml.org,2002:merge"
            or (event.value == "<<" and event.style is None and event.implicit[0])
        ):
            # SafeLoader expands merge aliases while constructing a mapping.
            # Ordinary bounded aliases remain compatible without this feature.
            _raise_limit()


def _iter_mapping_children(value: dict[Any, Any]) -> Iterator[Any]:
    for key, child in value.items():
        yield key
        yield child


def _container_children(value: Any) -> Iterator[Any] | None:
    if isinstance(value, dict):
        return _iter_mapping_children(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        return iter(value)
    return None


def _scalar_expanded_bytes(value: Any) -> int:
    if _container_children(value) is not None:
        return 0
    try:
        return len(str(value).encode("utf-8"))
    except UnicodeEncodeError:
        _raise_limit()


def _validate_object_graph(
    value: Any,
    *,
    max_expanded_bytes: int | None = None,
) -> None:
    """Reject cycles and bound alias-expanded graph work without recursion."""

    active: set[int] = set()
    stack: list[tuple[int, Iterator[Any], int]] = []
    traversed = 0
    expanded_bytes = 0
    expanded_bytes_limit = (
        MAX_YAML_EXPANDED_BYTES
        if max_expanded_bytes is None
        else max_expanded_bytes
    )

    def enter(child: Any, *, depth: int) -> None:
        nonlocal expanded_bytes, traversed
        traversed += 1
        if traversed > MAX_YAML_GRAPH_TRAVERSAL or depth > MAX_YAML_DEPTH:
            _raise_limit()
        expanded_bytes += _scalar_expanded_bytes(child)
        if expanded_bytes > expanded_bytes_limit:
            _raise_limit()
        children = _container_children(child)
        if children is None:
            return
        identity = id(child)
        if identity in active:
            _raise_limit()
        active.add(identity)
        stack.append((identity, children, depth))

    enter(value, depth=1)
    while stack:
        identity, children, depth = stack[-1]
        try:
            child = next(children)
        except StopIteration:
            stack.pop()
            active.remove(identity)
            continue
        enter(child, depth=depth + 1)


def load_bounded_yaml(
    text: str,
    *,
    max_expanded_bytes: int | None = None,
) -> Any:
    """Strictly construct YAML after event bounds, then validate its graph."""

    try:
        _preflight_yaml_events(text)
        loaded = strict_safe_load(text)
        _validate_object_graph(loaded, max_expanded_bytes=max_expanded_bytes)
    except (BoundedYamlInvalidError, BoundedYamlLimitError):
        raise
    except (MemoryError, OverflowError, RecursionError):
        _raise_limit()
    except yaml.YAMLError:
        _raise_invalid()
    except (TypeError, UnicodeError, ValueError):
        _raise_invalid()
    return loaded
