"""Focused regressions for untrusted JSON input and public JSON output."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from agent_guard import (
    context_guard,
    digest_guard,
    mcp_guard,
    report_render,
    report_sarif,
    surface_delta,
    surface_inventory_context,
    surface_inventory_mcp,
)


PUBLIC_BUDGET_SERIALIZERS: tuple[tuple[Callable[[object], int], str], ...] = (
    (context_guard._canonical_json_size, context_guard.ERROR_CONTEXT_SCAN_LIMIT),
    (digest_guard._canonical_json_size, digest_guard.ERROR_DIGEST_SCAN_LIMIT),
    (mcp_guard._canonical_json_size, mcp_guard.ERROR_MCP_CONFIG_LIMIT),
    (
        surface_inventory_mcp._canonical_json_size,
        surface_inventory_mcp.ERROR_MCP_CONFIG_LIMIT,
    ),
)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_mcp_config_rejects_nonfinite_json_constants(
    tmp_path: Path,
    constant: str,
) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(
        '{"mcpServers":{"server":{"weight":' + constant + '}}}\n',
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match=f"^{surface_inventory_mcp.ERROR_MCP_CONFIG_INVALID}$",
    ) as exc_info:
        surface_inventory_mcp.load_structured_config(config, root=tmp_path)

    assert constant not in str(exc_info.value)
    assert str(tmp_path) not in str(exc_info.value)


@pytest.mark.parametrize("constant", ["nan", "inf", "-inf"])
def test_mcp_toml_config_rejects_nonfinite_numbers(
    tmp_path: Path,
    constant: str,
) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        f"[mcp_servers.server]\nweight = {constant}\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match=f"^{surface_inventory_mcp.ERROR_MCP_CONFIG_INVALID}$",
    ) as exc_info:
        surface_inventory_mcp.load_structured_config(config, root=tmp_path)

    assert constant not in str(exc_info.value)
    assert str(tmp_path) not in str(exc_info.value)


def test_mcp_json_config_rejects_float_overflow(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(
        '{"mcpServers":{"server":{"weight":1e400}}}\n',
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match=f"^{surface_inventory_mcp.ERROR_MCP_CONFIG_INVALID}$",
    ):
        surface_inventory_mcp.load_structured_config(config, root=tmp_path)


@pytest.mark.parametrize(
    ("serializer", "error"),
    PUBLIC_BUDGET_SERIALIZERS,
    ids=["context", "digest", "mcp", "mcp-surface"],
)
@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf")],
    ids=["nan", "infinity", "negative-infinity"],
)
def test_public_budget_serializers_reject_nonfinite_numbers_with_fixed_errors(
    serializer: Callable[[object], int],
    error: str,
    value: float,
) -> None:
    with pytest.raises(ValueError, match=f"^{error}$") as exc_info:
        serializer({"metric": value})

    assert repr(value) not in str(exc_info.value)


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf")],
    ids=["nan", "infinity", "negative-infinity"],
)
def test_surface_fingerprint_rejects_nonfinite_numbers_with_fixed_error(
    value: float,
) -> None:
    with pytest.raises(
        surface_delta.SurfaceDeltaError,
        match=f"^{surface_delta.ERROR_SURFACE_DELTA_INVALID}$",
    ) as exc_info:
        surface_delta.surface_match_fingerprint(
            {"surface": "mcp_config", "metric": value}
        )

    assert repr(value) not in str(exc_info.value)


def test_budget_and_fingerprint_serializers_preserve_finite_numbers() -> None:
    for serializer, _error in PUBLIC_BUDGET_SERIALIZERS:
        assert serializer({"metric": 1.5}) > 0
    assert surface_delta.canonical_surface({"metric": 1.5}) == '{"metric":1.5}'


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf")],
    ids=["nan", "infinity", "negative-infinity"],
)
def test_public_json_renderers_reject_nonfinite_numbers(
    monkeypatch: pytest.MonkeyPatch,
    value: float,
) -> None:
    with pytest.raises(ValueError):
        report_render.render_report_output({"metric": value}, "json")
    with pytest.raises(ValueError):
        surface_inventory_context.public_safe_surface_text({"metric": value})

    def append_nonfinite_result(*, results: list[dict[str, object]], **_kwargs: object) -> None:
        results.append({"metric": value})

    monkeypatch.setattr(report_sarif, "append_sarif_result", append_nonfinite_result)
    with pytest.raises(ValueError):
        report_sarif.render_sarif_report({"status": "error"})


def test_public_json_renderers_preserve_finite_numbers() -> None:
    payload = {"metric": 1.5}

    assert json.loads(report_render.render_report_output(payload, "json")) == payload
    assert json.loads(surface_inventory_context.public_safe_surface_text(payload)) == payload
