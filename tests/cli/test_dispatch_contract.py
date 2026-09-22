"""Pin the pre-refactor CLI route-to-runner contract with independent cases.

The real parser supplies namespaces, but every runner is stubbed: these checks
complement the existing scanner/subprocess tests without scanning or writing.
"""

from __future__ import annotations

import argparse
import sys
from unittest.mock import Mock

import pytest

import agent_guard.cli as cli


# Deliberately literal: neither the registry nor main's dispatch builds this map.
# Each row contains the runner, required/representative options, and parsed values.
DISPATCH_CASES = {
    "init": (
        "run_init",
        ("--root", "worktree", "--write", "--skip-existing", "--json"),
        {"root": "worktree", "write": True, "skip_existing": True, "json": True},
    ),
    "api check": (
        "run_api_check",
        ("--policy", "api.yaml", "--json"),
        {"root": ".", "policy": "api.yaml", "json": True},
    ),
    "content check": (
        "run_content_check",
        (
            "--repo-root", "worktree", "--policy", "content.yaml",
            "--mode", "preregister", "--targets", "src/a.py", "src/b.py", "--json",
        ),
        {
            "repo_root": "worktree", "policy": "content.yaml", "mode": "preregister",
            "targets": ["src/a.py", "src/b.py"], "json": True,
        },
    ),
    "context check": (
        "run_context_check",
        ("--policy", "context.yaml", "--json"),
        {"root": ".", "policy": "context.yaml", "json": True},
    ),
    "context inventory": (
        "run_context_inventory",
        ("--root", "worktree", "--policy", "context.yaml"),
        {"root": "worktree", "policy": "context.yaml", "json": False},
    ),
    "context lock": (
        "run_context_lock",
        ("--policy", "context.yaml", "--check", "--digest-policy", "digest.yaml", "--json"),
        {"policy": "context.yaml", "check": True, "digest_policy": "digest.yaml", "json": True},
    ),
    "path check": (
        "run_path_check",
        ("--root", "worktree", "--policy", "path.yaml"),
        {"root": "worktree", "policy": "path.yaml", "json": False},
    ),
    "digest check": (
        "run_digest_check",
        ("--policy", "digest.yaml", "--json"),
        {"root": ".", "policy": "digest.yaml", "json": True},
    ),
    "workflow check": (
        "run_workflow_check",
        ("--policy", "workflow.yaml", "--json"),
        {"root": ".", "policy": "workflow.yaml", "json": True},
    ),
    "surface inventory": (
        "run_surface_inventory",
        ("--context-policy", "context.yaml", "--schema-version", "v2", "--json"),
        {"context_policy": "context.yaml", "schema_version": "v2", "json": True},
    ),
    "surface delta": (
        "run_surface_delta",
        ("--context-policy", "context.yaml", "--base-ref", "review-base", "--json"),
        {"context_policy": "context.yaml", "base_ref": "review-base", "schema_version": "v1", "json": True},
    ),
    "mcp check": (
        "run_mcp_check",
        ("--root", "worktree", "--policy", "mcp.yaml", "--json"),
        {"root": "worktree", "policy": "mcp.yaml", "json": True},
    ),
    "drift check": (
        "run_drift_check",
        ("--schema-version", "v2", "--base-ref", "review-base", "--json"),
        {"profile": "recommended", "schema_version": "v2", "base_ref": "review-base", "json": True},
    ),
    "conformance check": (
        "run_conformance_check",
        ("--evidence", "report.json", "--json"),
        {"evidence": "report.json", "profile": "recommended", "json": True},
    ),
    "evidence-pack manifest": (
        "run_evidence_pack_manifest",
        ("--report", "report.json", "--artifact", "report.md", "--artifact", "results.sarif", "--json"),
        {"report": "report.json", "artifact": ["report.md", "results.sarif"], "json": True},
    ),
    "report": (
        "run_report",
        ("--evidence-preset", "recommended", "--format", "sarif", "--output", "report.sarif", "--stderr-summary"),
        {"evidence_preset": "recommended", "format": "sarif", "output": "report.sarif", "stderr_summary": True},
    ),
    "render-report": (
        "run_report_render",
        ("--input", "report.json", "--format", "github-annotations", "--output", "annotations.txt"),
        {"input": "report.json", "format": "github-annotations", "output": "annotations.txt"},
    ),
}


@pytest.mark.parametrize("route", DISPATCH_CASES)
@pytest.mark.parametrize("runner_exit_code", (0, 1, 2))
def test_cli_dispatches_each_leaf_and_propagates_runner_exit_code(
    monkeypatch: pytest.MonkeyPatch, route: str, runner_exit_code: int
) -> None:
    expected_runner, options, expected_values = DISPATCH_CASES[route]
    runners = {
        name: Mock(name=name, return_value=runner_exit_code)
        for name, _, _ in DISPATCH_CASES.values()
    }
    # The shim copies exports; patching cli.run_* would miss main's globals.
    for name, runner in runners.items():
        monkeypatch.setitem(cli.main.__globals__, name, runner)
    monkeypatch.setattr(sys, "argv", ["agent-guard", *route.split(), *options])

    assert cli.main() == runner_exit_code

    selected = runners[expected_runner]
    selected.assert_called_once()
    namespace = selected.call_args.args[0]
    selected.assert_called_once_with(namespace)
    for name, runner in runners.items():
        if name != expected_runner:
            runner.assert_not_called()
    assert isinstance(namespace, argparse.Namespace)
    scanner, _, command = route.partition(" ")
    assert namespace.scanner == scanner
    if command:
        assert namespace.command == command
    else:
        assert not hasattr(namespace, "command")
    assert {name: getattr(namespace, name) for name in expected_values} == expected_values
