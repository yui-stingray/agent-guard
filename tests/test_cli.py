"""Where: tests/test_cli.py
What: subprocess tests for the agent-guard CLI.
Why: pin the shared exit-code and JSON envelope contract for wrappers and CI.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml

from agent_guard import __version__ as AGENT_GUARD_VERSION
from agent_guard.cli import build_parser, safe_policy_path
from agent_guard.cli_registry import AGENT_GUARD_COMMANDS
from agent_guard.init_guard import (
    GITHUB_EVENT_BASE_SHA_EXPRESSION,
    PUBLISHED_CONTEXT_POLICY_PREFLIGHT,
    PUBLISHED_PACKAGE_VERSION,
)

from tests.cli.helpers import assert_shared_envelope, run_cli, run_cli_from, write


INIT_FILE_PATHS = [
    ".agent-guard/context-policy.yaml",
    ".agent-guard/path-policy.yaml",
    ".agent-guard/content-policy.yaml",
    ".agent-guard/mcp-policy.yaml",
    ".agent-guard/workflow-policy.yaml",
    ".github/workflows/agent-guard.yml",
]


def test_agent_guard_version_does_not_require_subcommand() -> None:
    result = run_cli("--version")

    assert result.returncode == 0
    assert result.stdout == f"agent-guard {AGENT_GUARD_VERSION}\n"
    assert result.stderr == ""


def test_cli_module_entrypoint_does_not_execute_when_imported_as_spawn_main() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import runpy; "
                "runpy.run_module('agent_guard.cli', run_name='__mp_main__')"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_agent_guard_command_registry_matches_parser() -> None:
    parser = build_parser()
    top_action = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    actual: dict[str, tuple[str, ...]] = {}
    for scanner, scanner_parser in top_action.choices.items():
        sub_actions = [
            action for action in scanner_parser._actions if isinstance(action, argparse._SubParsersAction)
        ]
        actual[scanner] = tuple(sorted(sub_actions[0].choices)) if sub_actions else ("",)

    expected = {scanner: tuple(sorted(commands)) for scanner, commands in AGENT_GUARD_COMMANDS.items()}
    assert actual == expected


def test_init_cli_json_is_review_first_and_does_not_write(tmp_path: Path) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "agent-guard.init_plan.v1"
    assert payload["mode"] == "print"
    files = payload["files"]
    assert [item["path"] for item in files] == INIT_FILE_PATHS
    assert all(item["status"] == "create" for item in files)
    contents = {item["path"]: item["content"] for item in files}
    workflow = contents[".github/workflows/agent-guard.yml"]
    mcp_policy = contents[".agent-guard/mcp-policy.yaml"]
    workflow_policy = contents[".agent-guard/workflow-policy.yaml"]
    assert "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7" in workflow
    assert "fetch-depth: 0" in workflow
    assert "persist-credentials: false" in workflow
    assert "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6" in workflow
    assert AGENT_GUARD_VERSION == "0.3.10.dev0"
    assert PUBLISHED_PACKAGE_VERSION == "0.3.9"
    assert AGENT_GUARD_VERSION != PUBLISHED_PACKAGE_VERSION
    assert (
        f"python -I -m pip install yui-agent-guard=={PUBLISHED_PACKAGE_VERSION}"
        in workflow
    )
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1" in workflow
    assert "- id: generate-evidence" in workflow
    assert "if: always() && steps.generate-evidence.outputs.ready == 'true'" in workflow
    assert ".agent-guard/evidence/" not in workflow
    upload_paths = [
        "${{ steps.generate-evidence.outputs.evidence-dir }}/agent-guard-report.json",
        "${{ steps.generate-evidence.outputs.evidence-dir }}/agent-guard-report.md",
        "${{ steps.generate-evidence.outputs.evidence-dir }}/agent-guard-results.sarif",
        "${{ steps.generate-evidence.outputs.evidence-dir }}/agent-guard-conformance.json",
        "${{ steps.generate-evidence.outputs.evidence-dir }}/agent-guard-evidence-pack.json",
        "${{ steps.generate-evidence.outputs.evidence-dir }}/agent-surface-inventory.json",
    ]
    workflow_payload = yaml.safe_load(workflow)
    workflow_steps = workflow_payload["jobs"]["evidence"]["steps"]
    checkout_step = workflow_steps[0]
    assert checkout_step["with"] == {"fetch-depth": 0, "persist-credentials": False}
    preflight_step = next(
        step
        for step in workflow_steps
        if step.get("name") == "Reject unreviewed context policy changes"
    )
    assert preflight_step["if"] == "github.event_name == 'pull_request'"
    assert preflight_step["env"] == {
        "AGENT_GUARD_PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "AGENT_GUARD_ROOT": ".",
        "AGENT_GUARD_CONTEXT_POLICY": ".agent-guard/context-policy.yaml",
    }
    assert preflight_step["run"].rstrip() == PUBLISHED_CONTEXT_POLICY_PREFLIGHT
    assert "git cat-file -e" in preflight_step["run"]
    assert "git diff --quiet" in preflight_step["run"]
    assert "git diff --exit-code" not in preflight_step["run"]
    evidence_step = next(step for step in workflow_steps if step.get("id") == "generate-evidence")
    assert evidence_step["timeout-minutes"] == 1
    upload_step = next(
        step
        for step in workflow_steps
        if isinstance(step, dict) and step.get("name") == "Upload evidence"
    )
    assert upload_step["if"] == "always() && steps.generate-evidence.outputs.ready == 'true'"
    assert upload_step["with"]["path"].splitlines() == upload_paths
    policy_verification_steps = [
        step
        for step in workflow_steps
        if str(step.get("name", "")).startswith("Verify workflow policy ")
    ]
    assert len(policy_verification_steps) == 10
    assert all(step.get("if") == "always()" for step in policy_verification_steps)
    assert all(len(step["run"].splitlines()) == 1 for step in policy_verification_steps)
    assert "schema_version: agent-guard.mcp_policy.v1" in mcp_policy
    assert "forbidden_risky_patterns:" in mcp_policy
    assert "agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json" in workflow
    assert (
        "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml "
        "--schema-version v2 --json"
        in workflow
    )
    assert "agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json" in workflow
    assert "agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json" in workflow
    assert (
        'agent-guard drift check --root . --profile recommended --schema-version v2 '
        f'--base-ref "{GITHUB_EVENT_BASE_SHA_EXPRESSION}" --json'
        in workflow
    )
    assert (
        "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml "
        '--evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml '
        f'--drift-base-ref "{GITHUB_EVENT_BASE_SHA_EXPRESSION}" '
        '--format json --output "$report_json" > /dev/null 2>&1'
        in workflow
    )
    report_lines = [
        line.strip()
        for line in workflow.splitlines()
        if line.strip().startswith("( agent-guard report")
    ]
    assert report_lines == [
        "( agent-guard report --root . --context-policy .agent-guard/context-policy.yaml "
        '--evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml '
        f'--drift-base-ref "{GITHUB_EVENT_BASE_SHA_EXPRESSION}" '
        '--format json --output "$report_json" > /dev/null 2>&1 )'
    ]
    assert "AGENT_GUARD_EVENT_NAME: ${{ github.event_name }}" in workflow
    assert GITHUB_EVENT_BASE_SHA_EXPRESSION in workflow
    assert "Reject unreviewed context policy changes" in workflow
    assert (
        "context policy preflight rejected a pull-request change; review and merge it separately "
        "before rerunning evidence from a trusted revision"
        in workflow
    )
    assert "published agent-guard 0.3.4 cannot evaluate a context policy changed by a pull request" not in workflow
    assert "timeout-minutes: 1" in workflow
    assert 'base_sha=HEAD' not in workflow
    assert 'baseline_label="push before"' in workflow
    assert 'use_base_ref=' not in workflow
    assert 'drift_base_args=' not in workflow
    assert 'report_base_args=' not in workflow
    assert 'baseline_label="pull request base"' in workflow
    assert 'echo "::error::${baseline_label} SHA is unavailable"' in workflow
    assert "render_report_output" not in workflow
    assert "record_status() {" in workflow
    assert (
        'if [ "$code" -ge 2 ] || { [ "$code" -ne 0 ] && [ "$status" -eq 0 ]; }; then'
        in workflow
    )
    assert 'record_status "$?"' in workflow
    assert "code=$?" not in workflow
    assert (
        'agent-guard render-report --root . --input "$report_json" '
        '--format markdown --output "$report_markdown" > /dev/null 2>&1'
        in workflow
    )
    assert (
        'agent-guard render-report --root . --input "$report_json" '
        '--format sarif --output "$report_sarif" > /dev/null 2>&1'
        in workflow
    )
    assert (
        'agent-guard render-report --root . --input "$report_json" '
        '--format github-annotations 2>/dev/null > "$raw_dir/annotations.txt"'
        in workflow
    )
    raw_scanner_lines = [
        line.strip()
        for line in workflow.splitlines()
        if line.strip().lstrip("( ").startswith("agent-guard ")
        and "--json" in line
        and any(
            command in line
            for command in (
                "context check",
                "path check",
                "content check",
                "mcp check",
                "workflow check",
                "drift check",
            )
        )
    ]
    assert len(raw_scanner_lines) == 6
    assert all('2>/dev/null > "$raw_dir/' in line for line in raw_scanner_lines)
    assert (
        "if ! raw_dir=\"$(mktemp -d \"$raw_parent/agent-guard-raw.XXXXXX\" 2>/dev/null)\"; then"
        not in workflow
    )
    assert (
        "if ! raw_dir=\"$(mktemp -d \"$runner_temp/agent-guard-raw.XXXXXX\" 2>/dev/null)\"; then"
        in workflow
    )
    assert (
        "if ! evidence_dir=\"$(mktemp -d \"$runner_temp/agent-guard-evidence.XXXXXX\" 2>/dev/null)\"; then"
        in workflow
    )
    assert 'report_json="${evidence_dir%/}/agent-guard-report.json"' in workflow
    assert 'surface_inventory_json="${evidence_dir%/}/agent-surface-inventory.json"' in workflow
    assert "validate_raw_result() {" in workflow
    assert 'if [ ! -f "$output_path" ] || [ -L "$output_path" ]; then' in workflow
    assert workflow.count('validate_raw_result "$?" "$raw_dir/') == 7
    assert (
        'agent-guard conformance check --root . --evidence "$report_json" '
        '--profile recommended --json 2>/dev/null > "$conformance_json"'
        in workflow
    )
    assert (
        'agent-guard evidence-pack manifest --root . --report "$report_json" '
        '--artifact "$report_json" --json 2>/dev/null > "$evidence_pack_json"'
        in workflow
    )
    assert 'validate_raw_result "$?" "$surface_inventory_json"' in workflow
    assert 'validate_raw_result "$?" "$conformance_json"' in workflow
    assert 'validate_raw_result "$?" "$evidence_pack_json"' in workflow
    assert "validate_public_evidence() (" in workflow
    assert "public_artifact_names=(" in workflow
    assert "if [ \"$status\" -ge 2 ]; then" in workflow
    assert "::error::evidence generation failed" in workflow
    assert "::error::evidence validation failed" in workflow
    assert "::error::evidence output setup failed" in workflow
    assert (
        'if ! python -I -m agent_guard.consumer --evidence-dir "$evidence_dir" '
        '--emit-annotations "$report_json" 2>/dev/null; then'
        in workflow
    )
    assert 'cat "$annotations_path"' not in workflow
    assert workflow.index('--format github-annotations 2>/dev/null > "$raw_dir/annotations.txt"') < workflow.index(
        "agent_guard.consumer"
    )
    assert workflow.index("agent_guard.consumer") < workflow.index('rm -f "$annotations_path"')
    assert workflow.index("validate_public_evidence() (") < workflow.index("printf 'ready=true\\n'")
    assert workflow.index("agent_guard.consumer") < workflow.index("printf 'ready=true\\n'")
    assert workflow.index("printf 'evidence-dir=%s\\n'") < workflow.index("printf 'ready=true\\n'")
    assert workflow.index("evidence_ready=true") < workflow.index("printf 'ready=true\\n'")
    assert "if ! write_evidence_dir_output 2>/dev/null; then" in workflow
    assert "if ! write_ready_output 2>/dev/null; then" in workflow
    assert "workflow_checks:" in workflow_policy
    assert "path: .agent-guard/mcp-policy.yaml" in workflow_policy
    assert "command: agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml" in workflow_policy
    assert (
        'command: agent-guard drift check --root . --profile recommended '
        f'--schema-version v2 --base-ref "{GITHUB_EVENT_BASE_SHA_EXPRESSION}"'
        in workflow_policy
    )
    assert (
        "command: agent-guard conformance check --root . "
        "--evidence /tmp/agent-guard-policy-report.json "
        "--profile recommended"
        in workflow_policy
    )
    assert (
        "command: agent-guard evidence-pack manifest --root . "
        "--report /tmp/agent-guard-policy-report.json"
        in workflow_policy
    )
    assert (
        "command: agent-guard report --root . "
        "--context-policy .agent-guard/context-policy.yaml "
        "--evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml "
        f'--drift-base-ref "{GITHUB_EVENT_BASE_SHA_EXPRESSION}" '
        "--format json --output /tmp/agent-guard-policy-report.json"
        in workflow_policy
    )
    next_steps = "\n".join(payload["next_steps"])
    assert (
        "From the repository root, run `agent-guard init --root . --write` only after "
        "the printed plan is acceptable."
        in next_steps
    )
    assert "--stderr-summary" not in next_steps
    assert "raw per-scanner JSON as local or CI-internal" in next_steps
    assert "publish only the sanitized report, render-report, or evidence-pack outputs" in next_steps
    assert "runtime MCP validation, live OAuth validation, or MCP tool-poisoning detection" in next_steps
    assert not (tmp_path / ".agent-guard").exists()
    serialized = json.dumps(payload, sort_keys=True)
    assert str(tmp_path) not in serialized


def test_init_cli_written_workflow_policy_checks_generated_workflow(tmp_path: Path) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--write", "--json")
    assert result.returncode == 0

    result = run_cli(
        "workflow",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / ".agent-guard" / "workflow-policy.yaml"),
        "--json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="workflow",
        status="ok",
        exit_code=0,
        finding_count=0,
        scanned_unit="checks",
    )


def test_init_cli_write_next_steps_include_report_and_conformance_review(tmp_path: Path) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--write", "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    next_steps = "\n".join(payload["next_steps"])
    assert payload["mode"] == "write"
    assert "agent-guard init --root . --write` only after" not in next_steps
    assert (
        "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml "
        "--evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --stderr-summary "
        "--format json --output .agent-guard/evidence/agent-guard-report.json"
        in next_steps
    )
    assert (
        "agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json "
        "--profile recommended --json"
        in next_steps
    )
    assert "Treat exit code 1 as policy findings that require review" in next_steps
    assert "treat exit code >=2 as an execution/configuration error" in next_steps
    assert "review" in next_steps.lower()


def test_init_cli_skip_existing_all_existing_preserves_files(tmp_path: Path) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--write", "--json")
    assert result.returncode == 0
    before = {
        rel_path: (tmp_path / rel_path).read_bytes()
        for rel_path in INIT_FILE_PATHS
    }

    result = run_cli("init", "--root", str(tmp_path), "--write", "--skip-existing", "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "agent-guard.init_plan.v1"
    assert payload["mode"] == "write"
    assert payload["status"] == "ok"
    assert payload["bundle_state"] == "mixed_unverified"
    assert payload["file_count"] == len(INIT_FILE_PATHS)
    assert payload["written_count"] == 0
    assert payload["skipped_count"] == len(INIT_FILE_PATHS)
    assert [item["path"] for item in payload["files"]] == INIT_FILE_PATHS
    assert all(item["status"] == "skipped_existing" for item in payload["files"])
    assert all("content" not in item for item in payload["files"])
    assert {
        rel_path: (tmp_path / rel_path).read_bytes()
        for rel_path in INIT_FILE_PATHS
    } == before
    next_steps = "\n".join(payload["next_steps"])
    assert "Review every written and preserved starter file" in next_steps
    assert "before treating the bundle as ready" in next_steps
    assert "mixed_unverified" in json.dumps(payload, sort_keys=True)

    text_result = run_cli("init", "--root", str(tmp_path), "--write", "--skip-existing")
    assert text_result.returncode == 0
    assert "Bundle state: mixed_unverified" in text_result.stdout
    assert f"Skipped existing: {len(INIT_FILE_PATHS)}" in text_result.stdout
    assert str(tmp_path) not in text_result.stdout


def test_init_cli_skip_existing_partial_writes_only_missing_files(tmp_path: Path) -> None:
    preserved = b"custom context bytes\n"
    target = tmp_path / ".agent-guard" / "context-policy.yaml"
    target.parent.mkdir(parents=True)
    target.write_bytes(preserved)
    target.chmod(0o444)

    try:
        result = run_cli("init", "--root", str(tmp_path), "--write", "--skip-existing", "--json")
    finally:
        target.chmod(0o644)

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    statuses = {item["path"]: item["status"] for item in payload["files"]}
    assert statuses[".agent-guard/context-policy.yaml"] == "skipped_existing"
    assert all(statuses[rel_path] == "written" for rel_path in INIT_FILE_PATHS[1:])
    assert payload["file_count"] == len(INIT_FILE_PATHS)
    assert payload["written_count"] == len(INIT_FILE_PATHS) - 1
    assert payload["skipped_count"] == 1
    assert payload["bundle_state"] == "mixed_unverified"
    assert target.read_bytes() == preserved
    assert all((tmp_path / rel_path).exists() for rel_path in INIT_FILE_PATHS)
    serialized = json.dumps(payload, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "custom context bytes" not in serialized


def test_init_cli_skip_existing_rejects_invalid_modes_without_mutation(tmp_path: Path) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--skip-existing", "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "agent-guard.init_plan.v1"
    assert payload["status"] == "error"
    assert payload["error"] == "init --skip-existing requires --write"
    assert not (tmp_path / ".agent-guard").exists()

    result = run_cli("init", "--root", str(tmp_path), "--write", "--skip-existing", "--force", "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert payload["error"] == "init --skip-existing cannot be combined with --force"
    assert not (tmp_path / ".agent-guard").exists()


def test_init_cli_workflow_policy_detects_removed_drift_gate(tmp_path: Path) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--write", "--json")
    assert result.returncode == 0

    workflow = tmp_path / ".github" / "workflows" / "agent-guard.yml"
    original = workflow.read_text(encoding="utf-8")
    drift_command = (
        '        run: agent-guard drift check --root . --profile recommended '
        f'--schema-version v2 --base-ref "{GITHUB_EVENT_BASE_SHA_EXPRESSION}" '
        '--json > /dev/null\n'
    )
    assert drift_command in original
    workflow.write_text(original.replace(drift_command, ""), encoding="utf-8")

    result = run_cli(
        "workflow",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / ".agent-guard" / "workflow-policy.yaml"),
        "--json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="workflow",
        status="violation",
        exit_code=1,
        finding_count=1,
        scanned_unit="checks",
    )
    assert payload["findings"][0]["requirement_id"] == "drift_guard"


def test_init_cli_workflow_policy_rejects_weakened_event_base_refs(
    tmp_path: Path,
) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--write", "--json")
    assert result.returncode == 0

    workflow = tmp_path / ".github" / "workflows" / "agent-guard.yml"
    original = workflow.read_text(encoding="utf-8")
    weakened = original.replace(f'"{GITHUB_EVENT_BASE_SHA_EXPRESSION}"', "HEAD")
    assert weakened != original
    workflow.write_text(weakened, encoding="utf-8")

    result = run_cli(
        "workflow",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / ".agent-guard" / "workflow-policy.yaml"),
        "--json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert {
        finding["requirement_id"] for finding in payload["findings"]
    } == {"drift_guard", "evidence_report_with_drift"}


def test_init_cli_workflow_policy_rejects_reassigned_dynamic_event_base(
    tmp_path: Path,
) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--write", "--json")
    assert result.returncode == 0

    workflow = tmp_path / ".github" / "workflows" / "agent-guard.yml"
    original = workflow.read_text(encoding="utf-8")
    weakened = original.replace(
        f'"{GITHUB_EVENT_BASE_SHA_EXPRESSION}"',
        '"$base_sha"',
    ).replace('base_sha="$base_sha"', "base_sha=HEAD")
    assert weakened != original
    workflow.write_text(weakened, encoding="utf-8")

    result = run_cli(
        "workflow",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / ".agent-guard" / "workflow-policy.yaml"),
        "--json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert {
        finding["requirement_id"] for finding in payload["findings"]
    } == {"drift_guard", "evidence_report_with_drift"}


def test_init_cli_workflow_policy_rejects_split_weakened_event_arms(
    tmp_path: Path,
) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--write", "--json")
    assert result.returncode == 0

    workflow = tmp_path / ".github" / "workflows" / "agent-guard.yml"
    original = workflow.read_text(encoding="utf-8")
    drift_command = (
        '        run: agent-guard drift check --root . --profile recommended '
        f'--schema-version v2 --base-ref "{GITHUB_EVENT_BASE_SHA_EXPRESSION}" '
        '--json > /dev/null\n'
    )
    report_command = (
        "        run: agent-guard report --root . --context-policy "
        ".agent-guard/context-policy.yaml --evidence-preset recommended "
        "--mcp-policy .agent-guard/mcp-policy.yaml "
        f'--drift-base-ref "{GITHUB_EVENT_BASE_SHA_EXPRESSION}" '
        "--format json --output /tmp/agent-guard-policy-report.json > /dev/null\n"
    )
    assert drift_command in original and report_command in original
    drift_body = drift_command.removeprefix("        run: ").rstrip("\n")
    report_body = report_command.removeprefix("        run: ").rstrip("\n")
    weakened_drift = drift_body.replace(
        f' --base-ref "{GITHUB_EVENT_BASE_SHA_EXPRESSION}"',
        " --base-ref HEAD",
    )
    weakened_report = report_body.replace(
        f' --drift-base-ref "{GITHUB_EVENT_BASE_SHA_EXPRESSION}"',
        " --drift-base-ref HEAD",
    )
    split_drift = (
        "        run: |\n"
        '          if [ "$AGENT_GUARD_EVENT_NAME" = pull_request ]; then\n'
        f"            {weakened_drift}\n"
        "          else\n"
        f"            {drift_body}\n"
        "          fi\n"
    )
    split_report = (
        "        run: |\n"
        '          if [ "$AGENT_GUARD_EVENT_NAME" = pull_request ]; then\n'
        f"            {weakened_report}\n"
        "          else\n"
        f"            {report_body}\n"
        "          fi\n"
    )
    workflow.write_text(
        original.replace(drift_command, split_drift).replace(
            report_command,
            split_report,
        ),
        encoding="utf-8",
    )

    result = run_cli(
        "workflow",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / ".agent-guard" / "workflow-policy.yaml"),
        "--json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert {
        finding["requirement_id"] for finding in payload["findings"]
    } == {"drift_guard", "evidence_report_with_drift"}


def test_init_cli_workflow_policy_detects_report_without_recommended_preset(tmp_path: Path) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--write", "--json")
    assert result.returncode == 0

    workflow = tmp_path / ".github" / "workflows" / "agent-guard.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(" --evidence-preset recommended", ""),
        encoding="utf-8",
    )

    result = run_cli(
        "workflow",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / ".agent-guard" / "workflow-policy.yaml"),
        "--json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="workflow",
        status="violation",
        exit_code=1,
        finding_count=1,
        scanned_unit="checks",
    )
    assert payload["findings"][0]["requirement_id"] == "evidence_report_with_drift"


def test_init_cli_write_refuses_existing_files(tmp_path: Path) -> None:
    write(tmp_path / ".agent-guard" / "context-policy.yaml", "existing\n")

    result = run_cli("init", "--root", str(tmp_path), "--write", "--json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["mode"] == "write"
    assert payload["status"] == "blocked"
    statuses = {item["path"]: item["status"] for item in payload["files"]}
    assert statuses[".agent-guard/context-policy.yaml"] == "exists"
    next_steps = "\n".join(payload["next_steps"])
    assert "agent-guard init --root . --write` only after" not in next_steps
    assert "Review the existing starter files in the repository" in next_steps
    assert "agent-guard init --root . --write --skip-existing" in next_steps
    assert "agent-guard init --root . --write --force" in next_steps
    assert "intentionally reviewing" in next_steps
    serialized = json.dumps(payload, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "existing\n" not in serialized
    assert (tmp_path / ".agent-guard" / "context-policy.yaml").read_text(encoding="utf-8") == "existing\n"


def test_init_cli_write_skip_existing_is_public_path_and_content_hygienic(tmp_path: Path) -> None:
    write(tmp_path / ".agent-guard" / "context-policy.yaml", "private local override\n")

    result = run_cli("init", "--root", str(tmp_path), "--write", "--skip-existing", "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    serialized = json.dumps(payload, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "private local override" not in serialized
    assert all(set(item) == {"path", "status"} for item in payload["files"])


def test_init_cli_rejects_print_and_write_together(tmp_path: Path) -> None:
    result = run_cli("init", "--root", str(tmp_path), "--print", "--write", "--json")

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "agent-guard.init_plan.v1"
    assert payload["status"] == "error"
    assert payload["error"] == "init --print cannot be combined with --write"
    assert not (tmp_path / ".agent-guard").exists()


def test_direct_cli_text_errors_scrub_policy_paths_from_external_cwd(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    cwd = tmp_path / "cwd"
    repo.mkdir()
    cwd.mkdir()
    missing_policy = ".agent-guard/missing-policy.yaml"
    commands = [
        ("api", "check", "--root", str(repo), "--policy", missing_policy),
        (
            "content",
            "check",
            "--repo-root",
            str(repo),
            "--policy",
            missing_policy,
            "--mode",
            "registered",
            "--scan-dir",
            ".",
        ),
        ("context", "check", "--root", str(repo), "--policy", missing_policy),
        ("path", "check", "--root", str(repo), "--policy", missing_policy),
        ("digest", "check", "--root", str(repo), "--policy", missing_policy),
        ("workflow", "check", "--root", str(repo), "--policy", missing_policy),
    ]

    for command in commands:
        result = run_cli_from(cwd, *command)
        combined = result.stdout + result.stderr

        assert result.returncode == 2, command
        assert "ERROR:" in combined
        assert str(tmp_path) not in combined
        assert missing_policy in combined


def test_safe_policy_path_treats_url_like_policy_as_external(tmp_path: Path) -> None:
    url_policy = "https://policy.example.invalid/reviewed/policy.yaml"

    assert safe_policy_path(url_policy, tmp_path) == "<external-policy>"
