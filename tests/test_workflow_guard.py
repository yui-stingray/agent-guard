"""Where: tests/test_workflow_guard.py
What: unit tests for workflow drift guard parsing and matching.
Why: keep workflow evidence deterministic without shell execution or raw log output.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from agent_guard import workflow_guard
from agent_guard.workflow_guard import (
    command_line_matches_required,
    iter_active_shell_lines,
    iter_command_segments,
    scan_workflow_policy,
)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def scan_required_context_command(
    root: Path, workflow: dict[str, object]
) -> tuple[list[workflow_guard.WorkflowGuardFinding], int]:
    write(
        root / ".github" / "workflows" / "ci.yml",
        yaml.safe_dump(workflow, sort_keys=False),
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": [
                    {
                        "id": "context_guard",
                        "command": "python -m agent_guard.cli context check",
                    },
                ],
            }
        ],
    }
    return scan_workflow_policy(root=root, policy=policy)


class SliceTrackingCommand(str):
    slice_count: int

    def __new__(cls, value: str) -> SliceTrackingCommand:
        instance = super().__new__(cls, value)
        instance.slice_count = 0
        return instance

    def __getitem__(self, key: int | slice) -> str:
        if isinstance(key, slice):
            self.slice_count += 1
        return super().__getitem__(key)


def test_iter_active_shell_lines_joins_shell_continuations() -> None:
    run_text = (
        "python -m agent_guard.cli report \\\n"
        "  --root . \\\n"
        "  --context-policy .agent-guard/context-policy.yaml \\\n"
        "  --format json\n"
    )

    assert iter_active_shell_lines(run_text) == [
        "python -m agent_guard.cli report --root . "
        "--context-policy .agent-guard/context-policy.yaml --format json"
    ]


def test_iter_active_shell_lines_ignores_quoted_and_escaped_heredoc_lookalikes() -> None:
    required = "python -m agent_guard.cli context check"
    run_text = (
        'echo "<<WORKFLOW_END"\n'
        r"echo \<<WORKFLOW_END" "\n"
        "echo safe # <<WORKFLOW_END\n"
        f"{required} --root . --json\n"
    )

    assert iter_active_shell_lines(run_text) == [
        'echo "<<WORKFLOW_END"',
        r"echo \<<WORKFLOW_END",
        "echo safe # <<WORKFLOW_END",
        f"{required} --root . --json",
    ]


def test_iter_active_shell_lines_uses_exact_quoted_hyphenated_heredoc_delimiter() -> None:
    required = "python -m agent_guard.cli context check"
    run_text = (
        "python - <<'END-OF'\n"
        f"{required} --root . --json\n"
        "END\n"
        f"{required} --still-heredoc\n"
        "END-OF\n"
        f"{required} --root . --json\n"
    )

    assert iter_active_shell_lines(run_text) == [
        "python - <<'END-OF'",
        f"{required} --root . --json",
    ]


def test_iter_active_shell_lines_does_not_strip_spaces_from_heredoc_terminator() -> None:
    required = "python -m agent_guard.cli context check"
    run_text = (
        "python - <<END\n"
        " END\n"
        f"{required} --still-heredoc\n"
        "END\n"
        f"{required} --root . --json\n"
    )

    assert iter_active_shell_lines(run_text) == [
        "python - <<END",
        f"{required} --root . --json",
    ]


def test_iter_active_shell_lines_allows_tabs_only_for_dash_heredoc_terminator() -> None:
    required = "python -m agent_guard.cli context check"
    run_text = (
        "python - <<-END\n"
        " END\n"
        f"{required} --still-heredoc\n"
        "\tEND\n"
        f"{required} --root . --json\n"
    )

    assert iter_active_shell_lines(run_text) == [
        "python - <<-END",
        f"{required} --root . --json",
    ]


def test_iter_active_shell_lines_supports_multiple_heredocs_in_declaration_order() -> None:
    required = "python -m agent_guard.cli context check"
    run_text = (
        "cat <<FIRST <<'SECOND-END'\n"
        f"{required} --first-body\n"
        "FIRST\n"
        f"{required} --second-body\n"
        "SECOND-END\n"
        f"{required} --root . --json\n"
    )

    assert iter_active_shell_lines(run_text) == [
        "cat <<FIRST <<'SECOND-END'",
        f"{required} --root . --json",
    ]


@pytest.mark.parametrize("quote", ["'", '"'])
def test_multiline_quoted_required_command_is_not_an_active_command(quote: str) -> None:
    required = "python -m agent_guard.cli context check"
    run_text = f"message={quote}\n{required} --root . --json\n{quote}\n"

    active = iter_active_shell_lines(run_text)

    assert len(active) == 1
    assert not command_line_matches_required(active[0], required)


@pytest.mark.parametrize(
    "run_text",
    [
        "result=$(\n{required} --root . --json\n)\n",
        'result="$(\nsetup; {required} --root . --json\n)"\n',
        "result=`\n{required} --root . --json\n`\n",
    ],
)
def test_multiline_command_substitution_cannot_satisfy_required_command(run_text: str) -> None:
    required = "python -m agent_guard.cli context check"
    active = iter_active_shell_lines(run_text.format(required=required))

    assert len(active) == 1
    assert not command_line_matches_required(active[0], required)


def test_required_command_after_multiline_substitution_remains_active() -> None:
    required = "python -m agent_guard.cli context check"
    run_text = (
        "result=$(\n"
        "setup || true\n"
        ")\n"
        f"{required} --root . --json\n"
    )

    active = iter_active_shell_lines(run_text)

    assert len(active) == 2
    assert not command_line_matches_required(active[0], required)
    assert command_line_matches_required(active[1], required)


def test_multiline_array_literal_cannot_satisfy_required_command() -> None:
    required = "python -m agent_guard.cli context check"
    run_text = (
        "commands=(\n"
        f"{required} --literal-value\n"
        ")\n"
        f"{required} --root . --json\n"
    )

    active = iter_active_shell_lines(run_text)

    assert len(active) == 2
    assert not command_line_matches_required(active[0], required)
    assert command_line_matches_required(active[1], required)


def test_unterminated_shell_literal_fails_closed() -> None:
    with pytest.raises(
        ValueError,
        match="^workflow shell syntax is unsupported or ambiguous$",
    ):
        iter_active_shell_lines("message='unterminated\n")


@pytest.mark.parametrize(
    ("command_line", "operators"),
    [
        ("guard --message 'literal; semicolon' && echo done", ["&&"]),
        ('guard --message "literal; semicolon" && echo done', ["&&"]),
        (r"guard --message \; && echo done", ["&&"]),
        (r"guard --message \&\& \|\| \;", []),
        ("guard --message 'literal && and ||'", []),
        ('guard --message "literal && and ||"', []),
        ("guard --message 'literal | and &' && echo done", ["&&"]),
        (r"guard --message \| \& && echo done", ["&&"]),
        ("guard || true && echo done", ["||", "&&"]),
        ("value=$(setup; fallback || true) && guard", ["&&"]),
    ],
)
def test_iter_command_segments_ignores_quoted_and_escaped_operators(
    command_line: str, operators: list[str]
) -> None:
    assert [operator for _, operator in iter_command_segments(command_line) if operator] == operators


def test_iter_command_segments_limits_operator_flood_before_next_segment_slice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = SliceTrackingCommand("guard" + ";" * 100_000)
    monkeypatch.setattr(workflow_guard, "MAX_WORKFLOW_COMMAND_OPERATORS", 2)

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        iter_command_segments(command)

    assert command.slice_count == 2


def test_iter_command_segments_limits_segments_before_final_segment_slice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = SliceTrackingCommand("first;second;third")
    monkeypatch.setattr(workflow_guard, "MAX_WORKFLOW_COMMAND_SEGMENTS", 2)

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        iter_command_segments(command)

    assert command.slice_count == 2


def test_iter_command_segments_limits_characters_before_lexing_or_slicing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = SliceTrackingCommand("(" * 9)
    monkeypatch.setattr(workflow_guard, "MAX_WORKFLOW_LEXER_CHARS", 8)

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        iter_command_segments(command)

    assert command.slice_count == 0


def test_iter_command_segments_limits_repeated_parentheses_without_prefix_slices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = SliceTrackingCommand("(" * 100_000)
    monkeypatch.setattr(workflow_guard, "MAX_WORKFLOW_LEXER_STEPS", 8)

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        iter_command_segments(command)

    assert command.slice_count == 0


def test_shell_fragment_limits_repeated_parentheses_before_command_slice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = SliceTrackingCommand("(" * 100_000)
    monkeypatch.setattr(workflow_guard, "MAX_WORKFLOW_LEXER_STEPS", 8)

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        workflow_guard._scan_shell_fragment(
            command,
            state=workflow_guard._ShellState(),
        )

    assert command.slice_count == 0


def test_command_match_streams_bounded_segments_without_public_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_segment_list(_command_line: str) -> list[tuple[str, str | None]]:
        raise AssertionError("command matching materialized the public segment list")

    monkeypatch.setattr(workflow_guard, "iter_command_segments", unexpected_segment_list)

    assert command_line_matches_required(
        "setup && agent-guard report --root . && echo complete",
        "agent-guard report",
    )


@pytest.mark.parametrize(
    "command_line",
    [
        "python -m agent_guard.cli content check --targets 'literal; semicolon'",
        'python -m agent_guard.cli content check --targets "literal; semicolon"',
        r"python -m agent_guard.cli content check --targets \;",
        r"python -m agent_guard.cli content check --targets \&\& \|\| \;",
        "python -m agent_guard.cli content check --targets 'literal && and ||'",
        'python -m agent_guard.cli content check --targets "literal && and ||"',
        "python -m agent_guard.cli content check --targets 'literal | and &'",
        r"python -m agent_guard.cli content check --targets \| \&",
    ],
)
def test_command_match_accepts_quoted_and_escaped_operator_literals(command_line: str) -> None:
    assert command_line_matches_required(command_line, "python -m agent_guard.cli content check")


@pytest.mark.parametrize("comment", ["# || true", "# | tee guard.log", "# &", "# ; exit 0"])
def test_command_match_ignores_operators_in_inline_shell_comments(comment: str) -> None:
    required = "python -m agent_guard.cli context check"

    assert command_line_matches_required(f"{required} --root . --json {comment}", required)


def test_command_match_keeps_quoted_and_escaped_hashes_as_data() -> None:
    required = "python -m agent_guard.cli context check"

    assert not command_line_matches_required(f"{required} --policy '# literal' || true", required)
    assert not command_line_matches_required(rf"{required} --policy \# || true", required)
    assert not command_line_matches_required(f"{required} --policy value# || true", required)


@pytest.mark.parametrize("redirection", ["2>&1", "<&0", "&>guard.log", "&>>guard.log"])
def test_command_match_accepts_in_segment_redirections(redirection: str) -> None:
    required = "python -m agent_guard.cli context check"

    assert command_line_matches_required(f"{required} --root . --json {redirection}", required)


def test_scan_workflow_policy_ok_with_multiline_run(tmp_path: Path) -> None:
    write(tmp_path / ".agent-guard" / "context-policy.yaml", "{}\n")
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        """
name: ci
on: [push]
jobs:
  test:
    name: pytest
    runs-on: ubuntu-latest
    steps:
      - name: Run CLI smoke tests
        run: |
          # documented but ignored
          echo "python -m agent_guard.cli digest check"
          python - <<'PY'
          print("python -m agent_guard.cli path check")
          PY
          python -m agent_guard.cli context check --root . --policy .agent-guard/context-policy.yaml --json
          python -m agent_guard.cli path check --root . --policy examples/path-policy.yaml --json
""",
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "required_files": [
            {"id": "context_policy", "path": ".agent-guard/context-policy.yaml"},
        ],
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": [
                    {"id": "context_guard", "command": "python -m agent_guard.cli context check"},
                    {"id": "path_guard", "command": "python -m agent_guard.cli path check"},
                ],
            }
        ],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert findings == []
    assert checked_items == 3


@pytest.mark.parametrize(
    ("target", "key", "value"),
    [
        ("job", "if", False),
        ("job", "if", "${{ false }}"),
        ("job", "if", "${{ 0.0 }}"),
        ("job", "if", "${{ 0x0 }}"),
        ("job", "continue-on-error", True),
        ("job", "continue-on-error", "${{ matrix.experimental }}"),
        ("step", "if", False),
        ("step", "if", "${{ false }}"),
        ("step", "if", "0.0"),
        ("step", "if", "${{ 0e0 }}"),
        ("step", "continue-on-error", True),
        ("step", "continue-on-error", "${{ matrix.experimental }}"),
        ("step", "shell", "echo {0}"),
        ("step", "shell", "python"),
        ("parallel-parent", "if", False),
        ("parallel-parent", "continue-on-error", True),
        ("job-default", "shell", "echo {0}"),
        ("workflow-default", "shell", "echo {0}"),
    ],
)
def test_required_command_rejects_nonexecuting_or_failure_masking_controls(
    tmp_path: Path,
    target: str,
    key: str,
    value: object,
) -> None:
    step: dict[str, object] = {
        "run": "python -m agent_guard.cli context check --root . --json",
    }
    job: dict[str, object] = {
        "runs-on": "ubuntu-latest",
        "steps": [step],
    }
    workflow: dict[str, object] = {
        "name": "ci",
        "jobs": {"test": job},
    }
    if target == "step":
        step[key] = value
    elif target == "job":
        job[key] = value
    elif target == "parallel-parent":
        job["steps"] = [{key: value, "parallel": [step]}]
    elif target == "job-default":
        job["defaults"] = {"run": {key: value}}
    else:
        workflow["defaults"] = {"run": {key: value}}

    findings, checked_items = scan_required_context_command(tmp_path, workflow)

    assert checked_items == 1
    assert [finding.reason for finding in findings] == [
        "missing_required_workflow_command"
    ]


@pytest.mark.parametrize("shell", [None, "bash", "sh", "pwsh", "powershell", "cmd"])
def test_required_command_accepts_supported_shell_and_nonliteral_condition(
    tmp_path: Path,
    shell: str | None,
) -> None:
    step: dict[str, object] = {
        "if": "matrix.python-version == '3.12'",
        "continue-on-error": False,
        "run": "python -m agent_guard.cli context check --root . --json",
    }
    if shell is not None:
        step["shell"] = shell
    workflow: dict[str, object] = {
        "name": "ci",
        "jobs": {
            "test": {
                "if": "github.event_name == 'push'",
                "continue-on-error": False,
                "runs-on": "ubuntu-latest",
                "steps": [step],
            }
        },
    }

    findings, checked_items = scan_required_context_command(tmp_path, workflow)

    assert checked_items == 1
    assert findings == []


def test_scan_workflow_policy_rejects_echo_comment_and_heredoc_false_positives(tmp_path: Path) -> None:
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        """
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          # python -m agent_guard.cli digest check --root . --policy digest.yaml --json
          echo "python -m agent_guard.cli digest check --root . --policy digest.yaml --json"
          python - <<'PY'
          print("python -m agent_guard.cli digest check --root . --policy digest.yaml --json")
          PY
""",
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": [
                    {"id": "digest_guard", "command": "python -m agent_guard.cli digest check"},
                ],
            }
        ],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert checked_items == 1
    assert len(findings) == 1
    assert findings[0].reason == "missing_required_workflow_command"
    assert findings[0].to_dict() == {
        "rule_id": "digest_guard",
        "severity": "high",
        "file": ".github/workflows/ci.yml",
        "message": "required workflow command is missing",
        "reason": "missing_required_workflow_command",
        "workflow_id": "ci_smoke",
        "requirement_id": "digest_guard",
    }


def test_scan_workflow_policy_finds_commands_inside_parallel_steps(tmp_path: Path) -> None:
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        """
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Independent guard checks
        parallel:
          - name: Context guard
            run: python -m agent_guard.cli context check --root . --policy .agent-guard/context-policy.yaml --json
          - name: Surface inventory
            run: python -m agent_guard.cli surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json
      - name: Final report
        run: python -m agent_guard.cli report --root . --context-policy .agent-guard/context-policy.yaml --format json
""",
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": [
                    {"id": "context_guard", "command": "python -m agent_guard.cli context check"},
                    {"id": "surface_inventory", "command": "python -m agent_guard.cli surface inventory"},
                    {"id": "report", "command": "python -m agent_guard.cli report"},
                ],
            }
        ],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert findings == []
    assert checked_items == 3


def test_context_lock_coverage_requirement_needs_digest_policy_option(tmp_path: Path) -> None:
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        """
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: python -m agent_guard.cli context lock --root . --policy .agent-guard/context-policy.yaml --check --json
""",
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_self_dogfood",
                "path": ".github/workflows/ci.yml",
                "required_commands": [
                    {
                        "id": "context_lock_coverage",
                        "command": (
                            "python -m agent_guard.cli context lock --root . "
                            "--policy .agent-guard/context-policy.yaml --check "
                            "--digest-policy .agent-guard/context-digest-policy.yaml"
                        ),
                    },
                ],
            },
        ],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert checked_items == 1
    assert len(findings) == 1
    assert findings[0].to_dict() == {
        "rule_id": "context_lock_coverage",
        "severity": "high",
        "file": ".github/workflows/ci.yml",
        "message": "required workflow command is missing",
        "reason": "missing_required_workflow_command",
        "workflow_id": "ci_self_dogfood",
        "requirement_id": "context_lock_coverage",
    }


def test_command_match_requires_command_segment_start() -> None:
    assert command_line_matches_required(
        "python -m agent_guard.cli context check --root . --json",
        "python -m agent_guard.cli context check",
    )
    assert command_line_matches_required(
        "python -m agent_guard.cli context check --root . --json && echo guard-complete",
        "python -m agent_guard.cli context check",
    )
    assert command_line_matches_required(
        "echo setup; python -m agent_guard.cli context check --root . --json",
        "python -m agent_guard.cli context check",
    )
    assert command_line_matches_required(
        "python -m agent_guard.cli path check --json && python -m agent_guard.cli digest check --json",
        "python -m agent_guard.cli digest check",
    )
    assert not command_line_matches_required(
        "echo python -m agent_guard.cli context check",
        "python -m agent_guard.cli context check",
    )
    assert not command_line_matches_required(
        "python -m agent_guard.cli context check --help",
        "python -m agent_guard.cli context check",
    )
    assert not command_line_matches_required(
        "python -m agent_guard.cli context check --root . --policy p.yaml --json || true",
        "python -m agent_guard.cli context check",
    )
    assert not command_line_matches_required(
        "python -m agent_guard.cli context check --root . --policy p.yaml --json; true",
        "python -m agent_guard.cli context check",
    )
    assert not command_line_matches_required(
        "python -m agent_guard.cli context check --root . --policy p.yaml --json; exit 0",
        "python -m agent_guard.cli context check",
    )
    assert not command_line_matches_required(
        "python -m agent_guard.cli context check --root . --policy p.yaml --json; echo completed",
        "python -m agent_guard.cli context check",
    )
    assert not command_line_matches_required(
        "python -m agent_guard.cli context check --root . --policy p.yaml --json && echo ok || true",
        "python -m agent_guard.cli context check",
    )
    assert not command_line_matches_required(
        "python -m agent_guard.cli context checker",
        "python -m agent_guard.cli context check",
    )


@pytest.mark.parametrize("prefix", ["true ||", ": ||", "true || setup &&"])
def test_command_match_rejects_required_segment_reached_through_preceding_or(prefix: str) -> None:
    required = "python -m agent_guard.cli context check"

    assert not command_line_matches_required(f"{prefix} {required} --root . --json", required)


def test_command_match_preserves_safe_setup_and_tail_shapes() -> None:
    required = "python -m agent_guard.cli context check"

    assert command_line_matches_required(f"setup && {required} --root . --json", required)
    assert command_line_matches_required(f"setup; {required} --root . --json", required)
    assert command_line_matches_required(f"true || setup; {required} --root . --json", required)
    assert command_line_matches_required(f"{required} --root . --json && echo guard-complete", required)


@pytest.mark.parametrize(
    ("required", "candidate"),
    [
        (
            "python -m agent_guard.cli context check --policy reviewed.yaml",
            "python -m agent_guard.cli context check --policy reviewed.yaml "
            "--policy=attacker.yaml",
        ),
        (
            "agent-guard context lock --policy reviewed.yaml --check",
            "agent-guard context lock --policy reviewed.yaml --check --check",
        ),
        (
            "agent-guard content check --policy reviewed.yaml --targets reviewed.py",
            "agent-guard content check --policy reviewed.yaml --targets reviewed.py "
            "--targets attacker.py",
        ),
        (
            "agent-guard evidence-pack manifest --report reviewed.json --artifact reviewed.json",
            "agent-guard evidence-pack manifest --report reviewed.json --artifact reviewed.json "
            "--artifact attacker.json",
        ),
    ],
)
def test_command_match_rejects_appended_native_option_overrides(
    required: str, candidate: str
) -> None:
    assert not command_line_matches_required(candidate, required)


@pytest.mark.parametrize("override", ["--policy attacker.yaml", "--pol=attacker.yaml"])
def test_command_match_rejects_equivalent_native_option_overrides(override: str) -> None:
    required = "agent-guard context check --policy reviewed.yaml"

    assert not command_line_matches_required(f"{required} {override}", required)


def test_command_match_rejects_ambiguous_native_option_form() -> None:
    required = "agent-guard report --root ."
    candidate = f"{required} --drift=attacker"

    assert not command_line_matches_required(candidate, required)


def test_command_match_rejects_environment_expansion_that_can_append_policy() -> None:
    required = "agent-guard context check --policy reviewed.yaml"

    assert not command_line_matches_required(f"{required} $EXTRA_ARGS", required)


def test_command_match_normalizes_isolated_python_launcher_before_option_checks() -> None:
    required = (
        "python -I -m agent_guard.cli context check --policy reviewed.yaml"
    )

    assert not command_line_matches_required(
        f"{required} --policy attacker.yaml",
        required,
    )
    assert command_line_matches_required(f"{required} --json", required)


@pytest.mark.parametrize(
    ("required", "candidate"),
    [
        (
            "agent-guard context check --policy reviewed.yaml",
            "agent-guard context check --policy=reviewed.yaml --json",
        ),
        (
            "agent-guard content check --policy reviewed.yaml",
            "agent-guard content check --policy reviewed.yaml "
            "--targets first.py second.py --json",
        ),
        (
            "agent-guard evidence-pack manifest --report reviewed.json",
            "agent-guard evidence-pack manifest --report reviewed.json "
            "--artifact first.json --artifact second.json --json",
        ),
        ("custom-check reviewed", "custom-check reviewed --future-option value"),
    ],
)
def test_command_match_preserves_safe_known_and_generic_prefix_commands(
    required: str,
    candidate: str,
) -> None:
    assert command_line_matches_required(candidate, required)


@pytest.mark.parametrize("tail", ["unexpected", "--unknown value"])
def test_command_match_rejects_unknown_native_tail(tail: str) -> None:
    required = "agent-guard context check --policy reviewed.yaml"

    assert not command_line_matches_required(f"{required} {tail}", required)


def test_command_match_allows_the_same_quoted_scalar_value() -> None:
    required = (
        'agent-guard conformance check --root . --evidence "$report_json" '
        '--profile recommended'
    )

    assert command_line_matches_required(f"{required} --json", required)
    assert not command_line_matches_required(
        required.replace("$report_json", "$other_report"),
        required,
    )
    assert not command_line_matches_required(
        required.replace('"$report_json"', "$report_json"),
        required,
    )


def test_command_match_rejects_array_expansion_and_dynamic_option_override() -> None:
    required = "agent-guard context check --policy reviewed.yaml"

    assert not command_line_matches_required(
        f'{required} "${{extra_args[@]}}"',
        required,
    )
    assert not command_line_matches_required(
        f'{required} --policy "$other_policy"',
        required,
    )


def test_command_match_does_not_fall_back_for_unsupported_native_launcher() -> None:
    required = (
        "python -X dev -m agent_guard.cli context check --policy reviewed.yaml"
    )

    assert not command_line_matches_required(f"{required} --policy attacker.yaml", required)


def test_command_match_normalizes_native_options_without_rejecting_safe_prefix_tail() -> None:
    required = "agent-guard context check --policy reviewed.yaml"

    assert command_line_matches_required(f"{required} --json", required)
    assert command_line_matches_required(
        "agent-guard context check --policy=reviewed.yaml --json",
        required,
    )


def test_scan_workflow_policy_rejects_environment_expansion_with_fixed_finding(
    tmp_path: Path,
) -> None:
    workflow = {
        "name": "ci",
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "env": {"EXTRA_ARGS": "--policy attacker.yaml"},
                        "run": (
                            "python -m agent_guard.cli context check "
                            "--policy reviewed.yaml $EXTRA_ARGS"
                        ),
                    }
                ],
            }
        },
    }

    findings, checked_items = scan_required_context_command(tmp_path, workflow)

    assert checked_items == 1
    assert [finding.to_dict() for finding in findings] == [
        {
            "rule_id": "context_guard",
            "severity": "high",
            "file": ".github/workflows/ci.yml",
            "message": "required workflow command is missing",
            "reason": "missing_required_workflow_command",
            "workflow_id": "ci_smoke",
            "requirement_id": "context_guard",
        }
    ]


@pytest.mark.parametrize(
    ("shell", "escaped_option"),
    [
        ("cmd", "--pol^icy"),
        ("pwsh", "--pol`i`cy"),
        ("powershell", "--pol`i`cy"),
    ],
)
def test_scan_workflow_policy_rejects_declared_shell_option_escapes(
    tmp_path: Path,
    shell: str,
    escaped_option: str,
) -> None:
    workflow = {
        "name": "ci",
        "jobs": {
            "test": {
                "runs-on": "windows-latest",
                "steps": [
                    {
                        "shell": shell,
                        "run": (
                            "python -m agent_guard.cli context check "
                            "--policy reviewed.yaml "
                            f"{escaped_option} attacker.yaml"
                        ),
                    }
                ],
            }
        },
    }

    findings, checked_items = scan_required_context_command(tmp_path, workflow)

    assert checked_items == 1
    assert [finding.reason for finding in findings] == [
        "missing_required_workflow_command"
    ]


@pytest.mark.parametrize(
    "tail",
    [
        "|",
        "| true",
        "|& tee guard.log",
        "&",
        "&>guard.log &",
        "&>>guard.log &",
        "&& echo guard-complete &",
    ],
)
def test_command_match_rejects_unquoted_pipeline_and_background_tails(tail: str) -> None:
    required = "python -m agent_guard.cli context check"

    assert not command_line_matches_required(f"{required} --root . --json {tail}", required)


@pytest.mark.parametrize("tail", ["true", "exit 0", "echo completed"])
def test_scan_workflow_policy_rejects_unconditional_semicolon_tail(
    tmp_path: Path, tail: str
) -> None:
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        f"""
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: python -m agent_guard.cli context check --root . --policy context.yaml --json; {tail}
""",
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": [
                    {"id": "context_guard", "command": "python -m agent_guard.cli context check"},
                ],
            }
        ],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert checked_items == 1
    assert [finding.reason for finding in findings] == ["missing_required_workflow_command"]


@pytest.mark.parametrize(
    "tail", ["|", "| true", "|& tee guard.log", "&", "&>guard.log &", "&>>guard.log &"]
)
def test_scan_workflow_policy_rejects_unquoted_pipeline_and_background_tails(
    tmp_path: Path, tail: str
) -> None:
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        f"""
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          python -m agent_guard.cli context check --root . --policy context.yaml --json {tail}
""",
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": [
                    {"id": "context_guard", "command": "python -m agent_guard.cli context check"},
                ],
            }
        ],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert checked_items == 1
    assert [finding.reason for finding in findings] == ["missing_required_workflow_command"]


@pytest.mark.parametrize(
    "command",
    [
        "python -m agent_guard.cli context check --policy 'literal | and &'",
        r"python -m agent_guard.cli context check --root \| --policy \&",
        "python -m agent_guard.cli context check --root . &>guard.log",
        "python -m agent_guard.cli context check --root . &>>guard.log",
    ],
)
def test_scan_workflow_policy_accepts_safe_operator_literals_and_redirections(
    tmp_path: Path, command: str
) -> None:
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        f"""
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          {command}
""",
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": [
                    {"id": "context_guard", "command": "python -m agent_guard.cli context check"},
                ],
            }
        ],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert findings == []
    assert checked_items == 1


def test_scan_workflow_policy_reports_missing_required_file(tmp_path: Path) -> None:
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "required_files": [{"id": "context_policy", "path": ".agent-guard/context-policy.yaml"}],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert checked_items == 1
    assert len(findings) == 1
    assert findings[0].to_dict()["reason"] == "missing_required_file"
    assert findings[0].to_dict()["file"] == ".agent-guard/context-policy.yaml"


def test_scan_workflow_policy_rejects_external_required_file_symlink_without_leak(
    tmp_path: Path,
) -> None:
    repo_root = tmp_path / "repo"
    external_file = tmp_path / "external" / "private-policy.yaml"
    external_marker = "synthetic-external-required-file-marker"
    write(external_file, f"marker: {external_marker}\n")
    (repo_root / ".agent-guard").mkdir(parents=True)
    (repo_root / ".agent-guard" / "context-policy.yaml").symlink_to(external_file)
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "required_files": [{"id": "context_policy", "path": ".agent-guard/context-policy.yaml"}],
    }

    with pytest.raises(ValueError) as exc_info:
        scan_workflow_policy(root=repo_root, policy=policy)

    assert external_marker not in str(exc_info.value)
    assert str(external_file) not in str(exc_info.value)


def test_scan_workflow_policy_rejects_external_workflow_symlink_without_leak(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    external_file = tmp_path / "external" / "private-workflow.yml"
    external_marker = "synthetic-external-workflow-marker"
    write(external_file, f"marker: {external_marker}\n")
    workflow_path = repo_root / ".github" / "workflows" / "ci.yml"
    workflow_path.parent.mkdir(parents=True)
    workflow_path.symlink_to(external_file)
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": ["python -m agent_guard.cli context check"],
            }
        ],
    }

    with pytest.raises(ValueError) as exc_info:
        scan_workflow_policy(root=repo_root, policy=policy)

    assert external_marker not in str(exc_info.value)
    assert str(external_file) not in str(exc_info.value)


@pytest.mark.skipif(os.name != "posix", reason="exercises POSIX no-follow traversal")
def test_scan_workflow_policy_reads_opened_workflow_descriptor_after_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = tmp_path / "repo"
    workflow_path = repo_root / ".github" / "workflows" / "ci.yml"
    external_file = tmp_path / "external" / "replacement.yml"
    write(
        workflow_path,
        """
jobs:
  test:
    steps:
      - run: python -m agent_guard.cli context check --root . --json
""",
    )
    write(external_file, "jobs: {}\n")
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": ["python -m agent_guard.cli context check"],
            }
        ],
    }
    original_open = workflow_guard._open_repo_file_posix

    def open_then_swap(root: Path, relative_path: Path) -> int:
        file_fd = original_open(root, relative_path)
        workflow_path.unlink()
        workflow_path.symlink_to(external_file)
        return file_fd

    monkeypatch.setattr(workflow_guard, "_open_repo_file_posix", open_then_swap)

    findings, checked_items = scan_workflow_policy(root=repo_root, policy=policy)

    assert findings == []
    assert checked_items == 1


@pytest.mark.skipif(os.name != "posix", reason="exercises POSIX no-follow traversal")
def test_scan_workflow_policy_rejects_workflow_ancestor_swap_without_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = tmp_path / "repo"
    workflow_dir = repo_root / ".github" / "workflows" / "nested"
    workflow_path = workflow_dir / "ci.yml"
    external_dir = tmp_path / "external"
    external_marker = "synthetic-external-workflow-ancestor-marker"
    write(
        workflow_path,
        """
jobs:
  test:
    steps:
      - run: python -m agent_guard.cli context check --root . --json
""",
    )
    write(external_dir / "ci.yml", f"marker: {external_marker}\n")
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/nested/ci.yml",
                "required_commands": ["python -m agent_guard.cli context check"],
            }
        ],
    }
    original_open = workflow_guard._open_repo_file_posix

    def swap_ancestor_before_open(root: Path, relative_path: Path) -> int:
        workflow_dir.rename(workflow_dir.parent / "held")
        workflow_dir.symlink_to(external_dir, target_is_directory=True)
        return original_open(root, relative_path)

    monkeypatch.setattr(workflow_guard, "_open_repo_file_posix", swap_ancestor_before_open)

    with pytest.raises(
        ValueError,
        match="^workflow scan target must stay under repo root$",
    ) as exc_info:
        scan_workflow_policy(root=repo_root, policy=policy)

    assert external_marker not in str(exc_info.value)
    assert str(external_dir) not in str(exc_info.value)


def test_scan_workflow_policy_rejects_repo_escape(tmp_path: Path) -> None:
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "required_files": [{"id": "outside", "path": "../outside.yaml"}],
    }

    with pytest.raises(ValueError, match="path must not contain"):
        scan_workflow_policy(root=tmp_path, policy=policy)


def test_scan_workflow_policy_rejects_empty_policy() -> None:
    with pytest.raises(ValueError, match="schema_version"):
        scan_workflow_policy(root=Path("."), policy={})

    with pytest.raises(ValueError, match="at least one"):
        scan_workflow_policy(
            root=Path("."),
            policy={"schema_version": "agent-guard.workflow_policy.v1"},
        )


def test_scan_workflow_policy_rejects_null_path(tmp_path: Path) -> None:
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "required_files": [{"id": "context_policy", "path": None}],
    }

    with pytest.raises(ValueError, match="path.*must be a string"):
        scan_workflow_policy(root=tmp_path, policy=policy)


def test_scan_workflow_policy_rejects_workflow_check_without_commands(tmp_path: Path) -> None:
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [{"id": "ci_smoke", "path": ".github/workflows/ci.yml"}],
    }

    with pytest.raises(ValueError, match="required_commands must contain"):
        scan_workflow_policy(root=tmp_path, policy=policy)


def test_scan_workflow_policy_missing_configured_workflow_is_error(tmp_path: Path) -> None:
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": ["python -m agent_guard.cli context check"],
            }
        ]
    }

    with pytest.raises(FileNotFoundError, match="workflow file not found"):
        scan_workflow_policy(root=tmp_path, policy=policy)


def test_load_workflow_policy_rejects_oversized_descriptor_before_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = tmp_path / "workflow-policy.yaml"
    marker = "synthetic-oversized-policy-marker"
    write(policy_path, f"schema_version: agent-guard.workflow_policy.v1\nignored: {marker * 8}\n")
    monkeypatch.setattr(workflow_guard, "MAX_WORKFLOW_POLICY_BYTES", 64)

    def unexpected_parse(_raw: bytes) -> object:
        raise AssertionError("oversized policy reached YAML parsing")

    monkeypatch.setattr(workflow_guard, "_parse_bounded_yaml", unexpected_parse)

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ) as exc_info:
        workflow_guard.load_workflow_policy(policy_path)

    assert marker not in str(exc_info.value)


def test_scan_workflow_policy_rejects_oversized_workflow_before_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow_path = tmp_path / ".github" / "workflows" / "ci.yml"
    marker = "synthetic-oversized-workflow-marker"
    write(workflow_path, f"jobs: {{}}\nignored: {marker * 8}\n")
    monkeypatch.setattr(workflow_guard, "MAX_WORKFLOW_FILE_BYTES", 64)

    def unexpected_load(_raw: bytes, *, workflow_id: str) -> object:
        raise AssertionError(f"oversized workflow reached YAML parsing for {workflow_id}")

    monkeypatch.setattr(workflow_guard, "load_workflow_file", unexpected_load)
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": ["python -m agent_guard.cli context check"],
            }
        ],
    }

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ) as exc_info:
        scan_workflow_policy(root=tmp_path, policy=policy)

    assert marker not in str(exc_info.value)


def test_load_workflow_file_rejects_oversized_raw_descriptor_before_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(workflow_guard, "MAX_WORKFLOW_FILE_BYTES", 8)

    def unexpected_parse(_raw: bytes) -> object:
        raise AssertionError("oversized raw workflow reached YAML parsing")

    monkeypatch.setattr(workflow_guard, "_parse_bounded_yaml", unexpected_parse)

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        workflow_guard.load_workflow_file(b"jobs: {}\n", workflow_id="ci_smoke")


def test_load_workflow_policy_rejects_recursive_alias_with_sanitized_error(
    tmp_path: Path,
) -> None:
    marker = "synthetic-recursive-policy-marker"
    policy_path = tmp_path / "workflow-policy.yaml"
    write(
        policy_path,
        "schema_version: agent-guard.workflow_policy.v1\n"
        f"ignored_{marker}: &cycle\n"
        "  - *cycle\n",
    )

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ) as exc_info:
        workflow_guard.load_workflow_policy(policy_path)

    assert marker not in str(exc_info.value)


def test_scan_workflow_policy_rejects_recursive_parallel_alias_without_recursion_error(
    tmp_path: Path,
) -> None:
    marker = "synthetic-recursive-workflow-marker"
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        f"      - &{marker}\n"
        "        parallel:\n"
        f"          - *{marker}\n",
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": ["python -m agent_guard.cli context check"],
            }
        ],
    }

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ) as exc_info:
        scan_workflow_policy(root=tmp_path, policy=policy)

    assert marker not in str(exc_info.value)


def test_load_workflow_file_rejects_yaml_merge_before_mapping_expansion() -> None:
    raw_workflow = (
        b"base: &base {steps: []}\n"
        b"jobs:\n"
        b"  test:\n"
        b"    <<: *base\n"
    )

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        workflow_guard.load_workflow_file(raw_workflow, workflow_id="ci_smoke")


def test_scan_workflow_policy_preserves_bounded_acyclic_step_aliases(tmp_path: Path) -> None:
    required = "python -m agent_guard.cli context check"
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        f"      - &guard {{run: {required} --root . --json}}\n"
        "      - *guard\n",
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": [required],
            }
        ],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert findings == []
    assert checked_items == 1


@pytest.mark.parametrize(
    ("budget_name", "raw_workflow"),
    [
        ("MAX_WORKFLOW_YAML_ALIASES", b"jobs: &jobs {}\ncopy: *jobs\n"),
        ("MAX_WORKFLOW_YAML_NODES", b"jobs: {}\n"),
        ("MAX_WORKFLOW_YAML_DEPTH", b"jobs: {}\n"),
    ],
)
def test_load_workflow_file_enforces_yaml_budgets_before_construction(
    monkeypatch: pytest.MonkeyPatch,
    budget_name: str,
    raw_workflow: bytes,
) -> None:
    monkeypatch.setattr(workflow_guard, budget_name, 0)

    def unexpected_safe_load(_text: str) -> object:
        raise AssertionError("YAML object construction started before preflight budget check")

    monkeypatch.setattr(workflow_guard.yaml, "safe_load", unexpected_safe_load)

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        workflow_guard.load_workflow_file(raw_workflow, workflow_id="ci_smoke")


@pytest.mark.parametrize(
    ("budget_name", "workflow"),
    [
        (
            "MAX_WORKFLOW_JOBS",
            "jobs:\n  first: {steps: []}\n  second: {steps: []}\n",
        ),
        (
            "MAX_WORKFLOW_STEPS",
            "jobs:\n  test:\n    steps:\n      - {run: setup}\n      - {run: verify}\n",
        ),
        (
            "MAX_WORKFLOW_COMMANDS",
            "jobs:\n  test:\n    steps:\n      - run: |\n          setup\n          verify\n",
        ),
    ],
)
def test_scan_workflow_policy_enforces_job_step_and_command_count_budgets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    budget_name: str,
    workflow: str,
) -> None:
    write(tmp_path / ".github" / "workflows" / "ci.yml", workflow)
    monkeypatch.setattr(workflow_guard, budget_name, 1)
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": ["python -m agent_guard.cli context check"],
            }
        ],
    }

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        scan_workflow_policy(root=tmp_path, policy=policy)


@pytest.mark.parametrize(
    ("budget_name", "budget"),
    [
        ("MAX_WORKFLOW_PARALLEL_DEPTH", 1),
        ("MAX_WORKFLOW_TRAVERSAL", 2),
    ],
)
def test_scan_workflow_policy_enforces_iterative_parallel_traversal_budgets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    budget_name: str,
    budget: int,
) -> None:
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - parallel:\n"
        "          - parallel:\n"
        "              - run: verify\n",
    )
    monkeypatch.setattr(workflow_guard, budget_name, budget)
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": ["python -m agent_guard.cli context check"],
            }
        ],
    }

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        scan_workflow_policy(root=tmp_path, policy=policy)


def test_scan_workflow_policy_checks_command_budget_before_run_line_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "jobs:\n  test:\n    steps:\n      - run: verify\n",
    )
    monkeypatch.setattr(workflow_guard, "MAX_WORKFLOW_COMMANDS", 0)

    class UnexpectedRunLine:
        def __init__(self, **_kwargs: object) -> None:
            raise AssertionError("run line materialized before command budget check")

    monkeypatch.setattr(workflow_guard, "WorkflowRunLine", UnexpectedRunLine)
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "ci_smoke",
                "path": ".github/workflows/ci.yml",
                "required_commands": ["python -m agent_guard.cli context check"],
            }
        ],
    }

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        scan_workflow_policy(root=tmp_path, policy=policy)


def test_scan_workflow_policy_checks_finding_budget_before_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(workflow_guard, "MAX_WORKFLOW_FINDINGS", 0)

    class UnexpectedFinding:
        def __init__(self, **_kwargs: object) -> None:
            raise AssertionError("finding materialized before finding budget check")

    monkeypatch.setattr(workflow_guard, "WorkflowGuardFinding", UnexpectedFinding)
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "required_files": [{"id": "missing", "path": "missing.yaml"}],
    }

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        scan_workflow_policy(root=tmp_path, policy=policy)


@pytest.mark.parametrize(
    "field_name",
    [
        "schema_version",
        "required_file_id",
        "required_file_path",
        "required_file_severity",
        "workflow_id",
        "workflow_path",
        "workflow_severity",
        "required_command_id",
        "required_command",
    ],
)
def test_scan_workflow_policy_rejects_oversized_utf8_policy_strings_without_leak(
    tmp_path: Path,
    field_name: str,
) -> None:
    marker = f"synthetic-oversized-{field_name}-marker"
    oversized = marker + (
        "界" * (workflow_guard.MAX_WORKFLOW_POLICY_STRING_BYTES // 3 + 1)
    )
    policy: dict[str, object] = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "required_files": [{"id": "required", "path": "required.yaml", "severity": "high"}],
    }
    if field_name == "schema_version":
        policy["schema_version"] = oversized
    elif field_name.startswith("required_file_"):
        required_file = policy["required_files"][0]
        assert isinstance(required_file, dict)
        required_file[field_name.removeprefix("required_file_")] = oversized
    else:
        workflow_check = {
            "id": "workflow",
            "path": ".github/workflows/ci.yml",
            "severity": "high",
            "required_commands": [{"id": "guard", "command": "agent-guard report"}],
        }
        policy = {
            "schema_version": "agent-guard.workflow_policy.v1",
            "workflow_checks": [workflow_check],
        }
        if field_name.startswith("workflow_"):
            workflow_check[field_name.removeprefix("workflow_")] = oversized
        else:
            required_command = workflow_check["required_commands"][0]
            assert isinstance(required_command, dict)
            command_field = "id" if field_name == "required_command_id" else "command"
            required_command[command_field] = oversized

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ) as exc_info:
        scan_workflow_policy(root=tmp_path, policy=policy)

    assert marker not in str(exc_info.value)


def test_scan_workflow_policy_checks_result_byte_budget_before_finding_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "synthetic-workflow-result-marker"
    monkeypatch.setattr(workflow_guard, "MAX_WORKFLOW_AGGREGATE_RESULT_BYTES", 0)

    class UnexpectedFinding:
        def __init__(self, **_kwargs: object) -> None:
            raise AssertionError("finding materialized before aggregate result budget check")

    monkeypatch.setattr(workflow_guard, "WorkflowGuardFinding", UnexpectedFinding)
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "required_files": [{"id": marker, "path": "missing.yaml"}],
    }

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ) as exc_info:
        scan_workflow_policy(root=tmp_path, policy=policy)

    assert marker not in str(exc_info.value)


def test_scan_workflow_policy_enforces_aggregate_result_byte_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    materialized = 0
    original_finding = workflow_guard.WorkflowGuardFinding

    def counted_finding(**kwargs: object) -> object:
        nonlocal materialized
        materialized += 1
        return original_finding(**kwargs)

    first_finding_bytes = workflow_guard._workflow_finding_result_size_bytes(
        "missing_a",
        "high",
        "missing-a.yml",
        "required file is missing",
        "missing_required_file",
        "missing_a",
    )
    monkeypatch.setattr(
        workflow_guard,
        "MAX_WORKFLOW_AGGREGATE_RESULT_BYTES",
        first_finding_bytes,
    )
    monkeypatch.setattr(workflow_guard, "WorkflowGuardFinding", counted_finding)
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "required_files": [
            {"id": "missing_a", "path": "missing-a.yml"},
            {"id": "missing_b", "path": "missing-b.yml"},
        ],
    }

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        scan_workflow_policy(root=tmp_path, policy=policy)

    assert materialized == 1


def test_scan_workflow_policy_caches_duplicate_normalized_workflow_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow_text = "jobs: {}\n"
    write(tmp_path / ".github" / "workflows" / "ci.yml", workflow_text)
    calls = {"read": 0, "parse": 0, "run_lines": 0}
    original_read = workflow_guard._read_repo_bound_bytes
    original_load = workflow_guard.load_workflow_file
    original_collect = workflow_guard.collect_run_lines

    def counted_read(path: Path, repo_root: Path, *, max_bytes: int) -> bytes:
        calls["read"] += 1
        return original_read(path, repo_root, max_bytes=max_bytes)

    def counted_load(raw: bytes, *, workflow_id: str) -> dict[str, object]:
        calls["parse"] += 1
        return original_load(raw, workflow_id=workflow_id)

    def counted_collect(
        workflow: dict[str, object],
        *,
        workflow_path: str,
        _budget: object | None = None,
    ) -> list[workflow_guard.WorkflowRunLine]:
        calls["run_lines"] += 1
        return original_collect(workflow, workflow_path=workflow_path, _budget=_budget)

    monkeypatch.setattr(workflow_guard, "_read_repo_bound_bytes", counted_read)
    monkeypatch.setattr(workflow_guard, "load_workflow_file", counted_load)
    monkeypatch.setattr(workflow_guard, "collect_run_lines", counted_collect)
    monkeypatch.setattr(
        workflow_guard,
        "MAX_WORKFLOW_DISTINCT_INPUT_BYTES",
        len(workflow_text.encode("utf-8")),
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "first_check",
                "path": ".github/workflows/ci.yml",
                "required_commands": [{"id": "first_guard", "command": "agent-guard report"}],
            },
            {
                "id": "second_check",
                "path": ".github\\workflows\\ci.yml",
                "required_commands": [{"id": "second_guard", "command": "agent-guard report"}],
            },
        ],
    }

    findings, checked_items = scan_workflow_policy(root=tmp_path, policy=policy)

    assert calls == {"read": 1, "parse": 1, "run_lines": 1}
    assert checked_items == 2
    assert [finding.rule_id for finding in findings] == ["first_guard", "second_guard"]
    assert [finding.workflow_id for finding in findings] == ["first_check", "second_check"]


def test_scan_workflow_policy_limits_aggregate_distinct_workflow_bytes_before_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow_text = "jobs: {}\n"
    write(tmp_path / ".github" / "workflows" / "first.yml", workflow_text)
    write(tmp_path / ".github" / "workflows" / "second.yml", workflow_text)
    parse_calls = 0
    original_load = workflow_guard.load_workflow_file

    def counted_load(raw: bytes, *, workflow_id: str) -> dict[str, object]:
        nonlocal parse_calls
        parse_calls += 1
        return original_load(raw, workflow_id=workflow_id)

    monkeypatch.setattr(workflow_guard, "load_workflow_file", counted_load)
    monkeypatch.setattr(
        workflow_guard,
        "MAX_WORKFLOW_DISTINCT_INPUT_BYTES",
        len(workflow_text.encode("utf-8")),
    )
    policy = {
        "schema_version": "agent-guard.workflow_policy.v1",
        "workflow_checks": [
            {
                "id": "first_check",
                "path": ".github/workflows/first.yml",
                "required_commands": ["agent-guard report"],
            },
            {
                "id": "second_check",
                "path": ".github/workflows/second.yml",
                "required_commands": ["agent-guard report"],
            },
        ],
    }

    with pytest.raises(
        ValueError,
        match="^workflow configuration exceeds safety limits$",
    ):
        scan_workflow_policy(root=tmp_path, policy=policy)

    assert parse_calls == 1
