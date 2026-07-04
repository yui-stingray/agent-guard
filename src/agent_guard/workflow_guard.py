"""Where: src/agent_guard/workflow_guard.py
What: static workflow drift guard for repository safety gates.
Why: ensure CI keeps running declared guard commands and required policy files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any

import yaml


WORKFLOW_POLICY_SCHEMA_VERSION = "agent-guard.workflow_policy.v1"
HEREDOC_RE = re.compile(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")
COMMAND_OPERATOR_RE = re.compile(r"(\|\||&&|;)")
DOCUMENTATION_COMMANDS = {"echo", "printf"}
HELP_OPTIONS = {"--help", "-h"}


@dataclass(frozen=True)
class RequiredFile:
    check_id: str
    path: str
    severity: str


@dataclass(frozen=True)
class RequiredWorkflowCommand:
    command_id: str
    command: str


@dataclass(frozen=True)
class WorkflowCheck:
    check_id: str
    path: str
    severity: str
    required_commands: list[RequiredWorkflowCommand]


@dataclass(frozen=True)
class WorkflowGuardFinding:
    rule_id: str
    severity: str
    file: str
    message: str
    reason: str
    workflow_id: str | None = None
    requirement_id: str | None = None
    job_id: str | None = None
    job_name: str | None = None
    step_index: int | None = None
    step_name: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "message": self.message,
            "reason": self.reason,
        }
        optional: dict[str, object | None] = {
            "workflow_id": self.workflow_id,
            "requirement_id": self.requirement_id,
            "job_id": self.job_id,
            "job_name": self.job_name,
            "step_index": self.step_index,
            "step_name": self.step_name,
        }
        payload.update({key: value for key, value in optional.items() if value is not None})
        return payload


@dataclass(frozen=True)
class WorkflowRunLine:
    workflow: str
    job_id: str
    job_name: str
    step_index: int
    step_name: str
    command: str


def is_windows_absolute_path(raw_path: str) -> bool:
    return PureWindowsPath(raw_path).is_absolute() or bool(re.match(r"^[A-Za-z]:[\\/]", raw_path))


def load_workflow_policy(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")

    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"policy file must be YAML object: {path}")
    return loaded


def normalize_repo_relative_path(value: Any, *, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label}: path must be a string")
    path_text = str(value).strip()
    if not path_text:
        raise ValueError(f"{label}: path is required")
    if is_windows_absolute_path(path_text) or Path(path_text).is_absolute():
        raise ValueError(f"{label}: path must be repository-relative")

    normalized = path_text.replace("\\", "/")
    parts = Path(normalized).parts
    if ".." in parts:
        raise ValueError(f"{label}: path must not contain '..'")
    return Path(normalized).as_posix()


def optional_string_field(item: dict[str, Any], field: str, *, default: str, label: str) -> str:
    if field not in item:
        return default
    value = item[field]
    if not isinstance(value, str):
        raise ValueError(f"{label}.{field}: must be a string")
    return value.strip() or default


def required_string_field(item: dict[str, Any], field: str, *, label: str) -> str:
    if field not in item:
        raise ValueError(f"{label}.{field}: is required")
    value = item[field]
    if not isinstance(value, str):
        raise ValueError(f"{label}.{field}: must be a string")
    text = value.strip()
    if not text:
        raise ValueError(f"{label}.{field}: is required")
    return text


def resolve_repo_file(root: Path, rel_path: str, *, label: str) -> tuple[Path, str]:
    normalized = normalize_repo_relative_path(rel_path, label=label)
    target = (root / normalized).resolve()
    try:
        relative = target.relative_to(root)
    except ValueError:
        raise ValueError(f"{label}: path escapes root") from None
    return target, relative.as_posix()


def normalize_required_files(raw: Any) -> list[RequiredFile]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("required_files must be a list")

    required_files: list[RequiredFile] = []
    for idx, item in enumerate(raw, start=1):
        label = f"required_files[{idx}]"
        if isinstance(item, str):
            check_id = f"required_file_{idx}"
            path = normalize_repo_relative_path(item, label=label)
            severity = "high"
        elif isinstance(item, dict):
            check_id = optional_string_field(item, "id", default=f"required_file_{idx}", label=label)
            path = normalize_repo_relative_path(required_string_field(item, "path", label=label), label=label)
            severity = optional_string_field(item, "severity", default="high", label=label)
        else:
            raise ValueError(f"{label}: entry must be a string or object")
        required_files.append(RequiredFile(check_id=check_id, path=path, severity=severity))
    return required_files


def normalize_required_commands(raw: Any, *, workflow_id: str) -> list[RequiredWorkflowCommand]:
    if not isinstance(raw, list):
        raise ValueError(f"{workflow_id}: required_commands must be a list")

    commands: list[RequiredWorkflowCommand] = []
    for idx, item in enumerate(raw, start=1):
        if isinstance(item, str):
            command_id = f"required_command_{idx}"
            command = item.strip()
        elif isinstance(item, dict):
            label = f"{workflow_id}.required_commands[{idx}]"
            command_id = optional_string_field(item, "id", default=f"required_command_{idx}", label=label)
            command = required_string_field(item, "command", label=label)
        else:
            raise ValueError(f"{workflow_id}: required_commands[{idx}] must be a string or object")
        if not command:
            raise ValueError(f"{workflow_id}: required_commands[{idx}] command is required")
        commands.append(RequiredWorkflowCommand(command_id=command_id, command=command))
    if not commands:
        raise ValueError(f"{workflow_id}: required_commands must contain at least one command")
    return commands


def normalize_workflow_checks(raw: Any) -> list[WorkflowCheck]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("workflow_checks must be a list")

    checks: list[WorkflowCheck] = []
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"workflow_checks[{idx}] must be an object")
        label = f"workflow_checks[{idx}]"
        check_id = optional_string_field(item, "id", default=f"workflow_check_{idx}", label=label)
        path = normalize_repo_relative_path(required_string_field(item, "path", label=label), label=f"{check_id}.path")
        severity = optional_string_field(item, "severity", default="high", label=label)
        commands = normalize_required_commands(item.get("required_commands", []), workflow_id=check_id)
        checks.append(
            WorkflowCheck(
                check_id=check_id,
                path=path,
                severity=severity,
                required_commands=commands,
            )
        )
    return checks


def load_workflow_file(path: Path, *, workflow_id: str) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark is not None else ""
        raise ValueError(f"{workflow_id}: workflow YAML is invalid{location}") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"{workflow_id}: workflow file must be a YAML object")
    return loaded


def iter_active_shell_lines(run_text: str) -> list[str]:
    active: list[str] = []
    heredoc_delimiter: str | None = None
    pending = ""
    for raw_line in run_text.splitlines():
        line = raw_line.strip()
        if heredoc_delimiter is not None:
            if line == heredoc_delimiter:
                heredoc_delimiter = None
            continue
        if not line or line.startswith("#"):
            continue
        if pending:
            line = f"{pending} {line}"
        if line.endswith("\\"):
            pending = line[:-1].rstrip()
            continue
        active.append(line)
        pending = ""
        heredoc_match = HEREDOC_RE.search(line)
        if heredoc_match:
            heredoc_delimiter = heredoc_match.group(1)
    if pending:
        active.append(pending)
    return active


def collect_run_lines(workflow: dict[str, Any], *, workflow_path: str) -> list[WorkflowRunLine]:
    raw_jobs = workflow.get("jobs", {})
    if raw_jobs is None:
        raw_jobs = {}
    if not isinstance(raw_jobs, dict):
        raise ValueError(f"{workflow_path}: jobs must be an object")

    lines: list[WorkflowRunLine] = []
    for raw_job_id, raw_job in raw_jobs.items():
        job_id = str(raw_job_id)
        if not isinstance(raw_job, dict):
            raise ValueError(f"{workflow_path}: job {job_id} must be an object")
        job_name = str(raw_job.get("name", "")).strip()
        raw_steps = raw_job.get("steps", [])
        if raw_steps is None:
            raw_steps = []
        if not isinstance(raw_steps, list):
            raise ValueError(f"{workflow_path}: job {job_id} steps must be a list")
        for step_index, raw_step in enumerate(raw_steps, start=1):
            if not isinstance(raw_step, dict):
                raise ValueError(f"{workflow_path}: job {job_id} step {step_index} must be an object")
            lines.extend(
                collect_step_run_lines(
                    raw_step,
                    workflow_path=workflow_path,
                    job_id=job_id,
                    job_name=job_name,
                    step_index=step_index,
                )
            )
    return lines


def collect_step_run_lines(
    raw_step: dict[str, Any],
    *,
    workflow_path: str,
    job_id: str,
    job_name: str,
    step_index: int,
) -> list[WorkflowRunLine]:
    lines: list[WorkflowRunLine] = []
    run = raw_step.get("run")
    if isinstance(run, str):
        step_name = str(raw_step.get("name", "")).strip()
        for command in iter_active_shell_lines(run):
            lines.append(
                WorkflowRunLine(
                    workflow=workflow_path,
                    job_id=job_id,
                    job_name=job_name,
                    step_index=step_index,
                    step_name=step_name,
                    command=command,
                )
            )

    raw_parallel = raw_step.get("parallel")
    if raw_parallel is None:
        return lines
    if not isinstance(raw_parallel, list):
        raise ValueError(f"{workflow_path}: job {job_id} step {step_index} parallel must be a list")
    for parallel_index, raw_parallel_step in enumerate(raw_parallel, start=1):
        if not isinstance(raw_parallel_step, dict):
            raise ValueError(
                f"{workflow_path}: job {job_id} step {step_index} parallel item {parallel_index} must be an object"
            )
        lines.extend(
            collect_step_run_lines(
                raw_parallel_step,
                workflow_path=workflow_path,
                job_id=job_id,
                job_name=job_name,
                step_index=step_index,
            )
        )
    return lines


def normalize_command_text(command: str) -> str:
    return re.sub(r"\s+", " ", command.strip())


def is_documentation_segment(segment: str) -> bool:
    lowered = segment.lstrip().lower()
    if not lowered:
        return True
    command_name = lowered.split(maxsplit=1)[0]
    return command_name in DOCUMENTATION_COMMANDS


def has_help_option(segment: str) -> bool:
    tokens = normalize_command_text(segment).split()
    return any(token in HELP_OPTIONS for token in tokens)


def iter_command_segments(command_line: str) -> list[tuple[str, str | None]]:
    parts = COMMAND_OPERATOR_RE.split(command_line)
    segments: list[tuple[str, str | None]] = []
    for index in range(0, len(parts), 2):
        segment = parts[index]
        next_operator = parts[index + 1] if index + 1 < len(parts) else None
        segments.append((segment, next_operator))
    return segments


def command_line_matches_required(command_line: str, required_command: str) -> bool:
    required = normalize_command_text(required_command)
    if not required:
        return False

    segments = iter_command_segments(command_line)
    for index, (segment, next_operator) in enumerate(segments):
        normalized = normalize_command_text(segment)
        if not normalized or is_documentation_segment(normalized):
            continue
        if next_operator == "||" or has_help_option(normalized):
            continue
        if any(later_operator == "||" for _, later_operator in segments[index:]):
            continue
        if normalized == required or normalized.startswith(required + " "):
            return True
    return False


def validate_workflow_policy(policy: dict[str, Any]) -> None:
    schema_version = policy.get("schema_version")
    if schema_version != WORKFLOW_POLICY_SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {WORKFLOW_POLICY_SCHEMA_VERSION!r}")


def scan_workflow_policy(*, root: Path, policy: dict[str, Any]) -> tuple[list[WorkflowGuardFinding], int]:
    root = root.resolve()
    validate_workflow_policy(policy)
    required_files = normalize_required_files(policy.get("required_files", []))
    workflow_checks = normalize_workflow_checks(policy.get("workflow_checks", []))
    if not required_files and not workflow_checks:
        raise ValueError("workflow policy must configure at least one required_files or workflow_checks entry")

    findings: list[WorkflowGuardFinding] = []
    checked_items = 0
    for required in required_files:
        target, rel_path = resolve_repo_file(root, required.path, label=required.check_id)
        checked_items += 1
        if not target.is_file():
            findings.append(
                WorkflowGuardFinding(
                    rule_id=required.check_id,
                    severity=required.severity,
                    file=rel_path,
                    message="required file is missing",
                    reason="missing_required_file",
                    requirement_id=required.check_id,
                )
            )

    for check in workflow_checks:
        workflow_path, rel_path = resolve_repo_file(root, check.path, label=check.check_id)
        if not workflow_path.is_file():
            raise FileNotFoundError(f"{check.check_id}: workflow file not found: {rel_path}")
        workflow = load_workflow_file(workflow_path, workflow_id=check.check_id)
        run_lines = collect_run_lines(workflow, workflow_path=rel_path)

        for required in check.required_commands:
            checked_items += 1
            if any(command_line_matches_required(line.command, required.command) for line in run_lines):
                continue
            findings.append(
                WorkflowGuardFinding(
                    rule_id=required.command_id,
                    severity=check.severity,
                    file=rel_path,
                    message="required workflow command is missing",
                    reason="missing_required_workflow_command",
                    workflow_id=check.check_id,
                    requirement_id=required.command_id,
                )
            )

    return findings, checked_items
