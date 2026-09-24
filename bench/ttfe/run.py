"""Candidate-wheel replay and durable checking for the TTFE benchmark."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

LEGACY_SCHEMA_VERSION = "agent-guard.ttfe_results.v1"
SCHEMA_VERSION = "agent-guard.ttfe_results.v2"
PACK_COMMAND_MARKER = "agent-guard evidence-pack manifest"
RECOMMENDED_REPORT_MARKER = "--evidence-preset recommended"
DEFAULT_MAX_ELAPSED_MS = 900_000
DEFAULT_STAGE_TIMEOUT_MS = 120_000
REPORT_RELATIVE_PATH = Path(".agent-guard/evidence/agent-guard-report.json")

EXPECTED_DOCUMENTED_COMMANDS = (
    "python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11, 4) else \"agent-guard requires Python 3.11.4+\")' && python3 -m venv .venv && . .venv/bin/activate && python -m pip install yui-agent-guard==0.3.10",
    "agent-guard init --root . --print",
    "agent-guard init --root . --write",
    "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --format json --output .agent-guard/evidence/agent-guard-report.json --stderr-summary",
)
_STAGE_TO_DOCUMENTED_INDEX = {
    "build-candidate": None,
    "inspect-pyyaml": None,
    "prepare-pyyaml": None,
    "bootstrap": 1,
    "venv": 1,
    "install": 1,
    "verify-identity": 1,
    "init-print": 2,
    "init-write": 3,
    "report": 4,
    "validate-report": 4,
}
EXPECTED_STAGES = tuple(_STAGE_TO_DOCUMENTED_INDEX)
ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]


def extract_bash_commands(markdown: str) -> list[str]:
    """Extract complete commands from Bash-family fenced blocks."""

    commands: list[str] = []
    in_bash = False
    pending = ""
    for raw in markdown.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if stripped.startswith("```"):
            language = stripped.removeprefix("```").strip().lower()
            if in_bash:
                if pending:
                    commands.append(pending.strip())
                    pending = ""
                in_bash = False
            else:
                in_bash = language in {"bash", "sh", "shell"}
            continue
        if not in_bash or not stripped or stripped.startswith("#"):
            continue
        pending = f"{pending} {stripped}".strip() if pending else stripped
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
        else:
            commands.append(pending)
            pending = ""
    if pending:
        commands.append(pending.strip())
    return commands


def _legacy_first(records: list[dict[str, Any]], minimum: int) -> dict[str, Any] | None:
    for record in records:
        try:
            code = record.get("exit_code")
            if type(code) is not int:
                continue
        except (AttributeError, TypeError, ValueError):
            continue
        if code >= minimum:
            return {"index": record.get("index"), "command": record.get("command"), "exit_code": code}
    return None


def reaches_recommended_evidence_pack(records: list[dict[str, Any]]) -> bool:
    """Legacy marker check kept for callers which read v1 artifacts.

    The v2 gate does not trust this marker; it validates a freshly generated
    report through the candidate environment's public consumer API.
    """

    return any(
        PACK_COMMAND_MARKER in str(record.get("command", ""))
        or ("agent-guard report" in str(record.get("command", "")) and RECOMMENDED_REPORT_MARKER in str(record.get("command", "")))
        for record in records
    )


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _first_nonzero(records: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    for record in records:
        code = record.get("exit_code")
        if type(code) is int and code != 0:
            result = {"index": record.get("index"), "exit_code": code}
            if "stage" in record:
                result["stage"] = record["stage"]
            return result
    return None


def build_result_payload(
    *,
    source_doc: str,
    commands: list[str],
    records: list[dict[str, Any]],
    elapsed_ms: int,
    setup: dict[str, Any],
    execution: dict[str, Any] | None = None,
    candidate: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
    status: str | None = None,
    failure_point: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Shape a result while retaining the old callable signature.

    Historical callers that omit proof fields create v1.  v1 can be read but
    cannot pass ``check`` because it has no durable candidate-wheel proof.
    """

    if execution is None or candidate is None or evidence is None:
        reached = reaches_recommended_evidence_pack(records)
        first_nonzero = _legacy_first(records, 1)
        return {
            "schema_version": LEGACY_SCHEMA_VERSION,
            "generated_at": _now(),
            "status": "failed",
            "source_doc": source_doc,
            "command_count": len(records),
            "documented_command_count": len(commands),
            "elapsed_ms": elapsed_ms,
            "reached_recommended_evidence_pack": reached,
            "first_nonzero": first_nonzero,
            "failure_point": {
                "reason": "candidate-wheel proof unavailable; rerun required",
                "first_nonzero": first_nonzero,
            },
            "setup": setup,
            "commands": records,
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _now(),
        "status": status or "failed",
        "source_doc": source_doc,
        "command_count": len(records),
        "documented_command_count": len(commands),
        "elapsed_ms": elapsed_ms,
        "setup": setup,
        "execution": execution,
        "candidate": candidate,
        "evidence": evidence,
        "first_nonzero": _first_nonzero(records),
        "failure_point": failure_point,
        "commands": records,
    }


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("TTFE record must be an object")
            records.append(value)
    return records


def _int(value: Any) -> int | None:
    return value if type(value) is int else None


def _map(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _error(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def _validate_records(value: Any) -> tuple[list[str], list[Mapping[str, Any]]]:
    if not isinstance(value, list):
        return ["TTFE command records must be an array"], []
    errors: list[str] = []
    records: list[Mapping[str, Any]] = []
    if len(value) != len(EXPECTED_STAGES):
        errors.append("TTFE replay has incomplete command stages")
    for position, stage in enumerate(EXPECTED_STAGES, 1):
        if position > len(value):
            break
        record = _map(value[position - 1])
        if record is None:
            errors.append("TTFE command record must be an object")
            continue
        records.append(record)
        source_index = _STAGE_TO_DOCUMENTED_INDEX[stage]
        source_command = EXPECTED_DOCUMENTED_COMMANDS[source_index - 1] if source_index else None
        _error(errors, _int(record.get("index")) == position, "TTFE command records must be ordered and unique")
        _error(errors, record.get("stage") == stage, "TTFE command stages do not match the documented replay")
        _error(errors, record.get("documented_index") == source_index and type(record.get("documented_index")) is type(source_index), "TTFE command mapping is invalid")
        _error(errors, record.get("documented_command") == source_command, "TTFE command text does not match the documented quickstart")
        executable = record.get("executed_command")
        _error(errors, isinstance(executable, list) and bool(executable) and all(type(item) is str and item for item in executable), "TTFE executed command mapping is invalid")
        code = _int(record.get("exit_code"))
        _error(errors, code is not None and 0 <= code <= 255, "TTFE command exit code is invalid")
        duration = _int(record.get("duration_ms"))
        _error(errors, duration is not None and duration >= 0, "TTFE command duration is invalid")
        timeout = _int(record.get("timeout_ms"))
        _error(errors, timeout is not None and timeout > 0, "TTFE command timeout is invalid")
    if len(value) > len(EXPECTED_STAGES):
        errors.append("TTFE replay contains unexpected command stages")
    return errors, records


def _failure(records: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    for record in records:
        stage, code = record.get("stage"), _int(record.get("exit_code"))
        if not isinstance(stage, str) or code is None:
            return None
        if code not in ({0, 1} if stage == "report" else {0}):
            category = {
                "build-candidate": "wheel",
                "prepare-pyyaml": "dependency",
            }.get(stage, stage)
            return {"index": record.get("index"), "stage": stage, "category": category, "exit_code": code}
    return None


def _validate_execution(value: Any) -> list[str]:
    execution = _map(value)
    if execution is None:
        return ["TTFE execution proof is missing"]
    errors: list[str] = []
    _error(errors, execution.get("mode") == "candidate-wheel-replay", "TTFE execution mode is invalid")
    _error(errors, execution.get("prebuild_excluded") is True, "TTFE prebuild treatment is invalid")
    timeout = _int(execution.get("stage_timeout_ms"))
    _error(errors, timeout is not None and 0 < timeout <= DEFAULT_MAX_ELAPSED_MS, "TTFE stage timeout is invalid")
    documented = execution.get("documented_commands")
    _error(errors, isinstance(documented, list) and len(documented) == 4, "TTFE documented command mapping is incomplete")
    if isinstance(documented, list) and len(documented) == 4:
        for index, command in enumerate(EXPECTED_DOCUMENTED_COMMANDS, 1):
            item = _map(documented[index - 1])
            expected_stages = [name for name, source_index in _STAGE_TO_DOCUMENTED_INDEX.items() if source_index == index]
            _error(errors, item is not None and _int(item.get("index")) == index and item.get("command") == command and item.get("stages") == expected_stages, "TTFE documented command execution mapping is invalid")
    return errors


def _manifest_files(value: Any) -> dict[str, str] | None:
    item = _map(value)
    files = item.get("files") if item else None
    if not isinstance(files, Mapping) or not files:
        return None
    normalized: dict[str, str] = {}
    for relative, digest in files.items():
        if type(relative) is not str or not relative or relative.startswith("/") or "\\" in relative or ".." in Path(relative).parts:
            return None
        if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None or relative in normalized:
            return None
        normalized[relative] = digest
    if _int(item.get("file_count")) != len(normalized) or item.get("sha256") != _manifest_digest(normalized):
        return None
    return normalized


def _venv_label(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("<candidate-venv>/"):
        return False
    relative = value.removeprefix("<candidate-venv>/")
    return bool(relative) and "\\" not in relative and all(part not in {"", ".", ".."} for part in relative.split("/"))


def _validate_candidate(value: Any) -> list[str]:
    """Recompute the durable identity bindings; do not trust success flags."""

    candidate = _map(value)
    if candidate is None:
        return ["TTFE candidate identity proof is missing"]
    errors: list[str] = []
    source, wheel = _map(candidate.get("source")), _map(candidate.get("wheel"))
    install, runtime = _map(candidate.get("install")), _map(candidate.get("runtime"))
    manifests = _map(candidate.get("package_manifests"))
    _error(errors, source is not None and type(source.get("revision")) is str and re.fullmatch(r"[0-9a-f]{40}", source["revision"]) is not None, "TTFE source revision is invalid")
    wheel_digest = wheel.get("sha256") if wheel else None
    wheel_filename = wheel.get("filename") if wheel else None
    wheel_version = ""
    if isinstance(wheel_filename, str) and wheel_filename.startswith("yui_agent_guard-") and wheel_filename.endswith(".whl"):
        wheel_parts = wheel_filename[:-4].split("-")
        if len(wheel_parts) >= 5:
            wheel_version = wheel_parts[1]
    _error(errors, type(wheel_digest) is str and re.fullmatch(r"[0-9a-f]{64}", wheel_digest) is not None and bool(wheel_version), "TTFE candidate wheel proof is invalid")
    install_candidate = _map(install.get("candidate")) if install else None
    _error(
        errors,
        install is not None
        and install.get("report_version") == "1"
        and install_candidate is not None
        and str(install_candidate.get("name", "")).lower().replace("_", "-") == "yui-agent-guard"
        and install_candidate.get("version") == wheel_version
        and install_candidate.get("requested") is True
        and install_candidate.get("archive_sha256") == wheel_digest
        and install_candidate.get("filename") == wheel_filename,
        "TTFE pip installation is not bound to the candidate wheel",
    )
    _error(
        errors,
        runtime is not None
        and runtime.get("sys_prefix") == "<candidate-venv>"
        and _venv_label(runtime.get("sys_executable"))
        and _venv_label(runtime.get("module_origin"))
        and _venv_label(runtime.get("cli_origin"))
        and runtime.get("entrypoint") == "<candidate-venv>/bin/agent-guard"
        and str(runtime.get("distribution_name", "")).lower().replace("_", "-") == "yui-agent-guard"
        and runtime.get("distribution_version") == wheel_version,
        "TTFE runtime identity is invalid",
    )
    source_files = _manifest_files(manifests.get("source")) if manifests else None
    wheel_files = _manifest_files(manifests.get("wheel")) if manifests else None
    installed_files = _manifest_files(manifests.get("installed")) if manifests else None
    _error(errors, source_files is not None and wheel_files is not None and installed_files is not None and source_files == wheel_files == installed_files, "TTFE source, wheel, and installed package bytes disagree")
    return errors


def _revalidate_embedded_report(payload: Any) -> Mapping[str, Any]:
    """Use the public consumer again after the original replay tmpdir is gone."""

    if not isinstance(payload, Mapping):
        raise ValueError("embedded report must be an object")
    # Import lazily: ``run.py replay`` executes under ``-I`` as a standalone
    # helper, while the subsequent ``check`` runs from the candidate checkout.
    from agent_guard.consumer import load_payload, select_report_schema, validate_report

    with tempfile.TemporaryDirectory(prefix="agent-guard-ttfe-check.") as directory:
        path = Path(directory) / "report.json"
        path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        loaded = load_payload(path)
    return validate_report(loaded, select_report_schema(loaded))


def _validate_evidence(value: Any, records: Sequence[Mapping[str, Any]], *, revalidate_consumer: bool) -> list[str]:
    evidence = _map(value)
    report = _map(evidence.get("report")) if evidence else None
    if report is None:
        return ["TTFE generated evidence proof is missing"]
    errors: list[str] = []
    public_payload = report.get("payload")
    _error(errors, report.get("path") == REPORT_RELATIVE_PATH.as_posix() and report.get("fresh") is True and report.get("regular_file") is True and isinstance(public_payload, Mapping), "TTFE generated report is not fresh and complete")
    status = public_payload.get("status") if isinstance(public_payload, Mapping) else None
    _error(errors, status in ("ok", "violation"), "TTFE report status is invalid")
    conformance = _map(public_payload.get("conformance")) if isinstance(public_payload, Mapping) else None
    manifest = _map(public_payload.get("evidence_pack_manifest")) if isinstance(public_payload, Mapping) else None
    _error(errors, conformance is not None and conformance.get("schema_version") == "agent-guard.conformance.v1" and conformance.get("profile") == "recommended" and conformance.get("status") in ("ok", "violation"), "TTFE report lacks recommended conformance")
    _error(errors, manifest is not None and manifest.get("schema_version") in ("agent-guard.evidence_pack_manifest.v1", "agent-guard.evidence_pack_manifest.v2") and manifest.get("sanitized") is True, "TTFE report lacks a valid evidence-pack manifest")
    report_record = next((record for record in records if record.get("stage") == "report"), None)
    code = _int(report_record.get("exit_code")) if report_record else None
    _error(errors, code in {0, 1}, "TTFE report exit code is invalid")
    if code == 0:
        _error(errors, status == "ok", "TTFE report exit code and status disagree")
    if code == 1:
        _error(errors, status == "violation", "TTFE report exit code and status disagree")
    if revalidate_consumer and isinstance(public_payload, Mapping):
        try:
            summary = _revalidate_embedded_report(public_payload)
            _error(errors, report.get("consumer_summary") == summary, "TTFE embedded report consumer summary disagrees")
        except (ImportError, OSError, TypeError, ValueError, json.JSONDecodeError):
            errors.append("TTFE embedded report failed public consumer validation")
    return errors


def validate_result_payload(
    payload: dict[str, Any], *, max_elapsed_ms: int, revalidate_consumer: bool = True
) -> list[str]:
    """Fail closed on incomplete, stale, or unbound TTFE result evidence."""

    if not isinstance(payload, dict):
        return ["TTFE result must be a JSON object"]
    if payload.get("schema_version") == LEGACY_SCHEMA_VERSION:
        return ["TTFE result v1 lacks candidate-wheel proof; rerun the TTFE replay"]
    if payload.get("schema_version") != SCHEMA_VERSION:
        return ["unexpected TTFE schema version"]
    errors: list[str] = []
    try:
        timestamp = payload.get("generated_at")
        valid_timestamp = isinstance(timestamp, str) and timestamp.endswith("Z") and datetime.fromisoformat(timestamp).utcoffset() is not None
    except ValueError:
        valid_timestamp = False
    _error(errors, valid_timestamp, "TTFE generated timestamp is invalid")
    _error(errors, payload.get("source_doc") == "docs/quickstart-existing-repo.md", "TTFE source document is invalid")
    setup = _map(payload.get("setup"))
    _error(errors, setup is not None and setup.get("status") == "candidate-wheel" and setup.get("prebuild_excluded") is True and setup.get("temporary_workspace_cleanup") == "completed", "TTFE setup proof is invalid")
    elapsed = _int(payload.get("elapsed_ms"))
    _error(errors, elapsed is not None and elapsed >= 0, "TTFE elapsed time is invalid")
    if elapsed is not None and elapsed > max_elapsed_ms:
        errors.append("TTFE replay exceeded the configured time limit")
    _error(errors, _int(payload.get("documented_command_count")) == len(EXPECTED_DOCUMENTED_COMMANDS), "TTFE documented command count is invalid")
    record_errors, records = _validate_records(payload.get("commands"))
    errors.extend(record_errors)
    durations = [record.get("duration_ms") for record in records if record.get("documented_index") is not None]
    if elapsed is not None and all(type(duration) is int and duration >= 0 for duration in durations):
        _error(errors, elapsed >= sum(durations), "TTFE elapsed time contradicts command durations")
    raw_records = payload.get("commands")
    _error(errors, isinstance(raw_records, list) and _int(payload.get("command_count")) == len(raw_records), "TTFE command count is invalid")
    errors.extend(_validate_execution(payload.get("execution")))
    errors.extend(_validate_candidate(payload.get("candidate")))
    errors.extend(_validate_evidence(payload.get("evidence"), records, revalidate_consumer=revalidate_consumer))
    _error(errors, payload.get("first_nonzero") == _first_nonzero(records), "TTFE first nonzero summary disagrees with command records")
    failure = _failure(records)
    status = payload.get("status")
    _error(errors, status in ("ok", "failed"), "TTFE status is invalid")
    if status == "ok":
        _error(errors, failure is None and payload.get("failure_point") is None, "TTFE replay encountered a configuration or runtime error")
    else:
        errors.append("TTFE replay did not complete")
        if failure is not None:
            _error(errors, payload.get("failure_point") == failure, "TTFE failure summary disagrees with command records")
    return errors


def _strict_json(text: str) -> Any:
    """Reject duplicate keys and non-finite constants before validation."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    if len(text.encode("utf-8")) > 4 * 1024 * 1024:
        raise ValueError("TTFE JSON exceeds the input limit")
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except RecursionError:
        raise ValueError("TTFE JSON exceeds the nesting limit") from None


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _manifest_digest(files: Mapping[str, str]) -> str:
    return hashlib.sha256(json.dumps(dict(files), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _directory_manifest(root: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError("candidate package tree contains a non-regular file")
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        files[path.relative_to(root).as_posix()] = _hash_file(path)
    if not files:
        raise ValueError("candidate package tree is empty")
    return files


def _wheel_manifest(wheel: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            if member.is_dir() or not member.filename.startswith("agent_guard/"):
                continue
            relative = member.filename.removeprefix("agent_guard/")
            if not relative or relative.startswith("/") or ".." in Path(relative).parts or relative in files:
                raise ValueError("candidate wheel package layout is invalid")
            files[relative] = hashlib.sha256(archive.read(member)).hexdigest()
    if not files:
        raise ValueError("candidate wheel contains no package files")
    return files


def _safe_env(work_root: Path) -> dict[str, str]:
    """Strip inherited Python/pip settings before every replay subprocess."""

    home = work_root / "home"
    home.mkdir(parents=True, exist_ok=True)
    result = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("PYTHON") and not key.startswith("PIP_") and key != "VIRTUAL_ENV"
    }
    result.update(
        {
            "PATH": os.defpath,
            "HOME": str(home),
            "PIP_CACHE_DIR": str(work_root / "pip-cache"),
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PIP_NO_COMPILE": "1",
        }
    )
    return result


def _stage(
    records: list[dict[str, Any]],
    *,
    name: str,
    argv: Sequence[str | Path],
    display: Sequence[str],
    cwd: Path,
    env: Mapping[str, str],
    process_runner: ProcessRunner,
    clock_ms: Callable[[], int],
) -> tuple[dict[str, Any], subprocess.CompletedProcess[str] | None]:
    source_index = _STAGE_TO_DOCUMENTED_INDEX[name]
    source_command = EXPECTED_DOCUMENTED_COMMANDS[source_index - 1] if source_index else None
    started = clock_ms()
    completed: subprocess.CompletedProcess[str] | None = None
    code = 127
    try:
        completed = process_runner(
            [str(part) for part in argv],
            cwd=str(cwd),
            env=dict(env),
            capture_output=True,
            text=True,
            timeout=DEFAULT_STAGE_TIMEOUT_MS / 1000,
            check=False,
        )
        code = completed.returncode if type(completed.returncode) is int and 0 <= completed.returncode <= 255 else 127
    except subprocess.TimeoutExpired:
        code = 124
    except (OSError, ValueError):
        code = 127
    record = {
        "index": len(records) + 1,
        "stage": name,
        "documented_index": source_index,
        "documented_command": source_command,
        "executed_command": list(display),
        "exit_code": code,
        "duration_ms": max(0, clock_ms() - started),
        "timeout_ms": DEFAULT_STAGE_TIMEOUT_MS,
    }
    records.append(record)
    return record, completed


def _ok(record: Mapping[str, Any]) -> bool:
    return _int(record.get("exit_code")) == 0


def _source_revision(root: Path, env: Mapping[str, str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        cwd=str(root), env=dict(env), capture_output=True, text=True, timeout=15, check=False,
    )
    revision = result.stdout.strip()
    if result.returncode != 0 or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("unable to read candidate source revision")
    return revision


def _candidate_wheel(wheelhouse: Path) -> Path:
    candidates = sorted(wheelhouse.glob("yui_agent_guard-*.whl"))
    if len(candidates) != 1:
        raise ValueError("candidate build did not produce exactly one wheel")
    return candidates[0]


def _json_completed(completed: subprocess.CompletedProcess[str] | None) -> Mapping[str, Any]:
    if completed is None or completed.returncode != 0:
        raise ValueError("candidate verification subprocess failed")
    result = _strict_json(completed.stdout)
    if not isinstance(result, Mapping):
        raise ValueError("candidate verification subprocess returned non-object JSON")
    return result


def _relative_label(path_value: Any, root: Path, *, resolve: bool) -> str | None:
    if not isinstance(path_value, str) or not path_value:
        return None
    try:
        path = Path(path_value)
        candidate = path.resolve() if resolve else path.absolute()
        base = root.resolve() if resolve else root.absolute()
        relative = candidate.relative_to(base).as_posix()
    except (OSError, RuntimeError, ValueError):
        return None
    return "<candidate-venv>" if relative == "." else f"<candidate-venv>/{relative}"


def _report_path_ok(path: Path, fixture: Path) -> bool:
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            return False
        path.resolve(strict=True).relative_to(fixture.resolve())
        for ancestor in path.parents:
            if ancestor == fixture:
                break
            if ancestor.is_symlink():
                return False
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def _fixture(root: Path) -> Path:
    fixture = root / "fixture-repo"
    fixture.mkdir(parents=True, exist_ok=False)
    (fixture / "AGENTS.md").write_text(
        "Require approval before shell writes.\nKeep credentials redacted in public evidence.\nRun tests before reporting completion.\n",
        encoding="utf-8",
    )
    (fixture / "README.md").write_text(
        "# TTFE Fixture\n\n"
        "agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json\n"
        "agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json\n"
        "agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json\n"
        "agent-guard drift check --root . --profile recommended --schema-version v2 --json\n"
        "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --format json\n",
        encoding="utf-8",
    )
    return fixture


_IDENTITY_SCRIPT = r'''
import hashlib, importlib.metadata, json, sys
from pathlib import Path
import agent_guard, agent_guard.cli
root = Path(agent_guard.__file__).resolve().parent
files = {}
for path in sorted(root.rglob("*")):
    if path.is_dir() or path.is_symlink() or "__pycache__" in path.parts or path.suffix == ".pyc":
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    files[path.relative_to(root).as_posix()] = digest
distribution = importlib.metadata.distribution("yui-agent-guard")
print(json.dumps({"sys_prefix": sys.prefix, "sys_executable": sys.executable, "module_origin": agent_guard.__file__, "cli_origin": agent_guard.cli.__file__, "distribution_name": distribution.metadata.get("Name", ""), "distribution_version": distribution.version, "files": files}, sort_keys=True))
'''

_REPORT_SCRIPT = r'''
import json, sys
from pathlib import Path
from agent_guard.consumer import load_payload, select_report_schema, validate_report
payload = load_payload(Path(sys.argv[1]))
summary = validate_report(payload, select_report_schema(payload))
conformance = payload.get("conformance")
manifest = payload.get("evidence_pack_manifest")
if not isinstance(conformance, dict) or not isinstance(manifest, dict) or payload.get("status") == "error":
    raise ValueError("report lacks valid embedded recommended evidence")
print(json.dumps({"payload": payload, "summary": summary}, sort_keys=True))
'''


def _pip_proof(report_path: Path, wheel: Path, digest: str) -> dict[str, Any]:
    try:
        report = _strict_json(report_path.read_text(encoding="utf-8"))
        installs = report["install"]
        entry = next(
            item for item in installs
            if isinstance(item, Mapping)
            and isinstance(item.get("metadata"), Mapping)
            and str(item["metadata"].get("name", "")).lower().replace("_", "-") == "yui-agent-guard"
        )
        metadata = entry["metadata"]
        download = entry["download_info"]
        archive = download["archive_info"]
        hashes = archive.get("hashes", {})
        actual_digest = hashes.get("sha256") if isinstance(hashes, Mapping) else None
        if actual_digest is None and isinstance(archive.get("hash"), str) and archive["hash"].startswith("sha256="):
            actual_digest = archive["hash"].removeprefix("sha256=")
        url = download.get("url")
        filename = Path(urlparse(url).path).name if isinstance(url, str) else ""
        return {
            "report_version": report.get("version"),
            "candidate": {
                "name": metadata.get("name"),
                "version": metadata.get("version"),
                "requested": entry.get("requested"),
                "archive_sha256": actual_digest,
                "filename": filename,
            },
            "candidate_matches_wheel": actual_digest == digest and filename == wheel.name,
        }
    except (KeyError, OSError, StopIteration, TypeError, ValueError, json.JSONDecodeError):
        return {"report_version": "", "candidate": {}, "candidate_matches_wheel": False}


def _execution_proof() -> dict[str, Any]:
    return {
        "mode": "candidate-wheel-replay",
        "prebuild_excluded": True,
        "stage_timeout_ms": DEFAULT_STAGE_TIMEOUT_MS,
        "documented_commands": [
            {
                "index": index,
                "command": command,
                "stages": [stage for stage, source_index in _STAGE_TO_DOCUMENTED_INDEX.items() if source_index == index],
            }
            for index, command in enumerate(EXPECTED_DOCUMENTED_COMMANDS, 1)
        ],
    }


def _empty_candidate() -> dict[str, Any]:
    return {
        "source": {},
        "wheel": {},
        "install": {},
        "runtime": {},
        "package_manifests": {},
    }


def _empty_evidence() -> dict[str, Any]:
    return {"report": {}}


def _write_result(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def execute_replay(
    *,
    repo_root: Path,
    out_path: Path,
    python_bin: str | Path | None = None,
    process_runner: ProcessRunner = subprocess.run,
    clock_ms: Callable[[], int] | None = None,
    work_root: Path | None = None,
    candidate_wheel: Path | None = None,
) -> tuple[dict[str, Any], int]:
    """Run the known quickstart using only a freshly installed local wheel.

    The optional Python-level seams are intentionally not CLI options.  They
    let regression tests inject offline stage failures, a deterministic clock,
    and a supplied candidate wheel.  Supplied wheels still have to match the
    checkout package byte-for-byte before installation.
    """

    root = repo_root.resolve()
    commands = extract_bash_commands((root / "docs/quickstart-existing-repo.md").read_text(encoding="utf-8"))
    records: list[dict[str, Any]] = []
    candidate = _empty_candidate()
    evidence = _empty_evidence()
    execution = _execution_proof()
    setup = {"status": "candidate-wheel", "prebuild_excluded": True, "temporary_workspace_cleanup": "pending"}
    clock = clock_ms or (lambda: time.monotonic_ns() // 1_000_000)
    started = clock()
    diagnostic: dict[str, Any] | None = None
    temporary: tempfile.TemporaryDirectory[str] | None = None
    managed: Path | None = None
    payload: dict[str, Any]
    build_python = str(Path(python_bin or sys.executable).absolute())

    try:
        if commands != list(EXPECTED_DOCUMENTED_COMMANDS):
            raise ValueError("quickstart commands changed; TTFE replay refuses an unknown mapping")
        if work_root is None:
            temporary = tempfile.TemporaryDirectory(prefix="agent-guard-ttfe.")
            managed = Path(temporary.name)
        else:
            managed = work_root.resolve()
            managed.mkdir(parents=True, exist_ok=False)
        env = _safe_env(managed)
        wheelhouse = managed / "wheelhouse"
        wheelhouse.mkdir()
        fixture = _fixture(managed)
        venv = managed / "candidate-venv"
        candidate_python = venv / "bin/python"
        entrypoint = venv / "bin/agent-guard"
        pip_report = managed / "pip-install-report.json"
        source_files = _directory_manifest(root / "src/agent_guard")
        candidate["source"] = {"revision": _source_revision(root, env)}

        if candidate_wheel is None:
            build, _ = _stage(
                records, name="build-candidate",
                argv=[build_python, "-I", "-m", "pip", "wheel", "--no-build-isolation", "--no-deps", "--wheel-dir", wheelhouse, root],
                display=["<build-python>", "-I", "-m", "pip", "wheel", "--no-build-isolation", "--no-deps", "--wheel-dir", "<wheelhouse>", "<checkout>"],
                cwd=root, env=env, process_runner=process_runner, clock_ms=clock,
            )
            if not _ok(build):
                raise RuntimeError("candidate wheel build failed")
            wheel = _candidate_wheel(wheelhouse)
        else:
            wheel = candidate_wheel.resolve()
            records.append({
                "index": 1, "stage": "build-candidate", "documented_index": None, "documented_command": None,
                "executed_command": ["<test-supplied-candidate-wheel>"], "exit_code": 0 if wheel.is_file() else 1,
                "duration_ms": 0, "timeout_ms": DEFAULT_STAGE_TIMEOUT_MS,
            })
            if not wheel.is_file():
                raise RuntimeError("test candidate wheel is missing")
        wheel_digest = _hash_file(wheel)
        wheel_files = _wheel_manifest(wheel)
        candidate["wheel"] = {"filename": wheel.name, "sha256": wheel_digest}
        candidate["package_manifests"] = {
            "source": {"files": source_files, "sha256": _manifest_digest(source_files), "file_count": len(source_files)},
            "wheel": {"files": wheel_files, "sha256": _manifest_digest(wheel_files), "file_count": len(wheel_files)},
            "installed": {},
        }
        if source_files != wheel_files:
            raise RuntimeError("candidate wheel package bytes do not match the checkout")

        inspect, inspect_completed = _stage(
            records, name="inspect-pyyaml", argv=[build_python, "-I", "-c", "import yaml; print(yaml.__version__)"],
            display=["<build-python>", "-I", "-c", "import yaml; print(yaml.__version__)"], cwd=root, env=env,
            process_runner=process_runner, clock_ms=clock,
        )
        if not _ok(inspect) or inspect_completed is None or not re.fullmatch(r"[0-9]+(?:\.[0-9A-Za-z]+)+", inspect_completed.stdout.strip()):
            raise RuntimeError("installed PyYAML version inspection failed")
        pyyaml_version = inspect_completed.stdout.strip()
        prepare, _ = _stage(
            records, name="prepare-pyyaml",
            argv=[build_python, "-I", "-m", "pip", "wheel", "--no-deps", "--wheel-dir", wheelhouse, f"PyYAML=={pyyaml_version}"],
            display=["<build-python>", "-I", "-m", "pip", "wheel", "--no-deps", "--wheel-dir", "<wheelhouse>", "PyYAML==<installed-version>"],
            cwd=root, env=env, process_runner=process_runner, clock_ms=clock,
        )
        if not _ok(prepare):
            raise RuntimeError("PyYAML wheel preparation failed")
        # Preparation is recorded, but the onboarding clock starts here.
        started = clock()
        bootstrap, _ = _stage(
            records, name="bootstrap", argv=[build_python, "-I", "-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 11, 4) else 1)"],
            display=["<build-python>", "-I", "-c", "python-version-gate"], cwd=fixture, env=env,
            process_runner=process_runner, clock_ms=clock,
        )
        if not _ok(bootstrap):
            raise RuntimeError("bootstrap version check failed")
        venv_stage, _ = _stage(
            records, name="venv", argv=[build_python, "-I", "-m", "venv", venv],
            display=["<build-python>", "-I", "-m", "venv", "<candidate-venv>"], cwd=fixture, env=env,
            process_runner=process_runner, clock_ms=clock,
        )
        if not _ok(venv_stage) or not candidate_python.is_file():
            raise RuntimeError("candidate virtual environment creation failed")
        install, _ = _stage(
            records, name="install",
            argv=[candidate_python, "-I", "-m", "pip", "install", "--no-index", "--find-links", wheelhouse, "--report", pip_report, wheel],
            display=["<candidate-python>", "-I", "-m", "pip", "install", "--no-index", "--find-links", "<wheelhouse>", "--report", "<pip-install-report>", "<candidate-wheel>"],
            cwd=fixture, env=env, process_runner=process_runner, clock_ms=clock,
        )
        install_proof = _pip_proof(pip_report, wheel, wheel_digest)
        install_matches_wheel = install_proof.pop("candidate_matches_wheel", False)
        candidate["install"] = install_proof
        if not _ok(install) or install_matches_wheel is not True:
            raise RuntimeError("candidate wheel installation failed or was not bound to the built wheel")
        identity_stage, identity_completed = _stage(
            records, name="verify-identity", argv=[candidate_python, "-I", "-c", _IDENTITY_SCRIPT],
            display=["<candidate-python>", "-I", "-c", "candidate-identity-proof"], cwd=fixture, env=env,
            process_runner=process_runner, clock_ms=clock,
        )
        if not _ok(identity_stage):
            raise RuntimeError("candidate identity command failed")
        identity = _json_completed(identity_completed)
        installed_value = identity.get("files")
        if not isinstance(installed_value, Mapping) or not all(type(k) is str and type(v) is str and re.fullmatch(r"[0-9a-f]{64}", v) for k, v in installed_value.items()):
            raise RuntimeError("candidate installed package manifest is invalid")
        installed_files = dict(installed_value)
        source_label = _relative_label(identity.get("sys_prefix"), venv, resolve=True)
        executable_label = _relative_label(identity.get("sys_executable"), venv, resolve=False)
        module_label = _relative_label(identity.get("module_origin"), venv, resolve=True)
        cli_label = _relative_label(identity.get("cli_origin"), venv, resolve=True)
        if source_label != "<candidate-venv>" or executable_label is None or module_label is None or cli_label is None or not entrypoint.is_file() or entrypoint.is_symlink():
            raise RuntimeError("candidate runtime was not isolated in the new virtual environment")
        candidate["runtime"] = {
            "sys_prefix": source_label,
            "sys_executable": executable_label,
            "module_origin": module_label,
            "cli_origin": cli_label,
            "entrypoint": "<candidate-venv>/bin/agent-guard",
            "distribution_name": identity.get("distribution_name"),
            "distribution_version": identity.get("distribution_version"),
        }
        candidate["package_manifests"]["installed"] = {"files": installed_files, "sha256": _manifest_digest(installed_files), "file_count": len(installed_files)}
        if wheel_files != installed_files:
            raise RuntimeError("installed package bytes do not match candidate wheel")

        init_print, _ = _stage(
            records, name="init-print", argv=[entrypoint, "init", "--root", ".", "--print"],
            display=["<candidate-entrypoint>", "init", "--root", ".", "--print"], cwd=fixture, env=env,
            process_runner=process_runner, clock_ms=clock,
        )
        if not _ok(init_print):
            raise RuntimeError("candidate init preview failed")
        init_write, _ = _stage(
            records, name="init-write", argv=[entrypoint, "init", "--root", ".", "--write"],
            display=["<candidate-entrypoint>", "init", "--root", ".", "--write"], cwd=fixture, env=env,
            process_runner=process_runner, clock_ms=clock,
        )
        if not _ok(init_write):
            raise RuntimeError("candidate init write failed")
        report_path = fixture / REPORT_RELATIVE_PATH
        if os.path.lexists(report_path) or report_path.parent.is_symlink():
            raise RuntimeError("report path existed before the report stage")
        report, _ = _stage(
            records, name="report",
            argv=[entrypoint, "report", "--root", ".", "--context-policy", ".agent-guard/context-policy.yaml", "--evidence-preset", "recommended", "--format", "json", "--output", REPORT_RELATIVE_PATH, "--stderr-summary"],
            display=["<candidate-entrypoint>", "report", "--root", ".", "--context-policy", ".agent-guard/context-policy.yaml", "--evidence-preset", "recommended", "--format", "json", "--output", "<fixture-report>", "--stderr-summary"],
            cwd=fixture, env=env, process_runner=process_runner, clock_ms=clock,
        )
        if _int(report.get("exit_code")) not in {0, 1} or not _report_path_ok(report_path, fixture):
            evidence["report"] = {"path": REPORT_RELATIVE_PATH.as_posix(), "fresh": not os.path.lexists(report_path), "regular_file": _report_path_ok(report_path, fixture)}
            raise RuntimeError("candidate report did not create fresh evidence")
        validate, validated = _stage(
            records, name="validate-report", argv=[candidate_python, "-I", "-c", _REPORT_SCRIPT, report_path],
            display=["<candidate-python>", "-I", "-c", "validate-public-report", "<fixture-report>"], cwd=fixture, env=env,
            process_runner=process_runner, clock_ms=clock,
        )
        if not _ok(validate):
            raise RuntimeError("candidate report consumer validation failed")
        report_proof = _json_completed(validated)
        full_report = report_proof.get("payload")
        if not isinstance(full_report, Mapping):
            raise RuntimeError("candidate report proof has no public report payload")
        evidence["report"] = {
            "path": REPORT_RELATIVE_PATH.as_posix(), "fresh": True, "regular_file": True,
            "payload": full_report, "consumer_summary": report_proof.get("summary"),
        }
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        # Exception text may contain private paths or resolver URLs. Keep only
        # the stage and exception class in the durable diagnostic.
        diagnostic = {"stage": records[-1]["stage"] if records else "prepare-replay", "reason": type(error).__name__}
    finally:
        elapsed = max(0, clock() - started)
        if temporary is not None:
            try:
                temporary.cleanup()
                setup["temporary_workspace_cleanup"] = "completed"
            except OSError:
                setup["temporary_workspace_cleanup"] = "failed"
                diagnostic = {"stage": "cleanup", "reason": "OSError"}
        elif managed is not None:
            # Caller-owned work roots are a Python-only test seam, not proof of
            # cleanup. Never issue a successful benchmark for retained state.
            setup["temporary_workspace_cleanup"] = "retained-test-workspace"
        failure = _failure(records) or diagnostic
        complete = len(records) == len(EXPECTED_STAGES) and failure is None and isinstance(evidence.get("report", {}).get("payload"), Mapping)
        payload = build_result_payload(
            source_doc="docs/quickstart-existing-repo.md", commands=list(EXPECTED_DOCUMENTED_COMMANDS), records=records,
            elapsed_ms=elapsed, setup=setup, execution=execution, candidate=candidate, evidence=evidence,
            status="ok" if complete else "failed", failure_point=failure,
        )
        # A runner cannot claim success just because it wrote JSON.
        if validate_result_payload(payload, max_elapsed_ms=DEFAULT_MAX_ELAPSED_MS, revalidate_consumer=False) and payload["status"] == "ok":
            payload["status"] = "failed"
            payload["failure_point"] = {"stage": "validate-result", "reason": "inconsistent proof"}
        _write_result(out_path, payload)
    return payload, 0 if not validate_result_payload(payload, max_elapsed_ms=DEFAULT_MAX_ELAPSED_MS, revalidate_consumer=False) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--source", required=True)
    result_parser = subparsers.add_parser("result")
    result_parser.add_argument("--source", required=True)
    result_parser.add_argument("--records", required=True)
    result_parser.add_argument("--out", required=True)
    result_parser.add_argument("--elapsed-ms", required=True, type=int)
    result_parser.add_argument("--setup", required=True)
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--input", required=True)
    check_parser.add_argument("--max-elapsed-ms", default=DEFAULT_MAX_ELAPSED_MS, type=int)
    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("--repo-root", required=True)
    replay_parser.add_argument("--out", required=True)
    replay_parser.add_argument("--python", dest="python_bin", default=sys.executable)
    args = parser.parse_args(argv)
    if args.command == "check":
        try:
            payload = _strict_json(Path(args.input).read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            print("TTFE gate failed: unable to read strict result JSON")
            return 1
        errors = validate_result_payload(payload, max_elapsed_ms=args.max_elapsed_ms)
        if errors:
            for error in errors:
                print(f"TTFE gate failed: {error}")
            return 1
        print(f"TTFE gate passed: elapsed_ms={payload['elapsed_ms']} commands={payload['documented_command_count']}")
        return 0
    source = Path(args.source) if hasattr(args, "source") else None
    if args.command == "list":
        for command in extract_bash_commands(source.read_text(encoding="utf-8")):
            print(command)
        return 0
    if args.command == "replay":
        _, code = execute_replay(repo_root=Path(args.repo_root), out_path=Path(args.out), python_bin=args.python_bin)
        return code
    try:
        setup = _strict_json(args.setup)
        if not isinstance(setup, dict):
            raise ValueError("setup is not an object")
        payload = build_result_payload(source_doc=os.environ.get("AGENT_GUARD_TTFE_SOURCE_LABEL", source.as_posix()), commands=extract_bash_commands(source.read_text(encoding="utf-8")), records=load_jsonl(Path(args.records)), elapsed_ms=args.elapsed_ms, setup=setup)
        _write_result(Path(args.out), payload)
        return 0 if payload["status"] == "ok" else 1
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        print("TTFE result failed: invalid result arguments")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
