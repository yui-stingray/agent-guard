"""Where: src/agent_guard/evidence_pack.py
What: sanitized manifest for PR-reviewable agent-guard evidence packs.
Why: reviewers need a compact index of evidence artifacts without raw content.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .public_redaction import contains_raw_url, sanitize_public_mapping

EVIDENCE_PACK_MANIFEST_SCHEMA_VERSION = "agent-guard.evidence_pack_manifest.v1"
EVIDENCE_PACK_MANIFEST_SCHEMA_VERSION_V2 = "agent-guard.evidence_pack_manifest.v2"
REPORT_EVIDENCE_SCHEMA_VERSION_V2 = "agent-guard.report_evidence.v2"
AGENT_POLICY_AUDIT_EVENT_BINDING_SCHEMA_VERSION = (
    "agent-guard.agent_policy_audit_event_binding.v1"
)
AGENT_POLICY_AUDIT_EVENT_CANONICALIZATION = "canonical-json-v1"
AGENT_POLICY_AUDIT_EVENT_DIGEST_ALGORITHM = "sha256"
AGENT_POLICY_AUDIT_EVENT_DIGEST_ENCODING = "base32-lower-no-padding"
MAX_AGENT_POLICY_AUDIT_EVENT_BYTES = 1 * 1024 * 1024
ERROR_AUDIT_EVENT_INVALID = "agent-policy audit event is not valid bounded JSON"
ERROR_AUDIT_EVENT_PATH = "agent-policy audit event must be a repository file"
ERROR_AUDIT_EVENT_PROFILE = "agent-policy audit event profile is invalid"
ERROR_AUDIT_EVENT_REPORT_VERSION = (
    "bound agent-policy audit events require report evidence v2"
)
ERROR_AUDIT_EVENT_BINDING_REQUIRED = (
    "report evidence v2 requires bound agent-policy audit events"
)
ERROR_EVIDENCE_PACK_ARTIFACT_PATH = "evidence-pack artifact path is invalid"
PUBLIC_AGENT_POLICY_AUDIT_EVENT_PROFILE_V1 = (
    "agent-guard.public_agent_policy_audit_event.v1"
)
SUPPORTED_AGENT_POLICY_AUDIT_EVENT_PROFILES = frozenset(
    {PUBLIC_AGENT_POLICY_AUDIT_EVENT_PROFILE_V1}
)
_AUDIT_EVENT_PROFILE_RE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_AUDIT_EVENT_DIGEST_RE = re.compile(r"^b[a-z2-7]{52}$")
_AUDIT_EVENT_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._:@/+~-]+$")
SANITIZED_REPOSITORY_RELATIVE_PATH_PATTERN = (
    r"^(?!.*(?:sk-[A-Za-z0-9_-]{16,}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"ASIA[0-9A-Z]{16}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----))"
    r"(?!.*[A-Fa-f0-9]{64})"
    r"(?!.*\s)"
    r"(?!/)"
    r"(?!.*:)"
    r"(?!.*\\)"
    r"(?!.*//)"
    r"(?!.*\/$)"
    r"(?!\.{1,2}(?:/|$))"
    r"(?!.*\/\.{1,2}(?:/|$))"
    r"[\u0021-\u007E]+$"
)
_SANITIZED_REPOSITORY_RELATIVE_PATH_RE = re.compile(
    SANITIZED_REPOSITORY_RELATIVE_PATH_PATTERN
)
_AUDIT_EVENT_DECISION_MODES = frozenset(
    {"deny", "require_approval", "auto_allow"}
)
_AUDIT_EVENT_DECISION_REASONS = frozenset(
    {
        "hard_guardrail",
        "repo_policy",
        "default_mode",
        "condition_match",
        "no_match",
    }
)


class _JSONNumber(str):
    """A parser-validated JSON number retained without binary-float coercion."""


def safe_artifact_path(path: str, *, root: Path | None = None) -> str:
    text = str(path).strip()
    if not text:
        return ""
    if contains_raw_url(text):
        return "<redacted-url>"
    windows_path = PureWindowsPath(text)
    if windows_path.is_absolute() or windows_path.drive or text.startswith("\\\\"):
        return windows_path.name or "<external-artifact>"
    raw = Path(text)
    if raw.is_absolute() and root is not None:
        try:
            return raw.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
        except ValueError:
            pass
    if raw.is_absolute() or ".." in raw.parts:
        return raw.name or "<external-artifact>"
    return raw.as_posix()


def validate_agent_policy_audit_event_profile(profile: str) -> str:
    normalized = str(profile).strip()
    if (
        not _AUDIT_EVENT_PROFILE_RE.fullmatch(normalized)
        or normalized not in SUPPORTED_AGENT_POLICY_AUDIT_EVENT_PROFILES
    ):
        raise ValueError(ERROR_AUDIT_EVENT_PROFILE)
    public_profile = {"event_profile": normalized}
    try:
        sanitized_profile = sanitize_public_mapping(public_profile)
    except ValueError:
        raise ValueError(ERROR_AUDIT_EVENT_PROFILE) from None
    if sanitized_profile != public_profile:
        raise ValueError(ERROR_AUDIT_EVENT_PROFILE)
    return normalized


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(ERROR_AUDIT_EVENT_INVALID)
        payload[key] = value
    return payload


def _reject_nonstandard_json_constant(_value: str) -> None:
    raise ValueError(ERROR_AUDIT_EVENT_INVALID)


def _canonical_json_value(value: object) -> bytes:
    if isinstance(value, _JSONNumber):
        return value.encode("ascii")
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(_canonical_json_value(item) for item in value) + b"]"
    if isinstance(value, dict):
        members: list[bytes] = []
        for key in sorted(value):
            if not isinstance(key, str):
                raise TypeError(ERROR_AUDIT_EVENT_INVALID)
            members.append(
                json.dumps(key, ensure_ascii=False).encode("utf-8")
                + b":"
                + _canonical_json_value(value[key])
            )
        return b"{" + b",".join(members) + b"}"
    raise ValueError(ERROR_AUDIT_EVENT_INVALID)


def _is_json_string(value: object) -> bool:
    return type(value) is str


def _contains_control_character(value: str) -> bool:
    return any(ord(character) <= 0x1F for character in value)


def is_sanitized_repository_relative_path(value: object) -> bool:
    if type(value) is not str or not _SANITIZED_REPOSITORY_RELATIVE_PATH_RE.fullmatch(
        value
    ):
        return False
    posix_path = PurePosixPath(value)
    return posix_path.as_posix() == value


def _normalized_repository_relative_artifact_path(
    value: object,
    *,
    root: Path | None,
) -> str | None:
    if is_sanitized_repository_relative_path(value):
        return value
    if type(value) is not str or root is None:
        return None
    try:
        candidate = Path(value)
        if not candidate.is_absolute():
            return None
        relative = candidate.resolve(strict=False).relative_to(
            root.resolve(strict=True)
        ).as_posix()
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    return relative if is_sanitized_repository_relative_path(relative) else None


def _validate_public_agent_policy_audit_event_v1(payload: dict[str, Any]) -> None:
    required_fields = {"repo", "capability", "context", "decision"}
    optional_fields = {"session_id", "command", "path"}
    if not required_fields <= set(payload) or not set(payload) <= (
        required_fields | optional_fields
    ):
        raise ValueError(ERROR_AUDIT_EVENT_INVALID)

    for field in ("repo", "capability"):
        value = payload.get(field)
        if not _is_json_string(value) or not value:
            raise ValueError(ERROR_AUDIT_EVENT_INVALID)
    if not isinstance(payload.get("context"), dict):
        raise ValueError(ERROR_AUDIT_EVENT_INVALID)

    decision = payload.get("decision")
    if not isinstance(decision, dict) or set(decision) != {
        "mode",
        "reason",
        "matched_repo",
    }:
        raise ValueError(ERROR_AUDIT_EVENT_INVALID)
    mode = decision.get("mode")
    reason = decision.get("reason")
    matched_repo = decision.get("matched_repo")
    if not _is_json_string(mode) or mode not in _AUDIT_EVENT_DECISION_MODES:
        raise ValueError(ERROR_AUDIT_EVENT_INVALID)
    if not _is_json_string(reason) or reason not in _AUDIT_EVENT_DECISION_REASONS:
        raise ValueError(ERROR_AUDIT_EVENT_INVALID)
    if matched_repo is not None and (
        not _is_json_string(matched_repo)
        or not matched_repo
        or len(matched_repo) > 256
    ):
        raise ValueError(ERROR_AUDIT_EVENT_INVALID)

    if "session_id" in payload:
        session_id = payload["session_id"]
        if (
            not _is_json_string(session_id)
            or not 1 <= len(session_id) <= 256
            or not _AUDIT_EVENT_SESSION_ID_RE.fullmatch(session_id)
        ):
            raise ValueError(ERROR_AUDIT_EVENT_INVALID)
    if "command" in payload:
        command = payload["command"]
        if (
            not _is_json_string(command)
            or not 1 <= len(command) <= 4096
            or _contains_control_character(command)
        ):
            raise ValueError(ERROR_AUDIT_EVENT_INVALID)
    if "path" in payload:
        event_path = payload["path"]
        if (
            not _is_json_string(event_path)
            or not 1 <= len(event_path) <= 1024
            or not is_sanitized_repository_relative_path(event_path)
        ):
            raise ValueError(ERROR_AUDIT_EVENT_INVALID)


def _validate_agent_policy_audit_event_payload(
    payload: dict[str, Any],
    *,
    event_profile: str,
) -> None:
    if event_profile == PUBLIC_AGENT_POLICY_AUDIT_EVENT_PROFILE_V1:
        _validate_public_agent_policy_audit_event_v1(payload)
        return
    raise ValueError(ERROR_AUDIT_EVENT_PROFILE)


def _repo_relative_audit_event_path(path: Path, repo_root: Path) -> tuple[Path, Path]:
    """Return a lexical in-root path without dereferencing its components."""

    try:
        lexical_root = Path(os.path.abspath(repo_root))
        resolved_root = repo_root.resolve(strict=True)
        candidate = path if path.is_absolute() else lexical_root / path
        lexical_candidate = Path(os.path.abspath(candidate))
        try:
            relative_path = lexical_candidate.relative_to(lexical_root)
        except ValueError:
            relative_path = lexical_candidate.relative_to(resolved_root)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ValueError(ERROR_AUDIT_EVENT_PATH) from None
    if not relative_path.parts:
        raise ValueError(ERROR_AUDIT_EVENT_PATH)
    return resolved_root, relative_path


def _open_agent_policy_audit_event_posix(repo_root: Path, relative_path: Path) -> int:
    """Open an in-repository regular file without following any path component."""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if (
        not nofollow
        or not directory
        or os.open not in os.supports_dir_fd
        or relative_path.is_absolute()
        or not relative_path.parts
        or any(component in {".", ".."} for component in relative_path.parts)
    ):
        raise ValueError(ERROR_AUDIT_EVENT_PATH)

    directory_flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    directory_fd: int | None = None
    file_fd: int | None = None
    try:
        directory_fd = os.open(repo_root, directory_flags)
        for component in relative_path.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(relative_path.parts[-1], file_flags, dir_fd=directory_fd)
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise OSError
        return file_fd
    except (OSError, TypeError, ValueError):
        if file_fd is not None:
            os.close(file_fd)
        raise ValueError(ERROR_AUDIT_EVENT_PATH) from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def _open_exact_agent_policy_audit_event_posix(path: Path) -> int:
    """Open the exact supplied regular file without following its final component."""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise ValueError(ERROR_AUDIT_EVENT_PATH)
    file_fd: int | None = None
    try:
        file_fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise OSError
        return file_fd
    except (OSError, TypeError, ValueError):
        if file_fd is not None:
            os.close(file_fd)
        raise ValueError(ERROR_AUDIT_EVENT_PATH) from None


def _windows_final_handle_path(file_fd: int) -> str:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    get_final_path = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
    get_final_path.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    get_final_path.restype = wintypes.DWORD
    handle = msvcrt.get_osfhandle(file_fd)
    capacity = 512
    while capacity <= 32_768:
        buffer = ctypes.create_unicode_buffer(capacity)
        length = get_final_path(handle, buffer, capacity, 0)
        if length == 0:
            raise OSError
        if length < capacity:
            final_path = buffer.value
            if final_path.startswith("\\\\?\\UNC\\"):
                return "\\\\" + final_path[8:]
            if final_path.startswith("\\\\?\\"):
                return final_path[4:]
            return final_path
        capacity = length
    raise OSError


def _open_agent_policy_audit_event_windows(
    path: Path,
    *,
    repo_root: Path | None,
) -> int:
    """Open a regular file, reject path redirection, and enforce an optional root."""

    file_fd: int | None = None
    try:
        requested_path = os.path.normcase(os.path.normpath(os.path.abspath(path)))
        file_fd = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0),
        )
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise OSError
        final_path = os.path.normcase(os.path.normpath(_windows_final_handle_path(file_fd)))
        if final_path != requested_path:
            raise OSError
        if repo_root is not None:
            normalized_root = os.path.normcase(os.path.normpath(str(repo_root)))
            if os.path.commonpath((normalized_root, final_path)) != normalized_root:
                raise OSError
        return file_fd
    except (OSError, TypeError, ValueError):
        if file_fd is not None:
            os.close(file_fd)
        raise ValueError(ERROR_AUDIT_EVENT_PATH) from None


def _open_agent_policy_audit_event(
    path: Path,
    *,
    repo_root: Path | None,
) -> tuple[int, str | None]:
    if repo_root is None:
        if os.name == "nt":
            return _open_agent_policy_audit_event_windows(path, repo_root=None), None
        return _open_exact_agent_policy_audit_event_posix(path), None

    resolved_root, relative_path = _repo_relative_audit_event_path(path, repo_root)
    if os.name == "nt":
        file_fd = _open_agent_policy_audit_event_windows(
            resolved_root / relative_path,
            repo_root=resolved_root,
        )
    else:
        file_fd = _open_agent_policy_audit_event_posix(resolved_root, relative_path)
    return file_fd, relative_path.as_posix()


def _read_agent_policy_audit_event(
    path: Path,
    *,
    repo_root: Path | None,
) -> tuple[bytes, str | None]:
    file_fd, relative_path = _open_agent_policy_audit_event(path, repo_root=repo_root)
    try:
        handle = os.fdopen(file_fd, "rb")
    except OSError:
        try:
            os.close(file_fd)
        except OSError:
            pass
        raise ValueError(ERROR_AUDIT_EVENT_PATH) from None
    try:
        with handle:
            raw = handle.read(MAX_AGENT_POLICY_AUDIT_EVENT_BYTES + 1)
    except OSError:
        raise ValueError(ERROR_AUDIT_EVENT_PATH) from None
    if len(raw) > MAX_AGENT_POLICY_AUDIT_EVENT_BYTES:
        raise ValueError(ERROR_AUDIT_EVENT_INVALID)
    return raw, relative_path


def _canonical_agent_policy_audit_event(raw: bytes, *, event_profile: str) -> bytes:
    try:
        text = raw.decode("utf-8")
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonstandard_json_constant,
            parse_float=_JSONNumber,
            parse_int=_JSONNumber,
        )
        if not isinstance(payload, dict):
            raise TypeError(ERROR_AUDIT_EVENT_INVALID)
        _validate_agent_policy_audit_event_payload(
            payload,
            event_profile=event_profile,
        )
        canonical = _canonical_json_value(payload)
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise ValueError(ERROR_AUDIT_EVENT_INVALID) from None
    return canonical


def _build_agent_policy_audit_event_binding(
    path: Path,
    *,
    event_profile: str,
    repo_root: Path | None,
) -> tuple[dict[str, str], str | None]:
    profile = validate_agent_policy_audit_event_profile(event_profile)
    raw, relative_path = _read_agent_policy_audit_event(path, repo_root=repo_root)
    canonical = _canonical_agent_policy_audit_event(raw, event_profile=profile)
    domain = (
        AGENT_POLICY_AUDIT_EVENT_BINDING_SCHEMA_VERSION.encode("ascii")
        + b"\0"
        + profile.encode("ascii")
        + b"\0"
        + canonical
    )
    digest = (
        "b"
        + base64.b32encode(hashlib.sha256(domain).digest())
        .decode("ascii")
        .rstrip("=")
        .lower()
    )
    return (
        {
            "schema_version": AGENT_POLICY_AUDIT_EVENT_BINDING_SCHEMA_VERSION,
            "event_profile": profile,
            "canonicalization": AGENT_POLICY_AUDIT_EVENT_CANONICALIZATION,
            "digest_algorithm": AGENT_POLICY_AUDIT_EVENT_DIGEST_ALGORITHM,
            "digest_encoding": AGENT_POLICY_AUDIT_EVENT_DIGEST_ENCODING,
            "digest": digest,
        },
        relative_path,
    )


def build_agent_policy_audit_event_binding(
    path: Path,
    *,
    event_profile: str,
    repo_root: Path | None = None,
) -> dict[str, str]:
    binding, _ = _build_agent_policy_audit_event_binding(
        path,
        event_profile=event_profile,
        repo_root=repo_root,
    )
    return binding


def validate_agent_policy_audit_event_binding_shape(binding: object) -> dict[str, str]:
    if not isinstance(binding, dict) or set(binding) != {
        "schema_version",
        "event_profile",
        "canonicalization",
        "digest_algorithm",
        "digest_encoding",
        "digest",
    }:
        raise ValueError(ERROR_AUDIT_EVENT_INVALID)
    if binding.get("schema_version") != AGENT_POLICY_AUDIT_EVENT_BINDING_SCHEMA_VERSION:
        raise ValueError(ERROR_AUDIT_EVENT_INVALID)
    profile = validate_agent_policy_audit_event_profile(str(binding.get("event_profile", "")))
    if (
        binding.get("canonicalization") != AGENT_POLICY_AUDIT_EVENT_CANONICALIZATION
        or binding.get("digest_algorithm") != AGENT_POLICY_AUDIT_EVENT_DIGEST_ALGORITHM
        or binding.get("digest_encoding") != AGENT_POLICY_AUDIT_EVENT_DIGEST_ENCODING
        or not _AUDIT_EVENT_DIGEST_RE.fullmatch(str(binding.get("digest", "")))
    ):
        raise ValueError(ERROR_AUDIT_EVENT_INVALID)
    return {key: str(value) for key, value in binding.items()} | {"event_profile": profile}


def _validate_agent_policy_audit_event_artifact_shape(
    artifact: object,
    *,
    root: Path | None,
) -> dict[str, object]:
    if not isinstance(artifact, dict) or set(artifact) != {
        "path",
        "role",
        "content_binding",
    }:
        raise ValueError(ERROR_AUDIT_EVENT_INVALID)
    if artifact.get("role") != "agent-policy-audit-event":
        raise ValueError(ERROR_AUDIT_EVENT_INVALID)
    path = artifact.get("path")
    if not isinstance(path, str):
        raise TypeError(ERROR_AUDIT_EVENT_INVALID)
    if (
        not is_sanitized_repository_relative_path(path)
        or safe_artifact_path(path, root=root) != path
    ):
        raise ValueError(ERROR_AUDIT_EVENT_INVALID)
    binding = validate_agent_policy_audit_event_binding_shape(
        artifact.get("content_binding")
    )
    return {
        "path": path,
        "role": "agent-policy-audit-event",
        "content_binding": binding,
    }


def build_agent_policy_audit_event_artifacts(
    paths: list[str],
    *,
    event_profile: str,
    root: Path,
) -> list[dict[str, object]]:
    if not paths:
        if str(event_profile).strip():
            raise ValueError(ERROR_AUDIT_EVENT_PROFILE)
        return []
    profile = validate_agent_policy_audit_event_profile(event_profile)
    artifacts: list[dict[str, object]] = []
    for raw_path in paths:
        try:
            candidate = Path(raw_path)
        except (TypeError, ValueError):
            raise ValueError(ERROR_AUDIT_EVENT_PATH) from None
        binding, relative_path = _build_agent_policy_audit_event_binding(
            candidate,
            event_profile=profile,
            repo_root=root,
        )
        if relative_path is None:
            raise ValueError(ERROR_AUDIT_EVENT_PATH)
        artifacts.append(
            {
                "path": relative_path,
                "role": "agent-policy-audit-event",
                "content_binding": binding,
            }
        )
    return artifacts


def build_evidence_pack_manifest(
    *,
    report_payload: dict[str, object],
    artifact_paths: list[str] | None = None,
    agent_policy_audit_event_paths: list[str] | None = None,
    agent_policy_audit_event_profile: str = "",
    agent_policy_audit_event_artifacts: list[dict[str, object]] | None = None,
    root: Path | None = None,
) -> dict[str, object]:
    report = report_payload.get("report", {})
    summary = report_payload.get("summary", {})
    evidence_coverage = report_payload.get("evidence_coverage", {})
    conformance = report_payload.get("conformance", {})

    gates: list[dict[str, object]] = []
    if isinstance(evidence_coverage, dict):
        raw_gates = evidence_coverage.get("gates", [])
        if isinstance(raw_gates, list):
            for item in raw_gates:
                if not isinstance(item, dict):
                    continue
                gates.append(
                    {
                        "gate": item.get("gate", ""),
                        "status": item.get("status", ""),
                        "finding_count": item.get("finding_count", 0),
                    }
                )

    audit_event_artifacts: list[dict[str, object]] = []
    if agent_policy_audit_event_artifacts is not None:
        if agent_policy_audit_event_paths:
            raise ValueError(ERROR_AUDIT_EVENT_INVALID)
        audit_event_artifacts = [
            _validate_agent_policy_audit_event_artifact_shape(artifact, root=root)
            for artifact in agent_policy_audit_event_artifacts
        ]
        if (
            not audit_event_artifacts
            and str(agent_policy_audit_event_profile).strip()
        ):
            raise ValueError(ERROR_AUDIT_EVENT_PROFILE)
    elif agent_policy_audit_event_paths:
        if root is None:
            raise ValueError(ERROR_AUDIT_EVENT_PATH)
        audit_event_artifacts = build_agent_policy_audit_event_artifacts(
            list(agent_policy_audit_event_paths),
            event_profile=agent_policy_audit_event_profile,
            root=root,
        )
    elif str(agent_policy_audit_event_profile).strip():
        raise ValueError(ERROR_AUDIT_EVENT_PROFILE)
    report_metadata = report_payload.get("report")
    report_schema_version = (
        report_metadata.get("schema_version")
        if isinstance(report_metadata, dict)
        else ""
    )
    if audit_event_artifacts:
        if report_schema_version != REPORT_EVIDENCE_SCHEMA_VERSION_V2:
            raise ValueError(ERROR_AUDIT_EVENT_REPORT_VERSION)
    elif report_schema_version == REPORT_EVIDENCE_SCHEMA_VERSION_V2:
        raise ValueError(ERROR_AUDIT_EVENT_BINDING_REQUIRED)

    artifacts: list[dict[str, object]] = []
    for path in artifact_paths or []:
        if audit_event_artifacts:
            safe_path = _normalized_repository_relative_artifact_path(
                path,
                root=root,
            )
            if safe_path is None:
                raise ValueError(ERROR_EVIDENCE_PACK_ARTIFACT_PATH)
        else:
            safe_path = safe_artifact_path(path, root=root)
        if safe_path:
            artifacts.append({"path": safe_path, "role": "report"})
    artifacts.extend(audit_event_artifacts)

    manifest: dict[str, object] = {
        "schema_version": (
            EVIDENCE_PACK_MANIFEST_SCHEMA_VERSION_V2
            if audit_event_artifacts
            else EVIDENCE_PACK_MANIFEST_SCHEMA_VERSION
        ),
        "tool": report_payload.get("tool", {}),
        "sanitized": True,
        "report": {
            "schema_version": report.get("schema_version", "") if isinstance(report, dict) else "",
            "format": report.get("format", "") if isinstance(report, dict) else "",
            "scope": report.get("scope", "") if isinstance(report, dict) else "",
            "status": report_payload.get("status", ""),
            "finding_count": report_payload.get("finding_count", 0),
        },
        "summary": {
            "gate_count": evidence_coverage.get("gate_count", 0) if isinstance(evidence_coverage, dict) else 0,
            "enabled_gate_count": (
                evidence_coverage.get("enabled_count", 0) if isinstance(evidence_coverage, dict) else 0
            ),
            "missing_gate_count": (
                evidence_coverage.get("missing_count", 0) if isinstance(evidence_coverage, dict) else 0
            ),
            "failing_gate_count": (
                evidence_coverage.get("failing_count", 0) if isinstance(evidence_coverage, dict) else 0
            ),
            "surface_count": summary.get("surface_count", 0) if isinstance(summary, dict) else 0,
        },
        "gates": gates,
        **(
            {
                "conformance": {
                    "schema_version": conformance.get("schema_version", ""),
                    "profile": conformance.get("profile", ""),
                    "status": conformance.get("status", ""),
                    "finding_count": conformance.get("finding_count", 0),
                }
            }
            if isinstance(conformance, dict) and conformance
            else {}
        ),
        "artifacts": artifacts,
    }
    return sanitize_public_mapping(manifest)
