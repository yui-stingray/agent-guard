"""Where: src/agent_guard/surface_delta.py
What: sanitized PR base/head agent surface delta evidence (surface inventory v2 diff).
Why: turn ad hoc PR agent-surface review into deterministic, sanitized evidence
     without publishing raw diffs, base ref names, or instruction/description bodies.
"""

from __future__ import annotations

from functools import partial
import io
import json
import os
import subprocess
import tarfile
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .bounded_git import (
    BoundedGitOutputLimitError,
    BoundedGitProcessError,
    run_bounded_git,
)
from .bounded_scan import MAX_ISOLATED_MESSAGE_BYTES
from .content_guard import (
    CONTENT_TRAVERSAL_TIMEOUT_SECONDS,
    MAX_GIT_FILTER_CONFIG_OUTPUT_BYTES,
    MAX_GIT_NAME_LIST_OUTPUT_BYTES,
)
from .context_guard import (
    DEFAULT_EXCLUDE,
    DEFAULT_INCLUDE,
    MAX_CONTEXT_AGGREGATE_RESULT_BYTES,
    MAX_CONTEXT_FILE_BYTES,
    MAX_CONTEXT_SCAN_FILES,
    glob_matches,
    has_glob_magic,
    is_excluded,
    normalize_string_list,
    scan_section,
)
from .public_redaction import sanitize_public_mapping
from .surface_inventory import (
    AGENT_COMMAND_DIRS,
    AGENT_HOOK_FILES,
    AGENT_PROFILE_DIRS,
    AGENT_SKILL_DIRS,
    DOC_GLOBS,
    MCP_CONFIG_FILES,
    WORKFLOW_GLOBS,
    collect_agent_surface_inventory,
)
from .surface_inventory_mcp_safety import MCP_RISKY_PATTERNS


SURFACE_DELTA_SCHEMA_VERSION_V1 = "agent-guard.surface_delta.v1"
ERROR_SURFACE_DELTA_INVALID = "surface delta contains invalid public data"
ERROR_SURFACE_DELTA_LIMIT = "surface delta exceeds configured limits"
MAX_SURFACE_DELTA_ENTRIES = MAX_CONTEXT_SCAN_FILES * 2
MAX_SURFACE_DELTA_RESULT_BYTES = MAX_ISOLATED_MESSAGE_BYTES // 2

# Public identity fields group related records before collision-safe multiset
# matching. Locator-only moves do not change the represented surface.
_IDENTITY_FIELDS = frozenset({"surface", "path", "server_name", "name"})
_LOCATOR_FIELDS_BY_SURFACE = {
    "documented_guard_command": frozenset({"line"}),
    "evidence_artifact_reference": frozenset({"step_index"}),
    "workflow_reference": frozenset({"step_index"}),
}
# Track only records that represent repository files or directories directly.
# Parsed references remain metadata-driven so one edit does not create duplicate modifications.
_CONTENT_TRACKED_SURFACES = frozenset(
    {
        "agent_context",
        "policy_file",
        "workflow_file",
        "evidence_artifact",
        "agent_skill",
        "agent_profile",
        "agent_command",
        "agent_hook_config",
        "mcp_config",
        "git_submodule",
    }
)
_INTERNAL_CONTENT_REVISION_FIELD = "_content_revision"
_CHECKOUT_TRANSFORMED_METADATA_FIELDS = frozenset({"size_bytes"})
_PUBLIC_CHANGED_FIELD_ALIASES = {
    _INTERNAL_CONTENT_REVISION_FIELD: "content",
}
_PUBLIC_CHANGED_FIELDS = frozenset(
    {
        "artifact_path",
        "command",
        "command_basename",
        "content",
        "env_vars",
        "file_count",
        "filesystem_root",
        "job_id",
        "kind",
        "line_count",
        "package_manager",
        "remote_host",
        "risky_patterns",
        "size_bytes",
        "status",
        "transport",
        "truncated",
        "version_pinned",
    }
)
_UNSAFE_BASE_REF_CHARS = "\x00\r\n"
_BASE_REF_UNRESOLVED_MESSAGE = (
    "surface delta could not resolve --base-ref; fetch it explicitly in CI "
    "(for example: git fetch origin <base-ref> --depth=1) before running "
    "`agent-guard surface delta`"
)
_FILTER_CONFIG_SUFFIXES = (".clean", ".process", ".required")
_MAX_FILTER_DRIVERS = 128
_MAX_SYMLINK_TARGET_BYTES = 64 * 1024
_MAX_EXPANDED_SYMLINKS = 256
_MAX_SYMLINK_CHAIN_DEPTH = 40
_MAX_SYMLINK_TARGET_ENTRIES = 1000
_MAX_MATERIALIZATION_PROJECTIONS = 4096
_MAX_SURFACE_PATHSPECS = 256
_MAX_SURFACE_PATHSPEC_LENGTH = 1024
_MAX_GLOB_VARIANTS = 32
# Reuse established scanner ceilings: bounded Git metadata uses the inventory
# deadline/output cap, materialized files use the context per-file ceiling, and
# intermediate/tar output uses the existing isolated-message budgets.
_GIT_OPERATION_TIMEOUT_SECONDS = CONTENT_TRAVERSAL_TIMEOUT_SECONDS
_MAX_GIT_METADATA_OUTPUT_BYTES = MAX_GIT_NAME_LIST_OUTPUT_BYTES
_MAX_GIT_FILTER_CONFIG_OUTPUT_BYTES = MAX_GIT_FILTER_CONFIG_OUTPUT_BYTES
_MAX_MATERIALIZED_FILE_BYTES = MAX_CONTEXT_FILE_BYTES
_MAX_MATERIALIZED_BYTES = MAX_CONTEXT_AGGREGATE_RESULT_BYTES
_MAX_MATERIALIZED_OUTPUT_BYTES = MAX_ISOLATED_MESSAGE_BYTES
_MAX_MATERIALIZED_FILES = MAX_CONTEXT_SCAN_FILES
_GIT_QUERY_ERROR = "surface delta could not complete a bounded Git query"
_MATERIALIZATION_LIMIT_ERROR = (
    "surface delta base ref materialization exceeds configured limits"
)


class SurfaceDeltaError(Exception):
    """Raised when surface delta evidence cannot be computed; callers map this to exit 2."""


@dataclass(frozen=True)
class SurfaceDeltaEntry:
    kind: str
    path: str
    name: str
    status: str
    risk_labels: tuple[str, ...] = ()
    changed_fields: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        risk_labels = tuple(sorted(set(self.risk_labels)))
        changed_fields = tuple(sorted(set(self.changed_fields)))
        if self.status not in {"added", "removed", "modified"}:
            raise SurfaceDeltaError("surface delta found an unsupported entry status")
        if not set(risk_labels).issubset(MCP_RISKY_PATTERNS):
            raise SurfaceDeltaError("surface delta found an unsupported risk label")
        if not set(changed_fields).issubset(_PUBLIC_CHANGED_FIELDS):
            raise SurfaceDeltaError("surface delta found unsupported surface metadata")
        payload: dict[str, object] = {
            "kind": self.kind,
            "path": self.path,
            "name": self.name,
            "status": self.status,
        }
        if risk_labels:
            payload["risk_labels"] = list(risk_labels)
        payload["changed_fields"] = list(changed_fields)
        return sanitize_public_mapping(payload)


class _SurfaceDeltaResultBudget:
    """Bound delta entries before the complete public payload is materialized."""

    def __init__(self) -> None:
        self.used = len(b"[]")
        self.count = 0

    def add(self, entry: SurfaceDeltaEntry) -> None:
        if self.count >= MAX_SURFACE_DELTA_ENTRIES:
            raise SurfaceDeltaError(ERROR_SURFACE_DELTA_LIMIT)
        try:
            amount = len(
                json.dumps(
                    entry.to_dict(),
                    allow_nan=False,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8", errors="surrogatepass")
            ) + (1 if self.count else 0)
        except (MemoryError, OverflowError, RecursionError, TypeError, ValueError):
            raise SurfaceDeltaError(ERROR_SURFACE_DELTA_LIMIT) from None
        if amount > MAX_SURFACE_DELTA_RESULT_BYTES - self.used:
            raise SurfaceDeltaError(ERROR_SURFACE_DELTA_LIMIT)
        self.used += amount
        self.count += 1


@dataclass(frozen=True)
class GitTreeEntry:
    """Validated raw Git tree entry used only for base-tree materialization."""

    mode: str
    object_type: str
    object_id: str
    path: str


@dataclass(frozen=True)
class SurfaceMaterializationPlan:
    """Validated include/exclude sets used before any base blob is read."""

    context_includes: tuple[str, ...]
    context_excludes: tuple[str, ...]
    fixed_includes: tuple[str, ...]


@dataclass(frozen=True, order=True)
class SymlinkMaterializationRequest:
    """Alias-space selection that must follow a symlink target."""

    scope: str
    alias_root: str
    suffix: str
    physical_alias_roots: tuple[str, ...]


@dataclass(frozen=True, order=True)
class SurfaceMaterializationProjection:
    """Map one selected alias root onto its current physical target root."""

    scope: str
    alias_root: str
    target_root: str
    physical_alias_roots: tuple[str, ...]


class GitBlobReader:
    """Expose exactly one batch-protocol blob without buffering its contents."""

    def __init__(self, stream: BinaryIO, size: int) -> None:
        self.stream = stream
        self.remaining = size

    def read(self, size: int = -1) -> bytes:
        if self.remaining == 0:
            return b""
        read_size = self.remaining if size < 0 else min(size, self.remaining)
        data = self.stream.read(read_size)
        if len(data) != read_size:
            raise OSError("incomplete git blob stream")
        self.remaining -= len(data)
        return data


class SurfaceMaterializationBudget:
    """Share one deadline and byte/file budget across base-tree materialization."""

    def __init__(self) -> None:
        self.deadline = time.monotonic() + _GIT_OPERATION_TIMEOUT_SECONDS
        self.materialized_bytes = 0

    def check_deadline(self) -> None:
        if time.monotonic() >= self.deadline:
            raise SurfaceDeltaError(_MATERIALIZATION_LIMIT_ERROR)

    def remaining_timeout(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise SurfaceDeltaError(_MATERIALIZATION_LIMIT_ERROR)
        return remaining

    def check_file_count(self, count: int) -> None:
        self.check_deadline()
        if count > _MAX_MATERIALIZED_FILES:
            raise SurfaceDeltaError(_MATERIALIZATION_LIMIT_ERROR)

    def charge_materialized_bytes(self, size: int) -> None:
        self.check_deadline()
        if size < 0 or size > _MAX_MATERIALIZED_FILE_BYTES:
            raise SurfaceDeltaError(_MATERIALIZATION_LIMIT_ERROR)
        if size > _MAX_MATERIALIZED_BYTES - self.materialized_bytes:
            raise SurfaceDeltaError(_MATERIALIZATION_LIMIT_ERROR)
        self.materialized_bytes += size


class BoundedTarWriter:
    """Reject synthetic tar output before writing past its fixed ceiling."""

    def __init__(
        self,
        stream: BinaryIO,
        *,
        budget: SurfaceMaterializationBudget,
    ) -> None:
        self.stream = stream
        self.budget = budget
        self.written = 0

    def write(self, data: bytes) -> int:
        self.budget.check_deadline()
        if len(data) > _MAX_MATERIALIZED_OUTPUT_BYTES - self.written:
            raise SurfaceDeltaError(_MATERIALIZATION_LIMIT_ERROR)
        written = self.stream.write(data)
        if written != len(data):
            raise OSError("incomplete tar write")
        self.written += written
        return written

    def tell(self) -> int:
        return self.written


def is_safe_base_ref_arg(base_ref: str) -> bool:
    return bool(base_ref) and not base_ref.startswith("-") and not any(
        char in base_ref for char in _UNSAFE_BASE_REF_CHARS
    )


def _run_surface_git(
    cwd: Path,
    args: Sequence[str],
    *,
    timeout_seconds: float = _GIT_OPERATION_TIMEOUT_SECONDS,
    max_output_bytes: int = _MAX_GIT_METADATA_OUTPUT_BYTES,
    input_data: bytes | None = None,
    error_message: str = _GIT_QUERY_ERROR,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return run_bounded_git(
            cwd,
            args,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            input_data=input_data,
        )
    except (BoundedGitOutputLimitError, BoundedGitProcessError):
        raise SurfaceDeltaError(error_message) from None


def run_git_command(
    cwd: Path,
    args: list[str],
    *,
    max_output_bytes: int = _MAX_GIT_METADATA_OUTPUT_BYTES,
    _budget: SurfaceMaterializationBudget | None = None,
) -> subprocess.CompletedProcess[str]:
    result = _run_surface_git(
        cwd,
        args,
        timeout_seconds=(
            _budget.remaining_timeout()
            if _budget is not None
            else _GIT_OPERATION_TIMEOUT_SECONDS
        ),
        max_output_bytes=max_output_bytes,
    )
    stdout = result.stdout.decode("utf-8", errors="surrogateescape")
    return subprocess.CompletedProcess(result.args, result.returncode, stdout, "")


def resolve_repo_toplevel(
    root: Path,
    *,
    _budget: SurfaceMaterializationBudget | None = None,
) -> Path | None:
    try:
        result = run_git_command(
            root,
            ["rev-parse", "--show-toplevel"],
            _budget=_budget,
        )
    except SurfaceDeltaError:
        if _budget is not None:
            raise
        return None
    if result.returncode != 0:
        return None
    stdout = result.stdout.strip()
    if not stdout:
        return None
    return Path(stdout).resolve()


def repo_relative_root(*, root: Path, toplevel: Path) -> str:
    try:
        return root.resolve().relative_to(toplevel).as_posix()
    except ValueError as exc:
        raise SurfaceDeltaError("--root must stay inside the git repository") from exc


def is_valid_git_object_id(value: str) -> bool:
    return len(value) in (40, 64) and all(
        char in "0123456789abcdef" for char in value
    )


def resolve_merge_base(
    *,
    root: Path,
    base_ref: str,
    _budget: SurfaceMaterializationBudget | None = None,
) -> str:
    """Resolve the PR branch point without publishing the caller's ref value."""

    result = run_git_command(
        root,
        ["merge-base", "--all", "--", base_ref, "HEAD"],
        _budget=_budget,
    )
    candidates = result.stdout.splitlines()
    if result.returncode != 0 or len(candidates) != 1 or not is_valid_git_object_id(
        candidates[0]
    ):
        raise SurfaceDeltaError(_BASE_REF_UNRESOLVED_MESSAGE)
    return candidates[0]


def configured_filter_drivers(
    root: Path,
    *,
    _budget: SurfaceMaterializationBudget | None = None,
) -> tuple[str, ...]:
    """Return bounded effective Git filter driver names without reading commands."""

    result = run_git_command(
        root,
        [
            "config",
            "--null",
            "--name-only",
            "--get-regexp",
            r"^filter\..*\.(clean|process|required)$",
        ],
        max_output_bytes=_MAX_GIT_FILTER_CONFIG_OUTPUT_BYTES,
        _budget=_budget,
    )
    if result.returncode == 1:
        return ()
    if result.returncode != 0:
        raise SurfaceDeltaError("surface delta could not inspect Git filter configuration")

    drivers: set[str] = set()
    allowed = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    for raw_key in result.stdout.split("\0"):
        if not raw_key:
            continue
        key = raw_key.strip()
        folded = key.casefold()
        if not folded.startswith("filter."):
            raise SurfaceDeltaError("surface delta found an unsafe Git filter configuration")
        suffix = next(
            (candidate for candidate in _FILTER_CONFIG_SUFFIXES if folded.endswith(candidate)),
            None,
        )
        if suffix is None:
            raise SurfaceDeltaError("surface delta found an unsafe Git filter configuration")
        driver = key[len("filter.") : -len(suffix)]
        if not driver or len(driver) > 128 or any(char not in allowed for char in driver):
            raise SurfaceDeltaError("surface delta found an unsafe Git filter configuration")
        drivers.add(driver)
        if len(drivers) > _MAX_FILTER_DRIVERS:
            raise SurfaceDeltaError("surface delta found too many Git filter drivers")
    return tuple(sorted(drivers))


def changed_repo_paths(
    *,
    root: Path,
    base_ref: str,
    _budget: SurfaceMaterializationBudget | None = None,
) -> tuple[str, ...]:
    """Return Git-normalized changed paths relative to root without exposing them."""

    git_config_args: list[str] = []
    for driver in configured_filter_drivers(root, _budget=_budget):
        git_config_args.extend(
            [
                "-c",
                f"filter.{driver}.clean=",
                "-c",
                f"filter.{driver}.process=",
                "-c",
                f"filter.{driver}.required=false",
            ]
        )
    result = run_git_command(
        root,
        [
            *git_config_args,
            "diff",
            "--relative",
            "--name-only",
            "-z",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=dirty",
            "--no-renames",
            base_ref,
            "--",
        ],
        _budget=_budget,
    )
    if result.returncode != 0:
        raise SurfaceDeltaError(_BASE_REF_UNRESOLVED_MESSAGE)
    return tuple(sorted(path for path in result.stdout.split("\0") if path))


def ensure_changed_symlinks_stay_in_root(*, root: Path, changed_paths: Sequence[str]) -> None:
    """Fail closed before inventory can follow a changed external symlink."""

    resolved_root = root.resolve()
    for raw_path in changed_paths:
        relative = PurePosixPath(raw_path)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise SurfaceDeltaError("surface delta found an unsafe changed path")
        candidate = root.joinpath(*relative.parts)
        if not candidate.is_symlink():
            continue
        try:
            candidate.resolve(strict=True).relative_to(resolved_root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise SurfaceDeltaError(
                "surface delta found a repository-external symlink in the working tree"
            ) from exc


def surface_path_has_change(*, path: str, changed_paths: Sequence[str]) -> bool:
    candidate = PurePosixPath(path)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        return False
    prefix = candidate.as_posix().rstrip("/")
    return any(item == prefix or item.startswith(f"{prefix}/") for item in changed_paths)


def annotate_content_revisions(
    surfaces: Sequence[object],
    *,
    changed_paths: Sequence[str],
    revision: str,
) -> list[object]:
    """Add an internal-only marker when a file-backed surface changed."""

    annotated: list[object] = []
    for item in surfaces:
        if not isinstance(item, Mapping):
            annotated.append(item)
            continue
        surface = dict(item)
        if str(surface.get("surface", "")) in _CONTENT_TRACKED_SURFACES:
            path = str(surface.get("path", ""))
            if surface_path_has_change(path=path, changed_paths=changed_paths):
                surface[_INTERNAL_CONTENT_REVISION_FIELD] = revision
        annotated.append(surface)
    return annotated


def validate_materialization_patterns(patterns: Sequence[str]) -> tuple[str, ...]:
    """Normalize and bound inventory patterns without echoing unsafe values."""

    validated: set[str] = set()
    for raw_pattern in patterns:
        pattern = raw_pattern.strip()
        while pattern.startswith("./"):
            pattern = pattern[2:]
        parts = PurePosixPath(pattern).parts
        if (
            not pattern
            or "\x00" in pattern
            or "\\" in pattern
            or pattern.startswith("/")
            or ".." in parts
            or len(pattern) > _MAX_SURFACE_PATHSPEC_LENGTH
        ):
            raise SurfaceDeltaError("surface delta found an unsafe inventory pattern")
        validated.add(pattern)
        if len(validated) > _MAX_SURFACE_PATHSPECS:
            raise SurfaceDeltaError("surface delta found too many inventory patterns")
    return tuple(sorted(validated))


def surface_materialization_plan(
    context_policy: Mapping[str, object],
) -> SurfaceMaterializationPlan:
    """Return bounded context and fixed paths that surface inventory can read."""

    scan_cfg = scan_section(dict(context_policy))
    context_includes = normalize_string_list(scan_cfg.get("include", [])) or list(DEFAULT_INCLUDE)
    context_excludes = [
        *DEFAULT_EXCLUDE,
        *normalize_string_list(scan_cfg.get("exclude", [])),
    ]
    fixed_includes = [
        *DOC_GLOBS,
        ".agent-guard/*.yaml",
        ".agent-guard/evidence/*",
        "docs/evidence-samples/*",
        *(f".github/workflows/{pattern}" for pattern in WORKFLOW_GLOBS),
        *(path for path, _kind in AGENT_SKILL_DIRS),
        *(path for path, _kind in AGENT_PROFILE_DIRS),
        *(path for path, _kind in AGENT_COMMAND_DIRS),
        *(pattern for pattern, _kind in AGENT_HOOK_FILES),
        *(pattern for pattern, _kind in MCP_CONFIG_FILES),
    ]
    return SurfaceMaterializationPlan(
        context_includes=validate_materialization_patterns(context_includes),
        context_excludes=validate_materialization_patterns(context_excludes),
        fixed_includes=validate_materialization_patterns(fixed_includes),
    )


def inventory_path_matches(path: str, patterns: Sequence[str]) -> bool:
    """Match a root-relative Git path using context-inventory glob semantics."""

    candidate = PurePosixPath(path)
    for pattern in patterns:
        if pattern == ".":
            return True
        if has_glob_magic(pattern):
            variants = {pattern}
            pending = [pattern]
            while pending:
                current = pending.pop()
                if "/**/" not in current:
                    continue
                collapsed = current.replace("/**/", "/", 1)
                if collapsed not in variants:
                    variants.add(collapsed)
                    if len(variants) > _MAX_GLOB_VARIANTS:
                        raise SurfaceDeltaError(
                            "surface delta found an overly complex inventory include pattern"
                        )
                    pending.append(collapsed)
            if any(glob_matches(candidate, variant) for variant in variants):
                return True
            continue
        normalized = pattern.rstrip("/")
        if path == normalized or path.startswith(f"{normalized}/"):
            return True
    return False


def materialization_plan_matches(path: str, plan: SurfaceMaterializationPlan) -> bool:
    """Apply fixed surfaces plus context include/exclude semantics."""

    return materialization_scope(path, plan) is not None


def materialization_scope(path: str, plan: SurfaceMaterializationPlan) -> str | None:
    """Return the selection scope whose rules must follow a symlink target."""

    if inventory_path_matches(path, plan.fixed_includes):
        return "fixed"
    candidate = PurePosixPath(path)
    if inventory_path_matches(path, plan.context_includes) and not is_excluded(
        candidate, plan.context_excludes
    ):
        return "context"
    return None


def inventory_pattern_literal_root(pattern: str) -> str:
    """Return the fixed path prefix that precedes any glob component."""

    parts: list[str] = []
    for part in PurePosixPath(pattern.rstrip("/")).parts:
        if has_glob_magic(part):
            break
        parts.append(part)
    return PurePosixPath(*parts).as_posix() if parts else ""


def materialization_ancestor_roots(
    path: str,
    plan: SurfaceMaterializationPlan,
) -> dict[str, tuple[str, ...]]:
    """Return selected literal roots that may live below a symlink ancestor."""

    prefix = f"{path.rstrip('/')}/"
    fixed = {
        root
        for pattern in plan.fixed_includes
        if (root := inventory_pattern_literal_root(pattern))
        and (root == path or root.startswith(prefix))
    }
    context = {
        root
        for pattern in plan.context_includes
        if (root := inventory_pattern_literal_root(pattern))
        and (root == path or root.startswith(prefix))
        and not is_excluded(PurePosixPath(root), plan.context_excludes)
    }
    return {
        "fixed": tuple(sorted(fixed)),
        "context": tuple(sorted(context)),
    }


def scope_materialization_matches(
    *,
    path: str,
    scope: str,
    plan: SurfaceMaterializationPlan,
) -> bool:
    """Apply one materialization scope to an alias-space path."""

    if scope == "fixed":
        return inventory_path_matches(path, plan.fixed_includes)
    if scope == "context":
        return inventory_path_matches(path, plan.context_includes) and not is_excluded(
            PurePosixPath(path), plan.context_excludes
        )
    raise SurfaceDeltaError("surface delta found an unsafe materialization scope")


def symlink_materialization_requests(
    *,
    path: str,
    plan: SurfaceMaterializationPlan,
    allowed_scope: str | None = None,
) -> set[SymlinkMaterializationRequest]:
    """Return alias-space selections that a symlink must expose."""

    requests: set[SymlinkMaterializationRequest] = set()
    scopes = (allowed_scope,) if allowed_scope is not None else ("fixed", "context")
    for scope in scopes:
        if scope_materialization_matches(path=path, scope=scope, plan=plan):
            requests.add(
                SymlinkMaterializationRequest(
                    scope=scope,
                    alias_root=path,
                    suffix="",
                    physical_alias_roots=(),
                )
            )
        for root in materialization_ancestor_roots(path, plan)[scope]:
            if root == path:
                suffix = ""
            elif root.startswith(f"{path.rstrip('/')}/"):
                suffix = root[len(path.rstrip('/')) + 1 :]
            else:
                continue
            requests.add(
                SymlinkMaterializationRequest(
                    scope=scope,
                    alias_root=root,
                    suffix=suffix,
                    physical_alias_roots=(),
                )
            )
    return requests


def project_path_between_roots(
    path: str,
    *,
    source_root: str,
    target_root: str,
) -> str | None:
    """Project a descendant path between two equivalent roots."""

    if path == source_root:
        return target_root
    prefix = f"{source_root.rstrip('/')}/"
    if not path.startswith(prefix):
        return None
    suffix = path[len(prefix) :]
    return PurePosixPath(target_root, suffix).as_posix()


def projected_alias_path(
    path: str,
    projection: SurfaceMaterializationProjection,
) -> str | None:
    """Project a physical target path back into its selected alias space."""

    return project_path_between_roots(
        path,
        source_root=projection.target_root,
        target_root=projection.alias_root,
    )


def projection_physical_paths(
    path: str,
    projection: SurfaceMaterializationProjection,
) -> tuple[str, ...]:
    """Return current and prior physical namespaces for one target path."""

    projected = [path]
    for root in projection.physical_alias_roots:
        mapped = project_path_between_roots(
            path,
            source_root=projection.target_root,
            target_root=root,
        )
        if mapped is None:
            raise SurfaceDeltaError("surface delta found an unsafe materialization scope")
        projected.append(mapped)
    return tuple(projected)


def preserve_projection_physical_roots(
    request: SymlinkMaterializationRequest,
    projection: SurfaceMaterializationProjection,
) -> SymlinkMaterializationRequest:
    """Carry every prior physical namespace into a nested symlink request."""

    roots: set[str] = set()
    for root in (*projection.physical_alias_roots, projection.target_root):
        mapped = project_path_between_roots(
            request.alias_root,
            source_root=projection.alias_root,
            target_root=root,
        )
        if mapped is None:
            raise SurfaceDeltaError("surface delta found an unsafe materialization scope")
        roots.add(mapped)
    return SymlinkMaterializationRequest(
        scope=request.scope,
        alias_root=request.alias_root,
        suffix=request.suffix,
        physical_alias_roots=tuple(sorted(roots)),
    )


def materialization_projection_matches(
    *,
    path: str,
    mode: str,
    projection: SurfaceMaterializationProjection,
    plan: SurfaceMaterializationPlan,
) -> bool:
    """Apply original alias-space rules to one physical target path."""

    alias_path = projected_alias_path(path, projection)
    if alias_path is not None:
        if projection.scope == "context" and any(
            is_excluded(PurePosixPath(candidate), plan.context_excludes)
            for candidate in projection_physical_paths(path, projection)
        ):
            return False
        if scope_materialization_matches(
            path=alias_path,
            scope=projection.scope,
            plan=plan,
        ):
            return True
        return mode == "120000" and bool(
            symlink_materialization_requests(
                path=alias_path,
                plan=plan,
                allowed_scope=projection.scope,
            )
        )

    if mode != "120000" or not projection.target_root.startswith(
        f"{path.rstrip('/')}/"
    ):
        return False
    return projection.scope != "context" or not any(
        is_excluded(PurePosixPath(root), plan.context_excludes)
        for root in (projection.target_root, *projection.physical_alias_roots)
    )


def projected_symlink_requests(
    *,
    path: str,
    projections: Sequence[SurfaceMaterializationProjection],
    plan: SurfaceMaterializationPlan,
) -> set[SymlinkMaterializationRequest]:
    """Preserve alias selections while following nested physical symlinks."""

    requests: set[SymlinkMaterializationRequest] = set()
    for projection in projections:
        alias_path = projected_alias_path(path, projection)
        if alias_path is not None:
            requests.update(
                preserve_projection_physical_roots(request, projection)
                for request in symlink_materialization_requests(
                    path=alias_path,
                    plan=plan,
                    allowed_scope=projection.scope,
                )
            )
            continue
        prefix = f"{path.rstrip('/')}/"
        if projection.target_root.startswith(prefix):
            requests.add(
                SymlinkMaterializationRequest(
                    scope=projection.scope,
                    alias_root=projection.alias_root,
                    suffix=projection.target_root[len(prefix) :],
                    physical_alias_roots=tuple(
                        sorted(
                            {
                                projection.target_root,
                                *projection.physical_alias_roots,
                            }
                        )
                    ),
                )
            )
    return requests


def run_git_tree_list(
    *,
    toplevel: Path,
    base_ref: str,
    _budget: SurfaceMaterializationBudget | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """List raw tree metadata; callers select entries before reading any blobs."""

    budget = _budget or SurfaceMaterializationBudget()
    return _run_surface_git(
        toplevel,
        [
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            base_ref,
        ],
        timeout_seconds=budget.remaining_timeout(),
        max_output_bytes=_MAX_GIT_METADATA_OUTPUT_BYTES,
        error_message=_MATERIALIZATION_LIMIT_ERROR,
    )


def run_git_index_list(
    *,
    toplevel: Path,
    _budget: SurfaceMaterializationBudget | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """List tracked index entries without inspecting submodule worktrees."""

    budget = _budget or SurfaceMaterializationBudget()
    return _run_surface_git(
        toplevel,
        [
            "ls-files",
            "--stage",
            "-z",
        ],
        timeout_seconds=budget.remaining_timeout(),
        max_output_bytes=_MAX_GIT_METADATA_OUTPUT_BYTES,
        error_message=_MATERIALIZATION_LIMIT_ERROR,
    )


def safe_git_tree_path(raw_path: bytes) -> str:
    """Return a materializable Git path or fail without exposing the path."""

    parts = raw_path.split(b"/")
    first = parts[0] if parts else b""
    has_drive_prefix = (
        len(first) >= 2
        and first[1:2] == b":"
        and first[:1].isalpha()
    )
    if (
        not raw_path
        or raw_path.startswith((b"/", b"\\"))
        or b"\\" in raw_path
        or has_drive_prefix
        or any(not part or part in (b".", b"..") or part.lower() == b".git" for part in parts)
    ):
        raise SurfaceDeltaError("surface delta found an unsafe path in the base ref tree")
    return os.fsdecode(raw_path)


def relative_git_path(path: str, *, repo_relative: str) -> str | None:
    if repo_relative in ("", "."):
        return path
    prefix = f"{repo_relative.rstrip('/')}/"
    if not path.startswith(prefix):
        return None
    return path[len(prefix) :]


def raw_git_path_is_in_root(raw_path: bytes, *, repo_relative: str) -> bool:
    if repo_relative in ("", "."):
        return True
    return raw_path.startswith(os.fsencode(f"{repo_relative.rstrip('/')}/"))


def gitlink_paths_from_tree(
    raw_listing: bytes,
    *,
    repo_relative: str,
    _budget: SurfaceMaterializationBudget | None = None,
) -> tuple[str, ...]:
    """Return validated root-relative gitlinks from one raw commit tree listing."""

    gitlinks: set[str] = set()
    for record in raw_listing.split(b"\0"):
        if _budget is not None:
            _budget.check_deadline()
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise SurfaceDeltaError("surface delta could not parse the base ref tree")
        mode, object_type, raw_object_id = fields
        if mode != b"160000":
            continue
        if not raw_git_path_is_in_root(raw_path, repo_relative=repo_relative):
            continue
        try:
            object_id = raw_object_id.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SurfaceDeltaError("surface delta could not parse the base ref tree") from exc
        if object_type != b"commit" or not is_valid_git_object_id(object_id):
            raise SurfaceDeltaError("surface delta could not parse the base ref tree")
        path = safe_git_tree_path(raw_path)
        relative = relative_git_path(path, repo_relative=repo_relative)
        if relative:
            gitlinks.add(relative)
            if len(gitlinks) > _MAX_MATERIALIZED_FILES:
                raise SurfaceDeltaError(_MATERIALIZATION_LIMIT_ERROR)
    return tuple(sorted(gitlinks))


def gitlink_paths_from_index(
    *,
    toplevel: Path,
    repo_relative: str,
    _budget: SurfaceMaterializationBudget | None = None,
) -> tuple[str, ...]:
    """Return tracked root-relative gitlinks without entering initialized submodules."""

    budget = _budget or SurfaceMaterializationBudget()
    listing = run_git_index_list(toplevel=toplevel, _budget=budget)
    if listing.returncode != 0:
        raise SurfaceDeltaError("surface delta could not inspect the Git index")

    gitlinks: set[str] = set()
    for record in listing.stdout.split(b"\0"):
        budget.check_deadline()
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise SurfaceDeltaError("surface delta could not parse the Git index")
        mode, raw_object_id, stage = fields
        if not raw_git_path_is_in_root(raw_path, repo_relative=repo_relative):
            continue
        if stage != b"0":
            raise SurfaceDeltaError("surface delta requires a conflict-free Git index")
        if mode != b"160000":
            continue
        try:
            object_id = raw_object_id.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SurfaceDeltaError("surface delta could not parse the Git index") from exc
        if not is_valid_git_object_id(object_id):
            raise SurfaceDeltaError("surface delta could not parse the Git index")
        path = safe_git_tree_path(raw_path)
        relative = relative_git_path(path, repo_relative=repo_relative)
        if relative is None:
            raise SurfaceDeltaError("surface delta could not parse the Git index")
        gitlinks.add(relative)
        if len(gitlinks) > _MAX_MATERIALIZED_FILES:
            raise SurfaceDeltaError(_MATERIALIZATION_LIMIT_ERROR)
    return tuple(sorted(gitlinks))


def parse_git_tree_entries(
    raw_listing: bytes,
    *,
    repo_relative: str,
    materialization_plan: SurfaceMaterializationPlan | None = None,
    materialization_projections: Sequence[SurfaceMaterializationProjection] = (),
    _budget: SurfaceMaterializationBudget | None = None,
) -> list[GitTreeEntry]:
    """Parse and validate raw `git ls-tree -z` output deterministically."""

    if materialization_projections and materialization_plan is None:
        raise SurfaceDeltaError("surface delta found an unsafe materialization scope")
    entries: list[GitTreeEntry] = []
    seen_paths: set[str] = set()
    prefix = "" if repo_relative in ("", ".") else f"{repo_relative.rstrip('/')}/"
    raw_root = b"" if repo_relative in ("", ".") else os.fsencode(repo_relative.rstrip("/"))
    for record in raw_listing.split(b"\0"):
        if _budget is not None:
            _budget.check_deadline()
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise SurfaceDeltaError("surface delta could not parse the base ref tree")
        mode_bytes, object_type_bytes, object_id_bytes = fields
        try:
            mode = mode_bytes.decode("ascii")
            object_type = object_type_bytes.decode("ascii")
            object_id = object_id_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SurfaceDeltaError("surface delta could not parse the base ref tree") from exc
        if (mode, object_type) not in {
            ("100644", "blob"),
            ("100755", "blob"),
            ("120000", "blob"),
            ("160000", "commit"),
        }:
            raise SurfaceDeltaError("surface delta found an unsupported base ref tree entry")
        if not is_valid_git_object_id(object_id):
            raise SurfaceDeltaError("surface delta could not parse the base ref tree")
        if raw_root and raw_path != raw_root and not raw_path.startswith(raw_root + b"/"):
            continue
        raw_relative = raw_path[len(raw_root) + 1 :] if raw_root else raw_path
        raw_relative_path = os.fsdecode(raw_relative)
        selected = materialization_plan is None and not materialization_projections
        if materialization_plan is not None:
            if materialization_projections:
                selected = any(
                    materialization_projection_matches(
                        path=raw_relative_path,
                        mode=mode,
                        projection=projection,
                        plan=materialization_plan,
                    )
                    for projection in materialization_projections
                )
            elif materialization_plan_matches(raw_relative_path, materialization_plan):
                selected = True
            elif mode == "120000" and any(
                materialization_ancestor_roots(
                    raw_relative_path, materialization_plan
                ).values()
            ):
                selected = True
        if not selected:
            continue
        path = safe_git_tree_path(raw_path)
        if prefix and path != repo_relative and not path.startswith(prefix):
            continue
        normalized_path = os.path.normcase(path)
        if normalized_path in seen_paths:
            raise SurfaceDeltaError("surface delta found duplicate paths in the base ref tree")
        seen_paths.add(normalized_path)
        entries.append(
            GitTreeEntry(
                mode=mode,
                object_type=object_type,
                object_id=object_id,
                path=path,
            )
        )
        if _budget is not None:
            _budget.check_file_count(len(entries))
    entries.sort(key=lambda entry: entry.path)
    return entries


def begin_git_blob(stream: BinaryIO, object_id: str) -> GitBlobReader:
    """Begin one validated raw blob in bounded `git cat-file --batch` output."""

    header = stream.readline()
    fields = header.rstrip(b"\n").split(b" ")
    if len(fields) != 3 or fields[0] != object_id.encode("ascii") or fields[1] != b"blob":
        raise SurfaceDeltaError("surface delta could not read the base ref tree")
    try:
        size = int(fields[2])
    except ValueError as exc:
        raise SurfaceDeltaError("surface delta could not read the base ref tree") from exc
    if size < 0:
        raise SurfaceDeltaError("surface delta could not read the base ref tree")
    return GitBlobReader(stream, size)


def finish_git_blob(stream: BinaryIO, reader: GitBlobReader) -> None:
    """Verify the current batch-protocol blob was consumed exactly."""

    if reader.remaining != 0 or stream.read(1) != b"\n":
        raise SurfaceDeltaError("surface delta could not read the base ref tree")


def git_blob_sizes(
    *,
    toplevel: Path,
    entries: Sequence[GitTreeEntry],
    budget: SurfaceMaterializationBudget,
) -> dict[str, int]:
    """Preflight selected blob sizes before requesting any raw blob contents."""

    budget.check_file_count(len(entries))
    object_ids = sorted({entry.object_id for entry in entries})
    if not object_ids:
        return {}
    input_data = "".join(f"{object_id}\n" for object_id in object_ids).encode("ascii")
    result = _run_surface_git(
        toplevel,
        ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        timeout_seconds=budget.remaining_timeout(),
        max_output_bytes=_MAX_GIT_METADATA_OUTPUT_BYTES,
        input_data=input_data,
        error_message=_MATERIALIZATION_LIMIT_ERROR,
    )
    lines = result.stdout.splitlines()
    if result.returncode != 0 or len(lines) != len(object_ids):
        raise SurfaceDeltaError("surface delta could not read the base ref tree")

    sizes: dict[str, int] = {}
    for expected_id, line in zip(object_ids, lines, strict=True):
        fields = line.split(b" ")
        try:
            object_id = fields[0].decode("ascii")
            size = int(fields[2])
        except (IndexError, UnicodeDecodeError, ValueError):
            raise SurfaceDeltaError("surface delta could not read the base ref tree") from None
        if (
            len(fields) != 3
            or object_id != expected_id
            or fields[1] != b"blob"
            or size < 0
        ):
            raise SurfaceDeltaError("surface delta could not read the base ref tree")
        sizes[object_id] = size
    return sizes


def read_git_symlink_targets(
    *,
    toplevel: Path,
    entries: Sequence[GitTreeEntry],
    _budget: SurfaceMaterializationBudget | None = None,
) -> dict[str, bytes]:
    """Read a bounded set of raw symlink blobs without checkout filters."""

    budget = _budget or SurfaceMaterializationBudget()
    budget.check_file_count(len(entries))
    targets: dict[str, bytes] = {}
    try:
        result = _run_surface_git(
            toplevel,
            ["cat-file", "--batch"],
            timeout_seconds=budget.remaining_timeout(),
            max_output_bytes=_MAX_MATERIALIZED_OUTPUT_BYTES,
            input_data="".join(f"{entry.object_id}\n" for entry in entries).encode(
                "ascii"
            ),
            error_message=_MATERIALIZATION_LIMIT_ERROR,
        )
        if result.returncode != 0:
            raise SurfaceDeltaError("surface delta could not read the base ref tree")
        stream = io.BytesIO(result.stdout)
        for entry in entries:
            budget.check_deadline()
            if entry.mode != "120000":
                raise SurfaceDeltaError("surface delta could not read the base ref tree")
            reader = begin_git_blob(stream, entry.object_id)
            if reader.remaining > _MAX_SYMLINK_TARGET_BYTES:
                raise SurfaceDeltaError(
                    "surface delta found an unsafe symlink in the base ref tree"
                )
            budget.charge_materialized_bytes(reader.remaining)
            target = reader.read()
            finish_git_blob(stream, reader)
            if b"\0" in target:
                raise SurfaceDeltaError(
                    "surface delta found an unsafe symlink in the base ref tree"
                )
            targets[entry.path] = target
        if stream.read(1):
            raise SurfaceDeltaError("surface delta could not read the base ref tree")
    except SurfaceDeltaError:
        raise
    except (MemoryError, OSError, OverflowError) as exc:
        raise SurfaceDeltaError(_MATERIALIZATION_LIMIT_ERROR) from exc
    return targets


def normalize_git_symlink_target(
    *,
    link_path: str,
    raw_target: bytes,
    repo_relative: str,
) -> str:
    """Return a scan-root-relative in-root target without exposing its value."""

    target = os.fsdecode(raw_target)
    raw_parts = target.split("/")
    meaningful_parts = [part for part in raw_parts if part not in ("", ".")]
    has_drive_prefix = any(
        len(part) >= 2 and part[1] == ":" and part[0].isalpha()
        for part in meaningful_parts
    )
    if (
        not target
        or target.startswith(("/", "\\"))
        or "\\" in target
        or "\0" in target
        or has_drive_prefix
    ):
        raise SurfaceDeltaError("surface delta found an unsafe symlink in the base ref tree")

    root_parts = (
        [] if repo_relative in ("", ".") else list(PurePosixPath(repo_relative).parts)
    )
    link_parts = list(PurePosixPath(link_path).parts)
    if link_parts[: len(root_parts)] != root_parts or len(link_parts) <= len(root_parts):
        raise SurfaceDeltaError(
            "surface delta found an unsafe symlink in the base ref tree"
        )

    resolved_parts = link_parts[:-1]
    for part in raw_parts:
        if part in ("", "."):
            continue
        if part == "..":
            if len(resolved_parts) <= len(root_parts):
                raise SurfaceDeltaError(
                    "surface delta found an unsafe symlink in the base ref tree"
                )
            resolved_parts.pop()
            continue
        if part.casefold() == ".git":
            raise SurfaceDeltaError(
                "surface delta found an unsafe symlink in the base ref tree"
            )
        resolved_parts.append(part)

    relative_parts = resolved_parts[len(root_parts) :]
    if not relative_parts:
        raise SurfaceDeltaError("surface delta found an unsafe symlink in the base ref tree")
    return PurePosixPath(*relative_parts).as_posix()


def symlink_target_graph_has_cycle(targets: Mapping[str, str]) -> bool:
    """Return whether file or directory target traversal reaches a symlink cycle."""

    edges: dict[str, set[str]] = {}
    for link, target in targets.items():
        edges[link] = {
            candidate
            for candidate in targets
            if candidate == target
            or candidate.startswith(f"{target}/")
            or target.startswith(f"{candidate}/")
        }

    state: dict[str, int] = {}

    def visits_cycle(link: str) -> bool:
        current_state = state.get(link, 0)
        if current_state == 1:
            return True
        if current_state == 2:
            return False
        state[link] = 1
        if any(visits_cycle(target) for target in edges[link]):
            return True
        state[link] = 2
        return False

    return any(visits_cycle(link) for link in edges if state.get(link, 0) == 0)


def expand_git_tree_symlink_targets(
    *,
    toplevel: Path,
    raw_listing: bytes,
    repo_relative: str,
    entries: Sequence[GitTreeEntry],
    materialization_plan: SurfaceMaterializationPlan,
    _budget: SurfaceMaterializationBudget | None = None,
) -> tuple[list[GitTreeEntry], dict[str, bytes]]:
    """Add bounded repository-internal target chains for selected symlinks."""

    budget = _budget or SurfaceMaterializationBudget()
    budget.check_file_count(len(entries))
    selected = {os.path.normcase(entry.path): entry for entry in entries}
    selected_requests: dict[str, set[SymlinkMaterializationRequest]] = {}
    prefix = "" if repo_relative in ("", ".") else f"{repo_relative.rstrip('/')}/"
    for key, entry in selected.items():
        if entry.mode != "120000":
            continue
        relative_path = entry.path[len(prefix) :] if prefix else entry.path
        requests = symlink_materialization_requests(
            path=relative_path,
            plan=materialization_plan,
        )
        if not requests:
            raise SurfaceDeltaError("surface delta found an unsafe materialization scope")
        selected_requests[key] = requests
    processed_requests: dict[str, frozenset[SymlinkMaterializationRequest]] = {}
    symlink_targets: dict[str, bytes] = {}
    normalized_targets: dict[str, str] = {}
    expanded_entry_count = 0
    expansion_depth = 0

    while True:
        budget.check_deadline()
        pending = [
            entry
            for key, entry in selected.items()
            if entry.mode == "120000"
            and processed_requests.get(key) != frozenset(selected_requests[key])
        ]
        if not pending:
            break
        expansion_depth += 1
        if expansion_depth > _MAX_SYMLINK_CHAIN_DEPTH:
            raise SurfaceDeltaError(
                "surface delta found an overly deep symlink chain in the base ref tree"
            )
        if len(symlink_targets) + len(
            [entry for entry in pending if entry.path not in symlink_targets]
        ) > _MAX_EXPANDED_SYMLINKS:
            raise SurfaceDeltaError(
                "surface delta found too many symlinks in the base ref tree"
            )

        round_targets = read_git_symlink_targets(
            toplevel=toplevel,
            entries=pending,
            _budget=budget,
        )
        projections: set[SurfaceMaterializationProjection] = set()
        for entry in pending:
            key = os.path.normcase(entry.path)
            target = round_targets[entry.path]
            symlink_targets[entry.path] = target
            normalized_target = normalize_git_symlink_target(
                link_path=entry.path,
                raw_target=target,
                repo_relative=repo_relative,
            )
            relative_link = entry.path[len(prefix) :] if prefix else entry.path
            if relative_link == normalized_target or relative_link.startswith(
                f"{normalized_target}/"
            ):
                raise SurfaceDeltaError(
                    "surface delta found a symlink cycle in the base ref tree"
                )
            normalized_targets[relative_link] = normalized_target
            if symlink_target_graph_has_cycle(normalized_targets):
                raise SurfaceDeltaError(
                    "surface delta found a symlink cycle in the base ref tree"
                )
            for request in selected_requests[key]:
                target_root = (
                    PurePosixPath(normalized_target, request.suffix).as_posix()
                    if request.suffix
                    else normalized_target
                )
                projections.add(
                    SurfaceMaterializationProjection(
                        scope=request.scope,
                        alias_root=request.alias_root,
                        target_root=target_root,
                        physical_alias_roots=request.physical_alias_roots,
                    )
                )
                if len(projections) > _MAX_MATERIALIZATION_PROJECTIONS:
                    raise SurfaceDeltaError(
                        "surface delta found too many materialization projections"
                    )
            processed_requests[key] = frozenset(selected_requests[key])

        round_projections = tuple(sorted(projections))
        discovered = parse_git_tree_entries(
            raw_listing,
            repo_relative=repo_relative,
            materialization_plan=materialization_plan,
            materialization_projections=round_projections,
            _budget=budget,
        )
        for entry in discovered:
            key = os.path.normcase(entry.path)
            requests: set[SymlinkMaterializationRequest] = set()
            if entry.mode == "120000":
                relative_path = entry.path[len(prefix) :] if prefix else entry.path
                requests = projected_symlink_requests(
                    path=relative_path,
                    projections=round_projections,
                    plan=materialization_plan,
                )
                if not requests:
                    raise SurfaceDeltaError(
                        "surface delta found an unsafe materialization scope"
                    )
            existing = selected.get(key)
            if existing is not None:
                if existing != entry:
                    raise SurfaceDeltaError(
                        "surface delta found duplicate paths in the base ref tree"
                    )
                if entry.mode == "120000":
                    selected_requests[key].update(requests)
                continue
            expanded_entry_count += 1
            if expanded_entry_count > _MAX_SYMLINK_TARGET_ENTRIES:
                raise SurfaceDeltaError(
                    "surface delta found too many symlink target entries in the base ref tree"
                )
            selected[key] = entry
            budget.check_file_count(len(selected))
            if entry.mode == "120000":
                selected_requests[key] = requests

    return sorted(selected.values(), key=lambda entry: entry.path), symlink_targets


def make_tar_info(entry: GitTreeEntry) -> tarfile.TarInfo:
    """Build deterministic tar metadata for one validated Git tree entry."""

    info = tarfile.TarInfo(entry.path)
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def write_git_tree_tar(
    *,
    toplevel: Path,
    entries: Sequence[GitTreeEntry],
    symlink_targets: Mapping[str, bytes],
    tar_stream: BinaryIO,
    _budget: SurfaceMaterializationBudget | None = None,
) -> None:
    """Write bounded raw Git blob output into a synthetic tar."""

    budget = _budget or SurfaceMaterializationBudget()
    budget.check_file_count(len(entries))
    regular_entries = [
        entry for entry in entries if entry.mode not in {"120000", "160000"}
    ]
    sizes = git_blob_sizes(
        toplevel=toplevel,
        entries=regular_entries,
        budget=budget,
    )
    for entry in regular_entries:
        size = sizes.get(entry.object_id)
        if size is None:
            raise SurfaceDeltaError("surface delta could not read the base ref tree")
        budget.charge_materialized_bytes(size)

    raw_blobs = b""
    if regular_entries:
        result = _run_surface_git(
            toplevel,
            ["cat-file", "--batch"],
            timeout_seconds=budget.remaining_timeout(),
            max_output_bytes=_MAX_MATERIALIZED_OUTPUT_BYTES,
            input_data="".join(
                f"{entry.object_id}\n" for entry in regular_entries
            ).encode("ascii"),
            error_message=_MATERIALIZATION_LIMIT_ERROR,
        )
        if result.returncode != 0:
            raise SurfaceDeltaError("surface delta could not read the base ref tree")
        raw_blobs = result.stdout

    blob_stream = io.BytesIO(raw_blobs)
    bounded_tar = BoundedTarWriter(tar_stream, budget=budget)
    with tarfile.open(fileobj=bounded_tar, mode="w:", format=tarfile.PAX_FORMAT) as tar:
        for entry in entries:
            budget.check_deadline()
            info = make_tar_info(entry)
            if entry.mode == "160000":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.size = 0
                tar.addfile(info)
                continue

            if entry.mode == "120000":
                target = symlink_targets.get(entry.path)
                if target is None:
                    raise SurfaceDeltaError(
                        "surface delta could not read the base ref tree"
                    )
                info.type = tarfile.SYMTYPE
                info.mode = 0o777
                info.size = 0
                info.linkname = os.fsdecode(target)
                tar.addfile(info)
                continue

            reader = begin_git_blob(blob_stream, entry.object_id)
            expected_size = sizes.get(entry.object_id)
            if expected_size is None or reader.remaining != expected_size:
                raise SurfaceDeltaError("surface delta could not read the base ref tree")
            info.type = tarfile.REGTYPE
            info.mode = 0o755 if entry.mode == "100755" else 0o644
            info.size = reader.remaining
            tar.addfile(info, reader)
            finish_git_blob(blob_stream, reader)

    if blob_stream.read(1):
        raise SurfaceDeltaError("surface delta could not read the base ref tree")


def filter_git_tree_tar_member(
    member: tarfile.TarInfo,
    dest_path: str,
    *,
    data_filter: Callable[[tarfile.TarInfo, str], tarfile.TarInfo | None],
    repo_relative: str,
    materialization_budget: SurfaceMaterializationBudget | None = None,
) -> tarfile.TarInfo | None:
    """Apply the stdlib data filter with correct relative-symlink semantics."""

    if materialization_budget is not None:
        materialization_budget.check_deadline()
    if not member.issym():
        return data_filter(member, dest_path)

    normalized_target = normalize_git_symlink_target(
        link_path=member.name,
        raw_target=os.fsencode(member.linkname),
        repo_relative=repo_relative,
    )
    archive_target = (
        PurePosixPath(repo_relative, normalized_target).as_posix()
        if repo_relative not in ("", ".")
        else normalized_target
    )

    # Python 3.11.4 checks a symlink target relative to the extraction root,
    # rather than the member's parent. Use the validated archive-root target
    # for that check, then restore the relative link value used on disk.
    filtered = data_filter(
        member.replace(linkname=archive_target, deep=False),
        dest_path,
    )
    if filtered is None:
        return None

    try:
        resolved_dest = Path(dest_path).resolve(strict=False)
        member_parent = PurePosixPath(member.name).parent
        resolved_target = Path(dest_path).joinpath(
            *member_parent.parts,
            member.linkname,
        ).resolve(strict=False)
        resolved_target.relative_to(resolved_dest)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SurfaceDeltaError(
            "surface delta found an unsafe symlink in the base ref tree"
        ) from exc

    return filtered.replace(linkname=member.linkname, deep=False)


def archive_base_tree(
    *,
    toplevel: Path,
    base_ref: str,
    dest: Path,
    repo_relative: str = "",
    context_policy: Mapping[str, object] | None = None,
    _budget: SurfaceMaterializationBudget | None = None,
) -> tuple[str, ...]:
    """Materialize raw tracked base_ref content without archive or checkout attributes."""

    budget = _budget or SurfaceMaterializationBudget()
    listing = run_git_tree_list(
        toplevel=toplevel,
        base_ref=base_ref,
        _budget=budget,
    )
    if listing.returncode != 0:
        raise SurfaceDeltaError(_BASE_REF_UNRESOLVED_MESSAGE)

    gitlink_paths = gitlink_paths_from_tree(
        listing.stdout,
        repo_relative=repo_relative,
        _budget=budget,
    )
    plan = surface_materialization_plan(context_policy or {})
    entries = parse_git_tree_entries(
        listing.stdout,
        repo_relative=repo_relative,
        materialization_plan=plan,
        _budget=budget,
    )
    entries, symlink_targets = expand_git_tree_symlink_targets(
        toplevel=toplevel,
        raw_listing=listing.stdout,
        repo_relative=repo_relative,
        entries=entries,
        materialization_plan=plan,
        _budget=budget,
    )
    budget.check_file_count(len(entries))
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryFile() as tar_stream:
            write_git_tree_tar(
                toplevel=toplevel,
                entries=entries,
                symlink_targets=symlink_targets,
                tar_stream=tar_stream,
                _budget=budget,
            )
            tar_stream.seek(0)
            with tarfile.open(fileobj=tar_stream, mode="r:") as tar:
                data_filter = getattr(tarfile, "data_filter", None)
                if data_filter is None:
                    raise SurfaceDeltaError(
                        "surface delta requires a safe tar extraction filter"
                    )
                tar.extractall(
                    path=dest,
                    filter=partial(
                        filter_git_tree_tar_member,
                        data_filter=data_filter,
                        repo_relative=repo_relative,
                        materialization_budget=budget,
                    ),
                )
                budget.check_deadline()
    except SurfaceDeltaError:
        raise
    except (MemoryError, OSError, OverflowError, tarfile.TarError, UnicodeError) as exc:
        raise SurfaceDeltaError("surface delta could not materialize the base ref tree") from exc
    return gitlink_paths


def surface_entry_name(surface: Mapping[str, object]) -> str:
    server_name = surface.get("server_name")
    if isinstance(server_name, str) and server_name:
        return server_name
    return ""


def surface_entry_key(surface: Mapping[str, object]) -> tuple[str, str, str]:
    kind = str(surface.get("surface", ""))
    path = str(surface.get("path", ""))
    return (kind, path, surface_entry_name(surface))


def surface_entry_risk_labels(surface: Mapping[str, object]) -> tuple[str, ...]:
    raw = surface.get("risky_patterns")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return ()
    labels = tuple(sorted({str(item) for item in raw if isinstance(item, str) and item}))
    if not set(labels).issubset(MCP_RISKY_PATTERNS):
        raise SurfaceDeltaError("surface delta found an unsupported risk label")
    return labels


def diff_entry_fields(base: Mapping[str, object], head: Mapping[str, object]) -> tuple[str, ...]:
    """Return changed metadata field *names* only; values never leave this function."""

    surface_kinds = {str(base.get("surface", "")), str(head.get("surface", ""))}
    ignored_fields = _IDENTITY_FIELDS | frozenset(
        field
        for surface_kind in surface_kinds
        for field in _LOCATOR_FIELDS_BY_SURFACE.get(surface_kind, ())
    )
    if (
        surface_kinds.issubset(_CONTENT_TRACKED_SURFACES)
        and _INTERNAL_CONTENT_REVISION_FIELD not in base
        and _INTERNAL_CONTENT_REVISION_FIELD not in head
    ):
        ignored_fields |= _CHECKOUT_TRANSFORMED_METADATA_FIELDS
    keys = (set(base) | set(head)) - ignored_fields
    changed_fields = {
        _PUBLIC_CHANGED_FIELD_ALIASES.get(key, key)
        for key in keys
        if base.get(key) != head.get(key)
    }
    if not changed_fields.issubset(_PUBLIC_CHANGED_FIELDS):
        raise SurfaceDeltaError("surface delta found unsupported surface metadata")
    return tuple(sorted(changed_fields))


def canonical_surface(surface: Mapping[str, object]) -> str:
    try:
        return json.dumps(
            surface,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (MemoryError, OverflowError, RecursionError, TypeError, ValueError):
        raise SurfaceDeltaError(ERROR_SURFACE_DELTA_INVALID) from None


def surface_match_fingerprint(surface: Mapping[str, object]) -> str:
    surface_kind = str(surface.get("surface", ""))
    ignored_fields = set(_LOCATOR_FIELDS_BY_SURFACE.get(surface_kind, ()))
    if (
        surface_kind in _CONTENT_TRACKED_SURFACES
        and _INTERNAL_CONTENT_REVISION_FIELD not in surface
    ):
        ignored_fields.update(_CHECKOUT_TRANSFORMED_METADATA_FIELDS)
    comparable = {key: value for key, value in surface.items() if key not in ignored_fields}
    return canonical_surface(comparable)


def bucket_surfaces(
    surfaces: Sequence[object],
) -> dict[tuple[str, str, str], list[dict[str, object]]]:
    buckets: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    for item in surfaces:
        if isinstance(item, Mapping):
            buckets.setdefault(surface_entry_key(item), []).append(dict(item))
    for bucket in buckets.values():
        bucket.sort(key=canonical_surface)
    return buckets


def subtract_identical_surfaces(
    *,
    base_surfaces: Sequence[Mapping[str, object]],
    head_surfaces: Sequence[Mapping[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    base_by_fingerprint = {surface_match_fingerprint(item): dict(item) for item in base_surfaces}
    head_by_fingerprint = {surface_match_fingerprint(item): dict(item) for item in head_surfaces}
    base_counts = Counter(surface_match_fingerprint(item) for item in base_surfaces)
    head_counts = Counter(surface_match_fingerprint(item) for item in head_surfaces)
    common_counts = base_counts & head_counts

    base_remaining = [
        base_by_fingerprint[fingerprint]
        for fingerprint in sorted(base_counts)
        for _ in range(base_counts[fingerprint] - common_counts[fingerprint])
    ]
    head_remaining = [
        head_by_fingerprint[fingerprint]
        for fingerprint in sorted(head_counts)
        for _ in range(head_counts[fingerprint] - common_counts[fingerprint])
    ]
    return base_remaining, head_remaining, sum(common_counts.values())


def build_surface_delta_entries(
    *,
    base_surfaces: Sequence[object],
    head_surfaces: Sequence[object],
) -> tuple[list[SurfaceDeltaEntry], dict[str, int]]:
    base_buckets = bucket_surfaces(base_surfaces)
    head_buckets = bucket_surfaces(head_surfaces)

    entries: list[SurfaceDeltaEntry] = []
    result_budget = _SurfaceDeltaResultBudget()
    unchanged_count = 0
    for key in sorted(set(base_buckets) | set(head_buckets)):
        base_remaining, head_remaining, unchanged = subtract_identical_surfaces(
            base_surfaces=base_buckets.get(key, []),
            head_surfaces=head_buckets.get(key, []),
        )
        unchanged_count += unchanged
        kind, path, name = key
        paired_count = min(len(base_remaining), len(head_remaining))

        for base_item, head_item in zip(
            base_remaining[:paired_count],
            head_remaining[:paired_count],
            strict=True,
        ):
            changed_fields = diff_entry_fields(base_item, head_item)
            if not changed_fields:
                unchanged_count += 1
                continue
            entry = SurfaceDeltaEntry(
                kind=kind,
                path=path,
                name=name,
                status="modified",
                risk_labels=surface_entry_risk_labels(head_item),
                changed_fields=changed_fields,
            )
            result_budget.add(entry)
            entries.append(entry)

        for head_item in head_remaining[paired_count:]:
            entry = SurfaceDeltaEntry(
                kind=kind,
                path=path,
                name=name,
                status="added",
                risk_labels=surface_entry_risk_labels(head_item),
            )
            result_budget.add(entry)
            entries.append(entry)
        for base_item in base_remaining[paired_count:]:
            entry = SurfaceDeltaEntry(
                kind=kind,
                path=path,
                name=name,
                status="removed",
                risk_labels=surface_entry_risk_labels(base_item),
            )
            result_budget.add(entry)
            entries.append(entry)

    entries.sort(
        key=lambda entry: (
            entry.kind,
            entry.path,
            entry.name,
            entry.status,
            entry.changed_fields,
            entry.risk_labels,
        )
    )
    summary = {
        "added": sum(1 for entry in entries if entry.status == "added"),
        "removed": sum(1 for entry in entries if entry.status == "removed"),
        "modified": sum(1 for entry in entries if entry.status == "modified"),
        "unchanged": unchanged_count,
    }
    return entries, summary


def collect_surfaces_for_root(
    *,
    root: Path,
    context_policy: Mapping[str, object],
    opaque_directories: Sequence[str] = (),
) -> list[object]:
    if not root.is_dir():
        return []
    inventory = collect_agent_surface_inventory(
        root=root,
        context_policy=dict(context_policy),
        schema_version="v2",
        opaque_directories=opaque_directories,
        include_empty_directory_surfaces=False,
    )
    surfaces = inventory.get("surfaces", [])
    if not isinstance(surfaces, list):
        return []
    directory_surface_kinds = {"agent_skill", "agent_profile", "agent_command"}
    for path in opaque_directories:
        represented = any(
            isinstance(item, Mapping)
            and item.get("surface") in directory_surface_kinds
            and (
                str(item.get("path", "")) == path
                or path.startswith(f"{str(item.get('path', '')).rstrip('/')}/")
            )
            for item in surfaces
        )
        if not represented:
            surfaces.append(
                {
                    "surface": "git_submodule",
                    "path": path,
                    "kind": "gitlink",
                    "status": "present",
                }
            )
    return sorted(
        surfaces,
        key=lambda item: canonical_surface(item) if isinstance(item, Mapping) else repr(item),
    )


def build_surface_delta_report(
    *,
    root: Path,
    context_policy: dict[str, object],
    base_ref: str,
) -> dict[str, object]:
    """Compute sanitized surface-inventory-v2 delta between base_ref and the working tree.

    Security decisions (see PRD Surface Delta Evidence v1 SS3.2, SS3.4):
    policy/config is always read from head (context_policy is never re-read
    from the base tree); raw Git tree/blob objects are materialized read-only
    without archive attributes or checkout filters (no `git worktree`, no
    writes to .git); and nothing in the base tree is treated as executable
    instructions.
    """

    root = root.resolve()
    if not is_safe_base_ref_arg(base_ref):
        raise SurfaceDeltaError("surface delta requires a non-empty, safe --base-ref value")

    budget = SurfaceMaterializationBudget()
    toplevel = resolve_repo_toplevel(root, _budget=budget)
    if toplevel is None:
        raise SurfaceDeltaError("surface delta requires --root to be inside a git repository")

    repo_relative = repo_relative_root(root=root, toplevel=toplevel)
    merge_base = resolve_merge_base(
        root=root,
        base_ref=base_ref,
        _budget=budget,
    )
    changed_paths = changed_repo_paths(
        root=root,
        base_ref=merge_base,
        _budget=budget,
    )
    ensure_changed_symlinks_stay_in_root(root=root, changed_paths=changed_paths)
    head_gitlinks = gitlink_paths_from_index(
        toplevel=toplevel,
        repo_relative=repo_relative,
        _budget=budget,
    )

    with tempfile.TemporaryDirectory(prefix="agent-guard-surface-delta-") as raw_tmpdir:
        tmpdir = Path(raw_tmpdir)
        base_gitlinks = archive_base_tree(
            toplevel=toplevel,
            base_ref=merge_base,
            dest=tmpdir,
            repo_relative=repo_relative,
            context_policy=context_policy,
            _budget=budget,
        )
        base_root = tmpdir if repo_relative in ("", ".") else tmpdir / repo_relative

        base_surfaces = collect_surfaces_for_root(
            root=base_root,
            context_policy=context_policy,
            opaque_directories=base_gitlinks,
        )
        head_surfaces = collect_surfaces_for_root(
            root=root,
            context_policy=context_policy,
            opaque_directories=head_gitlinks,
        )

    base_surfaces = annotate_content_revisions(
        base_surfaces,
        changed_paths=changed_paths,
        revision="base",
    )
    head_surfaces = annotate_content_revisions(
        head_surfaces,
        changed_paths=changed_paths,
        revision="head",
    )

    entries, summary = build_surface_delta_entries(
        base_surfaces=base_surfaces,
        head_surfaces=head_surfaces,
    )

    return {
        "schema_version": SURFACE_DELTA_SCHEMA_VERSION_V1,
        "base_resolved": True,
        "summary": summary,
        "entries": [entry.to_dict() for entry in entries],
    }
