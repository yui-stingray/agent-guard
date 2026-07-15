"""Where: src/agent_guard/surface_delta.py
What: sanitized PR base/head agent surface delta evidence (surface inventory v2 diff).
Why: turn ad hoc PR agent-surface review into deterministic, sanitized evidence
     without publishing raw diffs, base ref names, or instruction/description bodies.
"""

from __future__ import annotations

import io
import subprocess
import tarfile
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .surface_inventory import collect_agent_surface_inventory


SURFACE_DELTA_SCHEMA_VERSION_V1 = "agent-guard.surface_delta.v1"

# Identity fields key a surface entry (added/removed/modified matching) and are
# never listed in changed_fields; every other field is compared by name only.
_IDENTITY_FIELDS = frozenset({"surface", "path", "server_name", "name"})
_UNSAFE_BASE_REF_CHARS = "\x00\r\n"
_BASE_REF_UNRESOLVED_MESSAGE = (
    "surface delta could not resolve --base-ref; fetch it explicitly in CI "
    "(for example: git fetch origin <base-ref> --depth=1) before running "
    "`agent-guard surface delta`"
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
        payload: dict[str, object] = {
            "kind": self.kind,
            "path": self.path,
            "name": self.name,
            "status": self.status,
        }
        if self.risk_labels:
            payload["risk_labels"] = list(self.risk_labels)
        payload["changed_fields"] = list(self.changed_fields)
        return payload


def is_safe_base_ref_arg(base_ref: str) -> bool:
    return bool(base_ref) and not base_ref.startswith("-") and not any(
        char in base_ref for char in _UNSAFE_BASE_REF_CHARS
    )


def run_git_command(cwd: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def resolve_repo_toplevel(root: Path) -> Path | None:
    try:
        result = run_git_command(root, ["rev-parse", "--show-toplevel"])
    except FileNotFoundError:
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


def run_git_archive(*, toplevel: Path, base_ref: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(toplevel), "archive", "--format=tar", base_ref],
        capture_output=True,
        check=False,
    )


def archive_base_tree(*, toplevel: Path, base_ref: str, dest: Path) -> None:
    """Materialize base_ref's tree into dest via read-only `git archive` (no git worktree)."""

    archive = run_git_archive(toplevel=toplevel, base_ref=base_ref)
    if archive.returncode != 0:
        raise SurfaceDeltaError(_BASE_REF_UNRESOLVED_MESSAGE)
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as tar:
            extract_filter = getattr(tarfile, "data_filter", None)
            if extract_filter is not None:
                tar.extractall(path=dest, filter=extract_filter)
            else:  # pragma: no cover - only reachable on interpreters missing the safety filter
                tar.extractall(path=dest)
    except (tarfile.TarError, OSError) as exc:
        raise SurfaceDeltaError("surface delta could not extract the base ref tree") from exc


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
    return tuple(sorted(str(item) for item in raw if isinstance(item, str) and item))


def diff_entry_fields(base: Mapping[str, object], head: Mapping[str, object]) -> tuple[str, ...]:
    """Return changed metadata field *names* only; values never leave this function."""

    keys = (set(base) | set(head)) - _IDENTITY_FIELDS
    return tuple(sorted(key for key in keys if base.get(key) != head.get(key)))


def index_surfaces(surfaces: Sequence[object]) -> dict[tuple[str, str, str], dict[str, object]]:
    indexed: dict[tuple[str, str, str], dict[str, object]] = {}
    for item in surfaces:
        if isinstance(item, Mapping):
            indexed[surface_entry_key(item)] = dict(item)
    return indexed


def build_surface_delta_entries(
    *,
    base_surfaces: Sequence[object],
    head_surfaces: Sequence[object],
) -> tuple[list[SurfaceDeltaEntry], dict[str, int]]:
    base_index = index_surfaces(base_surfaces)
    head_index = index_surfaces(head_surfaces)
    base_keys = set(base_index)
    head_keys = set(head_index)

    entries: list[SurfaceDeltaEntry] = []
    for kind, path, name in head_keys - base_keys:
        entries.append(
            SurfaceDeltaEntry(
                kind=kind,
                path=path,
                name=name,
                status="added",
                risk_labels=surface_entry_risk_labels(head_index[(kind, path, name)]),
            )
        )
    for kind, path, name in base_keys - head_keys:
        entries.append(
            SurfaceDeltaEntry(
                kind=kind,
                path=path,
                name=name,
                status="removed",
                risk_labels=surface_entry_risk_labels(base_index[(kind, path, name)]),
            )
        )

    unchanged_count = 0
    for key in base_keys & head_keys:
        changed_fields = diff_entry_fields(base_index[key], head_index[key])
        if not changed_fields:
            unchanged_count += 1
            continue
        kind, path, name = key
        entries.append(
            SurfaceDeltaEntry(
                kind=kind,
                path=path,
                name=name,
                status="modified",
                risk_labels=surface_entry_risk_labels(head_index[key]),
                changed_fields=changed_fields,
            )
        )

    entries.sort(key=lambda entry: (entry.kind, entry.path, entry.name))
    summary = {
        "added": sum(1 for entry in entries if entry.status == "added"),
        "removed": sum(1 for entry in entries if entry.status == "removed"),
        "modified": sum(1 for entry in entries if entry.status == "modified"),
        "unchanged": unchanged_count,
    }
    return entries, summary


def collect_surfaces_for_root(*, root: Path, context_policy: Mapping[str, object]) -> list[object]:
    if not root.is_dir():
        return []
    inventory = collect_agent_surface_inventory(
        root=root,
        context_policy=dict(context_policy),
        schema_version="v2",
    )
    surfaces = inventory.get("surfaces", [])
    return surfaces if isinstance(surfaces, list) else []


def build_surface_delta_report(
    *,
    root: Path,
    context_policy: dict[str, object],
    base_ref: str,
) -> dict[str, object]:
    """Compute sanitized surface-inventory-v2 delta between base_ref and the working tree.

    Security decisions (see PRD Surface Delta Evidence v1 SS3.2, SS3.4):
    policy/config is always read from head (context_policy is never re-read
    from the base tree); the base tree is materialized read-only via
    `git archive` (no `git worktree`, no writes to .git); and nothing in the
    base tree is treated as executable instructions.
    """

    root = root.resolve()
    if not is_safe_base_ref_arg(base_ref):
        raise SurfaceDeltaError("surface delta requires a non-empty, safe --base-ref value")

    toplevel = resolve_repo_toplevel(root)
    if toplevel is None:
        raise SurfaceDeltaError("surface delta requires --root to be inside a git repository")

    repo_relative = repo_relative_root(root=root, toplevel=toplevel)

    with tempfile.TemporaryDirectory(prefix="agent-guard-surface-delta-") as raw_tmpdir:
        tmpdir = Path(raw_tmpdir)
        archive_base_tree(toplevel=toplevel, base_ref=base_ref, dest=tmpdir)
        base_root = tmpdir if repo_relative in ("", ".") else tmpdir / repo_relative

        base_surfaces = collect_surfaces_for_root(root=base_root, context_policy=context_policy)
        head_surfaces = collect_surfaces_for_root(root=root, context_policy=context_policy)

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
