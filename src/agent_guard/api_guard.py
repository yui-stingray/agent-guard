"""Where: src/agent_guard/api_guard.py
What: static scanner for forbidden API endpoint usage inside a repository.
Why: keep CLI-first or otherwise bounded integration rules enforceable in CI and hooks.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

from .bounded_scan import MAX_ISOLATED_MESSAGE_BYTES, run_isolated_scan
from .bounded_yaml import (
    BoundedYamlInvalidError,
    BoundedYamlLimitError,
    load_bounded_yaml,
)


# Stable, public-safe errors for untrusted policy and scan resource failures.
ERROR_API_POLICY_NOT_FOUND = "api policy file not found"
ERROR_API_POLICY_INVALID = "api policy is invalid"
ERROR_API_POLICY_LIMIT = "api policy exceeds configured limits"
ERROR_API_SCAN_TARGET = "api scan target must stay under repo root"
ERROR_API_SCAN_LIMIT = "api scan exceeds configured limits"
ERROR_API_SCAN_TIMEOUT = "api scan exceeded execution budget"
ERROR_API_SCAN_RUNTIME = "api scan could not complete safely"

MAX_API_POLICY_BYTES = 256 * 1024
MAX_API_POLICY_LIST_ITEMS = 256
MAX_API_INCLUDE_TARGETS = 64
MAX_API_POLICY_REGEX_COUNT = 64
MAX_API_POLICY_REGEX_LENGTH = 4_096
MAX_API_SCAN_WORK_ITEMS = 20_000
MAX_API_SCAN_FILES = 10_000
MAX_API_FILE_BYTES = 1_048_576
MAX_API_LINES_PER_FILE = 50_000
MAX_API_LINE_CHARS = 16_384
MAX_API_URLS = 100_000
MAX_API_FINDINGS = 10_000
# Reserve half the isolated transport cap for pickle/container overhead.
MAX_API_AGGREGATE_RESULT_BYTES = MAX_ISOLATED_MESSAGE_BYTES // 2
API_FINDING_RESULT_OVERHEAD_BYTES = 256

URL_PATTERN = re.compile(r"https?://[^\s\"'`<>()]+", re.IGNORECASE)
TRAILING_URL_PUNCTUATION = ".,);"


@dataclass(frozen=True)
class ApiGuardFinding:
    path: str
    line: int
    url: str
    matched_forbidden_pattern: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "line": self.line,
            "url": self.url,
            "matched_forbidden_pattern": self.matched_forbidden_pattern,
        }


def _read_policy_text(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_API_POLICY_BYTES + 1)
    except FileNotFoundError:
        raise FileNotFoundError(f"{ERROR_API_POLICY_NOT_FOUND}: {path}") from None
    except OSError:
        raise ValueError(ERROR_API_POLICY_INVALID) from None

    if len(raw) > MAX_API_POLICY_BYTES:
        raise ValueError(ERROR_API_POLICY_LIMIT)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(ERROR_API_POLICY_INVALID) from None


def load_yaml_policy(path: Path) -> dict[str, Any]:
    try:
        loaded = load_bounded_yaml(
            _read_policy_text(path),
            construct=yaml.safe_load,
        ) or {}
        if not isinstance(loaded, dict):
            raise BoundedYamlInvalidError
    except BoundedYamlLimitError:
        raise ValueError(ERROR_API_POLICY_LIMIT) from None
    except BoundedYamlInvalidError:
        raise ValueError(ERROR_API_POLICY_INVALID) from None
    except (MemoryError, OverflowError, RecursionError):
        raise ValueError(ERROR_API_POLICY_LIMIT) from None
    return loaded


def _contains_parent_traversal(path_text: str) -> bool:
    return any(part == ".." for part in re.split(r"[\\/]", path_text))


def _lexical_rel_path(root: Path, path_text: str) -> tuple[Path, str]:
    text = path_text.strip()
    if _contains_parent_traversal(text):
        raise ValueError(ERROR_API_SCAN_TARGET)

    try:
        resolved_root = root.resolve()
        path = Path(text)
        target = path if path.is_absolute() else resolved_root / path
        target = Path(os.path.abspath(target))
        rel_path = target.relative_to(resolved_root).as_posix()
    except (OSError, RuntimeError, ValueError):
        raise ValueError(ERROR_API_SCAN_TARGET) from None
    return target, rel_path


def _resolve_repo_target(root: Path, target: Path) -> Path:
    try:
        resolved_root = root.resolve()
        resolved_target = target.resolve(strict=False)
        resolved_target.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError):
        raise ValueError(ERROR_API_SCAN_TARGET) from None
    return resolved_target


def normalize_rel_path(root: Path, path_text: str) -> Path:
    target, _ = _lexical_rel_path(root, path_text)
    return _resolve_repo_target(root, target)


def normalize_string_list(values: Any, *, limit: int = MAX_API_POLICY_LIST_ITEMS) -> list[str]:
    if not isinstance(values, list):
        raise ValueError(ERROR_API_POLICY_INVALID)
    if len(values) > limit:
        raise ValueError(ERROR_API_POLICY_LIMIT)
    out: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError(ERROR_API_POLICY_INVALID)
        text = value.strip()
        if len(text) > MAX_API_POLICY_REGEX_LENGTH:
            raise ValueError(ERROR_API_POLICY_LIMIT)
        if text:
            out.append(text)
    return out


def normalize_pattern_list(values: Any) -> list[re.Pattern[str]]:
    patterns: list[re.Pattern[str]] = []
    for text in normalize_string_list(values, limit=MAX_API_POLICY_REGEX_COUNT):
        if len(text) > MAX_API_POLICY_REGEX_LENGTH:
            raise ValueError(ERROR_API_POLICY_LIMIT)
        try:
            patterns.append(re.compile(text))
        except (OverflowError, RecursionError, re.error):
            raise ValueError(ERROR_API_POLICY_INVALID) from None
    return patterns


def is_excluded(rel_path: str, excluded_prefixes: list[str]) -> bool:
    return any(rel_path == prefix or rel_path.startswith(prefix + "/") for prefix in excluded_prefixes)


def _validate_include_targets(root: Path, include_paths: Iterable[str], exclude: list[str]) -> None:
    for include_path in include_paths:
        target, rel_path = _lexical_rel_path(root, include_path)
        if is_excluded(rel_path, exclude):
            continue
        _resolve_repo_target(root, target)


def iter_scan_files(root: Path, include: list[str], exclude: list[str]) -> Iterable[Path]:
    if len(include) > MAX_API_INCLUDE_TARGETS or len(exclude) > MAX_API_POLICY_LIST_ITEMS:
        raise ValueError(ERROR_API_POLICY_LIMIT)

    root = root.resolve()
    scanned_work_items = 0
    selected_files = 0
    for include_path in include:
        lexical_target, target_rel = _lexical_rel_path(root, include_path)
        if is_excluded(target_rel, exclude):
            continue
        target = _resolve_repo_target(root, lexical_target)
        resolved_target_rel = target.relative_to(root).as_posix()
        if is_excluded(resolved_target_rel, exclude):
            continue
        if not target.exists():
            continue
        if target.is_file():
            scanned_work_items += 1
            if scanned_work_items > MAX_API_SCAN_WORK_ITEMS:
                raise ValueError(ERROR_API_SCAN_LIMIT)
            rel = target.relative_to(root).as_posix()
            if not is_excluded(rel, exclude):
                selected_files += 1
                if selected_files > MAX_API_SCAN_FILES:
                    raise ValueError(ERROR_API_SCAN_LIMIT)
                yield target
            continue

        files: list[Path] = []
        pending = [target] if target.is_dir() else []
        try:
            while pending:
                current = pending.pop()
                with os.scandir(current) as entries:
                    for entry in entries:
                        scanned_work_items += 1
                        if scanned_work_items > MAX_API_SCAN_WORK_ITEMS:
                            raise ValueError(ERROR_API_SCAN_LIMIT)
                        path = current / entry.name
                        rel = path.relative_to(root).as_posix()
                        if is_excluded(rel, exclude):
                            continue
                        resolved_path = _resolve_repo_target(root, path)
                        resolved_rel = resolved_path.relative_to(root).as_posix()
                        if is_excluded(resolved_rel, exclude):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(path)
                            continue
                        if not path.is_file():
                            continue
                        selected_files += 1
                        if selected_files > MAX_API_SCAN_FILES:
                            raise ValueError(ERROR_API_SCAN_LIMIT)
                        files.append(path)
        except OSError:
            raise ValueError(ERROR_API_SCAN_LIMIT) from None

        for path in sorted(files):
            yield path


def _path_is_lexically_under(path: Path, root: Path) -> bool:
    try:
        Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
    except ValueError:
        return False
    return True


def _open_repo_file_posix(repo_root: Path, relative_path: Path) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory or os.open not in os.supports_dir_fd:
        raise ValueError(ERROR_API_SCAN_TARGET)

    directory_flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    directory_fd: int | None = None
    file_fd: int | None = None
    try:
        directory_fd = os.open(repo_root, directory_flags)
        for component in relative_path.parts[:-1]:
            next_fd = os.open(
                component,
                directory_flags,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            relative_path.parts[-1],
            file_flags,
            dir_fd=directory_fd,
        )
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise OSError
        return file_fd
    except (OSError, TypeError, ValueError):
        if file_fd is not None:
            os.close(file_fd)
        raise ValueError(ERROR_API_SCAN_TARGET) from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


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


def _open_repo_file_windows(repo_root: Path, resolved_path: Path) -> int:
    file_fd: int | None = None
    try:
        file_fd = os.open(
            resolved_path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0),
        )
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise OSError
        final_path = os.path.normcase(os.path.normpath(_windows_final_handle_path(file_fd)))
        normalized_root = os.path.normcase(os.path.normpath(str(repo_root)))
        if os.path.commonpath((normalized_root, final_path)) != normalized_root:
            raise OSError
        return file_fd
    except (OSError, TypeError, ValueError):
        if file_fd is not None:
            os.close(file_fd)
        raise ValueError(ERROR_API_SCAN_TARGET) from None


def _open_repo_bound_file(path: Path, repo_root: Path) -> tuple[int, str]:
    if not _path_is_lexically_under(path, repo_root):
        raise ValueError(ERROR_API_SCAN_TARGET)

    try:
        resolved_root = repo_root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        relative_path = resolved_path.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError):
        raise ValueError(ERROR_API_SCAN_TARGET) from None
    if not relative_path.parts:
        raise ValueError(ERROR_API_SCAN_TARGET)

    if os.name == "nt":
        file_fd = _open_repo_file_windows(resolved_root, resolved_path)
    else:
        file_fd = _open_repo_file_posix(resolved_root, relative_path)
    return file_fd, relative_path.as_posix()


def _read_repo_text(path: Path, repo_root: Path) -> tuple[str | None, str]:
    file_fd, rel_path = _open_repo_bound_file(path, repo_root)
    try:
        handle = os.fdopen(file_fd, "rb")
    except OSError:
        try:
            os.close(file_fd)
        except OSError:
            pass
        raise RuntimeError(ERROR_API_SCAN_RUNTIME) from None
    try:
        with handle:
            raw = handle.read(MAX_API_FILE_BYTES + 1)
    except OSError:
        raise RuntimeError(ERROR_API_SCAN_RUNTIME) from None
    if len(raw) > MAX_API_FILE_BYTES:
        raise ValueError(ERROR_API_SCAN_LIMIT)
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, rel_path
    if "\x00" in content:
        return None, rel_path
    return content, rel_path


def _trim_url_trailing_punctuation(raw_url: str) -> str:
    normalized = raw_url.rstrip(TRAILING_URL_PUNCTUATION)
    scheme, separator, remainder = normalized.partition("://")
    if not separator:
        return normalized.rstrip("]")
    authority_end = min(
        (index for delimiter in "/?#" if (index := remainder.find(delimiter)) >= 0),
        default=len(remainder),
    )
    authority = remainder[:authority_end]
    _userinfo, at_sign, host_port = authority.rpartition("@")
    if not at_sign:
        host_port = authority

    if (
        authority_end == len(remainder)
        and host_port.startswith("[")
        and "]" in host_port
        and host_port[host_port.index("]") + 1 :].strip("]") == ""
    ):
        return normalized.rstrip("]") + "]"
    return normalized.rstrip("]")


def normalize_url(raw_url: str) -> str:
    normalized = _trim_url_trailing_punctuation(raw_url)
    scheme, separator, remainder = normalized.partition("://")
    if not separator:
        return normalized
    authority_end = min(
        (index for delimiter in "/?#" if (index := remainder.find(delimiter)) >= 0),
        default=len(remainder),
    )
    authority = remainder[:authority_end]
    suffix = remainder[authority_end:]
    userinfo, at_sign, host_port = authority.rpartition("@")
    if not at_sign:
        userinfo = ""
        host_port = authority

    if host_port.startswith("[") and "]" in host_port:
        closing = host_port.index("]")
        normalized_host_port = host_port[: closing + 1].lower() + host_port[closing + 1 :]
    elif host_port.count(":") == 1:
        host, colon, port = host_port.partition(":")
        normalized_host_port = f"{host.lower()}{colon}{port}"
    else:
        normalized_host_port = host_port.lower()
    normalized_authority = (
        f"{userinfo}{at_sign}{normalized_host_port}"
        if at_sign
        else normalized_host_port
    )
    return f"{scheme.lower()}{separator}{normalized_authority}{suffix}"


def _finding_result_size_bytes(*values: str) -> int:
    return API_FINDING_RESULT_OVERHEAD_BYTES + sum(
        len(value.encode("utf-8", errors="surrogatepass")) for value in values
    )


def _scan_urls_unbounded(
    root: Path,
    include_paths: list[str],
    exclude_paths: list[str],
    allowed_patterns: list[re.Pattern[str]],
    forbidden_patterns: list[re.Pattern[str]],
) -> tuple[list[ApiGuardFinding], int]:
    findings: list[ApiGuardFinding] = []
    aggregate_result_bytes = 0
    scanned_count = 0
    urls_scanned = 0
    for path in iter_scan_files(root, include_paths, exclude_paths):
        scanned_count += 1
        content, rel_path = _read_repo_text(path, root)
        if content is None:
            continue

        for lineno, line in enumerate(content.splitlines(), start=1):
            if lineno > MAX_API_LINES_PER_FILE or len(line) > MAX_API_LINE_CHARS:
                raise ValueError(ERROR_API_SCAN_LIMIT)
            for match in URL_PATTERN.finditer(line):
                urls_scanned += 1
                if urls_scanned > MAX_API_URLS:
                    raise ValueError(ERROR_API_SCAN_LIMIT)
                url = _trim_url_trailing_punctuation(match.group(0))
                canonical_url = normalize_url(url)
                policy_candidates = (url, canonical_url)

                if any(
                    pattern.search(candidate)
                    for pattern in allowed_patterns
                    for candidate in policy_candidates
                ):
                    continue

                for forbidden in forbidden_patterns:
                    if any(
                        forbidden.search(candidate)
                        for candidate in policy_candidates
                    ):
                        if len(findings) >= MAX_API_FINDINGS:
                            raise ValueError(ERROR_API_SCAN_LIMIT)
                        finding_result_bytes = _finding_result_size_bytes(
                            rel_path,
                            url,
                            forbidden.pattern,
                        )
                        if finding_result_bytes > (
                            MAX_API_AGGREGATE_RESULT_BYTES - aggregate_result_bytes
                        ):
                            raise ValueError(ERROR_API_SCAN_LIMIT)
                        findings.append(
                            ApiGuardFinding(
                                path=rel_path,
                                line=lineno,
                                url=url,
                                matched_forbidden_pattern=forbidden.pattern,
                            )
                        )
                        aggregate_result_bytes += finding_result_bytes
                        break
    return findings, scanned_count


def scan_urls_with_count(
    *,
    root: Path,
    policy: dict[str, Any],
) -> tuple[list[ApiGuardFinding], int]:
    root = root.resolve()
    raw_scan_cfg = policy.get("scan", {})
    if not isinstance(raw_scan_cfg, dict):
        raise ValueError(ERROR_API_POLICY_INVALID)
    scan_cfg = raw_scan_cfg
    include_paths = normalize_string_list(
        scan_cfg.get("include", []),
        limit=MAX_API_INCLUDE_TARGETS,
    )
    exclude_paths = normalize_string_list(scan_cfg.get("exclude", []))
    _validate_include_targets(root, include_paths, exclude_paths)

    raw_policy_cfg = policy.get("policy", {})
    if not isinstance(raw_policy_cfg, dict):
        raise ValueError(ERROR_API_POLICY_INVALID)
    policy_cfg = raw_policy_cfg
    allowed_values = policy_cfg.get("allowed_api_patterns", [])
    forbidden_values = policy_cfg.get("forbidden_api_patterns", [])
    policy_regex_count = sum(
        len(values)
        for values in (allowed_values, forbidden_values)
        if isinstance(values, list)
    )
    if policy_regex_count > MAX_API_POLICY_REGEX_COUNT:
        raise ValueError(ERROR_API_POLICY_LIMIT)
    allowed_patterns = normalize_pattern_list(allowed_values)
    forbidden_patterns = normalize_pattern_list(forbidden_values)

    return run_isolated_scan(
        _scan_urls_unbounded,
        root,
        include_paths,
        exclude_paths,
        allowed_patterns,
        forbidden_patterns,
        timeout_error=ERROR_API_SCAN_TIMEOUT,
        runtime_error=ERROR_API_SCAN_RUNTIME,
        result_limit_error=ERROR_API_SCAN_LIMIT,
        safe_errors=(ERROR_API_SCAN_LIMIT, ERROR_API_SCAN_TARGET),
    )


def scan_urls(*, root: Path, policy: dict[str, Any]) -> list[ApiGuardFinding]:
    findings, _ = scan_urls_with_count(root=root, policy=policy)
    return findings
