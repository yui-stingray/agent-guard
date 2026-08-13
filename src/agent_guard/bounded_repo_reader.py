"""Where: src/agent_guard/bounded_repo_reader.py
What: race-resistant bounded reads for repository-controlled context and MCP files.
Why: bind containment and size decisions to the file descriptor that supplies bytes.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path


class BoundedRepoFileNotFoundError(Exception):
    """The selected file no longer exists."""


class BoundedRepoReadError(Exception):
    """The selected file could not be read as a regular file."""


class BoundedRepoContainmentError(Exception):
    """The selected file could not be bound below its allowed root."""


class BoundedRepoLimitError(Exception):
    """The selected file exceeded its caller-provided byte ceiling."""


@dataclass(frozen=True)
class BoundedRepoReceipt:
    relative_path: str
    identity: tuple[int, int]
    size_bytes: int
    sha256: bytes


@dataclass(frozen=True)
class BoundedRepoFile:
    data: bytes
    relative_path: str
    identity: tuple[int, int]

    def receipt(self) -> BoundedRepoReceipt:
        return BoundedRepoReceipt(
            relative_path=self.relative_path,
            identity=self.identity,
            size_bytes=len(self.data),
            sha256=hashlib.sha256(self.data).digest(),
        )


class DistinctInputBudget:
    """Charge each stable file version once against an aggregate byte ceiling."""

    def __init__(self, *, max_bytes: int) -> None:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
            raise BoundedRepoLimitError from None
        self.max_bytes = max_bytes
        self.used_bytes = 0
        self._seen: dict[object, bytes] = {}

    def charge(self, opened: BoundedRepoFile) -> None:
        self.charge_receipt(opened.receipt())

    def charge_receipt(self, receipt: BoundedRepoReceipt) -> None:
        identity: object = (
            ("file", receipt.identity)
            if receipt.identity != (0, 0)
            else ("path", receipt.relative_path)
        )
        if (
            isinstance(receipt.size_bytes, bool)
            or not isinstance(receipt.size_bytes, int)
            or receipt.size_bytes < 0
            or not isinstance(receipt.sha256, bytes)
            or len(receipt.sha256) != hashlib.sha256().digest_size
        ):
            raise BoundedRepoReadError from None
        self._charge_digest(
            identity=identity,
            digest=receipt.sha256,
            size_bytes=receipt.size_bytes,
        )

    def _charge_digest(
        self,
        *,
        identity: object,
        digest: bytes,
        size_bytes: int,
    ) -> None:
        previous_digest = self._seen.get(identity)
        if previous_digest == digest:
            return
        if previous_digest is not None:
            raise BoundedRepoReadError from None
        if size_bytes > self.max_bytes - self.used_bytes:
            raise BoundedRepoLimitError from None
        self._seen[identity] = digest
        self.used_bytes += size_bytes

    def charge_bytes(self, data: bytes, *, identity: object) -> None:
        """Charge bytes using a caller-provided stable repository identity."""

        self._charge_digest(
            identity=identity,
            digest=hashlib.sha256(data).digest(),
            size_bytes=len(data),
        )


def _path_is_lexically_under(path: Path, root: Path) -> bool:
    try:
        Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
    except (OSError, ValueError):
        return False
    return True


def _raise_open_error(exc: OSError) -> None:
    if isinstance(exc, FileNotFoundError):
        raise BoundedRepoFileNotFoundError from None
    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
        raise BoundedRepoContainmentError from None
    raise BoundedRepoReadError from None


def _open_repo_file_posix(repo_root: Path, relative_path: Path) -> int:
    """Open a regular file below ``repo_root`` without following components."""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory or os.open not in os.supports_dir_fd:
        raise BoundedRepoContainmentError from None

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
            raise BoundedRepoReadError
        return file_fd
    except BoundedRepoReadError:
        if file_fd is not None:
            os.close(file_fd)
        raise
    except OSError as exc:
        if file_fd is not None:
            os.close(file_fd)
        _raise_open_error(exc)
        raise AssertionError("unreachable")
    except ValueError:
        if file_fd is not None:
            os.close(file_fd)
        raise BoundedRepoContainmentError from None
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
    """Open a file and enforce root containment on its native final handle."""

    file_fd: int | None = None
    try:
        file_fd = os.open(
            resolved_path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0),
        )
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise BoundedRepoReadError
        final_path = os.path.normcase(os.path.normpath(_windows_final_handle_path(file_fd)))
        normalized_root = os.path.normcase(os.path.normpath(str(repo_root)))
        if os.path.commonpath((normalized_root, final_path)) != normalized_root:
            raise BoundedRepoContainmentError
        return file_fd
    except (BoundedRepoContainmentError, BoundedRepoReadError):
        if file_fd is not None:
            os.close(file_fd)
        raise
    except OSError as exc:
        if file_fd is not None:
            os.close(file_fd)
        _raise_open_error(exc)
        raise AssertionError("unreachable")
    except ValueError:
        if file_fd is not None:
            os.close(file_fd)
        raise BoundedRepoContainmentError from None


def _file_identity(value: os.stat_result) -> tuple[int, int]:
    return (int(value.st_dev), int(value.st_ino))


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    try:
        return os.path.samestat(first, second)
    except (AttributeError, OSError, ValueError):
        return _file_identity(first) == _file_identity(second)


def _stable_metadata(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(value.st_mode),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
        int(value.st_nlink),
    )


def _windows_cross_handle_metadata(value: os.stat_result) -> tuple[int, int, int]:
    """Return metadata Windows exposes consistently for fd/path comparisons."""

    return (
        stat.S_IFMT(int(value.st_mode)),
        int(value.st_size),
        int(value.st_mtime_ns),
    )


def _cross_handle_metadata(value: os.stat_result) -> tuple[int, ...]:
    if os.name == "nt":
        return _windows_cross_handle_metadata(value)
    return _stable_metadata(value)


def _stat_resolved_path(path: Path) -> os.stat_result:
    try:
        path_stat = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        raise BoundedRepoFileNotFoundError from None
    except OSError:
        raise BoundedRepoReadError from None
    if stat.S_ISLNK(path_stat.st_mode):
        raise BoundedRepoContainmentError from None
    if not stat.S_ISREG(path_stat.st_mode):
        raise BoundedRepoReadError from None
    return path_stat


def _open_repo_bound_file(
    path: Path,
    repo_root: Path,
) -> tuple[int, str, Path, os.stat_result]:
    if not _path_is_lexically_under(path, repo_root):
        raise BoundedRepoContainmentError from None

    try:
        resolved_root = repo_root.resolve(strict=True)
    except FileNotFoundError:
        raise BoundedRepoFileNotFoundError from None
    except (OSError, RuntimeError):
        raise BoundedRepoReadError from None

    try:
        resolved_path = path.resolve(strict=True)
    except FileNotFoundError:
        raise BoundedRepoFileNotFoundError from None
    except (OSError, RuntimeError):
        raise BoundedRepoReadError from None
    try:
        relative_path = resolved_path.relative_to(resolved_root)
    except ValueError:
        raise BoundedRepoContainmentError from None
    if not relative_path.parts:
        raise BoundedRepoReadError from None

    pre_open_stat = _stat_resolved_path(resolved_path)

    file_fd: int | None = None
    try:
        if os.name == "nt":
            file_fd = _open_repo_file_windows(resolved_root, resolved_path)
        else:
            file_fd = _open_repo_file_posix(resolved_root, relative_path)
        opened_stat = os.fstat(file_fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise BoundedRepoReadError
        if not _same_file_identity(pre_open_stat, opened_stat):
            raise BoundedRepoReadError
        return file_fd, relative_path.as_posix(), resolved_root, opened_stat
    except (BoundedRepoContainmentError, BoundedRepoFileNotFoundError, BoundedRepoReadError):
        if file_fd is not None:
            os.close(file_fd)
        raise
    except OSError:
        if file_fd is not None:
            os.close(file_fd)
        raise BoundedRepoReadError from None


def _read_open_file(file_fd: int, *, max_bytes: int) -> bytes:
    with os.fdopen(file_fd, "rb", closefd=False) as handle:
        return handle.read(max_bytes + 1)


def _relative_paths_match(first: str, second: Path) -> bool:
    return os.path.normcase(os.path.normpath(first)) == os.path.normcase(
        os.path.normpath(str(second))
    )


def _validate_current_path(
    *,
    path: Path,
    resolved_root: Path,
    relative_path: str,
    file_stat: os.stat_result,
) -> None:
    try:
        current_path = path.resolve(strict=True)
    except FileNotFoundError:
        raise BoundedRepoFileNotFoundError from None
    except (OSError, RuntimeError):
        raise BoundedRepoReadError from None
    try:
        current_relative = current_path.relative_to(resolved_root)
    except ValueError:
        raise BoundedRepoContainmentError from None
    if not _relative_paths_match(relative_path, current_relative):
        raise BoundedRepoReadError from None
    current_stat = _stat_resolved_path(current_path)
    if not _same_file_identity(file_stat, current_stat):
        raise BoundedRepoReadError from None
    if _cross_handle_metadata(file_stat) != _cross_handle_metadata(current_stat):
        raise BoundedRepoReadError from None


def read_repo_bound_bytes(
    path: Path,
    repo_root: Path,
    *,
    max_bytes: int,
) -> BoundedRepoFile:
    """Read at most ``max_bytes`` from one regular file bound below a root."""

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise BoundedRepoLimitError from None

    file_fd, relative_path, resolved_root, opened_stat = _open_repo_bound_file(path, repo_root)
    try:
        before_read_stat = os.fstat(file_fd)
        if not _same_file_identity(opened_stat, before_read_stat):
            raise BoundedRepoReadError
        if before_read_stat.st_size > max_bytes:
            raise BoundedRepoLimitError
        data = _read_open_file(file_fd, max_bytes=max_bytes)
        after_read_stat = os.fstat(file_fd)
        if not _same_file_identity(before_read_stat, after_read_stat):
            raise BoundedRepoReadError
        if _stable_metadata(before_read_stat) != _stable_metadata(after_read_stat):
            raise BoundedRepoReadError
        if len(data) > max_bytes:
            raise BoundedRepoLimitError
        if len(data) != after_read_stat.st_size:
            raise BoundedRepoReadError
        _validate_current_path(
            path=path,
            resolved_root=resolved_root,
            relative_path=relative_path,
            file_stat=after_read_stat,
        )
    except (BoundedRepoContainmentError, BoundedRepoFileNotFoundError, BoundedRepoLimitError, BoundedRepoReadError):
        raise
    except (MemoryError, OverflowError):
        raise BoundedRepoLimitError from None
    except OSError:
        raise BoundedRepoReadError from None
    finally:
        try:
            os.close(file_fd)
        except OSError:
            pass
    return BoundedRepoFile(
        data=data,
        relative_path=relative_path,
        identity=_file_identity(after_read_stat),
    )


def read_bounded_bytes(path: Path, *, max_bytes: int) -> BoundedRepoFile:
    """Securely read a standalone file while preserving external-policy support."""

    absolute_path = Path(os.path.abspath(path))
    return read_repo_bound_bytes(
        absolute_path,
        absolute_path.parent,
        max_bytes=max_bytes,
    )
