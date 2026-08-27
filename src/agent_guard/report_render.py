"""Where: src/agent_guard/report_render.py
What: thin render helpers for sanitized agent-guard report payloads.
Why: let CI render Markdown, SARIF, and annotations from one JSON evidence file.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
from pathlib import Path, PureWindowsPath
from typing import NoReturn

from .report import render_github_annotations_report, render_markdown_evidence_report, render_sarif_report


ERROR_REPORT_OUTPUT_PATH = "report output path is unsafe"


def _raise_output_path_error() -> NoReturn:
    raise ValueError(ERROR_REPORT_OUTPUT_PATH) from None


def _write_all(file_fd: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(file_fd, remaining)
        if written <= 0:
            raise OSError
        remaining = remaining[written:]


def _open_temp_file(
    directory: Path | int,
    *,
    use_dir_fd: bool,
) -> tuple[int, str | Path]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
    while True:
        name = f".agent-guard-{secrets.token_hex(16)}.tmp"
        target: str | Path = name if use_dir_fd else Path(directory) / name
        try:
            file_fd = (
                os.open(name, flags, 0o600, dir_fd=directory)
                if use_dir_fd
                else os.open(target, flags, 0o600)
            )
        except FileExistsError:
            continue
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            os.close(file_fd)
            _raise_output_path_error()
        return file_fd, target


def _write_in_posix_directory(
    directory_fd: int,
    *,
    final_name: str,
    data: bytes,
) -> None:
    file_fd: int | None = None
    temp_name: str | None = None
    try:
        file_fd, raw_temp_name = _open_temp_file(directory_fd, use_dir_fd=True)
        temp_name = str(raw_temp_name)
        _write_all(file_fd, data)
        os.fsync(file_fd)
        os.replace(
            temp_name,
            final_name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temp_name = None
    except (OSError, TypeError, ValueError):
        _raise_output_path_error()
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        if temp_name is not None:
            try:
                os.unlink(temp_name, dir_fd=directory_fd)
            except OSError:
                pass


def _open_relative_output_directory_posix(
    root: Path,
    parent_parts: tuple[str, ...],
) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if (
        not nofollow
        or not directory
        or os.open not in os.supports_dir_fd
        or os.mkdir not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
    ):
        _raise_output_path_error()
    flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    directory_fd: int | None = None
    try:
        directory_fd = os.open(root, flags)
        for component in parent_parts:
            try:
                next_fd = os.open(component, flags, dir_fd=directory_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o777, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(component, flags, dir_fd=directory_fd)
            previous_fd = directory_fd
            directory_fd = next_fd
            os.close(previous_fd)
        result = directory_fd
        directory_fd = None
        return result
    except (OSError, TypeError, ValueError):
        _raise_output_path_error()
    finally:
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                pass


def _open_absolute_output_directory_posix(parent: Path) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        _raise_output_path_error()
    flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(parent, flags)
    except (OSError, TypeError, ValueError):
        _raise_output_path_error()


def _is_link_or_reparse(value: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0) & reparse_flag
    )


def _windows_final_handle_path(file_fd: int) -> str:
    import msvcrt

    return _windows_path_from_handle(msvcrt.get_osfhandle(file_fd))


def _windows_path_from_handle(handle: int) -> str:
    import ctypes
    from ctypes import wintypes

    get_final_path = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
    get_final_path.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    get_final_path.restype = wintypes.DWORD
    capacity = 512
    while capacity <= 32_768:
        buffer = ctypes.create_unicode_buffer(capacity)
        length = get_final_path(handle, buffer, capacity, 0)
        if length == 0:
            raise OSError
        if length < capacity:
            value = buffer.value
            if value.startswith("\\\\?\\UNC\\"):
                return "\\\\" + value[8:]
            if value.startswith("\\\\?\\"):
                return value[4:]
            return value
        capacity = length
    raise OSError


def _windows_close_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    if not close_handle(handle):
        raise OSError


def _windows_open_directory_handle(parent: Path) -> int:
    import ctypes
    from ctypes import wintypes

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    get_info = ctypes.WinDLL("kernel32", use_last_error=True).GetFileInformationByHandleEx
    get_info.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    get_info.restype = wintypes.BOOL

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("ReparseTag", wintypes.DWORD),
        ]

    file_list_directory = 0x0001
    file_read_attributes = 0x0080
    share_all = 0x0001 | 0x0002 | 0x0004
    open_existing = 3
    file_flag_open_reparse_point = 0x00200000
    file_flag_backup_semantics = 0x02000000
    invalid_handle = ctypes.c_void_p(-1).value
    handle = create_file(
        str(parent),
        file_list_directory | file_read_attributes,
        share_all,
        None,
        open_existing,
        file_flag_open_reparse_point | file_flag_backup_semantics,
        None,
    )
    if handle == invalid_handle:
        raise OSError
    handle_value = int(handle)
    try:
        attributes = FileAttributeTagInfo()
        file_attribute_directory = 0x0010
        file_attribute_reparse_point = 0x0400
        if not get_info(
            handle_value,
            9,  # FileAttributeTagInfo
            ctypes.byref(attributes),
            ctypes.sizeof(attributes),
        ):
            raise OSError
        if not attributes.FileAttributes & file_attribute_directory:
            raise OSError
        if attributes.FileAttributes & file_attribute_reparse_point:
            raise OSError
        actual = os.path.normcase(
            os.path.normpath(_windows_path_from_handle(handle_value))
        )
        expected = os.path.normcase(os.path.normpath(str(parent)))
        if actual != expected:
            raise OSError
        return handle_value
    except (OSError, RuntimeError, TypeError, ValueError):
        try:
            _windows_close_handle(handle_value)
        except OSError:
            pass
        raise


def _open_windows_temp_file(parent: Path) -> tuple[int, Path]:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    generic_write = 0x40000000
    delete = 0x00010000
    file_read_attributes = 0x0080
    share_all = 0x0001 | 0x0002 | 0x0004
    create_new = 1
    file_attribute_normal = 0x0080
    file_flag_open_reparse_point = 0x00200000
    invalid_handle = ctypes.c_void_p(-1).value

    while True:
        path = parent / f".agent-guard-{secrets.token_hex(16)}.tmp"
        handle = create_file(
            str(path),
            generic_write | delete | file_read_attributes,
            share_all,
            None,
            create_new,
            file_attribute_normal | file_flag_open_reparse_point,
            None,
        )
        if handle == invalid_handle:
            if ctypes.get_last_error() in {80, 183}:  # already exists
                continue
            raise OSError
        handle_value = int(handle)
        try:
            file_fd = msvcrt.open_osfhandle(
                handle_value,
                os.O_WRONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOINHERIT", 0),
            )
        except (OSError, ValueError):
            try:
                _windows_close_handle(handle_value)
            except OSError:
                pass
            raise OSError from None
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            os.close(file_fd)
            raise OSError
        return file_fd, path


def _windows_rename_open_file(
    file_fd: int,
    *,
    directory_handle: int,
    final_name: str,
) -> None:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class FileRenameInfo(ctypes.Structure):
        _fields_ = [
            ("ReplaceIfExists", wintypes.BOOLEAN),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", wintypes.WCHAR * 1),
        ]

    encoded_name = final_name.encode("utf-16-le")
    offset = FileRenameInfo.FileName.offset
    buffer = ctypes.create_string_buffer(offset + len(encoded_name))
    info = ctypes.cast(buffer, ctypes.POINTER(FileRenameInfo)).contents
    info.ReplaceIfExists = True
    info.RootDirectory = directory_handle
    info.FileNameLength = len(encoded_name)
    ctypes.memmove(ctypes.addressof(buffer) + offset, encoded_name, len(encoded_name))

    set_info = ctypes.WinDLL("kernel32", use_last_error=True).SetFileInformationByHandle
    set_info.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    set_info.restype = wintypes.BOOL
    if not set_info(
        msvcrt.get_osfhandle(file_fd),
        3,  # FileRenameInfo
        ctypes.byref(buffer),
        len(buffer),
    ):
        raise OSError


def _validate_portable_relative_parent(root: Path, parent_parts: tuple[str, ...]) -> Path:
    current = root
    try:
        for component in parent_parts:
            current = current / component
            try:
                metadata = os.lstat(current)
            except FileNotFoundError:
                current.mkdir()
                metadata = os.lstat(current)
            if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
                _raise_output_path_error()
        resolved_parent = current.resolve(strict=True)
        if os.path.commonpath((str(root), str(resolved_parent))) != str(root):
            _raise_output_path_error()
        return resolved_parent
    except (OSError, RuntimeError, TypeError, ValueError):
        _raise_output_path_error()


def _write_in_portable_directory(
    parent: Path,
    *,
    final_name: str,
    data: bytes,
) -> None:
    file_fd: int | None = None
    temp_path: Path | None = None
    directory_handle: int | None = None
    try:
        if os.name == "nt":
            directory_handle = _windows_open_directory_handle(parent)
            file_fd, temp_path = _open_windows_temp_file(parent)
        else:
            file_fd, raw_temp_path = _open_temp_file(parent, use_dir_fd=False)
            temp_path = Path(raw_temp_path)
        _write_all(file_fd, data)
        os.fsync(file_fd)
        if os.name == "nt":
            assert directory_handle is not None
            actual_parent = os.path.normcase(os.path.normpath(
                str(Path(_windows_final_handle_path(file_fd)).parent)
            ))
            expected_parent = os.path.normcase(os.path.normpath(
                _windows_path_from_handle(directory_handle)
            ))
            if actual_parent != expected_parent:
                _raise_output_path_error()
            _windows_rename_open_file(
                file_fd,
                directory_handle=directory_handle,
                final_name=final_name,
            )
            temp_path = None
            return
        os.close(file_fd)
        file_fd = None
        assert temp_path is not None
        if _is_link_or_reparse(os.lstat(temp_path)) or not stat.S_ISREG(
            os.lstat(temp_path).st_mode
        ):
            _raise_output_path_error()
        os.replace(temp_path, parent / final_name)
        temp_path = None
    except (OSError, RuntimeError, TypeError, ValueError):
        _raise_output_path_error()
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        if directory_handle is not None:
            try:
                _windows_close_handle(directory_handle)
            except OSError:
                pass
        if temp_path is not None:
            try:
                temp_path.unlink()
            except OSError:
                pass


def _relative_output_parts(output: str) -> tuple[str, ...]:
    path = Path(output)
    windows_path = PureWindowsPath(output)
    if path.is_absolute() or windows_path.is_absolute() or windows_path.drive:
        _raise_output_path_error()
    parts = path.parts
    if not parts or any(component in {"", ".", ".."} for component in parts):
        _raise_output_path_error()
    if any(component == ".." for component in windows_path.parts):
        _raise_output_path_error()
    return parts


def _write_report_output(
    data: bytes,
    output: str,
    *,
    root: Path | None,
) -> None:
    path = Path(output)
    if path.is_absolute():
        if not path.name:
            _raise_output_path_error()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            parent = path.parent.resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            _raise_output_path_error()
        if os.name == "posix":
            directory_fd = _open_absolute_output_directory_posix(parent)
            try:
                _write_in_posix_directory(directory_fd, final_name=path.name, data=data)
            finally:
                try:
                    os.close(directory_fd)
                except OSError:
                    pass
            return
        _write_in_portable_directory(parent, final_name=path.name, data=data)
        return

    if root is None:
        _raise_output_path_error()
    parts = _relative_output_parts(output)
    try:
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        _raise_output_path_error()
    if not resolved_root.is_dir():
        _raise_output_path_error()
    if os.name == "posix":
        directory_fd = _open_relative_output_directory_posix(
            resolved_root,
            parts[:-1],
        )
        try:
            _write_in_posix_directory(directory_fd, final_name=parts[-1], data=data)
        finally:
            try:
                os.close(directory_fd)
            except OSError:
                pass
        return
    parent = _validate_portable_relative_parent(resolved_root, parts[:-1])
    _write_in_portable_directory(parent, final_name=parts[-1], data=data)


def render_report_output(payload: dict[str, object], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
        ) + "\n"
    if output_format == "github-annotations":
        return render_github_annotations_report(payload)
    if output_format == "sarif":
        return render_sarif_report(payload)
    return render_markdown_evidence_report(payload)


def emit_report_output(
    rendered: str,
    output_path: str,
    *,
    root: Path | None = None,
) -> None:
    output = str(output_path).strip()
    if not output:
        print(rendered, end="")
        return

    _write_report_output(rendered.encode("utf-8"), output, root=root)
