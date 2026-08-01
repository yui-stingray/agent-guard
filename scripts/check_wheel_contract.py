"""Where: scripts/check_wheel_contract.py
What: install the built wheel into an isolated venv and verify the public contract.
Why: editable installs can hide packaging mistakes; releases must prove the wheel works.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import signal
import stat
import struct
import subprocess
import tarfile
import tempfile
import textwrap
import threading
import time
import tomllib
import venv
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import BinaryIO, NoReturn

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
EXPECTED_EXPORTS = {
    "scan_urls",
    "ApiGuardFinding",
    "scan_context_files",
    "ContextGuardFinding",
    "scan_paths",
    "scan_content_paths",
    "ContentGuardFinding",
    "scan_repo_paths",
    "PathGuardFinding",
    "scan_digests",
    "DigestGuardFinding",
    "build_mcp_config_report",
    "scan_workflow_policy",
    "WorkflowGuardFinding",
}
MAX_ARCHIVE_FILE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_DECOMPRESSED_BYTES = MAX_ARCHIVE_TOTAL_BYTES + 64 * 1024 * 1024
MAX_TAR_EXTENSION_MEMBER_BYTES = 64 * 1024
MAX_TAR_EXTENSION_METADATA_BYTES = 1024 * 1024
MAX_TAR_EXTENSION_HEADERS = MAX_ARCHIVE_MEMBERS
MAX_TAR_METADATA_RECORDS = MAX_ARCHIVE_MEMBERS
MAX_TAR_PAX_RECORD_BYTES = 16 * 1024
MAX_TAR_PAX_RECORDS_PER_HEADER = 256
MAX_TAR_CONSECUTIVE_EXTENSION_HEADERS = 64
MAX_GZIP_TRAILING_ZERO_BYTES = 1024
MAX_TRACKED_PATH_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_TRACKED_PATHS = MAX_ARCHIVE_MEMBERS
GIT_INVENTORY_TIMEOUT_SECONDS = 10.0
GIT_READ_CHUNK_BYTES = 64 * 1024
GIT_TERMINATE_TIMEOUT_SECONDS = 1.0
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP_CENTRAL_SIGNATURE = b"PK\x01\x02"
_ZIP_LOCAL_SIGNATURE = b"PK\x03\x04"
_ZIP_EOCD = struct.Struct("<4s4H2IH")
_ZIP64_EOCD = struct.Struct("<4sQ2H2I4Q")
_ZIP64_LOCATOR = struct.Struct("<4sIQI")
_ZIP_CENTRAL_HEADER = struct.Struct("<4s6H3I5H2I")
_ZIP_LOCAL_HEADER = struct.Struct("<4s5H3I2H")
_ZIP_MAX_COMMENT_BYTES = (1 << 16) - 1
_ZIP64_MIN_RECORD_BODY_BYTES = _ZIP64_EOCD.size - 12
_TAR_BLOCK_BYTES = 512
_TAR_READ_CHUNK_BYTES = 64 * 1024
_ARCHIVE_COPY_CHUNK_BYTES = 64 * 1024
_GZIP_WBITS = 16 + zlib.MAX_WBITS
_TAR_PAX_TYPES = frozenset({b"x", b"g", b"X"})
_TAR_EXTENSION_TYPES = _TAR_PAX_TYPES | frozenset({b"L", b"K"})
_TAR_SPARSE_TYPE = b"S"
SDIST_EXCLUDED_PATHS = frozenset({"execution-notes.md"})
SDIST_EXCLUDED_PREFIXES = (
    ".venv/",
    ".venv312/",
    ".venv-py312/",
    "__pycache__/",
    "build/",
    "dist/",
)
GIT_ROUTING_ENVIRONMENT_VARIABLES = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    }
)


def project_version() -> str:
    """Return pyproject.toml [project].version."""
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def project_requires_python() -> str:
    """Return pyproject.toml [project].requires-python."""
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["requires-python"])


def find_release_distributions(version: str) -> tuple[Path, Path]:
    """Return the exact wheel and sdist set from a clean release build."""
    if not DIST.is_dir() or DIST.is_symlink():
        raise RuntimeError("release distribution directory is missing")
    wheel = DIST / f"yui_agent_guard-{version}-py3-none-any.whl"
    sdist = DIST / f"yui_agent_guard-{version}.tar.gz"
    expected = {wheel.name, sdist.name}
    observed: set[str] = set()
    try:
        with os.scandir(DIST) as entries:
            for index, entry in enumerate(entries, start=1):
                if (
                    index > len(expected)
                    or entry.name not in expected
                    or entry.name in observed
                    or not entry.is_file(follow_symlinks=False)
                ):
                    raise RuntimeError(
                        "expected exactly the current yui_agent_guard wheel and sdist"
                    )
                observed.add(entry.name)
    except OSError:
        raise RuntimeError(
            "expected exactly the current yui_agent_guard wheel and sdist"
        ) from None
    if observed != expected:
        raise RuntimeError("expected exactly the current yui_agent_guard wheel and sdist")
    return wheel, sdist


def _validate_member_name(name: str) -> None:
    parts = name.split("/")
    if (
        not name
        or "\\" in name
        or name.startswith("/")
        or name.endswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or PurePosixPath(name).is_absolute()
    ):
        raise RuntimeError("release archive members do not match contract")


def _raise_source_inventory_error() -> NoReturn:
    raise RuntimeError("release source inventory could not be verified") from None


def _stop_git_inventory_process(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                pass
    else:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=GIT_TERMINATE_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
            process.wait(timeout=GIT_TERMINATE_TIMEOUT_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _bounded_git_ls_files(environment: dict[str, str]) -> bytes:
    command = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-C",
        str(ROOT),
        "ls-files",
        "-z",
    ]
    creationflags = (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    )
    deadline = time.monotonic() + GIT_INVENTORY_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            bufsize=0,
            close_fds=True,
            creationflags=creationflags,
            start_new_session=os.name == "posix",
        )
    except OSError:
        _raise_source_inventory_error()

    if process.stdout is None:
        _stop_git_inventory_process(process)
        _raise_source_inventory_error()

    read_sizes: queue.Queue[int] = queue.Queue(maxsize=1)
    read_results: queue.Queue[tuple[bool, bytes]] = queue.Queue(maxsize=1)
    stop_reader = threading.Event()

    def read_stdout() -> None:
        while not stop_reader.is_set():
            read_size = read_sizes.get()
            if read_size <= 0 or stop_reader.is_set():
                return
            try:
                chunk = process.stdout.read(read_size)
            except (OSError, ValueError):
                read_results.put((False, b""))
                return
            read_results.put((True, chunk))
            if not chunk:
                return

    reader = threading.Thread(
        target=read_stdout,
        name="release-git-inventory-reader",
        daemon=True,
    )
    try:
        reader.start()
    except RuntimeError:
        _stop_git_inventory_process(process)
        try:
            process.stdout.close()
        except (OSError, ValueError):
            pass
        _raise_source_inventory_error()
    output = bytearray()
    path_count = 0
    succeeded = False
    try:
        while True:
            remaining_output = MAX_TRACKED_PATH_OUTPUT_BYTES + 1 - len(output)
            read_sizes.put(min(GIT_READ_CHUNK_BYTES, remaining_output))
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                _raise_source_inventory_error()
            try:
                read_ok, chunk = read_results.get(timeout=remaining_time)
            except queue.Empty:
                _raise_source_inventory_error()
            if not read_ok:
                _raise_source_inventory_error()
            if not chunk:
                break
            output.extend(chunk)
            path_count += chunk.count(b"\0")
            if len(output) > MAX_TRACKED_PATH_OUTPUT_BYTES:
                _raise_source_inventory_error()
            if path_count > MAX_TRACKED_PATHS:
                _raise_source_inventory_error()

        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            _raise_source_inventory_error()
        try:
            returncode = process.wait(timeout=remaining_time)
        except (OSError, subprocess.TimeoutExpired):
            _raise_source_inventory_error()
        if returncode != 0:
            _raise_source_inventory_error()
        succeeded = True
        return bytes(output)
    finally:
        stop_reader.set()
        try:
            read_sizes.put_nowait(0)
        except queue.Full:
            pass
        if not succeeded:
            _stop_git_inventory_process(process)
        try:
            process.stdout.close()
        except (OSError, ValueError):
            pass
        reader.join(timeout=GIT_TERMINATE_TIMEOUT_SECONDS)


def tracked_release_files() -> set[str]:
    environment = dict(os.environ)
    for variable in tuple(environment):
        normalized = variable.upper()
        if normalized in GIT_ROUTING_ENVIRONMENT_VARIABLES or normalized.startswith(
            ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
        ):
            environment.pop(variable, None)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    output = _bounded_git_ls_files(environment)
    if output and not output.endswith(b"\0"):
        _raise_source_inventory_error()

    tracked: set[str] = set()
    for raw_name in output[:-1].split(b"\0") if output else ():
        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            _raise_source_inventory_error()
        try:
            _validate_member_name(name)
        except RuntimeError:
            _raise_source_inventory_error()
        if name in tracked:
            _raise_source_inventory_error()
        tracked.add(name)
    return tracked


def expected_wheel_members(version: str, tracked: set[str]) -> set[str]:
    package_members = {
        name.removeprefix("src/")
        for name in tracked
        if name.startswith("src/agent_guard/")
    }
    dist_info = f"yui_agent_guard-{version}.dist-info"
    return package_members | {
        f"{dist_info}/METADATA",
        f"{dist_info}/WHEEL",
        f"{dist_info}/entry_points.txt",
        f"{dist_info}/licenses/LICENSE",
        f"{dist_info}/RECORD",
    }


def expected_sdist_members(version: str, tracked: set[str]) -> set[str]:
    prefix = f"yui_agent_guard-{version}"
    included = {
        name
        for name in tracked
        if name not in SDIST_EXCLUDED_PATHS
        and not name.startswith(SDIST_EXCLUDED_PREFIXES)
    }
    return {f"{prefix}/{name}" for name in included} | {f"{prefix}/PKG-INFO"}


def _raise_archive_verification_error() -> NoReturn:
    raise RuntimeError("release archive could not be verified") from None


def _raise_archive_safety_error() -> NoReturn:
    raise RuntimeError("release archive exceeds safety limits") from None


def _read_archive_bytes(
    archive_file: BinaryIO,
    offset: int,
    size: int,
) -> bytes:
    if offset < 0 or size < 0:
        _raise_archive_verification_error()
    archive_file.seek(offset)
    data = archive_file.read(size)
    if len(data) != size:
        _raise_archive_verification_error()
    return data


def _find_zip_eocd(
    archive_file: BinaryIO,
    file_size: int,
) -> tuple[tuple[int, ...], int]:
    tail_size = min(file_size, _ZIP_EOCD.size + _ZIP_MAX_COMMENT_BYTES)
    tail_offset = file_size - tail_size
    tail = _read_archive_bytes(archive_file, tail_offset, tail_size)
    relative_offset = tail.rfind(_ZIP_EOCD_SIGNATURE)
    if relative_offset < 0 or relative_offset + _ZIP_EOCD.size > len(tail):
        _raise_archive_verification_error()
    end_record = _ZIP_EOCD.unpack_from(tail, relative_offset)
    comment_size = end_record[-1]
    if relative_offset + _ZIP_EOCD.size + comment_size != len(tail):
        _raise_archive_verification_error()
    return tuple(int(value) for value in end_record[1:]), (
        tail_offset + relative_offset
    )


def _zip64_directory_metadata(
    archive_file: BinaryIO,
    eocd_offset: int,
    legacy_metadata: tuple[int, ...],
) -> tuple[int, int, int, int]:
    locator_offset = eocd_offset - _ZIP64_LOCATOR.size
    locator = _ZIP64_LOCATOR.unpack(
        _read_archive_bytes(archive_file, locator_offset, _ZIP64_LOCATOR.size)
    )
    signature, locator_disk, zip64_offset, disk_count = locator
    if (
        signature != _ZIP64_LOCATOR_SIGNATURE
        or locator_disk != 0
        or disk_count != 1
        or zip64_offset + _ZIP64_EOCD.size > locator_offset
    ):
        _raise_archive_verification_error()

    fixed_record = _ZIP64_EOCD.unpack(
        _read_archive_bytes(archive_file, zip64_offset, _ZIP64_EOCD.size)
    )
    (
        signature,
        record_body_size,
        _version_made,
        version_needed,
        disk_number,
        central_disk,
        entries_on_disk,
        member_count,
        central_size,
        central_offset,
    ) = fixed_record
    if (
        signature != _ZIP64_EOCD_SIGNATURE
        or record_body_size < _ZIP64_MIN_RECORD_BODY_BYTES
        or zip64_offset + 12 + record_body_size != locator_offset
        or version_needed < 45
        or disk_number != 0
        or central_disk != 0
        or entries_on_disk != member_count
    ):
        _raise_archive_verification_error()

    (
        legacy_disk_number,
        legacy_central_disk,
        legacy_entries_on_disk,
        legacy_member_count,
        legacy_central_size,
        legacy_central_offset,
        _comment_size,
    ) = legacy_metadata
    for legacy_value, zip64_value, sentinel in (
        (legacy_disk_number, disk_number, 0xFFFF),
        (legacy_central_disk, central_disk, 0xFFFF),
        (legacy_entries_on_disk, entries_on_disk, 0xFFFF),
        (legacy_member_count, member_count, 0xFFFF),
        (legacy_central_size, central_size, 0xFFFFFFFF),
        (legacy_central_offset, central_offset, 0xFFFFFFFF),
    ):
        if legacy_value != sentinel and legacy_value != zip64_value:
            _raise_archive_verification_error()

    return member_count, central_size, central_offset, zip64_offset


def _zip_directory_metadata(
    archive_file: BinaryIO,
    file_size: int,
) -> tuple[int, int, int]:
    legacy_metadata, eocd_offset = _find_zip_eocd(archive_file, file_size)
    (
        disk_number,
        central_disk,
        entries_on_disk,
        member_count,
        central_size,
        central_offset,
        _comment_size,
    ) = legacy_metadata
    locator_offset = eocd_offset - _ZIP64_LOCATOR.size
    has_zip64_locator = (
        locator_offset >= 0
        and _read_archive_bytes(archive_file, locator_offset, 4)
        == _ZIP64_LOCATOR_SIGNATURE
    )
    needs_zip64 = (
        disk_number == 0xFFFF
        or central_disk == 0xFFFF
        or entries_on_disk == 0xFFFF
        or member_count == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    )
    if needs_zip64 and not has_zip64_locator:
        _raise_archive_verification_error()
    if has_zip64_locator:
        member_count, central_size, central_offset, metadata_offset = (
            _zip64_directory_metadata(archive_file, eocd_offset, legacy_metadata)
        )
    else:
        if disk_number != 0 or central_disk != 0 or entries_on_disk != member_count:
            _raise_archive_verification_error()
        metadata_offset = eocd_offset

    if member_count > MAX_ARCHIVE_MEMBERS:
        _raise_archive_safety_error()
    if central_size > MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES:
        _raise_archive_safety_error()
    if (
        central_offset > metadata_offset
        or central_size > metadata_offset - central_offset
        or central_offset + central_size != metadata_offset
    ):
        _raise_archive_verification_error()
    return member_count, central_size, central_offset


def _zip64_extra_data(extra: bytes) -> bytes | None:
    offset = 0
    zip64_data: bytes | None = None
    while offset < len(extra):
        if len(extra) - offset < 4:
            _raise_archive_verification_error()
        field_id, field_size = struct.unpack_from("<HH", extra, offset)
        field_start = offset + 4
        field_end = field_start + field_size
        if field_end > len(extra):
            _raise_archive_verification_error()
        if field_id == 0x0001:
            if zip64_data is not None:
                _raise_archive_verification_error()
            zip64_data = extra[field_start:field_end]
        offset = field_end
    return zip64_data


def _resolve_zip64_central_values(
    uncompressed_size: int,
    compressed_size: int,
    local_header_offset: int,
    disk_number: int,
    extra: bytes,
) -> tuple[int, int, int, int]:
    needs_zip64 = (
        uncompressed_size == 0xFFFFFFFF
        or compressed_size == 0xFFFFFFFF
        or local_header_offset == 0xFFFFFFFF
        or disk_number == 0xFFFF
    )
    zip64_data = _zip64_extra_data(extra)
    if needs_zip64 and zip64_data is None:
        _raise_archive_verification_error()
    if zip64_data is None:
        return uncompressed_size, compressed_size, local_header_offset, disk_number

    offset = 0

    def take_value(format_string: str, size: int) -> int:
        nonlocal offset
        if len(zip64_data) - offset < size:
            _raise_archive_verification_error()
        value = struct.unpack_from(format_string, zip64_data, offset)[0]
        offset += size
        return int(value)

    if uncompressed_size == 0xFFFFFFFF:
        uncompressed_size = take_value("<Q", 8)
    if compressed_size == 0xFFFFFFFF:
        compressed_size = take_value("<Q", 8)
    if local_header_offset == 0xFFFFFFFF:
        local_header_offset = take_value("<Q", 8)
    if disk_number == 0xFFFF:
        disk_number = take_value("<I", 4)
    return uncompressed_size, compressed_size, local_header_offset, disk_number


def _preflight_zip_central_directory(
    archive_file: BinaryIO,
    member_count: int,
    central_size: int,
    central_offset: int,
) -> None:
    central_end = central_offset + central_size
    cursor = central_offset
    local_ranges: list[tuple[int, int]] = []
    local_offsets: set[int] = set()
    for _index in range(member_count):
        if central_end - cursor < _ZIP_CENTRAL_HEADER.size:
            _raise_archive_verification_error()
        central_header = _ZIP_CENTRAL_HEADER.unpack(
            _read_archive_bytes(archive_file, cursor, _ZIP_CENTRAL_HEADER.size)
        )
        (
            signature,
            _version_made,
            version_needed,
            flags,
            compression,
            _modified_time,
            _modified_date,
            _crc,
            compressed_size,
            uncompressed_size,
            filename_size,
            extra_size,
            comment_size,
            disk_number,
            _internal_attributes,
            _external_attributes,
            local_header_offset,
        ) = central_header
        if signature != _ZIP_CENTRAL_SIGNATURE:
            _raise_archive_verification_error()
        variable_size = filename_size + extra_size + comment_size
        record_end = cursor + _ZIP_CENTRAL_HEADER.size + variable_size
        if record_end > central_end:
            _raise_archive_verification_error()

        filename_offset = cursor + _ZIP_CENTRAL_HEADER.size
        filename = _read_archive_bytes(archive_file, filename_offset, filename_size)
        extra = _read_archive_bytes(
            archive_file,
            filename_offset + filename_size,
            extra_size,
        )
        (
            _uncompressed_size,
            compressed_size,
            local_header_offset,
            disk_number,
        ) = _resolve_zip64_central_values(
            uncompressed_size,
            compressed_size,
            local_header_offset,
            disk_number,
            extra,
        )
        if disk_number != 0 or local_header_offset in local_offsets:
            _raise_archive_verification_error()
        local_offsets.add(local_header_offset)

        if local_header_offset + _ZIP_LOCAL_HEADER.size > central_offset:
            _raise_archive_verification_error()
        local_header = _ZIP_LOCAL_HEADER.unpack(
            _read_archive_bytes(
                archive_file,
                local_header_offset,
                _ZIP_LOCAL_HEADER.size,
            )
        )
        (
            local_signature,
            local_version_needed,
            local_flags,
            local_compression,
            _local_modified_time,
            _local_modified_date,
            _local_crc,
            _local_compressed_size,
            _local_uncompressed_size,
            local_filename_size,
            local_extra_size,
        ) = local_header
        if (
            local_signature != _ZIP_LOCAL_SIGNATURE
            or local_version_needed != version_needed
            or local_flags != flags
            or local_compression != compression
        ):
            _raise_archive_verification_error()
        local_filename_offset = local_header_offset + _ZIP_LOCAL_HEADER.size
        local_data_offset = (
            local_filename_offset + local_filename_size + local_extra_size
        )
        if local_data_offset > central_offset:
            _raise_archive_verification_error()
        local_filename = _read_archive_bytes(
            archive_file,
            local_filename_offset,
            local_filename_size,
        )
        if local_filename != filename:
            _raise_archive_verification_error()
        local_data_end = local_data_offset + compressed_size
        if local_data_end > central_offset:
            _raise_archive_verification_error()
        local_ranges.append((local_header_offset, local_data_end))
        cursor = record_end

    if cursor != central_end:
        _raise_archive_verification_error()
    previous_end = 0
    for local_start, local_end in sorted(local_ranges):
        if local_start < previous_end:
            _raise_archive_verification_error()
        previous_end = local_end


def _preflight_wheel_archive(archive_file: BinaryIO) -> None:
    file_stat = os.fstat(archive_file.fileno())
    if not stat.S_ISREG(file_stat.st_mode):
        _raise_archive_verification_error()
    file_size = file_stat.st_size
    if file_size > MAX_ARCHIVE_FILE_BYTES:
        _raise_archive_safety_error()
    if file_size < _ZIP_EOCD.size:
        _raise_archive_verification_error()
    member_count, central_size, central_offset = _zip_directory_metadata(
        archive_file,
        file_size,
    )
    _preflight_zip_central_directory(
        archive_file,
        member_count,
        central_size,
        central_offset,
    )


def _read_tar_stream_bytes(
    stream: BinaryIO,
    size: int,
    decompressed_bytes: list[int],
    *,
    retain: bool,
) -> bytes:
    if size < 0:
        _raise_archive_verification_error()
    if size > MAX_ARCHIVE_DECOMPRESSED_BYTES - decompressed_bytes[0]:
        _raise_archive_safety_error()
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, _TAR_READ_CHUNK_BYTES))
        if not chunk:
            _raise_archive_verification_error()
        decompressed_bytes[0] += len(chunk)
        if decompressed_bytes[0] > MAX_ARCHIVE_DECOMPRESSED_BYTES:
            _raise_archive_safety_error()
        if retain:
            chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class _SingleGzipReader:
    def __init__(self, archive_file: BinaryIO) -> None:
        self._archive_file = archive_file
        self._decompressor = zlib.decompressobj(_GZIP_WBITS)
        self._pending = b""
        self._finished = False
        self._trailing_zero_bytes = 0

    def _finish_member(self, initial_trailing: bytes) -> None:
        trailing = initial_trailing
        while True:
            if trailing:
                if any(trailing):
                    _raise_archive_verification_error()
                self._trailing_zero_bytes += len(trailing)
                if self._trailing_zero_bytes > MAX_GZIP_TRAILING_ZERO_BYTES:
                    _raise_archive_safety_error()
            trailing = self._archive_file.read(_TAR_READ_CHUNK_BYTES)
            if not trailing:
                self._finished = True
                return

    def read(self, size: int) -> bytes:
        if size < 0:
            _raise_archive_verification_error()
        if size == 0 or self._finished:
            return b""
        output = bytearray()
        while len(output) < size and not self._finished:
            if self._pending:
                compressed = self._pending
                self._pending = b""
            else:
                compressed = self._archive_file.read(_TAR_READ_CHUNK_BYTES)
            if not compressed:
                if not self._decompressor.eof:
                    _raise_archive_verification_error()
                self._finish_member(b"")
                break
            produced = self._decompressor.decompress(
                compressed,
                size - len(output),
            )
            output.extend(produced)
            self._pending = self._decompressor.unconsumed_tail
            if self._decompressor.eof:
                trailing = self._decompressor.unused_data
                if self._pending and self._pending != trailing:
                    _raise_archive_verification_error()
                self._pending = b""
                self._finish_member(trailing)
        return bytes(output)


def _copy_archive_snapshot(source: BinaryIO, snapshot: BinaryIO) -> None:
    initial_stat = os.fstat(source.fileno())
    if not stat.S_ISREG(initial_stat.st_mode):
        _raise_archive_verification_error()
    if initial_stat.st_size > MAX_ARCHIVE_FILE_BYTES:
        _raise_archive_safety_error()
    copied = 0
    while True:
        remaining = MAX_ARCHIVE_FILE_BYTES - copied
        chunk = source.read(min(_ARCHIVE_COPY_CHUNK_BYTES, remaining + 1))
        if not chunk:
            break
        copied += len(chunk)
        if copied > MAX_ARCHIVE_FILE_BYTES:
            _raise_archive_safety_error()
        snapshot.write(chunk)
    final_stat = os.fstat(source.fileno())
    if (
        copied != initial_stat.st_size
        or initial_stat.st_dev != final_stat.st_dev
        or initial_stat.st_ino != final_stat.st_ino
        or initial_stat.st_size != final_stat.st_size
        or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
        or initial_stat.st_ctime_ns != final_stat.st_ctime_ns
    ):
        _raise_archive_verification_error()
    snapshot.flush()
    snapshot.seek(0)


def _tar_number(field: bytes) -> int:
    if not field:
        _raise_archive_verification_error()
    if field[0] in {0o200, 0o377}:
        value = int.from_bytes(field[1:], "big")
        if field[0] == 0o377:
            value -= 256 ** (len(field) - 1)
    else:
        nul = field.find(b"\0")
        raw = (field if nul < 0 else field[:nul]).strip()
        if raw and any(byte not in b"01234567" for byte in raw):
            _raise_archive_verification_error()
        value = int(raw or b"0", 8)
    if value < 0:
        _raise_archive_verification_error()
    return value


def _validate_tar_header(header: bytes) -> tuple[int, bytes]:
    if len(header) != _TAR_BLOCK_BYTES:
        _raise_archive_verification_error()
    stored_checksum = _tar_number(header[148:156])
    unsigned_checksum = 256 + sum(header[:148]) + sum(header[156:])
    signed_checksum = 256 + sum(
        byte if byte < 128 else byte - 256
        for byte in header[:148] + header[156:]
    )
    if stored_checksum not in {unsigned_checksum, signed_checksum}:
        _raise_archive_verification_error()
    return _tar_number(header[124:136]), header[156:157]


def _validate_pax_metadata(payload: bytes, record_count: list[int]) -> None:
    offset = 0
    header_record_count = 0
    while offset < len(payload):
        if payload[offset] == 0:
            if any(payload[offset:]):
                _raise_archive_verification_error()
            return
        separator = payload.find(b" ", offset)
        if separator < 0:
            _raise_archive_verification_error()
        raw_length = payload[offset:separator]
        if (
            not raw_length
            or len(raw_length) > 20
            or any(byte not in b"0123456789" for byte in raw_length)
        ):
            _raise_archive_verification_error()
        length = int(raw_length)
        record_end = offset + length
        if length < 5 or record_end > len(payload):
            _raise_archive_verification_error()
        if length > MAX_TAR_PAX_RECORD_BYTES:
            _raise_archive_safety_error()
        key_value = payload[separator + 1 : record_end - 1]
        key, equals, _value = key_value.partition(b"=")
        if not key or equals != b"=" or payload[record_end - 1] != 0x0A:
            _raise_archive_verification_error()
        record_count[0] += 1
        header_record_count += 1
        if (
            record_count[0] > MAX_TAR_METADATA_RECORDS
            or header_record_count > MAX_TAR_PAX_RECORDS_PER_HEADER
        ):
            _raise_archive_safety_error()
        if key == b"size" or key.startswith(b"GNU.sparse."):
            _raise_archive_verification_error()
        offset = record_end


def _preflight_sdist_archive(archive_file: BinaryIO) -> None:
    file_stat = os.fstat(archive_file.fileno())
    if not stat.S_ISREG(file_stat.st_mode):
        _raise_archive_verification_error()
    if file_stat.st_size > MAX_ARCHIVE_FILE_BYTES:
        _raise_archive_safety_error()

    decompressed_bytes = [0]
    logical_members = 0
    extension_headers = 0
    extension_metadata_bytes = 0
    payload_bytes = 0
    metadata_records = [0]
    consecutive_extension_headers = 0
    stream = _SingleGzipReader(archive_file)
    while True:
        header = _read_tar_stream_bytes(
            stream,
            _TAR_BLOCK_BYTES,
            decompressed_bytes,
            retain=True,
        )
        if not any(header):
            second_end_block = _read_tar_stream_bytes(
                stream,
                _TAR_BLOCK_BYTES,
                decompressed_bytes,
                retain=True,
            )
            if any(second_end_block):
                _raise_archive_verification_error()
            while True:
                remaining_budget = (
                    MAX_ARCHIVE_DECOMPRESSED_BYTES - decompressed_bytes[0]
                )
                trailing = stream.read(
                    min(_TAR_READ_CHUNK_BYTES, remaining_budget + 1)
                )
                if not trailing:
                    return
                decompressed_bytes[0] += len(trailing)
                if decompressed_bytes[0] > MAX_ARCHIVE_DECOMPRESSED_BYTES:
                    _raise_archive_safety_error()
                if any(trailing):
                    _raise_archive_verification_error()

        size, member_type = _validate_tar_header(header)
        is_extension = member_type in _TAR_EXTENSION_TYPES
        if member_type == _TAR_SPARSE_TYPE:
            _raise_archive_verification_error()
        if is_extension:
            extension_headers += 1
            consecutive_extension_headers += 1
            extension_metadata_bytes += size
            if (
                extension_headers > MAX_TAR_EXTENSION_HEADERS
                or consecutive_extension_headers
                > MAX_TAR_CONSECUTIVE_EXTENSION_HEADERS
                or size > MAX_TAR_EXTENSION_MEMBER_BYTES
                or extension_metadata_bytes > MAX_TAR_EXTENSION_METADATA_BYTES
            ):
                _raise_archive_safety_error()
            payload = _read_tar_stream_bytes(
                stream,
                size,
                decompressed_bytes,
                retain=True,
            )
            if member_type in _TAR_PAX_TYPES:
                _validate_pax_metadata(payload, metadata_records)
        else:
            consecutive_extension_headers = 0
            logical_members += 1
            if logical_members > MAX_ARCHIVE_MEMBERS:
                _raise_archive_safety_error()
            if size > MAX_ARCHIVE_MEMBER_BYTES:
                _raise_archive_safety_error()
            payload_bytes += size
            if payload_bytes > MAX_ARCHIVE_TOTAL_BYTES:
                _raise_archive_safety_error()
            _read_tar_stream_bytes(
                stream,
                size,
                decompressed_bytes,
                retain=False,
            )
        padding = (-size) % _TAR_BLOCK_BYTES
        _read_tar_stream_bytes(
            stream,
            padding,
            decompressed_bytes,
            retain=False,
        )


def validate_wheel_members(wheel: Path, expected: set[str]) -> None:
    observed: set[str] = set()
    total_size = 0
    try:
        with wheel.open("rb") as archive_file:
            _preflight_wheel_archive(archive_file)
            archive_file.seek(0)
            with zipfile.ZipFile(archive_file) as archive:
                for index, member in enumerate(archive.infolist(), start=1):
                    if index > MAX_ARCHIVE_MEMBERS:
                        raise RuntimeError("release archive exceeds safety limits")
                    _validate_member_name(member.filename)
                    mode = member.external_attr >> 16
                    if member.is_dir() or stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                        raise RuntimeError(
                            "release archive members do not match contract"
                        )
                    if member.filename in observed:
                        raise RuntimeError(
                            "release archive members do not match contract"
                        )
                    if member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                        raise RuntimeError("release archive exceeds safety limits")
                    total_size += member.file_size
                    if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                        raise RuntimeError("release archive exceeds safety limits")
                    observed.add(member.filename)
    except (
        EOFError,
        OSError,
        UnicodeError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ):
        raise RuntimeError("release archive could not be verified") from None
    if observed != expected:
        raise RuntimeError("release archive members do not match contract")


def validate_sdist_members(sdist: Path, expected: set[str]) -> None:
    observed: set[str] = set()
    total_size = 0
    try:
        with sdist.open("rb") as source_file, tempfile.TemporaryFile() as archive_file:
            _copy_archive_snapshot(source_file, archive_file)
            _preflight_sdist_archive(archive_file)
            archive_file.seek(0)
            with tarfile.open(fileobj=archive_file, mode="r:gz") as archive:
                for index, member in enumerate(archive, start=1):
                    if index > MAX_ARCHIVE_MEMBERS:
                        raise RuntimeError("release archive exceeds safety limits")
                    _validate_member_name(member.name)
                    if not member.isfile() or member.name in observed:
                        raise RuntimeError("release archive members do not match contract")
                    if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                        raise RuntimeError("release archive exceeds safety limits")
                    total_size += member.size
                    if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                        raise RuntimeError("release archive exceeds safety limits")
                    observed.add(member.name)
    except (
        EOFError,
        OSError,
        OverflowError,
        RecursionError,
        UnicodeError,
        ValueError,
        tarfile.TarError,
        zlib.error,
    ):
        raise RuntimeError("release archive could not be verified") from None
    if observed != expected:
        raise RuntimeError("release archive members do not match contract")


def venv_python_path(venv_dir: Path, *, platform_name: str = os.name) -> Path:
    """Return the interpreter path created by venv on the target platform."""

    if platform_name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def isolated_module_command(
    python: Path,
    module: str,
    *arguments: str,
) -> list[str]:
    """Build an isolated module command for installed-wheel smoke checks."""

    return [str(python), "-I", "-m", module, *arguments]


def isolated_code_command(python: Path, code: str) -> list[str]:
    """Build an isolated inline-code command for installed-wheel smoke checks."""

    return [str(python), "-I", "-c", code]


def run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run a subprocess and return its completed process."""
    result = subprocess.run(command, cwd=cwd, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed with exit {result.returncode}: {command!r}\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
    return result


def main() -> int:
    version = project_version()
    requires_python = project_requires_python()
    wheel, sdist = find_release_distributions(version)
    tracked = tracked_release_files()
    validate_wheel_members(wheel, expected_wheel_members(version, tracked))
    validate_sdist_members(sdist, expected_sdist_members(version, tracked))
    with tempfile.TemporaryDirectory(prefix="agent-guard-wheel-") as temp_dir:
        temp = Path(temp_dir)
        venv_dir = temp / "venv"
        venv.EnvBuilder(with_pip=True).create(venv_dir)
        python = venv_python_path(venv_dir)
        run(isolated_module_command(python, "pip", "install", "--quiet", str(wheel)), cwd=temp)
        smoke = textwrap.dedent(
            f"""
            import json
            import agent_guard
            from importlib import resources
            from importlib.metadata import metadata

            expected_exports = {sorted(EXPECTED_EXPORTS)!r}
            assert sorted(agent_guard.__all__) == expected_exports
            assert agent_guard.__version__ == {version!r}
            assert metadata("yui-agent-guard")["Requires-Python"] == {requires_python!r}
            assert agent_guard.scan_paths is agent_guard.scan_content_paths
            for name in expected_exports:
                assert getattr(agent_guard, name) is not None

            schema_names = {{
                "agent-guard.result.v1.schema.json": "agent-guard.result.v1",
                "agent-guard.context_inventory.v1.schema.json": "agent-guard.context_inventory.v1",
                "agent-guard.context_lock_coverage.v1.schema.json": "agent-guard.context_lock_coverage.v1",
                "agent-guard.report_evidence.v1.schema.json": "agent-guard.report_evidence.v1",
                "agent-guard.conformance.v1.schema.json": "agent-guard.conformance.v1",
                "agent-guard.evidence_pack_manifest.v1.schema.json": "agent-guard.evidence_pack_manifest.v1",
                "agent-guard.surface_delta.v1.schema.json": "agent-guard.surface_delta.v1",
            }}
            schema_dir = resources.files("agent_guard.schemas")
            for filename, schema_version in schema_names.items():
                schema = json.loads((schema_dir / filename).read_text(encoding="utf-8"))
                assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
                if filename == "agent-guard.report_evidence.v1.schema.json":
                    assert schema["properties"]["report"]["properties"]["schema_version"]["const"] == schema_version
                    assert "surface_inventory" in schema["allOf"][0]["then"]["required"]
                    assert "evidence_coverage" in schema["allOf"][0]["then"]["required"]
                    assert "conformance" in schema["properties"]
                    assert "evidence_pack_manifest" in schema["properties"]
                    assert schema["properties"]["conformance"]["properties"]["profile"]["enum"] == [
                        "minimal",
                        "recommended",
                        "strict",
                    ]
                    artifact_role = schema["properties"]["evidence_pack_manifest"]["properties"]["artifacts"]["items"]["properties"]["role"]
                    assert "agent-policy-audit-event" in artifact_role["enum"]
                    surface_schema = schema["properties"]["surface_inventory"]["properties"]["schema_version"]
                    assert "agent-guard.agent_surface_inventory.v2" in surface_schema["enum"]
                    assert schema["properties"]["surface_delta"]["properties"]["schema_version"]["const"] == (
                        "agent-guard.surface_delta.v1"
                    )
                else:
                    assert schema["properties"]["schema_version"]["const"] == schema_version
            """
        )
        run(isolated_code_command(python, smoke), cwd=temp)

        repo = temp / "repo"
        repo.mkdir()
        policy = repo / "path-policy.yaml"
        policy.write_text(
            "scan:\n"
            "  include:\n"
            "    - .\n"
            "  exclude: []\n"
            "policy:\n"
            "  allowed_path_patterns:\n"
            "    - '(^|/)\\.env\\.example$'\n"
            "  forbidden_path_patterns:\n"
            "    - id: env_file\n"
            "      severity: high\n"
            "      pattern: '(^|/)\\.env(\\..+)?$'\n"
            "      message: 'env files are forbidden except .env.example'\n",
            encoding="utf-8",
        )
        (repo / ".env.example").write_text("TOKEN=\n", encoding="utf-8")
        cli = run(
            isolated_module_command(
                python,
                "agent_guard.cli",
                "path",
                "check",
                "--root",
                str(repo),
                "--policy",
                str(policy),
                "--json",
            ),
            cwd=temp,
        )
        payload = json.loads(cli.stdout)
        assert payload["status"] == "ok"
        assert payload["scanner"] == "path"
        assert payload["finding_count"] == 0

        context_policy = repo / "context-policy.yaml"
        context_policy.write_text("{}\n", encoding="utf-8")
        agent_context = (
            "Require approval before shell writes.\n"
            "Keep credentials redacted in public evidence.\n"
            "Run pytest before reporting success.\n"
        )
        (repo / "AGENTS.md").write_text(agent_context, encoding="utf-8")
        init_cli = run(
            isolated_module_command(
                python,
                "agent_guard.cli",
                "init",
                "--root",
                str(repo / "init-preview"),
                "--json",
            ),
            cwd=temp,
        )
        init_payload = json.loads(init_cli.stdout)
        assert init_payload["schema_version"] == "agent-guard.init_plan.v1"
        assert init_payload["mode"] == "print"
        assert not (repo / "init-preview" / ".agent-guard").exists()

        context_cli = run(
            isolated_module_command(
                python,
                "agent_guard.cli",
                "context",
                "check",
                "--root",
                str(repo),
                "--policy",
                str(context_policy),
                "--json",
            ),
            cwd=temp,
        )
        context_payload = json.loads(context_cli.stdout)
        assert context_payload["status"] == "ok"
        assert context_payload["scanner"] == "context"
        assert context_payload["finding_count"] == 0

        digest_policy = repo / "digest-policy.yaml"
        agent_context_sha256 = hashlib.sha256(agent_context.encode("utf-8")).hexdigest()
        digest_policy.write_text(
            "checks:\n"
            "  - id: agent_context_pin\n"
            "    path: AGENTS.md\n"
            f"    sha256: '{agent_context_sha256}'\n",
            encoding="utf-8",
        )
        workflow_file = repo / ".github" / "workflows" / "ci.yml"
        workflow_file.parent.mkdir(parents=True, exist_ok=True)
        workflow_file.write_text(
            "name: ci\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - name: Run guard checks\n"
            "        run: |\n"
            "          python -m agent_guard.cli context check --root . --policy context-policy.yaml --json\n"
            "          python -m agent_guard.cli digest check --root . --policy digest-policy.yaml --json\n"
            "          python -m agent_guard.cli mcp check --root . --json\n",
            encoding="utf-8",
        )
        workflow_policy = repo / "workflow-policy.yaml"
        workflow_policy.write_text(
            "schema_version: agent-guard.workflow_policy.v1\n"
            "required_files:\n"
            "  - id: context_policy\n"
            "    path: context-policy.yaml\n"
            "  - id: digest_policy\n"
            "    path: digest-policy.yaml\n"
            "workflow_checks:\n"
            "  - id: ci_guard_smoke\n"
            "    path: .github/workflows/ci.yml\n"
            "    required_commands:\n"
            "      - id: context_guard\n"
            "        command: python -m agent_guard.cli context check\n"
            "      - id: digest_guard\n"
            "        command: python -m agent_guard.cli digest check\n"
            "      - id: mcp_config_guard\n"
            "        command: python -m agent_guard.cli mcp check\n",
            encoding="utf-8",
        )
        workflow_cli = run(
            isolated_module_command(
                python,
                "agent_guard.cli",
                "workflow",
                "check",
                "--root",
                str(repo),
                "--policy",
                str(workflow_policy),
                "--json",
            ),
            cwd=temp,
        )
        workflow_payload = json.loads(workflow_cli.stdout)
        assert workflow_payload["status"] == "ok"
        assert workflow_payload["scanner"] == "workflow"
        assert workflow_payload["finding_count"] == 0

        surface_cli = run(
            isolated_module_command(
                python,
                "agent_guard.cli",
                "surface",
                "inventory",
                "--root",
                str(repo),
                "--context-policy",
                str(context_policy),
                "--json",
            ),
            cwd=temp,
        )
        surface_payload = json.loads(surface_cli.stdout)
        assert surface_payload["status"] == "ok"
        assert surface_payload["scanner"] == "surface"
        assert surface_payload["surface_inventory"]["schema_version"] == "agent-guard.agent_surface_inventory.v1"
        surface_v2_cli = run(
            isolated_module_command(
                python,
                "agent_guard.cli",
                "surface",
                "inventory",
                "--root",
                str(repo),
                "--context-policy",
                str(context_policy),
                "--schema-version",
                "v2",
                "--json",
            ),
            cwd=temp,
        )
        surface_v2_payload = json.loads(surface_v2_cli.stdout)
        assert surface_v2_payload["status"] == "ok"
        assert surface_v2_payload["surface_inventory"]["schema_version"] == "agent-guard.agent_surface_inventory.v2"

        (repo / "README.md").write_text(
            "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml\n"
            "agent-guard context check --root . --policy .agent-guard/context-policy.yaml\n"
            "agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml\n"
            "agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml\n"
            "agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml\n"
            "agent-guard drift check --root .\n"
            "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --mcp-policy .agent-guard/mcp-policy.yaml\n",
            encoding="utf-8",
        )
        drift_policy_dir = repo / ".agent-guard"
        drift_policy_dir.mkdir(exist_ok=True)
        for source, destination in (
            (context_policy, drift_policy_dir / "context-policy.yaml"),
            (policy, drift_policy_dir / "path-policy.yaml"),
            (digest_policy, drift_policy_dir / "context-digest-policy.yaml"),
        ):
            destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        (drift_policy_dir / "content-policy.yaml").write_text(
            "file_globs:\n  - '**/*.md'\nexclude_globs: []\nforbidden_patterns: []\n",
            encoding="utf-8",
        )
        (drift_policy_dir / "mcp-policy.yaml").write_text(
            "schema_version: agent-guard.mcp_policy.v1\n"
            "policy:\n"
            "  fail_on_parse_error: true\n"
            "  forbidden_risky_patterns:\n"
            "    - broad_authorization_scope\n"
            "    - filesystem_root_reference\n"
            "    - inline_authorization_value\n"
            "    - inline_env_value\n"
            "    - instruction_like_description\n"
            "    - latest_package\n"
            "    - secret_shaped_inline_value\n"
            "    - unsafe_url_scheme\n"
            "    - unpinned_package\n",
            encoding="utf-8",
        )
        (drift_policy_dir / "workflow-policy.yaml").write_text(
            "schema_version: agent-guard.workflow_policy.v1\n"
            "required_files:\n"
            "  - id: context_policy\n"
            "    path: .agent-guard/context-policy.yaml\n"
            "  - id: path_policy\n"
            "    path: .agent-guard/path-policy.yaml\n"
            "  - id: content_policy\n"
            "    path: .agent-guard/content-policy.yaml\n"
            "  - id: mcp_policy\n"
            "    path: .agent-guard/mcp-policy.yaml\n"
            "  - id: workflow_policy\n"
            "    path: .agent-guard/workflow-policy.yaml\n",
            encoding="utf-8",
        )
        drift_cli = run(
            isolated_module_command(
                python,
                "agent_guard.cli",
                "drift",
                "check",
                "--root",
                str(repo),
                "--json",
            ),
            cwd=temp,
        )
        drift_payload = json.loads(drift_cli.stdout)
        assert drift_payload["status"] == "ok"
        assert drift_payload["scanner"] == "drift"

        report_cli = run(
            isolated_module_command(
                python,
                "agent_guard.cli",
                "report",
                "--root",
                str(repo),
                "--context-policy",
                str(context_policy),
                "--digest-policy",
                str(digest_policy),
                "--workflow-policy",
                str(workflow_policy),
                "--drift-check",
            ),
            cwd=temp,
        )
        assert report_cli.stdout.startswith("# Agent Guard Evidence Report\n")
        assert "| Status | ok |" in report_cli.stdout
        assert "| Policy | context-policy.yaml |" in report_cli.stdout
        assert "| Digest policy | digest-policy.yaml |" in report_cli.stdout
        assert "| Digest checks | 1 |" in report_cli.stdout
        assert "| Workflow policy | workflow-policy.yaml |" in report_cli.stdout
        assert "| Workflow checks | 5 |" in report_cli.stdout
        assert "| Workflow drift findings | 0 |" in report_cli.stdout
        assert "| Policy/spec drift findings | 0 |" in report_cli.stdout
        assert agent_context_sha256 not in report_cli.stdout
        assert str(temp) not in report_cli.stdout

        report_output = repo / ".agent-guard" / "evidence" / "agent-guard-report.json"
        report_output_cli = run(
            isolated_module_command(
                python,
                "agent_guard.cli",
                "report",
                "--root",
                str(repo),
                "--context-policy",
                str(context_policy),
                "--digest-policy",
                str(digest_policy),
                "--workflow-policy",
                str(workflow_policy),
                "--drift-check",
                "--format",
                "json",
                "--output",
                str(report_output),
            ),
            cwd=temp,
        )
        assert report_output_cli.stdout == ""
        report_payload = json.loads(report_output.read_text(encoding="utf-8"))
        assert report_payload["schema_version"] == "agent-guard.result.v1"
        assert report_payload["report"]["schema_version"] == "agent-guard.report_evidence.v1"
        assert report_payload["report"]["format"] == "json"
        assert report_payload["surface_inventory"]["schema_version"] == "agent-guard.agent_surface_inventory.v1"
        assert report_payload["evidence_coverage"]["schema_version"] == "agent-guard.evidence_coverage.v1"
        assert report_payload["policy_spec_drift"]["schema_version"] == "agent-guard.policy_spec_drift.v1"
        assert report_payload["context_lock"]["covered"] == [
            {
                "path": "AGENTS.md",
                "kind": "agents_md",
                "status": "covered",
                "check_id": "agent_context_pin",
            }
        ]
        assert agent_context_sha256 not in report_output.read_text(encoding="utf-8")
        assert str(temp) not in report_output.read_text(encoding="utf-8")

        sarif_output = repo / ".agent-guard" / "evidence" / "agent-guard-results.sarif"
        sarif_cli = run(
            isolated_module_command(
                python,
                "agent_guard.cli",
                "report",
                "--root",
                str(repo),
                "--context-policy",
                str(context_policy),
                "--digest-policy",
                str(digest_policy),
                "--workflow-policy",
                str(workflow_policy),
                "--drift-check",
                "--format",
                "sarif",
                "--output",
                str(sarif_output),
            ),
            cwd=temp,
        )
        assert sarif_cli.stdout == ""
        sarif_payload = json.loads(sarif_output.read_text(encoding="utf-8"))
        assert sarif_payload["version"] == "2.1.0"
        assert sarif_payload["runs"][0]["tool"]["driver"]["name"] == "agent-guard"
        assert sarif_payload["runs"][0]["results"] == []
        assert agent_context_sha256 not in sarif_output.read_text(encoding="utf-8")
        assert str(temp) not in sarif_output.read_text(encoding="utf-8")

        consumer_cli = run(
            isolated_module_command(
                python,
                "agent_guard.consumer",
                "--evidence-dir",
                str(report_output.parent),
                str(report_output),
            ),
            cwd=temp,
        )
        consumer_summary = json.loads(consumer_cli.stdout)
        assert consumer_summary["schema_version"] == "agent-guard.result.v1"
        assert consumer_summary["status"] == "ok"

        preset_cli = run(
            isolated_module_command(
                python,
                "agent_guard.cli",
                "report",
                "--root",
                str(repo),
                "--context-policy",
                str(drift_policy_dir / "context-policy.yaml"),
                "--evidence-preset",
                "recommended",
                "--format",
                "json",
            ),
            cwd=temp,
        )
        preset_payload = json.loads(preset_cli.stdout)
        assert preset_payload["report"]["scope"] == "context+path+content+mcp+workflow+drift"
        assert preset_payload["surface_inventory"]["schema_version"] == "agent-guard.agent_surface_inventory.v2"
        assert preset_payload["conformance"]["profile"] == "recommended"
        assert preset_payload["evidence_pack_manifest"]["sanitized"] is True

        conformance_input = repo / ".agent-guard" / "evidence" / "minimal-conformance.json"
        conformance_input.write_text(
            json.dumps(
                {
                    "evidence_coverage": {
                        "gates": [
                            {"gate": "context", "status": "ok", "checked_count": 1, "finding_count": 0},
                            {"gate": "surface_inventory", "status": "ok", "checked_count": 1, "finding_count": 0},
                        ]
                    },
                    "surface_inventory": {
                        "summary": {"by_surface": {"agent_context": 1, "policy_file": 2}},
                        "surfaces": [
                            {
                                "surface": "policy_file",
                                "path": ".agent-guard/context-policy.yaml",
                                "kind": "context_policy",
                                "status": "present",
                            },
                            {
                                "surface": "policy_file",
                                "path": ".agent-guard/workflow-policy.yaml",
                                "kind": "workflow_policy",
                                "status": "present",
                            },
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )
        conformance_cli = run(
            isolated_module_command(
                python,
                "agent_guard.cli",
                "conformance",
                "check",
                "--root",
                str(repo),
                "--evidence",
                str(conformance_input),
                "--profile",
                "minimal",
                "--json",
            ),
            cwd=temp,
        )
        conformance_payload = json.loads(conformance_cli.stdout)
        assert conformance_payload["status"] == "ok"
        assert conformance_payload["conformance"]["schema_version"] == "agent-guard.conformance.v1"

        manifest_cli = run(
            isolated_module_command(
                python,
                "agent_guard.cli",
                "evidence-pack",
                "manifest",
                "--root",
                str(repo),
                "--report",
                str(report_output),
                "--artifact",
                str(report_output),
                "--artifact",
                r"C:\Users\alice\secret\agent-guard-report.json",
                "--agent-policy-audit-event",
                str(repo / ".agent-guard" / "evidence" / "policy-admission-event.json"),
                "--json",
            ),
            cwd=temp,
        )
        manifest_payload = json.loads(manifest_cli.stdout)
        assert manifest_payload["status"] == "ok"
        assert manifest_payload["evidence_pack_manifest"]["schema_version"] == "agent-guard.evidence_pack_manifest.v1"
        assert manifest_payload["evidence_pack_manifest"]["artifacts"] == [
            {"path": ".agent-guard/evidence/agent-guard-report.json", "role": "report"},
            {"path": "agent-guard-report.json", "role": "report"},
            {"path": ".agent-guard/evidence/policy-admission-event.json", "role": "agent-policy-audit-event"},
        ]
        assert r"C:\Users\alice" not in manifest_cli.stdout
        assert str(temp) not in manifest_cli.stdout

    print(f"wheel contract OK: {wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
