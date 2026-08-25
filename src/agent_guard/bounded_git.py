"""Where: src/agent_guard/bounded_git.py
What: bounded, configuration-isolated Git process execution.
Why: keep untrusted repository metadata from escaping Git command boundaries.
"""

from __future__ import annotations

import ntpath
import os
import posixpath
import re
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path


GIT_IO_CHUNK_BYTES = 64 * 1024
GIT_WAIT_POLL_SECONDS = 0.05
GIT_TERMINATION_GRACE_SECONDS = 0.25
GIT_IO_JOIN_GRACE_SECONDS = 0.5

# A bare ``git`` command may resolve through a repository-controlled current
# directory or caller-controlled PATH. These are the supported host install
# locations, in deterministic preference order; their ownership is part of the
# runner trust boundary.
_POSIX_GIT_EXECUTABLES = (
    "/usr/bin/git",
    "/bin/git",
    "/usr/local/bin/git",
    "/opt/homebrew/bin/git",
    "/opt/local/bin/git",
)
_WINDOWS_GIT_EXECUTABLES = (
    r"C:\Program Files\Git\cmd\git.exe",
    r"C:\Program Files\Git\bin\git.exe",
    r"C:\Program Files (x86)\Git\cmd\git.exe",
    r"C:\Program Files (x86)\Git\bin\git.exe",
)

_SAFE_FILTER_OVERRIDE_RE = re.compile(
    r"filter\.([A-Za-z0-9._-]{1,128})\.(clean|process|required)=(.*)"
)
_SAFE_GIT_SUBCOMMANDS = frozenset(
    {
        "cat-file",
        "config",
        "diff",
        "ls-files",
        "ls-tree",
        "merge-base",
        "rev-parse",
    }
)
_FILTER_CONFIG_QUERY = (
    "config",
    "--null",
    "--name-only",
    "--get-regexp",
    r"^filter\..*\.(clean|process|required)$",
)

# Git reads these before repository-local command arguments can constrain it.
# Compare environment keys case-insensitively so Windows cannot retain a
# differently-cased spelling of the same variable.
UNTRUSTED_GIT_ENVIRONMENT_VARIABLES = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_ATTR_SOURCE",
        "GIT_CEILING_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_CURL_VERBOSE",
        "GIT_DIR",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_DIFF_OPTS",
        "GIT_EDITOR",
        "GIT_EXEC_PATH",
        "GIT_EXTERNAL_DIFF",
        "GIT_GRAFT_FILE",
        "GIT_IMPLICIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_NO_LAZY_FETCH",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_OBJECT_DIRECTORY",
        "GIT_OPTIONAL_LOCKS",
        "GIT_PREFIX",
        "GIT_PAGER",
        "GIT_PROXY_COMMAND",
        "GIT_QUARANTINE_PATH",
        "GIT_REDIRECT_STDIN",
        "GIT_REDIRECT_STDERR",
        "GIT_REDIRECT_STDOUT",
        "GIT_REPLACE_REF_BASE",
        "GIT_SEQUENCE_EDITOR",
        "GIT_SHALLOW_FILE",
        "GIT_SSH_VARIANT",
        "GIT_TERMINAL_PROMPT",
        "GIT_WORK_TREE",
        "GIT_ASKPASS",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
    }
)
_UNTRUSTED_GIT_ENVIRONMENT_PREFIXES = (
    "GIT_CONFIG_KEY_",
    "GIT_CONFIG_VALUE_",
    "GIT_TRACE",
)

_WINDOWS_JOB_WRAPPER = r"""
import os
import subprocess
import sys

if os.read(0, 1) != b"\0":
    raise SystemExit(125)
try:
    child = subprocess.Popen(sys.argv[1:])
    returncode = child.wait()
except BaseException:
    raise SystemExit(125)
raise SystemExit(returncode)
"""


class BoundedGitProcessError(RuntimeError):
    """A Git process could not complete inside its configured bounds."""


class BoundedGitOutputLimitError(BoundedGitProcessError):
    """A Git process produced more output than its caller permits."""


def sanitized_git_environment(
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a copy of ``source`` without caller-controlled Git routing/config."""

    environment = dict(os.environ if source is None else source)
    for variable in tuple(environment):
        normalized = variable.upper()
        if normalized in UNTRUSTED_GIT_ENVIRONMENT_VARIABLES or normalized.startswith(
            _UNTRUSTED_GIT_ENVIRONMENT_PREFIXES
        ):
            environment.pop(variable, None)

    # os.devnull is cross-platform (``/dev/null`` on POSIX, ``nul`` on Windows).
    # GIT_CONFIG_NOSYSTEM prevents a system read; explicit null selectors prevent
    # Git from falling back to either system or user-global configuration.
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_SYSTEM"] = os.devnull
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_PAGER"] = ""
    environment["GIT_TERMINAL_PROMPT"] = "0"
    return environment


def _trusted_git_executable_candidates() -> tuple[Path, ...]:
    """Return fixed host Git locations without consulting the caller's PATH."""

    candidates = (
        _WINDOWS_GIT_EXECUTABLES if os.name == "nt" else _POSIX_GIT_EXECUTABLES
    )
    return tuple(Path(candidate) for candidate in candidates)


def _repository_controlled_roots(root: Path) -> tuple[Path, ...]:
    """Return the reviewed and current directory roots, including Git parents."""

    try:
        starts = (root, Path.cwd())
    except OSError as error:
        raise BoundedGitProcessError from error

    roots: list[Path] = []
    for start in starts:
        try:
            resolved = start.resolve(strict=False)
        except (OSError, RuntimeError) as error:
            raise BoundedGitProcessError from error
        roots.append(resolved)
        for ancestor in (resolved, *resolved.parents):
            try:
                if (ancestor / ".git").exists():
                    roots.append(ancestor)
            except OSError:
                continue
    return tuple(roots)


def _path_is_within(
    path: Path,
    root: Path,
    *,
    windows: bool | None = None,
) -> bool:
    """Return whether ``path`` is ``root`` or a descendant using host identity."""

    is_windows = os.name == "nt" if windows is None else windows
    path_module = ntpath if is_windows else posixpath
    normalized_path = path_module.normcase(path_module.normpath(str(path)))
    normalized_root = path_module.normcase(path_module.normpath(str(root)))
    try:
        return (
            path_module.commonpath((normalized_path, normalized_root))
            == normalized_root
        )
    except ValueError:
        return False


def _resolve_trusted_git_executable(root: Path) -> Path:
    """Resolve a regular Git executable outside repository-controlled roots."""

    controlled_roots = _repository_controlled_roots(root)
    for candidate in _trusted_git_executable_candidates():
        try:
            executable = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if (
            not executable.is_absolute()
            or not executable.is_file()
            or not os.access(executable, os.X_OK)
            or any(
                _path_is_within(executable, boundary) for boundary in controlled_roots
            )
        ):
            continue
        return executable
    raise BoundedGitProcessError


def _validate_git_arguments(args: Sequence[str]) -> None:
    """Reject helper-capable Git invocations before starting a process.

    Process groups cannot portably contain a POSIX descendant that deliberately
    detaches with ``setsid()``. Keep this runner limited to the read-only Git
    commands used by static evidence and require helper-disabling diff flags.
    """

    arguments = tuple(args)
    index = 0
    filter_overrides: dict[str, set[str]] = {}
    while index < len(arguments) and arguments[index] == "-c":
        if index + 1 >= len(arguments):
            raise BoundedGitProcessError
        match = _SAFE_FILTER_OVERRIDE_RE.fullmatch(arguments[index + 1])
        if match is None:
            raise BoundedGitProcessError
        driver, field, value = match.groups()
        expected = "false" if field == "required" else ""
        if value != expected or field in filter_overrides.setdefault(driver, set()):
            raise BoundedGitProcessError
        filter_overrides[driver].add(field)
        index += 2

    if any(fields != {"clean", "process", "required"} for fields in filter_overrides.values()):
        raise BoundedGitProcessError
    if index >= len(arguments) or arguments[index] not in _SAFE_GIT_SUBCOMMANDS:
        raise BoundedGitProcessError

    subcommand = arguments[index]
    command_arguments = arguments[index:]
    if filter_overrides and subcommand != "diff":
        raise BoundedGitProcessError
    if subcommand == "config" and command_arguments != _FILTER_CONFIG_QUERY:
        raise BoundedGitProcessError
    if subcommand == "diff" and not {
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
    }.issubset(command_arguments):
        raise BoundedGitProcessError
    if subcommand == "ls-files" and "-z" not in command_arguments:
        raise BoundedGitProcessError
    if subcommand == "cat-file" and command_arguments not in {
        ("cat-file", "--batch"),
        (
            "cat-file",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ),
    }:
        raise BoundedGitProcessError
    if subcommand == "ls-tree" and not (
        len(command_arguments) == 5
        and command_arguments[1:4] == ("-r", "-z", "--full-tree")
        and command_arguments[4]
        and not command_arguments[4].startswith("-")
        and not any(char in command_arguments[4] for char in "\x00\r\n")
    ):
        raise BoundedGitProcessError
    if subcommand == "merge-base" and not (
        len(command_arguments) == 5
        and command_arguments[1:3] == ("--all", "--")
        and command_arguments[3]
        and not command_arguments[3].startswith("-")
        and not any(char in command_arguments[3] for char in "\x00\r\n")
        and command_arguments[4] == "HEAD"
    ):
        raise BoundedGitProcessError


def run_bounded_git(
    root: Path,
    args: Sequence[str],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
    input_data: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run one allowlisted, helper-free Git query inside fixed resource bounds."""

    _validate_git_arguments(args)
    executable = _resolve_trusted_git_executable(root)

    command = [
        str(executable),
        "-c",
        "core.fsmonitor=false",
        "-C",
        str(root),
        *args,
    ]
    return _run_bounded_process(
        command,
        environment=sanitized_git_environment(),
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        input_data=input_data,
    )


def _run_bounded_process(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
    input_data: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run a process behind the same containment used for Git.

    This private seam exists so process-tree behavior can be exercised without
    replacing the user's Git executable.
    """

    if max_output_bytes < 0:
        raise BoundedGitOutputLimitError

    process: subprocess.Popen[bytes] | None = None
    windows_job: object | None = None
    windows_handshake = os.name == "nt"
    try:
        if windows_handshake:
            windows_job = _create_windows_kill_job()
            process = subprocess.Popen(
                [sys.executable, "-I", "-S", "-c", _WINDOWS_JOB_WRAPPER, *command],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=dict(environment),
            )
            if not _assign_windows_process_to_job(windows_job, process):
                _stop_uncontained_process(process)
                _close_windows_handle(windows_job)
                windows_job = None
                raise BoundedGitProcessError
        else:
            process = subprocess.Popen(
                list(command),
                stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=dict(environment),
                start_new_session=True,
            )
    except BoundedGitProcessError:
        raise
    except Exception:
        if windows_job is not None:
            _close_windows_handle(windows_job)
        raise BoundedGitProcessError from None

    stdout = process.stdout
    stdin = process.stdin
    if stdout is None or (windows_handshake and stdin is None) or (
        input_data is not None and stdin is None
    ):
        _terminate_process_tree(process, windows_job)
        _close_stream(stdin)
        _close_stream(stdout)
        raise BoundedGitProcessError

    stopping = threading.Event()
    io_failed = threading.Event()
    output_limit_exceeded = threading.Event()
    output = bytearray()

    def read_stdout() -> None:
        try:
            read = getattr(stdout, "read1", stdout.read)
            while True:
                remaining = max_output_bytes - len(output)
                chunk = read(min(GIT_IO_CHUNK_BYTES, remaining + 1))
                if not chunk:
                    return
                if len(chunk) > remaining:
                    output_limit_exceeded.set()
                    return
                output.extend(chunk)
        except Exception:
            if not stopping.is_set():
                io_failed.set()

    def write_stdin() -> None:
        if stdin is None:
            return
        try:
            if windows_handshake:
                stdin.write(b"\0")
                stdin.flush()
            if input_data is not None:
                data = memoryview(input_data)
                for offset in range(0, len(data), GIT_IO_CHUNK_BYTES):
                    if stopping.is_set():
                        return
                    stdin.write(data[offset : offset + GIT_IO_CHUNK_BYTES])
                    stdin.flush()
        except Exception:
            if not stopping.is_set():
                io_failed.set()
        finally:
            _close_stream(stdin)

    workers = [
        threading.Thread(
            target=read_stdout,
            name=f"agent-guard-git-stdout-{process.pid}",
            daemon=True,
        )
    ]
    if input_data is not None or windows_handshake:
        workers.append(
            threading.Thread(
                target=write_stdin,
                name=f"agent-guard-git-stdin-{process.pid}",
                daemon=True,
            )
        )

    deadline = time.monotonic() + max(timeout_seconds, 0.0)
    observed_returncode: int | None = None
    timed_out = False
    runtime_failed = False
    started_workers: list[threading.Thread] = []
    containment_succeeded = False
    try:
        for worker in workers:
            worker.start()
            started_workers.append(worker)

        while not io_failed.is_set() and not output_limit_exceeded.is_set():
            observed_returncode = process.poll()
            if observed_returncode is not None:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                observed_returncode = process.wait(
                    timeout=min(remaining, GIT_WAIT_POLL_SECONDS)
                )
            except subprocess.TimeoutExpired:
                continue
            if observed_returncode is not None:
                break
    except Exception:
        runtime_failed = True
    finally:
        stopping.set()
        containment_succeeded = _terminate_process_tree(process, windows_job)
        workers_stopped = _join_io_workers(
            started_workers,
            streams=(stdin, stdout),
        )
        if workers_stopped:
            _close_stream(stdin)
            _close_stream(stdout)

    if output_limit_exceeded.is_set():
        raise BoundedGitOutputLimitError
    if (
        runtime_failed
        or timed_out
        or io_failed.is_set()
        or not containment_succeeded
        or observed_returncode is None
        or not workers_stopped
    ):
        raise BoundedGitProcessError
    return subprocess.CompletedProcess(list(command), observed_returncode, bytes(output))


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    windows_job: object | None,
) -> bool:
    try:
        if os.name == "nt":
            contained = windows_job is not None and _terminate_windows_job(windows_job)
            return _wait_for_process_exit(process) and contained

        contained = _terminate_posix_process_group(process.pid)
        return _wait_for_process_exit(process) and contained
    except Exception:
        _stop_uncontained_process(process)
        if windows_job is not None:
            _close_windows_handle(windows_job)
        return False


def _terminate_posix_process_group(process_group: int) -> bool:
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError:
        return False

    deadline = time.monotonic() + GIT_TERMINATION_GRACE_SECONDS
    while time.monotonic() < deadline:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        time.sleep(0.01)

    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return True


def _wait_for_process_exit(process: subprocess.Popen[bytes]) -> bool:
    try:
        process.wait(timeout=GIT_TERMINATION_GRACE_SECONDS)
        return True
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=GIT_TERMINATION_GRACE_SECONDS)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return False
    except OSError:
        return False


def _stop_uncontained_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=GIT_TERMINATION_GRACE_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _create_windows_kill_job() -> object:
    import ctypes
    from ctypes import wintypes

    class JobObjectBasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JobObjectExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JobObjectBasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    create_job.restype = wintypes.HANDLE
    set_job_information = kernel32.SetInformationJobObject
    set_job_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    set_job_information.restype = wintypes.BOOL

    job = create_job(None, None)
    if not job:
        raise BoundedGitProcessError
    information = JobObjectExtendedLimitInformation()
    information.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
    if not set_job_information(
        job,
        9,  # JobObjectExtendedLimitInformation
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        _close_windows_handle(job)
        raise BoundedGitProcessError
    return job


def _assign_windows_process_to_job(
    job: object,
    process: subprocess.Popen[bytes],
) -> bool:
    import ctypes
    from ctypes import wintypes

    assign_process = ctypes.WinDLL(
        "kernel32", use_last_error=True
    ).AssignProcessToJobObject
    assign_process.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    assign_process.restype = wintypes.BOOL
    try:
        process_handle = wintypes.HANDLE(int(process._handle))  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError):
        return False
    return bool(assign_process(job, process_handle))


def _terminate_windows_job(job: object) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    terminate_job = kernel32.TerminateJobObject
    terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
    terminate_job.restype = wintypes.BOOL
    terminated = bool(terminate_job(job, 1))
    closed = _close_windows_handle(job)
    return terminated and closed


def _close_windows_handle(handle: object) -> bool:
    if os.name != "nt":
        return True
    import ctypes
    from ctypes import wintypes

    try:
        close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        return bool(close_handle(handle))
    except Exception:
        return False


def _close_stream(stream: object | None) -> None:
    if stream is None:
        return
    try:
        stream.close()  # type: ignore[attr-defined]
    except Exception:
        pass


def _join_io_workers(
    workers: Sequence[threading.Thread],
    *,
    streams: Sequence[object | None],
) -> bool:
    deadline = time.monotonic() + GIT_IO_JOIN_GRACE_SECONDS
    for worker in workers:
        worker.join(timeout=max(deadline - time.monotonic(), 0.0))

    if any(worker.is_alive() for worker in workers):
        # Closing the descriptor directly avoids waiting on a buffered stream's
        # lock while another thread is blocked in read() or write().
        # The caller intentionally leaves the wrapper object alone unless all
        # workers have stopped; its underlying descriptor is already closed.
        for stream in streams:
            if stream is not None:
                _force_close_stream_descriptor(stream)
        deadline = time.monotonic() + GIT_IO_JOIN_GRACE_SECONDS
        for worker in workers:
            worker.join(timeout=max(deadline - time.monotonic(), 0.0))
    return not any(worker.is_alive() for worker in workers)


def _force_close_stream_descriptor(stream: object) -> None:
    try:
        descriptor = stream.fileno()  # type: ignore[attr-defined]
        os.close(descriptor)
    except (OSError, TypeError, ValueError):
        pass
