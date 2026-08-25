"""Where: tests/test_bounded_git.py
What: focused process and environment boundary tests for bounded Git execution.
Why: prove Git helpers cannot retain hostile configuration or pipe-holding descendants.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from agent_guard import bounded_git


def _process_is_running(process_id: int) -> bool:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        wait_for_single_object = kernel32.WaitForSingleObject
        wait_for_single_object.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        wait_for_single_object.restype = wintypes.DWORD
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        handle = open_process(0x00100000, False, process_id)
        if not handle:
            return False
        try:
            return wait_for_single_object(handle, 0) == 0x00000102
        finally:
            close_handle(handle)

    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    status = Path(f"/proc/{process_id}/stat")
    if status.is_file():
        try:
            return status.read_text(encoding="ascii").split()[2] != "Z"
        except (OSError, IndexError, UnicodeError):
            pass
    return True


def test_sanitized_git_environment_removes_config_injection_case_insensitively() -> None:
    source = {
        "PATH": os.environ.get("PATH", ""),
        "AGENT_GUARD_SYNTHETIC": "preserved",
        "GIT_DIR": "hostile-routing",
        "git_config_count": "2",
        "Git_Config_Key_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "synthetic-helper",
        "GIT_CONFIG_KEY_1": "core.pager",
        "git_config_value_1": "synthetic-pager",
        "GIT_CONFIG_PARAMETERS": "'core.fsmonitor=synthetic-parameter'",
        "GIT_CONFIG_SYSTEM": "hostile-system",
        "GIT_CONFIG_GLOBAL": "hostile-global",
        "GIT_CONFIG_NOSYSTEM": "0",
        "GIT_NO_LAZY_FETCH": "0",
        "GIT_NO_REPLACE_OBJECTS": "0",
    }

    environment = bounded_git.sanitized_git_environment(source)

    assert source["git_config_count"] == "2"
    assert environment["AGENT_GUARD_SYNTHETIC"] == "preserved"
    assert "GIT_DIR" not in environment
    assert not any(
        key.upper() == "GIT_CONFIG_COUNT"
        or key.upper() == "GIT_CONFIG_PARAMETERS"
        or key.upper().startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))
        for key in environment
    )
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_SYSTEM"] == os.devnull
    assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert environment["GIT_NO_LAZY_FETCH"] == "1"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert environment["GIT_PAGER"] == ""
    assert environment["GIT_TERMINAL_PROMPT"] == "0"


def test_run_bounded_git_passes_command_line_fsmonitor_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def run_process(command: list[str], **kwargs: object):
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, b"ok\n")

    monkeypatch.setattr(bounded_git, "_run_bounded_process", run_process)

    result = bounded_git.run_bounded_git(
        tmp_path,
        ["rev-parse", "--is-inside-work-tree"],
        timeout_seconds=1.0,
        max_output_bytes=128,
    )

    assert result.stdout == b"ok\n"
    assert captured["command"] == [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-C",
        str(tmp_path),
        "rev-parse",
        "--is-inside-work-tree",
    ]
    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"


@pytest.mark.parametrize(
    "args",
    [
        ["status", "--short"],
        ["diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv"],
        ["ls-files", "--cached"],
        ["-c", "filter.synthetic.clean=helper", "diff", "--no-ext-diff", "--no-textconv", "--no-renames"],
        ["-c", "filter.synthetic.clean=", "diff", "--no-ext-diff", "--no-textconv", "--no-renames"],
        ["cat-file", "--batch-all-objects"],
        ["ls-tree", "-r", "-z", "--full-tree", "--output=unsafe"],
        ["merge-base", "--all", "origin/main", "HEAD"],
    ],
)
def test_run_bounded_git_rejects_helper_capable_or_unbounded_invocations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
) -> None:
    started = False

    def unexpected_process(*_args: object, **_kwargs: object) -> None:
        nonlocal started
        started = True

    monkeypatch.setattr(bounded_git, "_run_bounded_process", unexpected_process)

    with pytest.raises(bounded_git.BoundedGitProcessError):
        bounded_git.run_bounded_git(
            tmp_path,
            args,
            timeout_seconds=1.0,
            max_output_bytes=128,
        )

    assert not started


def test_run_bounded_git_accepts_complete_filter_neutralization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def run_process(command: list[str], **kwargs: object):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, b"")

    monkeypatch.setattr(bounded_git, "_run_bounded_process", run_process)
    args = [
        "-c",
        "filter.synthetic.clean=",
        "-c",
        "filter.synthetic.process=",
        "-c",
        "filter.synthetic.required=false",
        "diff",
        "--name-only",
        "-z",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
    ]

    bounded_git.run_bounded_git(
        tmp_path,
        args,
        timeout_seconds=1.0,
        max_output_bytes=128,
    )

    command = captured["command"]
    assert isinstance(command, list)
    assert command[-len(args) :] == args


@pytest.mark.parametrize(
    "args",
    [
        ["cat-file", "--batch"],
        ["ls-tree", "-r", "-z", "--full-tree", "HEAD"],
        ["merge-base", "--all", "--", "origin/main", "HEAD"],
    ],
)
def test_run_bounded_git_accepts_surface_delta_read_only_queries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
) -> None:
    captured: dict[str, object] = {}

    def run_process(command: list[str], **kwargs: object):
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, b"")

    monkeypatch.setattr(bounded_git, "_run_bounded_process", run_process)

    bounded_git.run_bounded_git(
        tmp_path,
        args,
        timeout_seconds=1.0,
        max_output_bytes=128,
    )

    command = captured["command"]
    assert isinstance(command, list)
    assert command[-len(args) :] == args
    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert environment["GIT_NO_LAZY_FETCH"] == "1"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"


def test_bounded_process_kills_descendant_holding_stdout_and_joins_reader(
    tmp_path: Path,
) -> None:
    child_script = tmp_path / "pipe_holder.py"
    child_script.write_text(
        "import os\n"
        "from pathlib import Path\n"
        "import signal\n"
        "import sys\n"
        "import time\n"
        "if os.name == 'posix':\n"
        "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "pid_path = Path(sys.argv[1])\n"
        "staged_pid_path = pid_path.with_suffix('.tmp')\n"
        "staged_pid_path.write_text(str(os.getpid()), encoding='ascii')\n"
        "print(os.getpid(), flush=True)\n"
        "os.replace(staged_pid_path, pid_path)\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    launcher_script = tmp_path / "pipe_holder_launcher.py"
    launcher_script.write_text(
        "from pathlib import Path\n"
        "import subprocess\n"
        "import sys\n"
        "import time\n"
        "subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])\n"
        "deadline = time.monotonic() + 5\n"
        "while not Path(sys.argv[2]).exists():\n"
        "    if time.monotonic() >= deadline:\n"
        "        raise SystemExit(124)\n"
        "    time.sleep(0.01)\n",
        encoding="utf-8",
    )
    process_id_file = tmp_path / "pipe-holder.pid"
    baseline_threads = {
        thread.ident
        for thread in threading.enumerate()
        if thread.name.startswith("agent-guard-git-")
    }

    started = time.monotonic()
    result = bounded_git._run_bounded_process(
        [
            sys.executable,
            str(launcher_script),
            str(child_script),
            str(process_id_file),
        ],
        environment=os.environ,
        timeout_seconds=1.0,
        max_output_bytes=1_024,
    )
    elapsed = time.monotonic() - started
    process_id = int(process_id_file.read_text(encoding="ascii"))

    deadline = time.monotonic() + 2.0
    while _process_is_running(process_id) and time.monotonic() < deadline:
        time.sleep(0.01)

    assert result.returncode == 0
    assert str(process_id).encode("ascii") in result.stdout
    assert elapsed < 2.0
    assert not _process_is_running(process_id)
    assert {
        thread.ident
        for thread in threading.enumerate()
        if thread.name.startswith("agent-guard-git-")
    } == baseline_threads


@pytest.mark.parametrize("returncode", [0, 7])
def test_windows_job_wrapper_preserves_child_returncode(returncode: int) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            bounded_git._WINDOWS_JOB_WRAPPER,
            sys.executable,
            "-c",
            f"raise SystemExit({returncode})",
        ],
        input=b"\0",
        capture_output=True,
        check=False,
    )

    assert result.returncode == returncode
    assert result.stdout == b""
    assert result.stderr == b""


def test_bounded_process_stops_at_output_limit(tmp_path: Path) -> None:
    started = time.monotonic()
    with pytest.raises(bounded_git.BoundedGitOutputLimitError):
        bounded_git._run_bounded_process(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1024)"],
            environment=os.environ,
            timeout_seconds=1.0,
            max_output_bytes=8,
        )

    assert time.monotonic() - started < 2.0


@pytest.mark.skipif(os.name != "posix", reason="exercises POSIX process-group failure")
def test_bounded_process_does_not_wait_forever_when_containment_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_script = tmp_path / "uncontained_pipe_holder.py"
    child_script.write_text(
        "import os\n"
        "from pathlib import Path\n"
        "import sys\n"
        "import time\n"
        "Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii')\n"
        "print('ready', flush=True)\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    launcher_script = tmp_path / "uncontained_launcher.py"
    launcher_script.write_text(
        "from pathlib import Path\n"
        "import subprocess\n"
        "import sys\n"
        "import time\n"
        "subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])\n"
        "deadline = time.monotonic() + 5\n"
        "while not Path(sys.argv[2]).exists():\n"
        "    if time.monotonic() >= deadline:\n"
        "        raise SystemExit(124)\n"
        "    time.sleep(0.01)\n",
        encoding="utf-8",
    )
    process_id_file = tmp_path / "uncontained.pid"

    def fail_containment(
        process: subprocess.Popen[bytes],
        windows_job: object | None,
    ) -> bool:
        del windows_job
        bounded_git._stop_uncontained_process(process)
        return False

    monkeypatch.setattr(bounded_git, "_terminate_process_tree", fail_containment)
    baseline_threads = {
        thread.ident
        for thread in threading.enumerate()
        if thread.name.startswith("agent-guard-git-")
    }

    started = time.monotonic()
    try:
        with pytest.raises(bounded_git.BoundedGitProcessError):
            bounded_git._run_bounded_process(
                [
                    sys.executable,
                    str(launcher_script),
                    str(child_script),
                    str(process_id_file),
                ],
                environment=os.environ,
                timeout_seconds=1.0,
                max_output_bytes=1_024,
            )
    finally:
        if process_id_file.exists():
            process_id = int(process_id_file.read_text(encoding="ascii"))
            try:
                os.kill(process_id, signal.SIGKILL)
            except ProcessLookupError:
                pass

    assert time.monotonic() - started < 2.0
    deadline = time.monotonic() + 1.0
    current_threads = set()
    while time.monotonic() < deadline:
        current_threads = {
            thread.ident
            for thread in threading.enumerate()
            if thread.name.startswith("agent-guard-git-")
        }
        if current_threads == baseline_threads:
            break
        time.sleep(0.01)
    assert current_threads == baseline_threads
