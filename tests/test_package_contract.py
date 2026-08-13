"""Where: tests/test_package_contract.py
What: package metadata, schema resources, and typed package invariants.
Why: keep version drift and typed-package regressions out of the release path.
"""

from __future__ import annotations

import gzip
import io
import json
import stat
import struct
import subprocess
import sys
import tarfile
import time
import tomllib
import zipfile
import zlib
from pathlib import Path
from typing import BinaryIO

import agent_guard
from packaging.requirements import Requirement
import pytest
import scripts.check_wheel_contract as wheel_contract


REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
EVIDENCE_SAMPLE_REPORT = REPO_ROOT / "docs" / "evidence-samples" / "agent-guard-report.json"
PACKAGE_DIR = REPO_ROOT / "src" / "agent_guard"
SCHEMA_DIR = PACKAGE_DIR / "schemas"


def _write_raw_wheel_metadata(
    wheel: Path,
    version: str,
    payload: bytes,
    *,
    compression: int = zipfile.ZIP_STORED,
) -> None:
    metadata_name = f"yui_agent_guard-{version}.dist-info/METADATA"
    with zipfile.ZipFile(wheel, "w", compression=compression) as archive:
        archive.writestr(metadata_name, payload)


def _write_wheel_metadata(
    wheel: Path,
    version: str,
    requirements: list[str],
) -> None:
    metadata_lines = [
        "Metadata-Version: 2.4",
        "Name: yui-agent-guard",
        f"Version: {version}",
        *(f"Requires-Dist: {requirement}" for requirement in requirements),
        "",
        "",
    ]
    _write_raw_wheel_metadata(
        wheel,
        version,
        "\n".join(metadata_lines).encode("utf-8"),
    )


def pyproject_version() -> str:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_package_version_matches_pyproject() -> None:
    assert agent_guard.__version__ == pyproject_version()


def test_package_requires_safe_tar_filter_runtime() -> None:
    with PYPROJECT.open("rb") as fh:
        pyproject = tomllib.load(fh)

    assert pyproject["project"]["requires-python"] == ">=3.11.4"


def test_wheel_contract_uses_platform_specific_venv_interpreter() -> None:
    venv_dir = Path("contract-venv")

    assert wheel_contract.venv_python_path(venv_dir, platform_name="posix") == venv_dir / "bin" / "python"
    assert wheel_contract.venv_python_path(venv_dir, platform_name="nt") == venv_dir / "Scripts" / "python.exe"


def test_wheel_contract_install_command_is_offline_and_dependency_free() -> None:
    command = wheel_contract.isolated_wheel_install_command(
        Path("contract-python"),
        Path("contract-wheel.whl"),
    )

    assert command == [
        "contract-python",
        "-I",
        "-m",
        "pip",
        "install",
        "--quiet",
        "--disable-pip-version-check",
        "--no-index",
        "--no-deps",
        "contract-wheel.whl",
    ]


def test_wheel_contract_standalone_script_command_is_isolated() -> None:
    command = wheel_contract.isolated_script_command(
        Path("contract-python"),
        Path("consumer.py"),
    )

    assert command == ["contract-python", "-I", "consumer.py"]


def test_wheel_contract_subprocess_failure_is_bounded_and_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_output = "synthetic private subprocess output"

    def failed_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["timeout"] == wheel_contract.WHEEL_SMOKE_SUBPROCESS_TIMEOUT_SECONDS
        return subprocess.CompletedProcess(command, 7, private_output, private_output)

    monkeypatch.setattr(wheel_contract.subprocess, "run", failed_run)

    with pytest.raises(RuntimeError, match="^wheel contract subprocess failed with exit 7$") as exc_info:
        wheel_contract.run(["synthetic-command"], cwd=tmp_path)

    assert private_output not in str(exc_info.value)


def test_wheel_contract_subprocess_timeout_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_output = "synthetic private timeout output"

    def timed_out_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(
            command,
            kwargs["timeout"],
            output=private_output,
            stderr=private_output,
        )

    monkeypatch.setattr(wheel_contract.subprocess, "run", timed_out_run)

    with pytest.raises(RuntimeError, match="^wheel contract subprocess timed out$") as exc_info:
        wheel_contract.run(["synthetic-command"], cwd=tmp_path)

    assert private_output not in str(exc_info.value)


def test_wheel_contract_subprocess_start_failure_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_output = "synthetic private launch detail"

    def failed_start(_command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise OSError(private_output)

    monkeypatch.setattr(wheel_contract.subprocess, "run", failed_start)

    with pytest.raises(RuntimeError, match="^wheel contract subprocess could not start$") as exc_info:
        wheel_contract.run(["synthetic-command"], cwd=tmp_path)

    assert private_output not in str(exc_info.value)


def test_wheel_contract_copies_only_declared_runtime_dependency(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    venv_dir = tmp_path / "venv"
    site_packages = venv_dir / "site-packages"
    site_packages.mkdir(parents=True)
    dependency_root = tmp_path / "outer-site-packages"
    dependency_package = dependency_root / "yaml"
    dependency_package.mkdir(parents=True)
    (dependency_package / "__init__.py").write_text("SAFE = True\n", encoding="utf-8")
    (dependency_root / "unrelated.py").write_text("UNRELATED = True\n", encoding="utf-8")

    class SyntheticDistribution:
        version = "6"

        def locate_file(self, path: str) -> Path:
            assert path == "yaml"
            return dependency_package

    monkeypatch.setattr(
        wheel_contract.metadata,
        "distribution",
        lambda name: SyntheticDistribution() if name == "PyYAML" else None,
    )
    monkeypatch.setattr(
        wheel_contract,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["synthetic-python"],
            0,
            f"{site_packages}\n",
            "",
        ),
    )

    wheel_contract.copy_runtime_dependency_to_venv(
        Path("synthetic-python"),
        venv_dir,
        cwd=tmp_path,
    )

    assert (site_packages / "yaml" / "__init__.py").read_text(encoding="utf-8") == "SAFE = True\n"
    assert not (site_packages / "unrelated.py").exists()


@pytest.mark.parametrize("installed_version", ["5.999", "7"])
def test_wheel_contract_rejects_incompatible_runtime_dependency_version(
    installed_version: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    venv_dir = tmp_path / "venv"
    site_packages = venv_dir / "site-packages"
    site_packages.mkdir(parents=True)

    class SyntheticDistribution:
        version = installed_version

        def locate_file(self, _path: str) -> Path:
            pytest.fail("incompatible dependency was located before version rejection")

    monkeypatch.setattr(
        wheel_contract.metadata,
        "distribution",
        lambda name: SyntheticDistribution() if name == "PyYAML" else None,
    )
    monkeypatch.setattr(
        wheel_contract,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["synthetic-python"],
            0,
            f"{site_packages}\n",
            "",
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="^wheel contract runtime dependency could not be prepared$",
    ) as exc_info:
        wheel_contract.copy_runtime_dependency_to_venv(
            Path("synthetic-python"),
            venv_dir,
            cwd=tmp_path,
        )

    assert installed_version not in str(exc_info.value)
    assert not (site_packages / "yaml").exists()


def test_wheel_contract_isolated_module_smoke_ignores_pythonpath_shadow(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    venv_dir = tmp_path / "venv"
    wheel_contract.venv.EnvBuilder(with_pip=False).create(venv_dir)
    python = wheel_contract.venv_python_path(venv_dir)
    site_packages_result = subprocess.run(
        [
            str(python),
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ],
        capture_output=True,
        check=True,
        text=True,
    )
    site_packages = Path(site_packages_result.stdout.strip())

    installed_package = site_packages / "agent_guard"
    installed_package.mkdir()
    (installed_package / "__init__.py").write_text(
        "ORIGIN = 'wheel'\n",
        encoding="utf-8",
    )
    (installed_package / "cli.py").write_text("print('wheel-cli')\n", encoding="utf-8")
    installed_consumer = installed_package / "consumer"
    installed_consumer.mkdir()
    (installed_consumer / "__init__.py").write_text("", encoding="utf-8")
    (installed_consumer / "__main__.py").write_text(
        "print('wheel-consumer')\n",
        encoding="utf-8",
    )

    shadow_root = tmp_path / "shadow"
    shadow_package = shadow_root / "agent_guard"
    shadow_package.mkdir(parents=True)
    (shadow_package / "__init__.py").write_text(
        "ORIGIN = 'shadow'\n",
        encoding="utf-8",
    )
    for package_dir, module_name in (
        (shadow_package, "cli.py"),
        (shadow_package / "consumer", "__main__.py"),
    ):
        package_dir.mkdir(exist_ok=True)
        (package_dir / "__init__.py").write_text("", encoding="utf-8")
        (package_dir / module_name).write_text(
            "raise SystemExit('shadow package executed')\n",
            encoding="utf-8",
        )

    monkeypatch.setenv("PYTHONPATH", str(shadow_root))
    for module, expected_output in (
        ("agent_guard.cli", "wheel-cli\n"),
        ("agent_guard.consumer", "wheel-consumer\n"),
    ):
        result = subprocess.run(
            wheel_contract.isolated_module_command(python, module),
            cwd=tmp_path,
            capture_output=True,
            check=False,
            text=True,
        )

        assert result.returncode == 0
        assert result.stdout == expected_output

    inline_result = subprocess.run(
        wheel_contract.isolated_code_command(
            python,
            "import agent_guard; print(agent_guard.ORIGIN)",
        ),
        cwd=tmp_path,
        capture_output=True,
        check=False,
        text=True,
    )

    assert inline_result.returncode == 0
    assert inline_result.stdout == "wheel\n"


def test_wheel_contract_stops_git_producer_at_incremental_output_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    completed = tmp_path / "producer-completed"
    producer = (
        "import os, pathlib, sys, time\n"
        "for _ in range(100_000):\n"
        "    os.write(sys.stdout.fileno(), b'x' * 4096)\n"
        "    time.sleep(0.001)\n"
        "pathlib.Path(sys.argv[1]).write_text('completed', encoding='utf-8')\n"
    )
    original_popen = subprocess.Popen
    processes: list[subprocess.Popen[bytes]] = []

    def launch_producer(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        assert command[-2:] == ["ls-files", "-z"]
        process = original_popen(
            [sys.executable, "-c", producer, str(completed)],
            **kwargs,
        )
        processes.append(process)
        return process

    monkeypatch.setattr(wheel_contract, "MAX_TRACKED_PATH_OUTPUT_BYTES", 32)
    monkeypatch.setattr(wheel_contract, "GIT_INVENTORY_TIMEOUT_SECONDS", 10.0)
    monkeypatch.setattr(wheel_contract.subprocess, "Popen", launch_producer)

    try:
        started = time.monotonic()
        with pytest.raises(
            RuntimeError,
            match="^release source inventory could not be verified$",
        ):
            wheel_contract.tracked_release_files()
        elapsed = time.monotonic() - started

        assert elapsed < 5.0
        assert len(processes) == 1
        assert processes[0].poll() is not None
        assert not completed.exists()
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=1)


def test_wheel_contract_stops_git_producer_at_incremental_path_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    completed = tmp_path / "producer-completed"
    producer = (
        "import os, pathlib, sys\n"
        "for _ in range(100_000):\n"
        "    os.write(sys.stdout.fileno(), b'x\\0')\n"
        "pathlib.Path(sys.argv[1]).write_text('completed', encoding='utf-8')\n"
    )
    original_popen = subprocess.Popen
    processes: list[subprocess.Popen[bytes]] = []

    def launch_producer(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        assert command[-2:] == ["ls-files", "-z"]
        process = original_popen(
            [sys.executable, "-c", producer, str(completed)],
            **kwargs,
        )
        processes.append(process)
        return process

    monkeypatch.setattr(wheel_contract, "MAX_TRACKED_PATHS", 8)
    monkeypatch.setattr(wheel_contract, "GIT_INVENTORY_TIMEOUT_SECONDS", 10.0)
    monkeypatch.setattr(wheel_contract.subprocess, "Popen", launch_producer)

    try:
        with pytest.raises(
            RuntimeError,
            match="^release source inventory could not be verified$",
        ):
            wheel_contract.tracked_release_files()

        assert len(processes) == 1
        assert processes[0].poll() is not None
        assert not completed.exists()
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=1)


def test_wheel_contract_requires_exact_current_distribution_set(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    version = "1.2.3"
    dist = tmp_path / "dist"
    monkeypatch.setattr(wheel_contract, "DIST", dist)

    with pytest.raises(RuntimeError, match="directory is missing") as missing:
        wheel_contract.find_release_distributions(version)
    assert str(tmp_path) not in str(missing.value)

    dist.mkdir()
    wheel = dist / f"yui_agent_guard-{version}-py3-none-any.whl"
    sdist = dist / f"yui_agent_guard-{version}.tar.gz"
    wheel.write_bytes(b"wheel")

    with pytest.raises(RuntimeError, match="exactly the current") as incomplete:
        wheel_contract.find_release_distributions(version)
    assert str(tmp_path) not in str(incomplete.value)

    sdist.write_bytes(b"sdist")
    assert wheel_contract.find_release_distributions(version) == (wheel, sdist)

    (dist / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="exactly the current"):
        wheel_contract.find_release_distributions(version)


def test_wheel_contract_stops_distribution_enumeration_after_extra_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    version = "1.2.3"
    dist = tmp_path / "dist"
    dist.mkdir()
    monkeypatch.setattr(wheel_contract, "DIST", dist)
    expected_names = [
        f"yui_agent_guard-{version}-py3-none-any.whl",
        f"yui_agent_guard-{version}.tar.gz",
    ]
    consumed: list[str] = []

    class FakeEntry:
        def __init__(self, name: str) -> None:
            self.name = name

        def is_file(self, *, follow_symlinks: bool) -> bool:
            assert follow_symlinks is False
            return True

    class FakeScan:
        def __enter__(self) -> FakeScan:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self):
            for name in [*expected_names, "unexpected.txt", "must-not-be-read"]:
                consumed.append(name)
                if name == "must-not-be-read":
                    pytest.fail("distribution enumeration continued after the extra entry")
                yield FakeEntry(name)

    monkeypatch.setattr(wheel_contract.os, "scandir", lambda _path: FakeScan())

    with pytest.raises(RuntimeError, match="exactly the current"):
        wheel_contract.find_release_distributions(version)

    assert consumed == [*expected_names, "unexpected.txt"]


def test_wheel_contract_rejects_directories_and_symlinks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    version = "1.2.3"
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = dist / f"yui_agent_guard-{version}-py3-none-any.whl"
    sdist = dist / f"yui_agent_guard-{version}.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    monkeypatch.setattr(wheel_contract, "DIST", dist)

    extra_dir = dist / "extra"
    extra_dir.mkdir()
    with pytest.raises(RuntimeError, match="exactly the current"):
        wheel_contract.find_release_distributions(version)
    extra_dir.rmdir()

    sdist.unlink()
    sdist.mkdir()
    with pytest.raises(RuntimeError, match="exactly the current"):
        wheel_contract.find_release_distributions(version)
    sdist.rmdir()
    sdist.write_bytes(b"sdist")

    wheel.unlink()
    real_wheel = tmp_path / wheel.name
    real_wheel.write_bytes(b"wheel")
    wheel.symlink_to(real_wheel)
    with pytest.raises(RuntimeError, match="exactly the current"):
        wheel_contract.find_release_distributions(version)
    wheel.unlink()
    wheel.write_bytes(b"wheel")

    sdist.unlink()
    real_sdist = tmp_path / sdist.name
    real_sdist.write_bytes(b"sdist")
    sdist.symlink_to(real_sdist)
    with pytest.raises(RuntimeError, match="exactly the current"):
        wheel_contract.find_release_distributions(version)
    sdist.unlink()
    sdist.write_bytes(b"sdist")

    extra_symlink = dist / "extra-link"
    extra_symlink.symlink_to(real_wheel)
    with pytest.raises(RuntimeError, match="exactly the current"):
        wheel_contract.find_release_distributions(version)


def test_wheel_contract_requires_exact_safe_wheel_members(tmp_path: Path) -> None:
    wheel = tmp_path / "package.whl"
    expected = {"agent_guard/__init__.py"}
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("agent_guard/__init__.py", b"")

    wheel_contract.validate_wheel_members(wheel, expected)

    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("unexpected.txt", b"unexpected")
    with pytest.raises(RuntimeError, match="members do not match contract"):
        wheel_contract.validate_wheel_members(wheel, expected)

    symlink_wheel = tmp_path / "symlink.whl"
    symlink = zipfile.ZipInfo("agent_guard/__init__.py")
    symlink.create_system = 3
    symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(symlink_wheel, "w") as archive:
        archive.writestr(symlink, b"target")
    with pytest.raises(RuntimeError, match="members do not match contract"):
        wheel_contract.validate_wheel_members(symlink_wheel, expected)


def test_wheel_contract_accepts_equivalent_runtime_dependency_metadata(
    tmp_path: Path,
) -> None:
    version = "1.2.3"
    wheel = tmp_path / "package.whl"
    _write_wheel_metadata(wheel, version, ["pyyaml<7,>=6"])

    wheel_contract.validate_wheel_runtime_requirement(
        wheel,
        version,
        Requirement("PyYAML>=6,<7"),
    )


@pytest.mark.parametrize(
    "requirements",
    [
        [],
        ["PyYAML>=6,<8"],
        ["PyYAML>=6,<7", "PyYAML>=6,<7"],
        ["PyYAML>=6,<7", 'PyYAML<6.5; sys_platform == "win32"'],
    ],
)
def test_wheel_contract_rejects_missing_or_mismatched_runtime_dependency_metadata(
    requirements: list[str],
    tmp_path: Path,
) -> None:
    version = "1.2.3"
    wheel = tmp_path / "package.whl"
    _write_wheel_metadata(wheel, version, requirements)

    with pytest.raises(
        RuntimeError,
        match="^wheel runtime dependency metadata does not match contract$",
    ):
        wheel_contract.validate_wheel_runtime_requirement(
            wheel,
            version,
            Requirement("PyYAML>=6,<7"),
        )


def test_wheel_contract_rejects_malformed_runtime_dependency_metadata(
    tmp_path: Path,
) -> None:
    version = "1.2.3"
    wheel = tmp_path / "package.whl"
    private_detail = "synthetic malformed metadata detail"
    _write_raw_wheel_metadata(
        wheel,
        version,
        (
            "Metadata-Version: 2.4\n"
            "Name: yui-agent-guard\n"
            f"Version: {version}\n"
            "Requires-Dist: PyYAML>=6,<7\n"
            f"{private_detail}\n\n"
        ).encode("utf-8"),
    )

    with pytest.raises(
        RuntimeError,
        match="^wheel runtime dependency metadata does not match contract$",
    ) as exc_info:
        wheel_contract.validate_wheel_runtime_requirement(
            wheel,
            version,
            Requirement("PyYAML>=6,<7"),
        )

    assert private_detail not in str(exc_info.value)


def test_wheel_contract_rejects_encrypted_runtime_dependency_metadata(
    tmp_path: Path,
) -> None:
    version = "1.2.3"
    wheel = tmp_path / "package.whl"
    _write_wheel_metadata(wheel, version, ["PyYAML>=6,<7"])
    content = bytearray(wheel.read_bytes())
    local_header = content.index(b"PK\x03\x04")
    central_header = content.index(b"PK\x01\x02")
    for flags_offset in (local_header + 6, central_header + 8):
        flags = struct.unpack_from("<H", content, flags_offset)[0]
        struct.pack_into("<H", content, flags_offset, flags | 0x1)
    wheel.write_bytes(content)

    metadata_name = f"yui_agent_guard-{version}.dist-info/METADATA"
    wheel_contract.validate_wheel_members(wheel, {metadata_name})
    with pytest.raises(
        RuntimeError,
        match="^wheel runtime dependency metadata does not match contract$",
    ):
        wheel_contract.validate_wheel_runtime_requirement(
            wheel,
            version,
            Requirement("PyYAML>=6,<7"),
        )


def test_wheel_contract_sanitizes_runtime_dependency_decompression_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    version = "1.2.3"
    wheel = tmp_path / "package.whl"
    private_detail = "synthetic private decompression detail"
    _write_wheel_metadata(wheel, version, ["PyYAML>=6,<7"])

    def failed_read(
        _archive: zipfile.ZipFile,
        _member: zipfile.ZipInfo,
    ) -> bytes:
        raise zlib.error(private_detail)

    monkeypatch.setattr(wheel_contract.zipfile.ZipFile, "read", failed_read)

    with pytest.raises(
        RuntimeError,
        match="^wheel runtime dependency metadata does not match contract$",
    ) as exc_info:
        wheel_contract.validate_wheel_runtime_requirement(
            wheel,
            version,
            Requirement("PyYAML>=6,<7"),
        )

    assert private_detail not in str(exc_info.value)


def test_wheel_contract_rejects_unsupported_runtime_metadata_compression(
    tmp_path: Path,
) -> None:
    version = "1.2.3"
    wheel = tmp_path / "package.whl"
    metadata_lines = [
        "Metadata-Version: 2.4",
        "Name: yui-agent-guard",
        f"Version: {version}",
        "Requires-Dist: PyYAML>=6,<7",
        "",
        "",
    ]
    _write_raw_wheel_metadata(
        wheel,
        version,
        "\n".join(metadata_lines).encode("utf-8"),
        compression=zipfile.ZIP_LZMA,
    )

    with pytest.raises(
        RuntimeError,
        match="^wheel runtime dependency metadata does not match contract$",
    ):
        wheel_contract.validate_wheel_runtime_requirement(
            wheel,
            version,
            Requirement("PyYAML>=6,<7"),
        )


def test_wheel_contract_rejects_member_limit_before_zipfile_construction(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "too-many-members.whl"
    declared_count = wheel_contract.MAX_ARCHIVE_MEMBERS + 1
    wheel.write_bytes(
        struct.pack(
            "<4s4H2IH",
            b"PK\x05\x06",
            0,
            0,
            declared_count,
            declared_count,
            0,
            0,
            0,
        )
    )
    constructed = False

    def unexpected_zipfile(*_args: object, **_kwargs: object) -> None:
        nonlocal constructed
        constructed = True
        pytest.fail("ZipFile was constructed before the member-count preflight")

    monkeypatch.setattr(wheel_contract.zipfile, "ZipFile", unexpected_zipfile)

    with pytest.raises(
        RuntimeError,
        match="^release archive exceeds safety limits$",
    ):
        wheel_contract.validate_wheel_members(wheel, set())

    assert wheel.stat().st_size == 22
    assert not constructed


def test_wheel_contract_rejects_central_directory_byte_limit_before_zipfile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "large-central-directory.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("agent_guard/__init__.py", b"")

    def unexpected_zipfile(*_args: object, **_kwargs: object) -> None:
        pytest.fail("ZipFile was constructed before the central-size preflight")

    monkeypatch.setattr(
        wheel_contract,
        "MAX_ARCHIVE_CENTRAL_DIRECTORY_BYTES",
        1,
    )
    monkeypatch.setattr(wheel_contract.zipfile, "ZipFile", unexpected_zipfile)
    with pytest.raises(
        RuntimeError,
        match="^release archive exceeds safety limits$",
    ):
        wheel_contract.validate_wheel_members(
            wheel,
            {"agent_guard/__init__.py"},
        )


def test_wheel_contract_rejects_malformed_central_range_before_zipfile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "malformed-central-range.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("agent_guard/__init__.py", b"")
    content = bytearray(wheel.read_bytes())
    eocd_offset = content.rfind(b"PK\x05\x06")
    central_size = struct.unpack_from("<I", content, eocd_offset + 12)[0]
    struct.pack_into("<I", content, eocd_offset + 12, central_size + 1)
    wheel.write_bytes(content)

    def unexpected_zipfile(*_args: object, **_kwargs: object) -> None:
        pytest.fail("ZipFile was constructed before central-range preflight")

    monkeypatch.setattr(wheel_contract.zipfile, "ZipFile", unexpected_zipfile)

    with pytest.raises(
        RuntimeError,
        match="^release archive could not be verified$",
    ):
        wheel_contract.validate_wheel_members(
            wheel,
            {"agent_guard/__init__.py"},
        )


def test_wheel_contract_rejects_false_eocd_in_comment_before_zipfile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "false-comment-eocd.whl"
    false_eocd = struct.pack(
        "<4s4H2IH",
        b"PK\x05\x06",
        0,
        0,
        wheel_contract.MAX_ARCHIVE_MEMBERS + 1,
        wheel_contract.MAX_ARCHIVE_MEMBERS + 1,
        0,
        0,
        0,
    )
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("agent_guard/__init__.py", b"")
        archive.comment = false_eocd + b"trailing"

    def unexpected_zipfile(*_args: object, **_kwargs: object) -> None:
        pytest.fail("ZipFile was constructed after a false EOCD signature")

    monkeypatch.setattr(wheel_contract.zipfile, "ZipFile", unexpected_zipfile)
    with pytest.raises(
        RuntimeError,
        match="^release archive could not be verified$",
    ):
        wheel_contract.validate_wheel_members(
            wheel,
            {"agent_guard/__init__.py"},
        )


def test_wheel_contract_preflights_zip64_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "zip64.whl"
    expected = {"agent_guard/__init__.py"}
    with monkeypatch.context() as zip64_patch:
        zip64_patch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 0)
        with zipfile.ZipFile(wheel, "w", allowZip64=True) as archive:
            archive.writestr("agent_guard/__init__.py", b"")

    content = bytearray(wheel.read_bytes())
    locator_offset = content.rfind(b"PK\x06\x07")
    assert locator_offset >= 0
    assert content.rfind(b"PK\x06\x06", 0, locator_offset) >= 0
    wheel_contract.validate_wheel_members(wheel, expected)

    malformed = tmp_path / "zip64-multidisk.whl"
    struct.pack_into("<I", content, locator_offset + 16, 2)
    malformed.write_bytes(content)

    def unexpected_zipfile(*_args: object, **_kwargs: object) -> None:
        pytest.fail("ZipFile was constructed before ZIP64 preflight")

    monkeypatch.setattr(wheel_contract.zipfile, "ZipFile", unexpected_zipfile)
    with pytest.raises(
        RuntimeError,
        match="^release archive could not be verified$",
    ):
        wheel_contract.validate_wheel_members(malformed, expected)


def test_wheel_contract_requires_exact_regular_sdist_members(tmp_path: Path) -> None:
    sdist = tmp_path / "package.tar.gz"
    expected = {"package/file.txt"}
    with tarfile.open(sdist, "w:gz") as archive:
        member = tarfile.TarInfo("package/file.txt")
        member.size = 4
        archive.addfile(member, io.BytesIO(b"data"))

    wheel_contract.validate_sdist_members(sdist, expected)

    with tarfile.open(sdist, "w:gz") as archive:
        member = tarfile.TarInfo("package/link")
        member.type = tarfile.SYMTYPE
        member.linkname = "file.txt"
        archive.addfile(member)
    with pytest.raises(RuntimeError, match="members do not match contract"):
        wheel_contract.validate_sdist_members(sdist, {"package/link"})


def test_wheel_contract_accepts_bounded_pax_sdist(tmp_path: Path) -> None:
    sdist = tmp_path / "package-pax.tar.gz"
    long_name = f"package/{'x' * 128}.txt"
    expected = {long_name}
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo(long_name)
        member.size = 4
        member.pax_headers = {"comment": "bounded metadata"}
        archive.addfile(member, io.BytesIO(b"data"))

    wheel_contract.validate_sdist_members(sdist, expected)


def test_wheel_contract_rejects_oversized_pax_before_tarfile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sdist = tmp_path / "oversized-pax.tar.gz"
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("package/file.txt")
        member.size = 4
        member.pax_headers = {"comment": "x" * 512}
        archive.addfile(member, io.BytesIO(b"data"))

    def unexpected_tarfile(*_args: object, **_kwargs: object) -> None:
        pytest.fail("tarfile.open was called before PAX metadata preflight")

    monkeypatch.setattr(wheel_contract, "MAX_TAR_EXTENSION_MEMBER_BYTES", 64)
    monkeypatch.setattr(wheel_contract.tarfile, "open", unexpected_tarfile)
    with pytest.raises(
        RuntimeError,
        match="^release archive exceeds safety limits$",
    ):
        wheel_contract.validate_sdist_members(sdist, {"package/file.txt"})


def test_wheel_contract_rejects_oversized_gnu_longname_before_tarfile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sdist = tmp_path / "oversized-gnu-longname.tar.gz"
    long_name = f"package/{'x' * 256}.txt"
    with tarfile.open(sdist, "w:gz", format=tarfile.GNU_FORMAT) as archive:
        member = tarfile.TarInfo(long_name)
        member.size = 4
        archive.addfile(member, io.BytesIO(b"data"))

    def unexpected_tarfile(*_args: object, **_kwargs: object) -> None:
        pytest.fail("tarfile.open was called before GNU metadata preflight")

    monkeypatch.setattr(wheel_contract, "MAX_TAR_EXTENSION_MEMBER_BYTES", 64)
    monkeypatch.setattr(wheel_contract.tarfile, "open", unexpected_tarfile)
    with pytest.raises(
        RuntimeError,
        match="^release archive exceeds safety limits$",
    ):
        wheel_contract.validate_sdist_members(sdist, {long_name})


def test_wheel_contract_rejects_sparse_pax_before_tarfile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sdist = tmp_path / "sparse-pax.tar.gz"
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("package/file.txt")
        member.size = 4
        member.pax_headers = {"GNU.sparse.map": "0,4"}
        archive.addfile(member, io.BytesIO(b"data"))

    def unexpected_tarfile(*_args: object, **_kwargs: object) -> None:
        pytest.fail("tarfile.open was called before sparse metadata preflight")

    monkeypatch.setattr(wheel_contract.tarfile, "open", unexpected_tarfile)
    with pytest.raises(
        RuntimeError,
        match="^release archive could not be verified$",
    ):
        wheel_contract.validate_sdist_members(sdist, {"package/file.txt"})


def test_wheel_contract_rejects_pax_size_override_before_tarfile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sdist = tmp_path / "size-override-pax.tar.gz"
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("package/file.txt")
        member.size = 4
        member.pax_headers = {"size": "8"}
        archive.addfile(member, io.BytesIO(b"data"))

    def unexpected_tarfile(*_args: object, **_kwargs: object) -> None:
        pytest.fail("tarfile.open was called before PAX size preflight")

    monkeypatch.setattr(wheel_contract.tarfile, "open", unexpected_tarfile)
    with pytest.raises(
        RuntimeError,
        match="^release archive could not be verified$",
    ):
        wheel_contract.validate_sdist_members(sdist, {"package/file.txt"})


def test_wheel_contract_bounds_decompressed_sdist_before_tarfile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sdist = tmp_path / "expanded.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        member = tarfile.TarInfo("package/file.txt")
        member.size = 4096
        archive.addfile(member, io.BytesIO(b"x" * member.size))

    def unexpected_tarfile(*_args: object, **_kwargs: object) -> None:
        pytest.fail("tarfile.open was called before decompressed-size preflight")

    monkeypatch.setattr(wheel_contract, "MAX_ARCHIVE_DECOMPRESSED_BYTES", 1024)
    monkeypatch.setattr(wheel_contract.tarfile, "open", unexpected_tarfile)
    with pytest.raises(
        RuntimeError,
        match="^release archive exceeds safety limits$",
    ):
        wheel_contract.validate_sdist_members(sdist, {"package/file.txt"})


def test_wheel_contract_rejects_concatenated_gzip_before_tarfile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sdist = tmp_path / "concatenated.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        member = tarfile.TarInfo("package/file.txt")
        member.size = 4
        archive.addfile(member, io.BytesIO(b"data"))
    with sdist.open("ab") as archive_file:
        archive_file.write(gzip.compress(b""))

    def unexpected_tarfile(*_args: object, **_kwargs: object) -> None:
        pytest.fail("tarfile.open was called before gzip framing preflight")

    monkeypatch.setattr(wheel_contract.tarfile, "open", unexpected_tarfile)
    with pytest.raises(
        RuntimeError,
        match="^release archive could not be verified$",
    ):
        wheel_contract.validate_sdist_members(sdist, {"package/file.txt"})


def test_wheel_contract_bounds_gzip_zero_padding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sdist = tmp_path / "zero-padded.tar.gz"
    expected = {"package/file.txt"}
    with tarfile.open(sdist, "w:gz") as archive:
        member = tarfile.TarInfo("package/file.txt")
        member.size = 4
        archive.addfile(member, io.BytesIO(b"data"))
    with sdist.open("ab") as archive_file:
        archive_file.write(b"\0" * wheel_contract.MAX_GZIP_TRAILING_ZERO_BYTES)

    wheel_contract.validate_sdist_members(sdist, expected)

    with sdist.open("ab") as archive_file:
        archive_file.write(b"\0")

    def unexpected_tarfile(*_args: object, **_kwargs: object) -> None:
        pytest.fail("tarfile.open was called before gzip padding preflight")

    monkeypatch.setattr(wheel_contract.tarfile, "open", unexpected_tarfile)
    with pytest.raises(
        RuntimeError,
        match="^release archive exceeds safety limits$",
    ):
        wheel_contract.validate_sdist_members(sdist, expected)


def test_wheel_contract_rejects_extension_chain_before_tarfile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sdist = tmp_path / "extension-chain.tar.gz"
    pax_record = b"13 comment=x\n"
    with tarfile.open(sdist, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for _ in range(5):
            extension = tarfile.TarInfo("PaxHeader")
            extension.type = tarfile.XHDTYPE
            extension.size = len(pax_record)
            archive.addfile(extension, io.BytesIO(pax_record))
        member = tarfile.TarInfo("package/file.txt")
        member.size = 4
        archive.addfile(member, io.BytesIO(b"data"))

    def unexpected_tarfile(*_args: object, **_kwargs: object) -> None:
        pytest.fail("tarfile.open was called before extension-chain preflight")

    monkeypatch.setattr(
        wheel_contract,
        "MAX_TAR_CONSECUTIVE_EXTENSION_HEADERS",
        4,
    )
    monkeypatch.setattr(wheel_contract.tarfile, "open", unexpected_tarfile)
    with pytest.raises(
        RuntimeError,
        match="^release archive exceeds safety limits$",
    ):
        wheel_contract.validate_sdist_members(sdist, {"package/file.txt"})


def test_wheel_contract_snapshots_sdist_before_preflight(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sdist = tmp_path / "same-descriptor.tar.gz"
    expected = {"package/file.txt"}
    with tarfile.open(sdist, "w:gz") as archive:
        member = tarfile.TarInfo("package/file.txt")
        member.size = 4
        archive.addfile(member, io.BytesIO(b"data"))
    replacement = tmp_path / "replacement.tar.gz"
    with tarfile.open(replacement, "w:gz") as archive:
        member = tarfile.TarInfo("package/replaced.txt")
        member.size = 8
        archive.addfile(member, io.BytesIO(b"replaced"))
    replacement_bytes = replacement.read_bytes()

    preflight_handles: list[object] = []
    parser_handles: list[object] = []
    original_preflight = wheel_contract._preflight_sdist_archive
    original_tarfile_open = tarfile.open

    def preflight_spy(archive_file: BinaryIO) -> None:
        preflight_handles.append(archive_file)
        original_preflight(archive_file)
        sdist.write_bytes(replacement_bytes)

    def tarfile_open_spy(*args: object, **kwargs: object):
        assert not args
        parser_handles.append(kwargs["fileobj"])
        return original_tarfile_open(*args, **kwargs)

    monkeypatch.setattr(wheel_contract, "_preflight_sdist_archive", preflight_spy)
    monkeypatch.setattr(wheel_contract.tarfile, "open", tarfile_open_spy)

    wheel_contract.validate_sdist_members(sdist, expected)

    assert len(preflight_handles) == len(parser_handles) == 1
    assert preflight_handles[0] is parser_handles[0]


def test_wheel_contract_expected_members_follow_tracked_release_files() -> None:
    version = "1.2.3"
    tracked = {
        "src/agent_guard/__init__.py",
        "LICENSE",
        "README.md",
        "execution-notes.md",
        "dist/old.whl",
    }

    assert wheel_contract.expected_wheel_members(version, tracked) == {
        "agent_guard/__init__.py",
        "yui_agent_guard-1.2.3.dist-info/METADATA",
        "yui_agent_guard-1.2.3.dist-info/WHEEL",
        "yui_agent_guard-1.2.3.dist-info/entry_points.txt",
        "yui_agent_guard-1.2.3.dist-info/licenses/LICENSE",
        "yui_agent_guard-1.2.3.dist-info/RECORD",
    }
    assert wheel_contract.expected_sdist_members(version, tracked) == {
        "yui_agent_guard-1.2.3/src/agent_guard/__init__.py",
        "yui_agent_guard-1.2.3/LICENSE",
        "yui_agent_guard-1.2.3/README.md",
        "yui_agent_guard-1.2.3/PKG-INFO",
    }


def test_dev_extra_includes_benchmark_schema_tools() -> None:
    with PYPROJECT.open("rb") as fh:
        pyproject = tomllib.load(fh)

    dev_deps = pyproject["project"]["optional-dependencies"]["dev"]

    assert any(dep.startswith("pytest-cov") for dep in dev_deps)
    assert any(dep.startswith("jsonschema") for dep in dev_deps)


def test_execution_notes_are_not_tracked_or_packaged() -> None:
    with PYPROJECT.open("rb") as fh:
        pyproject = tomllib.load(fh)

    assert not (REPO_ROOT / "execution-notes.md").exists()
    assert "execution-notes.md" in (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "/execution-notes.md" in pyproject["tool"]["hatch"]["build"]["exclude"]


def test_public_sample_report_matches_pyproject_version() -> None:
    payload = json.loads(EVIDENCE_SAMPLE_REPORT.read_text(encoding="utf-8"))

    assert payload["tool"]["name"] == "agent-guard"
    assert payload["tool"]["version"] == pyproject_version()


def test_schema_resources_are_present_in_package_tree() -> None:
    expected = {
        "agent-guard.result.v1.schema.json",
        "agent-guard.context_inventory.v1.schema.json",
        "agent-guard.context_lock_coverage.v1.schema.json",
        "agent-guard.report_evidence.v1.schema.json",
        "agent-guard.report_evidence.v2.schema.json",
        "agent-guard.conformance.v1.schema.json",
        "agent-guard.evidence_pack_manifest.v1.schema.json",
        "agent-guard.evidence_pack_manifest.v2.schema.json",
        "agent-guard.surface_delta.v1.schema.json",
    }

    assert SCHEMA_DIR.is_dir()
    assert {path.name for path in SCHEMA_DIR.glob("*.schema.json")} == expected


def test_py_typed_marker_is_present() -> None:
    marker = PACKAGE_DIR / "py.typed"
    assert marker.is_file()
    assert marker.stat().st_size == 0
