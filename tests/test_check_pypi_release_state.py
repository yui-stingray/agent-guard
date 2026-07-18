"""Where: tests/test_check_pypi_release_state.py
What: unit tests for the PyPI release-state preflight.
Why: keep immutable-version checks predictable without live network calls.
"""

from __future__ import annotations

import importlib.util
import json
import urllib.error
from pathlib import Path
from typing import Any

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_pypi_release_state.py"
SPEC = importlib.util.spec_from_file_location("check_pypi_release_state", SCRIPT)
assert SPEC is not None
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
check_release_state = MODULE.check_release_state
check_published_state = MODULE.check_published_state
fetch_pypi_project = MODULE.fetch_pypi_project
fetch_pypi_release = MODULE.fetch_pypi_release
main = MODULE.main


def expected_release_files(version: str) -> list[dict[str, Any]]:
    return [
        {
            "filename": f"yui_agent_guard-{version}-py3-none-any.whl",
            "packagetype": "bdist_wheel",
            "yanked": False,
        },
        {
            "filename": f"yui_agent_guard-{version}.tar.gz",
            "packagetype": "sdist",
            "yanked": False,
        },
    ]


def test_missing_project_is_allowed_with_pending_publisher_note() -> None:
    ok, message = check_release_state("yui-agent-guard", "0.1.0", None)

    assert ok is True
    assert "does not exist yet" in message
    assert "Trusted Publisher" in message


def test_existing_version_blocks_release() -> None:
    ok, message = check_release_state(
        "yui-agent-guard",
        "0.1.0",
        {"info": {"version": "0.1.0"}, "releases": {"0.1.0": [{}]}},
    )

    assert ok is False
    assert "already exists" in message


def test_new_version_for_existing_project_is_allowed() -> None:
    ok, message = check_release_state(
        "yui-agent-guard",
        "0.1.1",
        {"info": {"version": "0.1.0"}, "releases": {"0.1.0": [{}]}},
    )

    assert ok is True
    assert "candidate version is unused" in message
    assert "yui-agent-guard==0.1.1" in message


def test_malformed_project_metadata_blocks_release_without_echoing_values() -> None:
    cases: list[Any] = [
        [],
        {},
        {"releases": []},
        {"releases": "response-content"},
    ]

    for pypi_data in cases:
        ok, message = check_release_state("yui-agent-guard", "0.1.1", pypi_data)

        assert ok is False
        assert "malformed" in message
        assert "response-content" not in message


def test_published_state_requires_nonempty_release_files() -> None:
    missing_ok, missing_message = check_published_state("yui-agent-guard", "0.1.1", None)
    wrong_shape_ok, wrong_shape_message = check_published_state("yui-agent-guard", "0.1.1", [])
    malformed_ok, malformed_message = check_published_state("yui-agent-guard", "0.1.1", {"releases": {}})
    empty_ok, empty_message = check_published_state("yui-agent-guard", "0.1.1", {"urls": []})

    assert missing_ok is False
    assert wrong_shape_ok is False
    assert malformed_ok is False
    assert empty_ok is False
    assert "not published" in missing_message
    assert "malformed" in wrong_shape_message
    assert "malformed" in malformed_message
    assert "not published" in empty_message


def test_published_state_accepts_exact_expected_release_files() -> None:
    ok, message = check_published_state("yui-agent-guard", "0.1.1", {"urls": expected_release_files("0.1.1")})

    assert ok is True
    assert "is published" in message


def test_published_state_rejects_missing_wrong_extra_duplicate_and_yanked_files() -> None:
    version = "0.1.1"
    files = expected_release_files(version)

    cases = [
        {"urls": [files[0]]},
        {
            "urls": [
                files[0],
                {"filename": f"yui_agent_guard-{version}.tar.gz", "packagetype": "bdist_wheel", "yanked": False},
            ],
        },
        {
            "urls": [
                *files,
                {"filename": f"yui_agent_guard-{version}-extra.whl", "packagetype": "bdist_wheel", "yanked": False},
            ],
        },
        {"urls": [files[0], files[0], files[1]]},
        {"urls": [files[0], {**files[1], "yanked": True}]},
    ]

    for pypi_data in cases:
        ok, _message = check_published_state("yui-agent-guard", version, pypi_data)

        assert ok is False


def test_published_state_rejects_malformed_file_entries_without_echoing_values() -> None:
    cases = [
        {"urls": ["not-a-dict"]},
        {"urls": [{"packagetype": "sdist", "yanked": False}]},
        {"urls": [{"filename": "", "packagetype": "sdist", "yanked": False}]},
        {"urls": [{"filename": "leaked-file.tar.gz", "yanked": False}]},
        {"urls": [{"filename": "leaked-file.tar.gz", "packagetype": "", "yanked": False}]},
        {"urls": [{"filename": "leaked-file.tar.gz", "packagetype": "sdist", "yanked": "false"}]},
    ]

    for pypi_data in cases:
        ok, message = check_published_state("yui-agent-guard", "0.1.1", pypi_data)

        assert ok is False
        assert "malformed" in message
        assert "leaked-file" not in message
        assert "tar.gz" not in message


def test_fetch_pypi_project_and_release_encode_path_segments(monkeypatch) -> None:
    requested_urls: list[str] = []

    class Response:
        def __enter__(self) -> Any:
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps({"ok": True}).encode()

    def fake_urlopen(url: str, timeout: int) -> Response:
        requested_urls.append(url)
        assert timeout == 20
        return Response()

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", fake_urlopen)

    assert fetch_pypi_project("name with/slash") == {"ok": True}
    assert fetch_pypi_release("name with/slash", "1.0.0+local/build") == {"ok": True}
    assert requested_urls == [
        "https://pypi.org/pypi/name%20with%2Fslash/json",
        "https://pypi.org/pypi/name%20with%2Fslash/1.0.0%2Blocal%2Fbuild/json",
    ]


def test_fetch_pypi_release_returns_none_on_404(monkeypatch) -> None:
    def fake_urlopen(url: str, timeout: int) -> None:
        raise urllib.error.HTTPError(url, 404, "missing", hdrs=None, fp=None)

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", fake_urlopen)

    assert fetch_pypi_release("yui-agent-guard", "0.1.1") is None


def test_fetch_pypi_json_rejects_non_object_payload(monkeypatch) -> None:
    class Response:
        def __enter__(self) -> Any:
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def read(self) -> bytes:
            return b"null"

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", lambda _url, timeout: Response())

    with pytest.raises(ValueError, match="JSON object"):
        fetch_pypi_project("yui-agent-guard")


def test_main_uses_project_endpoint_only_before_upload(monkeypatch, tmp_path, capsys) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "yui-agent-guard"\nversion = "0.1.1"\n')
    calls: list[str] = []

    def fake_project(project_name: str) -> dict[str, Any]:
        calls.append(f"project:{project_name}")
        return {"info": {"version": "0.1.0"}, "releases": {"0.1.0": [{}]}}

    def fake_release(project_name: str, version: str) -> dict[str, Any]:
        calls.append(f"release:{project_name}:{version}")
        return {"urls": expected_release_files(version)}

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(MODULE, "fetch_pypi_project", fake_project)
    monkeypatch.setattr(MODULE, "fetch_pypi_release", fake_release)

    assert main(["check_pypi_release_state.py"]) == 0
    captured = capsys.readouterr()
    assert calls == ["project:yui-agent-guard"]
    assert "candidate version is unused" in captured.out
    assert captured.err == ""


def test_main_uses_exact_release_endpoint_only_when_expect_present(monkeypatch, tmp_path, capsys) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "yui-agent-guard"\nversion = "0.1.1"\n')
    calls: list[str] = []

    def fake_project(project_name: str) -> dict[str, Any]:
        calls.append(f"project:{project_name}")
        return {"info": {"version": "0.1.1"}, "releases": {"0.1.1": [{}]}}

    def fake_release(project_name: str, version: str) -> dict[str, Any]:
        calls.append(f"release:{project_name}:{version}")
        return {"urls": expected_release_files(version)}

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(MODULE, "fetch_pypi_project", fake_project)
    monkeypatch.setattr(MODULE, "fetch_pypi_release", fake_release)

    assert main(["check_pypi_release_state.py", "--expect-present"]) == 0
    captured = capsys.readouterr()
    assert calls == ["release:yui-agent-guard:0.1.1"]
    assert "is published" in captured.out
    assert captured.err == ""


def test_main_failure_output_does_not_echo_response_details(monkeypatch, tmp_path, capsys) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "yui-agent-guard"\nversion = "0.1.1"\n')
    leaked_filename = "https://files.pythonhosted.org/packages/private/yui_agent_guard-0.1.1.tar.gz"

    def fake_release(project_name: str, version: str) -> dict[str, Any]:
        return {
            "urls": [
                {
                    "filename": leaked_filename,
                    "packagetype": "sdist",
                    "yanked": False,
                    "url": leaked_filename,
                    "digests": {"sha256": "response-content"},
                }
            ]
        }

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(MODULE, "fetch_pypi_release", fake_release)

    assert main(["check_pypi_release_state.py", "--expect-present"]) == 1
    captured = capsys.readouterr()
    public_output = captured.out + captured.err
    assert "https://" not in public_output
    assert "files.pythonhosted.org" not in public_output
    assert "yui_agent_guard-0.1.1.tar.gz" not in public_output
    assert "response-content" not in public_output
    assert str(tmp_path) not in public_output


def test_main_fetch_failure_output_does_not_echo_url_or_local_path(monkeypatch, tmp_path, capsys) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "yui-agent-guard"\nversion = "0.1.1"\n')
    leaked_url = "https://pypi.org/pypi/yui-agent-guard/0.1.1/json?token=secret"

    def fake_release(project_name: str, version: str) -> None:
        raise urllib.error.HTTPError(leaked_url, 500, "server error includes secret", hdrs=None, fp=None)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(MODULE, "fetch_pypi_release", fake_release)

    assert main(["check_pypi_release_state.py", "--expect-present"]) == 1
    captured = capsys.readouterr()
    public_output = captured.out + captured.err
    assert "Could not fetch PyPI release metadata" in public_output
    assert "https://" not in public_output
    assert "secret" not in public_output
    assert str(tmp_path) not in public_output
