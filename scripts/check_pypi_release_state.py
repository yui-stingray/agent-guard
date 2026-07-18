"""Where: scripts/check_pypi_release_state.py
What: verify that the package version is not already present on PyPI.
Why: fail release tags before upload when a version is immutable or already used.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def load_project_metadata(pyproject_path: Path) -> tuple[str, str]:
    """Return the declared package name and version from pyproject.toml."""
    with pyproject_path.open("rb") as handle:
        project = tomllib.load(handle)["project"]
    return str(project["name"]), str(project["version"])


def fetch_pypi_project(project_name: str) -> dict[str, Any] | None:
    """Return PyPI JSON metadata, or None when the project does not exist yet."""
    project_segment = urllib.parse.quote(project_name, safe="")
    url = f"https://pypi.org/pypi/{project_segment}/json"
    return fetch_pypi_json(url)


def fetch_pypi_release(project_name: str, version: str) -> dict[str, Any] | None:
    """Return PyPI JSON metadata for one version, or None when it is absent."""
    project_segment = urllib.parse.quote(project_name, safe="")
    version_segment = urllib.parse.quote(version, safe="")
    url = f"https://pypi.org/pypi/{project_segment}/{version_segment}/json"
    return fetch_pypi_json(url)


def fetch_pypi_json(url: str) -> dict[str, Any] | None:
    """Return PyPI JSON metadata, or None for a 404."""
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            payload = json.load(response)
            if not isinstance(payload, dict):
                raise ValueError("PyPI metadata must be a JSON object")
            return payload
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def check_release_state(project_name: str, version: str, pypi_data: object | None) -> tuple[bool, str]:
    """Return whether a release may proceed and a human-readable reason."""
    if pypi_data is None:
        return (
            True,
            f"PyPI project {project_name!r} does not exist yet; pending Trusted Publisher setup must exist.",
        )
    if not isinstance(pypi_data, dict):
        return False, "PyPI project metadata is malformed"

    releases = pypi_data.get("releases")
    if not isinstance(releases, dict):
        return False, "PyPI project metadata is malformed"
    if version in releases:
        return False, f"PyPI version already exists: {project_name}=={version}"

    return True, f"PyPI project exists; candidate version is unused: {project_name}=={version}"


def check_published_state(project_name: str, version: str, pypi_data: object | None) -> tuple[bool, str]:
    """Return whether PyPI exposes exactly the expected files for the version."""
    if pypi_data is None:
        return False, f"PyPI version is not published: {project_name}=={version}"
    if not isinstance(pypi_data, dict):
        return False, "PyPI release file metadata is malformed"
    files = pypi_data.get("urls")
    if not isinstance(files, list):
        return False, "PyPI release file metadata is malformed"
    if not files:
        return False, f"PyPI version is not published: {project_name}=={version}"

    expected_files = {
        f"yui_agent_guard-{version}-py3-none-any.whl": "bdist_wheel",
        f"yui_agent_guard-{version}.tar.gz": "sdist",
    }
    seen_files: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            return False, "PyPI release file metadata is malformed"
        filename = entry.get("filename")
        packagetype = entry.get("packagetype")
        yanked = entry.get("yanked")
        if not isinstance(filename, str) or not filename:
            return False, "PyPI release file metadata is malformed"
        if not isinstance(packagetype, str) or not packagetype:
            return False, "PyPI release file metadata is malformed"
        if not isinstance(yanked, bool):
            return False, "PyPI release file metadata is malformed"
        if filename not in expected_files or expected_files[filename] != packagetype or yanked:
            return False, f"PyPI version has unexpected release files: {project_name}=={version}"
        if filename in seen_files:
            return False, f"PyPI version has duplicate release files: {project_name}=={version}"
        seen_files.add(filename)

    if seen_files != set(expected_files):
        return False, f"PyPI version is missing expected release files: {project_name}=={version}"
    return True, f"PyPI version is published: {project_name}=={version}"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="check whether the project version is absent from or present on PyPI")
    parser.add_argument("--expect-present", action="store_true")
    parser.add_argument("--version")
    args = parser.parse_args(argv[1:])

    project_name, declared_version = load_project_metadata(Path("pyproject.toml"))
    version = args.version or declared_version
    mode = "release" if args.expect_present else "project"
    try:
        if args.expect_present:
            pypi_data = fetch_pypi_release(project_name, version)
        else:
            pypi_data = fetch_pypi_project(project_name)
    except (ValueError, OSError, urllib.error.URLError):
        print(f"Could not fetch PyPI {mode} metadata", file=sys.stderr)
        return 1

    if args.expect_present:
        ok, message = check_published_state(project_name, version, pypi_data)
    else:
        ok, message = check_release_state(project_name, version, pypi_data)
    stream = sys.stdout if ok else sys.stderr
    print(message, file=stream)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
