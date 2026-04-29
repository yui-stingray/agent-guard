"""Where: scripts/check_pypi_release_state.py
What: verify that the package version is not already present on PyPI.
Why: fail release tags before upload when a version is immutable or already used.
"""

from __future__ import annotations

import json
import sys
import tomllib
import urllib.error
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
    url = f"https://pypi.org/pypi/{project_name}/json"
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def check_release_state(project_name: str, version: str, pypi_data: dict[str, Any] | None) -> tuple[bool, str]:
    """Return whether a release may proceed and a human-readable reason."""
    if pypi_data is None:
        return (
            True,
            f"PyPI project {project_name!r} does not exist yet; pending Trusted Publisher setup must exist.",
        )

    releases = pypi_data.get("releases", {})
    if isinstance(releases, dict) and version in releases:
        return False, f"PyPI version already exists: {project_name}=={version}"

    latest = pypi_data.get("info", {}).get("version", "unknown")
    return True, f"PyPI project exists; latest={latest}, candidate={version}"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: check_pypi_release_state.py", file=sys.stderr)
        return 2

    project_name, version = load_project_metadata(Path("pyproject.toml"))
    ok, message = check_release_state(project_name, version, fetch_pypi_project(project_name))
    stream = sys.stdout if ok else sys.stderr
    print(message, file=stream)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
