"""Where: scripts/check_changelog.py
What: ensure CHANGELOG.md has notes for the current package version.
Why: fail releases before tagging when user-visible release notes are missing.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


VERSION_HEADING_RE = re.compile(r"^##\s+(?P<version>\d+\.\d+\.\d+)(?:\s+-\s+.*)?$")


def load_project_version(pyproject_path: Path) -> str:
    """Return the declared package version from pyproject.toml."""
    with pyproject_path.open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def changelog_versions(changelog_path: Path) -> list[str]:
    """Return semantic versions that have a second-level changelog heading."""
    versions: list[str] = []
    for line in changelog_path.read_text(encoding="utf-8").splitlines():
        match = VERSION_HEADING_RE.match(line)
        if match:
            versions.append(match.group("version"))
    return versions


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: check_changelog.py", file=sys.stderr)
        return 2

    version = load_project_version(Path("pyproject.toml"))
    versions = changelog_versions(Path("CHANGELOG.md"))
    if version not in versions:
        print(f"CHANGELOG.md missing release notes for version {version}", file=sys.stderr)
        return 1

    print(f"CHANGELOG.md contains release notes for version {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

