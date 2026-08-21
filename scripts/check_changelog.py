"""Where: scripts/check_changelog.py
What: ensure CHANGELOG.md has notes for the current package version.
Why: fail releases before tagging when user-visible release notes are missing.
"""

from __future__ import annotations

import re
import sys
import tomllib
import argparse
from pathlib import Path


VERSION_HEADING_RE = re.compile(r"^##\s+(?P<version>\d+\.\d+\.\d+)(?:\s+-\s+.*)?$")
DEVELOPMENT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+\.dev\d+$")


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


def changelog_heading(version: str) -> str:
    """Map a development package version to the existing Unreleased section."""
    return "Unreleased" if DEVELOPMENT_VERSION_RE.fullmatch(version) else version


def _extract_heading_notes(changelog_path: Path, heading_text: str) -> str:
    lines = changelog_path.read_text(encoding="utf-8").splitlines()
    heading = re.compile(rf"^##\s+{re.escape(heading_text)}(?:\s+-\s+.*)?$")
    start: int | None = None
    for index, line in enumerate(lines):
        if heading.match(line):
            start = index + 1
            break
    if start is None:
        raise ValueError(f"CHANGELOG.md missing release notes for version {heading_text}")

    body: list[str] = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        body.append(line)

    notes = "\n".join(body).strip()
    if not notes:
        raise ValueError(f"CHANGELOG.md has an empty release notes section for version {heading_text}")
    return notes + "\n"


def extract_release_notes(changelog_path: Path, version: str) -> str:
    """Return the changelog body for one version heading."""
    return _extract_heading_notes(changelog_path, version)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", help="version to check; defaults to pyproject.toml [project].version")
    parser.add_argument("--write-notes", help="write extracted notes for the selected version to this path")
    parser.add_argument(
        "--release",
        action="store_true",
        help="require a final versioned release heading instead of Unreleased",
    )
    args = parser.parse_args(argv[1:])

    version = args.version or load_project_version(Path("pyproject.toml"))
    changelog = Path("CHANGELOG.md")
    heading = changelog_heading(version)
    if args.release and heading == "Unreleased":
        print(
            f"CHANGELOG.md requires a final versioned heading for release {version}",
            file=sys.stderr,
        )
        return 1
    if heading != "Unreleased" and heading not in changelog_versions(changelog):
        print(f"CHANGELOG.md missing release notes for version {version}", file=sys.stderr)
        return 1
    try:
        notes = _extract_heading_notes(changelog, heading)
    except ValueError:
        print(f"CHANGELOG.md missing release notes for version {version}", file=sys.stderr)
        return 1

    if args.write_notes:
        Path(args.write_notes).write_text(notes, encoding="utf-8")
        print(f"wrote release notes for version {version} to {args.write_notes}")
        return 0

    print(f"CHANGELOG.md contains {heading} notes for version {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
