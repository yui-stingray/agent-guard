"""Where: scripts/check_release_version.py
What: fail fast when a release tag and package version diverge.
Why: prevent PyPI upload attempts for the wrong version.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


FINAL_RELEASE_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def load_project_version(pyproject_path: Path) -> str:
    """Return the declared package version from pyproject.toml."""
    with pyproject_path.open("rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def normalize_tag(tag_name: str) -> str:
    """Translate a release tag like v0.1.0 into the package version string."""
    return tag_name[1:] if tag_name.startswith("v") else tag_name


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_release_version.py <tag-name>", file=sys.stderr)
        return 2

    tag_name = argv[1]
    expected_version = normalize_tag(tag_name)
    actual_version = load_project_version(Path("pyproject.toml"))

    if not FINAL_RELEASE_VERSION_RE.fullmatch(expected_version):
        print(
            "release tag must name a final numeric x.y.z version",
            file=sys.stderr,
        )
        return 1

    if actual_version != expected_version:
        print(
            "release tag/version mismatch: "
            f"tag={expected_version} pyproject={actual_version}",
            file=sys.stderr,
        )
        return 1

    print(f"release tag/version match: {actual_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
