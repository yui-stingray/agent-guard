"""Require a release tag to point at current master with successful CI."""

from __future__ import annotations

import argparse
import re

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def check_release_source(
    *, tag_sha: str, master_sha: str, ci_conclusions: list[str]
) -> tuple[bool, str]:
    normalized_tag = tag_sha.strip().lower()
    normalized_master = master_sha.strip().lower()
    if not SHA_PATTERN.fullmatch(normalized_tag) or not SHA_PATTERN.fullmatch(
        normalized_master
    ):
        return False, "release source commit identifiers are invalid"
    if normalized_tag != normalized_master:
        return False, "release tag must point at the current origin/master commit"
    if "success" not in {item.strip().lower() for item in ci_conclusions}:
        return False, "release commit must have a successful completed CI run"
    return True, "release source is current protected master with successful CI"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag-sha", required=True)
    parser.add_argument("--master-sha", required=True)
    parser.add_argument("--ci-conclusion", action="append", default=[])
    args = parser.parse_args(argv)
    ok, message = check_release_source(
        tag_sha=args.tag_sha,
        master_sha=args.master_sha,
        ci_conclusions=args.ci_conclusion,
    )
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
