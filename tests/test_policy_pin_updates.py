"""Where: tests/test_policy_pin_updates.py
What: focused tests for the .agent-guard/context-digest-policy.yaml and
.agent-guard/path-policy.yaml updates in this change.
Why: pin the refreshed path-policy.yaml sha256 digest and lock the quarantine
exclude behavior described by the updated path-policy.yaml comment.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from agent_guard.digest_guard import load_digest_policy, scan_digests
from agent_guard.path_guard import load_path_policy, scan_paths as scan_repo_paths


REPO_ROOT = Path(__file__).resolve().parents[1]
DIGEST_POLICY_PATH = REPO_ROOT / ".agent-guard" / "context-digest-policy.yaml"
PATH_POLICY_PATH = REPO_ROOT / ".agent-guard" / "path-policy.yaml"

# The sha256 value that was pinned before this change updated the path-policy.yaml
# comment. It must not still be referenced once the file content changes.
STALE_PATH_POLICY_SHA256 = "25a58d78386c420cdea67b0ca46f0c572bf31e53c5f6643f5760aff80d426abc"


def test_context_digest_policy_pins_the_current_path_policy_sha256() -> None:
    payload = yaml.safe_load(DIGEST_POLICY_PATH.read_text(encoding="utf-8"))
    checks_by_id = {item["id"]: item for item in payload["checks"]}

    pinned_sha256 = checks_by_id["path_policy"]["sha256"]
    actual_sha256 = hashlib.sha256(PATH_POLICY_PATH.read_bytes()).hexdigest()

    assert pinned_sha256 == actual_sha256
    assert pinned_sha256 != STALE_PATH_POLICY_SHA256


def test_scan_digests_reports_no_drift_for_the_path_policy_check() -> None:
    digest_policy = load_digest_policy(DIGEST_POLICY_PATH)
    checks = [item for item in digest_policy["checks"] if item["id"] == "path_policy"]
    assert len(checks) == 1

    findings, checked = scan_digests(root=REPO_ROOT, policy={"checks": checks})

    assert checked == 1
    assert findings == []


def test_path_policy_comment_documents_bench_fixture_quarantine() -> None:
    text = PATH_POLICY_PATH.read_text(encoding="utf-8")

    assert (
        "AGB fixtures are quarantined adversarial samples scanned only by the "
        "bench runner per-fixture." in text
    )
    assert "Benchmark fixtures intentionally model paths" not in text


def test_path_policy_still_excludes_bench_agb_fixtures_from_scan() -> None:
    loaded = load_path_policy(PATH_POLICY_PATH)
    assert "bench/agb/fixtures" in loaded["scan"]["exclude"]


def test_path_policy_exclusion_quarantines_fixtures_but_still_catches_real_violations(
    tmp_path: Path,
) -> None:
    policy = load_path_policy(PATH_POLICY_PATH)

    quarantined = tmp_path / "bench" / "agb" / "fixtures" / "zz-quarantined" / "artifacts" / "private" / "leak.json"
    quarantined.parent.mkdir(parents=True, exist_ok=True)
    quarantined.write_text('{"status": "quarantined"}', encoding="utf-8")

    real_violation = tmp_path / "artifacts" / "private" / "leak.json"
    real_violation.parent.mkdir(parents=True, exist_ok=True)
    real_violation.write_text('{"status": "real"}', encoding="utf-8")

    findings, _scanned = scan_repo_paths(root=tmp_path, policy=policy)
    matched_paths = {finding.path for finding in findings}

    assert "artifacts/private/leak.json" in matched_paths
    assert not any(path.startswith("bench/agb/fixtures/") for path in matched_paths)


def test_repo_root_path_check_stays_clean_with_updated_policy() -> None:
    findings, scanned = scan_repo_paths(root=REPO_ROOT, policy=load_path_policy(PATH_POLICY_PATH))

    assert scanned >= 1
    assert findings == []