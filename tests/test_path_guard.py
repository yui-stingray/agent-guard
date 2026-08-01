"""Where: tests/test_path_guard.py
What: behavior tests for repository path-name guardrails.
Why: catch private artifacts and env-file leaks before content scanning is possible.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml

from agent_guard import bounded_scan, bounded_yaml, path_guard
from agent_guard.path_guard import (
    MAX_PATH_POLICY_REGEX_COUNT,
    PathGuardFinding,
    load_path_policy,
    scan_paths,
)


ROOT = Path(__file__).resolve().parents[1]


def write(path: Path, text: str = "x\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def policy_file(tmp_path: Path) -> Path:
    payload = {
        "scan": {"include": ["."], "exclude": []},
        "policy": {
            "allowed_path_patterns": [r"(^|/)\.env\.example$"],
            "forbidden_path_patterns": [
                {
                    "id": "private_artifacts",
                    "severity": "high",
                    "pattern": r"(^|/)artifacts/private(/|$)",
                    "message": "private artifact directory must stay outside published/tracked paths",
                },
                {
                    "id": "bypass_corpus",
                    "severity": "high",
                    "pattern": r"(^|/)bypass[^/]*\.(jsonl|json|txt)$",
                    "message": "bypass corpus material must not be placed in repository paths",
                },
                {
                    "id": "red_session_log",
                    "severity": "high",
                    "pattern": r"(^|/)red_session_[^/]+",
                    "message": "red-team session logs must not be placed in repository paths",
                },
                {
                    "id": "env_file",
                    "severity": "high",
                    "pattern": r"(^|/)\.env(\..+)?$",
                    "message": "env files are forbidden except .env.example",
                },
            ],
        },
    }
    path = tmp_path / "path_policy.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


YAML_POLICY_SENTINEL = "synthetic-path-yaml-policy-sentinel"


def _alias_expansion_policy() -> str:
    lines = [f"n0: &n0 [{YAML_POLICY_SENTINEL}]\n"]
    for index in range(1, 18):
        lines.append(f"n{index}: &n{index} [*n{index - 1}, *n{index - 1}]\n")
    lines.append("root: *n17\n")
    return "".join(lines)


YAML_POLICY_LIMIT_CASES = [
    pytest.param(
        "root: " + ("[" * 65) + YAML_POLICY_SENTINEL + ("]" * 65) + "\n",
        id="deep",
    ),
    pytest.param(
        f"base: &base [{YAML_POLICY_SENTINEL}]\nrefs:\n"
        + ("  - *base\n" * 129),
        id="aliases",
    ),
    pytest.param(
        f"base: &base {{marker: {YAML_POLICY_SENTINEL}}}\n"
        "policy:\n"
        "  <<: *base\n",
        id="merge",
    ),
    pytest.param(
        f"cycle: &cycle [{YAML_POLICY_SENTINEL}, *cycle]\n",
        id="cycle",
    ),
    pytest.param(_alias_expansion_policy(), id="alias-expansion"),
]


def test_path_guard_blocks_private_artifacts_and_sensitive_names(tmp_path: Path) -> None:
    policy = load_path_policy(policy_file(tmp_path))
    write(tmp_path / "artifacts" / "private" / "bypass_cases.jsonl")
    write(tmp_path / "logs" / "red_session_001.txt")
    write(tmp_path / ".env.evil")
    write(tmp_path / ".env.example")

    findings, scanned = scan_paths(root=tmp_path, policy=policy)

    assert scanned >= 5
    assert {(item.path, item.rule_id) for item in findings} == {
        (".env.evil", "env_file"),
        ("artifacts/private", "private_artifacts"),
        ("artifacts/private/bypass_cases.jsonl", "private_artifacts"),
        ("logs/red_session_001.txt", "red_session_log"),
    }


def test_ai_resilience_example_policy_matches_publication_gate_names(tmp_path: Path) -> None:
    policy = load_path_policy(ROOT / "examples" / "ai_resilience_path_policy.yaml")
    write(tmp_path / "artifacts" / "local" / "agent-policy-decisions.jsonl")
    write(tmp_path / "artifacts" / "private" / ".gitkeep")
    write(tmp_path / "data" / "bypass_cases.ndjson")
    write(tmp_path / "logs" / "red_session_001.log")
    write(tmp_path / ".env.local")
    write(tmp_path / ".env.example")

    findings, _ = scan_paths(root=tmp_path, policy=policy)

    assert {(item.path, item.rule_id) for item in findings} == {
        (".env.local", "env_file"),
        ("artifacts/local", "local_artifacts"),
        ("artifacts/local/agent-policy-decisions.jsonl", "local_artifacts"),
        ("artifacts/private", "private_artifacts"),
        ("artifacts/private/.gitkeep", "private_artifacts"),
        ("data/bypass_cases.ndjson", "bypass_corpus"),
        ("logs/red_session_001.log", "red_session_log"),
    }


def test_path_guard_allowlist_runs_before_deny_patterns(tmp_path: Path) -> None:
    policy = load_path_policy(policy_file(tmp_path))
    write(tmp_path / ".env.example")
    write(tmp_path / "nested" / ".env.example")

    findings, _ = scan_paths(root=tmp_path, policy=policy)

    assert findings == []


def test_path_guard_blocks_root_env_file(tmp_path: Path) -> None:
    policy = load_path_policy(policy_file(tmp_path))
    write(tmp_path / ".env")

    findings, _ = scan_paths(root=tmp_path, policy=policy)

    assert findings == [
        PathGuardFinding(
            path=".env",
            rule_id="env_file",
            severity="high",
            message="env files are forbidden except .env.example",
            matched_pattern=r"(^|/)\.env(\..+)?$",
        )
    ]


def test_path_guard_checks_symlink_name_without_following_target(tmp_path: Path) -> None:
    policy = load_path_policy(policy_file(tmp_path))
    outside = tmp_path.parent / "outside-private-target"
    outside.mkdir(exist_ok=True)
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts" / "private").symlink_to(outside, target_is_directory=True)

    findings, _ = scan_paths(root=tmp_path, policy=policy)

    assert any(item.path == "artifacts/private" for item in findings)


def test_malformed_path_policy_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- not-a-mapping\n", encoding="utf-8")

    with pytest.raises(ValueError, match="^path policy is invalid$"):
        load_path_policy(bad)


@pytest.mark.parametrize("raw_policy", YAML_POLICY_LIMIT_CASES)
def test_path_policy_yaml_limits_are_fast_and_sanitized(
    tmp_path: Path,
    raw_policy: str,
) -> None:
    policy_path = tmp_path / "path-policy.yaml"
    policy_path.write_text(raw_policy, encoding="utf-8")

    started = time.monotonic()
    with pytest.raises(
        ValueError,
        match="^path policy exceeds configured limits$",
    ) as exc_info:
        load_path_policy(policy_path)

    assert time.monotonic() - started < 3
    assert YAML_POLICY_SENTINEL not in str(exc_info.value)


@pytest.mark.parametrize("failure_type", [RecursionError, OverflowError, MemoryError])
def test_path_policy_yaml_resource_failures_are_sanitized_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
) -> None:
    policy_path = tmp_path / "path-policy.yaml"
    policy_path.write_text("{}\n", encoding="utf-8")

    def fail_safe_load(_text: str) -> object:
        raise failure_type(YAML_POLICY_SENTINEL)

    monkeypatch.setattr(path_guard.yaml, "safe_load", fail_safe_load)

    with pytest.raises(
        ValueError,
        match="^path policy exceeds configured limits$",
    ) as exc_info:
        load_path_policy(policy_path)

    assert YAML_POLICY_SENTINEL not in str(exc_info.value)


@pytest.mark.parametrize(
    ("budget_name", "raw_policy"),
    [
        ("MAX_YAML_NODES", "{}\n"),
        ("MAX_YAML_DEPTH", "{}\n"),
        ("MAX_YAML_ALIASES", "base: &base []\ncopy: *base\n"),
        (None, "base: &base {}\ncopy:\n  <<: *base\n"),
    ],
)
def test_path_policy_preflights_yaml_before_object_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    budget_name: str | None,
    raw_policy: str,
) -> None:
    policy_path = tmp_path / "path-policy.yaml"
    policy_path.write_text(raw_policy, encoding="utf-8")
    if budget_name is not None:
        monkeypatch.setattr(bounded_yaml, budget_name, 0)

    def unexpected_safe_load(_text: str) -> object:
        raise AssertionError("YAML object construction started before preflight")

    monkeypatch.setattr(path_guard.yaml, "safe_load", unexpected_safe_load)

    with pytest.raises(ValueError, match="^path policy exceeds configured limits$"):
        load_path_policy(policy_path)


def test_path_policy_preserves_bounded_non_merge_anchors(tmp_path: Path) -> None:
    policy_path = tmp_path / "path-policy.yaml"
    policy_path.write_text(
        "shared: &shared []\n"
        "scan:\n"
        "  include: *shared\n"
        "  exclude: *shared\n"
        "policy:\n"
        "  allowed_path_patterns: *shared\n"
        "  forbidden_path_patterns: *shared\n",
        encoding="utf-8",
    )

    policy = load_path_policy(policy_path)

    assert policy["shared"] is policy["scan"]["include"]
    assert policy["shared"] is policy["policy"]["forbidden_path_patterns"]


@pytest.mark.parametrize("include", ["../outside", "linked"])
def test_path_guard_rejects_traversal_and_outward_symlink_include_targets(tmp_path: Path, include: str) -> None:
    repo_root = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo_root.mkdir()
    outside.mkdir()
    (repo_root / "linked").symlink_to(outside, target_is_directory=True)

    policy = {
        "scan": {"include": [include], "exclude": []},
        "policy": {"allowed_path_patterns": [], "forbidden_path_patterns": []},
    }

    with pytest.raises(ValueError, match="^path scan target must stay under repo root$"):
        scan_paths(root=repo_root, policy=policy)


def test_path_guard_rejects_external_absolute_include_target(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo_root.mkdir()
    outside.mkdir()
    policy = {
        "scan": {"include": [str(outside)], "exclude": []},
        "policy": {"allowed_path_patterns": [], "forbidden_path_patterns": []},
    }

    with pytest.raises(ValueError, match="^path scan target must stay under repo root$"):
        scan_paths(root=repo_root, policy=policy)


def test_path_guard_enforces_regex_execution_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bounded_scan, "ISOLATED_SCAN_TIMEOUT_SECONDS", 0.25)
    sentinel = "sk-" + ("p" * 24)
    write(tmp_path / (("a" * 30) + "!"))
    policy = {
        "scan": {"include": ["."], "exclude": []},
        "policy": {
            "allowed_path_patterns": [],
            "forbidden_path_patterns": [
                {
                    "id": "catastrophic",
                    "pattern": f"(?# {sentinel})(a+)+$",
                }
            ],
        },
    }

    started = time.monotonic()
    with pytest.raises(RuntimeError, match="^path scan exceeded execution budget$") as exc_info:
        scan_paths(root=tmp_path, policy=policy)

    assert time.monotonic() - started < 3
    assert sentinel not in str(exc_info.value)


def test_path_guard_rejects_combined_regex_count_before_scan(tmp_path: Path) -> None:
    policy = {
        "scan": {"include": ["."], "exclude": []},
        "policy": {
            "allowed_path_patterns": ["safe"] * MAX_PATH_POLICY_REGEX_COUNT,
            "forbidden_path_patterns": [{"pattern": "blocked"}],
        },
    }

    with pytest.raises(ValueError, match="^path policy exceeds configured limits$"):
        scan_paths(root=tmp_path, policy=policy)


@pytest.mark.parametrize(
    "limit_name",
    ["MAX_PATH_FINDINGS", "MAX_PATH_AGGREGATE_RESULT_BYTES"],
)
def test_path_guard_checks_result_limits_before_finding_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
) -> None:
    marker = "synthetic-path-result-marker"
    write(tmp_path / marker)
    policy = {
        "scan": {"include": ["."], "exclude": []},
        "policy": {
            "allowed_path_patterns": [],
            "forbidden_path_patterns": [{"id": "blocked", "pattern": marker}],
        },
    }

    def run_inline(operation: object, *args: object, **_kwargs: object) -> object:
        assert callable(operation)
        return operation(*args)

    def fail_finding_materialization(**_kwargs: object) -> object:
        raise AssertionError("finding was materialized before its result budget check")

    assert path_guard.MAX_PATH_AGGREGATE_RESULT_BYTES <= (
        bounded_scan.MAX_ISOLATED_MESSAGE_BYTES // 2
    )
    monkeypatch.setattr(path_guard, limit_name, 0)
    monkeypatch.setattr(path_guard, "PathGuardFinding", fail_finding_materialization)
    monkeypatch.setattr(path_guard, "run_isolated_scan", run_inline)

    with pytest.raises(ValueError, match="^path scan exceeds configured limits$") as exc_info:
        scan_paths(root=tmp_path, policy=policy)

    assert marker not in str(exc_info.value)


@pytest.mark.parametrize(
    "policy",
    [
        {"scan": {"include": [["."]], "exclude": []}, "policy": {}},
        {
            "scan": {"include": ["."], "exclude": []},
            "policy": {"allowed_path_patterns": [], "forbidden_path_patterns": [["blocked"]]},
        },
        {
            "scan": {"include": ["."], "exclude": []},
            "policy": {
                "allowed_path_patterns": [],
                "forbidden_path_patterns": [{"id": ["nested"], "pattern": "blocked"}],
            },
        },
        {"scan": [], "policy": {}},
        {"scan": {}, "policy": []},
    ],
)
def test_path_guard_rejects_non_string_or_non_object_policy_values_without_echo(
    tmp_path: Path,
    policy: dict[str, object],
) -> None:
    sentinel = "synthetic-policy-sentinel"
    policy["marker"] = sentinel

    with pytest.raises(ValueError, match="^path policy is invalid$") as exc_info:
        scan_paths(root=tmp_path, policy=policy)

    assert sentinel not in str(exc_info.value)
