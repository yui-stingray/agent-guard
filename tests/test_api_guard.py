"""Where: tests/test_api_guard.py
What: behavior tests for the extracted API surface guard.
Why: preserve ai-company's architecture_guard semantics during extraction.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
import yaml

from agent_guard import api_guard, bounded_scan, bounded_yaml
from agent_guard.api_guard import MAX_API_POLICY_REGEX_COUNT, ApiGuardFinding, load_yaml_policy, scan_urls


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def policy_file(tmp_path: Path, *, include: list[str], exclude: list[str], allowed: list[str], forbidden: list[str]) -> Path:
    payload = {
        "scan": {"include": include, "exclude": exclude},
        "policy": {
            "allowed_api_patterns": allowed,
            "forbidden_api_patterns": forbidden,
        },
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


YAML_POLICY_SENTINEL = "synthetic-api-yaml-policy-sentinel"


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


def basic_policy(tmp_path: Path) -> Path:
    return policy_file(
        tmp_path,
        include=["src", "scripts"],
        exclude=[],
        allowed=[r"^https://ntfy\.sh/"],
        forbidden=[r"^https://api\.openai\.com/", r"^https://api\.anthropic\.com/"],
    )


def test_allowed_url_passes(tmp_path: Path) -> None:
    policy_path = basic_policy(tmp_path)
    write(tmp_path / "src" / "ok.py", 'URL = "https://ntfy.sh/example"\n')

    findings = scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert findings == []


def test_forbidden_url_fails(tmp_path: Path) -> None:
    policy_path = basic_policy(tmp_path)
    write(tmp_path / "src" / "bad.py", 'URL = "https://api.openai.com/v1/responses"\n')

    findings = scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert findings == [
        ApiGuardFinding(
            path="src/bad.py",
            line=1,
            url="https://api.openai.com/v1/responses",
            matched_forbidden_pattern=r"^https://api\.openai\.com/",
        )
    ]


def test_allowed_rule_wins_over_broader_forbidden_prefix(tmp_path: Path) -> None:
    policy_path = policy_file(
        tmp_path,
        include=["src"],
        exclude=[],
        allowed=[r"^https://api\.anthropic\.com/api/oauth/usage$"],
        forbidden=[r"^https://api\.anthropic\.com/"],
    )
    write(tmp_path / "src" / "usage.py", 'URL = "https://api.anthropic.com/api/oauth/usage"\n')

    findings = scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert findings == []


def test_include_exclude_paths_are_honored(tmp_path: Path) -> None:
    policy_path = policy_file(
        tmp_path,
        include=["src", "scripts"],
        exclude=["scripts/generated"],
        allowed=[],
        forbidden=[r"^https://api\.openai\.com/"],
    )
    write(tmp_path / "src" / "bad.py", 'URL = "https://api.openai.com/v1/responses"\n')
    write(tmp_path / "scripts" / "generated" / "skip.py", 'URL = "https://api.openai.com/v1/responses"\n')

    findings = scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert [finding.path for finding in findings] == ["src/bad.py"]


def test_exclude_paths_still_match_resolved_internal_symlink_targets(tmp_path: Path) -> None:
    target = tmp_path / "shared" / "ignored.py"
    write(tmp_path / "src" / "selected.py", 'URL = "https://api.openai.com/v1/responses"\n')
    write(target, 'URL = "https://api.openai.com/v1/internal-link"\n')
    (tmp_path / "src" / "alias.py").symlink_to(target)
    policy_path = policy_file(
        tmp_path,
        include=["src"],
        exclude=["shared"],
        allowed=[],
        forbidden=[r"^https://api\.openai\.com/"],
    )

    findings = scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert [finding.path for finding in findings] == ["src/selected.py"]


def test_excluded_nested_external_file_symlink_is_pruned_before_resolution(
    tmp_path: Path,
) -> None:
    repo_root = tmp_path / "repo"
    outside_file = tmp_path / "outside" / "private.py"
    write(repo_root / "src" / "selected.py", 'URL = "https://api.openai.com/v1/responses"\n')
    write(outside_file, 'URL = "https://api.openai.com/v1/external"\n')
    (repo_root / "src" / "ignored.py").symlink_to(outside_file)
    policy_path = policy_file(
        repo_root,
        include=["src"],
        exclude=["src/ignored.py"],
        allowed=[],
        forbidden=[r"^https://api\.openai\.com/"],
    )

    findings = scan_urls(root=repo_root, policy=load_yaml_policy(policy_path))

    assert [finding.path for finding in findings] == ["src/selected.py"]


def test_excluded_nested_external_directory_symlink_is_pruned_before_resolution(
    tmp_path: Path,
) -> None:
    repo_root = tmp_path / "repo"
    outside_dir = tmp_path / "outside"
    write(repo_root / "src" / "selected.py", 'URL = "https://api.openai.com/v1/responses"\n')
    write(outside_dir / "private.py", 'URL = "https://api.openai.com/v1/external"\n')
    (repo_root / "src" / "ignored").symlink_to(outside_dir, target_is_directory=True)
    policy_path = policy_file(
        repo_root,
        include=["src"],
        exclude=["src/ignored"],
        allowed=[],
        forbidden=[r"^https://api\.openai\.com/"],
    )

    findings = scan_urls(root=repo_root, policy=load_yaml_policy(policy_path))

    assert [finding.path for finding in findings] == ["src/selected.py"]


@pytest.mark.parametrize("target_is_directory", [False, True], ids=["file", "directory"])
def test_selected_nested_external_symlink_fails_closed(
    tmp_path: Path,
    target_is_directory: bool,
) -> None:
    repo_root = tmp_path / "repo"
    outside = tmp_path / "outside"
    write(repo_root / "src" / "selected.py", 'URL = "https://example.com"\n')
    if target_is_directory:
        write(outside / "private.py", 'URL = "https://api.openai.com/v1/external"\n')
        external_target = outside
    else:
        external_target = outside / "private.py"
        write(external_target, 'URL = "https://api.openai.com/v1/external"\n')
    (repo_root / "src" / "selected-external").symlink_to(
        external_target,
        target_is_directory=target_is_directory,
    )
    policy_path = policy_file(
        repo_root,
        include=["src"],
        exclude=[],
        allowed=[],
        forbidden=[r"^https://api\.openai\.com/"],
    )

    with pytest.raises(
        ValueError,
        match="^api scan target must stay under repo root$",
    ) as exc_info:
        scan_urls(root=repo_root, policy=load_yaml_policy(policy_path))

    assert str(outside.resolve()) not in str(exc_info.value)


def test_api_scan_results_are_deterministic_across_creation_order(tmp_path: Path) -> None:
    policy_path = policy_file(
        tmp_path,
        include=["src"],
        exclude=[],
        allowed=[],
        forbidden=[r"^https://api\.openai\.com/"],
    )
    expected_paths = [
        "src/a.py",
        "src/nested/a.py",
        "src/nested/z.py",
        "src/z.py",
    ]
    for rel_path in reversed(expected_paths):
        write(tmp_path / rel_path, 'URL = "https://api.openai.com/v1/responses"\n')

    first = scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))
    second = scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert [finding.path for finding in first] == expected_paths
    assert [finding.path for finding in second] == expected_paths


def test_binary_file_is_skipped(tmp_path: Path) -> None:
    policy_path = basic_policy(tmp_path)
    binary_path = tmp_path / "src" / "blob.bin"
    binary_path.parent.mkdir(parents=True, exist_ok=True)
    binary_path.write_bytes(b"\x00\xff\x00https://api.openai.com/")

    findings = scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert findings == []


def test_api_scan_returns_count_and_findings_from_one_walk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = basic_policy(tmp_path)
    write(tmp_path / "src" / "bad.py", 'URL = "https://api.openai.com/v1/responses"\n')
    write(tmp_path / "scripts" / "ok.py", 'URL = "https://example.com"\n')
    original_iter_scan_files = api_guard.iter_scan_files
    walk_count = 0

    def counted_iter_scan_files(
        root: Path,
        include: list[str],
        exclude: list[str],
    ) -> object:
        nonlocal walk_count
        walk_count += 1
        yield from original_iter_scan_files(root, include, exclude)

    def run_inline(operation: object, *args: object, **_kwargs: object) -> object:
        assert callable(operation)
        return operation(*args)

    monkeypatch.setattr(api_guard, "iter_scan_files", counted_iter_scan_files)
    monkeypatch.setattr(api_guard, "run_isolated_scan", run_inline)

    findings, scanned_count = api_guard.scan_urls_with_count(
        root=tmp_path,
        policy=load_yaml_policy(policy_path),
    )

    assert walk_count == 1
    assert scanned_count == 2
    assert [finding.path for finding in findings] == ["src/bad.py"]


def test_api_scan_charges_scandir_entries_before_consuming_past_work_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_dir = tmp_path / "src"
    scan_dir.mkdir()
    budget = 2
    consumed = 0
    name_reads = 0

    class InstrumentedEntry:
        def __init__(self, index: int) -> None:
            self.index = index

        @property
        def name(self) -> str:
            nonlocal name_reads
            name_reads += 1
            return f"candidate-{self.index}.py"

        def is_dir(self, *, follow_symlinks: bool = True) -> bool:
            return False

    class InstrumentedScandir:
        def __init__(self) -> None:
            self.index = 0

        def __enter__(self) -> InstrumentedScandir:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self) -> InstrumentedScandir:
            return self

        def __next__(self) -> InstrumentedEntry:
            nonlocal consumed
            if self.index >= 8:
                raise StopIteration
            entry = InstrumentedEntry(self.index)
            self.index += 1
            consumed += 1
            return entry

    def instrumented_scandir(_path: object) -> InstrumentedScandir:
        return InstrumentedScandir()

    monkeypatch.setattr(api_guard, "MAX_API_SCAN_WORK_ITEMS", budget)
    monkeypatch.setattr(api_guard.os, "scandir", instrumented_scandir)

    with pytest.raises(ValueError, match="^api scan exceeds configured limits$"):
        list(api_guard.iter_scan_files(tmp_path, ["src"], []))

    assert consumed == budget + 1
    assert name_reads == budget


@pytest.mark.skipif(os.name != "posix", reason="exercises POSIX no-follow traversal")
def test_api_guard_binds_containment_to_opened_file_after_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = tmp_path / "repo"
    outside = tmp_path / "outside"
    target = repo_root / "src" / "target.py"
    write(target, 'URL = "https://example.com"\n')
    external_marker = "synthetic-external-api-marker"
    external_file = outside / "private-marker.py"
    write(
        external_file,
        f'{external_marker} = "https://api.openai.com/v1/responses"\n',
    )
    policy = {
        "scan": {"include": ["src"], "exclude": []},
        "policy": {
            "allowed_api_patterns": [],
            "forbidden_api_patterns": [r"^https://api\.openai\.com/"],
        },
    }
    original_open = api_guard._open_repo_file_posix

    def swap_before_open(root: Path, relative_path: Path) -> int:
        target.unlink()
        target.symlink_to(external_file)
        return original_open(root, relative_path)

    monkeypatch.setattr(api_guard, "_open_repo_file_posix", swap_before_open)

    with pytest.raises(
        ValueError,
        match="^api scan target must stay under repo root$",
    ) as exc_info:
        scan_urls(root=repo_root, policy=policy)

    error = str(exc_info.value)
    assert external_marker not in error
    assert str(outside.resolve()) not in error


def test_api_guard_read_oserror_fails_closed_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = basic_policy(tmp_path)
    write(tmp_path / "src" / "target.py", 'URL = "https://example.com"\n')
    external_marker = "synthetic-api-read-error-marker"
    external_path = tmp_path.parent / external_marker / "private.txt"

    class FailingReadHandle:
        def __init__(self, file_fd: int) -> None:
            self.file_fd = file_fd

        def __enter__(self) -> FailingReadHandle:
            return self

        def __exit__(self, *_args: object) -> None:
            os.close(self.file_fd)

        def read(self, _size: int) -> bytes:
            raise OSError(f"{external_marker}: {external_path.resolve()}")

    def failing_fdopen(file_fd: int, mode: str) -> FailingReadHandle:
        assert mode == "rb"
        return FailingReadHandle(file_fd)

    def run_inline(operation: object, *args: object, **_kwargs: object) -> object:
        assert callable(operation)
        return operation(*args)

    monkeypatch.setattr(api_guard.os, "fdopen", failing_fdopen)
    monkeypatch.setattr(api_guard, "run_isolated_scan", run_inline)

    with pytest.raises(
        RuntimeError,
        match="^api scan could not complete safely$",
    ) as exc_info:
        scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    error = str(exc_info.value)
    assert external_marker not in error
    assert str(external_path.resolve()) not in error


def test_api_guard_checks_aggregate_result_budget_before_finding_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = basic_policy(tmp_path)
    marker = "synthetic-api-result-marker"
    write(
        tmp_path / "src" / "bad.py",
        f'URL = "https://api.openai.com/v1/responses?marker={marker}"\n',
    )

    def run_inline(operation: object, *args: object, **_kwargs: object) -> object:
        assert callable(operation)
        return operation(*args)

    def fail_finding_materialization(**_kwargs: object) -> object:
        raise AssertionError("finding was materialized before its aggregate budget check")

    assert api_guard.MAX_API_AGGREGATE_RESULT_BYTES <= (
        bounded_scan.MAX_ISOLATED_MESSAGE_BYTES // 2
    )
    monkeypatch.setattr(api_guard, "MAX_API_AGGREGATE_RESULT_BYTES", 0)
    monkeypatch.setattr(api_guard, "ApiGuardFinding", fail_finding_materialization)
    monkeypatch.setattr(api_guard, "run_isolated_scan", run_inline)

    with pytest.raises(
        ValueError,
        match="^api scan exceeds configured limits$",
    ) as exc_info:
        scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert marker not in str(exc_info.value)


def test_missing_policy_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_yaml_policy(tmp_path / "missing.yaml")


def test_malformed_policy_object_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- not-a-mapping\n", encoding="utf-8")

    with pytest.raises(ValueError, match="^api policy is invalid$"):
        load_yaml_policy(bad)


@pytest.mark.parametrize("raw_policy", YAML_POLICY_LIMIT_CASES)
def test_api_policy_yaml_limits_are_fast_and_sanitized(
    tmp_path: Path,
    raw_policy: str,
) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(raw_policy, encoding="utf-8")

    started = time.monotonic()
    with pytest.raises(
        ValueError,
        match="^api policy exceeds configured limits$",
    ) as exc_info:
        load_yaml_policy(policy_path)

    assert time.monotonic() - started < 3
    assert YAML_POLICY_SENTINEL not in str(exc_info.value)


@pytest.mark.parametrize("failure_type", [RecursionError, OverflowError, MemoryError])
def test_api_policy_yaml_resource_failures_are_sanitized_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("{}\n", encoding="utf-8")

    def fail_safe_load(_text: str) -> object:
        raise failure_type(YAML_POLICY_SENTINEL)

    monkeypatch.setattr(api_guard.yaml, "safe_load", fail_safe_load)

    with pytest.raises(
        ValueError,
        match="^api policy exceeds configured limits$",
    ) as exc_info:
        load_yaml_policy(policy_path)

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
def test_api_policy_preflights_yaml_before_object_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    budget_name: str | None,
    raw_policy: str,
) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(raw_policy, encoding="utf-8")
    if budget_name is not None:
        monkeypatch.setattr(bounded_yaml, budget_name, 0)

    def unexpected_safe_load(_text: str) -> object:
        raise AssertionError("YAML object construction started before preflight")

    monkeypatch.setattr(api_guard.yaml, "safe_load", unexpected_safe_load)

    with pytest.raises(ValueError, match="^api policy exceeds configured limits$"):
        load_yaml_policy(policy_path)


def test_api_policy_preserves_bounded_non_merge_anchors(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "shared: &shared []\n"
        "scan:\n"
        "  include: *shared\n"
        "  exclude: *shared\n"
        "policy:\n"
        "  allowed_api_patterns: *shared\n"
        "  forbidden_api_patterns: *shared\n",
        encoding="utf-8",
    )

    policy = load_yaml_policy(policy_path)

    assert policy["shared"] is policy["scan"]["include"]
    assert policy["shared"] is policy["policy"]["forbidden_api_patterns"]


@pytest.mark.parametrize("include", ["../outside", "linked"])
def test_api_guard_rejects_traversal_and_outward_symlink_include_targets(tmp_path: Path, include: str) -> None:
    repo_root = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo_root.mkdir()
    outside.mkdir()
    (repo_root / "linked").symlink_to(outside, target_is_directory=True)
    policy = {
        "scan": {"include": [include], "exclude": []},
        "policy": {"allowed_api_patterns": [], "forbidden_api_patterns": []},
    }

    with pytest.raises(ValueError, match="^api scan target must stay under repo root$"):
        scan_urls(root=repo_root, policy=policy)


def test_api_guard_rejects_external_absolute_include_target(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo_root.mkdir()
    outside.mkdir()
    policy = {
        "scan": {"include": [str(outside)], "exclude": []},
        "policy": {"allowed_api_patterns": [], "forbidden_api_patterns": []},
    }

    with pytest.raises(ValueError, match="^api scan target must stay under repo root$"):
        scan_urls(root=repo_root, policy=policy)


def test_api_guard_enforces_regex_execution_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bounded_scan, "ISOLATED_SCAN_TIMEOUT_SECONDS", 0.25)
    sentinel = "sk-" + ("u" * 24)
    policy_path = policy_file(
        tmp_path,
        include=["src"],
        exclude=[],
        allowed=[],
        forbidden=[f"(?# {sentinel})(a+)+$"],
    )
    write(tmp_path / "src" / "catastrophic.py", f'URL = "https://example.test/{"a" * 30}!"\n')

    started = time.monotonic()
    with pytest.raises(RuntimeError, match="^api scan exceeded execution budget$") as exc_info:
        scan_urls(root=tmp_path, policy=load_yaml_policy(policy_path))

    assert time.monotonic() - started < 3
    assert sentinel not in str(exc_info.value)


def test_api_guard_rejects_combined_regex_count_before_scan(tmp_path: Path) -> None:
    policy = {
        "scan": {"include": [], "exclude": []},
        "policy": {
            "allowed_api_patterns": ["safe"] * MAX_API_POLICY_REGEX_COUNT,
            "forbidden_api_patterns": ["blocked"],
        },
    }

    with pytest.raises(ValueError, match="^api policy exceeds configured limits$"):
        scan_urls(root=tmp_path, policy=policy)


@pytest.mark.parametrize(
    "policy",
    [
        {"scan": {"include": [["src"]], "exclude": []}, "policy": {}},
        {
            "scan": {"include": [], "exclude": []},
            "policy": {"allowed_api_patterns": [], "forbidden_api_patterns": [["blocked"]]},
        },
        {"scan": [], "policy": {}},
        {"scan": {}, "policy": []},
    ],
)
def test_api_guard_rejects_non_string_or_non_object_policy_values_without_echo(
    tmp_path: Path,
    policy: dict[str, object],
) -> None:
    sentinel = "synthetic-policy-sentinel"
    policy["marker"] = sentinel

    with pytest.raises(ValueError, match="^api policy is invalid$") as exc_info:
        scan_urls(root=tmp_path, policy=policy)

    assert sentinel not in str(exc_info.value)
