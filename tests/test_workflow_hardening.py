"""Regression tests for CI and release supply-chain hardening."""

from __future__ import annotations

import os
import re
import subprocess
import tomllib
from pathlib import Path

import yaml

from agent_guard.init_guard import GITHUB_WORKFLOW

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_FILES = [
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "release.yml",
    ROOT / ".github" / "workflows" / "github-release.yml",
    ROOT / "action.yml",
]
USES_PATTERN = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)
HARD_ERROR_PRECEDENCE = (
    'if [ "$code" -ge 2 ] || { [ "$code" -ne 0 ] && [ "$status" -eq 0 ]; }; then'
)


def advertised_python_versions() -> list[str]:
    with (ROOT / "pyproject.toml").open("rb") as fh:
        project = tomllib.load(fh)["project"]
    minimum = project["requires-python"].removeprefix(">=")
    minimum_minor = ".".join(minimum.split(".")[:2])
    supported_minors = []
    for classifier in project["classifiers"]:
        match = re.fullmatch(r"Programming Language :: Python :: (\d+\.\d+)", classifier)
        if match:
            supported_minors.append(match.group(1))
    return [minimum if version == minimum_minor else version for version in supported_minors]


def test_executable_action_dependencies_are_pinned_to_full_commit_shas() -> None:
    for path in WORKFLOW_FILES:
        text = path.read_text(encoding="utf-8")
        references = USES_PATTERN.findall(text)
        assert references, path
        for reference in references:
            if reference == "./":
                assert path == ROOT / ".github" / "workflows" / "ci.yml"
                continue
            assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference), (path, reference)


def test_ci_covers_supported_current_python_versions_and_ttfe() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for version in advertised_python_versions():
        assert f"'{version}'" in workflow
    assert "Replay 15-minute onboarding path" in workflow
    assert "--max-elapsed-ms 900000" in workflow


def test_ci_runs_packaged_action_consumer_smoke() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    parsed = yaml.safe_load(workflow)
    action_smoke = parsed["jobs"]["action-smoke"]
    assert action_smoke["name"] == "packaged action smoke (py${{ matrix.python-version }})"
    assert action_smoke["strategy"]["fail-fast"] is False
    assert action_smoke["strategy"]["matrix"]["python-version"] == advertised_python_versions()
    action_step = next(step for step in action_smoke["steps"] if step.get("uses") == "./")
    assert action_step["with"]["python-version"] == "${{ matrix.python-version }}"
    action_smoke_status = parsed["jobs"]["action-smoke-status"]
    assert action_smoke_status["name"] == "packaged action smoke"
    assert action_smoke_status["needs"] == "action-smoke"
    assert action_smoke_status["if"] == "${{ always() }}"
    status_step = action_smoke_status["steps"][0]
    assert status_step["env"]["ACTION_SMOKE_RESULT"] == "${{ needs.action-smoke.result }}"
    assert status_step["run"] == 'test "$ACTION_SMOKE_RESULT" = "success"'
    assert "uses: ./" in workflow
    assert 'test "$ACTION_STATUS" = "0"' in workflow
    assert 'sh examples/evidence_contracts_ci.sh consume' in workflow
    consumer_example = (ROOT / "examples" / "evidence_contracts_ci.sh").read_text(
        encoding="utf-8"
    )
    assert consumer_example.count('"$python_bin" -I -m agent_guard.consumer') >= 2
    assert re.search(r'"\$python_bin"\s+-I\s+-\s+[^\n]*<<', consumer_example)
    assert '"$python_bin" - <<' not in consumer_example
    assert '"$python_bin" - >/dev/null' not in consumer_example


def test_evidence_workflows_preserve_runtime_error_precedence() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    manual_workflow = (ROOT / "docs" / "github-actions-evidence.md").read_text(
        encoding="utf-8"
    )
    for text in (action, GITHUB_WORKFLOW):
        assert HARD_ERROR_PRECEDENCE in text
        assert 'if [ "$code" -eq 2 ]' not in text
    manual_single_line = " ".join(manual_workflow.split())
    assert "preserves status `1` for reviewed policy violations" in manual_single_line
    assert "status `>=2`" in manual_single_line
    assert "omit `ready`" in manual_single_line

    result = subprocess.run(
        [
            "bash",
            "-c",
            f"""
status=0
record_status() {{
  code="$1"
  {HARD_ERROR_PRECEDENCE}
    status="$code"
  fi
}}
record_status 1
record_status 127
printf '%s\\n' "$status"
""",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout == "127\n"
    assert result.stderr == ""


def test_release_requires_current_master_and_successful_ci() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "actions: read" in workflow
    assert "check_release_source.py" in workflow
    assert '--workflow ci.yml' in workflow
    assert '--branch master' in workflow
    assert '--event push' in workflow


def test_github_release_uses_least_privilege_prepare_and_publish_jobs(tmp_path: Path) -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "github-release.yml").read_text(
            encoding="utf-8"
        )
    )
    assert workflow["permissions"] == {"contents": "read"}

    prepare_job = workflow["jobs"]["prepare-github-release"]
    release_job = workflow["jobs"]["publish-github-release"]
    assert prepare_job["timeout-minutes"] == 5
    assert release_job["timeout-minutes"] == 5
    assert prepare_job["permissions"] == {"actions": "read", "contents": "read"}
    assert release_job["permissions"] == {"contents": "write"}
    assert release_job["needs"] == "prepare-github-release"
    assert release_job["if"] == "needs.prepare-github-release.outputs.publish == 'true'"
    assert prepare_job["outputs"] == {
        "prepared-sha": "${{ steps.tag.outputs.prepared-sha }}",
        "publish": "${{ steps.tag.outputs.publish }}",
        "tag": "${{ steps.tag.outputs.tag }}",
    }

    default_branch_step = next(
        step
        for step in prepare_job["steps"]
        if step.get("name") == "Require default branch for manual retry"
    )
    assert default_branch_step["if"] == "github.event_name == 'workflow_dispatch'"
    assert default_branch_step["env"] == {
        "DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}"
    }
    assert '"$GITHUB_REF" != "refs/heads/${DEFAULT_BRANCH}"' in default_branch_step["run"]

    upstream_step = next(
        step for step in prepare_job["steps"] if step.get("id") == "upstream"
    )
    assert upstream_step["if"] == (
        "github.event_name == 'workflow_run' && github.event.workflow_run.event == 'push'"
    )
    assert upstream_step["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "RUN_ID": "${{ github.event.workflow_run.id }}",
    }
    assert '[[ ! "$RUN_ID" =~ ^[0-9]+$ ]]' in upstream_step["run"]
    assert 'publish to PyPI (OIDC)' in upstream_step["run"]
    assert '.conclusion == "success"' in upstream_step["run"]
    assert 'echo "published=false" >> "$GITHUB_OUTPUT"' in upstream_step["run"]

    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    gh_shim = shim_dir / "gh"
    gh_shim.write_text(
        "#!/usr/bin/env bash\nprintf '%s\\n' \"${FAKE_PUBLISHED_COUNT:-0}\"\n",
        encoding="utf-8",
    )
    gh_shim.chmod(0o755)
    for count, expected in (("0", "published=false\n"), ("1", "published=true\n")):
        upstream_output = tmp_path / f"upstream-output-{count}"
        upstream_result = subprocess.run(
            ["bash", "-c", upstream_step["run"]],
            env={
                **os.environ,
                "FAKE_PUBLISHED_COUNT": count,
                "GITHUB_OUTPUT": str(upstream_output),
                "GITHUB_REPOSITORY": "example/agent-guard",
                "PATH": f"{shim_dir}:{os.environ['PATH']}",
                "RUN_ID": "12345",
            },
            capture_output=True,
            text=True,
            check=False,
        )
        assert upstream_result.returncode == 0
        assert upstream_output.read_text(encoding="utf-8") == expected

    checkout_steps = [
        step
        for step in prepare_job["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    assert len(checkout_steps) == 1
    assert checkout_steps[0]["with"]["persist-credentials"] is False
    assert checkout_steps[0]["with"]["fetch-depth"] == 0
    assert checkout_steps[0]["with"]["ref"] == "${{ github.sha }}"

    assert not any(
        str(step.get("uses", "")).startswith("actions/checkout@")
        for step in release_job["steps"]
    )

    tag_step = next(step for step in prepare_job["steps"] if step.get("id") == "tag")
    assert 'github.event_name == \'workflow_dispatch\'' in prepare_job["if"]
    assert "github.event.workflow_run.conclusion == 'success'" in prepare_job["if"]
    assert tag_step["env"] == {
        "INPUT_TAG": "${{ inputs.tag }}",
        "UPSTREAM_EVENT": "${{ github.event.workflow_run.event }}",
        "UPSTREAM_HEAD_SHA": "${{ github.event.workflow_run.head_sha }}",
        "UPSTREAM_PUBLISHED": "${{ steps.upstream.outputs.published }}",
        "UPSTREAM_TAG": "${{ github.event.workflow_run.head_branch }}",
    }
    assert "${{ inputs.tag }}" not in tag_step["run"]
    assert 'tag="$INPUT_TAG"' in tag_step["run"]
    assert '[[ ! "$tag" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]' in tag_step["run"]
    assert 'echo "publish=false" >> "$GITHUB_OUTPUT"' in tag_step["run"]
    assert 'git rev-parse -q --verify "refs/tags/${tag}"' in tag_step["run"]
    assert 'tag_sha="$(git rev-parse "refs/tags/${tag}^{commit}")"' in tag_step["run"]
    assert '[[ ! "$tag_sha" =~ ^[0-9a-f]{40}$ ]]' in tag_step["run"]
    assert 'echo "prepared-sha=${tag_sha}"' in tag_step["run"]
    assert 'git merge-base --is-ancestor "$tag_sha" "$master_sha"' in tag_step["run"]

    marker = tmp_path / "must-not-exist"
    for invalid_tag in ("v0.3.1-rc1", "v0.3.1suffix", f'v0.3.1"; touch "{marker}'):
        output = tmp_path / "github-output"
        output.unlink(missing_ok=True)
        result = subprocess.run(
            ["bash", "-c", tag_step["run"]],
            env={
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_EVENT_PATH": str(tmp_path / "unused-event.json"),
                "GITHUB_OUTPUT": str(output),
                "INPUT_TAG": invalid_tag,
                "UPSTREAM_EVENT": "",
                "UPSTREAM_HEAD_SHA": "",
                "UPSTREAM_PUBLISHED": "",
                "UPSTREAM_TAG": "",
            },
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert output.read_text(encoding="utf-8") == "publish=false\n"
        assert invalid_tag not in result.stdout + result.stderr
        assert not marker.exists()

    dry_run_output = tmp_path / "dry-run-output"
    dry_run_result = subprocess.run(
        ["bash", "-c", tag_step["run"]],
        env={
            "GITHUB_EVENT_NAME": "workflow_run",
            "GITHUB_OUTPUT": str(dry_run_output),
            "INPUT_TAG": "",
            "UPSTREAM_EVENT": "workflow_dispatch",
            "UPSTREAM_HEAD_SHA": "",
            "UPSTREAM_PUBLISHED": "false",
            "UPSTREAM_TAG": "v0.3.1",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert dry_run_result.returncode == 0
    assert dry_run_output.read_text(encoding="utf-8") == "publish=false\n"
    assert "v0.3.1" not in dry_run_result.stdout + dry_run_result.stderr

    release_repo = tmp_path / "release-repo"
    release_repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "master"], cwd=release_repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"],
        cwd=release_repo,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=release_repo, check=True)
    (release_repo / "README.md").write_text("release test\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=release_repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "test release"], cwd=release_repo, check=True)
    subprocess.run(["git", "tag", "v1.2.3"], cwd=release_repo, check=True)
    tag_sha = subprocess.check_output(
        ["git", "rev-parse", "v1.2.3^{commit}"],
        cwd=release_repo,
        text=True,
    ).strip()
    (release_repo / "README.md").write_text("release test\nmaster advanced\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=release_repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "advance master"], cwd=release_repo, check=True)
    subprocess.run(
        ["git", "update-ref", "refs/remotes/origin/master", "HEAD"],
        cwd=release_repo,
        check=True,
    )

    def run_tag_step(output_name: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        output_path = tmp_path / output_name
        isolated_home = tmp_path / "home"
        isolated_home.mkdir(exist_ok=True)
        environment = {
            "GITHUB_EVENT_NAME": "workflow_run",
            "GITHUB_OUTPUT": str(output_path),
            "HOME": str(isolated_home),
            "INPUT_TAG": "",
            "PATH": os.environ["PATH"],
            "UPSTREAM_EVENT": "push",
            "UPSTREAM_HEAD_SHA": tag_sha,
            "UPSTREAM_PUBLISHED": "true",
            "UPSTREAM_TAG": "v1.2.3",
            **overrides,
        }
        return subprocess.run(
            ["bash", "-c", tag_step["run"]],
            cwd=release_repo,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    valid_release_result = run_tag_step("valid-release-output")
    assert valid_release_result.returncode == 0
    assert (tmp_path / "valid-release-output").read_text(encoding="utf-8") == (
        f"publish=true\ntag=v1.2.3\nprepared-sha={tag_sha}\nversion=1.2.3\n"
    )

    mismatched_release_result = run_tag_step(
        "mismatched-release-output",
        UPSTREAM_HEAD_SHA="0" * 40,
    )
    assert mismatched_release_result.returncode == 0
    assert (tmp_path / "mismatched-release-output").read_text(encoding="utf-8") == (
        "publish=false\n"
    )

    manual_release_result = run_tag_step(
        "manual-release-output",
        GITHUB_EVENT_NAME="workflow_dispatch",
        INPUT_TAG="v1.2.3",
        UPSTREAM_EVENT="",
        UPSTREAM_HEAD_SHA="",
        UPSTREAM_PUBLISHED="",
        UPSTREAM_TAG="",
    )
    assert manual_release_result.returncode == 0
    assert (tmp_path / "manual-release-output").read_text(encoding="utf-8") == (
        f"publish=true\ntag=v1.2.3\nprepared-sha={tag_sha}\nversion=1.2.3\n"
    )

    manual_source_step = next(
        step
        for step in prepare_job["steps"]
        if step.get("name") == "Verify manual retry source"
    )
    assert manual_source_step["if"] == (
        "github.event_name == 'workflow_dispatch' && steps.tag.outputs.publish == 'true'"
    )
    assert manual_source_step["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "RELEASE_SHA": "${{ steps.tag.outputs.prepared-sha }}",
        "RELEASE_TAG": "${{ steps.tag.outputs.tag }}",
    }
    manual_source_script = manual_source_step["run"]
    assert 'current_sha="$(git rev-parse "HEAD^{commit}")"' in manual_source_script
    assert 'git merge-base --is-ancestor "$RELEASE_SHA" "$master_sha"' in manual_source_script
    assert "gh run list" in manual_source_script
    assert "--workflow release.yml" in manual_source_script
    assert '--branch "$RELEASE_TAG"' in manual_source_script
    assert '--commit "$RELEASE_SHA"' in manual_source_script
    assert '--event push' in manual_source_script
    assert 'publish to PyPI (OIDC)' in manual_source_script

    manual_shim_dir = tmp_path / "manual-bin"
    manual_shim_dir.mkdir()
    manual_gh_shim = manual_shim_dir / "gh"
    manual_gh_shim.write_text(
        """#!/usr/bin/env bash
if [ "$1" = "run" ] && [ "$2" = "list" ]; then
  printf '%s\n' "2468"
elif [ "$1" = "api" ]; then
  printf '%s\n' "${FAKE_PUBLISH_COUNT:-0}"
else
  exit 2
fi
""",
        encoding="utf-8",
    )
    manual_gh_shim.chmod(0o755)

    def run_manual_source(publish_count: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-c", manual_source_script],
            cwd=release_repo,
            env={
                **os.environ,
                "FAKE_PUBLISH_COUNT": publish_count,
                "GH_TOKEN": "unused",
                "GITHUB_REPOSITORY": "example/agent-guard",
                "PATH": f"{manual_shim_dir}:{os.environ['PATH']}",
                "RELEASE_SHA": tag_sha,
                "RELEASE_TAG": "v1.2.3",
            },
            capture_output=True,
            text=True,
            check=False,
        )

    assert run_manual_source("1").returncode == 0
    rejected_manual_source = run_manual_source("0")
    assert rejected_manual_source.returncode == 1
    assert "matching successful tag-push PyPI publication" in rejected_manual_source.stdout

    pypi_step = next(
        step
        for step in prepare_job["steps"]
        if step.get("name") == "Verify published PyPI version"
    )
    assert pypi_step["if"] == "steps.tag.outputs.publish == 'true'"
    assert pypi_step["env"] == {
        "RELEASE_VERSION": "${{ steps.tag.outputs.version }}"
    }
    assert "--expect-present" in pypi_step["run"]
    assert '--version "$RELEASE_VERSION"' in pypi_step["run"]
    assert "for attempt in {1..5}" in pypi_step["run"]
    assert "sleep 10" in pypi_step["run"]

    detach_step = next(
        step
        for step in prepare_job["steps"]
        if step.get("name") == "Detach checkout to release commit"
    )
    extract_step = next(
        step
        for step in prepare_job["steps"]
        if step.get("name") == "Extract release notes"
    )
    assert detach_step["env"] == {
        "RELEASE_SHA": "${{ steps.tag.outputs.prepared-sha }}"
    }
    assert detach_step["run"] == 'git checkout --detach "$RELEASE_SHA"'
    assert prepare_job["steps"].index(pypi_step) < prepare_job["steps"].index(detach_step)
    assert prepare_job["steps"].index(detach_step) < prepare_job["steps"].index(extract_step)

    upload_steps = [
        step
        for step in prepare_job["steps"]
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert len(upload_steps) == 1
    assert re.fullmatch(r"actions/upload-artifact@[0-9a-f]{40}", upload_steps[0]["uses"])
    assert upload_steps[0]["if"] == "steps.tag.outputs.publish == 'true'"
    assert upload_steps[0]["with"] == {
        "name": "release-notes",
        "path": "release-notes.md",
        "if-no-files-found": "error",
        "retention-days": 1,
    }

    download_steps = [
        step
        for step in release_job["steps"]
        if str(step.get("uses", "")).startswith("actions/download-artifact@")
    ]
    assert len(download_steps) == 1
    assert re.fullmatch(
        r"actions/download-artifact@[0-9a-f]{40}", download_steps[0]["uses"]
    )
    assert download_steps[0]["with"] == {"name": "release-notes", "path": "."}

    token_steps = [
        step for step in release_job["steps"] if step.get("env", {}).get("GH_TOKEN")
    ]
    assert len(token_steps) == 1
    assert token_steps[0]["name"] == "Create or update GitHub release"
    assert token_steps[0]["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "PREPARED_SHA": "${{ needs.prepare-github-release.outputs.prepared-sha }}",
        "TAG_NAME": "${{ needs.prepare-github-release.outputs.tag }}",
    }
    assert '[[ ! "$PREPARED_SHA" =~ ^[0-9a-f]{40}$ ]]' in token_steps[0]["run"]
    assert 'gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${TAG_NAME}"' in token_steps[0]["run"]
    assert 'gh api "repos/${GITHUB_REPOSITORY}/git/tags/${object_sha}"' in token_steps[0]["run"]
    assert '[ "$object_type" != "commit" ] || [ "$object_sha" != "$PREPARED_SHA" ]' in token_steps[0]["run"]
    assert "--verify-tag" in token_steps[0]["run"]

    gh_log = tmp_path / "publish-gh.log"
    release_marker = tmp_path / "release-mutated"
    annotated_tag_sha = "1" * 40
    wrong_commit_sha = "2" * 40
    publish_shim_dir = tmp_path / "publish-bin"
    publish_shim_dir.mkdir()
    publish_gh_shim = publish_shim_dir / "gh"
    publish_gh_shim.write_text(
        f"""#!/usr/bin/env bash
printf '%s\\n' "$*" >> "{gh_log}"
if [ "$1" = "api" ]; then
  case "$2" in
    repos/example/agent-guard/git/ref/tags/v1.2.3)
      printf '%s\\n' "tag {annotated_tag_sha}"
      ;;
    repos/example/agent-guard/git/tags/{annotated_tag_sha})
      printf '%s\\n' "commit {wrong_commit_sha}"
      ;;
    *)
      exit 2
      ;;
  esac
elif [ "$1" = "release" ]; then
  touch "{release_marker}"
  exit 0
else
  exit 2
fi
""",
        encoding="utf-8",
    )
    publish_gh_shim.chmod(0o755)
    publish_result = subprocess.run(
        ["bash", "-c", token_steps[0]["run"]],
        env={
            **os.environ,
            "GH_TOKEN": "unused",
            "GITHUB_REPOSITORY": "example/agent-guard",
            "PATH": f"{publish_shim_dir}:{os.environ['PATH']}",
            "PREPARED_SHA": tag_sha,
            "TAG_NAME": "v1.2.3",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert publish_result.returncode == 1
    publish_output = publish_result.stdout + publish_result.stderr
    assert "release tag does not match prepared commit" in publish_output
    assert tag_sha not in publish_output
    assert wrong_commit_sha not in publish_output
    assert not release_marker.exists()
    assert "release view" not in gh_log.read_text(encoding="utf-8")
