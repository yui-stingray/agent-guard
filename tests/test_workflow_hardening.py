"""Regression tests for CI and release supply-chain hardening."""

from __future__ import annotations

import os
import re
import subprocess
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
    for version in ("3.11.4", "3.12", "3.13", "3.14"):
        assert f"'{version}'" in workflow
    assert "Replay 15-minute onboarding path" in workflow
    assert "--max-elapsed-ms 900000" in workflow


def test_ci_runs_packaged_action_consumer_smoke() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "name: packaged action smoke" in workflow
    assert "uses: ./" in workflow
    assert 'test "$ACTION_STATUS" = "0"' in workflow
    assert 'python -m agent_guard.consumer "$REPORT_JSON"' in workflow


def test_evidence_workflows_preserve_runtime_error_precedence() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    manual_workflow = (ROOT / "docs" / "github-actions-evidence.md").read_text(
        encoding="utf-8"
    )
    for text in (action, GITHUB_WORKFLOW, manual_workflow):
        assert HARD_ERROR_PRECEDENCE in text
        assert 'if [ "$code" -eq 2 ]' not in text

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
        "publish": "${{ steps.tag.outputs.publish }}",
        "tag": "${{ steps.tag.outputs.tag }}",
    }

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
        environment = {
            "GITHUB_EVENT_NAME": "workflow_run",
            "GITHUB_OUTPUT": str(output_path),
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
        "publish=true\ntag=v1.2.3\nversion=1.2.3\n"
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
        "publish=true\ntag=v1.2.3\nversion=1.2.3\n"
    )

    pypi_step = next(
        step
        for step in prepare_job["steps"]
        if step.get("name") == "Verify published PyPI version"
    )
    assert pypi_step["if"] == "steps.tag.outputs.publish == 'true'"
    assert "--expect-present" in pypi_step["run"]
    assert '--version "${{ steps.tag.outputs.version }}"' in pypi_step["run"]

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
        "TAG_NAME": "${{ needs.prepare-github-release.outputs.tag }}",
    }
    assert "--verify-tag" in token_steps[0]["run"]
