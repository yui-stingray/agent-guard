# Releases

Release, publication, and attestation-verification notes. Release timing is
governed by [`release-criteria.md`](release-criteria.md).

Tag-driven. Pushing a `vX.Y.Z` version tag triggers
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which first
verifies that the tag matches `[project].version` in `pyproject.toml`, checks
that the version is not already present on PyPI, then builds the sdist + wheel
and publishes to PyPI via Trusted Publishing (OIDC). No maintainer-side PyPI
token is required once the PyPI project environment is configured. Manual
`workflow_dispatch` with `publish=false` is a build-only dry run; it skips the
publish job. Manual `publish=true` must be run against a `v*` tag ref; running
it from a branch fails before build.

The follow-up GitHub Release workflow publishes automatically only after the
upstream PyPI job succeeds, the tag resolves to that run's commit on protected
`master` history, and PyPI exposes exactly the expected non-yanked wheel and
sdist for the version. A manual GitHub Release retry must run from the current
default branch and requires a matching successful tag-push PyPI publication.

After the release build passes its contract checks, a separate least-privilege
job creates GitHub artifact attestations for the generated `dist/*` wheel and
sdist before the publish job runs. PyPI Trusted
Publishing and the PyPA publish action provide PyPI-side distribution
attestations for the uploaded files. These attestations are provenance metadata
and integrity evidence for a specific artifact and workflow identity; they are
not proof of code correctness, dependency safety, maintainer approval, or
absence of secrets.

To verify the GitHub provenance for a downloaded release artifact, install the
GitHub CLI and check the tag, repository, and signer workflow explicitly:

```bash
(
set -euo pipefail
verify_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-guard-dist-verify.XXXXXX")"
trap 'rm -rf -- "$verify_dir"' EXIT
python - "$verify_dir" <<'PY'
import json
import shutil
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

version = "0.3.10"
target = Path(sys.argv[1])
request_timeout_seconds = 20
metadata_url = f"https://pypi.org/pypi/yui-agent-guard/{version}/json"
with urllib.request.urlopen(metadata_url, timeout=request_timeout_seconds) as response:
    final_metadata_url = urlparse(response.geturl())
    if final_metadata_url.scheme != "https" or final_metadata_url.hostname != "pypi.org":
        raise SystemExit("PyPI release metadata URL is not an expected HTTPS host")
    release = json.load(response)
if not isinstance(release, dict):
    raise SystemExit("PyPI release metadata is malformed")
expected = {
    f"yui_agent_guard-{version}-py3-none-any.whl": "bdist_wheel",
    f"yui_agent_guard-{version}.tar.gz": "sdist",
}
files = release.get("urls")
if not isinstance(files, list) or len(files) != len(expected):
    raise SystemExit("PyPI release does not contain the exact expected artifact set")
by_name = {}
for file_info in files:
    if not isinstance(file_info, dict):
        raise SystemExit("PyPI release metadata is malformed")
    filename = file_info.get("filename")
    url = file_info.get("url")
    if (
        not isinstance(filename, str)
        or filename not in expected
        or file_info.get("packagetype") != expected[filename]
        or file_info.get("yanked") is not False
        or not isinstance(url, str)
    ):
        raise SystemExit("PyPI release metadata does not match the expected artifact contract")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org":
        raise SystemExit("PyPI release artifact URL is not an expected HTTPS host")
    if filename in by_name:
        raise SystemExit("PyPI release metadata contains duplicate artifacts")
    by_name[filename] = url
if set(by_name) != set(expected):
    raise SystemExit("PyPI release does not contain the exact expected artifact set")
for filename in sorted(expected):
    with urllib.request.urlopen(
        by_name[filename], timeout=request_timeout_seconds
    ) as response:
        final_artifact_url = urlparse(response.geturl())
        if (
            final_artifact_url.scheme != "https"
            or final_artifact_url.hostname != "files.pythonhosted.org"
        ):
            raise SystemExit("Downloaded artifact URL is not an expected HTTPS host")
        with (target / filename).open("xb") as destination:
            shutil.copyfileobj(response, destination)
PY
gh attestation verify "$verify_dir/yui_agent_guard-0.3.10-py3-none-any.whl" \
  --repo yui-stingray/agent-guard \
  --signer-workflow yui-stingray/agent-guard/.github/workflows/release.yml \
  --source-ref refs/tags/v0.3.10
gh attestation verify "$verify_dir/yui_agent_guard-0.3.10.tar.gz" \
  --repo yui-stingray/agent-guard \
  --signer-workflow yui-stingray/agent-guard/.github/workflows/release.yml \
  --source-ref refs/tags/v0.3.10
)
```
