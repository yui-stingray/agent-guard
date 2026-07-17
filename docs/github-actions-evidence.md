# GitHub Actions Evidence

`agent-guard report` can produce two CI-friendly surfaces:

- artifacts for reviewer inspection;
- GitHub workflow annotations for inline failure anchors.

It does not post pull request comments, call an LLM reviewer, or make merge
decisions. The packaged Action is an alpha, static-only evidence surface.
Maintainers should treat the output as deterministic evidence.

## Recommended Action Workflow

After `agent-guard init --root . --write` has created reviewed `.agent-guard`
policies, the root GitHub Action runs the recommended evidence preset and
exposes the generated report paths as action outputs:

```yaml
permissions:
  contents: read

jobs:
  agent-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - id: agent-guard
        uses: yui-stingray/agent-guard@v0.3.1
        with:
          conformance-profile: recommended
      - name: Upload evidence
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: agent-guard-evidence
          path: ${{ steps.agent-guard.outputs.evidence-dir }}/
          if-no-files-found: error
```

The action keeps per-scanner JSON in temporary runner storage so scanner
diagnostics do not appear in workflow logs or uploaded public artifacts. Raw
scanner JSON may include scanner-specific metadata or policy diagnostics
depending on the scanner, so do not upload it publicly unless a maintainer has
reviewed that exact output. The uploadable files from the packaged action are
the sanitized report, SARIF report, recursively sanitized surface inventory,
conformance result, and evidence-pack manifest. Markdown, SARIF, and GitHub
annotations are rendered from the same sanitized JSON report instead of
rerunning the full report scan. GitHub annotations can be disabled with
`github-annotations: "false"`.

The recommended report preset includes static MCP configuration evidence and
fails on malformed committed MCP config files or deterministic risky MCP
configuration metadata. Set `conformance-profile: strict` only when the
repository also wants those v2 surface inventory labels to appear as conformance
findings. Neither mode executes MCP servers, inspects MCP tool results, or acts
as a runtime MCP tool-poisoning detector or live OAuth validator. The packaged
action always generates the recommended evidence preset; use the CLI commands in
[`docs/quickstart-existing-repo.md`](quickstart-existing-repo.md) for a
minimal-first pass before adopting the action. The action expects the reviewed
repo-local `.agent-guard/mcp-policy.yaml` for recommended evidence. Set
`mcp-policy` only for scanner experiments or local migration checks; an external
policy path is reported as `<external-policy>` and does not satisfy recommended
or strict conformance.

Recommended evidence is the default reviewed static baseline. It leaves
repository-specific digest and context-lock pinning optional unless the digest
policy file exists; use `conformance-profile: strict` when digest/context-lock
evidence, sanitized evidence-pack expectations, and v2 MCP risk metadata should
all be required conformance evidence.

If the reviewed MCP policy is missing, the action still renders uploadable
artifacts and then exits non-zero. Read the JSON report's `mcp_config` section
and the conformance artifact for controlled findings such as
`mcp_policy_missing`, `required_mcp_policy_not_reviewed`, or
`mcp_policy_weakened`. Fix those by committing a reviewed repo-local
`.agent-guard/mcp-policy.yaml` with the default risk-label set, not by pointing
recommended evidence at an external policy file.

For monorepos or repositories where the reviewed agent-maintained project lives
in a subdirectory, set `root` to that project root. Policy and evidence paths are
resolved relative to that root unless they are absolute paths:

```yaml
      - id: agent-guard
        uses: yui-stingray/agent-guard@v0.3.1
        with:
          root: services/api
          conformance-profile: recommended
```

When a pull request should surface guard policy or workflow changes relative
to its base branch, fetch the base ref and pass it explicitly:

```yaml
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - id: agent-guard
        uses: yui-stingray/agent-guard@v0.3.1
        with:
          base-ref: origin/${{ github.base_ref }}
```

The `base-ref` input only adds sanitized review evidence for changed
`.agent-guard` policies, digest policies, guard workflows, action metadata, or
pre-commit hook metadata. It does not approve, reject, or enforce GitHub branch
protection, and it does not publish raw diffs, hash values, raw workflow
bodies, branch names, or local paths.

## Surface Delta Evidence On Pull Requests

Set `surface-delta-base-ref` to embed sanitized PR agent-surface delta
evidence: which agent-facing surfaces (context files, skills, MCP servers,
workflows, policies, hooks) were added, removed, or modified relative to the
merge base of the supplied ref and `HEAD`. This avoids reporting additions made
only on an advanced base branch as PR removals. This is deterministic review
evidence, not a gate. It is never emitted to SARIF and does not fail the job by
itself.

This Action input is available in `v0.3.0`.

Fetch the base ref explicitly before running the action, the same way
`base-ref` requires it:

```yaml
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - id: agent-guard
        uses: yui-stingray/agent-guard@v0.3.1
        with:
          conformance-profile: recommended
          surface-delta-base-ref: origin/${{ github.base_ref }}
```

For a pull request event, the exact base commit is also available as
`${{ github.event.pull_request.base.sha }}`. Fetch it first, then pass it as a
stable merge-base anchor instead of a branch name that can move:

```yaml
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - name: Fetch PR base commit
        run: git fetch origin ${{ github.event.pull_request.base.sha }} --depth=1
      - id: agent-guard
        uses: yui-stingray/agent-guard@v0.3.1
        with:
          conformance-profile: recommended
          surface-delta-base-ref: ${{ github.event.pull_request.base.sha }}
```

Auto-detecting the base ref from the `pull_request` event and fetching it
automatically is intentionally out of scope for this alpha surface; the caller
always fetches and passes the ref explicitly, matching `base-ref`. Read the
`surface_delta` section of the JSON report or the `## Surface Delta Evidence`
Markdown heading for `added`/`removed`/`modified` counts and a sanitized
per-surface entry list with controlled-vocabulary `changed_fields` names (no
values) and risk labels. It never includes the base ref name, raw diffs, MCP
args/env values, or instruction/description text.

## Expanded Workflow Step

Use this form when a repository wants the commands visible in workflow review
instead of using the packaged composite action. The example mirrors the
recommended static baseline after `agent-guard init --root . --write`; add
`--digest-policy .agent-guard/context-digest-policy.yaml` only after generating
and reviewing that digest policy file.

```yaml
permissions:
  contents: read

jobs:
  agent-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - name: Install agent-guard
        run: python -m pip install yui-agent-guard
      - name: Generate evidence
        run: |
          set +e
          status=0
          record_status() {
            code="$1"
            if [ "$code" -ge 2 ] || { [ "$code" -ne 0 ] && [ "$status" -eq 0 ]; }; then
              status="$code"
            fi
          }
          mkdir -p .agent-guard/evidence
          raw_parent="${RUNNER_TEMP:-/tmp}"
          mkdir -p "$raw_parent"
          raw_dir="$(mktemp -d "$raw_parent/agent-guard-raw.XXXXXX")"
          trap 'rm -rf "$raw_dir"' EXIT
          agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json > "$raw_dir/context.json"
          record_status "$?"
          agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json > .agent-guard/evidence/agent-surface-inventory.json
          record_status "$?"
          agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json > "$raw_dir/mcp.json"
          record_status "$?"
          agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json > "$raw_dir/workflow.json"
          record_status "$?"
          agent-guard drift check --root . --profile recommended --schema-version v2 --json > "$raw_dir/drift.json"
          record_status "$?"
          agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --conformance-profile recommended --format json --output .agent-guard/evidence/agent-guard-report.json
          record_status "$?"
          agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format markdown --output .agent-guard/evidence/agent-guard-report.md
          record_status "$?"
          agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format sarif --output .agent-guard/evidence/agent-guard-results.sarif
          record_status "$?"
          agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json --profile recommended --json > .agent-guard/evidence/agent-guard-conformance.json
          record_status "$?"
          agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json --artifact .agent-guard/evidence/agent-guard-report.json --agent-policy-audit-event .agent-guard/evidence/policy-admission-event.json --json > .agent-guard/evidence/agent-guard-evidence-pack.json
          record_status "$?"
          agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format github-annotations
          record_status "$?"
          exit "$status"
      - name: Upload evidence
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: agent-guard-evidence
          path: .agent-guard/evidence/
          if-no-files-found: error
```

Pin third-party actions to commit SHAs if that is required by the repository's
supply-chain policy.

## Optional SARIF Upload

If the repository uses GitHub code scanning, upload the SARIF file in a
separate step. This requires `security-events: write`; keep the base evidence
workflow read-only when code scanning is not used.

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: yui-stingray/agent-guard@v0.3.1
    id: agent-guard
  - name: Upload SARIF
    if: always()
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: ${{ steps.agent-guard.outputs.report-sarif }}
      category: agent-guard
```

The SARIF file uses repository-relative paths and omits snippets, raw context
text, raw workflow commands, raw repository/content/digest hashes, secrets, and
absolute local paths. It may include SARIF `partialFingerprints` derived only
from sanitized rule, location, and message metadata for code-scanning
deduplication.

## How Maintainers Should Read It

Use the Markdown artifact for a short human review and the sanitized report
JSON artifact for automation, downstream conformance checks, or evidence-pack
manifests. The JSON report follows
`agent-guard.report_evidence.v1` inside the shared `agent-guard.result.v1`
envelope and includes `surface_inventory` plus `evidence_coverage` on
success/violation payloads. When `--conformance-profile` and
`--evidence-pack-manifest` are enabled, it also includes `conformance` and
`evidence_pack_manifest` sections. `--evidence-preset recommended` enables
those recommended report surfaces plus static MCP configuration evidence while
leaving repository-specific API and digest policies opt-in.

Automation that consumes the JSON report should fail closed on schema drift,
missing `surface_inventory`, missing `evidence_coverage`, inconsistent finding
or gate counts, unexplained top-level `status` values, non-sanitized report
metadata, unexpected conformance profiles, and forbidden public-evidence
fragments such as snippets, token-shaped strings, hash values, or absolute
local paths. Use the report as reviewer evidence, not
as proof that runtime prompt injection, MCP tool poisoning, live OAuth flows,
or secrets are safe. The boundary is summarized in
[`docs/threat-model.md`](threat-model.md), and
[`examples/evidence_consumer.py`](../examples/evidence_consumer.py) shows a
minimal fail-closed consumer. For runnable CI examples that also reject missing
or stale reports, lint public artifact names, and run strict release
conformance, see
[`docs/evidence-consumer-contracts.md`](evidence-consumer-contracts.md).

GitHub annotations are intentionally quiet on clean runs. On failures, they
contain only controlled scanner metadata such as scanner name, rule id, file,
line, category, status, reason, and OWASP risk-theme labels when a deterministic
rule maps to them. They do not include raw context text, matched snippets, hash
values, workflow run bodies, secrets, or absolute local paths.

## Failure Policy

The report command exits `1` when any enabled static gate finds drift or a
violation. That should fail the workflow. Prefer fixing the policy, context
file, digest pin, workflow drift, or README/policy drift instead of bypassing
the job.

The workflow snippet keeps generating all evidence surfaces after the first
non-zero report result, then exits with the captured failure status. The upload
step uses `if: always()` so reviewers can inspect artifacts on failing runs.

If a repository wants pull request comments, build that as a separate reviewed
wrapper that consumes the JSON artifact. Keep comments sanitized and avoid
posting local diagnostics or private data.
