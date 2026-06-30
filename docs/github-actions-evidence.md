# GitHub Actions Evidence

`agent-guard report` can produce two CI-friendly surfaces:

- artifacts for reviewer inspection;
- GitHub workflow annotations for inline failure anchors.

It does not post pull request comments, call an LLM reviewer, or make merge
decisions. Maintainers should treat the output as deterministic evidence.

## Minimal Action Workflow

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
        uses: yui-stingray/agent-guard@v0.1.17
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
scanner JSON may include raw snippets, matched URLs, configured patterns, or
other policy diagnostics depending on the scanner, so do not upload it publicly
unless a maintainer has reviewed that exact output. The uploadable files from
the packaged action are the sanitized report, SARIF report, surface inventory,
conformance result, and evidence-pack manifest. Markdown, SARIF, and GitHub
annotations are rendered from the same sanitized JSON report instead of
rerunning the full report scan. GitHub annotations can be disabled with
`github-annotations: "false"`.

The recommended report preset includes static MCP configuration evidence and
fails on malformed committed MCP config files or deterministic risky MCP
configuration metadata. Set `conformance-profile: strict` only when the
repository also wants those v2 surface inventory labels to appear as conformance
findings. Neither mode executes MCP servers, inspects MCP tool results, or acts
as a runtime MCP tool-poisoning detector or live OAuth validator.

When a pull request should surface guard policy or workflow changes relative
to its base branch, fetch the base ref and pass it explicitly:

```yaml
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - id: agent-guard
        uses: yui-stingray/agent-guard@v0.1.17
        with:
          base-ref: origin/${{ github.base_ref }}
```

The `base-ref` input only adds sanitized review evidence for changed
`.agent-guard` policies, digest policies, guard workflows, action metadata, or
pre-commit hook metadata. It does not approve, reject, or enforce GitHub branch
protection, and it does not publish raw diffs, hash values, raw workflow
bodies, branch names, or local paths.

## Expanded Workflow Step

Use this form when a repository wants the commands visible in workflow review
instead of using the packaged composite action.

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
          mkdir -p .agent-guard/evidence
          raw_parent="${RUNNER_TEMP:-/tmp}"
          mkdir -p "$raw_parent"
          raw_dir="$(mktemp -d "$raw_parent/agent-guard-raw.XXXXXX")"
          trap 'rm -rf "$raw_dir"' EXIT
          agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json > "$raw_dir/context.json"
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json > .agent-guard/evidence/agent-surface-inventory.json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard mcp check --root . --json > "$raw_dir/mcp.json"
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json > "$raw_dir/workflow.json"
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard drift check --root . --profile recommended --schema-version v2 --json > "$raw_dir/drift.json"
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --digest-policy .agent-guard/context-digest-policy.yaml --conformance-profile recommended --format json --output .agent-guard/evidence/agent-guard-report.json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format markdown --output .agent-guard/evidence/agent-guard-report.md
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format sarif --output .agent-guard/evidence/agent-guard-results.sarif
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json --profile recommended --json > .agent-guard/evidence/agent-guard-conformance.json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json --artifact .agent-guard/evidence/agent-guard-report.json --agent-policy-audit-event .agent-guard/evidence/policy-admission-event.json --json > .agent-guard/evidence/agent-guard-evidence-pack.json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format github-annotations
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
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
  - uses: yui-stingray/agent-guard@v0.1.17
    id: agent-guard
  - name: Upload SARIF
    if: always()
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: ${{ steps.agent-guard.outputs.report-sarif }}
      category: agent-guard
```

The SARIF file uses repository-relative paths and omits snippets, raw context
text, raw workflow commands, hashes, secrets, and absolute local paths.

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

## Parallel Step Support

GitHub Actions supports step-level `parallel`, `background`, `wait`,
`wait-all`, and `cancel` syntax. Use it only for independent guard commands
that do not write the same output file. Keep `agent-guard report`,
`agent-guard evidence-pack manifest`, and `actions/upload-artifact` in later
serial steps so the final evidence pack is produced after every input is
available.

If the repository runs `actionlint`, verify that the installed actionlint
version accepts the new syntax before committing a workflow that uses
`parallel`. Older actionlint versions can reject documented GitHub syntax. In
that case, keep the workflow serial or split checks into separate jobs with
`needs` for the final artifact step.
