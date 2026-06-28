# GitHub Actions Evidence

`agent-guard report` can produce two CI-friendly surfaces:

- artifacts for reviewer inspection;
- GitHub workflow annotations for inline failure anchors.

It does not post pull request comments, call an LLM reviewer, or make merge
decisions. Maintainers should treat the output as deterministic evidence.

## Minimal Workflow Step

```yaml
permissions:
  contents: read

jobs:
  agent-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
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
          agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json > .agent-guard/evidence/agent-surface-inventory.json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard drift check --root . --profile recommended --schema-version v2 --json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --digest-policy .agent-guard/context-digest-policy.yaml --format markdown --output .agent-guard/evidence/agent-guard-report.md
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --digest-policy .agent-guard/context-digest-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json --profile recommended --json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json --artifact .agent-guard/evidence/agent-guard-report.json --agent-policy-audit-event .agent-guard/evidence/policy-admission-event.json --json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --digest-policy .agent-guard/context-digest-policy.yaml --format github-annotations
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

## How Maintainers Should Read It

Use the Markdown artifact for a short human review and the JSON artifact for
automation, downstream conformance checks, or evidence-pack manifests. The JSON report follows
`agent-guard.report_evidence.v1` inside the shared `agent-guard.result.v1`
envelope and includes `surface_inventory` plus `evidence_coverage` on
success/violation payloads. When `--conformance-profile` and
`--evidence-pack-manifest` are enabled, it also includes `conformance` and
`evidence_pack_manifest` sections. `--evidence-preset recommended` enables
those recommended report surfaces while leaving repository-specific API and
digest policies opt-in.

GitHub annotations are intentionally quiet on clean runs. On failures, they
contain only controlled scanner metadata such as scanner name, rule id, file,
line, category, status, or reason. They do not include raw context text, matched
snippets, hash values, workflow run bodies, secrets, or absolute local paths.

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
