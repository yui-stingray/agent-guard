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
          status=0
          mkdir -p .agent-guard/evidence
          agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format markdown --output .agent-guard/evidence/agent-guard-report.md || status=$?
          agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json || status=$?
          agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format github-annotations || status=$?
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
automation or downstream conformance checks. The JSON report follows
`agent-guard.report_evidence.v1` inside the shared `agent-guard.result.v1`
envelope.

GitHub annotations are intentionally quiet on clean runs. On failures, they
contain only controlled scanner metadata such as scanner name, rule id, file,
line, category, status, or reason. They do not include raw context text, matched
snippets, hash values, workflow run bodies, secrets, or absolute local paths.

## Failure Policy

The report command exits `1` when any enabled static gate finds drift or a
violation. That should fail the workflow. Prefer fixing the policy, context
file, digest pin, or workflow drift instead of bypassing the job.

The workflow snippet keeps generating all evidence surfaces after the first
non-zero report result, then exits with the captured failure status. The upload
step uses `if: always()` so reviewers can inspect artifacts on failing runs.

If a repository wants pull request comments, build that as a separate reviewed
wrapper that consumes the JSON artifact. Keep comments sanitized and avoid
posting local diagnostics or private data.
