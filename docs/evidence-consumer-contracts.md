# Evidence Consumer Contracts

These examples show downstream CI jobs that consume `agent-guard` evidence
without adding new detection logic. They reuse the packaged report consumer,
`report`, `render-report`, `conformance check`, and `evidence-pack manifest`
commands.

The runnable script is
[`examples/evidence_contracts_ci.sh`](../examples/evidence_contracts_ci.sh).
Run it from the repository root after the repo has reviewed `.agent-guard`
policies.

## Fail-Closed Evidence Consumer

Use this on a job that consumes a committed, downloaded, or previously
generated sanitized report. The job fails when the report is missing, invalid,
unsanitized, or stale relative to the current checkout.

```yaml
permissions:
  contents: read

jobs:
  consume-agent-guard-evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - run: python -m pip install yui-agent-guard
      - name: Consume sanitized evidence
        run: sh examples/evidence_contracts_ci.sh consume
```

`consume` first runs the packaged validator with
`python -m agent_guard.consumer .agent-guard/evidence/agent-guard-report.json`.
It then copies the consumed report, regenerates the canonical recommended
report with the current checkout, validates the regenerated report, and compares
the two files. A mismatch means the consumed report is stale and the job exits
`1`. If the regenerated report itself exits non-zero because current static
evidence has findings, the job also fails closed.

## Public Artifact Lint

Use this before uploading evidence as a public artifact. It validates the
sanitized JSON report, renders Markdown, SARIF, and GitHub annotations from
that same report, and rejects unexpected files in `.agent-guard/evidence/`.

```yaml
      - name: Lint public evidence artifacts
        run: sh examples/evidence_contracts_ci.sh lint-public
      - name: Upload public evidence
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: agent-guard-evidence
          path: .agent-guard/evidence/
          if-no-files-found: error
```

The allow-list is intentionally narrow: report JSON, rendered Markdown, rendered
SARIF, rendered annotations, conformance JSON, evidence-pack JSON, and surface
inventory JSON. Raw scanner JSON such as `context.json`, `mcp.json`, or
`workflow.json` should stay in temporary CI storage unless a maintainer reviews
that exact output.

## Strict Release Gate

Use this on a release candidate after the repository has reviewed digest policy
coverage and wants strict conformance to be part of the release evidence.

```yaml
permissions:
  contents: read

jobs:
  strict-agent-guard-release-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - run: python -m pip install yui-agent-guard
      - name: Strict release gate
        run: sh examples/evidence_contracts_ci.sh strict-release
```

`strict-release` regenerates the recommended evidence preset with
`.agent-guard/context-digest-policy.yaml`, embeds strict conformance in the
report, validates the report with the packaged consumer, writes a strict
`agent-guard-conformance.json`, writes an evidence-pack manifest, and then runs
the public artifact lint step. Missing digest/context-lock evidence, missing
evidence-pack report artifacts, strict MCP risk metadata, invalid reports, or
unexpected public artifacts fail the job.

## Configuration

The script defaults are suitable for a single-root repository:

```text
AGENT_GUARD_ROOT=.
AGENT_GUARD_EVIDENCE_DIR=.agent-guard/evidence
AGENT_GUARD_REPORT_JSON=.agent-guard/evidence/agent-guard-report.json
AGENT_GUARD_BIN=agent-guard
PYTHON_BIN=python
```

Set those environment variables for monorepos or source-tree smoke tests. For
example, the test suite runs the same script with
`AGENT_GUARD_BIN="python -m agent_guard.cli"` so the example exercises the
source checkout instead of an installed console script.

These examples remain static evidence consumers. They do not execute MCP
servers, validate live OAuth flows, detect runtime prompt/tool poisoning, scan
for arbitrary credentials, publish comments, approve releases, or change GitHub
state.
