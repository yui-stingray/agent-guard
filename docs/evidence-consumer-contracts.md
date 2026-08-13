# Evidence Consumer Contracts

These examples show downstream CI jobs that consume `agent-guard` evidence
without adding new detection logic. They reuse the packaged report consumer,
`report`, `render-report`, `conformance check`, and `evidence-pack manifest`
commands.

The runnable script is
[`examples/evidence_contracts_ci.sh`](../examples/evidence_contracts_ci.sh).
Run it from the repository root after the repo has reviewed `.agent-guard`
policies.

The copyable shell consumer requires a POSIX host. The packaged Python consumer
remains available wherever the Python CLI is supported; the shell wrapper's
host constraint is not a restriction on repository languages or scanned file
content.

## Fail-Closed Evidence Consumer

Use this on a job that consumes a committed, downloaded, or previously
generated sanitized report. The job fails when the report is missing, invalid,
unsanitized, or differs from the report-visible sanitized state of the current
checkout.

```yaml
permissions:
  contents: read

jobs:
  consume-agent-guard-evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
        with:
          persist-credentials: false
      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
        with:
          python-version: "3.12"
      - run: python -m pip install yui-agent-guard==0.3.5
      - name: Consume sanitized evidence
        run: sh examples/evidence_contracts_ci.sh consume
```

`consume` first runs the packaged bundle validator so the fixed seven-name
public-artifact allow-list and per-artifact byte limits apply before report-only
validation or digest inspection. It then runs the compatible report-only
validator, creates a same-device backup outside the selected
scan root, and moves the whole directory into that backup before regeneration
and comparison; it does not copy the consumed report. The script regenerates
the canonical recommended report with the current checkout, validates it, and
compares it with the backed-up original. A mismatch means the consumed report is
stale for a field exposed by the sanitized report and the job exits `1`. If the
regenerated report itself exits non-zero because current static evidence has
findings, the job also fails closed.

Transaction moves use rename-only filesystem semantics. They never fall back to
copy/delete; an `EXDEV` boundary fails closed and leaves the original directory
authoritative.

From the whole-directory rename until restoration completes, the normal evidence
directory is not a stable consumable artifact: it can be temporarily absent or
hold regenerated or partial evidence. Do not concurrently consume or publish it;
the original consumed bundle is available there only after `consume` exits with
restoration complete. The script attempts that restoration after comparison and
on ordinary failure or catchable `HUP`, `INT`, or `TERM` signals. If restoration
cannot complete, it fails and retains the backup for manual recovery. `SIGKILL`,
runner power loss, and filesystem failure can prevent or interrupt the trap, so
automatic restoration and normal-directory availability are not guaranteed in
those cases.

This comparison is not a whole-tree, commit-identity, or arbitrary file-content
binding. Surface inventory metadata intentionally represents public artifacts by
sanitized fields such as path, kind, status, and size; a same-size content edit
that changes no scanner result can therefore remain outside this comparison.
Use version-control provenance, release attestations, and reviewed digest policy
when exact content identity is required. Do not add raw repository hashes or
local paths to a public evidence report to compensate for that boundary.

## Public Artifact Lint

Use this before uploading evidence as a public artifact. It validates the
sanitized JSON report, renders Markdown, SARIF, and GitHub annotations from
that same report, and rejects unexpected files in `.agent-guard/evidence/`.

```yaml
      - name: Lint public evidence artifacts
        id: lint-agent-guard-evidence
        run: sh examples/evidence_contracts_ci.sh lint-public
      - name: Upload public evidence
        if: steps.lint-agent-guard-evidence.outcome == 'success'
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: agent-guard-evidence
          path: |
            .agent-guard/evidence/agent-guard-report.json
            .agent-guard/evidence/agent-guard-report.md
            .agent-guard/evidence/agent-guard-results.sarif
            .agent-guard/evidence/agent-guard-annotations.txt
            .agent-guard/evidence/agent-guard-conformance.json
            .agent-guard/evidence/agent-guard-evidence-pack.json
            .agent-guard/evidence/agent-surface-inventory.json
          if-no-files-found: error
```

The allow-list is intentionally narrow: report JSON, rendered Markdown, rendered
SARIF, rendered annotations, conformance JSON, evidence-pack JSON, and surface
inventory JSON. Raw scanner JSON such as `context.json`, `mcp.json`, or
`workflow.json` should stay in temporary CI storage unless a maintainer reviews
that exact output.

`lint-public` delegates this bundle check to the installed package:

```text
python -I -m agent_guard.consumer --evidence-dir .agent-guard/evidence \
  .agent-guard/evidence/agent-guard-report.json
```

The report-only invocation remains available for consumers that download just
the canonical JSON report. Bundle mode additionally rejects non-allowlisted or
non-regular entries and validates the optional rendered and standalone public
artifacts against the selected report. Every standalone envelope must carry the
same tool identity as that report. Surface-inventory policy metadata must match
the report policy, conformance and evidence-pack policy metadata must identify
the report artifact claimed by the embedded manifest or use the controlled
`<external-policy>` sentinel for runner-external staging, and a standalone
evidence-pack manifest must exactly match the embedded manifest. This validation
is location-independent so a downloaded bundle can be checked after relocation;
use `consume` when the current checkout also needs a stale-report comparison.
Directory enumeration is incremental and stops on the first entry beyond the
seven-name limit instead of materializing an unbounded name list.

Report-only mode and every JSON artifact parsed in bundle mode reject duplicate
object member names at any nesting depth before semantic validation. Duplicate
failures use a stable sanitized error and do not include the member name, value,
or JSON path. `report --output` and `render-report --output` write UTF-8 bytes
with LF line endings on every platform for canonical JSON, Markdown, SARIF, and
GitHub annotations. Bundle validation compares rendered artifacts exactly; it
does not normalize CRLF or otherwise repair producer drift.

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
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
        with:
          persist-credentials: false
      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
        with:
          python-version: "3.12"
      - run: python -m pip install yui-agent-guard==0.3.5
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
`AGENT_GUARD_BIN="python -I -m agent_guard.cli"` so the example exercises the
source checkout instead of an installed console script.

For monorepos, run the consumer per reviewed project root instead of merging
multiple service reports into one public artifact. Keep `AGENT_GUARD_ROOT`,
`AGENT_GUARD_EVIDENCE_DIR`, and `AGENT_GUARD_REPORT_JSON` aligned to the same
selected root. A relative evidence directory is resolved from the selected root
and is rejected before mutation if it escapes that root or traverses a symlinked
component. Every `..` component is rejected, including one whose lexical
normalization would remain beneath the root. In `consume` mode, the report must
resolve beneath the selected evidence directory so stale or failed regeneration
can restore the bundle as a single transaction; an external report path is
rejected before mutation:

The location validation is check-then-use rather than an atomic filesystem
snapshot. Run it against a quiescent checkout without a concurrent writer.

```text
AGENT_GUARD_ROOT=services/api
AGENT_GUARD_EVIDENCE_DIR=.agent-guard/evidence
AGENT_GUARD_REPORT_JSON=services/api/.agent-guard/evidence/agent-guard-report.json
```

The stale-report check must regenerate evidence with the same selected root,
same reviewed repo-local policies, and same public artifact directory. A report
from `services/api` should not be consumed as evidence for `services/worker`,
and a repo-external MCP policy still cannot satisfy recommended or strict
reviewed-policy conformance. If a repository needs an aggregate status page,
publish a small wrapper summary that links to per-root sanitized reports instead
of uploading raw scanner JSON or concatenating service outputs.

These examples remain static evidence consumers. They do not execute MCP
servers, validate live OAuth flows, detect runtime prompt/tool poisoning, scan
for arbitrary credentials, publish comments, approve releases, or change GitHub
state.
