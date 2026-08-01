# GitHub Actions Evidence

`agent-guard report` can produce two CI-friendly surfaces:

- artifacts for reviewer inspection;
- GitHub workflow annotations for inline failure anchors.

It does not post pull request comments, call an LLM reviewer, or make merge
decisions. The packaged Action is an alpha, static-only evidence surface.
It currently requires a Linux runner. This wrapper constraint is separate from
the Python CLI's documented Windows support.
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
        with:
          persist-credentials: false
      - id: agent-guard
        uses: yui-stingray/agent-guard@v0.3.4
        with:
          conformance-profile: recommended
      - name: Upload evidence
        if: >-
          always() &&
          steps.agent-guard.outputs.ready == 'true' &&
          (steps.agent-guard.outputs.status == '0' || steps.agent-guard.outputs.status == '1')
        uses: actions/upload-artifact@v7
        with:
          name: agent-guard-evidence
          path: |
            ${{ steps.agent-guard.outputs.report-json }}
            ${{ steps.agent-guard.outputs.report-markdown }}
            ${{ steps.agent-guard.outputs.report-sarif }}
            ${{ steps.agent-guard.outputs.evidence-dir }}/agent-guard-conformance.json
            ${{ steps.agent-guard.outputs.evidence-dir }}/agent-guard-evidence-pack.json
            ${{ steps.agent-guard.outputs.evidence-dir }}/agent-surface-inventory.json
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

The Action sets `ready=true` only after the complete fresh bundle validates and
all path/status outputs have been recorded. Publication steps must require that
output; `status` alone is not a publication signal because an output append can
fail after exposing only a prefix of the path outputs. A fatal generation error
attempts to expose only the sanitized numeric `status=2` for diagnostics;
`ready` and every publication path output remain absent.

Before generation, an existing evidence directory is checked against the fixed
seven-name public-artifact allow-list and moved by whole-directory rename to a
same-device backup outside the scan root. The transaction uses rename-only
filesystem semantics; it does not fall back to copy/delete, and an `EXDEV`
boundary fails closed. Ordinary fatal failures and catchable
`HUP`, `INT`, or `TERM` signals run a restoration trap. `SIGKILL`, runner power
loss, and filesystem failure cannot run or guarantee that trap; `ready` remains
absent, and a backup that cannot be safely restored or removed is retained for
manual recovery rather than overwritten.

A relative `evidence-dir` is resolved from `root` and must stay beneath that
root without symlinked path components. The Action rejects an escaping or
symlink-redirected relative destination before it stages or writes evidence.
It also rejects every `..` component, even when lexical normalization would
remain beneath `root`; use the normalized root-relative path instead.
An explicit absolute destination remains a caller-selected external location.
This path check is not an atomic filesystem snapshot: a concurrent writer could
replace a component after validation. Run the Action in a trusted runner against
a quiescent checkout.

The normal packaged consumer command,
`python -I -m agent_guard.consumer --evidence-dir <dir> <report>`, prints its
compatible JSON validation summary. Adding `--emit-annotations` suppresses that
summary and emits only the exact canonical annotation bytes retained while the
same invocation validates the whole bundle. If the optional annotation artifact
is absent, the mode succeeds without writing annotation bytes.

Here, public-safe means sanitized under the declared
controlled-field/controlled-pattern contract. It is not a generic secret/PII
absence guarantee or a replacement for dedicated secret scanners. Review the
repository and the bounded output contract before publishing artifacts.

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
        uses: yui-stingray/agent-guard@v0.3.4
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
        uses: yui-stingray/agent-guard@v0.3.4
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
        uses: yui-stingray/agent-guard@v0.3.4
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
        uses: yui-stingray/agent-guard@v0.3.4
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

Use the workflow generated by `init` when a repository wants every command
visible in workflow review instead of using the packaged composite action. The
generated `.github/workflows/agent-guard.yml` is the canonical expanded form;
the complete YAML is deliberately not duplicated here because its staging,
validation, and upload contract must change atomically with the package.

```bash
agent-guard init --root . --print
agent-guard init --root . --write
git diff -- .agent-guard .github/workflows/agent-guard.yml
```

Review the printed plan before writing. If files already exist, resolve each
reported conflict instead of overwriting reviewed repository policy. Add
`--digest-policy .agent-guard/context-digest-policy.yaml` to the report command
only after generating and reviewing that digest policy file.

The generated workflow:

- runs the context, path, content, MCP, workflow, drift, report, surface
  inventory, render, conformance, and evidence-pack commands as the recommended
  static baseline;
- stages raw scanner JSON and public evidence in separate fresh directories
  under `RUNNER_TEMP`, removes the raw directory, and never treats a prior
  checkout `.agent-guard/evidence` directory as current output;
- requires exactly `agent-guard-report.json`, `agent-guard-report.md`,
  `agent-guard-results.sarif`, `agent-guard-conformance.json`,
  `agent-guard-evidence-pack.json`, and `agent-surface-inventory.json`, each a
  regular non-symlink file;
- runs `python -I -m agent_guard.consumer --evidence-dir --emit-annotations`
  over that complete bundle without importing checkout-provided Python modules,
  emits the exact canonical annotation bytes retained by that validation
  invocation, and never reopens the annotation path for publication;
- records the internal `evidence-dir` step output, sets
  `evidence_ready=true`, and writes `ready=true` last; it then uploads only
  the six explicit files when
  `if: always() && steps.generate-evidence.outputs.ready == 'true'`; and
- handles output setup failures by phase: before `evidence-dir` is recorded,
  cleanup removes incomplete public staging. After that output is recorded and
  `evidence_ready=true`, a failure to append `ready=true` preserves the
  validated fresh bundle, but leaves `ready` absent so the ready-gated upload
  cannot publish it.

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
  - uses: yui-stingray/agent-guard@v0.3.4
    id: agent-guard
  - name: Upload SARIF
    if: >-
      always() &&
      steps.agent-guard.outputs.ready == 'true' &&
      (steps.agent-guard.outputs.status == '0' || steps.agent-guard.outputs.status == '1')
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: ${{ steps.agent-guard.outputs.report-sarif }}
      category: agent-guard
```

The SARIF file uses repository-relative paths and omits snippets, raw context
text, raw workflow commands, raw repository/content/digest hashes, absolute
local paths, and secret-shaped values covered by the controlled public-artifact
contract. It may include SARIF `partialFingerprints` derived only from sanitized
rule, location, and message metadata for code-scanning deduplication.

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
values, workflow run bodies, absolute local paths, or secret-shaped values
covered by the controlled public-artifact contract.

## Failure Policy

The report command exits `1` when any enabled static gate finds drift or a
violation. That should fail the workflow. Prefer fixing the policy, context
file, digest pin, workflow drift, or README/policy drift instead of bypassing
the job.

The generated expanded workflow keeps generating controlled evidence surfaces
after the first status `1` finding, validates the fresh bundle, records its
publication outputs, and then exits `1`. Fatal setup/runtime errors (`>=2`) and
bundle validation failures remove incomplete staging and never publish
`evidence_ready`, so its ready-gated upload cannot use a prior or partial
directory.
If its `evidence-dir` output append fails, cleanup removes that staging
directory. Once `evidence-dir` is recorded, a later `ready=true` append failure
retains the validated bundle but leaves `ready` absent, so the upload remains
blocked.

The packaged Action applies the same ready-gated status `0`/`1` publication
boundary to its explicitly named public artifacts, but its transaction order is
different. It commits the validated fresh bundle before recording outputs. A
fatal generation error before that commit may expose only `status=2`, without
publication paths. If an output append fails after the commit, the validated
fresh bundle remains and a prefix of non-ready outputs may have been recorded,
but the Action withholds `ready=true`. Consumers and uploads must therefore gate
only on `ready == 'true'`; path outputs alone are not publication authority.
The shared status reducer preserves status `1` for reviewed policy violations
while allowing a later status `>=2` to dominate; fatal branches omit `ready`.

If a repository wants pull request comments, build that as a separate reviewed
wrapper that consumes the JSON artifact. Keep comments sanitized and avoid
posting local diagnostics or private data.
