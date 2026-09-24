# Scanner reference

Per-scanner behavior, report details, packaged JSON schemas, and example
policies. The [README](../README.md#scanners) has the one-line summary of each scanner.

## Current scanners

### API guard

The API guard scans configured paths for URL/API endpoint references and
compares them against allow/deny regex lists. It is endpoint-pattern evidence
for repository architecture boundaries, not a live API client, API catalog,
credential scanner, or network monitor.

Typical use case:
- keep a CLI-first repository from silently drifting into direct inference API endpoint references

It returns:
- exit `0` on clean
- exit `1` on violation
- exit `2` on configuration/runtime error

### Content guard

The content guard scans configured text content for forbidden regex patterns.

Supported modes:
- `registered`: scan a configured directory under the repo
- `preregister`: scan explicit file or directory targets
- `new`: scan changed files from git diff, optionally including untracked files

`new` mode always scans bytes from the current working tree. With
`--since-ref`, the `ref...HEAD` diff selects file names and does not add staged,
unstaged, or untracked names. Without `--since-ref`, staged and unstaged names
are selected and untracked names are optional. A selected staged file whose
index and working-tree versions differ is rejected with exit `2` instead of
claiming that either version was checked for commit. Use a clean, quiescent
checkout when treating `--since-ref` output as change-range evidence.

Typical use cases:
- keep dangerous install instructions out of skills docs
- block hardcoded credential-like strings in agent-authored Markdown, YAML, and scripts
- catch destructive command suggestions before they spread

It returns:
- exit `0` on clean
- exit `1` on violation
- exit `2` on configuration/runtime error

### Context guard

The context guard scans common agent instruction files and rule locations:

- `AGENTS.md`
- `CLAUDE.md`
- `GEMINI.md`
- `.github/copilot-instructions.md`
- `.github/instructions/**/*.instructions.md`
- `.cursor/rules/**`
- `.cursorrules`
- `.windsurfrules`
- `.windsurf/rules/**`
- `.continue/rules/**`

Default rules catch context drift that would weaken the repository safety
boundary, such as approval bypass instructions, plaintext secret prompts,
destructive command normalization, and hidden-action instructions.

Typical use cases:
- reject agent context files that tell coding agents to bypass approval or
  policy checks
- keep plaintext secret requests out of durable agent instructions
- scan agent-specific rule files without scanning the entire repository

The opt-in inventory command emits deterministic metadata for discovered
context files without changing `context check --json`:

```bash
agent-guard context inventory --root . --policy .agent-guard/context-policy.yaml --json
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml > .agent-guard/context-digest-policy.yaml
```

Inventory output uses the shared JSON envelope with `command: "inventory"` and
an `inventory` payload. Each entry includes repository-relative paths, context
kind, read status, file size, line count for readable text, and redacted
evidence records for categories such as approval boundaries, tool permissions,
network boundaries, secret handling, destructive-action boundaries, and local
verification guidance. It does not emit raw context contents, snippets, matched
text, raw regex patterns, or absolute local paths.

For `context inventory`, exit `0` means inventory collection succeeded and exit
`2` means configuration/runtime error. Evidence and missing boundary categories
are report data, not violations.

The `context lock` command first requires the existing context check to pass,
then emits a digest policy for the discovered agent context files. It hashes raw
file bytes, emits only repository-relative paths and SHA-256 values, and omits
raw context text. It fails closed when no agent context files are discovered.
The generated YAML can be used directly with `agent-guard digest check` to make
agent context drift explicit. If a repository already has a broader digest
policy for guard policies or verifier scripts, merge the generated context
checks into that policy instead of overwriting it.

Use `context lock --check --digest-policy <yaml>` in CI after the lock has
been reviewed and committed. This coverage gate checks that every discovered
agent context file is present in the digest policy as a full-file pin and that
the current bytes still match. It fails on missing, partial, or mismatched
coverage and emits only repository-relative paths, rule ids, statuses, and
controlled messages.

The report command renders deterministic review evidence for pull requests,
review notes, and GitHub Actions annotations:

```bash
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --format markdown
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --format json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format markdown --output .agent-guard/evidence/agent-guard-report.md
agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format github-annotations
agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format sarif --output .agent-guard/evidence/agent-guard-results.sarif
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format markdown
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --format markdown
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --path-policy .agent-guard/path-policy.yaml --content-policy .agent-guard/content-policy.yaml --content-scan-dir . --api-policy examples/architecture_policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --drift-check --format markdown
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --path-policy .agent-guard/path-policy.yaml --content-policy .agent-guard/content-policy.yaml --content-scan-dir . --api-policy examples/architecture_policy.yaml --mcp-policy .agent-guard/mcp-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --drift-check --drift-schema-version v2 --surface-inventory-version v2 --conformance-profile recommended --evidence-pack-manifest --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --path-policy .agent-guard/path-policy.yaml --content-policy .agent-guard/content-policy.yaml --content-scan-dir . --api-policy examples/architecture_policy.yaml --mcp-policy .agent-guard/mcp-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --drift-check --drift-schema-version v2 --drift-base-ref origin/main --surface-inventory-version v2 --conformance-profile recommended --evidence-pack-manifest --format json --output .agent-guard/evidence/agent-guard-report.json
```

Use `agent-guard render-report` in CI when Markdown, SARIF, or GitHub
annotations should be derived from one already-sanitized JSON report instead of
rerunning scanner and policy checks for each output format.

`agent-guard report` runs the context check, redacted context inventory, agent surface inventory,
and evidence coverage summary, then emits scanner status, counts,
repository-relative context file paths, permission-boundary status, and finding
anchors limited to severity, rule id, file, and line. Surface inventory lists
agent context files, `.agent-guard` policy files, workflow files, and
agent-guard workflow references as metadata only; v2 also records documented
guard commands, evidence artifact references, agent skills/profiles/commands/
hooks, and MCP configuration metadata. MCP metadata is limited to server name,
transport, command basename, package-manager pin status, remote host, env var
names, filesystem-root presence, and deterministic risk labels for static
authorization, scope, URL-scheme, package, path, and inline-value review; it
does not emit raw args, env values, authorization values, scope strings, URLs,
instruction bodies, or hook bodies. Static authorization, scope, and URL-scheme
labels are review metadata over committed configuration only; they do not prove
that a live OAuth flow is correctly implemented or that an MCP server is safe to
execute. Findings and surface risk labels may also include
`owasp_agentic_risk_themes`, a static crosswalk to OWASP Agentic Top 10 risk
themes. These labels are review metadata for deterministic evidence; they are
not runtime vulnerability detection, live OAuth validation,
SLSA/provenance verification, or proof that a category is exploitable.
Evidence coverage records which gates
were enabled, missing, clean, or failing without
making missing optional gates a failure. With `--evidence-preset recommended`,
unset report options expand to
the current recommended static evidence bundle: path, content, MCP config,
workflow, policy/spec drift v2, surface inventory v2, recommended conformance,
and an embedded evidence-pack manifest. The preset intentionally does not enable
API or digest evidence because those policies are repository-specific. With
`--conformance-profile <minimal|recommended|strict>`, it checks the sanitized
report evidence against a named adoption profile. `mcp check` and the
recommended report preset fail on malformed committed MCP config files or risky
MCP configuration metadata, such as unpinned package-manager commands or
secret-shaped inline values, unsafe URL schemes, broad authorization scopes, or
inline authorization values. For recommended and strict evidence, keep the
reviewed risk-label policy at `.agent-guard/mcp-policy.yaml`; external MCP
policy files can be used for scanner experiments but do not satisfy conformance.
The `strict` profile also turns the same v2 surface inventory labels into conformance findings.
None of these modes execute MCP servers, inspect tool results, validate live OAuth flows,
detect MCP tool-poisoning behavior, or act as an MCP runtime security validator. The current
MCP 2026-07-28 protocol/runtime/OAuth changes do not justify runtime execution or live OAuth
validation. No changelog item directly invalidates the current static committed-config labels, so
this update does not change their taxonomy or code. With `--evidence-pack-manifest`,
it embeds a public-safe artifact handoff manifest for pull request review. Use
`--agent-policy-audit-event <path>` with profile
`agent-guard.public_agent_policy_audit_event.v1`
to bind a reviewed event without its body. Consumers require that event again;
source-tree v2 consumers also require `--repo-root <repo>` and exact positional
artifact-path equality. Arbitrary JSON objects, path aliases or escapes, and
unsupported profile labels fail closed before binding verification. The
programmatic v2 validator accepts only raw path strings, not normalized `Path`
objects, and rejects replacement of the repository path during its bounded
descriptor read.

Read `recommended` as the reviewed static evidence baseline, not as the full
pin-integrity profile. The recommended preset can emit digest and context-lock
evidence when `--digest-policy` is supplied, but recommended conformance does not
require those gates because digest policies are repository-specific. Use
`strict` when context-lock coverage, digest drift, sanitized evidence-pack
artifacts, and v2 MCP configuration risk labels should be conformance
requirements.

With `--path-policy`, it emits path-name evidence
limited to severity, rule id, and repository-relative path. With
`--content-policy`, it emits
registered-mode content evidence limited to severity, rule id,
repository-relative file, and line. With `--api-policy`, it emits API evidence
limited to repository-relative file, line, and controlled category. The report
command does not support content `new` or `preregister` modes; use
`content check` directly for those workflows. With `--digest-policy`, it also
emits sanitized digest drift evidence for pinned context or policy files: check
id, repository-relative path, status, and controlled message. With
`--workflow-policy`, it emits sanitized workflow drift evidence: checked count,
drift finding count, repository-relative workflow file paths, rule ids,
workflow ids, requirement ids, and controlled reasons. With `--drift-check`, it
adds a small policy/spec drift section that checks README recommended guard
commands, required `.agent-guard` policy files, and the workflow policy's
required-file and workflow-command declarations. Add `--drift-base-ref <ref>`
only when CI has fetched an explicit base ref and reviewers need evidence that
`.agent-guard` policies, digest policies, guard workflows, action metadata, or
pre-commit hook metadata changed relative to that baseline. This comparison is
review evidence, not approval or tamper-proof authorization; combine it with
digest and context-lock evidence when context or policy pins matter. It does
not emit the base ref name, raw diffs, expected or actual SHA-256 values, raw
workflow commands, or workflow `run` bodies.

When `--digest-policy` is supplied, the report also emits context lock coverage
evidence. This is separate from digest drift: digest drift checks existing pins,
while context lock coverage checks that all discovered agent context files are
actually pinned. The coverage section contains only severity, rule id,
repository-relative path, status, and check id. It does not emit context text or
hash values.

The Markdown headings for these review sections include `Evidence Coverage`,
`Agent Surface Inventory`, `Conformance Evidence`, `Evidence Pack Manifest`,
and `Context Lock Coverage Evidence`.

Report output omits raw context contents, snippets, matched text, raw regex
patterns, raw evidence URLs, raw repository/content/digest hashes, secrets, and
absolute local paths. Here, public-safe means sanitized under the declared
controlled-field/controlled-pattern contract, not a generic guarantee that an
artifact contains no secrets or PII; it does not replace a dedicated secret scanner.
This scope applies only to report/render-report/evidence artifacts, not raw per-scanner JSON; Markdown table cells escape HTML and Markdown control characters before output.

Use `--format json` to emit the same sanitized evidence payload inside the
shared `agent-guard.result.v1` envelope. This is the machine-readable report
contract for wrappers, CI checks, and downstream tooling. Add `--output <path>`
when CI should store the rendered Markdown, JSON, GitHub annotation, or SARIF
evidence as an artifact instead of writing it to stdout. SARIF is a thin
adapter over the sanitized report payload: it emits SARIF 2.1.0 rules,
locations, severity levels, and fingerprints derived from sanitized rule,
location, and message metadata, but not snippets, raw context text, raw
workflow commands, raw repository/content/digest hash values, raw evidence
URLs, secrets, or absolute local paths.

Relative report and render-report output paths are resolved beneath `--root`;
parent traversal and symlink or Windows reparse-point ancestors are rejected.
An absolute output path is an explicit trusted destination. Both forms write
through an exclusive regular temporary file in the validated destination
directory and atomically replace the final entry without following a final
symlink.

Native Windows rejects report file destinations on WSL shares (`\\\\wsl$`
and `\\\\wsl.localhost`, including their extended UNC forms). The opened
directory is checked before temporary-file creation; an unidentified or
inconsistent temporary-file destination is rejected before payload writing or
publication. Rejection preserves an existing final report and uses the
existing fatal output-error status (exit 2), without falling back to stdout.
If temporary-file identity cannot be verified, handles are closed but an empty
temporary file may remain: deleting an unverified name could delete another
file. Parent directories may already have been created.
Windows local output and ordinary UNC destinations retain the existing boundary
checks. A WSL-hosted input repository does not itself prevent output to a
supported destination or explicit stdout output. The Linux writer is unchanged;
shell redirection is outside these file-output guarantees.

Use `--format github-annotations` in GitHub Actions to emit `::error` or
`::warning` lines for findings and drift from the same sanitized payload. Clean
reports are quiet in this format. Annotation titles and messages contain only
controlled scanner metadata such as scanner name, rule id, category, status, or
reason, plus OWASP risk-theme labels when a deterministic rule maps to them.

Use `--format sarif --output .agent-guard/evidence/agent-guard-results.sarif`
when a repository wants to upload findings to GitHub code scanning with
`github/codeql-action/upload-sarif`. Uploading is intentionally left to the
consumer workflow because it changes repository permissions.
SARIF is a thin adapter and not a separate scanner.

`agent-guard` does not detect runtime prompt injection, MCP tool poisoning,
live MCP authorization failures, or agent memory poisoning. It emits static
repository evidence that can help a maintainer decide where those runtime
controls may be needed.

For `report`, it returns:
- exit `0` when the report is generated and all enabled checks pass
- exit `1` when the report is generated and any enabled check finds violations
  or context-lock coverage, digest, workflow, or policy/spec drift
- exit `2` on configuration/runtime error

Event-free output follows `agent-guard.report_evidence.v1`; attaching a reviewed
audit event selects `agent-guard.report_evidence.v2` with a bound v2 manifest.
Both remain sanitized, inside the shared `agent-guard.result.v1` envelope.

#### Packaged JSON schemas

Installed wheels include JSON Schema resources under the `agent_guard.schemas`
package so wrappers and demos can load the evidence contracts without copying
files from the source tree:

- `agent-guard.result.v1.schema.json`: shared scanner result envelope.
- `agent-guard.context_inventory.v1.schema.json`: redacted agent context
  inventory evidence.
- `agent-guard.context_lock_coverage.v1.schema.json`: hash-free context lock
  coverage evidence, including covered context files.
- `agent-guard.report_evidence.v1.schema.json` (event-free) and
  `agent-guard.report_evidence.v2.schema.json` (bound audit event): sanitized
  report evidence, including surface inventory and evidence coverage.
- `agent-guard.conformance.v1.schema.json`: profile evidence for `minimal`,
  `recommended`, and `strict` adoption levels.
- `agent-guard.evidence_pack_manifest.v1.schema.json` (legacy unbound) and
  `agent-guard.evidence_pack_manifest.v2.schema.json` (bound): sanitized manifests.

Installed wheels also include `agent-guard.surface_delta.v1.schema.json` for
sanitized PR base/head agent surface delta evidence.

For `context check`, it returns:
- exit `0` on clean
- exit `1` on violation
- exit `2` on configuration/runtime error

### Surface delta evidence

Surface Delta evidence is available in `0.3.0`.

`agent-guard surface delta --root . --context-policy <policy> --base-ref <ref>`
computes a sanitized diff of surface inventory v2 between the merge base of a
fetched base ref and `HEAD`, including current working-tree changes: which
agent-facing surfaces (context files, skills, MCP servers, workflows, policies,
hooks) were added, removed, or modified. Resolving `git merge-base <ref> HEAD`
prevents base-branch-only additions from appearing as PR removals when the base
branch advances. The base snapshot is built from raw Git tree/blob objects for
the requested repository root; release-archive attributes (`export-ignore` and
`export-subst`) are not applied, and configured clean/process/smudge filters are
not executed. Tree metadata is filtered against the requested root and inventory
patterns, including context `scan.exclude`, before blobs are read, so unrelated
tracked blobs are not materialized. Selected repository-internal symlink targets
and chains are materialized with bounded expansion so target-only changes remain
comparable. Repository-external symlink targets are not followed; external,
`.git`, cyclic, and otherwise unsafe targets fail closed, while context-excluded
alias paths and resolved in-repo target paths are not expanded through
context-selected symlinks. Target values are never published.
Git queries and base materialization run with shared scanner deadlines and
per-file, aggregate-input, selected-file, process-output, and tar-output ceilings;
exceeding any ceiling fails with a fixed sanitized runtime error.
Tracked submodules are opaque boundaries for the parent repository delta:
initialized checkout contents and dirty/untracked submodule files are not
inventoried, while a superproject gitlink pin change is reported only as
`changed_fields: ["content"]` without publishing an object id or submodule
content. Opaque paths are pruned before collector file reads. When no existing
skill/profile/command surface represents the boundary, the delta uses the
controlled `git_submodule` kind. Scan each submodule as its own repository when
its internal surfaces also require review evidence.
`changed_fields` lists metadata field names only, never values, and
the section never emits the base ref name, raw diffs, MCP args/env values, or
instruction/description text. Repeated records retain their count, while
line-number and workflow-step-position-only moves remain unchanged. Content-only
changes to existing file-backed context, policy, workflow, evidence artifact,
skill, profile, command, hook, and MCP configuration surfaces are reported with
`changed_fields: ["content"]`; neither content nor a content fingerprint value
is published. It is
deterministic review evidence, not a gate: exit `0` regardless of whether
entries are present, exit `2` on
configuration/runtime error such as an unfetched base ref. Pass
`--surface-delta-base-ref <ref>` to `agent-guard report` to embed the same
evidence as an optional `surface_delta` section (Markdown heading
`## Surface Delta Evidence`, informational GitHub annotations, never SARIF).

### Path guard

The path guard scans file and directory names under configured roots. It uses
allowlist-first matching so narrow exceptions such as `.env.example` can be
allowed while broader deny patterns still block `.env`, `.env.local`, and
`.env.evil`.

Typical use cases:
- keep `artifacts/private/` out of publishable repository paths
- block bypass corpus files and red-team session logs by name
- catch env-file leaks even when contents are ignored or unreadable

It returns:
- exit `0` on clean
- exit `1` on violation
- exit `2` on configuration/runtime error

### Digest guard

The digest guard verifies pinned SHA-256 values for files that should not
drift silently. Each check names a repository-relative path, an expected
digest, and an optional `start_line` when only the content body should be
hashed.

Typical use cases:
- detect unreviewed edits to governance documents
- pin verifier scripts that protect publication or release gates
- preserve B9-style constitution integrity checks without shell-specific logic

It returns:
- exit `0` on clean
- exit `1` on violation
- exit `2` on configuration/runtime error

### Workflow guard

The workflow guard checks a declared CI workflow for required guard commands
and checks that configured policy files are still present in the repository.
It is intentionally narrower than a workflow security scanner: it does not
evaluate GitHub permissions, branch protection, workflow logs, action versions,
or complete shell semantics.
Workflow policies must declare `schema_version:
agent-guard.workflow_policy.v1` and at least one `required_files` or
`workflow_checks` entry; empty policies are configuration errors.

Typical use cases:
- catch CI drift where `context`, `digest`, `path`, or `content` guard commands
  are removed from the release gate
- make policy-file presence explicit before a workflow declares guard coverage
- keep static guard coverage reviewable through deterministic JSON output

Command matching only inspects active `jobs.*.steps[*].run` lines. Its bounded
lexical recognizer tracks supported quoting, substitutions, arrays,
continuations, comments, and here-documents across lines. Blank lines, comments,
`echo` / `printf` documentation lines, and recognized here-document bodies are
not treated as executed guard commands. Unsupported, unterminated, or
over-budget shell/YAML structure fails closed with exit `2`. A command does not
count when its job or step has a recognized literal-false `if`, when job/step
`continue-on-error` is not absent or explicitly false, or when its effective
shell is an explicit custom template instead of `bash`, `sh`, `pwsh`,
`powershell`, or `cmd`.
Other context- or matrix-dependent `if` expressions are not evaluated.

A requirement is satisfied only by a dedicated supported-shell step whose
active shell body reduces to one direct command. The evidence step cannot also
contain setup, another active command, a shell list/control operator, a compound
group, a leading assignment or command wrapper, or a dynamic redirection
target. Static redirections remain supported. Workflow-, job-, or step-level
`PATH`, Python/import, shell-startup, loader, or equivalent resolution-sensitive
environment declarations make the step ineligible. Any job-container
declaration is also ineligible because its image, mounts, environment, and
runtime options can change executable resolution. This includes Python
startup, warning, user-site, and import selectors such as `PYTHONSTARTUP`,
`PYTHONINSPECT`, `PYTHONWARNINGS`, `PYTHON_PRESITE`, `PYTHONUSERBASE`,
`PYTHONNOUSERSITE`, `PYTHONSAFEPATH`, `PYTHONPLATLIBDIR`, `PYTHONCASEOK`, `HOME`,
`USERPROFILE`, and `APPDATA`. An effective `working-directory` declaration is
also ineligible.

The installed `agent-guard` console script remains a supported entrypoint.
When a requirement uses the Python module entrypoint, both the policy and the
workflow must use `python -I -m agent_guard.cli ...`; bare
`python -m agent_guard.cli ...` does not count because a package in the
reviewed checkout can shadow the installed module.

This boundary proves only the checked repository text has that restricted
static shape. It does not prove which host executable a runner resolves, runner
integrity, shell startup behavior, mutations persisted by prior steps (including
`GITHUB_PATH` / `GITHUB_ENV`), or that a context-dependent job or step executes
on every workflow path.
Findings include repository-relative paths, rule ids, workflow ids, requirement ids, reasons, and controlled messages; they do not include raw workflow `run` bodies or raw command text.

It returns:
- exit `0` on clean
- exit `1` on missing required files or missing required workflow commands
- exit `2` on configuration/runtime error

## Example policies

### API guard policy

```yaml
scan:
  include:
    - src
    - scripts
  exclude:
    - scripts/build_instructions.sh

policy:
  allowed_api_patterns:
    - '^https://ntfy\.sh/'
  forbidden_api_patterns:
    - '^https://api\.openai\.com/'
    - '^https://api\.anthropic\.com/'
```

A ready-to-run copy lives in [`examples/architecture_policy.yaml`](../examples/architecture_policy.yaml).

### Content guard policy

```yaml
file_globs:
  - "**/*.md"
  - "**/*.yaml"
  - "**/*.yml"
  - "**/*.sh"
  - "**/*.mjs"
exclude_globs:
  - "archive/**"
  - "artifacts/**"
  - "node_modules/**"
  - "examples/content_security_policy.yaml"
forbidden_patterns:
  - id: pipe_to_shell
    severity: high
    pattern: '(?i)curl\s+[^\n|]+\|\s*(bash|sh)\b'
    message: "pipe-to-shell pattern is forbidden"
    exclude_globs:
      - "fixtures/red-team/**"
  - id: destructive_rm_root
    severity: high
    pattern: '(?i)rm\s+-rf\s+(/|~|/home|/mnt/c)'
    message: "destructive rm pattern is forbidden"
```

A ready-to-run copy lives in [`examples/content_security_policy.yaml`](../examples/content_security_policy.yaml).

Content rules may define per-rule `include_globs` / `exclude_globs`. Use this
when a repository contains intentional adversarial fixtures that should stay
scannable for secrets but should not fail dangerous-command rules. For narrow
reviewed exceptions, scope the rule in the policy; inline `agent-guard: allow`
text is scanned as ordinary content and cannot suppress a finding.

### Context guard policy

```yaml
scan:
  include:
    - "AGENTS.md"
    - "**/AGENTS.md"
    - "CLAUDE.md"
    - "**/CLAUDE.md"
    - ".github/copilot-instructions.md"
    - ".github/instructions/**/*.instructions.md"
    - ".cursor/rules/**/*.md"
    - ".cursorrules"
    - ".windsurfrules"
  exclude:
    - "archive/**"

policy:
  extra_forbidden_patterns:
    - id: unreviewed_tool_allow
      severity: medium
      pattern: "(?i)always\\s+allow.{0,80}(bash|shell|network|write|edit)"
      message: "agent context should not broadly auto-allow risky tools"
```

For symlinked context files, `scan.exclude` is evaluated against both the
repository-relative alias path and the resolved in-repo target path.

Use `forbidden_patterns` to replace the default context rules, or
`extra_forbidden_patterns` to append repository-specific rules. A ready-to-run
copy lives in [`examples/agent_context_policy.yaml`](../examples/agent_context_policy.yaml).

### Path guard policy

```yaml
scan:
  include:
    - "."
  exclude:
    - ".git"
    - ".venv"
    - "node_modules"

policy:
  allowed_path_patterns:
    - "(^|/)\\.env\\.example$"
  forbidden_path_patterns:
    - id: private_artifacts
      severity: high
      pattern: "(^|/)artifacts/private(/|$)"
      message: "private artifact directory must stay outside published/tracked paths"
    - id: local_artifacts
      severity: high
      pattern: "(^|/)artifacts/local(/|$)"
      message: "local-only artifact directory must stay outside published/tracked paths"
```

A ready-to-run example policy lives in
[`examples/ai_resilience_path_policy.yaml`](../examples/ai_resilience_path_policy.yaml).

### Digest guard policy

```yaml
checks:
  - id: constitution_full
    path: agent-constitution-v0.md
    sha256: "<64-char lowercase sha256>"
  - id: constitution_content
    path: agent-constitution-v0.md
    sha256: "<64-char lowercase sha256>"
    start_line: 15
```

### Workflow guard policy

```yaml
schema_version: agent-guard.workflow_policy.v1

required_files:
  - id: context_policy
    path: .agent-guard/context-policy.yaml
  - id: digest_policy
    path: .agent-guard/context-digest-policy.yaml

workflow_checks:
  - id: ci_static_guards
    path: .github/workflows/ci.yml
    required_commands:
      - id: context_guard
        command: agent-guard context check
      - id: context_lock_coverage
        command: agent-guard context lock --check --digest-policy .agent-guard/context-digest-policy.yaml
      - id: digest_guard
        command: agent-guard digest check
```

Ready-to-run copies live in
[`examples/workflow_policy.yaml`](../examples/workflow_policy.yaml) for a minimal
example and [`.agent-guard/workflow-policy.yaml`](../.agent-guard/workflow-policy.yaml)
for this repository's self-dogfood gate.
