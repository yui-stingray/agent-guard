# Changelog

Where: `CHANGELOG.md`  
What: release notes for published `yui-agent-guard` versions.  
Why: keep static guard releases auditable while the package is still alpha.

## Unreleased

- Corrected `bun x` and direct `bunx` pin inference to evaluate only the package operand
  (optionally preceded by `--bun`). Bun global `--cwd` and `--shell` are
  consumed only before `x`; version-dependent post-`x` selectors such as
  `--package` fail closed as unpinned metadata.
- Made static MCP package pin and latest-tag inference inspect recognized
  package-manager operands and selectors instead of arbitrary command arguments.
  JavaScript launchers require npm-compatible full SemVer (total version text
  at most 256 characters and core numeric identifiers at most
  `Number.MAX_SAFE_INTEGER`) and do not treat synthetic package-attached SHA-256
  selectors as pins; exact `uvx` requirements and uv's exact-only positional
  `name@version` syntax remain eligible. Both labels use bounded, explicit
  launcher option and alias arities; unsupported or ambiguous layouts fail
  closed without treating arbitrary arguments as package operands. Trailing
  executed-command arguments are excluded after the package operand, and
  recognized Windows launcher suffixes are normalized internally without
  changing the public command basename. Ranges, npm-style major/minor-only
  versions, digest selectors, option values, and ambiguous layouts fail closed
  as unpinned metadata.
- Bounded context inventory, digest, and MCP configuration inputs by file size, file
  count, aggregate distinct bytes, structured-object depth, and public result
  size. Repository containment is bound to the opened regular file, and
  resource or race failures remain deterministic sanitized errors without raw
  policy, context, command, URL, or local-path content.
- Isolated repository-controlled context-policy regular-expression matching
  behind the existing bounded scanner worker and added fixed pattern-count and
  pattern-length limits. Timeout and limit failures remain deterministic,
  sanitized configuration errors; no raw pattern or context text is emitted.
- Tuned narrow English negation handling for built-in context rules so safe
  prohibitions do not become findings, while custom regular expressions,
  mixed unsafe clauses, double negation, and verification-skip instructions
  retain deterministic fail-closed behavior.
- Content-bound optional `agent-policy` audit-event references with a
  canonical-JSON, profile-bound, public-safe digest. Producers require a
  caller-designated repo-local JSON event and the recognized
  `agent-policy.audit_event.v1.1` profile. Producers and consumers validate that
  profile's published event shape and reject unsupported profiles, malformed
  events, or replaced content. Maintainer review remains external. Audit-event
  binding uses report and manifest v2; the released v1
  schemas remain unchanged and their path-and-role references remain readable
  as explicitly unbound legacy metadata. The event body remains outside the
  fixed seven-file public bundle.
- Defined a bounded demand-validation window through 2026-09-20 and froze
  feature releases pending an explicit maintainer decision after the 2026-09-21
  review. Marketplace publication remains separately prohibited without
  explicit authorization.
- Locked the release build toolchain, pinned copyable GitHub Action examples to
  the immutable v0.3.4 release commit, and documented the post-release pin
  refresh contract.
- Simplified reviewed bootstrap and monorepo onboarding, added explicit Python
  interpreter checks, and tightened guidance for copying public-safe evidence.
- Hardened the documented PyPI provenance flow with isolated temporary
  downloads, request timeouts, exact artifact checks, redirect-final HTTPS host
  validation, exclusive file creation, and cleanup on success or failure.
- Aligned self-dogfood CI with the canonical public evidence filenames and
  required fail-closed bundle validation before artifact upload.

## 0.3.4 - 2026-08-01

- Preserved top-level standalone compatibility for the public API, content, and
  path scanners. Default isolation uses a fresh package-owned interpreter with
  a bounded framed protocol and package-origin handshake, so consumers do not
  need a `__main__` guard; scan work still avoids automatic POSIX `fork` and
  inherited parent-thread locks. Windows CI exercises the same unguarded public
  scanner contract.
- Bounded workflow shell lexing per command by characters, lexer steps,
  operators, and segments before materialization. Required-command matching now
  streams bounded segments, and incremental array-assignment state replaces
  repeated prefix copies and regex scans. Limit failures remain sanitized.
- Made every path-bearing Git query in content `new` mode use an explicit
  repository-top literal pathspec, including staged-index metadata and
  index/worktree mismatch checks, so scan-directory bytes cannot become Git
  pathspec syntax.
- Bounded API, content, and path policy YAML by event count, nesting, aliases,
  and iterative object-graph traversal before scanner use. YAML merge expansion
  and cyclic or excessive alias graphs now fail with each scanner's existing
  sanitized policy-limit error; bounded non-merge anchors remain supported.
- Bound API, content, and path policy inputs and scan work, isolate
  policy-controlled regular-expression matching behind a fixed execution
  deadline, apply finding/result budgets before result materialization, and
  reject include targets that resolve outside the repository. Supported POSIX
  workers also lower their address-space ceiling. API walks charge incremental
  directory entries and prune lexical exclusions before resolution, so excluded
  external symlinks are not inspected while selected ones still fail closed.
  Registered and preregistration
  content walks now share a monotonic deadline and charge glob-state work as well
  as directory entries. Errors remain sanitized and this does not broaden
  agent-guard into a generic secret scanner. Automatic POSIX `fork` selection
  is avoided so Python and native parent-thread locks are not inherited.
- Made evidence-artifact inventory metadata come from regular Git-index blobs
  so generated or modified worktree artifacts cannot feed back into their own
  report. Inventory and content-diff Git calls disable lazy fetch and ignore
  inherited repository/index/object routing environment overrides, inherited
  global/system configuration, replace refs, and fsmonitor helpers. Content base refs are
  resolved to commit object ids before diffing, Git output and runtime are
  bounded. Git execution is restricted to the helper-disabled query shapes used
  by static evidence; Windows uses a Job Object and POSIX terminates the direct
  process group. A POSIX descendant that deliberately starts a new session is
  outside that portable containment boundary, so the selected Python, Git, and
  executable search path remain trusted. The packaged Action now stages prior
  public artifacts by same-device, rename-only directory operations outside the
  scan root that fail closed on `EXDEV` instead of falling back to copy/delete,
  restores them after ordinary fatal generation failures and catchable signals
  when possible, retains the staged backup if restoration itself fails, and
  verifies required outputs before replacement. Uncatchable termination such as
  `SIGKILL` or runner power loss cannot execute shell restoration traps.
- Made the CI Action smoke replay the fail-closed evidence consumer against the
  current repository, and made generated pull-request workflows anchor drift
  evidence to the fetched base commit. Added a focused Windows CLI contract job
  for Job Object cleanup, spawn-based scans, Windows path rejection, and report
  consumption, including native final-handle reads and outside-junction
  rejection. The packaged Action remains Linux-runner-only, while the shell
  consumer example requires a POSIX host.
- Removed the packaged Action's unnecessary runtime `pip` self-upgrade, marked
  the package override as a caller-trusted code-execution boundary, and ran the
  packaged Action smoke across every advertised Python version.
- Added a bounded packaged public-bundle consumer mode, replaced the duplicated
  shell validator with that entry point, and made stale-report wording match the
  sanitized report-visible comparison rather than imply whole-tree identity.
  Present Markdown, SARIF, and annotation artifacts must now exactly match
  canonical renders of the selected report. Bundle directory enumeration stops
  at the first excess entry, and public `consume`/`lint-public` flows run bounded
  bundle validation before report-only parsing or digest inspection.
- Bound standalone bundle envelopes to the selected report's tool and policy
  claims, and require a standalone evidence-pack manifest to exactly match the
  embedded manifest. Relocated runner-staged bundles may use only the controlled
  `<external-policy>` sentinel where the report contract permits it; arbitrary
  policy metadata remains rejected.
- Made generated workflows build public evidence in fresh runner-temporary
  staging, validate the complete bundle with an isolated Python import before
  emitting captured annotations, and expose upload-ready outputs only after an
  exact artifact allowlist passes. Raw-output and output-file failures now stop
  with sanitized configuration errors instead of publishing partial evidence.
- Applied the same pre-publication bundle validation, annotation staging,
  raw-output checks, isolated Python imports, and checked output writes to the
  packaged Action. The downstream `consume` gate now preserves an up-to-date
  report's policy-finding exit status instead of converting it to success. A
  fatal Action generation path records only sanitized `status=2`; `ready` and
  publication path outputs remain absent.
- Made generated workflows retain a validated fresh directory before recording
  `ready=true` as their final publication operation. The shell consumer installs
  restoration traps before moving the original evidence so a termination at the
  setup boundary restores the prior bundle. Package, Action, installation, and
  attestation examples are synchronized to the `0.3.4` release contract.
- Rejected required workflow commands that can be skipped through same-line
  semicolon tails, pipelines, background execution, or short-circuit OR lists;
  excluded recognized literal-false jobs/steps, failure-masking `continue-on-error`,
  and custom shell templates from required-command evidence;
  added a bounded stateful shell lexer for quoting, substitutions, arrays,
  comments, continuations, and supported here-documents; bounded workflow YAML,
  object-graph, traversal, command, match, and finding work while rejecting YAML
  merge expansion; made repository-scoped workflow reads descriptor-bound
  against symlink swaps;
  refreshed the static-only MCP reference to the final 2026-07-28
  specification; and clarified that public-safe means bounded sanitization
  rather than a generic secret or PII absence guarantee.
- Required root-relative Action and shell-example evidence destinations to stay
  beneath the selected root without parent traversal or symlinked path
  components before any staging or publication mutation. Explicit absolute
  destinations retain their caller-selected semantics.
- Capped each workflow-policy string, aggregate distinct workflow input, and
  serialized finding work; duplicate normalized workflow paths now share one
  descriptor-bound read and parse while retaining independent check identities.
  Limit failures remain sanitized and are checked before finding materialization.
- Made content `new` mode consume bounded NUL-delimited Git path lists without
  altering special file names; repository-configured clean/process filters and
  text converters are neutralized for diff discovery, and configured filter
  names are enumerated without reading or executing their commands. Rename
  detection is disabled so configured rename policy cannot hide added paths.
  Every Git entry is charged, but policy-excluded or nonmatching lexical paths
  are discarded before symlink containment resolution, so a nonselected
  external symlink cannot block selected evidence.
  Selected staged paths fail closed on skip-worktree, assume-unchanged, or
  fsmonitor-valid index flags and on a remaining index/worktree mismatch. The
  scanner still reads current working-tree files; it does not add a Git-blob
  scanning mode, and built-in Git text normalization remains compatible.
- Documented that bounded static walks require a quiescent checkout: repository-
  bound reads prevent outside-root byte access, but do not claim atomic
  filesystem snapshot completeness under a concurrent writer.
- Made report and render-report output-file writes emit deterministic UTF-8/LF
  bytes on every platform, and made report-only and bundle consumers reject
  duplicate JSON object members recursively before semantic validation with
  stable sanitized errors. Rendered artifacts remain exact comparisons; the
  consumer does not normalize line-ending drift.
- Made the release contract derive exact wheel and sdist member sets from a
  sanitized tracked-file inventory bounded by output bytes, path count, and a
  fixed deadline. Clean-build enumeration stops after the two expected
  distributions, and wheel member count and central-directory size are checked
  before Python's ZIP reader materializes member metadata. The sdist preflight
  first copies the bounded compressed input into a private snapshot, accepts one
  gzip member with limited zero padding, and incrementally bounds decompressed
  tar bytes, consecutive extension headers, PAX records, and PAX/GNU extension
  metadata before Python's tar reader materializes those records. GNU sparse
  forms and PAX size overrides are outside the regular-file-only release
  contract and fail closed. Missing, extra, duplicate, unsafe, non-regular, or
  oversized archive members fail before isolated wheel installation.
- Made non-Git evidence fallback enumeration use incremental directory entries
  and stop at the configured candidate count before constructing or sorting
  additional paths.

## 0.3.3 - 2026-07-27

- Released a bounded P0 public-artifact hygiene patch so the standalone
  evidence-pack command recursively sanitizes copied report metadata and
  recognized HTTP(S)- or file-scheme artifact inputs before emission. The
  reproduced cases used synthetic inputs; review identified no real credential
  exposure.
- Kept producer and evidence-consumer checks aligned for mixed-case URLs,
  Windows drive paths, and UNC paths while preserving the existing controlled
  secret-shape contract.
- Replaced ambiguous URL-like or absolute-path-containing metadata values as a
  whole and made sanitized mapping-key collisions fail closed instead of
  silently overwriting evidence.
- Clarified generated init guidance to use explicit repository-root commands
  for reviewed write operations.

## 0.3.2 - 2026-07-19

- Released ahead of the default batch so repository-root containment fixes for
  content scans reach installed users before the next scheduled batch; this
  release also carries the reviewed release supply-chain hardening below.
- Made repository-scoped content scans reject scan directories that resolve
  outside the repository root with a sanitized configuration error. Registered
  scans also reject nested file or directory symlinks that resolve outside that
  root.
  Explicit preregistration targets remain available for local review without
  broadening the scanner's public evidence contract.
- Made Agent-Guard Bench fail closed on guard runner errors, preserve raw
  comparisons for scoring, and redact finding metadata only at JSON output
  boundaries while using controlled diagnostic labels. Malformed fixture
  fields and case diagnostics are rejected instead of being scored or rendered.
- Reduced remaining first-run friction with a top-level `--version` command,
  recovery-specific guidance for blocked starter writes, and earlier Python
  runtime requirement guidance.
- Required a successful upstream PyPI publish job, trusted tag ancestry, and
  the exact non-yanked wheel and sdist on PyPI before automatic GitHub Release
  publishing. Manual retries now run the current default-branch verifier and
  require a matching successful tag-push PyPI publication.
  The write-capable GitHub Release job re-resolves the tag and requires it to
  match the prepared commit before mutation, and it no longer persists checkout
  credentials in its working copy.
- Split release provenance attestation into a dedicated least-privilege job,
  made publish-time PyPI verification fail closed on missing, extra, duplicate,
  malformed, or yanked distributions, and required clean builds to contain
  exactly the current wheel and sdist before publication.

## 0.3.1 - 2026-07-17

- Released ahead of the default batch so installed evidence consumers receive
  the fail-closed public-redaction parity fixes together with the reviewed
  onboarding behavior that produces those artifacts.
- Reduced first-run friction with readable review-first init guidance, an
  opt-in missing-only write mode for partially onboarded repositories,
  mode-specific next steps, sanitized opt-in report status summaries, and
  fail-closed exit-status precedence aligned across the generated workflow,
  packaged Action, and manual workflow example.
- Hardened the packaged evidence consumer to reject AWS access-key-ID-shaped
  values already redacted by public evidence producers, without emitting the
  matched value in validation errors.
- Extended that fail-closed parity to the producer's existing lower-bound token
  shapes and WSL-mounted Windows user paths without adding generic secret
  scanning.

## 0.3.0 - 2026-07-17

- Raised the minimum supported Python version from 3.11 to 3.11.4 so every
  supported installation includes the security-backported tar extraction
  filter required by fail-closed surface delta base-tree materialization. No
  unfiltered or project-maintained tar extraction fallback is used.
- Added `agent-guard surface delta --base-ref <ref>` and
  `agent-guard report --surface-delta-base-ref <ref>`: sanitized PR base/head
  agent surface delta evidence (surface inventory v2 diff) reporting
  added/removed/modified surfaces with controlled-vocabulary `changed_fields`
  names (never values) and risk labels. It is deterministic review evidence,
  not a gate, and is never emitted to SARIF. Added the packaged
  `agent-guard.surface_delta.v1.schema.json` schema and the matching
  `action.yml` `surface-delta-base-ref` input. Repeated records retain their
  multiplicity instead of overwriting one another, locator-only line/step moves
  remain unchanged, content-only edits to all direct file-backed surfaces are
  reported without publishing content or fingerprint values, the supplied base
  ref is resolved to its merge base with `HEAD` so an advanced base branch does
  not create false PR removals, public `changed_fields` and risk labels are
  schema-enumerated, public locator
  fields redact secret-, URL-, hash-, and absolute-path-shaped text before JSON
  emission, unresolved-base report sections validate against the same schema,
  and base snapshots now stream raw Git tree/blob objects without applying
  `export-ignore` or `export-subst`. Configured clean/process/smudge filters
  are not executed, and tree metadata is filtered against the requested root
  and inventory patterns, including context `scan.exclude`, before any blob is
  read, so unrelated tracked blobs are not materialized. Selected repository-
  internal symlink targets and chains use bounded expansion so target-only
  changes remain comparable; repository-external, `.git`, cyclic, and otherwise
  unsafe targets fail closed, while context `scan.exclude` is applied to both
  repository-relative alias paths and resolved in-repo target paths before
  expansion through context-selected symlinks. Target values are never
  published. Tracked submodules are treated as opaque parent-repository
  boundaries: initialized checkout contents and dirty/untracked files do not
  affect the delta, while gitlink pin changes emit only the controlled
  `content` field name without object ids or submodule content. Opaque paths
  are pruned before collector reads, and otherwise unrepresented boundaries use
  the controlled `git_submodule` kind. Synthetic tar extraction fails closed
  when the safe tar filter is not available.
- Recursively sanitized standalone Surface Inventory output before GitHub
  Action upload, preventing secret-shaped repository-relative metadata from
  appearing raw in public review artifacts.
- Reworked the README opening around agent-facing repository surfaces,
  concrete inventory/check/evidence value, and the reviewed bootstrap path
  without implying authorship, runtime protection, provenance, or compliance.
- Required out-of-cadence P0 patch releases to record a one-sentence,
  public-safe rationale in the release-preparation pull request or that
  release's CHANGELOG entry without exposing embargoed vulnerability details,
  credentials, private incident data, or local paths.
- Prepared the unpublished GitHub Action metadata for a future Marketplace
  listing with a distinct static-evidence name, explicit alpha scope, and a
  CI consumer smoke gate; Marketplace publication remains a separate manual
  maintainer decision.
- Reduced first-run friction with a no-write `uvx` preview, a four-command
  review-first quickstart, repo-local context policy defaults for `report`, and
  a single recommended report that already embeds conformance and evidence-pack
  metadata. Starter workflows now pin the current package and action SHAs.
- Pinned executable GitHub Action dependencies to full commit SHAs, required
  release tags to point at the current `master` commit with successful CI, and
  added a bounded TTFE onboarding gate.
- Added Python 3.13 and 3.14 to the supported CI matrix and package classifiers.
- Clarified the current `CONTINUE-NARROW` product strategy: keep `agent-guard`
  as a Python/PyPI static repository evidence package, defer rename and broad
  benchmark work until demand signals justify them, and keep runtime security
  controls in separate layers.

## 0.2.4 - 2026-07-09

- Clarified external risk-reference currentness for MCP, OWASP, SLSA, NIST, and
  AI data security material while keeping those references as review context,
  not certification, compliance, runtime validation, or provenance proof.
- Tuned context guard coverage for narrow Japanese-language skip-verification
  and private-data exfiltration wording, reducing the documented Agent-Guard
  Bench known false negatives without adding runtime detection or model judging.
- Added a sanitized static MCP metadata-poisoning label for instruction-like
  server descriptions, keeping raw description text out of public evidence.
- Tuned split-token approval-bypass context detection while keeping quoted
  reviewer-training examples benign.

## 0.2.3 - 2026-07-05

- Expanded Agent-Guard Bench to 60 self-authored static evidence cases across
  context, MCP metadata, path, digest, and workflow drift checks, with the
  current metrics, known gaps, and scope caveats documented in
  `docs/benchmark-results.md`.
- Added fail-closed evidence-consumer CI examples and a package entry point for
  `python -m agent_guard.consumer` so downstream repos can validate sanitized
  recommended evidence contracts directly.
- Locked README, quickstart, policy-pin, and benchmark documentation contracts
  with regression tests while keeping the green CI path separate from the
  diagnostic adoption pass.
- Kept the bounded static-evidence scope intact: no runtime MCP execution, live
  OAuth validation, generic secret scanning, LLM review, or autonomous policy
  execution was added.

## 0.2.2 - 2026-07-04

- Validated documented `agent-guard` command references against the CLI
  registry so bogus command surfaces are dropped from evidence.
- Split report and surface-inventory renderers into focused modules without
  changing rendered output.
- Added subprocess-aware coverage measurement, completed the yamllint burn-down,
  and made the health gate fail closed on lint errors.
- Shortened the existing-repo quickstart to a five-command golden path.
- Validated SARIF output against the vendored official OASIS SARIF 2.1.0
  errata01 schema in the alignment bench.

## 0.2.1 - 2026-07-03

- Fixed recommended preset policy defaults for subdirectory and monorepo roots
  so root-relative policy paths resolve under the selected repository root.
- Added the MCP policy weakening conformance matrix to lock expected
  recommended and strict profile behavior for weakened reviewed policies.
- Published the `agent-guard` and `agent-audit` comparison doc as local project
  positioning material after human review.

## 0.2.0 - 2026-07-03

- Prepared a stable evidence contract compatibility policy for v1 consumers,
  including a documented compatibility promise, explicit volatile fields, and a
  freeze test for packaged schema file names, `$id` values, and schema-version
  constants.
- Added the Agent-Guard Bench, evidence integrity, taxonomy alignment, and TTFE
  benchmark result pipeline so evidence quality and regression risk are
  measured before release.
- Promoted the downstream evidence consumer into `agent_guard.consumer` while
  keeping `examples/evidence_consumer.py` as a compatibility shim.
- Fixed the public API surface so the MCP scanner export is covered alongside
  the other scanners.
- Completed taxonomy coverage for emitted guard rule ids, labels, statuses, and
  classifications so evidence metadata cannot silently drift.
- Switched release guidance toward batched releases for schema/contract
  stability, with immediate releases reserved for explicit P0 fixes.

## 0.1.23 - 2026-07-02

- Treated URL-like policy arguments as repo-external policy inputs in public
  evidence so URL-shaped policy values are not displayed as repo paths.
- Tightened the copyable downstream evidence consumer for recommended and
  strict MCP policy conformance consistency, including stale or missing MCP
  policy violation summaries.
- Clarified recommended GitHub Action and existing-repo adoption guidance, and
  preserved explicit configuration-error exits when later checks also find
  policy violations.
- Kept the bounded static-evidence scope: no runtime MCP execution, live OAuth
  validation, generic secret scanning, LLM review, or autonomous policy
  execution was added.

## 0.1.22 - 2026-07-01

- Added a dedicated threat model and evidence-consumer guidance that clarifies
  the static evidence boundary without adding runtime MCP execution, live OAuth
  validation, generic secret scanning, or LLM review behavior.
- Hardened the copyable downstream evidence consumer so it checks conformance
  and evidence-pack consistency, recognizes reviewed MCP policy conformance
  rule ids, rejects unexplained top-level report status values, and uses
  shape-aware public-evidence hygiene checks instead of broad token/hash
  substrings.
- Resolved non-MCP policy path arguments relative to the relevant repository
  root for direct scanner checks and `report`, while keeping public policy path
  display sanitized and repo-relative.
- Trimmed direct `api check` and `content check` finding output to public-safe
  metadata and made direct-check text errors print scrubbed paths.

## 0.1.21 - 2026-07-01

- Clarified the recommended/strict adoption boundary and MCP policy
  failure-reading guidance without changing runtime behavior or expanding beyond
  deterministic static evidence.

## 0.1.20 - 2026-07-01

- Clarified README and GitHub Actions evidence guidance so recommended evidence
  examples pass the reviewed repo-local MCP policy explicitly and avoid implying
  that MCP policy is optional for recommended or strict conformance.
- Documented the existing packaged action `root` input for monorepo or
  subdirectory adoption while keeping policy and evidence paths root-relative.
- Corrected release wording to describe `vX.Y.Z` version tags and added
  regression coverage for explicitly empty MCP `forbidden_risky_patterns`
  weakening.

## 0.1.19 - 2026-06-30

- Tightened `0.1.x` alpha recommended evidence so `report --evidence-preset
  recommended` expects the reviewed repo-local `.agent-guard/mcp-policy.yaml`
  by default and reports a sanitized violation when it is missing.
- Resolved MCP policy paths for `mcp check --policy` and `report --mcp-policy`
  relative to `--root`, while displaying repo-external policy files as
  `<external-policy>` in public payloads.
- Made recommended and strict conformance require the repo-local MCP policy and
  fail when its `forbidden_risky_patterns` omits any default deterministic MCP
  risk labels, while leaving direct `mcp check --policy` subset experiments
  supported.
- Preserved the static evidence boundary: no runtime MCP execution, live OAuth
  validation, generic secret scanning, LLM review, or autonomous policy
  execution was added.

## 0.1.18 - 2026-06-30

- Kept raw per-scanner JSON out of generated CI artifacts by writing scanner
  diagnostics to temporary runner storage while publishing only sanitized
  report, conformance, SARIF, and evidence-pack outputs.
- Made profile conformance fail closed on malformed surface inventory counts
  without exposing local report paths in the CLI error envelope.
- Updated starter, documentation, and repository workflows to the current
  `actions/checkout@v7` major while keeping uploadable evidence read-only and
  review-first.
- Clarified that static MCP labels and risk-theme crosswalks are repository
  review evidence, not runtime MCP execution, live OAuth validation, MCP
  tool-poisoning detection, generic secret scanning, SLSA/provenance
  verification, or compliance attestation.

## 0.1.17 - 2026-06-30

- Extended the deterministic MCP config gate with sanitized static labels for
  unsafe URL schemes, inline authorization values, and broad authorization
  scopes.
- Mapped the new MCP labels to OWASP Agentic risk-theme metadata while keeping
  them as review context, not runtime vulnerability detection or compliance
  proof.
- Added regression coverage that verifies MCP auth/scope/URL findings do not
  emit raw URLs, authorization values, scope strings, host fragments, or local
  paths in public JSON evidence.
- Updated docs and release examples for `0.1.17` while keeping MCP server
  execution, live OAuth validation, tool-poisoning detection, and generic secret
  scanning out of scope.

## 0.1.16 - 2026-06-29

- Promoted committed MCP configuration metadata into a first-class deterministic
  static evidence gate via `agent-guard mcp check` and report
  `--mcp-config-check`.
- Included the `mcp_config` gate in the recommended evidence preset and
  recommended conformance profile, while keeping repository-specific API and
  digest evidence opt-in.
- Added sanitized MCP findings to JSON reports, Markdown, GitHub annotations,
  and SARIF without emitting raw MCP args, env values, secret-shaped server
  names, or local absolute paths.
- Updated the composite Action, starter workflow, self-dogfood workflow, schemas,
  docs, and public sample around the static MCP gate while keeping MCP server
  execution, runtime tool-poisoning detection, and MCP security validation out
  of scope.

## 0.1.15 - 2026-06-29

- Hardened the public composite Action by moving user-supplied inputs out of
  generated shell scripts and into quoted environment variables, with
  allowlist validation for conformance profile and annotation options,
  control-character rejection for shell/path inputs, and safe multiline output
  records.
- Made strict conformance fail on malformed MCP config files surfaced by v2
  inventory, while keeping MCP server execution and runtime validation out of
  scope.
- Removed stale release-candidate execution notes from the public repository and
  kept local execution notes ignored and excluded from package artifacts.

## 0.1.14 - 2026-06-29

- Strengthened the downstream evidence consumer example so it fails closed on
  inconsistent report status, finding counts, evidence coverage, and surface
  inventory counts.
- Added `owasp_agentic_risk_themes` metadata to deterministic sanitized report
  findings, rendered Markdown, GitHub annotations, and SARIF rule properties as
  a review crosswalk to OWASP Agentic Top 10 risk themes.
- Added strict conformance findings for risky MCP configuration metadata from
  surface inventory v2, while keeping MCP server execution and runtime
  poisoning detection out of scope.
- Added a composite Action `conformance-profile` input so adopters can stay on
  the recommended profile or opt into strict MCP configuration review.
- Updated packaged schemas, public evidence docs, and README examples without
  adding LLM review, issue triage, generic secret scanning, agent execution UI,
  or broad governance behavior.

## 0.1.13 - 2026-06-29

- Corrected the release provenance verification example so it downloads both
  the wheel and sdist explicitly from the PyPI release JSON before running
  `gh attestation verify`.

## 0.1.12 - 2026-06-29

- Added GitHub artifact attestations for release workflow `dist/*` outputs so
  published wheel and sdist files can be verified against release workflow
  provenance.
- Documented release provenance verification and its limits: attestation
  verification proves artifact identity and build provenance, not code
  correctness, maintainer approval, or absence of vulnerabilities.
- Kept the change in the release pipeline and documentation only; no generic
  reviewer, issue triage, secret scanner, runtime UI, or governance framework
  behavior was added.

## 0.1.11 - 2026-06-29

- Added optional `--base-ref` / `--drift-base-ref` policy/spec drift evidence
  that flags changed `.agent-guard` policy files, digest policy files, and
  guard workflow/action surfaces relative to an explicit git base ref.
- Added a composite action `base-ref` input that passes the same opt-in
  baseline comparison into raw drift JSON and the sanitized evidence report.
- Kept baseline comparison as review evidence only: reports emit controlled
  categories and repository-relative paths, not raw diffs, hashes, workflow
  bodies, branch names, local paths, or approval decisions.
- Updated adoption docs to pair baseline-sensitive change evidence with
  digest and context-lock checks without expanding into runtime authorization
  or broad governance tooling.

## 0.1.10 - 2026-06-29

- Added `agent-guard render-report` to render an existing sanitized JSON report
  into Markdown, SARIF, GitHub annotations, or canonical JSON without rerunning
  scanner and policy checks.
- Moved report rendering helpers into a small dedicated module so CI delivery
  code no longer imports private CLI helpers.
- Updated the composite GitHub Action and `agent-guard init` starter workflow
  to render Markdown, SARIF, and annotations through the public CLI.
- Expanded default agent-context rules for delegation-based policy bypasses,
  broad tool auto-allow instructions, unreviewed agent output, unreviewed
  background agents, and unreviewed guard suppressions.
- Added public-safe rendering examples and updated adoption docs to keep the
  sanitized JSON report as the single source for review surfaces.
- Clarified the public artifact boundary: raw per-scanner JSON is local/CI
  automation material, while report/render-report/conformance/evidence-pack
  outputs are the reviewable sanitized artifacts.
- Expanded surface inventory v2 with metadata-only agent skills, agent
  profiles, agent commands, hooks, and MCP config references without emitting
  instruction bodies, MCP args, env values, secrets, or local paths.
- Recognized `python3 -m agent_guard.cli` workflow references in addition to
  `python -m agent_guard.cli` and `agent-guard` commands.

## 0.1.9 - 2026-06-28

- Added a root composite GitHub Action that generates recommended
  `agent-guard` evidence reports and exposes artifact paths for upload.
- Added packaged `pre-commit` hooks with an evidence-first hook before the
  individual context, path, and content scanners.
- Expanded default agent-context rules for approval bypasses, verification
  skips, audit-trail removal, unsafe publication, sandbox and permission
  boundary weakening, and private-data exfiltration instructions.
- Added deterministic context drift classifications for unsafe context
  instructions and context-lock digest drift.
- Added `agent-guard report --format sarif` as a snippet-free SARIF 2.1.0
  adapter over sanitized report evidence.
- Strengthened strict conformance to require a sanitized evidence-pack manifest
  with a report artifact reference.
- Updated README and quickstart docs with badges, an evidence-first adoption
  path, and a narrow public positioning note.

## 0.1.8 - 2026-06-28

- Added `agent-guard report --evidence-preset recommended` as a shorter
  adoption path for the recommended static evidence bundle.
- Added optional `--agent-policy-audit-event` artifact references for
  evidence-pack manifests without reading or embedding runtime event bodies.
- Tightened packaged evidence schemas around conformance profiles and evidence
  artifact roles.
- Updated workflow parsing to recognize GitHub Actions `parallel` step groups
  while keeping repository CI serial until the lint toolchain accepts the new
  syntax.

## 0.1.7 - 2026-06-28

- Added profile-based conformance evidence for `minimal`, `recommended`, and
  `strict` adoption levels.
- Added sanitized evidence pack manifests for pull request review artifacts.
- Added surface inventory v2 metadata for documented guard commands and
  evidence artifact references without emitting raw workflow commands.
- Added profile-aware policy/spec drift v2 checks for README, workflow policy,
  guard policy files, and required agent-context safety boundary categories.
- Updated the downstream evidence consumer and packaged schemas for the new
  conformance and evidence-pack contracts.

## 0.1.6 - 2026-06-28

- Added review-first `agent-guard init` for printing or writing starter
  `.agent-guard` policies and a CI evidence workflow without overwriting
  existing files by default.
- Added `agent-guard surface inventory` to enumerate agent context files,
  `.agent-guard` policy files, workflow files, and agent-guard workflow
  references as sanitized repository-relative metadata.
- Added `agent-guard drift check` plus optional `agent-guard report
  --drift-check` evidence for README recommended guard commands,
  workflow-policy declarations, and required guard policy files.
- Added report `surface_inventory` and `evidence_coverage` payloads so
  downstream consumers can see enabled, missing, clean, and failing gates.
- Updated CI self-dogfood, public evidence docs, and the downstream evidence
  consumer to validate the expanded deterministic evidence contract.

## 0.1.5 - 2026-06-27

- Added packaged JSON Schema resources for the shared result envelope, context
  inventory, context lock coverage, and sanitized report evidence contracts.
- Added `agent-guard report --output <path>` so CI can write deterministic
  Markdown or JSON evidence artifacts without stdout redirection.
- Added hash-free covered context file evidence to context lock coverage and
  report JSON/Markdown output.
- Updated self-dogfood CI to upload sanitized evidence report artifacts.
- Kept SARIF intentionally deferred until the JSON evidence contract has more
  downstream usage.

## 0.1.4 - 2026-06-27

- Added `agent-guard report --format json` for sanitized machine-readable
  evidence reports backed by the shared `agent-guard.result.v1` envelope.
- Added golden fixture coverage for Markdown, JSON, and GitHub annotation
  report evidence outputs.
- Added `agent-guard context lock --check --digest-policy <yaml>` to fail when
  discovered agent context files are missing from, partially pinned by, or
  mismatched against a committed digest policy.
- Added context lock coverage evidence and an `agent-guard.report_evidence.v1`
  contract marker to sanitized reports.
- Documented SARIF as intentionally deferred while JSON and GitHub annotations
  remain the supported CI-friendly report formats.

## 0.1.3 - 2026-06-26

- Added `agent-guard context inventory --json` for redacted agent context
  metadata, permission-boundary evidence, and CI-friendly audit records.
- Kept `context check --json` unchanged while adding the opt-in inventory
  command to the shared scanner result envelope.
- Added `agent-guard workflow check` for deterministic CI guard-command and
  required-policy-file drift checks.
- Added optional workflow drift evidence to `agent-guard report`.
- Added optional path, content, and API evidence sections to
  `agent-guard report` without emitting snippets, URLs, raw regex patterns, or
  absolute local paths.
- Added `agent-guard report --format github-annotations` for sanitized
  GitHub Actions annotations backed by the same report evidence payload.
- Added `agent-guard context lock` to generate digest policy checks for
  discovered agent context files without emitting raw context content.

## 0.1.2 - 2026-06-26

- Added the `context` scanner for agent instruction files such as `AGENTS.md`,
  `CLAUDE.md`, `.github/copilot-instructions.md`, Cursor, Windsurf, and
  Continue rule files.

## 0.1.1 - 2026-04-30

- Added path, digest, and content scanner guidance for `ai-resilience-system` CI gates.
- Added README coverage for the static gate recipe.
- Published the first PyPI release consumed by `ai-resilience-system` final gates.
