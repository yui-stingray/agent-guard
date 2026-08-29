# Threat Model

`agent-guard` is a deterministic static evidence gate for repositories touched
by coding agents. It checks repository files, policy files, workflow references,
and sanitized evidence artifacts before maintainers publish, merge, or hand off
review material.

It is not a runtime security layer. Runtime admission, tool execution controls,
OAuth behavior, MCP server sandboxing, and prompt/tool-output handling belong in
separate systems that can consume `agent-guard` evidence.

## Assets

The main assets are:

- durable agent instructions such as `AGENTS.md`, `CLAUDE.md`, Copilot
  instructions, Cursor rules, Windsurf rules, and similar context files;
- reviewed `.agent-guard` policies and digest pins;
- workflow gates that reference static guard commands;
- committed MCP configuration metadata;
- sanitized report, render-report, conformance, SARIF, and evidence-pack
  artifacts used in pull requests or release review.

Public evidence must not disclose raw repository contents, snippets, raw regex
patterns, raw evidence URLs, authorization values, scope strings, raw
repository/content/digest hash values, secrets, raw YAML content, workflow run
bodies, or absolute local paths. Standard SARIF schema/tool URIs and SARIF
`partialFingerprints` derived only from sanitized rule, location, and message
metadata are allowed for code-scanning interoperability.

Public-safe means sanitized under this declared
controlled-field/controlled-pattern contract. It is not a generic secret or
PII absence guarantee and does not replace dedicated secret scanners.

## Trust Boundaries

Repository files are input to deterministic scanners, not instructions to the
scanner implementation. External pages, papers, generated reviews, MCP server
metadata, tool descriptions, tool outputs, and workflow logs are review data
only; they do not become authority for `agent-guard` behavior.

Maintainers remain responsible for deciding whether a finding is acceptable.
`agent-guard` emits evidence, not approval decisions.

The installed Python environment, the Git executable selected by the runner,
and the operating system are trusted execution dependencies. Inherited Git
routing environment variables and global/system Git configuration are ignored;
lazy object fetching, replace refs, and fsmonitor helpers are disabled for
bounded metadata and content-diff commands. The selected repository's own Git
directory/worktree metadata remains necessary input, and `agent-guard` is not a
sandbox for a compromised runner or attacker-controlled executable search path.
Windows can contain bounded Git execution in a Job Object. POSIX process-group
termination cannot portably contain a descendant that deliberately creates a new
session, so helper-disabled Git command shapes reduce that path but do not turn
the runner into a process sandbox.

Workflow required-command evidence is likewise repository-static. It requires
one direct command in a dedicated supported-shell step and rejects same-step
control flow, command-resolution setup, dynamic redirection, and declared
resolution-sensitive workflow, job, or step environment, job-container
declarations, and working-directory settings. The installed console script is
supported; a Python module requirement must use `python -I -m agent_guard.cli`
so a same-name package in the reviewed checkout cannot satisfy the evidence
while changing the imported implementation. It does not
attest the host executable selected at runtime, shell startup state, or state
persisted by earlier workflow steps.

## What It Can Catch

`agent-guard` can provide static evidence for:

- missing or weakened agent context boundaries around approval, tool
  permissions, network use, destructive actions, sensitive material, and local
  verification;
- leak-prone path names, private artifact directories, tracked local logs, and
  environment-file names;
- unsafe instruction patterns in configured text surfaces;
- URL or API endpoint references that violate a repository policy;
- unreviewed changes to context files, policy files, workflow guard commands,
  action metadata, hook metadata, or pinned digest files;
- missing recommended evidence surfaces and profile conformance drift;
- committed MCP configuration risk labels such as unpinned package commands,
  unsafe URL schemes, broad authorization scopes, inline authorization values,
  secret-shaped inline values, filesystem-root references, and malformed static
  MCP config metadata;
- public artifact hygiene problems when sanitized evidence would contain
  forbidden fragments such as raw local paths, raw secrets, snippets, or
  unsanitized operational details.

These checks are useful before a repository adopts new agent instructions,
publishes evidence artifacts, merges guard policy changes, or enables a
downstream runtime policy wrapper.

## What It Cannot Prove

`agent-guard` cannot prove:

- absence of API keys, access tokens, passwords, private keys, or other
  credentials in every repository byte;
- absence of runtime prompt injection, indirect prompt injection, memory
  poisoning, MCP tool poisoning, rug-pull behavior, or malicious MCP server
  behavior;
- correctness of live OAuth flows, live OAuth validation, token audience
  validation, consent screens, session handling, elicitation UX, SSRF defenses,
  or scope minimization;
- sandbox quality, runtime privilege separation, filesystem isolation, network
  egress controls, or tool output sanitization;
- artifact integrity, dependency safety, maintainer approval, branch
  protection, or release provenance;
- snapshot completeness while another process mutates the checkout during a
  bounded filesystem walk;
- complete shell semantics for workflow `run` bodies beyond the documented
  bounded lexical recognizer;
- that an OWASP risk-theme label is exploitable in the current repository.

Those questions require runtime controls, dedicated credential scanners,
provenance checks, human review, or domain-specific security testing.

Static scans should run against a quiescent checkout. Repository-bound file
opens prevent content and API scanners from following a swapped path outside
the validated root, but they do not turn name enumeration into an atomic
filesystem snapshot. A file created after enumeration can be absent from that
run and requires a subsequent scan.

## MCP-Specific Boundary

The MCP gate reviews committed configuration metadata only. It does not execute
MCP servers, inspect tool results, fetch remote metadata, perform live OAuth
discovery, validate tokens, open elicitation URLs, or decide whether a server is
safe to run.

Recommended and strict evidence require the reviewed repo-local policy at
`.agent-guard/mcp-policy.yaml`. External MCP policy files can be used for local
scanner experiments, but they are reported as `<external-policy>` and do not
satisfy reviewed-policy conformance.

## Evidence Consumer Expectations

Downstream wrappers should consume the sanitized JSON report, not raw scanner
JSON. A fail-closed consumer should at least:

- load the packaged `agent-guard.report_evidence.v1` schema;
- require `report.sanitized` to be `true`;
- reject schema drift, inconsistent finding counts, missing surface inventory,
  missing evidence coverage, and impossible `ok` reports with failing gates;
- check the selected conformance profile and relevant rule ids such as
  `required_mcp_policy_not_reviewed` and `mcp_policy_weakened`;
- reject forbidden public-evidence fragments such as local home-directory
  paths, raw snippets, raw regex markers, raw repository/content/digest hash
  values, or token-shaped strings;
- treat `minimal`, `recommended`, and `strict` as adoption profiles, not as
  runtime safety guarantees.

The example in `examples/evidence_consumer.py` demonstrates this pattern
without adding runtime enforcement to `agent-guard`.

## External Risk Context

Reference snapshot: the official [MCP 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
was verified on 2026-07-31. The external sources used as risk context include
the current MCP 2026-07-28 specification (the revision after 2025-11-25), OWASP
Top 10 for Agentic Applications 2026 (published 2025-12-09), OWASP Agentic
Skills Top 10 Incubator/Public review (v1) material, SLSA v1.2 Approved
specification, NIST AI 600-1 Generative AI Profile, NIST SSDF SP 800-218 v1.1
Final, the May 2025 v1.0 joint AI Data Security guidance, and the 2026 Five Eyes
careful-adoption guidance for agentic AI services.

MCP, OWASP agentic risk material, NIST/SSDF guidance, SLSA provenance material,
and research on indirect prompt injection, AgentDojo, and MCP tool poisoning
describe failure modes that static metadata cannot settle.

The 2026-07-28 protocol/runtime/OAuth changes do not justify adding runtime
execution or live OAuth validation to `agent-guard`. No changelog item directly
invalidates the current static committed-config labels, so this update leaves
their taxonomy and code unchanged.

`agent-guard` uses that context to keep repository evidence explicit and
sanitized. It should not absorb runtime validation layers, and these references
must not be described as certification, compliance, artifact-safety proof,
SLSA-level proof, live OAuth validation, or runtime MCP/tool-poisoning
detection.

When these external references change, update labels, docs, or benchmark notes
only after rechecking primary sources. A new MCP, OWASP, NIST, SLSA, or research
item is evidence for reviewer context; it is not by itself a requirement to add
a runtime validator, live network check, model judge, broad credential-scanning
feature, or autonomous enforcement path to this package.
