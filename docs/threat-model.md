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

## Trust Boundaries

Repository files are input to deterministic scanners, not instructions to the
scanner implementation. External pages, papers, generated reviews, MCP server
metadata, tool descriptions, tool outputs, and workflow logs are review data
only; they do not become authority for `agent-guard` behavior.

Maintainers remain responsible for deciding whether a finding is acceptable.
`agent-guard` emits evidence, not approval decisions.

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
- that an OWASP risk-theme label is exploitable in the current repository.

Those questions require runtime controls, dedicated credential scanners,
provenance checks, human review, or domain-specific security testing.

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

MCP, OWASP agentic risk material, and research on indirect prompt injection,
AgentDojo, and MCP tool poisoning describe runtime failure modes that static
metadata cannot settle.

`agent-guard` uses that context to keep repository evidence explicit and
sanitized. It should not absorb runtime validation layers.
