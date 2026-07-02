# OWASP Agentic Skills Top 10 Crosswalk

This crosswalk is documentation-first and additive. `agent-guard` still emits
the existing `owasp_agentic_risk_themes` ASI labels in findings; AST labels are
not a required finding field and are not a claim of runtime exploit detection.

The OWASP Agentic Skills Top 10 is still incubator-stage, with a v1.0 release
candidate expected in Q3 2026. Treat this page as review context until the AST
taxonomy is final.

## AST Categories

| Code | Category |
| --- | --- |
| AST01 | Malicious Skills |
| AST02 | Supply Chain Compromise |
| AST03 | Over-Privileged Skills |
| AST04 | Insecure Metadata |
| AST05 | Untrusted External Instructions |
| AST06 | Weak Isolation |
| AST07 | Update Drift |
| AST08 | Poor Scanning |
| AST09 | No Governance |
| AST10 | Cross-Platform Reuse |

## Current agent-guard Mapping

| agent-guard capability | AST relevance | Coverage today |
| --- | --- | --- |
| Context guard | AST05, AST09 | Partial. Finds risky committed agent instructions and missing review/governance evidence in known context files; it does not prove whether a skill runtime obeys those instructions. |
| Surface inventory | AST01, AST04, AST10 | Partial. Inventories repo-local skill/profile/command directories and metadata-bearing surfaces so reviewers can notice skill surfaces and cross-platform reuse; it does not classify a skill as malicious. |
| MCP config guard | AST02, AST03, AST06 | Adjacent. Flags unpinned package references, broad filesystem/authorization patterns, and inline secret-shaped values in committed MCP configuration; MCP servers are not the same artifact as AST skills. |
| Digest pinning and context lock | AST02, AST06, AST07 | Partial. Pins reviewed context files and detects missing, partial, or drifted digest coverage; it does not sandbox execution. |
| Workflow guard | AST07, AST09 | Partial. Checks committed CI evidence commands and required policy files so guard coverage changes are visible in review. |
| Policy/spec drift | AST07, AST09 | Partial. Reports changes to guard policies, workflows, hooks, README guard commands, and pinned context coverage. |
| Evidence pack | AST08, AST09 | Partial. Packages sanitized review evidence and artifact manifests so evidence can be consumed consistently. |
| Conformance | AST08, AST09 | Partial. Evaluates whether expected gates, surfaces, policy files, and evidence sections are present for a selected profile. |

## Non-Coverage

`agent-guard` does not execute skills, inspect live tool calls, verify OAuth
scopes, evaluate model behavior, or decide that a skill is exploitable. AST
coverage remains static repository evidence only.
