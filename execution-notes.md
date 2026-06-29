# Execution Notes

## Open Items

- Decide whether to commit, push, tag, and publish; publishing remains a separate human-visible step.

## Decisions

- Keep the product boundary as static evidence contracts for AI-agent-maintained repositories.
- Do not add AST analysis, framework-specific parsers, runtime MCP firewall behavior, LLM review, issue triage, or generic secret scanning.
- Treat MCP risky patterns as metadata/evidence first; only strict conformance should fail on unresolved risky MCP metadata.
- Use `owasp_agentic_risk_themes` only as deterministic evidence metadata and rendered review context, not as a runtime detection or compliance claim.
- Keep the composite Action default at recommended conformance; strict MCP config review is opt-in through `conformance-profile`.

## Evidence Checked

- Started from clean `v0.1.13` worktree.
- Reviewed external evaluation memo and positioning doc.
- Reviewed existing evidence consumer, schema, report, surface inventory, profile, action, and packaging tests.
- Implemented stricter public evidence consumer consistency checks.
- Added OWASP Agentic Top 10 static risk-theme metadata to report findings, Markdown, GitHub annotations, and SARIF rule properties.
- Added strict conformance findings for risky MCP configuration metadata from v2 surface inventory.
- Added composite Action `conformance-profile` input and docs describing recommended vs strict usage.
- Targeted tests passed for OWASP metadata, rendered report fixtures, strict MCP conformance, and evidence consumer hardening before docs/schema synchronization.
- Bumped release-candidate version to 0.1.14 and added changelog entry because report/schema/action/README public surfaces changed.
- Full pytest passed with `TMPDIR=/tmp` after the version/sample updates.
- `actionlint` 1.7.12 passed.
- Built `yui_agent_guard-0.1.14` wheel/sdist, `twine check` passed, and `scripts/check_wheel_contract.py` passed from an isolated install.
- `scripts/check_pypi_release_state.py` reported latest PyPI version 0.1.13 and candidate 0.1.14.
- Self-dogfood path/context/context-lock/digest/content/workflow/surface/drift/report/render/conformance/evidence-pack commands passed with status ok and finding_count 0.
- Public sample and temporary self-dogfood evidence leak checks found no user-home path fragments, snippets, matched text, raw regex, SHA-256 text, or credential-like key fragments.
- First independent review blocked on two issues: `taxonomy.py` could be missed by a release commit because it was a new untracked file, and the hardened consumer rejected schema-valid `status: error` report envelopes.
- Added intent-to-add index entries for new files so the release diff includes `src/agent_guard/taxonomy.py` and `execution-notes.md`; no commit/tag/push has been performed.
- Fixed the evidence consumer to accept schema-valid sanitized error report envelopes while still validating status/exit-code/error/finding-count consistency, and added a regression test.
- After that fix, `tests/test_evidence_consumer.py`, full pytest with `TMPDIR=/tmp`, `git diff --check`, build, `twine check`, and `scripts/check_wheel_contract.py` all passed again.
- Final independent review returned ACCEPT with no findings for the local v0.1.14 release candidate.
- Excluded `execution-notes.md` from packaged build artifacts; rebuilt the wheel/sdist and verified the sdist and wheel include `src/agent_guard/taxonomy.py` but not `execution-notes.md`.
- Final checks passed: full pytest with `TMPDIR=/tmp`, `actionlint`, PyPI release-state candidate check, public sample consumer check, and real-user-path fragment scan.

## State

- Status: local release candidate ready.
- Current risk: no commit, push, tag, release workflow run, PyPI publish, or demo pin update has been performed yet.
