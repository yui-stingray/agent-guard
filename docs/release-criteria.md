# Release Criteria

`agent-guard` is still `0.1.x` alpha. Releases should stay small and evidence
driven.

## Patch Release Candidates

Consider the next patch release when at least one of these changes lands:

- a CLI behavior change that downstream CI users need from PyPI;
- a new deterministic evidence surface such as init, surface inventory, or
  policy/spec drift checks;
- a packaged JSON Schema change or new packaged schema;
- a report payload compatibility fix;
- a workflow, packaging, or wheel-contract fix that affects installed users;
- documentation that must appear on PyPI because the README changed materially.

Docs-only changes under `docs/` do not need an immediate release unless they
change the README or are needed by users who only read the packaged project
page.

## Release Readiness

Before tagging, verify:

- full test suite passes on the supported Python versions;
- self-dogfood `path`, `context`, `context lock`, `digest`, `content`,
  `workflow`, `surface inventory`, `drift`, and `report` gates pass;
- packaged schemas are present in the wheel;
- wheel contract check passes from a clean install;
- GitHub Actions CI is green on the release commit;
- no generated private evidence, local paths, credentials, or private fixtures
  are tracked.
- the release workflow creates provenance attestations for the built wheel and
  sdist, and verification examples name the expected tag, repository, and
  signer workflow explicitly.

The release workflow remains tag-driven. Do not publish from an unreviewed
branch.

## Release Provenance

Release distributions are built in the tag-triggered release workflow, checked
with `twine` and the wheel contract script, then attested as `dist/*` artifacts
before the publish job downloads them. PyPI upload uses Trusted Publishing, and
the PyPA publish action uploads PyPI-compatible distribution attestations for
the same files.

Treat this as provenance and integrity evidence only. A successful attestation
verification proves that an artifact matches a signed statement from the named
GitHub workflow identity and tag. It does not prove code correctness,
maintainer approval, dependency safety, branch protection, secret absence, SLSA
level, vulnerability absence, or security/compliance certification.

## Non-Goals For Releases

Do not use a release as a reason to expand into LLM review, issue triage,
model routing, MoA orchestration, broad credential scanning, or a general
governance framework. Do not use release pressure to add runtime MCP execution,
live OAuth validation, MCP tool-poisoning detection, or an MCP security
validator. Those tools can consume `agent-guard` evidence, but they should
remain separate layers.
