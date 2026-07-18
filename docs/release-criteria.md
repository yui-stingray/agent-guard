# Release Criteria

`agent-guard` is still `0.x` alpha. Releases should stay small, batched, and
evidence driven. The default is to protect schema/contract stability rather
than publish every isolated change immediately.

## Batched Release Cadence

Do not cut a patch release for every qualifying change. By default, batch
reviewed release candidates on a weekly cadence. Cut an earlier patch only when
a P0 fix needs to reach installed users before the next batch.

When cutting an earlier P0 patch, record a one-sentence, public-safe rationale
in the release-preparation pull request or that release's CHANGELOG entry. Keep
embargoed vulnerability details, credentials, private incident data, and local
paths out of the rationale.

A release batch may include:

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

The reason for batching is schema/contract stability, not process for its own
sake. `agent-guard` is an evidence contract; frequent shape changes make
downstream wrappers and golden-file consumers less trustworthy even when each
individual change is small.

## Release Readiness

Before tagging, verify:

- full test suite passes on the supported Python versions;
- self-dogfood `path`, `context`, `context lock`, `digest`, `content`,
  `workflow`, `surface inventory`, `drift`, and `report` gates pass;
- packaged schemas are present in the wheel;
- wheel contract check passes from a clean install;
- the clean build contains exactly the current wheel and sdist, and
  exact-version PyPI metadata exposes exactly those two files as non-yanked;
- GitHub Actions CI is green on the release commit;
- no generated private evidence, local paths, credentials, or private fixtures
  are tracked.
- the release workflow creates provenance attestations for the built wheel and
  sdist, and verification examples name the expected tag, repository, and
  signer workflow explicitly.

The release workflow remains tag-driven. Do not publish from an unreviewed
branch.

## GitHub Marketplace Readiness

GitHub Marketplace publication is not part of the automated release workflows.
It remains a separate manual action that requires explicit maintainer approval.
Before submitting the Marketplace release form:

- use the candidate Action name `agent-guard static evidence` and confirm that
  GitHub's final uniqueness validator still accepts it;
- use `Security` as the primary category and `Code quality` as the secondary
  category; do not select `Code Scanning Ready`, because the Action emits SARIF
  but does not upload it to GitHub code scanning;
- require the release commit's CI `packaged action smoke` job to pass, so the
  checked-out composite Action, its public outputs, and the packaged evidence
  consumer are verified before the release tag can publish to PyPI;
- keep the Action description and release notes explicit that the package is
  alpha and static-only, not a runtime agent, MCP, OAuth, or LLM validator;
- use exact version tags while the package is `0.x`; do not create a moving
  `v0` alias that silently changes an alpha consumer's code;
- stop at the validated release form until the maintainer separately approves
  Marketplace publication and any required developer agreement.

## Release Provenance

Release distributions are built in the tag-triggered release workflow, checked
with `twine` and the wheel contract script, then passed to a separate
least-privilege attestation job as `dist/*` artifacts before publication. PyPI
upload uses Trusted Publishing, and
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
