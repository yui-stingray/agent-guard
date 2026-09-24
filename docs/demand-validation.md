# Demand Validation

**Decision owner:** `agent-guard` repository maintainer.

**Measurement owner:** the same maintainer, with an independent review of the
aggregate decision record.

**Evidence location:** private maintainer records keyed by observation date.
Do not commit raw clone/traffic details, outreach identities, or private replies.
The public repository records only aggregate signal values, source types, the
go/no-go result, the review date, and maintainer sign-off.

**Decision record:** add the aggregate result to this document, or link a
reviewed public issue/PR, on the decision date. Until then, status is `pending`.
Status: recorded; see [2026-09-21 Decision Record](#2026-09-21-decision-record).

`agent-guard` is in **VALIDATE-NARROW**. Public feature expansion is frozen
while the project tests whether its current static evidence package and GitHub
Action solve a repeatable external need.

## Window and Decision

The validation window is 2026-08-10 through 2026-09-20. On 2026-09-21, decide
whether to continue public feature investment using the gates below. Until then,
work is limited to maintenance and self-infrastructure, with a maximum of four
hours per week for validation work. Outreach and measurement stop on
2026-09-20. An extension requires a new explicit maintainer decision that
records a new period, budget, and hypothesis.

## What Counts

- **Qualified exposure**: an external maintainer receives enough reviewed,
  project-relevant information to evaluate the current package without a
  demand-only follow-up. Deduplicate this denominator by person, organization,
  and proposal, and record it even when adoption does not follow.
- **Owner-external repository**: a repository not owned or controlled by the
  `agent-guard` project owner. Forks, project-owned repositories, and the public
  demo are excluded.
- **Activation**: an external maintainer adopts `agent-guard` configuration or
  workflow on an owner-external repository's default branch, and a qualifying
  CI run or documented reproduction succeeds from that branch. An owner-created
  pull-request branch, a review comment, or green CI on that branch does not
  count. Count at most one activation per organization.
- **Qualifying success**: the adopted configuration is executed against an
  identified default-branch revision using an exact published package version
  or immutable release Action pin. The selected documented command must return
  its successful status; a diagnostic finding status does not count as success.
  Keep a dated private measurement record of the revision, version or pin,
  command, and result. Public summaries must not expose repository identifiers,
  commit hashes, raw output, or other private evidence.
- **Retention**: at least 14 days after activation, the adopted configuration
  remains on the default branch and a qualifying run after that 14-day point
  succeeds. To mature before the end of this window, an activation must occur
  no later than 2026-09-06. Count at most one retained result per activation.
  Later activations may count toward activation, but cannot count toward
  retention in this validation window.
- **Specific feedback**: feedback from an external person that identifies a
  concrete setup, outcome, integration need, or caught issue; an unqualified
  endorsement does not count. Deduplicate by person, organization, and topic.

## Continuation Gate

Continue public feature investment only when all of the following are true on
2026-09-21:

- activations are at least 3;
- retained activations are at least 2; and
- at least 2 external people have supplied at least 3 specific feedback items
  in total.

These thresholds are minimum evidence for considering another bounded public
investment, not statistical validation or product-market-fit evidence. If any
gate is unmet or cannot be measured, the 2026-09-21 decision is **NO-GO** for
public feature investment. Continue only maintenance and self-infrastructure
unless the maintainer records a new explicit decision.

## External Contact Boundary

- Reply when a maintainer asks a question or requests a change, or when a
  materially new fact could change the review decision.
- Do not post "just checking in" comments or comments whose only purpose is
  demand measurement.
- Across all proposals in this window, an owner-initiated follow-up is limited
  to one per person or organization and must be at least 14 days after the
  previous owner comment.
- A decline, closure, unanswered permitted follow-up, or conduct concern ends
  all owner-initiated contact with that person or organization unless the
  recipient reinitiates.
- Comments, open pull requests, and pull-request-branch CI never count as an
  activation.

## Scope and Public Artifact Hygiene

This validation does not add runtime MCP execution, live OAuth validation, an
LLM reviewer, or a generic secret scanner. GitHub Marketplace publication,
whether manual or automated, is out of scope and remains prohibited until a
new explicit maintainer instruction authorizes that separate action. Meeting
the continuation gate does not authorize publication. Maintenance and
self-infrastructure may improve reliability, compatibility, or project-owned
validation, but must not create a new public feature surface.

For public updates, use sanitized aggregate metrics or feedback approved for
public quotation. Do not publish raw reports, raw CI logs, repository contents,
unapproved repository identifiers, local paths, credentials, private data, or
unreviewed feedback. The existing [public-artifact contract](evidence-contracts.md)
remains the boundary for generated evidence.

## 2026-09-21 Decision Record

**Result: NO-GO for public feature investment.** Recorded on 2026-09-24 for
the 2026-09-21 decision date.

| Signal | Gate | Observed | Source types |
| --- | --- | --- | --- |
| Activations | at least 3 | 0 | public code search, repository issues and pull requests, owner records |
| Retained activations | at least 2 | 0 | no activation matured by 2026-09-06 |
| Specific feedback | at least 3 items from at least 2 people | 0 items, 0 people | repository issues and pull requests, public mentions, owner records |
| Qualified exposures | recorded, no gate | 0 | owner outreach records |

Package downloads and repository clone counts were reviewed but are not
signals under [What Counts](#what-counts): they cannot be attributed to an
owner-external default branch, and project-owned CI installs the published
package on every run.

Consequences, per the [Continuation Gate](#continuation-gate):

- Public feature expansion stays frozen. Work is limited to maintenance and
  self-infrastructure that does not create a new public feature surface.
- The [release freeze](release-criteria.md#demand-validation-freeze) stays in
  effect, except for the one stable-point release below.
- Outreach and measurement for this window have ended. Any new window requires
  a new explicit maintainer decision that records a new period, budget, and
  hypothesis.

### Stable-Point Release Exception

The maintainer approves one release, `0.3.10`, as an explicit freeze
exception. Rationale: publish a stable point of the current default branch,
which carries the bug fixes accepted since `0.3.9`, so installed users do not
stay on known-fixed defects.

- Scope is the full default branch at release preparation: every change listed
  under `Unreleased` in `CHANGELOG.md`, plus release preparation.
- The release follows [Release Readiness](release-criteria.md#release-readiness)
  and the post-release Action pin refresh. Required CI is not bypassed.
- This exception does not lift the freeze, does not change the NO-GO result,
  and does not authorize Marketplace publication. Later releases need their own
  decision.

Maintainer sign-off: yui-stingray, 2026-09-24.
Independent review of this aggregate record: this pull request's review.
