# Operations Governance

This runbook owns only `agent-guard` operational controls and the integration
sequence initiated from this repository. The system coordination baseline is
[`architecture/agent-guard-ecosystem-design.md`](architecture/agent-guard-ecosystem-design.md),
but it does not transfer operational authority over `agent-policy` or the
reference toolkit. Each repository maintainer owns and approves that
repository's rulesets, release controls, incident actions, and implementation.
Cross-repository requirements take effect in an affected repository only through
that repository's reviewed change and local controls.

## Normal Path

- Change code and contracts through a reviewed pull request.
- Require the stable aggregate configured for the default branch.
- Build a candidate distribution once and run the cross-repository toolkit
  compatibility gate before publication.
- Publish only from an annotated `vX.Y.Z` tag that peels to the protected
  default branch commit with successful required CI.
- Keep release tags immutable. Never move or reuse a published version.
- Update toolkit pins, hashes, docs, and evidence only after the exact public
  distribution is available and verified.

## Break-Glass

A required check failure blocks merge by default in the affected repository.
Repeated reruns are not a substitute for diagnosis. A provider outage or
verified CI infrastructure defect
may use break-glass only when all of the following are recorded in the pull
request or incident record:

1. affected repository, pull request, check, and outage evidence;
2. explicit authorization by the affected repository's maintainer and an
   independent read-only diff review;
3. the current active ruleset, required checks, and bypass actors captured from
   the GitHub API;
4. equivalent local or alternate-CI verification for the affected contract;
5. the person responsible for restoring the rule and rerunning normal CI.

Do not direct-push, force-push, or move a tag. The current rulesets have no
bypass actors. If a temporary ruleset edit is unavoidable, change only the
unavailable check, merge the reviewed pull request, restore the exact prior
ruleset immediately, and record the rule edit, merge, restoration, and follow-up
CI identifiers. Do not start a release until restoration and normal CI succeed.
Permanent bypass actors are not an emergency mechanism.

## Mispublication Or Compromise

1. Freeze new tags, releases, and toolkit synchronization.
2. Identify the exact version, distribution files, workflow run, tag object,
   peeled commit, and affected contract without copying secrets into public
   evidence.
3. If a PyPI release is broken, violates compatibility, or is vulnerable, yank
   the whole release with a concise reason. Yanking is preferred to deletion and
   does not make exact `==` installs impossible, so it is containment rather than
   complete revocation.
4. Do not move the protected tag. Preserve the GitHub Release as an audit record
   and mark it withdrawn with the replacement version. Remove an exposed asset
   only after preserving an incident record.
5. Revoke or rotate credentials at the provider when exposure is possible.
   Redaction and repository deletion do not revoke a credential.
6. Build a new patch version from a clean reviewed commit through normal CI,
   candidate compatibility, annotated tag, attestations, and Trusted Publishing.
7. Update toolkit pins and regenerate v2 evidence only after the fixed public
   release is verified.
8. Record impact, timeline, root cause, containment, replacement, and residual
   risk. Public records contain aggregate facts, not raw tokens, URLs, event
   bodies, personal paths, or private payloads.

## Live Control Audit

Rulesets are live GitHub configuration, not immutable files in the repository.
Before an `agent-guard` release or integration change, observe the relevant
configured rulesets to confirm that each is
active, targets the expected ref, has the expected stable check, and has no
bypass actor:

```bash
gh api repos/yui-stingray/agent-guard/rulesets
gh api repos/yui-stingray/agent-policy/rulesets
gh api repos/yui-stingray/agent-safety-toolkit-example/rulesets
```

This cross-repository query is an observational compatibility check; it does not
authorize this repository to change another repository's ruleset. The expected
stable checks are `agent-guard required CI`,
`agent-policy required CI`, and `Safety evidence demo`. The branch rules must
remain strict and the release-tag rules for the two packages must reject update
and deletion.

## Demand Decision

The `agent-guard` repository maintainer owns measurement and the go/no-go
decision. The observation window, thresholds, and decision date are normative in
[`demand-validation.md`](demand-validation.md). Store private clone/traffic and
outreach details outside the public repository. The public decision record
contains only aggregate signal values, source types, the decision, review date,
and maintainer sign-off.
