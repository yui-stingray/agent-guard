# Security Policy

`agent-guard` is intended to catch unsafe repository content before it reaches
hooks, CI, releases, or public publication paths.

## Supported versions

The latest published `0.x` release is supported while the project is in
alpha. Security fixes may be released as a new patch version without preserving
compatibility for undocumented internals.

## Known risk in published 0.3.4

Published `0.3.4` can spend excessive CPU evaluating an unreviewed custom
regular expression supplied through a repository-controlled context policy.
Until a fixed release exists, do not run `context check` or `report` from
`0.3.4` against policy changes from an untrusted contribution. Use a
maintainer-reviewed policy from a trusted revision, or review and reject policy
changes before the scanner executes.

The copyable pull-request workflows in the README and quickstart perform a
context-policy diff preflight before invoking the immutable `0.3.4` Action and
apply a one-minute Action step timeout. Keep both controls until a fixed release
is published. They reduce exposure but do not replace normal review of workflow
changes and are not an independent trust anchor.

Master identifies as unreleased `0.3.5.dev0` and isolates and bounds this regex
matching. That source fix is not a published package or Action release. The
demand-validation release freeze remains in effect and no release is authorized
by this notice.

## Reporting a vulnerability

If GitHub private vulnerability reporting is available for this repository,
use it. Otherwise, open a public issue with a high-level description and omit
exploit payloads, private logs, credentials, or repository-specific secrets.

Helpful reports include:

- the affected version or commit
- the scanner command and policy shape
- a minimal safe fixture that reproduces the issue
- the expected finding or block
- the observed missed finding, false allow, or unsafe traversal

Do not use this project to scan repositories, systems, or codebases that you do
not own or do not have permission to review.
