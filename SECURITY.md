# Security Policy

`agent-guard` is intended to catch unsafe repository content before it reaches
hooks, CI, releases, or public publication paths.

## Supported versions

The latest published `0.x` release is supported while the project is in
alpha. Security fixes may be released as a new patch version without preserving
compatibility for undocumented internals.

## Fixed in 0.3.5

Published `0.3.4` can spend excessive CPU evaluating an unreviewed custom
regular expression supplied through a repository-controlled context policy.
Do not run `context check` or `report` from `0.3.4` against policy changes from
an untrusted contribution. Upgrade to `0.3.5`, which isolates and bounds regex
matching, or use a maintainer-reviewed policy from a trusted revision.

The copyable pull-request workflows in the README and quickstart perform a
context-policy diff preflight before invoking the immutable `0.3.7` Action and
apply a one-minute Action step timeout. Keep both as defense-in-depth controls.
They do not replace normal review of workflow changes and are not an
independent trust anchor.

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
