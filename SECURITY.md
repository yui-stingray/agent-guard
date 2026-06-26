# Security Policy

`agent-guard` is intended to catch unsafe repository content before it reaches
hooks, CI, releases, or public publication paths.

## Supported versions

The latest published `0.1.x` release is supported while the project is in
alpha. Security fixes may be released as a new patch version without preserving
compatibility for undocumented internals.

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
