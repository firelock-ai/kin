# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately. **Do not open a public
issue for a suspected vulnerability.**

Use GitHub's private vulnerability reporting on this repository:

1. Go to the **Security** tab of [firelock-ai/kin-blobs](https://github.com/firelock-ai/kin-blobs/security).
2. Click **Report a vulnerability** to open a private security advisory.
3. Include a description, affected versions, reproduction steps, and the
   impact you observed.

We aim to acknowledge new reports within a few business days and will keep
you informed as we investigate. Please give us a reasonable opportunity to
release a fix before any public disclosure.

There is no paid bug-bounty program at this time.

## Supported Versions

Kin is pre-1.0 and published as `0.x` releases (alpha-grade: APIs and formats
may change between minor versions). Only the most recent `0.x` release receives
security fixes; older tags are not patched. Fixes are shipped in a new `0.x`
release rather than backported.

| Version              | Supported          |
| -------------------- | ------------------ |
| Latest `0.x` release | :white_check_mark: |
| Older `0.x` tags     | :x:                |

When a 1.0 line is published, this table will be updated with a concrete
support window.

## Scope

This policy covers the `kin-blobs` repository: the content-addressable blob
storage substrate — immutable content keyed by its SHA-256 digest, with atomic,
Git-style sharded writes. Other Kin ecosystem repositories (for example `kin`,
`kin-db`, `kin-vfs`, `kinlab`) carry their own security policies; report issues
against the repository where the affected code lives.
