# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately. **Do not open a public
issue for a suspected vulnerability.**

Use GitHub's private vulnerability reporting on this repository:

1. Go to the **Security** tab of [firelock-ai/kin](https://github.com/firelock-ai/kin/security).
2. Click **Report a vulnerability** to open a private security advisory.
3. Include a description, affected versions, reproduction steps, and the
   impact you observed.

We aim to acknowledge new reports within a few business days and will keep
you informed as we investigate. Please give us a reasonable opportunity to
release a fix before any public disclosure.

There is no paid bug-bounty program at this time.

## Supported Versions

Kin is pre-1.0 and currently published as `0.1.0-alpha.*` prereleases. Only
the most recent alpha release receives security fixes; older alpha tags are
not patched. Fixes are shipped in a new alpha release rather than backported.

| Version            | Supported          |
| ------------------ | ------------------ |
| Latest `0.1.0-alpha.*` release | :white_check_mark: |
| Older `0.1.0-alpha.*` tags     | :x:                |

When a 1.0 line is published, this table will be updated with a concrete
support window.

## Scope

This policy covers the `kin` repository: the CLI, daemon, MCP server,
projections, and the bundled crates and packages under `crates/` and
`packages/`. Other Kin ecosystem repositories (for example `kin-db`,
`kin-vfs`, `kinlab`) carry their own security policies; report issues
against the repository where the affected code lives.
