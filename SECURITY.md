# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately. **Do not open a public
issue for a suspected vulnerability.**

Use GitHub's private vulnerability reporting on this repository:

1. Go to the **Security** tab of [firelock-ai/kin](https://github.com/firelock-ai/kin/security).
2. Click **Report a vulnerability** to open a private security advisory.
3. Include a description, affected versions, reproduction steps, and the
   impact you observed.

There is no paid bug-bounty program at this time.

## Response SLA

| Stage | Target |
| ----- | ------ |
| Acknowledgement | 48 hours of receipt |
| Initial assessment | 5 business days |
| Fix or mitigation | 90 days (critical), 180 days (high/medium) |
| Coordinated disclosure | After fix ships; we contact the reporter before going public |

We will keep you informed as we investigate. If 90 days pass without a
fix, we will discuss an extension or limited disclosure with you.

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

This policy covers the `kin` repository: the CLI, daemon, MCP server,
projections, and the bundled crates and packages under `crates/` and
`packages/`. Other Kin ecosystem repositories (for example `kin-db`,
`kin-vfs`, `kinlab`) carry their own security policies; report issues
against the repository where the affected code lives.

## High-Risk Features

### POST /commands/exec

`POST /commands/exec` lets the daemon materialize a graph workspace and
execute an arbitrary shell command (`sh -c`) inside it. This is a
high-risk capability.

**Decision: disabled by default, explicit opt-in required.**

The endpoint returns `403 Forbidden` unless the operator sets
`KIN_DAEMON_ALLOW_EXEC=1` in the daemon environment. The daemon only
listens on loopback (`127.0.0.1`) and validates the `Host` header and an
auth token for non-loopback callers; even so, shell execution is off
unless you consciously enable it.

Enable only in controlled, local development environments where you trust
all processes on the machine. Do not expose the daemon to untrusted
networks with this flag set.

### kin-vfs LD_PRELOAD / DYLD_INSERT_LIBRARIES shim

`kin-vfs` intercepts libc calls at runtime. Only install and use it from
the official signed release binaries. Verify the installer checksum
before running `kin setup`.
