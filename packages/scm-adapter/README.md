# kin-scm-adapter

`kin-scm-adapter` is the headless bridge that turns Kin repo state into editor-friendly SCM snapshots and review-oriented command results.

It stays as a separate package from `kin-code` so the Kin SCM surface can be reused by other editors, terminals, and review tools without coupling them to Code - OSS internals.

## What This Repo Owns

- repo discovery for SCM-oriented tools
- Kin CLI resolution
- SCM context and snapshot assembly
- daemon-backed session, intent, and change summaries
- reusable trace, history, and review command bridging

## Current State

The adapter currently:

- resolves Kin repos and Kin CLI binaries
- reads Kin repo mode and status summary
- queries the Kin daemon when available for working-copy counts, sessions, and intents
- emits editor-friendly resource groups
- validates its SCM payloads against `@kin/boundary-contracts`

It is intentionally read-mostly today. Commit, mutation, and quick-diff flows should layer on top of this repo rather than being embedded directly into `kin-code`.

## Validate

```bash
npm run lint
npm test
```

## CLI

```bash
kin-scm-adapter context --repo /path/to/repo
kin-scm-adapter snapshot --repo /path/to/repo
kin-scm-adapter resource-groups --repo /path/to/repo
kin-scm-adapter trace --repo /path/to/repo --entity Router::route
kin-scm-adapter history --repo /path/to/repo --entity Router::route
kin-scm-adapter review --repo /path/to/repo
```

Optional flags:

- `--kin /path/to/kin`
- `--daemon http://127.0.0.1:4219`

## Contract Resolution Order

- installed `@kin/boundary-contracts` package
- `KIN_BOUNDARY_CONTRACTS_PATH`

## Relationship To Other Repos

- `kin`
  remains the owner of local semantic truth and actual SCM semantics
- `kin-code`
  consumes this repo as its reusable SCM/status/history boundary
- `kin-daemon`
  provides the live session and intent data this adapter can surface
- `@kin/boundary-contracts`
  owns the shared payload shapes emitted here

## Boundary Rule

Put behavior here when it turns Kin SCM state into reusable, tool-friendly payloads.

Do not put here:

- local semantic repo mutations
- editor UI behavior
- hosted review workflow logic
