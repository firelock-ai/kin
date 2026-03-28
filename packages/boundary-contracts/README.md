# Boundary Contracts

`@kin/boundary-contracts` is the shared contract layer for Kin workspace boundaries.

This package keeps the editor, agent, adapter, graph-service, and hosted layers from drifting into incompatible JSON shapes and undocumented implicit protocols.

The package exports [`src/index.js`](src/index.js) directly so bundled consumers can load it as a runtime dependency instead of treating it as test-only authority.

The intended firewall is:

1. open-core repos publish this package under semver
2. closed or proprietary consumers install it from a registry
3. no closed repo consumes it through a sibling `file:` link

## What This Repo Owns

- shared JSON/schema contracts for ecosystem boundaries
- validation helpers for those contracts
- fixtures and examples that keep bundled consumers aligned
- the canonical source of truth for shared cross-boundary payload families

## Current State

The repo currently ships:

- schemas under `schemas/`
- runtime loading and validation helpers under `src/`
- package-level contract tests under `test/`

The package is structured to be versioned and published. That is the required
consumption path for any repo that needs to stay physically decoupled from the
open-core checkout, including `kinlab`.

Current contract families include:

- `workspace-context`
- `scm-context`
- `file-stat`
- `directory-entry`
- `directory-list`
- `file-content`
- `command-ack`
- `kin-command-result`
- `scm-snapshot`
- `scm-resource-groups`

The package also exposes a type-only TypeScript surface for shared semantic payload families that must stay open-core:

- actor/evidence/risk enums
- review authority / plane / provenance / lifecycle enums
- surface discovery/truth enums
- projected file entries
- semantic search results
- blob/entity annotations
- semantic diff payloads
- semantic change sets
- cross-repo impact summaries
- repo-local review primitives: state enums, repository refs, change context, queue items, file diffs, decisions, notes, assignments, discussion threads/comments, and mutation/create request payloads

## Ownership Matrix Summary

| Family | Owner | Notes |
| --- | --- | --- |
| Workspace / file boundary payloads | `@kin/boundary-contracts` | Must stay identical across CLI, adapters, editor, VFS, and hosted consumers. |
| Shared semantic substrate payloads | `@kin/boundary-contracts` | Shared open-core payloads belong here, even if KinLab consumes them. |
| Repo-local review primitives | `@kin/boundary-contracts` | Repo-local review truth should be graph-native; KinLab may augment, but not own, the shared contract. |
| KinLab UX / hosted workflow payloads | `kinlab/packages/contracts` | Product-local hosted value stays private. |

## Validate

```bash
npm run lint
npm test
```

The tests validate current outputs from bundled packages such as:

- `kin-fs-adapter`
- `kin-scm-adapter`
- `kin-graph-service`

against the shared schemas in this repo.

## How Consumers Should Resolve It

Active consumers should resolve the contracts package in this order:

1. installed `@kin/boundary-contracts` package
2. `KIN_BOUNDARY_CONTRACTS_PATH`

Closed or proprietary consumers should use step 1 by default. Step 2 is a
debugging escape hatch, not the normal production boundary.

## Release Posture

This package should be published from the open-core release pipeline with normal
semver versioning.

Recommended consumer pattern:

- open-core repos: consume the published version or a release-candidate tag
- `kinlab`: consume the published version from npm or an isolated internal
  registry mirror
- local umbrellas: use registry installs first and only fall back to a local
  override when explicitly debugging package changes

## Boundary Rule

Put a contract here when it crosses package or product boundaries inside the active Kin ecosystem.

Do not put here:

- KinLab product-specific domain models and UX contracts
- local semantic core logic
- database internals

KinLab product contracts can keep living in `kinlab/packages/contracts`. Shared ecosystem contracts that cross product, editor, adapter, or service boundaries should live here.

If a shape is used by both open-core and KinLab, this package is the canonical owner unless the shape is clearly KinLab-private hosted value.

For the explicit ownership matrix and migration rules, see:

- [planning/strategy/contract-authority-codification.md](/Users/troyfortinjr/GitHub/kin-ecosystem/planning/strategy/contract-authority-codification.md)

## Relationship To Other Repos

- `kin-fs-adapter`
  uses these contracts for workspace and file-service payloads
- `kin-scm-adapter`
  uses these contracts for SCM context and snapshot payloads
- `kin-graph-service`
  uses these contracts for graph-backed file/projection responses
- `kin-code`
  relies on these contracts indirectly through the adapter and service stack
- `kinlab`
  should use this package for shared ecosystem boundaries, while keeping product-local contracts in `kinlab/packages/contracts`
