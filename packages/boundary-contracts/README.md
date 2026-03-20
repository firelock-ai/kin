# Boundary Contracts

`@kin/boundary-contracts` is the shared contract layer for Kin workspace boundaries.

This package keeps the editor, agent, adapter, graph-service, and hosted layers from drifting into incompatible JSON shapes and undocumented implicit protocols.

The package exports [`src/index.js`](/Users/troyfortinjr/GitHub/kin-ecosystem/kin/packages/boundary-contracts/src/index.js) directly so bundled consumers can load it as a runtime dependency instead of treating it as test-only authority.

## What This Repo Owns

- shared JSON/schema contracts for ecosystem boundaries
- validation helpers for those contracts
- fixtures and examples that keep bundled consumers aligned

## Current State

The repo currently ships:

- schemas under `schemas/`
- runtime loading and validation helpers under `src/`
- package-level contract tests under `test/`

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

## Boundary Rule

Put a contract here when it crosses package or product boundaries inside the active Kin stack.

Do not put here:

- KinLab product-specific domain models and UX contracts
- local semantic core logic
- database internals

KinLab product contracts can keep living in `kinlab/packages/contracts`. Shared ecosystem contracts that cross product, editor, adapter, or service boundaries should live here.

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
