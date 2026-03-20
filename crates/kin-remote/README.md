# Kin Remote

`kin-remote` is the shared boundary for native Kin remotes and hosted transport semantics.

The goal is to let Kin publish and synchronize semantic state without pretending every remote must remain Git forever.

## What This Crate Owns

- remote identity and capability modeling
- transport kind distinctions such as Git export vs native Kin transport
- push planning and publish gating
- fast-forward and divergence decisions
- approval and proof-publish policy inputs
- readiness checks when a repo lacks semantic head state

## Current State

Today this crate provides a small Rust library in [`src/lib.rs`](/Users/troyfortinjr/GitHub/kin-ecosystem/kin/crates/kin-remote/src/lib.rs) with:

- `HostKind`
- `TransportKind`
- `RemoteRef`
- `RepoState`
- `PushDecision`
- `PushPlan`
- `plan_push(...)`

That logic already models an important transition state:

- Git-export remotes remain valid
- KinLab-style native remotes are explicit
- publish can be blocked by missing semantic state, divergence, or approval requirements

The first real native-host loop is now live through `kin` plus the KinLab control plane:

- `kin remote plan-push` can fetch native remote head state from KinLab
- `kin push` can publish a semantic head to a `native-kin` remote when approval and divergence checks pass

This crate remains the decision layer that the local CLI and KinLab should share while pull, sync, and broader hosted semantics harden.

## Validate

```bash
cargo test
```

## Relationship To Other Repos

- `kin`
  owns the local-first repository, CLI, and actual `remote` / `push` user surfaces
- `kinlab`
  owns the hosted product surface and future native-host implementation
- `@kin/boundary-contracts`
  should own shared wire shapes when remote payloads cross process or service boundaries

## Boundary Rule

Put code here when it answers:

- what kind of remote is this
- what can it publish
- is publish allowed now
- what must happen before publish or pull

Do not put:

- local semantic graph logic
- hosted product UX
- Git emulation for its own sake

For the broader target architecture, see [docs/architecture.md](docs/architecture.md).
