# Kin

![Kin hero](./docs/pitch/kin-hero.svg)

**Local-first semantic version control for AI-native teams.**

> Git stores text history. Kin understands code.

Kin is a sovereign VCS that replaces file-based version control with a graph of semantic entities, relationships, contracts, and `SemanticChange` history. It serves precise, token-budgeted context to AI agents and developers through a CLI, daemon, MCP server, and local UI. `kin init` works with or without `.git`.

## Status

Kin is under active implementation. This repository contains the open local-first semantic core: Rust crates, the local UI, and supporting public docs.

Architecture reference: **[docs/architecture/kin-system-architecture.md](./docs/architecture/kin-system-architecture.md)**.
Pitch deck: **[docs/pitch/kin-deck.md](./docs/pitch/kin-deck.md)**.

## Why Kin

- **Precise context delivery** instead of file dumping
- **Identity tracking across refactors** through semantic fingerprints
- **Semantic diff, history, review, and impact analysis** at the entity level
- **Provenance and evidence** for who or what changed code and why
- **Assistant-neutral integration** through MCP and local APIs
- **Git interop without Git dependence** through the optional `kin-git` adapter
- **Reversible adoption** because deleting `.kin/` leaves normal files intact

## Why Now

AI agents are colliding with a developer stack built for text files, line diffs, and directory trees. That mismatch leaks everywhere:

- agents over-read and under-understand
- refactors lose identity and intent
- review and blame stop at files and line numbers
- monorepos become a context workaround instead of a product choice

Kin changes the substrate. The semantic graph becomes the source of truth, and files become projections for compatibility.

## Getting Started

Prerequisites:

- Rust toolchain
- Git, if you want to exercise Git interop flows

Common commands:

```bash
cargo test --workspace
cargo run -p kin-cli -- init .
cargo run -p kin-cli -- status
```

## Repo Layout

- `crates/` — Rust workspace for the semantic core
- `apps/kin-local-ui/` — local web UI
- `tests/integration/` — end-to-end acceptance coverage
- `docs/architecture/` — public architecture documentation
- `docs/pitch/` — public positioning and presentation material

## V1 Open Semantic Core

V1 is the full open-source semantic core, released under Apache 2.0. It includes:

- `kin-cli`, `kin-daemon`, `kin-mcp`, and `apps/kin-local-ui`
- `kin-model`, `kin-core`, `kin-graph`, and `kin-blobs`
- `kin-parser`, `kin-index`, `kin-projection`, and `kin-reconcile`
- `kin-context`, `kin-contracts`, and `kin-review`
- `kin-git`, `kin-migrate`, `kin-bench`, and `kin-runtime`

Tier-1 language support in V1:

- TypeScript / JavaScript
- Python
- Go
- Java
- Rust

## Non-Negotiables

- Kin is the primary VCS. Git is an optional legacy adapter.
- KuzuDB is the query engine for graph operations.
- The graph stores topology and metadata; the blob store stores content.
- Tree-sitter is the parsing foundation, with LSP/SCIP enrichment where useful.
- Files are projections of semantic state, not the source of truth.
- The system is local-first by default.
- Deleting `.kin/` must leave the working directory intact and runnable.

## CLI Surface

Kin currently exposes the core semantic VCS and assistant-facing commands through `kin`:

```bash
kin init
kin status
kin commit
kin log
kin branch
kin merge
kin diff
kin stash
kin history
kin blame
kin impact
kin context
kin search
kin review
kin spec
kin bench
kin migrate
kin workspace
kin run
kin mcp
kin assistant
kin git import
kin git export
kin git sync
```

## License

Apache 2.0
