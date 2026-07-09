# kin-lsp

> Language-server enrichment boundary that feeds type-resolved relations into the Kin graph.

`kin-lsp` bridges standard language servers and the Kin semantic graph. Tree-sitter
parsing gives Kin syntax-level structure; `kin-lsp` adds the type-resolved relations
that require language-server knowledge — call hierarchy edges, type hierarchy edges,
cross-file type-definition links, and trait/interface implementation mappings. The
resulting relations are consumed by `kin` and stored in `kin-db` as first-class graph
edges with stable identity and Merkle-verified provenance.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Part of Kin](https://img.shields.io/badge/part%20of-Kin-6E56CF.svg)](https://github.com/firelock-ai/kin)

## What is Kin?

Kin is the system of record for AI-written software — your code as a graph of
entities, relations, and intents, not a pile of files and diffs. AI agents and humans
navigate it semantically, with provenance, review, and governance built in. It coexists
with Git and projects graph truth back to a normal filesystem, so any tool works unchanged.

Start at **[firelock-ai/kin](https://github.com/firelock-ai/kin)** · **[kinlab.ai](https://kinlab.ai)**

## kin-lsp's role

`kin-lsp` is an async Rust library crate. It spawns external language server processes
over stdin/stdout JSON-RPC (the LSP wire protocol), performs the initialize handshake,
drives targeted requests (`textDocument/definition`, `textDocument/references`,
`callHierarchy/incomingCalls`, etc.), and translates the results into `kin-model`
relation types that the Kin ingest pipeline commits to the graph.

`kin` depends on this crate directly via the `kin` Cargo registry. No hosted or
control-plane logic lives here — this crate belongs to the open local substrate.

## Supported language-server adapters

| Language | Server | Notes |
|----------|--------|-------|
| Rust | `rust-analyzer` | call hierarchy, type defs, trait impls |
| C / C++ | `clangd` | requires `compile_commands.json` |
| Go | `gopls` | full call + type hierarchy |
| Java | `jdtls` | Eclipse JDT Language Server |
| Python | `pyright-langserver` | type-resolved references |
| TypeScript / JavaScript | `typescript-language-server` | full LSP surface |

The adapter for each language is a small `LspAdapter` impl in `src/adapters/`. The
`which` crate gates adapter availability at runtime — if the server binary is not on
`PATH`, that language is silently skipped during enrichment.

## Build

```bash
cargo build --release
cargo test
```

There are no compile-time feature flags. Language-server availability is a runtime
concern, not a build-time one.

## How it feeds the graph

During `kin ingest` (or triggered by the daemon on file change), `kin` calls into
`kin-lsp` to enrich a set of source files:

1. `kin-lsp` discovers the applicable language server for each file via `src/discovery.rs`.
2. For each server, it spawns the process (`src/lifecycle.rs`), performs the LSP
   `initialize` handshake, and drives the enrichment loop (`src/enrichment.rs`).
3. Resolved relations (call edges, type edges, definition links) are returned as
   `EnrichmentResult` values using `kin-model` types.
4. `kin` merges these into the graph via `kin-db`, where they become permanent graph
   edges with content hashes and provenance records.

Results are cached per file hash (`src/cache.rs`) so unchanged files skip re-enrichment.

## Daemon lifecycle

`kin-lsp` manages language server processes per enrichment session. Each server is
started fresh, used for the enrichment pass, and shut down cleanly (`shutdown` +
`exit` notifications). The crate does not hold long-lived background processes —
the `kin` daemon controls the enrichment schedule and calls into `kin-lsp` as needed.

## Ecosystem

| Repo | Role |
|------|------|
| [kin](https://github.com/firelock-ai/kin) | Semantic system of record — consumes this crate |
| [kin-db](https://github.com/firelock-ai/kin-db) | Semantic engine — stores the enriched relations |
| [kin-model](https://github.com/firelock-ai/kin-model) | Canonical types consumed and produced here |
| [kinlab](https://kinlab.ai) | Hosted collaboration and control plane |

## License

[Apache-2.0](LICENSE).
