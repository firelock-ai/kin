# kin-lsp

> Language-server enrichment boundary that feeds type-resolved relations into the Kin graph.

`kin-lsp` bridges standard language servers and the Kin semantic graph. Tree-sitter
parsing gives Kin syntax-level structure; `kin-lsp` adds the type-resolved relations
that require language-server knowledge: call edges from call hierarchy, override edges
from type hierarchy, cross-file type-usage edges from go-to-type-definition, and
reference edges from find-references. Every relation it emits carries
`RelationOrigin::Lsp`, so an edge a language server vouched for stays distinguishable
from a tree-sitter or linker edge once `kin` commits it to the graph through `kin-db`.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Part of Kin](https://img.shields.io/badge/part%20of-Kin-6E56CF.svg)](https://github.com/firelock-ai/kin)

## What is Kin?

Kin is the system of record for AI-written software: your code as a graph of
entities, relations, and intents, not a pile of files and diffs. AI agents and humans
navigate it semantically, with provenance, review, and governance built in. It coexists
with Git and projects graph truth back to a normal filesystem, so any tool works unchanged.

Start at **[firelock-ai/kin](https://github.com/firelock-ai/kin)** · **[kinlab.ai](https://kinlab.ai)**

## kin-lsp's role

`kin-lsp` is an async Rust library crate. It spawns external language server processes
over stdin/stdout JSON-RPC (the LSP wire protocol), performs the initialize handshake,
drives targeted requests (`textDocument/definition`, `textDocument/references`,
`textDocument/typeDefinition`, `callHierarchy/outgoingCalls`, `typeHierarchy/supertypes`),
and translates the results into `kin-model` relation types that the Kin ingest pipeline
commits to the graph.

`kin` depends on this crate directly via the `kin` Cargo registry. No hosted or
control-plane logic lives here; this crate belongs to the open local substrate.

## Language-server adapters

Each language has a small `LspAdapter` impl in `src/adapters/` carrying the server
command, its launch args, and the extensions it claims. Where a language has more than
one known server, the first one found on `PATH` wins:

| Language | Servers tried, in order |
|----------|-------------------------|
| Rust | `rust-analyzer` |
| Python | `pyright-langserver`, then `pylsp` |
| TypeScript | `typescript-language-server`, then `vtsls` |
| JavaScript | `typescript-language-server` |
| Go | `gopls` |
| Java | `jdtls` (Eclipse JDT Language Server) |
| C / C++ | `clangd` (needs `compile_commands.json`) |

Availability is decided at runtime against `PATH` via the `which` crate, not at build
time. If the server binary is not on `PATH`, that language is silently skipped during
enrichment, because `discovery::discover_servers()` just omits it from the list it
returns. There is a louder path in `src/registry.rs`, where `ProviderRegistry::resolve`
returns a `ProviderGap` naming the language and every provider it tried, but nothing
calls it outside its own unit tests yet. The gap type is available, not wired.

## What a consumer actually drives

Shipping an adapter is not the same as a consumer driving it, and the gap is wider than
the table above suggests. The `kin` daemon's enrichment loop builds an adapter for Rust
and Python only. A file in any other language falls through to no adapter and is
skipped, even when its server is installed and on `PATH`. So Go, Java, C, C++,
TypeScript, and JavaScript have adapters here that nothing drives today.

Read the table as this crate's surface. Live language coverage is whatever the consumer
wires up, and right now that is two languages.

## Build

```bash
cargo build
```

There are no compile-time feature flags.

## How it feeds the graph

During `kin ingest` (or triggered by the daemon on file change), `kin` calls into
`kin-lsp` to enrich a set of source files:

1. `discovery::discover_servers()` reports which servers are installed at all. The
   consumer uses that to decide whether enrichment is worth enabling, then picks an
   adapter per file from the file's own language.
2. For each server, `kin-lsp` spawns the process (`src/lifecycle.rs`), performs the LSP
   `initialize` handshake, and drives the enrichment loop (`src/enrichment.rs`).
3. Resolved relations (call, override, type-usage, and reference edges) are returned as
   `EnrichmentResult` values using `kin-model` types, each tagged `RelationOrigin::Lsp`.
4. `kin` merges these into the graph via `kin-db`.

Results are cached per file hash (`src/cache.rs`) so unchanged files skip re-enrichment.

The origin tag is the only provenance this crate attaches on its own. A finer record of
which provider, at which version, through which capability produced an edge exists as
`LspProvenance` and `stamp_lsp_provenance`, which encode into `RelationEvidence` and
round-trip back out. Nothing calls the stamping helper, so it is available and unused.

## Daemon lifecycle

`kin-lsp` manages language server processes per enrichment session. Each server is
started fresh, used for the enrichment pass, and shut down cleanly (`shutdown` +
`exit` notifications). The crate does not hold long-lived background processes; the
`kin` daemon controls the enrichment schedule and calls into `kin-lsp` as needed.

## Testing

```bash
cargo test
```

That runs 35 unit tests across `src/`, which need nothing installed, plus 5 integration
tests in `tests/` that drive a real `rust-analyzer`.

Every integration test looks for `rust-analyzer` on `PATH` first and returns early when
it is missing. The three in `tests/rust_analyzer_integration.rs` also need a Rust
workspace to point the server at, either a sibling `kin` checkout or the parent
workspace, and skip when neither is there. The two in `tests/daemon_repro.rs` and
`tests/max_enrichment_probe.rs` write a throwaway crate into the temp directory
themselves, so a missing `rust-analyzer` is their only skip condition.

A skip prints `SKIP` to stderr and passes. On a machine without `rust-analyzer`, a green
`cargo test` has therefore exercised the unit tests and none of the LSP protocol path.
Read the output before reading the pass as coverage.

The ones that do run are slow by design, since a server has to index before it can
answer. `daemon_repro` and `max_enrichment_probe` each wait 25 seconds for indexing and
then wait again after `didOpen`, 10 and 5 seconds respectively. The two
`rust_analyzer_integration` tests that issue queries wait 10 and 20 seconds.

## Ecosystem

| Repo | Role |
|------|------|
| [kin](https://github.com/firelock-ai/kin) | Semantic system of record, consumes this crate |
| [kin-db](https://github.com/firelock-ai/kin-db) | Semantic engine, stores the enriched relations |
| [kin-model](https://github.com/firelock-ai/kin-model) | Canonical types consumed and produced here |
| [kinlab](https://kinlab.ai) | Hosted collaboration and control plane |

## License

[Apache-2.0](LICENSE).
