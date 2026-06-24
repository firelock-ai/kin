> **Umbrella guidance:** the workspace-root `AGENTS.md` is the source of truth for cross-repo thesis, boundaries, and rules. This file is the repo-specific authority for `kin-lsp`.

# kin-lsp

LSP client for graph enrichment. Spawns and drives language servers (clangd,
rust-analyzer, typescript-language-server, etc.) to resolve type-level
relations that the Kin parser cannot derive from AST analysis alone — call
targets across dynamic dispatch, trait implementations, cross-file type
aliases.

## Build

```bash
cargo build
cargo test
```

## Architecture

- `src/lib.rs` — `LspClient` struct; spawn, initialize, request, shutdown
- Async (tokio): child-process stdin/stdout I/O over the LSP JSON-RPC protocol
- Stateless beyond the per-session LSP handshake

## Boundary rule

Put work here when the job is LSP protocol handling or type-resolved relation
extraction. Ranking, proof-weighting, and graph storage belong in `kin-db`
and `kin`. `kin` depends on this crate directly via `cargo registry = "kin"`.
