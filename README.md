# Kin

**Git stores text history. Kin understands code.**

Kin is a local-first semantic version control system built in Rust. It replaces Git's file-diff model with a graph of semantic entities and relationships, then serves precise context to AI agents and developers. Kin is not a coding assistant or a Git wrapper -- it is a sovereign VCS and the semantic operating layer that any assistant can use. `kin init` works with or without `.git`.

> **Alpha** -- Kin is in active development. The core architecture is solid, but APIs and CLI surface may change. See [Status](#status) below.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021_edition-orange.svg)](https://www.rust-lang.org/)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-yellow.svg)](#status)

---

## Why Kin?

- **Precise context delivery** -- Graph-traversal context under token budgets, not file dumping. AI assistants get exactly the entities they need, with signatures for dependencies.
- **Identity tracking across refactors** -- Semantic fingerprints survive renames, moves, and formatting changes. Kin knows `processOrder` and `handle_order` are the same function.
- **Semantic review** -- Review changed entities and their impact graph, not line diffs. See what a change actually affects.
- **Provenance and trust** -- Every change carries evidence of who or what made it and why, with full execution traces.
- **Git interop** -- Import from Git, export to Git, but Git is not required. Kin adoption is reversible: delete `.kin/` and your source files remain untouched.
- **Measurable economic value** -- Built-in benchmarks prove token savings, CI/CD reduction, and context quality improvements.

---

## Architecture Overview

Kin organizes code understanding into four planes:

```
┌─────────────────────────────────────────────────────────────┐
│                     SEMANTIC PLANE                           │
│  Entities, Relations, Contracts, SemanticChanges, Specs      │
│  ↕ source of truth                                          │
├─────────────────────────────────────────────────────────────┤
│                     PROJECTION PLANE                         │
│  Source files, Git commits, PR views, Living docs            │
│  ↕ rendered from semantic state                             │
├─────────────────────────────────────────────────────────────┤
│                     EXECUTION PLANE                          │
│  Local workspaces, Validation runs, Evidence capture         │
│  ↕ proves correctness                                       │
├─────────────────────────────────────────────────────────────┤
│                     CONTROL PLANE                            │
│  Reviews, Governance, Assistant adapters, Benchmarks         │
│  ↕ manages quality and trust                                │
└─────────────────────────────────────────────────────────────┘
```

**Semantic entities** are the source of truth. Files are projections of semantic state -- rendered outputs, not primary artifacts. The embedded KuzuDB graph database stores topology, metadata, signatures, and fingerprints. A content-addressable blob store holds raw code text.

---

## Quick Start

```bash
# Install from source
git clone https://github.com/firelock-ai/kin.git
cd kin
cargo build --release

# Initialize a project
cd /path/to/your/project
kin init

# See semantic state
kin status

# Trace entity relationships
kin trace
```

---

## CLI Commands

### Core VCS

| Command | Description |
|---------|-------------|
| `kin init` | Initialize `.kin/` in any directory (Git not required) |
| `kin status` | Show semantic state vs working directory |
| `kin commit` | Record a SemanticChange (Kin's native commit) |
| `kin log` | Show semantic change history |
| `kin branch` | Create, list, or switch semantic branches |
| `kin merge` | Semantic merge (entity-level, not line-level) |
| `kin diff` | Semantic diff (entity-level, not line-level) |
| `kin stash` | Snapshot and manage overlay state |
| `kin history` | Full semantic history for a specific entity |
| `kin blame` | Semantic blame -- who or what changed this entity? |

### Intelligence

| Command | Description |
|---------|-------------|
| `kin impact` | Impact analysis -- what does this change affect? |
| `kin context` | Build a token-budgeted context pack |
| `kin search` | Semantic search across entities |
| `kin trace` | Trace a focal entity: resolve, show body, summarize nearby context |
| `kin overview` | Quick codebase overview (entity counts by kind, language, top files) |
| `kin dead-code` | Find unreferenced entities (dead code) |
| `kin review` | Start or view semantic review |
| `kin spec` | Create and manage intent specs |

### Native Mode

| Command | Description |
|---------|-------------|
| `kin mode` | Manage repository mode (compat or native) |
| `kin open` | Launch an editor in a materialized session workspace |
| `kin shell` | Open an interactive shell in a materialized session workspace |
| `kin with` | Launch an assistant with Kin guidance injected |
| `kin reconcile` | Reconcile session workspace changes back into the graph |
| `kin exec` | Execute a command in a materialized workspace |

### Work Management

| Command | Description |
|---------|-------------|
| `kin work` | Manage work items (features, tasks, issues, debt, TODOs) |
| `kin note` | Manage annotations (comments, warnings, instructions, reasoning) |
| `kin todo` | Import inline TODOs as work items |
| `kin feature` | Create a feature (alias for `kin work create --kind feature`) |

### Governance

| Command | Description |
|---------|-------------|
| `kin audit` | Show audit trail |
| `kin approvals` | Manage change approvals |
| `kin security` | Scan entity graph for security patterns |
| `kin verify` | Verify test coverage for entities |

### Release & Operations

| Command | Description |
|---------|-------------|
| `kin semver` | Analyze semver impact of changes |
| `kin release` | Create a release snapshot |
| `kin rollback` | Rollback to a previous change |
| `kin support` | Show coverage report |
| `kin bench` | Run benchmarks on repo |
| `kin migrate` | Import a Git/GitHub repo into Kin |
| `kin workspace` | Manage workspaces (create, list, delete, rename) |
| `kin run` | Execute validation runs with evidence capture |
| `kin mcp` | Start or manage MCP server |
| `kin assistant` | Register and manage assistant adapters |

### Session

| Command | Description |
|---------|-------------|
| `kin intent` | Manage agent intents (locks on scopes) |
| `kin traffic` | Show active intents on a scope |

### Git Interop (optional)

| Command | Description |
|---------|-------------|
| `kin git import` | Import Git history into Kin graph |
| `kin git export` | Export Kin state as Git commits |
| `kin git sync` | Bidirectional sync with a `.git` repo |

---

## Language Support

Tier 1 -- full entity extraction, relation extraction, fingerprinting, and contract adapters:

- TypeScript / JavaScript
- Python
- Go
- Java
- Rust

Parsing is powered by Tree-sitter with per-language adapters.

---

## MCP Integration

Kin exposes its semantic graph through the [Model Context Protocol](https://modelcontextprotocol.io/), making it assistant-neutral. Any MCP-compatible tool -- Claude Code, Codex, Gemini CLI, Cursor, or others -- can query:

- Semantic search and graph retrieval
- Impact analysis and semantic diffs
- Dead code detection
- Review and evidence lookup
- Spec and living docs retrieval
- Benchmark execution and results

Start the MCP server with `kin mcp` or configure it as an MCP server in your assistant's settings.

---

## Crate Architecture

Kin is built as 18 Rust crates in a Cargo workspace:

| Crate | Description |
|-------|-------------|
| `kin-cli` | CLI with full command set |
| `kin-daemon` | Background service: file watch, incremental indexing, reconciliation |
| `kin-core` | Shared runtime, config, error types |
| `kin-model` | Canonical types: Entity, Relation, Contract, SemanticChange, Spec |
| `kin-graph` | KuzuDB embedded property graph -- topology, metadata, fingerprints |
| `kin-blobs` | Content-addressable blob store (SHA-256 addressed) |
| `kin-index` | Graph build and update pipeline |
| `kin-parser` | Tree-sitter parsing and language adapters |
| `kin-contracts` | Cross-language contract linking (OpenAPI, Protobuf, GraphQL, DB schema) |
| `kin-projection` | File and doc projection engine |
| `kin-reconcile` | Kubernetes-style reconciliation loop (working directory <-> semantic state) |
| `kin-git` | Legacy adapter -- import/export Git history (optional) |
| `kin-context` | Token-budgeted context pack builder with semantic slicing |
| `kin-review` | Semantic review engine and risk summaries |
| `kin-bench` | Benchmark engine: velocity, reliability, economic metrics |
| `kin-migrate` | GitHub/Git repo migration pipeline |
| `kin-mcp` | MCP server -- assistant-neutral integration surface |
| `kin-runtime` | Workspace runs, validation, evidence capture |

---

## Status

Kin is in **public alpha**. Here is an honest assessment:

**What's solid:**
- Core data model (Entity, Relation, SemanticChange, Fingerprint)
- Embedded graph database (KuzuDB) with Cypher query support
- Content-addressable blob store
- Tree-sitter parsing pipeline for all Tier 1 languages
- CLI command structure and routing
- Git import/export adapter
- MCP server protocol

**What's still hardening:**
- Reconciliation loop edge cases (broken ASTs, partial parses)
- Semantic merge conflict resolution
- Multi-workspace coordination
- Performance optimization on large repos (100k+ entities)
- Living docs projection

We ship what works and are transparent about what doesn't yet. If you hit a rough edge, [open an issue](https://github.com/firelock-ai/kin/issues).

---

## Building from Source

```bash
# Prerequisites: Rust 1.75+ (2021 edition), cmake
# cmake is required for KuzuDB: brew install cmake (macOS) or apt install cmake (Linux)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/firelock-ai/kin.git
cd kin
cargo build --release

# Run tests
cargo test

# The binary is at target/release/kin
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, PR process, and code style guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

Apache-2.0. See [LICENSE](LICENSE) for details.

---

Built by [Firelock AI](https://firelock.ai).
