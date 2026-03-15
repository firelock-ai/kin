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

**Semantic entities** are the source of truth. Files are projections of semantic state -- rendered outputs, not primary artifacts. The embedded KinDB graph engine stores topology, metadata, signatures, and fingerprints. A content-addressable blob store holds raw code text.

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
| `kin mode` | Manage repository mode plus world-policy presets (`hybrid`, `radical`, `brownfield`) |
| `kin open` | Launch an editor in a materialized session workspace |
| `kin shell` | Open an interactive shell in a materialized session workspace |
| `kin with` | Launch an assistant with Kin guidance injected |
| `kin reconcile` | Reconcile session workspace changes back into the graph |
| `kin exec` | Execute a command in a materialized workspace |

`kin mode preset radical` keeps non-code artifacts in a more Kin-first worldview and refuses to auto-widen scoped `docker compose`, `docker build`, or `make` style commands.

`kin mode preset brownfield` favors conventional workspace compatibility and will widen those broad external tools to a full materialized workspace when needed.

Compose files (`docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml`) are now tracked as first-class structured artifacts alongside Dockerfiles and Makefiles.

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
| `kin remote` | Configure or inspect GitHub/KinHub-style remotes |
| `kin push` | Plan or prepare a publish to the default remote |
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

`kin push` now resolves a configured Kin remote first and falls back to detected Git `origin` when no Kin remote is configured. For `git-export` remotes it prepares the local Git-shaped export and tells you what `git push` still needs to happen. For `native-kin` remotes it gives you the publish plan and gate state, which is the first step toward real KinHub-native hosting. If the repo has not recorded any semantic branch/head yet, `kin remote plan-push` and `kin push` explain that state directly and point you to `kin commit` or `kin git sync` instead of failing with an internal-looking branch error.

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

Kin is built as 17 Rust crates in a Cargo workspace:

| Crate | Description |
|-------|-------------|
| `kin-cli` | CLI with full command set |
| `kin-daemon` | Background service: file watch, incremental indexing, reconciliation |
| `kin-core` | Shared runtime, config, error types |
| `kin-model` | Canonical types: Entity, Relation, Contract, SemanticChange, Spec |
| `kin-db` | Embedded graph engine, snapshot persistence, vector index, and query acceleration |
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
- Embedded graph database (KinDB) with snapshot persistence and read indexes
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

## Benchmarks

We benchmark Kin against raw Git exploration using a **validated** task suite, not hand-picked demos.

The public matrix below focuses on the primary production workflow: **Git vs Kin-native**. Other arms (`kin-compat`, `kin-native-cli`) are still exercised in targeted runs, but the 10-repo public sweep uses the native semantic workflow we actively optimize.

Latest checked sweep:

- 10 popular open source repos
- Language coverage in this checked matrix: JavaScript, TypeScript, Python
- 70 validated task comparisons (`7 tasks x 10 repos`)
- Assistant: Codex CLI `0.114.0`
- Result: **66/70 wins**, **54.0% less wall-clock time overall**, **41.3% fewer tokens overall**
- Total query time: `1416.1s` with Git vs `651.0s` with Kin-native

### Repo Results

| Repo | Language | Entities | Files | Git | Kin-native | Savings | Wins |
|------|----------|----------|-------|-----|------------|---------|------|
| [express](https://github.com/expressjs/express) | JavaScript | 203 | 245 | 132.2s | 56.1s | 57.6% | 7/7 |
| [axios](https://github.com/axios/axios) | JavaScript | 546 | 371 | 128.2s | 56.1s | 56.2% | 7/7 |
| [hono](https://github.com/honojs/hono) | TypeScript | 1847 | 501 | 150.2s | 58.1s | 61.3% | 7/7 |
| [zod](https://github.com/colinhacks/zod) | TypeScript | 3199 | 582 | 138.2s | 58.1s | 58.0% | 7/7 |
| [flask](https://github.com/pallets/flask) | Python | 1018 | 269 | 134.2s | 60.1s | 55.2% | 6/7 |
| [typer](https://github.com/fastapi/typer) | Python | 1663 | 766 | 124.2s | 58.1s | 53.2% | 7/7 |
| [requests](https://github.com/psf/requests) | Python | 758 | 158 | 160.2s | 96.1s | 40.0% | 5/7 |
| [redux](https://github.com/reduxjs/redux) | JavaScript | 257 | 483 | 144.2s | 64.1s | 55.6% | 7/7 |
| [click](https://github.com/pallets/click) | Python | 1156 | 182 | 156.2s | 86.1s | 44.9% | 6/7 |
| [dayjs](https://github.com/iamkun/dayjs) | JavaScript | 191 | 413 | 148.2s | 58.1s | 60.8% | 7/7 |

### Task Results

| Task | Kin-native Wins | Average Savings |
|------|------------------|-----------------|
| `count-real-callers` | 8/10 | 31.6% |
| `find-dead-code` | 10/10 | 58.0% |
| `find-planted-secret` | 8/10 | 22.9% |
| `fix-planted-bug` | 10/10 | 51.1% |
| `implement-stub` | 10/10 | 47.2% |
| `trace-computation` | 10/10 | 72.6% |
| `trace-type-imports` | 10/10 | 66.7% |

The only losses in the 70-task sweep were:

- `flask` / `find-planted-secret` (`10.0107s` git vs `10.0167s` native)
- `requests` / `find-planted-secret` (`10.0176s` git vs `10.0213s` native)
- `requests` / `count-real-callers` (`28.0446s` git vs `40.0530s` native)
- `click` / `count-real-callers` (`22.0409s` git vs `42.0566s` native)

Two of those four misses were effectively ties measured in milliseconds.

### How We Keep It Fair

This harness is designed to be reviewable and hard to game:

- We use the **same assistant binary**, **same machine**, **same repo snapshot**, and **same validated task set** for both arms.
- Every run uses `--fresh-conversion`, so Kin rebuilds its graph for that repo instead of reusing a stale prepared cache.
- The harness plants randomized benchmark artifacts into the source tree **once**, then copies that exact `_source/` tree into every arm. The arms see identical files.
- Artifact names carry random tags and secret values are random UUIDs, so the assistant cannot answer from training data.
- The planted files import **real symbols** from the host repo and inject a real entry-point reference, forcing the benchmark through the repo's actual dependency graph.
- Prompts are identical across arms. Only the available tools differ.
- Validation is automatic against planted ground truth. Slow runs and wrong answers stay in the totals; there is no manual scoring.
- Conversion cost is reported separately from per-task timings so we do not hide Kin's one-time indexing cost inside query numbers.
- Raw per-run reports are written locally to `.kin/bench/live-*.json`.

### Environment Caveat

This sweep was **not** run on a perfectly clean benchmark box. The harness recorded:

- load average range: `5.3` to `8.8`
- swap usage range: `2764 MB` to `2788 MB`
- competing assistant processes: `3` on every run

So treat the absolute times as noisy and the task-by-task win/loss counts as more meaningful than single-run millisecond deltas.

Detailed notes for this exact sweep are checked in at [docs/benchmarks/validated-popular-repos-2026-03-15.md](docs/benchmarks/validated-popular-repos-2026-03-15.md).

### Reproduce

```bash
# Build Kin
cargo build --release -p kin-cli

# Run the public 10-repo validated matrix
python3 scripts/run_popular_validated_benchmarks.py --assistant codex

# Raw reports land in .kin/bench/live-*.json
# Aggregate summaries land in .kin/bench/popular-validated-*.json and .md
```

---

## Building from Source

```bash
# Prerequisites: Rust 1.75+ (2021 edition)
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

---

*"So neither the one who plants nor the one who waters is anything, but only God, who makes things grow." — 1 Corinthians 3:7*
