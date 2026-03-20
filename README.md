# Kin

**Git stores text history. Kin understands code.**

Kin is a local-first semantic version control system built in Rust. It replaces Git's file-diff model with a graph of semantic entities and relationships, then serves precise context to AI agents and developers. Kin is not a coding assistant or a Git wrapper -- it is a sovereign VCS and the semantic operating layer that any assistant can use. `kin init` works with or without `.git`.

> **Alpha** -- Kin is in active development. The core thesis is proven (1,400+ tests, validated benchmarks, working brownfield migration), but APIs and CLI surface will evolve.

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021_edition-orange.svg)](https://www.rust-lang.org/)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-yellow.svg)](#status)

---

## Why Kin?

- **Precise context delivery** -- Graph-traversal context under token budgets, not file dumping. AI assistants get exactly the entities they need, with signatures for dependencies.
- **Identity tracking across refactors** -- Semantic fingerprints survive renames, moves, and formatting changes. Kin knows `processOrder` and `handle_order` are the same function.
- **Semantic review** -- Review changed entities and their impact graph, not line diffs. See what a change actually affects.
- **Provenance and trust** -- Every change carries evidence of who or what made it and why, with full execution traces.
- **Git interop** -- Import from Git, export to Git, but Git is not required. Kin adoption is reversible: delete `.kin/` and your source files remain untouched.
- **Measurable results** -- Built-in benchmarks prove token savings, wall-clock reduction, and context quality improvements against validated task suites.

---

## Quick Start

```bash
# Prerequisites: Rust 1.75+ (2021 edition)
git clone https://github.com/anthropics/kin.git
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

**Semantic entities** are the source of truth. Files are projections of semantic state -- rendered outputs, not primary artifacts. The embedded [KinDB](https://github.com/anthropics/kin-db) graph engine stores topology, metadata, signatures, and fingerprints. A content-addressable blob store holds raw code text.

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
| `kin bench` | Run benchmarks on repo |
| `kin migrate` | Import a Git/GitHub repo into Kin |
| `kin mcp` | Start or manage MCP server |
| `kin remote` | Configure or inspect GitHub/KinHub-style remotes |
| `kin push` | Publish to the default remote or prepare Git export |

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

Kin exposes its semantic graph through the [Model Context Protocol](https://modelcontextprotocol.io/), making it assistant-neutral. Any MCP-compatible tool -- Claude Code, Codex, Gemini CLI, Cursor, or others -- can query semantic search, impact analysis, dead code detection, review state, and more.

Start the MCP server with `kin mcp` or configure it as an MCP server in your assistant's settings.

---

## Benchmarks

We benchmark Kin against raw Git exploration using a **validated** task suite, not hand-picked demos.

Latest checked sweep:

- 10 popular open source repos (Express, Axios, Hono, Zod, Flask, Typer, Requests, Redux, Click, Day.js)
- 70 validated task comparisons (7 tasks x 10 repos)
- Assistant: Codex CLI 0.114.0
- Result: **66/70 wins**, **54.0% less wall-clock time**, **41.3% fewer tokens**

### How We Keep It Fair

- Same assistant binary, same machine, same repo snapshot, same task set for both arms.
- Every run uses `--fresh-conversion` -- Kin rebuilds its graph from scratch.
- Planted artifacts carry random tags and secret values -- the assistant cannot answer from training data.
- Validation is automatic against planted ground truth. No manual scoring.
- Conversion cost is reported separately from per-task timings.

Full benchmark methodology and per-repo results: [docs/benchmarks/validated-popular-repos-2026-03-15.md](docs/benchmarks/validated-popular-repos-2026-03-15.md).

```bash
# Reproduce
cargo build --release -p kin-cli
python3 scripts/run_popular_validated_benchmarks.py --assistant codex
```

---

## Crate Architecture

Kin is built as 19 Rust crates in a Cargo workspace. Key crates:

| Crate | Description |
|-------|-------------|
| `kin-cli` | CLI with full command set |
| `kin-daemon` | Background service: file watch, incremental indexing, reconciliation |
| `kin-core` | Shared runtime, config, error types |
| `kin-model` | Canonical types: Entity, Relation, Contract, SemanticChange, Spec |
| `kin-db` | Embedded graph engine (also available as [standalone repo](https://github.com/anthropics/kin-db)) |
| `kin-parser` | Tree-sitter parsing and language adapters |
| `kin-context` | Token-budgeted context pack builder with semantic slicing |
| `kin-mcp` | MCP server -- assistant-neutral integration surface |

---

## Status

Kin is in **public alpha**.

**What's solid:**
- Core data model (Entity, Relation, SemanticChange, Fingerprint)
- Embedded graph database ([KinDB](https://github.com/anthropics/kin-db)) with snapshot persistence and read indexes
- Content-addressable blob store
- Tree-sitter parsing pipeline for all Tier 1 languages
- CLI command structure and routing
- Git import/export adapter
- MCP server protocol
- Validated benchmark suite (66/70 wins against Git-based exploration)

**What's still hardening:**
- Reconciliation loop edge cases (broken ASTs, partial parses)
- Semantic merge conflict resolution
- Multi-workspace coordination
- Performance optimization on large repos (100k+ entities)
- Living docs projection

We ship what works and are transparent about what doesn't yet. If you hit a rough edge, [open an issue](https://github.com/anthropics/kin/issues).

---

## Ecosystem

Kin is part of a larger ecosystem:

| Component | Description |
|-----------|-------------|
| **[kin](https://github.com/anthropics/kin)** | Semantic VCS (this repo) |
| **[kin-db](https://github.com/anthropics/kin-db)** | Embeddable graph engine substrate |
| **[kin-stack](https://github.com/anthropics/kin-stack)** | Orchestration, benchmarking, and proof tooling |
| **kin-code** | Editor shell |
| **kin-pilot** | Agent shell |
| **[KinHub](https://dev.kinhub.firelock.ai)** | Hosted collaboration layer |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, PR process, and code style guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License & Why Source-Available

Kin is licensed under the **Business Source License 1.1 (BSL)**. It converts to **Apache-2.0** on March 18, 2030. [KinDB](https://github.com/anthropics/kin-db), the embedded graph engine under Kin, is **Apache-2.0 today**.

BSL is not open source by the [OSI definition](https://opensource.org/osd). We use the term **source-available** deliberately.

### What you can do with Kin under BSL

- **Use it.** Run `kin init` on any repo, personal or commercial. No restrictions on local use.
- **Read it.** The full source is public. Audit it, learn from it, file issues against it.
- **Modify it.** Fork it, patch it, extend it for your own workflows.
- **Embed it.** Build internal tools, consulting workflows, or products on top of Kin -- as long as you are not offering a competing hosted VCS or collaboration service.
- **Wait.** Every version converts to Apache-2.0 four years after release. Your code will never be locked up forever.

### What you cannot do

Offer Kin as a managed or hosted service that competes with [KinHub](https://dev.kinhub.firelock.ai). That's it. That's the only restriction.

### Why not Apache-2.0 for everything?

We are a small team building a new category of developer infrastructure against trillion-dollar incumbents. We cannot afford to ship years of R&D under a license that lets a cloud provider offer "Managed Kin" as a service before we can sustain ourselves.

This is not theoretical. Elasticsearch, Redis, and Terraform all started fully open, built massive communities, watched cloud providers monetize their work, and then changed licenses after the fact -- breaking trust with the developers who built on them.

We chose a different path: **set the boundaries on day one**, before anyone writes a line of code against our APIs. No bait-and-switch. No rug pull. BSL from the start, with a public conversion date.

### The trust gradient

| Layer | License | Rationale |
|-------|---------|-----------|
| **[kin-db](https://github.com/anthropics/kin-db)** | Apache-2.0 | The foundation is fully open. Use it, embed it, fork it, no restrictions. |
| **kin** (this repo) | BSL 1.1 → Apache-2.0 | The semantic engine is source-available with a 4-year conversion guarantee. |
| **[kin-stack](https://github.com/anthropics/kin-stack)** | BSL 1.1 → Apache-2.0 | The orchestration layer follows the engine. |
| **KinHub** | Proprietary | The hosted collaboration platform is our business. |

We believe this is the most honest version of open core: permissive at the base, protective in the middle, commercial at the top. You can see exactly where the lines are drawn and why.

### FAQ

**Q: Can I use Kin at work?**
Yes. BSL explicitly permits production use in commercial environments. The only restriction is offering Kin itself as a competing hosted service.

**Q: Can I build a product that uses Kin internally?**
Yes. Your product is not a competing hosted VCS service -- it's your product. Kin is a tool in your stack.

**Q: What if I disagree with BSL on principle?**
We respect that position. KinDB is Apache-2.0 if you want the graph engine without any restrictions. And every version of Kin converts to Apache-2.0 after four years.

**Q: What happens if Firelock is acquired or shuts down?**
The conversion date is baked into the license. It does not depend on Firelock existing. Even if we disappear tomorrow, the March 2030 conversion to Apache-2.0 still happens automatically.

See [LICENSE](LICENSE) for the full legal text.

---

Built by [Firelock, LLC](https://firelock.ai).

---

*"So neither the one who plants nor the one who waters is anything, but only God, who makes things grow." -- 1 Corinthians 3:7*
