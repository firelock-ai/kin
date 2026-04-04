<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/kin-lockup-dark.png">
    <source media="(prefers-color-scheme: light)" srcset=".github/kin-lockup-light.png">
    <img src=".github/kin-lockup-light.png" height="96" alt="Kin">
  </picture>
</p>

# Kin

**Git stores text history. Kin understands code.**

Kin is the semantic system of record for software work. It replaces the file-first, diff-first repository model with a graph of semantic entities and relationships, then serves precise context to AI agents and developers. Kin is not a coding assistant or a Git wrapper -- it is a sovereign VCS and the semantic operating layer that any assistant can use. `kin init` works with or without `.git`.

Latest checked result: on a validated 10-repo Codex CLI sweep, `kin-native` won `69/70` task comparisons while using `50.0%` less wall-clock time and `44.6%` fewer tokens than raw Git exploration. The benchmark methodology, per-repo matrix, and caveats are published in [docs/benchmarks/validated-popular-repos-2026-03-20.md](docs/benchmarks/validated-popular-repos-2026-03-20.md).

> **Alpha** -- Kin is in active development. The core thesis is proven (1,900+ tests, validated benchmarks, working brownfield migration), but APIs and CLI surface will evolve. Install via `curl -fsSL https://get.kinlab.dev/install | sh` or build from source with Cargo.

[![CI](https://github.com/firelock-ai/kin/actions/workflows/ci.yml/badge.svg)](https://github.com/firelock-ai/kin/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/firelock-ai/kin/branch/main/graph/badge.svg)](https://codecov.io/gh/firelock-ai/kin)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021_edition-orange.svg)](https://www.rust-lang.org/)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-yellow.svg)](#status)

---

## Proof

Kin is making a measurable claim, not a branding claim.

- **Validated benchmark sweep** -- `69/70` wins across 10 popular repos and 70 checked task comparisons
- **Speed** -- `50.0%` less wall-clock time overall (`1659.7s` for Git vs `829.8s` for Kin-native)
- **Efficiency** -- `44.6%` fewer tokens overall (`5,539,366` for Git vs `3,068,820` for Kin-native)
- **Breadth** -- 10 validated repos spanning JavaScript, TypeScript, and Python; this is repo breadth, not a claim of full language coverage
- **Validation** -- randomized planted artifacts, identical prompts, automatic scoring, and published raw run artifacts

Read the checked benchmark summary: [docs/benchmarks/validated-popular-repos-2026-03-20.md](docs/benchmarks/validated-popular-repos-2026-03-20.md).

---

## Demo

<p align="center">
  <img src=".github/demos/full-demo.gif" width="800" alt="Kin demo: init, import, commit, status, overview, and trace on a sample project">
</p>

Real CLI output on a sample project. `kin init` adopts an existing repo and builds the semantic graph immediately, and `kin trace` resolves any symbol through the graph in one hop.

---

## Git vs Kin

<p align="center">
  <img src=".github/demos/git-vs-kin-kin.gif" width="800" alt="Git vs Kin on the Kin repo: grep versus semantic trace and impact">
</p>

This is the comparison that matters in practice: the same real repo, the same question, and two different substrates. Git can find text. Kin can resolve the symbol semantically and show downstream impact directly.

Additional real-repo demos:

- [KinDB comparison](.github/demos/git-vs-kin-kin-db.gif)
- [KinLab comparison](.github/demos/git-vs-kin-kinlab.gif)

---

## Why Kin?

- **The file-first model is the bottleneck** -- AI agents should not have to repeatedly reconstruct software structure from files, line diffs, grep passes, and transient context windows. Kin makes semantic truth primary and treats files as projections.
- **Precise context delivery** -- Graph-traversal context under token budgets, not file dumping. AI assistants get exactly the entities they need, with signatures for dependencies.
- **Identity tracking across refactors** -- Semantic fingerprints survive renames, moves, and formatting changes. Kin knows `processOrder` and `handle_order` are the same function.
- **Semantic review** -- Review changed entities and their impact graph, not line diffs. See what a change actually affects.
- **Provenance and trust** -- Every change carries evidence of who or what made it and why, with full execution traces.
- **Git interop** -- Import from Git, export to Git, but Git is not required. Kin adoption is reversible: run `kin eject` and your source files remain untouched.
- **Measurable results** -- The latest checked sweep came in at `69/70` wins, `50.0%` less wall-clock time, and `44.6%` fewer tokens against validated Git-based exploration.

---

## Install

```bash
# One-line install (macOS/Linux)
curl -fsSL https://get.kinlab.dev/install | sh

# Or via cargo
cargo install --locked --path crates/kin-cli

# Then run interactive setup
kin setup
```

## Getting Started

```bash
# 1. Install
curl -fsSL https://get.kinlab.dev/install | sh

# 2. Initialize on any project
cd my-project
kin init .

# 3. Explore
kin status                    # See entity counts and graph state
kin search "authentication"   # Semantic search across the graph
kin overview                  # High-level codebase summary
kin impact                    # Analyze downstream impact
```

## MCP Integration

Kin exposes its semantic graph through the [Model Context Protocol](https://modelcontextprotocol.io/), making it assistant-neutral. Any MCP-compatible tool -- Claude Code, Codex, Gemini CLI, Cursor, or others -- can query semantic search, impact analysis, dead code detection, review state, and more.

```bash
# Auto-configure for Claude Code / Cursor
kin setup   # Select AI Assistants in the wizard

# Or manually
claude mcp add kin -- npx -y kin-mcp
codex mcp add kin -- npx -y kin-mcp
gemini mcp add kin -- npx -y kin-mcp
```

<p align="center">
  <img src=".github/demos/mcp-setup.gif" width="700" alt="MCP setup: one command, zero config">
</p>

The `npx` wrapper downloads the matching Kin release binary on first run, verifies the published checksum, caches it locally, and auto-initializes a `.kin/` repo if one doesn't exist. For full CLI workflows, use the standalone `kin` install via `curl | sh` or `cargo install`.

Start the MCP server with `kin mcp` or configure it as an MCP server in your assistant's settings.

<p align="center">
  <img src=".github/demos/git-interop.gif" width="700" alt="Adopting Kin on an existing Git repo">
</p>

`kin init` bootstraps the semantic graph from the current checkout -- entity extraction, fingerprinting, and relation mapping happen automatically. For full Git history import, `kin migrate` is available as an advanced surface. After initialization, `kin status` shows entity counts and `kin trace` resolves symbols through the graph rather than falling back to source text.

Kin adoption is reversible: run `kin eject` and your source files remain untouched. You can still `kin push` and `kin pull` against regular Git remotes — Kin-native mode does not require your collaborators to use Kin.

For day-to-day brownfield use, treat Kin as the local VCS and GitHub as the transport. `kin push` and `kin pull` keep a hidden `.git-export/` mirror in sync with the remote, so you do not have to use the checked-out `.git` repo as your primary interface once Kin is initialized.

---

## Key Workflows

You do not need to memorize a huge command catalog to get value from Kin. Most day-one usage falls into four workflows:

| Workflow | Start Here | What You Get |
|---------|------------|--------------|
| Understand one symbol fast | `kin trace`, `kin context`, `kin refs`, `kin impact` | Resolve a focal entity, build a narrow context pack, inspect callers/importers, and see downstream blast radius |
| Review and verify changes | `kin diff`, `kin review`, `kin verify`, `kin audit` | Entity-level change review, semantic risk signals, coverage checks, and provenance |
| Work in native mode | `kin mode`, `kin with`, `kin open`, `kin reconcile`, `kin exec` | Materialized workspaces, Kin-guided assistant sessions, and graph-backed reconciliation |
| Adopt without a flag day | `kin init`, `kin migrate`, `kin git export`, `kin remote`, `kin push`, `kin pull`, `kin mcp` | Brownfield adoption, optional full-history migration, Git coexistence, remotes, and assistant-neutral integration |

For the full CLI surface, run `kin --help` and `kin <command> --help`.

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

---

## Benchmarks

We benchmark Kin against raw Git exploration using a **validated** task suite, not hand-picked demos.

Latest checked sweep:

- 10 popular open source repos (Express, Axios, Hono, Zod, Flask, Typer, Requests, Redux, Click, Day.js)
- 70 validated task comparisons (7 tasks x 10 repos)
- Assistant: Codex CLI 0.114.0
- Result: **69/70 wins**, **50.0% less wall-clock time**, **44.6% fewer tokens**
- Scope: JavaScript, TypeScript, and Python only; Rust was excluded from the published matrix

Important caveats:

- This checked sweep is a strong proof of the current wedge, not a claim that every language or repository shape is equally covered.
- The run used one assistant configuration and one repetition per repo.
- The checked run was not on a lab-clean machine; see the linked methodology doc for the exact caveats and environment notes.

### How We Keep It Fair

- Same assistant binary, same machine, same repo snapshot, same task set for both arms.
- Every run uses `--fresh-conversion` -- Kin rebuilds its graph from scratch.
- Planted artifacts carry random tags and secret values -- the assistant cannot answer from training data.
- Validation is automatic against planted ground truth. No manual scoring.
- Conversion cost is reported separately from per-task timings.

Full benchmark methodology and per-repo results: [docs/benchmarks/validated-popular-repos-2026-03-20.md](docs/benchmarks/validated-popular-repos-2026-03-20.md). Reproducing the sweep locally will write raw run artifacts under `.kin/bench/`.

```bash
# Reproduce
cargo build --release -p kin-cli
python3 scripts/run_popular_validated_benchmarks.py --assistant codex
```

---

## Architecture Overview

Kin organizes code understanding into four planes:

```
┌─────────────────────────────────────────────────────────────┐
│                     SEMANTIC PLANE                          │
│  Entities, Relations, Contracts, SemanticChanges, Specs     │
│  ↕ source of truth                                          │
├─────────────────────────────────────────────────────────────┤
│                     PROJECTION PLANE                        │
│  Source files, Git commits, PR views, Living docs           │
│  ↕ rendered from semantic state                             │
├─────────────────────────────────────────────────────────────┤
│                     EXECUTION PLANE                         │
│  Local workspaces, Validation runs, Evidence capture        │
│  ↕ proves correctness                                       │
├─────────────────────────────────────────────────────────────┤
│                     CONTROL PLANE                           │
│  Reviews, Governance, Assistant adapters, Benchmarks        │
│  ↕ manages quality and trust                                │
└─────────────────────────────────────────────────────────────┘
```

**Semantic entities** are the source of truth. Files are projections of semantic state -- rendered outputs, not primary artifacts. The embedded [KinDB](https://github.com/firelock-ai/kin-db) graph engine stores topology, metadata, signatures, and fingerprints. A content-addressable blob store holds raw code text.

---

## Crate Architecture

Kin is built as 18 Rust crates in this workspace plus the shared `kin-model` crate shipped from the [kin-db](https://github.com/firelock-ai/kin-db) repo. Key crates:

| Crate | Description |
|-------|-------------|
| `kin-cli` | CLI with full command set |
| `kin-daemon` | Background service: file watch, incremental indexing, reconciliation |
| `kin-core` | Shared runtime, config, error types |
| `kin-model` | Canonical types: Entity, Relation, Contract, SemanticChange, Spec (consumed from the [kin-db](https://github.com/firelock-ai/kin-db) repo) |
| `kin-db` | Embedded graph engine (released in tandem as [its own repo](https://github.com/firelock-ai/kin-db)) |
| `kin-parser` | Tree-sitter parsing and language adapters |
| `kin-context` | Token-budgeted context pack builder with semantic slicing |
| `kin-mcp` | MCP server -- assistant-neutral integration surface |

---

## Status

Kin is in **public alpha**.

**What's solid:**
- Core data model (Entity, Relation, SemanticChange, Fingerprint)
- Embedded graph database ([KinDB](https://github.com/firelock-ai/kin-db)) with snapshot persistence and read indexes
- Content-addressable blob store
- Tree-sitter parsing pipeline for all Tier 1 languages
- CLI command structure and routing
- Git import/export adapter
- MCP server protocol
- Validated benchmark suite (69/70 wins against Git-based exploration)

**What's still hardening:**
- Reconciliation loop edge cases (broken ASTs, partial parses)
- Semantic merge conflict resolution
- Multi-workspace coordination
- Performance optimization on large repos (100k+ entities)
- Living docs projection

We ship what works and are transparent about what doesn't yet. If you hit a rough edge, [open an issue](https://github.com/firelock-ai/kin/issues).

---

## Ecosystem

Only `kin` and `kin-db` are shipping in this public alpha as the core substrate. `kin-vfs`, `kin-editor`, and `kinlab` are active surfaces around that core, with some surfaces still hardening rather than speculative.

| Component | Status | Description |
|-----------|--------|-------------|
| **[kin](https://github.com/firelock-ai/kin)** | Shipping now | Semantic VCS (this repo) |
| **[kin-db](https://github.com/firelock-ai/kin-db)** | Shipping now | Graph engine substrate |
| **[kin-vfs](https://github.com/firelock-ai/kin-vfs)** | Alpha | First-class transparent filesystem projection — serves files from blob store |
| **[kin-editor](https://github.com/firelock-ai/kin-editor)** | Alpha | Lightweight VS Code extension (MCP-first with CLI fallback) |
| **kin-mcp** | Alpha | Assistant-neutral MCP server bundled inside `kin` |
| **[KinLab](https://kinlab.ai)** | Hardening | Hosted collaboration layer |

Historical note: `kin-code` and `kin-pilot` are historical-only surfaces retained for reference. They are not part of the active product wedge.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, PR process, and code style guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

Kin is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for the full text.

[KinDB](https://github.com/firelock-ai/kin-db), the embedded graph engine under Kin, is also **Apache-2.0**.

---

Created by [Troy Fortin](https://www.linkedin.com/in/troy-fortin-jr/) at [Firelock, LLC](https://firelock.ai).

---

*"So neither the one who plants nor the one who waters is anything, but only God, who makes things grow." -- 1 Corinthians 3:7*
