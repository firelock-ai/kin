# Kin

> **AI writes code. Kin proves it safe to ship.**
> AI made code cheap to write and expensive to trust.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v0.2.15-6E56CF.svg)](https://github.com/firelock-ai/kin/releases)
[![kinlab.ai](https://img.shields.io/badge/hosted-kinlab.ai-111111.svg)](https://kinlab.ai)

AI agents now generate code faster than teams can review it. The hard part is no longer
writing a change — it's trusting one: knowing what it actually touches, whether it silently
reverts an earlier fix, and how far its blast radius reaches before it merges. Git tracks
lines and files, so it can't answer those questions directly. Kin is **the system of record
for AI-written software**: it represents your codebase as a graph of entities and
relations and reasons over that graph instead of over text diffs.

---

## What Kin is

Kin is a graph-native repository substrate. Instead of files and line diffs, it models
software as a semantic graph:

- **Entities** — functions, methods, classes, structs, traits, enums, interfaces, types, constants.
- **Relations** — calls, imports, references, inheritance.

The graph is the source of authority. Your filesystem becomes a derived projection over that
graph truth, served transparently to existing editors and compilers through the `kin-vfs`
virtual filesystem — so every tool you already use keeps working, unchanged.

Because Kin reasons over entities and relations, it can answer questions a line-diff tool
can't: which callers a change reaches, whether an edit undoes an earlier one, and what the
real blast radius of a merge is.

---

## Install

Kin ships as native binaries on [GitHub Releases](https://github.com/firelock-ai/kin/releases)
(currently **v0.2.15**) for five targets: macOS (Apple Silicon and Intel), Linux (x86_64 and
aarch64, static musl), and Windows (x86_64, supported for the vector-free surface described below).

**Direct download.** Grab the archive for your platform, verify its checksum, and extract.
The release publishes a `.sha256` next to every archive.

```sh
# Apple Silicon macOS shown; swap in your platform's archive name.
curl -fsSLO https://github.com/firelock-ai/kin/releases/download/v0.2.15/kin-macos-aarch64.tar.gz
curl -fsSLO https://github.com/firelock-ai/kin/releases/download/v0.2.15/kin-macos-aarch64.tar.gz.sha256
shasum -a 256 -c kin-macos-aarch64.tar.gz.sha256
tar xzf kin-macos-aarch64.tar.gz      # contains the `kin` and `kin-daemon` binaries
```

Archive names: `kin-macos-aarch64`, `kin-macos-x86_64`, `kin-linux-x86_64`,
`kin-linux-aarch64`, `kin-windows-x86_64`.

**Install script.** The convenience installer downloads the latest release, verifies its
SHA-256 checksum (and refuses to install a tampered or unverified download), places `kin` and
`kin-daemon` in `~/.kin/bin`, updates your shell profile, and launches setup:

```sh
curl -fsSL https://get.kinlab.dev/install | sh
```

On **Windows**, use PowerShell (`irm https://get.kinlab.dev/install.ps1 | iex`). The native
Windows build is a supported vector-free runtime for graph, lexical, daemon, setup, and MCP
workflows, with vector similarity and filesystem projection explicitly unsupported. For the
complete vector-enabled/projection experience, install under WSL2 — see
[docs/windows-wsl2.md](docs/windows-wsl2.md).

**For AI agents.** `kin setup --intent agent` wires Kin's built-in MCP server into every
detected assistant with the curated `agent-default` tool profile. npm users can install the
canonical launcher with `npm install -g @kinlab/kin` (**0.2.15**) and run the same setup
command; the older `@kinlab/kin-mcp` package remains as a compatibility wrapper.

See [docs/quickstart.md](docs/quickstart.md) for installer environment variables
(`KIN_VERSION`, `KIN_HOME`, `KIN_DIR`, `KIN_NO_SETUP`, `KIN_BASE_URL`) and daemon/runtime configuration.

---

## 60-second quickstart

With `kin` on your PATH:

```sh
kin setup                            # wire Kin's MCP tools into your AI agents
                                     #   (detects Claude Code, Cursor, Codex, Gemini, Windsurf)
kin init                             # new no-Git folders become Kin-native by default;
                                     # existing Git repos import recent history by default
kin locate "webhook retries twice"   # find the entities/files behind an issue
kin refs charge_customer             # who calls, imports, or references this entity
kin review shadow main..HEAD         # report-only merge-gate verdict:
                                     #   blast radius, repair context, audit evidence
```

`kin init` builds the graph instantly without embeddings; `kin locate` and `kin search` still
work over lexical and graph signals and tell you when the semantic signal is only partial. Run
`kin embed` once to add the local vector index that powers full semantic search. `kin setup
status` (or `kin doctor --fix`) verifies your setup end to end.

---

## What you get

**Report-only review — the shadow merge gate.** `kin review shadow <base>..<head>` evaluates a
PR-shaped change and emits a report-only verdict: blast radius, repair context, and audit
evidence. It never blocks and never mutates graph state, so you can run it in CI or locally as
evidence. Because Kin tracks entities over time, the report surfaces what a text diff misses —
for example, a change that silently reverts an earlier fix shows up as evidence instead of
slipping through.

**Semantic locate, refs, and trace.** Ask for the entities behind an issue (`kin locate`), the
upstream callers/importers/references of an entity (`kin refs`), or an entire call and
data-flow chain in a single call (`kin trace`, `kin trace-data-flow`) — instead of looping over
file reads. Add embeddings (`kin embed`) for vector similarity in `kin locate` and
`kin search --semantic`.

**MCP tools for agents.** Kin ships a built-in MCP server that exposes these same operations as
tools to any MCP-capable assistant (Claude Code, Cursor, Codex, Gemini, Windsurf). `kin setup`
configures every detected client automatically. `kin mcp start` runs as a stdio server that the
MCP client launches as a subprocess; for manual configuration use the canonical npm package
(`npx -y @kinlab/kin`, which provisions the Kin CLI and daemon; `@kinlab/kin-mcp` remains as a
compatibility wrapper), or read the
[Advanced configuration](docs/quickstart.md#9-advanced-configuration) section of the
quickstart. For the full tool surface, see [docs/mcp-tools.md](docs/mcp-tools.md).

**Transparent filesystem projection.** `kin-vfs` serves graph-backed files to any tool as
ordinary files, so your editor, compiler, and scripts operate over graph truth without
modification.

---

## How it relates to Git

Kin coexists with Git — it does not rewrite or replace your Git history or remotes. `kin init`
bootstraps your current tree as semantic truth and imports recent Git history by default
(`--git-history off|recent|full`); `kin migrate` handles deep, full-history import.

There is no lock-in:

- `kin eject` removes Kin's `.kin/` graph and metadata and leaves your working files exactly as they are.
- `kin eject --revert-files` additionally restores files to their byte-for-byte pre-init state.

Eject never touches `.git`. After ejecting, the directory is a plain Git repository again.
Today Kin runs alongside Git as the semantic layer; the file and Git surfaces remain the
interop boundary.

---

## Proof posture

We keep benchmark claims narrow and reproducible. On the current citable evaluation, Kin's
`locate` is a **statistical tie with `grep` on F1**, with Kin ahead on **precision and
specificity**, and Kin's retrieval pipeline is **bit-identical across runs** (deterministic).
We are not claiming a speed or token-savings win. Full methodology, tasks, and artifacts live
in the [kin-bench](https://github.com/firelock-ai/kin-bench) proof package.

---

## The Kin ecosystem

Kin is one system with a few clear surfaces:

- **[kin](https://github.com/firelock-ai/kin)** — the semantic system of record (this repo): CLI, daemon, MCP server, projections, reconcile, review, provenance.
- **[kin-vfs](https://github.com/firelock-ai/kin-vfs)** — the transparent virtual filesystem that serves graph-backed files to any tool, unchanged.
- **[kin-editor](https://github.com/firelock-ai/kin-editor)** — the VS Code extension: entity explorer, semantic search, trace, rename/review.
- **[kin-mcp](https://www.npmjs.com/package/@kinlab/kin-mcp)** — the MCP server that gives AI agents Kin's semantic tools (bundled in this repo; published as `@kinlab/kin-mcp`).
- **[kinlab.ai](https://kinlab.ai)** — the hosted collaboration and control-plane layer.

Supporting substrate:
[kin-db](https://github.com/firelock-ai/kin-db) (graph storage, snapshots, text + vector search) ·
[kin-blobs](https://github.com/firelock-ai/kin-blobs) ·
[kin-search](https://github.com/firelock-ai/kin-search) ·
[kin-vector](https://github.com/firelock-ai/kin-vector) ·
[kin-infer](https://github.com/firelock-ai/kin-infer) ·
[kin-lsp](https://github.com/firelock-ai/kin-lsp) ·
[kin-model](https://github.com/firelock-ai/kin-model) ·
[kin-bench](https://github.com/firelock-ai/kin-bench).

---

## Status & roadmap

Kin is **0.2.x** — pre-1.0 and under active development. Expect rough edges and breaking
changes between releases. Being precise about what is and isn't ready today:

- **Install surface.** Native binaries ship on GitHub Releases and via the install script; the canonical `@kinlab/kin` npm package (`npm i -g @kinlab/kin`, or `npx -y @kinlab/kin`) provisions the same managed `kin` + `kin-daemon` release for npm-based workflows. `@kinlab/kin-mcp` remains published as a compatibility wrapper.
- **Windows.** The native Windows binary is a supported vector-free build for graph, lexical, daemon, setup, and MCP workflows; vector similarity and filesystem projection are unsupported. Use WSL2 for the complete experience.
- **Semantic search.** `kin init` builds the graph without embeddings; run `kin embed` to enable vector search. Until then, `locate`/`search` run on lexical + graph signals and say so.
- **Hosted KinLab.** Connecting a repo to hosted KinLab is coming soon; it is not yet a first-run flow.
- **Graph-first, with transitional compatibility.** The graph is the authority for Kin's own commands. File-first and Git-interop paths are supported as a migration boundary, not the long-term model.

To understand the philosophy behind Kin, see the [thesis document](docs/thesis.md).

---

## License

Kin is licensed under [Apache-2.0](LICENSE).
