# Kin — The Semantic System of Record for Software Work

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Install](https://img.shields.io/badge/install-get.kinlab.dev-6E56CF.svg)](https://get.kinlab.dev/install)
[![Homebrew](https://img.shields.io/badge/brew-firelock--ai%2Fkin-orange.svg)](https://github.com/firelock-ai/homebrew-kin)
[![kinlab.ai](https://img.shields.io/badge/hosted-kinlab.ai-111111.svg)](https://kinlab.ai)

Kin is a semantic, graph-first repository and collaboration substrate for AI-native software development. Unlike traditional file-first, diff-first systems (like Git), Kin represents software as a semantic graph of entities (functions, methods, classes, structs, traits, enums, interfaces, types, constants) and relations (calls, imports, references, inheritance).

In Kin, the graph is the source of authority. The filesystem is a derived projection over that graph truth, made transparently available to existing editors and compilers through the `kin-vfs` virtual filesystem.

## Core Features

- **Semantic VCS**: Version control at the level of entities and relations instead of lines and files.
- **AI-native context packs**: Build structured context packs containing a target entity plus its caller/callee neighborhood in a single call (`kin context`).
- **Trace & dataflow**: Trace call chains and dataflow dependencies in one step instead of looping over file reads (`kin trace`, `kin trace-data-flow`).
- **Ejectable brownfield compatibility**: Works alongside Git and traditional toolchains. `kin eject` removes Kin and leaves your working files untouched; `kin eject --revert-files` additionally restores files to their byte-for-byte pre-init state. Git history is never touched, so there is no data lock-in.

---

## Installation

Install Kin with a single command:

```sh
curl -fsSL https://get.kinlab.dev/install | sh
```

The installer downloads the latest release from GitHub, verifies its SHA-256 checksum
(and refuses to install an unverified or tampered download), places the `kin` and
`kin-daemon` binaries — plus the optional `kin-vfs` projection client where bundled —
into `~/.kin/bin`, updates your shell profile (`.zshrc` / `.bashrc`), and then runs the
interactive setup wizard. Re-running the installer upgrades an existing install in place.

On **Windows**, use PowerShell:

```powershell
irm https://get.kinlab.dev/install.ps1 | iex
```

The native Windows build is a limited, vector-free convenience binary with no filesystem
projection. For the complete, vector-enabled Kin with working projection, install under
WSL2 — see [docs/windows-wsl2.md](docs/windows-wsl2.md).

### Installer configuration

Configure the installer with environment variables:

- `KIN_VERSION`: Pin a specific version to download (e.g. `0.1.0`). If omitted, the latest release is resolved automatically.
- `KIN_DIR`: Custom installation directory (defaults to `~/.kin`).
- `KIN_NO_SETUP`: Set to `1` to skip the interactive setup wizard after the binaries are downloaded.
- `KIN_BASE_URL`: Install from a mirror or local path instead of GitHub releases (offline/airgapped installs and CI smoke tests). Supported by both the `sh` and PowerShell installers.

### Runtime configuration

The Kin daemon is the canonical authority for graph truth. Commands that analyze the
graph in-process (`kin merge`, `kin tag`, `kin semver`, `kin rollback`, `kin git export`)
read from the daemon and auto-start it as needed — no configuration required for normal use.

- `KIN_NO_DAEMON`: Set to `1` to disable daemon auto-start. The CLI will only use an
  already-running daemon (or `KIN_DAEMON_URL`).
- `KIN_DAEMON_URL`: Point the CLI at an explicit daemon endpoint instead of the
  repo-local one.
- `KIN_ALLOW_DAEMON_BOOTSTRAP_ADMIN`: Offline/admin escape hatch. Set to `1` to let
  the above read-only commands fall back to reading the local `.kin` snapshot directly
  when the daemon cannot be reached. Not needed for normal use, and never used for
  writes — all graph mutations still route through the daemon.

---

## Quickstart

There is **one recommended first-run path**, and it's the same on macOS, Linux, and
Windows (via WSL2): install → run the guided `kin setup` wizard → build the graph → verify.
See [docs/quickstart.md](docs/quickstart.md) for the full end-to-end walkthrough.

### 1. Run guided setup

The installer above already launches `kin setup` for you (run it again any time). It opens
with **"What do you want Kin for?"** and asks for your **intent**, then configures the
matching pieces:

```sh
kin setup
```

- **AI agents** (default) — wires Kin's MCP server into every detected AI client
  (Claude Code, Cursor, Codex, Gemini, Windsurf), plus shell integration and daemon
  auto-start. The smallest path to value.
- **Local-only** — shell integration + daemon auto-start; no AI client config.
- **Editor** — local-only, plus how to install the `kin-editor` VS Code extension.
- **Hosted / KinLab** — local setup, plus a note that hosted connect is coming soon (not
  yet a first-run flow).
- **Advanced / manual** — choose shell, per-client MCP, and daemon options yourself.

*Flags* (global; `kin setup --intent agent --no-interactive` for scripts/CI):
- `--intent <local|agent|editor|hosted|advanced>`: pick the first-run intent up front.
- `--shell <zsh|bash|powershell>`: target shell for profile updates.
- `--auto-daemon`: force daemon auto-start on (default on for every intent).
- `--no-interactive`: run with defaults / provided flags (default intent: `agent`).

*Subcommands:*
- `kin setup status [--json]`: probe and show what's installed (the health checklist).
- `kin setup doctor [--fix]` (or top-level `kin doctor [--fix]`): run health checks and
  optionally apply safe repairs.

### 2. Initialize a repository

Build a semantic graph over your codebase:

```sh
kin init
```

*Options:*
- `[PATH]`: Directory to initialize (defaults to the current directory).
- `--force`: Initialize even if a `.git/` directory is detected.
- `--git-history <off|recent|full>`: Git history import depth (default: `recent`).
- `--no-lsp`: Skip LSP enrichment for a faster, tree-sitter-only init.

### 3. Add embeddings (enables semantic search)

`kin init` builds the graph instantly without embeddings. Run `kin embed` to add the
vector index that powers semantic search and `kin locate`:

```sh
kin embed
```

Embeddings are generated locally with `nomic-embed-text-v1.5` (768 dimensions; override
via `KIN_EMBED_MODEL_ID`). `kin status --json` reports embedding coverage under its
`enrichment` block (`embeddingsIndexed` / `embeddingsPending` / `embeddingsTotal`).

### 4. Verify

Run the health checklist any time — it probes real filesystem, daemon, and agent state:

```sh
kin setup status
```

Checks cover the `kin` and `kin-daemon` binaries, VFS projection (macOS/Linux; **n/a** on
native Windows), shell integration, repository init, AI-client MCP config (the
`agent-default` profile), editor extension, KinLab connect (**n/a** — coming soon), and
semantic query readiness (**STALE** until you run `kin embed`). Failing checks print their
own `fix:` line; `kin doctor --fix` applies the safe repairs. See
[docs/quickstart.md](docs/quickstart.md#8-verify-your-setup-kin-setup-status) for the full
check table and what to do for each state.

### 5. Everyday commands

- **Status of the working copy**:
  ```sh
  kin status [--json]
  ```
- **Commit changes semantically**:
  ```sh
  kin commit -m "commit message"
  ```
- **Show the change log**:
  ```sh
  kin log [-n <count>]
  ```
- **Semantic diff**:
  ```sh
  kin diff [<base>] [<head>]
  ```
- **Search entities** (add `--semantic` for vector similarity over what is embedded):
  ```sh
  kin search "<pattern>" [--semantic] [--show-body]
  ```
- **Locate files relevant to an issue**:
  ```sh
  kin locate "<problem text>" [--explain]
  ```
- **Remove Kin (working files untouched)**:
  ```sh
  kin eject
  ```
- **Remove Kin and restore files to their pre-init state**:
  ```sh
  kin eject --revert-files
  ```

---

## MCP Server Integration

Kin ships with a built-in MCP (Model Context Protocol) server that exposes semantic tools
to AI assistants (Claude, Cursor, Gemini, Codex, Windsurf, etc.). The **AI agents** intent
in `kin setup` wires this up for every detected client automatically — there is nothing
else to configure. The wizard writes a `kin` server entry running `kin mcp start --global`
with `KIN_MCP_TOOL_PROFILE=agent-default` (the small curated tool surface).

`kin mcp start` runs as a stdio server that the MCP client launches as a subprocess; you
normally do not run it by hand. To wire up a client manually, use the npm wrapper
(`@kinlab/kin-mcp`), or see the exact config and config-file locations, read the
[Advanced configuration](docs/quickstart.md#9-advanced-configuration) section of the
quickstart. For the full tool surface, see [docs/mcp-tools.md](docs/mcp-tools.md).

---

## Architecture & Thesis

To understand the philosophy behind Kin, see the [thesis document](docs/thesis.md).

---

## The Kin ecosystem

Kin is one system with a few clear surfaces:

- **[kin](https://github.com/firelock-ai/kin)** — the semantic system of record (this repo): CLI, daemon, MCP server, projections, reconcile, review, provenance.
- **[kin-vfs](https://github.com/firelock-ai/kin-vfs)** — the transparent virtual filesystem that serves graph-backed files to any tool, unchanged.
- **[kin-editor](https://github.com/firelock-ai/kin-editor)** — the VS Code extension: entity explorer, semantic search, trace, rename/review.
- **[kin-db](https://github.com/firelock-ai/kin-db)** — the semantic engine: graph storage, snapshots, indexing, text + vector search.
- **[kinlab.ai](https://kinlab.ai)** — the hosted collaboration and control-plane layer.

Supporting substrate: [kin-blobs](https://github.com/firelock-ai/kin-blobs) · [kin-search](https://github.com/firelock-ai/kin-search) · [kin-vector](https://github.com/firelock-ai/kin-vector) · [kin-infer](https://github.com/firelock-ai/kin-infer) · [kin-lsp](https://github.com/firelock-ai/kin-lsp) · [kin-model](https://github.com/firelock-ai/kin-model).

## License

Kin is licensed under [Apache-2.0](LICENSE).
