# Kin — The Semantic System of Record for Software Work

Kin is a semantic, graph-first repository and collaboration substrate for AI-native software development. Unlike traditional file-first, diff-first systems (like Git), Kin represents software as a semantic graph of entities (functions, methods, classes, structs, traits, enums, interfaces, types, constants) and relations (calls, imports, references, inheritance).

In Kin, the graph is the source of authority. The filesystem is a derived projection over that graph truth, made transparently available to existing editors and compilers through the `kin-vfs` virtual filesystem.

## Core Features

- **Semantic VCS**: Version control at the level of entities and relations instead of lines and files.
- **AI-native context packs**: Build structured context packs containing a target entity plus its caller/callee neighborhood in a single call (`kin context`).
- **Trace & dataflow**: Trace call chains and dataflow dependencies in one step instead of looping over file reads (`kin trace`, `kin trace-data-flow`).
- **Ejectable brownfield compatibility**: Works alongside Git and traditional toolchains. `kin eject` removes Kin and restores files to their pre-init state, so there is no data lock-in.

---

## Installation

Install Kin with a single command:

```sh
curl -fsSL https://get.kinlab.dev/install | sh
```

The installer downloads the latest release from GitHub, places the `kin` and `kin-vfs`
binaries into `~/.kin/bin`, updates your shell profile (`.zshrc` / `.bashrc`), and then
runs the interactive setup wizard.

### Installer configuration

Configure the installer with environment variables:

- `KIN_VERSION`: Pin a specific version to download (e.g. `0.1.0`). If omitted, the latest release is resolved automatically.
- `KIN_DIR`: Custom installation directory (defaults to `~/.kin`).
- `KIN_NO_SETUP`: Set to `1` to skip the interactive setup wizard after the binaries are downloaded.

---

## Quickstart

See [docs/quickstart.md](docs/quickstart.md) for the full end-to-end walkthrough.

### 1. Initialize a repository

Build a semantic graph over your codebase:

```sh
kin init
```

*Options:*
- `[PATH]`: Directory to initialize (defaults to the current directory).
- `--force`: Initialize even if a `.git/` directory is detected.
- `--git-history <off|recent|full>`: Git history import depth (default: `recent`).
- `--no-lsp`: Skip LSP enrichment for a faster, tree-sitter-only init.

### 2. Add embeddings (enables semantic search)

`kin init` builds the graph instantly without embeddings. Run `kin embed` to add the
vector index that powers semantic search and `kin locate`:

```sh
kin embed
```

Embeddings are generated locally with `nomic-embed-text-v1.5` (768 dimensions; override
via `KIN_EMBED_MODEL_ID`). `kin status --json` reports embedding coverage under its
`semantic_coverage` block.

### 3. Configure your system and shell

Run the setup wizard, or run health checks at any time:

```sh
kin setup
```

*Options:*
- `status`: Show what's installed.
- `doctor`: Run a quick health check.
- `--mode <native|compatibility>`: Repository operation mode.
- `--shell <zsh|bash|powershell>`: Target shell for profile updates.
- `--auto-daemon`: Auto-start `kin-daemon` when entering workspaces.

### 4. Everyday commands

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
- **Eject and restore files**:
  ```sh
  kin eject [--force]
  ```

---

## MCP Server Integration

Kin ships with a built-in MCP (Model Context Protocol) server that exposes semantic tools
to AI assistants (Claude, Cursor, Gemini, Codex, etc.). It runs as a stdio server that the
MCP client launches as a subprocess:

```sh
kin mcp start
```

For the full tool surface, see [docs/mcp-tools.md](docs/mcp-tools.md).

---

## Architecture & Thesis

To understand the philosophy behind Kin, see the [thesis document](docs/thesis.md).
