# Kin Quickstart Guide

This guide walks you through installing Kin, initializing a repository, and running the
core semantic commands.

---

## 1. Install

Run the installer:

```sh
curl -fsSL https://get.kinlab.dev/install | sh
```

This downloads the latest release from GitHub, installs the `kin` and `kin-vfs` binaries
into `~/.kin/bin`, and updates your shell profile (`.zshrc` / `.bashrc`). To skip the
setup wizard during install, set `KIN_NO_SETUP=1`.

---

## 2. First-time setup

Run the interactive setup wizard to configure shell hooks, daemon auto-start, and health
checks:

```sh
kin setup
```

Run health checks at any time:

```sh
kin setup doctor
```

Show what components are installed:

```sh
kin setup status
```

---

## 3. Initialize a repository

Build a semantic graph over an existing Git repository or folder:

```sh
# Initialize in the current directory
kin init

# Or initialize a specific path
kin init path/to/project
```

*Flags:*
- `--git-history <off|recent|full>`: How much Git history to import into the graph on init (default: `recent`).
- `--force`: Initialize even if a `.git/` directory is already present.
- `--no-lsp`: Skip LSP enrichment (faster, tree-sitter-only init).

---

## 4. Add embeddings for semantic search

`kin init` builds the graph instantly **without** embeddings. To enable semantic
(vector) search and `kin locate`, build the vector index:

```sh
kin embed
```

Embeddings are generated locally with `nomic-embed-text-v1.5` (768 dimensions; override
via `KIN_EMBED_MODEL_ID`). You can check coverage at any time:

```sh
kin status --json   # see the "enrichment" block: embeddingsIndexed / embeddingsPending / embeddingsTotal
```

> Until embedding is complete, `kin search --semantic` and `kin locate` degrade
> gracefully (vector hits over whatever is already embedded, plus a text fallback) and
> report their coverage honestly rather than erroring.

---

## 5. Basic development workflow

### Check working copy status

```sh
kin status
```

### Commit changes

Save a new semantic change snapshot:

```sh
kin commit -m "refactor: optimize user query path"
```

### View history

```sh
kin log -n 10
```

### Semantic diff

Inspect changes at the level of entities rather than raw lines:

```sh
kin diff
```

---

## 6. Semantic exploration and retrieval

### Search

```sh
# Name / kind / language matching over declarations
kin search "save_user"

# Semantic (vector) search using a query description
kin search "persist user session to database" --semantic --show-body
```

### Trace

Resolve a focal entity, show its body, and summarize nearby context in one call:

```sh
kin trace "save_user" --max-lines 50
```

### Build context packs

Package a target entity along with its callers and dependencies for an AI assistant:

```sh
kin context "UserService" --budget 16k
```

### Locate

Rank the files most relevant to a problem description:

```sh
kin locate "users can't reset their password" --explain
```

---

## 7. Model Context Protocol (MCP) setup

Kin exposes its semantic tools to AI agents over MCP.

### Start the MCP server

`kin mcp start` launches the MCP **stdio** server. You normally do not run this by hand —
your AI client launches it as a subprocess (see the config below):

```sh
kin mcp start
```

### Configure your AI client

Add the Kin MCP server to your client's configuration (e.g.
`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "kin": {
      "command": "kin",
      "args": ["mcp", "start"]
    }
  }
}
```

> Vector-backed MCP retrieval (`semantic_locate`) and the stateful session/transaction/
> review/work tools operate against the repo's running Kin daemon. Enable
> `kin setup --auto-daemon` (or start the daemon yourself) so these tools have a live
> graph to query — `semantic_locate` returns an explicit error in offline/no-daemon mode.

Once configured, your assistant can use the semantic tools listed in the
[MCP Tools Reference](mcp-tools.md).
