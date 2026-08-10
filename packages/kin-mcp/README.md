# @kinlab/kin-mcp

> **Superseded by [`@kinlab/kin`](https://www.npmjs.com/package/@kinlab/kin)**, the
> canonical Kin install surface. It includes the MCP server (`kin mcp start`) along
> with the full CLI. This package keeps working for existing configurations, but new
> setups should install `@kinlab/kin`.

`@kinlab/kin-mcp` is the npm-friendly launcher for Kin's MCP server (the installed
command is still `kin-mcp`).

It downloads the matching Kin release archive from GitHub, verifies the published
SHA-256 checksum, extracts both the `kin` CLI and the `kin-daemon` it depends on
into a local cache, and runs:

```sh
kin mcp start
```

On first run it:

- provisions `kin-daemon` next to `kin` and points the CLI at it with
  `KIN_DAEMON_BIN`, so the MCP path never depends on a locally-built `kin`, a
  stale daemon on `PATH`, or a pre-existing daemon;
- defaults `KIN_MCP_TOOL_PROFILE=agent-default`, so agents see the small curated
  tool surface instead of the full internal one;
- starts (or reuses) the repo daemon automatically, and only then serves tools;
- requires an explicit `kin init` (no silent init) unless you opt in with
  `KIN_MCP_AUTO_INIT=1`.

If a runnable Kin cannot be provisioned (unsupported target, release download
blocked), the wrapper exits with a precise guided fix instead of a stack trace.

## Usage

Use it directly from an MCP client with `npx`:

```json
{
  "mcpServers": {
    "kin": {
      "command": "npx",
      "args": ["-y", "@kinlab/kin-mcp"]
    }
  }
}
```

For a pinned version:

```json
{
  "mcpServers": {
    "kin": {
      "command": "npx",
      "args": ["-y", "@kinlab/kin-mcp@0.5.14"]
    }
  }
}
```

## Requirements

- Node.js 20+
- macOS, Linux, or native Windows x64
- A Kin-initialized repository (`kin init`)

The native Windows archive carries semantic vector search but does not include
transparent filesystem projection. Use WSL2 when you need projection.

## Cache

The wrapper caches the downloaded `kin` and `kin-daemon` binaries under:

- macOS: `~/Library/Caches/kin-mcp`
- Linux: `~/.cache/kin-mcp`
- Windows: `%LOCALAPPDATA%\kin-mcp\Cache`

Set `KIN_MCP_CACHE_DIR` to override the cache location.

## Environment

- `KIN_MCP_KIN_BINARY`: run a specific local `kin` binary instead of downloading
  one (you are then responsible for its `kin-daemon`)
- `KIN_BINARY_PATH`: alias for `KIN_MCP_KIN_BINARY`
- `KIN_MCP_CACHE_DIR`: override the cache directory
- `KIN_MCP_AUTO_INIT=1`: allow the wrapper to run `kin init .` when `.kin/` is missing
- `KIN_MCP_TOOL_PROFILE`: override the default `agent-default` tool profile
- `KIN_MCP_RELEASE_BASE_URL`: override the GitHub release download base URL

## Local Check

```sh
npx -y @kinlab/kin-mcp --print-bin         # provisioned kin path
npx -y @kinlab/kin-mcp --print-daemon-bin  # provisioned kin-daemon path
```

Then initialize a repository and let the MCP client launch `kin-mcp`.

## First-run smoke proof

`test/smoke-first-run.mjs` exercises the whole first-run path against built Kin
binaries: it stages `kin` + `kin-daemon` into a throwaway cache (no pre-existing
daemon, no dev `PATH` state), runs the wrapper, and drives the MCP stdio protocol
through one safe semantic tool (`kin_graph_status`). Run it with:

```sh
cargo build --release -p kin-cli -p kin-daemon
KIN_BIN=target/release/kin \
KIN_DAEMON_BIN=target/release/kin-daemon \
npm run smoke
```
