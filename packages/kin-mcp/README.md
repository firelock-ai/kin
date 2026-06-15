# kin-mcp

`kin-mcp` is the npm-friendly launcher for Kin's MCP server.

It downloads the matching Kin release archive from GitHub, verifies the published
SHA-256 checksum, extracts the `kin` binary into a local cache, and runs:

```sh
kin mcp start
```

## Usage

Use it directly from an MCP client with `npx`:

```json
{
  "mcpServers": {
    "kin": {
      "command": "npx",
      "args": ["-y", "kin-mcp@alpha"]
    }
  }
}
```

For a pinned alpha:

```json
{
  "mcpServers": {
    "kin": {
      "command": "npx",
      "args": ["-y", "kin-mcp@0.1.0-alpha.26"]
    }
  }
}
```

## Requirements

- Node.js 20+
- macOS or Linux
- A Kin-initialized repository (`kin init`)

Windows users should run Kin through WSL2 during the alpha.

## Cache

The wrapper caches the downloaded `kin` binary under:

- macOS: `~/Library/Caches/kin-mcp`
- Linux: `~/.cache/kin-mcp`

Set `KIN_MCP_CACHE_DIR` to override the cache location.

## Environment

- `KIN_MCP_KIN_BINARY`: run a specific local `kin` binary instead of downloading one
- `KIN_BINARY_PATH`: alias for `KIN_MCP_KIN_BINARY`
- `KIN_MCP_CACHE_DIR`: override the cache directory
- `KIN_MCP_AUTO_INIT=1`: allow the wrapper to run `kin init .` when `.kin/` is missing
- `KIN_MCP_RELEASE_BASE_URL`: override the GitHub release download base URL

## Local Check

```sh
npx -y kin-mcp@alpha --print-bin
```

Then initialize a repository and let the MCP client launch `kin-mcp`.
