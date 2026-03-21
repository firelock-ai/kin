# kin-mcp

`kin-mcp` gives MCP-capable assistants an npm-native way to launch Kin's stdio
server without asking users to install the full CLI first.

## Usage

```bash
claude mcp add kin -- npx -y kin-mcp
codex mcp add kin -- npx -y kin-mcp
gemini mcp add kin -- npx -y kin-mcp
```

On first run, the wrapper downloads the matching `kin` release binary from
GitHub Releases, verifies the published SHA256 checksum, caches it locally, and
then runs:

```bash
kin mcp start
```

## Supported platforms

`kin-mcp` follows the release assets currently published for Kin:

- macOS `arm64`
- macOS `x64`
- Linux `x64`

## Environment overrides

- `KIN_MCP_KIN_BINARY` or `KIN_BINARY_PATH`: use an explicit local `kin` binary
  instead of the cached download
- `KIN_MCP_CACHE_DIR`: override the cache directory
- `KIN_MCP_RELEASE_BASE_URL`: override the release download base URL

## Notes

This package is for low-friction MCP setup. If you want the full Kin CLI on
your `PATH`, install the standalone release binary or build `kin` directly.
