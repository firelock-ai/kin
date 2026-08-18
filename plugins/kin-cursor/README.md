# Kin for Cursor

Kin keeps a living map of the software itself so humans and agents can understand what
every change touches. Locate, search, context packs, data-flow tracing, and impact
analysis without raw file search.

## Install

Install from the Cursor Marketplace, or add the MCP server directly with the one-click link
in the [repository README](https://github.com/firelock-ai/kin#works-with-your-agent).

By hand, add this to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "kin": { "command": "npx", "args": ["-y", "@kinlab/kin-mcp"] }
  }
}
```

`kin setup --intent agent` writes that entry for you, pointing at your installed binary.

## What it does

The plugin registers Kin's MCP server, which runs `npx -y @kinlab/kin-mcp`. On first run
that downloads the matching Kin release for your platform, verifies its published SHA-256,
and serves the curated `agent-default` tool profile.

The tools worth knowing: `semantic_search` finds parsed declarations by name, kind, and
language. `semantic_locate` ranks code against a natural-language description using the
vector index. `get_context_pack` returns an entity with its callers and imports in one
call. `find_references` and `graph_neighborhood` walk the reference graph. `trace_data_flow`
returns the ordered chain a value travels. `impact_analysis` answers what a change can
reach. The full surface is documented in
[docs/mcp-tools.md](https://github.com/firelock-ai/kin/blob/main/docs/mcp-tools.md).

Every response names the graph state that produced it, and an empty result says whether the
absence can be trusted. A graph gap is reported as a gap rather than filled in from raw file
search.

## Before the tools can answer

Kin answers from a graph, so a repository has to be admitted first. Run `kin init .` in the
repository, or set `KIN_MCP_AUTO_INIT=1` to let the server do it. Then run `kin embed` to
build the vector index that `semantic_locate` ranks against. The structural tools work as
soon as admission finishes.
[llms-install.md](https://github.com/firelock-ai/kin/blob/main/llms-install.md) is the
step-by-step version, written so an agent can follow it unattended.

## Requirements

Node 20 or newer for `npx`, and network access on the first run to fetch the Kin release.
macOS, Linux, and Windows x64 are supported. On Windows, WSL2 is the recommended path.

Apache-2.0. Home: https://kinlab.ai
