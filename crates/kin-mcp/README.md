# kin-mcp

MCP server for Kin -- assistant-neutral integration.

## Overview

kin-mcp implements a Model Context Protocol (MCP) server that exposes 48 semantic tools over stdio. Any AI agent or IDE that speaks MCP can use these tools for semantic search, entity tracing, impact analysis, code review, context packing, benchmarking, and session management. The server is assistant-neutral -- it works with Claude, GPT, Gemini, or any MCP-compatible client.

## Key Types

- **`McpServerConfig`** -- Server configuration (tool filtering, session options).
- **`AssistantSession`** / **`SessionRegistry`** -- Per-assistant session state and registry.
- **`ToolDefinition`** -- JSON schema definition for an MCP tool.
- **`ToolCallParams`** / **`ToolCallResult`** -- Input/output types for tool invocations.
- **`JsonRpcRequest`** / **`JsonRpcResponse`** -- JSON-RPC 2.0 transport types.

## Usage

```bash
# Start the MCP server over stdio (typically invoked by an AI agent)
kin mcp start

# Tools are called via JSON-RPC over stdin/stdout
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"semantic_search","arguments":{"query":"auth"}},"id":1}' | kin mcp start
```

## Tool Categories

- **Search**: `semantic_search`, `find_references`, `dead_code`
- **Graph**: `get_entity`, `graph_neighborhood`, `explore_codebase`
- **Analysis**: `impact_analysis`, `semantic_diff`, `entity_history`
- **Review**: `semantic_review`, `contract_check`, `security_scan`
- **Context**: `get_context_pack`
- **Sessions**: `session_start`, `session_end`, `register_intent`
- **Benchmarks**: `benchmark`

## Testing

```bash
cargo test -p kin-mcp
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
