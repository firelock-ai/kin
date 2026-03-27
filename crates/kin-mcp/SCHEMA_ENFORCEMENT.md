# MCP Tool Schema Enforcement -- Design

## Problem

Tool definitions in `tools.rs` use inline `serde_json::json!()` for schemas.
Handler signatures in `handlers.rs` are separate. Schema/handler drift is possible:
a field can be added to the handler struct but forgotten in the JSON schema, or
vice versa. This is caught at runtime (deserialization fails) rather than at
compile time.

## Proposed Solution

A proc-macro `#[mcp_tool]` that derives the JSON schema from the handler's
params struct, eliminating the separate hand-written schema entirely.

## Example

```rust
#[derive(Deserialize, McpSchema)]
struct SemanticSearchParams {
    query: String,
    #[schema(description = "Max results to return")]
    limit: Option<u32>,
    kind: Option<String>,
}

#[mcp_tool(name = "semantic_search", description = "Search entities by name")]
async fn semantic_search(graph: &G, params: SemanticSearchParams) -> Result<Value, McpError> {
    // ...
}
```

The `McpSchema` derive macro would:

1. Generate a `json_schema() -> Value` method on the params struct
2. Map Rust types to JSON Schema types (`String` -> `"string"`, `Option<T>` -> nullable, `u32` -> `"integer"`)
3. Collect `#[schema(description = "...")]` attributes for field descriptions
4. Mark non-`Option` fields as `required`

The `#[mcp_tool]` attribute macro would:

1. Register the tool in a static inventory (via `linkme` or `inventory` crate)
2. Wire up the handler function with automatic deserialization from `Value` -> params struct
3. Generate the tool definition entry combining name, description, and derived schema

## Implementation Sketch

```
kin-mcp-macros/          (new proc-macro crate)
  src/lib.rs             #[mcp_tool] and #[derive(McpSchema)]
```

The proc-macro crate would use `syn` + `quote` to parse struct fields, extract
types and attributes, and emit the schema JSON at compile time.

## Trade-offs

**Pros:**
- Single source of truth for tool parameters
- Compile-time guarantee that schema matches handler
- Less boilerplate in tools.rs

**Cons:**
- Proc-macro crates add compile-time overhead
- Type mapping (Rust -> JSON Schema) has edge cases (enums, nested structs, Vec<T>)
- Debugging proc-macro output is harder than debugging inline JSON

## Status

Deferred to post-10/10 milestone. Current inline schemas work correctly and the
37 tools are stable. The macro becomes more valuable as the tool count grows or
if external contributors add tools.
