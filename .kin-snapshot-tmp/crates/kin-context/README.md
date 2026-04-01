# kin-context

Token-budgeted context pack builder for Kin.

## Overview

kin-context builds optimized context packs for AI agents by selecting the most relevant entities, relations, and source fragments from the graph within a token budget. It estimates token counts and prioritizes context based on entity relevance, traffic signals, and graph proximity, ensuring agents get maximum signal within their context window.

## Key Types

- **`ContextOptions`** -- Configuration for context pack generation (token budget, filters, scope).
- **`AssistantHint`** -- Hints from the assistant about what context is most useful.
- **`ContextError`** -- Error type for context building failures.

## Key Functions

- **`build_context_pack`** -- Build a context pack within a token budget.
- **`build_context_pack_with_traffic`** -- Same, but prioritizes entities with active traffic.
- **`estimate_tokens`** -- Estimate token count for a string.

## Usage

```rust
use kin_context::{build_context_pack, ContextOptions};

let options = ContextOptions {
    token_budget: 8000,
    ..Default::default()
};
let pack = build_context_pack(&graph, &blob_store, &options)?;
```

## Testing

```bash
cargo test -p kin-context
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
