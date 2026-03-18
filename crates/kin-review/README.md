# Kin Review

`kin-review` is Kin's semantic review engine.

The old top-level extraction repo has been folded back into this crate so review logic stays close to the local semantic substrate while the interfaces are still moving. If review semantics become independently reusable later, this crate remains the extraction point.

## Owns

- semantic diff and impact analysis
- review summaries and risk highlights
- reusable gate and review formatting used by CLI and MCP paths

## Validate

```bash
cargo test -p kin-review
```
