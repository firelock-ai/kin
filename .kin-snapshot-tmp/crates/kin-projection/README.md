# kin-projection

File/doc projection engine for Kin.

## Overview

kin-projection reconstructs source files from the semantic graph without destructive formatting churn. It uses surgical byte-range splicing on CST-preserving `FileLayout` structures, ensuring that projected files remain runnable (`npm test`, `cargo build`, etc. still pass). The engine handles entity mutation projection, import management, placement decisions for new entities, and living documentation generation.

## Key Types

- **`ProjectionState`** -- Tracks the state of a projection pass.
- **`Splice`** -- A byte-range replacement in a source file.
- **`PlacementDecision`** -- Where to insert a new entity in an existing file.
- **`FileLayout`** -- CST-preserving layout tracker mapping entities to byte ranges.

## Key Functions

- **`project_to_bytes`** / **`project_overlay_to_bytes`** -- Project graph state to file bytes.
- **`project_entity_mutations`** -- Apply entity-level changes to a file.
- **`reconstruct_file`** / **`apply_splices`** -- Byte-range splicing for surgical edits.
- **`add_import`** / **`remove_import`** -- Import statement management.
- **`generate_living_docs`** -- Auto-generated documentation from graph state.

## Testing

```bash
cargo test -p kin-projection
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
