# kin-reconcile

Kubernetes-style reconciliation loop for Kin.

## Overview

kin-reconcile keeps working directory files and the working copy graph overlay in bidirectional sync. It detects file edits and updates the overlay (file -> graph), and detects overlay mutations and re-projects affected files (graph -> file). It enforces Last Known Good (LKG) semantics: broken ASTs never corrupt the graph -- the previous valid parse is retained until the next successful one.

## Key Types

- **`Reconciler`** -- Main reconciliation engine with bidirectional sync.
- **`ReconcileOutcome`** -- Result of a reconciliation pass (entities synced, files projected).
- **`SemanticDelta`** / **`SemanticDeltaKind`** -- Describes what changed between reconciliation passes.
- **`MergePreview`** -- Preview of a merge before applying.
- **`CollisionCheck`** / **`MergeConflict`** -- Collision detection for concurrent entity modifications.
- **`TrafficChecker`** -- Checks entity-level traffic (who is editing what) for conflict prevention.
- **`LkgStore`** -- Last Known Good state persistence.

## Usage

```rust
use kin_reconcile::Reconciler;

let reconciler = Reconciler::new(&graph, &blob_store, &layout);
let outcome = reconciler.reconcile_file(&path)?;
```

## Testing

```bash
cargo test -p kin-reconcile
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
