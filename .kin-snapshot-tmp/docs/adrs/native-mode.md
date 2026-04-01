# ADR: Native Mode vs Compat Mode

**Status:** Accepted
**Date:** 2026-03-26
**Authors:** Troy Fortin

## Context

Kin operates in two fundamental modes that define the relationship between the entity graph and the filesystem. The choice of mode affects how edits flow, how conflicts are detected, and what happens when the AST breaks.

### The two modes

**Compat mode (brownfield):** Files on disk are the source of truth. The graph tracks them reactively via the reconciliation loop. This is the current default and is designed for coexistence with Git-based workflows.

**Native mode (greenfield):** The entity graph is the source of truth. Files in the working directory are projections of the graph state. Edits are captured as entity mutations in the graph, then projected back to disk for tool compatibility. This is the endgame architecture documented in `kin-vfs`.

### Current behavior

Today, Kin runs in compat mode by default:

1. **File -> Graph direction (reconcile):** The daemon watches the filesystem via `notify`. When a file changes, `kin-reconcile` parses it, diffs against existing entities, and updates the working copy overlay. Broken ASTs trigger LKG (Last Known Good) fallback -- the graph retains the previous valid state.

2. **Graph -> File direction (project):** When entities are mutated in the graph (e.g., via `kin-projection`), the engine uses CST-preserving byte-range splicing to update only the affected spans in the file, avoiding formatting churn.

3. **Commit:** `kin commit` scans all files, parses them, builds entity/relation deltas against the previous change, and creates a `SemanticChange` node. The snapshot is saved atomically via rename.

4. **VFS layer:** `kin-vfs` intercepts `open`/`read`/`stat` calls via `DYLD_INSERT_LIBRARIES` (macOS) or `LD_PRELOAD` (Linux) and serves file content from the blob store. This enables native mode without requiring editors or tools to be aware of the graph.

### Ambiguous fallback paths

Several code paths currently have implicit mode assumptions:

- `collect_all_files()` in `commit.rs` reads from `kin_core::source_dir(&layout)`, which returns the source root based on mode. In compat mode this is the repo root; in native mode it would be `.kin/source-root/`.
- The reconciler always reads from disk and updates the overlay. In native mode, edits should go graph-first and project to disk, reversing the data flow.
- The `--dry-run` flag on `kin commit` now allows validation of the full pipeline without persisting, useful for CI and pre-flight checks in either mode.

## Decision

### Mode selection

The mode is configured in `.kin/config.toml` under the `[mode]` section:

```toml
[mode]
type = "compat"  # or "native"
```

The default is `compat`. Switching to native mode requires explicit user action (`kin mode native`).

### Compat mode behavior (current default)

| Operation | Source of truth | Data flow |
|-----------|----------------|-----------|
| Edit a file | Filesystem | File -> reconcile -> overlay -> commit -> graph |
| Review changes | Graph (overlay) | Graph diff against base change |
| Commit | Graph | Overlay flattened into SemanticChange |
| Branch/merge | Graph | SemanticChange DAG operations |
| Git export | Graph -> files | `kin git export` projects graph to working tree |

### Native mode behavior (target)

| Operation | Source of truth | Data flow |
|-----------|----------------|-----------|
| Edit a file | Graph (via VFS) | Graph mutation -> project -> file (for tooling) |
| Review changes | Graph | Direct entity diff |
| Commit | Graph | Working copy overlay committed |
| Branch/merge | Graph | Same as compat (already graph-native) |
| File access | VFS | `kin-vfs` serves blob content on `open()`/`read()` |

### LKG semantics

In both modes, Last Known Good (LKG) semantics apply:
- A broken AST (syntax error) does not corrupt the graph.
- The `LkgStore` retains the previous valid entity state.
- The `ReconcilePolicy` controls whether broken ASTs are rejected (`BrokenAstBehavior::Reject`) or silently preserved (`BrokenAstBehavior::FallbackToLkg`).

### Projection invariant

After any projection, the working directory must still be runnable: `npm test`, `cargo build`, etc. should pass if they passed before. This invariant is enforced by the CST-preserving splice engine and is the primary constraint on native mode file generation.

## Acceptance matrix for native-mode daily driver

Before native mode can be the default, the following workflows must work end-to-end:

| Workflow | Acceptance criteria |
|----------|-------------------|
| **Edit + save** | Editor writes go through VFS -> graph mutation -> re-project. Round-trip produces identical file content. |
| **Build** | `cargo build` / `npm run build` succeeds when all files are VFS-served. |
| **Test** | `cargo test` / `npm test` succeeds with VFS-served files. |
| **Git interop** | `kin git export` produces a valid Git working tree. `kin git import` reconstitutes the graph. |
| **Search** | `grep`, `rg`, IDE search all work against VFS-served files. |
| **Debug** | Debuggers can set breakpoints via source maps that resolve through VFS. |
| **Large repo** | 10k+ entity repos operate within 100ms latency for common operations. |
| **Multi-language** | All 14 supported languages (TS, JS, Python, Go, Java, Rust, C, C++, C#, Ruby, Kotlin, PHP, Swift, HCL) parse and project correctly. |
| **Crash recovery** | Daemon crash leaves graph in a consistent state (atomic snapshot save). No data loss. |
| **Offline** | All local operations work without network. Registry and remote sync degrade gracefully. |

## Consequences

- Compat mode remains the safe default for brownfield adoption alongside Git.
- Native mode is incrementally enabled as VFS and projection mature.
- The `ReconcilePolicy` preset system (Brownfield, Hybrid, Native) already parameterizes the behavioral differences.
- CI can use `--dry-run` commits to validate the pipeline without persisting state, supporting both modes.
