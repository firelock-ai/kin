# kin-runtime

Workspace runs, validation, and evidence capture for Kin.

## Overview

kin-runtime provides the execution layer for running validation commands against materialized workspaces. It creates isolated workspace snapshots, executes commands within them, captures evidence (stdout, stderr, exit codes, test results), and manages workspace lifecycle for reproducibility. This is the foundation for benchmarking and proof generation.

## Key Types

- **`ValidationRun`** / **`RunStatus`** / **`RunOptions`** -- A validation run with its status and configuration.
- **`Workspace`** / **`MaterializedWorkspace`** -- Workspace abstraction and materialized instance.
- **`WorkspaceSnapshot`** -- Point-in-time snapshot of a workspace for reproducibility.
- **`MaterializeStrategy`** / **`MaterializeConfig`** -- How to materialize a workspace from graph state.
- **`ExecContext`** / **`ExecResult`** -- Execution context and result for commands run in a workspace.
- **`CapturedEvidence`** -- Captured output (stdout, stderr, test results) from a run.
- **`ReplayMetadata`** -- Metadata for replaying a previous run.

## Key Functions

- **`create_workspace`** / **`snapshot_workspace`** -- Create and snapshot workspaces.
- **`exec_in_workspace`** -- Execute a command in a materialized workspace.
- **`create_run`** / **`execute_run`** -- Create and execute validation runs.
- **`store_evidence`** / **`parse_test_output`** -- Capture and parse execution evidence.

## Testing

```bash
cargo test -p kin-runtime
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
