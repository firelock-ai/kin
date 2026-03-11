# Kin Open-Core TODOs

This file tracks **non-blocking open-core follow-up work** that should stay visible after launch.

These are not private-roadmap or hosted/P4 items. They are local-core refinements that are useful, but not required to claim the current open-core release.

## Current TODOs

### 1. Split Semantic Depth Into C3 / C4 / C5

Status: later refinement

Current support reporting uses:

- `C0` opaque
- `C1` structured artifact
- `C2` shallow syntax
- `C5` full semantic pipeline

That is honest for the current implementation, but it does not distinguish:

- `C3`: entity/declaration extraction only
- `C4`: intra-file relations without confirmed cross-file linkage
- `C5`: confirmed cross-file semantics

Why this is deferred:

- Kin does not yet persist per-file semantic depth state strongly enough to report `C3` and `C4` without guesswork.
- Adding the labels now would create fake precision.

What a real implementation needs:

- per-file semantic depth/capability state
- persisted counts for intra-file and cross-file relation resolution
- support-report output that reflects observed depth, not just parser capability

### 2. Entity-Scoped `kin exec`

Status: later refinement

Current `kin exec --scope` supports file-path scoping, but `entity:<id>` scope still falls back to full materialization.

Why this is deferred:

- entity scope needs graph-backed entity-to-file resolution at materialization time
- materialization currently operates on filesystem paths, not semantic slices

What a real implementation needs:

- graph lookup from entity scope to owning files
- minimal workspace assembly from resolved semantic scope
- tests proving entity-scoped execution produces the expected file set

### 3. First-Class Persistence For C2 Shallow Files

Status: thin, working, still worth hardening

Current behavior:

- C2 files are parser-backed and extracted at shallow tier
- shallow metadata is persisted to `.kin/shallow/*.json`

What is still missing:

- graph-native persistence/query support for shallow tracked files
- unified tracked-file storage instead of a sidecar-only path
- richer queries over shallow declarations/imports

This is not a launch blocker because the data is now durable locally, but it is still a worthwhile hardening task.

## Rule

Do not turn these into fake-complete features in docs or CLI output. If Kin cannot report a distinction honestly, keep the simpler contract until the underlying state is real.
