# Phase 9 Acceptance: Verification Graph And Completion Engine

This is the concrete acceptance artifact for the current Phase 9 slice.

It proves that Kin can:

- model tests and verification runs as first-class graph objects
- drive a targeted runner from semantic test linkage instead of only file names
- persist run evidence in the repo snapshot
- link proof runs back to entities and work items
- report work completion from targeted proof state instead of only coverage presence

## What This Demo Covers

- entity-linked test cases and work-linked tests
- persisted `VerificationRun` objects
- proof links from runs to entities and work items
- `kin verify run <entity>` choosing a targeted proof set when linked tests exist
- `kin work verify <work-id>` reporting direct work tests, proof runs, and completion state

## CLI Walkthrough

Assume you are inside a Kin repo with semantic state already indexed and at least one entity already present in the graph.

Create a work item and link its proof:

```bash
kin work create --kind feature --title "Ship checkout" --scope entity:<entity_id>
kin work show <work_id>
```

Attach a test case to the same semantic scope and link it to the work item through the graph setup or migration path used by the repo.

Run targeted verification:

```bash
kin verify run checkout --runner printf
kin work verify <work_id>
```

Expected outcome:

- `kin verify run` prints the targeted proof set when linked tests exist
- the resulting run is persisted in the snapshot and linked back to the entity
- if the linked tests also verify the work item, the run is linked back to the work item too
- `kin work verify` reports:
  - direct work tests
  - direct proof runs
  - the targeted test set and latest run status
  - `VERIFIED` only when proof is passing and no scoped proof gaps remain

## Acceptance Backing

This acceptance artifact is backed by:

- CLI/unit coverage in [`crates/kin-cli/src/commands/verify.rs`](../../crates/kin-cli/src/commands/verify.rs)
- work-verification coverage in [`crates/kin-cli/src/commands/work.rs`](../../crates/kin-cli/src/commands/work.rs)
- graph acceptance coverage in [`tests/integration/src/p9_acceptance.rs`](../../tests/integration/src/p9_acceptance.rs)

Focused validation:

```bash
cargo test -p kin-cli
cargo test -p kin-integration-tests p9_acceptance -- --nocapture
```

## Remaining Phase 9 Work

This does not close Phase 9 entirely yet.

Still remaining:

- stronger contract-outcome and failure-path proof modeling
- smaller impacted-test computation from semantic change sets instead of entity-only targeting
- benchmark/demo evidence showing targeted proof materially smaller than broad file-based execution
