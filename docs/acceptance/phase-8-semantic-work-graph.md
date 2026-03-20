# Phase 8 Acceptance: Semantic Work Graph

This is the concrete acceptance artifact for Phase 8.

It proves that Kin can track work and annotations as first-class semantic graph
objects attached to semantic scopes and work items, not only as file-local text.

## What This Demo Covers

- feature and task work items anchored to semantic scopes
- parent/child work decomposition
- blocking relationships between work items
- implementor links from semantic scopes to work items
- annotations attached directly to work items
- CLI and MCP surfaces exposing the same graph state

## CLI Walkthrough

Assume you are inside a Kin repo with semantic state already indexed.

```bash
kin work create --kind feature --title "Semantic review hub" --scope artifact:src/review.rs
kin work create --kind task --title "Wire review graph queries" --scope artifact:src/review.rs
kin work create --kind issue --title "Resolve remote divergence edge case"
```

Use the returned IDs below as:

- `<feature_id>`
- `<task_id>`
- `<issue_id>`

Link the work graph:

```bash
kin work decompose <feature_id> <task_id>
kin work block <task_id> <issue_id>
kin work implement <task_id> artifact:src/review.rs
kin work status <task_id> in_progress
kin note add work:<task_id> --kind reasoning --body "This task is the bridge between repo-local review and hosted KinLab review."
```

Inspect the result:

```bash
kin work show <task_id>
kin note list work:<task_id>
kin work list --scope artifact:src/review.rs
```

Expected outcome:

- `kin work show` reports parent items, blockers, implementors, and attached annotations
- `kin note list work:<task_id>` returns the work-targeted annotation
- `kin work list --scope ...` returns the feature/task scoped to that artifact

## MCP Walkthrough

The MCP surface now mirrors the same graph operations.

Relevant tools:

- `kin_work_create`
- `kin_work_list`
- `kin_work_show`
- `kin_work_link`
- `kin_work_decompose`
- `kin_work_block`
- `kin_work_implement`
- `kin_work_status`
- `kin_annotation_add`
- `kin_annotation_list`

Use `kin_annotation_add` / `kin_annotation_list` with `targets`, including
`work:<uuid>` targets, not only scope strings.

## Validation

This acceptance artifact is backed by:

- CLI/unit tests in `crates/kin-cli/src/commands/work.rs` and `crates/kin-cli/src/commands/note.rs`
- MCP handler tests in `crates/kin-mcp/src/handlers.rs`
- integration coverage in `tests/integration/src/p8_acceptance.rs`

Run the focused validation with:

```bash
cargo test -p kin-cli -p kin-mcp -p kin-db -p kin-review -p kin-git -p kin-migrate
cargo test -p kin-integration-tests p8_acceptance
```
