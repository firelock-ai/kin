# ADR: Ref-Scoped Temporal Graph Reads

**Status:** Proposed
**Date:** 2026-04-06
**Authors:** Codex

## Context

Kin's thesis is that the semantic graph is the system of record and familiar
surfaces such as files, diffs, branches, and reviews are projections of that
truth.

Today, Kin already has part of that model:

- one semantic change DAG per repo
- branch heads as named pointers into that DAG
- semantic entity identity that survives many refactors
- artifact replay that can reconstruct the file tree at a branch head

However, the runtime does not yet treat **point-in-time semantic state** as a
first-class read model.

Today:

- the live entity store is effectively "current graph state"
- entity history is recovered by scanning `SemanticChange` deltas
- commits mutate the current entity map in place and record the old/new pair in
  the change object
- file state can be replayed from changes, but entity state is not exposed as
  "`entity at ref`" or "`graph at ref`"

This gap matters in two places.

### Product/runtime gap

Kin should be able to answer:

- what did this entity look like at change `X`
- what entities exist on branch `feature/foo`
- what is the semantic graph at the current branch head

without requiring duplicated repo materialization or branch-specific graph
copies.

### Benchmark/runtime gap

`kin-bench` currently proves retrieval on materialized repo states. That is
useful evidence, but it still carries harness-only behavior:

- task-specific worktree materialization
- prepared-state reuse
- temporary runtime flags such as `KIN_NO_VFS=1`

Benchmarks must not evolve into a separate behavioral fork of Kin. The harness
may compensate for current runtime limitations, but the command surface and the
semantic answers must converge with normal product usage.

## Decision

Kin should converge on a **single semantic graph per repo with first-class
ref-scoped temporal reads**.

The semantic graph remains the system of record. Branches and commits remain
named or content-addressed refs into the semantic change DAG. Reads become:

- `graph at ref`
- `entity at ref`
- `relation at ref`
- `artifact tree at ref`

If no ref is specified, the default is the current branch head in the local
repo authority.

## Core Model

### Stable identity vs temporal revision

Kin should separate stable semantic identity from immutable temporal shape.

#### Entity anchor

An `EntityAnchor` is the stable semantic identity across time.

It answers:

- what logical entity is this
- what is the durable semantic identity that renames and moves attach to

For migration compatibility, the current `EntityId` should become the anchor
identity rather than introducing a second top-level stable ID for the same
purpose.

#### Entity revision

An `EntityRevision` is an immutable entity shape introduced by one semantic
change.

It contains the temporal entity payload for that revision:

- name
- kind
- language
- fingerprint
- file origin
- span
- signature
- visibility
- role
- doc summary
- metadata
- lineage parent anchor where applicable
- `introduced_by` change
- optional `supersedes` revision

An unchanged entity across many refs does not need duplicate revisions. One
revision remains valid for every reachable ref until another reachable revision
for that anchor supersedes it.

#### Relation and artifact revisions

The same principle applies to relations and non-entity artifacts.

Kin should not make entity reads temporal while leaving relation/artifact state
as mutable global state. A ref-scoped read must resolve a consistent committed
view across:

- entities
- relations
- file/artifact tree
- projection metadata required for correctness

## Ref Semantics

### Refs remain DAG-based

Kin should not store "valid branches" or "valid commits" as explicit lists on
each entity revision.

That model is wrong for mergeable history because validity is not a flat list
membership problem. It is a **reachability problem in the semantic change DAG**.

Branch membership and commit visibility are derived from:

1. the target ref's resolved head change
2. the set of ancestor changes reachable from that head
3. the latest reachable revision for each anchor that is not superseded by a
   later reachable revision for the same anchor

### Default read behavior

If a command does not specify a ref:

- local CLI defaults to the current branch head
- daemon-backed reads default to the repo authority's current branch head unless
  the API call specifies another ref
- MCP and editor surfaces should expose an optional ref parameter but default to
  the current branch head as well

## Runtime Read APIs

Kin should add first-class read APIs around ref resolution.

### Required APIs

- `resolve_ref(input) -> SemanticChangeId`
- `resolve_entity_at(anchor_id, ref) -> Option<EntityRevision>`
- `resolve_relations_at(anchor_id, ref, kinds) -> Vec<RelationRevision>`
- `resolve_file_tree_at(ref) -> FileTreeView`
- `resolve_graph_at(ref) -> GraphView`

`GraphView` is a committed immutable read view. It is not a mutable clone of the
repo graph and it is not a separate repo copy on disk.

### Fast path

Kin should keep a cached committed view for the current branch head or current
repo epoch so that the common case stays fast.

Historical and non-head refs may be resolved by replay and cached on demand.

The target is:

- one hot current committed view
- cheap ref resolution for common reads
- cached replayed views for repeated historical access

not one fully materialized graph per branch or per commit.

## Write Model

The write model should converge on immutable revision introduction rather than
mutable overwrite as the semantic ground truth.

### Commit semantics

A commit introduces new revisions for the anchors it changes.

Net effect:

- unchanged anchors point to the same current revision as before
- changed anchors get a new revision introduced by this semantic change
- removed anchors become absent from the resolved view at descendants unless
  reintroduced later

### Current-head cache

Kin may still maintain a current-head cache or materialized current view for
performance, but that cache is derived state.

The source of truth becomes:

- anchors
- immutable revisions
- change DAG reachability

not "whatever is currently in the mutable entity hashmap."

## Benchmark Alignment Rule

`kin-bench` must prove Kin's real product behavior, not a benchmark-only fork.

### Required alignment

Benchmarks should use:

- public commands, not benchmark-only hidden commands, whenever a public command
  exists
- the normal repo-daemon authority model for local runtime behavior
- the same retrieval and ranking code paths that users hit in normal CLI usage

### Temporary exceptions

Temporary harness-only behavior is acceptable only when it compensates for a
known product limitation and is clearly documented as temporary.

Examples:

- `KIN_NO_VFS=1` while benchmark worktrees still hit a known VFS deadlock path
- prepared-state reuse while ref-scoped graph reads do not yet exist
- materialized per-task refs while `resolve_graph_at(ref)` is not yet available

These exceptions must not become permanent product truth.

### End-state benchmark model

Once ref-scoped temporal reads exist, the benchmark path should converge toward:

1. import or materialize semantic history once per repo
2. resolve the task's `base_commit` as a semantic ref
3. execute public `kin` commands against that ref-scoped view
4. score the resulting public command output

The benchmark should not need:

- one `.kin` state per task
- one daemon per worktree
- duplicated branch-specific graph copies

## Invariants

### Temporal read invariants

1. A read at ref `R` sees one committed semantic view only.
2. A read at ref `R` never observes revisions introduced only on unrelated
   branches not reachable from `R`.
3. If two refs reach the same latest revision for an anchor, they resolve to
   the same entity shape.
4. If no revision for an anchor is reachable from `R`, the anchor is absent at
   `R`.

### Branch/ref invariants

1. Branches remain named pointers to semantic changes.
2. Commit/change IDs remain content-addressed semantic refs.
3. Ref visibility is derived from DAG reachability, not explicit branch lists on
   revisions.

### Benchmark invariants

1. Benchmarks use public Kin command surfaces where those surfaces exist.
2. Benchmark-specific environment flags are temporary exceptions, not the
   intended permanent runtime shape.
3. Benchmark answers must match the semantic answers a product user would get
   for the same ref and query.

## Consequences

### Positive

- one semantic repo graph can answer many ref-scoped questions
- unchanged entities are naturally shared across refs
- branch switching and historical inspection become semantic view selection,
  not graph duplication
- benchmarks can converge on true product behavior instead of worktree-heavy
  approximations
- the design matches Kin's "graph-first, projection-second" thesis

### Costs

- new storage and API concepts for revisions and ref resolution
- migration work in `kin-db`, `kin`, daemon APIs, CLI, and MCP
- replay/caching strategy required for good historical-read performance
- benchmark harness simplification depends on the runtime work landing first

## Alternatives Considered

### Store branch/commit validity lists on each entity

Rejected.

This is awkward in a merge DAG, duplicates information derivable from reachability,
and encourages branch-centric modeling instead of change-centric modeling.

### Keep one mutable current graph plus ad hoc history scanning

Rejected as the end state.

This is good enough for early correctness, but it does not provide first-class
`graph at ref` semantics and it keeps pushing historical use cases into
worktree/materialization hacks.

### Materialize one graph or daemon per branch/worktree

Rejected as product architecture.

This may remain a transitional benchmark harness tactic, but it is the wrong
steady-state model for Kin's semantic substrate.

## Migration Plan

### Phase 1: Read semantics first

Add ref-scoped read APIs backed by the existing change DAG and replay logic.

This phase can be implemented without immediately changing every write path to
immutable revisions.

### Phase 2: Public surface adoption

Add optional ref parameters to daemon, CLI, and MCP read surfaces where they
matter:

- locate
- search
- trace
- history
- review/diff helpers

Default behavior remains current branch head when omitted.

### Phase 3: Revision-native storage

Split stable anchors from immutable revisions and make current-head state a
derived cache rather than the only semantic representation.

### Phase 4: Benchmark convergence

Update `kin-bench` to evaluate public commands against ref-scoped graph views
instead of per-task worktree-specific graph copies wherever possible.

### Phase 5: Cleanup

Remove obsolete benchmark-only wrappers and reduce temporary runtime flags as
the product path catches up.

## Non-Goals

This ADR does not propose:

- replacing Git immediately
- removing compat mode immediately
- introducing a single global daemon for all local repos
- making OS/kernel/hardware work the current product wedge

The goal is narrower and more central to Kin's primary stack:

- one semantic graph per repo
- point-in-time semantic reads by ref
- product and benchmark behavior converging on the same semantic runtime model
