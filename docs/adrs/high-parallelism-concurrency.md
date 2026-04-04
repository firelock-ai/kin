# ADR: High-Parallelism Concurrency Model

**Status:** Proposed
**Date:** 2026-04-03
**Authors:** Codex

## Context

Kin's current local concurrency model is safe but coarser than the target
operator experience for AI-native work.

Today:

- `kin-db::InMemoryGraph` shards data by domain and protects each domain with a
  `RwLock`.
- entity and relation writes still serialize through the whole `entities` shard
  rather than the specific entity or scope being edited.
- `SnapshotManager` uses repo-level file locking for local multi-process
  coordination.
- the session/intent model can express per-entity, per-contract, and per-file
  work claims, but those claims are not yet the universal write gate for all
  local mutation paths.
- some read-only flows still open writable local snapshots instead of using a
  daemon-first read path or a read-only snapshot path.

This is acceptable for early correctness, but it leaves concurrency on the
table in the exact places where Kin should be strongest:

- many agents reading simultaneously
- many agents working in parallel on disjoint scopes
- short commit windows instead of long-held storage locks
- clear conflict semantics when scopes overlap

The target is not "one giant mutable graph with finer mutexes." The target is:

1. snapshot-based reads that never block on normal writes
2. semantic leases that declare who is working on what
3. optimistic atomic commits that validate a write set at commit time
4. background persistence and projection work that does not widen the critical
   section

## Decision

Kin should converge on a **lease + MVCC + optimistic commit** model with a
single authoritative writer/coordinator per repo.

### Runtime authority

The repo daemon is the default local authority for:

- session lifecycle
- lease registration and expiry
- write admission
- transaction validation
- commit ordering

Hosted Kinlab authority can supersede the local daemon for multi-user or
multi-repo deployments, but the semantics must stay the same.

Direct local snapshot mutation remains a degraded fallback mode, not the normal
concurrency path.

### Reads

Reads operate on immutable committed snapshots identified by a repo epoch.

- a read acquires a snapshot handle, not a hot mutable lock
- snapshot reads never block one another
- normal writes do not block reads
- readers may observe a slightly older committed epoch, but never a partial
  commit

This is the default for CLI, daemon, MCP, and any future editor/runtime
surface.

### Leases

The existing session/intent concepts become authoritative **leases**.

Lease scopes remain semantic:

- entity
- artifact
- contract
- change
- work item

Lease types remain:

- soft: advisory, visible traffic, no hard exclusion
- hard: exclusive for mutation of the covered scope set

Leases are long-lived coordination claims with heartbeats and expiry. They are
not storage mutexes.

### Transactions

Every mutation executes as a transaction with:

- `session_id`
- `base_epoch`
- `read_set`
- `write_set`
- `base_versions` for all members of the write set
- mutation payload

The coordinator validates a commit by checking:

1. the caller holds the required hard lease for the write set
2. no conflicting hard lease exists for the same canonical scope set
3. every write-set member still has the expected version
4. any policy-required read-set validations still hold

If validation succeeds, the commit is applied atomically and the repo epoch is
advanced. If validation fails, the client receives a structured conflict and can
re-read, merge, or retry.

### Storage model

The in-memory graph should move from coarse domain locks to partitioned MVCC
storage:

- entity records partitioned by stable hash of `EntityId`
- relation records partitioned separately
- adjacency/index structures versioned or partitioned so commits touch only the
  affected partitions
- immutable committed views published by epoch
- tiny commit-time synchronization only around the touched partitions and epoch
  publication

The goal is not per-map concurrency. The goal is atomic multi-record commits
without broad reader blocking.

### Persistence model

Commit latency should not depend on full snapshot serialization.

The hot path becomes:

1. validate transaction
2. append durable mutation record or WAL entry
3. publish new committed epoch in memory
4. acknowledge success
5. compact to snapshots, indexes, and projections asynchronously

Periodic compaction and snapshotting remain necessary, but they are not on the
critical path for every semantic mutation.

### Derived state

Projection outputs, text indexes, vector indexes, and other denormalized
surfaces are derived state.

They must:

- be tagged with the committed epoch they represent
- be safe to refresh asynchronously
- never force unrelated semantic writes to wait for expensive rebuilds

Correctness-critical metadata may be updated transactionally if it is required
for conflict detection or routing, but heavyweight rebuild work should happen
off the write path.

## Invariants

The target system must preserve these invariants.

### Read invariants

1. A read sees one committed epoch only.
2. Reads never observe partial writes.
3. Reads never block each other.
4. Normal writes do not block reads.

### Lease invariants

1. A hard lease is required before mutating a scope.
2. Hard leases on overlapping canonical scope sets are mutually exclusive.
3. Soft leases never block, but always surface traffic.
4. Lease ownership is tied to a live session and expires without heartbeat.

### Commit invariants

1. A commit either publishes all graph changes for the transaction or none.
2. A commit succeeds only if the write set still matches its base versions.
3. Two disjoint write sets may commit concurrently.
4. Overlapping write sets must serialize or conflict deterministically.

### Recovery invariants

1. After a crash, the repo replays to the last durable committed epoch.
2. Uncommitted mutations are never partially visible as committed truth.
3. Lease recovery is session-based and time-bounded, not permanent.

## Canonical Scope Rules

The system must not pretend every mutation is "one entity."

Canonical write scopes are derived from the operation:

- entity update: the entity plus any adjacency/index rows it mutates
- relation update: the relation plus both endpoint adjacency scopes
- file reconcile: the file artifact plus the entity set added, removed, or
  rewritten by the reconcile
- contract update: the contract plus any contract reference edges or affected
  declaration entities
- projection write: the projection target plus the semantic source entities that
  authorize it

The coordinator may internally widen a requested lease into a canonical scope
set before admission.

## Transaction Semantics

### Read-only transactions

Read-only transactions pin an epoch and perform all traversal/query work against
that epoch. They never acquire hard leases.

### Write transactions

Write transactions follow this sequence:

1. start from a committed base epoch
2. declare or derive the write set
3. ensure the session holds the necessary hard lease
4. perform local planning or reconciliation work against the pinned snapshot
5. submit the commit with base versions
6. either publish atomically or fail with structured conflicts

### Conflict categories

Conflicts should be explicit:

- lease conflict: another session holds a hard lease on overlapping scope
- version conflict: a touched scope changed since the caller's base epoch
- projection conflict: a derived output no longer matches its source epoch
- policy conflict: a higher-level rule rejected the mutation

These categories should be returned to clients in machine-readable form.

## API Shape

The authoritative runtime should expose a transaction-oriented API surface:

- `session.start`
- `session.heartbeat`
- `lease.acquire`
- `lease.release`
- `traffic.check`
- `txn.prepare`
- `txn.commit`
- `txn.abort`
- `graph.read_at`
- `graph.current_epoch`

Existing intent and traffic APIs can evolve into these semantics without
changing the core mental model.

## Implementation Guidance

### What to avoid

- long-lived storage mutexes held for the duration of an editing session
- direct graph mutations that bypass lease validation
- broad repo-level writable opens for read-only commands
- synchronous full-snapshot persistence on every semantic write
- in-process side registries that can diverge from the authoritative lease view

### What to prefer

- daemon-first authority
- immutable snapshot reads
- optimistic retries over pessimistic global blocking
- explicit write-set modeling
- background projection and compaction pipelines

## Migration Plan

### Phase 0: Make authority explicit

- make the daemon the default owner of local writes
- make CLI and MCP delegate session and lease operations to the daemon whenever
  available
- mark direct local mutation paths as fallback-only

### Phase 1: Fix read-path lock posture

- audit all read-only CLI and MCP flows
- route pure reads through daemon reads or read-only snapshot opens
- eliminate writable snapshot opens from read-only commands

### Phase 2: Enforce leases on all write paths

- wire the existing traffic-check hooks into daemon reconcile and CLI write
  paths
- require a session and hard lease for every semantic mutation
- remove direct graph intent insertion as a normal path

### Phase 3: Add versions and optimistic commit validation

- add per-scope or per-partition versions
- require write-set base versions on commit
- return structured lease/version conflicts

### Phase 4: Introduce transaction log durability

- append durable mutation records before publishing an epoch
- replay the log on restart
- decouple commit latency from full snapshot save latency

### Phase 5: Replace coarse entity locking with partitioned MVCC

- split entity and relation storage into partitions
- publish immutable committed views by epoch
- keep commit-time synchronization scoped to touched partitions

### Phase 6: Move projections and indexes fully off the critical path

- tag all derived artifacts with source epoch
- refresh asynchronously
- add repair and catch-up jobs for stale derived state

## Consequences

### Benefits

- many overlapping readers with no meaningful contention
- significantly more safe parallel agent work on disjoint scopes
- shorter write critical sections
- deterministic conflict handling instead of accidental broad blocking
- a cleaner path from local daemon authority to hosted authority

### Costs

- more metadata: epochs, versions, write sets, lease heartbeats
- more complex commit protocol
- more recovery logic due to WAL or mutation-log durability
- storage refactor complexity inside `kin-db`

## Work Allocation

This design splits cleanly across repo boundaries.

### `kin`

Owns:

- daemon write authority
- session and lease lifecycle
- transaction API
- reconcile admission and conflict handling
- CLI/MCP delegation and fallback policy

### `kin-db`

Owns:

- partitioned MVCC storage substrate
- epoch publication
- version tracking
- WAL/mutation-log durability
- compaction and snapshotting

### `kin/packages/boundary-contracts`

Owns:

- transaction, lease, epoch, and conflict payload schemas
- cross-process request and response contracts

## Non-goals

- turning every semantic operation into a distributed transaction across many
  repos in the first phase
- requiring hard leases for read-only operations
- pretending relation/file/contract mutations can always be reduced to one
  entity ID

## Success Criteria

The design is successful when the system demonstrates all of the following:

1. pure reads never require writable snapshot ownership
2. two agents can safely mutate disjoint scope sets in parallel
3. overlapping writes fail deterministically with structured conflicts
4. session leases, not hidden storage locks, explain who is working on what
5. commit latency remains bounded without full-snapshot save on each mutation
