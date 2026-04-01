# Federated Graph Protocol

## Goal

Connect many sovereign Kin repo graphs into a usable network of graphs without requiring a giant monorepo or forcing teams to abandon Git coexistence, local work, or reversible adoption.

The protocol should support:

- cross-repo semantic relationships
- org-wide search, impact, review, and memory
- live multi-user and multi-agent coordination
- a connected mode where local projection is a cache of shared semantic state
- a later remote-first `sIDE` mode where the main interface is hosted

## Primary Thesis

The right shape is not one global graph database that swallows every repo.

The right shape is:

- one sovereign semantic graph per repo
- hosted discovery, trust, and coordination above those graphs
- selective subgraph exchange instead of full-repo flattening
- explicit cross-graph edges instead of implicit monorepo coupling

This keeps the primary Kin wedge intact:

- better local semantic truth
- survivable migration
- Git coexistence
- hosted coordination as an added layer, not a prerequisite

## Non-Goals

This protocol should not:

- turn `kin-db` into the internet-facing federation layer
- require perfect connectivity for all work
- default to blind CRDT merging of executable code
- erase repo sovereignty in favor of one central writable graph
- outrun the primary stack by jumping straight to remote-only development

## Current Starting Point

Today the stack already has the right beginnings:

- `kin-db` is a local graph engine with work, provenance, sessions, and intents
- `kin` already models native remotes, delta pull, mutation push, and connection lifecycle
- KinLab already acts as a hosted control-plane seam
- repo identity already exists through `.kin/manifest.json`

The missing pieces are:

- global addressing
- cross-graph edge types
- hosted session and intent authority
- subscription and invalidation channels
- imported subgraph materialization
- org-level overlay graph semantics

## Model

### 1. Sovereign Repo Graphs

Each Kin repo keeps its own local semantic truth, local change DAG, local projections, and local execution surfaces.

That graph remains authoritative for:

- entities
- local relations
- local work
- local provenance
- local proof objects
- local projection and reconcile

### 2. Hosted Org Overlay

KinLab owns an org-level overlay that composes many repo graphs together.

That overlay is authoritative for:

- graph discovery
- graph manifests and publish registry
- org-wide search and memory
- cross-graph edges
- hosted review and policy state
- session presence, intent leases, and coordination
- notifications and subscriptions

### 3. Imported Subgraphs

A local Kin repo can selectively materialize a foreign subgraph for:

- context packing
- downstream impact checks
- proof targeting
- local agent execution

Imported subgraphs are cached views, not promoted to local repo truth unless explicitly adopted.

## Object Model

The first protocol cut should add global refs above current local IDs rather than replacing local IDs.

### Local IDs That Stay

- `repo_id` in `.kin/manifest.json`
- `EntityId`
- `ContractId`
- `SemanticChangeId`
- `WorkId`
- `SessionId`
- `IntentId`

### New Federated Types

```rust
struct GraphLocator {
    authority: String,        // example: https://kinlab.example.com
    organization_id: String,
    repo_id: String,          // existing repo identity from .kin/manifest.json
}

enum ScopeRef {
    Entity { graph: GraphLocator, entity_id: EntityId },
    Contract { graph: GraphLocator, contract_id: ContractId },
    Artifact { graph: GraphLocator, path: FilePathId },
    Change { graph: GraphLocator, change_id: SemanticChangeId },
    Work { graph: GraphLocator, work_id: WorkId },
}

struct ActorRef {
    authority: String,
    actor_id: String,
}

struct GraphManifest {
    graph: GraphLocator,
    default_branch: String,
    head_change: Option<SemanticChangeId>,
    graph_root_hash: Option<Hash256>,
    published_at: Timestamp,
    protocol_version: String,
    capabilities: GraphCapabilitySet,
}

struct GraphCapabilitySet {
    can_publish_semantic_changes: bool,
    can_publish_review_state: bool,
    can_publish_proofs: bool,
    can_subscribe: bool,
    can_grant_intent_leases: bool,
    can_serve_subgraphs: bool,
}

struct RemoteRelation {
    relation_id: String,
    kind: RemoteRelationKind,
    src: ScopeRef,
    dst: ScopeRef,
    asserted_by: GraphLocator,
    confidence: f32,
    origin: RemoteRelationOrigin,
}
```

### Cross-Graph Edge Classes

The protocol should distinguish between:

- `local_relation`
  Both endpoints live in the same repo graph.
- `foreign_asserted_relation`
  A repo graph explicitly points at a foreign scope.
- `overlay_relation`
  KinLab inferred or administratively created the relation.
- `imported_relation`
  A cached relation arrived from a foreign graph through a subscription or subgraph fetch.

This matters because trust, edit rights, and ownership differ for each class.

## Addressing

The protocol should use the current repo identity as the stable graph identity and add a locator above it.

Recommended address shape:

```text
kin://<authority>/<organization_id>/<repo_id>/entities/<entity_id>
kin://<authority>/<organization_id>/<repo_id>/contracts/<contract_id>
kin://<authority>/<organization_id>/<repo_id>/changes/<semantic_change_id>
```

The local repo remains identifiable offline by `repo_id`.
The locator makes it routable on a network.

## Sync Model

The initial protocol should stay hybrid:

- HTTP for bootstrap, manifests, publish, delta fetch, subgraph fetch, search, and review/proof mutations
- WebSocket for presence, heartbeat, invalidations, intent events, and live review/activity notifications

This fits the current stack more naturally than inventing a new binary transport first.

### Session Lifecycle

1. `kin connect` authenticates with KinLab.
2. KinLab returns a `SessionLease`.
3. The client opens a long-lived event channel.
4. The client sends heartbeats and intent events.
5. KinLab fans out invalidations, traffic, policy notices, and hosted review events.

Recommended lease shape:

```rust
struct SessionLease {
    session_id: SessionId,
    actor: ActorRef,
    graph: GraphLocator,
    transport: SessionTransport,
    capabilities: SessionCapabilities,
    expires_at: Timestamp,
}
```

### Subscription Model

Clients should subscribe to scopes or subgraphs rather than entire repos by default.

```rust
struct SubscriptionSpec {
    roots: Vec<ScopeRef>,
    max_depth: u32,
    relation_kinds: Vec<String>,
    include_work: bool,
    include_proof: bool,
    include_provenance: bool,
}
```

Example uses:

- "watch my current work scopes"
- "watch downstream consumers of this contract"
- "watch all repos that depend on this service boundary"

### Invalidation Model

The event channel should push small signals, not full graph payloads.

Examples:

- `entity.invalidated`
- `relation.invalidated`
- `intent.acquired`
- `intent.released`
- `work.updated`
- `proof.updated`
- `review.updated`

The client then pulls exact deltas or subgraphs over HTTP.

### Delta Model

The first cut should extend current delta payloads with global refs and cursors.

```rust
struct DeltaCursor {
    graph: GraphLocator,
    sequence: u64,
    head_change: Option<SemanticChangeId>,
}

struct FederatedSemanticDelta {
    scope: ScopeRef,
    before_hash: Option<Hash256>,
    after_hash: Hash256,
    changed_fields: Vec<FieldDiff>,
    timestamp: Timestamp,
    actor: ActorRef,
    cursor: DeltaCursor,
}
```

### Mutation Push Model

Pushing should remain optimistic and head-aware:

- client declares base head
- KinLab checks leases, policy, and divergence
- accepted mutations advance the hosted head
- rejected mutations return conflict metadata and current remote cursor

This should stay semantic-change-centric, not file-diff-centric.

## Collaboration Model

### Lease First, Merge Second

For code truth, the protocol should prefer:

- presence
- declared intent
- lease arbitration
- semantic conflict detection
- explicit reconcile

It should not begin with unrestricted multi-writer CRDT semantics for executable code.

CRDT-style collaboration is still useful for:

- comments
- drafts
- notes
- live cursors
- ephemeral discussion state

But code truth needs stronger coordination because downstream blast radius matters.

### Traffic Semantics

KinLab should become the hosted authority for:

- session presence
- intent leases
- traffic queries
- downstream warning fanout

Local daemon traffic remains useful, but hosted connected mode should stop duplicating authority between MCP-local registries and hosted registries.

## Cross-Graph Search And Impact

Org-wide graph queries should work in two layers:

- local repo graph query in `kin`
- hosted overlay query in KinLab

A query like "who consumes this contract?" should return:

- local consumers from the current repo graph
- foreign consumers from KinLab overlay edges or imported subgraphs

This avoids forcing every local repo to fully ingest the whole org graph.

## Trust And Verification

Kin already has a Merkle-DAG-style integrity story.

The federation layer should build on that by publishing:

- graph manifests
- optional graph root hashes
- semantic change IDs
- signed publish receipts

The key idea is:

- `kin-db` proves local graph integrity
- `kin` publishes graph manifests and scoped deltas
- KinLab records and routes trustable graph state

## Boundary Split

### `kin-db`

Keep in `kin-db`:

- local graph storage
- local indexes
- local snapshots
- local integrity primitives

Do not move into `kin-db`:

- hosted session authority
- federation routing
- org-wide overlay graph policy
- internet-facing sync protocol

### `kin`

Own in `kin` and `kin-remote`:

- graph locator and scope-ref model
- manifest publish and fetch
- client connection lifecycle
- subscriptions and delta cursors
- imported subgraph materialization
- local cache of foreign graph state
- reconcile and projection against connected state

### KinLab

Own in KinLab:

- graph registry and discovery
- auth and actor identity
- session and intent authority
- cross-graph overlay edges
- org-wide search, memory, review, and policy
- notification fanout
- hosted connected-mode UX

## Incremental Rollout

### Phase A. Global Addressing

Add:

- `GraphLocator`
- `ScopeRef`
- published graph manifests

Acceptance:

- a repo can identify itself and a foreign scope without ambiguity

### Phase B. Hosted Session Authority

Add:

- KinLab-backed session leases
- KinLab-backed intent leases
- unified traffic queries

Acceptance:

- two connected users on two repos can see active nearby agent traffic and lock conflicts through KinLab

### Phase C. Subscription And Invalidation

Add:

- event channel
- scoped subscriptions
- delta cursors

Acceptance:

- one repo can stay connected and live-refresh semantic state from another without a manual pull loop

### Phase D. Imported Subgraphs

Add:

- selective subgraph fetch
- imported-scope cache
- foreign scope search and context packing

Acceptance:

- a repo can inspect downstream consumers in another repo without joining a monorepo

### Phase E. Org Overlay Graph

Add:

- authoritative overlay relations in KinLab
- org-wide impact and search
- hosted review that spans repo boundaries

Acceptance:

- KinLab can answer org-level semantic questions that `kin + GitHub` cannot answer alone

### Phase F. Connected Mode

Add:

- `kin connect`
- connected workspace projection
- live review/proof/work updates

Acceptance:

- developers can remain connected in real time while still having local projection and execution

### Phase G. Remote-First sIDE

Add:

- hosted semantic workspace
- remote execution attachment
- agent-first control surface

Acceptance:

- a user can direct agents and review semantic state from a hosted interface without requiring the full repo locally

## Why This Replaces Monorepo Pressure

Monorepos often exist because the tooling cannot express:

- cross-repo dependency truth
- shared review and impact analysis
- cross-team coordination
- shared agent context

If KinLab can provide those things with federated graph semantics, then teams can preserve separate repos without losing shared semantic visibility.

That is the real point of this protocol.
