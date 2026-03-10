# Kin System Architecture

This document visualizes the **target V1 architecture** defined in [PLAN.md](../../PLAN.md) and the **Phase 7 assistant-coordination overlay** defined in [PLAN_P2.md](../../PLAN_P2.md).

It is intentionally comprehensive. Use it as the shared technical reference for implementation, review, and onboarding. If this document and `PLAN.md` ever diverge on V1, `PLAN.md` wins. If this document and `PLAN_P2.md` ever diverge on assistant coordination, `PLAN_P2.md` wins.

## 1. Master System Diagram

```mermaid
flowchart TB
  Dev["Human Developer"]
  Assistant["Assistant Clients<br/>Claude Code / Codex / Gemini / Cursor"]
  FileOnly["Non-cooperative File Tools<br/>plain editors / copilots"]
  GitWorld["Git Repos / GitHub<br/>Optional legacy interop"]

  subgraph Interfaces["Interface Layer"]
    CLI["kin-cli"]
    MCP["kin-mcp"]
    UI["apps/kin-local-ui"]
    Guide["AGENTS.md + .kin/docs/<br/>generated guidance"]
  end

  subgraph Orchestration["Daemon / Orchestration Layer"]
    DaemonSvc["kin-daemon<br/>API server, file watch, graph lifecycle"]
    Traffic["Agent traffic control<br/>sessions, intents, heartbeats,<br/>lock arbitration, notifications"]
    AdapterCfg["Assistant bootstrap<br/>adapter config + wrappers"]
  end

  subgraph WorkLoop["Working Copy + Reconciliation Loop"]
    Index["kin-index<br/>incremental indexing"]
    Parser["kin-parser<br/>Tree-sitter + language adapters"]
    WorkingCopy["WorkingCopy + GraphOverlay<br/>uncommitted semantic state"]
    Reconcile["kin-reconcile<br/>file <-> overlay reconciliation"]
    Projection["kin-projection<br/>CST-preserving projection"]
    Workdir["Working directory<br/>projected runnable files"]
  end

  subgraph Intelligence["Semantic Services"]
    Context["kin-context<br/>token-budgeted context packs"]
    Contracts["kin-contracts<br/>cross-language contract linking"]
    Review["kin-review<br/>semantic review + risk"]
    Runtime["kin-runtime<br/>validation runs + evidence"]
    Bench["kin-bench<br/>velocity, reliability, ROI"]
    Migrate["kin-migrate<br/>repo onboarding + history backfill"]
    GitAdapter["kin-git<br/>optional import / export / sync"]
  end

  subgraph Core["Semantic Core"]
    Model["kin-model<br/>canonical types + GraphStore trait"]
    Graph["kin-graph<br/>KuzuGraphStore"]
    Blobs["kin-blobs<br/>SHA-256 content store"]
    CoreSvc["kin-core<br/>.kin layout, config, init, errors"]
  end

  subgraph State["Local State (.kin/)"]
    Kuzu["graph/<br/>KuzuDB: entities, relations, contracts,<br/>SemanticChanges, branches, specs, evidence,<br/>transient sessions + intents"]
    Objects["objects/<br/>content-addressable blobs"]
    Journal["overlay.journal"]
    Stashes["stashes/"]
    Projections["projections/"]
    Docs["docs/<br/>living docs + assistant guidance"]
    Runs["runs/"]
    BenchData["bench/"]
    Logs["logs/"]
    Adapters["adapters/"]
  end

  Dev --> CLI
  Dev --> UI
  Assistant --> MCP
  Assistant --> Guide
  Assistant --> Workdir
  FileOnly --> Workdir
  GitWorld <--> GitAdapter

  CLI --> DaemonSvc
  MCP --> DaemonSvc
  UI --> DaemonSvc
  CLI --> AdapterCfg
  DaemonSvc --> AdapterCfg
  DaemonSvc <--> Traffic
  MCP <--> Traffic
  UI <--> Traffic
  AdapterCfg --> Guide

  DaemonSvc --> Index
  DaemonSvc --> Reconcile
  DaemonSvc --> Context
  DaemonSvc --> Contracts
  DaemonSvc --> Review
  DaemonSvc --> Runtime
  DaemonSvc --> Bench
  DaemonSvc --> Migrate

  Index --> Parser
  Parser --> WorkingCopy
  Index --> WorkingCopy
  Traffic --> Reconcile
  Traffic --> Context
  Traffic --> Review
  Reconcile <--> WorkingCopy
  Reconcile <--> Projection
  Projection <--> Workdir
  Workdir --> Index

  Traffic <--> Graph
  Context --> Graph
  Context --> Blobs
  Contracts <--> Graph
  Review --> Graph
  Runtime --> Graph
  Runtime --> Blobs
  Bench --> Graph
  Bench --> Blobs
  Migrate --> GitAdapter
  Migrate --> Graph
  Migrate --> Blobs

  Model -.-> Graph
  Model -.-> WorkingCopy
  Model -.-> Context
  Model -.-> Review

  Graph <--> Kuzu
  Blobs <--> Objects

  CoreSvc --> Kuzu
  CoreSvc --> Objects
  CoreSvc --> Journal
  CoreSvc --> Stashes
  CoreSvc --> Projections
  CoreSvc --> Docs
  CoreSvc --> Runs
  CoreSvc --> BenchData
  CoreSvc --> Logs
  CoreSvc --> Adapters
```

**Reading this diagram**

- Kin is **sovereign**: the semantic graph and `SemanticChange` DAG are primary, not Git.
- Git is present only through `kin-git`, which is a **legacy adapter**.
- The daemon owns runtime orchestration; the working copy loop keeps projected files and semantic state aligned.
- Cooperative assistants use CLI and MCP to register sessions, heartbeats, and intents before mutation.
- Non-cooperative file tools still work through the projected filesystem, but they bypass proactive intent coordination.
- The graph stores topology, history, and transient traffic state; the blob store stores content payloads.

## 2. Four Planes

```mermaid
flowchart TB
  subgraph Semantic["Semantic Plane"]
    SemA["Entities"]
    SemB["Relations"]
    SemC["Contracts"]
    SemD["SemanticChanges"]
    SemE["Branches + WorkingCopy"]
    SemF["kin-model + kin-graph"]
  end

  subgraph ProjectionPlane["Projection Plane"]
    ProjA["Working directory source files"]
    ProjB["Living docs in .kin/docs/"]
    ProjC["Review views"]
    ProjD["Optional Git export"]
    ProjE["kin-projection + kin-git"]
  end

  subgraph Execution["Execution Plane"]
    ExecA["Local workspaces"]
    ExecB["Validation runs"]
    ExecC["Evidence capture"]
    ExecD["kin-daemon + kin-runtime"]
  end

  subgraph Control["Control Plane"]
    CtrlA["Context packs"]
    CtrlB["Semantic review"]
    CtrlC["Benchmarks"]
    CtrlD["Assistant adapters + MCP"]
    CtrlE["Traffic control + intent registry"]
    CtrlF["kin-context + kin-review + kin-bench + kin-mcp + kin-daemon"]
  end

  Semantic <--> ProjectionPlane
  ProjectionPlane <--> Execution
  Execution <--> Control
  Control --> Semantic
```

**Plane responsibilities**

- The **semantic plane** is the source of truth.
- The **projection plane** renders runnable artifacts from semantic state.
- The **execution plane** proves correctness through real runs and evidence.
- The **control plane** manages retrieval, review, benchmarking, assistant access, and multi-agent coordination.

## 3. Working Copy and Commit Lifecycle

```mermaid
sequenceDiagram
  actor User as Human or Assistant
  participant WD as Working Directory
  participant D as kin-daemon
  participant P as kin-parser
  participant I as kin-index
  participant O as WorkingCopy + GraphOverlay
  participant B as kin-blobs
  participant R as kin-reconcile
  participant J as kin-projection
  participant G as kin-graph / KuzuDB

  User->>WD: Edit file
  WD->>D: File change notification
  D->>P: Parse changed file
  P-->>D: Entities + relations or ParseState::Incomplete

  alt Valid parse
    D->>I: Compute fingerprints
    I->>B: Write code text by SHA-256
    I->>O: Update overlay only
    D->>R: Reconcile working copy and files
    R->>J: Project affected entities
    J->>WD: Byte-range splice changed EntityRef regions
  else Broken AST
    D->>O: Preserve Last Known Good state
    D-->>WD: Skip canonical fingerprint update
  end

  User->>D: kin status / kin context / kin impact
  D->>O: Read merged overlay view

  User->>D: kin commit
  D->>G: Create SemanticChange
  D->>G: Advance Branch.head
  D->>O: Clear committed overlay deltas
```

**Lifecycle rules**

- File edits update the **overlay**, not committed history.
- `kin commit` collapses overlay state into a new `SemanticChange`.
- Broken parses never overwrite canonical fingerprints or sever lineage.
- Projection is surgical: mutate entity byte ranges, preserve surrounding trivia.

## 4. Cooperative Agent Messaging Lifecycle

```mermaid
sequenceDiagram
  actor A as Assistant A
  actor B as Assistant B
  participant Guide as "AGENTS.md + .kin/docs/"
  participant Surface as "kin-cli / kin-mcp"
  participant D as kin-daemon
  participant G as "kin-graph / KuzuDB"
  participant C as kin-context
  participant R as kin-reconcile
  participant WD as Working Directory

  A->>Guide: Read Kin workflow guidance
  A->>Surface: kin_session_start(...)
  Surface->>D: Register AgentSession
  D->>G: Store transient session state

  loop Every 30 seconds
    A->>Surface: kin_session_heartbeat(session_id)
    Surface->>D: Heartbeat
    D->>G: Update last_heartbeat
  end

  A->>Surface: kin_register_intent(scopes, hard, task)
  Surface->>D: Validate + register intent
  D->>G: Check collisions and expand downstream warnings

  alt No hard collision
    D-->>A: intent_id + TrafficReport
    opt Nearby cooperative session exists
      D-->>B: CoordinationEvent(scope, lock, task, owner)
    end
    A->>Surface: kin_context(entity_id, include_traffic=true)
    Surface->>C: Build traffic-aware context pack
    C->>G: Read semantic neighborhood + active intents
    C-->>A: ContextPack + traffic metadata
    A->>WD: Edit file
    WD->>D: File change notification
    D->>R: Reconcile mutation
    R->>G: Enforce hard locks / attach soft warnings
    alt Allowed mutation
      R-->>D: Apply change with optional warnings
      D-->>A: Mutation result + traffic warnings
    else Blocked by another hard lock
      R-->>D: IntentConflict::HardCollision
      D-->>A: Blocking session + task metadata
    end
  else Hard collision on registration
    D-->>A: IntentConflict::HardCollision
  end

  B->>Surface: kin_check_traffic(scopes)
  Surface->>D: Query traffic
  D->>G: Read active intents and downstream warnings
  D-->>B: TrafficReport

  opt Session crashes or exits
    D->>G: Sweep expired session and owned intents
    D-->>B: CoordinationEvent(session expired, traffic cleared)
  end
```

**Messaging rules**

- Cooperative clients establish an `AgentSession` first, then register intent before mutation.
- Heartbeats and reaping keep traffic state current without making it part of version history.
- Context, impact, review, and reconcile all become traffic-aware when the client cooperates through CLI or MCP.
- File-only tools remain compatible, but Kin can only detect their edits after the filesystem change lands.

## 5. Canonical Data Model

```mermaid
classDiagram
  class SemanticFingerprint {
    +ast_hash
    +signature_hash
    +behavior_hash
    +stability_score
  }

  class Entity {
    +id
    +kind
    +name
    +language
    +fingerprint
    +file_origin
    +span
    +signature
    +lineage_parent
    +created_in
    +superseded_by
  }

  class Relation {
    +id
    +kind
    +src
    +dst
    +confidence
    +origin
    +created_in
  }

  class Contract {
    +kind
    +schema_hash
    +producer_links
    +consumer_links
  }

  class SemanticChange {
    +id
    +parents
    +timestamp
    +author
    +message
    +entity_deltas
    +relation_deltas
    +artifact_deltas
    +projected_files
    +spec_link
    +evidence
    +risk_summary
    +authored_on
  }

  class Branch {
    +name
    +head
  }

  class WorkingCopy {
    +base_change
    +uncommitted_mutations
  }

  class GraphOverlay {
    +entity_deltas
    +relation_deltas
    +artifact_deltas
  }

  class Spec {
    +intent
    +scope
    +constraints
    +acceptance_criteria
  }

  class Evidence {
    +assistant_identity
    +context_provenance
    +tool_calls
    +validation_results
    +workspace_snapshot_ids
  }

  class ConflictObject {
    +conflict_kind
    +divergence_reason
    +affected_entities
    +affected_files
    +suggested_resolutions
  }

  class AgentSession {
    +session_id
    +vendor
    +client_name
    +transport
    +pid
    +cwd
    +started_at
    +last_heartbeat
    +capabilities
  }

  class Intent {
    +intent_id
    +session_id
    +scopes
    +lock_type
    +task_description
    +registered_at
    +expires_at
  }

  class IntentScope {
    <<enum>>
    Entity
    Contract
    Artifact
  }

  class LockType {
    <<enum>>
    Soft
    Hard
  }

  class TrafficReport {
    +target
    +active_intents
    +downstream_warnings
  }

  class CoordinationEvent {
    +event_id
    +event_kind
    +scope
    +message
    +emitted_at
  }

  class FileLayout {
    +file_id
    +imports
    +regions
  }

  class SourceRegion {
    +EntityRef
    +Trivia
  }

  class GraphStore {
    <<trait>>
    +get_entity()
    +get_relations()
    +get_downstream_impact()
    +get_dependency_neighborhood()
    +find_dead_code()
    +get_entity_history()
    +find_merge_bases()
    +query_entities()
  }

  Entity --> SemanticFingerprint : uses
  Relation --> Entity : connects
  Contract --> Entity : producer / consumer links
  SemanticChange --> Entity : entity deltas
  SemanticChange --> Relation : relation deltas
  SemanticChange --> Spec : spec_link
  SemanticChange --> Evidence : evidence
  Branch --> SemanticChange : head
  WorkingCopy --> SemanticChange : base_change
  WorkingCopy --> GraphOverlay : overlay
  ConflictObject --> SemanticChange : merge / reconcile output
  ConflictObject --> Intent : traffic conflict context
  AgentSession --> Intent : owns
  Intent --> IntentScope : locks
  Intent --> LockType : uses
  Intent --> Entity : locks / warns downstream
  Intent --> Contract : locks / warns downstream
  TrafficReport --> Intent : active / nearby
  CoordinationEvent --> AgentSession : emitted to
  CoordinationEvent --> Intent : describes
  FileLayout --> SourceRegion : contains
  GraphStore --> Entity : query surface
  GraphStore --> SemanticChange : history and DAG queries
  GraphStore --> AgentSession : traffic queries
  GraphStore --> Intent : lock queries
```

**Data model notes**

- `SemanticChange` is Kin's native commit object and the unit of history.
- `Branch.head` points to a `SemanticChange`; branches are refs, not embedded commit metadata.
- `WorkingCopy` is the branch head plus an uncommitted `GraphOverlay`.
- `AgentSession`, `Intent`, `TrafficReport`, and `CoordinationEvent` are transient coordination state from Phase 7.
- Intent traffic lives in KuzuDB for queryability, but it is not part of `SemanticChange`, Git export, or permanent repo history.
- `GraphStore` isolates KuzuDB behind typed Rust methods. No raw Cypher outside `kin-graph`.

## 6. Local State Layout

```mermaid
flowchart TB
  Root[".kin/"]
  Config["config.toml<br/>repo-local config"]
  Manifest["manifest.json<br/>repo identity, languages, adapters, Kin version"]
  GraphDir["graph/<br/>KuzuDB database files"]
  Objects["objects/<br/>SHA-256 blobs"]
  Journal["overlay.journal<br/>overlay crash recovery"]
  Stashes["stashes/<br/>overlay snapshots"]
  Projections["projections/<br/>generated projections"]
  Docs["docs/<br/>living docs + assistant guidance"]
  Bench["bench/<br/>benchmark traces and reports"]
  Runs["runs/<br/>validation evidence"]
  Logs["logs/<br/>daemon logs"]
  Adapters["adapters/<br/>assistant adapter config"]

  Root --> Config
  Root --> Manifest
  Root --> GraphDir
  Root --> Objects
  Root --> Journal
  Root --> Stashes
  Root --> Projections
  Root --> Docs
  Root --> Bench
  Root --> Runs
  Root --> Logs
  Root --> Adapters
```

**Storage rules**

- KuzuDB stores graph topology, signatures, fingerprints, history, and metadata.
- KuzuDB also stores transient agent sessions, intents, downstream warnings, and coordination events for local queryability.
- The blob store stores code text, projection outputs, evidence artifacts, and benchmark payloads.
- `.kin/docs/` may include generated assistant guidance and living docs emitted by `kin assistant install`.
- Deleting `.kin/` removes Kin state while leaving ordinary project files intact.

## 7. Crate Map by Architectural Responsibility

```mermaid
flowchart LR
  subgraph Foundation["Phase 1: Foundation"]
    Model["kin-model"]
    Graph["kin-graph"]
    Blobs["kin-blobs"]
    Core["kin-core"]
  end

  subgraph Parse["Phase 2: Parsing + Indexing"]
    Parser["kin-parser"]
    Index["kin-index"]
  end

  subgraph Sync["Phase 3: Projection + Reconciliation + Git"]
    Projection["kin-projection"]
    Reconcile["kin-reconcile"]
    Git["kin-git"]
  end

  subgraph Intelligence["Phase 4: Context + Contracts + Review"]
    Context["kin-context"]
    Contracts["kin-contracts"]
    Review["kin-review"]
  end

  subgraph Surface["Phase 5: CLI + Daemon + MCP"]
    CLI["kin-cli"]
    Daemon["kin-daemon"]
    MCP["kin-mcp"]
  end

  subgraph Value["Phase 6: Bench + Migrate + Runtime + UI"]
    Bench["kin-bench"]
    Migrate["kin-migrate"]
    Runtime["kin-runtime"]
    UI["apps/kin-local-ui"]
  end

  Model --> Graph
  Model --> Parser
  Model --> Projection
  Model --> Context
  Model --> Review
  Model --> Runtime

  Core --> Index
  Graph --> Index
  Blobs --> Index

  Parser --> Index
  Index --> Reconcile
  Projection --> Reconcile
  Graph --> Context
  Graph --> Contracts
  Graph --> Review
  Graph --> Bench
  Blobs --> Context
  Blobs --> Runtime
  Git --> Migrate

  Reconcile --> Daemon
  Context --> MCP
  Review --> CLI
  Bench --> CLI
  Runtime --> Daemon
  Daemon --> CLI
  Daemon --> MCP
  Daemon --> UI
```

**Implementation reading**

- Phase order follows hard dependencies from the plan.
- `kin-model` is the foundation under nearly everything else.
- `kin-daemon` is the runtime hub for indexing, reconciliation, and API access.
- Phase 7 extends the existing crates rather than adding a parallel assistant subsystem.
- `apps/kin-local-ui` is an app surface on top of daemon APIs, not a separate source of truth.

## 8. Architecture Summary

- **Source of truth:** semantic graph plus `SemanticChange` DAG in KuzuDB
- **Content storage:** SHA-256 blob store on local disk
- **Uncommitted state:** `WorkingCopy` and `GraphOverlay`
- **Transient coordination state:** `AgentSession`, `Intent`, `TrafficReport`, and `CoordinationEvent`
- **Projection model:** CST-preserving byte-range splicing
- **Interop model:** Git is optional and isolated in `kin-git`
- **Assistant integration:** assistant-neutral MCP, CLI bootstrap, generated guidance, and local daemon APIs
- **Primary guarantee:** Kin remains local-first, sovereign, reversible, and runnable
