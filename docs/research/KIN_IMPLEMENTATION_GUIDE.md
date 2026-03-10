# Kin Implementation Guide

**Date:** March 10, 2026  
**Status:** Decision-complete architecture guide  
**Audience:** Engineers and coding agents implementing Kin

## 1. Purpose

This document is the implementation guide for **Kin**.

It converts the existing research, strategy, and product planning into concrete technical decisions. It is intentionally opinionated. An implementer should not need to re-decide the major architectural questions.

Kin is designed as:

- a local-first semantic code platform
- an assistant-neutral context and workflow layer
- a Git-compatible system whose internal source of truth is semantic, not file-based

The key principle is:

**Git stores text history. Kin understands and reconciles code relationships.**

## 2. Product Definition

Kin is not a coding assistant. Kin is the shared semantic operating layer that external assistants use.

The platform has two parts:

1. **Open Semantic Core**
   - local semantic index
   - semantic VCS engine
   - CLI
   - daemon
   - local UI
   - MCP server
   - Git bridge
   - local benchmarking and migration tools

2. **Hosted Kin Platform**
   - org-wide graph
   - managed workspaces and runners
   - semantic review inbox
   - spec/task management
   - governance and audit
   - benchmark, migration, and ROI dashboards

Kin must assume users bring their own assistants:

- Claude Code
- Codex
- Gemini CLI
- Cursor
- future assistants

Kin's value is:

- precise context delivery
- identity tracking across refactors
- semantic review
- provenance and trust
- compatibility with existing Git workflows
- measurable economic value

## 3. Non-Negotiable Decisions

These are fixed:

1. **Rust is the core implementation language.**
2. **Semantic entities are the internal source of truth.**
3. **Files and Git history are projections.**
4. **Git compatibility is mandatory.**
5. **Kin and Git must work side-by-side indefinitely.**
6. **Kin adoption must be reversible.**
7. **Kin must preserve normal code execution through ordinary files.**
8. **Kin is assistant-neutral by default.**
9. **The semantic graph, fingerprints, and evidence remain customer-controlled by default.**
10. **The open semantic core is the strategic asset.**

## 4. Final-State Product Boundary

### 4.1 What Kin Owns

Kin owns:

- semantic identity of code
- graph of relations between entities
- semantic history, diff, and review
- intent/spec objects
- provenance and evidence
- assistant-neutral context delivery
- semantic reconciliation between graph state and projected file/Git state
- org-wide engineering memory
- benchmarking and migration

### 4.2 What Kin Does Not Replace Directly

Kin does not replace:

- compilers
- interpreters
- build tools
- test runners
- editors
- existing assistants

Kin changes how code is represented, reasoned about, reviewed, and synchronized. It does not change the fact that ordinary tools still run ordinary files.

### 4.3 How Kin Relates to Git

Kin does not "rip out" Git. Kin subjugates Git.

Git becomes:

- compatibility layer
- storage protocol
- projection target
- migration bridge

Kin becomes:

- intelligence layer
- semantic versioning layer
- review layer
- agent context layer

## 5. System Overview

Kin has four main planes:

1. **Semantic Plane**
   - entities
   - relations
   - contracts
   - semantic changes
   - specs

2. **Projection Plane**
   - files
   - Git commits
   - PR-like views
   - living docs

3. **Execution Plane**
   - local workspaces
   - managed runners
   - validation runs
   - evidence capture

4. **Control Plane**
   - reviews
   - governance
   - assistant adapter registry
   - org dashboards
   - benchmark reporting

The first release sequence should build the semantic plane and projection plane first, then layer execution and control.

## 6. Implementation Language and Runtime Choices

### 6.1 Rust

Rust is required for:

- zero-copy parsing paths
- fast local indexing
- safe concurrency
- long-running daemon reliability
- single-binary distribution
- direct filesystem and Git-level control

Do not build the core in Python or Node.js.

### 6.2 Supporting Technologies

- **Parsing:** Tree-sitter
- **Semantic enrichment:** LSP, SCIP, compiler metadata, language-specific analysis hooks
- **Local persistence:** embedded SQLite/libSQL or RocksDB + local file artifacts
- **Vector/semantic search:** local vector store or table-backed ANN later, but not a mandatory external dependency in the first implementation
- **UI:** local web app backed by daemon APIs
- **MCP:** local MCP server over stdio and/or local sockets

### 6.3 Deployment Modes

Kin must support:

- local-only mode
- self-hosted/air-gapped org mode
- hosted Kin Cloud mode
- hybrid mode with customer-controlled semantic data plane and hosted control plane

## 7. Repository and Workspace Structure

The first repository should be a Rust workspace organized by behavior, not by infrastructure vendor.

Suggested crate layout:

```text
kin/
  crates/
    kin-cli/
    kin-daemon/
    kin-core/
    kin-model/
    kin-store/
    kin-index/
    kin-parser/
    kin-contracts/
    kin-projection/
    kin-reconcile/
    kin-git/
    kin-mcp/
    kin-context/
    kin-review/
    kin-bench/
    kin-migrate/
    kin-runtime/
  apps/
    kin-local-ui/
  docs/
    architecture/
```

Ownership:

- `kin-model`: canonical types and IDs
- `kin-store`: storage abstraction and persistence
- `kin-index`: graph build and update pipeline
- `kin-projection`: file and doc projections
- `kin-reconcile`: reconciliation loop and conflict objects
- `kin-git`: Git import/export, commit projection, sync hooks
- `kin-context`: context pack building
- `kin-review`: semantic review and risk summaries
- `kin-bench`: benchmark engine and metrics
- `kin-runtime`: workspace runs and evidence capture
- `kin-mcp`: assistant-neutral integration surface

## 8. Local State Layout

Every Kin-enabled repository should have a `.kin/` directory.

Suggested layout:

```text
.kin/
  config.toml
  manifest.json
  graph.sqlite
  blobs/
  projections/
  snapshots/
  docs/
  bench/
  runs/
  logs/
  adapters/
```

Purpose:

- `config.toml`: repo-local Kin config
- `manifest.json`: repo identity, languages, adapters, versions
- `graph.sqlite`: canonical local store
- `blobs/`: normalized entity payloads and cached text blocks
- `projections/`: generated file/doc projections
- `snapshots/`: semantic snapshot metadata
- `docs/`: generated living docs
- `bench/`: benchmark traces and reports
- `runs/`: validation run evidence
- `adapters/`: assistant adapter config and metadata

Deleting `.kin/` must leave the repository as ordinary files + ordinary `.git`.

## 9. Canonical Data Model

### 9.1 Core Objects

The canonical internal model is built around:

- `Entity`
- `SemanticFingerprint`
- `Relation`
- `Contract`
- `SemanticChange`
- `Spec`
- `Review`
- `Workspace`
- `Run`
- `Evidence`
- `Projection`
- `ConflictObject`
- `Policy`
- `BenchmarkRun`
- `AssistantSession`
- `ContextPack`
- `AssistantAdapter`

### 9.2 Entity

An `Entity` is the atomic semantic unit of Kin.

Supported entity kinds in near-final state:

- function
- method
- class
- interface
- trait
- type alias
- module
- package
- test
- schema
- API endpoint
- event contract
- file
- document node

Suggested fields:

```rust
pub struct Entity {
    pub id: EntityId,
    pub kind: EntityKind,
    pub name: String,
    pub language: LanguageId,
    pub fingerprint: SemanticFingerprint,
    pub file_origin: FilePathId,
    pub span: SourceSpan,
    pub signature: String,
    pub visibility: Visibility,
    pub doc_summary: Option<String>,
    pub metadata: EntityMetadata,
    pub lineage_parent: Option<EntityId>,
    pub created_in: SemanticChangeId,
    pub superseded_by: Option<EntityId>,
}
```

### 9.3 Semantic Fingerprint

`SemanticFingerprint` is Kin's identity moat.

It must be derived from:

- normalized AST shape
- signature
- behaviorally relevant structure
- stable symbol graph features

It must not be invalidated by:

- whitespace changes
- formatting changes
- comment-only edits
- file moves
- symbol renames where structural identity remains intact

It may change on:

- logic changes
- control flow changes
- parameter/return contract changes
- side-effect changes

Suggested fields:

```rust
pub struct SemanticFingerprint {
    pub algorithm: FingerprintAlgorithm,
    pub ast_hash: Hash256,
    pub signature_hash: Hash256,
    pub behavior_hash: Hash256,
    pub stability_score: f32,
}
```

### 9.4 Relation

`Relation` expresses typed edges.

Core edge kinds:

- calls
- imports
- contains
- references
- implements
- extends
- tests
- depends_on
- defines_contract
- consumes_contract
- emits_event
- owned_by
- documented_by

Suggested fields:

```rust
pub struct Relation {
    pub id: RelationId,
    pub kind: RelationKind,
    pub src: NodeId,
    pub dst: NodeId,
    pub confidence: f32,
    pub origin: RelationOrigin,
    pub created_in: SemanticChangeId,
}
```

### 9.5 Contract

`Contract` is the cross-language linking primitive.

Contract kinds:

- OpenAPI
- Protobuf
- GraphQL schema
- DB schema
- event schema
- typed interface

This object links code across repos and languages.

### 9.6 Semantic Change

`SemanticChange` is the canonical change unit.

It records:

- changed entities
- relation deltas
- projected files
- spec linkage
- author and assistant provenance
- validation evidence
- risk summary

### 9.7 Spec

`Spec` is the planning primitive.

Minimum fields:

- intent
- scope
- constraints
- acceptance criteria
- affected systems
- validation requirements
- policy/risk expectations

### 9.8 Evidence

`Evidence` is execution provenance, not just success/failure.

It must capture:

- assistant identity and version
- prompt/context provenance
- tool calls
- touched entities/files
- validation commands
- stdout/stderr/test results
- replay metadata
- workspace snapshot identifiers
- optional session/video artifacts

### 9.9 Projection

`Projection` is any rendered or compatibility-facing output:

- source file
- Git commit/tree
- PR-like view
- `.kin/AGENTS.md`
- `.kin/ARCHITECTURE.md`
- benchmark report

### 9.10 Conflict Object

`ConflictObject` is a first-class artifact, not an error string.

It should capture:

- semantic desired state
- projected current state
- divergence reason
- affected entities/files
- suggested resolutions
- required human review flag

## 10. Storage Model

Kin should use an embedded local store first.

Recommended storage split:

1. **Structured Store**
   - entities
   - relations
   - contracts
   - changes
   - specs
   - runs
   - evidence
   - projections

2. **Artifact Store**
   - raw entity text
   - projection outputs
   - run artifacts
   - benchmark traces

3. **Search Store**
   - symbol index
   - entity name index
   - semantic embedding index

Use a single local authority, then add hosted org sync on top. Do not start with a distributed graph database dependency.

## 11. Semantic Compiler and Indexing Pipeline

The indexing pipeline is:

1. repo discovery
2. language detection
3. file watch + Git watch
4. parse changed files with Tree-sitter
5. extract entities
6. extract relations
7. run language-specific enrichment
8. build/update contracts
9. compute fingerprints
10. update semantic store
11. update projections and living docs as needed

### 11.1 Language Adapters

Tier-1 languages:

- TS/JS
- Python
- Go
- Java
- Rust

Each language adapter must define:

- entity extraction rules
- relation extraction rules
- signature normalization rules
- fingerprint normalization rules
- contract adapter hooks

### 11.2 Cross-Language Contract Adapters

This is the hardest technical problem.

Kin must support contract-addressable linking through:

- OpenAPI
- Protobuf
- GraphQL
- database schemas
- event schemas

Adapters should create `Contract` nodes and connect producers/consumers to them.

### 11.3 Performance Targets

Targets:

- zero-config onboarding
- 50k+ lines per second indexing target on modern consumer hardware
- 500k-line repo first graph build under 10 seconds on high-end developer hardware
- incremental graph updates near real time after save or Git operation

## 12. Context Pack Builder

`ContextPack` is Kin's primary assistant-facing output.

It should contain:

- primary entities
- minimal dependency neighborhood
- relevant contracts
- test coverage links
- ownership/context docs
- risk hints
- optional historical context

Rules:

- never send the whole graph unless explicitly asked
- default to minimum sufficient context
- support token budgets
- support local summarization before cloud assistant calls

## 13. Projection Engine

Kin must project semantic state into ordinary files and Git-compatible history.

Projection targets:

- source files
- repo snapshots
- Git commits
- living docs
- review views

Projection rules:

- preserve stable file ordering
- preserve formatting where possible
- preserve human-readable file structure
- materialize valid code at all times

## 14. Reconciliation Loop

Kin uses a continuous reconciliation loop.

Model:

- semantic graph = desired state
- files/Git = projected current state

Sources of change:

- human file edits
- Git operations
- assistant semantic edits
- assistant file edits

Loop:

1. detect change
2. parse and fingerprint
3. compare semantic and projected states
4. either reconcile automatically or emit conflict object
5. update projections and history

This must behave like a Kubernetes-style reconciler, not a one-shot sync job.

## 15. Parallel Git/Kin Operation

Kin must support permanent side-by-side usage:

- Kin-native users can work semantically
- Git-native users can continue with normal Git
- both feed the same repo
- both are kept consistent by the daemon and reconciler

This is the standard adoption mode, not a transition-only mode.

## 16. Reversible Adoption

Kin must provide a zero-lock-in escape hatch.

If the team uninstalls Kin:

- code remains as normal files
- Git history remains valid
- code still builds and runs
- deleting `.kin/` removes Kin state without bricking the repo

This is a hard requirement.

## 17. Assistant-Neutral Integration

Kin must be assistant-neutral.

This means:

- no Kin-owned assistant is required
- no core workflow depends on Kin-specific prompts
- provenance is normalized regardless of assistant vendor
- adapters exist for Claude Code, Codex, Gemini CLI, Cursor, and future assistants

Integration surfaces:

- MCP
- local context pack APIs
- assistant adapter config
- session registration
- evidence submission

## 18. Living Documentation

Kin must generate contextual virtual files from graph state.

Examples:

- `.kin/AGENTS.md`
- `.kin/ARCHITECTURE.md`
- `.kin/CLAUDE.md`
- `.kin/CONTEXT.md`

These are:

- not Git-committed by default
- projections, not primary authored sources
- regenerated as code/ownership/contracts change

This is the main "aha" demo for developers.

## 19. Semantic Review

Semantic review is the default review model.

Every review should show:

- changed entities
- impacted callers/dependencies/contracts/tests
- intent/spec alignment
- risk and policy implications
- evidence and validation provenance
- fallback line diff

PRs remain as a compatibility view only.

## 20. Semantic Build and Test Skipping

Kin must reduce CI/CD spend by using semantic fingerprints instead of file hashes.

Rules:

- whitespace-only changes should not trigger full rebuilds
- comment-only changes should not trigger full rebuilds
- formatting-only changes should not trigger full rebuilds
- only affected validation graphs should rerun

Target business outcome:

- 30-60% CI/CD compute savings in repos with meaningful non-semantic churn

## 21. Benchmarking and Value Proof

Benchmarking is a first-class product area, not a side feature.

### 21.1 Developer Velocity Metrics

- context warm-up latency
- first-pass pass rate
- semantic review turnaround
- time-to-impact-analysis
- context precision and recall

### 21.2 Reliability Metrics

- dependency coverage
- risk detection accuracy
- contract breakage detection
- reconciliation correctness
- orphan/dead-code identification accuracy

### 21.3 Economic Metrics

- token-to-logic ratio
- token waste avoided
- API spend projections
- cost per task
- CI/CD cost savings
- cost of hallucination avoided

### 21.4 Reports

Required dashboards:

- side-by-side assistant comparison
- repo-level ROI dashboard
- adoption progress dashboard
- hallucination tax report
- migration preview report

## 22. Migration Pipeline

Kin adoption must be frictionless.

Flow:

1. connect to existing GitHub repo
2. clone or inspect HEAD
3. build graph immediately
4. show graph visualization and impact analysis
5. enable benchmark preview
6. optionally enable bidirectional sync

The first value must arrive before the user fully migrates.

## 23. Hosted Platform Requirements

The hosted product should include:

- org graph sync
- semantic review hub
- spec/task management
- managed assistant workspaces
- self-hosted enterprise runner support
- governance
- audit
- benchmark dashboards
- migration dashboards

The hosted platform should not own the semantic truth itself if the customer wants local or self-hosted semantic control.

## 24. Privacy, Security, and Air-Gap Requirements

Defaults:

- semantic graph stays local/on-prem by default
- fingerprints stay local/on-prem by default
- evidence stays local/on-prem by default
- assistants receive only minimal context packs by default

Required enterprise modes:

- fully local
- self-hosted / air-gapped
- hybrid control-plane mode

## 25. Public Interfaces

### 25.1 CLI

Required near-final commands:

- `kin init`
- `kin clone`
- `kin status`
- `kin diff`
- `kin history`
- `kin impact`
- `kin blame`
- `kin review`
- `kin spec`
- `kin context`
- `kin search`
- `kin bench`
- `kin migrate`
- `kin sync`
- `kin workspace`
- `kin run`
- `kin mcp`
- `kin assistant`

### 25.2 MCP

Required MCP capability groups:

- semantic search
- graph retrieval
- impact analysis
- semantic diff/history
- dead code detection
- review/evidence lookup
- spec lookup
- benchmark execution/results
- workspace/run status
- assistant session registration
- living docs retrieval

### 25.3 Hosted APIs

Required API domains:

- graph query
- review lifecycle
- spec lifecycle
- run/workspace lifecycle
- benchmark results
- migration state
- sync/projection state
- policy/audit
- assistant adapter/session reporting

## 26. Open Source vs Commercial Split

### Open Source

- semantic VCS core
- graph engine
- CLI
- daemon
- local UI
- MCP server
- Git bridge
- local benchmark tools
- local migration tools
- assistant-neutral adapter layer
- living documentation projections

### Commercial

- org graph sync
- hosted workspace UI
- managed execution
- semantic review hub
- governance and policy
- enterprise controls
- assistant fleet dashboards
- semantic build orchestration

## 27. Testing and Acceptance

### 27.1 Semantic Correctness

- extract entities across tier-1 languages
- extract relations correctly
- preserve identity across rename and move
- preserve file/entity round-trip fidelity

### 27.2 Contract Linking

- link Go producer to TS consumer correctly
- include Python consumer in cross-language impact
- preserve contract lineage over version changes

### 27.3 Reconciliation

- human file edit vs assistant semantic edit
- explicit conflict object emission
- deterministic resolution path
- valid Git projection after reconciliation

### 27.4 Parallel Operation and Reversibility

- Git-native and Kin-native users collaborate without breakage
- ordinary Git commits update semantic state correctly
- deleting `.kin/` leaves repo intact and runnable

### 27.5 Review and Provenance

- semantic review shows impact, risk, evidence
- replay reconstructs validation run
- authorship is preserved through projections

### 27.6 Privacy and Data Locality

- graph remains local by default
- context packs are minimal
- local summarization reduces cloud egress

### 27.7 Performance

- onboarding performance targets hit on modern hardware
- incremental re-index latency is acceptable
- graph preview appears immediately enough for adoption
- semantic build skipping avoids unnecessary compute safely

### 27.8 Execution Continuity

- `npm`, `python`, `cargo`, `go`, `java`, and CI workflows run on projected files
- semantic mutations remain immediately runnable
- hot reload continues to work

## 28. Recommended Implementation Sequence

This is not a product roadmap. It is the correct dependency order for implementation.

1. canonical types and IDs
2. local storage and `.kin/` layout
3. parser and entity extraction
4. relation extraction
5. fingerprinting and lineage
6. file/Git watcher
7. projection engine
8. reconciliation loop
9. context pack builder
10. MCP server
11. semantic review primitives
12. living docs projections
13. benchmarking engine
14. migration/import pipeline
15. hosted org graph and control plane
16. managed execution and semantic build orchestration

## 29. Final Technical Position

Kin should be built as the semantic operating layer for software engineering.

It should:

- think in entities
- preserve identity across refactors
- project to ordinary files and Git
- work in parallel with Git forever if needed
- remain reversible
- support any assistant
- keep sensitive semantic state local by default
- prove value through performance, reliability, and savings

That is the architecture to implement.
