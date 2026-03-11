# Kin Build Board

This is the implementation board for the **open-core** Kin repository.

It is not a replacement for the phase plans. It is the execution map that turns the current audit into actionable build slices.

For non-blocking post-launch refinements, see [kin-open-core-todos.md](./kin-open-core-todos.md).

## Ownership

- **Claude Code**: implementation
- **Codex**: audit, regression checks, plan conformance review

## Status Legend

- `Done`: implemented and validated in the current tree
- `Thin`: implemented, but still materially below the plan's intended depth
- `Missing`: not implemented or only present as scaffolding
- `Deferred`: intentionally out of scope for the open core right now

## Current Phase Summary

| Area | Status | Notes |
|------|--------|-------|
| P1 / V1 core sovereignty | Done | `kin init`, graph/blob store, commit/log/branch/diff/history/blame, Git import/export/sync, migrate, runtime, never-drop indexing, structured artifacts, tier-1 parsing all exist |
| P1 semantic review depth | Done | review computes risk on demand from change/diff/impact state |
| P1 merge maturity | Thin | unrelated-history merge is handled; entity-scoped execution and deeper merge semantics remain refinement work |
| P2 / Phase 7 traffic + coordination | Done | sessions, intents, collisions, traffic-aware context, assistant adapters, MCP tools, acceptance tests are real |
| P2 local UI/operator depth | Done | local UI has real traffic, work, provenance, verification, and benchmark-backed views |
| P3 / Phase 8 work graph | Done | work items, annotations, TODO import, staleness, context/review integration, CLI/MCP, acceptance tests are real |
| P3 / Phase 9 verification graph | Done | test cases, assertions, coverage summaries, verification CLI, and acceptance coverage are real |
| P3 / Phase 10 provenance + audit | Done | actor/delegation/approval/audit model and CLI surfaces are real |
| P3 / Phase 11 execution surfaces | Thin | `kin exec` and materialized workspaces are real; entity-scoped exec remains a refinement area |
| P3 / Phase 12 release/security/rollback | Done | `kin semver`, `kin release`, `kin rollback`, and `kin security` are implemented |
| Additional open-core benchmark lane | Done | import, capture, corpus, dashboard JSON, and local UI comparison views are real |
| Additional open-core coverage lane | Thin | never-drop indexing, corpus, support reporting, and C2 shallow syntax are real; finer-grained semantic depth remains later work |

## Board

## Lane A: Harden V1 / P2 Thin Spots

### A1. Semantic Review Depth

- Status: `Thin`
- Priority: `P0`
- Goal: make `kin review` compute and display meaningful risk output even when the change does not already carry a stored `risk_summary`
- Primary crates:
  - `crates/kin-review`
  - `crates/kin-cli`
  - `tests/integration`
- Needed work:
  - compute review/risk summary on demand from change deltas, work graph state, annotation staleness, and contract/dependency impact
  - stop relying on pre-populated `change.risk_summary` as the only path
  - add acceptance coverage proving risk notes appear for non-trivial changes
- Acceptance:
  - `kin review` on a change with entity/relation/artifact deltas produces non-empty structured risk output
  - review surfaces stale annotations and unresolved work where relevant

### A2. Merge Maturity

- Status: `Thin`
- Priority: `P1`
- Goal: close the remaining merge gap for unrelated or full-tree merge scenarios
- Primary crates:
  - `crates/kin-cli`
  - `crates/kin-reconcile`
  - `crates/kin-projection`
  - `tests/integration`
- Needed work:
  - define and implement fallback behavior for unrelated histories
  - add stronger projection/reconcile-backed merge validation
  - document what semantic vs structural merge actually guarantees in V1/P2
- Acceptance:
  - unrelated-history merge no longer dead-ends with a console message only
  - merge behavior is covered by integration tests for divergent and full-tree cases

### A3. Phase 7 Local UI Depth

- Status: `Thin`
- Priority: `P2`
- Goal: make the local UI meaningfully useful for active traffic, sessions, work, and benchmarks
- Primary crates:
  - `apps/kin-local-ui`
  - `crates/kin-daemon`
  - `crates/kin-bench`
- Needed work:
  - replace static placeholder pages with real daemon-backed views
  - add benchmark comparison cards
  - add active session / intent / lock inspection beyond simple tables
- Acceptance:
  - local UI can inspect traffic, work, and benchmark data without editing files or reading raw JSON

## Lane B: P3 Phase 9 Verification Graph

### B1. Verification Model

- Status: `Missing`
- Priority: `P0`
- Goal: implement the actual Phase 9 model from the plan
- Primary crates:
  - `crates/kin-model`
  - `crates/kin-graph`
- Needed work:
  - add `TestCase`
  - add `Assertion`
  - add `VerificationStatus`
  - add `CoverageSummary`
  - add `CompletionState`
  - persist proof links between tests, entities, contracts, work items, and validation runs
- Acceptance:
  - model and graph can represent tests linked to entities and work
  - graph queries can answer "what verifies this entity/work item?"

### B2. Runtime + CLI Verification Flows

- Status: `Missing`
- Priority: `P0`
- Goal: build the user-facing proof workflow
- Primary crates:
  - `crates/kin-runtime`
  - `crates/kin-cli`
  - `crates/kin-context`
  - `crates/kin-review`
  - `tests/integration`
- Needed work:
  - add `kin verify ...`
  - add `kin run --scope ...`
  - add `kin work verify ...`
  - link validation runs to scoped tests/entities/work items
  - surface proof gaps in context and review
- Acceptance:
  - impacted proof set can be computed for a changed entity
  - a work item can move to `Verified` only when linked proof exists

### B3. Parser / Contracts Hooks For Proof

- Status: `Missing`
- Priority: `P1`
- Goal: connect test discovery and contract outcomes to the proof graph
- Primary crates:
  - `crates/kin-parser`
  - `crates/kin-contracts`
  - `tests/integration`
- Needed work:
  - add test block extraction hooks where feasible
  - link tests to contract outcomes/failure paths
  - add missing-proof queries for contract coverage
- Acceptance:
  - Kin can surface missing proof for at least one contract outcome class, not only generic test absence

## Lane C: P3 Phase 10 Provenance, Delegation, Audit

### C1. Provenance Model

- Status: `Missing`
- Priority: `P1`
- Goal: replace Phase 8's lightweight identity placeholders with the real provenance graph
- Primary crates:
  - `crates/kin-model`
  - `crates/kin-graph`
- Needed work:
  - add `Actor`
  - add `ActorKind`
  - add `Delegation`
  - add `Approval`
  - add `AuditEvent` / audit query support
- Acceptance:
  - changes, work items, and annotations can be attributed to actors
  - delegation and approval state can be queried from the graph

### C2. Audit / Approval Surface

- Status: `Missing`
- Priority: `P1`
- Goal: make provenance visible to humans and agents
- Primary crates:
  - `crates/kin-cli`
  - `crates/kin-mcp`
  - `crates/kin-context`
  - `apps/kin-local-ui`
- Needed work:
  - add `kin audit ...`
  - add `kin approvals ...`
  - extend blame to distinguish human authorship vs assistant execution
  - surface unreviewed agent-authored changes
- Acceptance:
  - Kin can answer "who last changed this function?" after a rename or move
  - Kin can filter agent-authored changes lacking approval

## Lane D: P3 Phase 11 Execution Surfaces

### D1. JIT / Materialized Execution First

- Status: `Missing`
- Priority: `P1`
- Goal: implement the open-core execution surface around projected files plus materialized workspaces
- Primary crates:
  - `crates/kin-runtime`
  - `crates/kin-projection`
  - `crates/kin-cli`
  - `tests/integration`
- Needed work:
  - add `kin exec ...`
  - materialize scoped workspaces from semantic state
  - support `reflink -> hardlink -> copy` fallback policy
  - keep projected working directory as the default human path
- Acceptance:
  - a build/test command can run against a materialized workspace without requiring FUSE
  - output semantic state matches the standard projection path

### D2. View / Mount Surfaces

- Status: `Missing`
- Priority: `P2`
- Goal: add secondary execution surfaces only after `kin exec` is solid
- Primary crates:
  - `crates/kin-cli`
  - `crates/kin-daemon`
  - `crates/kin-projection`
- Needed work:
  - add `kin view ...`
  - evaluate whether `kin mount` is needed after `kin exec`
  - keep mount layers optional, not required
- Acceptance:
  - execution surface story is explicit and cross-platform, with no plugin requirement

## Lane E: P3 Phase 12 Release / Security / Rollback

### E1. Local Release Intelligence

- Status: `Missing`
- Priority: `P2`
- Goal: implement the local open-core portion of semantic release/security/rollback
- Primary crates:
  - `crates/kin-model`
  - `crates/kin-graph`
  - `crates/kin-review`
  - `crates/kin-cli`
- Needed work:
  - add `VersionImpact`
  - add `ReleaseBoundary`
  - add `Vulnerability`
  - add `RollbackPlan`
  - add `kin semver`, `kin release`, `kin rollback`, `kin security`
- Acceptance:
  - Kin can recommend patch/minor/major impact from semantic contract changes
  - Kin can produce a local rollback plan for a feature or issue scope

## Lane F: Additional Open-Core Items We Agreed On

### F1. Coverage / Support Reporting

- Status: `Missing`
- Priority: `P0`
- Goal: make Kin's coverage honest and inspectable
- Primary crates:
  - `crates/kin-index`
  - `crates/kin-cli`
  - `apps/kin-local-ui`
- Needed work:
  - add support-tier reporting for C0-C5
  - add a CLI surface such as `kin support` or `kin doctor support`
  - show file counts by semantic depth and artifact kind
- Acceptance:
  - users can see what a repo got indexed as semantic, structured, shallow, or opaque

### F2. Benchmark Capture

- Status: `Partial`
- Priority: `P0`
- Goal: move from imported assistant traces to direct capture
- Primary crates:
  - `crates/kin-bench`
  - `crates/kin-cli`
  - `apps/kin-local-ui`
  - `docs/benchmarks`
- Needed work:
  - add `kin bench capture claude`
  - add `kin bench capture codex`
  - add `kin bench capture gemini`
  - optionally support OTel ingestion later, but do not block on it
  - render benchmark comparison cards in the local UI
- Acceptance:
  - a user can run the same task under `git` and `kin` and get saved comparison output without hand-writing JSON specs

### F3. Real-Repo Corpus Harness

- Status: `Missing`
- Priority: `P0`
- Goal: validate Kin against real repositories instead of fixtures only
- Primary crates:
  - `tests/integration`
  - `crates/kin-bench`
  - `crates/kin-index`
- Needed work:
  - add a corpus runner over selected repos in `~/GitHub`
  - record coverage, fallback rates, relation counts, and parse failures
  - use it as the audit gate for language hardening
- Acceptance:
  - Kin can run repeatedly over a fixed corpus and emit comparable quality metrics over time

### F4. C2 Shallow Syntax Tier

- Status: `Missing`
- Priority: `P1`
- Goal: add honest intermediate support for languages with a grammar but without full semantic extraction
- Primary crates:
  - `crates/kin-parser`
  - `crates/kin-index`
  - `crates/kin-model`
- Needed work:
  - define shallow syntax extraction contract
  - use parser-backed coarse structure where useful
  - allow narrow regex only for bounded helpers, never as the semantic core
- Acceptance:
  - unsupported languages no longer force an all-or-nothing choice between rich semantics and opaque blobs

#### Execution Rule

`F4` may run **now in parallel** with the other outstanding items, but only under these constraints:

- start with **one pilot language family or one parser-backed shallow mode**, not a broad rollout
- keep the implementation isolated to parser/index/support layers
- do not let `C2` semantics influence merge confidence, reconcile authority, or strong review guarantees
- do not block `B1` / `B2` / provenance work on `C2`

The right bar is:

> make more files usefully queryable without pretending they are deeply semantic

Recommended pilot scope:

- parser-backed shallow extraction for files where a grammar exists but Kin does not yet provide full entity/relation fidelity
- expose `C2` clearly in `kin support`
- allow context/search to surface shallow declarations/imports/TODOs
- do not project or merge `C2` files with `C5` confidence

### F5. Contributor Adapter SDK

- Status: `Missing`
- Priority: `P2`
- Goal: make it cheap to add languages and artifact extractors without touching core logic everywhere
- Primary crates:
  - `crates/kin-parser`
  - `tests/integration`
  - `docs/architecture`
- Needed work:
  - formalize adapter trait expectations
  - add golden fixture harness
  - add conformance tests and coverage-level labeling
- Acceptance:
  - a new adapter can be built and validated against a standard contributor path

## Audit Rules

Claude should treat a slice as complete only when all of these are true:

1. the command/model/graph surface exists
2. workspace tests are green
3. the relevant acceptance tests exist
4. the behavior matches the phase plan, not just a thinner placeholder

Codex audits each completed slice against:

- `PLAN.md`
- `PLAN_P2.md`
- `PLAN_P3.md`
- this build board

## Recommended Implementation Order

1. `F1` coverage/support reporting
2. `F3` real-repo corpus harness
3. `A1` semantic review depth
4. `B1` and `B2` verification graph + CLI/runtime proof flow
5. `F2` benchmark capture
6. `F4` shallow syntax tier (pilot only, in parallel with 4-5 if isolated)
7. `C1` and `C2` provenance/audit
8. `D1` `kin exec` with JIT/materialized workspaces
9. `E1` local release/security/rollback intelligence
10. `F5` contributor adapter SDK

This order keeps the open core focused on:

- proving value on real repos
- proving Kin beats Git for agent workflows
- building the missing proof and audit layers
- delaying broader execution-surface complexity until the semantic core is stronger
