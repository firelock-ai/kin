# Projection / Reconcile Acceptance Package

**Date:** 2026-03-17
**Auditor:** proj-reconcile agent
**Scope:** `kin-projection`, `kin-reconcile`, `kin-blobs`, and their integration surface

---

## 1. Architecture Overview

### Projection (Graph -> Files)

The projection engine lives in `crates/kin-projection/`. It materializes semantic graph state into working directory files using surgical byte-range splicing on CST-preserving `FileLayout` structures.

**Core flow:**
1. `ProjectionState` caches `FileLayout` + raw file bytes per `FilePathId`
2. `project_entity_mutations()` groups mutations by file, builds `Splice` ops, writes via temp-file-then-rename (two-phase commit)
3. `splice_entity()` finds an entity's byte range in the layout and produces a `Splice`
4. `apply_splices()` sorts splices by descending offset and applies them back-to-front to preserve earlier ranges
5. `reconstruct_file()` rebuilds a complete file from layout + entity body provider (used during branch switch)

**Supporting modules:**
- `layout_tracker.rs` -- builds `FileLayout` from parsed entities, interleaving Trivia regions
- `placement.rs` -- decides where new entities go (file_origin > parent module > language search > generate)
- `imports.rs` -- surgical import add/remove/update via splices
- `living_docs.rs` -- regenerates ARCHITECTURE.md, AGENTS.md, CONTEXT.md from graph state

### Reconciliation (Files -> Graph)

The reconciler lives in `crates/kin-reconcile/`. It is a Kubernetes-style reconciliation loop with two directions:

**Direction 1 -- File -> Overlay (`reconcile_file_change`):**
1. Receives a `FileEvent` (Changed or Removed)
2. For Changed: indexes the file via `IndexPipeline`, checks for broken AST
3. Matches parsed entities against existing graph entities by name+kind
4. Remaps parser-assigned UUIDs to stable graph IDs for matched entities
5. Populates `GraphOverlay` with adds/mods/removes
6. Updates `LkgStore` and `ProjectionState` layout

**Direction 2 -- Overlay -> File (`project_overlay_to_files`):**
1. Extracts entity body text for each modified entity (span > blob > signature fallback)
2. Checks collision scopes against traffic checker
3. Delegates to `project_entity_mutations()` for file writes

**Supporting modules:**
- `lkg.rs` -- Last Known Good store; retains entity state during broken AST parses
- `collision.rs` -- pre-write collision checking against active intents/sessions; merge conflict detection

### Blob Store

`crates/kin-blobs/` provides content-addressed SHA-256 blob storage with Git-style sharding (`{root}/{hash[0..2]}/{hash[2..]}`). Writes are atomic (temp file then rename). Deduplication on hash match.

---

## 2. Bugs and Gaps Found

### CRITICAL -- Data Loss / Corruption Risk

#### C1. `extract_entity_body` signature fallback is lossy (reconciler.rs:690-695)

When an entity has no span and no blob_hash in metadata, `extract_entity_body` falls back to `entity.signature.as_bytes()`. The signature is a short summary (e.g., `"fn foo()"`) -- NOT the full function body. This means **the entire body is silently replaced with just the signature**, destroying all implementation code.

**Severity:** CRITICAL -- silent data loss on the fallback path
**Trigger conditions:** Entity lacks both `span` and `metadata.extra["blob_hash"]`; this can happen during overlay-to-file projection when the entity was created programmatically or when the projection state cache is stale.

#### C2. `blob_hash` metadata key is never written (dead fallback path)

The `extract_entity_body` blob store fallback (reconciler.rs:680-688) reads `entity.metadata.extra.get("blob_hash")` -- but no code in the entire codebase ever writes `"blob_hash"` into `entity.metadata.extra`. The blob store fallback path is **dead code**. This means the only reliable body extraction path is span-based, and if that fails, you hit C1.

**Severity:** CRITICAL -- the designed safety net for body extraction does not function
**File:** `crates/kin-reconcile/src/reconciler.rs:680`

#### C3. `project_file_from_entities` ignores blob_store (engine.rs:188)

The branch-switch projection function accepts a `&BlobStore` parameter but suppresses it with `let _ = blob_store`. Entity bodies are only extracted from spans within `original_content`. If `original_content` is stale or the entity's span doesn't match (e.g., after a rebase or external edit), the function silently returns `None` from the closure, keeping original bytes instead of fetching the correct body from blobs.

**Severity:** CRITICAL -- branch switch may project stale entity bodies
**File:** `crates/kin-projection/src/engine.rs:188`

### HIGH -- Functionality Gaps

#### H1. No atomic transaction in reconcile_file_edit (reconciler.rs:127-295)

`reconcile_file_edit` mutates the overlay, LKG store, and projection state in sequence with no rollback mechanism. If an error occurs partway through (e.g., during layout registration at line 277), the overlay may have partial adds/mods/removes, the LKG store may have recorded some entities but not others, and the projection state may be inconsistent.

**Severity:** HIGH -- partial mutation on error leaves system in inconsistent state
**File:** `crates/kin-reconcile/src/reconciler.rs:127-295`

#### H2. Projection two-phase commit is best-effort, not atomic (engine.rs:134-148)

The projection engine writes temp files in Phase 1, then renames them in Phase 2. The code explicitly acknowledges: "if a rename fails after some have already succeeded, those committed files cannot be rolled back." This means a crash or disk error during Phase 2 can leave some files updated and others not.

**Severity:** HIGH -- partial file writes on crash during commit phase
**File:** `crates/kin-projection/src/engine.rs:134-148`

#### H3. No full-stack round-trip integration test (project -> edit -> reconcile -> verify graph)

There is no test that:
1. Projects entities to files
2. Externally edits the projected files
3. Reconciles the edits back
4. Verifies the graph matches expectations

The existing round-trip tests in `crates/kin-reconcile/tests/round_trip.rs` test overlay-to-file projection but do NOT test file-edit-back-to-graph. The `p3_acceptance.rs:reconciler_file_to_overlay_round_trip` test only exercises file-to-graph (parse + upsert), not the complete cycle.

**Severity:** HIGH -- the core claim of Kin (graph <-> file fidelity) is not verified end-to-end

#### H4. Entity matching by name+kind is fragile (reconciler.rs:189-191)

Reconciliation matches newly-parsed entities to existing graph entities using `name + kind`. This breaks when:
- An entity is renamed (old entity removed, new entity added -- loss of identity continuity)
- Two entities have the same name+kind in different scopes/namespaces within the same file
- A function is converted to a method (kind changes, treated as remove+add)

**Severity:** HIGH -- identity drift under rename/refactor, contradicts Kin's identity stability promise

#### H5. Relation handling in reconcile is append-only (reconciler.rs:262-265)

During file reconciliation, new relations from the parse are always added to the overlay (`relation_adds`), but existing relations that are no longer present in the parse are never removed (except when an entity is entirely removed). This means stale relations accumulate in the graph over time.

**Severity:** HIGH -- graph pollution with stale relations after code edits

### MEDIUM -- Edge Cases

#### M1. Overlapping entity spans are not validated (layout_tracker.rs:56-69)

`build_layout` sorts entity spans by start byte and creates regions, but does not check for overlapping spans. If the parser produces overlapping entity spans (e.g., a nested function whose span overlaps its parent), the resulting layout will have overlapping EntityRef regions. When spliced, one splice may invalidate the byte range of another.

**Severity:** MEDIUM -- corrupted output on overlapping parser spans
**File:** `crates/kin-projection/src/layout_tracker.rs:56-69`

#### M2. FilePathId constructed from display path (reconciler.rs:305)

`reconcile_file_removal` constructs `FilePathId::new(path.display().to_string())`. On some platforms, `display()` may produce different output than the `FilePathId` registered by `reconcile_file_edit` (which gets its ID from `IndexPipeline`). This mismatch would cause the removal to find no existing entities.

**Severity:** MEDIUM -- file removal may silently fail to clean up entities on some platforms
**File:** `crates/kin-reconcile/src/reconciler.rs:305`

#### M3. No cleanup of stale `.kin_tmp` files on process crash (engine.rs:112-131)

If the process crashes between Phase 1 (temp file write) and Phase 2 (rename), stale `.kin_tmp` files remain on disk. There is no startup cleanup or garbage collection for these.

**Severity:** MEDIUM -- disk pollution after crashes
**File:** `crates/kin-projection/src/engine.rs:112-131`

#### M4. Import section byte_range is not updated after splices (imports.rs)

`add_import` inserts at `layout.imports.byte_range.end`, but after the splice the layout's import byte_range is not updated. Subsequent import additions will insert at the old position, potentially in the middle of the previous import.

**Severity:** MEDIUM -- incorrect import positioning on multiple sequential import additions
**File:** `crates/kin-projection/src/imports.rs:15`

#### M5. Broken AST handling does not distinguish severity (reconciler.rs:138-148)

Any parse error causes the entire file to be treated as BrokenAst. There is no concept of partial success (e.g., 10 of 11 functions parsed correctly, only 1 had an error). This means a single syntax error in one function blocks reconciliation of all entities in that file.

**Severity:** MEDIUM -- over-conservative error handling blocks valid entity updates

#### M6. `decide_placement` file existence check is racy (placement.rs:34)

`decide_placement` checks `path.exists()` to determine if a file_origin target exists. Between the existence check and the subsequent write, another process could create or delete the file.

**Severity:** MEDIUM -- race condition in concurrent agent scenarios

### LOW -- Polish / Robustness

#### L1. No BlobStore garbage collection

Blobs are written by `IndexPipeline` but never cleaned up when entities or files are removed. Over time, the blob store accumulates orphaned blobs.

**File:** `crates/kin-blobs/src/lib.rs`

#### L2. `living_docs` uses `list_all_entities` with no pagination

For large repos, `list_all_entities()` loads every entity into memory at once.

**File:** `crates/kin-projection/src/living_docs.rs:18`

#### L3. `generate_file_path` produces all-lowercase paths

`generate_file_path` lowercases the entity name, which may not match language conventions (e.g., Go packages, Java class files that must match class name casing).

**File:** `crates/kin-projection/src/placement.rs:99`

#### L4. Collision check iterates all scopes sequentially

`check_scopes` checks each scope one at a time. For files with many entities, this could be slow with a real traffic checker implementation.

**File:** `crates/kin-reconcile/src/reconciler.rs:599-632`

#### L5. MergePreview does not detect ModifyDelete conflicts

`analyze_merge` checks for Divergent, Convergent, SignatureChange, VisibilityChange, and AddAdd conflicts, but does not detect ModifyDelete (entity modified on one side, deleted on the other). The `MergeConflictKind::ModifyDelete` variant exists but is never constructed.

**File:** `crates/kin-reconcile/src/reconciler.rs:444-531`

---

## 3. Existing Test Coverage Assessment

### Unit Tests (Good)
- **kin-projection:** 16 unit tests covering splice operations, layout building, placement, imports, entity lookup, cache update, temp file isolation
- **kin-reconcile:** 15 unit tests covering collision checking, merge conflict detection, LKG store, detect_conflict, merge analysis
- **kin-blobs:** 11 unit tests covering write/read round-trip, dedup, sharding, deletion, empty/large blobs

### Integration Tests (Partial)
- `crates/kin-reconcile/tests/round_trip.rs`: 4 tests covering overlay-to-file projection (body extraction from span, trivia preservation, multi-entity isolation, stable ID remap after reconcile)
- `tests/integration/src/v1_acceptance.rs`: projection fingerprint stability (re-index same file)
- `tests/integration/src/p3_acceptance.rs`: file-to-overlay round-trip (parse + upsert), LKG retention on broken parse, git export/import
- `tests/integration/src/p7_acceptance.rs`: collision blocking during projection

### What Is NOT Tested
1. **Full round-trip: project -> external edit -> reconcile -> verify graph** -- the critical path
2. Entity rename handling (name+kind match failure)
3. Multi-file reconciliation in a single pass
4. Concurrent reconciliation from multiple sessions
5. Crash recovery (stale temp files, partial overlay state)
6. `project_file_from_entities` (branch switch) -- zero tests
7. Entity body extraction when span is missing (signature fallback)
8. Import splice correctness with multiple sequential operations
9. File removal reconciliation end-to-end
10. Overlapping entity spans
11. Large file / many-entity performance

---

## 4. Acceptance Scenarios

These scenarios must ALL pass before projection/reconcile can be declared "hardened."

### Tier 1: Critical (Must pass for data integrity)

| # | Scenario | Status |
|---|----------|--------|
| A1 | **Full round-trip:** Create entities in graph -> project to files -> externally edit file (change function body) -> reconcile -> verify graph entity has new body and correct fingerprint | NOT TESTED |
| A2 | **Body fidelity:** `extract_entity_body` returns full body text from span, matching exactly what is on disk | PARTIAL (tested for span path only) |
| A3 | **Blob fallback works:** When entity has no span but has blob_hash in metadata, body is correctly extracted from blob store | NOT TESTED (dead code) |
| A4 | **No silent data loss on fallback:** When neither span nor blob is available, reconciler MUST error, not silently use signature | FAILS (uses signature) |
| A5 | **Branch switch body fidelity:** `project_file_from_entities` uses blob store for body extraction when span is stale | NOT TESTED (blob_store ignored) |
| A6 | **Atomic projection:** All files are updated together or none are; partial rename failure rolls back | PARTIAL (best-effort only) |
| A7 | **LKG preserves state on broken AST:** Entity with good parse -> introduce syntax error -> reconcile -> entity retains LKG fingerprint and relations | TESTED (p3_acceptance) |
| A8 | **Entity identity stable across edits:** Edit entity body (not signature) -> reconcile -> same EntityId retained | TESTED (round_trip.rs) |

### Tier 2: High (Must pass for correctness)

| # | Scenario | Status |
|---|----------|--------|
| B1 | **Rename detection:** Rename function `foo` to `bar` in file -> reconcile -> old entity removed, new entity added, lineage preserved | NOT TESTED |
| B2 | **Stale relation cleanup:** Remove a function call from file -> reconcile -> relation is removed from graph | NOT TESTED |
| B3 | **Multi-file projection consistency:** Mutate entities in 3 files -> project -> all 3 files updated correctly | PARTIAL (2-file test exists) |
| B4 | **Concurrent session collision:** Two sessions modify same entity -> first writes, second gets CollisionBlocked | TESTED (p7_acceptance) |
| B5 | **File removal cascades:** Delete file on disk -> reconcile -> all entities and relations from that file removed | NOT TESTED end-to-end |
| B6 | **Entity ID remap during reconcile:** Parser assigns new UUID -> reconciler remaps to stable graph ID -> overlay uses stable ID | TESTED (round_trip.rs) |
| B7 | **ModifyDelete merge conflict detected:** One branch modifies entity, other deletes it -> merge analysis reports conflict | NOT TESTED (variant never constructed) |
| B8 | **Overlay transactionality:** Error during reconcile_file_edit -> overlay, LKG, and projection state are all consistent | NOT TESTED |

### Tier 3: Medium (Should pass for robustness)

| # | Scenario | Status |
|---|----------|--------|
| C1 | **Overlapping entity spans:** Parser produces overlapping spans -> projection handles gracefully (error or merge) | NOT TESTED |
| C2 | **FilePathId consistency:** Path from reconcile_file_edit matches path from reconcile_file_removal on all platforms | NOT TESTED |
| C3 | **Stale temp file cleanup:** After crash, next projection cleans up `.kin_tmp` files | NOT TESTED |
| C4 | **Sequential import additions:** Add 3 imports in sequence -> all positioned correctly | NOT TESTED |
| C5 | **Partial parse recovery:** File with 10 functions, 1 has syntax error -> 9 entities reconciled, 1 retains LKG | NOT TESTED (all-or-nothing currently) |
| C6 | **Large file performance:** File with 500 entities -> projection completes in < 1s | NOT TESTED |
| C7 | **Same-name different-scope entities:** File has `Foo::bar()` and `Baz::bar()` -> both matched correctly during reconcile | NOT TESTED |

### Tier 4: Low (Nice to have)

| # | Scenario | Status |
|---|----------|--------|
| D1 | **Blob GC:** After entity removal, orphaned blobs can be collected | NOT IMPLEMENTED |
| D2 | **Living docs accuracy:** Generated docs match actual graph state after mutations | TESTED (unit only) |
| D3 | **Placement decision for all languages:** Verify generated file paths match language conventions | PARTIAL (unit tests for 5 languages) |

---

## 5. Recommended Fix Order

### Phase 1: Stop the bleeding (Critical data integrity)

1. **Fix C1/C2:** Wire blob_hash into entity metadata during `reconcile_file_edit`. When `IndexPipeline.index_file` returns a `blob_hash`, store it in `entity.metadata.extra["blob_hash"]`. This makes the blob fallback in `extract_entity_body` functional.
   - File: `crates/kin-reconcile/src/reconciler.rs` (~10 lines)

2. **Fix C3:** Implement blob-based body extraction in `project_file_from_entities`. Replace `let _ = blob_store` with actual blob lookup when span extraction fails.
   - File: `crates/kin-projection/src/engine.rs:174-191` (~15 lines)

3. **Fix C1 fallback:** Change `extract_entity_body` to return an error instead of falling back to signature. The signature fallback is always wrong.
   - File: `crates/kin-reconcile/src/reconciler.rs:690-695` (~5 lines)

### Phase 2: Transactionality (Critical correctness)

4. **Fix H1:** Add rollback support to `reconcile_file_edit`. Snapshot overlay/LKG state at entry, restore on error.
   - File: `crates/kin-reconcile/src/reconciler.rs:127-295` (~30 lines)

5. **Fix H2:** Improve projection atomicity with a write-ahead journal or at minimum log which files were committed before a failure so they can be identified.
   - File: `crates/kin-projection/src/engine.rs:134-148` (~20 lines)

### Phase 3: Identity and relations (High correctness)

6. **Fix H4:** Enhance entity matching to use fingerprint-based identity (signature_hash) as a secondary match when name changes but structure is similar. This is the semantic rename detection problem.
   - File: `crates/kin-reconcile/src/reconciler.rs:187-243`

7. **Fix H5:** Track existing relations per file, diff against newly parsed relations, and add removes to the overlay for relations that disappeared.
   - File: `crates/kin-reconcile/src/reconciler.rs:262-265`

8. **Fix L5:** Implement ModifyDelete detection in `analyze_merge`.
   - File: `crates/kin-reconcile/src/reconciler.rs:444-531`

### Phase 4: Test coverage (Verification)

9. **Write A1:** Full round-trip integration test (the single most important test for Kin)
10. **Write B1:** Rename detection test
11. **Write B2:** Stale relation cleanup test
12. **Write B5:** File removal cascade test
13. **Write B8:** Overlay transactionality test
14. **Write A5:** Branch switch projection test with blob fallback

### Phase 5: Edge cases and polish

15. Fix M1 (overlapping span validation)
16. Fix M2 (FilePathId consistency)
17. Fix M3 (stale temp file cleanup)
18. Fix M4 (import byte_range update)
19. Fix M5 (partial parse recovery)

---

## 6. What Is Already Solid

- **Splice engine** (`splice.rs`): Clean, correct, well-tested. Back-to-front application with pre-validation is the right design.
- **Two-phase temp file writes**: The temp-then-rename pattern is correct for single-file atomicity. The distinct temp path fix for same-stem files is good.
- **LKG semantics**: The design is correct -- broken ASTs don't corrupt the graph. Implementation is clean and well-tested.
- **Collision/traffic checking**: Intent-based collision detection is well-designed. Session self-exclusion, hard/soft lock priority, scope-based checking are all correct.
- **Merge analysis**: Divergent/Convergent/AddAdd/SignatureChange/VisibilityChange detection is thorough for implemented cases.
- **Layout building**: Trivia interleaving is correct. Entity ID remap during reconcile (stable IDs in layout) works and is tested.
- **Cache key fix**: Phase 3 of projection correctly carries the original `FilePathId` through the pending tuple, avoiding strip_prefix mismatch.

---

## 7. Strategic Assessment

Projection and reconciliation are **architecturally sound** but have **critical gaps in the body extraction pipeline**. The most dangerous issue is the trio of C1/C2/C3: the blob store -- intended as the authoritative source of entity body text -- is not wired into the write path, making the read path dead code, and leaving the signature fallback as the only safety net (which silently destroys data).

The good news is that these are **wiring bugs, not design bugs**. The blob store exists, works correctly, and is already used by `IndexPipeline`. The fix is to propagate the blob_hash through to entity metadata and use it in the extraction chain. This is a small, focused fix with high impact.

The second major gap is **test coverage**. The most important property of Kin -- that graph and files stay in sync across the full edit cycle -- is not verified by any integration test. Writing the full round-trip test (A1) should be the immediate next step after fixing the body extraction pipeline.

**Bottom line:** Projection/reconcile cannot be called "hardened" until C1/C2/C3 are fixed and A1 is passing. Everything else is important but secondary.
