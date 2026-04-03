# Search & Retrieval Policy Audit

**Date:** 2026-03-17
**Scope:** All search, retrieval, ranking, and embedding implementations across the Kin ecosystem

**Historical note:** Later sections still inventory deprecated consumers such as
`kin-pilot` and `kin-code` because they existed at audit time. Treat those
references as historical implementation context, not active product surfaces.

---

## 1. Inventory of Search/Retrieval Implementations

### 1.1 kin-db: TextIndex (Tantivy full-text)

**Location:** `kin-db/crates/kin-db/src/search/text.rs`

| Aspect | Detail |
|--------|--------|
| **Engine** | Tantivy, in-memory RAM directory |
| **Indexed fields** | `name` (TEXT), `signature` (TEXT), `file_path` (TEXT), `kind` (TEXT), `id` (STRING, stored) |
| **Query API** | `fuzzy_search(query_str, limit) -> Vec<(EntityId, f32)>` |
| **Ranking** | Tantivy's default BM25 scoring via `TopDocs::order_by_score()` |
| **Data source** | Entity objects upserted individually; writes commit per-upsert |
| **Output** | Entity ID + raw BM25 score; no explanation or provenance |
| **Explanation** | None |

**Notes:** The per-upsert commit pattern is correct for the current batch-write/continuous-read model but would be a bottleneck for streaming ingestion. The query parser searches across name, signature, and file_path fields with equal weight.

### 1.2 kin-db: VectorIndex (HNSW via usearch)

**Location:** `kin-db/crates/kin-db/src/vector/hnsw.rs`

| Aspect | Detail |
|--------|--------|
| **Engine** | usearch (HNSW approximate nearest-neighbor) |
| **Metric** | Cosine similarity (`MetricKind::Cos`) |
| **Quantization** | F32 (no compression) |
| **HNSW params** | connectivity=16, expansion_add=128, expansion_search=64 |
| **Query API** | `search_similar(embedding, limit) -> Vec<(EntityId, f32)>` |
| **Data source** | Pre-computed embeddings upserted per-entity |
| **Output** | Entity ID + cosine distance; no explanation |
| **Explanation** | None |

**Notes:** Auto-grows capacity (doubles when full, min 1024). Manages EntityId-to-u64 key mapping internally. Returns distance (not similarity); callers must compute `1.0 - distance`.

### 1.3 kin-db: CodeEmbedder (BGE-small-en-v1.5 via Candle)

**Location:** `kin-db/crates/kin-db/src/embed/mod.rs`

| Aspect | Detail |
|--------|--------|
| **Model** | BAAI/bge-small-en-v1.5 (384 dimensions, ~130 MB) |
| **Runtime** | Candle (Rust-native ML); Metal > CUDA > CPU fallback |
| **Input format** | `"{name} {signature} {body_preview}"` concatenated |
| **Pooling** | Mean pooling with attention mask, L2-normalized |
| **Batch support** | Yes, via `embed_batch()` |

**Notes:** This is the only embedding provider in the ecosystem. All vector search depends on this model. The input format is deliberately simple (space-joined fields); no special tokens or structured prompts.

### 1.4 kin-db: InMemoryGraph / IndexSet (name/file/kind indexes)

**Location:** `kin-db/crates/kin-db/src/engine/index.rs`, `kin-db/crates/kin-db/src/engine/graph.rs:739`

| Aspect | Detail |
|--------|--------|
| **Engine** | hashbrown::HashMap with lowercased name keys |
| **Query API** | `query_entities(EntityFilter) -> Vec<Entity>` via `GraphStore` trait |
| **Pattern matching** | `by_name_pattern()`: prefix (`foo*`), suffix (`*foo`), or substring (contains) |
| **Ranking** | None -- returns in arbitrary HashMap iteration order |
| **Filtering** | Kind, language, file path, name pattern |
| **Explanation** | None |

**Notes:** This is the primary search path used by `kin search` CLI. Results are unranked. The `query_entities` method uses rayon for parallel filtering. Index is used for fast candidate narrowing, then full entity filter is applied.

### 1.5 kin-db: ReadIndex (bincode-serialized slim index)

**Location:** `kin-db/crates/kin-db/src/storage/index.rs`

| Aspect | Detail |
|--------|--------|
| **Format** | Custom binary (KIDX magic + bincode body) |
| **Size** | ~27 MB vs ~73 MB full snapshot |
| **Query API** | `search_by_name(pattern) -> Vec<u32>` (substring match) |
| **Ranking** | None |
| **Used by** | `kin search` fast path (when no `--show-body`, no kind/language filters) |

**Notes:** Read-only acceleration layer. Duplicates the substring matching logic from IndexSet but operates on a flat array with u32 indices. No Tantivy or vector search integration.

### 1.6 kin/crates/kin-ranking (bundled ranking crate)

**Location:** `kin/crates/kin-ranking/src/lib.rs`

| Aspect | Detail |
|--------|--------|
| **Status** | **Bundled Kin policy layer** |
| **Types** | `SearchQuery`, `CandidateSignals`, `SearchCandidate`, `RankedResult` |
| **Signals** | lexical (0.30), semantic (0.28), graph (0.18), proof (0.16), provenance (0.08) |
| **Proof bias** | 1.35x boost when `require_proof = true` |
| **Ranking** | Weighted linear combination of 5 signals |
| **Explanation** | Yes: `explanation_for()` lists which signals contributed (e.g. "ranked via lexical, semantic, proof") |
| **Limit** | Configurable via `SearchQuery.limit` (default 20) |

**Notes:** This is the Kin-local ranking and explanation layer. It should be described separately from the extracted `kin-search` repo, which owns low-level lexical retrieval primitives rather than final Kin search policy.

### 1.7 kin CLI: search command

**Location:** `kin/crates/kin-cli/src/commands/search.rs`

| Aspect | Detail |
|--------|--------|
| **Text search** | Calls `graph.query_entities(EntityFilter)` -- uses kin-db's IndexSet, NOT Tantivy |
| **Semantic search** | `run_semantic()` builds a VectorIndex from stored JSON embeddings, embeds query via CodeEmbedder, runs HNSW search |
| **Fast path** | Uses `ReadIndex.search_by_name()` when no --show-body |
| **Precision mode** | `KIN_SEARCH_MODE=precise` enforces exact names, limit<=5, max 2 OR terms |
| **Ranking** | Text: none (unranked). Semantic: cosine distance only |
| **Explanation** | None (just prints similarity score for semantic mode) |

**Key gap:** The CLI search does NOT use `kin-search`'s multi-signal ranking. It does NOT use kin-db's Tantivy TextIndex either. It uses the simplest possible path: HashMap-based substring matching on entity names.

### 1.8 kin-pilot: Kin tool handlers (CLI delegation)

**Location:** `kin-pilot/codex-rs/core/src/tools/handlers/kin.rs`

| Aspect | Detail |
|--------|--------|
| **kin_search tool** | Shells out to `kin search <query> [--show-body] [--limit N]` |
| **kin_trace tool** | Shells out to `kin trace <query> [--compact]` |
| **kin_context tool** | Shells out to `kin context <entity>` |
| **Search implementation** | None -- pure delegation to CLI binary |
| **Ranking** | Inherits whatever the CLI returns (currently unranked text search) |
| **Explanation** | None beyond what CLI prints |

**Notes:** Auto-allowed via exec policy (`kin_exec_policy.rs`). The kin_search tool has a default limit of 5. No independent search logic; entirely depends on the `kin` binary.

### 1.9 kin-code: VS Code extension graph search

**Location:** `kin-code/extensions/kin/src/extension.js:287-313`, `kin-code/extensions/kin/src/graph-search.js`

| Aspect | Detail |
|--------|--------|
| **Implementation** | `runKinSearch()` spawns `kin search <query>` via `cp.spawnSync` |
| **Output parsing** | Regex-based stdout parser (`parseKinSearchOutput`) extracting name, kind, language, file, optional score |
| **UI** | `KinGraphSearchProvider` tree view with results shown in sidebar |
| **Ranking** | None -- inherits CLI's unranked output; displays score if present (semantic mode) |
| **Explanation** | None |

**Notes:** The parser regex expects the format `  [score] name (kind, language) - file`. This is fragile and coupled to CLI output format. No independent search logic.

---

## 2. Shared vs. Duplicated Analysis

### Name-based substring matching (DUPLICATED 3x)

| Implementation | Location | Mechanism |
|----------------|----------|-----------|
| `IndexSet.by_name_pattern()` | `kin-db/src/engine/index.rs:91` | HashMap iteration + lowercase contains/prefix/suffix |
| `ReadIndex.search_by_name()` | `kin-db/src/storage/index.rs:199` | HashMap iteration + lowercase contains |
| `query_entities()` dispatcher | `kin-db/src/engine/graph.rs:744` | Delegates to `by_name_pattern()` |

All three do case-insensitive substring matching. ReadIndex duplicates IndexSet's logic in a slightly different data structure. They should share a common matching function.

### Ranking logic (FRAGMENTED)

| Component | Ranking | Signals used |
|-----------|---------|-------------|
| kin-search (unused) | Weighted linear: lex 0.30 + sem 0.28 + graph 0.18 + proof 0.16 + prov 0.08 | 5 signals |
| kin-db TextIndex | BM25 (Tantivy default) | 1 signal (text relevance) |
| kin-db VectorIndex | Cosine distance | 1 signal (semantic similarity) |
| kin CLI text search | None | 0 signals |
| kin CLI semantic search | Cosine distance only | 1 signal |

The intended ranking model (kin-search) defines 5 signals. The actual search path uses 0-1 signals. The gap is severe.

### Embedding pipeline (SINGLE SOURCE, used correctly)

CodeEmbedder in kin-db is the sole embedding provider. The CLI semantic search correctly loads stored embeddings and uses CodeEmbedder for query embedding. No duplication here.

---

## 3. KinDB Integration Gap Assessment

The gap between kin-search (the ranking crate) and kin-db (the database) is the central blocker:

### What kin-search needs but doesn't have

1. **No dependency on kin-db** -- `Cargo.toml` has zero deps; it can't query the graph
2. **No CandidateSignals builder** -- nothing converts kin-db query results into the `CandidateSignals` struct
3. **No integration of kin-db's TextIndex** -- the Tantivy BM25 score should feed into `signals.lexical`
4. **No integration of kin-db's VectorIndex** -- cosine similarity should feed into `signals.semantic`
5. **No graph signal computation** -- `signals.graph` is defined but nothing computes it (e.g., graph distance, relation density)
6. **No proof signal computation** -- `signals.proof` is defined but nothing connects to kin-db's verification system (TestCase, VerificationRun, run_proves_entity)
7. **No provenance signal computation** -- `signals.provenance` is defined but nothing connects to kin-db's provenance system (Actor, Approval, AuditEvent)

### What's needed to close the gap

```
kin-search should depend on kin-db (or on a trait that kin-db implements):

1. Add kin-db as dependency to kin-search/Cargo.toml
2. Create a SignalBuilder that takes:
   - TextIndex.fuzzy_search() result -> lexical signal (normalize BM25 to 0..1)
   - VectorIndex.search_similar() result -> semantic signal (1.0 - distance)
   - InMemoryGraph traversal -> graph signal (hop count, relation density)
   - Verification coverage -> proof signal (test_covers_entity, run_proves_entity)
   - Provenance data -> provenance signal (actor approvals, audit trail)
3. Replace kin CLI's query_entities() call with a ranked search path
4. Expose RankedResult (with explanation) through CLI output format
```

### No crate depends on kin-search today

```
kin-search consumers: 0
kin-search is workspace member: yes
kin-search has tests: yes (passing)
kin-search is used by kin-cli: NO
kin-search is used by kin-pilot: NO (delegates to CLI)
kin-search is used by kin-code: NO (delegates to CLI)
```

---

## 4. Fan-out and Output Size Analysis

### Current search output sizes

| Path | Typical output | Bounded? |
|------|---------------|----------|
| `kin search <name>` | All entities matching substring | No -- can return hundreds for broad patterns |
| `kin search <name> --show-body` | All matching entities + source code | No (though `KIN_SEARCH_MODE=precise` caps at 5) |
| `kin search --semantic <query>` | Top N by cosine | Yes (limit param) |
| kin-pilot kin_search tool | Defaults to limit=5 | Yes |
| kin-code graph search | All results from CLI | No |

### Fan-out concerns

1. **Unbounded text search:** `kin search` without `--limit` can return the entire entity set for broad patterns like "get" or "set". The precision mode guard (`KIN_SEARCH_MODE=precise`) is only active in benchmarks, not by default.

2. **--show-body amplification:** Each result with `--show-body` reads the file from disk and extracts source. For 100+ results, this produces massive output. Body limit defaults to 10 lines but result count is unbounded.

3. **CLI-to-Codex pipeline:** When kin-pilot calls `kin search`, the entire stdout is captured and sent to the LLM as tool output. Large result sets waste context window tokens.

4. **Semantic search is correctly bounded** but requires pre-computed embeddings and model loading (~2-3 seconds startup).

### Recommended output budget

For LLM consumers (kin-pilot), search output should be hard-capped at:
- **5 results** with source body
- **20 results** without source body
- **Ranked by relevance** so truncation doesn't lose the best results

---

## 5. Explanation/Provenance in Search Results -- Current State

### Where explanation exists

| Component | Explanation | Format |
|-----------|-------------|--------|
| kin-search (unused) | Yes | `"ranked via lexical, semantic, proof"` -- lists contributing signals |
| kin-db TextIndex | No | Returns raw BM25 score only |
| kin-db VectorIndex | No | Returns cosine distance only |
| kin CLI text search | No | No score or explanation in output |
| kin CLI semantic search | Partial | Prints similarity score but no explanation of why |
| kin-pilot | No | Passes through CLI output |
| kin-code | No | Parses optional score from CLI output |

### Assessment

Explanation/provenance is designed in kin-search but never reaches the user. The `RankedResult.explanation` field produces human-readable strings like "ranked via lexical, semantic, proof" but this code is never called by anything.

For trust, users (especially AI agents using kin-pilot) need to understand WHY a result ranked highly. Without explanation, the agent cannot assess whether a search result is trustworthy or whether it should refine its query.

---

## 6. Concrete Recommendations (Prioritized)

### P0: Wire kin-search into the CLI search path

**Effort:** Medium (3-5 days)
**Impact:** Transforms search from unranked substring matching to multi-signal ranked results

1. Add `kin-db` as a dependency of `kin-search`
2. Create `SignalBuilder` in kin-search that computes `CandidateSignals` from:
   - kin-db TextIndex BM25 score (lexical)
   - kin-db VectorIndex cosine similarity (semantic)
   - Stub for graph/proof/provenance (return 0.0 initially)
3. Replace `kin-cli/src/commands/search.rs` `run_with_store()` to:
   - Call TextIndex + VectorIndex for candidates
   - Build CandidateSignals per candidate
   - Call `rank_candidates()` from kin-search
   - Output RankedResult with explanation
4. Add `--explain` flag to CLI to show explanation string

### P1: Hard-cap search output for LLM consumers

**Effort:** Small (1 day)
**Impact:** Prevents context window blowout in kin-pilot

1. Add `--limit` flag to text search (not just semantic)
2. Default to 20 for CLI, 5 for kin-pilot tool handler
3. When truncating, display `(showing N of M results; refine query for more)`
4. Apply limit AFTER ranking (requires P0)

### P2: Consolidate duplicate substring matching

**Effort:** Small (1 day)
**Impact:** Code hygiene; single place to change matching behavior

1. Extract a `fn name_matches(name: &str, pattern: &str) -> bool` into kin-db
2. Have IndexSet, ReadIndex, and query_entities all use it
3. Remove the duplicated lowercasing and contains/prefix/suffix logic

### P3: Compute graph signal

**Effort:** Medium (2-3 days)
**Impact:** Search quality -- entities with more connections rank higher

1. For each candidate, compute graph density:
   - Count incoming + outgoing relations
   - Normalize by max in result set
2. Optionally weight by relation kind (Calls > References)
3. Feed into `CandidateSignals.graph`

### P4: Compute proof signal

**Effort:** Medium (2-3 days)
**Impact:** Proof-aware search -- verified entities rank higher

1. For each candidate entity, check:
   - Number of TestCases covering it (`test_covers_entity`)
   - Number of passing VerificationRuns (`run_proves_entity`)
2. Normalize to 0..1 range
3. Feed into `CandidateSignals.proof`

### P5: Compute provenance signal

**Effort:** Small (1-2 days)
**Impact:** Trust -- entities with clear ownership/review rank higher

1. For each candidate, check:
   - Has associated Actor via SemanticChange
   - Has Approval records
2. Binary or graded signal
3. Feed into `CandidateSignals.provenance`

### P6: Expose search via kin-db's GraphStore trait

**Effort:** Medium (2-3 days)
**Impact:** Any GraphStore consumer gets ranked search automatically

1. Add `search()` method to GraphStore trait returning `RankedResult`
2. InMemoryGraph implements it using TextIndex + VectorIndex + kin-search ranking
3. All consumers (CLI, kin-pilot, kin-code) get ranked search through the same API

---

## 7. Architecture Sketch: Unified Search Policy

```
                    ┌──────────────────────────────────────────┐
                    │            kin-search crate               │
                    │  ┌──────────────────────────────────────┐ │
                    │  │  rank_candidates(query, candidates)  │ │
                    │  │  ┌─────────┐ ┌─────────┐ ┌────────┐ │ │
                    │  │  │ lexical │ │semantic │ │ graph  │ │ │
                    │  │  │  0.30   │ │  0.28   │ │  0.18  │ │ │
                    │  │  └────┬────┘ └────┬────┘ └───┬────┘ │ │
                    │  │  ┌────┴────┐ ┌────┴────┐ ┌───┴────┐ │ │
                    │  │  │ proof  │ │provnce │ │explain │ │ │
                    │  │  │  0.16  │ │  0.08  │ │  gen   │ │ │
                    │  │  └────────┘ └────────┘ └────────┘ │ │
                    │  └──────────────────────────────────────┘ │
                    └─────────────────┬────────────────────────┘
                                      │
                    ┌─────────────────┼────────────────────────┐
                    │            SignalBuilder                   │
                    │                 │                          │
                    │  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
                    │  │TextIndex │  │VectorIdx │  │  Graph   │ │
                    │  │(Tantivy) │  │ (HNSW)   │  │traversal│ │
                    │  │ BM25     │  │ cosine   │  │ density │ │
                    │  └────┬─────┘  └────┬─────┘  └────┬────┘ │
                    │       │             │             │       │
                    │  ┌────┴─────┐  ┌────┴─────┐  ┌───┴────┐ │
                    │  │Verifier  │  │Provenance│  │        │ │
                    │  │coverage  │  │ actors   │  │        │ │
                    │  └──────────┘  └──────────┘  └────────┘ │
                    └─────────────────┬────────────────────────┘
                                      │
                    ┌─────────────────┼────────────────────────┐
                    │            kin-db crate                    │
                    │  GraphStore::search(query) -> RankedResult │
                    └─────────────────┬────────────────────────┘
                                      │
              ┌───────────────────────┼────────────────────────┐
              │                       │                        │
     ┌────────┴─────┐     ┌──────────┴────────┐     ┌────────┴──────┐
     │  kin CLI     │     │   kin-pilot        │     │   kin-code    │
     │  search cmd  │     │   kin_search tool  │     │   tree view   │
     │  (terminal)  │     │   (shell to CLI)   │     │   (shell CLI) │
     └──────────────┘     └───────────────────┘     └───────────────┘
```

### Data flow (target state)

1. **Query arrives** at any consumer (CLI, kin-pilot tool, kin-code extension)
2. **Consumer calls** `GraphStore::search(SearchQuery)` or `kin search` CLI
3. **SignalBuilder** fans out to:
   - TextIndex for lexical candidates + BM25 scores
   - VectorIndex for semantic candidates + cosine scores
   - Graph traversal for relation density
   - Verification system for proof coverage
   - Provenance system for actor/approval status
4. **kin-search** merges signals, applies weights, generates explanations
5. **RankedResult** returned with score + explanation string
6. **Consumer** presents results (truncated to limit) with optional explanation

### Key design principles

- **Single ranking policy:** All consumers get the same ranking from kin-search
- **Signal independence:** Each signal can be computed independently (parallel-friendly)
- **Explanation by default:** Every result carries a human-readable explanation
- **Proof-awareness:** Verified entities surface higher when `require_proof = true`
- **Bounded output:** Hard limit on results prevents fan-out blowout
- **CLI-stable format:** kin-code's regex parser must not break when explanation is added (add explanation as a new line, not inline)
