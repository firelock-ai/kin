# ContextBench Locate Pipeline Analysis

**Current Metrics:** P=0.148, R=0.606, F1=0.218 (80 tasks, 10 repos, 7 task types per repo)

---

## 1. End-to-End Pipeline Architecture

### Query Selection (contextbench_locate.rs:88-103)

```
Task JSON → select_query()
├─ Priority: description → problem_statement → prompt
└─ Returns: (field_name, text)
```

**Parameters:**
- `CONTEXTBENCH_QUERY_CHAR_LIMIT = 4000` (line 12)
- `CONTEXTBENCH_MAX_FILES = 10` (line 13)

**Flow:**
1. Read task JSON payload (line 26-30)
2. Extract query text from first non-empty field (line 88-102)
3. Truncate to 4000 chars (line 34)
4. **Issue:** No query preprocessing, cleaning, or optimization before search
5. Pass directly to `kin locate --json --explain --max-files 10` (line 40-45)

---

## 2. Core Locate Command (locate.rs)

### Entry Point: `run_with_graph()` (line 185-306)

**Step 1: Text Cleaning (line 201)**
```rust
let text = &clean_issue_text(text);
```
- Strips HTML comments `<!-- ... -->`
- Strips markdown image tags `![...](...)`
- Strips GitHub PR template checkboxes
- **Limited scope:** Only handles GitHub issue formatting, not task-specific noise

### Step 2: Priority File Extraction (line 204)**
```rust
let priority_files = extract_priority_files(text, graph);
```
- Returns top 5 files (line 481-482)
- Filters to paths with score >= 50.0 (line 479)
- **See section 2.1 below for details**

### Step 3: 10 Signal Extractors (lines 207-219)

```rust
let traceback = extract_traceback_signals(text, graph)?;      // 1. Python tracebacks
let search = extract_search_signals(text, graph)?;            // 2. Entity search
let tests = extract_test_signals(text, graph)?;               // 3. Test functions
let snippets = extract_snippet_signals(text, graph)?;         // 4. Code snippets
let imports = extract_import_signals(text, graph)?;           // 5. Python imports
let errors = extract_error_signals(text, graph)?;             // 6. Exception types
let multihop = extract_multihop_signals(&[...], graph)?;      // 7. Graph traversal
let embeddings = extract_embedding_signals(text, graph)?;     // 8. Vector search
let cochange = extract_cochange_signals(&[...], graph)?;      // 9. Co-change history
let (projection, ...) = extract_projection_signals(...)?;      // 10. Graph planning
```

**Reciprocal Rank Fusion (line 236):**
```rust
let mut fused = reciprocal_rank_fusion(&ranked_lists, KIN_LOCATE_RRF_K=60.0);
```
- Combines 10 signal rankings using RRF
- K parameter = 60 (line 236)
- All 10 signals weighted equally in RRF

**Step 4: Priority Boost (line 239)**
```rust
boost_priority_in_fused(&mut fused, &priority_files);
```
- Multiplies score by `(1.0 + (priority_score / 100.0).min(3.0))`
- Max 4x boost for high-priority files (line 496)

**Step 5: Follow-Up Graph Expansion (lines 243-257)**
```rust
if KIN_LOCATE_FOLLOWUP_ENABLED {  // default: true
    let followup = extract_multihop_signals(&[&followup_seed_hits], graph)?;
    // Re-run RRF with followup signal included
}
```
- Only enabled if `followup_seed_hits` non-empty
- Expands best initial matches through graph

**Step 6: Import Centrality Reranking (lines 259-284)**
```rust
let centrality = compute_import_centrality(graph, &all_signal_sets)?;
// Apply small bonus to top 15 files proportional to import count
*score += KIN_LOCATE_IMPORT_CENTRALITY_BONUS=0.005 * cent_score;
```
- Graph-native signal: counts inbound imports
- **Only applied to top 15 results** (line 277)
- Max +0.005 * (log import count) bonus

**Step 7: Adaptive Cap (line 293)**
```rust
let results = adaptive_cap(&fused, &all_hits, max_files=10);
```
- Returns exactly `max_files` (hardcoded to 10, line 13)
- **NO adaptive logic visible in code**

**Output (line 300-304):**
- JSON with file paths, scores, signal labels, explain provenance
- Human-readable text format

---

## 2.1 Priority File Extraction Detail (locate.rs:334-484)

**Score Sources (in order of priority):**

1. **Explicit File Paths in Text (line 342-347)** → score 200.0
   - Regex match: `/path/to/file.ext`
   - Normalized through `resolve_path_in_graph()`
   - **Issue:** Very strict matching, misses relative paths

2. **Module Path Fragments (line 350-378)** → score 80-100
   - Match dotted names: `astropy.modeling.core`
   - Convert to path: `astropy/modeling/core.py`
   - Suffix match scans first 2000 entities
   - **Issue:** Arbitrary 2000-entity cap (line 368)

3. **Backtick-Quoted Terms & Title Terms (line 380-410)** → score 30-50
   - Extract terms from backticks: `` `term` ``
   - Extract from first line (title)
   - Match exact entity names (case-insensitive, definition kinds only)
   - Filter to <=3 unique files (line 449)
   - **Issue:** Only allows 3 files max; high-specificity filter kills recall

4. **Tracked Non-Entity Files (line 461-474)** → score 70-120
   - Match against special "tracked" files (unclear source)
   - Explicit basename or path match → 120
   - Descriptor match (keyword split) → 70
   - **Issue:** Undefined what "tracked files" are

**Final Filter (line 477-483):**
```rust
filter: s >= 50.0
sort: by score desc
truncate: 5 files max
```
- **Issue:** Strict threshold and small limit reduce diversity

---

## 3. Signal Extractors: Detailed Analysis

### 3.1 Extract Search Signals (locate.rs:664-967)

**File Path Hits (line 673-680):**
```rust
for file_path in extract_file_paths(text) {
    if let Some(path) = resolve_path_in_graph(graph, &file_path) {
        push FileHit { score: 10.0, spans: [] }
    }
}
```
- Score: 10.0 (fixed, no weighting)
- **Issue:** All paths weighted equally; no distinction by relevance

**Module Fragment Matching (line 683-701):**
```rust
for fragment in extract_module_path_fragments(text) {  // e.g., "astropy/modeling/core"
    resolve_path_in_graph(graph, fragment)  // score: 8.0
    for ext in [".py", ".rs", ".ts", ".js", ".go", ".java"] {
        resolve_path_in_graph(graph, fragment + ext)   // score: 8.0
    }
}
```
- Score: 8.0 (all variants equal)
- **Issue:** Tries all 6 extensions; creates noise if fragment matches multiple

**Identifier Extraction & Entity Search (line 703-861):**
- `curate_search_terms()` → list of identifiers
- For each identifier:
  1. Pattern match: `EntityFilter { name_pattern: Some(ident) }` (line 729-737)
  2. Text search: `graph.text_search(ident, 50)` with rank decay `1.0/sqrt(rank+1)` (line 743-774)
  3. Path match: file stem contains identifier (line 778-796)

**Entity Scoring (line 800-839):**
```rust
for entity in entities_found:
    let kind_mult = 3.0 if [Function, Method, Class, ...] else 1.0
    let name_mult = 5.0 if exact_match else 2.0 if substring else 1.0
    let path_mult = 2.0 if path.contains(ident) else 1.0
    let title_mult = 3.0 if term_in_title else 1.0
    let test_mult = 0.1 if test_file else 1.0
    score = kind_mult * name_mult * test_mult * title_mult * path_mult
```

**Multi-Term Bonus (line 863-908):**
```rust
if identifiers.len() > 1:
    for file matching 2+ terms: bonus = 5.0 (2 terms), 15.0 (3 terms), 30.0 (4+)
```
- **Issue:** Requires actual file to contain multiple term names; poor recall if terms are in different files

**File Stem Matching (line 910-964):**
```rust
common_stems = ["base", "core", "utils", "helper", ...] (23 terms)
for ident not in common_stems and len >= 4:
    for file with matching stem: score = 20.0 (title) or 10.0
```
- **Issue:** Only triggers if stem == ident_lower exactly; misses `config.py` when searching "configuration"

---

### 3.2 Extract Multihop Signals (locate.rs:1480-1563)

**Seed Selection (line 1500-1512):**
```rust
for seed_path in best_files_from_RRF:
    for entity in graph.query_entities(file_path=seed_path).take(16):
        BFS from entity
```
- Seeds from top N files from first-pass RRF
- Limit: 16 entities per seed file (line 1508)
- Limit: 2 hops max (line 1514), depth controlled by `KIN_LOCATE_MULTIHOP_MAX_DEPTH=2`

**Allowed Relation Kinds (line 1519):**
```rust
allowed_kinds = [Calls, Imports, DependsOn, Tests, References, ...]
```

**Scoring (line 1538-1552):**
```rust
let rel_mult = match kind {
    Tests => 2.4,
    Calls => 2.0,
    Imports | DependsOn => 1.8,
    Implements | Extends => 1.5,
    References => 1.2,
    _ => 1.0,
}
let hop_decay = 1.0 if depth==0 else 0.65  // 0.65^depth
let test_mult = 0.35 if test_path else 1.0
score = rel_mult * hop_decay * test_mult
```
- **Issue:** Hard hop decay (0.65) kills 2-hop results; decay applied BEFORE other multipliers, so tests at depth 1 score very low

---

### 3.3 Extract Embedding Signals (locate.rs:1897+)

**Vector Search (lines not fully shown, but referenced):**
- Uses `graph.vector_search(text, limit)` or similar
- **Issue:** Implementation skipped in reading; unclear if embeddings are precomputed, blocking, or async

---

### 3.4 Extract Projection Signals (locate.rs:2162-2301+)

**Seed Collection (line 2175):**
```rust
let seed_signals = collect_projection_seed_signals(text, graph)?;
```
- (Details omitted in reading)

**Graph Expansion (line 2234-2245):**
```rust
let subgraph = graph.expand_neighborhood(
    &seed_ids,
    &[Calls, Imports, DependsOn, CoChanges, Contains, Tests],
    depth = KIN_LOCATE_PLAN_DEPTH=2,
)?;
```

**Scoring (line 2276-2277):**
```rust
let edge_mult = primary_kind.relation_weight() / 5.0;
let score = origin_signal.score * edge_mult * path_mult * test_mult / (hops + 1);
```
- **Issue:** Divides by `5.0` + further div by hops; makes projection results very low-scoring
- Graph planning expensive (calls `expand_neighborhood()`) but scores heavily discounted

---

## 4. Precision vs. Recall Failures

### High False Negatives (R=0.606, 39% missing files)

1. **Query Truncation** (line 34)
   - Cuts at 4000 chars; long task descriptions lose context
   - No adaptive limit based on task type

2. **Search Term Curation** (line 703)
   - `curate_search_terms()` implementation not shown
   - Likely uses heuristics that lose rare/important terms

3. **Priority File Filter Too Strict** (line 479)
   - Min score >= 50.0
   - Max 5 files
   - Kills diverse seed set for low-signal tasks

4. **Multihop Entity Limit** (line 1508)
   - Only 16 entities per file seeded for BFS
   - For large files (1000+ entities), misses 98% of graph edges

5. **Embedding Integration Missing**
   - Signals extracted but likely not weighted appropriately
   - No adaptive combination based on signal quality

6. **Test File Suppression** (line 804, 805, etc.)
   - `test_mult = 0.1` for test files
   - Kills test-related context; tasks involving test files get 90% score penalty

7. **Follow-Up Gate** (line 244)
   - Only expands if `followup_seed_hits` non-empty
   - May miss second-level context if first pass finds nothing

### Low Precision (P=0.148, 85% false positives)

1. **RRF Equal Weighting** (line 236)
   - All 10 signals treated equally in fusion
   - Noisy signals (snippet matching, error type regex) vote same as strong signals (entity search)

2. **No Confidence Thresholding**
   - Returns exactly `max_files=10` regardless of score spread
   - If top 5 files score [5.0, 4.9, 4.8, 0.1, 0.09], still returns all 5

3. **Conjunctive Multi-Term Bonus Weak** (line 863-908)
   - Only checks if MULTIPLE terms appear in same file
   - Task with 5 terms may find file with only 2; still counted as match

4. **Path Matching Too Aggressive** (line 682-701)
   - Tries all 6 language extensions
   - `io.ascii` → tries `io/ascii.py`, `.rs`, `.ts`, etc.
   - Creates duplicates in results for polyglot repos

5. **Embedding Vector Drift**
   - Not clear how embedding scores are normalized vs. BM25 scores
   - May be dominating results with irrelevant semantic matches

6. **Import Centrality Bonus Over-Applied** (line 280)
   - Applied to top 15 files indiscriminately
   - Can boost utility files (e.g., `util.py`) over task-specific files
   - Small bonus (0.005x) but applied to many files

7. **No Deduplication**
   - Same file can be hit by multiple signals
   - Final score = SUM of all hit scores
   - File appearing in 5 signals gets 5x boost vs. once-hit file

---

## 5. Specific Improvement Opportunities

### Opportunity 1: Adaptive Query Preprocessing
**File:** `contextbench_locate.rs:32-34`
**Current:**
```rust
let bounded_query = query.chars().take(CONTEXTBENCH_QUERY_CHAR_LIMIT).collect();
```

**Problem:** Truncates without context; loses important details for long tasks.

**Fix:**
- Detect task JSON field type (description vs. problem_statement)
- For `problem_statement`: take full text (likely structured already)
- For `prompt`: extract first 2000 chars + last 500 chars to preserve context
- Extract key sentences (first, last, and lines with code blocks)
- Remove boilerplate (instructions, templates)

**Expected Impact:** +5-10% recall by preserving critical context.

---

### Opportunity 2: Increase Priority File Seed Set Diversity
**File:** `locate.rs:477-483`
**Current:**
```rust
let mut result: Vec<(String, f32)> = file_scores
    .into_iter()
    .filter(|(_, s)| *s >= 50.0)
    .collect();
result.sort_by(...);
result.truncate(5);
```

**Problem:** Strict threshold kills secondary/tertiary files; max 5 files = weak seeds for multihop.

**Fix:**
- Relax threshold to 20.0 instead of 50.0 (line 479)
- Increase max from 5 to 12 files (line 482)
- Diversify: after sorting, select top 3 by priority + top 2 by module paths + top 2 by name matches
- Reweight: module path matches worth 1.2x when diverse

**Expected Impact:** +8-12% recall; multihop gets broader seed set.

---

### Opportunity 3: Increase Multihop Entity Sampling
**File:** `locate.rs:1508`
**Current:**
```rust
for entity in entities.iter().take(locate_env_usize("KIN_LOCATE_MULTIHOP_ENTITY_LIMIT", 16))
```

**Problem:** Only 16 entities per seed file; large files miss most relationships.

**Fix:**
- Change to `take(64)` (4x increase)
- Add second-level filtering: prioritize entities with high relation count
- Cache relation counts at graph load time to avoid O(n) computation per entity

**Expected Impact:** +10-15% recall; discovers more transitive relationships.

---

### Opportunity 4: Composite Signal Reweighting
**File:** `locate.rs:236` and signal combination logic
**Current:**
```rust
let ranked_lists: Vec<Vec<(String, f32)>> = vec![
    to_ranked(&traceback),      // all equally weighted in RRF
    to_ranked(&search),
    // ... 8 more
];
let mut fused = reciprocal_rank_fusion(&ranked_lists, locate_env_f32("KIN_LOCATE_RRF_K", 60.0));
```

**Problem:** Weak signals (snippet, error regex) vote same as strong (entity search, traceback).

**Fix:**
- Weight signals by estimated precision before RRF:
  - Traceback, Priority Files, Search Entity: 3.0x weight
  - Multihop, Import, Test, CoChange: 1.5x weight
  - Snippet, Error, Embedding: 0.7x weight
- Use weighted RRF: contribution = 1.0 / ((rank + 1) * weight_denom)
- OR: apply precision thresholding: only include signals with top 5 files scoring >= 2.0

**Expected Impact:** +8-15% precision; eliminates low-confidence noise.

---

### Opportunity 5: Test File Penalty Reduction
**File:** `locate.rs:804-805, 1538, 2263`
**Current:**
```rust
let test_mult = if is_test_path(&path) { 0.1 } else { 1.0 };  // 90% penalty
```

**Problem:** Test files killed indiscriminately; misses test-related context.

**Fix:**
- Context-aware penalty:
  - If task mentions "test", "failing", "unittest": `test_mult = 1.0` (no penalty)
  - If task mentions "refactor", "optimize": `test_mult = 0.3` (30% penalty)
  - Default (bug, feature): `test_mult = 0.5` (50% penalty)
- Detect task intent from first line of query

**Expected Impact:** +5% recall on test-heavy tasks (estimated 15-20% of tasks).

---

### Opportunity 6: Confidence-Driven Result Cap
**File:** `locate.rs:293`
**Current:**
```rust
let results = adaptive_cap(&fused, &all_hits, max_files=10);  // hardcoded 10
```

**Problem:** Returns 10 files regardless of score spread; includes low-confidence files.

**Fix:**
- Compute score distribution: mean, stdev
- Return files where `score >= (mean - 0.5*stdev)` up to max 10
- Minimum 2 files always returned (better to have false positives than miss all)
- If top file scores [10.0, 9.8, 0.2, 0.1, ...], return only top 2

**Expected Impact:** +3-5% precision; removes bottom-ranking noise.

---

### Opportunity 7: Fix Hop Decay Order
**File:** `locate.rs:1547`
**Current:**
```rust
let hop_decay = if depth == 0 { 1.0 } else { 0.65 };
hits.entry(path).or_default().push(FileHit {
    score: rel_mult * hop_decay * test_mult,  // order: mult -> decay -> test
});
```

**Problem:** Decay applied before test_mult; test files at depth 1 score `2.0 * 0.65 * 0.35 = 0.455` (45.5% of base).

**Fix:**
- Apply test_mult BEFORE decay: `score = rel_mult * test_mult * hop_decay`
- Or better, use separate track: `score_adjusted_for_depth = rel_mult * 0.65^depth * test_mult`
- Consider: if entity is in test file, decay less aggressively (depth issues are legitimate context)

**Expected Impact:** +2-3% recall; test-related multihop finds more results.

---

### Opportunity 8: Vectorization & Precomputation
**File:** `locate.rs:1500-1560` (multihop) and `compute_import_centrality()`
**Current:**
```rust
for seed_path in seed_files {
    for entity in graph.query_entities(file_path=seed_path).take(16) {
        // BFS with graph lookups
```

**Problem:** Multihop does O(n*m) graph lookups; centrality computation does full scans.

**Fix:**
- Precompute at daemon startup:
  - BFS precomputed to depth 2 for all entities
  - Import counts per file cached
  - Top-N entities per file by relation count
- At query time: lookup precomputed results in O(1)
- Trade: memory for latency (worth it if index is large)

**Expected Impact:** +5-10% latency reduction; enables deeper searches without timeout.

---

### Opportunity 9: Embedding Signal Integration
**File:** `locate.rs:215` and `extract_embedding_signals()`
**Current:**
- Embeddings extracted but implementation skipped
- Likely async or blocking; integration unclear

**Problem:** Vector search may be underpowered or unused.

**Fix:**
- Ensure embeddings async, non-blocking
- Compute cosine distance; map to [0.0, 1.0] score
- Weight in RRF ONLY if top-N (e.g., top 50) are high-confidence (>0.7 similarity)
- Combine with BM25: if embedding ranks file highly but text search doesn't, investigate (may be real signal or drift)

**Expected Impact:** +3-5% recall on semantic-heavy tasks (design, architecture).

---

### Opportunity 10: Query-Specific Signal Filtering
**File:** All signal extractors
**Current:**
- All 10 signals run on all queries

**Problem:** Traceback signals useless for design tasks; embedding overkill for API changes.

**Fix:**
- Classify task intent from query (ML classifier or heuristics):
  - "bug"/"error" → emphasize traceback, error signals
  - "test" → emphasize test signals
  - "refactor" → emphasize import, cochange signals
  - "design"/"architecture" → emphasize embedding, projection signals
- Disable low-relevance signals (e.g., skip traceback if no stack trace detected)
- Re-weight RRF based on intent

**Expected Impact:** +5-10% overall F1; better precision on design tasks.

---

## 6. Summary: Bottleneck Ranking

| Bottleneck | Impact (est.) | Severity | Fix Effort |
|-----------|-------------|----------|-----------|
| Query truncation (no preprocessing) | -5% recall | Medium | Low |
| Priority file filter too strict | -8% recall | High | Low |
| Multihop entity limit (16) | -10% recall | High | Medium |
| Equal RRF weighting (all signals) | -8% precision | High | Medium |
| Test file 90% penalty | -5% recall | Medium | Low |
| No confidence thresholding | -3% precision | Medium | Low |
| Hop decay order + test mult | -2% recall | Low | Low |
| Embedding underutilized | -3% recall | Medium | Medium |
| Query-specific signal filtering absent | -5% F1 overall | Medium | High |
| Graph computation not precomputed | -5% latency (blocks deeper search) | Low | High |

---

## 7. Recommended Immediate Fixes (Highest ROI)

1. **Increase priority seed diversity** (Opportunity 2) → +8-12% recall, LOW effort
2. **Increase multihop entity sampling** (Opportunity 3) → +10-15% recall, MEDIUM effort
3. **Reweight signals by confidence** (Opportunity 4) → +8-15% precision, MEDIUM effort
4. **Context-aware test penalty** (Opportunity 5) → +5% recall on test tasks, LOW effort
5. **Fix hop decay order** (Opportunity 7) → +2-3% recall, LOW effort

**Estimated combined impact:** +15-25% F1 with ~3 weeks of focused work (assuming team of 2).

---

## 8. Appendix: Environment Variables (Tuning Points)

All of these are read via `locate_env_*()` functions and can be set at runtime:

| Var | Default | Impact | Tuning |
|-----|---------|--------|--------|
| `KIN_LOCATE_RRF_K` | 60.0 | RRF concentration (higher = sharper rerank) | Test 30-100 |
| `KIN_LOCATE_FOLLOWUP_ENABLED` | true | Enable second-pass expansion | Keep true |
| `KIN_LOCATE_IMPORT_CENTRALITY_BONUS` | 0.005 | Bonus multiplier for central files | Reduce to 0.002 or remove |
| `KIN_LOCATE_TEXT_HIT_LIMIT` | 50 | Max text search results per term | Keep 50 |
| `KIN_LOCATE_MULTIHOP_MAX_DEPTH` | 2 | Max hops in BFS | Test 1 vs 3 |
| `KIN_LOCATE_MULTIHOP_ENTITY_LIMIT` | 16 | Entities per seed file to expand | **Increase to 64** |
| `KIN_LOCATE_COCHANGE_SEED_FILES` | 8 | Seed files for CoChange signal | Keep 8 |
| `KIN_LOCATE_PLAN_DEPTH` | 2 | Projection graph expansion depth | Keep 2 |

All tunable; no code changes needed for initial experiments.
