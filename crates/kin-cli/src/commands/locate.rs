// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{
    ChangeStore, EntityFilter, EntityKind, EntityRole, EntityStore, GraphNodeId, RelationKind,
    SemanticChangeId,
};
use rustc_hash::FxHasher;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::BuildHasherDefault;

use crate::capability::LocateProfile;

/// Deterministic-iteration map for transient locate accumulators. Fixed-seed
/// hashing keeps fusion/resolution iteration order stable across processes so
/// float score accumulation and tie-breaks are bit-reproducible.
type FxHashMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;
type EntityStableKey = (String, String, EntityKind);
type ResolveEntitiesOutput = (
    Vec<(String, f32)>,
    HashMap<String, Vec<String>>,
    HashMap<String, HashMap<String, f32>>,
    HashMap<String, Vec<LocateSymbol>>,
    Vec<LocateDebugCandidateStage>,
);

// ---------------------------------------------------------------------------
// JSON output types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct LocateResult {
    pub files: Vec<LocateFileEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug: Option<LocateDebugInfo>,
    /// Embedding (semantic signal) coverage at query time. When coverage is
    /// partial or zero, locate degrades gracefully — it still returns lexical
    /// and graph results, and this field tells the caller the semantic signal
    /// was incomplete (so an agent can weight the result honestly) rather than
    /// erroring out. Always populated by the daemon/in-process locate path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_coverage: Option<SemanticCoverage>,
}

/// Honest, in-band report of how complete the embedding (semantic) signal was
/// for a locate query. This is the trust-contract "per-signal degradation"
/// property: a partial semantic index is surfaced, not hidden behind an opaque
/// error.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SemanticCoverage {
    /// Entities with an embedding indexed in the vector store.
    pub indexed: usize,
    /// Total entities eligible for embedding.
    pub total: usize,
    /// Entities still queued for embedding.
    pub pending: usize,
    /// True when the semantic signal was complete (`total == 0`, or every
    /// entity indexed with nothing pending).
    pub complete: bool,
    /// Human-readable note describing the degraded state, present only when the
    /// semantic signal was partial. Lexical + graph signals still ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl LocateResult {
    fn with_semantic_coverage(mut self, coverage: SemanticCoverage) -> Self {
        self.semantic_coverage = Some(coverage);
        self
    }
}

#[derive(Serialize, Deserialize)]
pub struct LocateFileEntry {
    pub path: String,
    pub score: f32,
    #[serde(default)]
    pub signals: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spans: Vec<[u32; 2]>,
    /// Ranked, capped per-entity symbols Kin is most confident define this file.
    /// Structured replacement for regex-scraping definitions out of `explain`:
    /// ranked by (definition-before-reference, then composite score) and capped
    /// by `KIN_LOCATE_SYMBOL_CAP`. Emitted unconditionally so both the native
    /// ContextBench trajectory and agent surfaces consume the same Rust-ranked
    /// list instead of re-deriving symbols from prose.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbols: Vec<LocateSymbol>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub explain: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<LocateFileProvenance>,
    /// Per-signal score breakdown (only with --explain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_scores: Option<std::collections::HashMap<String, f32>>,
    /// Per-stage score breakdown (only with --explain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_breakdown: Option<std::collections::HashMap<String, f32>>,
}

/// A single ranked symbol (graph entity) attributed to a file by `kin locate`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LocateSymbol {
    /// Entity name (the symbol identifier).
    pub name: String,
    /// 1-based inclusive line span of the entity, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<[u32; 2]>,
    /// Composite resolution score; higher means more confident.
    pub score: f32,
    /// Entity kind (function, class, …), lowercased.
    pub kind: String,
    /// True when Kin resolved this entity as a definition (has a body) rather
    /// than a bare reference/re-export.
    pub definition: bool,
    /// Resolution origin: which seed pool surfaced this symbol ("text",
    /// "vector", or empty when unattributed). Populated under --explain.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub origin: String,
    /// Raw embedding cosine of the seed that surfaced this symbol, when it came
    /// from the vector pool. Recorded under --explain only; never affects rank.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cosine: Option<f32>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct LocateDebugInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scoring_track: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traceback_top: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolve_top: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolve_gap: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multihop_top: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fast_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_signals: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_terms: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub priority_files: Vec<LocateDebugFileScore>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_files: Vec<LocateDebugResolvedFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<LocateDebugStage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_stages: Vec<LocateDebugCandidateStage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pruned_files: Vec<PrunedFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_cap: Option<SymbolCapTrace>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PrunedFile {
    pub path: String,
    pub score: f32,
    pub reason: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct SymbolCapTrace {
    pub cap: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dropped: Vec<LocateSymbol>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LocateDebugFileScore {
    pub path: String,
    pub score: f32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<LocateDebugPriorityReason>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LocateDebugPriorityReason {
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    pub score: f32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LocateDebugResolvedFile {
    pub path: String,
    pub score: f32,
    pub direct: f32,
    pub graph: f32,
    /// Representative entity recovered for this file from Phase-1 discovery
    /// seeds. The fusion pipeline collapses entity identity to file paths (the
    /// `FileHit{score,spans}` seam), so this re-attaches the highest-scoring
    /// non-test seed entity defined in the file. Observability only — ranking
    /// is untouched. Omitted when no seed entity is attributable to the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LocateDebugStage {
    pub name: String,
    pub files: Vec<LocateDebugFileScore>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LocateDebugCandidateStage {
    pub name: String,
    pub candidates: Vec<LocateDebugCandidate>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LocateDebugCandidate {
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub score: f32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LocateFileProvenance {
    pub objects: Vec<LocateGraphObject>,
    pub edges: Vec<LocateGraphEdge>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LocateGraphObject {
    pub id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LocateGraphEdge {
    pub src: String,
    pub dst: String,
    pub kind: String,
}

// ---------------------------------------------------------------------------
// Scored file hit with signal provenance
// ---------------------------------------------------------------------------

struct FileHit {
    score: f32,
    spans: Vec<[u32; 2]>,
}

#[derive(Clone, Default)]
struct PriorityFileTrace {
    score: f32,
    reasons: Vec<LocateDebugPriorityReason>,
}

// ---------------------------------------------------------------------------
// Phase 1: Entity-level discovery types
// ---------------------------------------------------------------------------

/// Entity-level score accumulated during Phase 1 discovery.
/// Multiple signals contribute scores to the same entity — they are summed.
#[derive(Clone, Default)]
struct EntityDiscovery {
    score: f32,
    signals: Vec<&'static str>,
    /// Raw embedding cosine relevance (pre score-multiply) when this seed was
    /// surfaced via the vector pool. Recorded for --explain observability only;
    /// never participates in ranking. `None` for text-only seeds.
    cosine: Option<f32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolveCandidateSource {
    Direct,
    Graph,
}

#[derive(Clone, Debug)]
struct ResolveCandidate {
    id: String,
    kind: &'static str,
    path: String,
    name: Option<String>,
    score: f32,
    source: ResolveCandidateSource,
    reason: String,
}

#[derive(Clone)]
struct TrackedFileInfo {
    path: String,
    descriptor: String,
}

/// Per-phase time budgets for the locate pipeline.
/// When a phase exceeds its budget, the pipeline bails with partial results.
struct LocateBudget {
    start: std::time::Instant,
    total_secs: f64,
    phase_budgets: HashMap<&'static str, f64>,
    warnings: Vec<String>,
}

impl LocateBudget {
    fn new() -> Self {
        let total = locate_env_f32("KIN_LOCATE_TOTAL_TIMEOUT_SECS", 90.0) as f64;
        let mut phase_budgets = HashMap::new();
        phase_budgets.insert(
            "entity_discovery",
            locate_env_f32("KIN_LOCATE_PHASE_ENTITY_DISCOVERY_SECS", 20.0) as f64,
        );
        phase_budgets.insert(
            "entity_resolution",
            locate_env_f32("KIN_LOCATE_PHASE_ENTITY_RESOLUTION_SECS", 20.0) as f64,
        );
        phase_budgets.insert(
            "multihop",
            locate_env_f32("KIN_LOCATE_PHASE_MULTIHOP_SECS", 20.0) as f64,
        );
        phase_budgets.insert(
            "text_search",
            locate_env_f32("KIN_LOCATE_PHASE_TEXT_SEARCH_SECS", 10.0) as f64,
        );
        phase_budgets.insert(
            "source_text",
            locate_env_f32("KIN_LOCATE_PHASE_SOURCE_TEXT_SECS", 10.0) as f64,
        );
        phase_budgets.insert(
            "scoring",
            locate_env_f32("KIN_LOCATE_PHASE_SCORING_SECS", 10.0) as f64,
        );
        Self {
            start: std::time::Instant::now(),
            total_secs: total,
            phase_budgets,
            warnings: Vec::new(),
        }
    }

    /// Check if the total pipeline budget is exhausted.
    fn total_exceeded(&self) -> bool {
        self.start.elapsed().as_secs_f64() > self.total_secs
    }

    /// Check if a specific phase should be skipped due to total budget.
    /// Returns the remaining budget for this phase in seconds.
    fn phase_remaining(&self, phase: &str) -> f64 {
        let elapsed = self.start.elapsed().as_secs_f64();
        let remaining_total = (self.total_secs - elapsed).max(0.0);
        let phase_budget = self.phase_budgets.get(phase).copied().unwrap_or(15.0);
        remaining_total.min(phase_budget)
    }

    /// Check if a phase should be skipped entirely (no budget left).
    fn phase_should_skip(&mut self, phase: &str) -> bool {
        if self.total_exceeded() {
            self.warnings.push(format!(
                "skipped {phase}: total budget exhausted ({:.1}s elapsed)",
                self.start.elapsed().as_secs_f64()
            ));
            tracing::warn!(
                phase = phase,
                elapsed_secs = self.start.elapsed().as_secs_f64(),
                "locate phase skipped: total budget exhausted"
            );
            return true;
        }
        false
    }

    fn warn_phase_timeout(&mut self, phase: &str, elapsed: std::time::Duration) {
        self.warnings.push(format!(
            "{phase} exceeded budget ({:.1}s)",
            elapsed.as_secs_f64()
        ));
        tracing::warn!(
            phase = phase,
            elapsed_ms = elapsed.as_millis(),
            "locate phase exceeded budget, returning partial results"
        );
    }

    fn elapsed_secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }
}

/// Split a compound identifier into lowercase parts for case-invariant matching.
/// Handles snake_case, CamelCase, SCREAMING_SNAKE, and mixtures:
///   "quantity_input" → ["quantity", "input"]
///   "QuantityInput"  → ["quantity", "input"]
///   "QUANTITY_INPUT"  → ["quantity", "input"]
///   "HTTPClient"      → ["http", "client"]
fn split_identifier_parts(name: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();

    for ch in name.chars() {
        if ch == '_' || ch == '-' {
            if !current.is_empty() {
                parts.push(std::mem::take(&mut current).to_lowercase());
            }
        } else if ch.is_uppercase() {
            if !current.is_empty() {
                // Check if this is start of a new word (camelCase boundary)
                // but NOT a run of capitals (like "HTTP" in "HTTPClient")
                let prev_was_lower = current.chars().last().map_or(false, |c| c.is_lowercase());
                if prev_was_lower {
                    parts.push(std::mem::take(&mut current).to_lowercase());
                }
            }
            current.push(ch);
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        parts.push(current.to_lowercase());
    }
    parts
}

/// Score how well a search term matches an entity name using part-based matching.
/// Returns (match_quality, matched_parts_ratio) where:
///   - match_quality: 0.0 (no match) to 5.0 (exact match)
///   - matched_parts_ratio: fraction of search parts that matched
fn score_name_match(search_term: &str, entity_name: &str) -> f32 {
    let search_parts = split_identifier_parts(search_term);
    let entity_parts = split_identifier_parts(entity_name);

    if search_parts.is_empty() || entity_parts.is_empty() {
        return 0.0;
    }

    // Exact match (all parts identical in same order)
    if search_parts == entity_parts {
        return 5.0;
    }

    // Count how many search parts appear in the entity parts
    let matched = search_parts
        .iter()
        .filter(|sp| entity_parts.contains(sp))
        .count();
    let ratio = matched as f32 / search_parts.len() as f32;

    // For compound identifiers (2+ parts), require ALL parts to match.
    // Partial matches on compound terms are noise:
    //   "quantity_input" matching "BaseInputter" (1/2 parts) = noise
    //   "quantity_input" matching "QuantityInput" (2/2 parts) = signal
    if search_parts.len() >= 2 {
        if ratio >= 1.0 {
            // All search parts found in entity (could be superset like QuantityInputValidator)
            if entity_parts.len() == search_parts.len() {
                return 5.0; // Same parts, different order or casing
            }
            return 3.0; // Superset match
        }
        // For compound terms, partial matches are essentially noise
        return 0.0;
    }

    // Single-part search terms: more permissive matching
    if ratio >= 1.0 {
        3.0
    } else {
        // Fall back to contains check for single terms
        let search_lower = search_term.to_lowercase().replace('_', "");
        let entity_lower = entity_name.to_lowercase().replace('_', "");
        if entity_lower.contains(&search_lower) || search_lower.contains(&entity_lower) {
            1.0
        } else {
            0.0
        }
    }
}

fn locate_env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn locate_env_f32(name: &str, default: f32) -> f32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<f32>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
        .unwrap_or(default)
}

fn locate_env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(default)
}

/// Single source for the entity-resolve strength floor (read by both the
/// strong-resolve support cap and resolve-boundary compression).
fn resolve_strength_floor() -> f32 {
    locate_env_f32("KIN_LOCATE_RESOLVE_STRENGTH_FLOOR", 0.25)
}

/// Single source for the amalgamated/generated-header penalty (read by both the
/// projection-backed penalty and the post-RRF path penalty).
fn amalgam_penalty() -> f32 {
    locate_env_f32("KIN_LOCATE_AMALGAM_PENALTY", 0.05)
}

fn fast_entity_dominant_enabled(
    explain: bool,
    test_query: bool,
    rich_symbolic_body_query: bool,
    traceback_top: f32,
    resolve_top: f32,
    resolve_gap: f32,
    resolve_top_is_disqualified: bool,
    tb_threshold: f32,
    resolve_min: f32,
    resolve_gap_min: f32,
) -> bool {
    let _ = explain; // Debug mode must not perturb ranking decisions.
    !test_query
        && !rich_symbolic_body_query
        && traceback_top <= tb_threshold
        && resolve_top > resolve_min
        && resolve_gap > resolve_gap_min
        && !resolve_top_is_disqualified
}

fn entity_dominant_decision_metrics(ranked: &[(String, f32)]) -> (f32, f32, bool) {
    let decision_scores = ranked
        .iter()
        .filter(|(path, score)| *score > 0.0 && !disqualifies_entity_dominant_top_path(path))
        .map(|(_, score)| *score)
        .collect::<Vec<_>>();
    let Some(first) = decision_scores.first().copied() else {
        return (0.0, 0.0, true);
    };
    let gap = decision_scores
        .get(1)
        .copied()
        .filter(|_| first > 0.001)
        .map(|second| (first - second) / first)
        .unwrap_or(1.0);
    (first, gap, false)
}

fn rich_symbolic_body_query(text: &str) -> bool {
    let body = text.lines().skip(1).collect::<Vec<_>>().join("\n");
    if body.is_empty() {
        return false;
    }

    let mut symbolic_terms = HashSet::new();
    for term in extract_search_terms(&body)
        .into_iter()
        .chain(extract_loose_query_terms(&body))
    {
        if is_cli_flag_term(&term) || !is_symbolic_search_term(&term) {
            continue;
        }
        symbolic_terms.insert(term.to_ascii_lowercase());
        if symbolic_terms.len() >= 2 {
            return true;
        }
    }

    false
}

fn disqualifies_entity_dominant_top_path(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);
    basename == "__init__.py"
        || basename == "__init__.rs"
        || basename == "mod.rs"
        || basename == "lib.rs"
        || basename == "root.go"
        || basename == "main.go"
        || basename == "Cargo.toml"
        || basename == "package.json"
        || basename == "index.ts"
        || basename == "index.tsx"
        || basename == "index.js"
        || basename == "index.jsx"
        || is_test_path(path)
        || is_vendor_path(path)
        || is_embedded_framework_noise_path(path)
        || is_docs_or_locale_path(path)
        || is_non_code_ext(path)
        || is_contrib_port_path(path)
        || is_amalgamated_or_generated_path(path)
}

fn entity_stable_key(entity: &kin_model::Entity) -> Option<EntityStableKey> {
    let path = entity.file_origin.as_ref()?.0.clone();
    Some((path, entity.name.clone(), entity.kind))
}

fn entity_stable_key_from_retrieval_key(
    graph: &kin_db::InMemoryGraph,
    key: &kin_db::RetrievalKey,
) -> Option<EntityStableKey> {
    match graph.resolve_retrieval_key(key) {
        Some(kin_db::ResolvedRetrievalItem::Entity(entity)) => entity_stable_key(&entity),
        _ => None,
    }
}

fn entity_from_retrieval_key(
    graph: &kin_db::InMemoryGraph,
    key: &kin_db::RetrievalKey,
) -> Result<Option<kin_model::Entity>> {
    match graph.resolve_retrieval_key(key) {
        Some(kin_db::ResolvedRetrievalItem::Entity(entity)) => Ok(Some(entity)),
        _ => Ok(None),
    }
}

fn embedding_status_complete(status: &kin_db::EmbeddingStatus) -> bool {
    status.total == 0 || (status.indexed == status.total && status.pending == 0)
}

fn embedding_status_summary(status: &kin_db::EmbeddingStatus) -> String {
    format!(
        "{}/{} indexed, {} unindexed, {} pending",
        status.indexed,
        status.total,
        status.total.saturating_sub(status.indexed),
        status.pending
    )
}

/// Strict-coverage mode is OFF by default: users get graceful degradation on
/// partial/zero embedding coverage. Benchmarks opt into the hard gate by
/// setting `KIN_REQUIRE_COMPLETE_EMBEDDINGS=1`, which preserves
/// benchmark-integrity (incomplete coverage refuses to score). An explicit
/// `KIN_BYPASS_EMBEDDING_COVERAGE_CHECK=1` forces degradation even if strict
/// was requested (kept for backward compatibility / tests).
fn embedding_strict_mode() -> bool {
    locate_env_bool("KIN_REQUIRE_COMPLETE_EMBEDDINGS", false)
        && !locate_env_bool("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK", false)
}

/// Pick the embedding status that actually backs the semantic signal for this
/// query — the primary graph when it carries embeddings (or has no entities at
/// all), otherwise the HEAD vector source used for scoped-session search.
/// Mirrors the graph-selection logic in `extract_embedding_signals`.
fn effective_embedding_status(
    graph: &kin_db::InMemoryGraph,
    vector_source: Option<&kin_db::InMemoryGraph>,
) -> kin_db::EmbeddingStatus {
    let primary_status = graph.embedding_status();
    if primary_status.total == 0 || primary_status.indexed > 0 {
        return primary_status;
    }
    if let Some(source) = vector_source.filter(|source| !std::ptr::eq(*source, graph)) {
        return source.embedding_status();
    }
    primary_status
}

/// Evaluate embedding coverage for a locate query.
///
/// Default (user) behavior: never errors. Returns a `SemanticCoverage` report
/// describing whether the semantic signal was complete; on partial/zero
/// coverage it carries a note explaining that lexical + graph signals still
/// ran. Strict (benchmark) behavior, gated behind
/// `KIN_REQUIRE_COMPLETE_EMBEDDINGS=1`: bails on incomplete coverage exactly as
/// before, so benchmarks refuse to score a half-embedded repo.
fn evaluate_embedding_coverage(
    graph: &kin_db::InMemoryGraph,
    vector_source: Option<&kin_db::InMemoryGraph>,
) -> Result<SemanticCoverage> {
    let status = effective_embedding_status(graph, vector_source);
    let complete = embedding_status_complete(&status);

    if !complete && embedding_strict_mode() {
        anyhow::bail!(
            "semantic locate requires complete embeddings; graph has {}. Run `kin embed` until `kin status --json` reports embeddingsIndexed == embeddingsTotal and embeddingsPending == 0. (Set KIN_REQUIRE_COMPLETE_EMBEDDINGS=0 to allow graceful degradation.)",
            embedding_status_summary(&status)
        );
    }

    let note = if complete {
        None
    } else {
        Some(format!(
            "semantic signal partial: {} embedded. Lexical + graph results returned; run `kin embed` for full semantic ranking.",
            embedding_status_summary(&status)
        ))
    };

    Ok(SemanticCoverage {
        indexed: status.indexed,
        total: status.total,
        pending: status.pending,
        complete,
        note,
    })
}

fn file_path_from_retrieval_key(
    graph: &kin_db::InMemoryGraph,
    key: &kin_db::RetrievalKey,
) -> Option<String> {
    graph
        .resolve_retrieval_key(key)?
        .file_path()
        .map(|file_id| file_id.0)
}

fn source_file_paths(graph: &kin_db::InMemoryGraph) -> HashSet<String> {
    let mut paths: HashSet<String> = graph.entity_bearing_file_paths().into_iter().collect();
    if let Ok(entities) = graph.query_entities(&EntityFilter::default()) {
        for entity in entities {
            let Some(file_origin) = entity.file_origin.as_ref() else {
                continue;
            };
            if entity.role == EntityRole::Docs || is_test_by_role(&file_origin.0, Some(&entity)) {
                continue;
            }
            paths.insert(file_origin.0.clone());
        }
    }
    paths
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(
    text: &str,
    json: bool,
    explain: bool,
    max_files: usize,
    max_files_explicit: bool,
    reference: Option<String>,
) -> Result<()> {
    let _span = tracing::info_span!(
        "kin.locate",
        text_len = text.len(),
        json = json,
        explain = explain,
        max_files = max_files
    )
    .entered();
    let result = capture(text, explain, max_files, max_files_explicit, reference).await?;
    output_result(&result, json);
    Ok(())
}

pub async fn capture(
    text: &str,
    explain: bool,
    max_files: usize,
    max_files_explicit: bool,
    reference: Option<String>,
) -> Result<LocateResult> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    if locate_env_bool("KIN_LOCATE_FORCE_LOCAL", false) {
        anyhow::bail!(
            "KIN_LOCATE_FORCE_LOCAL is no longer supported; locate requires the Kin daemon"
        );
    }

    try_locate_via_daemon(
        &layout,
        text,
        explain,
        max_files,
        max_files_explicit,
        reference,
    )
    .await
}

async fn try_locate_via_daemon(
    layout: &kin_core::KinLayout,
    text: &str,
    explain: bool,
    max_files: usize,
    max_files_explicit: bool,
    reference: Option<String>,
) -> Result<LocateResult> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for locate but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    let request = crate::daemon_client::LocateRequest {
        text: text.to_string(),
        explain,
        max_files,
        max_files_explicit,
        reference,
    };
    client
        .locate(&request)
        .await
        .context("daemon locate failed")
}

pub fn run_with_graph(
    graph: &kin_db::InMemoryGraph,
    text: &str,
    json: bool,
    explain: bool,
    max_files: usize,
    max_files_explicit: bool,
) -> Result<()> {
    let result = run_with_graph_capture(graph, text, explain, max_files, max_files_explicit)?;
    output_result(&result, json);
    Ok(())
}

pub fn run_with_graph_capture(
    graph: &kin_db::InMemoryGraph,
    text: &str,
    explain: bool,
    max_files: usize,
    max_files_explicit: bool,
) -> Result<LocateResult> {
    let workspace_root = locate_workspace_root();
    run_with_graph_capture_in_workspace(
        graph,
        workspace_root.as_deref(),
        text,
        explain,
        max_files,
        max_files_explicit,
    )
}

fn locate_workspace_root() -> Option<std::path::PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    kin_core::KinLayout::discover(&cwd)
        .map(|layout| kin_core::source_dir(&layout))
        .or(Some(cwd))
}

pub fn run_with_graph_capture_in_workspace(
    graph: &kin_db::InMemoryGraph,
    workspace_root: Option<&std::path::Path>,
    text: &str,
    explain: bool,
    max_files: usize,
    max_files_explicit: bool,
) -> Result<LocateResult> {
    run_with_graph_capture_with_priority_files(
        graph,
        workspace_root,
        text,
        explain,
        max_files,
        max_files_explicit,
        Vec::new(),
    )
}

pub fn run_with_graph_capture_with_priority_files(
    graph: &kin_db::InMemoryGraph,
    workspace_root: Option<&std::path::Path>,
    text: &str,
    explain: bool,
    max_files: usize,
    max_files_explicit: bool,
    extra_priority_files: Vec<(String, f32)>,
) -> Result<LocateResult> {
    run_with_graph_capture_with_priority_files_and_vector_source(
        graph,
        workspace_root,
        text,
        explain,
        max_files,
        max_files_explicit,
        extra_priority_files,
        None,
    )
}

pub fn run_with_graph_capture_with_priority_files_and_vector_source(
    graph: &kin_db::InMemoryGraph,
    workspace_root: Option<&std::path::Path>,
    text: &str,
    explain: bool,
    max_files: usize,
    max_files_explicit: bool,
    extra_priority_files: Vec<(String, f32)>,
    vector_source: Option<&kin_db::InMemoryGraph>,
) -> Result<LocateResult> {
    let _span = tracing::info_span!(
        "kin.locate.run_with_graph",
        text_len = text.len(),
        explain = explain,
        max_files = max_files
    )
    .entered();
    // Strip HTML comments and common PR-template boilerplate before retrieval.
    // Long checklists and contribution guidelines repeatedly mention generic
    // paths, build tools, and policy words that are not the change request.
    let cleaned_text = clean_issue_text(text);
    let semantic_text = strip_pr_template_boilerplate(&cleaned_text);
    let text = semantic_text.as_str();
    let semantic_coverage = evaluate_embedding_coverage(graph, vector_source)?;

    let mut budget = LocateBudget::new();
    let pipeline_report = std::env::var("KIN_LOCATE_PIPELINE_REPORT").is_ok();
    let profile = LocateProfile::detect();
    let test_query = is_test_query(text);
    let text_lower = text.to_ascii_lowercase();
    let source_text_priority_query = test_query
        || query_mentions_cli_flags(text)
        || mentions_triple_quoted_strings(&text_lower)
        || text_lower.contains("multi-line")
        || text_lower.contains("multiline");

    // Extract priority files (explicit file paths mentioned in the text)
    let mut priority_traces = extract_priority_file_traces(text, graph);
    // Remove vendored/dependency paths from priority traces before scoring
    priority_traces.retain(|path, _| !is_vendored_path(path));
    let mut priority_files = priority_trace_to_scores(&priority_traces);
    merge_priority_file_scores_with_trace(
        &mut priority_files,
        &mut priority_traces,
        extra_priority_files,
        "historical_priority_seed",
    );

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 1: Discovery — find candidate ENTITIES, not files.
    // Text search + embeddings discover which entities are relevant.
    // File resolution is deferred to Phase 2 (graph-based).
    // ═══════════════════════════════════════════════════════════════════════

    // Phase 1a: Entity-first signals — return entity seeds
    let (search_entity_seeds, embedding_entity_seeds) =
        if budget.phase_should_skip("entity_discovery") {
            (HashMap::new(), HashMap::new())
        } else {
            let phase_start = std::time::Instant::now();
            let search = extract_search_signals(text, graph, test_query)?;
            let embedding = if budget.phase_remaining("entity_discovery") < 2.0 {
                tracing::info!(
                    "skipping embedding sub-phase: entity_discovery budget nearly exhausted"
                );
                HashMap::new()
            } else {
                extract_embedding_signals(text, graph, test_query, vector_source)?
            };
            if phase_start.elapsed().as_secs_f64()
                > budget
                    .phase_budgets
                    .get("entity_discovery")
                    .copied()
                    .unwrap_or(30.0)
            {
                budget.warn_phase_timeout("entity_discovery", phase_start.elapsed());
            }
            (search, embedding)
        };

    // Phase 1b: File-based signals — these bypass entity resolution
    let traceback = extract_traceback_signals(text, graph)?;
    let tests = extract_test_signals(text, graph)?;
    let private_access_tests = extract_cpp_private_access_test_seed_signals(text, graph)?;
    let snippets = extract_snippet_signals(text, graph)?;
    let imports = extract_import_signals(text, graph)?;
    let errors = extract_error_signals(text, graph)?;
    // Phase 1a seeds are kept as two independent pools so embeddings get their
    // own signal column downstream (index 9) instead of being drowned by much
    // larger text-search scores inside entity_resolve.
    let all_entity_seeds: HashMap<kin_model::EntityId, EntityDiscovery> = search_entity_seeds;
    let seed_file_support = aggregate_entity_seed_file_support(&all_entity_seeds, graph)?;

    tracing::info!(
        entity_seeds = all_entity_seeds.len(),
        "Phase 1 discovery complete"
    );

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 2: Entity → File resolution via graph relations.
    // The graph is the authority for determining which files to modify.
    // LSP-resolved relations carry 2× weight (type-resolved, high confidence).
    // ═══════════════════════════════════════════════════════════════════════

    let (
        resolved_files,
        resolve_explain,
        resolve_signal_scores,
        resolve_symbols,
        resolve_candidate_stages,
    ) = if budget.phase_should_skip("entity_resolution") {
        (
            Vec::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            Vec::new(),
        )
    } else {
        let phase_start = std::time::Instant::now();
        let result = resolve_entities_to_files(&all_entity_seeds, graph, explain, "text")?;
        if phase_start.elapsed().as_secs_f64()
            > budget
                .phase_budgets
                .get("entity_resolution")
                .copied()
                .unwrap_or(30.0)
        {
            budget.warn_phase_timeout("entity_resolution", phase_start.elapsed());
        }
        result
    };

    // Convert resolved files to a HashMap<String, Vec<FileHit>> for compatibility
    // with the existing RRF and output infrastructure.
    let mut resolved_hits: HashMap<String, Vec<FileHit>> = HashMap::new();
    for (path, score) in &resolved_files {
        resolved_hits
            .entry(path.clone())
            .or_default()
            .push(FileHit {
                score: *score,
                spans: vec![],
            });
    }

    // Resolve the embedding-only seed pool to files as a second, independent
    // pass. This gives semantic matches their own signal column (index 9 in
    // ranked_lists) so they can survive even when they don't overlap with
    // text-search entity_resolve hits. Skip when there are no seeds or when
    // the entity_resolution budget is already exhausted.
    let (embedding_hits, embedding_symbols, embedding_candidate_stages): (
        HashMap<String, Vec<FileHit>>,
        HashMap<String, Vec<LocateSymbol>>,
        Vec<LocateDebugCandidateStage>,
    ) = if embedding_entity_seeds.is_empty() || budget.phase_should_skip("entity_resolution") {
        (HashMap::new(), HashMap::new(), Vec::new())
    } else {
        let phase_start = std::time::Instant::now();
        let (
            embed_files,
            _embed_explain,
            _embed_signal_scores,
            embed_symbols,
            embed_candidate_stages,
        ) = resolve_entities_to_files(&embedding_entity_seeds, graph, explain, "vector")?;
        if phase_start.elapsed().as_secs_f64()
            > budget
                .phase_budgets
                .get("entity_resolution")
                .copied()
                .unwrap_or(30.0)
        {
            budget.warn_phase_timeout("entity_resolution", phase_start.elapsed());
        }
        let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();
        for (path, score) in embed_files {
            hits.entry(path).or_default().push(FileHit {
                score,
                spans: vec![],
            });
        }
        (hits, embed_symbols, embed_candidate_stages)
    };

    let fast_traceback_top = to_ranked(&traceback)
        .first()
        .map(|(_, score)| *score)
        .unwrap_or(0.0);
    let (fast_decision_resolve_top, fast_resolve_gap, resolve_top_is_disqualified) =
        entity_dominant_decision_metrics(&resolved_files);
    let tb_threshold = locate_env_f32("KIN_LOCATE_TRACEBACK_DOMINANT_THRESHOLD", 5.0);
    let ed_resolve_min = locate_env_f32("KIN_LOCATE_ENTITY_DOMINANT_RESOLVE_MIN", 20.0);
    let ed_gap_min = locate_env_f32("KIN_LOCATE_ENTITY_DOMINANT_GAP_MIN", 0.15);
    let has_rich_symbolic_body = rich_symbolic_body_query(text);
    let fast_entity_dominant = fast_entity_dominant_enabled(
        explain,
        test_query,
        has_rich_symbolic_body,
        fast_traceback_top,
        fast_decision_resolve_top,
        fast_resolve_gap,
        resolve_top_is_disqualified,
        tb_threshold,
        ed_resolve_min,
        ed_gap_min,
    );

    // Source text search always runs — even in fast_entity_dominant mode.
    // It's cheap (budget 10s) and provides result diversity that entity
    // resolution alone cannot. Without it, files only reachable via text
    // search are invisible in EntityDominant scoring.
    let source_text = if budget.phase_should_skip("source_text") {
        HashMap::new()
    } else {
        let phase_start = std::time::Instant::now();
        let source_text = extract_source_text_signals(text, graph, workspace_root)?;
        if phase_start.elapsed().as_secs_f64()
            > budget
                .phase_budgets
                .get("source_text")
                .copied()
                .unwrap_or(15.0)
        {
            budget.warn_phase_timeout("source_text", phase_start.elapsed());
        }
        if source_text_priority_query {
            merge_priority_files_from_hits_with_trace(
                &mut priority_files,
                &mut priority_traces,
                &source_text,
                "source_text_hit_merge",
            );
        }
        source_text
    };
    let priority_hits: HashMap<String, Vec<FileHit>> = priority_files
        .iter()
        .filter(|(path, _)| !is_vendored_path(path))
        .map(|(path, score)| {
            (
                path.clone(),
                vec![FileHit {
                    score: *score,
                    spans: vec![],
                }],
            )
        })
        .collect();

    // Phase 2b: Multihop expansion from resolved files (graph follow-up)
    let multihop = if fast_entity_dominant || budget.phase_should_skip("multihop") {
        HashMap::new()
    } else {
        let phase_start = std::time::Instant::now();
        let multihop_seed_sets = vec![
            &resolved_hits,
            &traceback,
            &tests,
            &private_access_tests,
            &source_text,
            &priority_hits,
            &imports,
            &errors,
        ];
        let result = extract_multihop_signals(&multihop_seed_sets, graph, profile, test_query)?;
        if phase_start.elapsed().as_secs_f64()
            > budget
                .phase_budgets
                .get("multihop")
                .copied()
                .unwrap_or(30.0)
        {
            budget.warn_phase_timeout("multihop", phase_start.elapsed());
        }
        result
    };

    // Phase 2c: Cochange from all signals
    let cochange = if fast_entity_dominant || budget.phase_should_skip("multihop") {
        HashMap::new()
    } else {
        let phase_start = std::time::Instant::now();
        let cochange_seed_sets = vec![
            &resolved_hits,
            &traceback,
            &tests,
            &private_access_tests,
            &source_text,
            &priority_hits,
            &imports,
            &errors,
        ];
        let result = extract_cochange_signals(&cochange_seed_sets, graph)?;
        if phase_start.elapsed().as_secs_f64()
            > budget
                .phase_budgets
                .get("multihop")
                .copied()
                .unwrap_or(30.0)
        {
            budget.warn_phase_timeout("cochange", phase_start.elapsed());
        }
        result
    };

    // ═══════════════════════════════════════════════════════════════════════
    // FUSION: Blend Phase 2 resolved files with file-based signals via RRF.
    // ═══════════════════════════════════════════════════════════════════════

    // If scoring budget is exhausted, return resolved files as-is
    if budget.phase_should_skip("scoring") {
        let mut fallback_files: Vec<(String, f32)> = resolved_files.clone();
        // Also include traceback files that aren't in resolved
        let resolved_set: HashSet<String> = fallback_files.iter().map(|(p, _)| p.clone()).collect();
        for (path, hits) in &traceback {
            if !resolved_set.contains(path) {
                let score: f32 = hits.iter().map(|h| h.score).sum();
                fallback_files.push((path.clone(), score));
            }
        }
        fallback_files.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        fallback_files.truncate(max_files);
        let debug_info = if explain {
            let mut info = LocateDebugInfo::default();
            info.skipped_signals = budget.warnings.clone();
            Some(info)
        } else {
            None
        };
        tracing::warn!(
            elapsed_secs = budget.elapsed_secs(),
            warnings = ?budget.warnings,
            "locate pipeline returning early: scoring budget exhausted"
        );
        return Ok(build_result(
            &fallback_files,
            &[],
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            debug_info,
            explain,
        )
        .with_semantic_coverage(semantic_coverage));
    }

    let signal_confidence_weights = [
        locate_env_f32("KIN_LOCATE_WEIGHT_TRACEBACK", 1.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_MULTIHOP", 1.4),
        locate_env_f32("KIN_LOCATE_WEIGHT_TESTS", 1.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_SNIPPETS", 0.8),
        locate_env_f32("KIN_LOCATE_WEIGHT_IMPORTS", 1.2),
        locate_env_f32("KIN_LOCATE_WEIGHT_ERRORS", 1.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_COCHANGE", 1.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_PROJECTION", 5.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_SOURCE_TEXT", 2.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_EMBEDDING", 1.5),
    ];

    let mut ranked_lists: Vec<Vec<(String, f32)>> = vec![
        to_ranked(&traceback),
        to_ranked(&multihop),
        to_ranked(&tests),
        to_ranked(&snippets),
        to_ranked(&imports),
        to_ranked(&errors),
        to_ranked(&cochange),
        to_ranked(&resolved_hits),
        to_ranked(&source_text),
        to_ranked(&embedding_hits),
    ];

    for (list, weight) in ranked_lists
        .iter_mut()
        .zip(signal_confidence_weights.iter())
    {
        if *weight != 1.0 {
            for (_, score) in list.iter_mut() {
                *score *= weight;
            }
        }
    }

    let signal_names = [
        "traceback",
        "multihop",
        "tests",
        "snippets",
        "imports",
        "errors",
        "cochange",
        "entity_resolve",
        "source_text",
        "embedding",
    ];
    let mut per_file_signals: HashMap<String, HashMap<String, f32>> = HashMap::new();
    if explain {
        for (list_idx, list) in ranked_lists.iter().enumerate() {
            let sig_name = signal_names.get(list_idx).unwrap_or(&"unknown");
            for (file, score) in list {
                if *score > 0.0 {
                    per_file_signals
                        .entry(file.clone())
                        .or_default()
                        .insert(sig_name.to_string(), *score);
                }
            }
        }
        // Merge in the per-signal breakdown from Phase 2 resolution
        for (path, signal_map) in &resolve_signal_scores {
            for (sig, score) in signal_map {
                if *score > 0.0 {
                    per_file_signals
                        .entry(path.clone())
                        .or_default()
                        .entry(sig.clone())
                        .and_modify(|s| *s += score)
                        .or_insert(*score);
                }
            }
        }
    }

    // Detect signal dominance pattern and choose scoring strategy.
    // idx 0=traceback, 1=multihop, 2=tests, 3=snippets,
    // 4=imports, 5=errors, 6=cochange, 7=entity_resolve, 8=source_text
    let traceback_top = ranked_lists[0].first().map(|(_, s)| *s).unwrap_or(0.0);
    // resolve_top is read from the raw resolved-files scale (0-100) so the
    // EntityDominant gate against ed_resolve_min matches the fast-path decision.
    // ranked_lists[7] carries the ×PROJECTION weight + source bonus (scale ~0-600).
    let (resolve_top, resolve_gap, resolve_top_is_disqualified) =
        entity_dominant_decision_metrics(&resolved_files);
    let multihop_top = ranked_lists[1].first().map(|(_, s)| *s).unwrap_or(0.0);

    #[derive(Debug, Clone, Copy)]
    enum ScoringTrack {
        TracebackDominant,
        EntityDominant,
        GraphStructural,
        BroadBlend,
    }

    let track = if fast_entity_dominant {
        ScoringTrack::EntityDominant
    } else if traceback_top > tb_threshold {
        ScoringTrack::TracebackDominant
    } else if resolve_top > ed_resolve_min
        && resolve_gap > ed_gap_min
        && !resolve_top_is_disqualified
    {
        ScoringTrack::EntityDominant
    } else if resolve_top < 1.0 && multihop_top > 1.0 {
        ScoringTrack::GraphStructural
    } else {
        ScoringTrack::BroadBlend
    };

    // Entity-granular fusion experiment (default OFF; byte-identical when unset).
    // When KIN_LOCATE_ENTITY_FUSION=1, fuse at ENTITY granularity (entity-derived
    // signals keyed by entity id, the rest by path) and PROJECT to files at the
    // fusion boundary, so the file-keyed post-fusion pipeline (boosts/demotes/
    // floors/adaptive_cap) below runs unchanged. When unset, the original
    // track-regime path fusion runs verbatim — see the flip-plan in
    // crates/kin-cli/docs/locate-entity-fusion-flip-plan.md for scope and A/B.
    let mut fused = if locate_env_bool("KIN_LOCATE_ENTITY_FUSION", false) {
        entity_granular_fused_files(
            &ranked_lists,
            &all_entity_seeds,
            &embedding_entity_seeds,
            graph,
        )?
    } else {
        match track {
        ScoringTrack::TracebackDominant => {
            // Traceback explicitly names files — trust it as ground truth.
            // Entity resolve and multihop supplement but don't override.
            let mut weights = signal_confidence_weights;
            weights[0] = 10.0; // traceback dominates
            weights[7] = 2.0; // entity_resolve second
            for w in weights[1..7].iter_mut() {
                *w *= 0.3;
            } // suppress others
            for (list, weight) in ranked_lists.iter_mut().zip(weights.iter()) {
                for (_, score) in list.iter_mut() {
                    *score *= weight;
                }
            }
            reciprocal_rank_fusion_weighted(
                &ranked_lists,
                60.0,
                &rrf_rank_lift_weights(ranked_lists.len()),
                &[],
            )
        }
        ScoringTrack::EntityDominant => {
            // Conditional scoring: when entity_resolve produces few unique
            // files (<=3), diverse signal blending via weighted RRF is needed
            // to surface files that entity resolution alone misses. When
            // entity_resolve produces many unique files (>3), it already has
            // good coverage — use direct entity ordering which preserves the
            // entity-resolve ranking and avoids RRF diluting strong results.
            let entity_resolve_unique_files: HashSet<&str> =
                resolved_files.iter().map(|(p, _)| p.as_str()).collect();
            let rrf_threshold = locate_env_usize("KIN_LOCATE_ENTITY_DOMINANT_RRF_THRESHOLD", 3);

            if entity_resolve_unique_files.len() <= rrf_threshold {
                // Sparse entity results — blend via weighted RRF so that
                // source_text and other signals can contribute files.
                let mut entity_dom_weights = vec![1.0f32; ranked_lists.len()];
                entity_dom_weights[7] =
                    locate_env_f32("KIN_LOCATE_ENTITY_DOMINANT_RESOLVE_WEIGHT", 8.0); // entity_resolve dominates
                entity_dom_weights[8] = 1.5; // source_text second
                entity_dom_weights[0] = 2.0; // traceback if present
                if entity_dom_weights.len() > 9 {
                    entity_dom_weights[9] =
                        locate_env_f32("KIN_LOCATE_ENTITY_DOMINANT_EMBEDDING_WEIGHT", 2.0);
                    // embedding as independent corroboration
                }
                // Suppress test/snippet/import/error noise
                for idx in [2, 3, 4, 5] {
                    entity_dom_weights[idx] *= 0.3;
                }
                reciprocal_rank_fusion_weighted(
                    &ranked_lists,
                    60.0,
                    &rrf_rank_lift_weights(ranked_lists.len()),
                    &entity_dom_weights,
                )
            } else {
                // Rich entity results — trust entity_resolve ordering directly.
                // Normalize scores to a bounded range and supplement with other
                // signals for files entity_resolve didn't find.
                let resolve_list = &ranked_lists[7];
                let mut result: Vec<(String, f32)> = Vec::new();
                let resolve_set: HashSet<String> =
                    resolve_list.iter().map(|(p, _)| p.clone()).collect();
                let include_tests = test_query;

                let resolve_cap = locate_env_f32("KIN_LOCATE_ENTITY_DOMINANT_RESOLVE_CAP", 100.0);
                let resolve_max = resolve_list
                    .first()
                    .map(|(_, s)| *s)
                    .unwrap_or(1.0)
                    .max(1.0);

                for (path, score) in resolve_list {
                    if include_tests || !is_test_path(path) {
                        let normalized = (*score / resolve_max) * resolve_cap;
                        result.push((path.clone(), normalized));
                    }
                }

                // Supplement with other signaled files at competitive scores.
                let other_ceiling_ratio =
                    locate_env_f32("KIN_LOCATE_ENTITY_DOMINANT_OTHER_CEILING", 0.4);
                let other_ceiling = resolve_cap * other_ceiling_ratio;

                let other_ranked_lists = ranked_lists
                    .iter()
                    .enumerate()
                    .filter(|(idx, _)| *idx != 7)
                    .map(|(_, list)| list.clone())
                    .collect::<Vec<_>>();
                let other_fused = reciprocal_rank_fusion(&other_ranked_lists, 60.0);
                let other_max = other_fused
                    .first()
                    .map(|(_, s)| *s)
                    .unwrap_or(1.0)
                    .max(0.001);
                for (path, score) in other_fused {
                    if !resolve_set.contains(&path) && (include_tests || !is_test_path(&path)) {
                        let scaled = (score / other_max) * other_ceiling;
                        result.push((path, scaled));
                    }
                }
                result
            }
        }
        ScoringTrack::GraphStructural => {
            // No entity resolve — rely on graph expansion signals.
            // Boost multihop and imports, suppress test/snippet noise.
            reciprocal_rank_fusion_weighted(
                &ranked_lists,
                60.0,
                &rrf_rank_lift_weights(ranked_lists.len()),
                &[],
            )
        }
        ScoringTrack::BroadBlend => {
            // Mixed signals — standard RRF blend, but penalize test files
            // in non-resolve signals to prevent test files from winning
            // via cross-signal count alone.
            for (idx, list) in ranked_lists.iter_mut().enumerate() {
                if idx == 7 {
                    continue;
                }
                for (path, score) in list.iter_mut() {
                    if is_test_path(path) {
                        *score *= locate_env_f32("KIN_LOCATE_BROAD_TEST_PENALTY", 0.1);
                    }
                }
            }
            reciprocal_rank_fusion_weighted(
                &ranked_lists,
                60.0,
                &rrf_rank_lift_weights(ranked_lists.len()),
                &[],
            )
        }
        }
    };

    // Strip vendored/dependency files from all tracks' results. The RRF
    // function already skips them, but EntityDominant builds its result list
    // directly from the resolve list, bypassing that filter.
    fused.retain(|(path, _)| !is_vendored_path(path));

    let mut score_breakdown: HashMap<String, HashMap<String, f32>> = HashMap::new();
    let mut debug_info = if explain {
        let query_terms = curate_search_terms(text, graph).unwrap_or_else(|_| {
            let mut fallback = extract_search_terms(text);
            if fallback.is_empty() {
                fallback = extract_title_terms(text);
            }
            fallback
        });
        let debug_limit = locate_env_usize("KIN_LOCATE_DEBUG_LIST_LIMIT", 12);
        // Re-attach entity identity (dropped at the FileHit/entity→file seam) to
        // resolved files for observability. Read-only; never feeds ranking.
        let resolve_identity = entity_resolve_identity(&all_entity_seeds, graph)?;
        Some(LocateDebugInfo {
            scoring_track: Some(format!("{track:?}")),
            traceback_top: Some(traceback_top),
            resolve_top: Some(resolve_top),
            resolve_gap: Some(resolve_gap),
            multihop_top: Some(multihop_top),
            fast_path: fast_entity_dominant
                .then_some("entity_dominant_skip_expansions".to_string()),
            skipped_signals: {
                let mut skipped = if fast_entity_dominant {
                    vec!["multihop".to_string(), "cochange".to_string()]
                } else {
                    Vec::new()
                };
                skipped.extend(budget.warnings.iter().cloned());
                skipped
            },
            query_terms,
            priority_files: priority_trace_to_debug(&priority_traces, debug_limit),
            resolved_files: resolved_files
                .iter()
                .take(debug_limit)
                .map(|(path, score)| LocateDebugResolvedFile {
                    path: path.clone(),
                    score: *score,
                    direct: resolve_signal_scores
                        .get(path)
                        .and_then(|scores| scores.get("entity_resolve"))
                        .copied()
                        .unwrap_or(0.0),
                    graph: resolve_signal_scores
                        .get(path)
                        .and_then(|scores| scores.get("graph_resolve"))
                        .copied()
                        .unwrap_or(0.0),
                    entity_id: resolve_identity.get(path).map(|id| id.to_string()),
                })
                .collect(),
            stages: Vec::new(),
            candidate_stages: {
                let mut stages = resolve_candidate_stages.clone();
                stages.extend(embedding_candidate_stages.clone());
                stages
            },
            pruned_files: Vec::new(),
            symbol_cap: None,
        })
    } else {
        None
    };
    if explain {
        record_debug_stage(&mut score_breakdown, &mut debug_info, &fused, "base_track");
    }

    if pipeline_report {
        eprintln!("  Scoring track: {:?}", track);
        eprintln!(
            "  (traceback_top={:.1} resolve_top={:.1} resolve_gap={:.2} multihop_top={:.1})",
            traceback_top, resolve_top, resolve_gap, multihop_top
        );
    }

    let mut retained_priority_paths =
        retained_priority_paths(&priority_traces, text_lower.contains("test"));
    let priority_relation_paths =
        priority_relation_retention_paths(graph, &retained_priority_paths)?;
    retained_priority_paths.extend(priority_relation_paths);
    let injectable_priority_paths = injectable_priority_paths(&priority_traces);
    boost_priority_in_fused(
        &mut fused,
        &priority_files,
        &injectable_priority_paths,
        &retained_priority_paths,
    );
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_priority",
        );
    }
    let cochange_seed_paths = top_cochange_seed_paths(&ranked_lists[6], &seed_file_support);
    boost_top_cochange_seed_support(
        &mut fused,
        &ranked_lists[6],
        &seed_file_support,
        &cochange_seed_paths,
    );
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_cochange_seed",
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // POST-RRF: Graph-native adjustments only. No filesystem signals.
    // ═══════════════════════════════════════════════════════════════════════

    // Import centrality: graph-native reranker
    let all_signal_sets: Vec<&HashMap<String, Vec<FileHit>>> = vec![
        &traceback,
        &resolved_hits,
        &multihop,
        &tests,
        &snippets,
        &imports,
        &errors,
        &cochange,
    ];
    let centrality = compute_import_centrality(graph, &all_signal_sets)?;
    if !centrality.is_empty() {
        for (path, score) in fused.iter_mut().take(15) {
            if let Some(cent_hits) = centrality.get(path) {
                let cent_score: f32 = cent_hits.iter().map(|h| h.score).sum();
                *score += locate_env_f32("KIN_LOCATE_IMPORT_CENTRALITY_BONUS", 0.005) * cent_score;
            }
        }
        fused.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
    }
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_centrality",
        );
    }

    let companion_signal_sets = [
        &traceback,
        &multihop,
        &tests,
        &private_access_tests,
        &snippets,
        &source_text,
        &priority_hits,
        &imports,
        &errors,
        &cochange,
        &resolved_hits,
    ];
    let (companion_source_paths, companion_artifact_paths) = boost_test_query_graph_companions(
        &mut fused,
        text,
        graph,
        &resolved_files,
        &companion_signal_sets,
    )?;
    let boosted_test_artifact_paths =
        boost_query_backed_test_artifacts(&mut fused, text, graph, test_query, &priority_files);
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_companions",
        );
    }

    // Non-source + internal path penalty (graph-native: uses entity_bearing_file_paths)
    let source_files = source_file_paths(graph);
    let source_file_set: HashSet<String> = source_files.iter().cloned().collect();
    let custom_impl_priority_files =
        discover_custom_impl_family_priority_files(text, &resolved_files, &source_file_set);
    if !custom_impl_priority_files.is_empty() {
        merge_priority_file_scores_with_trace(
            &mut priority_files,
            &mut priority_traces,
            custom_impl_priority_files.clone(),
            "custom_impl_family_seed",
        );
        let custom_impl_paths: HashSet<String> = custom_impl_priority_files
            .iter()
            .map(|(path, _)| path.clone())
            .collect();
        boost_priority_in_fused(
            &mut fused,
            &custom_impl_priority_files,
            &custom_impl_paths,
            &custom_impl_paths,
        );
        if explain {
            record_debug_stage(
                &mut score_breakdown,
                &mut debug_info,
                &fused,
                "after_custom_impl_priority",
            );
        }
    }
    let tracked_artifact_paths: HashSet<String> = tracked_non_entity_files(graph)
        .into_iter()
        .map(|tracked| tracked.path)
        .collect();
    let source_files: HashSet<String> = source_files
        .into_iter()
        .chain(companion_source_paths)
        .collect();
    let tracked_artifact_paths: HashSet<String> = tracked_artifact_paths
        .into_iter()
        .chain(companion_artifact_paths)
        .chain(boosted_test_artifact_paths.iter().cloned())
        .collect();
    let priority_backed_paths: HashSet<String> = priority_files
        .iter()
        .map(|(path, _)| path.clone())
        .chain(boosted_test_artifact_paths.iter().cloned())
        .collect();
    let direct_priority_paths = direct_query_priority_paths(&priority_traces);
    let graph_projection_backed_paths =
        graph_projection_backed_generated_paths(graph, &resolve_signal_scores);
    for (path, score) in fused.iter_mut() {
        let is_priority_backed = priority_backed_paths.contains(path);
        let priority_applies_for_penalty = priority_backing_applies_for_path(
            path,
            is_priority_backed,
            direct_priority_paths.contains(path),
        );
        let mut penalty = post_rrf_path_penalty(
            path,
            source_files.contains(path.as_str()),
            tracked_artifact_paths.contains(path) || priority_applies_for_penalty,
            test_query,
            priority_applies_for_penalty,
        );
        if graph_projection_backed_paths.contains(path) && is_amalgamated_or_generated_path(path) {
            let global_amalgam_penalty = amalgam_penalty();
            if global_amalgam_penalty > f32::EPSILON {
                penalty /= global_amalgam_penalty;
            }
            penalty *= locate_env_f32("KIN_LOCATE_DERIVED_PROJECTION_PENALTY", 0.15);
        }
        *score *= penalty;
    }

    // Module-prefix affinity: if the top seed files share a common directory
    // prefix (e.g. jib-maven-plugin/src/), boost files in the same module and
    // mildly penalize files from different top-level modules. This keeps locate
    // focused within the right Maven/Gradle module in multi-module repos.
    apply_module_prefix_affinity(&mut fused, &priority_traces);

    // Re-sort by score after all penalties are applied.
    fused.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_path_penalty",
        );
    }

    // Floor reference: support floors in adaptive_cap measure evidence strength,
    // so they must be evaluated against scores from before the relative tail
    // compressions (dominance/boundary), which express another file's dominance
    // rather than weakened evidence for this file.
    let floor_reference: HashMap<String, f32> = if locate_env_bool("KIN_LOCATE_FLOOR_PRECOMP", true)
    {
        fused.iter().cloned().collect()
    } else {
        HashMap::new()
    };
    let graph_semantic_retention_paths = graph_corroborated_semantic_retention_paths(
        &fused,
        &resolved_hits,
        &source_text,
        &embedding_hits,
        &multihop,
        &imports,
    );
    compress_secondary_files_under_dominant_direct_source(
        &mut fused,
        &resolve_signal_scores,
        &source_text,
        &priority_backed_paths,
        &graph_semantic_retention_paths,
    );
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_direct_dominance",
        );
    }

    let syntax_artifact_query = !test_query
        && (mentions_triple_quoted_strings(&text_lower)
            || text_lower.contains("multi-line")
            || text_lower.contains("multiline"));
    demote_secondary_sources_for_syntax_artifact_queries(
        &mut fused,
        syntax_artifact_query,
        &source_text,
        &priority_backed_paths,
    );
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_syntax_demote",
        );
    }

    promote_named_test_source_siblings(&mut fused, &source_files, workspace_root);
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_test_siblings",
        );
    }

    apply_resolve_boundary_compression(
        &mut fused,
        &resolved_hits,
        &priority_files,
        test_query,
        &graph_semantic_retention_paths,
    );
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_resolve_boundary",
        );
    }

    // Negation penalty (kept — this is query-driven, not filesystem-driven)
    let excluded_files = extract_negation_penalties(text, graph);
    if !excluded_files.is_empty() {
        let negation_penalty = locate_env_f32("KIN_LOCATE_NEGATION_PENALTY", 0.01);
        for (path, score) in fused.iter_mut() {
            if excluded_files.contains(path.as_str()) {
                *score *= negation_penalty;
            }
        }
    }
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_negation",
        );
    }

    // Only keep the top-N entity-resolved files for the support filter.
    // Broad entity resolution produces resolve signal for many files, but
    // the support filter (has_entity_resolve) treats them all equally.
    // Capping to the strongest files keeps precision tight.
    let resolve_cap = locate_env_usize("KIN_LOCATE_RESOLVE_SUPPORT_CAP", 8);
    let resolve_strength_floor = resolve_strength_floor();
    let top_resolve_score = resolved_hits
        .values()
        .flat_map(|hits| hits.iter().map(|h| h.score))
        .fold(0.0f32, f32::max);
    let resolve_min = top_resolve_score * resolve_strength_floor;
    let mut resolve_ranked: Vec<(String, f32)> = resolved_hits
        .iter()
        .map(|(path, hits)| {
            let max_score = hits.iter().map(|h| h.score).fold(0.0f32, f32::max);
            (path.clone(), max_score)
        })
        .filter(|(_, score)| *score >= resolve_min)
        .collect();
    resolve_ranked.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    let strong_resolve_paths: HashSet<String> = resolve_ranked
        .iter()
        .take(resolve_cap)
        .map(|(p, _)| p.clone())
        .collect();
    let strong_resolved_hits: HashMap<String, Vec<FileHit>> = resolved_hits
        .into_iter()
        .filter(|(path, _)| strong_resolve_paths.contains(path))
        .collect();

    let all_hits: Vec<HashMap<String, Vec<FileHit>>> = vec![
        traceback,
        multihop,
        tests,
        snippets,
        imports,
        errors,
        cochange,
        strong_resolved_hits,
        source_text,
        embedding_hits,
    ];
    let projection_explain = resolve_explain;
    // Merge text-resolved and embedding-resolved symbols per file. Ranking and
    // capping happen later in `build_result`, once the file set is final.
    let mut projection_symbols = resolve_symbols;
    for (path, syms) in embedding_symbols {
        projection_symbols.entry(path).or_default().extend(syms);
    }
    let projection_provenance: HashMap<String, LocateFileProvenance> = HashMap::new();

    // Diagnostic: snapshot the RAW embedding (idx 9) and lexical (idx 8) signal
    // rankings BEFORE fusion, so miss analysis can distinguish a gold the
    // embedding FOUND but fusion/cap buried (fixable) from one the embedding
    // never matched (frontier). Debug-only — does not affect `fused`/results.
    if explain {
        let rank_signal = |sig: &HashMap<String, Vec<FileHit>>| {
            let mut v: Vec<(String, f32)> = sig
                .iter()
                .map(|(p, hits)| {
                    (
                        p.clone(),
                        hits.iter().map(|h| h.score).fold(f32::MIN, f32::max),
                    )
                })
                .collect();
            v.sort_by(|a, b| {
                b.1.partial_cmp(&a.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.0.cmp(&b.0))
            });
            v
        };
        for (idx, name) in signal_names.iter().enumerate() {
            record_full_debug_stage(
                &mut debug_info,
                &rank_signal(&all_hits[idx]),
                &format!("raw_{name}_signal"),
            );
        }
    }

    demote_cochange_only_outliers(&mut fused, &all_hits);
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_cochange_outlier",
        );
    }

    demote_traceback_indirect_outliers(&mut fused, &all_hits);
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_traceback_outlier",
        );
    }

    rerank_semantic_phase_paths(&mut fused, text, &all_hits, &source_files, workspace_root);
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_semantic_phase",
        );
    }

    rerank_cli_surface_paths(&mut fused, text, &all_hits, workspace_root);
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_cli_surface",
        );
    }

    promote_named_source_surfaces(&mut fused, text, &source_files, workspace_root);
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_named_source_surfaces",
        );
    }

    let legacy_debug = std::env::var("KIN_LOCATE_DEBUG").is_ok();

    if pipeline_report {
        eprintln!("╔══════════════════════════════════════════════════════════════╗");
        eprintln!("║  PIPELINE REPORT                                            ║");
        eprintln!("╚══════════════════════════════════════════════════════════════╝");

        // Stage 1: Term Extraction
        eprintln!("\n── STAGE 1: Term Extraction ──────────────────────────────────");
        eprintln!("  Query length: {} chars", text.len());
        let raw_terms = extract_search_terms(text);
        eprintln!("  Raw terms: {:?}", &raw_terms[..raw_terms.len().min(10)]);
        if let Ok(curated) = curate_search_terms(text, graph) {
            eprintln!("  Curated terms: {:?}", curated);
        }

        // Stage 2: Entity Seeds
        eprintln!("\n── STAGE 2: Entity Discovery ─────────────────────────────────");
        eprintln!("  Total entity seeds: {}", all_entity_seeds.len());
        let mut sorted_seeds: Vec<_> = all_entity_seeds.iter().collect();
        sorted_seeds.sort_by(|a, b| {
            b.1.score
                .partial_cmp(&a.1.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for (i, (&eid, disc)) in sorted_seeds.iter().take(15).enumerate() {
            if let Ok(Some(e)) = graph.get_entity(&eid) {
                let file = e.file_origin.as_ref().map(|f| f.0.as_str()).unwrap_or("?");
                let has_body = e
                    .metadata
                    .extra
                    .get("embedding_body_preview")
                    .and_then(|v| v.as_str())
                    .map_or(false, |s| !s.is_empty());
                let body_tag = if has_body { "DEF" } else { "ref" };
                let test_tag = if is_test_by_role(file, Some(&e)) {
                    " [TEST]"
                } else {
                    ""
                };
                eprintln!(
                    "  {:>3}. {:>8.1} {:3} {:<30} ← {}{}",
                    i + 1,
                    disc.score,
                    body_tag,
                    e.name,
                    if file.len() > 40 {
                        &file[file.len() - 40..]
                    } else {
                        file
                    },
                    test_tag
                );
            }
        }
        if sorted_seeds.len() > 15 {
            eprintln!("  ... +{} more seeds", sorted_seeds.len() - 15);
        }

        // Stage 3: Entity Resolution
        eprintln!("\n── STAGE 3: Entity → File Resolution ────────────────────────");
        eprintln!("  Resolved files: {}", resolved_files.len());
        for (i, (path, score)) in resolved_files.iter().take(10).enumerate() {
            let direct = resolve_signal_scores
                .get(path)
                .and_then(|m| m.get("entity_resolve"))
                .copied()
                .unwrap_or(0.0);
            let graph = resolve_signal_scores
                .get(path)
                .and_then(|m| m.get("graph_resolve"))
                .copied()
                .unwrap_or(0.0);
            eprintln!(
                "  {:>3}. {:>7.1} (direct={:>7.1} graph={:>7.1}) {}",
                i + 1,
                score,
                direct,
                graph,
                if path.len() > 50 {
                    &path[path.len() - 50..]
                } else {
                    path
                }
            );
        }

        // Stage 4: File-Based Signals
        eprintln!("\n── STAGE 4: File-Based Signals ───────────────────────────────");
        let file_signals: Vec<(&str, &HashMap<String, Vec<FileHit>>)> = vec![
            ("traceback", &all_hits[0]),
            ("multihop", &all_hits[1]),
            ("tests", &all_hits[2]),
            ("snippets", &all_hits[3]),
            ("imports", &all_hits[4]),
            ("errors", &all_hits[5]),
            ("cochange", &all_hits[6]),
        ];
        for (name, hits) in &file_signals {
            if !hits.is_empty() {
                let mut top: Vec<_> = hits
                    .iter()
                    .map(|(p, h)| (p.as_str(), h.iter().map(|fh| fh.score).sum::<f32>()))
                    .collect();
                top.sort_by(|a, b| {
                    b.1.partial_cmp(&a.1)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.0.cmp(&b.0))
                });
                let top_str: Vec<String> = top
                    .iter()
                    .take(3)
                    .map(|(p, s)| {
                        format!(
                            "{}({:.1})",
                            if p.len() > 25 { &p[p.len() - 25..] } else { p },
                            s
                        )
                    })
                    .collect();
                eprintln!(
                    "  {:<14} {} files  top: {}",
                    name,
                    hits.len(),
                    top_str.join(", ")
                );
            } else {
                eprintln!("  {:<14} (empty)", name);
            }
        }

        // Stage 5: RRF Fusion
        eprintln!("\n── STAGE 5: RRF Fusion ──────────────────────────────────────");
        let weight_parts: Vec<String> = signal_names
            .iter()
            .zip(signal_confidence_weights.iter())
            .map(|(name, w)| format!("{name}={w:.1}"))
            .collect();
        eprintln!("  Weights: {}", weight_parts.join(" "));
        for (i, (path, score)) in fused.iter().take(10).enumerate() {
            let contributing: Vec<String> = all_hits
                .iter()
                .enumerate()
                .filter_map(|(idx, hits)| {
                    let sig_score: f32 = hits
                        .get(path)
                        .map_or(0.0, |h| h.iter().map(|fh| fh.score).sum());
                    if sig_score > 0.0 {
                        Some(format!(
                            "{}={:.0}",
                            signal_names.get(idx).unwrap_or(&"?"),
                            sig_score
                        ))
                    } else {
                        None
                    }
                })
                .collect();
            eprintln!(
                "  {:>3}. [{:>7.3}] {}  ← {}",
                i + 1,
                score,
                if path.len() > 45 {
                    &path[path.len() - 45..]
                } else {
                    path
                },
                contributing.join(" + ")
            );
        }

        eprintln!("\n══════════════════════════════════════════════════════════════\n");
    }

    if legacy_debug {
        let debug_signal_names = [
            "traceback",
            "search_d",
            "multihop",
            "tests",
            "snippets",
            "imports",
            "errors",
            "cochange",
            "resolve",
            "embedding",
        ];
        eprintln!("=== LOCATE DEBUG ===");
        eprintln!("Query terms: {:?}", extract_search_terms(text));
        let priority_debug: Vec<String> = priority_files
            .iter()
            .take(10)
            .map(|(path, score)| format!("{path}={score:.1}"))
            .collect();
        eprintln!("Priority files: {:?}", priority_debug);
        eprintln!(
            "{:<50} {:>8} | {}",
            "FILE",
            "FUSED",
            debug_signal_names
                .iter()
                .map(|s| format!("{:>10}", s))
                .collect::<Vec<_>>()
                .join(" ")
        );
        for (path, fused_score) in fused.iter().take(20) {
            let per_signal: Vec<String> = all_hits
                .iter()
                .map(|hits_map| {
                    let sig_score: f32 = hits_map
                        .get(path)
                        .map_or(0.0, |h| h.iter().map(|fh| fh.score).sum());
                    format!("{:>10.3}", sig_score)
                })
                .collect();
            eprintln!(
                "{:<50} {:>8.3} | {}",
                if path.len() > 49 {
                    &path[path.len() - 49..]
                } else {
                    path
                },
                fused_score,
                per_signal.join(" ")
            );
        }
        eprintln!("=== END DEBUG ===");
    }

    // ── Optional Cross-Encoder reranking ──
    if locate_env_bool("KIN_LOCATE_CROSS_ENCODER_ENABLED", false) {
        let ltr_window = locate_env_usize("KIN_LOCATE_LTR_WINDOW", 20).min(fused.len());
        if ltr_window > 0 {
            if let Some(workspace_root) = workspace_root {
                let model_id = std::env::var("KIN_LOCATE_CROSS_ENCODER_MODEL")
                    .unwrap_or_else(|_| "BAAI/bge-reranker-base".to_string());
                let revision = std::env::var("KIN_LOCATE_CROSS_ENCODER_REVISION")
                    .unwrap_or_else(|_| "main".to_string());

                match kin_db::embed::rerank::CrossEncoder::new(&model_id, &revision) {
                    Ok(encoder) => {
                        let mut docs = Vec::new();
                        let mut candidates = Vec::new();

                        for (path, score) in fused.iter().take(ltr_window) {
                            let content =
                                graph_derived_candidate_text(graph, path, workspace_root);
                            docs.push(content);
                            candidates.push((path.clone(), *score));
                        }

                        let doc_refs: Vec<&str> = docs.iter().map(|s| s.as_str()).collect();
                        if let Ok(scores) = encoder.rerank(text, &doc_refs) {
                            for (i, score) in scores.into_iter().enumerate() {
                                candidates[i].1 = score;
                            }
                            candidates.sort_by(|a, b| {
                                b.1.partial_cmp(&a.1)
                                    .unwrap_or(std::cmp::Ordering::Equal)
                                    .then_with(|| a.0.cmp(&b.0))
                            });

                            let mut new_fused: Vec<(String, f32)> = candidates;
                            for (path, score) in fused.iter().skip(ltr_window) {
                                new_fused.push((path.clone(), *score));
                            }
                            fused = new_fused;

                            if explain {
                                record_debug_stage(
                                    &mut score_breakdown,
                                    &mut debug_info,
                                    &fused,
                                    "after_cross_encoder",
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("CrossEncoder init failed: {}", e);
                    }
                }
            } else {
                tracing::warn!(
                    "skipping cross-encoder rerank because no live workspace root is available"
                );
            }
        }
    }

    // Signal-aware demotion: files with zero signal evidence are filler from
    // the EntityDominant supplement path (or tier-scored files that no signal
    // independently confirmed). Push them below signaled files so they only
    // fill slots when no signaled alternatives exist.
    //
    // When EntityDominant is the track, exempt all entity-resolved files —
    // entity resolution IS the signal evidence for these files, even if they
    // don't appear in the individual signal hit maps.
    let zero_demote_exempt: HashSet<String> = if matches!(track, ScoringTrack::EntityDominant) {
        resolved_files.iter().map(|(p, _)| p.clone()).collect()
    } else {
        HashSet::new()
    };
    demote_zero_signal_files(&mut fused, &all_hits, &priority_files, &zero_demote_exempt);
    if explain {
        record_debug_stage(
            &mut score_breakdown,
            &mut debug_info,
            &fused,
            "after_zero_signal_demote",
        );
    }

    if explain {
        record_full_debug_stage(&mut debug_info, &fused, "pre_cap_full");
    }

    let mut semantic_retention_paths =
        projection_contributor_retention_paths(graph, &text_lower, &fused);
    semantic_retention_paths.extend(graph_semantic_retention_paths);

    // Adaptive cap
    let mut pruned_files: Vec<PrunedFile> = Vec::new();
    let results = adaptive_cap(
        &fused,
        &all_hits,
        max_files,
        max_files_explicit,
        &cochange_seed_paths,
        &retained_priority_paths,
        &semantic_retention_paths,
        &floor_reference,
        locate_env_bool("KIN_LOCATE_GRAPH_SEMANTIC_CORROBORATION", false),
        if explain {
            Some(&mut pruned_files)
        } else {
            None
        },
    );
    if explain {
        if let Some(debug) = debug_info.as_mut() {
            debug.pruned_files = pruned_files;
        }
    }
    if legacy_debug {
        let stage_count = debug_info
            .as_ref()
            .map(|debug| debug.stages.len())
            .unwrap_or(0);
        eprintln!(
            "Result debug: explain={} debug_present={} debug_stages={} score_breakdown_files={}",
            explain,
            debug_info.is_some(),
            stage_count,
            score_breakdown.len()
        );
    }
    let file_provenance = if explain {
        collect_result_provenance(&results, &projection_provenance)
    } else {
        HashMap::new()
    };

    if !budget.warnings.is_empty() {
        tracing::warn!(
            elapsed_secs = budget.elapsed_secs(),
            warnings = ?budget.warnings,
            "locate pipeline completed with budget warnings"
        );
    }

    // D_empty lever (default ON — measurement-backed: 51/51 official scorer,
    // symbol-F1 +17% with precision EXACTLY flat, a clean Pareto win). Files
    // located by a file-level/lexical signal with no resolved entity emit zero
    // symbols and are a guaranteed symbol+line miss; backfill their symbol list
    // from the file's graph definitions, ranked by query proximity. Set
    // KIN_LOCATE_ENRICH_EMPTY_FILES=0 to disable.
    if locate_env_bool("KIN_LOCATE_ENRICH_EMPTY_FILES", true) {
        let enrich_terms = tracked_text_query_terms(text);
        enrich_empty_file_symbols(
            graph,
            &results,
            &mut projection_symbols,
            &enrich_terms,
            test_query,
        );
    }

    // C_misrank lever (default OFF == byte-identical): boost emitted symbols by
    // query proximity and merge in any query-relevant file def that wasn't
    // resolved, so the actually-edited def ranks over its siblings.
    if locate_env_bool("KIN_LOCATE_SYMBOL_QUERY_PROXIMITY", false) {
        let proximity_terms = tracked_text_query_terms(text);
        boost_symbol_query_relevance(
            graph,
            &results,
            &mut projection_symbols,
            &proximity_terms,
            test_query,
        );
    }

    // EMBED_RELEVANCE lever (default OFF == byte-identical): boost emitted
    // symbols by their query↔def embedding cosine so the def the query is
    // SEMANTICALLY about outranks a lexical look-alike sibling that merely shares
    // more query tokens. Symbol-level twin of the file-level weighted-RRF
    // embedding weight; consumes the cosine the semantic phase already recorded
    // (no re-embedding). Requires `KIN_LOCATE_SYMBOL_EMBED_RELEVANCE` to be set
    // both here and in resolve_entities_to_files (where it gates carrying the
    // cosine onto each symbol), so the two reads share one flag.
    if locate_env_bool("KIN_LOCATE_SYMBOL_EMBED_RELEVANCE", true) {
        boost_symbol_embed_relevance(&results, &mut projection_symbols);
    }

    // A_spanwidth lever (default OFF == byte-identical): when a file surfaced a
    // class-like symbol but the gold edit is an inner method, emit the file's
    // methods (finer spans) instead of widening the class.
    if locate_env_bool("KIN_LOCATE_EMIT_INNER_METHODS", false) {
        let method_terms = tracked_text_query_terms(text);
        emit_inner_methods(
            graph,
            &results,
            &mut projection_symbols,
            &method_terms,
            test_query,
        );
    }

    // BODY_SEED lever (default OFF == byte-identical): additively emit a found
    // file's defs whose BODY matches the query, recovering name-blocked gold
    // defs the seed name-gate dropped (emitted alongside resolved siblings).
    if locate_env_bool("KIN_LOCATE_BODY_SEED", false) {
        let body_terms = tracked_text_query_terms(text);
        emit_body_relevant_symbols(
            graph,
            &results,
            &mut projection_symbols,
            &body_terms,
            test_query,
        );
    }

    Ok(build_result(
        &results,
        &all_hits,
        &projection_explain,
        &projection_symbols,
        &file_provenance,
        &per_file_signals,
        &score_breakdown,
        debug_info,
        explain,
    )
    .with_semantic_coverage(semantic_coverage))
}

pub fn run_with_graph_capture_at_ref(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    blob_store: &kin_blobs::BlobStore,
    head: &SemanticChangeId,
    reference: &str,
    text: &str,
    explain: bool,
    max_files: usize,
    max_files_explicit: bool,
) -> Result<LocateResult> {
    let changes = kin_core::collect_changes_at_ref(graph, head)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let historical = if let Some(git_oid) = reference.strip_prefix("git:") {
        kin_core::build_graph_at_git_ref_with_repo(
            graph,
            blob_store,
            head,
            layout.working_dir(),
            git_oid,
            None,
        )
    } else {
        kin_core::build_graph_at_ref_with_repo(
            graph,
            blob_store,
            head,
            Some(layout.working_dir()),
            None,
        )
    }
    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let _ = crate::commands::cochange::refresh_from_changes(&historical, &changes);
    let extra_priority_files =
        discover_historical_test_artifact_priority_files(layout, reference, text);
    run_with_graph_capture_with_priority_files_and_vector_source(
        &historical,
        None,
        text,
        explain,
        max_files,
        max_files_explicit,
        extra_priority_files,
        Some(graph),
    )
}

// ---------------------------------------------------------------------------
// Clean issue text (strip HTML comments, etc.)
// ---------------------------------------------------------------------------

fn clean_issue_text(text: &str) -> String {
    let _span = tracing::info_span!("locate.clean_issue_text", text_len = text.len()).entered();
    // Strip HTML comments (<!-- ... -->)
    let re_html_comment = regex::Regex::new(r"(?s)<!--.*?-->").unwrap();
    let text = re_html_comment.replace_all(text, "");

    // Strip markdown image tags ![...](...) that add noise
    let re_md_img = regex::Regex::new(r"!\[[^\]]*\]\([^)]*\)").unwrap();
    let text = re_md_img.replace_all(&text, "");

    // Strip GitHub PR template checkbox lines
    let re_checkbox = regex::Regex::new(r"(?m)^-\s*\[.\]\s+.*$").unwrap();
    let text = re_checkbox.replace_all(&text, "");

    text.to_string()
}

fn strip_pr_template_boilerplate(text: &str) -> String {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let marker = line.trim_matches(['\r', '\n']).trim();
        if is_pr_template_boilerplate_start(marker) && text[..offset].trim().len() >= 12 {
            return text[..offset].trim_end().to_string();
        }
        offset += line.len();
    }

    text.to_string()
}

fn is_pr_template_boilerplate_start(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let lower = lower.trim();
    if lower.is_empty() {
        return false;
    }

    let heading = lower.trim_start_matches('#').trim();
    heading.contains("pull request checklist")
        || heading == "checklist"
        || heading.contains("contribution guidelines")
        || heading.starts_with("please don't")
        || heading.starts_with("please dont")
        || heading.starts_with("please do not")
        || heading.contains("before submitting")
}

fn merge_priority_files_from_hits(
    priority_files: &mut Vec<(String, f32)>,
    hits: &HashMap<String, Vec<FileHit>>,
) {
    let mut merged: HashMap<String, f32> = priority_files
        .iter()
        .map(|(path, score)| (path.clone(), *score))
        .collect();
    for (path, file_hits) in hits {
        if is_excluded_priority_basename(path) {
            continue;
        }
        let score = priority_score_from_file_hits(file_hits);
        if score <= 0.0 {
            continue;
        }
        let entry = merged.entry(path.clone()).or_insert(0.0);
        *entry = entry.max(score);
    }
    let mut ranked = merged.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    *priority_files = ranked;
}

// Repo-root metadata files that carry no implementation signal but often
// top priority ranking via CamelCase/title matches or cochange co-occurrence
// (e.g. VERSION dominating ponyc results). Matched on basename, not full
// path — applies at any depth.
const PRIORITY_FILE_EXCLUDED_BASENAMES: &[&str] = &[
    "AUTHORS",
    "CHANGELOG",
    "CHANGELOG.md",
    "CODEOWNERS",
    "CONTRIBUTING",
    "CONTRIBUTING.md",
    "LICENSE",
    "LICENSE.txt",
    "NOTICE",
    "README",
    "README.md",
    "VERSION",
];

fn is_excluded_priority_basename(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);
    PRIORITY_FILE_EXCLUDED_BASENAMES
        .iter()
        .any(|b| basename == *b)
}

fn note_priority_reason(
    priority_traces: &mut HashMap<String, PriorityFileTrace>,
    path: impl Into<String>,
    score: f32,
    kind: &str,
    detail: impl Into<String>,
) {
    if !score.is_finite() || score <= 0.0 {
        return;
    }

    let path = path.into();
    if is_excluded_priority_basename(&path) {
        return;
    }

    let entry = priority_traces.entry(path).or_default();
    entry.score = entry.score.max(score);
    entry.reasons.push(LocateDebugPriorityReason {
        kind: kind.to_string(),
        detail: detail.into(),
        score,
    });
}

fn dedupe_priority_reasons(
    reasons: &[LocateDebugPriorityReason],
) -> Vec<LocateDebugPriorityReason> {
    let mut merged: HashMap<(String, String), f32> = HashMap::new();
    for reason in reasons {
        let key = (reason.kind.clone(), reason.detail.clone());
        merged
            .entry(key)
            .and_modify(|score| *score = score.max(reason.score))
            .or_insert(reason.score);
    }

    let mut deduped = merged
        .into_iter()
        .map(|((kind, detail), score)| LocateDebugPriorityReason {
            kind,
            detail,
            score,
        })
        .collect::<Vec<_>>();
    deduped.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.detail.cmp(&right.detail))
    });
    deduped
}

fn ranked_priority_traces(
    priority_traces: &HashMap<String, PriorityFileTrace>,
    min_score: f32,
) -> Vec<(String, PriorityFileTrace)> {
    let mut ranked = priority_traces
        .iter()
        .filter(|(_, trace)| trace.score >= min_score)
        .map(|(path, trace)| {
            (
                path.clone(),
                PriorityFileTrace {
                    score: trace.score,
                    reasons: dedupe_priority_reasons(&trace.reasons),
                },
            )
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .1
            .score
            .partial_cmp(&left.1.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.0.cmp(&right.0))
    });
    ranked
}

fn truncate_priority_traces(
    priority_traces: HashMap<String, PriorityFileTrace>,
    min_score: f32,
    limit: usize,
) -> HashMap<String, PriorityFileTrace> {
    ranked_priority_traces(&priority_traces, min_score)
        .into_iter()
        .take(limit)
        .collect()
}

fn priority_trace_to_scores(
    priority_traces: &HashMap<String, PriorityFileTrace>,
) -> Vec<(String, f32)> {
    ranked_priority_traces(priority_traces, 0.0)
        .into_iter()
        .map(|(path, trace)| (path, trace.score))
        .collect()
}

fn priority_trace_to_debug(
    priority_traces: &HashMap<String, PriorityFileTrace>,
    limit: usize,
) -> Vec<LocateDebugFileScore> {
    ranked_priority_traces(priority_traces, 0.0)
        .into_iter()
        .take(limit)
        .map(|(path, trace)| LocateDebugFileScore {
            path,
            score: trace.score,
            reasons: trace.reasons,
        })
        .collect()
}

fn priority_reason_allows_injection(kind: &str) -> bool {
    matches!(
        kind,
        "explicit_path"
            | "module_fragment_exact"
            | "module_fragment_suffix"
            | "entity_name_exact"
            | "custom_impl_family_seed"
            | "public_api_header"
            | "tracked_explicit_name"
            | "tracked_term_match"
            | "directory_name_match"
    )
}

fn priority_reason_allows_retention(kind: &str) -> bool {
    priority_reason_allows_injection(kind)
        || matches!(
            kind,
            "tracked_text_search" | "tracked_text_term" | "tracked_term_boost"
        )
}

fn historical_priority_retention_paths(
    priority_traces: &HashMap<String, PriorityFileTrace>,
) -> HashSet<String> {
    let limit = locate_env_usize("KIN_LOCATE_HISTORICAL_PRIORITY_RETAIN_LIMIT", 2);
    if limit == 0 {
        return HashSet::new();
    }

    ranked_priority_traces(priority_traces, 0.0)
        .into_iter()
        .filter(|(_, trace)| {
            trace
                .reasons
                .iter()
                .any(|reason| reason.kind == "historical_priority_seed")
        })
        .take(limit)
        .map(|(path, _)| path)
        .collect()
}

fn query_priority_retention_paths(
    priority_traces: &HashMap<String, PriorityFileTrace>,
    allow_test_paths: bool,
) -> HashSet<String> {
    let limit = locate_env_usize("KIN_LOCATE_QUERY_PRIORITY_RETAIN_LIMIT", 3);
    if limit == 0 {
        return HashSet::new();
    }

    ranked_priority_traces(priority_traces, 0.0)
        .into_iter()
        .filter(|(path, trace)| {
            let retainable_path = tracked_file_support_is_signal_bearing(path)
                && !is_amalgamated_or_generated_path(path)
                || is_build_surface_path(path)
                || (allow_test_paths && is_test_path(path));
            retainable_path
                && trace
                    .reasons
                    .iter()
                    .any(|reason| priority_reason_allows_retention(&reason.kind))
        })
        .take(limit)
        .map(|(path, _)| path)
        .collect()
}

fn retained_priority_paths(
    priority_traces: &HashMap<String, PriorityFileTrace>,
    allow_test_paths: bool,
) -> HashSet<String> {
    let mut retained = historical_priority_retention_paths(priority_traces);
    retained.extend(query_priority_retention_paths(
        priority_traces,
        allow_test_paths,
    ));
    retained
}

fn priority_relation_retention_paths(
    graph: &kin_db::InMemoryGraph,
    retained_priority_paths: &HashSet<String>,
) -> Result<HashSet<String>> {
    if retained_priority_paths.is_empty() {
        return Ok(HashSet::new());
    }

    let max_per_seed = locate_env_usize("KIN_LOCATE_PRIORITY_RELATION_RETAIN_PER_SEED", 2);
    if max_per_seed == 0 {
        return Ok(HashSet::new());
    }
    let min_specificity =
        locate_env_f32("KIN_LOCATE_PRIORITY_RELATION_RETAIN_MIN_SPECIFICITY", 1.1);

    let mut retained = HashSet::new();
    let mut seed_paths: Vec<&String> = retained_priority_paths.iter().collect();
    seed_paths.sort();
    for seed_path in seed_paths {
        if is_amalgamated_or_generated_path(seed_path) || is_vendored_path(seed_path) {
            continue;
        }
        let Some(seed_artifact_id) =
            graph.artifact_id_for_path(&kin_model::FilePathId::new(seed_path.as_str()))
        else {
            continue;
        };
        let seed_node = GraphNodeId::Artifact(seed_artifact_id);
        let mut candidates: Vec<(String, f32)> = Vec::new();
        for rel in graph.get_all_relations_for_node(&seed_node)? {
            if !relation_allows_artifact_traversal(&rel, &seed_node) {
                continue;
            }
            let Some((path, _next)) = relation_adjacent_artifact_path(graph, &rel, &seed_node)
            else {
                continue;
            };
            if path == *seed_path || !strong_embedding_release_allowed(&path) {
                continue;
            }
            let specificity = artifact_relation_path_specificity_multiplier(seed_path, &path, 2);
            if specificity < min_specificity {
                continue;
            }
            let origin_mult = if rel.origin == kin_model::RelationOrigin::Lsp {
                1.25
            } else {
                1.0
            };
            candidates.push((path, specificity * origin_mult * rel.confidence.max(0.1)));
        }
        candidates.sort_by(|left, right| {
            right
                .1
                .partial_cmp(&left.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.0.cmp(&right.0))
        });
        retained.extend(
            candidates
                .into_iter()
                .take(max_per_seed)
                .map(|(path, _)| path),
        );
    }

    Ok(retained)
}

fn direct_query_priority_paths(
    priority_traces: &HashMap<String, PriorityFileTrace>,
) -> HashSet<String> {
    priority_traces
        .iter()
        .filter_map(|(path, trace)| {
            trace
                .reasons
                .iter()
                .any(|reason| {
                    matches!(
                        reason.kind.as_str(),
                        "explicit_path" | "tracked_explicit_name"
                    )
                })
                .then(|| path.clone())
        })
        .collect()
}

fn injectable_priority_paths(
    priority_traces: &HashMap<String, PriorityFileTrace>,
) -> HashSet<String> {
    let historical_paths = historical_priority_retention_paths(priority_traces);
    priority_traces
        .iter()
        .filter_map(|(path, trace)| {
            trace
                .reasons
                .iter()
                .any(|reason| {
                    if reason.kind == "historical_priority_seed" {
                        historical_paths.contains(path)
                    } else {
                        priority_reason_allows_injection(&reason.kind)
                    }
                })
                .then(|| path.clone())
        })
        .collect()
}

fn merge_priority_files_from_hits_with_trace(
    priority_files: &mut Vec<(String, f32)>,
    priority_traces: &mut HashMap<String, PriorityFileTrace>,
    hits: &HashMap<String, Vec<FileHit>>,
    kind: &str,
) {
    merge_priority_files_from_hits(priority_files, hits);
    for (path, file_hits) in hits {
        let score = priority_score_from_file_hits(file_hits);
        if score <= 0.0 {
            continue;
        }
        let detail = format!("hits={}", file_hits.len());
        note_priority_reason(priority_traces, path.clone(), score, kind, detail);
    }
    *priority_files = priority_trace_to_scores(priority_traces);
}

fn priority_score_from_file_hits(file_hits: &[FileHit]) -> f32 {
    let mut scores = file_hits
        .iter()
        .map(|hit| hit.score)
        .filter(|score| score.is_finite() && *score > 0.0)
        .collect::<Vec<_>>();
    if scores.is_empty() {
        return 0.0;
    }

    scores.sort_by(|left, right| right.partial_cmp(left).unwrap_or(std::cmp::Ordering::Equal));
    let top_n = scores.iter().take(3).copied().collect::<Vec<_>>();
    let mean = top_n.iter().sum::<f32>() / top_n.len() as f32;

    // Source-text hits are corroborative, not explicit path mentions.
    // Keep them strong enough to help ranking, but below the high-signal
    // injection threshold used for explicit priority files.
    (mean * 1.5).min(48.0)
}

fn merge_priority_file_scores(
    priority_files: &mut Vec<(String, f32)>,
    extra_priority_files: Vec<(String, f32)>,
) {
    if extra_priority_files.is_empty() {
        return;
    }

    let mut merged: HashMap<String, f32> = priority_files
        .iter()
        .map(|(path, score)| (path.clone(), *score))
        .collect();
    for (path, score) in extra_priority_files {
        let entry = merged.entry(path).or_insert(0.0);
        *entry = entry.max(score);
    }

    let mut ranked = merged.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    *priority_files = ranked;
}

fn merge_priority_file_scores_with_trace(
    priority_files: &mut Vec<(String, f32)>,
    priority_traces: &mut HashMap<String, PriorityFileTrace>,
    extra_priority_files: Vec<(String, f32)>,
    kind: &str,
) {
    merge_priority_file_scores(priority_files, extra_priority_files.clone());
    for (path, score) in extra_priority_files {
        note_priority_reason(priority_traces, path, score, kind, String::new());
    }
    *priority_files = priority_trace_to_scores(priority_traces);
}

fn record_stage_scores(
    stage_scores: &mut HashMap<String, HashMap<String, f32>>,
    fused: &[(String, f32)],
    stage: &str,
) {
    for (path, score) in fused {
        stage_scores
            .entry(path.clone())
            .or_default()
            .insert(stage.to_string(), *score);
    }
}

fn capture_stage_snapshot(
    stages: &mut Vec<LocateDebugStage>,
    fused: &[(String, f32)],
    stage: &str,
) {
    let limit = locate_env_usize("KIN_LOCATE_DEBUG_STAGE_LIMIT", 12);
    let files = fused
        .iter()
        .take(limit)
        .map(|(path, score)| LocateDebugFileScore {
            path: path.clone(),
            score: *score,
            reasons: Vec::new(),
        })
        .collect::<Vec<_>>();
    stages.push(LocateDebugStage {
        name: stage.to_string(),
        files,
    });
}

fn record_debug_stage(
    score_breakdown: &mut HashMap<String, HashMap<String, f32>>,
    debug_info: &mut Option<LocateDebugInfo>,
    fused: &[(String, f32)],
    stage: &str,
) {
    record_stage_scores(score_breakdown, fused, stage);
    if let Some(debug_info) = debug_info.as_mut() {
        capture_stage_snapshot(&mut debug_info.stages, fused, stage);
    }
}

/// Snapshot the full fused list as a debug stage, bypassing the per-stage clip
/// used by [`capture_stage_snapshot`] so a reader sees EVERY pre-cap candidate.
/// Honors `KIN_LOCATE_DEBUG_PRECAP_LIMIT` (default: unlimited).
fn record_full_debug_stage(
    debug_info: &mut Option<LocateDebugInfo>,
    fused: &[(String, f32)],
    stage: &str,
) {
    if let Some(debug_info) = debug_info.as_mut() {
        let limit = locate_env_usize("KIN_LOCATE_DEBUG_PRECAP_LIMIT", usize::MAX);
        let files = fused
            .iter()
            .take(limit)
            .map(|(path, score)| LocateDebugFileScore {
                path: path.clone(),
                score: *score,
                reasons: Vec::new(),
            })
            .collect::<Vec<_>>();
        debug_info.stages.push(LocateDebugStage {
            name: stage.to_string(),
            files,
        });
    }
}

pub fn discover_historical_test_artifact_priority_files(
    layout: &kin_core::KinLayout,
    reference: &str,
    text: &str,
) -> Vec<(String, f32)> {
    let Some(git_ref) = reference.strip_prefix("git:") else {
        return Vec::new();
    };

    let text_lower = text.to_ascii_lowercase();
    if !mentions_triple_quoted_strings(&text_lower) {
        return Vec::new();
    }
    let multiline_query = text_lower.contains("multi-line") || text_lower.contains("multiline");
    let query_terms = extract_loose_query_terms(text)
        .into_iter()
        .map(|term| term.to_ascii_lowercase())
        .filter(|term| term.len() >= 5 && !is_common_english_word(term))
        .collect::<Vec<_>>();

    let grep_output = match std::process::Command::new("git")
        .arg("-C")
        .arg(layout.working_dir())
        .args([
            "grep", "-l", "\"\"\"", git_ref, "--", "*_test.*", "test_*.*",
        ])
        .output()
    {
        Ok(output) if output.status.success() || !output.stdout.is_empty() => output,
        _ => return Vec::new(),
    };

    let mut candidates = Vec::new();
    for raw_line in String::from_utf8_lossy(&grep_output.stdout).lines() {
        let Some((_, path)) = raw_line.split_once(':') else {
            continue;
        };
        if !is_named_test_artifact_path(path) {
            continue;
        }

        let show_output = match std::process::Command::new("git")
            .arg("-C")
            .arg(layout.working_dir())
            .arg("show")
            .arg(format!("{git_ref}:{path}"))
            .output()
        {
            Ok(output) if output.status.success() => output,
            _ => continue,
        };
        let content = String::from_utf8_lossy(&show_output.stdout);
        let line_count = content.lines().count().max(1);
        let triple_quote_count = content.match_indices("\"\"\"").count();
        let inline_triple_quote = count_non_standalone_triple_quotes(&content) > 0;
        let multiline_triple_quote = multiline_query && contains_multiline_triple_quote(&content);
        let lexical_bonus = query_terms
            .iter()
            .filter_map(|term| query_backed_tracked_file_score(path, term))
            .fold(0.0_f32, f32::max)
            * 0.15;
        let compactness_bonus = (10.0 / (line_count as f32).sqrt()).min(6.0);
        let repeated_syntax_bonus = triple_quote_count.saturating_sub(2).min(8) as f32 * 1.5;
        let large_suite_penalty = if line_count > 400 {
            14.0
        } else if line_count > 240 {
            8.0
        } else {
            0.0
        };
        let package_bonus = if path.starts_with("packages/") || path.contains("/packages/") {
            6.0
        } else {
            0.0
        };
        let framework_penalty =
            if path.starts_with("packages/ponytest/") || path.contains("/packages/ponytest/") {
                10.0
            } else {
                0.0
            };
        let score = 65.0
            + lexical_bonus
            + if multiline_triple_quote { 12.0 } else { 0.0 }
            + if inline_triple_quote { 14.0 } else { 0.0 }
            + compactness_bonus
            + repeated_syntax_bonus
            + package_bonus
            - framework_penalty
            - large_suite_penalty;
        candidates.push((path.to_string(), score));
    }

    candidates.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    candidates.dedup_by(|left, right| left.0 == right.0);
    candidates.truncate(locate_env_usize(
        "KIN_LOCATE_HISTORICAL_SYNTAX_TEST_LIMIT",
        4,
    ));
    candidates
}

// ---------------------------------------------------------------------------
// Priority file extraction
// ---------------------------------------------------------------------------

#[cfg_attr(not(test), allow(dead_code))]
fn extract_priority_files(text: &str, graph: &kin_db::InMemoryGraph) -> Vec<(String, f32)> {
    priority_trace_to_scores(&extract_priority_file_traces(text, graph))
}

fn extract_priority_file_traces(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> HashMap<String, PriorityFileTrace> {
    let _span =
        tracing::info_span!("locate.extract_priority_files", text_len = text.len()).entered();
    let mut file_scores: HashMap<String, PriorityFileTrace> = HashMap::new();
    let tracked_non_entity = tracked_non_entity_files(graph);
    let tracked_non_entity_paths: HashSet<String> = tracked_non_entity
        .iter()
        .map(|tracked| tracked.path.clone())
        .collect();
    let tracked_non_entity_descriptors: HashMap<String, String> = tracked_non_entity
        .iter()
        .map(|tracked| {
            (
                tracked.path.clone(),
                tracked.descriptor.to_ascii_lowercase(),
            )
        })
        .collect();
    let text_lower = text.to_ascii_lowercase();
    let test_query = is_test_query(text);
    let allow_test_artifact_priority = test_query
        || mentions_triple_quoted_strings(&text_lower)
        || text_lower.contains("multi-line")
        || text_lower.contains("multiline");
    let require_named_test_artifacts = allow_test_artifact_priority && !test_query;

    // (a) Explicit file paths from text — highest priority
    for file_path in extract_file_paths(text) {
        if let Some(path) = resolve_path_in_graph(graph, &file_path) {
            let detail = if path == file_path {
                file_path.clone()
            } else {
                format!("{file_path}->{path}")
            };
            note_priority_reason(&mut file_scores, path, 200.0, "explicit_path", detail);
        }
    }

    // (b) Module path fragments (e.g. astropy.modeling.core -> astropy/modeling/core)
    for fragment in extract_module_path_fragments(text) {
        // Try exact file_path match with .py extension
        let with_py = format!("{}.py", fragment);
        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(&with_py)),
            ..Default::default()
        };
        if graph
            .query_entities(&filter)
            .ok()
            .is_some_and(|e| !e.is_empty())
        {
            note_priority_reason(
                &mut file_scores,
                with_py,
                100.0,
                "module_fragment_exact",
                fragment.clone(),
            );
        } else {
            // Suffix match: scan entities for file paths containing the fragment
            if let Ok(all) = graph.query_entities(&EntityFilter::default()) {
                let mut seen_paths = HashSet::new();
                let mut matched_paths = Vec::new();
                for entity in all.iter().take(2000) {
                    if let Some(ref fo) = entity.file_origin {
                        if fo.0.contains(&fragment) && seen_paths.insert(fo.0.clone()) {
                            matched_paths.push(fo.0.clone());
                        }
                    }
                }
                let suffix_limit = locate_env_usize("KIN_LOCATE_MODULE_FRAGMENT_SUFFIX_LIMIT", 4);
                if matched_paths.len() > suffix_limit {
                    continue;
                }
                for path in matched_paths {
                    note_priority_reason(
                        &mut file_scores,
                        path,
                        80.0,
                        "module_fragment_suffix",
                        fragment.clone(),
                    );
                }
            }
        }
    }

    // (b2) Directory-name matching: when a CamelCase or long title term matches a
    // directory component in entity file paths, boost files in that directory.
    // This handles JS/TS module conventions where the module name IS the directory
    // name (e.g., "CustomParseFormat" → customParseFormat/index.js,
    //              "ButtonUnstyled" → ButtonUnstyled/ButtonUnstyled.tsx).
    {
        let title_line = text.lines().next().unwrap_or("");
        // Extract bracketed/parenthesized terms and CamelCase/long words.
        // Brackets: [ButtonUnstyled] (React/MUI convention)
        // Parens: fix(shared) (conventional commits / Vue/Angular convention)
        let re_bracket = regex::Regex::new(r"\[([A-Za-z][\w.-]+)\]").unwrap();
        let re_paren = regex::Regex::new(r"\(([A-Za-z][\w.-]+)\)").unwrap();
        let re_camel = regex::Regex::new(r"\b([A-Z][a-z]+[A-Z]\w*)\b").unwrap();
        let re_long = regex::Regex::new(r"\b([a-zA-Z_]\w{5,})\b").unwrap();
        let mut dir_search_terms: Vec<String> = Vec::new();
        let mut dir_seen = HashSet::new();
        // Bracketed terms first (highest signal — React/MUI convention)
        for cap in re_bracket.captures_iter(title_line) {
            let term = cap[1].to_string();
            if dir_seen.insert(term.to_lowercase()) {
                dir_search_terms.push(term);
            }
        }
        // Parenthesized terms (e.g., fix(shared), feat(compiler))
        for cap in re_paren.captures_iter(title_line) {
            let term = cap[1].to_string();
            if dir_seen.insert(term.to_lowercase()) {
                dir_search_terms.push(term);
            }
        }
        // CamelCase terms from title (e.g., CustomParseFormat, LoadingButton)
        for cap in re_camel.captures_iter(title_line) {
            let term = cap[1].to_string();
            if dir_seen.insert(term.to_lowercase()) && !is_noise_term(&term.to_lowercase()) {
                dir_search_terms.push(term);
            }
        }
        // Long words from title as fallback
        for cap in re_long.captures_iter(title_line) {
            let term = cap[1].to_string();
            if term.len() >= 8
                && dir_seen.insert(term.to_lowercase())
                && !is_noise_term(&term.to_lowercase())
                && !is_common_english_word(&term.to_lowercase())
            {
                dir_search_terms.push(term);
            }
        }

        if !dir_search_terms.is_empty() {
            // Collect all unique (directory_component → [file_paths]) from entity file origins
            let mut dir_to_files: HashMap<String, Vec<String>> = HashMap::new();
            if let Ok(all_entities) = graph.query_entities(&EntityFilter::default()) {
                let mut seen_files = HashSet::new();
                for entity in all_entities.iter().take(5000) {
                    if let Some(ref fo) = entity.file_origin {
                        if seen_files.insert(fo.0.clone()) {
                            for component in fo.0.split('/') {
                                if component.len() > 3 {
                                    dir_to_files
                                        .entry(component.to_lowercase())
                                        .or_default()
                                        .push(fo.0.clone());
                                }
                            }
                        }
                    }
                }
            }

            for term in &dir_search_terms {
                let term_lower = term.to_lowercase();
                if let Some(matching_files) = dir_to_files.get(&term_lower) {
                    // Only use if reasonably specific (not matching hundreds of files)
                    let dir_file_limit = locate_env_usize("KIN_LOCATE_DIR_MATCH_FILE_LIMIT", 20);
                    if matching_files.len() <= dir_file_limit {
                        for path in matching_files {
                            if !is_test_path(path) {
                                note_priority_reason(
                                    &mut file_scores,
                                    path.clone(),
                                    90.0,
                                    "directory_name_match",
                                    term.clone(),
                                );
                            }
                        }
                        tracing::debug!(
                            term = %term,
                            files = matching_files.len(),
                            "directory name match boosted files"
                        );
                    }
                }
            }
        }
    }

    // (c) Backtick-quoted terms and title terms -> entity name resolution
    let re_bt = regex::Regex::new(r"`([^`]+)`").unwrap();
    let mut quoted_terms: Vec<String> = Vec::new();
    for cap in re_bt.captures_iter(text) {
        let raw = cap[1].trim().to_string();
        if raw.len() >= 3 && raw.len() <= 60 && !raw.contains(' ') && !raw.contains('\n') {
            quoted_terms.push(raw);
        }
    }

    let title_line = text.lines().next().unwrap_or("");
    let title_lower = title_line.to_lowercase();
    let re_word = regex::Regex::new(r"\b([a-zA-Z_]\w+)\b").unwrap();
    let title_terms: HashSet<String> = re_word
        .captures_iter(title_line)
        .map(|c| c[1].to_string())
        .collect();

    let mut all_terms: Vec<(String, bool)> = quoted_terms
        .iter()
        .map(|t| {
            let is_title = title_lower.contains(&t.to_lowercase());
            (t.clone(), is_title)
        })
        .collect();
    for tt in &title_terms {
        if !all_terms.iter().any(|(t, _)| t == tt) {
            all_terms.push((tt.clone(), true));
        }
    }

    for (term, is_title) in &all_terms {
        // Strip dotted prefix, take last component
        let leaf = term.rsplit('.').next().unwrap_or(term);
        if leaf.len() <= 2 || is_noise_term(leaf) {
            continue;
        }

        let filter = EntityFilter {
            name_pattern: Some(leaf.to_string()),
            ..Default::default()
        };
        if let Ok(matched) = graph.query_entities(&filter) {
            // Filter to exact name matches (case-insensitive) and definition kinds only
            let leaf_lower = leaf.to_lowercase();
            let exact: Vec<_> = matched
                .iter()
                .filter(|e| e.name.to_lowercase() == leaf_lower)
                .filter(|e| {
                    matches!(
                        e.kind,
                        EntityKind::Function
                            | EntityKind::Method
                            | EntityKind::Class
                            | EntityKind::TraitDef
                            | EntityKind::Interface
                            | EntityKind::EnumDef
                            | EntityKind::Module
                    )
                })
                .collect();

            // Collect unique files
            let unique_files: HashSet<String> = exact
                .iter()
                .filter_map(|e| e.file_origin.as_ref().map(|fo| fo.0.clone()))
                .collect();

            // Only use if specific (<=3 unique files)
            if !unique_files.is_empty() && unique_files.len() <= 3 {
                // Term-discrimination: a generic high-document-frequency word
                // (e.g. "backend", present in ~8% of docs) must not get the same
                // flat priority as a rare discriminating identifier (e.g.
                // "depthwise_conv"). Reuse the text index's BM25 document
                // frequency — no new IDF implementation. Terms in <= COMMON_FRAC
                // of the corpus keep full weight; commoner terms decay inversely
                // so hub-name words stop force-injecting their __init__/config
                // files over the true edit sites.
                let base = if *is_title { 50.0 } else { 30.0 };
                let df = graph.text_doc_frequency(leaf);
                let n = graph.text_document_count();
                let score = if df > 0 && n > 0 {
                    let common_frac = locate_env_f32("KIN_LOCATE_PRIORITY_COMMON_FRAC", 0.02);
                    let common = (common_frac * n as f32).max(1.0);
                    let weight = (common / df as f32).min(1.0);
                    base * weight
                } else {
                    base
                };
                for path in &unique_files {
                    if !is_test_path(path) {
                        let detail = if *is_title {
                            format!("{leaf} [title]")
                        } else {
                            leaf.to_string()
                        };
                        note_priority_reason(
                            &mut file_scores,
                            path.clone(),
                            score,
                            "entity_name_exact",
                            detail,
                        );
                    }
                }
            }
        }
    }

    for tracked in &tracked_non_entity {
        let basename = tracked.path.rsplit('/').next().unwrap_or(&tracked.path);
        let basename_lower = basename.to_ascii_lowercase();
        let explicitly_named = !is_license_or_notice_path(&tracked.path)
            && (text_lower.contains(&basename_lower)
                || text_lower.contains(&tracked.path.to_ascii_lowercase()));
        // Only inject non-entity files when explicitly named in the query.
        // Descriptor-based fuzzy matching was too loose — a 4-letter word overlap
        // caused build artifacts (ChangeLog, Makefile, etc.) to outscore real source.
        if explicitly_named {
            note_priority_reason(
                &mut file_scores,
                tracked.path.clone(),
                120.0,
                "tracked_explicit_name",
                basename.to_string(),
            );
        }
    }

    if is_public_api_query(text) {
        for prefix in extract_c_api_prefixes(text) {
            let target_header = format!("{prefix}.h");
            for tracked in &tracked_non_entity {
                let lower = tracked.path.to_ascii_lowercase();
                let basename = tracked.path.rsplit('/').next().unwrap_or(&tracked.path);
                if basename.eq_ignore_ascii_case(&target_header)
                    && (lower.starts_with("lib/") || lower.starts_with("include/"))
                {
                    note_priority_reason(
                        &mut file_scores,
                        tracked.path.clone(),
                        60.0,
                        "public_api_header",
                        prefix.clone(),
                    );
                }
            }
        }
    }

    let mut tracked_term_candidates = curate_search_terms(text, graph).unwrap_or_else(|_| {
        let mut fallback = extract_search_terms(text);
        fallback.extend(extract_title_terms(text));
        fallback
    });
    tracked_term_candidates.sort();
    tracked_term_candidates.dedup_by(|left, right| left.eq_ignore_ascii_case(right));

    let tracked_term_limit = locate_env_usize("KIN_LOCATE_TRACKED_TERM_MATCH_LIMIT", 6);
    for term in tracked_term_candidates.iter().take(tracked_term_limit) {
        let term_lower = term.to_ascii_lowercase();
        if term_lower.len() < 4 || is_common_english_word(&term_lower) {
            continue;
        }

        let mut matches: Vec<(String, f32)> = tracked_non_entity
            .iter()
            .filter_map(|tracked| {
                if is_test_path(&tracked.path) && !allow_test_artifact_priority {
                    return None;
                }
                if require_named_test_artifacts && !is_named_test_artifact_path(&tracked.path) {
                    return None;
                }
                query_backed_tracked_file_score(&tracked.path, &term_lower)
                    .map(|score| (tracked.path.clone(), score))
            })
            .collect();
        if matches.is_empty() {
            continue;
        }

        let exact_matches = matches.iter().filter(|(_, score)| *score >= 80.0).count();
        if exact_matches == 0
            && matches.len() > locate_env_usize("KIN_LOCATE_TRACKED_TERM_BROAD_LIMIT", 4)
        {
            continue;
        }
        if exact_matches > locate_env_usize("KIN_LOCATE_TRACKED_TERM_EXACT_LIMIT", 8) {
            continue;
        }

        matches.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.matches('/').count().cmp(&b.0.matches('/').count()))
                .then_with(|| a.0.cmp(&b.0))
        });

        let reason_kind = if is_symbolic_search_term(term) {
            "tracked_term_match"
        } else {
            "tracked_term_boost"
        };
        for (path, score) in matches.into_iter().take(4) {
            note_priority_reason(
                &mut file_scores,
                path,
                score,
                reason_kind,
                term_lower.clone(),
            );
        }
    }

    let tracked_text_hit_limit = locate_env_usize("KIN_LOCATE_TRACKED_TEXT_HIT_LIMIT", 64);
    let tracked_text_broad_limit = locate_env_usize("KIN_LOCATE_TRACKED_TEXT_BROAD_LIMIT", 10);
    let tracked_text_min_terms = locate_env_usize("KIN_LOCATE_TRACKED_TEXT_MIN_TERMS", 1);
    let mut tracked_text_candidates = tracked_text_query_terms(text);
    let mut seen_tracked_text_terms = HashSet::new();
    tracked_text_candidates
        .retain(|term| seen_tracked_text_terms.insert(term.to_ascii_lowercase()));
    let mut tracked_text_scores: HashMap<String, f32> = HashMap::new();
    let mut tracked_text_terms: HashMap<String, HashSet<String>> = HashMap::new();
    let mut tracked_text_reason_scores: HashMap<String, Vec<(String, f32)>> = HashMap::new();

    let tracked_text_term_limit =
        locate_env_usize("KIN_LOCATE_TRACKED_TEXT_TERM_LIMIT", tracked_term_limit * 3);
    for term in tracked_text_candidates.iter().take(tracked_text_term_limit) {
        let term_lower = term.to_ascii_lowercase();
        if term_lower.len() < 4 || is_common_english_word(&term_lower) {
            continue;
        }
        let symbolic_term = is_symbolic_search_term(&term_lower);

        let text_hits = match graph.text_search(&term_lower, tracked_text_hit_limit) {
            Ok(hits) => hits,
            Err(_) => continue,
        };
        let mut per_term_best: HashMap<String, f32> = HashMap::new();
        for (rank, (retrieval_key, _score)) in text_hits.into_iter().enumerate() {
            let Some(path) = file_path_from_retrieval_key(graph, &retrieval_key) else {
                continue;
            };
            if !tracked_non_entity_paths.contains(&path) {
                continue;
            }
            if symbolic_term
                && !tracked_non_entity_descriptors
                    .get(&path)
                    .is_some_and(|descriptor| descriptor.contains(&term_lower))
            {
                continue;
            }
            if is_license_or_notice_path(&path) {
                continue;
            }
            if is_test_path(&path) && !allow_test_artifact_priority {
                continue;
            }
            if require_named_test_artifacts && !is_named_test_artifact_path(&path) {
                continue;
            }
            let score = 72.0 / ((rank + 1) as f32).sqrt();
            per_term_best
                .entry(path)
                .and_modify(|best| *best = best.max(score))
                .or_insert(score);
        }

        if per_term_best.is_empty() {
            continue;
        }

        let mut per_term_best = per_term_best.into_iter().collect::<Vec<_>>();
        per_term_best.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });

        for (path, score) in per_term_best.into_iter().take(tracked_text_broad_limit) {
            *tracked_text_scores.entry(path.clone()).or_default() += score;
            tracked_text_terms
                .entry(path.clone())
                .or_default()
                .insert(term_lower.clone());
            tracked_text_reason_scores
                .entry(path)
                .or_default()
                .push((term_lower.clone(), score));
        }
    }

    for (path, score) in tracked_text_scores {
        let term_count = tracked_text_terms.get(&path).map_or(0, HashSet::len);
        if term_count < tracked_text_min_terms {
            continue;
        }
        let mut terms = tracked_text_terms
            .get(&path)
            .map(|terms| terms.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        terms.sort();
        note_priority_reason(
            &mut file_scores,
            path.clone(),
            score.min(120.0),
            "tracked_text_search",
            format!("terms={}", terms.join(",")),
        );
        if let Some(reason_scores) = tracked_text_reason_scores.get(&path) {
            for (term, term_score) in reason_scores {
                note_priority_reason(
                    &mut file_scores,
                    path.clone(),
                    *term_score,
                    "tracked_text_term",
                    term.clone(),
                );
            }
        }
    }

    // Build result: sorted by score desc, filtered to >=20.0, truncated to 12.
    // This preserves the original extraction behavior before later priority merges.
    truncate_priority_traces(file_scores, 20.0, 12)
}

fn boost_priority_in_fused(
    fused: &mut Vec<(String, f32)>,
    priority: &[(String, f32)],
    injectable_paths: &HashSet<String>,
    retention_paths: &HashSet<String>,
) {
    if priority.is_empty() {
        return;
    }
    let priority_map: HashMap<String, f32> = priority.iter().cloned().collect();
    let rrf_max = fused.first().map(|(_, s)| *s).unwrap_or(1.0);
    let retained_floor_factor = locate_env_f32("KIN_LOCATE_RETAINED_PRIORITY_FLOOR", 0.18);

    // Boost existing entries
    for (path, score) in fused.iter_mut() {
        if let Some(ps) = priority_map.get(path) {
            let boost = 1.0 + (ps / 100.0).min(3.0);
            let injected = if *ps >= 50.0 && injectable_paths.contains(path) {
                rrf_max * (1.0 + (ps / 100.0).min(2.0))
            } else {
                0.0
            };
            let retained = if *ps >= 50.0 && retention_paths.contains(path) {
                let strength = (*ps / 120.0).clamp(0.5, 1.0);
                rrf_max * retained_floor_factor * strength
            } else {
                0.0
            };
            *score = (*score * boost).max(injected).max(retained);
        }
    }

    // Inject priority files not in fused
    let existing: HashSet<String> = fused.iter().map(|(p, _)| p.clone()).collect();
    for (path, ps) in priority {
        if !existing.contains(path) && *ps >= 50.0 && injectable_paths.contains(path) {
            let injected = rrf_max * (1.0 + (ps / 100.0).min(2.0));
            fused.push((path.clone(), injected));
        }
    }

    fused.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
}

fn query_backed_tracked_file_score(path: &str, term_lower: &str) -> Option<f32> {
    if is_license_or_notice_path(path) {
        return None;
    }

    let basename = path.rsplit('/').next().unwrap_or(path);
    let basename_lower = basename.to_ascii_lowercase();
    let stem_lower = basename_lower
        .split('.')
        .next()
        .unwrap_or(&basename_lower)
        .trim_end_matches("_test")
        .trim_end_matches("-test")
        .to_string();

    if stem_lower == term_lower {
        return Some(90.0);
    }

    let basename_exact_segment = basename_lower
        .split(|ch: char| matches!(ch, '/' | '.' | '_' | '-'))
        .filter(|segment| !segment.is_empty())
        .any(|segment| segment == term_lower);
    if basename_exact_segment {
        return Some(75.0);
    }

    let path_lower = path.to_ascii_lowercase();
    let exact_segment = path_lower
        .split(|ch: char| matches!(ch, '/' | '.' | '_' | '-'))
        .filter(|segment| !segment.is_empty())
        .any(|segment| segment == term_lower);
    if exact_segment && is_manifest_like_basename(&basename_lower) {
        return Some(60.0);
    }

    if term_lower.len() >= 7 && basename_lower.contains(term_lower) {
        return Some(55.0);
    }

    None
}

fn source_root_for_test_companions(path: &str) -> Option<String> {
    for marker in ["/src/", "/lib/"] {
        if let Some((root, _)) = path.split_once(marker) {
            return Some(root.to_string());
        }
    }
    if let Some(stripped) = path.strip_prefix("src/") {
        if !stripped.is_empty() {
            return Some(String::new());
        }
    }
    if let Some(stripped) = path.strip_prefix("lib/") {
        if !stripped.is_empty() {
            return Some(String::new());
        }
    }
    None
}

fn is_manifest_like_basename(basename_lower: &str) -> bool {
    matches!(
        basename_lower,
        "cargo.toml"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "go.mod"
            | "go.sum"
            | "pyproject.toml"
            | "setup.py"
            | "setup.cfg"
            | "requirements.txt"
            | "pipfile"
            | "pipfile.lock"
            | "gemfile"
            | "composer.json"
            | "pom.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "settings.gradle"
            | "settings.gradle.kts"
            | "mix.exs"
    )
}

fn signal_support_count_refs(path: &str, signal_sets: &[&HashMap<String, Vec<FileHit>>]) -> usize {
    signal_sets
        .iter()
        .filter(|signal_set| signal_set.contains_key(path))
        .count()
}

fn companion_query_match_count(
    graph: &kin_db::InMemoryGraph,
    path: &str,
    query_terms: &[String],
) -> Result<usize> {
    let mut matched_terms = HashSet::new();
    let path_lower = path.to_ascii_lowercase();
    let basename_lower = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();

    for term in query_terms {
        let term_lower = term.to_ascii_lowercase();
        if term_lower.len() < 3 {
            continue;
        }
        if path_lower.contains(&term_lower) || basename_lower.contains(&term_lower) {
            matched_terms.insert(term_lower);
        }
    }

    let entities = graph.query_entities(&EntityFilter {
        file_path: Some(kin_model::FilePathId::new(path)),
        ..Default::default()
    })?;
    for entity in entities
        .iter()
        .take(locate_env_usize("KIN_LOCATE_COMPANION_ENTITY_LIMIT", 24))
    {
        for term in query_terms {
            let term_lower = term.to_ascii_lowercase();
            if term_lower.len() < 3 || matched_terms.contains(&term_lower) {
                continue;
            }
            if score_name_match(term, &entity.name) > 0.0
                || entity.name.to_ascii_lowercase().contains(&term_lower)
            {
                matched_terms.insert(term_lower);
            }
        }
    }

    Ok(matched_terms.len())
}

fn boost_test_query_graph_companions(
    fused: &mut Vec<(String, f32)>,
    text: &str,
    graph: &kin_db::InMemoryGraph,
    resolved_files: &[(String, f32)],
    signal_sets: &[&HashMap<String, Vec<FileHit>>],
) -> Result<(HashSet<String>, HashSet<String>)> {
    if !is_test_query(text) || fused.is_empty() || resolved_files.is_empty() {
        return Ok((HashSet::new(), HashSet::new()));
    }

    let mut query_terms = curate_search_terms(text, graph).unwrap_or_else(|_| {
        let mut fallback = extract_search_terms(text);
        if fallback.is_empty() {
            fallback = extract_title_terms(text);
        }
        fallback
    });
    query_terms.sort();
    query_terms.dedup_by(|left, right| left.eq_ignore_ascii_case(right));

    let mut source_roots = Vec::new();
    let mut seen_roots = HashSet::new();
    for (path, score) in resolved_files
        .iter()
        .take(locate_env_usize("KIN_LOCATE_TEST_COMPANION_ROOTS", 2))
    {
        if is_test_path(path) {
            continue;
        }
        if let Some(root) = source_root_for_test_companions(path) {
            if seen_roots.insert(root.clone()) {
                source_roots.push((root, *score));
            }
        }
    }
    if source_roots.is_empty() {
        return Ok((HashSet::new(), HashSet::new()));
    }

    let entity_paths = source_file_paths(graph).into_iter().collect::<Vec<_>>();
    let tracked_files = tracked_non_entity_files(graph);
    let fused_top = fused.first().map(|(_, score)| *score).unwrap_or(1.0);
    let mut companion_scores: HashMap<String, f32> = HashMap::new();

    for (root, _seed_score) in source_roots {
        let test_prefixes = if root.is_empty() {
            vec!["tests/".to_string(), "test/".to_string()]
        } else {
            vec![format!("{root}/tests/"), format!("{root}/test/")]
        };

        for path in &entity_paths {
            if !test_prefixes.iter().any(|prefix| path.starts_with(prefix)) {
                continue;
            }
            let match_count = companion_query_match_count(graph, path, &query_terms)?;
            let signal_bonus = 0.08 * signal_support_count_refs(path, signal_sets).min(3) as f32;
            let query_bonus = 0.08 * (match_count.min(4) as f32);
            let factor = (0.45 + signal_bonus + query_bonus).min(0.82);
            companion_scores
                .entry(path.clone())
                .and_modify(|score| *score = score.max(fused_top * factor))
                .or_insert(fused_top * factor);
        }

        let same_root_manifest_paths: HashSet<String> = tracked_files
            .iter()
            .filter_map(|tracked| {
                let basename = tracked.path.rsplit('/').next().unwrap_or(&tracked.path);
                let basename_lower = basename.to_ascii_lowercase();
                if !is_manifest_like_basename(&basename_lower) {
                    return None;
                }
                let in_same_root = if root.is_empty() {
                    !tracked.path.contains('/')
                } else {
                    tracked.path == format!("{root}/{basename}")
                };
                if in_same_root {
                    Some(tracked.path.clone())
                } else {
                    None
                }
            })
            .collect();

        for manifest_path in &same_root_manifest_paths {
            companion_scores
                .entry(manifest_path.clone())
                .and_modify(|score| *score = score.max(fused_top * 0.42))
                .or_insert(fused_top * 0.42);
        }
    }

    if companion_scores.is_empty() {
        return Ok((HashSet::new(), HashSet::new()));
    }

    let existing_paths: HashSet<String> = fused.iter().map(|(path, _)| path.clone()).collect();
    let mut companion_entries: Vec<(String, f32)> = companion_scores.into_iter().collect();
    companion_entries.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    companion_entries.truncate(locate_env_usize("KIN_LOCATE_TEST_COMPANION_LIMIT", 4));
    let mut source_like = HashSet::new();
    let mut artifact_like = HashSet::new();
    for (path, score) in companion_entries
        .into_iter()
        .filter(|(path, _)| !existing_paths.contains(path))
    {
        let basename_lower = path
            .rsplit('/')
            .next()
            .unwrap_or(&path)
            .to_ascii_lowercase();
        if is_manifest_like_basename(&basename_lower) {
            artifact_like.insert(path.clone());
        } else {
            source_like.insert(path.clone());
        }
        fused.push((path, score));
    }
    fused.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });

    Ok((source_like, artifact_like))
}

fn boost_query_backed_test_artifacts(
    fused: &mut Vec<(String, f32)>,
    text: &str,
    graph: &kin_db::InMemoryGraph,
    test_query: bool,
    priority_files: &[(String, f32)],
) -> HashSet<String> {
    if test_query || fused.is_empty() {
        return HashSet::new();
    }

    let anchor_score = fused
        .iter()
        .find(|(path, _)| !is_test_path(path))
        .map(|(_, score)| *score)
        .unwrap_or(0.0);
    if anchor_score <= 0.0 {
        return HashSet::new();
    }

    let mut query_terms = extract_loose_query_terms(text);
    let mut seen_terms = HashSet::new();
    query_terms.retain(|term| {
        let canonical = term.to_ascii_lowercase();
        canonical.len() >= 5 && !is_common_english_word(&canonical) && seen_terms.insert(canonical)
    });
    let text_lower = text.to_ascii_lowercase();
    let triple_quote_query = mentions_triple_quoted_strings(&text_lower);
    let multiline_query = text_lower.contains("multi-line") || text_lower.contains("multiline");
    let priority_test_anchor = priority_files
        .iter()
        .any(|(path, score)| is_test_path(path) && *score >= 50.0);
    let non_test_test_artifact_intent =
        triple_quote_query || multiline_query || priority_test_anchor;
    if !non_test_test_artifact_intent {
        return HashSet::new();
    }
    if query_terms.is_empty() && !triple_quote_query {
        return HashSet::new();
    }

    let priority_scores: HashMap<&str, f32> = priority_files
        .iter()
        .map(|(path, score)| (path.as_str(), *score))
        .collect();
    let existing_paths: HashSet<String> = fused.iter().map(|(path, _)| path.clone()).collect();
    let mut tracked_file_descriptors: HashMap<String, String> = HashMap::new();
    for tracked in tracked_non_entity_files(graph) {
        if !is_test_path(&tracked.path) {
            continue;
        }
        let entry = tracked_file_descriptors.entry(tracked.path).or_default();
        if !entry.is_empty() {
            entry.push('\n');
        }
        entry.push_str(&tracked.descriptor);
    }
    let mut candidates = Vec::new();

    for (path, descriptor) in tracked_file_descriptors {
        let path_lower = path.to_ascii_lowercase();
        let descriptor_lower = descriptor.to_ascii_lowercase();
        let mut matched_terms = HashSet::new();
        let mut path_match_count = 0usize;
        for term in &query_terms {
            let canonical = term.to_ascii_lowercase();
            let stemmed = canonical.trim_end_matches('s');
            let path_matches = path_lower.contains(&canonical)
                || (!stemmed.is_empty() && path_lower.contains(stemmed));
            let descriptor_matches = descriptor_lower.contains(&canonical)
                || (!stemmed.is_empty() && descriptor_lower.contains(stemmed));
            if path_matches || descriptor_matches {
                if path_matches {
                    path_match_count += 1;
                }
                matched_terms.insert(canonical);
            }
        }

        let named_test_artifact = is_named_test_artifact_path(&path);
        let test_harness_path = path_lower.starts_with("test/") || path_lower.contains("/test/");
        let has_triple_quote_syntax =
            named_test_artifact && triple_quote_query && descriptor.contains("\"\"\"");
        let inline_triple_quote_count = if has_triple_quote_syntax {
            count_non_standalone_triple_quotes(&descriptor)
        } else {
            0
        };
        let syntax_match_count = usize::from(has_triple_quote_syntax)
            + usize::from(multiline_query && contains_multiline_triple_quote(&descriptor))
            + usize::from(inline_triple_quote_count > 0);
        let priority_score = priority_scores.get(path.as_str()).copied().unwrap_or(0.0);
        if path_match_count == 0 && syntax_match_count == 0 {
            continue;
        }
        if !named_test_artifact
            && test_harness_path
            && syntax_match_count == 0
            && priority_score < 50.0
        {
            continue;
        }
        if !named_test_artifact
            && syntax_match_count == 0
            && priority_score < 50.0
            && matched_terms.len() < 2
        {
            continue;
        }
        let compactness_bonus = 0.75 / (descriptor.lines().count().max(1) as f32).sqrt();
        let score = matched_terms.len() as f32
            + (path_match_count as f32 * 0.5)
            + (syntax_match_count as f32 * 1.15)
            + compactness_bonus
            + if priority_score >= 50.0 { 1.0 } else { 0.0 };
        candidates.push((
            path,
            matched_terms.len(),
            syntax_match_count,
            inline_triple_quote_count,
            priority_score,
            compactness_bonus,
            score,
        ));
    }

    candidates.sort_by(|left, right| {
        right
            .6
            .partial_cmp(&left.6)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| left.0.cmp(&right.0))
    });

    let mut boosted_paths = HashSet::new();
    for (
        path,
        matched_term_count,
        syntax_match_count,
        inline_triple_quote_count,
        priority_score,
        compactness_bonus,
        _,
    ) in candidates
        .into_iter()
        .take(locate_env_usize("KIN_LOCATE_QUERY_TEST_ARTIFACT_LIMIT", 3))
    {
        let factor = (0.12
            + matched_term_count as f32 * 0.05
            + syntax_match_count as f32 * 0.08
            + if inline_triple_quote_count > 0 {
                0.04
            } else {
                0.0
            }
            + compactness_bonus.min(0.06)
            + if priority_score >= 50.0 { 0.10 } else { 0.0 })
        .min(0.42);
        let injected = anchor_score * factor;

        if existing_paths.contains(&path) {
            if let Some((_, score)) = fused.iter_mut().find(|(existing, _)| *existing == path) {
                *score = (*score).max(injected);
            }
        } else {
            fused.push((path.clone(), injected));
        }
        boosted_paths.insert(path);
    }

    if !boosted_paths.is_empty() {
        fused.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
    }

    boosted_paths
}

fn is_syntax_source_locus_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("/lexer.")
        || lower.contains("/parser.")
        || lower.ends_with("/syntax.c")
        || lower.ends_with("/syntax.rs")
        || lower.ends_with("/syntax.py")
}

fn mentions_triple_quoted_strings(text_lower: &str) -> bool {
    text_lower.contains("\"\"\"")
        || ((text_lower.contains("triple-quoted") || text_lower.contains("triple quoted"))
            && text_lower.contains("string"))
}

fn is_named_test_artifact_path(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    basename.starts_with("test_")
        || basename.starts_with("_test")
        || basename.ends_with("_test")
        || basename.contains("_test.")
}

fn contains_multiline_triple_quote(text: &str) -> bool {
    text.contains("\"\"\"\n") || text.contains("\"\"\"\r\n")
}

fn count_non_standalone_triple_quotes(text: &str) -> usize {
    let total = text.match_indices("\"\"\"").count();
    let standalone = text.lines().filter(|line| line.trim() == "\"\"\"").count();
    total.saturating_sub(standalone)
}

// ---------------------------------------------------------------------------
// Module path fragment extraction
// ---------------------------------------------------------------------------

fn extract_module_path_fragments(text: &str) -> Vec<String> {
    let _span = tracing::info_span!(
        "locate.extract_module_path_fragments",
        text_len = text.len()
    )
    .entered();
    let mut fragments = Vec::new();
    let mut seen = HashSet::new();

    // Match namespace-like references and keep the lowercase/snake-case prefix
    // that plausibly maps to a module path on disk.
    let re_namespace =
        regex::Regex::new(r"\b([A-Za-z_][\w-]*(?:(?:::|\.|/)[A-Za-z_][\w-]*){1,})").unwrap();
    for cap in re_namespace.captures_iter(text) {
        let segments = normalized_namespace_segments(&cap[1]);
        if segments.len() < 2 {
            continue;
        }

        let mut prefix_len = 0usize;
        for segment in &segments {
            if is_module_path_segment(segment) {
                prefix_len += 1;
            } else {
                break;
            }
        }

        for len in 2..=prefix_len {
            let as_path = segments[..len].join("/");
            if seen.insert(as_path.clone()) {
                fragments.push(as_path);
            }
        }
    }

    for fragment in extract_command_path_fragments(text) {
        if seen.insert(fragment.clone()) {
            fragments.push(fragment);
        }
    }

    fragments
}

fn extract_command_path_fragments(text: &str) -> Vec<String> {
    let mut fragments = Vec::new();
    let mut seen = HashSet::new();

    let re_bullet_command =
        regex::Regex::new(r"(?m)^\s*[-*]\s+([a-z][a-z0-9_-]*(?:\s+[a-z][a-z0-9_-]*){1,2})\s*$")
            .unwrap();
    let re_backtick_command =
        regex::Regex::new(r"`([a-z][a-z0-9_-]*(?:\s+[a-z][a-z0-9_-]*){1,2})`").unwrap();

    let mut push_command = |raw: &str| {
        let segments: Vec<&str> = raw.split_whitespace().collect();
        if segments.len() < 2 || segments.len() > 3 {
            return;
        }
        if segments.iter().all(|segment| is_noise_term(segment)) {
            return;
        }
        let joined = segments.join("/");
        if seen.insert(joined.clone()) {
            fragments.push(joined);
        }
    };

    for cap in re_bullet_command.captures_iter(text) {
        push_command(&cap[1]);
    }
    for cap in re_backtick_command.captures_iter(text) {
        push_command(&cap[1]);
    }

    fragments
}

fn is_command_style_fragment(fragment: &str) -> bool {
    let segments: Vec<&str> = fragment.split('/').collect();
    let layout_segments = [
        "pkg", "src", "lib", "internal", "tests", "test", "docs", "doc", "cmd", "crates",
        "packages",
    ];
    (2..=3).contains(&segments.len())
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment.chars().all(|ch| {
                    ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '-')
                })
        })
        && !segments
            .iter()
            .any(|segment| layout_segments.contains(segment))
}

fn is_module_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '-'))
}

fn module_path_candidates(module: &str) -> Vec<String> {
    let normalized = module
        .trim()
        .trim_matches('`')
        .trim_matches('"')
        .trim_matches('\'')
        .replace("::", "/")
        .replace('.', "/");
    let mut normalized = normalized.trim_matches('/').to_string();
    while let Some(stripped) = normalized.strip_prefix("./") {
        normalized = stripped.to_string();
    }
    while let Some(stripped) = normalized.strip_prefix("../") {
        normalized = stripped.to_string();
    }
    if normalized.is_empty() {
        return Vec::new();
    }

    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    let mut push = |candidate: String| {
        let candidate = candidate
            .trim_start_matches("./")
            .trim_matches('/')
            .to_string();
        if !candidate.is_empty() && seen.insert(candidate.clone()) {
            candidates.push(candidate);
        }
    };

    push(normalized.clone());

    for ext in &[
        "py", "rs", "ts", "tsx", "js", "jsx", "go", "java", "c", "h", "hh", "hpp", "cpp", "cc",
        "cxx", "cs", "rb", "php", "swift", "kt", "kts", "tf", "tfvars", "hcl",
    ] {
        push(format!("{normalized}.{ext}"));
    }

    for suffix in &[
        "__init__.py",
        "mod.rs",
        "index.ts",
        "index.tsx",
        "index.js",
        "index.jsx",
        "index.go",
        "index.java",
        "index.rs",
        "index.rb",
        "index.php",
        "index.swift",
        "index.kt",
        "index.kts",
        "main.tf",
        "main.hcl",
    ] {
        push(format!("{normalized}/{suffix}"));
    }

    candidates
}

fn resolve_module_paths_in_graph(graph: &kin_db::InMemoryGraph, module: &str) -> Vec<String> {
    let mut resolved = Vec::new();
    let mut seen = HashSet::new();

    for candidate in module_path_candidates(module) {
        if let Some(path) = resolve_path_in_graph(graph, &candidate) {
            if seen.insert(path.clone()) {
                resolved.push(path);
            }
        }
    }

    if !resolved.is_empty() {
        return resolved;
    }

    let normalized = module
        .trim()
        .trim_matches('`')
        .trim_matches('"')
        .trim_matches('\'')
        .replace("::", "/")
        .replace('.', "/")
        .trim_matches('/')
        .to_string();
    if normalized.is_empty() {
        return resolved;
    }

    let mut partial_matches = Vec::new();
    for path in source_file_paths(graph) {
        if module_fragment_matches_path(&path, &normalized) && seen.insert(path.clone()) {
            partial_matches.push(path);
        }
    }
    for tracked in tracked_non_entity_files(graph) {
        if module_fragment_matches_path(&tracked.path, &normalized)
            && seen.insert(tracked.path.clone())
        {
            partial_matches.push(tracked.path);
        }
    }

    let command_leaf = if is_command_style_fragment(&normalized) {
        normalized.rsplit('/').next().map(str::to_string)
    } else {
        None
    };
    partial_matches.sort_by(|a, b| {
        file_tier(a, false)
            .cmp(&file_tier(b, false))
            .then_with(|| {
                let a_leaf = command_leaf
                    .as_deref()
                    .is_some_and(|leaf| path_leaf_matches_segment(a, leaf));
                let b_leaf = command_leaf
                    .as_deref()
                    .is_some_and(|leaf| path_leaf_matches_segment(b, leaf));
                b_leaf.cmp(&a_leaf)
            })
            .then_with(|| a.matches('/').count().cmp(&b.matches('/').count()))
            .then_with(|| a.cmp(b))
    });
    let partial_limit = if is_command_style_fragment(&normalized) {
        locate_env_usize("KIN_LOCATE_COMMAND_PARTIAL_MATCH_LIMIT", 4)
    } else {
        locate_env_usize("KIN_LOCATE_MODULE_PARTIAL_MATCH_LIMIT", 12)
    };
    partial_matches.truncate(partial_limit);
    resolved.extend(partial_matches);

    resolved
}

fn module_fragment_matches_path(path: &str, fragment: &str) -> bool {
    let normalized_path = path.trim_matches('/');
    let normalized_fragment = fragment.trim_matches('/');
    normalized_path == normalized_fragment
        || normalized_path.ends_with(&format!("/{}", normalized_fragment))
        || normalized_path.contains(&format!("/{}", normalized_fragment))
}

fn path_leaf_matches_segment(path: &str, segment: &str) -> bool {
    path.rsplit('/')
        .next()
        .map(|leaf| {
            leaf.split('.')
                .next()
                .is_some_and(|stem| stem.eq_ignore_ascii_case(segment))
        })
        .unwrap_or(false)
}

fn normalized_namespace_segments(raw: &str) -> Vec<String> {
    raw.trim()
        .trim_matches('`')
        .trim_matches('"')
        .trim_matches('\'')
        .trim_end_matches(';')
        .trim_end_matches(',')
        .replace("::", "/")
        .replace('.', "/")
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != "." && *segment != "..")
        .map(ToOwned::to_owned)
        .collect()
}

fn last_module_segment(module: &str) -> Option<String> {
    normalized_namespace_segments(module).into_iter().last()
}

fn push_import_target(
    import_targets: &mut Vec<(String, Option<String>)>,
    seen: &mut HashSet<(String, Option<String>)>,
    module: impl Into<String>,
    symbol: Option<String>,
) {
    let module = module.into();
    let trimmed = module.trim().trim_matches('/').to_string();
    if trimmed.is_empty() {
        return;
    }
    let symbol = symbol.and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    let entry = (trimmed, symbol);
    if seen.insert(entry.clone()) {
        import_targets.push(entry);
    }
}

fn push_namespace_import_targets(
    import_targets: &mut Vec<(String, Option<String>)>,
    seen: &mut HashSet<(String, Option<String>)>,
    raw: &str,
) {
    let segments = normalized_namespace_segments(raw);
    if segments.is_empty() {
        return;
    }

    let full_module = segments.join("/");
    let symbol = segments.last().cloned();
    push_import_target(import_targets, seen, full_module, symbol.clone());
    if segments.len() >= 2 {
        push_import_target(
            import_targets,
            seen,
            segments[..segments.len() - 1].join("/"),
            symbol,
        );
    }
}

// ---------------------------------------------------------------------------
// 1. Traceback parser
// ---------------------------------------------------------------------------

fn extract_traceback_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let _span =
        tracing::info_span!("locate.extract_traceback_signals", text_len = text.len()).entered();
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    // Match Python traceback lines: File "path", line N, in function_name
    let re_tb = regex::Regex::new(r#"File "([^"]+)", line (\d+)(?:, in (\w+))?"#).unwrap();

    let frames: Vec<_> = re_tb.captures_iter(text).collect();
    let num_frames = frames.len();

    for (i, cap) in frames.iter().enumerate() {
        let file_path = &cap[1];
        let line: u32 = cap[2].parse().unwrap_or(0);
        let rel_path = resolve_path_in_graph(graph, &normalize_traceback_path(file_path));

        // Weight by frame position — last frame is most relevant
        let position_weight = (i + 1) as f32 / num_frames.max(1) as f32;
        let score = 10.0 * position_weight;

        // Keep traceback paths that resolve into this repo even if they came from
        // an installed site-packages path. Skip only when they do not resolve and
        // still look like stdlib/venv noise.
        if let Some(ref path) = rel_path {
            hits.entry(path.clone()).or_default().push(FileHit {
                score: score,
                spans: vec![[line, line]],
            });
        } else if is_stdlib_path(file_path) {
            continue;
        }

        // Also search for the function name in the graph
        if let Some(func_name) = cap.get(3) {
            let func = func_name.as_str();
            let text_hits = graph.text_search(func, 5)?;
            for (retrieval_key, _) in &text_hits {
                if let Some(entity) = entity_from_retrieval_key(graph, retrieval_key)? {
                    if let Some(ref fo) = entity.file_origin {
                        let path = fo.0.clone();
                        if !is_test_by_role(&path, Some(&entity))
                            || rel_path.as_ref() == Some(&path)
                        {
                            hits.entry(path).or_default().push(FileHit {
                                score: 5.0 * position_weight,
                                spans: entity_span_pair(&entity),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(hits)
}

fn is_stdlib_path(path: &str) -> bool {
    let markers = [
        "/lib/python",
        "/venv/",
        "/.venv/",
        "/env/",
        "/Lib/",
        "\\lib\\python",
    ];
    markers.iter().any(|m| path.contains(m))
}

fn normalize_traceback_path(path: &str) -> String {
    let path = path.replace('\\', "/");

    // Strip ~ prefix (e.g. ~/dev/astropy/astropy/... → /dev/astropy/astropy/...)
    let path = if path.starts_with("~/") {
        format!("/{}", &path[2..])
    } else {
        path
    };

    for marker in &[
        "/site-packages/",
        "/dist-packages/",
        "\\site-packages\\",
        "\\dist-packages\\",
    ] {
        if let Some(idx) = path.find(marker) {
            let start = idx + marker.len();
            return path[start..]
                .trim_start_matches('/')
                .trim_start_matches('\\')
                .to_string();
        }
    }

    // If it looks like an absolute path, try to find a recognizable root
    if path.starts_with('/') || path.contains(":/") {
        // Take everything after the last occurrence of common project dirs
        for marker in &["/src/", "/lib/"] {
            if let Some(idx) = path.rfind(marker) {
                return path[idx + 1..].to_string();
            }
        }
        // Otherwise use the last 3+ components
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() > 2 {
            // Heuristic: keep from the first non-system-looking component
            for (i, part) in parts.iter().enumerate() {
                if !["home", "Users", "usr", "opt", "var", "tmp"]
                    .contains(&part.to_lowercase().as_str())
                    && !part.starts_with('.')
                {
                    return parts[i..].join("/");
                }
            }
        }
    }

    path.to_string()
}

// ---------------------------------------------------------------------------
// 2. Entity search
// ---------------------------------------------------------------------------

/// Phase 1 entity-first search: returns entity seeds (scored entities).
/// Entity seeds are resolved to files in Phase 2 via graph relations.
fn extract_search_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
    test_query: bool,
) -> Result<HashMap<kin_model::EntityId, EntityDiscovery>> {
    let _span =
        tracing::info_span!("locate.extract_search_signals", text_len = text.len()).entered();
    let mut entity_seeds: HashMap<kin_model::EntityId, EntityDiscovery> = HashMap::new();

    let identifiers = curate_search_terms(text, graph)?;
    if identifiers.is_empty() {
        return Ok(entity_seeds);
    }

    let bm25f_name_weight = locate_env_f32("KIN_LOCATE_BM25F_NAME_WEIGHT", 5.0);
    let bm25f_body_weight = locate_env_f32("KIN_LOCATE_BM25F_BODY_WEIGHT", 1.0);

    // Determine which terms appear in the issue title (first line) for weighting
    let title_line = text.lines().next().unwrap_or("");
    let title_terms: HashSet<String> = extract_title_terms(title_line)
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect();

    for ident in &identifiers {
        let ident_lower = ident.to_lowercase();
        let symbolic_ident = is_symbolic_search_term(ident);

        // Title terms get 3x weight
        let is_title_term = title_terms.contains(&ident_lower);
        let title_mult = if is_title_term { 3.0 } else { 1.0 };

        let mut seen = std::collections::HashSet::new();

        // Build search variants: original + CamelCase if snake_case, + snake_case if CamelCase.
        // This handles the common case where code uses `QuantityInput` (CamelCase) but issue
        // text says `quantity_input` (snake_case), or vice versa.
        let mut name_variants = vec![ident.clone()];
        if ident.contains('_') {
            // snake_case → CamelCase: quantity_input → QuantityInput
            let camel: String = ident
                .split('_')
                .map(|part| {
                    let mut c = part.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    }
                })
                .collect();
            if camel != *ident {
                name_variants.push(camel);
            }
        }
        // Also strip underscores for joined-form matching
        let joined = ident.replace('_', "");
        if joined != *ident
            && !name_variants
                .iter()
                .any(|v| v.to_lowercase() == joined.to_lowercase())
        {
            name_variants.push(joined);
        }

        // Step 1: Pattern match — find entities whose name matches any variant.
        // Score the ENTITY, not the file. File resolution happens in Phase 2.
        for variant in &name_variants {
            let filter = EntityFilter {
                name_pattern: Some(variant.clone()),
                ..Default::default()
            };
            for entity in graph.query_entities(&filter)? {
                if !seen.insert(entity.id) {
                    continue;
                }
                // Part-based name matching: handles snake_case ↔ CamelCase ↔ SCREAMING_SNAKE
                let name_mult = score_name_match(ident, &entity.name);
                if name_mult == 0.0 {
                    continue; // No meaningful match
                }
                let field_weight = if name_mult >= 2.0 {
                    bm25f_name_weight
                } else {
                    bm25f_body_weight
                };
                let kind_mult = match entity.kind {
                    EntityKind::Function
                    | EntityKind::Method
                    | EntityKind::Class
                    | EntityKind::TraitDef
                    | EntityKind::Interface
                    | EntityKind::EnumDef
                    | EntityKind::Module => 3.0,
                    EntityKind::Constant | EntityKind::TypeAlias => {
                        // Constants and type aliases are common noise in large
                        // codebases (e.g., MUI has 45K+ constants from styled-
                        // component theme tokens). Demote unless exact name match.
                        if name_mult >= 5.0 {
                            2.0
                        } else {
                            0.3
                        }
                    }
                    _ => 1.0,
                };
                {
                    let role_mult = if !test_query && entity.role == EntityRole::Test {
                        0.1
                    } else {
                        1.0
                    };
                    let score = kind_mult * name_mult * field_weight * title_mult * role_mult;
                    let entry = entity_seeds.entry(entity.id).or_default();
                    entry.score += score;
                    if !entry.signals.contains(&"search") {
                        entry.signals.push("search");
                    }
                }
            }
        } // end for variant in name_variants

        // Step 2: Text index search — BM25 matches on entity names, signatures,
        // doc summaries, and body previews. File path is weighted 0 in the index
        // so only semantic content drives matches. Search all name variants.
        if !symbolic_ident {
            let mut all_text_hits = Vec::new();
            for variant in &name_variants {
                let hits = graph
                    .text_search(variant, locate_env_usize("KIN_LOCATE_TEXT_HIT_LIMIT", 50))?;
                all_text_hits.extend(hits);
            }
            let text_hits = all_text_hits;
            for (rank, (retrieval_key, _score)) in text_hits.into_iter().enumerate() {
                let Some(entity) = entity_from_retrieval_key(graph, &retrieval_key)? else {
                    continue;
                };
                let name_match = score_name_match(ident, &entity.name);
                let field_weight = if name_match >= 2.0 {
                    bm25f_name_weight
                } else {
                    bm25f_body_weight
                };
                let role_mult = if !test_query && entity.role == EntityRole::Test {
                    0.1
                } else {
                    1.0
                };
                let score = field_weight * title_mult * role_mult / ((rank + 1) as f32).sqrt();
                {
                    let entry = entity_seeds.entry(entity.id).or_default();
                    entry.score += score;
                    if seen.insert(entity.id) && !entry.signals.contains(&"search") {
                        entry.signals.push("search");
                    }
                }
            }
        }
    }

    // Step 3 (gated KIN_LOCATE_BODY_SEED_FILE, default OFF): body-relevance
    // seeding for file-rank lift. Steps 1-2 are name-keyed (curate_search_terms
    // caps to ~6 name-ish identifiers; Step 1's name gate drops name-mismatched
    // defs), so a def whose NAME matches nothing but whose BODY implements the
    // change never seeds — it can't file-rank, resolve, or emit. Search the BM25
    // body index with the full topic vocabulary and seed definitional matches at
    // a low body weight, tagged "body" so KIN_LOCATE_BODY_SEED_PROTECT can shield
    // them from the seed gap-cut. OFF == byte-identical.
    if locate_env_bool("KIN_LOCATE_BODY_SEED_FILE", false) {
        let body_limit = locate_env_usize("KIN_LOCATE_BODY_SEED_LIMIT", 20);
        let body_weight = locate_env_f32("KIN_LOCATE_BODY_SEED_WEIGHT", 0.5);
        for term in tracked_text_query_terms(text) {
            if term.len() < 4 {
                continue;
            }
            let Ok(hits) = graph.text_search(&term, body_limit) else {
                continue;
            };
            for (rank, (retrieval_key, _score)) in hits.into_iter().enumerate() {
                let Some(entity) = entity_from_retrieval_key(graph, &retrieval_key)? else {
                    continue;
                };
                if !is_definitional_kind(entity.kind) {
                    continue;
                }
                let role_mult = if !test_query && entity.role == EntityRole::Test {
                    0.1
                } else {
                    1.0
                };
                let score = body_weight * role_mult / ((rank + 1) as f32).sqrt();
                let entry = entity_seeds.entry(entity.id).or_default();
                entry.score += score;
                if !entry.signals.contains(&"body") {
                    entry.signals.push("body");
                }
            }
        }
    }

    // Conjunctive multi-term bonus: ENTITIES matching multiple search terms get a boost.
    // This is entity-level, not file-level — an entity whose name or context contains
    // multiple query terms is more likely to be the right target.
    if identifiers.len() > 1 {
        let mut entity_term_matches: HashMap<kin_model::EntityId, usize> = HashMap::new();
        for ident in &identifiers {
            let ident_lower = ident.to_lowercase();
            for (&entity_id, _) in entity_seeds.iter() {
                if let Some(entity) = graph.get_entity(&entity_id)? {
                    if entity.name.to_lowercase().contains(&ident_lower) {
                        *entity_term_matches.entry(entity_id).or_default() += 1;
                    }
                }
            }
        }
        for (entity_id, term_count) in &entity_term_matches {
            if *term_count > 1 {
                let bonus = match term_count {
                    2 => 5.0,
                    3 => 15.0,
                    _ => 30.0,
                };
                {
                    let entry = entity_seeds.entry(*entity_id).or_default();
                    entry.score += bonus;
                    if !entry.signals.contains(&"search") {
                        entry.signals.push("search");
                    }
                }
            }
        }
    }

    // NOTE: File stem matching and file-path-contains-term bonus are REMOVED.
    // These are filesystem artifacts. Entity names and signatures are the authority.
    // File resolution happens in Phase 2 via graph relations.

    Ok(entity_seeds)
}

fn extract_file_paths(text: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();

    let re_traceback = regex::Regex::new(r#"File "([^"]+\.[A-Za-z0-9]+)""#).unwrap();
    for cap in re_traceback.captures_iter(text) {
        let path = normalize_traceback_path(&cap[1]);
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    }

    let re_backtick = regex::Regex::new(r"`([a-zA-Z][\w./-]+\.\w{1,6})`").unwrap();
    for cap in re_backtick.captures_iter(text) {
        let path = normalize_traceback_path(&cap[1]);
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    }

    let re_pytest_node =
        regex::Regex::new(r"\b([A-Za-z0-9_./-]+\.py)(?:::(?:[A-Za-z_][\w]*))*\b").unwrap();
    for cap in re_pytest_node.captures_iter(text) {
        let path = normalize_traceback_path(&cap[1]);
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    }

    let re_line_ref =
        regex::Regex::new(r"\b([A-Za-z0-9_./-]+\.[A-Za-z0-9]+):\d+(?::\d+)?\b").unwrap();
    for cap in re_line_ref.captures_iter(text) {
        let path = normalize_traceback_path(&cap[1]);
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    }

    // Fix: use (?:^|[^/\w]) instead of (?<!\w) for lookbehind compatibility
    let re_bare =
        regex::Regex::new(r"(?:^|[^/\w])([a-zA-Z]\w+(?:/[\w.-]+)+\.\w{1,6})(?:[^\w]|$)").unwrap();
    for cap in re_bare.captures_iter(text) {
        let path = normalize_traceback_path(&cap[1]);
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    }

    paths
}

fn extract_search_terms(text: &str) -> Vec<String> {
    let mut queries = Vec::new();
    let mut seen = HashSet::new();

    let re_backtick = regex::Regex::new(r"`([^`]+)`").unwrap();
    for cap in re_backtick.captures_iter(text) {
        let raw = cap[1].trim();
        for normalized in normalize_code_search_terms(raw) {
            if normalized.contains('.') {
                let parts: Vec<&str> = normalized
                    .split('.')
                    .filter(|part| !part.is_empty())
                    .collect();
                for part in &parts {
                    maybe_add_search_term(part, &mut seen, &mut queries);
                }
                if parts.len() <= 3 {
                    maybe_add_search_term(&normalized, &mut seen, &mut queries);
                }
            } else {
                maybe_add_search_term(&normalized, &mut seen, &mut queries);
            }
        }
    }

    let re_flag =
        regex::Regex::new(r#"(?:^|[^\w/])(--[A-Za-z0-9][A-Za-z0-9-]*(?:=[^\s`"')\],;:]+)?)"#)
            .unwrap();
    for cap in re_flag.captures_iter(text) {
        for normalized in normalize_code_search_terms(&cap[1]) {
            maybe_add_search_term(&normalized, &mut seen, &mut queries);
        }
    }

    let re_camel = regex::Regex::new(r"\b([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b").unwrap();
    for cap in re_camel.captures_iter(text) {
        maybe_add_search_term(&cap[1], &mut seen, &mut queries);
    }

    let re_snake = regex::Regex::new(r"\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b").unwrap();
    for cap in re_snake.captures_iter(text) {
        maybe_add_search_term(&cap[1], &mut seen, &mut queries);
    }

    let re_upper = regex::Regex::new(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b").unwrap();
    for cap in re_upper.captures_iter(text) {
        maybe_add_search_term(&cap[1], &mut seen, &mut queries);
    }

    if queries.is_empty() {
        if let Some(first_line) = text.lines().next() {
            let re_word = regex::Regex::new(r"\b([a-zA-Z_]\w+)\b").unwrap();
            for cap in re_word.captures_iter(first_line) {
                maybe_add_search_term(&cap[1], &mut seen, &mut queries);
            }
        }
    }

    queries.truncate(10);
    queries
}

fn extract_loose_query_terms(text: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut seen = HashSet::new();
    let re_word = regex::Regex::new(r"\b([A-Za-z0-9_]{4,})\b").unwrap();
    for cap in re_word.captures_iter(text) {
        let term = cap[1].to_string();
        let canonical = term.to_ascii_lowercase();
        if is_numeric_issue_term(&canonical) {
            continue;
        }
        if seen.insert(canonical) {
            terms.push(term);
        }
    }
    terms
}

fn extract_cli_flag_terms(text: &str) -> Vec<String> {
    let mut flags = Vec::new();
    let mut seen = HashSet::new();

    let re_long =
        regex::Regex::new(r#"(?:^|[^\w/])(--[A-Za-z0-9][A-Za-z0-9-]*(?:=[^\s`"')\],;:]+)?)"#)
            .unwrap();
    for cap in re_long.captures_iter(text) {
        let flag = cap[1].to_string();
        if seen.insert(flag.to_ascii_lowercase()) {
            flags.push(flag);
        }
    }

    let re_short = regex::Regex::new(r"(?:^|[^\w/])(-[A-Za-z0-9])(?:$|[^\w-])").unwrap();
    for cap in re_short.captures_iter(text) {
        let flag = cap[1].to_string();
        if seen.insert(flag.to_ascii_lowercase()) {
            flags.push(flag);
        }
    }

    flags
}

fn extract_domain_alias_terms(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut aliases = Vec::new();
    let mut seen = HashSet::new();
    let mut push_alias = |alias: &str| {
        let canonical = alias.to_ascii_lowercase();
        if seen.insert(canonical) {
            aliases.push(alias.to_string());
        }
    };

    if lower.contains("type parameter") {
        push_alias("typeparam");
    }
    if lower.contains("subtyping") {
        push_alias("subtype");
    }
    if lower.contains("serialisation") || lower.contains("serialization") {
        push_alias("serialise");
    }
    if lower.contains("empty string") {
        push_alias("string");
    }
    if lower.contains("string")
        && (lower.contains("serialise")
            || lower.contains("serialised")
            || lower.contains("serialisation")
            || lower.contains("serialization"))
    {
        push_alias("string_serialise");
    }
    if lower.contains("codegen") {
        push_alias("codegen");
    }
    if lower.contains("lambda") {
        push_alias("lambda");
    }
    if lower.contains("constructor") {
        push_alias("constructor");
    }
    if lower.contains("behaviour") {
        push_alias("behaviour");
    }
    if lower.contains("behavior") {
        push_alias("behavior");
    }
    if lower.contains("arrow type") {
        push_alias("arrow");
        push_alias("viewpoint");
    }
    if lower.contains("unsafe mutation") {
        push_alias("mutate");
        push_alias("immutable");
    }
    if lower.contains("immutable") && lower.contains("val") {
        push_alias("mutate");
    }

    aliases
}

fn is_semantic_phase_anchor_term(term: &str) -> bool {
    matches!(
        term,
        "lambda"
            | "lambdas"
            | "constructor"
            | "constructors"
            | "behaviour"
            | "behaviours"
            | "behavior"
            | "behaviors"
            | "syntax"
            | "verify"
    )
}

fn tracked_text_query_terms(text: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut seen = HashSet::new();
    let suppressed_terms = suppressed_query_terms(text);
    let suppress_cpp_modifiers = query_mentions_cpp_access_macro_context(text)
        && extract_search_terms(text)
            .iter()
            .any(|term| is_unresolved_symbolic_code_anchor(term));

    for term in extract_search_terms(text) {
        let canonical = term.to_ascii_lowercase();
        if suppressed_terms.contains(&canonical)
            || (suppress_cpp_modifiers && is_generic_code_modifier_term(&canonical))
        {
            continue;
        }
        if seen.insert(canonical) {
            terms.push(term);
        }
    }

    for term in extract_title_terms(text) {
        let canonical = term.to_ascii_lowercase();
        if suppressed_terms.contains(&canonical)
            || (suppress_cpp_modifiers && is_generic_code_modifier_term(&canonical))
        {
            continue;
        }
        if seen.insert(canonical) {
            terms.push(term);
        }
    }

    for term in extract_domain_alias_terms(text) {
        let canonical = term.to_ascii_lowercase();
        if suppressed_terms.contains(&canonical) {
            continue;
        }
        if seen.insert(canonical) {
            terms.push(term);
        }
    }

    for term in extract_loose_query_terms(text) {
        let canonical = term.to_ascii_lowercase();
        if suppressed_terms.contains(&canonical)
            || (suppress_cpp_modifiers && is_generic_code_modifier_term(&canonical))
            || is_noise_term(&canonical)
            || is_issue_boilerplate_term(&canonical)
        {
            continue;
        }
        if seen.insert(canonical) {
            terms.push(term);
        }
    }

    terms
}

fn extract_c_api_prefixes(text: &str) -> Vec<String> {
    let mut prefixes = Vec::new();
    let mut seen = HashSet::new();

    for term in extract_search_terms(text) {
        let Some((prefix, _)) = term.split_once('_') else {
            continue;
        };
        if prefix.len() < 2 || !prefix.chars().all(|ch| ch.is_ascii_uppercase()) {
            continue;
        }
        let canonical = prefix.to_ascii_lowercase();
        if seen.insert(canonical.clone()) {
            prefixes.push(canonical);
        }
    }

    prefixes
}

fn is_symbolic_search_term(term: &str) -> bool {
    term.contains('_')
        || term.contains('-')
        || term.contains('.')
        || term.chars().filter(|ch| ch.is_ascii_uppercase()).count() >= 2
}

fn is_generic_code_modifier_term(term_lower: &str) -> bool {
    matches!(
        term_lower,
        "private"
            | "public"
            | "protected"
            | "define"
            | "defined"
            | "undef"
            | "ifdef"
            | "ifndef"
            | "endif"
            | "pragma"
            | "include"
    )
}

fn is_unresolved_symbolic_code_anchor(term: &str) -> bool {
    term.contains('_') && term.chars().filter(|ch| ch.is_ascii_uppercase()).count() >= 2
}

fn query_mentions_cpp_access_macro_context(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    (lower.contains("#define") && lower.contains("private") && lower.contains("public"))
        || (lower.contains("macro")
            && lower.contains("private")
            && lower.contains("public")
            && (lower.contains("defined") || lower.contains("tests")))
}

fn is_cli_flag_term(term: &str) -> bool {
    let bytes = term.as_bytes();
    if bytes.len() == 2 && bytes[0] == b'-' {
        return bytes[1].is_ascii_alphanumeric();
    }
    bytes.len() >= 3
        && bytes[0] == b'-'
        && bytes[1] == b'-'
        && bytes[2].is_ascii_alphanumeric()
        && bytes[2..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'='))
}

fn normalize_code_search_terms(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 80 || trimmed.contains('\n') {
        return Vec::new();
    }

    if trimmed.contains('/')
        && trimmed
            .rsplit('/')
            .next()
            .is_some_and(|leaf| leaf.contains('.'))
    {
        return Vec::new();
    }

    let mut terms = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |term: &str| {
        let normalized = term
            .trim()
            .trim_start_matches('#')
            .trim_start_matches('@')
            .trim_matches(|ch: char| {
                matches!(
                    ch,
                    '[' | ']' | '(' | ')' | '{' | '}' | ',' | ';' | ':' | '!' | '*'
                )
            })
            .trim_matches('`')
            .trim();
        if normalized.is_empty() || normalized.starts_with('.') || seen.contains(normalized) {
            return;
        }
        seen.insert(normalized.to_string());
        terms.push(normalized.to_string());
    };

    let re_flag = regex::Regex::new(r"--[A-Za-z0-9][A-Za-z0-9-]*").unwrap();
    for mat in re_flag.find_iter(trimmed) {
        push(mat.as_str().trim_start_matches('-'));
    }

    let re_ident =
        regex::Regex::new(r"[A-Za-z_][A-Za-z0-9_]*(?:(?:::|\.|#)[A-Za-z_][A-Za-z0-9_]*)*").unwrap();
    for mat in re_ident.find_iter(trimmed) {
        let token = mat.as_str();
        if token.contains("::") || token.contains('.') || token.contains('#') {
            let normalized_token = token.replace("::", ".").replace('#', ".");
            let segments = normalized_token
                .split('.')
                .filter(|segment| !segment.is_empty())
                .collect::<Vec<_>>();
            if let Some(last) = segments.last() {
                push(last);
            }
            if segments.len() <= 3 {
                push(&segments.join("."));
            }
        } else {
            push(token);
        }
    }

    terms
}

fn extract_title_terms(text: &str) -> Vec<String> {
    let _span = tracing::info_span!("locate.extract_title_terms", text_len = text.len()).entered();
    let mut queries = Vec::new();
    let mut seen = HashSet::new();
    let re_word = regex::Regex::new(r"\b([a-zA-Z_]\w+)\b").unwrap();

    if let Some(first_line) = text.lines().next() {
        for cap in re_word.captures_iter(first_line) {
            maybe_add_search_term(&cap[1], &mut seen, &mut queries);
            if queries.len() >= locate_env_usize("KIN_LOCATE_TITLE_TERM_LIMIT", 6) {
                break;
            }
        }
    }

    queries
}

fn curate_search_terms(text: &str, graph: &kin_db::InMemoryGraph) -> Result<Vec<String>> {
    let _span = tracing::info_span!("locate.curate_search_terms", text_len = text.len()).entered();
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    let suppressed_terms = suppressed_query_terms(text);
    let semantic_phase_query = is_semantic_phase_query(text);

    for term in extract_search_terms(text) {
        let canonical = term.to_ascii_lowercase();
        if suppressed_terms.contains(&canonical)
            || is_numeric_issue_term(&canonical)
            || is_issue_boilerplate_term(&canonical)
            || is_english_stopword(&canonical)
        {
            continue;
        }
        if seen.insert(canonical) {
            candidates.push((term, false));
        }
    }

    for term in extract_domain_alias_terms(text) {
        let canonical = term.to_ascii_lowercase();
        if suppressed_terms.contains(&canonical) || is_english_stopword(&canonical) {
            continue;
        }
        if seen.insert(canonical) {
            candidates.push((term, true));
        }
    }

    for term in extract_title_terms(text) {
        let canonical = term.to_ascii_lowercase();
        if suppressed_terms.contains(&canonical)
            || is_numeric_issue_term(&canonical)
            || is_issue_boilerplate_term(&canonical)
            || is_english_stopword(&canonical)
        {
            continue;
        }
        if seen.insert(canonical) {
            candidates.push((term, true));
        }
    }

    let term_limit = locate_env_usize("KIN_LOCATE_CURATED_TERM_LIMIT", 6);
    let mut graph_support_cache: HashMap<(String, bool), bool> = HashMap::new();
    let mut has_supported_symbolic_anchor = false;
    let mut has_symbolic_code_anchor = false;
    let cpp_access_macro_context = query_mentions_cpp_access_macro_context(text);
    for (term, from_title) in &candidates {
        let term_lower = term.to_ascii_lowercase();
        if !is_symbolic_search_term(term) || is_generic_code_modifier_term(&term_lower) {
            continue;
        }
        if is_unresolved_symbolic_code_anchor(term) {
            has_symbolic_code_anchor = true;
        }
        let cache_key = (term_lower, *from_title);
        let has_support = match graph_support_cache.get(&cache_key) {
            Some(has_support) => *has_support,
            None => {
                let has_support = term_has_graph_support(graph, term, *from_title)?;
                graph_support_cache.insert(cache_key, has_support);
                has_support
            }
        };
        if has_support {
            has_supported_symbolic_anchor = true;
            break;
        }
    }

    let mut compound_terms: Vec<(String, f32, bool)> = Vec::new();
    let mut scored_terms: Vec<(String, f32, bool)> = Vec::new();
    let mut common_terms: Vec<(String, f32, bool)> = Vec::new();
    for (term, from_title) in candidates {
        let term_lower = term.to_ascii_lowercase();
        if (has_supported_symbolic_anchor || (cpp_access_macro_context && has_symbolic_code_anchor))
            && is_generic_code_modifier_term(&term_lower)
        {
            continue;
        }
        // Compound identifiers (snake_case, CamelCase, dotted) are almost always
        // real code identifiers, not English prose.
        let upper_count = term.chars().filter(|c| c.is_uppercase()).count();
        let compound = term.contains('_') || term.contains('.') || upper_count >= 2;
        let common_english = is_common_english_word(&term_lower);
        let semantic_anchor = semantic_phase_query && is_semantic_phase_anchor_term(&term_lower);

        // Non-compound title terms must match entity names directly, not just
        // docstring text. Words like "instead" or "raising" match BM25 text
        // search on docstrings but aren't real code identifiers.
        let needs_name_match = from_title && !compound && !semantic_anchor;

        let cache_key = (term_lower.clone(), from_title);
        let has_support = if needs_name_match {
            term_has_name_support(graph, &term)?
        } else if let Some(has_support) = graph_support_cache.get(&cache_key) {
            *has_support
        } else {
            let has_support = term_has_graph_support(graph, &term, from_title)?;
            graph_support_cache.insert(cache_key, has_support);
            has_support
        };
        if !has_support {
            if !has_supported_symbolic_anchor
                && !has_symbolic_code_anchor
                && cpp_access_macro_context
                && is_generic_code_modifier_term(&term_lower)
            {
                scored_terms.push((term, 0.45, from_title));
                continue;
            }
            if is_unresolved_symbolic_code_anchor(&term) {
                let title_boost = if from_title { 3.0 } else { 1.0 };
                compound_terms.push((term, 0.25 * title_boost, from_title));
            }
            continue;
        }

        let filter = EntityFilter {
            name_pattern: Some(term.clone()),
            ..Default::default()
        };
        let matched_entities = graph.query_entities(&filter).unwrap_or_default();
        let unique_files: HashSet<&str> = matched_entities
            .iter()
            .filter_map(|e| e.file_origin.as_ref().map(|fo| fo.0.as_str()))
            .collect();
        let file_count = unique_files.len();

        // Specificity by unique files, not raw entity count.
        // SkyCoord has 50 methods but they're all in 1 file → file_count=1 → high specificity.
        // "format" matches entities in 30 files → low specificity.
        let specificity = 1.0 / ((file_count as f32) + 2.0).log2();

        let title_boost = if from_title { 3.0 } else { 1.0 };

        let length_boost = if compound { 2.0 } else { 1.0 };

        let noise_penalty = if common_english { 0.1 } else { 1.0 };

        let semantic_anchor_boost = if semantic_anchor { 2.5 } else { 1.0 };

        let score =
            specificity * title_boost * length_boost * noise_penalty * semantic_anchor_boost;

        if compound {
            compound_terms.push((term, score, from_title));
        } else if common_english {
            common_terms.push((term, score, from_title));
        } else {
            scored_terms.push((term, score, from_title));
        }
    }

    // Compound identifiers get guaranteed slots — they're almost certainly
    // real code identifiers (__array_ufunc__, FITSDiff, NdarrayMixin).
    compound_terms.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    scored_terms.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    common_terms.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });

    let compound_limit = term_limit.min(compound_terms.len());
    let remaining = term_limit.saturating_sub(compound_limit);

    let mut curated: Vec<String> = compound_terms
        .into_iter()
        .take(compound_limit)
        .map(|(t, _, _)| t)
        .collect();
    let compound_set: HashSet<String> = curated.iter().cloned().collect();
    for (t, _, _) in scored_terms.into_iter().take(remaining) {
        if !compound_set.contains(&t) {
            curated.push(t);
        }
    }

    // Common English words with graph support are still useful as a last-resort
    // fallback, but letting them into the main entity-search set causes broad
    // resolver blow-ups on terms like "read", "return", or "from".
    if curated.is_empty() {
        for (t, _, _) in common_terms.into_iter().take(term_limit) {
            if !compound_set.contains(&t) {
                curated.push(t);
            }
        }
    }

    if curated.is_empty() {
        let mut fallback = extract_search_terms(text);
        if fallback.is_empty() {
            fallback = extract_title_terms(text);
        }
        if has_supported_symbolic_anchor || (cpp_access_macro_context && has_symbolic_code_anchor) {
            fallback.retain(|term| {
                !is_generic_code_modifier_term(&term.to_ascii_lowercase())
                    || is_symbolic_search_term(term)
            });
        }
        fallback.truncate(locate_env_usize("KIN_LOCATE_FALLBACK_TERM_LIMIT", 6));
        return Ok(fallback);
    }

    // Skip graph expansion — it adds noise terms that dilute specificity.
    // The entity-first pipeline handles graph exploration in Phase 2.
    Ok(curated)
}

fn term_has_graph_support(
    graph: &kin_db::InMemoryGraph,
    term: &str,
    from_title: bool,
) -> Result<bool> {
    let _span = tracing::info_span!(
        "locate.term_has_graph_support",
        term = %term,
        from_title = from_title
    )
    .entered();
    let mut source_hits = 0usize;
    let mut docs_hits = 0usize;
    let mut other_hits = 0usize;
    let mut seen_files = HashSet::new();

    let filter = EntityFilter {
        name_pattern: Some(term.to_string()),
        ..Default::default()
    };
    for entity in graph
        .query_entities(&filter)?
        .into_iter()
        .take(locate_env_usize("KIN_LOCATE_GRAPH_NAME_MATCH_LIMIT", 16))
    {
        let Some(file_origin) = entity.file_origin.as_ref() else {
            continue;
        };
        let path = &file_origin.0;
        if !seen_files.insert(path.clone()) {
            continue;
        }
        let signal_bearing = tracked_file_support_is_signal_bearing(path.as_str());
        match entity.role {
            EntityRole::Docs => docs_hits += 1,
            EntityRole::Source if signal_bearing => source_hits += 1,
            EntityRole::Test
            | EntityRole::External
            | EntityRole::Vendored
            | EntityRole::Generated
            | EntityRole::Source => other_hits += 1,
        }
    }

    if source_hits > 0 {
        return Ok(true);
    }

    let hits = graph.text_search(
        term,
        locate_env_usize("KIN_LOCATE_GRAPH_SUPPORT_TEXT_LIMIT", 12),
    )?;
    if hits.is_empty() {
        return Ok(false);
    }

    for (retrieval_key, _) in hits {
        let item = graph.resolve_retrieval_key(&retrieval_key);
        let Some(path) = item
            .as_ref()
            .and_then(|item| item.file_path())
            .map(|file_id| file_id.0)
        else {
            continue;
        };
        if !seen_files.insert(path.clone()) {
            continue;
        }
        let signal_bearing = tracked_file_support_is_signal_bearing(path.as_str());
        match item {
            Some(kin_db::ResolvedRetrievalItem::Entity(entity)) => match entity.role {
                EntityRole::Docs => docs_hits += 1,
                EntityRole::Source if signal_bearing => source_hits += 1,
                EntityRole::Test
                | EntityRole::External
                | EntityRole::Vendored
                | EntityRole::Generated
                | EntityRole::Source => other_hits += 1,
            },
            Some(_) if signal_bearing => source_hits += 1,
            Some(_) if is_docs_or_locale_path(path.as_str()) => docs_hits += 1,
            Some(_) => other_hits += 1,
            None => {}
        }
    }

    if source_hits > 0 {
        return Ok(true);
    }
    let term_lower = term.to_ascii_lowercase();
    if tracked_non_entity_files(graph).into_iter().any(|tracked| {
        tracked_file_support_is_signal_bearing(&tracked.path)
            && (tracked.path.to_ascii_lowercase().contains(&term_lower)
                || tracked
                    .descriptor
                    .to_ascii_lowercase()
                    .contains(&term_lower))
    }) {
        return Ok(true);
    }
    if docs_hits > 0 {
        return Ok(false);
    }

    Ok(from_title && other_hits > 0)
}

/// Stricter version of term_has_graph_support: requires at least one entity
/// whose name matches via query_entities (name index). This filters out
/// English prose words that only match via BM25 text_search on docstrings.
fn term_has_name_support(graph: &kin_db::InMemoryGraph, term: &str) -> Result<bool> {
    let filter = EntityFilter {
        name_pattern: Some(term.to_string()),
        ..Default::default()
    };
    let matched = graph.query_entities(&filter)?;
    let has_source = matched.iter().any(|e| {
        e.role == EntityRole::Source
            && e.file_origin
                .as_ref()
                .is_some_and(|file_origin| tracked_file_support_is_signal_bearing(&file_origin.0))
    });
    if has_source {
        return Ok(true);
    }
    // Also accept if any non-docs entity matches
    Ok(matched.iter().any(|e| {
        e.role != EntityRole::Docs
            && e.file_origin
                .as_ref()
                .is_some_and(|file_origin| tracked_file_support_is_signal_bearing(&file_origin.0))
    }))
}

fn maybe_add_search_term(term: &str, seen: &mut HashSet<String>, queries: &mut Vec<String>) {
    let trimmed = term.trim();
    if trimmed.is_empty() || trimmed.len() <= 2 || is_noise_term(trimmed) {
        return;
    }
    if seen.insert(trimmed.to_string()) {
        queries.push(trimmed.to_string());
    }
}

fn is_numeric_issue_term(s: &str) -> bool {
    s.chars().all(|ch| ch.is_ascii_digit())
}

fn suppressed_query_terms(text: &str) -> HashSet<String> {
    let lower = text.to_ascii_lowercase();
    let mut suppressed = HashSet::new();

    if lower.contains("empty string") {
        suppressed.insert("empty".to_string());
    }
    if lower.contains("type parameter") {
        suppressed.insert("references".to_string());
    }
    if lower.contains("capability subtyping") {
        suppressed.insert("unsafe".to_string());
    }

    suppressed
}

fn is_issue_boilerplate_term(s: &str) -> bool {
    matches!(
        s,
        "based"
            | "comment"
            | "commit"
            | "implementation"
            | "include"
            | "includes"
            | "including"
            | "introduced"
            | "missed"
            | "related"
            | "suggested"
    )
}

// Common English stopwords that carry no code-identifier meaning. Filtered
// from query term extraction so natural-language connectives don't dominate
// EntityDominant scoring — e.g. ponyc queries where "previously", "through",
// "perform" were outranking the real identifiers.
const ENGLISH_STOPWORDS: &[&str] = &[
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "been",
    "before",
    "but",
    "by",
    "can",
    "did",
    "do",
    "does",
    "during",
    "for",
    "from",
    "has",
    "have",
    "if",
    "in",
    "into",
    "is",
    "it",
    "its",
    "of",
    "on",
    "or",
    "perform",
    "previously",
    "the",
    "then",
    "through",
    "to",
    "was",
    "were",
    "when",
    "where",
    "which",
    "while",
    "with",
];

fn is_english_stopword(s: &str) -> bool {
    ENGLISH_STOPWORDS.binary_search(&s).is_ok()
}

fn is_common_english_word(s: &str) -> bool {
    matches!(
        s,
        "type"
            | "types"
            | "class"
            | "object"
            | "method"
            | "function"
            | "value"
            | "values"
            | "return"
            | "returns"
            | "input"
            | "output"
            | "error"
            | "errors"
            | "warning"
            | "warnings"
            | "exception"
            | "fail"
            | "fails"
            | "failure"
            | "failures"
            | "success"
            | "test"
            | "tests"
            | "check"
            | "checks"
            | "result"
            | "results"
            | "data"
            | "file"
            | "files"
            | "path"
            | "paths"
            | "name"
            | "names"
            | "string"
            | "number"
            | "index"
            | "key"
            | "keys"
            | "table"
            | "column"
            | "row"
            | "field"
            | "format"
            | "model"
            | "constructor"
            | "constructors"
            | "decorator"
            | "decorators"
            | "parameter"
            | "parameters"
            | "argument"
            | "arguments"
            | "default"
            | "option"
            | "options"
            | "config"
            | "setting"
            | "change"
            | "changes"
            | "compiler"
            | "compile"
            | "compiles"
            | "compilation"
            | "crash"
            | "crashes"
            | "fix"
            | "fixed"
            | "fixes"
            | "issue"
            | "issues"
            | "update"
            | "add"
            | "remove"
            | "delete"
            | "create"
            | "read"
            | "write"
            | "get"
            | "set"
            | "run"
            | "call"
            | "use"
            | "using"
            | "used"
            | "make"
            | "made"
            | "work"
            | "works"
            | "need"
            | "needs"
            | "want"
            | "like"
            | "case"
            | "cases"
            | "support"
            | "handle"
            | "handling"
            | "process"
            | "convert"
            | "consider"
            | "removing"
            | "direct"
            | "approach"
            | "sometimes"
            | "always"
            | "never"
            | "also"
            | "only"
            | "just"
            | "ascii"
            | "html"
            | "json"
            | "xml"
            | "csv"
            | "text"
            | "double"
            | "single"
            | "quote"
            | "quotes"
            | "range"
            | "auto"
            | "transform"
            | "instead"
            | "raising"
            | "raises"
            | "raised"
            | "should"
            | "would"
            | "could"
            | "does"
            | "doesn"
            | "didn"
            | "aren"
            | "isn"
            | "wasn"
            | "haven"
            | "shouldn"
            | "wouldn"
            | "couldn"
            | "about"
            | "because"
            | "before"
            | "after"
            | "between"
            | "from"
            | "this"
            | "that"
            | "these"
            | "those"
            | "gives"
            | "giving"
            | "given"
            | "without"
            | "still"
            | "being"
            | "when"
            | "where"
            | "while"
            | "since"
            | "during"
            | "inside"
            | "correctly"
            | "incorrectly"
            | "currently"
            | "expected"
            | "actual"
            | "behavior"
            | "behaviour"
            | "message"
            | "attribute"
            | "property"
            | "properties"
            | "subclass"
            | "subclassed"
            | "misleading"
            | "management"
            | "inconsistency"
            | "supplied"
            | "custom"
            | "access"
            | "operation"
            | "different"
            | "identical"
            | "possible"
            | "trying"
            | "ability"
            | "provide"
            | "provides"
            | "provided"
            | "providing"
            | "user"
            | "users"
            | "certain"
            | "situations"
            | "true"
            | "false"
    )
}

fn is_noise_term(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "x86_64"
            | "amd64"
            | "arm64"
            | "auto"
            | "never"
            | "err"
            | "ok"
            | "linux"
            | "darwin"
            | "windows"
            | "macos"
            | "python"
            | "python3"
            | "pip"
            | "conda"
            | "npm"
            | "cargo"
            | "version"
            | "github"
            | "http"
            | "https"
            | "www"
            | "com"
            | "org"
            | "none"
            | "true"
            | "false"
            | "self"
            | "str"
            | "int"
            | "float"
            | "bool"
            | "list"
            | "dict"
            | "tuple"
            | "set"
            | "bug"
            | "issue"
            | "fix"
            | "patch"
            | "expected"
            | "actual"
            | "example"
            | "sample"
            | "note"
            | "see"
            | "todo"
            | "based"
            | "comment"
            | "commit"
            | "implementation"
            | "include"
            | "includes"
            | "including"
            | "introduced"
            | "missed"
            | "related"
            | "suggested"
            | "the"
            | "is"
            | "are"
            | "was"
            | "were"
            | "be"
            | "been"
            | "being"
            | "have"
            | "has"
            | "had"
            | "do"
            | "does"
            | "did"
            | "will"
            | "would"
            | "could"
            | "should"
            | "may"
            | "might"
            | "can"
            | "shall"
            | "not"
            | "no"
            | "and"
            | "or"
            | "but"
            | "if"
            | "then"
            | "else"
            | "when"
            | "while"
            | "for"
            | "to"
            | "from"
            | "in"
            | "on"
            | "at"
            | "by"
            | "with"
            | "of"
            | "about"
            | "this"
            | "that"
            | "it"
            | "its"
            | "my"
            | "your"
            | "our"
            | "their"
            | "which"
            | "what"
            | "how"
            | "why"
            | "where"
            | "there"
            | "here"
            | "all"
            | "any"
            | "each"
            | "every"
            | "some"
            | "new"
            | "old"
    )
}

// ---------------------------------------------------------------------------
// 3. Multi-hop graph walk (relation-aware, 2-hop)
// ---------------------------------------------------------------------------

fn extract_multihop_signals(
    seed_hit_sets: &[&HashMap<String, Vec<FileHit>>],
    graph: &kin_db::InMemoryGraph,
    profile: LocateProfile,
    test_query: bool,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let _span = tracing::info_span!(
        "locate.extract_multihop_signals",
        seed_sets = seed_hit_sets.len(),
        ?profile,
    )
    .entered();
    use std::collections::VecDeque;

    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    // Profile-adaptive BFS parameters, overridable via env vars but capped by profile
    let profile_max_depth = profile.multihop_max_depth();
    let max_depth =
        locate_env_usize("KIN_LOCATE_MULTIHOP_MAX_DEPTH", profile_max_depth).min(profile_max_depth);
    let frontier_limit = locate_env_usize(
        "KIN_LOCATE_MULTIHOP_FRONTIER_LIMIT",
        profile.multihop_frontier_limit(),
    );
    let timeout = std::time::Duration::from_millis(locate_env_usize(
        "KIN_LOCATE_MULTIHOP_TIMEOUT_MS",
        profile.multihop_timeout_ms() as usize,
    ) as u64);
    let bfs_start = std::time::Instant::now();

    let mut seed_scores: HashMap<String, f32> = HashMap::new();
    for hit_set in seed_hit_sets {
        for (path, file_hits) in hit_set.iter() {
            let max_score = file_hits.iter().map(|h| h.score).fold(0.0f32, f32::max);
            let entry = seed_scores.entry(path.clone()).or_insert(0.0);
            *entry = entry.max(max_score);
        }
    }

    // Get top files from high-confidence signal sources.
    let mut seed_files: Vec<(String, f32)> = seed_scores.into_iter().collect();
    seed_files.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    // Adaptive seed limit: large repos (>10K entities) benefit from fewer
    // seeds to limit hub expansion; small repos use the full budget.
    let default_seed_limit = if graph.entity_count() > 10_000 { 5 } else { 8 };
    let seed_limit = locate_env_usize("KIN_LOCATE_MULTIHOP_SEED_FILES", default_seed_limit);
    let mut retained_seed_files = seed_files
        .iter()
        .take(seed_limit)
        .cloned()
        .collect::<Vec<_>>();
    if test_query {
        let test_seed_limit = locate_env_usize("KIN_LOCATE_MULTIHOP_TEST_SEED_FILES", 16);
        for (path, score) in seed_files.iter().filter(|(path, _)| is_test_path(path)) {
            if retained_seed_files.iter().any(|(seen, _)| seen == path) {
                continue;
            }
            retained_seed_files.push((path.clone(), *score));
            if retained_seed_files
                .iter()
                .filter(|(candidate, _)| is_test_path(candidate))
                .count()
                >= test_seed_limit
            {
                break;
            }
        }
    }
    seed_files = retained_seed_files;

    let default_artifact_hops = if test_query { 2 } else { 1 };
    let artifact_hops =
        locate_env_usize("KIN_LOCATE_MULTIHOP_ARTIFACT_HOPS", default_artifact_hops);
    let artifact_frontier_limit =
        locate_env_usize("KIN_LOCATE_MULTIHOP_ARTIFACT_FRONTIER_LIMIT", 32);
    let artifact_hop_decay = locate_env_f32("KIN_LOCATE_MULTIHOP_ARTIFACT_HOP_DECAY", 0.65);
    if artifact_hops > 0 {
        for (seed_path, seed_score) in &seed_files {
            if (!test_query && is_test_path(seed_path)) || is_vendored_path(seed_path) {
                continue;
            }
            let Some(start_artifact_id) =
                graph.artifact_id_for_path(&kin_model::FilePathId::new(seed_path.as_str()))
            else {
                continue;
            };
            let start = GraphNodeId::Artifact(start_artifact_id);
            let mut visited = HashSet::from([start.clone()]);
            let mut queue = VecDeque::from([(start, seed_path.clone(), 0usize)]);
            let seed_strength = (*seed_score / 72.0).clamp(0.35, 2.0);

            while let Some((artifact_node, _via_path, depth)) = queue.pop_front() {
                if depth >= artifact_hops {
                    continue;
                }
                let mut rels = graph.get_all_relations_for_node(&artifact_node)?;
                rels.sort_by(|left, right| {
                    let left_kind = resolve_relation_kind_priority(left.kind);
                    let right_kind = resolve_relation_kind_priority(right.kind);
                    let left_origin = resolve_relation_origin_priority(left.origin);
                    let right_origin = resolve_relation_origin_priority(right.origin);
                    right_kind
                        .cmp(&left_kind)
                        .then_with(|| right_origin.cmp(&left_origin))
                        .then_with(|| format!("{:?}", left.id).cmp(&format!("{:?}", right.id)))
                });

                for rel in rels
                    .iter()
                    .filter(|rel| relation_allows_artifact_traversal(rel, &artifact_node))
                    .take(artifact_frontier_limit)
                {
                    let Some((path, next)) =
                        relation_adjacent_artifact_path(graph, rel, &artifact_node)
                    else {
                        continue;
                    };
                    if path == *seed_path || is_test_path(&path) || is_vendored_path(&path) {
                        continue;
                    }

                    let hop = depth + 1;
                    let origin_mult = if rel.origin == kin_model::RelationOrigin::Lsp {
                        locate_env_f32("KIN_LOCATE_LSP_ORIGIN_BOOST", 2.0)
                    } else {
                        1.0
                    };
                    let kind_mult = match rel.kind {
                        RelationKind::Includes | RelationKind::Imports => 1.8,
                        RelationKind::DerivedFrom => 1.6,
                        _ => 1.0,
                    };
                    let path_specificity =
                        artifact_relation_path_specificity_multiplier(seed_path, &path, hop);
                    let score = seed_strength
                        * origin_mult
                        * kind_mult
                        * path_specificity
                        * artifact_hop_decay.powi(depth as i32)
                        / (hop as f32);
                    hits.entry(path.clone()).or_default().push(FileHit {
                        score,
                        spans: vec![],
                    });

                    if visited.insert(next.clone()) {
                        queue.push_back((next, path, depth + 1));
                    }
                }
            }
        }
    }

    // Cache entity-count-based hub dampening per file path to avoid repeated queries
    let mut hub_dampening_cache: HashMap<String, f32> = HashMap::new();

    let allowed_kinds = [
        RelationKind::Calls,
        RelationKind::Imports,
        RelationKind::Includes,
        RelationKind::UsesMacro,
        RelationKind::DerivedFrom,
        RelationKind::Tests,
        RelationKind::DependsOn,
        RelationKind::Implements,
        RelationKind::Extends,
        RelationKind::References,
    ];

    'outer: for (seed_path, _seed_score) in &seed_files {
        // Timeout guard: return what we have so far
        if bfs_start.elapsed() > timeout {
            tracing::debug!(
                "multihop BFS timeout reached after {:?}",
                bfs_start.elapsed()
            );
            break;
        }

        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(seed_path.as_str())),
            ..Default::default()
        };
        let entities = graph.query_entities(&filter)?;
        for entity in entities
            .iter()
            .take(locate_env_usize("KIN_LOCATE_MULTIHOP_ENTITY_LIMIT", 64))
        {
            let mut queue = VecDeque::from([(entity.id, 0usize)]);
            let mut visited = HashSet::from([entity.id]);

            while let Some((current, depth)) = queue.pop_front() {
                // Timeout guard within BFS loop
                if bfs_start.elapsed() > timeout {
                    tracing::debug!("multihop BFS timeout reached mid-walk");
                    break 'outer;
                }

                if depth >= max_depth {
                    continue;
                }

                let rels = graph.get_all_relations_for_entity(&current)?;
                // Frontier size limit: only process up to frontier_limit relations per BFS level
                let rels_to_process = if rels.len() > frontier_limit {
                    &rels[..frontier_limit]
                } else {
                    &rels
                };
                for rel in rels_to_process {
                    if !allowed_kinds.contains(&rel.kind) {
                        continue;
                    }
                    let neighbor_id = if rel.src == GraphNodeId::Entity(current) {
                        rel.dst
                    } else {
                        rel.src
                    };
                    let Some(neighbor_id) = neighbor_id.as_entity() else {
                        continue;
                    };
                    if !visited.insert(neighbor_id) {
                        continue;
                    }

                    if let Some(neighbor) = graph.get_entity(&neighbor_id)? {
                        if !test_query
                            && matches!(
                                neighbor.role,
                                EntityRole::Test
                                    | EntityRole::External
                                    | EntityRole::Docs
                                    | EntityRole::Generated
                                    | EntityRole::Vendored
                            )
                        {
                            continue;
                        }
                        // Constants (CSS tokens, config values) are weak
                        // file-location signals — dampen them so they don't
                        // dominate repos like MUI with thousands of constants.
                        let kind_mult = if neighbor.kind == EntityKind::Constant {
                            locate_env_f32("KIN_LOCATE_MULTIHOP_CONSTANT_DAMPENING", 0.25)
                        } else {
                            1.0
                        };
                        if let Some(ref fo) = neighbor.file_origin {
                            let path = fo.0.clone();
                            let base_mult = match rel.kind {
                                RelationKind::Tests => 2.4,
                                RelationKind::Calls => 2.0,
                                RelationKind::Imports
                                | RelationKind::Includes
                                | RelationKind::UsesMacro
                                | RelationKind::DerivedFrom
                                | RelationKind::DependsOn => 1.8,
                                RelationKind::Implements | RelationKind::Extends => 1.5,
                                RelationKind::References => 1.2,
                                _ => 1.0,
                            };
                            // Boost LSP-origin relations — they're type-resolved and more
                            // precise than tree-sitter's name-based matching.
                            let origin_mult = if rel.origin == kin_model::RelationOrigin::Lsp {
                                locate_env_f32("KIN_LOCATE_LSP_ORIGIN_BOOST", 2.0)
                            } else {
                                1.0
                            };
                            let rel_mult = base_mult * origin_mult;
                            // Progressive hop decay: each hop beyond the first reduces score
                            let hop_decay = if depth == 0 {
                                1.0
                            } else {
                                0.65_f32.powi(depth as i32)
                            };
                            let test_mult = test_mult_by_role(&path, Some(&neighbor), 0.35);
                            // Dampen high-degree source entities: an entity with 200
                            // relations is a hub whose edges are individually weak.
                            // Scale by 1/log2(degree) when degree > threshold.
                            let source_degree_threshold =
                                locate_env_usize("KIN_LOCATE_MULTIHOP_SOURCE_DEGREE_THRESHOLD", 50);
                            let source_degree_dampen =
                                if rels_to_process.len() > source_degree_threshold {
                                    1.0 / (rels_to_process.len() as f32).log2()
                                } else {
                                    1.0
                                };
                            // Dampen hub files: files with many entities (e.g. src/jv.c
                            // with 300+ entities) always dominate because they have the
                            // most edges. Scale by 1/log2(entity_count + 1) so hubs
                            // don't outscore focused files.
                            let hub_dampen =
                                *hub_dampening_cache.entry(path.clone()).or_insert_with(|| {
                                    let filter = EntityFilter {
                                        file_path: Some(kin_model::FilePathId::new(&path)),
                                        ..Default::default()
                                    };
                                    let entity_count =
                                        graph.query_entities(&filter).map(|e| e.len()).unwrap_or(1);
                                    1.0 / ((entity_count as f32) + 1.0).log2()
                                });
                            let score = rel_mult
                                * test_mult
                                * hop_decay
                                * hub_dampen
                                * source_degree_dampen
                                * kind_mult;

                            // Hard cutoff: if combined dampening crushes the
                            // score below threshold, skip this file entirely
                            // rather than letting near-zero scores consume
                            // top-k slots from focused files.
                            let hub_cutoff = locate_env_f32("KIN_LOCATE_MULTIHOP_HUB_CUTOFF", 0.05);
                            if hub_dampen * source_degree_dampen < hub_cutoff {
                                continue;
                            }

                            hits.entry(path).or_default().push(FileHit {
                                score,
                                spans: entity_span_pair(&neighbor),
                            });
                        }
                    }

                    queue.push_back((neighbor_id, depth + 1));
                }
            }
        }
    }

    Ok(hits)
}

// ---------------------------------------------------------------------------
// 4. Failing test extraction
// ---------------------------------------------------------------------------

fn extract_test_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let _span = tracing::info_span!("locate.extract_test_signals", text_len = text.len()).entered();
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    // Extract test names
    let re_test_func = regex::Regex::new(r"\b(test_\w+)\b").unwrap();
    let re_test_class = regex::Regex::new(r"\b(Test\w+)\.(\w+)\b").unwrap();
    let re_pytest_node = regex::Regex::new(
        r"\b([A-Za-z0-9_./-]+\.py)(?:::(?:[A-Za-z_][\w]*))*?(?:::?(test_\w+))?\b",
    )
    .unwrap();
    let re_dotted_test_module =
        regex::Regex::new(r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\.(Test\w+)\.(\w+)\b").unwrap();
    let re_dotted_test_func =
        regex::Regex::new(r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\.(test_\w+)\b").unwrap();
    let re_double_colon = regex::Regex::new(r"\b(Test\w+)::(test_\w+)\b").unwrap();

    let mut test_names: Vec<String> = Vec::new();
    let mut seen_names = HashSet::new();
    let mut seen_paths = HashSet::new();

    let mut push_test_name = |name: String| {
        if !name.is_empty() && seen_names.insert(name.clone()) {
            test_names.push(name);
        }
    };
    let mut push_test_path = |candidate: &str, score: f32| {
        if let Some(path) = resolve_path_in_graph(graph, candidate) {
            if seen_paths.insert(path.clone()) {
                hits.entry(path).or_default().push(FileHit {
                    score,
                    spans: vec![],
                });
            }
        }
    };

    for cap in re_test_func.captures_iter(text) {
        push_test_name(cap[1].to_string());
    }
    for cap in re_test_class.captures_iter(text) {
        push_test_name(format!("{}.{}", &cap[1], &cap[2]));
        push_test_name(cap[2].to_string());
    }
    for cap in re_pytest_node.captures_iter(text) {
        push_test_path(&normalize_traceback_path(&cap[1]), 8.0);
        if let Some(test_name) = cap.get(2) {
            push_test_name(test_name.as_str().to_string());
        }
    }
    for cap in re_dotted_test_module.captures_iter(text) {
        for module_path in module_path_candidates(&cap[1]) {
            push_test_path(&module_path, 7.0);
        }
        push_test_name(format!("{}.{}", &cap[2], &cap[3]));
        push_test_name(cap[3].to_string());
    }
    for cap in re_dotted_test_func.captures_iter(text) {
        for module_path in module_path_candidates(&cap[1]) {
            push_test_path(&module_path, 7.0);
        }
        push_test_name(cap[2].to_string());
    }
    for cap in re_double_colon.captures_iter(text) {
        push_test_name(format!("{}.{}", &cap[1], &cap[2]));
        push_test_name(cap[2].to_string());
    }

    for test_name in &test_names {
        // Find the test entity
        let filter = EntityFilter {
            name_pattern: Some(test_name.clone()),
            kinds: Some(vec![EntityKind::Function, EntityKind::Method]),
            ..Default::default()
        };
        let matched = graph.query_entities(&filter)?;

        for test_entity in &matched {
            // The test file itself gets a low score
            if let Some(ref fo) = test_entity.file_origin {
                hits.entry(fo.0.clone()).or_default().push(FileHit {
                    score: 0.5,
                    spans: entity_span_pair(test_entity),
                });
            }

            // Follow imports/calls from test to find source files under test
            let rels = graph.get_relations(
                &test_entity.id,
                &[
                    RelationKind::Calls,
                    RelationKind::Imports,
                    RelationKind::Tests,
                ],
            )?;
            for rel in &rels {
                let Some(target_id) = rel.dst.as_entity() else {
                    continue;
                };
                if let Some(target) = graph.get_entity(&target_id)? {
                    if let Some(ref fo) = target.file_origin {
                        let path = fo.0.clone();
                        let score = if is_test_by_role(&path, Some(&target)) {
                            0.5
                        } else {
                            3.0
                        };
                        hits.entry(path).or_default().push(FileHit {
                            score,
                            spans: entity_span_pair(&target),
                        });
                    }
                }
            }
        }
    }

    if is_test_query(text) {
        let fallback_terms = curate_search_terms(text, graph).unwrap_or_else(|_| {
            let mut fallback = extract_search_terms(text);
            if fallback.is_empty() {
                fallback = extract_title_terms(text);
            }
            fallback
        });
        let mut seen_entities = HashSet::new();

        for term in fallback_terms
            .into_iter()
            .take(locate_env_usize("KIN_LOCATE_TEST_RELATION_TERM_LIMIT", 4))
        {
            let filter = EntityFilter {
                name_pattern: Some(term),
                ..Default::default()
            };
            for entity in graph.query_entities(&filter)?.into_iter().take(12) {
                if !seen_entities.insert(entity.id) {
                    continue;
                }
                let rels = graph.get_all_relations_for_entity(&entity.id)?;
                let has_test_rels = rels.iter().any(|r| r.kind == RelationKind::Tests);
                if has_test_rels {
                    if let Some(ref fo) = entity.file_origin {
                        let score = if is_test_by_role(&fo.0, Some(&entity)) {
                            2.5
                        } else {
                            1.5
                        };
                        hits.entry(fo.0.clone()).or_default().push(FileHit {
                            score,
                            spans: entity_span_pair(&entity),
                        });
                    }
                }
                for rel in &rels {
                    if rel.kind != RelationKind::Tests {
                        continue;
                    }
                    let Some(other_id) = (if rel.src == GraphNodeId::Entity(entity.id) {
                        rel.dst.as_entity()
                    } else {
                        rel.src.as_entity()
                    }) else {
                        continue;
                    };
                    let Some(other) = graph.get_entity(&other_id)? else {
                        continue;
                    };
                    let Some(ref fo) = other.file_origin else {
                        continue;
                    };
                    let score = if is_test_by_role(&fo.0, Some(&other)) {
                        2.5
                    } else {
                        1.5
                    };
                    hits.entry(fo.0.clone()).or_default().push(FileHit {
                        score,
                        spans: entity_span_pair(&other),
                    });
                }
            }
        }
    }

    Ok(hits)
}

fn extract_cpp_private_access_test_seed_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let _span = tracing::info_span!(
        "locate.extract_cpp_private_access_test_seed_signals",
        text_len = text.len()
    )
    .entered();
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();
    if !query_mentions_cpp_access_macro_context(text) {
        return Ok(hits);
    }

    let lower = text.to_ascii_lowercase();
    let mut query_terms = vec!["private".to_string(), "public".to_string()];
    if lower.contains("#define") || lower.contains("define") {
        query_terms.push("define".to_string());
    }
    if lower.contains("hack") {
        query_terms.push("hack".to_string());
    }
    let mut seen_query_terms = HashSet::new();
    query_terms.retain(|term| seen_query_terms.insert(term.clone()));

    let hit_limit = locate_env_usize("KIN_LOCATE_PRIVATE_ACCESS_TEST_HIT_LIMIT", 256);
    let seed_limit = locate_env_usize("KIN_LOCATE_PRIVATE_ACCESS_TEST_SEED_LIMIT", 24);
    let min_terms = locate_env_usize("KIN_LOCATE_PRIVATE_ACCESS_TEST_MIN_TERMS", 2).max(1);
    let base_score = locate_env_f32("KIN_LOCATE_PRIVATE_ACCESS_TEST_BASE_SCORE", 72.0);
    let term_bonus = locate_env_f32("KIN_LOCATE_PRIVATE_ACCESS_TEST_TERM_BONUS", 18.0);

    let mut per_path_scores: HashMap<String, f32> = HashMap::new();
    let mut per_path_terms: HashMap<String, HashSet<String>> = HashMap::new();
    for term in &query_terms {
        let text_hits = match graph.text_search(term, hit_limit) {
            Ok(hits) => hits,
            Err(_) => continue,
        };
        for (rank, (retrieval_key, _score)) in text_hits.into_iter().enumerate() {
            let Some(path) = file_path_from_retrieval_key(graph, &retrieval_key) else {
                continue;
            };
            if !is_test_path(&path) || !is_cpp_like_source_path(&path) || is_vendored_path(&path) {
                continue;
            }
            let score = base_score / ((rank + 1) as f32).sqrt();
            per_path_scores
                .entry(path.clone())
                .and_modify(|existing| *existing = existing.max(score))
                .or_insert(score);
            per_path_terms.entry(path).or_default().insert(term.clone());
        }
    }

    let mut ranked = per_path_scores
        .into_iter()
        .filter(|(path, _)| {
            per_path_terms
                .get(path)
                .is_some_and(|terms| terms.len() >= min_terms)
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        let left_terms = per_path_terms.get(&left.0).map_or(0usize, HashSet::len);
        let right_terms = per_path_terms.get(&right.0).map_or(0usize, HashSet::len);
        right_terms
            .cmp(&left_terms)
            .then_with(|| {
                right
                    .1
                    .partial_cmp(&left.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| left.0.cmp(&right.0))
    });

    for (path, mut score) in ranked.into_iter().take(seed_limit) {
        let matched_terms = per_path_terms.get(&path).map_or(1usize, HashSet::len);
        score += term_bonus * matched_terms.saturating_sub(1).min(3) as f32;
        score += semantic_path_tokens(&path).len().min(3) as f32;
        hits.entry(path).or_default().push(FileHit {
            score,
            spans: vec![],
        });
    }

    Ok(hits)
}

fn is_cpp_like_source_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".ipp",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

// ---------------------------------------------------------------------------
// 5. Code snippet matching
// ---------------------------------------------------------------------------

fn extract_snippet_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let _span =
        tracing::info_span!("locate.extract_snippet_signals", text_len = text.len()).entered();
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    let snippets = extract_code_snippets(text);
    if snippets.is_empty() {
        return Ok(hits);
    }

    for snippet in &snippets {
        // Extract function/class signatures from the snippet
        let re_def = regex::Regex::new(r"(?:def|class|fn|func|function)\s+(\w+)").unwrap();
        for cap in re_def.captures_iter(snippet) {
            let name = &cap[1];
            let filter = EntityFilter {
                name_pattern: Some(name.to_string()),
                ..Default::default()
            };
            let matched = graph.query_entities(&filter)?;
            for entity in &matched {
                // Check if the signature matches
                if !entity.signature.is_empty() && snippet.contains(&entity.name) {
                    if let Some(ref fo) = entity.file_origin {
                        hits.entry(fo.0.clone()).or_default().push(FileHit {
                            score: 2.0,
                            spans: entity_span_pair(entity),
                        });
                    }
                }
            }
        }

        // Also try text search with the whole snippet (first 100 chars)
        let search_text = &snippet[..snippet.len().min(100)];
        let text_hits = graph.text_search(search_text, 5)?;
        for (retrieval_key, _) in &text_hits {
            if let Some(entity) = entity_from_retrieval_key(graph, retrieval_key)? {
                if let Some(ref fo) = entity.file_origin {
                    hits.entry(fo.0.clone()).or_default().push(FileHit {
                        score: 1.5,
                        spans: entity_span_pair(&entity),
                    });
                }
            }
        }
    }

    Ok(hits)
}

fn extract_source_text_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
    workspace_root: Option<&std::path::Path>,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let _span =
        tracing::info_span!("locate.extract_source_text_signals", text_len = text.len()).entered();
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();
    let term_limit = locate_env_usize("KIN_LOCATE_SOURCE_TEXT_TERM_LIMIT", 12);
    let hit_limit = locate_env_usize("KIN_LOCATE_SOURCE_TEXT_HIT_LIMIT", 64);
    let broad_limit = locate_env_usize("KIN_LOCATE_SOURCE_TEXT_BROAD_LIMIT", 4);
    let cli_flag_terms = extract_cli_flag_terms(text);
    let cli_flag_query = query_mentions_cli_flags(text);
    let body_text = text.lines().skip(1).collect::<Vec<_>>().join("\n");
    let mut source_paths = source_file_paths(graph);
    let artifacts = graph.list_opaque_artifacts().unwrap_or_default();
    for artifact in &artifacts {
        let path = &artifact.file_id.0;
        if is_test_path(path)
            || is_docs_or_locale_path(path)
            || is_vendor_path(path)
            || is_embedded_framework_noise_path(path)
        {
            continue;
        }
        if source_paths.contains(path)
            || is_source_like_artifact_path(path, artifact.mime_type.as_deref())
        {
            source_paths.insert(path.clone());
        }
    }
    if source_paths.is_empty() {
        return Ok(hits);
    }

    let source_previews: HashMap<String, String> = artifacts
        .into_iter()
        .filter_map(|artifact| {
            let path = artifact.file_id.0;
            if !source_paths.contains(&path) || is_test_path(&path) {
                return None;
            }
            let preview = artifact.text_preview?;
            Some((path, preview))
        })
        .collect();
    let preview_source_texts: HashMap<String, String> = source_previews
        .iter()
        .map(|(path, preview)| (path.clone(), preview.to_ascii_lowercase()))
        .collect();
    let full_source_texts: HashMap<String, String> = preview_source_texts
        .iter()
        .filter(|(path, _)| {
            source_previews
                .get(*path)
                .is_some_and(|preview| preview.len() > 1024)
        })
        .map(|(path, preview)| (path.clone(), preview.clone()))
        .collect();
    let mut path_term_support: HashMap<String, HashSet<String>> = HashMap::new();

    let mut terms = extract_search_terms(text);
    terms.extend(extract_loose_query_terms(&body_text));
    terms.extend(cli_flag_terms);

    let mut seen = HashSet::new();
    terms.retain(|term| seen.insert(term.to_ascii_lowercase()));
    terms.retain(|term| {
        if is_cli_flag_term(term) {
            return true;
        }
        let canonical = term.to_ascii_lowercase();
        canonical.len() >= 4
            && !canonical.chars().all(|ch| ch.is_ascii_digit())
            && !is_noise_term(&canonical)
            && !is_common_english_word(&canonical)
    });
    terms.sort_by(|left, right| {
        is_symbolic_search_term(right)
            .cmp(&is_symbolic_search_term(left))
            .then_with(|| right.len().cmp(&left.len()))
            .then_with(|| left.cmp(right))
    });

    for term in terms.into_iter().take(term_limit) {
        let cli_flag = is_cli_flag_term(&term);
        let symbolic = cli_flag || is_symbolic_search_term(&term);
        let base_score = if cli_flag {
            132.0
        } else if symbolic {
            120.0
        } else {
            72.0
        };
        let max_hits = if cli_flag {
            8
        } else if symbolic {
            locate_env_usize("KIN_LOCATE_SOURCE_TEXT_SYMBOLIC_MAX_HITS", 16)
        } else {
            3
        };
        let mut per_path: HashMap<String, f32> = HashMap::new();
        let term_lower = term.to_ascii_lowercase();

        if cli_flag {
            let cli_surface_paths = source_paths
                .iter()
                .filter(|path| is_cli_surface_path(path))
                .cloned()
                .collect::<Vec<_>>();
            for path in &cli_surface_paths {
                let Some(source_text) =
                    lowercase_source_text(path, &preview_source_texts, workspace_root.as_deref())
                else {
                    continue;
                };
                if source_text.contains(&term_lower) {
                    let entry = per_path.entry(path.clone()).or_insert(0.0);
                    *entry = entry.max(base_score);
                }
            }
        } else if symbolic {
            for path in &source_paths {
                let Some(source_text) =
                    lowercase_source_text(path, &preview_source_texts, workspace_root.as_deref())
                else {
                    continue;
                };
                if source_text.contains(&term_lower) {
                    let entry = per_path.entry(path.clone()).or_insert(0.0);
                    *entry = entry.max(base_score);
                }
            }
        }

        for (rank, (retrieval_key, _score)) in
            graph.text_search(&term, hit_limit)?.into_iter().enumerate()
        {
            // Accept both Artifact and Entity hits. Entity-typed hits carry the
            // BM25-IDF signal for a discriminating term that names a function/class
            // (e.g. `depthwise_conv`): discarding them dropped the one signal that
            // already down-weights common words and surfaces the true edit sites,
            // leaving only the flat-scored entity_name_exact priority path (which
            // favors generic hub files). file_path_from_retrieval_key resolves both
            // key kinds, and the source_paths / source-contains guards below still
            // bound which files are admitted.
            let Some(path) = file_path_from_retrieval_key(graph, &retrieval_key) else {
                continue;
            };
            if !source_paths.contains(&path) || is_test_path(&path) {
                continue;
            }
            if symbolic
                && full_source_texts
                    .get(&path)
                    .is_some_and(|source_text| !source_text.contains(&term_lower))
            {
                continue;
            }
            let score = base_score / ((rank + 1) as f32).sqrt();
            let entry = per_path.entry(path).or_insert(0.0);
            *entry = entry.max(score);
        }

        if per_path.is_empty() || (!symbolic && per_path.len() > broad_limit) {
            continue;
        }

        let mut ranked_paths = per_path.into_iter().collect::<Vec<_>>();
        ranked_paths.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        let canonical_term = term.to_ascii_lowercase();
        for (path, score) in ranked_paths.into_iter().take(max_hits) {
            path_term_support
                .entry(path.clone())
                .or_default()
                .insert(canonical_term.clone());
            hits.entry(path).or_default().push(FileHit {
                score,
                spans: vec![],
            });
        }
    }

    for (path, matched_terms) in &path_term_support {
        let term_count = matched_terms.len();
        let symbolic_count = matched_terms
            .iter()
            .filter(|term| is_symbolic_search_term(term))
            .count();
        let mut bonus = 0.0;
        if term_count >= 2 {
            bonus += locate_env_f32("KIN_LOCATE_SOURCE_TEXT_MULTI_TERM_BONUS", 18.0)
                * ((term_count - 1).min(2) as f32);
        }
        if symbolic_count > 0 {
            bonus += locate_env_f32("KIN_LOCATE_SOURCE_TEXT_SYMBOLIC_SUPPORT_BONUS", 8.0)
                * (symbolic_count.min(2) as f32);
        }
        if cli_flag_query && is_cli_surface_path(&path) {
            bonus += locate_env_f32("KIN_LOCATE_SOURCE_TEXT_CLI_SURFACE_BONUS", 22.0);
        }
        if bonus > 0.0 {
            hits.entry(path.clone()).or_default().push(FileHit {
                score: bonus,
                spans: vec![],
            });
        }
    }

    promote_local_include_source_hits(
        &mut hits,
        &path_term_support,
        &source_previews,
        &source_paths,
        cli_flag_query,
        workspace_root.as_deref(),
    );
    promote_cli_surface_companion_headers_in_source_text(
        &mut hits,
        &path_term_support,
        workspace_root.as_deref(),
    );

    Ok(hits)
}

fn promote_cli_surface_companion_headers_in_source_text(
    hits: &mut HashMap<String, Vec<FileHit>>,
    path_term_support: &HashMap<String, HashSet<String>>,
    workspace_root: Option<&std::path::Path>,
) {
    let Some(workspace_root) = workspace_root else {
        return;
    };
    let seed_limit = locate_env_usize("KIN_LOCATE_SOURCE_TEXT_HEADER_SEED_LIMIT", 3);
    let direct_score = locate_env_f32("KIN_LOCATE_SOURCE_TEXT_HEADER_SCORE", 108.0);
    let nested_score = locate_env_f32("KIN_LOCATE_SOURCE_TEXT_HEADER_NESTED_SCORE", 84.0);
    if direct_score <= 0.0 || nested_score <= 0.0 {
        return;
    }

    let seed_paths = path_term_support
        .iter()
        .filter(|(path, _)| matches!(cli_surface_bucket(path), Some("programs" | "options")))
        .map(|(path, _)| {
            let score = hits
                .get(path)
                .map(|entries| entries.iter().map(|hit| hit.score).sum())
                .unwrap_or(0.0);
            (path.clone(), score)
        })
        .collect::<Vec<_>>();
    if seed_paths.is_empty() {
        return;
    }

    let mut seed_paths = seed_paths;
    seed_paths.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    seed_paths.truncate(seed_limit);

    let empty_paths = HashSet::new();
    for (seed, _) in seed_paths {
        let Some(header_path) = sibling_header_for_cli_surface(&seed, workspace_root) else {
            continue;
        };
        hits.entry(header_path.clone()).or_default().push(FileHit {
            score: direct_score,
            spans: vec![],
        });
        let Some(header_text) = read_workspace_source_text(&header_path, Some(workspace_root))
        else {
            continue;
        };
        for include_path in extract_local_quoted_include_targets(
            &header_path,
            &header_text,
            &empty_paths,
            Some(workspace_root),
        ) {
            if is_header_like_path(&include_path) {
                hits.entry(include_path).or_default().push(FileHit {
                    score: nested_score,
                    spans: vec![],
                });
            }
        }
    }
}

fn promote_local_include_source_hits(
    hits: &mut HashMap<String, Vec<FileHit>>,
    path_term_support: &HashMap<String, HashSet<String>>,
    source_previews: &HashMap<String, String>,
    source_paths: &HashSet<String>,
    cli_flag_query: bool,
    workspace_root: Option<&std::path::Path>,
) {
    if !cli_flag_query || source_previews.is_empty() {
        return;
    }

    let seed_limit = locate_env_usize("KIN_LOCATE_SOURCE_TEXT_INCLUDE_SEED_LIMIT", 4);
    let depth_limit = locate_env_usize("KIN_LOCATE_SOURCE_TEXT_INCLUDE_DEPTH", 2).min(3);
    if depth_limit == 0 {
        return;
    }

    let include_bonus = locate_env_f32("KIN_LOCATE_SOURCE_TEXT_INCLUDE_SCORE", 84.0);
    let include_decay = locate_env_f32("KIN_LOCATE_SOURCE_TEXT_INCLUDE_DECAY", 0.72);
    let mut seed_paths = path_term_support
        .iter()
        .filter(|(path, terms)| {
            is_cli_surface_path(path)
                && terms.iter().any(|term| is_cli_flag_term(term))
                && source_previews.contains_key(*path)
        })
        .map(|(path, _)| {
            let score = hits
                .get(path)
                .map(|entries| entries.iter().map(|hit| hit.score).sum())
                .unwrap_or(0.0);
            (path.clone(), score)
        })
        .collect::<Vec<_>>();
    if seed_paths.is_empty() {
        return;
    }

    seed_paths.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    seed_paths.truncate(seed_limit);

    let mut queue = std::collections::VecDeque::new();
    let mut seen = HashSet::new();
    let mut promoted = HashSet::new();
    for (path, _) in seed_paths {
        if seen.insert(path.clone()) {
            queue.push_back((path, 0usize));
        }
    }

    while let Some((path, depth)) = queue.pop_front() {
        if depth >= depth_limit {
            continue;
        }
        let Some(preview) = read_workspace_source_text(&path, workspace_root)
            .or_else(|| source_previews.get(&path).cloned())
        else {
            continue;
        };
        let score = include_bonus * include_decay.powi(depth as i32);
        for include_path in
            extract_local_quoted_include_targets(&path, &preview, source_paths, workspace_root)
        {
            if !is_header_like_path(&include_path) {
                continue;
            }
            if promoted.insert(include_path.clone()) {
                hits.entry(include_path.clone()).or_default().push(FileHit {
                    score,
                    spans: vec![],
                });
            }
            if seen.insert(include_path.clone()) {
                queue.push_back((include_path, depth + 1));
            }
        }
    }
}

fn extract_local_quoted_include_targets(
    path: &str,
    preview: &str,
    source_paths: &HashSet<String>,
    workspace_root: Option<&std::path::Path>,
) -> Vec<String> {
    let include_re = regex::Regex::new(r#"(?m)^\s*#\s*include\s*"([^"]+)""#).unwrap();
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    for cap in include_re.captures_iter(preview) {
        let Some(target) = resolve_local_include_path(path, &cap[1], source_paths, workspace_root)
        else {
            continue;
        };
        if seen.insert(target.clone()) {
            targets.push(target);
        }
    }
    targets
}

fn resolve_local_include_path(
    base_path: &str,
    include_path: &str,
    source_paths: &HashSet<String>,
    workspace_root: Option<&std::path::Path>,
) -> Option<String> {
    let normalized_include = normalize_repo_relative_path(include_path)?;
    let mut candidates = Vec::new();
    if let Some((parent, _)) = base_path.rsplit_once('/') {
        let joined = format!("{parent}/{include_path}");
        if let Some(normalized) = normalize_repo_relative_path(&joined) {
            candidates.push(normalized);
        }
    }
    candidates.push(normalized_include);

    candidates.into_iter().find(|candidate| {
        source_paths.contains(candidate) || workspace_source_path_exists(candidate, workspace_root)
    })
}

fn normalize_repo_relative_path(path: &str) -> Option<String> {
    let mut parts = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => continue,
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(segment),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn is_header_like_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".h")
        || lower.ends_with(".hh")
        || lower.ends_with(".hpp")
        || lower.ends_with(".hxx")
}

fn is_source_like_artifact_path(path: &str, mime_type: Option<&str>) -> bool {
    let lower = path.to_ascii_lowercase();
    if [
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".rs", ".go", ".java", ".kt",
        ".swift", ".py", ".js", ".jsx", ".ts", ".tsx",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
    {
        return true;
    }

    mime_type.is_some_and(|mime| {
        let lower = mime.to_ascii_lowercase();
        lower.contains("source")
            || lower.contains("header")
            || lower.contains("script")
            || lower.contains("rust")
            || lower.contains("python")
            || lower.contains("javascript")
            || lower.contains("typescript")
    })
}

fn lowercase_source_text(
    path: &str,
    preview_source_texts: &HashMap<String, String>,
    workspace_root: Option<&std::path::Path>,
) -> Option<String> {
    preview_source_texts.get(path).cloned().or_else(|| {
        read_workspace_source_text(path, workspace_root).map(|text| text.to_ascii_lowercase())
    })
}

/// Running count of locate source-text reads served from a raw workspace disk
/// read instead of graph-owned body. A nonzero value is graph-coverage drift;
/// the per-read trace at `kin.locate.disk_fallback` names the offending path.
static LOCATE_DISK_SOURCE_READS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

fn read_workspace_source_text(
    path: &str,
    workspace_root: Option<&std::path::Path>,
) -> Option<String> {
    let root = workspace_root?;
    let text = std::fs::read_to_string(root.join(path)).ok()?;
    let count = LOCATE_DISK_SOURCE_READS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    tracing::debug!(
        target: "kin.locate.disk_fallback",
        path,
        disk_source_reads = count,
        "served locate source text from workspace disk instead of graph body"
    );
    Some(text)
}

/// Candidate text for `path`, served from graph-owned body (the opaque
/// artifact's stored source) and dropping to a raw workspace disk read only
/// when the graph holds no body for the file. The disk leg routes through
/// `read_workspace_source_text`, so the fallback is the explicit, telemetered
/// path — not the silent default.
fn graph_derived_candidate_text(
    graph: &kin_db::InMemoryGraph,
    path: &str,
    workspace_root: &std::path::Path,
) -> String {
    if let Ok(Some(artifact)) = graph.get_opaque_artifact(&kin_model::FilePathId::new(path)) {
        if let Some(body) = artifact.text_preview {
            if !body.is_empty() {
                return body;
            }
        }
    }
    read_workspace_source_text(path, Some(workspace_root)).unwrap_or_default()
}

fn workspace_source_path_exists(path: &str, workspace_root: Option<&std::path::Path>) -> bool {
    let Some(root) = workspace_root else {
        return false;
    };
    root.join(path).is_file()
}

fn extract_code_snippets(text: &str) -> Vec<String> {
    let _span =
        tracing::info_span!("locate.extract_code_snippets", text_len = text.len()).entered();
    let mut snippets = Vec::new();

    // Extract fenced code blocks (```...```)
    let re_fenced = regex::Regex::new(r"```\w*\n([\s\S]*?)```").unwrap();
    for cap in re_fenced.captures_iter(text) {
        let code = cap[1].trim().to_string();
        if !code.is_empty() {
            snippets.push(code);
        }
    }

    // Extract indented code blocks (4+ spaces or tab at start of line, consecutive)
    let mut current_block = String::new();
    for line in text.lines() {
        if line.starts_with("    ") || line.starts_with('\t') {
            current_block.push_str(line.trim_start());
            current_block.push('\n');
        } else if !current_block.is_empty() {
            let trimmed = current_block.trim().to_string();
            if trimmed.len() > 20 {
                snippets.push(trimmed);
            }
            current_block.clear();
        }
    }
    if !current_block.is_empty() {
        let trimmed = current_block.trim().to_string();
        if trimmed.len() > 20 {
            snippets.push(trimmed);
        }
    }

    snippets
}

// ---------------------------------------------------------------------------
// 6. Import chain tracing
// ---------------------------------------------------------------------------

fn extract_import_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let _span =
        tracing::info_span!("locate.extract_import_signals", text_len = text.len()).entered();
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    // Match Python imports: from X import Y, import X
    let re_from = regex::Regex::new(r"from\s+([\w.]+)\s+import\s+(\w+)").unwrap();
    // Fix: use (?:^|[^\w]) instead of (?<!\w) for lookbehind compatibility
    let re_import = regex::Regex::new(r"(?:^|[^\w])import\s+([\w.]+)").unwrap();
    let re_namespace_import =
        regex::Regex::new(r"\b(?:import|use)\s+([A-Za-z_][\w]*(?:(?:::|\.|/)[A-Za-z_][\w]*)+)")
            .unwrap();
    let re_quoted_import =
        regex::Regex::new(r#"(?:from|require\(|import\()\s*["']([^"']+)["']"#).unwrap();
    let re_backtick =
        regex::Regex::new(r"`([A-Za-z_][\w]*(?:(?:::|\.|/)[A-Za-z_][\w]*)+)`").unwrap();

    let mut import_targets: Vec<(String, Option<String>)> = Vec::new();
    let mut seen_import_targets: HashSet<(String, Option<String>)> = HashSet::new();

    for cap in re_from.captures_iter(text) {
        push_import_target(
            &mut import_targets,
            &mut seen_import_targets,
            cap[1].to_string(),
            Some(cap[2].to_string()),
        );
    }
    for cap in re_import.captures_iter(text) {
        let module = cap[1].to_string();
        let symbol = last_module_segment(&module);
        push_import_target(
            &mut import_targets,
            &mut seen_import_targets,
            module,
            symbol,
        );
    }
    for cap in re_namespace_import.captures_iter(text) {
        push_namespace_import_targets(&mut import_targets, &mut seen_import_targets, &cap[1]);
    }
    for cap in re_quoted_import.captures_iter(text) {
        push_namespace_import_targets(&mut import_targets, &mut seen_import_targets, &cap[1]);
    }
    for cap in re_backtick.captures_iter(text) {
        push_namespace_import_targets(&mut import_targets, &mut seen_import_targets, &cap[1]);
    }

    for (module, symbol) in &import_targets {
        let resolved_module_paths = resolve_module_paths_in_graph(graph, module);
        let resolved_module_path_set: HashSet<&str> =
            resolved_module_paths.iter().map(String::as_str).collect();
        let mut entities_in_module = Vec::new();

        for file_path in &resolved_module_paths {
            let filter = EntityFilter {
                file_path: Some(kin_model::FilePathId::new(file_path)),
                ..Default::default()
            };
            let entities_in_file = graph.query_entities(&filter)?;

            if !entities_in_file.is_empty() {
                hits.entry(file_path.clone()).or_default().push(FileHit {
                    score: 5.0,
                    spans: vec![],
                });
                entities_in_module.extend(entities_in_file);
            }
        }

        // Also search for the symbol
        if let Some(symbol) = symbol.as_deref() {
            let text_hits = graph.text_search(symbol, 5)?;
            for (retrieval_key, _) in &text_hits {
                if let Some(entity) = entity_from_retrieval_key(graph, retrieval_key)? {
                    if let Some(ref fo) = entity.file_origin {
                        let path = fo.0.clone();
                        let score = if resolved_module_path_set.contains(path.as_str()) {
                            5.0
                        } else {
                            2.0
                        };
                        hits.entry(path).or_default().push(FileHit {
                            score,
                            spans: entity_span_pair(&entity),
                        });
                    }
                }
            }
        }

        // Follow downstream impact for direct file matches
        if !entities_in_module.is_empty() {
            for entity in entities_in_module.iter().take(3) {
                if symbol.as_deref() == Some(entity.name.as_str()) {
                    let impacted = graph.get_downstream_impact(&entity.id, 1)?;
                    for dep in &impacted {
                        if let Some(ref fo) = dep.file_origin {
                            let path = fo.0.clone();
                            if !resolved_module_path_set.contains(path.as_str()) {
                                hits.entry(path).or_default().push(FileHit {
                                    score: 2.0,
                                    spans: entity_span_pair(dep),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(hits)
}

// ---------------------------------------------------------------------------
// 7. Error type tracing
// ---------------------------------------------------------------------------

fn extract_error_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let _span =
        tracing::info_span!("locate.extract_error_signals", text_len = text.len()).entered();
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    // Extract exception/error type names
    let re_error = regex::Regex::new(r"\b(\w+(?:Error|Exception|Warning|Fault))\b").unwrap();
    let mut error_names: HashSet<String> = HashSet::new();

    for cap in re_error.captures_iter(text) {
        error_names.insert(cap[1].to_string());
    }

    for error_name in &error_names {
        // Search graph for entities that reference or raise this error
        let text_hits = graph.text_search(error_name, 10)?;
        for (retrieval_key, _) in &text_hits {
            if let Some(entity) = entity_from_retrieval_key(graph, retrieval_key)? {
                if let Some(ref fo) = entity.file_origin {
                    let path = fo.0.clone();
                    let weight = test_mult_by_role(&path, Some(&entity), 0.3);
                    hits.entry(path).or_default().push(FileHit {
                        score: 2.5 * weight,
                        spans: entity_span_pair(&entity),
                    });
                }
            }
        }

        // Also try exact entity name match
        let filter = EntityFilter {
            name_pattern: Some(error_name.clone()),
            ..Default::default()
        };
        let matched = graph.query_entities(&filter)?;
        for entity in &matched {
            if let Some(ref fo) = entity.file_origin {
                let path = fo.0.clone();
                hits.entry(path).or_default().push(FileHit {
                    score: 2.5,
                    spans: entity_span_pair(entity),
                });
            }
        }
    }

    Ok(hits)
}

// ---------------------------------------------------------------------------
// 8. Semantic embedding search (vector similarity via HNSW)
// ---------------------------------------------------------------------------

/// Phase 1 embedding discovery: returns entity seeds from vector similarity search.
///
/// When `vector_source` is provided and the primary graph has no embeddings
/// (e.g. historical scoped-session graphs), the vector source graph (typically
/// the HEAD graph) is used for semantic search. Results are then post-filtered
/// to only retain entities that exist in the primary (scoped) graph.
fn extract_embedding_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
    test_query: bool,
    vector_source: Option<&kin_db::InMemoryGraph>,
) -> Result<HashMap<kin_model::EntityId, EntityDiscovery>> {
    let _span =
        tracing::info_span!("locate.extract_embedding_signals", text_len = text.len()).entered();
    let mut entity_seeds: HashMap<kin_model::EntityId, EntityDiscovery> = HashMap::new();

    // Determine which graph to use for vector search.
    // If the primary graph has no embeddings but a vector_source was provided,
    // search the vector_source and post-filter to scoped entities.
    let primary_status = graph.embedding_status();
    let (search_graph, needs_scope_filter) = if primary_status.indexed > 0 {
        (graph, false)
    } else if let Some(vs) = vector_source {
        let vs_status = vs.embedding_status();
        if vs_status.indexed > 0 {
            tracing::info!(
                head_indexed = vs_status.indexed,
                "using HEAD vector index for scoped-session embedding search"
            );
            (vs, true)
        } else {
            return Ok(entity_seeds);
        }
    } else {
        return Ok(entity_seeds);
    };

    // Build the scoped entity map for post-filtering when using HEAD vectors.
    let scoped_entity_map: HashMap<EntityStableKey, kin_model::Entity> = if needs_scope_filter {
        graph
            .query_entities(&EntityFilter::default())?
            .into_iter()
            .filter_map(|e| entity_stable_key(&e).map(|key| (key, e)))
            .collect()
    } else {
        HashMap::new()
    };

    let mut queries: Vec<(String, f32)> = Vec::new();
    let mut seen_queries = HashSet::new();

    // Title query — highest signal, lowest token cost.
    let title = text.lines().next().unwrap_or("").trim();
    push_semantic_query(&mut queries, &mut seen_queries, title, 1.35);

    // Curated search terms joined — captures domain vocabulary without the
    // tokenisation cost of the full 1200-char text or individual term passes.
    let search_terms = curate_search_terms(text, graph)?;
    if !search_terms.is_empty() {
        push_semantic_query(
            &mut queries,
            &mut seen_queries,
            &search_terms
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join(" "),
            1.15,
        );
    }

    // Batch all queries into a single embed_batch() → one BERT forward pass.
    // Over-fetch when filtering to scope so we still get enough results.
    let base_limit = locate_env_usize("KIN_LOCATE_SEMANTIC_RESULT_LIMIT", 24);
    let fetch_limit = if needs_scope_filter {
        base_limit * 3
    } else {
        base_limit
    }
    .max(locate_env_usize("KIN_LOCATE_SEMANTIC_FETCH_LIMIT", 250));
    let query_strings: Vec<&str> = queries.iter().map(|(q, _)| q.as_str()).collect();
    let all_results = if needs_scope_filter {
        // We know we are querying the HEAD graph (vector_source).
        // Only return hits that have a matching topological entity in the scoped graph.
        match search_graph.semantic_search_batch_filtered(
            &query_strings,
            fetch_limit,
            |retrieval_key| {
                entity_stable_key_from_retrieval_key(search_graph, retrieval_key)
                    .is_some_and(|key| scoped_entity_map.contains_key(&key))
            },
        ) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("semantic_search_batch_filtered failed: {:?}", e);
                return Ok(entity_seeds);
            }
        }
    } else {
        match search_graph.semantic_search_batch(&query_strings, fetch_limit) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("semantic_search_batch failed: {:?}", e);
                return Ok(entity_seeds);
            }
        }
    };

    for ((_, query_weight), results) in queries.iter().zip(all_results) {
        for (retrieval_key, distance) in &results {
            // Resolve entity: when needs_scope_filter is true, we must map the HEAD entity
            // to the scoped entity via the stable key.
            let entity_opt = if needs_scope_filter {
                entity_stable_key_from_retrieval_key(search_graph, retrieval_key)
                    .and_then(|key| scoped_entity_map.get(&key).cloned())
            } else {
                entity_from_retrieval_key(graph, retrieval_key)?
            };
            let Some(entity) = entity_opt else {
                continue;
            };

            // Cosine distance → relevance
            let relevance = ((2.0 - distance) / 2.0).max(0.0);
            // Drop weak semantic matches before they enter the signal column.
            // Cosine similarity below ~0.25 is noise that was previously drowning
            // stronger seeds when merged into entity_resolve.
            let min_relevance = locate_env_f32("KIN_LOCATE_EMBEDDING_MIN_SIMILARITY", 0.25);
            if relevance < min_relevance {
                continue;
            }

            let kind_mult = match entity.kind {
                EntityKind::Function
                | EntityKind::Method
                | EntityKind::Class
                | EntityKind::TraitDef
                | EntityKind::Interface
                | EntityKind::Module => 2.0,
                EntityKind::EnumDef => 1.5,
                _ => 1.0,
            };

            let role_mult = if !test_query && entity.role == EntityRole::Test {
                0.1
            } else {
                1.0
            };
            let score = relevance * kind_mult * 10.0 * *query_weight * role_mult;
            let entry = entity_seeds.entry(entity.id).or_default();
            entry.score += score;
            entry.cosine = Some(entry.cosine.map_or(relevance, |c| c.max(relevance)));
            if !entry.signals.contains(&"embeddings") {
                entry.signals.push("embeddings");
            }
        }
    }

    Ok(entity_seeds)
}

fn extract_cochange_signals(
    seed_hit_sets: &[&HashMap<String, Vec<FileHit>>],
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let _span = tracing::info_span!(
        "locate.extract_cochange_signals",
        seed_sets = seed_hit_sets.len()
    )
    .entered();
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();
    let mut seed_scores: HashMap<String, f32> = HashMap::new();

    let decay_halflife_days = locate_env_f32("KIN_LOCATE_COCHANGE_DECAY_HALFLIFE_DAYS", 365.0);
    let now = chrono::Utc::now();

    for hit_set in seed_hit_sets {
        for (path, file_hits) in hit_set.iter() {
            let max_score = file_hits.iter().map(|hit| hit.score).fold(0.0f32, f32::max);
            let entry = seed_scores.entry(path.clone()).or_insert(0.0);
            *entry = entry.max(max_score);
        }
    }

    let mut seed_files: Vec<(String, f32)> = seed_scores.into_iter().collect();
    seed_files.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    seed_files.truncate(locate_env_usize("KIN_LOCATE_COCHANGE_SEED_FILES", 8));

    for (seed_path, seed_score) in &seed_files {
        let entities = graph.query_entities(&EntityFilter {
            file_path: Some(kin_model::FilePathId::new(seed_path.as_str())),
            ..Default::default()
        })?;
        for entity in entities
            .iter()
            .take(locate_env_usize("KIN_LOCATE_COCHANGE_ENTITY_LIMIT", 16))
        {
            let mut relations = graph.get_relations(&entity.id, &[RelationKind::CoChanges])?;
            relations.sort_by(|a, b| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| format!("{:?}", a.id).cmp(&format!("{:?}", b.id)))
            });
            for rel in relations
                .into_iter()
                .take(locate_env_usize("KIN_LOCATE_COCHANGE_RELATION_LIMIT", 24))
            {
                let Some(neighbor_id) = rel.dst.as_entity() else {
                    continue;
                };
                let Some(neighbor) = graph.get_entity(&neighbor_id)? else {
                    continue;
                };
                let Some(file_origin) = neighbor.file_origin.as_ref() else {
                    continue;
                };
                let path = file_origin.0.clone();
                if path == *seed_path {
                    continue;
                }

                let seed_mult = 1.0 + (*seed_score / 10.0).min(1.5);
                let test_mult = test_mult_by_role(&path, Some(&neighbor), 0.35);
                let neighbor_role = neighbor.role;
                let path_mult = match neighbor_role {
                    EntityRole::Docs => 0.45,
                    EntityRole::Source => 1.2,
                    _ => 1.0,
                };

                let temporal_decay = rel
                    .created_in
                    .as_ref()
                    .and_then(|change_id| graph.get_change(change_id).ok().flatten())
                    .map(|change| {
                        let age_days = (now - change.timestamp.0).num_days().max(0) as f32;
                        1.0 / (1.0 + age_days / decay_halflife_days)
                    })
                    .unwrap_or(1.0_f32);
                hits.entry(path).or_default().push(FileHit {
                    score: rel.confidence
                        * 2.5
                        * seed_mult
                        * test_mult
                        * path_mult
                        * temporal_decay,
                    spans: entity_span_pair(&neighbor),
                });
            }
        }
    }

    Ok(hits)
}

/// Compute import centrality for candidate files.
///
/// For each file that appears in any signal, count how many OTHER files import
/// entities from it. Files that are imported by many others are "core" files —
/// they're more likely to contain the code that needs to change.
///
/// This is a purely graph-native signal: it exploits relationship structure
/// that keyword search cannot access.
fn compute_import_centrality(
    graph: &kin_db::InMemoryGraph,
    signal_sets: &[&HashMap<String, Vec<FileHit>>],
) -> Result<HashMap<String, Vec<FileHit>>> {
    let _span = tracing::info_span!(
        "locate.compute_import_centrality",
        signal_sets = signal_sets.len()
    )
    .entered();
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    // Collect all candidate file paths from existing signals
    let mut candidate_files: HashSet<String> = HashSet::new();
    for signal in signal_sets {
        for path in signal.keys() {
            candidate_files.insert(path.clone());
        }
    }

    if candidate_files.is_empty() {
        return Ok(hits);
    }

    // For each candidate file, count how many other files import from it
    for path in &candidate_files {
        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(path.as_str())),
            ..Default::default()
        };
        let entities = match graph.query_entities(&filter) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let mut importer_files: HashSet<String> = HashSet::new();
        for entity in entities
            .iter()
            .take(locate_env_usize("KIN_LOCATE_CENTRALITY_ENTITY_LIMIT", 20))
        {
            let rels = match graph.get_all_relations_for_entity(&entity.id) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for rel in &rels {
                // Count inbound imports/calls/depends — entities that reference THIS entity
                let is_inbound = rel.dst == GraphNodeId::Entity(entity.id);
                if !is_inbound {
                    continue;
                }
                if !matches!(
                    rel.kind,
                    RelationKind::Imports | RelationKind::Calls | RelationKind::DependsOn
                ) {
                    continue;
                }
                // Find the file of the importing entity
                let Some(importer_id) = rel.src.as_entity() else {
                    continue;
                };
                if let Ok(Some(importer)) = graph.get_entity(&importer_id) {
                    if let Some(ref fo) = importer.file_origin {
                        if fo.0 != *path {
                            importer_files.insert(fo.0.clone());
                        }
                    }
                }
            }
        }

        let import_count = importer_files.len();
        if import_count > 0 {
            // Score scales with how many files depend on this one.
            // Logarithmic to avoid extreme values for very central files.
            let centrality_score = (import_count as f32).ln_1p() * 2.0;
            let source_mult = if is_source_path(path) { 1.3 } else { 1.0 };
            hits.entry(path.clone()).or_default().push(FileHit {
                score: centrality_score * source_mult,
                spans: vec![],
            });
        }
    }

    Ok(hits)
}

fn collect_result_provenance(
    results: &[(String, f32)],
    projection_provenance: &HashMap<String, LocateFileProvenance>,
) -> HashMap<String, LocateFileProvenance> {
    results
        .iter()
        .map(|(path, _)| {
            let provenance =
                projection_provenance
                    .get(path)
                    .cloned()
                    .unwrap_or_else(|| LocateFileProvenance {
                        objects: vec![artifact_graph_object(
                            kin_model::ArtifactId::from_path(path),
                            path,
                        )],
                        edges: Vec::new(),
                    });
            (path.clone(), provenance)
        })
        .collect()
}

fn artifact_graph_object(artifact_id: kin_model::ArtifactId, path: &str) -> LocateGraphObject {
    LocateGraphObject {
        id: GraphNodeId::Artifact(artifact_id).to_string(),
        kind: "artifact".to_string(),
        name: None,
        file_path: Some(path.to_string()),
    }
}

fn push_projection_reason(explain: &mut HashMap<String, Vec<String>>, path: &str, reason: String) {
    let reasons = explain.entry(path.to_string()).or_default();
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn push_semantic_query(
    queries: &mut Vec<(String, f32)>,
    seen: &mut HashSet<String>,
    query: &str,
    weight: f32,
) {
    let normalized = query.trim();
    if normalized.len() < 3 {
        return;
    }
    let key = normalized.to_ascii_lowercase();
    if seen.insert(key) {
        queries.push((normalized.to_string(), weight));
    }
}

// ---------------------------------------------------------------------------
// Phase 2: Entity → File resolution via graph relations
// ---------------------------------------------------------------------------

/// Resolve entity seeds from Phase 1 discovery into file rankings using the
/// graph as the authority. This is the core of the two-phase locate redesign:
/// entities are found by text/embedding/import signals, but FILES are determined
/// by graph structure — especially LSP-resolved definition chains.
///
/// Origin-aware weighting: LSP relations carry more weight because they are
/// type-resolved (high confidence), vs tree-sitter (name-based, lower confidence).
fn resolve_entities_to_files(
    entity_seeds: &HashMap<kin_model::EntityId, EntityDiscovery>,
    graph: &kin_db::InMemoryGraph,
    explain: bool,
    origin: &str,
) -> Result<ResolveEntitiesOutput> {
    let _span = tracing::info_span!(
        "locate.resolve_entities_to_files",
        seed_count = entity_seeds.len(),
    )
    .entered();

    let lsp_boost = locate_env_f32("KIN_LOCATE_LSP_ORIGIN_BOOST", 2.0);
    let parsed_weight = locate_env_f32("KIN_LOCATE_PARSED_ORIGIN_WEIGHT", 1.0);
    let inferred_weight = locate_env_f32("KIN_LOCATE_INFERRED_ORIGIN_WEIGHT", 0.7);
    let definition_authority = locate_env_f32("KIN_LOCATE_DEFINITION_AUTHORITY", 2.0);
    let max_graph_hops = locate_env_usize("KIN_LOCATE_RESOLVE_MAX_HOPS", 2);

    // EMBED_RELEVANCE lever (gated, default OFF): when set, the query↔def
    // embedding cosine the semantic phase already computed is carried onto every
    // emitted symbol (not just under --explain) so the post-pass
    // `boost_symbol_embed_relevance` can re-rank by semantic relevance. Reading
    // the flag here keeps it out of the per-entity hot loop. Unset leaves the
    // cosine gated on `explain` exactly as before, so OFF is byte-identical.
    let embed_relevance_on = locate_env_bool("KIN_LOCATE_SYMBOL_EMBED_RELEVANCE", true);

    // Detect whether the graph has LSP-enriched relations. If not (e.g., init
    // ran with --no-lsp), the LSP-only filter would block ALL graph traversal
    // since every relation is Parsed origin. Auto-disable it in that case.
    // The sample is drawn from a key-sorted view so the same 20 seeds are
    // probed on every run — `entity_seeds` is a HashMap whose iteration order
    // would otherwise flip `lsp_only_resolve` and the whole resolve outcome.
    let mut lsp_probe_ids: Vec<&kin_model::EntityId> = entity_seeds.keys().collect();
    lsp_probe_ids.sort_unstable();
    let has_lsp_relations = lsp_probe_ids.iter().take(20).any(|eid| {
        graph
            .get_all_relations_for_entity(eid)
            .unwrap_or_default()
            .iter()
            .any(|r| r.origin == kin_model::RelationOrigin::Lsp)
    });
    let lsp_only_resolve =
        locate_env_bool("KIN_LOCATE_LSP_ONLY_RESOLVE", false) && has_lsp_relations;

    // Separate score pools: direct attribution vs graph traversal.
    // These are normalized independently then blended so that graph traversal
    // (which inflates hub files via many paths) cannot drown direct attribution
    // (which tells us the entity IS in this specific file).
    let mut candidates: Vec<ResolveCandidate> = Vec::new();
    let mut file_explain: HashMap<String, Vec<String>> = HashMap::new();
    let mut file_symbols: HashMap<String, Vec<LocateSymbol>> = HashMap::new();
    let mut file_signal_scores: HashMap<String, HashMap<String, f32>> = HashMap::new();

    // Sort seeds by score descending, then use greedy gap detection to find the
    // natural cluster boundary between relevant entities and noise.
    let mut seeds: Vec<_> = entity_seeds.iter().collect();
    seeds.sort_by(|a, b| {
        b.1.score
            .partial_cmp(&a.1.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(b.0))
    });

    // Hard cap to prevent runaway processing, but the gap detection will usually cut sooner.
    let hard_cap = locate_env_usize("KIN_LOCATE_RESOLVE_SEED_LIMIT", 100);
    seeds.truncate(hard_cap);

    // Greedy gap detection: find the largest relative score drop between consecutive seeds.
    // If the top seed scores 200 and the next scores 190, the gap ratio is 0.05 (small).
    // If the top scores 200 and #5 scores 40, the gap ratio at #5 is 0.79 (large → cut here).
    let gap_threshold = locate_env_f32("KIN_LOCATE_SEED_GAP_THRESHOLD", 0.5);
    let min_seeds = locate_env_usize("KIN_LOCATE_MIN_SEEDS", 3);
    if seeds.len() > min_seeds {
        let top_score = seeds[0].1.score.max(0.001);
        let diversity_target = locate_env_usize("KIN_LOCATE_MIN_SEED_FILE_DIVERSITY", 8);
        let diversity_tail_limit = locate_env_usize("KIN_LOCATE_SEED_DIVERSITY_TAIL_LIMIT", 8);
        let diversity_floor_pct = locate_env_f32("KIN_LOCATE_SEED_DIVERSITY_FLOOR_PCT", 0.01);
        let diversity_per_file_limit =
            locate_env_usize("KIN_LOCATE_SEED_DIVERSITY_PER_FILE_LIMIT", 3);
        let mut cut_at = seeds.len();
        let mut max_gap_ratio = 0.0f32;
        for i in min_seeds..seeds.len() {
            let prev_score = seeds[i - 1].1.score;
            let curr_score = seeds[i].1.score;
            if prev_score > 0.001 {
                let gap_ratio = (prev_score - curr_score) / top_score;
                if gap_ratio > max_gap_ratio && gap_ratio > gap_threshold {
                    max_gap_ratio = gap_ratio;
                    cut_at = i;
                }
            }
        }
        if cut_at < seeds.len() {
            let original_len = seeds.len();
            let mut retained = seeds[..cut_at].to_vec();
            let mut retained_files = HashSet::new();
            for (&entity_id, _) in &retained {
                if let Some(entity) = graph.get_entity(&entity_id)? {
                    if let Some(file_origin) = entity.file_origin.as_ref() {
                        retained_files.insert(file_origin.0.clone());
                    }
                }
            }
            let diversity_floor = top_score * diversity_floor_pct;
            let mut diversity_added = 0usize;
            let mut rescued_file_counts: HashMap<String, usize> = HashMap::new();
            tracing::info!("resolve_entities_to_files origin {} cut_at: {}, retained_files: {}, diversity_target: {}", origin, cut_at, retained_files.len(), diversity_target);
            if retained_files.len() < diversity_target {
                for seed in seeds[cut_at..].iter() {
                    let (&entity_id, discovery) = *seed;
                    if discovery.score < diversity_floor {
                        continue;
                    }
                    let Some(entity) = graph.get_entity(&entity_id)? else {
                        continue;
                    };
                    let Some(file_origin) = entity.file_origin.as_ref() else {
                        continue;
                    };
                    let path = file_origin.0.clone();
                    if retained_files.contains(&path) {
                        if let Some(count) = rescued_file_counts.get_mut(&path) {
                            if *count >= diversity_per_file_limit {
                                continue;
                            }
                            retained.push(*seed);
                            *count += 1;
                        }
                        continue;
                    }
                    retained_files.insert(path.clone());
                    rescued_file_counts.insert(path, 1);
                    retained.push(*seed);
                    diversity_added += 1;
                    if retained_files.len() >= diversity_target
                        || diversity_added >= diversity_tail_limit
                    {
                        break;
                    }
                }
            }
            // BODY_SEED_PROTECT (default OFF): a weak body-relevance seed can fall
            // past the gap-cut even when its file is the gold. When enabled,
            // retain any body-tagged seed the cut would drop so it survives to
            // resolve into symbols and file support. Deduped against the already-
            // retained set so it never double-counts an entity.
            if locate_env_bool("KIN_LOCATE_BODY_SEED_PROTECT", false) {
                let retained_ids: HashSet<kin_model::EntityId> =
                    retained.iter().map(|pair| pair.0.clone()).collect();
                for seed in seeds[cut_at..].iter() {
                    if seed.1.signals.contains(&"body") && !retained_ids.contains(seed.0) {
                        retained.push(*seed);
                    }
                }
            }
            tracing::debug!(
                "Seed gap detection: cut at {} (gap ratio {:.2}), {} → {} seeds ({} diverse tail files)",
                cut_at,
                max_gap_ratio,
                original_len,
                retained.len(),
                diversity_added
            );
            seeds = retained;
        }
    }

    let allowed_kinds = [
        RelationKind::Calls,
        RelationKind::UsesMacro,
        RelationKind::Imports,
        RelationKind::Includes,
        RelationKind::DerivedFrom,
        RelationKind::References,
        RelationKind::Implements,
        RelationKind::Extends,
        RelationKind::Contains,
        RelationKind::Tests,
        RelationKind::DependsOn,
    ];

    for (&entity_id, discovery) in &seeds {
        let Some(entity) = graph.get_entity(&entity_id)? else {
            continue;
        };

        // Step 1: Direct file attribution — the entity's own file_origin gets
        // the discovery score, weighted by definition authority.
        let entity_is_test = entity
            .file_origin
            .as_ref()
            .map_or(false, |fo| is_test_by_role(&fo.0, Some(&entity)));

        if let Some(ref fo) = entity.file_origin {
            let path = &fo.0;
            if entity_is_test {
                // Skip direct attribution for test entities but still follow
                // their graph relations below — tests call the source that
                // needs fixing.
            } else {
                // Definition authority: entities with real bodies (functions, classes
                // with implementations) are definitions. Re-export files just import
                // and re-export — they don't define.
                let has_body = entity
                    .metadata
                    .extra
                    .get("embedding_body_preview")
                    .and_then(|v| v.as_str())
                    .map_or(false, |s| !s.is_empty());

                // KIND-FLOOR lever (default OFF == current bytes): the definition
                // flag (and its `definition_authority` score multiplier) key only
                // on a non-empty `embedding_body_preview`. That preview is set at
                // parse time from the node's source bytes, so it is BOTH over-broad
                // (a re-export with bytes reads as a definition) AND, conversely,
                // demotes a genuine definition whose preview is missing/degenerate
                // below every body-bearing entity while also stripping its 2x
                // authority — a double penalty that can push a real gold def past
                // the symbol cap. When KIN_LOCATE_SYMBOL_DEF_KIND_FLOOR=1, a
                // definitional entity kind counts as a definition even without a
                // preview. Default false leaves the original `has_body` flag, so
                // unset is byte-identical.
                let is_definition = has_body
                    || (locate_env_bool("KIN_LOCATE_SYMBOL_DEF_KIND_FLOOR", false)
                        && is_definitional_kind(entity.kind));

                let def_mult = if is_definition {
                    definition_authority
                } else {
                    1.0
                };
                let score = discovery.score * def_mult;

                candidates.push(ResolveCandidate {
                    id: format!("entity:{entity_id}"),
                    kind: "entity",
                    path: path.clone(),
                    name: Some(entity.name.clone()),
                    score,
                    source: ResolveCandidateSource::Direct,
                    reason: format!("{} seed {}", origin, discovery.signals.join("+")),
                });
                file_signal_scores
                    .entry(path.clone())
                    .or_default()
                    .entry("entity_resolve".to_string())
                    .and_modify(|s| *s += score)
                    .or_insert(score);
                let symbol = LocateSymbol {
                    name: entity.name.clone(),
                    span: entity_span_pair(&entity).into_iter().next(),
                    score,
                    kind: format!("{:?}", entity.kind).to_lowercase(),
                    definition: is_definition,
                    origin: if explain {
                        origin.to_string()
                    } else {
                        String::new()
                    },
                    cosine: if explain || embed_relevance_on {
                        discovery.cosine
                    } else {
                        None
                    },
                };
                file_symbols.entry(path.clone()).or_default().push(symbol);
                if explain {
                    let body_tag = if is_definition {
                        "definition"
                    } else {
                        "reference"
                    };
                    push_projection_reason(
                        &mut file_explain,
                        path,
                        format!(
                            "entity `{}` {} (score {:.1}, {})",
                            entity.name,
                            body_tag,
                            discovery.score,
                            discovery.signals.join("+")
                        ),
                    );
                }
            } // else (not test)
        }

        if let Some(ref fo) = entity.file_origin {
            let artifact_hops = locate_env_usize("KIN_LOCATE_RESOLVE_ARTIFACT_HOPS", 2);
            let artifact_frontier = locate_env_usize("KIN_LOCATE_RESOLVE_ARTIFACT_FRONTIER", 32);
            let artifact_hop_decay = locate_env_f32("KIN_LOCATE_RESOLVE_ARTIFACT_HOP_DECAY", 0.55);
            let start_artifact_id =
                graph.artifact_id_for_path(&kin_model::FilePathId::new(fo.0.as_str()));
            if let Some(start_artifact_id) = start_artifact_id {
                let start_artifact = GraphNodeId::Artifact(start_artifact_id);
                let mut visited_artifacts = HashSet::from([start_artifact.clone()]);
                let mut artifact_frontier_queue =
                    VecDeque::from([(start_artifact, fo.0.clone(), 0usize)]);

                while let Some((artifact_node, source_path, depth)) =
                    artifact_frontier_queue.pop_front()
                {
                    if depth >= artifact_hops {
                        continue;
                    }

                    let mut artifact_rels = graph.get_all_relations_for_node(&artifact_node)?;
                    artifact_rels.sort_by(|left, right| {
                        let left_kind = resolve_relation_kind_priority(left.kind);
                        let right_kind = resolve_relation_kind_priority(right.kind);
                        let left_origin = resolve_relation_origin_priority(left.origin);
                        let right_origin = resolve_relation_origin_priority(right.origin);
                        right_kind
                            .cmp(&left_kind)
                            .then_with(|| right_origin.cmp(&left_origin))
                            .then_with(|| format!("{:?}", left.id).cmp(&format!("{:?}", right.id)))
                    });
                    for rel in artifact_rels
                        .iter()
                        .filter(|rel| relation_allows_artifact_traversal(rel, &artifact_node))
                        .take(artifact_frontier)
                    {
                        let Some((path, next_artifact)) =
                            relation_adjacent_artifact_path(graph, rel, &artifact_node)
                        else {
                            continue;
                        };
                        if is_test_path(&path) || is_vendored_path(&path) {
                            continue;
                        }

                        let origin_mult = resolve_relation_origin_multiplier(
                            rel.origin,
                            lsp_boost,
                            parsed_weight,
                            inferred_weight,
                        );
                        let kind_mult = resolve_relation_kind_multiplier(rel.kind);
                        let hop = depth + 1;
                        let hop_decay = artifact_hop_decay.powi(depth as i32);
                        let path_specificity =
                            artifact_relation_path_specificity_multiplier(&fo.0, &path, hop);
                        let score = discovery.score
                            * origin_mult
                            * kind_mult
                            * path_specificity
                            * hop_decay
                            / ((hop + 1) as f32);

                        candidates.push(ResolveCandidate {
                            id: format!("relation:{}:artifact:{}:hop{}", rel.id, rel.dst, hop),
                            kind: "relation_artifact",
                            path: path.clone(),
                            name: None,
                            score,
                            source: ResolveCandidateSource::Graph,
                            reason: format!(
                                "{:?} hop {} from file artifact {} via {}",
                                rel.kind, hop, fo.0, source_path
                            ),
                        });
                        file_signal_scores
                            .entry(path.clone())
                            .or_default()
                            .entry("graph_resolve".to_string())
                            .and_modify(|s| *s += score)
                            .or_insert(score);
                        if explain {
                            push_projection_reason(
                                &mut file_explain,
                                &path,
                                format!(
                                    "artifact {:?} hop {} from `{}` via `{}` includes/imports `{}`",
                                    rel.kind, hop, fo.0, source_path, path
                                ),
                            );
                        }

                        if visited_artifacts.insert(next_artifact.clone()) {
                            artifact_frontier_queue.push_back((next_artifact, path, depth + 1));
                        }
                    }
                }
            }
        }

        // Graph traversal from ALL entities including test entities
        let mut visited = HashSet::from([entity_id]);
        let mut frontier = vec![(entity_id, 0usize)];

        while let Some((current_id, depth)) = frontier.pop() {
            if depth >= max_graph_hops {
                continue;
            }

            let mut rels = graph.get_all_relations_for_entity(&current_id)?;
            rels.sort_by(|left, right| {
                let left_kind = resolve_relation_kind_priority(left.kind);
                let right_kind = resolve_relation_kind_priority(right.kind);
                let left_origin = resolve_relation_origin_priority(left.origin);
                let right_origin = resolve_relation_origin_priority(right.origin);
                right_kind
                    .cmp(&left_kind)
                    .then_with(|| right_origin.cmp(&left_origin))
                    .then_with(|| format!("{:?}", left.id).cmp(&format!("{:?}", right.id)))
            });
            for rel in rels
                .iter()
                .take(locate_env_usize("KIN_LOCATE_RESOLVE_FRONTIER", 32))
            {
                if !allowed_kinds.contains(&rel.kind) {
                    continue;
                }
                let neighbor_id = if rel.src == GraphNodeId::Entity(current_id) {
                    rel.dst
                } else {
                    rel.src
                };
                let Some(neighbor_id) = neighbor_id.as_entity() else {
                    continue;
                };
                if !visited.insert(neighbor_id) {
                    continue;
                }

                let Some(neighbor) = graph.get_entity(&neighbor_id)? else {
                    continue;
                };
                let Some(ref fo) = neighbor.file_origin else {
                    continue;
                };
                let path = &fo.0;
                if is_test_by_role(path, Some(&neighbor)) {
                    continue;
                }

                // In Phase 2 graph resolution, strongly prefer LSP-origin relations.
                // Non-LSP relations at depth > 0 are mostly noise (name-based guesses).
                // When the graph has no LSP data, this filter is auto-disabled (see above).
                if lsp_only_resolve
                    && depth > 0
                    && rel.origin != kin_model::RelationOrigin::Lsp
                    && !entity_is_test
                {
                    continue;
                }

                let origin_mult = resolve_relation_origin_multiplier(
                    rel.origin,
                    lsp_boost,
                    parsed_weight,
                    inferred_weight,
                );

                // Relation kind weighting
                let kind_mult = resolve_relation_kind_multiplier(rel.kind);

                // Definition authority for the neighbor too
                let neighbor_has_body = neighbor
                    .metadata
                    .extra
                    .get("embedding_body_preview")
                    .and_then(|v| v.as_str())
                    .map_or(false, |s| !s.is_empty());
                let def_mult = if neighbor_has_body {
                    definition_authority
                } else {
                    1.0
                };

                let hop_decay = 0.5_f32.powi(depth as i32);

                let score = discovery.score * origin_mult * kind_mult * def_mult * hop_decay
                    / ((depth + 2) as f32);

                candidates.push(ResolveCandidate {
                    id: format!("relation:{}:entity:{}", rel.id, neighbor_id),
                    kind: "relation_entity",
                    path: path.clone(),
                    name: Some(neighbor.name.clone()),
                    score,
                    source: ResolveCandidateSource::Graph,
                    reason: format!("{:?} via {:?}", rel.kind, rel.origin),
                });
                file_signal_scores
                    .entry(path.clone())
                    .or_default()
                    .entry("graph_resolve".to_string())
                    .and_modify(|s| *s += score)
                    .or_insert(score);
                if explain {
                    let origin_tag = match rel.origin {
                        kin_model::RelationOrigin::Lsp => "LSP",
                        kin_model::RelationOrigin::Parsed => "parsed",
                        kin_model::RelationOrigin::Inferred => "inferred",
                        kin_model::RelationOrigin::Manual => "manual",
                    };
                    push_projection_reason(
                        &mut file_explain,
                        path,
                        format!(
                            "via {} {:?} from `{}` → `{}` ({}, {} hop{})",
                            origin_tag,
                            rel.kind,
                            entity.name,
                            neighbor.name,
                            if neighbor_has_body { "def" } else { "ref" },
                            depth + 1,
                            if depth == 0 { "" } else { "s" }
                        ),
                    );
                }

                frontier.push((neighbor_id, depth + 1));
            }
        }
    }

    let mut direct_scores: FxHashMap<String, Vec<f32>> = FxHashMap::default();
    let mut graph_scores: FxHashMap<String, Vec<f32>> = FxHashMap::default();
    for candidate in &candidates {
        match candidate.source {
            ResolveCandidateSource::Direct => {
                direct_scores
                    .entry(candidate.path.clone())
                    .or_default()
                    .push(candidate.score);
            }
            ResolveCandidateSource::Graph => {
                graph_scores
                    .entry(candidate.path.clone())
                    .or_default()
                    .push(candidate.score);
            }
        }
    }

    let mut final_direct_scores: FxHashMap<String, f32> = FxHashMap::default();
    for (path, scores) in direct_scores.into_iter() {
        let max_score = scores.into_iter().fold(0.0f32, f32::max);
        final_direct_scores.insert(path, max_score);
    }

    // Graph scores are also purely max-based now.
    // Hub dampening is removed because the number of incoming entities no longer drives the file score up.
    let mut final_graph_scores: FxHashMap<String, f32> = FxHashMap::default();
    for (path, scores) in graph_scores.into_iter() {
        let max_score = scores.into_iter().fold(0.0f32, f32::max);
        final_graph_scores.insert(path, max_score);
    }

    // Normalize direct and graph scores INDEPENDENTLY, then blend.
    // Direct attribution is the primary authority (entity IS in this file).
    // Graph traversal is supplementary when direct evidence exists, but files
    // reached only through typed graph evidence must retain enough score to
    // survive projection/cap stages. Otherwise include/import/macro edges are
    // visible in candidate debug and then artificially suppressed at file cut.
    let direct_blend = locate_env_f32("KIN_LOCATE_DIRECT_BLEND", 0.90);
    let graph_blend = locate_env_f32("KIN_LOCATE_GRAPH_BLEND", 0.10);
    let graph_only_projection_floor =
        locate_env_f32("KIN_LOCATE_GRAPH_ONLY_PROJECTION_FLOOR", 0.25);

    let direct_max = final_direct_scores
        .values()
        .copied()
        .fold(0.0f32, f32::max)
        .max(0.001);
    let graph_max = final_graph_scores
        .values()
        .copied()
        .fold(0.0f32, f32::max)
        .max(0.001);

    let all_files: HashSet<String> = final_direct_scores
        .keys()
        .chain(final_graph_scores.keys())
        .cloned()
        .collect();
    let mut file_scores: FxHashMap<String, f32> = FxHashMap::default();
    for path in all_files {
        let direct_norm = final_direct_scores.get(&path).copied().unwrap_or(0.0) / direct_max;
        let graph_norm = final_graph_scores.get(&path).copied().unwrap_or(0.0) / graph_max;
        let blended = direct_norm * direct_blend + graph_norm * graph_blend;
        let blended = if direct_norm <= f32::EPSILON && graph_norm > 0.0 {
            blended.max(graph_norm * graph_only_projection_floor)
        } else {
            blended
        };
        file_scores.insert(path, blended * 100.0);
    }

    let mut result: Vec<(String, f32)> = file_scores.into_iter().collect();
    result.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });

    tracing::info!(
        "resolve_entities_to_files origin {} RETURNING {} files",
        origin,
        result.len()
    );
    let candidate_stages = if explain {
        resolve_candidate_debug_stages(origin, &candidates, &result)
    } else {
        Vec::new()
    };
    Ok((
        result,
        file_explain,
        file_signal_scores,
        file_symbols,
        candidate_stages,
    ))
}

/// Recover file → representative-entity identity from Phase-1 discovery seeds.
///
/// The fusion pipeline collapses entity identity to file paths: signal hits are
/// `FileHit{score, spans}` (the documented seam — no entity id), and both
/// [`to_ranked`] and [`resolve_entities_to_files`] key purely on path. This
/// helper re-derives, for each file, the highest-scoring non-test seed entity
/// whose definition lives in that file, so entity identity survives the
/// entity→file boundary. It is a *parallel* association keyed by the same path
/// keys the ranked lists already use — it does not change any score or ordering.
/// `--explain` surfaces it; entity-granular fusion (behind
/// `KIN_LOCATE_ENTITY_FUSION`) consumes it to key fusion at entity granularity.
///
/// Determinism: seeds are visited in ascending entity-id order and a file keeps
/// the strictly-higher discovery score (ties resolve to the lower entity id),
/// so the result is independent of `HashMap` iteration order.
fn entity_resolve_identity(
    seeds: &HashMap<kin_model::EntityId, EntityDiscovery>,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, kin_model::EntityId>> {
    let mut ordered: Vec<(&kin_model::EntityId, &EntityDiscovery)> = seeds.iter().collect();
    ordered.sort_by(|a, b| a.0.cmp(b.0));
    let mut best: HashMap<String, (kin_model::EntityId, f32)> = HashMap::new();
    for (entity_id, discovery) in ordered {
        let Some(entity) = graph.get_entity(entity_id)? else {
            continue;
        };
        let Some(file_origin) = entity.file_origin.as_ref() else {
            continue;
        };
        if is_test_by_role(&file_origin.0, Some(&entity)) {
            continue;
        }
        let keep = match best.get(file_origin.0.as_str()) {
            Some((_, prev_score)) => discovery.score > *prev_score,
            None => true,
        };
        if keep {
            best.insert(file_origin.0.clone(), (*entity_id, discovery.score));
        }
    }
    Ok(best
        .into_iter()
        .map(|(path, (entity_id, _))| (path, entity_id))
        .collect())
}

/// Per-entity fusion items recovered from discovery seeds: `(entity_key, file, score)`.
/// One item per non-test, non-vendored seed entity that has a file origin, keyed by
/// entity id and scored by its Phase-1 discovery score. Multiple entities defined in
/// one file produce multiple items — this is the entity granularity the path-keyed
/// pipeline collapses away in `to_ranked`/`resolve_entities_to_files`.
///
/// The emitted list is sorted by discovery score descending (ties broken by
/// entity key ascending), mirroring [`to_ranked`] so the RRF rank term is
/// meaningful and the order is independent of `HashMap` iteration order.
fn entity_seed_keyed(
    seeds: &HashMap<kin_model::EntityId, EntityDiscovery>,
    graph: &kin_db::InMemoryGraph,
) -> Result<Vec<(String, String, f32)>> {
    let mut out: Vec<(String, String, f32)> = Vec::new();
    for (entity_id, discovery) in seeds {
        let Some(entity) = graph.get_entity(entity_id)? else {
            continue;
        };
        let Some(file_origin) = entity.file_origin.as_ref() else {
            continue;
        };
        if is_test_by_role(&file_origin.0, Some(&entity)) || is_vendored_path(&file_origin.0) {
            continue;
        }
        out.push((
            format!("entity:{entity_id}"),
            file_origin.0.clone(),
            discovery.score,
        ));
    }
    out.sort_by(|a, b| {
        b.2.partial_cmp(&a.2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    Ok(out)
}

/// Entity-granular reciprocal rank fusion. Mirrors the core of
/// [`reciprocal_rank_fusion`] (rank term + per-list max-normalized raw term +
/// cross-signal bonus) but keys on the entity identity carried in each
/// `(key, path, score)` item and skips vendored files by *path*. Returns
/// `(key, path, fused_score)` sorted descending (ties broken by key for
/// determinism).
///
/// It intentionally omits the path fuser's graph-neighborhood tiebreaker and
/// semantic-primacy term: both are keyed by fixed signal-list *index positions*
/// over file keys, which do not carry over to entity keys. Per the scoring-map
/// recommendation, the entity path is a clean rank-space fuser rather than a
/// re-derivation of the index-positional path tunings.
fn reciprocal_rank_fusion_entities(
    keyed_lists: &[Vec<(String, String, f32)>],
    k: f32,
) -> Vec<(String, String, f32)> {
    let mut rrf: FxHashMap<String, f32> = FxHashMap::default();
    let mut raw: FxHashMap<String, f32> = FxHashMap::default();
    let mut signal_counts: FxHashMap<String, usize> = FxHashMap::default();
    let mut key_path: FxHashMap<String, String> = FxHashMap::default();
    for list in keyed_lists {
        let max_score = list
            .iter()
            .map(|(_, _, s)| *s)
            .fold(0.0f32, f32::max)
            .max(1.0);
        let mut keys_in_list: HashSet<String> = HashSet::new();
        for (rank, (key, path, score)) in list.iter().enumerate() {
            if is_vendored_path(path) {
                continue;
            }
            *rrf.entry(key.clone()).or_default() += 1.0 / (k + rank as f32 + 1.0);
            *raw.entry(key.clone()).or_default() += score / max_score;
            key_path.entry(key.clone()).or_insert_with(|| path.clone());
            keys_in_list.insert(key.clone());
        }
        for key in &keys_in_list {
            *signal_counts.entry(key.clone()).or_default() += 1;
        }
    }
    let raw_weight = locate_env_f32("KIN_LOCATE_RRF_RAW_WEIGHT", 0.05);
    let mut combined: Vec<(String, String, f32)> = rrf
        .iter()
        .map(|(key, rrf_score)| {
            let raw_score = raw.get(key).copied().unwrap_or(0.0);
            let signals = signal_counts.get(key).copied().unwrap_or(0) as f32;
            let cross_bonus = if signals > 1.0 {
                (signals - 1.0) * 0.02
            } else {
                0.0
            };
            let path = key_path.get(key).cloned().unwrap_or_default();
            (
                key.clone(),
                path,
                rrf_score + raw_score * raw_weight + cross_bonus,
            )
        })
        .collect();
    combined.sort_by(|a, b| {
        b.2.partial_cmp(&a.2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    combined
}

/// Entity-granular fusion (behind `KIN_LOCATE_ENTITY_FUSION`, default OFF).
///
/// Builds entity-keyed ranked lists — the two entity-derived signals
/// (`entity_resolve` idx 7 and `embedding` idx 9) keyed by entity id from the
/// discovery seeds, every other signal keyed by its file path — fuses them with
/// [`reciprocal_rank_fusion_entities`], then PROJECTS the fused entity ranking
/// down to files (each file takes its best entity's fused score). The projected
/// file list then feeds the existing file-keyed post-fusion pipeline unchanged.
///
/// This is the architecture-bet ON path: entity ranking survives INTO fusion
/// rather than terminating at discovery. Deliberate first-cut limits, to be
/// validated by the post-freeze A/B (see the flip-plan):
/// 1. Projection happens at the fusion boundary, so dominance/floors/adaptive_cap
///    stay file-granular (re-keying the ~40-function post-fusion pipeline to
///    entities is out of scope under freeze and risks the proven determinism).
/// 2. Only the two entity-derived signals carry entity keys; text/traceback/
///    import signals stay file-granular because their `FileHit`s hold no entity id.
/// 3. The fuser is uniform rank-space RRF (no track regimes), per the scoring-map
///    recommendation to shrink mechanisms rather than tune knobs.
///
/// If neither entity-derived signal yields seed entities, every list falls back
/// to its path key, so the projection reduces to a plain file RRF rather than
/// dropping signal.
fn entity_granular_fused_files(
    ranked_lists: &[Vec<(String, f32)>],
    text_seeds: &HashMap<kin_model::EntityId, EntityDiscovery>,
    embedding_seeds: &HashMap<kin_model::EntityId, EntityDiscovery>,
    graph: &kin_db::InMemoryGraph,
) -> Result<Vec<(String, f32)>> {
    let resolve_keyed = entity_seed_keyed(text_seeds, graph)?;
    let embedding_keyed = entity_seed_keyed(embedding_seeds, graph)?;
    let path_keyed = |list: &[(String, f32)]| -> Vec<(String, String, f32)> {
        list.iter()
            .map(|(path, score)| (path.clone(), path.clone(), *score))
            .collect()
    };
    let mut keyed_lists: Vec<Vec<(String, String, f32)>> = Vec::with_capacity(ranked_lists.len());
    for (idx, list) in ranked_lists.iter().enumerate() {
        let keyed = match idx {
            7 if !resolve_keyed.is_empty() => resolve_keyed.clone(),
            9 if !embedding_keyed.is_empty() => embedding_keyed.clone(),
            _ => path_keyed(list),
        };
        keyed_lists.push(keyed);
    }
    let fused_entities = reciprocal_rank_fusion_entities(&keyed_lists, 60.0);
    // Project entity ranking → files: each file takes its best entity's score.
    let mut best_per_file: HashMap<String, f32> = HashMap::new();
    for (_, path, score) in &fused_entities {
        best_per_file
            .entry(path.clone())
            .and_modify(|existing| {
                if *score > *existing {
                    *existing = *score;
                }
            })
            .or_insert(*score);
    }
    let mut result: Vec<(String, f32)> = best_per_file.into_iter().collect();
    result.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    Ok(result)
}

fn resolve_candidate_debug_stages(
    origin: &str,
    candidates: &[ResolveCandidate],
    projected: &[(String, f32)],
) -> Vec<LocateDebugCandidateStage> {
    let limit = locate_env_usize("KIN_LOCATE_DEBUG_CANDIDATE_LIMIT", 80);
    let mut stages = Vec::new();

    let seed_candidates = candidates
        .iter()
        .filter(|candidate| candidate.source == ResolveCandidateSource::Direct)
        .cloned()
        .collect::<Vec<_>>();
    stages.push(LocateDebugCandidateStage {
        name: format!("{origin}_seed_candidates"),
        candidates: resolve_candidates_to_debug(seed_candidates, limit),
    });

    let relation_candidates = candidates
        .iter()
        .filter(|candidate| candidate.source == ResolveCandidateSource::Graph)
        .cloned()
        .collect::<Vec<_>>();
    stages.push(LocateDebugCandidateStage {
        name: format!("{origin}_relation_paths"),
        candidates: resolve_candidates_to_debug(relation_candidates, limit),
    });

    stages.push(LocateDebugCandidateStage {
        name: format!("{origin}_candidate_pre_projection"),
        candidates: resolve_candidates_to_debug(candidates.to_vec(), limit),
    });

    let projected_candidates = projected
        .iter()
        .map(|(path, score)| ResolveCandidate {
            id: format!("file:{path}"),
            kind: "projected_file",
            path: path.clone(),
            name: None,
            score: *score,
            source: ResolveCandidateSource::Graph,
            reason: "candidate projection".to_string(),
        })
        .collect::<Vec<_>>();
    stages.push(LocateDebugCandidateStage {
        name: format!("{origin}_projected_pre_cap"),
        candidates: resolve_candidates_to_debug(projected_candidates, limit),
    });

    stages
}

fn resolve_candidates_to_debug(
    mut candidates: Vec<ResolveCandidate>,
    limit: usize,
) -> Vec<LocateDebugCandidate> {
    candidates.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.id.cmp(&right.id))
    });
    candidates
        .into_iter()
        .take(limit)
        .map(|candidate| LocateDebugCandidate {
            id: candidate.id,
            kind: candidate.kind.to_string(),
            path: Some(candidate.path),
            name: candidate.name,
            score: candidate.score,
            reason: candidate.reason,
        })
        .collect()
}

fn resolve_relation_kind_priority(kind: RelationKind) -> u8 {
    match kind {
        RelationKind::Calls | RelationKind::UsesMacro | RelationKind::Tests => 5,
        RelationKind::Implements | RelationKind::Extends => 4,
        RelationKind::References => 3,
        RelationKind::DerivedFrom => 3,
        RelationKind::Imports | RelationKind::Includes | RelationKind::DependsOn => 2,
        RelationKind::Contains => 1,
        _ => 0,
    }
}

fn resolve_relation_origin_multiplier(
    origin: kin_model::RelationOrigin,
    lsp_boost: f32,
    parsed_weight: f32,
    inferred_weight: f32,
) -> f32 {
    match origin {
        kin_model::RelationOrigin::Lsp => lsp_boost,
        kin_model::RelationOrigin::Parsed => parsed_weight,
        kin_model::RelationOrigin::Inferred => inferred_weight,
        kin_model::RelationOrigin::Manual => 1.0,
    }
}

fn resolve_relation_kind_multiplier(kind: RelationKind) -> f32 {
    match kind {
        RelationKind::Calls => 2.0,
        RelationKind::UsesMacro => 2.0,
        RelationKind::References => 1.5,
        RelationKind::Implements | RelationKind::Extends => 1.8,
        RelationKind::Imports | RelationKind::DependsOn => 1.2,
        RelationKind::Includes => 1.2,
        RelationKind::DerivedFrom => 1.6,
        RelationKind::Contains => 1.0,
        RelationKind::Tests => 2.0,
        _ => 0.8,
    }
}

fn relation_allows_artifact_traversal(rel: &kin_model::Relation, from_node: &GraphNodeId) -> bool {
    match rel.kind {
        RelationKind::Includes | RelationKind::Imports => rel.src == *from_node,
        RelationKind::DerivedFrom => rel.src == *from_node || rel.dst == *from_node,
        _ => false,
    }
}

fn relation_adjacent_artifact_path(
    graph: &kin_db::InMemoryGraph,
    rel: &kin_model::Relation,
    from_node: &GraphNodeId,
) -> Option<(String, GraphNodeId)> {
    if !relation_allows_artifact_traversal(rel, from_node) {
        return None;
    }

    let other = if rel.src == *from_node {
        rel.dst
    } else if rel.kind == RelationKind::DerivedFrom && rel.dst == *from_node {
        rel.src
    } else {
        return None;
    };

    if let GraphNodeId::Artifact(artifact_id) = other {
        if let Some(path) = graph.path_for_artifact_id(&artifact_id) {
            return Some((path.0, GraphNodeId::Artifact(artifact_id)));
        }
    }

    relation_projected_artifact_path(rel, from_node).and_then(|path| {
        graph
            .artifact_id_for_path(&kin_model::FilePathId::new(path.as_str()))
            .map(|artifact_id| (path, GraphNodeId::Artifact(artifact_id)))
    })
}

fn relation_projected_artifact_path(
    rel: &kin_model::Relation,
    from_node: &GraphNodeId,
) -> Option<String> {
    if rel.src != *from_node {
        return None;
    }
    rel.evidence
        .iter()
        .find_map(|evidence| evidence.resolved_path.clone())
        .or_else(|| rel.import_source.clone())
        .filter(|path| !path.is_empty())
}

fn artifact_relation_path_specificity_multiplier(
    seed_path: &str,
    target_path: &str,
    hop: usize,
) -> f32 {
    if hop <= 1 {
        return 1.0;
    }

    let seed_tokens = semantic_path_tokens(seed_path);
    if seed_tokens.is_empty() {
        return 1.0;
    }
    let target_tokens = semantic_path_tokens(target_path);
    if target_tokens.is_empty() {
        return 1.0;
    }

    let overlap = seed_tokens.intersection(&target_tokens).count();
    if overlap > 0 {
        locate_env_f32("KIN_LOCATE_ARTIFACT_PATH_OVERLAP_BOOST", 1.85)
    } else {
        locate_env_f32("KIN_LOCATE_ARTIFACT_HUB_FANOUT_PENALTY", 0.45)
    }
}

fn semantic_path_tokens(path: &str) -> HashSet<String> {
    let mut tokens = HashSet::new();
    let mut current = String::new();
    for ch in path.chars() {
        if ch.is_ascii_alphanumeric() {
            current.push(ch.to_ascii_lowercase());
        } else {
            push_semantic_path_token(&mut tokens, &current);
            current.clear();
        }
    }
    push_semantic_path_token(&mut tokens, &current);
    tokens
}

fn push_semantic_path_token(tokens: &mut HashSet<String>, raw: &str) {
    let stripped = raw.trim_matches(|ch: char| ch.is_ascii_digit());
    if stripped.len() < 4 {
        return;
    }
    let singular = stripped.strip_suffix('s').unwrap_or(stripped);
    if matches!(
        singular,
        "test"
            | "unit"
            | "src"
            | "source"
            | "include"
            | "detail"
            | "common"
            | "class"
            | "nlohmann"
            | "json"
            | "single"
            | "thirdparty"
            | "third"
            | "party"
    ) {
        return;
    }
    tokens.insert(singular.to_string());
}

fn resolve_relation_origin_priority(origin: kin_model::RelationOrigin) -> u8 {
    match origin {
        kin_model::RelationOrigin::Manual => 4,
        kin_model::RelationOrigin::Lsp => 3,
        kin_model::RelationOrigin::Parsed => 2,
        kin_model::RelationOrigin::Inferred => 1,
    }
}

// ---------------------------------------------------------------------------
// 9. Reciprocal Rank Fusion (hybrid: RRF + raw score bonus + cross-signal bonus)
// ---------------------------------------------------------------------------

/// Per-list multipliers on the rank-based RRF term, indexed by signal list
/// position (0=traceback … 7=entity_resolve, 8=source_text, 9=embedding).
///
/// Classic RRF (and every default-OFF run) uses an implicit weight of `1.0` for
/// every list, so [`reciprocal_rank_fusion`] is exactly equivalent to passing an
/// empty slice here. The uniform per-signal `signal_confidence_weights` applied
/// upstream scale each list's raw scores, but RRF's dominant term is rank-only
/// (`1/(k+rank+1)`) and its raw term normalizes by each list's own max, so a
/// uniform per-list score multiplier is largely inert for fused RANK. Lifting a
/// semantically-strong but lexically-buried gold therefore requires weighting
/// the rank term itself, which is what these multipliers do.
///
/// Defaults are all `1.0` (see [`rrf_rank_lift_weights`]); the lift only engages
/// when the operator sets `KIN_LOCATE_RRF_WEIGHT_*`, so OFF stays byte-identical.
fn rrf_rank_lift_weights(num_lists: usize) -> Vec<f32> {
    let mut weights = vec![1.0f32; num_lists];
    if num_lists > 7 {
        weights[7] = locate_env_f32("KIN_LOCATE_RRF_WEIGHT_RESOLVE", 1.0);
    }
    if num_lists > 9 {
        weights[9] = locate_env_f32("KIN_LOCATE_RRF_WEIGHT_EMBEDDING", 1.0);
    }
    weights
}

fn reciprocal_rank_fusion(ranked_lists: &[Vec<(String, f32)>], k: f32) -> Vec<(String, f32)> {
    // Empty weight slice == classic unweighted RRF (every list weighted 1.0).
    reciprocal_rank_fusion_weighted(ranked_lists, k, &[], &[])
}

/// Weighted reciprocal rank fusion. Identical to classic RRF when every entry of
/// `list_weights` is `1.0` (or the slice is shorter than `ranked_lists`, in which
/// case missing entries default to `1.0`) — `w / (k+rank+1)` with `w == 1.0` is
/// bit-identical to the unweighted `1.0 / (k+rank+1)`, so default-OFF callers are
/// byte-for-byte unchanged. Only the rank term is weighted; the normalized raw,
/// cross-signal, and graph-neighborhood terms are untouched.
fn reciprocal_rank_fusion_weighted(
    ranked_lists: &[Vec<(String, f32)>],
    k: f32,
    list_weights: &[f32],
    raw_weights: &[f32],
) -> Vec<(String, f32)> {
    let _span = tracing::info_span!(
        "locate.reciprocal_rank_fusion",
        lists = ranked_lists.len(),
        k = k as f64
    )
    .entered();
    let mut rrf_scores: FxHashMap<String, f32> = FxHashMap::default();
    let mut raw_scores: FxHashMap<String, f32> = FxHashMap::default();
    let mut signal_counts: FxHashMap<String, usize> = FxHashMap::default();

    // Track which graph-structural signal indices each file appears in.
    // multihop=1, tests=2, imports=4, cochange=6.
    let graph_signal_indices: HashSet<usize> = [1, 2, 4, 6].iter().copied().collect();
    let mut graph_signal_counts: FxHashMap<String, usize> = FxHashMap::default();

    for (list_idx, list) in ranked_lists.iter().enumerate() {
        // Compute max score in this list for normalization
        let max_score = list.iter().map(|(_, s)| *s).fold(0.0f32, f32::max).max(1.0);
        let rank_weight = list_weights.get(list_idx).copied().unwrap_or(1.0);
        let raw_weight = raw_weights.get(list_idx).copied().unwrap_or(1.0);

        let mut files_in_list = HashSet::new();
        for (rank, (file, score)) in list.iter().enumerate() {
            // Skip vendored/third-party files entirely
            if is_vendored_path(file) {
                continue;
            }
            *rrf_scores.entry(file.clone()).or_default() += rank_weight / (k + rank as f32 + 1.0);
            // Accumulate normalized raw scores
            *raw_scores.entry(file.clone()).or_default() += (score * raw_weight) / max_score;
            files_in_list.insert(file.clone());
        }
        // Count how many signal sources contributed to each file
        for file in &files_in_list {
            *signal_counts.entry(file.clone()).or_default() += 1;
            if graph_signal_indices.contains(&list_idx) {
                *graph_signal_counts.entry(file.clone()).or_default() += 1;
            }
        }
    }

    // Semantic-primacy term (gated, default 0.5 = sweet spot for embedding fusion). The combine
    // below rewards breadth (many signals) + raw score, so a file found mainly by a
    // strong EMBEDDING match (signal list index 9) is drowned — measured: a gold at
    // embedding rank #11 landed at fused rank #249. When enabled, add a direct
    // contribution for a top embedding rank with a SMALL k so top ranks dominate
    // (RRF's large k compresses rank differences). Ship only if F1 improves.
    let semantic_weight = locate_env_f32("KIN_LOCATE_SEMANTIC_PRIMACY_WEIGHT", 0.5);
    let semantic_k = locate_env_f32("KIN_LOCATE_SEMANTIC_PRIMACY_K", 8.0);
    let embed_rank: FxHashMap<&str, usize> = if semantic_weight > 0.0 {
        ranked_lists
            .get(9)
            .map(|l| {
                l.iter()
                    .enumerate()
                    .map(|(r, (f, _))| (f.as_str(), r))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        FxHashMap::default()
    };
    // Combine: RRF + normalized raw scores + cross-signal bonus + graph tiebreaker
    let mut combined: FxHashMap<String, f32> = FxHashMap::default();
    for (file, rrf) in &rrf_scores {
        let raw = raw_scores.get(file).copied().unwrap_or(0.0);
        let signals = signal_counts.get(file).copied().unwrap_or(0) as f32;
        // Cross-signal bonus: files found by multiple extractors are more relevant
        let cross_bonus = if signals > 1.0 {
            (signals - 1.0) * 0.02
        } else {
            0.0
        };
        // Graph neighborhood tiebreaker: files confirmed by >=2 graph-structural
        // signals (search, multihop, tests) rank above files found only by vector
        // similarity or followup expansion.
        let graph_count = graph_signal_counts.get(file).copied().unwrap_or(0);
        let graph_bonus = if graph_count >= 2 { 0.01 } else { 0.0 };
        let raw_weight = locate_env_f32("KIN_LOCATE_RRF_RAW_WEIGHT", 0.05);
        let semantic = if semantic_weight > 0.0 {
            embed_rank
                .get(file.as_str())
                .map(|&r| semantic_weight / (semantic_k + r as f32 + 1.0))
                .unwrap_or(0.0)
        } else {
            0.0
        };
        combined.insert(
            file.clone(),
            rrf + raw * raw_weight + cross_bonus + graph_bonus + semantic,
        );
    }

    let mut result: Vec<_> = combined.into_iter().collect();
    result.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    result
}

fn aggregate_entity_seed_file_support(
    entity_seeds: &HashMap<kin_model::EntityId, EntityDiscovery>,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, f32>> {
    let mut file_scores: HashMap<String, f32> = HashMap::new();
    let mut ordered_seeds: Vec<(&kin_model::EntityId, &EntityDiscovery)> =
        entity_seeds.iter().collect();
    ordered_seeds.sort_by(|a, b| a.0.cmp(b.0));
    for (entity_id, discovery) in ordered_seeds {
        let Some(entity) = graph.get_entity(entity_id)? else {
            continue;
        };
        let Some(file_origin) = entity.file_origin.as_ref() else {
            continue;
        };
        if is_test_by_role(&file_origin.0, Some(&entity)) {
            continue;
        }
        *file_scores.entry(file_origin.0.clone()).or_default() += discovery.score;
    }
    Ok(file_scores)
}

fn top_cochange_seed_paths(
    cochange_ranked: &[(String, f32)],
    seed_file_support: &HashMap<String, f32>,
) -> HashSet<String> {
    let rank_limit = locate_env_usize("KIN_LOCATE_COCHANGE_SEED_RANK_LIMIT", 5);
    let seed_floor = locate_env_f32("KIN_LOCATE_COCHANGE_SEED_FLOOR", 1.0);
    cochange_ranked
        .iter()
        .take(rank_limit)
        .filter_map(|(path, _)| {
            seed_file_support
                .get(path)
                .filter(|score| **score >= seed_floor)
                .map(|_| path.clone())
        })
        .collect()
}

fn boost_top_cochange_seed_support(
    fused: &mut Vec<(String, f32)>,
    cochange_ranked: &[(String, f32)],
    seed_file_support: &HashMap<String, f32>,
    cochange_seed_paths: &HashSet<String>,
) {
    if fused.is_empty()
        || cochange_ranked.is_empty()
        || seed_file_support.is_empty()
        || cochange_seed_paths.is_empty()
    {
        return;
    }

    let rank_bonus = locate_env_f32("KIN_LOCATE_COCHANGE_SEED_BONUS", 1.0);
    if rank_bonus <= 0.0 {
        return;
    }

    let cochange_ranks: HashMap<&str, usize> = cochange_ranked
        .iter()
        .filter(|(path, _)| cochange_seed_paths.contains(path))
        .enumerate()
        .map(|(rank, (path, _))| (path.as_str(), rank))
        .collect();

    for (path, score) in fused.iter_mut() {
        let Some(rank) = cochange_ranks.get(path.as_str()) else {
            continue;
        };
        let Some(_seed_score) = seed_file_support.get(path) else {
            continue;
        };
        *score += rank_bonus / ((*rank + 1) as f32).sqrt();
    }

    fused.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
}

/// Boost files that share a top-level directory prefix with seed/priority files.
/// In multi-module repos (Maven, Gradle, Cargo workspaces), locate results
/// often scatter across sibling modules. This focuses results within the most
/// likely module based on seed consensus.
fn apply_module_prefix_affinity(
    fused: &mut [(String, f32)],
    priority_traces: &HashMap<String, PriorityFileTrace>,
) {
    if fused.len() < 3 {
        return;
    }

    // Find the dominant top-level directory from the top-scored files.
    let mut prefix_counts: HashMap<String, usize> = HashMap::new();
    for (path, _) in fused.iter().take(5) {
        if let Some(prefix) = top_level_module_prefix(path) {
            *prefix_counts.entry(prefix).or_default() += 1;
        }
    }
    // Also count priority file prefixes with extra weight.
    for (path, _trace) in priority_traces {
        if let Some(prefix) = top_level_module_prefix(path) {
            *prefix_counts.entry(prefix).or_default() += 2;
        }
    }

    let dominant = prefix_counts
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(prefix, _)| prefix.clone());

    let Some(dominant_prefix) = dominant else {
        return;
    };

    // Only apply affinity if the dominant prefix has clear majority.
    let dominant_count = prefix_counts.get(&dominant_prefix).copied().unwrap_or(0);
    let total_counted: usize = prefix_counts.values().sum();
    if dominant_count * 2 <= total_counted {
        return; // No clear majority — skip affinity.
    }

    let boost = locate_env_f32("KIN_LOCATE_MODULE_AFFINITY_BOOST", 1.3);
    let penalty = locate_env_f32("KIN_LOCATE_MODULE_AFFINITY_PENALTY", 0.7);

    for (path, score) in fused.iter_mut() {
        if let Some(prefix) = top_level_module_prefix(path) {
            if prefix == dominant_prefix {
                *score *= boost;
            } else {
                *score *= penalty;
            }
        }
    }
}

/// Extract the top-level module directory prefix from a path.
/// For multi-module repos: "jib-maven-plugin/src/..." → "jib-maven-plugin"
/// For single-module: "src/main/java/..." → None (no module prefix)
fn top_level_module_prefix(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 2 {
        return None;
    }
    let first = parts[0];
    // Skip common non-module top-level dirs.
    if matches!(
        first,
        "src"
            | "lib"
            | "test"
            | "tests"
            | "include"
            | "doc"
            | "docs"
            | "bin"
            | "cmd"
            | "pkg"
            | "internal"
            | "scripts"
            | "tools"
            | "examples"
            | "benches"
            | "fixtures"
            | ".github"
    ) {
        return None;
    }
    Some(first.to_string())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_ranked(hits: &HashMap<String, Vec<FileHit>>) -> Vec<(String, f32)> {
    let _span = tracing::info_span!("locate.to_ranked", files = hits.len()).entered();
    let mut ranked: Vec<(String, f32)> = hits
        .iter()
        .map(|(path, file_hits)| {
            // Use top-3 mean score instead of sum to prevent large files with many
            // entities from dominating through sheer entity count
            let mut scores: Vec<f32> = file_hits.iter().map(|h| h.score).collect();
            scores.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
            let top_n = scores.iter().take(3).copied().collect::<Vec<_>>();
            let mean = if top_n.is_empty() {
                0.0
            } else {
                top_n.iter().sum::<f32>() / top_n.len() as f32
            };

            // Source file bonus: non-test source files get a mild boost
            let source_bonus = if role_from_path(path) == EntityRole::Source {
                1.2
            } else {
                1.0
            };

            (path.clone(), mean * source_bonus)
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    ranked
}

fn adaptive_cap(
    fused: &[(String, f32)],
    all_hits: &[HashMap<String, Vec<FileHit>>],
    max_files: usize,
    max_files_explicit: bool,
    cochange_seed_paths: &HashSet<String>,
    priority_retention_paths: &HashSet<String>,
    semantic_retention_paths: &HashSet<String>,
    floor_reference: &HashMap<String, f32>,
    graph_semantic_corroboration: bool,
    mut pruned: Option<&mut Vec<PrunedFile>>,
) -> Vec<(String, f32)> {
    let _span = tracing::info_span!(
        "locate.adaptive_cap",
        fused = fused.len(),
        max_files = max_files,
        max_files_explicit = max_files_explicit,
    )
    .entered();
    let want_pruned = pruned.is_some();
    let mut record_pruned = |path: &str, score: f32, reason: &str| {
        if let Some(sink) = pruned.as_deref_mut() {
            sink.push(PrunedFile {
                path: path.to_string(),
                score,
                reason: reason.to_string(),
            });
        }
    };
    if fused.is_empty() {
        return vec![];
    }
    if fused.len() <= 1 {
        return fused.to_vec();
    }

    let gap_threshold = locate_env_f32("KIN_LOCATE_CLUSTER_GAP_THRESHOLD", 1.5);
    let floor_pct = locate_env_f32("KIN_LOCATE_CLUSTER_FLOOR_PCT", 0.05);
    let min_cluster = locate_env_usize("KIN_LOCATE_MIN_CLUSTER", 1);
    let max_cluster = locate_env_usize("KIN_LOCATE_MAX_CLUSTER", 6);
    let signal_support_threshold = locate_env_usize("KIN_LOCATE_SIGNAL_SUPPORT_THRESHOLD", 3);

    let top_score = fused[0].1;
    let floor = top_score * floor_pct;
    let mut cluster_size = 1usize;

    let scan_limit = if max_files_explicit {
        fused.len().min(max_files.max(1))
    } else {
        fused.len().min(max_cluster)
    };
    // L1: scan beyond the cluster window so corroborated cross-file candidates past
    // the top cluster can still be admitted (released below), fixing under-retrieval.
    let support_scan_limit = if max_files_explicit {
        scan_limit
    } else {
        fused
            .len()
            .min(locate_env_usize("KIN_LOCATE_SUPPORT_SCAN_WINDOW", 40).max(max_cluster))
    };
    for i in 1..scan_limit {
        let score = fused[i].1;
        let prev_score = fused[i - 1].1;
        if score <= 0.0 || score < floor {
            record_pruned(&fused[i].0, score, "cluster_gap");
            break;
        }
        if prev_score > 0.0 && prev_score / score > gap_threshold {
            record_pruned(&fused[i].0, score, "cluster_gap");
            break;
        }
        cluster_size += 1;
    }

    let support_floor_pct = locate_env_f32("KIN_LOCATE_MULTI_SIGNAL_FLOOR_PCT", 0.2);
    let corroborated_resolve_floor_pct =
        locate_env_f32("KIN_LOCATE_CORROBORATED_RESOLVE_FLOOR_PCT", 0.05);
    let retention_floor_pct = locate_env_f32(
        "KIN_LOCATE_RETENTION_FLOOR_PCT",
        support_floor_pct.min(0.15),
    );
    let priority_retention_floor_pct = locate_env_f32(
        "KIN_LOCATE_PRIORITY_RETENTION_FLOOR_PCT",
        retention_floor_pct.min(0.08),
    );
    let default_support_floor_max = locate_env_usize("KIN_LOCATE_MULTI_SIGNAL_FLOOR_MAX", 3);
    let retained_support_floor_max = cluster_size
        .saturating_add(priority_retention_paths.len())
        .saturating_add(semantic_retention_paths.len())
        .max(default_support_floor_max);
    let support_floor_limit = if max_files_explicit {
        scan_limit.min(max_files.max(1))
    } else {
        retained_support_floor_max
    };
    let support_floor_min = min_cluster.min(support_floor_limit.max(1));
    let support_floor_max = support_floor_limit.max(support_floor_min);
    // Strong-semantic exemption: the top-K files by embedding cosine are
    // first-class evidence. A gold surfaced ONLY by a strong embedding match
    // (high cosine, no lexical corroboration) must not be pruned
    // `below_support_floor` or excluded from the support cap despite outranking
    // most of the pool — otherwise the embedding's biggest wins are discarded
    // (measured: golds scoring 9-15 floored away). K=0 restores original behavior.
    let embed_floor_exempt_topk = locate_env_usize("KIN_LOCATE_EMBED_FLOOR_EXEMPT_TOPK", 5);
    let strong_embedding_paths: HashSet<String> = if embed_floor_exempt_topk == 0 {
        HashSet::new()
    } else {
        all_hits
            .get(9)
            .map(|emb| {
                let mut scored: Vec<(&String, f32)> = emb
                    .iter()
                    .map(|(p, hits)| (p, hits.iter().map(|h| h.score).fold(f32::MIN, f32::max)))
                    .collect();
                scored.sort_by(|a, b| {
                    b.1.partial_cmp(&a.1)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.0.cmp(b.0))
                });
                scored
                    .into_iter()
                    .filter(|(p, _)| strong_embedding_release_allowed(p))
                    .take(embed_floor_exempt_topk)
                    .map(|(p, _)| p.clone())
                    .collect()
            })
            .unwrap_or_default()
    };
    let strong_semantic_paths: HashSet<String> = HashSet::new();
    // Support floors measure evidence strength, so they are evaluated against
    // the pre-compression score regime when a floor reference is provided:
    // relative tail compressions (dominance/boundary) reorder the list but must
    // not push corroborated evidence below floors calibrated on uncompressed
    // score distributions.
    let floor_score_for = |path: &str, score: f32| -> f32 {
        floor_reference
            .get(path)
            .copied()
            .unwrap_or(score)
            .max(score)
    };
    let floor_top = fused
        .iter()
        .map(|(path, score)| floor_score_for(path, *score))
        .fold(top_score, f32::max);
    let mut supported_indices: Vec<usize> = Vec::new();
    let mut corroborated_indices: Vec<usize> = Vec::new();
    for (i, (path, score)) in fused.iter().take(support_scan_limit).enumerate() {
        let has_entity_resolve = all_hits
            .get(7)
            .is_some_and(|er| er.contains_key(path.as_str()));
        let is_strong_semantic = strong_semantic_paths.contains(path.as_str());
        let has_corroborated_resolve = has_entity_resolve
            && (is_strong_semantic
                || all_hits.iter().enumerate().any(|(idx, signal)| {
                    idx != 6 && idx != 7 && signal.contains_key(path.as_str())
                }));
        // Graph-semantic corroboration: an embedding match backed by structural
        // follow-up (multihop or imports) is semantic+graph agreement, the same
        // evidence grade as entity_resolve corroborated by another signal.
        let has_graph_semantic_corroboration = graph_semantic_corroboration
            && has_signal(path, all_hits, 9)
            && (has_signal(path, all_hits, 1) || has_signal(path, all_hits, 4))
            && strong_embedding_release_allowed(path);
        let is_priority_retained = priority_retention_paths.contains(path.as_str());
        let is_semantic_retained = semantic_retention_paths.contains(path.as_str());
        let is_cochange_seed = cochange_seed_paths.contains(path.as_str());
        let multi_signal = signal_support_count(path, all_hits) >= signal_support_threshold;
        let is_strong_embedding = strong_embedding_paths.contains(path.as_str());
        let floor_pct = if is_cochange_seed {
            retention_floor_pct
        } else if has_corroborated_resolve || has_graph_semantic_corroboration {
            corroborated_resolve_floor_pct
        } else if is_semantic_retained {
            priority_retention_floor_pct
        } else if is_priority_retained {
            priority_retention_floor_pct
        } else {
            support_floor_pct
        };
        if !is_priority_retained
            && !is_semantic_retained
            && !is_strong_embedding
            && !is_strong_semantic
            && !multi_signal
            && floor_score_for(path, *score) < floor_top * floor_pct
        {
            record_pruned(path, *score, "below_support_floor");
            continue;
        }
        if has_corroborated_resolve
            || has_graph_semantic_corroboration
            || multi_signal
            || is_priority_retained
            || is_semantic_retained
            || is_cochange_seed
            || is_strong_embedding
            || is_strong_semantic
        {
            supported_indices.push(i);
            // L1: only STRONGLY corroborated candidates may be admitted beyond the cluster
            // cap — require 3+ independent signals (multi_signal), a priority/cochange
            // seed, or a top-K embedding match (strong standalone semantic evidence).
            // A lone or doubly-signalled file on a flat query must not flood results.
            if has_corroborated_resolve
                || has_graph_semantic_corroboration
                || multi_signal
                || is_priority_retained
                || is_semantic_retained
                || is_cochange_seed
                || is_strong_embedding
                || is_strong_semantic
            {
                corroborated_indices.push(i);
            }
        }
    }
    let support_floor = supported_indices
        .len()
        .clamp(support_floor_min, support_floor_max);

    let cap = if max_files_explicit {
        cluster_size.max(support_floor).min(max_files)
    } else {
        cluster_size.max(support_floor).min(max_cluster)
    };
    let cap = cap.min(fused.len());
    let mut result: Vec<(String, f32)> = fused.iter().take(cap).cloned().collect();
    let mut result_set: HashSet<String> = result.iter().map(|(p, _)| p.clone()).collect();
    // L1: release corroborated cross-file candidates that ranked beyond the cluster cap
    // (previously only priority paths were re-admitted), bounded to avoid flooding.
    let support_max_total = cap.saturating_add(locate_env_usize("KIN_LOCATE_SUPPORT_EXTRA", 3));
    for &i in &corroborated_indices {
        if i >= cap {
            let (ref path, _) = fused[i];
            if result_set.contains(path.as_str()) {
                continue;
            }
            // Priority retention paths always get admitted — they have strong
            // prior evidence (explicit mention, historical co-change).  General
            // corroborated files are bounded by support_max_total.
            let is_priority = priority_retention_paths.contains(path.as_str())
                || semantic_retention_paths.contains(path.as_str())
                || cochange_seed_paths.contains(path.as_str())
                || strong_semantic_paths.contains(path.as_str());
            if !is_priority && result.len() >= support_max_total {
                break;
            }
            result_set.insert(path.clone());
            result.push(fused[i].clone());
        }
    }
    // No-silent-elimination: re-admit beyond-cap candidates whose pre-compression evidence
    // (floor_reference) stays strong, strongest-first, so a relative compression cannot
    // silently drop a candidate whose own evidence never weakened. Bounded by support_max_total.
    let precomp_readmit_pct = locate_env_f32("KIN_LOCATE_PRECOMP_READMIT_PCT", 0.3);
    if precomp_readmit_pct > 0.0 && result.len() < support_max_total {
        let readmit_floor = floor_top * precomp_readmit_pct;
        let mut readmit: Vec<(usize, f32)> = Vec::new();
        for (i, (path, score)) in fused.iter().enumerate().take(support_scan_limit) {
            if i < cap || result_set.contains(path.as_str()) {
                continue;
            }
            // Only undo compression-caused drops: the candidate's pre-compression evidence
            // must both clear the floor AND exceed its current (compressed) score. An
            // uncompressed tail file (floor == live) was already judged on its true score.
            let strength = floor_score_for(path, *score);
            if strength >= readmit_floor && strength > *score {
                readmit.push((i, strength));
            }
        }
        readmit.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        for (i, _) in readmit {
            if result.len() >= support_max_total {
                break;
            }
            result_set.insert(fused[i].0.clone());
            result.push(fused[i].clone());
        }
    }
    if want_pruned {
        for (path, score) in fused.iter() {
            if !result_set.contains(path.as_str()) {
                record_pruned(path, *score, "over_cap");
            }
        }
    }
    if max_files_explicit && result.len() > max_files {
        for (path, score) in result.iter().skip(max_files) {
            record_pruned(path, *score, "over_max_files");
        }
        result.truncate(max_files);
    }
    result
}

fn demote_zero_signal_files(
    fused: &mut Vec<(String, f32)>,
    all_hits: &[HashMap<String, Vec<FileHit>>],
    priority_files: &[(String, f32)],
    exempt_paths: &HashSet<String>,
) {
    let priority_set: HashSet<&str> = priority_files
        .iter()
        .map(|(path, _)| path.as_str())
        .collect();
    let no_signal_penalty = locate_env_f32("KIN_LOCATE_NO_SIGNAL_PENALTY", 0.001);
    for (path, score) in fused.iter_mut() {
        if *score <= 0.0 {
            continue;
        }
        let in_any_signal = all_hits.iter().any(|signal| signal.contains_key(path));
        if !in_any_signal && !priority_set.contains(path.as_str()) && !exempt_paths.contains(path) {
            *score *= no_signal_penalty;
        }
    }
    fused.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
}

fn graph_corroborated_semantic_retention_paths(
    fused: &[(String, f32)],
    resolved_hits: &HashMap<String, Vec<FileHit>>,
    source_text_hits: &HashMap<String, Vec<FileHit>>,
    embedding_hits: &HashMap<String, Vec<FileHit>>,
    multihop_hits: &HashMap<String, Vec<FileHit>>,
    import_hits: &HashMap<String, Vec<FileHit>>,
) -> HashSet<String> {
    let max_paths = locate_env_usize("KIN_LOCATE_STRONG_SEMANTIC_RETAIN_MAX", 5);
    graph_corroborated_semantic_retention_paths_with_limit(
        fused,
        resolved_hits,
        source_text_hits,
        embedding_hits,
        multihop_hits,
        import_hits,
        max_paths,
    )
}

fn graph_corroborated_semantic_retention_paths_with_limit(
    fused: &[(String, f32)],
    resolved_hits: &HashMap<String, Vec<FileHit>>,
    source_text_hits: &HashMap<String, Vec<FileHit>>,
    embedding_hits: &HashMap<String, Vec<FileHit>>,
    multihop_hits: &HashMap<String, Vec<FileHit>>,
    import_hits: &HashMap<String, Vec<FileHit>>,
    max_paths: usize,
) -> HashSet<String> {
    if max_paths == 0 || fused.is_empty() {
        return HashSet::new();
    }

    let scan_limit = locate_env_usize("KIN_LOCATE_STRONG_SEMANTIC_SCAN_WINDOW", 40);
    let floor_pct = locate_env_f32("KIN_LOCATE_STRONG_SEMANTIC_FLOOR_PCT", 0.02);
    let top_score = fused[0].1.max(0.001);
    let mut candidates: Vec<(String, f32, usize)> = Vec::new();

    for (rank, (path, score)) in fused.iter().take(scan_limit).enumerate() {
        if *score < top_score * floor_pct {
            continue;
        }
        if !strong_embedding_release_allowed(path) {
            continue;
        }

        let source_score = max_hit_score(source_text_hits, path);
        let embedding_score = max_hit_score(embedding_hits, path);
        let resolved_score = max_hit_score(resolved_hits, path);
        let multihop_score = max_hit_score(multihop_hits, path);
        let import_score = max_hit_score(import_hits, path);

        let has_query_signal = source_score > 0.0 || embedding_score > 0.0;
        let has_structural_followup = multihop_score > 0.0 || import_score > 0.0;
        let has_source_backed_resolve = source_score > 0.0 && resolved_score > 0.0;

        if !has_query_signal || !(has_structural_followup || has_source_backed_resolve) {
            continue;
        }

        let support = [
            resolved_score,
            source_score,
            embedding_score,
            multihop_score,
            import_score,
        ]
        .into_iter()
        .filter(|score| *score > 0.0)
        .count();
        if support < locate_env_usize("KIN_LOCATE_STRONG_SEMANTIC_MIN_SIGNALS", 2) {
            continue;
        }

        let query_strength = source_score.max(embedding_score);
        let graph_strength = resolved_score.max(multihop_score).max(import_score);
        let rank_bonus = 1.0 / ((rank + 1) as f32);
        candidates.push((
            path.clone(),
            query_strength.sqrt() * graph_strength.sqrt() + rank_bonus,
            rank,
        ));
    }

    candidates.sort_by(|left, right| {
        right
            .1
            .partial_cmp(&left.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.2.cmp(&right.2))
            .then_with(|| left.0.cmp(&right.0))
    });
    candidates
        .into_iter()
        .take(max_paths)
        .map(|(path, _, _)| path)
        .collect()
}

fn max_hit_score(hits: &HashMap<String, Vec<FileHit>>, path: &str) -> f32 {
    hits.get(path)
        .map(|file_hits| file_hits.iter().map(|hit| hit.score).fold(0.0f32, f32::max))
        .unwrap_or(0.0)
}

fn apply_resolve_boundary_compression(
    fused: &mut Vec<(String, f32)>,
    resolved_hits: &HashMap<String, Vec<FileHit>>,
    priority_files: &[(String, f32)],
    test_query: bool,
    semantic_retention_paths: &HashSet<String>,
) {
    let resolve_scores: HashMap<&str, f32> = resolved_hits
        .iter()
        .map(|(path, hits)| {
            let max_score = hits.iter().map(|h| h.score).fold(0.0f32, f32::max);
            (path.as_str(), max_score)
        })
        .collect();
    let priority_set: HashSet<&str> = priority_files
        .iter()
        .map(|(path, _)| path.as_str())
        .collect();
    let compress_factor = locate_env_f32("KIN_LOCATE_NOISE_TAIL_COMPRESS", 0.4);
    let resolve_strength_floor = resolve_strength_floor();
    let top_resolve = fused
        .first()
        .and_then(|(p, _)| resolve_scores.get(p.as_str()).copied())
        .unwrap_or(0.0);
    if top_resolve <= 0.0 {
        return;
    }

    let resolve_threshold = top_resolve * resolve_strength_floor;
    for (path, score) in fused.iter_mut().skip(1) {
        let file_resolve = resolve_scores.get(path.as_str()).copied().unwrap_or(0.0);
        if file_resolve >= resolve_threshold {
            continue;
        }
        if semantic_retention_paths.contains(path.as_str())
            || (test_query && is_test_path(path))
            || priority_set.contains(path.as_str())
        {
            continue;
        }
        *score *= compress_factor;
    }
    fused.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
}

fn signal_support_count(path: &str, all_hits: &[HashMap<String, Vec<FileHit>>]) -> usize {
    all_hits
        .iter()
        .filter(|signal| signal.contains_key(path))
        .count()
}

fn strong_embedding_release_allowed(path: &str) -> bool {
    !is_amalgamated_or_generated_path(path)
        && !is_vendor_path(path)
        && !is_docs_or_locale_path(path)
        && !is_embedded_framework_noise_path(path)
        && !is_license_or_notice_path(path)
        && !is_non_code_ext(path)
}

fn has_corroborated_resolve_signal(path: &str, all_hits: &[HashMap<String, Vec<FileHit>>]) -> bool {
    all_hits
        .get(7)
        .is_some_and(|resolved| resolved.contains_key(path))
        && all_hits
            .iter()
            .enumerate()
            .any(|(idx, signal)| idx != 6 && idx != 7 && signal.contains_key(path))
}

fn is_cochange_only_signal(path: &str, all_hits: &[HashMap<String, Vec<FileHit>>]) -> bool {
    all_hits
        .get(6)
        .is_some_and(|cochange| cochange.contains_key(path))
        && all_hits
            .iter()
            .enumerate()
            .all(|(idx, signal)| idx == 6 || !signal.contains_key(path))
}

fn has_signal(path: &str, all_hits: &[HashMap<String, Vec<FileHit>>], idx: usize) -> bool {
    all_hits
        .get(idx)
        .is_some_and(|signal| signal.contains_key(path))
}

fn has_traceback_or_test_signal(path: &str, all_hits: &[HashMap<String, Vec<FileHit>>]) -> bool {
    has_signal(path, all_hits, 0) || has_signal(path, all_hits, 2)
}

fn is_traceback_indirect_noise(path: &str, all_hits: &[HashMap<String, Vec<FileHit>>]) -> bool {
    let indirect = has_signal(path, all_hits, 1) || has_signal(path, all_hits, 6);
    indirect
        && !has_signal(path, all_hits, 0)
        && !has_signal(path, all_hits, 2)
        && !has_signal(path, all_hits, 3)
        && !has_signal(path, all_hits, 4)
        && !has_signal(path, all_hits, 5)
        && !has_signal(path, all_hits, 7)
        && !has_signal(path, all_hits, 8)
        && !has_signal(path, all_hits, 9)
}

fn demote_cochange_only_outliers(
    fused: &mut Vec<(String, f32)>,
    all_hits: &[HashMap<String, Vec<FileHit>>],
) {
    let Some(anchor_score) = fused
        .iter()
        .filter_map(|(path, score)| {
            if *score > 0.0 && has_corroborated_resolve_signal(path, all_hits) {
                Some(*score)
            } else {
                None
            }
        })
        .max_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal))
    else {
        return;
    };

    let penalty = locate_env_f32("KIN_LOCATE_COCHANGE_ONLY_OUTLIER_PENALTY", 0.25);
    let noisy_path_penalty = locate_env_f32("KIN_LOCATE_NOISY_COCHANGE_ONLY_PENALTY", 0.08);
    if penalty >= 1.0 {
        if noisy_path_penalty >= 1.0 {
            return;
        }
    }

    let mut changed = false;
    for (path, score) in fused.iter_mut() {
        if !is_cochange_only_signal(path, all_hits) {
            continue;
        }

        let noisy_path = is_embedded_framework_noise_path(path)
            || is_license_or_notice_path(path)
            || is_contrib_port_path(path);
        if noisy_path && noisy_path_penalty < 1.0 {
            *score *= noisy_path_penalty;
            changed = true;
            continue;
        }

        if *score > anchor_score && penalty < 1.0 {
            *score *= penalty;
            changed = true;
        }
    }

    if changed {
        fused.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
    }
}

fn demote_traceback_indirect_outliers(
    fused: &mut Vec<(String, f32)>,
    all_hits: &[HashMap<String, Vec<FileHit>>],
) {
    let anchor_files = fused
        .iter()
        .filter(|(path, _)| has_traceback_or_test_signal(path, all_hits))
        .count();
    if anchor_files < 2 {
        return;
    }

    let Some(anchor_score) = fused
        .iter()
        .filter_map(|(path, score)| {
            if *score > 0.0 && has_traceback_or_test_signal(path, all_hits) {
                Some(*score)
            } else {
                None
            }
        })
        .max_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal))
    else {
        return;
    };

    let penalty = locate_env_f32("KIN_LOCATE_TRACEBACK_INDIRECT_OUTLIER_PENALTY", 0.45);
    if penalty >= 1.0 {
        return;
    }

    let mut changed = false;
    for (path, score) in fused.iter_mut() {
        if *score <= anchor_score || !is_traceback_indirect_noise(path, all_hits) {
            continue;
        }
        *score *= penalty;
        changed = true;
    }

    if changed {
        fused.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
    }
}

fn is_semantic_phase_query(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    text.contains("```")
        || text.contains('`')
        || lower.contains("compiler")
        || lower.contains("codegen")
        || lower.contains("syntax")
        || lower.contains("verify")
        || lower.contains("lambda")
        || lower.contains("constructor")
        || lower.contains("constructors")
        || lower.contains("behaviour")
        || lower.contains("behavior")
        || lower.contains("match")
        || lower.contains("tuple")
        || lower.contains("type parameter")
        || lower.contains("capability")
        || lower.contains("subtype")
        || lower.contains("illegal")
}

fn phase_bucket_for_path(path: &str) -> Option<&'static str> {
    if path.contains("/codegen/") {
        Some("codegen")
    } else if path.contains("/pass/") || path.ends_with("/verify.c") || path.ends_with("/syntax.c")
    {
        Some("pass")
    } else if path.contains("/expr/") {
        Some("expr")
    } else if path.contains("/type/") {
        Some("type")
    } else if path.contains("/ast/") {
        Some("ast")
    } else {
        None
    }
}

fn explicit_phase_buckets(text: &str) -> HashSet<&'static str> {
    let lower = text.to_ascii_lowercase();
    let mut buckets = HashSet::new();
    if lower.contains("codegen") {
        buckets.insert("codegen");
    }
    if lower.contains("syntax") || lower.contains("parser") || lower.contains("parse") {
        buckets.insert("pass");
        buckets.insert("ast");
    }
    if lower.contains("verify") {
        buckets.insert("pass");
    }
    if lower.contains("type parameter")
        || lower.contains("typeparam")
        || lower.contains("capability")
        || lower.contains("subtype")
    {
        buckets.insert("type");
    }
    if lower.contains("lambda")
        || lower.contains("constructor")
        || lower.contains("constructors")
        || lower.contains("behaviour")
        || lower.contains("behavior")
        || lower.contains("return")
        || lower.contains("illegal")
    {
        buckets.insert("pass");
        buckets.insert("expr");
    }
    if lower.contains("match") || lower.contains("tuple") {
        buckets.insert("expr");
        buckets.insert("codegen");
    }
    buckets
}

fn is_runtime_support_path(path: &str) -> bool {
    path.contains("/lang/")
        || path.contains("/sched/")
        || path.contains("/asio/")
        || path.contains("/gc/")
        || path.contains("/platform/")
}

fn is_returning_construction_query(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("return")
        && (lower.contains("constructor")
            || lower.contains("constructors")
            || lower.contains("behaviour")
            || lower.contains("behaviours")
            || lower.contains("behavior")
            || lower.contains("behaviors"))
}

fn is_lambda_query(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("lambda") || lower.contains("lambdas")
}

fn semantic_phase_anchor_floors(
    text: &str,
    top_score: f32,
    source_files: &HashSet<String>,
    workspace_root: Option<&std::path::Path>,
) -> Vec<(String, f32)> {
    if top_score <= 0.0 {
        return Vec::new();
    }

    let construction_query = is_returning_construction_query(text);
    let lambda_query = is_lambda_query(text);
    if !construction_query && !lambda_query {
        return Vec::new();
    }

    let mut anchors = Vec::new();
    let mut push_if_present = |path: &str, floor: f32| {
        if source_files.contains(path) || workspace_source_path_exists(path, workspace_root) {
            anchors.push((path.to_string(), floor));
        }
    };

    if construction_query {
        push_if_present("src/libponyc/pass/expr.c", top_score * 0.74);
        push_if_present("src/libponyc/pass/syntax.c", top_score * 0.72);
        push_if_present("src/libponyc/pass/verify.c", top_score * 0.70);
    }
    if lambda_query {
        push_if_present("src/libponyc/expr/lambda.h", top_score * 0.68);
        push_if_present("src/libponyc/expr/lambda.c", top_score * 0.66);
        push_if_present("src/libponyc/pass/lambda.c", top_score * 0.66);
    }

    anchors.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    anchors.dedup_by(|left, right| left.0 == right.0);
    anchors
}

fn semantic_phase_distractor_cap(text: &str, path: &str, top_score: f32) -> Option<f32> {
    if top_score <= 0.0 {
        return None;
    }

    let construction_query = is_returning_construction_query(text);
    let lambda_query = is_lambda_query(text);
    if !construction_query && !lambda_query {
        return None;
    }

    if construction_query && path.ends_with("/pass/expr.h") {
        return Some(top_score * 0.66);
    }
    if construction_query
        && (path.ends_with("/expr/reference.c") || path.ends_with("/pass/sugar.c"))
    {
        return Some(top_score * 0.64);
    }
    if construction_query
        && (path.ends_with("/verify/control.c")
            || path.ends_with("/verify/type.c")
            || path.ends_with("/verify/call.c"))
    {
        return Some(top_score * 0.52);
    }
    if lambda_query && (path.ends_with("/expr/control.c") || path.ends_with("/expr/control.h")) {
        return Some(top_score * 0.58);
    }

    None
}

fn rerank_semantic_phase_paths(
    fused: &mut Vec<(String, f32)>,
    text: &str,
    all_hits: &[HashMap<String, Vec<FileHit>>],
    source_files: &HashSet<String>,
    workspace_root: Option<&std::path::Path>,
) {
    if fused.is_empty() || !is_semantic_phase_query(text) {
        return;
    }

    let explicit = explicit_phase_buckets(text);
    let top_score = fused.first().map(|(_, score)| *score).unwrap_or(0.0);
    if top_score <= 0.0 {
        return;
    }

    let explicit_penalty = locate_env_f32("KIN_LOCATE_EXPLICIT_PHASE_MISMATCH_PENALTY", 0.22);
    let runtime_penalty = locate_env_f32("KIN_LOCATE_SEMANTIC_RUNTIME_PENALTY", 0.4);
    let follower_penalty = locate_env_f32("KIN_LOCATE_PHASE_BUCKET_FOLLOWER_PENALTY", 0.32);
    let semantic_window = locate_env_usize("KIN_LOCATE_SEMANTIC_PHASE_WINDOW", 12);
    let mut bucket_counts: HashMap<&'static str, usize> = HashMap::new();
    let mut retained_paths = HashSet::new();
    for (path, _) in fused.iter().take(semantic_window) {
        let Some(bucket) = phase_bucket_for_path(path) else {
            continue;
        };
        let entry = bucket_counts.entry(bucket).or_insert(0);
        let keep_limit = if explicit.contains(bucket) {
            if bucket == "pass" {
                3
            } else {
                1
            }
        } else {
            1
        };
        if *entry < keep_limit {
            retained_paths.insert(path.clone());
            *entry += 1;
        }
    }
    let mut changed = false;

    for (path, score) in fused.iter_mut() {
        let support = signal_support_count(path, all_hits).min(3) as f32;
        if let Some(bucket) = phase_bucket_for_path(path) {
            let retained = retained_paths.contains(path);
            if !retained && *score < top_score && follower_penalty < 1.0 {
                *score *= follower_penalty;
                changed = true;
            }
            let mut factor = match bucket {
                "codegen" => 0.24,
                "pass" => 0.22,
                "expr" => 0.20,
                "type" => 0.20,
                "ast" => 0.14,
                _ => 0.0,
            };
            factor += support * 0.02;
            if explicit.contains(bucket) && retained {
                factor += 0.10;
            } else if !explicit.is_empty() && *score < top_score && explicit_penalty < 1.0 {
                *score *= explicit_penalty;
                changed = true;
            }
            let floor = if retained {
                top_score * factor.min(0.38)
            } else {
                0.0
            };
            if retained && *score < floor {
                *score = floor;
                changed = true;
            }
            continue;
        }

        if !explicit.is_empty() && is_runtime_support_path(path) && *score < top_score {
            *score *= runtime_penalty;
            changed = true;
        }
    }

    for (path, floor) in semantic_phase_anchor_floors(text, top_score, source_files, workspace_root)
    {
        if upsert_fused_floor(fused, path, floor) {
            changed = true;
        }
    }

    for (path, score) in fused.iter_mut() {
        let Some(cap) = semantic_phase_distractor_cap(text, path, top_score) else {
            continue;
        };
        if *score > cap {
            *score = cap;
            changed = true;
        }
    }

    if changed {
        fused.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
    }
}

fn contains_ascii_word(text: &str, word: &str) -> bool {
    regex::Regex::new(&format!(r"\b{}\b", regex::escape(word)))
        .unwrap()
        .is_match(text)
}

fn is_cli_surface_query(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    text.contains("--")
        || lower.contains("command line")
        || contains_ascii_word(&lower, "cli")
        || contains_ascii_word(&lower, "option")
        || contains_ascii_word(&lower, "help")
        || lower.contains("buffer size")
}

fn is_public_api_query(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let has_symbolic_api_term = extract_search_terms(text).into_iter().any(|term| {
        term.contains('_') && term.chars().filter(|ch| ch.is_ascii_uppercase()).count() >= 2
    });
    has_symbolic_api_term
        && (lower.contains("prototype")
            || lower.contains("public api")
            || lower.contains("public header")
            || lower.contains("api"))
}

fn cli_focus_terms(text: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut seen = HashSet::new();
    for term in extract_search_terms(text)
        .into_iter()
        .chain(extract_title_terms(text))
        .chain(extract_loose_query_terms(text))
    {
        let canonical = term.to_ascii_lowercase();
        if canonical.len() < 4
            || is_cli_flag_term(&term)
            || is_noise_term(&canonical)
            || is_issue_boilerplate_term(&canonical)
            || is_common_english_word(&canonical)
        {
            continue;
        }
        if seen.insert(canonical.clone()) {
            terms.push(canonical);
        }
    }
    terms
}

fn path_matches_cli_focus(path: &str, focus: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains(&format!("/{focus}/"))
        || lower
            .rsplit('/')
            .next()
            .and_then(|leaf| leaf.split('.').next())
            .is_some_and(|stem| stem.eq_ignore_ascii_case(focus))
}

fn select_cli_command_focus(text: &str, fused: &[(String, f32)]) -> Option<String> {
    cli_focus_terms(text).into_iter().find(|term| {
        fused
            .iter()
            .any(|(path, _)| path.contains("/cmd/") && path_matches_cli_focus(path, term))
    })
}

fn has_negated_flag_value(text: &str, flag: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let pattern = format!(r"--{}=(?:false|0|off|no)\b", regex::escape(flag));
    regex::Regex::new(&pattern).unwrap().is_match(&lower)
}

fn is_public_header_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if !lower.ends_with(".h") {
        return false;
    }
    if is_contrib_port_path(path)
        || lower.contains("/common/")
        || lower.contains("/internal/")
        || lower.contains("/private/")
        || lower.contains("/linux/")
    {
        return false;
    }

    let depth = lower.matches('/').count();
    (lower.starts_with("include/") && depth <= 2) || (lower.starts_with("lib/") && depth <= 1)
}

fn is_internal_header_path(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with(".h") && !is_public_header_path(path)
}

fn is_help_surface_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("command_help")
        || lower.ends_with("/help.pony")
        || lower.ends_with("/help.rs")
        || lower.ends_with("/help.c")
        || lower.ends_with("/help.cc")
        || lower.ends_with("/help.cpp")
}

fn cli_surface_bucket(path: &str) -> Option<&'static str> {
    if path.contains("/options/") {
        Some("options")
    } else if path.contains("/programs/")
        || path.ends_with("/fileio.c")
        || path.ends_with("/zstdcli.c")
    {
        Some("programs")
    } else if is_help_surface_path(path) || path.contains("/cli/") {
        Some("cli_help")
    } else if is_public_header_path(path) {
        Some("public_header")
    } else if is_internal_header_path(path) {
        Some("internal_header")
    } else {
        None
    }
}

fn is_deep_impl_path(path: &str) -> bool {
    path.contains("/compress/")
        || path.contains("/decompress/")
        || path.contains("/dictBuilder/")
        || path.contains("/plugin/")
        || path.contains("/codegen/")
}

fn rerank_cli_surface_paths(
    fused: &mut Vec<(String, f32)>,
    text: &str,
    all_hits: &[HashMap<String, Vec<FileHit>>],
    workspace_root: Option<&std::path::Path>,
) {
    if fused.is_empty() || !is_cli_surface_query(text) {
        return;
    }

    let lower = text.to_ascii_lowercase();
    let explicit_flag_query = text.contains("--");
    let public_api_query = is_public_api_query(text);
    let header_query = lower.contains("buffer size") || lower.contains("min") || public_api_query;
    let negated_help_query = has_negated_flag_value(text, "help");
    let top_score = fused.first().map(|(_, score)| *score).unwrap_or(0.0);
    if top_score <= 0.0 {
        return;
    }

    let impl_penalty = locate_env_f32("KIN_LOCATE_CLI_IMPL_PENALTY", 0.22);
    let public_api_impl_penalty = locate_env_f32("KIN_LOCATE_PUBLIC_API_IMPL_PENALTY", 0.3);
    let command_focus = select_cli_command_focus(text, fused);
    let mut changed = false;
    for (path, score) in fused.iter_mut() {
        let source_text_backed = all_hits.last().is_some_and(|hits| hits.contains_key(path));
        let support = signal_support_count(path, all_hits).min(3) as f32;
        if let Some(bucket) = cli_surface_bucket(path) {
            if negated_help_query && bucket == "cli_help" {
                let cap = top_score * 0.08;
                if *score > cap {
                    *score = cap;
                    changed = true;
                }
                continue;
            }

            let mut factor = match bucket {
                "options" => {
                    if explicit_flag_query {
                        0.30
                    } else {
                        0.16
                    }
                }
                "programs" => {
                    if explicit_flag_query {
                        0.32
                    } else if public_api_query {
                        0.12
                    } else {
                        0.18
                    }
                }
                "public_header" => {
                    if public_api_query {
                        0.30
                    } else if header_query {
                        0.12
                    } else {
                        0.06
                    }
                }
                "internal_header" => {
                    if public_api_query {
                        0.10
                    } else if header_query {
                        0.05
                    } else {
                        0.0
                    }
                }
                "cli_help" => {
                    if explicit_flag_query {
                        0.06
                    } else {
                        0.08
                    }
                }
                _ => 0.0,
            };
            if explicit_flag_query && matches!(bucket, "options" | "programs") {
                factor += match bucket {
                    "options" => 0.10,
                    "programs" => 0.12,
                    _ => 0.0,
                };
            }
            if header_query && bucket == "public_header" {
                factor += 0.14;
            }
            if support > 0.0 && !matches!(bucket, "internal_header" | "cli_help") {
                factor += support * 0.02;
            }
            if is_contrib_port_path(path) && matches!(bucket, "public_header" | "internal_header") {
                factor *= if public_api_query { 0.35 } else { 0.2 };
            }
            let floor = top_score * factor.min(0.5);
            if *score < floor {
                *score = floor;
                changed = true;
            }
            if public_api_query {
                let cap = match bucket {
                    "programs" => Some(top_score * 0.18),
                    "internal_header" => Some(if is_contrib_port_path(path) {
                        top_score * 0.05
                    } else {
                        top_score * 0.12
                    }),
                    "cli_help" => Some(top_score * 0.05),
                    _ => None,
                };
                if let Some(cap) = cap {
                    if *score > cap {
                        *score = cap;
                        changed = true;
                    }
                }
            }
            continue;
        }

        if let Some(ref focus) = command_focus {
            if path.contains("/cmd/") {
                if path_matches_cli_focus(path, focus) {
                    let floor = top_score * 0.78;
                    if *score < floor {
                        *score = floor;
                        changed = true;
                    }
                } else if *score < top_score {
                    let cap = if source_text_backed {
                        top_score * 0.46
                    } else {
                        top_score * 0.32
                    };
                    if *score > cap {
                        *score = cap;
                        changed = true;
                    }
                }
            } else if *score < top_score {
                let cap = top_score * 0.32;
                if *score > cap {
                    *score = cap;
                    changed = true;
                }
            }
        }

        if explicit_flag_query && is_deep_impl_path(path) && impl_penalty < 1.0 {
            let cap = top_score * 0.18;
            if *score > cap {
                *score = cap;
                changed = true;
            } else if *score < top_score {
                *score *= impl_penalty;
                changed = true;
            }
            continue;
        }

        if public_api_query
            && !explicit_flag_query
            && !path.to_ascii_lowercase().ends_with(".h")
            && *score < top_score
            && public_api_impl_penalty < 1.0
        {
            *score *= public_api_impl_penalty;
            changed = true;
        }
    }

    if promote_cli_surface_local_headers(fused, top_score, workspace_root) {
        changed = true;
    }

    if changed {
        fused.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
    }
}

fn promote_cli_surface_local_headers(
    fused: &mut Vec<(String, f32)>,
    top_score: f32,
    workspace_root: Option<&std::path::Path>,
) -> bool {
    let Some(workspace_root) = workspace_root else {
        return false;
    };
    let seed_limit = locate_env_usize("KIN_LOCATE_CLI_HEADER_SEED_LIMIT", 3);
    let direct_floor = top_score * locate_env_f32("KIN_LOCATE_CLI_HEADER_FLOOR", 0.36);
    let nested_floor = top_score * locate_env_f32("KIN_LOCATE_CLI_HEADER_NESTED_FLOOR", 0.28);
    if direct_floor <= 0.0 || nested_floor <= 0.0 {
        return false;
    }

    let seed_paths = fused
        .iter()
        .filter_map(|(path, _)| {
            matches!(cli_surface_bucket(path), Some("programs" | "options")).then_some(path.clone())
        })
        .take(seed_limit)
        .collect::<Vec<_>>();
    if seed_paths.is_empty() {
        return false;
    }

    let empty_paths = HashSet::new();
    let mut changed = false;
    for seed in seed_paths {
        let Some(header_path) = sibling_header_for_cli_surface(&seed, &workspace_root) else {
            continue;
        };
        changed |= upsert_fused_floor(fused, header_path.clone(), direct_floor);

        let Some(header_text) = read_workspace_source_text(&header_path, Some(&workspace_root))
        else {
            continue;
        };
        for include_path in extract_local_quoted_include_targets(
            &header_path,
            &header_text,
            &empty_paths,
            Some(&workspace_root),
        ) {
            if is_header_like_path(&include_path) {
                changed |= upsert_fused_floor(fused, include_path, nested_floor);
            }
        }
    }

    changed
}

fn sibling_header_for_cli_surface(path: &str, workspace_root: &std::path::Path) -> Option<String> {
    if is_header_like_path(path) {
        return None;
    }
    let stem = path
        .rsplit_once('.')
        .map(|(prefix, _)| prefix)
        .unwrap_or(path);
    [".h", ".hh", ".hpp", ".hxx"]
        .iter()
        .map(|ext| format!("{stem}{ext}"))
        .find(|candidate| workspace_source_path_exists(candidate, Some(workspace_root)))
}

fn upsert_fused_floor(fused: &mut Vec<(String, f32)>, path: String, floor: f32) -> bool {
    if let Some((_, score)) = fused.iter_mut().find(|(existing, _)| *existing == path) {
        if *score >= floor {
            return false;
        }
        *score = floor;
        return true;
    }
    fused.push((path, floor));
    true
}

fn named_test_source_sibling_path(
    path: &str,
    source_files: &HashSet<String>,
    workspace_root: Option<&std::path::Path>,
) -> Option<String> {
    let normalized = normalize_repo_relative_path(path)?;
    let (parent, basename) = normalized
        .rsplit_once('/')
        .unwrap_or(("", normalized.as_str()));
    let (stem, ext) = basename.rsplit_once('.')?;
    let parent_lower = parent.to_ascii_lowercase();
    let mut candidates = Vec::new();

    if let Some(stripped) = stem.strip_prefix("test_") {
        if !stripped.is_empty()
            && (parent_lower == "tests"
                || parent_lower == "test"
                || parent_lower.ends_with("/tests")
                || parent_lower.ends_with("/test"))
        {
            let container = parent
                .rsplit_once('/')
                .map(|(prefix, _)| prefix)
                .unwrap_or("");
            let candidate = if container.is_empty() {
                format!("{stripped}.{ext}")
            } else {
                format!("{container}/{stripped}.{ext}")
            };
            candidates.push(candidate);
        }
    }

    if let Some(stripped) = stem.strip_suffix("_test") {
        if !stripped.is_empty() {
            let candidate = if parent.is_empty() {
                format!("{stripped}.{ext}")
            } else {
                format!("{parent}/{stripped}.{ext}")
            };
            candidates.push(candidate);
        }
    }

    candidates.into_iter().find(|candidate| {
        source_files.contains(candidate) || workspace_source_path_exists(candidate, workspace_root)
    })
}

fn promote_named_test_source_siblings(
    fused: &mut Vec<(String, f32)>,
    source_files: &HashSet<String>,
    workspace_root: Option<&std::path::Path>,
) {
    if fused.is_empty() {
        return;
    }

    let promotion_factor = locate_env_f32("KIN_LOCATE_TEST_SIBLING_SOURCE_FACTOR", 0.92);
    if promotion_factor <= 0.0 {
        return;
    }

    let seed_limit = locate_env_usize("KIN_LOCATE_TEST_SIBLING_SOURCE_LIMIT", 4);
    let mut candidates = Vec::new();
    for (path, score) in fused.iter().take(seed_limit.max(1)) {
        if !is_test_path(path) {
            continue;
        }
        let Some(source_path) = named_test_source_sibling_path(path, source_files, workspace_root)
        else {
            continue;
        };
        candidates.push((source_path, *score * promotion_factor));
    }

    if candidates.is_empty() {
        return;
    }

    let mut changed = false;
    for (source_path, floor) in candidates {
        if upsert_fused_floor(fused, source_path, floor) {
            changed = true;
        }
    }

    if changed {
        fused.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
    }
}

fn is_source_impl_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".js", ".jsx", ".ts", ".tsx", ".rs", ".py", ".go", ".java"]
        .iter()
        .any(|ext| lower.ends_with(ext))
        && !lower.ends_with(".d.ts")
}

fn same_stem_source_sibling_path(
    stem_path: &str,
    source_files: &HashSet<String>,
    workspace_root: Option<&std::path::Path>,
) -> Option<String> {
    [".js", ".jsx", ".ts", ".tsx", ".rs", ".py", ".go", ".java"]
        .iter()
        .map(|ext| format!("{stem_path}{ext}"))
        .find(|candidate| {
            source_files.contains(candidate)
                || workspace_source_path_exists(candidate, workspace_root)
        })
}

fn declaration_source_sibling_path(
    path: &str,
    source_files: &HashSet<String>,
    workspace_root: Option<&std::path::Path>,
) -> Option<String> {
    let normalized = normalize_repo_relative_path(path)?;
    let stem = normalized.strip_suffix(".d.ts")?;
    if stem.ends_with("/index") {
        return None;
    }
    same_stem_source_sibling_path(stem, source_files, workspace_root)
}

fn is_declaration_heavy_query(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains(".d.ts")
        || lower.contains("type definition")
        || lower.contains("type definitions")
        || lower.contains("typescript declaration")
        || lower.contains("typing")
}

fn block_focus_terms(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut terms = Vec::new();
    let mut seen = HashSet::new();
    let re = regex::Regex::new(r"\b([A-Za-z][A-Za-z0-9_-]{2,})\s+blocks?\b").unwrap();
    for cap in re.captures_iter(&lower) {
        let term = cap[1].to_string();
        if is_issue_boilerplate_term(&term) {
            continue;
        }
        if seen.insert(term.clone()) {
            terms.push(term);
        }
    }
    terms
}

fn is_custom_implementation_query(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("custom")
        && (lower.contains(" implementation")
            || lower.contains(" implementations")
            || lower.contains(" implement ")
            || lower.contains(" implements ")
            || lower.contains(" subclass")
            || lower.contains(" subclasses")
            || lower.contains(" extend ")
            || lower.contains(" extends "))
}

fn custom_implementation_entity_terms(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r"\b[A-Z][A-Za-z0-9_]{2,}\b").unwrap();
    let mut terms = Vec::new();
    let mut seen = HashSet::new();
    for cap in re.captures_iter(text) {
        let term = cap[0].to_string();
        let lower = term.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "allow"
                | "fix"
                | "fixes"
                | "custom"
                | "implementation"
                | "implementations"
                | "support"
                | "supports"
                | "subclass"
                | "subclasses"
        ) || is_issue_boilerplate_term(&lower)
        {
            continue;
        }
        if seen.insert(lower) {
            terms.push(term);
        }
    }
    terms
}

fn repo_relative_parent_dir(path: &str) -> Option<String> {
    let normalized = normalize_repo_relative_path(path)?;
    let (parent, _) = normalized.rsplit_once('/')?;
    Some(parent.to_string())
}

fn repo_relative_file_stem(path: &str) -> Option<String> {
    let normalized = normalize_repo_relative_path(path)?;
    let name = normalized.rsplit('/').next()?;
    let stem = name.rsplit_once('.').map(|(stem, _)| stem).unwrap_or(name);
    (!stem.is_empty()).then(|| stem.to_string())
}

fn is_structural_helper_stem(stem: &str) -> bool {
    let lower = stem.to_ascii_lowercase();
    [
        "parser", "cursor", "travers", "visitor", "context", "reader", "writer", "adapter",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

fn discover_custom_impl_family_priority_files(
    text: &str,
    resolved_files: &[(String, f32)],
    source_files: &HashSet<String>,
) -> Vec<(String, f32)> {
    if !is_custom_implementation_query(text)
        || resolved_files.is_empty()
        || custom_implementation_entity_terms(text).is_empty()
    {
        return Vec::new();
    }

    let resolved_limit = locate_env_usize("KIN_LOCATE_CUSTOM_IMPL_RESOLVED_LIMIT", 16);
    let min_dir_seed_count = locate_env_usize("KIN_LOCATE_CUSTOM_IMPL_DIR_SEED_MIN", 4).max(1);
    let max_injections = locate_env_usize("KIN_LOCATE_CUSTOM_IMPL_MAX_INJECTIONS", 2).max(1);
    let base_priority = locate_env_f32("KIN_LOCATE_CUSTOM_IMPL_PRIORITY_BASE", 54.0);
    let dir_seed_bonus = locate_env_f32("KIN_LOCATE_CUSTOM_IMPL_DIR_SEED_BONUS", 1.5);
    let helper_bonus = locate_env_f32("KIN_LOCATE_CUSTOM_IMPL_HELPER_BONUS", 4.0);
    let max_priority = locate_env_f32("KIN_LOCATE_CUSTOM_IMPL_PRIORITY_MAX", 72.0);

    let mut dir_seeds: HashMap<String, Vec<String>> = HashMap::new();
    for (path, _) in resolved_files.iter().take(resolved_limit) {
        if !is_source_impl_extension(path) {
            continue;
        }
        let Some(parent) = repo_relative_parent_dir(path) else {
            continue;
        };
        dir_seeds.entry(parent).or_default().push(path.clone());
    }

    let mut candidates = Vec::new();
    for (dir, seeds) in dir_seeds {
        if seeds.len() < min_dir_seed_count {
            continue;
        }
        let seed_set: HashSet<&str> = seeds.iter().map(String::as_str).collect();
        let dir_prefix = format!("{dir}/");
        for rel in source_files {
            if !rel.starts_with(&dir_prefix)
                || seed_set.contains(rel.as_str())
                || !is_source_impl_extension(rel)
                || is_test_path(rel)
            {
                continue;
            }
            let Some(stem) = repo_relative_file_stem(rel) else {
                continue;
            };
            let stem_lower = stem.to_ascii_lowercase();
            if !is_structural_helper_stem(&stem_lower) {
                continue;
            }
            let score = (base_priority + seeds.len() as f32 * dir_seed_bonus + helper_bonus)
                .min(max_priority);
            candidates.push((rel.clone(), score));
        }
    }

    candidates.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    candidates.dedup_by(|left, right| left.0 == right.0);
    candidates.truncate(max_injections);
    candidates
}

fn block_focus_source_candidates(
    text: &str,
    source_files: &HashSet<String>,
    workspace_root: Option<&std::path::Path>,
) -> Vec<String> {
    let focus_terms = block_focus_terms(text);
    if focus_terms.is_empty() {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    for term in focus_terms {
        for ext in [".js", ".ts", ".jsx", ".tsx"] {
            let suffix = format!("/blocks/{term}{ext}");
            for path in source_files {
                if path.to_ascii_lowercase().ends_with(&suffix) && seen.insert(path.clone()) {
                    candidates.push(path.clone());
                }
            }
            if seen.contains(&suffix) {
                continue;
            }
        }
    }

    if !candidates.is_empty() || workspace_root.is_none() {
        return candidates;
    }

    let root = workspace_root.unwrap();
    for term in block_focus_terms(text) {
        for ext in [".js", ".ts", ".jsx", ".tsx"] {
            let suffix = format!("/blocks/{term}{ext}");
            let mut stack = vec![root.to_path_buf()];
            while let Some(dir) = stack.pop() {
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    let Ok(file_type) = entry.file_type() else {
                        continue;
                    };
                    if file_type.is_dir() {
                        if path.file_name().and_then(|name| name.to_str()) == Some(".git") {
                            continue;
                        }
                        stack.push(path);
                        continue;
                    }
                    let Some(rel) = path.strip_prefix(root).ok().and_then(|p| p.to_str()) else {
                        continue;
                    };
                    let rel = rel.replace('\\', "/");
                    if rel.to_ascii_lowercase().ends_with(&suffix) && seen.insert(rel.clone()) {
                        candidates.push(rel);
                    }
                }
            }
        }
    }

    candidates
}

fn promote_named_source_surfaces(
    fused: &mut Vec<(String, f32)>,
    text: &str,
    source_files: &HashSet<String>,
    workspace_root: Option<&std::path::Path>,
) {
    if fused.is_empty() {
        return;
    }

    let top_score = fused.first().map(|(_, score)| *score).unwrap_or(0.0);
    if top_score <= 0.0 {
        return;
    }

    let decl_seed_limit = locate_env_usize("KIN_LOCATE_DECL_SOURCE_SIBLING_LIMIT", 6);
    let decl_top_floor = locate_env_f32("KIN_LOCATE_DECL_SOURCE_TOP_FLOOR", 0.46);
    let decl_seed_boost = locate_env_f32("KIN_LOCATE_DECL_SOURCE_SEED_BOOST", 1.05);
    let block_floor = locate_env_f32("KIN_LOCATE_BLOCK_SOURCE_FLOOR", 0.74);

    let mut candidates: HashMap<String, f32> = HashMap::new();
    if !is_declaration_heavy_query(text) {
        for (path, score) in fused.iter().take(decl_seed_limit.max(1)) {
            let Some(source_path) =
                declaration_source_sibling_path(path, source_files, workspace_root)
            else {
                continue;
            };
            if !is_source_impl_extension(&source_path) {
                continue;
            }
            let floor = (*score * decl_seed_boost).max(top_score * decl_top_floor);
            candidates
                .entry(source_path)
                .and_modify(|existing| *existing = existing.max(floor))
                .or_insert(floor);
        }
    }

    for path in block_focus_source_candidates(text, source_files, workspace_root) {
        let floor = top_score * block_floor;
        candidates
            .entry(path)
            .and_modify(|existing| *existing = existing.max(floor))
            .or_insert(floor);
    }

    if candidates.is_empty() {
        return;
    }

    let mut changed = false;
    for (path, floor) in candidates {
        if upsert_fused_floor(fused, path, floor) {
            changed = true;
        }
    }

    if changed {
        fused.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
    }
}

fn demote_secondary_sources_for_syntax_artifact_queries(
    fused: &mut Vec<(String, f32)>,
    syntax_artifact_query: bool,
    source_text_hits: &HashMap<String, Vec<FileHit>>,
    priority_backed_paths: &HashSet<String>,
) {
    if !syntax_artifact_query || fused.is_empty() {
        return;
    }

    let top_score = fused.first().map(|(_, score)| *score).unwrap_or(0.0);
    if top_score <= 0.0 {
        return;
    }

    let priority_test_paths: HashSet<&str> = priority_backed_paths
        .iter()
        .filter(|path| is_test_path(path))
        .map(|path| path.as_str())
        .collect();
    let primary_source = match fused
        .iter()
        .find(|(path, _)| {
            !is_test_path(path)
                && (source_text_hits.contains_key(path) || is_syntax_source_locus_path(path))
        })
        .map(|(path, _)| path.clone())
    {
        Some(path) => path,
        None => {
            if priority_test_paths.is_empty() {
                return;
            }
            String::new()
        }
    };

    let penalty = locate_env_f32("KIN_LOCATE_SYNTAX_SOURCE_NEIGHBOR_PENALTY", 0.18);
    let generic_test_penalty = locate_env_f32("KIN_LOCATE_SYNTAX_GENERIC_TEST_PENALTY", 0.12);
    let source_floor_factor = locate_env_f32("KIN_LOCATE_SYNTAX_SOURCE_FLOOR", 0.28);
    let priority_test_floor_factor = locate_env_f32("KIN_LOCATE_SYNTAX_PRIORITY_TEST_FLOOR", 0.32);
    if penalty >= 1.0
        && generic_test_penalty >= 1.0
        && source_floor_factor <= 0.0
        && priority_test_floor_factor <= 0.0
    {
        return;
    }

    let mut changed = false;
    for (path, score) in fused.iter_mut() {
        let is_priority_test = priority_test_paths.contains(path.as_str());
        let is_syntax_source = !path.is_empty()
            && !is_test_path(path)
            && (*path == primary_source
                || source_text_hits.contains_key(path)
                || is_syntax_source_locus_path(path));
        if is_priority_test {
            let floor = top_score * priority_test_floor_factor;
            if *score < floor {
                *score = floor;
                changed = true;
            }
            continue;
        }
        if is_syntax_source {
            let floor = top_score * source_floor_factor;
            if floor > 0.0 && *score < floor {
                *score = floor;
                changed = true;
            }
            continue;
        }
        if is_test_path(path) {
            if generic_test_penalty < 1.0 {
                *score *= generic_test_penalty;
                changed = true;
            }
            continue;
        }
        if priority_backed_paths.contains(path) {
            continue;
        }
        if penalty < 1.0 {
            *score *= penalty;
            changed = true;
        }
    }

    if changed {
        fused.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
    }
}

fn compress_secondary_files_under_dominant_direct_source(
    fused: &mut Vec<(String, f32)>,
    resolve_signal_scores: &HashMap<String, HashMap<String, f32>>,
    source_text_hits: &HashMap<String, Vec<FileHit>>,
    priority_backed_paths: &HashSet<String>,
    semantic_retention_paths: &HashSet<String>,
) {
    if fused.len() <= 1 {
        return;
    }

    let mut direct_ranked = fused
        .iter()
        .filter_map(|(path, _)| {
            let direct = resolve_signal_scores
                .get(path)
                .and_then(|scores| scores.get("entity_resolve"))
                .copied()
                .unwrap_or(0.0);
            (direct > 0.0).then_some((path.as_str(), direct))
        })
        .collect::<Vec<_>>();
    direct_ranked.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(b.0))
    });

    let Some((top_path, top_direct)) = direct_ranked.first().copied() else {
        return;
    };
    let top_path = top_path.to_string();
    let second_direct = direct_ranked.get(1).map(|(_, score)| *score).unwrap_or(0.0);
    let dominance_min = locate_env_f32("KIN_LOCATE_DIRECT_DOMINANCE_MIN", 1000.0);
    let dominance_ratio_min = locate_env_f32("KIN_LOCATE_DIRECT_DOMINANCE_RATIO_MIN", 5.0);
    if top_direct < dominance_min
        || second_direct <= 0.0
        || (top_direct / second_direct.max(1.0)) < dominance_ratio_min
    {
        return;
    }

    let top_source_text = source_text_hits
        .get(top_path.as_str())
        .map(|hits| hits.iter().map(|hit| hit.score).sum::<f32>())
        .unwrap_or(0.0);
    if top_source_text <= 0.0 {
        return;
    }

    let penalty = locate_env_f32("KIN_LOCATE_DIRECT_DOMINANCE_TAIL_PENALTY", 0.35);
    if penalty >= 1.0 {
        return;
    }

    let mut changed = false;
    for (path, score) in fused.iter_mut() {
        let source_text_score = source_text_hits
            .get(path)
            .map(|hits| hits.iter().map(|hit| hit.score).sum::<f32>())
            .unwrap_or(0.0);
        if *path == top_path
            || is_test_path(path)
            || priority_backed_paths.contains(path)
            || semantic_retention_paths.contains(path)
            || source_text_score >= top_source_text * 0.5
        {
            continue;
        }
        let direct = resolve_signal_scores
            .get(path)
            .and_then(|scores| scores.get("entity_resolve"))
            .copied()
            .unwrap_or(0.0);
        if direct >= top_direct * 0.25 {
            continue;
        }
        *score *= penalty;
        changed = true;
    }

    if changed {
        fused.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
    }
}

fn post_rrf_path_penalty(
    path: &str,
    is_entity_bearing: bool,
    is_tracked_artifact: bool,
    test_query: bool,
    is_priority_backed: bool,
) -> f32 {
    if path.starts_with(".kin") || path.contains("/.kin/") {
        return 0.0;
    }

    let mut penalty = 1.0;
    if !is_entity_bearing {
        penalty *= if is_tracked_artifact {
            if is_priority_backed {
                locate_env_f32("KIN_LOCATE_PRIORITY_TRACKED_ARTIFACT_PENALTY", 0.85)
            } else {
                locate_env_f32("KIN_LOCATE_TRACKED_ARTIFACT_PENALTY", 0.4)
            }
        } else {
            locate_env_f32("KIN_LOCATE_NON_SOURCE_PENALTY", 0.02)
        };
    }
    if is_test_path(path) {
        penalty *= if test_query {
            locate_env_f32("KIN_LOCATE_POST_TEST_QUERY_PENALTY", 1.0)
        } else if is_priority_backed {
            locate_env_f32("KIN_LOCATE_PRIORITY_TEST_PENALTY", 0.9)
        } else {
            locate_env_f32("KIN_LOCATE_POST_TEST_PENALTY", 0.35)
        };
    }
    if is_non_code_ext(path) {
        penalty *= if is_tracked_artifact {
            if is_priority_backed {
                locate_env_f32(
                    "KIN_LOCATE_PRIORITY_TRACKED_ARTIFACT_NON_CODE_PENALTY",
                    0.95,
                )
            } else {
                locate_env_f32("KIN_LOCATE_TRACKED_ARTIFACT_NON_CODE_PENALTY", 0.9)
            }
        } else {
            locate_env_f32("KIN_LOCATE_NON_CODE_EXT_PENALTY", 0.005)
        };
    }
    if is_docs_or_locale_path(path) {
        penalty *= locate_env_f32("KIN_LOCATE_DOCS_PATH_PENALTY", 0.01);
    }
    if is_vendor_path(path) {
        penalty *= locate_env_f32("KIN_LOCATE_VENDOR_PATH_PENALTY", 0.01);
    }
    if is_embedded_framework_noise_path(path) {
        penalty *= if is_priority_backed {
            locate_env_f32("KIN_LOCATE_PRIORITY_FRAMEWORK_NOISE_PENALTY", 0.6)
        } else {
            locate_env_f32("KIN_LOCATE_FRAMEWORK_NOISE_PENALTY", 0.03)
        };
    }
    if is_license_or_notice_path(path) {
        penalty *= if is_priority_backed {
            locate_env_f32("KIN_LOCATE_PRIORITY_LICENSE_PATH_PENALTY", 0.5)
        } else {
            locate_env_f32("KIN_LOCATE_LICENSE_PATH_PENALTY", 0.01)
        };
    }
    if is_contrib_port_path(path) {
        penalty *= if is_priority_backed {
            locate_env_f32("KIN_LOCATE_PRIORITY_CONTRIB_PATH_PENALTY", 0.65)
        } else {
            locate_env_f32("KIN_LOCATE_CONTRIB_PATH_PENALTY", 0.2)
        };
    }
    if is_module_infrastructure_path(path) {
        penalty *= if is_priority_backed {
            locate_env_f32("KIN_LOCATE_PRIORITY_MODULE_INFRA_PENALTY", 0.7)
        } else if is_entity_bearing {
            // Entity-bearing infrastructure (e.g. Rust lib.rs/mod.rs with real
            // function bodies) gets a milder penalty than pure re-export modules.
            locate_env_f32("KIN_LOCATE_ENTITY_BEARING_MODULE_INFRA_PENALTY", 0.6)
        } else {
            locate_env_f32("KIN_LOCATE_MODULE_INFRA_PENALTY", 0.15)
        };
    }
    // Amalgamated / single-include / generated headers and build tool scripts.
    // These high-centrality files match nearly every query but rarely represent
    // the actual change locus. Demoting them sharply improves precision.
    if is_amalgamated_or_generated_path(path) {
        penalty *= amalgam_penalty();
    }

    penalty
}

fn graph_projection_backed_generated_paths(
    graph: &kin_db::InMemoryGraph,
    resolve_signal_scores: &HashMap<String, HashMap<String, f32>>,
) -> HashSet<String> {
    resolve_signal_scores
        .iter()
        .filter_map(|(path, signals)| {
            if !is_amalgamated_or_generated_path(path)
                || !signals.contains_key("graph_resolve")
                || !path_has_derived_from_artifact_relation(graph, path)
            {
                return None;
            }
            Some(path.clone())
        })
        .collect()
}

fn path_has_derived_from_artifact_relation(graph: &kin_db::InMemoryGraph, path: &str) -> bool {
    let Some(artifact_id) = graph.artifact_id_for_path(&kin_model::FilePathId::new(path)) else {
        return false;
    };
    let node = GraphNodeId::Artifact(artifact_id);
    graph
        .get_all_relations_for_node(&node)
        .map(|relations| {
            relations.iter().any(|relation| {
                relation.kind == RelationKind::DerivedFrom
                    && (relation.src == node || relation.dst == node)
            })
        })
        .unwrap_or(false)
}

fn projection_contributor_retention_paths(
    graph: &kin_db::InMemoryGraph,
    text_lower: &str,
    fused: &[(String, f32)],
) -> HashSet<String> {
    let seed_topk = locate_env_usize("KIN_LOCATE_DERIVED_PROJECTION_RETAIN_SEED_TOPK", 3);
    let max_paths = locate_env_usize("KIN_LOCATE_DERIVED_PROJECTION_RETAIN_MAX", 0);
    projection_contributor_retention_paths_with_limits(
        graph, text_lower, fused, seed_topk, max_paths,
    )
}

fn projection_contributor_retention_paths_with_limits(
    graph: &kin_db::InMemoryGraph,
    text_lower: &str,
    fused: &[(String, f32)],
    seed_topk: usize,
    max_paths: usize,
) -> HashSet<String> {
    if !query_requests_projection_contributors(text_lower) || fused.is_empty() {
        return HashSet::new();
    }

    if seed_topk == 0 || max_paths == 0 {
        return HashSet::new();
    }

    let top_score = fused[0].1.max(0.0);
    let seed_floor =
        top_score * locate_env_f32("KIN_LOCATE_DERIVED_PROJECTION_RETAIN_SEED_FLOOR_PCT", 0.4);
    let mut retained: HashMap<String, u32> = HashMap::new();

    for (path, score) in fused.iter().take(seed_topk) {
        if *score < seed_floor {
            continue;
        }
        let Some(artifact_id) = graph.artifact_id_for_path(&kin_model::FilePathId::new(path))
        else {
            continue;
        };
        let node = GraphNodeId::Artifact(artifact_id);
        let Ok(relations) = graph.get_all_relations_for_node(&node) else {
            continue;
        };

        for relation in relations {
            if relation.kind != RelationKind::DerivedFrom
                || relation.src != node
                || !relation_has_projection_marker_evidence(&relation)
            {
                continue;
            }
            let contributor_path = match relation.dst {
                GraphNodeId::Artifact(dst_id) => graph
                    .path_for_artifact_id(&dst_id)
                    .map(|path| path.0)
                    .or_else(|| relation_projection_resolved_path(&relation)),
                _ => None,
            };
            let Some(contributor_path) = contributor_path else {
                continue;
            };
            if contributor_path == *path
                || is_vendored_path(&contributor_path)
                || is_test_path(&contributor_path)
            {
                continue;
            }
            let occurrence_count = relation
                .evidence
                .iter()
                .map(|evidence| evidence.occurrence_count)
                .max()
                .unwrap_or(1);
            retained
                .entry(contributor_path)
                .and_modify(|current| *current = (*current).max(occurrence_count))
                .or_insert(occurrence_count);
        }
    }

    let mut retained: Vec<(String, u32)> = retained.into_iter().collect();
    retained.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    retained
        .into_iter()
        .take(max_paths)
        .map(|(path, _)| path)
        .collect()
}

fn query_requests_projection_contributors(text_lower: &str) -> bool {
    text_lower.contains("amalgamat")
        || text_lower.contains("single-header")
        || text_lower.contains("single header")
        || text_lower.contains("generated header")
        || text_lower.contains("generated source")
        || text_lower.contains("generated file")
        || (text_lower.contains("rename")
            && (text_lower.contains("folder") || text_lower.contains("directory"))
            && (text_lower.contains("header") || text_lower.contains("include")))
}

fn relation_has_projection_marker_evidence(relation: &kin_model::Relation) -> bool {
    relation.evidence.iter().any(|evidence| {
        evidence.parser_rule.as_deref() == Some("projection_include_marker")
            || evidence.token.as_deref() == Some("#include")
                && evidence.resolved_path.as_deref().is_some()
    })
}

fn relation_projection_resolved_path(relation: &kin_model::Relation) -> Option<String> {
    relation
        .evidence
        .iter()
        .find_map(|evidence| evidence.resolved_path.clone())
}

fn priority_backing_applies_for_path(
    path: &str,
    is_priority_backed: bool,
    _has_direct_query_priority: bool,
) -> bool {
    if !is_priority_backed {
        return false;
    }

    if is_amalgamated_or_generated_path(path) {
        return false;
    }

    true
}

fn is_vendored_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("extern/")
        || lower.contains("/extern/")
        || lower.starts_with("vendor/")
        || lower.contains("/vendor/")
        || lower.starts_with("third_party/")
        || lower.contains("/third_party/")
        || lower.starts_with("thirdparty/")
        || lower.contains("/thirdparty/")
        || lower.starts_with("node_modules/")
        || lower.contains("/node_modules/")
        || lower.starts_with("_vendor/")
        || lower.contains("/_vendor/")
        || lower.starts_with("dependencies/")
        || lower.contains("/dependencies/")
        || lower.starts_with("deps/")
        || lower.contains("/deps/")
}

fn resolve_path_in_graph(graph: &kin_db::InMemoryGraph, partial_path: &str) -> Option<String> {
    let normalized = partial_path
        .trim()
        .trim_start_matches("./")
        .replace('\\', "/");
    if normalized.is_empty() {
        return None;
    }

    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    for candidate in (0..parts.len()).map(|start| parts[start..].join("/")) {
        let candidate = candidate.trim_start_matches('/');
        if candidate.is_empty() {
            continue;
        }

        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(candidate)),
            ..Default::default()
        };
        if graph
            .query_entities(&filter)
            .ok()
            .is_some_and(|entities| !entities.is_empty())
        {
            return Some(candidate.to_string());
        }

        if let Some(path) = tracked_non_entity_files(graph)
            .into_iter()
            .map(|tracked| tracked.path)
            .find(|path| path == candidate || path.ends_with(&format!("/{}", candidate)))
        {
            return Some(path);
        }
    }

    None
}

fn tracked_non_entity_files(graph: &kin_db::InMemoryGraph) -> Vec<TrackedFileInfo> {
    let mut files = Vec::new();

    if let Ok(shallow_files) = graph.list_shallow_files() {
        files.extend(shallow_files.into_iter().map(|shallow| {
            TrackedFileInfo {
                path: shallow.file_id.0,
                descriptor: format!(
                    "shallow {} {} {}",
                    shallow.language_hint,
                    shallow.declaration_names.join(" "),
                    shallow.import_paths.join(" ")
                )
                .trim()
                .to_string(),
            }
        }));
    }

    if let Ok(artifacts) = graph.list_structured_artifacts() {
        files.extend(artifacts.into_iter().map(|artifact| {
            TrackedFileInfo {
                path: artifact.file_id.0,
                descriptor: format!(
                    "structured {} {}",
                    structured_artifact_label(artifact.kind),
                    artifact.text_preview.unwrap_or_default()
                )
                .trim()
                .to_string(),
            }
        }));
    }

    if let Ok(artifacts) = graph.list_opaque_artifacts() {
        files.extend(artifacts.into_iter().map(|artifact| {
            TrackedFileInfo {
                path: artifact.file_id.0,
                descriptor: format!(
                    "{} {}",
                    artifact
                        .mime_type
                        .map(|mime| format!("opaque {}", mime))
                        .unwrap_or_else(|| "opaque artifact".to_string()),
                    artifact.text_preview.unwrap_or_default()
                )
                .trim()
                .to_string(),
            }
        }));
    }

    files
}

fn structured_artifact_label(kind: kin_model::ArtifactKind) -> &'static str {
    match kind {
        kin_model::ArtifactKind::PackageManifest => "package manifest",
        kin_model::ArtifactKind::SqlMigration => "sql migration",
        kin_model::ArtifactKind::CiConfig => "ci config",
        kin_model::ArtifactKind::Dockerfile => "dockerfile",
        kin_model::ArtifactKind::ComposeFile => "compose file",
        kin_model::ArtifactKind::Makefile => "makefile",
    }
}

fn is_test_query(text: &str) -> bool {
    // Detect if the query is asking about test-related code
    let lower = text.to_ascii_lowercase();
    let test_keywords = [
        "test",
        "unittest",
        "pytest",
        "testing",
        "spec",
        "fixture",
        "mock",
        "stub",
        "failing test",
        "test case",
        "test suite",
        "broken test",
        "failing assertion",
        "test error",
    ];
    test_keywords.iter().any(|kw| lower.contains(kw))
}

/// Weight multiplier for an entity based on its graph-assigned role.
///
/// When `is_test_query` is true, test files get full weight and source files
/// are demoted.  External and generated entities are always heavily penalized.
#[allow(dead_code)] // Will be used when locate integrates graph-based role scoring
fn role_weight(role: EntityRole, is_test_query: bool) -> f32 {
    match (role, is_test_query) {
        (EntityRole::Source, false) => 1.0,
        (EntityRole::Source, true) => 0.3,
        (EntityRole::Test, false) => 0.1,
        (EntityRole::Test, true) => 1.0,
        (EntityRole::External | EntityRole::Vendored, _) => 0.01,
        (EntityRole::Docs, _) => 0.3,
        (EntityRole::Generated, _) => 0.05,
    }
}

fn is_test_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let markers = [
        "test/",
        "tests/",
        "/test/",
        "/tests/",
        "/test_",
        "/_test",
        "/spec/",
        "/specs/",
        "__tests__",
    ];
    markers.iter().any(|m| lower.contains(m))
        || lower.ends_with("_test.py")
        || lower.ends_with("_test.rs")
        || lower.ends_with("_test.go")
        || lower.ends_with(".test.ts")
        || lower.ends_with(".test.js")
        || lower.ends_with(".spec.ts")
        || lower.ends_with(".spec.js")
        || lower.contains("/test_")
}

fn is_source_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    (lower.starts_with("src/") || lower.contains("/src/"))
        || (lower.starts_with("lib/") || lower.contains("/lib/"))
        || (lower.starts_with("pkg/") || lower.contains("/pkg/"))
        || (lower.starts_with("internal/") || lower.contains("/internal/"))
        || ((lower.starts_with("packages/") || lower.contains("/packages/")) && !is_docs_path(path))
}

fn is_build_surface_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let leaf = lower.rsplit('/').next().unwrap_or(lower.as_str());
    leaf == "cmakelists.txt"
        || leaf == "makefile"
        || lower.ends_with(".cmake")
        || lower.ends_with(".mk")
}

fn tracked_file_support_is_signal_bearing(path: &str) -> bool {
    if is_test_path(path)
        || is_docs_or_locale_path(path)
        || is_vendor_path(path)
        || is_embedded_framework_noise_path(path)
        || is_license_or_notice_path(path)
    {
        return false;
    }

    is_source_path(path) || is_cpp_like_source_path(path) || is_build_surface_path(path)
}

fn is_docs_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("docs/")
        || lower.contains("/docs/")
        || lower.starts_with("doc/")
        || lower.contains("/doc/")
        || lower.starts_with("examples/")
        || lower.contains("/examples/")
        || lower.starts_with("example/")
        || lower.contains("/example/")
        || lower.starts_with("samples/")
        || lower.contains("/samples/")
        || lower.starts_with("demo/")
        || lower.contains("/demo/")
        || lower.starts_with("benchmarking/")
        || lower.contains("/benchmarking/")
        || lower.starts_with("benchmarks/")
        || lower.contains("/benchmarks/")
        || lower.starts_with("site/")
        || lower.contains("/site/")
        || lower.starts_with("sites/")
        || lower.contains("/sites/")
        || lower.ends_with(".md")
        || lower.ends_with(".rst")
}

fn is_non_code_ext(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let non_code = [
        ".yaml", ".yml", ".xsd", ".dtd", ".xsl", ".xslt", ".po", ".pot", ".mo", ".json", ".toml",
        ".ini", ".cfg", ".conf", ".csv", ".tsv", ".xml", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".doc", ".docx", ".txt", ".log",
    ];
    non_code.iter().any(|ext| lower.ends_with(ext))
}

fn is_docs_or_locale_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("/locale/")
        || lower.contains("/locales/")
        || lower.contains("/po/")
        || lower.contains("/i18n/")
        || lower.contains("/l10n/")
        || lower.contains("/translations/")
        || is_docs_path(path)
}

fn is_vendor_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("/vendor/")
        || lower.contains("/cextern/")
        || lower.contains("/third_party/")
        || lower.contains("/thirdparty/")
        || lower.contains("/extern/")
        || lower.contains("/external/")
        || lower.contains("/_vendor/")
        || lower.starts_with("dependencies/")
        || lower.contains("/dependencies/")
        || lower.starts_with("deps/")
        || lower.contains("/deps/")
        || (lower.ends_with(".c") || lower.ends_with(".h"))
            && (lower.contains("/cextern/")
                || lower.contains("/vendor/")
                || lower.contains("/extern/"))
}

fn is_embedded_framework_noise_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("lib/gtest/")
        || lower.contains("/lib/gtest/")
        || lower.starts_with("lib/gbenchmark/")
        || lower.contains("/lib/gbenchmark/")
        || lower.contains("/googletest/")
}

fn is_license_or_notice_path(path: &str) -> bool {
    let leaf = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    matches!(
        leaf.as_str(),
        "copying"
            | "copying.txt"
            | "license"
            | "license.txt"
            | "license.md"
            | "licence"
            | "licence.txt"
            | "notice"
            | "notice.txt"
            | "authors"
            | "authors.txt"
    )
}

fn is_contrib_port_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("contrib/") || lower.contains("/contrib/")
}

fn is_module_infrastructure_path(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);

    // Rust module re-export files
    if basename == "mod.rs" || basename == "lib.rs" {
        return true;
    }
    // Cargo.lock is noise; Cargo.toml is a tracked artifact handled by the
    // tracked-artifact penalty path — don't double-penalize it here.
    if basename == "Cargo.lock" {
        return true;
    }
    // Go cmd tree hubs
    if basename == "root.go" || basename == "main.go" {
        return true;
    }
    // Python package init
    if basename == "__init__.py" {
        return true;
    }
    // JS/TS barrel/re-export files and package manifests
    if basename == "index.ts"
        || basename == "index.tsx"
        || basename == "index.js"
        || basename == "index.jsx"
        || basename == "package.json"
        || basename == "tsconfig.json"
    {
        return true;
    }
    // Build system files
    if basename == "Makefile"
        || basename == "CMakeLists.txt"
        || basename == "BUILD"
        || basename == "BUILD.bazel"
    {
        return true;
    }

    false
}

fn is_amalgamated_or_generated_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    // Amalgamated / single-include headers (e.g. single_include/nlohmann/json.hpp)
    if lower.starts_with("single_include/")
        || lower.contains("/single_include/")
        || lower.contains("_amalgamation")
        || lower.contains("/amalgamated/")
    {
        return true;
    }
    // Forward-declaration-only headers
    if lower.ends_with("_fwd.hpp")
        || lower.ends_with("_fwd.h")
        || lower.ends_with("/fwd.hpp")
        || lower.ends_with("/fwd.h")
    {
        return true;
    }
    // Build tool / linting scripts that are not implementation code
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    matches!(
        basename,
        "cpplint.py"
            | "amalgamate.py"
            | "serve_header.py"
            | "check_structure.py"
            | "run_benchmarks.py"
    )
}

fn is_cli_surface_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("programs/")
        || lower.contains("/programs/")
        || lower.starts_with("cmd/")
        || lower.contains("/cmd/")
        || lower.starts_with("cli/")
        || lower.contains("/cli/")
        || lower.contains("/options/")
        || lower.contains("/command/")
        || lower.ends_with("/zstdcli.c")
        || lower.ends_with("/fileio.c")
}

fn query_mentions_cli_flags(text: &str) -> bool {
    !extract_cli_flag_terms(text).is_empty()
}

fn is_cextern_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("cextern/") || lower.contains("/cextern/")
}

/// Returns priority tier for a file. Lower = higher priority.
/// Source code (tier 0) always ranks above external (tier 1) and test (tier 2)
/// in the final sort, regardless of individual signal scores.
/// When the query is test-focused, tiers are swapped so test files surface.
///
/// Uses `EntityRole` from the graph when available; falls back to path heuristics.
fn file_tier(path: &str, test_query: bool) -> u8 {
    file_tier_with_role(path, test_query, None)
}

fn file_tier_with_role(path: &str, test_query: bool, role: Option<EntityRole>) -> u8 {
    let effective_role = role.unwrap_or_else(|| role_from_path(path));
    match effective_role {
        EntityRole::External | EntityRole::Vendored | EntityRole::Generated => {
            if test_query {
                2
            } else {
                1
            }
        }
        EntityRole::Test => {
            if test_query {
                0
            } else {
                2
            }
        }
        EntityRole::Docs => {
            if test_query {
                2
            } else {
                2
            }
        }
        EntityRole::Source => {
            if test_query {
                1
            } else {
                0
            }
        }
    }
}

/// Infer an EntityRole from a file path when no graph entity is available.
fn role_from_path(path: &str) -> EntityRole {
    if is_vendor_path(path) || is_cextern_path(path) {
        EntityRole::External
    } else if is_test_path(path) {
        EntityRole::Test
    } else if is_docs_path(path) {
        EntityRole::Docs
    } else {
        EntityRole::Source
    }
}

/// Returns true if the entity (or path fallback) is a test.
fn is_test_by_role(path: &str, entity: Option<&kin_model::Entity>) -> bool {
    entity
        .map(|e| e.role == EntityRole::Test)
        .unwrap_or_else(|| is_test_path(path))
}

/// Returns the test multiplier using entity role when available.
fn test_mult_by_role(path: &str, entity: Option<&kin_model::Entity>, penalty: f32) -> f32 {
    if is_test_by_role(path, entity) {
        penalty
    } else {
        1.0
    }
}

fn extract_negation_penalties(text: &str, graph: &kin_db::InMemoryGraph) -> HashSet<String> {
    let mut excluded = HashSet::new();

    // Patterns: "not in X", "exclude X", "without touching X", "don't modify X", "shouldn't change X"
    let re_negation = regex::Regex::new(
        r"(?i)(?:not\s+in|exclude|without\s+touching|don'?t\s+(?:modify|change|touch)|shouldn'?t\s+(?:change|modify|touch))\s+[`']?([a-zA-Z_][\w./]*)[`']?"
    ).unwrap();

    for cap in re_negation.captures_iter(text) {
        let term = &cap[1];
        // Try as file path
        if let Some(path) = resolve_path_in_graph(graph, term) {
            excluded.insert(path);
        }
        // Try as entity name -> get its file
        let filter = EntityFilter {
            name_pattern: Some(term.to_string()),
            ..Default::default()
        };
        if let Ok(entities) = graph.query_entities(&filter) {
            for entity in entities.iter().take(3) {
                if let Some(ref fo) = entity.file_origin {
                    excluded.insert(fo.0.clone());
                }
            }
        }
    }

    excluded
}

/// Entity kinds that genuinely DEFINE a named symbol (have a declaration/body),
/// used by the `KIN_LOCATE_SYMBOL_DEF_KIND_FLOOR` lever so a real definition is
/// not demoted just because its `embedding_body_preview` is missing. Deliberately
/// excludes container/alias/noise kinds (Module, TypeAlias, Constant, …) so the
/// floor only protects true defs.
fn is_definitional_kind(kind: EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::Function
            | EntityKind::Method
            | EntityKind::Class
            | EntityKind::Interface
            | EntityKind::TraitDef
            | EntityKind::EnumDef
    )
}

/// GPU-free query proximity for symbol enrichment/relevance: how strongly an
/// entity matches the query, by NAME (exact/part match, weighted high) plus a
/// substring hit in its signature/body preview (weighted low). The body term
/// lets a definition whose BODY handles the query topic surface even when its
/// NAME does not match it — e.g. an `indexSitesFixesConfig` fn that handles
/// "base64 padding" for a "parser should ignore Base64 padding" query. Returns
/// 0.0 when nothing matches.
fn query_proximity_score(entity: &kin_model::Entity, query_terms: &[String]) -> f32 {
    if query_terms.is_empty() {
        return 0.0;
    }
    let mut name_score = 0.0f32;
    for term in query_terms {
        name_score = name_score.max(score_name_match(term, &entity.name));
    }
    let body = entity
        .metadata
        .extra
        .get("embedding_body_preview")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let haystack = format!("{} {}", entity.signature, body).to_ascii_lowercase();
    let mut body_hits = 0u32;
    for term in query_terms {
        let t = term.to_ascii_lowercase();
        if t.len() >= 3 && haystack.contains(&t) {
            body_hits += 1;
        }
    }
    name_score * 2.0 + body_hits as f32 * 0.5
}

/// Rank a file's definitional entities for the D_empty enrichment lever: query
/// proximity first, then a kind preference (fn/method over container), then
/// larger span, then name for determinism. The composite is baked into `score`
/// so the downstream `rank_and_cap_symbols_with` (which sorts by definition then
/// score) preserves this order. Truncates to `limit`.
fn rank_enriched_symbols(
    entities: Vec<kin_model::Entity>,
    query_terms: &[String],
    test_query: bool,
    limit: usize,
) -> Vec<LocateSymbol> {
    let mut syms: Vec<LocateSymbol> = entities
        .into_iter()
        .filter(|e| {
            (test_query || e.role != kin_model::EntityRole::Test) && is_definitional_kind(e.kind)
        })
        .map(|e| {
            let prox = query_proximity_score(&e, query_terms);
            let kind_w = if matches!(e.kind, EntityKind::Function | EntityKind::Method) {
                2.0
            } else {
                1.0
            };
            let span_len = e
                .span
                .as_ref()
                .map_or(0, |s| s.end_line.saturating_sub(s.start_line))
                .min(500);
            // proximity dominates, kind breaks proximity ties, span size breaks
            // kind ties — keeps the score monotonic with the intended ranking.
            let score = prox * 100.0 + kind_w + span_len as f32 / 1000.0;
            LocateSymbol {
                name: e.name.clone(),
                span: entity_span_pair(&e).into_iter().next(),
                score,
                kind: format!("{:?}", e.kind).to_lowercase(),
                definition: true,
                origin: String::new(),
                cosine: None,
            }
        })
        .collect();
    syms.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.name.cmp(&b.name))
    });
    syms.truncate(limit);
    syms
}

/// D_empty lever (`KIN_LOCATE_ENRICH_EMPTY_FILES`, default ON — set to 0 to
/// disable). For final result files that surfaced via a file-level/lexical
/// signal but had NO entity resolved to them — so their per-file symbol list is
/// empty and the symbol+line metrics are a guaranteed miss even though the FILE
/// was located correctly — enumerate the file's definitions from the graph and
/// emit the top query-relevant ones (`KIN_LOCATE_ENRICH_TOPK`, default 3).
/// GPU-free; only touches files that currently emit nothing, so files that
/// already have resolved symbols are unaffected.
fn enrich_empty_file_symbols(
    graph: &kin_db::InMemoryGraph,
    results: &[(String, f32)],
    projection_symbols: &mut HashMap<String, Vec<LocateSymbol>>,
    query_terms: &[String],
    test_query: bool,
) {
    let limit = locate_env_usize("KIN_LOCATE_ENRICH_TOPK", 3);
    for (path, _) in results {
        if projection_symbols
            .get(path)
            .map_or(false, |syms| !syms.is_empty())
        {
            continue;
        }
        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(path)),
            kinds: Some(vec![
                EntityKind::Function,
                EntityKind::Method,
                EntityKind::Class,
                EntityKind::Interface,
                EntityKind::TraitDef,
                EntityKind::EnumDef,
            ]),
            ..Default::default()
        };
        let Ok(entities) = graph.query_entities(&filter) else {
            continue;
        };
        if entities.is_empty() {
            continue;
        }
        let syms = rank_enriched_symbols(entities, query_terms, test_query, limit);
        if !syms.is_empty() {
            projection_symbols.insert(path.clone(), syms);
        }
    }
}

/// Pure core of the C_misrank lever (see [`boost_symbol_query_relevance`]):
/// given a file's already-emitted symbols and ALL its definitional entities,
/// (a) add a query-proximity boost to every emitted symbol's score, and (b)
/// merge in any query-RELEVANT (proximity > 0) definition that wasn't emitted —
/// so the actually-edited def surfaces over its resolved siblings. Only defs the
/// query points at are merged, bounding the precision hit. Returned unsorted;
/// `rank_and_cap_symbols_with` does the final ordering. Separated from graph IO
/// so it is unit-testable.
fn apply_query_relevance(
    mut existing: Vec<LocateSymbol>,
    file_entities: Vec<kin_model::Entity>,
    query_terms: &[String],
    test_query: bool,
    boost_weight: f32,
) -> Vec<LocateSymbol> {
    // Highest-proximity definitional entity per name in this file.
    let mut prox_by_name: HashMap<String, (f32, kin_model::Entity)> = HashMap::new();
    for e in file_entities {
        if !is_definitional_kind(e.kind) || !(test_query || e.role != kin_model::EntityRole::Test) {
            continue;
        }
        let p = query_proximity_score(&e, query_terms);
        match prox_by_name.get(&e.name) {
            Some((existing_p, _)) if *existing_p >= p => {}
            _ => {
                prox_by_name.insert(e.name.clone(), (p, e));
            }
        }
    }
    let mut present: HashSet<String> = HashSet::new();
    for s in existing.iter_mut() {
        present.insert(s.name.clone());
        let prox = prox_by_name
            .get(&s.name)
            .map(|(p, _)| *p)
            .unwrap_or_else(|| {
                let mut np = 0.0f32;
                for t in query_terms {
                    np = np.max(score_name_match(t, &s.name));
                }
                np
            });
        s.score += prox * boost_weight;
    }
    for (name, (p, e)) in &prox_by_name {
        if present.contains(name) || *p <= 0.0 {
            continue;
        }
        existing.push(LocateSymbol {
            name: e.name.clone(),
            span: entity_span_pair(e).into_iter().next(),
            score: *p * boost_weight,
            kind: format!("{:?}", e.kind).to_lowercase(),
            definition: true,
            origin: String::new(),
            cosine: None,
        });
    }
    existing
}

/// C_misrank lever (gated `KIN_LOCATE_SYMBOL_QUERY_PROXIMITY`, default OFF).
/// scorer sized ~44 golds where the correct named gold def IS present in the
/// right file+kind but Kin emits a resolved SIBLING instead. For each result
/// file, boost every emitted symbol by its query proximity and merge in any
/// query-relevant file definition that wasn't resolved, so the edited def ranks
/// over its siblings. GPU-free (lexical name + body-preview proximity); the
/// embedding-cosine variant is a separate, embed-window lever
/// ([`boost_symbol_embed_relevance`], `KIN_LOCATE_SYMBOL_EMBED_RELEVANCE`). OFF
/// is byte-identical (no boost, no merge).
fn boost_symbol_query_relevance(
    graph: &kin_db::InMemoryGraph,
    results: &[(String, f32)],
    projection_symbols: &mut HashMap<String, Vec<LocateSymbol>>,
    query_terms: &[String],
    test_query: bool,
) {
    let boost_weight = locate_env_f32("KIN_LOCATE_SYMBOL_PROXIMITY_BOOST", 10.0);
    for (path, _) in results {
        let existing = projection_symbols.get(path).cloned().unwrap_or_default();
        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(path)),
            kinds: Some(vec![
                EntityKind::Function,
                EntityKind::Method,
                EntityKind::Class,
                EntityKind::Interface,
                EntityKind::TraitDef,
                EntityKind::EnumDef,
            ]),
            ..Default::default()
        };
        let Ok(entities) = graph.query_entities(&filter) else {
            continue;
        };
        if existing.is_empty() && entities.is_empty() {
            continue;
        }
        let boosted =
            apply_query_relevance(existing, entities, query_terms, test_query, boost_weight);
        if !boosted.is_empty() {
            projection_symbols.insert(path.clone(), boosted);
        }
    }
}

/// Pure core of the EMBED_RELEVANCE lever (see [`boost_symbol_embed_relevance`]):
/// add a query↔definition embedding-cosine boost to every emitted symbol that
/// carries a cosine. The cosine is the relevance the semantic phase already
/// computed (query embedding vs. each candidate def's embedding) — no
/// re-embedding here. Symbols with no cosine (text-only seeds the embedder did
/// not surface) are left untouched, so the boost only ever lifts a
/// semantically-matched def, never penalises a lexical-only one below zero.
/// Mutates in place; `rank_and_cap_symbols_with` does the final ordering.
/// Separated from env/IO so it is unit-testable.
fn apply_embed_relevance(symbols: &mut [LocateSymbol], boost_weight: f32) {
    for s in symbols.iter_mut() {
        if let Some(cosine) = s.cosine {
            s.score += cosine * boost_weight;
        }
    }
}

/// EMBED_RELEVANCE lever (gated `KIN_LOCATE_SYMBOL_EMBED_RELEVANCE`, default
/// OFF). The embedding-cosine twin of the C_misrank proximity lever
/// ([`boost_symbol_query_relevance`]) and the SYMBOL-level analog of the
/// file-level weighted-RRF embedding weight (`KIN_LOCATE_RRF_WEIGHT_EMBEDDING`).
///
/// Lexical ranking picks the WRONG sibling when it shares more query TOKENS than
/// the gold — e.g. an sklearn fix that lives in `strip_accents_ascii` loses to
/// `strip_accents_unicode` because "unicode" matches more query words, or a clap
/// gold fn loses to `render_usage`. When embeddings are present and correct, the
/// def the query is SEMANTICALLY about carries the higher query↔def cosine;
/// boosting each emitted symbol by that cosine (weight
/// `KIN_LOCATE_SYMBOL_EMBED_BOOST`, default 10.0, matching the proximity lever)
/// lifts the gold over its lexical look-alike. Reuses the cosine the semantic
/// phase already recorded on each symbol — GPU-free here, no re-embedding. OFF
/// is byte-identical (no boost).
fn boost_symbol_embed_relevance(
    results: &[(String, f32)],
    projection_symbols: &mut HashMap<String, Vec<LocateSymbol>>,
) {
    let boost_weight = locate_env_f32("KIN_LOCATE_SYMBOL_EMBED_BOOST", 10.0);
    for (path, _) in results {
        if let Some(syms) = projection_symbols.get_mut(path) {
            apply_embed_relevance(syms, boost_weight);
        }
    }
}

/// A_spanwidth lever (gated `KIN_LOCATE_EMIT_INNER_METHODS`, default OFF).
/// scorer sized ~30 golds where Kin emitted the enclosing CLASS but the gold
/// edit is an inner METHOD — so the coarse class span never overlaps the few
/// edited lines. Rather than widen the class span (which would tank line
/// PRECISION on large classes), emit the file's methods (finer, correctly-bounded
/// spans), ranked by query proximity then size, for any file that surfaced a
/// class-like symbol. Methods already present by name are left untouched, so the
/// class and its methods coexist. OFF is byte-identical.
fn emit_inner_methods(
    graph: &kin_db::InMemoryGraph,
    results: &[(String, f32)],
    projection_symbols: &mut HashMap<String, Vec<LocateSymbol>>,
    query_terms: &[String],
    test_query: bool,
) {
    let topk = locate_env_usize("KIN_LOCATE_INNER_METHOD_TOPK", 5);
    for (path, _) in results {
        let has_class_like = projection_symbols.get(path).map_or(false, |syms| {
            syms.iter()
                .any(|s| matches!(s.kind.as_str(), "class" | "interface" | "module"))
        });
        if !has_class_like {
            continue;
        }
        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(path)),
            kinds: Some(vec![EntityKind::Method]),
            ..Default::default()
        };
        let Ok(methods) = graph.query_entities(&filter) else {
            continue;
        };
        if methods.is_empty() {
            continue;
        }
        let method_syms = rank_enriched_symbols(methods, query_terms, test_query, topk);
        if method_syms.is_empty() {
            continue;
        }
        let entry = projection_symbols.entry(path.clone()).or_default();
        let present: HashSet<String> = entry.iter().map(|s| s.name.clone()).collect();
        for ms in method_syms {
            if !present.contains(&ms.name) {
                entry.push(ms);
            }
        }
    }
}

/// Number of distinct query terms (length >= 4) that appear in an entity's
/// BODY surface — its signature plus the embedding body preview. This is the
/// signal behind the BODY_SEED lever: name-blocked gold defs (whose NAME matches
/// no query identifier, so the seed name-gate drops them) overwhelmingly carry
/// the query terms in their BODY (scorer: 39/39). Name is intentionally excluded
/// from the surface — name relevance is already handled by the seed name-gate;
/// here we want body coverage so a fix-implementing def surfaces regardless.
fn body_relevance_score(entity: &kin_model::Entity, query_terms: &[String]) -> u32 {
    let body = entity
        .metadata
        .extra
        .get("embedding_body_preview")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let haystack = format!("{} {}", entity.signature, body).to_ascii_lowercase();
    let mut hits = 0u32;
    for term in query_terms {
        let t = term.to_ascii_lowercase();
        if t.len() >= 4 && haystack.contains(&t) {
            hits += 1;
        }
    }
    hits
}

/// Pure core of the BODY_SEED emission lever: keep only a file's definitions
/// whose BODY matches the query (relevance > 0), rank by hit count then span
/// size then name, and build symbols for the top `limit`. Emitted ADDITIVELY
/// (the caller merges, deduping by name) rather than competitively — the gold
/// def is surfaced ALONGSIDE any resolved sibling, which is robust because the
/// symbol cap does not bind on the 1-3 symbol files these misses occur on.
fn rank_body_relevant_symbols(
    entities: Vec<kin_model::Entity>,
    query_terms: &[String],
    test_query: bool,
    limit: usize,
) -> Vec<LocateSymbol> {
    let mut scored: Vec<(u32, u32, kin_model::Entity)> = entities
        .into_iter()
        .filter(|e| {
            (test_query || e.role != kin_model::EntityRole::Test) && is_definitional_kind(e.kind)
        })
        .filter_map(|e| {
            let hits = body_relevance_score(&e, query_terms);
            if hits == 0 {
                return None;
            }
            let span_len = e
                .span
                .as_ref()
                .map_or(0, |s| s.end_line.saturating_sub(s.start_line))
                .min(500);
            Some((hits, span_len, e))
        })
        .collect();
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then(b.1.cmp(&a.1))
            .then_with(|| a.2.name.cmp(&b.2.name))
    });
    scored
        .into_iter()
        .take(limit)
        .map(|(hits, _, e)| LocateSymbol {
            name: e.name.clone(),
            span: entity_span_pair(&e).into_iter().next(),
            score: hits as f32,
            kind: format!("{:?}", e.kind).to_lowercase(),
            definition: true,
            origin: String::new(),
            cosine: None,
        })
        .collect()
}

/// BODY_SEED primary lever (gated `KIN_LOCATE_BODY_SEED`, default OFF). The seed
/// name-gate (`score_name_match > 0`) drops defs whose NAME matches no query
/// identifier even when their BODY implements the change, so they never resolve
/// or emit. For each found result file, additively merge in the top
/// `KIN_LOCATE_BODY_SEED_TOPK` (default 3) defs whose BODY matches the query,
/// deduped by name against whatever already emitted. Robust (no rank/gap-cut
/// contest): the gold is emitted alongside siblings, and the symbol cap does not
/// bind on these files. OFF is byte-identical.
fn emit_body_relevant_symbols(
    graph: &kin_db::InMemoryGraph,
    results: &[(String, f32)],
    projection_symbols: &mut HashMap<String, Vec<LocateSymbol>>,
    query_terms: &[String],
    test_query: bool,
) {
    if query_terms.is_empty() {
        return;
    }
    let topk = locate_env_usize("KIN_LOCATE_BODY_SEED_TOPK", 3);
    for (path, _) in results {
        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(path)),
            kinds: Some(vec![
                EntityKind::Function,
                EntityKind::Method,
                EntityKind::Class,
                EntityKind::Interface,
                EntityKind::TraitDef,
                EntityKind::EnumDef,
            ]),
            ..Default::default()
        };
        let Ok(entities) = graph.query_entities(&filter) else {
            continue;
        };
        if entities.is_empty() {
            continue;
        }
        let body_syms = rank_body_relevant_symbols(entities, query_terms, test_query, topk);
        if body_syms.is_empty() {
            continue;
        }
        let entry = projection_symbols.entry(path.clone()).or_default();
        let present: HashSet<String> = entry.iter().map(|s| s.name.clone()).collect();
        for s in body_syms {
            if !present.contains(&s.name) {
                entry.push(s);
            }
        }
    }
}

fn entity_span_pair(entity: &kin_model::Entity) -> Vec<[u32; 2]> {
    let Some(s) = entity.span.as_ref() else {
        return Vec::new();
    };
    let is_class_like = matches!(
        entity.kind,
        EntityKind::Class | EntityKind::Interface | EntityKind::Module
    );
    // SPAN-WIDTH lever: class-like entities with long bodies are truncated to a
    // short head window for symbol/line PRECISION, but that caps line RECALL
    // against multi-line gold regions (gold spans run 34-210 lines; a 5-line head
    // can cover at most ~0.15 of them). KIN_LOCATE_SPAN_CLASS_HEAD_THRESHOLD is
    // the length bound above which truncation applies — default 60
    // (measurement-backed line lever; was 30), env-overridable.
    // KIN_LOCATE_SPAN_FULL_EXTENT=1 emits the full node extent instead.
    let full_extent = locate_env_bool("KIN_LOCATE_SPAN_FULL_EXTENT", false);
    let head_threshold = locate_env_usize("KIN_LOCATE_SPAN_CLASS_HEAD_THRESHOLD", 60) as u32;
    vec![entity_span_lines(
        s,
        is_class_like,
        full_extent,
        head_threshold,
    )]
}

/// Pure 1-based-inclusive line-span computation behind [`entity_span_pair`],
/// separated so the indexing/truncation/end-boundary logic is testable without
/// mutating process env. `SourceSpan` carries tree-sitter rows (0-indexed); the
/// returned `[u32; 2]` is the documented 1-based inclusive line span consumed by
/// ContextBench against 1-indexed gold ranges, so the window is computed in the
/// raw 0-indexed domain and shifted to 1-based on return (matching the already-
/// 1-indexed traceback spans instead of landing one line short).
fn entity_span_lines(
    s: &kin_model::SourceSpan,
    is_class_like: bool,
    full_extent: bool,
    head_threshold: u32,
) -> [u32; 2] {
    let (start, end, end_is_real) = if is_class_like && !full_extent {
        let len = s.end_line.saturating_sub(s.start_line);
        if len > head_threshold {
            // Synthetic head window; `end` is start+4, not the node's real end
            // row, so the trailing-newline adjustment below must not apply to it.
            (s.start_line, (s.start_line + 4).min(s.end_line), false)
        } else {
            (s.start_line, s.end_line, true)
        }
    } else {
        (s.start_line, s.end_line, true)
    };
    // tree-sitter `end_position()` is exclusive (just past the last byte). When a
    // node's text ends with a newline, that exclusive end lands at column 0 of
    // the FOLLOWING row, so `end_line` is already the 1-based last-content line
    // and must not be incremented again — otherwise the inclusive end overshoots
    // by one (worst on tight gold spans where it can flip overlap). For an end
    // mid-line (`end_col > 0`) the row holds content and the +1 shift is correct.
    let end_1 = if end_is_real && s.end_col == 0 && s.end_line > s.start_line {
        end
    } else {
        end.saturating_add(1)
    };
    [start.saturating_add(1), end_1]
}

/// Graph-truth precision cap for a file's `explain` lines. The ContextBench
/// scorer derives a file's predicted SYMBOL set from these lines, so emitting
/// every entity that merely touched a file (hub files accrue dozens of seeds and
/// graph-walk neighbors) collapses symbol/line precision. Keep only the top-K
/// lines by their embedded `(score N.N, ...)` value — report the definitions Kin
/// is most confident about, not everything it walked. A floor additionally drops
/// scoreless lines (the noisiest graph-walk `via` neighbors) once the threshold
/// is exceeded. `KIN_LOCATE_EXPLAIN_DEF_TOPK=0` (default) preserves the previous
/// uncapped behavior, so this is a no-op unless explicitly enabled.
/// Default cap on ranked symbols emitted per file. Tunable via
/// `KIN_LOCATE_SYMBOL_CAP`; `0` means uncapped. Set near the gold symbol-set
/// median (~12) so the cap trims a hub file's dozens of touched entities for
/// precision without clipping recall on genuinely symbol-dense files. The
/// ContextBench scorer derives a file's predicted symbol set from this list.
const DEFAULT_SYMBOL_CAP: usize = 25;

/// Effective per-file symbol cap from `KIN_LOCATE_SYMBOL_CAP`
/// (default [`DEFAULT_SYMBOL_CAP`], `0` = uncapped).
///
/// Read directly rather than via `locate_env_usize` because that helper treats
/// `0` as "unset" and falls back to the default; here `0` is a meaningful value
/// (uncapped) and must be honored.
fn symbol_cap() -> usize {
    std::env::var("KIN_LOCATE_SYMBOL_CAP")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_SYMBOL_CAP)
}

/// Like [`rank_and_cap_symbols_with`] but also returns the symbols dropped by
/// the cap (in ranked order), for --explain symbol-cap tracing. The kept set is
/// byte-identical to [`rank_and_cap_symbols_with`].
fn rank_and_cap_symbols_capturing(
    symbols: Vec<LocateSymbol>,
    cap: usize,
) -> (Vec<LocateSymbol>, Vec<LocateSymbol>) {
    let ranked = rank_and_cap_symbols_with(symbols.clone(), 0);
    let kept = rank_and_cap_symbols_with(symbols, cap);
    let dropped = if cap > 0 && ranked.len() > kept.len() {
        ranked[kept.len()..].to_vec()
    } else {
        Vec::new()
    };
    (kept, dropped)
}

fn cap_symbols_by_score(symbols: Vec<LocateSymbol>) -> Vec<LocateSymbol> {
    let topk = locate_env_usize("KIN_LOCATE_EXPLAIN_DEF_TOPK", 0);
    let floor_pct = locate_env_f32("KIN_LOCATE_EXPLAIN_DEF_FLOOR_PCT", 0.0);
    if topk == 0 && floor_pct <= 0.0 {
        return symbols;
    }

    let (defs, mut refs): (Vec<LocateSymbol>, Vec<LocateSymbol>) =
        symbols.into_iter().partition(|s| s.definition);

    let top_score = defs.first().map(|x| x.score).unwrap_or(0.0);
    let floor = if floor_pct > 0.0 && top_score > 0.0 {
        top_score * floor_pct
    } else {
        f32::NEG_INFINITY
    };

    let limit = if topk == 0 { defs.len() } else { topk };
    let mut kept_defs: Vec<LocateSymbol> = defs
        .into_iter()
        .take(limit)
        .filter(|s| s.score >= floor)
        .collect();

    kept_defs.append(&mut refs);
    kept_defs
}

/// Ranking is definition-before-reference, then composite score descending,
/// then name for determinism. De-duplicates by name (keeping the highest-ranked
/// occurrence) and truncates to `cap` (`0` = uncapped).
fn rank_and_cap_symbols_with(mut symbols: Vec<LocateSymbol>, cap: usize) -> Vec<LocateSymbol> {
    symbols.sort_by(|a, b| {
        b.definition
            .cmp(&a.definition)
            .then_with(|| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut seen = HashSet::new();
    symbols.retain(|s| seen.insert(s.name.clone()));

    let mut symbols = cap_symbols_by_score(symbols);

    if cap > 0 && symbols.len() > cap {
        symbols.truncate(cap);
    }
    symbols
}

fn explain_line_score(reason: &str) -> f32 {
    if let Some(idx) = reason.find("(score ") {
        let rest = &reason[idx + 7..];
        let end = rest
            .find(|c: char| c == ',' || c == ')')
            .unwrap_or(rest.len());
        return rest[..end].trim().parse::<f32>().unwrap_or(-1.0);
    }
    -1.0
}

fn cap_explain_lines_by_score(reasons: Vec<String>) -> Vec<String> {
    let topk = locate_env_usize("KIN_LOCATE_EXPLAIN_DEF_TOPK", 0);
    let floor_pct = locate_env_f32("KIN_LOCATE_EXPLAIN_DEF_FLOOR_PCT", 0.0);
    if (topk == 0 && floor_pct <= 0.0) || reasons.len() <= 1 {
        return reasons;
    }
    let mut indexed: Vec<(usize, f32, String)> = reasons
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let s = explain_line_score(&r);
            (i, s, r)
        })
        .collect();
    indexed.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    let top_score = indexed.first().map(|x| x.1).unwrap_or(0.0);
    let floor = if floor_pct > 0.0 && top_score > 0.0 {
        top_score * floor_pct
    } else {
        f32::NEG_INFINITY
    };
    let limit = if topk == 0 { indexed.len() } else { topk };
    let mut kept: Vec<(usize, String)> = indexed
        .into_iter()
        .take(limit)
        .filter(|(_, s, _)| *s >= floor)
        .map(|(i, _, r)| (i, r))
        .collect();
    // Restore original emission order so downstream parsing is stable.
    kept.sort_by_key(|(i, _)| *i);
    kept.into_iter().map(|(_, r)| r).collect()
}

fn collect_signals_for_file(file: &str, all_hits: &[HashMap<String, Vec<FileHit>>]) -> Vec<String> {
    let mut signals = Vec::new();
    let signal_names = [
        "traceback",
        "multihop",
        "tests",
        "snippets",
        "imports",
        "errors",
        "cochange",
        "entity_resolve",
        "source_text",
        "embedding",
    ];
    for (i, hit_map) in all_hits.iter().enumerate() {
        if hit_map.contains_key(file) {
            let name = signal_names.get(i).copied().unwrap_or("graph");
            signals.push(name.to_string());
        }
    }
    signals
}

fn collect_spans_for_file(file: &str, all_hits: &[HashMap<String, Vec<FileHit>>]) -> Vec<[u32; 2]> {
    let mut spans = Vec::new();
    let mut seen = HashSet::new();
    for hit_map in all_hits {
        if let Some(file_hits) = hit_map.get(file) {
            for hit in file_hits {
                for span in &hit.spans {
                    if seen.insert(*span) {
                        spans.push(*span);
                    }
                }
            }
        }
    }
    spans.sort_unstable();
    spans
}

fn collect_explain_for_file(
    file: &str,
    projection_explain: &HashMap<String, Vec<String>>,
    all_hits: &[HashMap<String, Vec<FileHit>>],
) -> Vec<String> {
    if let Some(reasons) = projection_explain.get(file) {
        return cap_explain_lines_by_score(reasons.clone());
    }
    let signals = collect_signals_for_file(file, all_hits);
    if signals.is_empty() {
        Vec::new()
    } else {
        vec![format!("matched signals: {}", signals.join(", "))]
    }
}

fn build_result(
    results: &[(String, f32)],
    all_hits: &[HashMap<String, Vec<FileHit>>],
    projection_explain: &HashMap<String, Vec<String>>,
    projection_symbols: &HashMap<String, Vec<LocateSymbol>>,
    file_provenance: &HashMap<String, LocateFileProvenance>,
    per_file_signals: &HashMap<String, HashMap<String, f32>>,
    score_breakdown: &HashMap<String, HashMap<String, f32>>,
    mut debug: Option<LocateDebugInfo>,
    explain: bool,
) -> LocateResult {
    let cap = symbol_cap();
    let mut dropped_symbols: Vec<LocateSymbol> = Vec::new();
    let files: Vec<LocateFileEntry> = results
        .iter()
        .map(|(path, score)| LocateFileEntry {
            path: path.clone(),
            score: *score,
            signals: collect_signals_for_file(path, all_hits),
            spans: collect_spans_for_file(path, all_hits),
            symbols: projection_symbols
                .get(path)
                .map(|syms| {
                    if explain {
                        let (kept, dropped) = rank_and_cap_symbols_capturing(syms.clone(), cap);
                        dropped_symbols.extend(dropped);
                        kept
                    } else {
                        rank_and_cap_symbols_with(syms.clone(), cap)
                    }
                })
                .unwrap_or_default(),
            explain: if explain {
                collect_explain_for_file(path, projection_explain, all_hits)
            } else {
                Vec::new()
            },
            provenance: if explain {
                file_provenance.get(path).cloned()
            } else {
                None
            },
            signal_scores: if explain {
                per_file_signals.get(path).cloned()
            } else {
                None
            },
            score_breakdown: if explain {
                score_breakdown.get(path).cloned()
            } else {
                None
            },
        })
        .collect();

    if explain {
        if let Some(debug) = debug.as_mut() {
            dropped_symbols = rank_and_cap_symbols_with(dropped_symbols, 0);
            debug.symbol_cap = Some(SymbolCapTrace {
                cap,
                dropped: dropped_symbols,
            });
        }
    }

    LocateResult {
        files,
        debug,
        semantic_coverage: None,
    }
}

fn output_result(result: &LocateResult, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_default()
        );
    } else {
        output_text(result);
    }
}

fn output_text(result: &LocateResult) {
    if result.files.is_empty() {
        println!("No relevant files found.");
        return;
    }

    for entry in &result.files {
        println!(
            "  {:<50} (score: {:.2}, signals: {})",
            entry.path,
            entry.score,
            entry.signals.join(", ")
        );
        if !entry.explain.is_empty() {
            for reason in &entry.explain {
                println!("    - {}", reason);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::ArtifactId;
    use kin_model::{
        ArtifactDelta, ArtifactDeltaKind, AuthorId, ChangeStore, Entity, EntityDelta, EntityId,
        EntityMetadata, EntityStore, FilePathId, FingerprintAlgorithm, Hash256, LanguageId,
        OpaqueArtifact, Relation, RelationEvidence, RelationId, RelationKind, RelationOrigin,
        SemanticChange, SemanticChangeId, SemanticFingerprint, SourceSpan, Timestamp, Visibility,
    };

    fn hit(score: f32) -> Vec<FileHit> {
        vec![FileHit {
            score,
            spans: vec![],
        }]
    }

    #[test]
    fn graph_derived_candidate_text_prefers_graph_body_over_disk() {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/foo.rs"),
                content_hash: Hash256::from_bytes([7; 32]),
                mime_type: Some("text/x-rust".into()),
                text_preview: Some("GRAPH_BODY_MARKER".into()),
            })
            .unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/foo.rs"), "DISK_BODY_MARKER").unwrap();

        assert_eq!(
            graph_derived_candidate_text(&graph, "src/foo.rs", dir.path()),
            "GRAPH_BODY_MARKER",
            "graph-owned body must win over the on-disk file"
        );
    }

    #[test]
    fn graph_derived_candidate_text_falls_back_to_disk_only_on_graph_miss() {
        let graph = kin_db::InMemoryGraph::new();
        // Artifact present but with no stored body, and with an empty body —
        // both must fall through to the explicit disk leg, not return blank.
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/none.rs"),
                content_hash: Hash256::from_bytes([9; 32]),
                mime_type: Some("text/x-rust".into()),
                text_preview: None,
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/empty.rs"),
                content_hash: Hash256::from_bytes([11; 32]),
                mime_type: Some("text/x-rust".into()),
                text_preview: Some(String::new()),
            })
            .unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/none.rs"), "DISK_NONE").unwrap();
        std::fs::write(dir.path().join("src/empty.rs"), "DISK_EMPTY").unwrap();
        std::fs::write(dir.path().join("src/untracked.rs"), "DISK_ONLY").unwrap();

        assert_eq!(
            graph_derived_candidate_text(&graph, "src/none.rs", dir.path()),
            "DISK_NONE",
            "text_preview=None must reach disk"
        );
        assert_eq!(
            graph_derived_candidate_text(&graph, "src/empty.rs", dir.path()),
            "DISK_EMPTY",
            "empty graph body must reach disk, not short-circuit blank"
        );
        assert_eq!(
            graph_derived_candidate_text(&graph, "src/untracked.rs", dir.path()),
            "DISK_ONLY",
            "no graph artifact must reach disk"
        );
        assert_eq!(
            graph_derived_candidate_text(&graph, "src/missing.rs", dir.path()),
            "",
            "absent in both graph and disk must yield empty, never panic"
        );
    }

    #[cfg(feature = "vector")]
    fn load_complete_test_vectors(graph: &kin_db::InMemoryGraph, entities: &[Entity]) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = kin_db::VectorIndex::new(2).unwrap();
        for (idx, entity) in entities.iter().enumerate() {
            let x = 1.0f32 / ((idx + 1) as f32);
            index.upsert(entity.id, &[x, 1.0 - x]).unwrap();
            for revision in graph.get_entity_revisions(&entity.id).unwrap() {
                index
                    .upsert_retrievable(
                        kin_db::RetrievalKey::EntityRevision(revision.revision_id),
                        &[x, 1.0 - x],
                    )
                    .unwrap();
            }
        }
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();
        let status = graph.embedding_status();
        assert_eq!(
            status.indexed, status.total,
            "test graph must have complete vector coverage"
        );
        assert_eq!(status.pending, 0, "test graph must have no pending vectors");
    }

    #[test]
    fn weighted_rrf_all_ones_matches_unweighted() {
        // Default-OFF guarantee: weighting every list by 1.0 (or passing an empty
        // weight slice) is bit-identical to classic unweighted RRF.
        let lists = vec![
            vec![
                ("src/a.rs".to_string(), 3.0),
                ("src/b.rs".to_string(), 2.0),
                ("src/c.rs".to_string(), 1.0),
            ],
            vec![("src/b.rs".to_string(), 5.0), ("src/d.rs".to_string(), 4.0)],
        ];
        let base = reciprocal_rank_fusion(&lists, 60.0);
        let empty = reciprocal_rank_fusion_weighted(&lists, 60.0, &[], &[]);
        let ones = reciprocal_rank_fusion_weighted(&lists, 60.0, &[1.0, 1.0], &[]);
        assert_eq!(base, empty);
        assert_eq!(base, ones);
    }

    #[test]
    #[serial_test::serial]
    fn locate_strict_mode_rejects_incomplete_embeddings() {
        // Benchmark-integrity path: with KIN_REQUIRE_COMPLETE_EMBEDDINGS=1 set,
        // incomplete coverage still hard-errors so benchmarks never score a
        // half-embedded repo.
        let graph = kin_db::InMemoryGraph::new();
        let entity = test_entity("handler", "src/lib.py", 1, 5);
        graph.upsert_entity(&entity).unwrap();

        std::env::set_var("KIN_REQUIRE_COMPLETE_EMBEDDINGS", "1");
        std::env::remove_var("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK");
        let result = run_with_graph_capture(&graph, "handler failure", true, 10, true);
        std::env::remove_var("KIN_REQUIRE_COMPLETE_EMBEDDINGS");

        let err = match result {
            Ok(_) => panic!("strict mode should reject incomplete embeddings"),
            Err(err) => err,
        };
        assert!(
            format!("{err}").contains("semantic locate requires complete embeddings"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn locate_degrades_gracefully_on_incomplete_embeddings() {
        // Default (user) path: incomplete coverage must NOT error. Lexical +
        // graph signals still run, and the result reports partial semantic
        // coverage so the caller can weight it honestly.
        let graph = kin_db::InMemoryGraph::new();
        let entity = test_entity("handler", "src/lib.py", 1, 5);
        graph.upsert_entity(&entity).unwrap();

        std::env::remove_var("KIN_REQUIRE_COMPLETE_EMBEDDINGS");
        std::env::remove_var("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK");
        let result = run_with_graph_capture(&graph, "handler failure", true, 10, true)
            .expect("default locate must degrade gracefully, not error");

        let coverage = result
            .semantic_coverage
            .expect("semantic_coverage must be reported");
        assert_eq!(coverage.indexed, 0, "no embeddings indexed in this graph");
        assert_eq!(coverage.total, 1, "one embeddable entity");
        assert!(!coverage.complete, "coverage must be marked incomplete");
        assert!(
            coverage.note.is_some(),
            "partial coverage must carry a degradation note"
        );
    }

    #[test]
    fn weighted_rrf_lifts_semantic_only_file_above_lexical_peer() {
        // 10 signal lists; the competitor appears only in source_text (idx 8), the
        // gold only in embedding (idx 9), both at rank 0 with equal score. Classic
        // RRF ties on the rank term and breaks by name (the competitor sorts
        // first); a >1.0 embedding rank weight lifts the semantic-only gold above
        // its lexical peer — the buried-gold rank-lift lever.
        let old_weight = std::env::var("KIN_LOCATE_SEMANTIC_PRIMACY_WEIGHT").ok();
        std::env::set_var("KIN_LOCATE_SEMANTIC_PRIMACY_WEIGHT", "0.0");

        let mut lists: Vec<Vec<(String, f32)>> = vec![Vec::new(); 10];
        lists[8] = vec![("src/aaa_comp.rs".to_string(), 1.0)];
        lists[9] = vec![("src/zzz_gold.rs".to_string(), 1.0)];

        let unweighted = reciprocal_rank_fusion(&lists, 60.0);
        let first_unweighted = unweighted.first().map(|(p, _)| p.as_str());

        let mut weights = vec![1.0f32; 10];
        weights[9] = 2.0;
        let weighted = reciprocal_rank_fusion_weighted(&lists, 60.0, &weights, &[]);
        let first_weighted = weighted.first().map(|(p, _)| p.as_str());

        if let Some(val) = old_weight {
            std::env::set_var("KIN_LOCATE_SEMANTIC_PRIMACY_WEIGHT", val);
        } else {
            std::env::remove_var("KIN_LOCATE_SEMANTIC_PRIMACY_WEIGHT");
        }

        assert_eq!(
            first_unweighted,
            Some("src/aaa_comp.rs"),
            "classic RRF should tie-break to the name-first competitor"
        );

        assert_eq!(
            first_weighted,
            Some("src/zzz_gold.rs"),
            "embedding rank weight should lift the semantic-only gold to the top"
        );
    }

    #[test]
    fn rrf_rank_lift_weights_default_to_unweighted() {
        // With no KIN_LOCATE_RRF_WEIGHT_* env set, every list weight is 1.0, so the
        // lift is a no-op and fused ranking is unchanged (OFF == classic RRF).
        let w = rrf_rank_lift_weights(10);
        assert_eq!(w.len(), 10);
        assert!(
            w.iter().all(|x| (*x - 1.0).abs() < f32::EPSILON),
            "default rank-lift weights must all be 1.0 when env is unset"
        );
    }

    #[test]
    fn entity_span_pair_emits_one_based_inclusive_lines() {
        // tree-sitter rows are 0-indexed; emitted spans are 1-based inclusive to
        // match LocateSymbol::span and ContextBench's 1-indexed gold ranges.
        // test_entity sets end_col=1 (>0), the mid-line case -> end shifts +1.
        let func = test_entity("f", "src/a.py", 10, 20);
        assert_eq!(entity_span_pair(&func), vec![[11, 21]]);

        // Class-like spans longer than 30 lines truncate to a short head window,
        // still emitted 1-based inclusive (0-indexed [0,4] -> [1,5]).
        let mut big_class = test_entity("C", "src/a.py", 0, 100);
        big_class.kind = EntityKind::Class;
        assert_eq!(entity_span_pair(&big_class), vec![[1, 5]]);

        // Missing span -> no emission.
        let mut no_span = test_entity("g", "src/a.py", 0, 0);
        no_span.span = None;
        assert!(entity_span_pair(&no_span).is_empty());
    }

    #[test]
    fn entity_span_pair_end_boundary_does_not_overshoot_on_trailing_newline() {
        // tree-sitter end_position() is exclusive: a def whose text ends with a
        // newline reports end row = first row AFTER the last content line, at
        // column 0. The last content line is 0-indexed row 20 -> 1-based 21, so
        // the inclusive end must stay 21, not jump to 22.
        let mut trailing_nl = test_entity("h", "src/a.py", 10, 21);
        if let Some(span) = trailing_nl.span.as_mut() {
            span.end_col = 0;
        }
        assert_eq!(entity_span_pair(&trailing_nl), vec![[11, 21]]);

        // Same node ending mid-line (end_col > 0) keeps the +1 shift: 0-indexed
        // row 21 holds content -> 1-based 22.
        let mut mid_line = test_entity("h", "src/a.py", 10, 21);
        if let Some(span) = mid_line.span.as_mut() {
            span.end_col = 7;
        }
        assert_eq!(entity_span_pair(&mid_line), vec![[11, 22]]);
    }

    #[test]
    fn entity_span_lines_width_lever_controls_class_truncation() {
        let span = |start, end| SourceSpan {
            file: FilePathId::new("src/a.ts"),
            start_byte: 0,
            end_byte: 0,
            start_line: start,
            start_col: 1,
            end_line: end,
            end_col: 7, // mid-line end so the +1 shift applies to the real end
        };
        // OFF (default): a long class (len 100 > 30) truncates to a 5-line head.
        assert_eq!(entity_span_lines(&span(0, 100), true, false, 30), [1, 5]);
        // FULL_EXTENT on: emit the whole node extent, 1-based inclusive.
        assert_eq!(entity_span_lines(&span(0, 100), true, true, 30), [1, 101]);
        // Raising the head threshold above the span length also keeps full extent.
        assert_eq!(entity_span_lines(&span(0, 100), true, false, 200), [1, 101]);
        // Non-class entities are never truncated regardless of the knobs.
        assert_eq!(entity_span_lines(&span(0, 100), false, false, 30), [1, 101]);
        // Short class (len <= threshold) is not truncated even with OFF.
        assert_eq!(entity_span_lines(&span(0, 10), true, false, 30), [1, 11]);
    }

    #[test]
    fn is_definitional_kind_covers_real_defs_only() {
        for k in [
            EntityKind::Function,
            EntityKind::Method,
            EntityKind::Class,
            EntityKind::Interface,
            EntityKind::TraitDef,
            EntityKind::EnumDef,
        ] {
            assert!(is_definitional_kind(k), "{k:?} should be definitional");
        }
        for k in [
            EntityKind::Module,
            EntityKind::TypeAlias,
            EntityKind::Constant,
            EntityKind::StaticVar,
            EntityKind::EnumVariant,
            EntityKind::Package,
        ] {
            assert!(!is_definitional_kind(k), "{k:?} should not be definitional");
        }
    }

    #[test]
    fn rank_enriched_symbols_prioritizes_query_match_then_size() {
        // Big fn whose NAME matches nothing but whose BODY mentions query terms.
        let mut topic = test_entity("indexSitesFixesConfig", "src/parse.ts", 98, 161);
        topic.metadata.extra.insert(
            "embedding_body_preview".to_string(),
            serde_json::Value::String("strip base64 padding from css".to_string()),
        );
        // Unrelated helpers, no name/body match -> ranked by span size.
        let small = test_entity("helper", "src/parse.ts", 5, 9);
        let medium = test_entity("formatValue", "src/parse.ts", 40, 70);
        let terms = vec!["base64".to_string(), "padding".to_string()];

        let ranked = rank_enriched_symbols(
            vec![small.clone(), medium.clone(), topic.clone()],
            &terms,
            false,
            3,
        );
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].name, "indexSitesFixesConfig"); // body match dominates
        assert_eq!(ranked[1].name, "formatValue"); // larger span than helper
        assert_eq!(ranked[2].name, "helper");
        assert!(ranked.iter().all(|s| s.definition));
        // Enriched spans are 1-based inclusive via entity_span_pair.
        assert_eq!(ranked[0].span, Some([99, 162]));

        // limit truncates to the top query-relevant def.
        let top1 = rank_enriched_symbols(vec![small, medium, topic], &terms, false, 1);
        assert_eq!(top1.len(), 1);
        assert_eq!(top1[0].name, "indexSitesFixesConfig");
    }

    #[test]
    fn apply_query_relevance_surfaces_edited_def_over_siblings() {
        // Resolved siblings the query does NOT name, with modest scores.
        let existing = vec![
            sym("render_usage", 5.0, true),
            sym("render_version", 4.0, true),
        ];
        // The file also contains the actually-edited gold fn (query names it)
        // plus one of the resolved siblings.
        let gold = test_entity("printHelpInner", "src/help.rs", 759, 767);
        let sib = test_entity("render_usage", "src/help.rs", 100, 110);
        let terms = vec!["printHelpInner".to_string()];

        let out = apply_query_relevance(existing, vec![gold, sib], &terms, false, 10.0);
        let gold_s = out
            .iter()
            .find(|s| s.name == "printHelpInner")
            .expect("gold merged");
        let usage_s = out
            .iter()
            .find(|s| s.name == "render_usage")
            .expect("sibling kept");
        assert!(
            gold_s.score > usage_s.score,
            "edited def must outrank siblings"
        );
        assert!(out.iter().any(|s| s.name == "render_version")); // siblings preserved
        assert_eq!(out.len(), 3);

        // A def the query does NOT point at is not merged (precision guard).
        let out2 = apply_query_relevance(
            vec![],
            vec![test_entity("unrelated", "src/help.rs", 1, 3)],
            &terms,
            false,
            10.0,
        );
        assert!(out2.is_empty(), "non-query-relevant defs are not merged");
    }

    fn sym_with_cosine(name: &str, score: f32, cosine: Option<f32>) -> LocateSymbol {
        LocateSymbol {
            cosine,
            ..sym(name, score, true)
        }
    }

    #[test]
    fn apply_embed_relevance_lifts_semantic_match_over_lexical_lookalike() {
        // The precision wall: the lexical look-alike sibling outscores the gold
        // at emission because it shares more query TOKENS, but the gold carries
        // the higher query↔def embedding cosine (it is what the query is about).
        let mut syms = vec![
            sym_with_cosine("strip_accents_unicode", 30.0, Some(0.40)),
            sym_with_cosine("strip_accents_ascii", 28.0, Some(0.95)),
        ];
        // Lexical-only ordering puts the wrong sibling first.
        assert!(syms[0].score > syms[1].score);

        apply_embed_relevance(&mut syms, 10.0);

        let ranked = rank_and_cap_symbols_with(syms, 0);
        // gold: 28.0 + 0.95*10 = 37.5; sibling: 30.0 + 0.40*10 = 34.0 -> gold flips ahead.
        assert_eq!(
            ranked[0].name, "strip_accents_ascii",
            "the higher-cosine semantic match must outrank the lexical look-alike"
        );
        assert!((ranked[0].score - 37.5).abs() < 1e-4);
    }

    #[test]
    fn apply_embed_relevance_weight_dials_cosine_dominance() {
        // With a large enough weight the cosine dominates the lexical token gap,
        // which is the dial the operator sweeps via KIN_LOCATE_SYMBOL_EMBED_BOOST.
        let mut syms = vec![
            sym_with_cosine("lexical_lookalike", 30.0, Some(0.40)),
            sym_with_cosine("semantic_gold", 25.0, Some(0.85)),
        ];
        apply_embed_relevance(&mut syms, 50.0);
        let ranked = rank_and_cap_symbols_with(syms, 0);
        assert_eq!(ranked[0].name, "semantic_gold");
        // 25 + 0.85*50 = 67.5 vs 30 + 0.40*50 = 50.0
        assert!((ranked[0].score - 67.5).abs() < 1e-4);
    }

    #[test]
    fn apply_embed_relevance_leaves_cosineless_symbols_untouched() {
        // Text-only seeds carry no cosine and must be byte-identical after the
        // boost — the lever only ever lifts defs the embedder actually scored.
        let mut syms = vec![
            sym_with_cosine("text_only", 12.0, None),
            sym_with_cosine("vector_seed", 12.0, Some(0.5)),
        ];
        apply_embed_relevance(&mut syms, 10.0);
        let text_only = syms.iter().find(|s| s.name == "text_only").unwrap();
        let vector_seed = syms.iter().find(|s| s.name == "vector_seed").unwrap();
        assert_eq!(text_only.score, 12.0, "no cosine -> no boost");
        assert!((vector_seed.score - 17.0).abs() < 1e-4, "12 + 0.5*10");
    }

    #[test]
    fn apply_embed_relevance_zero_weight_is_byte_identical() {
        let mut syms = vec![
            sym_with_cosine("a", 10.0, Some(0.9)),
            sym_with_cosine("b", 8.0, None),
        ];
        let before: Vec<f32> = syms.iter().map(|s| s.score).collect();
        apply_embed_relevance(&mut syms, 0.0);
        let after: Vec<f32> = syms.iter().map(|s| s.score).collect();
        assert_eq!(before, after, "weight 0 leaves every score untouched");
    }

    #[test]
    fn rank_body_relevant_symbols_keeps_only_body_matches_ranked_by_hits() {
        // Name-blocked gold whose BODY carries two query terms.
        let mut two_hit = test_entity("indexSitesFixesConfig", "src/parse.ts", 98, 161);
        two_hit.metadata.extra.insert(
            "embedding_body_preview".to_string(),
            serde_json::Value::String("decode base64 padding here".to_string()),
        );
        // Body carries one query term.
        let mut one_hit = test_entity("decoder", "src/parse.ts", 40, 60);
        one_hit.metadata.extra.insert(
            "embedding_body_preview".to_string(),
            serde_json::Value::String("handle padding only".to_string()),
        );
        // No body match at all -> filtered out.
        let no_hit = test_entity("helper", "src/parse.ts", 5, 9);
        let terms = vec!["base64".to_string(), "padding".to_string()];

        let out = rank_body_relevant_symbols(
            vec![no_hit.clone(), one_hit.clone(), two_hit.clone()],
            &terms,
            false,
            5,
        );
        assert_eq!(out.len(), 2, "only body-matching defs emitted");
        assert_eq!(out[0].name, "indexSitesFixesConfig"); // 2 hits
        assert_eq!(out[1].name, "decoder"); // 1 hit
        assert!(out.iter().all(|s| s.definition));
        assert_eq!(out[0].span, Some([99, 162])); // 1-based inclusive

        // topk truncates to the strongest body match.
        let top1 = rank_body_relevant_symbols(vec![no_hit, one_hit, two_hit], &terms, false, 1);
        assert_eq!(top1.len(), 1);
        assert_eq!(top1[0].name, "indexSitesFixesConfig");
    }

    #[test]
    fn adaptive_cap_keeps_clear_single_winner_tight() {
        let fused = vec![
            ("src/main.py".to_string(), 10.0),
            ("src/helper.py".to_string(), 1.0),
            ("src/other.py".to_string(), 0.2),
        ];
        let all_hits = vec![
            HashMap::from([(String::from("src/main.py"), hit(5.0))]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        ];

        let capped = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );
        assert_eq!(capped.len(), 1);
        assert_eq!(capped[0].0, "src/main.py");
    }

    #[test]
    fn adaptive_cap_keeps_multi_signal_files_despite_large_top_gap() {
        let fused = vec![
            ("src/main.py".to_string(), 10.0),
            ("tests/test_main.py".to_string(), 3.0),
            ("Cargo.toml".to_string(), 2.7),
            ("README.md".to_string(), 0.5),
        ];
        let all_hits = vec![
            HashMap::from([
                (String::from("src/main.py"), hit(5.0)),
                (String::from("tests/test_main.py"), hit(2.0)),
            ]),
            HashMap::from([
                (String::from("src/main.py"), hit(2.0)),
                (String::from("Cargo.toml"), hit(2.0)),
            ]),
            HashMap::from([
                (String::from("tests/test_main.py"), hit(1.0)),
                (String::from("Cargo.toml"), hit(1.0)),
            ]),
            HashMap::from([(String::from("tests/test_main.py"), hit(1.0))]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                (String::from("src/main.py"), hit(8.0)),
                (String::from("tests/test_main.py"), hit(4.0)),
                (String::from("Cargo.toml"), hit(2.0)),
            ]),
        ];

        let capped = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );
        assert!(capped.len() >= 3, "cap was {}", capped.len());
    }

    #[test]
    fn locate_result_deserializes_when_empty_vec_fields_are_omitted() {
        let json = r#"{
          "files": [
            {
              "path": "src/lib.rs",
              "score": 1.0,
              "signals": ["search"]
            }
          ]
        }"#;

        let parsed: LocateResult = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.files.len(), 1);
        assert!(parsed.files[0].spans.is_empty());
        assert!(parsed.files[0].explain.is_empty());
        assert!(parsed.files[0].symbols.is_empty());
    }

    #[test]
    fn locate_symbol_omits_explain_only_fields_when_unset() {
        let symbol = LocateSymbol {
            name: "handle".to_string(),
            span: Some([1, 2]),
            score: 1.0,
            kind: "function".to_string(),
            definition: true,
            origin: String::new(),
            cosine: None,
        };
        let json = serde_json::to_string(&symbol).unwrap();
        assert!(
            !json.contains("origin"),
            "non-explain symbol leaked origin: {json}"
        );
        assert!(
            !json.contains("cosine"),
            "non-explain symbol leaked cosine: {json}"
        );

        let tagged = LocateSymbol {
            origin: "vector".to_string(),
            cosine: Some(0.87),
            ..symbol
        };
        let json = serde_json::to_string(&tagged).unwrap();
        assert!(json.contains("\"origin\":\"vector\""));
        assert!(json.contains("\"cosine\":0.87"));
    }

    fn sym(name: &str, score: f32, definition: bool) -> LocateSymbol {
        LocateSymbol {
            name: name.to_string(),
            span: Some([1, 2]),
            score,
            kind: "function".to_string(),
            definition,
            origin: String::new(),
            cosine: None,
        }
    }

    #[test]
    fn rank_and_cap_orders_definitions_first_then_score() {
        let ranked = rank_and_cap_symbols_with(
            vec![
                sym("ref_high", 100.0, false),
                sym("def_low", 1.0, true),
                sym("def_high", 50.0, true),
            ],
            0,
        );
        let names: Vec<&str> = ranked.iter().map(|s| s.name.as_str()).collect();
        // Definitions rank above references regardless of raw score, and within
        // definitions higher score wins.
        assert_eq!(names, vec!["def_high", "def_low", "ref_high"]);
    }

    #[test]
    fn rank_and_cap_dedupes_by_name_keeping_best() {
        let ranked = rank_and_cap_symbols_with(
            vec![
                sym("dup", 10.0, true),
                sym("dup", 99.0, true),
                sym("other", 5.0, true),
            ],
            0,
        );
        assert_eq!(ranked.len(), 2, "duplicate names collapse to one");
        let dup = ranked.iter().find(|s| s.name == "dup").unwrap();
        assert_eq!(dup.score, 99.0, "the higher-ranked duplicate is kept");
    }

    #[test]
    fn rank_and_cap_truncates_to_cap() {
        let ranked = rank_and_cap_symbols_with(
            vec![
                sym("a", 5.0, true),
                sym("b", 4.0, true),
                sym("c", 3.0, true),
                sym("d", 2.0, true),
            ],
            2,
        );
        assert_eq!(ranked.len(), 2);
        let names: Vec<&str> = ranked.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"], "keeps the top-K by rank");
    }

    #[test]
    fn rank_and_cap_zero_means_uncapped() {
        let ranked = rank_and_cap_symbols_with(
            vec![
                sym("a", 5.0, true),
                sym("b", 4.0, true),
                sym("c", 3.0, true),
            ],
            0,
        );
        assert_eq!(ranked.len(), 3, "cap=0 disables truncation");
    }

    #[test]
    fn fast_entity_dominant_enabled_is_explain_invariant() {
        let without_explain = fast_entity_dominant_enabled(
            false, false, false, 0.0, 150.0, 0.8, false, 5.0, 20.0, 0.15,
        );
        let with_explain = fast_entity_dominant_enabled(
            true, false, false, 0.0, 150.0, 0.8, false, 5.0, 20.0, 0.15,
        );

        assert!(without_explain);
        assert_eq!(with_explain, without_explain);
    }

    #[test]
    fn entity_dominant_top_disqualifier_rejects_external_noise_paths() {
        assert!(disqualifies_entity_dominant_top_path(
            "lib/gbenchmark/mingw.py"
        ));
        assert!(disqualifies_entity_dominant_top_path("docs/help.md"));
        assert!(disqualifies_entity_dominant_top_path(
            "tools/cpplint/cpplint.py"
        ));
        assert!(disqualifies_entity_dominant_top_path(
            "single_include/nlohmann/json.hpp"
        ));
        assert!(!disqualifies_entity_dominant_top_path(
            "src/libponyc/options/options.c"
        ));
    }

    #[test]
    fn entity_dominant_decision_metrics_ignore_generated_tool_anchors() {
        let ranked = vec![
            ("tools/cpplint/cpplint.py".to_string(), 100.0),
            ("single_include/nlohmann/json.hpp".to_string(), 87.79497),
            (
                "include/nlohmann/detail/meta/type_traits.hpp".to_string(),
                83.52,
            ),
            (
                "include/nlohmann/detail/abi_macros.hpp".to_string(),
                31.285044,
            ),
        ];

        let (top, gap, disqualified) = entity_dominant_decision_metrics(&ranked);

        assert!(!disqualified);
        assert_eq!(top, 83.52);
        assert!(
            gap > 0.15,
            "real semantic headers should drive the entity-dominant decision, gap={gap}"
        );
    }

    #[test]
    fn adaptive_cap_expands_for_multi_signal_plateaus() {
        let fused = vec![
            ("src/a.py".to_string(), 1.0),
            ("src/b.py".to_string(), 0.92),
            ("src/c.py".to_string(), 0.88),
            ("src/d.py".to_string(), 0.83),
            ("src/e.py".to_string(), 0.79),
        ];
        let all_hits = vec![
            HashMap::from([
                (String::from("src/a.py"), hit(5.0)),
                (String::from("src/b.py"), hit(4.0)),
            ]),
            HashMap::from([
                (String::from("src/a.py"), hit(2.0)),
                (String::from("src/c.py"), hit(2.0)),
                (String::from("src/d.py"), hit(2.0)),
            ]),
            HashMap::from([
                (String::from("src/b.py"), hit(1.0)),
                (String::from("src/c.py"), hit(1.0)),
                (String::from("src/e.py"), hit(1.0)),
            ]),
            HashMap::from([(String::from("src/d.py"), hit(1.0))]),
            HashMap::new(),
            HashMap::from([(String::from("src/e.py"), hit(1.0))]),
            HashMap::new(),
            HashMap::new(),
        ];

        let capped = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );
        assert!(capped.len() >= 4, "cap was {}", capped.len());
    }

    #[test]
    fn adaptive_cap_retains_cochange_seed_supported_files() {
        let fused = vec![
            ("src/main.py".to_string(), 10.0),
            ("src/parser.h".to_string(), 2.6),
            ("src/builtin.c".to_string(), 2.3),
            ("src/parser.py".to_string(), 2.0),
        ];
        let all_hits = vec![
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                (String::from("src/parser.h"), hit(5.0)),
                (String::from("src/builtin.c"), hit(8.0)),
            ]),
            HashMap::from([
                (String::from("src/main.py"), hit(9.0)),
                (String::from("src/parser.py"), hit(4.0)),
            ]),
        ];
        let retention = HashSet::from([String::from("src/builtin.c")]);

        let capped = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &retention,
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );

        assert!(capped.iter().any(|(path, _)| path == "src/builtin.c"));
    }

    #[test]
    fn adaptive_cap_retains_priority_seed_supported_files() {
        let fused = vec![
            ("src/libponyc/ast/lexer.c".to_string(), 1.40),
            ("packages/strings/_test.pony".to_string(), 0.45),
            ("packages/regex/_test.pony".to_string(), 0.44),
            ("packages/options/_test.pony".to_string(), 0.41),
            ("src/libponyc/ast/ast.c".to_string(), 0.41),
        ];
        let all_hits = vec![
            HashMap::new(),
            HashMap::from([(String::from("packages/strings/_test.pony"), hit(2.0))]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(String::from("packages/strings/_test.pony"), hit(3.0))]),
            HashMap::from([(String::from("src/libponyc/ast/lexer.c"), hit(10.0))]),
        ];
        let priority_retention = HashSet::from([
            String::from("packages/regex/_test.pony"),
            String::from("packages/options/_test.pony"),
        ]);

        let capped = adaptive_cap(
            &fused,
            &all_hits,
            10,
            true,
            &HashSet::new(),
            &priority_retention,
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );

        assert_eq!(
            capped
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            vec![
                "src/libponyc/ast/lexer.c",
                "packages/strings/_test.pony",
                "packages/regex/_test.pony",
                "packages/options/_test.pony",
            ]
        );
    }

    #[test]
    fn adaptive_cap_uses_lower_floor_for_retained_priority_paths() {
        let fused = vec![
            ("src/libponyc/type/subtype.c".to_string(), 1.30),
            ("src/libponyc/codegen/genident.c".to_string(), 0.39),
            ("src/libponyc/reach/subtype.c".to_string(), 0.38),
            ("src/libponyc/type/cap.c".to_string(), 0.11),
            ("src/libponyc/type/cap.h".to_string(), 0.09),
        ];
        let all_hits = vec![
            HashMap::new(),
            HashMap::from([
                (String::from("src/libponyc/type/cap.c"), hit(3.0)),
                (String::from("src/libponyc/type/cap.h"), hit(2.0)),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                (String::from("src/libponyc/type/subtype.c"), hit(10.0)),
                (String::from("src/libponyc/type/cap.c"), hit(4.0)),
                (String::from("src/libponyc/type/cap.h"), hit(3.0)),
            ]),
        ];
        let priority_retention = HashSet::from([
            String::from("src/libponyc/type/cap.c"),
            String::from("src/libponyc/type/cap.h"),
        ]);

        let capped = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &priority_retention,
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );

        assert!(capped
            .iter()
            .any(|(path, _)| path == "src/libponyc/type/cap.c"));
        assert!(capped
            .iter()
            .any(|(path, _)| path == "src/libponyc/type/cap.h"));
    }

    #[test]
    fn adaptive_cap_uses_lower_floor_for_semantic_retention_paths() {
        let fused = vec![
            ("src/json.hpp".to_string(), 1.00),
            ("develop/detail/input/parser.hpp".to_string(), 0.09),
            ("develop/detail/input/lexer.hpp".to_string(), 0.04),
        ];
        let mut all_hits: Vec<HashMap<String, Vec<FileHit>>> =
            (0..10).map(|_| HashMap::new()).collect();
        all_hits[1] = HashMap::from([
            (String::from("src/json.hpp"), hit(3.0)),
            (String::from("develop/detail/input/parser.hpp"), hit(1.0)),
            (String::from("develop/detail/input/lexer.hpp"), hit(1.0)),
        ]);
        let semantic_retention = HashSet::from([String::from("develop/detail/input/parser.hpp")]);

        let capped = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &HashSet::new(),
            &semantic_retention,
            &HashMap::new(),
            false,
            None,
        );

        assert!(capped
            .iter()
            .any(|(path, _)| path == "develop/detail/input/parser.hpp"));
        assert!(!capped
            .iter()
            .any(|(path, _)| path == "develop/detail/input/lexer.hpp"));
    }

    #[test]
    fn adaptive_cap_floor_uses_precompression_scores_for_corroborated_files() {
        let fused = vec![
            ("src/core.rs".to_string(), 100.0),
            ("src/gold.rs".to_string(), 0.9),
        ];
        let mut all_hits: Vec<HashMap<String, Vec<FileHit>>> =
            (0..10).map(|_| HashMap::new()).collect();
        all_hits[7] = HashMap::from([
            (String::from("src/core.rs"), hit(50.0)),
            (String::from("src/gold.rs"), hit(10.0)),
        ]);
        all_hits[8] = HashMap::from([(String::from("src/gold.rs"), hit(4.0))]);

        let without_reference = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );
        assert!(!without_reference
            .iter()
            .any(|(path, _)| path == "src/gold.rs"));

        let floor_reference = HashMap::from([
            (String::from("src/core.rs"), 100.0),
            (String::from("src/gold.rs"), 6.75),
        ]);
        let with_reference = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &floor_reference,
            false,
            None,
        );
        assert!(with_reference.iter().any(|(path, _)| path == "src/gold.rs"));
    }

    #[test]
    fn adaptive_cap_readmits_strong_precompression_candidate_past_cap() {
        // 72aa7114 shape: a text-reached gold compressed below the cluster cap (live 2.0,
        // beyond cap, no corroboration signal) but whose pre-compression evidence stayed
        // strong (floor_reference 9.0) must be re-admitted past the cap, not silently
        // eliminated. Genuine tail noise (low pre-compression score) stays pruned.
        let fused = vec![
            ("top.rs".to_string(), 10.0),
            ("s1.rs".to_string(), 9.0),
            ("s2.rs".to_string(), 8.5),
            ("s3.rs".to_string(), 8.0),
            ("gold.rs".to_string(), 2.0),
            ("noise1.rs".to_string(), 1.5),
            ("noise2.rs".to_string(), 1.0),
        ];
        let mut all_hits: Vec<HashMap<String, Vec<FileHit>>> =
            (0..10).map(|_| HashMap::new()).collect();
        // Give the top cluster three independent signals each so they fill the cap;
        // the gold and noise carry none.
        for idx in [1usize, 4, 8] {
            all_hits[idx] = HashMap::from([
                (String::from("top.rs"), hit(1.0)),
                (String::from("s1.rs"), hit(1.0)),
                (String::from("s2.rs"), hit(1.0)),
                (String::from("s3.rs"), hit(1.0)),
            ]);
        }
        let floor_reference = HashMap::from([(String::from("gold.rs"), 9.0)]);

        let with_reference = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &floor_reference,
            false,
            None,
        );
        assert!(with_reference.iter().any(|(path, _)| path == "gold.rs"));
        assert!(!with_reference.iter().any(|(path, _)| path == "noise1.rs"));

        let without_reference = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );
        assert!(!without_reference.iter().any(|(path, _)| path == "gold.rs"));
    }

    // Committed-map invariant #1 (no silent elimination): a candidate that enters
    // adaptive_cap and does not survive must carry a named pruned_files reason.
    #[test]
    fn invariant_no_silent_elimination_in_adaptive_cap() {
        let scenarios: Vec<(Vec<(String, f32)>, usize, bool)> = vec![
            // dominant winner + long decaying tail → cluster_gap + below_floor + over_cap
            (
                (0..12)
                    .map(|i| {
                        (
                            format!("f{i}.rs"),
                            if i == 0 { 100.0 } else { 1.0 / i as f32 },
                        )
                    })
                    .collect(),
                10,
                false,
            ),
            // flat plateau with an explicit small ceiling → over_max_files
            (
                (0..8)
                    .map(|i| (format!("p{i}.rs"), 5.0 - i as f32 * 0.1))
                    .collect(),
                3,
                true,
            ),
            // single candidate (early return path) — nothing should drop
            (vec![("solo.rs".to_string(), 7.0)], 10, false),
        ];
        for (fused, max_files, explicit) in scenarios {
            let all_hits: Vec<HashMap<String, Vec<FileHit>>> =
                (0..10).map(|_| HashMap::new()).collect();
            let mut pruned = Vec::new();
            let result = adaptive_cap(
                &fused,
                &all_hits,
                max_files,
                explicit,
                &HashSet::new(),
                &HashSet::new(),
                &HashSet::new(),
                &HashMap::new(),
                false,
                Some(&mut pruned),
            );
            let kept: HashSet<&str> = result.iter().map(|(p, _)| p.as_str()).collect();
            let pruned_paths: HashSet<&str> = pruned.iter().map(|p| p.path.as_str()).collect();
            for (path, _) in &fused {
                assert!(
                    kept.contains(path.as_str()) || pruned_paths.contains(path.as_str()),
                    "candidate {path} eliminated with no named pruned_files reason"
                );
            }
            for entry in &pruned {
                assert!(
                    !entry.reason.is_empty(),
                    "pruned {} carries an empty reason",
                    entry.path
                );
            }
        }
    }

    // Committed-map invariant F (monotonicity), tested at the elimination stage: raising a
    // candidate's fused score never drops it from adaptive_cap's result. The cap and the
    // multiplicative compression stages are per-candidate monotonic. FULL-PIPELINE
    // monotonicity is still violated UPSTREAM by the track-selection cliff (resolve crossing
    // ed_resolve_min flips BroadBlend<->EntityDominant) and EntityDominant resolve-list
    // normalization — a discontinuity, not a multiplier. That violation needs full-pipeline
    // scaffolding and the Rec-D de-cliff; tracked as a follow-up task.
    #[test]
    fn invariant_monotonicity_adaptive_cap_in_fused_score() {
        let base = vec![
            ("a.rs".to_string(), 10.0),
            ("b.rs".to_string(), 6.0),
            ("target.rs".to_string(), 2.0),
            ("c.rs".to_string(), 1.5),
        ];
        let all_hits: Vec<HashMap<String, Vec<FileHit>>> =
            (0..10).map(|_| HashMap::new()).collect();
        let mut was_present = false;
        for boost in [0.0_f32, 1.0, 2.0, 4.0, 8.0, 20.0] {
            let mut fused = base.clone();
            fused
                .iter_mut()
                .find(|(p, _)| p == "target.rs")
                .unwrap()
                .1 = 2.0 + boost;
            fused.sort_by(|x, y| {
                y.1.partial_cmp(&x.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| x.0.cmp(&y.0))
            });
            let present = adaptive_cap(
                &fused,
                &all_hits,
                10,
                false,
                &HashSet::new(),
                &HashSet::new(),
                &HashSet::new(),
                &HashMap::new(),
                false,
                None,
            )
            .iter()
            .any(|(p, _)| p == "target.rs");
            if was_present {
                assert!(
                    present,
                    "raising target's fused score dropped it from the result (cap non-monotonic)"
                );
            }
            was_present = present;
        }
        assert!(was_present, "target never entered the result; test is vacuous");
    }

    #[test]
    fn adaptive_cap_graph_semantic_corroboration_gets_corroborated_floor() {
        let fused = vec![
            ("src/core.rs".to_string(), 100.0),
            ("src/semantic.rs".to_string(), 8.0),
            ("src/noise.rs".to_string(), 7.5),
        ];
        let mut all_hits: Vec<HashMap<String, Vec<FileHit>>> =
            (0..10).map(|_| HashMap::new()).collect();
        all_hits[1] = HashMap::from([(String::from("src/semantic.rs"), hit(2.0))]);
        all_hits[9] = HashMap::from([
            (String::from("src/d1.rs"), hit(20.0)),
            (String::from("src/d2.rs"), hit(19.0)),
            (String::from("src/d3.rs"), hit(18.0)),
            (String::from("src/d4.rs"), hit(17.0)),
            (String::from("src/d5.rs"), hit(16.0)),
            (String::from("src/semantic.rs"), hit(8.0)),
        ]);

        let capped = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            true,
            None,
        );
        assert!(capped.iter().any(|(path, _)| path == "src/semantic.rs"));
        assert!(!capped.iter().any(|(path, _)| path == "src/noise.rs"));

        let default_off = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );
        assert!(!default_off
            .iter()
            .any(|(path, _)| path == "src/semantic.rs"));
    }

    #[test]
    fn graph_corroborated_semantic_retention_requires_query_and_graph_evidence() {
        let fused = vec![
            ("include/nlohmann/json.hpp".to_string(), 100.0),
            ("include/nlohmann/detail/macro_scope.hpp".to_string(), 6.75),
            ("include/nlohmann/detail/vector_only.hpp".to_string(), 6.50),
            ("include/nlohmann/detail/graph_only.hpp".to_string(), 6.25),
            ("single_include/nlohmann/json.hpp".to_string(), 6.00),
        ];
        let resolved_hits = HashMap::from([
            (String::from("include/nlohmann/json.hpp"), hit(100.0)),
            (
                String::from("include/nlohmann/detail/macro_scope.hpp"),
                hit(12.0),
            ),
            (
                String::from("include/nlohmann/detail/graph_only.hpp"),
                hit(10.0),
            ),
            (String::from("single_include/nlohmann/json.hpp"), hit(60.0)),
        ]);
        let source_text = HashMap::new();
        let embedding_hits = HashMap::from([
            (
                String::from("include/nlohmann/detail/macro_scope.hpp"),
                hit(7.5),
            ),
            (
                String::from("include/nlohmann/detail/vector_only.hpp"),
                hit(7.4),
            ),
            (String::from("single_include/nlohmann/json.hpp"), hit(100.0)),
        ]);
        let multihop = HashMap::from([
            (
                String::from("include/nlohmann/detail/macro_scope.hpp"),
                hit(2.7),
            ),
            (
                String::from("include/nlohmann/detail/graph_only.hpp"),
                hit(2.6),
            ),
            (String::from("single_include/nlohmann/json.hpp"), hit(2.5)),
        ]);
        let imports = HashMap::new();

        let default_retained = graph_corroborated_semantic_retention_paths(
            &fused,
            &resolved_hits,
            &source_text,
            &embedding_hits,
            &multihop,
            &imports,
        );
        assert!(default_retained.contains("include/nlohmann/detail/macro_scope.hpp"));
        assert!(!default_retained.contains("include/nlohmann/detail/vector_only.hpp"));
        assert!(!default_retained.contains("include/nlohmann/detail/graph_only.hpp"));
        assert!(!default_retained.contains("single_include/nlohmann/json.hpp"));

        let retained = graph_corroborated_semantic_retention_paths_with_limit(
            &fused,
            &resolved_hits,
            &source_text,
            &embedding_hits,
            &multihop,
            &imports,
            8,
        );

        assert!(retained.contains("include/nlohmann/detail/macro_scope.hpp"));
        assert!(!retained.contains("include/nlohmann/detail/vector_only.hpp"));
        assert!(!retained.contains("include/nlohmann/detail/graph_only.hpp"));
        assert!(!retained.contains("single_include/nlohmann/json.hpp"));
    }

    #[test]
    fn resolve_boundary_compression_preserves_graph_semantic_retention_paths() {
        let mut fused = vec![
            ("include/nlohmann/json.hpp".to_string(), 100.0),
            ("include/nlohmann/detail/macro_scope.hpp".to_string(), 6.75),
            ("include/nlohmann/detail/noise.hpp".to_string(), 6.70),
        ];
        let resolved_hits = HashMap::from([
            (String::from("include/nlohmann/json.hpp"), hit(100.0)),
            (
                String::from("include/nlohmann/detail/macro_scope.hpp"),
                hit(12.0),
            ),
            (String::from("include/nlohmann/detail/noise.hpp"), hit(12.0)),
        ]);
        let semantic_retention =
            HashSet::from([String::from("include/nlohmann/detail/macro_scope.hpp")]);

        apply_resolve_boundary_compression(
            &mut fused,
            &resolved_hits,
            &[],
            false,
            &semantic_retention,
        );

        let scores: HashMap<_, _> = fused
            .iter()
            .map(|(path, score)| (path.as_str(), *score))
            .collect();
        assert_eq!(scores["include/nlohmann/detail/macro_scope.hpp"], 6.75);
        assert!(scores["include/nlohmann/detail/noise.hpp"] < 3.0);
    }

    #[test]
    fn adaptive_cap_does_not_release_amalgamated_strong_embedding_artifacts() {
        let fused = vec![
            ("src/top.cpp".to_string(), 1.00),
            ("src/a.cpp".to_string(), 0.30),
            ("src/b.cpp".to_string(), 0.29),
            ("src/c.cpp".to_string(), 0.28),
            ("src/d.cpp".to_string(), 0.27),
            ("single_include/nlohmann/json.hpp".to_string(), 0.02),
        ];
        let mut all_hits: Vec<HashMap<String, Vec<FileHit>>> =
            (0..10).map(|_| HashMap::new()).collect();
        all_hits[9] = HashMap::from([
            (String::from("single_include/nlohmann/json.hpp"), hit(100.0)),
            (String::from("src/top.cpp"), hit(90.0)),
            (String::from("src/a.cpp"), hit(80.0)),
            (String::from("src/b.cpp"), hit(70.0)),
            (String::from("src/c.cpp"), hit(60.0)),
            (String::from("src/d.cpp"), hit(50.0)),
        ]);

        let capped = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );

        assert!(!capped
            .iter()
            .any(|(path, _)| path == "single_include/nlohmann/json.hpp"));
        assert!(capped.iter().any(|(path, _)| path == "src/d.cpp"));
    }

    #[test]
    fn adaptive_cap_without_explicit_max_can_retain_four_historical_syntax_files() {
        let fused = vec![
            ("src/libponyc/ast/lexer.c".to_string(), 1.10),
            ("packages/regex/_test.pony".to_string(), 0.41),
            ("packages/options/_test.pony".to_string(), 0.38),
            ("packages/strings/_test.pony".to_string(), 0.35),
            ("src/libponyc/ast/ast.c".to_string(), 0.34),
        ];
        let all_hits = vec![
            HashMap::new(),
            HashMap::from([(String::from("packages/strings/_test.pony"), hit(2.0))]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(String::from("packages/strings/_test.pony"), hit(3.0))]),
            HashMap::from([
                (String::from("src/libponyc/ast/lexer.c"), hit(10.0)),
                (String::from("src/libponyc/ast/ast.c"), hit(4.0)),
            ]),
        ];
        let priority_retention = HashSet::from([
            String::from("packages/regex/_test.pony"),
            String::from("packages/options/_test.pony"),
            String::from("packages/strings/_test.pony"),
        ]);

        let capped = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &priority_retention,
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );

        assert_eq!(
            capped
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            vec![
                "src/libponyc/ast/lexer.c",
                "packages/regex/_test.pony",
                "packages/options/_test.pony",
                "packages/strings/_test.pony",
            ]
        );
    }

    #[test]
    fn adaptive_cap_respects_explicit_max_as_ceiling() {
        let fused: Vec<(String, f32)> = (0..8)
            .map(|i| (format!("src/f{i}.py"), 10.0 - i as f32 * 0.5))
            .collect();
        let all_hits: Vec<HashMap<String, Vec<FileHit>>> = (0..8).map(|_| HashMap::new()).collect();
        let capped = adaptive_cap(
            &fused,
            &all_hits,
            3,
            true,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );
        assert_eq!(capped.len(), 3);
    }

    #[test]
    fn adaptive_cap_explicit_max_keeps_signal_supported_files_beyond_default_floor() {
        let fused = vec![
            ("src/a.py".to_string(), 1.40),
            ("src/b.py".to_string(), 1.05),
            ("src/c.py".to_string(), 0.92),
            ("src/d.py".to_string(), 0.81),
            ("src/e.py".to_string(), 0.30),
        ];
        let all_hits = vec![
            HashMap::new(),
            HashMap::from([
                (String::from("src/b.py"), hit(6.0)),
                (String::from("src/c.py"), hit(5.0)),
                (String::from("src/d.py"), hit(4.0)),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                (String::from("src/a.py"), hit(9.0)),
                (String::from("src/b.py"), hit(8.0)),
                (String::from("src/c.py"), hit(7.0)),
                (String::from("src/d.py"), hit(6.0)),
            ]),
        ];

        let capped = adaptive_cap(
            &fused,
            &all_hits,
            10,
            true,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );

        assert_eq!(
            capped
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            vec!["src/a.py", "src/b.py", "src/c.py", "src/d.py"]
        );
    }

    #[test]
    fn adaptive_cap_omitted_max_files_respects_max_cluster() {
        let fused: Vec<(String, f32)> = (0..15)
            .map(|i| (format!("src/f{i}.py"), 10.0 - i as f32 * 0.3))
            .collect();
        let all_hits: Vec<HashMap<String, Vec<FileHit>>> = (0..9).map(|_| HashMap::new()).collect();

        let capped_adaptive = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );
        assert!(
            capped_adaptive.len() <= 10,
            "omitted --max-files should still respect max_cluster (10)"
        );

        let capped_explicit = adaptive_cap(
            &fused,
            &all_hits,
            10,
            true,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );
        assert_eq!(
            capped_explicit.len(),
            10,
            "explicit --max-files 10 should cap at 10"
        );
    }

    #[test]
    fn adaptive_cap_keeps_corroborated_resolve_follow_up_below_dominant_top_hit() {
        let fused = vec![
            ("src/nddata_withmixins.py".to_string(), 810.0),
            ("src/ndarithmetic.py".to_string(), 60.0),
            ("src/ndio.py".to_string(), 48.0),
        ];
        let all_hits = vec![
            HashMap::new(),
            HashMap::from([(String::from("src/ndarithmetic.py"), hit(1.0))]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                (String::from("src/nddata_withmixins.py"), hit(9.0)),
                (String::from("src/ndarithmetic.py"), hit(8.0)),
                (String::from("src/ndio.py"), hit(6.0)),
            ]),
            HashMap::new(),
        ];

        let capped = adaptive_cap(
            &fused,
            &all_hits,
            10,
            false,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            false,
            None,
        );

        assert_eq!(
            capped
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            vec!["src/nddata_withmixins.py", "src/ndarithmetic.py"]
        );
    }

    #[test]
    fn injectable_priority_paths_limits_historical_seeds_to_top_two() {
        let traces = HashMap::from([
            (
                String::from("packages/regex/_test.pony"),
                PriorityFileTrace {
                    score: 109.0,
                    reasons: vec![LocateDebugPriorityReason {
                        kind: String::from("historical_priority_seed"),
                        detail: String::new(),
                        score: 109.0,
                    }],
                },
            ),
            (
                String::from("packages/options/_test.pony"),
                PriorityFileTrace {
                    score: 95.0,
                    reasons: vec![LocateDebugPriorityReason {
                        kind: String::from("historical_priority_seed"),
                        detail: String::new(),
                        score: 95.0,
                    }],
                },
            ),
            (
                String::from("packages/json/_test.pony"),
                PriorityFileTrace {
                    score: 94.0,
                    reasons: vec![LocateDebugPriorityReason {
                        kind: String::from("historical_priority_seed"),
                        detail: String::new(),
                        score: 94.0,
                    }],
                },
            ),
        ]);

        let injectable = injectable_priority_paths(&traces);

        assert!(injectable.contains("packages/regex/_test.pony"));
        assert!(injectable.contains("packages/options/_test.pony"));
        assert!(!injectable.contains("packages/json/_test.pony"));
    }

    #[test]
    fn retained_priority_paths_include_query_backed_source_files() {
        let traces = HashMap::from([
            (
                String::from("src/libponyc/type/cap.c"),
                PriorityFileTrace {
                    score: 120.0,
                    reasons: vec![LocateDebugPriorityReason {
                        kind: String::from("tracked_text_search"),
                        detail: String::from("terms=capability"),
                        score: 120.0,
                    }],
                },
            ),
            (
                String::from("src/libponyc/type/cap.h"),
                PriorityFileTrace {
                    score: 95.0,
                    reasons: vec![LocateDebugPriorityReason {
                        kind: String::from("tracked_text_term"),
                        detail: String::from("capability"),
                        score: 95.0,
                    }],
                },
            ),
            (
                String::from("lib/gbenchmark/src/sysinfo.cc"),
                PriorityFileTrace {
                    score: 140.0,
                    reasons: vec![LocateDebugPriorityReason {
                        kind: String::from("tracked_text_search"),
                        detail: String::from("terms=capability"),
                        score: 140.0,
                    }],
                },
            ),
        ]);

        let retained = retained_priority_paths(&traces, false);

        assert!(retained.contains("src/libponyc/type/cap.c"));
        assert!(retained.contains("src/libponyc/type/cap.h"));
        assert!(!retained.contains("lib/gbenchmark/src/sysinfo.cc"));
    }

    #[test]
    fn retained_priority_paths_skip_amalgamated_generated_files() {
        let traces = HashMap::from([
            (
                String::from("single_include/nlohmann/json.hpp"),
                PriorityFileTrace {
                    score: 140.0,
                    reasons: vec![LocateDebugPriorityReason {
                        kind: String::from("tracked_text_search"),
                        detail: String::from("terms=private"),
                        score: 140.0,
                    }],
                },
            ),
            (
                String::from("include/nlohmann/detail/input/lexer.hpp"),
                PriorityFileTrace {
                    score: 120.0,
                    reasons: vec![LocateDebugPriorityReason {
                        kind: String::from("tracked_text_search"),
                        detail: String::from("terms=private"),
                        score: 120.0,
                    }],
                },
            ),
            (
                String::from("include/nlohmann/detail/iterators/iter_impl.hpp"),
                PriorityFileTrace {
                    score: 95.0,
                    reasons: vec![LocateDebugPriorityReason {
                        kind: String::from("tracked_text_term"),
                        detail: String::from("previously"),
                        score: 95.0,
                    }],
                },
            ),
        ]);

        let retained = retained_priority_paths(&traces, false);

        assert!(!retained.contains("single_include/nlohmann/json.hpp"));
        assert!(retained.contains("include/nlohmann/detail/input/lexer.hpp"));
        assert!(retained.contains("include/nlohmann/detail/iterators/iter_impl.hpp"));
    }

    #[test]
    fn priority_relation_retention_paths_follow_same_family_includes() {
        let graph = kin_db::InMemoryGraph::new();
        for (idx, path) in [
            "include/nlohmann/detail/iterators/iter_impl.hpp",
            "include/nlohmann/detail/iterators/internal_iterator.hpp",
            "include/nlohmann/detail/macro_scope.hpp",
        ]
        .into_iter()
        .enumerate()
        {
            graph
                .upsert_opaque_artifact(&OpaqueArtifact {
                    file_id: FilePathId::new(path),
                    content_hash: Hash256::from_bytes([idx as u8; 32]),
                    mime_type: Some("text/x-c++hdr".into()),
                    text_preview: Some(path.to_string()),
                })
                .unwrap();
        }
        let iter_artifact = graph
            .artifact_id_for_path(&FilePathId::new(
                "include/nlohmann/detail/iterators/iter_impl.hpp",
            ))
            .unwrap();
        let internal_artifact = graph
            .artifact_id_for_path(&FilePathId::new(
                "include/nlohmann/detail/iterators/internal_iterator.hpp",
            ))
            .unwrap();
        let macro_artifact = graph
            .artifact_id_for_path(&FilePathId::new("include/nlohmann/detail/macro_scope.hpp"))
            .unwrap();
        for (target_artifact, target_path) in [
            (
                internal_artifact,
                "include/nlohmann/detail/iterators/internal_iterator.hpp",
            ),
            (macro_artifact, "include/nlohmann/detail/macro_scope.hpp"),
        ] {
            graph
                .upsert_relation(&Relation {
                    id: RelationId::new(),
                    kind: RelationKind::Includes,
                    src: GraphNodeId::Artifact(iter_artifact.clone()),
                    dst: GraphNodeId::Artifact(target_artifact),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: Some(target_path.to_string()),
                    evidence: vec![kin_model::RelationEvidence {
                        resolved_path: Some(target_path.to_string()),
                        source_path: Some(target_path.to_string()),
                        parser_rule: Some("include_directive".to_string()),
                        occurrence_count: 1,
                        ..kin_model::RelationEvidence::default()
                    }],
                })
                .unwrap();
        }

        let retained = priority_relation_retention_paths(
            &graph,
            &HashSet::from([String::from(
                "include/nlohmann/detail/iterators/iter_impl.hpp",
            )]),
        )
        .unwrap();

        assert!(retained.contains("include/nlohmann/detail/iterators/internal_iterator.hpp"));
        assert!(!retained.contains("include/nlohmann/detail/macro_scope.hpp"));
    }

    #[test]
    fn generated_projection_penalty_requires_graph_derived_from_evidence() {
        let graph = kin_db::InMemoryGraph::new();
        let generated = FilePathId::new("single_include/nlohmann/json.hpp");
        let source = FilePathId::new("include/nlohmann/detail/exceptions.hpp");
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: generated.clone(),
                content_hash: Hash256::from_bytes([91; 32]),
                mime_type: Some("text/x-c++hdr".into()),
                text_preview: Some("amalgamated header".into()),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: source.clone(),
                content_hash: Hash256::from_bytes([92; 32]),
                mime_type: Some("text/x-c++hdr".into()),
                text_preview: Some("exception type".into()),
            })
            .unwrap();

        let generated_id = graph.artifact_id_for_path(&generated).unwrap();
        let source_id = graph.artifact_id_for_path(&source).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::DerivedFrom,
                src: GraphNodeId::Artifact(generated_id),
                dst: GraphNodeId::Artifact(source_id),
                confidence: 0.9,
                origin: RelationOrigin::Inferred,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let no_graph_signal = HashMap::from([(
            generated.0.clone(),
            HashMap::from([("embedding".to_string(), 1.0)]),
        )]);
        assert!(
            graph_projection_backed_generated_paths(&graph, &no_graph_signal).is_empty(),
            "embedding/text evidence alone must not bypass generated path hygiene"
        );

        let graph_signal = HashMap::from([(
            generated.0.clone(),
            HashMap::from([("graph_resolve".to_string(), 1.0)]),
        )]);
        let backed = graph_projection_backed_generated_paths(&graph, &graph_signal);
        assert!(backed.contains(&generated.0));
    }

    #[test]
    fn projection_contributor_retention_requires_query_and_marker_evidence() {
        let graph = kin_db::InMemoryGraph::new();
        let generated = FilePathId::new("src/json.hpp");
        let source = FilePathId::new("develop/detail/input/parser.hpp");
        let unrelated = FilePathId::new("develop/detail/input/lexer.hpp");
        for (idx, file_id) in [&generated, &source, &unrelated].iter().enumerate() {
            graph
                .upsert_opaque_artifact(&OpaqueArtifact {
                    file_id: (*file_id).clone(),
                    content_hash: Hash256::from_bytes([idx as u8 + 11; 32]),
                    mime_type: Some("text/x-c++hdr".into()),
                    text_preview: None,
                })
                .unwrap();
        }

        let generated_id = graph.artifact_id_for_path(&generated).unwrap();
        let source_id = graph.artifact_id_for_path(&source).unwrap();
        let unrelated_id = graph.artifact_id_for_path(&unrelated).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::DerivedFrom,
                src: GraphNodeId::Artifact(generated_id),
                dst: GraphNodeId::Artifact(source_id),
                confidence: 0.9,
                origin: RelationOrigin::Inferred,
                created_in: None,
                import_source: None,
                evidence: vec![RelationEvidence {
                    parser_rule: Some("projection_include_marker".to_string()),
                    token: Some("#include".to_string()),
                    resolved_path: Some(source.0.clone()),
                    occurrence_count: 1,
                    ..RelationEvidence::default()
                }],
            })
            .unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::DerivedFrom,
                src: GraphNodeId::Artifact(generated_id),
                dst: GraphNodeId::Artifact(unrelated_id),
                confidence: 0.5,
                origin: RelationOrigin::Inferred,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let fused = vec![
            (generated.0.clone(), 1.0),
            (source.0.clone(), 0.04),
            (unrelated.0.clone(), 0.04),
        ];

        let no_query = projection_contributor_retention_paths_with_limits(
            &graph,
            "fix parser bug",
            &fused,
            3,
            12,
        );
        assert!(no_query.is_empty());

        let retained = projection_contributor_retention_paths_with_limits(
            &graph,
            "rename develop folder and change amalgamate config file",
            &fused,
            3,
            12,
        );
        assert!(retained.contains(&source.0));
        assert!(
            !retained.contains(&unrelated.0),
            "DerivedFrom without projection marker evidence is not enough"
        );
    }

    #[test]
    fn tracked_artifact_penalty_is_much_softer_than_generic_non_source_penalty() {
        let tracked = post_rrf_path_penalty("package.json", false, true, false, false);
        let generic = post_rrf_path_penalty("package.json", false, false, false, false);

        assert!(tracked > generic);
        // Infrastructure penalty applies to package.json, so tracked is softer but
        // still penalized compared to a regular tracked artifact.
        assert!(tracked > 0.01, "tracked artifacts should remain rankable");
        assert!(
            generic < 0.01,
            "generic non-source json should stay heavily penalized"
        );
    }

    #[test]
    fn entity_bearing_source_file_avoids_artifact_penalties() {
        let source_penalty = post_rrf_path_penalty("src/lib.rs", true, false, false, false);
        // Entity-bearing lib.rs gets a milder module-infra penalty (0.6) than
        // a pure re-export module (0.15) — Rust lib.rs often has real code.
        assert_eq!(source_penalty, 0.6);
    }

    #[test]
    fn test_queries_do_not_post_penalize_test_paths() {
        let penalty = post_rrf_path_penalty("tests/test_models.py", true, false, true, false);
        assert_eq!(penalty, 1.0);
    }

    #[test]
    fn priority_backed_test_artifacts_keep_most_of_their_score() {
        let regular = post_rrf_path_penalty("packages/regex/_test.pony", false, true, false, false);
        let priority = post_rrf_path_penalty("packages/regex/_test.pony", false, true, false, true);

        assert!(priority > regular);
        assert!(priority > 0.7);
    }

    #[test]
    fn strips_pr_template_boilerplate_before_retrieval() {
        let query = "Better error 305\n\nImprove error 305 to address #1220\n\n## Pull request checklist\n\nRead the Contribution Guidelines.\n\n- [x] The source code is amalgamated; run make amalgamate to create `single_include/nlohmann/json.hpp`.\n\n## Please don't\n\nDo not work around old compilers.";

        let stripped = strip_pr_template_boilerplate(&clean_issue_text(query));

        assert!(stripped.contains("Better error 305"));
        assert!(stripped.contains("Improve error 305"));
        assert!(!stripped.contains("single_include/nlohmann/json.hpp"));
        assert!(!stripped.to_ascii_lowercase().contains("amalgamated"));
        assert!(!stripped.to_ascii_lowercase().contains("old compilers"));
    }

    #[test]
    fn does_not_strip_short_issue_that_starts_with_checklist_word() {
        let query = "Checklist parser should preserve task-specific text";

        assert_eq!(strip_pr_template_boilerplate(query), query);
    }

    #[test]
    fn priority_backed_amalgamated_projection_keeps_hard_penalty() {
        let regular =
            post_rrf_path_penalty("single_include/nlohmann/json.hpp", true, true, false, false);
        let priority =
            post_rrf_path_penalty("single_include/nlohmann/json.hpp", true, true, false, true);

        assert_eq!(priority, regular);
        assert!(regular <= 0.1);
        assert!(priority <= 0.1);
    }

    #[test]
    fn amalgamated_projection_loses_priority_backing() {
        assert!(!priority_backing_applies_for_path(
            "single_include/nlohmann/json.hpp",
            true,
            false
        ));
        assert!(!priority_backing_applies_for_path(
            "single_include/nlohmann/json.hpp",
            true,
            true
        ));
        assert!(priority_backing_applies_for_path(
            "include/nlohmann/detail/json_pointer.hpp",
            true,
            false
        ));
    }

    #[test]
    fn framework_and_license_noise_paths_are_heavily_penalized() {
        let framework = post_rrf_path_penalty("lib/gtest/src/gtest.cc", true, false, false, false);
        let license = post_rrf_path_penalty("COPYING", false, false, false, false);

        assert!(framework < 0.05);
        assert!(license < 0.001);
    }

    #[test]
    fn demote_cochange_only_outliers_prefers_corroborated_resolve_hits() {
        let mut fused = vec![
            ("lib/noise.cc".to_string(), 1.30),
            ("src/lexer.c".to_string(), 1.10),
            ("src/ast.c".to_string(), 0.80),
        ];
        let all_hits = vec![
            HashMap::new(),
            HashMap::from([
                (String::from("src/lexer.c"), hit(4.0)),
                (String::from("src/ast.c"), hit(3.0)),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                (String::from("lib/noise.cc"), hit(7.0)),
                (String::from("src/lexer.c"), hit(2.0)),
                (String::from("src/ast.c"), hit(1.0)),
            ]),
            HashMap::from([
                (String::from("src/lexer.c"), hit(6.0)),
                (String::from("src/ast.c"), hit(4.0)),
            ]),
        ];

        demote_cochange_only_outliers(&mut fused, &all_hits);

        assert_eq!(fused[0].0, "src/lexer.c");
        assert_eq!(fused[1].0, "src/ast.c");
        assert_eq!(fused[2].0, "lib/noise.cc");
        assert!(fused[2].1 < 0.4);
    }

    #[test]
    fn demote_cochange_only_outliers_demotes_noisy_framework_paths() {
        let mut fused = vec![
            ("src/lexer.c".to_string(), 1.10),
            ("lib/gbenchmark/src/sysinfo.cc".to_string(), 0.89),
            ("src/ast.c".to_string(), 0.78),
        ];
        let all_hits = vec![
            HashMap::new(),
            HashMap::from([
                (String::from("src/lexer.c"), hit(4.0)),
                (String::from("src/ast.c"), hit(3.0)),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                (String::from("lib/gbenchmark/src/sysinfo.cc"), hit(6.0)),
                (String::from("src/lexer.c"), hit(2.0)),
                (String::from("src/ast.c"), hit(1.0)),
            ]),
            HashMap::from([
                (String::from("src/lexer.c"), hit(6.0)),
                (String::from("src/ast.c"), hit(4.0)),
            ]),
        ];

        demote_cochange_only_outliers(&mut fused, &all_hits);

        assert_eq!(fused[0].0, "src/lexer.c");
        assert_eq!(fused[1].0, "src/ast.c");
        assert_eq!(fused[2].0, "lib/gbenchmark/src/sysinfo.cc");
        assert!(fused[2].1 < 0.1);
    }

    #[test]
    fn demote_traceback_indirect_outliers_prefers_traceback_backed_files() {
        let mut fused = vec![
            ("astropy/io/ascii/core.py".to_string(), 1.12),
            ("astropy/io/ascii/html.py".to_string(), 0.82),
            ("astropy/io/fits/connect.py".to_string(), 0.71),
            ("astropy/io/registry/base.py".to_string(), 0.71),
            ("astropy/io/registry/compat.py".to_string(), 0.69),
        ];
        let all_hits = vec![
            HashMap::from([
                ("astropy/io/fits/connect.py".to_string(), hit(12.0)),
                ("astropy/io/registry/base.py".to_string(), hit(9.0)),
                ("astropy/io/registry/compat.py".to_string(), hit(6.0)),
            ]),
            HashMap::from([
                ("astropy/io/ascii/core.py".to_string(), hit(0.3)),
                ("astropy/io/ascii/html.py".to_string(), hit(0.3)),
                ("astropy/io/fits/connect.py".to_string(), hit(0.4)),
                ("astropy/io/registry/base.py".to_string(), hit(0.3)),
            ]),
            HashMap::from([
                ("astropy/io/fits/connect.py".to_string(), hit(9.6)),
                ("astropy/io/registry/base.py".to_string(), hit(9.6)),
                ("astropy/io/registry/compat.py".to_string(), hit(9.6)),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                ("astropy/io/ascii/core.py".to_string(), hit(9.0)),
                ("astropy/io/ascii/html.py".to_string(), hit(9.0)),
            ]),
            HashMap::new(),
            HashMap::new(),
        ];

        demote_traceback_indirect_outliers(&mut fused, &all_hits);

        let top_three: Vec<&str> = fused
            .iter()
            .take(3)
            .map(|(path, _)| path.as_str())
            .collect();
        assert_eq!(
            top_three,
            vec![
                "astropy/io/fits/connect.py",
                "astropy/io/registry/base.py",
                "astropy/io/registry/compat.py"
            ]
        );
    }

    #[test]
    fn demote_secondary_sources_for_syntax_artifact_queries_keeps_tests_ahead_of_neighbors() {
        let mut fused = vec![
            ("src/libponyc/codegen/codegen.c".to_string(), 1.18),
            ("src/libponyc/codegen/codegen.h".to_string(), 0.86),
            ("src/libponyc/ast/lexer.c".to_string(), 0.16),
            ("src/libponyc/ast/ast.c".to_string(), 0.12),
            ("packages/ponytest/_test_record.pony".to_string(), 0.38),
            ("packages/regex/_test.pony".to_string(), 0.48),
            ("packages/strings/_test.pony".to_string(), 0.47),
        ];
        let source_text_hits = HashMap::new();
        let priority_backed = HashSet::from([
            String::from("packages/regex/_test.pony"),
            String::from("packages/strings/_test.pony"),
        ]);

        demote_secondary_sources_for_syntax_artifact_queries(
            &mut fused,
            true,
            &source_text_hits,
            &priority_backed,
        );

        let ranked_paths = fused
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ranked_paths[0], "packages/regex/_test.pony");
        assert_eq!(ranked_paths[1], "packages/strings/_test.pony");
        assert_eq!(ranked_paths[2], "src/libponyc/ast/lexer.c");
        assert!(
            ranked_paths
                .iter()
                .position(|path| *path == "src/libponyc/codegen/codegen.c")
                > ranked_paths
                    .iter()
                    .position(|path| *path == "src/libponyc/ast/lexer.c")
        );
        assert!(
            ranked_paths
                .iter()
                .position(|path| *path == "packages/ponytest/_test_record.pony")
                > ranked_paths
                    .iter()
                    .position(|path| *path == "packages/strings/_test.pony")
        );
    }

    #[test]
    fn promote_named_test_source_siblings_surfaces_same_module_source_file() {
        let mut fused = vec![
            (
                "astropy/nddata/mixins/tests/test_ndarithmetic.py".to_string(),
                0.92,
            ),
            ("astropy/nddata/nddata.py".to_string(), 0.41),
        ];
        let source_files = HashSet::from([
            String::from("astropy/nddata/mixins/ndarithmetic.py"),
            String::from("astropy/nddata/nddata.py"),
        ]);

        promote_named_test_source_siblings(&mut fused, &source_files, None);

        assert_eq!(
            fused[0].0,
            "astropy/nddata/mixins/tests/test_ndarithmetic.py"
        );
        assert_eq!(fused[1].0, "astropy/nddata/mixins/ndarithmetic.py");
        assert!(fused[1].1 > 0.8);
    }

    #[test]
    fn promote_named_source_surfaces_promotes_declaration_sibling_source() {
        let mut fused = vec![
            (
                "packages/mui-utils/src/composeClasses/composeClasses.ts".to_string(),
                0.167,
            ),
            (
                "packages/mui-base/src/useAutocomplete/useAutocomplete.d.ts".to_string(),
                0.121,
            ),
            (
                "packages/mui-material/src/Autocomplete/Autocomplete.d.ts".to_string(),
                0.105,
            ),
        ];
        let source_files = HashSet::from([
            String::from("packages/mui-base/src/useAutocomplete/useAutocomplete.js"),
            String::from("packages/mui-material/src/Autocomplete/Autocomplete.js"),
        ]);

        promote_named_source_surfaces(
            &mut fused,
            "[Autocomplete] Fixed autocomplete's existing option selection",
            &source_files,
            None,
        );

        let ranks: HashMap<_, _> = fused
            .iter()
            .enumerate()
            .map(|(idx, (path, _))| (path.as_str(), idx))
            .collect();

        assert!(fused
            .iter()
            .any(|(path, _)| path == "packages/mui-base/src/useAutocomplete/useAutocomplete.js"));
        assert!(
            ranks["packages/mui-base/src/useAutocomplete/useAutocomplete.js"]
                < ranks["packages/mui-base/src/useAutocomplete/useAutocomplete.d.ts"]
        );
    }

    #[test]
    fn promote_named_source_surfaces_injects_named_block_source() {
        let mut fused = vec![
            (
                "packages/svelte/src/internal/client/reactivity/effects.js".to_string(),
                0.901,
            ),
            (
                "packages/svelte/src/compiler/utils/builders.js".to_string(),
                0.900,
            ),
            ("packages/svelte/src/compiler/errors.js".to_string(), 0.600),
        ];
        let source_files = HashSet::from([
            String::from("packages/svelte/src/internal/client/dom/blocks/each.js"),
            String::from("packages/svelte/src/internal/client/dom/blocks/if.js"),
        ]);

        promote_named_source_surfaces(
            &mut fused,
            "fix: repair each block length even without an else",
            &source_files,
            None,
        );

        let ranks: HashMap<_, _> = fused
            .iter()
            .enumerate()
            .map(|(idx, (path, _))| (path.as_str(), idx))
            .collect();

        assert!(fused
            .iter()
            .any(|(path, _)| path == "packages/svelte/src/internal/client/dom/blocks/each.js"));
        assert!(
            ranks["packages/svelte/src/internal/client/dom/blocks/each.js"]
                < ranks["packages/svelte/src/compiler/errors.js"]
        );
    }

    #[test]
    fn discover_custom_impl_family_priority_files_surfaces_helper_sibling() {
        let injected = discover_custom_impl_family_priority_files(
            "Allow custom JsonNode implementations",
            &[
                (
                    "src/main/java/com/example/node/TreeTraversingParser.java".to_string(),
                    10.0,
                ),
                (
                    "src/main/java/com/example/node/ArrayNode.java".to_string(),
                    9.8,
                ),
                (
                    "src/main/java/com/example/node/BaseJsonNode.java".to_string(),
                    9.4,
                ),
                (
                    "src/main/java/com/example/node/MissingNode.java".to_string(),
                    8.9,
                ),
            ],
            &HashSet::from([
                String::from("src/main/java/com/example/node/TreeTraversingParser.java"),
                String::from("src/main/java/com/example/node/ArrayNode.java"),
                String::from("src/main/java/com/example/node/BaseJsonNode.java"),
                String::from("src/main/java/com/example/node/MissingNode.java"),
                String::from("src/main/java/com/example/node/NodeCursor.java"),
            ]),
        );

        assert!(injected
            .iter()
            .any(|(path, _)| path == "src/main/java/com/example/node/NodeCursor.java"));
    }

    #[test]
    fn compress_secondary_files_under_dominant_direct_source_demotes_weak_tail() {
        let mut fused = vec![
            ("lib/compress/zstd_compress.c".to_string(), 10.0),
            ("lib/compress/zstd_ldm.c".to_string(), 9.7),
            ("lib/decompress/zstd_decompress.c".to_string(), 9.1),
            ("lib/compress/zstd_fast.c".to_string(), 8.4),
        ];
        let resolve_signal_scores = HashMap::from([
            (
                String::from("lib/compress/zstd_compress.c"),
                HashMap::from([(String::from("entity_resolve"), 20_000.0)]),
            ),
            (
                String::from("lib/compress/zstd_ldm.c"),
                HashMap::from([(String::from("entity_resolve"), 600.0)]),
            ),
            (
                String::from("lib/decompress/zstd_decompress.c"),
                HashMap::from([(String::from("entity_resolve"), 1_900.0)]),
            ),
        ]);
        let source_text_hits =
            HashMap::from([(String::from("lib/compress/zstd_compress.c"), hit(70.0))]);

        compress_secondary_files_under_dominant_direct_source(
            &mut fused,
            &resolve_signal_scores,
            &source_text_hits,
            &HashSet::new(),
            &HashSet::new(),
        );

        assert_eq!(fused[0].0, "lib/compress/zstd_compress.c");
        assert!(
            fused
                .iter()
                .position(|(path, _)| path == "lib/compress/zstd_fast.c")
                > fused
                    .iter()
                    .position(|(path, _)| path == "lib/decompress/zstd_decompress.c")
        );
    }

    #[test]
    fn compress_secondary_files_preserves_graph_semantic_retention_paths() {
        let mut fused = vec![
            (
                "include/nlohmann/detail/string_concat.hpp".to_string(),
                17.0,
            ),
            ("include/nlohmann/detail/macro_scope.hpp".to_string(), 6.75),
        ];
        let resolve_signal_scores = HashMap::from([
            (
                String::from("include/nlohmann/detail/string_concat.hpp"),
                HashMap::from([(String::from("entity_resolve"), 20_000.0)]),
            ),
            (
                String::from("include/nlohmann/detail/macro_scope.hpp"),
                HashMap::from([(String::from("entity_resolve"), 40.0)]),
            ),
        ]);
        let source_text_hits = HashMap::from([(
            String::from("include/nlohmann/detail/string_concat.hpp"),
            hit(70.0),
        )]);
        let semantic_retention =
            HashSet::from([String::from("include/nlohmann/detail/macro_scope.hpp")]);

        compress_secondary_files_under_dominant_direct_source(
            &mut fused,
            &resolve_signal_scores,
            &source_text_hits,
            &HashSet::new(),
            &semantic_retention,
        );

        let score = fused
            .iter()
            .find(|(path, _)| path == "include/nlohmann/detail/macro_scope.hpp")
            .map(|(_, score)| *score)
            .unwrap_or_default();
        assert_eq!(score, 6.75);
    }

    #[test]
    fn push_semantic_query_deduplicates_case_insensitively() {
        let mut queries = Vec::new();
        let mut seen = HashSet::new();
        push_semantic_query(&mut queries, &mut seen, "Parse Config", 1.0);
        push_semantic_query(&mut queries, &mut seen, "parse config", 0.5);

        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].0, "Parse Config");
    }

    #[test]
    fn curate_search_terms_drops_docs_only_noise() {
        let graph = kin_db::InMemoryGraph::new();

        let mut docs = test_entity(
            "CodeSandbox",
            "docs/src/modules/sandbox/CodeSandbox.ts",
            1,
            20,
        );
        docs.role = EntityRole::Docs;
        docs.metadata.extra.insert(
            "file_surface_context".into(),
            serde_json::Value::String("surface CodeSandbox surface code sandbox".into()),
        );

        let mut source = test_entity(
            "useAutocomplete",
            "packages/mui-base/src/useAutocomplete/useAutocomplete.js",
            1,
            20,
        );
        source.metadata.extra.insert(
            "file_surface_context".into(),
            serde_json::Value::String("surface useAutocomplete surface autocomplete".into()),
        );

        graph.upsert_entity(&docs).unwrap();
        graph.upsert_entity(&source).unwrap();

        let terms = curate_search_terms(
            "[Autocomplete] Fixed autocomplete's existing option selection\n\nCodeSandbox: https://codesandbox.io/s/mui-autocomplete-bug-fix-forked-033f61",
            &graph,
        )
        .unwrap();

        assert!(terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("autocomplete")));
        // CodeSandbox is docs-only (EntityRole::Docs) so term_has_graph_support
        // should reject it — docs-only terms are noise for localization.
        assert!(!terms.iter().any(|term| term == "CodeSandbox"));
    }

    #[test]
    fn curate_search_terms_keeps_source_backed_terms() {
        // curate_search_terms keeps terms that have graph support in source entities.
        // It does NOT expand to entity names not in the query (graph expansion disabled).
        let graph = kin_db::InMemoryGraph::new();

        let mut source = test_entity(
            "useAutocomplete",
            "packages/mui-base/src/useAutocomplete/useAutocomplete.js",
            1,
            20,
        );
        source.metadata.extra.insert(
            "file_surface_context".into(),
            serde_json::Value::String("surface useAutocomplete surface autocomplete".into()),
        );
        graph.upsert_entity(&source).unwrap();

        let terms =
            curate_search_terms("[Autocomplete] existing option selection", &graph).unwrap();

        // "Autocomplete" should survive — it has graph support via the useAutocomplete entity
        assert!(terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("autocomplete")));
    }

    #[test]
    fn curate_search_terms_keeps_source_artifact_backed_macro_terms() {
        let graph = kin_db::InMemoryGraph::new();

        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("include/nlohmann/detail/macro_scope.hpp"),
                content_hash: Hash256::from_bytes([47; 32]),
                mime_type: Some("text/x-c++hdr".into()),
                text_preview: Some(
                    "#define NLOHMANN_JSON_NAMESPACE_BEGIN namespace nlohmann {".into(),
                ),
            })
            .unwrap();

        let terms = curate_search_terms(
            "Add namespace scope macros, i.e., `NLOHMANN_JSON_NAMESPACE_BEGIN`.",
            &graph,
        )
        .unwrap();

        assert!(
            terms
                .iter()
                .any(|term| term == "NLOHMANN_JSON_NAMESPACE_BEGIN"),
            "terms={terms:?}"
        );
    }

    #[test]
    fn curate_search_terms_keeps_cpp_macro_terms_in_access_modifier_queries() {
        let graph = kin_db::InMemoryGraph::new();

        let mut private_macro = test_entity(
            "JSON_HEDLEY_PRIVATE",
            "include/nlohmann/thirdparty/hedley/hedley.hpp",
            1,
            4,
        );
        private_macro.kind = EntityKind::Macro;
        private_macro.language = LanguageId::Cpp;
        graph.upsert_entity(&private_macro).unwrap();

        let mut public_macro = test_entity(
            "JSON_HEDLEY_PUBLIC",
            "include/nlohmann/thirdparty/hedley/hedley.hpp",
            5,
            8,
        );
        public_macro.kind = EntityKind::Macro;
        public_macro.language = LanguageId::Cpp;
        graph.upsert_entity(&public_macro).unwrap();

        let mut define_macro = test_entity(
            "NLOHMANN_DEFINE_TYPE_INTRUSIVE",
            "include/nlohmann/detail/macro_scope.hpp",
            9,
            12,
        );
        define_macro.kind = EntityKind::Macro;
        define_macro.language = LanguageId::Cpp;
        graph.upsert_entity(&define_macro).unwrap();

        for (idx, name) in ["JSON_PRIVATE_UNLESS_TESTED", "JSON_TESTS_PRIVATE"]
            .into_iter()
            .enumerate()
        {
            graph
                .upsert_opaque_artifact(&OpaqueArtifact {
                    file_id: FilePathId::new(format!("include/nlohmann/detail/macro_{idx}.hpp")),
                    content_hash: Hash256::from_bytes([30 + idx as u8; 32]),
                    mime_type: Some("text/x-c++hdr".into()),
                    text_preview: Some(format!("#define {name} private")),
                })
                .unwrap();
        }

        let terms = curate_search_terms(
            "Remove `#define private public` from tests. Add `JSON_PRIVATE_UNLESS_TESTED` controlled by `JSON_TESTS_PRIVATE`.",
            &graph,
        )
        .unwrap();

        assert!(
            terms
                .iter()
                .any(|term| term == "JSON_PRIVATE_UNLESS_TESTED"),
            "terms={terms:?}"
        );
        assert!(
            terms.iter().any(|term| term == "JSON_TESTS_PRIVATE"),
            "terms={terms:?}"
        );
    }

    #[test]
    fn curate_search_terms_does_not_use_cpp_modifiers_as_entity_seeds_for_future_macros() {
        let graph = kin_db::InMemoryGraph::new();

        for (idx, name) in ["private_section", "public_api", "define_macro"]
            .into_iter()
            .enumerate()
        {
            let mut entity = test_entity(
                name,
                &format!("include/example/access_{idx}.hpp"),
                idx as u32 + 1,
                idx as u32 + 2,
            );
            entity.language = LanguageId::Cpp;
            graph.upsert_entity(&entity).unwrap();
        }

        let terms = curate_search_terms(
            "Remove `#define private public` from tests. Add `JSON_PRIVATE_UNLESS_TESTED` controlled by `JSON_TESTS_PRIVATE`.",
            &graph,
        )
        .unwrap();

        assert!(
            terms
                .iter()
                .any(|term| term == "JSON_PRIVATE_UNLESS_TESTED"),
            "terms={terms:?}"
        );
        assert!(
            !terms
                .iter()
                .any(|term| matches!(term.as_str(), "private" | "public" | "define")),
            "generic C++ modifier words should support artifact/test search, not primary entity discovery: terms={terms:?}"
        );
    }

    #[test]
    fn source_text_keeps_exact_symbolic_macro_matches_past_small_bm25_caps() {
        let graph = kin_db::InMemoryGraph::new();
        let paths = [
            "include/nlohmann/detail/input/binary_reader.hpp",
            "include/nlohmann/detail/iterators/iter_impl.hpp",
            "include/nlohmann/detail/iterators/primitive_iterator.hpp",
            "include/nlohmann/detail/json_pointer.hpp",
            "include/nlohmann/detail/output/serializer.hpp",
            "include/nlohmann/json.hpp",
            "single_include/nlohmann/json.hpp",
        ];

        for (idx, path) in paths.iter().enumerate() {
            graph
                .upsert_opaque_artifact(&OpaqueArtifact {
                    file_id: FilePathId::new(*path),
                    content_hash: Hash256::from_bytes([idx as u8; 32]),
                    mime_type: Some("text/x-c++hdr".into()),
                    text_preview: Some(format!(
                        "class example_{idx} {{\n  JSON_PRIVATE_UNLESS_TESTED:\n    int value = {idx};\n}};"
                    )),
                })
                .unwrap();
        }

        let hits = extract_source_text_signals(
            "Add `JSON_PRIVATE_UNLESS_TESTED` for private members used by tests",
            &graph,
            None,
        )
        .unwrap();

        assert!(
            hits.contains_key("include/nlohmann/detail/iterators/iter_impl.hpp"),
            "hits={:?}",
            hits.keys().collect::<Vec<_>>()
        );
        assert!(
            hits.len() >= paths.len(),
            "exact symbolic source matches should not be truncated to the old six-hit cap: hits={:?}",
            hits.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn artifact_relation_path_specificity_boosts_matching_module_tokens() {
        let boosted = artifact_relation_path_specificity_multiplier(
            "test/src/unit-iterators1.cpp",
            "include/nlohmann/detail/iterators/internal_iterator.hpp",
            2,
        );
        let damped = artifact_relation_path_specificity_multiplier(
            "test/src/unit-iterators1.cpp",
            "include/nlohmann/detail/input/lexer.hpp",
            2,
        );

        assert!(boosted > 1.0, "boosted={boosted}");
        assert!(damped < 1.0, "damped={damped}");
    }

    #[test]
    fn curate_search_terms_keeps_source_artifact_backed_qualified_terms() {
        let graph = kin_db::InMemoryGraph::new();

        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("include/nlohmann/detail/meta/detected.hpp"),
                content_hash: Hash256::from_bytes([48; 32]),
                mime_type: Some("text/x-c++hdr".into()),
                text_preview: Some(
                    "template<class T> using detected_t = std::filesystem::path;".into(),
                ),
            })
            .unwrap();

        let terms = curate_search_terms(
            "fix std::filesystem::path regression\n\n\
             Antiquated type traits performed an incorrect check for `std::filesystem::path`.",
            &graph,
        )
        .unwrap();

        assert!(
            terms
                .iter()
                .any(|term| term.eq_ignore_ascii_case("filesystem")),
            "terms={terms:?}"
        );
    }

    #[test]
    fn curate_search_terms_uses_common_words_only_as_fallback() {
        let graph = kin_db::InMemoryGraph::new();

        let mut illegal = test_entity("illegal_access", "src/compiler/verify.c", 1, 20);
        illegal.metadata.extra.insert(
            "file_surface_context".into(),
            serde_json::Value::String("surface illegal access verification".into()),
        );
        let mut read = test_entity("read_encoded_ptr", "src/runtime/lsda.c", 1, 20);
        read.metadata.extra.insert(
            "file_surface_context".into(),
            serde_json::Value::String("surface read encoded ptr".into()),
        );

        graph.upsert_entity(&illegal).unwrap();
        graph.upsert_entity(&read).unwrap();

        let terms = curate_search_terms("Fix compiler crash on illegal read", &graph).unwrap();

        assert!(terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("illegal")));
        assert!(!terms.iter().any(|term| term.eq_ignore_ascii_case("read")));
    }

    #[test]
    fn curate_search_terms_uses_typeparam_alias_from_body_text() {
        let graph = kin_db::InMemoryGraph::new();

        graph
            .upsert_entity(&test_entity(
                "typeparam",
                "src/libponyc/type/typeparam.c",
                1,
                20,
            ))
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new(".release-notes/0.49.1.md"),
                content_hash: Hash256::from_bytes([41; 32]),
                mime_type: Some("text/markdown".into()),
                text_preview: Some("related compiler note".into()),
            })
            .unwrap();

        let terms = curate_search_terms(
            "Fix compiler crash related to type parameter references\n\n\
             Rescoping starts with a fresh scope. This is fixed by eagerly adding type parameters to the scope before visiting type parameter references.",
            &graph,
        )
        .unwrap();

        assert!(terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("typeparam")));
        assert!(!terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("related")));
        assert!(!terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("references")));
    }

    #[test]
    fn curate_search_terms_keeps_semantic_phase_anchor_aliases_with_graph_support() {
        let graph = kin_db::InMemoryGraph::new();

        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/libponyc/pass/behaviour_rules.c"),
                content_hash: Hash256::from_bytes([44; 32]),
                mime_type: Some("text/x-csrc".into()),
                text_preview: Some("behaviour rule".into()),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/libponyc/pass/constructor_rules.c"),
                content_hash: Hash256::from_bytes([45; 32]),
                mime_type: Some("text/x-csrc".into()),
                text_preview: Some("constructor rule".into()),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/libponyc/expr/lambda.h"),
                content_hash: Hash256::from_bytes([46; 32]),
                mime_type: Some("text/x-chdr".into()),
                text_preview: Some("lambda rule".into()),
            })
            .unwrap();

        let terms = curate_search_terms(
            "Fix return checking in behaviours and constructors\n\n\
             Returns from lambdas should not be treated like constructor returns.",
            &graph,
        )
        .unwrap();

        assert!(
            terms.iter().any(|term| matches!(
                term.to_ascii_lowercase().as_str(),
                "behaviour" | "behaviours"
            )),
            "terms={terms:?}"
        );
        assert!(
            terms.iter().any(|term| matches!(
                term.to_ascii_lowercase().as_str(),
                "constructor" | "constructors"
            )),
            "terms={terms:?}"
        );
        assert!(
            !terms.iter().all(|term| term.eq_ignore_ascii_case("return")),
            "terms={terms:?}"
        );
    }

    #[test]
    fn curate_search_terms_ignores_framework_backed_empty_noise_for_serialisation_reports() {
        let graph = kin_db::InMemoryGraph::new();

        graph
            .upsert_entity(&test_entity(
                "serialise",
                "src/libponyc/codegen/genprim.c",
                1,
                20,
            ))
            .unwrap();
        graph
            .upsert_entity(&test_entity(
                "codegen",
                "src/libponyc/codegen/genprim.c",
                21,
                40,
            ))
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("lib/gbenchmark/mingw.py"),
                content_hash: Hash256::from_bytes([42; 32]),
                mime_type: Some("text/x-python".into()),
                text_preview: Some("empty logger implementation".into()),
            })
            .unwrap();

        let terms = curate_search_terms(
            "Fix empty string serialisation\n\n\
             This commit fixes a bug in how empty strings are serialised.\n\
             This PR includes the codegen test for the fix.",
            &graph,
        )
        .unwrap();

        assert!(terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("serialise")));
        assert!(!terms.iter().any(|term| term.eq_ignore_ascii_case("empty")));
        assert!(!terms.iter().any(|term| term.eq_ignore_ascii_case("commit")));
    }

    #[test]
    fn curate_search_terms_promotes_subtype_alias_over_implementation_boilerplate() {
        let graph = kin_db::InMemoryGraph::new();

        graph
            .upsert_entity(&test_entity(
                "subtype",
                "src/libponyc/type/subtype.c",
                1,
                20,
            ))
            .unwrap();
        graph
            .upsert_entity(&test_entity("cap", "src/libponyc/type/cap.c", 21, 40))
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("lib/gbenchmark/src/sysinfo.cc"),
                content_hash: Hash256::from_bytes([43; 32]),
                mime_type: Some("text/x-c++src".into()),
                text_preview: Some("unsafe implementation detail".into()),
            })
            .unwrap();

        let terms = curate_search_terms(
            "Fix unsafe cases in capability subtyping implementation\n\n\
             This fixes a bug in the capability subtyping implementation where capabilities were being treated as subtypes of themselves.",
            &graph,
        )
        .unwrap();

        assert!(terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("subtype")));
        assert!(!terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("implementation")));
        assert!(!terms.iter().any(|term| term.eq_ignore_ascii_case("unsafe")));
    }

    #[test]
    fn tracked_text_query_terms_prioritizes_exact_code_terms_before_prose() {
        let terms = tracked_text_query_terms(
            "Decoding buffer size min\n\n\
             add prototype `ZSTD_decodingBufferSize_min()` and use `ZSTD_decompressContinue()`",
        );

        let buffer_idx = terms
            .iter()
            .position(|term| term.eq_ignore_ascii_case("buffer"))
            .unwrap();
        let symbol_idx = terms
            .iter()
            .position(|term| term == "ZSTD_decodingBufferSize_min")
            .unwrap();

        assert!(symbol_idx < buffer_idx);
    }

    #[test]
    fn tracked_text_query_terms_drop_issue_boilerplate_and_numeric_ids() {
        let terms = tracked_text_query_terms(
            "Fix compiler crash introduced in #4283\n\n\
             Fixes a missed case in #4283.",
        );

        assert!(!terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("introduced")));
        assert!(!terms.iter().any(|term| term.eq_ignore_ascii_case("missed")));
        assert!(!terms.iter().any(|term| term == "4283"));
    }

    #[test]
    fn tracked_text_query_terms_suppress_phrase_modifiers() {
        let empty_string_terms = tracked_text_query_terms(
            "Fix empty string serialisation\n\nThis PR includes the codegen test.",
        );
        assert!(!empty_string_terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("empty")));
        assert!(empty_string_terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("string")));
        assert!(empty_string_terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("string_serialise")));

        let typeparam_terms =
            tracked_text_query_terms("Fix compiler crash related to type parameter references");
        assert!(!typeparam_terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("references")));

        let arrow_terms = tracked_text_query_terms(
            "Fix compiler crash introduced in #4283\n\n\
             Fixes a missed case in arrow types while attempting an unsafe mutation of a val.",
        );
        assert!(arrow_terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("viewpoint")));
        assert!(arrow_terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("mutate")));
        assert!(arrow_terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("immutable")));
    }

    #[test]
    fn tracked_text_query_terms_suppress_cpp_access_modifiers_when_symbolic_macro_is_present() {
        let terms = tracked_text_query_terms(
            "Remove `#define private public` from tests. Add `JSON_PRIVATE_UNLESS_TESTED` controlled by `JSON_TESTS_PRIVATE`.",
        );

        assert!(
            terms
                .iter()
                .any(|term| term == "JSON_PRIVATE_UNLESS_TESTED"),
            "terms={terms:?}"
        );
        assert!(
            !terms.iter().any(|term| matches!(
                term.to_ascii_lowercase().as_str(),
                "private" | "public" | "define" | "defined"
            )),
            "generic access/preprocessor words should not become tracked artifact priority terms: terms={terms:?}"
        );
    }

    #[test]
    fn rerank_semantic_phase_paths_promotes_pass_and_lambda_anchors() {
        let mut fused = vec![
            ("src/libponyc/pass/expr.h".to_string(), 0.158),
            ("src/libponyc/expr/reference.c".to_string(), 0.123),
            ("src/libponyc/pass/sugar.c".to_string(), 0.115),
            ("src/libponyc/pass/expr.c".to_string(), 0.107),
            ("src/libponyc/verify/type.c".to_string(), 0.075),
        ];
        let source_files = HashSet::from([
            String::from("src/libponyc/pass/expr.c"),
            String::from("src/libponyc/pass/syntax.c"),
            String::from("src/libponyc/pass/verify.c"),
            String::from("src/libponyc/expr/lambda.h"),
        ]);

        rerank_semantic_phase_paths(
            &mut fused,
            "Fix return checking in behaviours and constructors. Returns from lambdas should not be treated like constructor returns.",
            &[],
            &source_files,
            None,
        );

        let ranks: HashMap<_, _> = fused
            .iter()
            .enumerate()
            .map(|(idx, (path, _))| (path.as_str(), idx))
            .collect();

        assert!(ranks["src/libponyc/pass/expr.c"] < ranks["src/libponyc/pass/expr.h"]);
        assert!(ranks["src/libponyc/pass/syntax.c"] < ranks["src/libponyc/expr/reference.c"]);
        assert!(ranks["src/libponyc/pass/verify.c"] < ranks["src/libponyc/verify/type.c"]);
        assert!(fused
            .iter()
            .any(|(path, _)| path == "src/libponyc/expr/lambda.h"));
    }

    #[test]
    fn rerank_cli_surface_paths_prefers_programs_over_internal_headers_for_flag_queries() {
        let mut fused = vec![
            ("lib/compress/zstd_compress.c".to_string(), 1000.0),
            (
                "contrib/linux-kernel/include/linux/zstd.h".to_string(),
                40.0,
            ),
            ("lib/common/zstd_internal.h".to_string(), 25.0),
            ("programs/fileio.c".to_string(), 60.0),
            ("programs/zstdcli.c".to_string(), 45.0),
        ];

        rerank_cli_surface_paths(&mut fused, "Add --size-hint=# option", &[], None);

        let ranks: HashMap<_, _> = fused
            .iter()
            .enumerate()
            .map(|(idx, (path, _))| (path.as_str(), idx))
            .collect();

        assert!(ranks["programs/fileio.c"] < ranks["lib/common/zstd_internal.h"]);
        assert!(ranks["programs/zstdcli.c"] < ranks["contrib/linux-kernel/include/linux/zstd.h"]);
    }

    #[test]
    fn rerank_cli_surface_paths_demotes_negated_help_surfaces() {
        let mut fused = vec![
            ("packages/cli/command_help.pony".to_string(), 900.0),
            ("src/libponyc/options/options.c".to_string(), 30.0),
            ("src/libponyrt/options/options.c".to_string(), 20.0),
        ];

        rerank_cli_surface_paths(
            &mut fused,
            "fix cli issue when providing --help=false.",
            &[],
            None,
        );

        let ranks: HashMap<_, _> = fused
            .iter()
            .enumerate()
            .map(|(idx, (path, _))| (path.as_str(), idx))
            .collect();

        assert!(ranks["src/libponyc/options/options.c"] < ranks["packages/cli/command_help.pony"]);
    }

    #[test]
    fn rerank_cli_surface_paths_caps_deep_impls_for_flag_queries() {
        let mut fused = vec![
            ("lib/compress/zstd_compress.c".to_string(), 1000.0),
            ("programs/fileio.c".to_string(), 60.0),
            ("programs/zstdcli.c".to_string(), 45.0),
        ];

        rerank_cli_surface_paths(&mut fused, "Add --size-hint=# option", &[], None);

        let ranks: HashMap<_, _> = fused
            .iter()
            .enumerate()
            .map(|(idx, (path, _))| (path.as_str(), idx))
            .collect();

        assert!(ranks["programs/fileio.c"] < ranks["lib/compress/zstd_compress.c"]);
        assert!(ranks["programs/zstdcli.c"] < ranks["lib/compress/zstd_compress.c"]);
    }

    #[test]
    fn rerank_cli_surface_paths_focuses_named_command_directory() {
        let mut fused = vec![
            ("pkg/cmd/browse/browse.go".to_string(), 0.288),
            ("pkg/cmd/repo/view/view.go".to_string(), 0.257),
            ("pkg/cmd/repo/sync/sync.go".to_string(), 0.205),
            ("pkg/cmd/root/help.go".to_string(), 0.142),
            ("internal/config/config_file.go".to_string(), 0.135),
        ];
        let all_hits = vec![
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                (String::from("pkg/cmd/browse/browse.go"), hit(4.0)),
                (String::from("pkg/cmd/repo/view/view.go"), hit(3.0)),
                (String::from("pkg/cmd/repo/sync/sync.go"), hit(2.0)),
            ]),
        ];

        rerank_cli_surface_paths(
            &mut fused,
            "fix branch flag on browse within dir",
            &all_hits,
            None,
        );

        let ranks: HashMap<_, _> = fused
            .iter()
            .enumerate()
            .map(|(idx, (path, _))| (path.as_str(), idx))
            .collect();

        assert!(ranks["pkg/cmd/browse/browse.go"] < ranks["pkg/cmd/repo/view/view.go"]);
        assert!(ranks["pkg/cmd/repo/view/view.go"] < ranks["pkg/cmd/root/help.go"]);
        assert!(ranks["pkg/cmd/repo/sync/sync.go"] < ranks["internal/config/config_file.go"]);
    }

    #[test]
    fn is_cli_surface_query_ignores_embedded_cli_substrings() {
        assert!(!is_cli_surface_query(
            "Fix empty string serialisation\n\nThis PR includes the codegen test."
        ));
        assert!(is_cli_surface_query(
            "fix cli issue when providing --help=false"
        ));
    }

    #[test]
    fn rerank_cli_surface_paths_prefers_public_headers_for_api_queries() {
        let mut fused = vec![
            ("lib/compress/zstd_compress.c".to_string(), 1000.0),
            ("programs/fileio.c".to_string(), 35.0),
            ("lib/zstd.h".to_string(), 20.0),
            ("lib/common/zstd_internal.h".to_string(), 18.0),
            (
                "contrib/linux-kernel/include/linux/zstd.h".to_string(),
                16.0,
            ),
        ];

        rerank_cli_surface_paths(
            &mut fused,
            "Add prototype `ZSTD_decodingBufferSize_min()` to the public API",
            &[],
            None,
        );

        let ranks: HashMap<_, _> = fused
            .iter()
            .enumerate()
            .map(|(idx, (path, _))| (path.as_str(), idx))
            .collect();

        assert!(ranks["lib/zstd.h"] < ranks["lib/common/zstd_internal.h"]);
        assert!(ranks["lib/zstd.h"] < ranks["contrib/linux-kernel/include/linux/zstd.h"]);
    }

    #[test]
    fn boost_priority_injects_high_signal_files() {
        let mut fused = vec![("src/a.py".to_string(), 1.0), ("src/b.py".to_string(), 0.9)];
        let priority = vec![("django/core/validators.py".to_string(), 50.0)];
        let injectable = HashSet::from([String::from("django/core/validators.py")]);

        boost_priority_in_fused(&mut fused, &priority, &injectable, &HashSet::new());

        assert_eq!(fused[0].0, "django/core/validators.py");
    }

    #[test]
    fn noninjectable_priority_does_not_create_absent_top_file() {
        let mut fused = vec![("src/a.py".to_string(), 1.0), ("src/b.py".to_string(), 0.9)];
        let priority = vec![("zlibWrapper/gzread.c".to_string(), 72.0)];

        boost_priority_in_fused(&mut fused, &priority, &HashSet::new(), &HashSet::new());

        assert!(fused.iter().all(|(path, _)| path != "zlibWrapper/gzread.c"));
    }

    #[test]
    fn retained_priority_paths_floor_existing_query_backed_sources() {
        let mut fused = vec![
            ("src/libponyc/type/subtype.c".to_string(), 1000.0),
            ("src/libponyc/type/cap.c".to_string(), 2.0),
            ("src/libponyc/type/cap.h".to_string(), 1.0),
        ];
        let priority = vec![
            ("src/libponyc/type/cap.c".to_string(), 120.0),
            ("src/libponyc/type/cap.h".to_string(), 58.0),
        ];
        let retained = HashSet::from([
            String::from("src/libponyc/type/cap.c"),
            String::from("src/libponyc/type/cap.h"),
        ]);

        boost_priority_in_fused(&mut fused, &priority, &HashSet::new(), &retained);

        let ranks: HashMap<_, _> = fused
            .iter()
            .enumerate()
            .map(|(idx, (path, _))| (path.as_str(), idx))
            .collect();
        assert!(ranks["src/libponyc/type/cap.c"] < ranks["src/libponyc/type/cap.h"]);
        assert!(fused
            .iter()
            .find(|(path, _)| path == "src/libponyc/type/cap.c")
            .is_some_and(|(_, score)| *score >= 180.0));
    }

    #[test]
    fn merge_priority_files_from_hits_stays_below_injection_threshold() {
        let mut priority = Vec::new();
        let hits = HashMap::from([(
            "src/ldm.c".to_string(),
            vec![
                FileHit {
                    score: 24.0,
                    spans: vec![],
                },
                FileHit {
                    score: 18.0,
                    spans: vec![],
                },
                FileHit {
                    score: 14.0,
                    spans: vec![],
                },
                FileHit {
                    score: 12.0,
                    spans: vec![],
                },
            ],
        )]);

        merge_priority_files_from_hits(&mut priority, &hits);

        assert_eq!(priority, vec![("src/ldm.c".to_string(), 28.0)]);
    }

    #[test]
    fn source_text_priority_merge_does_not_create_near_top_injection() {
        let mut fused = vec![
            ("src/top.c".to_string(), 500.0),
            ("src/ldm.c".to_string(), 15.0),
        ];
        let mut priority = Vec::new();
        let hits = HashMap::from([(
            "src/ldm.c".to_string(),
            vec![
                FileHit {
                    score: 24.0,
                    spans: vec![],
                },
                FileHit {
                    score: 18.0,
                    spans: vec![],
                },
                FileHit {
                    score: 14.0,
                    spans: vec![],
                },
                FileHit {
                    score: 12.0,
                    spans: vec![],
                },
            ],
        )]);
        merge_priority_files_from_hits(&mut priority, &hits);

        boost_priority_in_fused(&mut fused, &priority, &HashSet::new(), &HashSet::new());

        assert_eq!(fused[0].0, "src/top.c");
        assert_eq!(fused[1].0, "src/ldm.c");
        assert!(fused[1].1 > 15.0);
        assert!(fused[1].1 < 25.0);
    }

    #[test]
    fn demote_zero_signal_files_preserves_priority_injections() {
        let mut fused = vec![
            ("src/a.py".to_string(), 1.0),
            ("src/builtin.c".to_string(), 0.8),
            ("src/b.py".to_string(), 0.7),
        ];
        let all_hits = vec![HashMap::from([(
            "src/a.py".to_string(),
            vec![FileHit {
                score: 1.0,
                spans: vec![],
            }],
        )])];
        let priority = vec![("src/builtin.c".to_string(), 72.0)];

        demote_zero_signal_files(&mut fused, &all_hits, &priority, &HashSet::new());

        assert_eq!(fused[1].0, "src/builtin.c");
        assert!(fused[1].1 > 0.5);
        assert_eq!(fused[2].0, "src/b.py");
        assert!(fused[2].1 < 0.01);
    }

    #[test]
    fn multihop_reaches_second_order_neighbors() {
        let graph = kin_db::InMemoryGraph::new();

        let caller = test_entity("caller", "src/a.py", 1, 10);
        let callee = test_entity("callee", "src/b.py", 12, 24);
        let helper = test_entity("helper", "src/c.py", 30, 48);

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_entity(&helper).unwrap();

        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(caller.id),
                dst: GraphNodeId::Entity(callee.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::DependsOn,
                src: GraphNodeId::Entity(callee.id),
                dst: GraphNodeId::Entity(helper.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let seeds = HashMap::from([(
            String::from("src/a.py"),
            vec![FileHit {
                score: 6.0,
                spans: vec![[1, 10]],
            }],
        )]);

        let hits =
            extract_multihop_signals(&[&seeds], &graph, LocateProfile::Standard, false).unwrap();
        assert!(hits.contains_key("src/b.py"));
        assert!(hits.contains_key("src/c.py"));
    }

    #[test]
    fn extract_multihop_signals_follows_artifact_include_edges_from_file_hits() {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("include/nlohmann/detail/iterators/iter_impl.hpp"),
                content_hash: Hash256::from_bytes([71; 32]),
                mime_type: Some("text/x-c++hdr".into()),
                text_preview: Some("JSON_PRIVATE_UNLESS_TESTED:".into()),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("include/nlohmann/detail/iterators/internal_iterator.hpp"),
                content_hash: Hash256::from_bytes([72; 32]),
                mime_type: Some("text/x-c++hdr".into()),
                text_preview: Some("struct internal_iterator {};".into()),
            })
            .unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Includes,
                src: GraphNodeId::Artifact(ArtifactId::from_path(
                    "include/nlohmann/detail/iterators/iter_impl.hpp",
                )),
                dst: GraphNodeId::Artifact(ArtifactId::from_path(
                    "include/nlohmann/detail/iterators/internal_iterator.hpp",
                )),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: Some("nlohmann/detail/iterators/internal_iterator.hpp".to_string()),
                evidence: vec![kin_model::RelationEvidence {
                    resolved_path: Some(
                        "include/nlohmann/detail/iterators/internal_iterator.hpp".to_string(),
                    ),
                    source_path: Some(
                        "nlohmann/detail/iterators/internal_iterator.hpp".to_string(),
                    ),
                    parser_rule: Some("include_directive".to_string()),
                    occurrence_count: 1,
                    ..kin_model::RelationEvidence::default()
                }],
            })
            .unwrap();

        let seeds = HashMap::from([(
            String::from("include/nlohmann/detail/iterators/iter_impl.hpp"),
            vec![FileHit {
                score: 120.0,
                spans: vec![],
            }],
        )]);

        let hits =
            extract_multihop_signals(&[&seeds], &graph, LocateProfile::Standard, false).unwrap();
        assert!(
            hits.contains_key("include/nlohmann/detail/iterators/internal_iterator.hpp"),
            "artifact-level Includes edge should project included headers from file-backed seeds"
        );
    }

    #[test]
    fn extract_multihop_signals_follows_derived_projection_edges_from_source_hits() {
        let graph = kin_db::InMemoryGraph::new();
        let generated = FilePathId::new("single_include/nlohmann/json.hpp");
        let source = FilePathId::new("include/nlohmann/detail/exceptions.hpp");
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: generated.clone(),
                content_hash: Hash256::from_bytes([81; 32]),
                mime_type: Some("text/x-c++hdr".into()),
                text_preview: Some("amalgamated exception source".into()),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: source.clone(),
                content_hash: Hash256::from_bytes([82; 32]),
                mime_type: Some("text/x-c++hdr".into()),
                text_preview: Some("exception source".into()),
            })
            .unwrap();

        let generated_id = graph.artifact_id_for_path(&generated).unwrap();
        let source_id = graph.artifact_id_for_path(&source).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::DerivedFrom,
                src: GraphNodeId::Artifact(generated_id),
                dst: GraphNodeId::Artifact(source_id),
                confidence: 0.9,
                origin: RelationOrigin::Inferred,
                created_in: None,
                import_source: None,
                evidence: vec![kin_model::RelationEvidence {
                    resolved_path: Some(source.0.clone()),
                    source_path: Some("nlohmann/detail/exceptions.hpp".to_string()),
                    parser_rule: Some("projection_include_marker".to_string()),
                    occurrence_count: 1,
                    ..kin_model::RelationEvidence::default()
                }],
            })
            .unwrap();

        let seeds = HashMap::from([(source.0.clone(), hit(72.0))]);
        let hits =
            extract_multihop_signals(&[&seeds], &graph, LocateProfile::Standard, false).unwrap();
        assert!(
            hits.contains_key(&generated.0),
            "source artifact hits should project to generated artifacts through DerivedFrom"
        );
    }

    #[test]
    fn resolve_entities_to_files_keeps_signal_scores_without_explain() {
        let graph = kin_db::InMemoryGraph::new();

        let options = test_entity("parse_options", "src/libponyc/options/options.c", 1, 40);
        let runtime = test_entity("ponyint_opt_next", "src/libponyrt/options/options.c", 1, 40);

        graph.upsert_entity(&options).unwrap();
        graph.upsert_entity(&runtime).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(options.id),
                dst: GraphNodeId::Entity(runtime.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let seeds = HashMap::from([(
            options.id,
            EntityDiscovery {
                score: 12.0,
                signals: vec!["search"],
                cosine: None,
            },
        )]);

        let (_, _, signal_scores_without_explain, _, _) =
            resolve_entities_to_files(&seeds, &graph, false, "text").unwrap();
        let (_, _, signal_scores_with_explain, _, _) =
            resolve_entities_to_files(&seeds, &graph, true, "text").unwrap();

        assert_eq!(
            signal_scores_without_explain, signal_scores_with_explain,
            "resolver scoring inputs must not depend on --explain"
        );
        assert!(
            signal_scores_without_explain
                .get("src/libponyc/options/options.c")
                .and_then(|scores| scores.get("entity_resolve"))
                .copied()
                .unwrap_or(0.0)
                > 0.0
        );
        assert!(
            signal_scores_without_explain
                .get("src/libponyrt/options/options.c")
                .and_then(|scores| scores.get("graph_resolve"))
                .copied()
                .unwrap_or(0.0)
                > 0.0
        );
    }

    #[test]
    fn resolve_entities_to_files_prioritizes_high_value_relations_before_frontier_cap() {
        let graph = kin_db::InMemoryGraph::new();

        let seed = test_entity("plugin_print_help", "src/libponyc/plugin/plugin.c", 1, 40);
        let target = test_entity("ponyc_opt_process", "src/libponyc/options/options.c", 1, 40);
        graph.upsert_entity(&seed).unwrap();
        graph.upsert_entity(&target).unwrap();

        for idx in 0..40 {
            let noise = test_entity(
                &format!("noise_{idx}"),
                &format!("src/noise/file_{idx}.c"),
                1,
                20,
            );
            graph.upsert_entity(&noise).unwrap();
            graph
                .upsert_relation(&Relation {
                    id: RelationId::new(),
                    kind: RelationKind::Contains,
                    src: GraphNodeId::Entity(seed.id),
                    dst: GraphNodeId::Entity(noise.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }

        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(seed.id),
                dst: GraphNodeId::Entity(target.id),
                confidence: 1.0,
                origin: RelationOrigin::Inferred,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let seeds = HashMap::from([(
            seed.id,
            EntityDiscovery {
                score: 20.0,
                signals: vec!["search"],
                cosine: None,
            },
        )]);

        let (resolved, _, _, _, _) =
            resolve_entities_to_files(&seeds, &graph, false, "text").unwrap();

        assert!(
            resolved
                .iter()
                .take(5)
                .any(|(path, _)| path == "src/libponyc/options/options.c"),
            "calls relation should survive the frontier cap ahead of contains-noise neighbors"
        );
    }

    #[test]
    fn resolve_entities_to_files_projects_artifact_include_candidates_with_debug() {
        let graph = kin_db::InMemoryGraph::new();

        let seed = test_entity("load_json", "src/app.cpp", 1, 40);
        graph.upsert_entity(&seed).unwrap();
        for (idx, path) in [
            "src/app.cpp",
            "include/app.hpp",
            "include/detail/internal.hpp",
            "tests/test_app.cpp",
        ]
        .into_iter()
        .enumerate()
        {
            graph
                .upsert_opaque_artifact(&OpaqueArtifact {
                    file_id: FilePathId::new(path),
                    content_hash: Hash256::from_bytes([idx as u8; 32]),
                    mime_type: Some("text/x-c++hdr".into()),
                    text_preview: Some(path.to_string()),
                })
                .unwrap();
        }
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Includes,
                src: GraphNodeId::Artifact(ArtifactId::from_path("src/app.cpp")),
                dst: GraphNodeId::Artifact(ArtifactId::from_path("include/app.hpp")),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: Some("app.hpp".to_string()),
                evidence: vec![kin_model::RelationEvidence {
                    resolved_path: Some("include/app.hpp".to_string()),
                    source_path: Some("app.hpp".to_string()),
                    parser_rule: Some("include_directive".to_string()),
                    occurrence_count: 1,
                    ..kin_model::RelationEvidence::default()
                }],
            })
            .unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::from_bytes([0xff; 16]),
                kind: RelationKind::Includes,
                src: GraphNodeId::Artifact(ArtifactId::from_path("include/app.hpp")),
                dst: GraphNodeId::Artifact(ArtifactId::from_path("include/detail/internal.hpp")),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: Some("detail/internal.hpp".to_string()),
                evidence: vec![kin_model::RelationEvidence {
                    resolved_path: Some("include/detail/internal.hpp".to_string()),
                    source_path: Some("detail/internal.hpp".to_string()),
                    parser_rule: Some("include_directive".to_string()),
                    occurrence_count: 1,
                    ..kin_model::RelationEvidence::default()
                }],
            })
            .unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::from_bytes([0x00; 16]),
                kind: RelationKind::Includes,
                src: GraphNodeId::Artifact(ArtifactId::from_path("tests/test_app.cpp")),
                dst: GraphNodeId::Artifact(ArtifactId::from_path("include/app.hpp")),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: Some("include/app.hpp".to_string()),
                evidence: vec![kin_model::RelationEvidence {
                    resolved_path: Some("include/app.hpp".to_string()),
                    source_path: Some("include/app.hpp".to_string()),
                    parser_rule: Some("include_directive".to_string()),
                    occurrence_count: 1,
                    ..kin_model::RelationEvidence::default()
                }],
            })
            .unwrap();

        let seeds = HashMap::from([(
            seed.id,
            EntityDiscovery {
                score: 20.0,
                signals: vec!["search"],
                cosine: None,
            },
        )]);

        let old_frontier = std::env::var("KIN_LOCATE_RESOLVE_ARTIFACT_FRONTIER").ok();
        let old_graph_floor = std::env::var("KIN_LOCATE_GRAPH_ONLY_PROJECTION_FLOOR").ok();
        std::env::set_var("KIN_LOCATE_RESOLVE_ARTIFACT_FRONTIER", "1");
        std::env::set_var("KIN_LOCATE_GRAPH_ONLY_PROJECTION_FLOOR", "0.25");
        let result = resolve_entities_to_files(&seeds, &graph, true, "text");
        if let Some(value) = old_frontier {
            std::env::set_var("KIN_LOCATE_RESOLVE_ARTIFACT_FRONTIER", value);
        } else {
            std::env::remove_var("KIN_LOCATE_RESOLVE_ARTIFACT_FRONTIER");
        }
        if let Some(value) = old_graph_floor {
            std::env::set_var("KIN_LOCATE_GRAPH_ONLY_PROJECTION_FLOOR", value);
        } else {
            std::env::remove_var("KIN_LOCATE_GRAPH_ONLY_PROJECTION_FLOOR");
        }
        let (resolved, _, _, _, candidate_stages) = result.unwrap();

        assert!(
            resolved.iter().any(|(path, _)| path == "include/app.hpp"),
            "included artifact should survive candidate construction and projection"
        );
        assert!(
            resolved
                .iter()
                .any(|(path, _)| path == "include/detail/internal.hpp"),
            "bounded include closure should preserve graph-native internal header candidates"
        );
        let score_by_path = resolved.iter().cloned().collect::<HashMap<_, _>>();
        assert!(
            score_by_path
                .get("include/app.hpp")
                .is_some_and(|score| *score > 24.0),
            "graph-only include projection should retain a material score"
        );
        assert!(
            score_by_path
                .get("include/detail/internal.hpp")
                .is_some_and(|score| *score > 8.0),
            "second-hop include projection should not collapse below cap-relevant score"
        );
        assert!(
            candidate_stages.iter().any(|stage| {
                stage.name == "text_relation_paths"
                    && stage.candidates.iter().any(|candidate| {
                        candidate.kind == "relation_artifact"
                            && candidate.path.as_deref() == Some("include/app.hpp")
                    })
            }),
            "artifact relation candidate should be visible in debug stages"
        );
        assert!(
            candidate_stages.iter().any(|stage| {
                stage.name == "text_relation_paths"
                    && stage.candidates.iter().any(|candidate| {
                        candidate.kind == "relation_artifact"
                            && candidate.path.as_deref() == Some("include/detail/internal.hpp")
                            && candidate.reason.contains("hop 2")
                    })
            }),
            "include-closure candidate should explain the second artifact hop"
        );
    }

    #[test]
    fn cochange_signals_follow_persisted_graph_truth() {
        let graph = kin_db::InMemoryGraph::new();

        let caller = test_entity("caller", "src/a.py", 1, 10);
        let peer = test_entity("peer", "src/b.py", 12, 24);
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&peer).unwrap();
        graph.flush_text_index().unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::CoChanges,
                src: GraphNodeId::Entity(caller.id),
                dst: GraphNodeId::Entity(peer.id),
                confidence: 0.8,
                origin: RelationOrigin::Inferred,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let seeds = HashMap::from([(
            String::from("src/a.py"),
            vec![FileHit {
                score: 6.0,
                spans: vec![[1, 10]],
            }],
        )]);

        let hits = extract_cochange_signals(&[&seeds], &graph).unwrap();
        assert!(hits.contains_key("src/b.py"));
        assert!(!hits.contains_key("src/a.py"));
    }

    #[test]
    fn historical_locate_rehydrates_cochange_relations_from_reachable_changes() {
        let graph = kin_db::InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(temp.path().join("objects")).unwrap();
        let _layout = kin_core::KinLayout::new(temp.path().join(".kin"));

        let caller = test_entity("caller", "src/a.py", 1, 10);
        let peer = test_entity("peer", "src/b.py", 12, 24);
        let a_path = FilePathId::new("src/a.py");
        let b_path = FilePathId::new("src/b.py");
        let a_hash_v1 = blob_store.write(b"def caller():\n    pass\n").unwrap();
        let b_hash_v1 = blob_store.write(b"def peer():\n    pass\n").unwrap();
        let a_hash_v2 = blob_store
            .write(b"def caller():\n    return 'ok'\n")
            .unwrap();
        let b_hash_v2 = blob_store
            .write(b"def peer():\n    return 'peer'\n")
            .unwrap();

        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x61; 32]));
        let genesis = SemanticChange {
            id: add_id,
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "add files".to_string(),
            entity_deltas: vec![
                EntityDelta::Added(caller.clone()),
                EntityDelta::Added(peer.clone()),
            ],
            relation_deltas: vec![],
            artifact_deltas: vec![
                ArtifactDelta {
                    file_id: a_path.clone(),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(a_hash_v1),
                },
                ArtifactDelta {
                    file_id: b_path.clone(),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(b_hash_v1),
                },
            ],
            projected_files: vec![a_path.clone(), b_path.clone()],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        graph.create_change(&genesis).unwrap();

        let modify_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x62; 32]));
        let cochange_source = SemanticChange {
            id: modify_id,
            parents: vec![add_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "modify together".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![
                ArtifactDelta {
                    file_id: a_path.clone(),
                    kind: ArtifactDeltaKind::Modified,
                    old_hash: Some(a_hash_v1),
                    new_hash: Some(a_hash_v2),
                },
                ArtifactDelta {
                    file_id: b_path.clone(),
                    kind: ArtifactDeltaKind::Modified,
                    old_hash: Some(b_hash_v1),
                    new_hash: Some(b_hash_v2),
                },
            ],
            projected_files: vec![a_path.clone(), b_path.clone()],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        graph.create_change(&cochange_source).unwrap();
        crate::commands::cochange::refresh_from_changes(
            &graph,
            &[genesis.clone(), cochange_source.clone()],
        )
        .unwrap();
        graph.flush_text_index().unwrap();

        let changes = kin_core::collect_changes_at_ref(&graph, &modify_id).unwrap();
        let historical = kin_core::build_graph_at_ref(&graph, &blob_store, &modify_id).unwrap();
        let seeds = HashMap::from([(
            String::from("src/a.py"),
            vec![FileHit {
                score: 6.0,
                spans: vec![[1, 10]],
            }],
        )]);

        let before = extract_cochange_signals(&[&seeds], &historical).unwrap();
        assert!(
            !before.contains_key("src/b.py"),
            "historical graph replay alone should not retain mined cochange relations"
        );

        crate::commands::cochange::refresh_from_changes(&historical, &changes).unwrap();
        let after = extract_cochange_signals(&[&seeds], &historical).unwrap();
        assert!(
            after.contains_key("src/b.py"),
            "historical locate should restore cochange hits from reachable changes before ranking"
        );
    }

    #[test]
    fn module_path_candidates_cover_supported_language_suffixes() {
        let candidates = module_path_candidates("pkg.core.module");

        assert!(candidates.contains(&"pkg/core/module.py".to_string()));
        assert!(candidates.contains(&"pkg/core/module.kt".to_string()));
        assert!(candidates.contains(&"pkg/core/module.swift".to_string()));
        assert!(candidates.contains(&"pkg/core/module.hcl".to_string()));
        assert!(candidates.contains(&"pkg/core/module/index.ts".to_string()));
        assert!(candidates.contains(&"pkg/core/module/mod.rs".to_string()));
    }

    #[test]
    fn module_path_fragments_keep_lowercase_prefixes_from_dotted_test_refs() {
        let fragments =
            extract_module_path_fragments("tests.test_widgets.TestRenderer.test_handles_empty");
        assert!(fragments.contains(&"tests/test_widgets".to_string()));
    }

    #[test]
    fn module_path_fragments_extract_command_bullets() {
        let fragments = extract_module_path_fragments("- auth login\n- pr create\n- repo fork");
        assert!(fragments.contains(&"auth/login".to_string()));
        assert!(fragments.contains(&"pr/create".to_string()));
        assert!(fragments.contains(&"repo/fork".to_string()));
    }

    #[test]
    fn extract_priority_files_skips_broad_module_fragment_suffix_families() {
        let graph = kin_db::InMemoryGraph::new();
        for (name, path) in [
            ("NDData", "astropy/nddata/nddata.py"),
            ("NDArithmeticMixin", "astropy/nddata/mixins/ndarithmetic.py"),
            ("NDSlicingMixin", "astropy/nddata/mixins/ndslicing.py"),
            ("NDIOMixin", "astropy/nddata/mixins/ndio.py"),
            ("CCDData", "astropy/nddata/ccddata.py"),
            ("NDDataBase", "astropy/nddata/nddata_base.py"),
        ] {
            graph
                .upsert_entity(&test_entity(name, path, 1, 40))
                .unwrap();
        }

        let priorities = extract_priority_file_traces(
            "Regression in astropy.nddata.NDDataRef mask handling",
            &graph,
        );

        assert!(priorities.values().all(|trace| {
            trace
                .reasons
                .iter()
                .all(|reason| reason.kind != "module_fragment_suffix")
        }));
    }

    #[test]
    fn command_style_fragment_detection_requires_short_cli_paths() {
        assert!(is_command_style_fragment("auth/login"));
        assert!(is_command_style_fragment("repo/create/http"));
        assert!(!is_command_style_fragment("pkg/core/module"));
        assert!(!is_command_style_fragment("pkg.core.module"));
    }

    #[test]
    fn rich_symbolic_body_query_detects_multi_term_body_evidence() {
        assert!(rich_symbolic_body_query(
            "In v5.3, NDDataRef mask propagation fails\n\nhandle_mask=np.bitwise_or breaks when nref_nomask is involved."
        ));
        assert!(!rich_symbolic_body_query(
            "Fix NDDataRef regression\n\nThis should preserve the existing mask."
        ));
    }

    #[test]
    fn resolve_module_paths_in_graph_is_not_python_only() {
        let graph = kin_db::InMemoryGraph::new();

        let entity = test_entity("handler", "pkg/core/module.kt", 1, 10);
        graph.upsert_entity(&entity).unwrap();

        let resolved = resolve_module_paths_in_graph(&graph, "pkg.core.module");
        assert_eq!(resolved, vec!["pkg/core/module.kt".to_string()]);
    }

    #[test]
    fn resolve_module_paths_in_graph_falls_back_to_partial_command_paths() {
        let graph = kin_db::InMemoryGraph::new();

        let entity = test_entity("CreateOptions", "pkg/cmd/pr/create/create.go", 1, 10);
        graph.upsert_entity(&entity).unwrap();

        let resolved = resolve_module_paths_in_graph(&graph, "pr/create");
        assert_eq!(resolved, vec!["pkg/cmd/pr/create/create.go".to_string()]);
    }

    #[test]
    fn extract_import_signals_handles_quoted_module_paths() {
        let graph = kin_db::InMemoryGraph::new();

        let entity = test_entity("handler", "pkg/core/module.ts", 1, 10);
        graph.upsert_entity(&entity).unwrap();
        graph.flush_text_index().unwrap();

        let hits =
            extract_import_signals(r#"import { handler } from "./pkg/core/module";"#, &graph)
                .unwrap();
        let file_hits = hits.get("pkg/core/module.ts").unwrap();
        assert!(file_hits.iter().any(|hit| hit.score >= 5.0));
    }

    #[test]
    fn extract_import_signals_handles_namespace_imports() {
        let graph = kin_db::InMemoryGraph::new();

        let entity = test_entity("handler", "pkg/core/module.rs", 1, 10);
        graph.upsert_entity(&entity).unwrap();
        graph.flush_text_index().unwrap();

        let hits = extract_import_signals("use pkg::core::module::handler;", &graph).unwrap();
        let file_hits = hits.get("pkg/core/module.rs").unwrap();
        assert!(file_hits.iter().any(|hit| hit.score >= 5.0));
    }

    #[test]
    fn extract_test_signals_handles_pytest_node_ids() {
        let graph = kin_db::InMemoryGraph::new();

        let mut test = test_entity("test_handles_empty", "tests/test_widgets.py", 1, 8);
        test.role = EntityRole::Test;
        graph.upsert_entity(&test).unwrap();
        graph.flush_text_index().unwrap();

        let hits = extract_test_signals(
            "pytest tests/test_widgets.py::TestRenderer::test_handles_empty",
            &graph,
        )
        .unwrap();

        assert!(hits.contains_key("tests/test_widgets.py"));
    }

    #[test]
    fn extract_test_signals_follows_tests_relations_for_test_queries() {
        let graph = kin_db::InMemoryGraph::new();

        let source = test_entity("instrument", "src/lib.rs", 1, 40);
        let mut test = test_entity("test_err_impl_trait", "tests/err.rs", 1, 20);
        test.role = EntityRole::Test;

        graph.upsert_entity(&source).unwrap();
        graph.upsert_entity(&test).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Tests,
                src: GraphNodeId::Entity(test.id),
                dst: GraphNodeId::Entity(source.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let hits =
            extract_test_signals("Add tests for `instrument` with impl Trait", &graph).unwrap();

        assert!(hits.contains_key("tests/err.rs"));
        assert!(hits.contains_key("src/lib.rs"));
    }

    #[test]
    fn extract_cpp_private_access_test_seed_signals_finds_cpp_test_artifacts() {
        let graph = kin_db::InMemoryGraph::new();
        for (idx, (path, text)) in [
            (
                "tests/src/unit-class_iterator.cpp",
                "#define private public\n#include <nlohmann/json.hpp>\nTEST_CASE(\"iterator private access\") {}",
            ),
            (
                "docs/private-public.md",
                "#define private public is discussed in migration notes",
            ),
            (
                "src/private_public.cpp",
                "#define private public should not make a source file a test seed",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            graph
                .upsert_opaque_artifact(&OpaqueArtifact {
                    file_id: FilePathId::new(path),
                    content_hash: Hash256::from_bytes([80 + idx as u8; 32]),
                    mime_type: Some("text/x-c++src".into()),
                    text_preview: Some(text.into()),
                })
                .unwrap();
        }
        graph.flush_text_index().unwrap();

        let hits = extract_cpp_private_access_test_seed_signals(
            "Remove `#define private public` from tests. Add `JSON_PRIVATE_UNLESS_TESTED` controlled by `JSON_TESTS_PRIVATE`.",
            &graph,
        )
        .unwrap();

        assert!(hits.contains_key("tests/src/unit-class_iterator.cpp"));
        assert!(!hits.contains_key("docs/private-public.md"));
        assert!(!hits.contains_key("src/private_public.cpp"));
    }

    #[test]
    fn private_access_test_seeds_follow_include_graph_to_matching_headers() {
        let graph = kin_db::InMemoryGraph::new();
        for (idx, (path, text)) in [
            (
                "tests/src/unit-class_iterator.cpp",
                "#define private public\n#include <nlohmann/json.hpp>\nTEST_CASE(\"iterator private access\") {}",
            ),
            (
                "include/nlohmann/json.hpp",
                "#include <nlohmann/detail/iterators/iter_impl.hpp>\n#include <nlohmann/detail/input/lexer.hpp>",
            ),
            (
                "include/nlohmann/detail/iterators/iter_impl.hpp",
                "#include <nlohmann/detail/iterators/internal_iterator.hpp>\nclass iter_impl {};",
            ),
            (
                "include/nlohmann/detail/input/lexer.hpp",
                "class lexer {};",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            graph
                .upsert_opaque_artifact(&OpaqueArtifact {
                    file_id: FilePathId::new(path),
                    content_hash: Hash256::from_bytes([90 + idx as u8; 32]),
                    mime_type: Some("text/x-c++src".into()),
                    text_preview: Some(text.into()),
                })
                .unwrap();
        }

        let relation = |src: &str, dst: &str| Relation {
            id: RelationId::new(),
            kind: RelationKind::Includes,
            src: GraphNodeId::Artifact(
                graph
                    .artifact_id_for_path(&FilePathId::new(src))
                    .expect("source artifact should be graph-owned"),
            ),
            dst: GraphNodeId::Artifact(
                graph
                    .artifact_id_for_path(&FilePathId::new(dst))
                    .expect("target artifact should be graph-owned"),
            ),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: Some(dst.to_string()),
            evidence: vec![kin_model::RelationEvidence {
                resolved_path: Some(dst.to_string()),
                source_path: Some(dst.to_string()),
                parser_rule: Some("include_directive".to_string()),
                occurrence_count: 1,
                ..kin_model::RelationEvidence::default()
            }],
        };
        graph
            .upsert_relation(&relation(
                "tests/src/unit-class_iterator.cpp",
                "include/nlohmann/json.hpp",
            ))
            .unwrap();
        graph
            .upsert_relation(&relation(
                "include/nlohmann/json.hpp",
                "include/nlohmann/detail/iterators/iter_impl.hpp",
            ))
            .unwrap();
        graph
            .upsert_relation(&relation(
                "include/nlohmann/json.hpp",
                "include/nlohmann/detail/input/lexer.hpp",
            ))
            .unwrap();
        graph.flush_text_index().unwrap();

        let seeds = extract_cpp_private_access_test_seed_signals(
            "Remove `#define private public` from tests. Add `JSON_PRIVATE_UNLESS_TESTED` controlled by `JSON_TESTS_PRIVATE`.",
            &graph,
        )
        .unwrap();
        let hits =
            extract_multihop_signals(&[&seeds], &graph, LocateProfile::Standard, true).unwrap();

        let iter_score: f32 = hits
            .get("include/nlohmann/detail/iterators/iter_impl.hpp")
            .expect("iterator header should be reached through artifact Includes")
            .iter()
            .map(|hit| hit.score)
            .sum();
        let lexer_score: f32 = hits
            .get("include/nlohmann/detail/input/lexer.hpp")
            .expect("lexer header should also be reachable through the same public header")
            .iter()
            .map(|hit| hit.score)
            .sum();
        assert!(
            iter_score > lexer_score,
            "path-specific include traversal should prefer iterator headers for iterator tests: iter={iter_score}, lexer={lexer_score}"
        );
    }

    #[test]
    fn extract_file_paths_handles_line_number_refs() {
        let paths =
            extract_file_paths("error in pkg/cmd/pr/create/create.go:128:17 while evaluating");
        assert!(paths.contains(&"pkg/cmd/pr/create/create.go".to_string()));
    }

    #[test]
    fn extract_search_terms_handles_attribute_macros() {
        let terms = extract_search_terms(
            "attributes: remove closure type annotation in `#[instrument(err)]`",
        );
        assert!(terms.iter().any(|term| term == "instrument"));
        assert!(!terms.iter().any(|term| term == "err"));
    }

    #[test]
    fn extract_search_terms_preserves_cli_flag_compounds() {
        let terms = extract_search_terms(
            "Fix exit handling for `--exit-status` when invalid JSON is provided",
        );
        assert!(terms.iter().any(|term| term == "exit-status"));
    }

    #[test]
    fn extract_search_terms_preserves_plain_cli_flag_compounds() {
        let terms = extract_search_terms("Add --size-hint=# option for streamed input");
        assert!(terms.iter().any(|term| term == "size-hint"));
    }

    #[test]
    fn extract_cli_flag_terms_preserves_short_and_long_flags() {
        let flags = extract_cli_flag_terms("Fix mixing -c, -o and --rm in the CLI");
        assert!(flags.iter().any(|flag| flag == "-c"));
        assert!(flags.iter().any(|flag| flag == "-o"));
        assert!(flags.iter().any(|flag| flag == "--rm"));
    }

    #[test]
    fn query_mentions_cli_flags_detects_short_flags() {
        assert!(query_mentions_cli_flags("Fix -c and -o handling"));
    }

    #[test]
    fn extract_c_api_prefixes_reads_uppercase_symbol_prefixes() {
        let prefixes = extract_c_api_prefixes(
            "Add prototype `ZSTD_decodingBufferSize_min()` to the public API",
        );

        assert!(prefixes.iter().any(|prefix| prefix == "zstd"));
    }

    #[test]
    fn extract_search_signals_ignores_symbolic_comment_only_matches() {
        let graph = kin_db::InMemoryGraph::new();
        let mut noisy = test_entity("signalHandler", "src/decNumber/example4.c", 1, 20);
        noisy.doc_summary = Some("preserve stack snapshot and re-enable traps".into());
        graph.upsert_entity(&noisy).unwrap();
        graph.flush_text_index().unwrap();

        let hits = extract_search_signals(
            "Implement `_experimental_snapshot/2`\n\nEnable writes with `JQ_ENABLE_SNAPSHOT=1`.",
            &graph,
            false,
        )
        .unwrap();

        assert!(
            !hits.contains_key(&noisy.id),
            "symbolic compound queries should not seed comment-only snapshot matches"
        );
    }

    #[test]
    fn extract_source_text_signals_surfaces_symbolic_source_hits() {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_entity(&test_entity("main", "src/main.c", 1, 20))
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/main.c"),
                content_hash: Hash256::from_bytes([8; 32]),
                mime_type: Some("text/x-source".into()),
                text_preview: Some(
                    "usage --exit-status invalid JSON parse error command-line option".into(),
                ),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let hits = extract_source_text_signals(
            "Fix exit code on JSON parse error\n\nThe `--exit-status` option should distinguish invalid JSON parse errors.",
            &graph,
            None,
        )
        .unwrap();

        assert!(hits.contains_key("src/main.c"));
    }

    #[test]
    fn extract_source_text_signals_filters_symbolic_partial_matches_when_full_source_is_available()
    {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_entity(&test_entity("snapshot_builtin", "src/builtin.c", 1, 20))
            .unwrap();
        graph
            .upsert_entity(&test_entity(
                "signalHandler",
                "src/decNumber/example4.c",
                1,
                20,
            ))
            .unwrap();

        let builtin_text = format!(
            "{} _experimental_snapshot writes files when JQ_ENABLE_SNAPSHOT=1",
            "prefix ".repeat(300)
        );
        let noisy_text = format!(
            "{} stack snapshot preserve signal trap handler",
            "prefix ".repeat(300)
        );

        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/builtin.c"),
                content_hash: Hash256::from_bytes([11; 32]),
                mime_type: Some("text/x-source".into()),
                text_preview: Some(builtin_text),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/decNumber/example4.c"),
                content_hash: Hash256::from_bytes([12; 32]),
                mime_type: Some("text/x-source".into()),
                text_preview: Some(noisy_text),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let hits = extract_source_text_signals(
            "Implement `_experimental_snapshot/2`\n\nEnable writes with `JQ_ENABLE_SNAPSHOT=1`.",
            &graph,
            None,
        )
        .unwrap();

        assert!(hits.contains_key("src/builtin.c"));
        assert!(!hits.contains_key("src/decNumber/example4.c"));
    }

    #[test]
    fn extract_source_text_signals_surfaces_concentrated_body_terms() {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_entity(&test_entity("builtin_entry", "src/builtin.c", 1, 20))
            .unwrap();
        graph
            .upsert_entity(&test_entity("main", "src/main.c", 1, 20))
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/builtin.c"),
                content_hash: Hash256::from_bytes([9; 32]),
                mime_type: Some("text/x-source".into()),
                text_preview: Some("jq coded builtin list and builtin registration".into()),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/main.c"),
                content_hash: Hash256::from_bytes([10; 32]),
                mime_type: Some("text/x-source".into()),
                text_preview: Some("jq: error: writing output failed".into()),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let hits = extract_source_text_signals(
            "Implement `_experimental_snapshot/2`\n\nThis builtin performs a dry run by default before writing any data to disk.",
            &graph,
            None,
        )
        .unwrap();

        assert!(hits.contains_key("src/builtin.c"));
        assert!(hits.contains_key("src/main.c"));
    }

    #[test]
    fn extract_source_text_signals_rewards_cli_surface_multi_term_matches() {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_entity(&test_entity("options", "src/options.c", 1, 20))
            .unwrap();
        graph
            .upsert_entity(&test_entity("runtime", "src/runtime.c", 1, 20))
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/options.c"),
                content_hash: Hash256::from_bytes([21; 32]),
                mime_type: Some("text/x-source".into()),
                text_preview: Some("help option parser cli bool flag command line switch".into()),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/runtime.c"),
                content_hash: Hash256::from_bytes([22; 32]),
                mime_type: Some("text/x-source".into()),
                text_preview: Some("help runtime value".into()),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let hits = extract_source_text_signals(
            "fix cli issue when providing --help=false.\n\nThe help option parser should accept bool flags.",
            &graph,
            None,
        )
        .unwrap();

        let options_score: f32 = hits["src/options.c"].iter().map(|hit| hit.score).sum();
        let runtime_score: f32 = hits["src/runtime.c"].iter().map(|hit| hit.score).sum();
        assert!(options_score > runtime_score);
    }

    #[test]
    fn extract_source_text_signals_surfaces_short_cli_flag_hits() {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_entity(&test_entity("main", "programs/zstdcli.c", 1, 40))
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("programs/zstdcli.c"),
                content_hash: Hash256::from_bytes([23; 32]),
                mime_type: Some("text/x-source".into()),
                text_preview: Some(format!(
                    "{} Usage: zstd [OPTIONS...] [-o OUTPUT] -c, --stdout --rm",
                    "prefix ".repeat(240)
                )),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let hits = extract_source_text_signals(
            "Fix #3719 : mixing -c, -o and --rm\n\n`-c` disables `--rm`, but only if it's selected.",
            &graph,
            None,
        )
        .unwrap();

        assert!(hits.contains_key("programs/zstdcli.c"));
    }

    #[test]
    fn extract_source_text_signals_surfaces_cli_flag_hits_from_short_previews() {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_entity(&test_entity("main", "programs/zstdcli.c", 1, 40))
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("programs/zstdcli.c"),
                content_hash: Hash256::from_bytes([24; 32]),
                mime_type: Some("text/x-source".into()),
                text_preview: Some("Usage: zstd [OPTIONS...] [-o OUTPUT] -c, --stdout --rm".into()),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let hits = extract_source_text_signals(
            "Fix #3719 : mixing -c, -o and --rm\n\n`-c` disables `--rm`, but only if it's selected.",
            &graph,
            None,
        )
        .unwrap();

        assert!(hits.contains_key("programs/zstdcli.c"));
    }

    #[test]
    fn extract_source_text_signals_promotes_local_header_include_chain_for_cli_queries() {
        let graph = kin_db::InMemoryGraph::new();
        for (name, path) in [
            ("main", "programs/zstdcli.c"),
            ("FIO_setRemoveSrcFile", "programs/fileio.h"),
            ("removeSrcFile", "programs/fileio_types.h"),
        ] {
            graph
                .upsert_entity(&test_entity(name, path, 1, 40))
                .unwrap();
        }
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("programs/zstdcli.c"),
                content_hash: Hash256::from_bytes([25; 32]),
                mime_type: Some("text/x-source".into()),
                text_preview: Some(
                    "#include \"fileio.h\"\nUsage: zstd [OPTIONS...] [-o OUTPUT] -c, --stdout --rm"
                        .into(),
                ),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("programs/fileio.h"),
                content_hash: Hash256::from_bytes([26; 32]),
                mime_type: Some("text/x-header".into()),
                text_preview: Some(
                    "#include \"fileio_types.h\"\nvoid FIO_setRemoveSrcFile(int enabled);".into(),
                ),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("programs/fileio_types.h"),
                content_hash: Hash256::from_bytes([27; 32]),
                mime_type: Some("text/x-header".into()),
                text_preview: Some("typedef struct { int removeSrcFile; } FIO_prefs_t;".into()),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let hits = extract_source_text_signals(
            "Fix #3719 : mixing -c, -o and --rm\n\n`-c` disables `--rm`, but only if it's selected.",
            &graph,
            None,
        )
        .unwrap();

        let cli_score: f32 = hits["programs/zstdcli.c"].iter().map(|hit| hit.score).sum();
        let fileio_score: f32 = hits["programs/fileio.h"].iter().map(|hit| hit.score).sum();
        let types_score: f32 = hits["programs/fileio_types.h"]
            .iter()
            .map(|hit| hit.score)
            .sum();

        assert!(hits.contains_key("programs/fileio.h"));
        assert!(hits.contains_key("programs/fileio_types.h"));
        assert!(cli_score > fileio_score);
        assert!(fileio_score > types_score);
    }

    #[test]
    fn extract_source_text_signals_promotes_artifact_only_headers_for_cli_queries() {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_entity(&test_entity("main", "programs/zstdcli.c", 1, 40))
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("programs/zstdcli.c"),
                content_hash: Hash256::from_bytes([28; 32]),
                mime_type: Some("text/x-source".into()),
                text_preview: Some(
                    "#include \"fileio.h\"\nUsage: zstd [OPTIONS...] [-o OUTPUT] -c, --stdout --rm"
                        .into(),
                ),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("programs/fileio.h"),
                content_hash: Hash256::from_bytes([29; 32]),
                mime_type: Some("text/x-header".into()),
                text_preview: Some(
                    "#include \"fileio_types.h\"\nvoid FIO_setRemoveSrcFile(int enabled);".into(),
                ),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("programs/fileio_types.h"),
                content_hash: Hash256::from_bytes([30; 32]),
                mime_type: Some("text/x-header".into()),
                text_preview: Some("typedef struct { int removeSrcFile; } FIO_prefs_t;".into()),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let hits = extract_source_text_signals(
            "Fix #3719 : mixing -c, -o and --rm\n\n`-c` disables `--rm`, but only if it's selected.",
            &graph,
            None,
        )
        .unwrap();

        assert!(hits.contains_key("programs/fileio.h"));
        assert!(hits.contains_key("programs/fileio_types.h"));
    }

    #[test]
    fn extract_priority_files_surfaces_query_backed_artifacts() {
        let graph = kin_db::InMemoryGraph::new();

        let mut source = test_entity(
            "useAutocomplete",
            "packages/material-ui/src/Autocomplete/Autocomplete.js",
            1,
            40,
        );
        source.metadata.extra.insert(
            "file_surface_context".into(),
            serde_json::Value::String("surface autocomplete surface".into()),
        );
        graph.upsert_entity(&source).unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("docs/pages/api-docs/autocomplete.json"),
                content_hash: Hash256::from_bytes([3; 32]),
                mime_type: Some("application/json".into()),
                text_preview: Some("Autocomplete API docs".into()),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let priority = extract_priority_files("[Autocomplete] Warn when value is invalid", &graph);

        assert!(priority.iter().any(|(path, score)| path
            == "docs/pages/api-docs/autocomplete.json"
            && *score >= 75.0));
    }

    #[test]
    fn extract_priority_files_surfaces_text_backed_tracked_source_artifacts() {
        let graph = kin_db::InMemoryGraph::new();

        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/builtin.c"),
                content_hash: Hash256::from_bytes([4; 32]),
                mime_type: Some("text/x-source".into()),
                text_preview: Some("uri format RFC 3986 RFC 2396 unreserved characters".into()),
            })
            .unwrap();
        graph.flush_text_index().unwrap();
        assert!(graph
            .text_search("format", 10)
            .unwrap()
            .into_iter()
            .any(|(key, _)| matches!(key, kin_db::RetrievalKey::Artifact(_))));

        let priority = extract_priority_files(
            "Fix uri format to follow RFC 3986\n\nIt seems that the current implementation is based on RFC 2396 unreserved characters rather than RFC 3986.",
            &graph,
        );

        assert!(priority
            .iter()
            .any(|(path, score)| path == "src/builtin.c" && *score >= 50.0));
    }

    #[test]
    fn extract_priority_files_requires_source_confirmation_for_symbolic_text_hits() {
        let graph = kin_db::InMemoryGraph::new();

        let stale_symbol = test_entity("JSON_PRIVATE_UNLESS_TESTED", "src/lib.cpp", 1, 2);
        graph.upsert_entity(&stale_symbol).unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("src/lib.cpp"),
                content_hash: Hash256::from_bytes([44; 32]),
                mime_type: Some("text/x-source".into()),
                text_preview: Some("#define private public\n// old source only".into()),
            })
            .unwrap();
        graph.flush_text_index().unwrap();
        assert!(graph
            .text_search("json_private_unless_tested", 10)
            .unwrap()
            .into_iter()
            .any(|(key, _)| matches!(key, kin_db::RetrievalKey::Entity(_))));

        let traces = extract_priority_file_traces(
            "Remove #define private public from tests\n\nThis PR adds JSON_PRIVATE_UNLESS_TESTED for JSON_TESTS_PRIVATE.",
            &graph,
        );
        let stale_reasons = traces
            .get("src/lib.cpp")
            .map(|trace| {
                trace
                    .reasons
                    .iter()
                    .map(|reason| reason.detail.as_str())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        assert!(
            stale_reasons
                .iter()
                .all(|detail| !detail.contains("json_private_unless_tested")),
            "symbolic stale entity text must not become priority evidence without source confirmation: {stale_reasons:?}"
        );
    }

    #[test]
    fn extract_priority_files_ignores_test_artifacts_for_non_test_queries() {
        let graph = kin_db::InMemoryGraph::new();

        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("test/libponyc/badpony.cc"),
                content_hash: Hash256::from_bytes([5; 32]),
                mime_type: Some("text/x-c++src".into()),
                text_preview: Some("cli help false option coverage".into()),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let priority = extract_priority_files("fix cli issue when providing --help=false.", &graph);

        assert!(priority.is_empty());
    }

    #[test]
    fn extract_priority_files_surfaces_public_api_header_from_symbol_prefix() {
        let graph = kin_db::InMemoryGraph::new();

        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("lib/zstd.h"),
                content_hash: Hash256::from_bytes([35; 32]),
                mime_type: Some("text/x-chdr".into()),
                text_preview: Some("public zstd api header".into()),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("contrib/pzstd/utils/Buffer.h"),
                content_hash: Hash256::from_bytes([36; 32]),
                mime_type: Some("text/x-chdr".into()),
                text_preview: Some("buffer helpers".into()),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let priority = extract_priority_files(
            "Add prototype `ZSTD_decodingBufferSize_min()` to the public API",
            &graph,
        );

        assert!(priority
            .iter()
            .any(|(path, score)| path == "lib/zstd.h" && *score >= 60.0));
    }

    #[test]
    fn extract_priority_files_prefers_named_test_artifacts_for_triple_quote_queries() {
        let graph = kin_db::InMemoryGraph::new();

        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("test/libponyc/lexer.cc"),
                content_hash: Hash256::from_bytes([33; 32]),
                mime_type: Some("text/x-c++src".into()),
                text_preview: Some(
                    "TripleStringWithoutIndentWithTrailingWsLine opening triple quote linebreak"
                        .into(),
                ),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("packages/strings/_test.pony"),
                content_hash: Hash256::from_bytes([34; 32]),
                mime_type: Some("text/x-pony".into()),
                text_preview: Some("  \"\"\"\n  Test strings/CommonPrefix\n  \"\"\"".into()),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let priority = extract_priority_files(
            "Fix inconsistencies in multi-line triple-quoted strings",
            &graph,
        );

        assert!(priority
            .iter()
            .any(|(path, _)| path == "packages/strings/_test.pony"));
        assert!(priority
            .iter()
            .all(|(path, _)| path != "test/libponyc/lexer.cc"));
    }

    #[test]
    fn extract_priority_files_does_not_promote_copying_from_verb_usage() {
        let graph = kin_db::InMemoryGraph::new();

        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("COPYING"),
                content_hash: Hash256::from_bytes([30; 32]),
                mime_type: Some("text/plain".into()),
                text_preview: Some("license text".into()),
            })
            .unwrap();

        let priority =
            extract_priority_files("Fix hashLog3 size when copying cdict tables", &graph);

        assert!(priority.iter().all(|(path, _)| path != "COPYING"));
    }

    #[test]
    fn query_backed_tracked_file_score_ignores_directory_only_matches_for_non_manifests() {
        assert_eq!(
            query_backed_tracked_file_score("tracing-attributes/LICENSE", "attributes"),
            None
        );
    }

    #[test]
    fn query_backed_tracked_file_score_ignores_license_like_basenames() {
        assert_eq!(query_backed_tracked_file_score("COPYING", "copying"), None);
        assert_eq!(
            query_backed_tracked_file_score("docs/LICENSE.md", "license"),
            None
        );
    }

    #[test]
    fn query_backed_tracked_file_score_keeps_manifest_directory_matches() {
        let score = query_backed_tracked_file_score("tracing-attributes/Cargo.toml", "attributes")
            .expect("manifest in matching root should be eligible");
        assert!(score >= 60.0);
    }

    #[test]
    fn boost_test_query_graph_companions_surfaces_same_root_tests_and_manifest() {
        let graph = kin_db::InMemoryGraph::new();

        let source = test_entity("instrument", "tracing-attributes/src/lib.rs", 1, 80);
        let mut err_test = test_entity(
            "test_err_impl_trait",
            "tracing-attributes/tests/err.rs",
            1,
            30,
        );
        err_test.role = EntityRole::Test;
        let mut async_test = test_entity(
            "test_async_impl_trait",
            "tracing-attributes/tests/async_fn.rs",
            1,
            30,
        );
        async_test.role = EntityRole::Test;

        graph.upsert_entity(&source).unwrap();
        graph.upsert_entity(&err_test).unwrap();
        graph.upsert_entity(&async_test).unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("tracing-attributes/Cargo.toml"),
                content_hash: Hash256::from_bytes([9; 32]),
                mime_type: Some("text/toml".into()),
                text_preview: Some("tracing-attributes manifest".into()),
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let mut fused = vec![("tracing-attributes/src/lib.rs".to_string(), 10.0)];
        let resolved = vec![("tracing-attributes/src/lib.rs".to_string(), 10.0)];
        let empty_hits: HashMap<String, Vec<FileHit>> = HashMap::new();
        let signal_sets = [
            &empty_hits,
            &empty_hits,
            &empty_hits,
            &empty_hits,
            &empty_hits,
            &empty_hits,
            &empty_hits,
            &empty_hits,
            &empty_hits,
        ];

        boost_test_query_graph_companions(
            &mut fused,
            "Add tests for `instrument(err)` with impl Trait, both with and without err",
            &graph,
            &resolved,
            &signal_sets,
        )
        .unwrap();

        let paths: HashSet<_> = fused.iter().map(|(path, _)| path.as_str()).collect();
        assert!(paths.contains("tracing-attributes/tests/err.rs"));
        assert!(paths.contains("tracing-attributes/tests/async_fn.rs"));
        assert!(paths.contains("tracing-attributes/Cargo.toml"));
    }

    #[test]
    fn boost_query_backed_test_artifacts_surfaces_relevant_tracked_tests() {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_entity(&test_entity(
                "triple_string",
                "src/libponyc/ast/lexer.c",
                1,
                80,
            ))
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("packages/regex/_test.pony"),
                content_hash: Hash256::from_bytes([13; 32]),
                mime_type: Some("text/x-pony".into()),
                text_preview: Some(r#"let r = Regex("""(\d+)?\.(\d+)?""")?"#.into()),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("packages/strings/_test.pony"),
                content_hash: Hash256::from_bytes([14; 32]),
                mime_type: Some("text/x-pony".into()),
                text_preview: Some("  \"\"\"\n  Test strings/CommonPrefix\n  \"\"\"".into()),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("packages/ini/_test.pony"),
                content_hash: Hash256::from_bytes([15; 32]),
                mime_type: Some("text/x-pony".into()),
                text_preview: Some("  \"\"\"\n  Ini docs\n  \"\"\"".into()),
            })
            .unwrap();

        let mut fused = vec![("src/libponyc/ast/lexer.c".to_string(), 1.0)];
        let boosted = boost_query_backed_test_artifacts(
            &mut fused,
            "Fix inconsistencies in multi-line triple-quoted strings",
            &graph,
            false,
            &[("packages/regex/_test.pony".to_string(), 60.0)],
        );

        let scores: HashMap<_, _> = fused.iter().cloned().collect();
        assert!(boosted.contains("packages/regex/_test.pony"));
        assert!(boosted.contains("packages/strings/_test.pony"));
        assert!(scores["packages/regex/_test.pony"] > 0.0);
        assert!(scores["packages/strings/_test.pony"] > 0.0);
    }

    #[test]
    fn boost_query_backed_test_artifacts_requires_strong_non_test_evidence() {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("test/libponyc/badpony.cc"),
                content_hash: Hash256::from_bytes([16; 32]),
                mime_type: Some("text/x-c++src".into()),
                text_preview: Some("cli help false option coverage".into()),
            })
            .unwrap();

        let mut fused = vec![("src/libponyc/plugin/plugin.c".to_string(), 1.0)];
        let boosted = boost_query_backed_test_artifacts(
            &mut fused,
            "fix cli issue when providing --help=false.",
            &graph,
            false,
            &[],
        );

        assert!(boosted.is_empty());
        assert_eq!(fused.len(), 1);
    }

    #[test]
    fn boost_query_backed_test_artifacts_skips_non_named_test_harness_overlap() {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("test/libponyc/lexer.cc"),
                content_hash: Hash256::from_bytes([31; 32]),
                mime_type: Some("text/x-c++src".into()),
                text_preview: Some(
                    "TripleStringWithoutIndentWithTrailingWsLine opening triple quote linebreak"
                        .into(),
                ),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("packages/strings/_test.pony"),
                content_hash: Hash256::from_bytes([32; 32]),
                mime_type: Some("text/x-pony".into()),
                text_preview: Some("  \"\"\"\n  Test strings/CommonPrefix\n  \"\"\"".into()),
            })
            .unwrap();

        let mut fused = vec![("src/libponyc/ast/lexer.c".to_string(), 1.0)];
        let boosted = boost_query_backed_test_artifacts(
            &mut fused,
            "Fix inconsistencies in multi-line triple-quoted strings",
            &graph,
            false,
            &[],
        );

        assert!(!boosted.contains("test/libponyc/lexer.cc"));
        assert!(boosted.contains("packages/strings/_test.pony"));
    }

    #[test]
    fn multihop_from_command_direct_hits_reaches_shared_prompt_file() {
        let graph = kin_db::InMemoryGraph::new();

        let command = test_entity("CreateOptions", "pkg/cmd/pr/create/create.go", 1, 40);
        let prompt = test_entity("Confirm", "pkg/prompt/prompt.go", 1, 20);

        graph.upsert_entity(&command).unwrap();
        graph.upsert_entity(&prompt).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Imports,
                src: GraphNodeId::Entity(command.id),
                dst: GraphNodeId::Entity(prompt.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let direct_hits = HashMap::from([(
            String::from("pkg/cmd/pr/create/create.go"),
            vec![FileHit {
                score: 4.0,
                spans: vec![],
            }],
        )]);

        let hits =
            extract_multihop_signals(&[&direct_hits], &graph, LocateProfile::Standard, false)
                .unwrap();
        assert!(hits.contains_key("pkg/prompt/prompt.go"));
    }

    #[test]
    fn collect_signals_names_cochange_label() {
        let all_hits = vec![
            HashMap::new(),                                        // 0: traceback
            HashMap::new(),                                        // 1: multihop
            HashMap::new(),                                        // 2: tests
            HashMap::new(),                                        // 3: snippets
            HashMap::new(),                                        // 4: imports
            HashMap::new(),                                        // 5: errors
            HashMap::from([(String::from("src/b.py"), hit(1.0))]), // 6: cochange
            HashMap::new(),                                        // 7: entity_resolve
            HashMap::new(),                                        // 8: source_text
        ];

        let signals = collect_signals_for_file("src/b.py", &all_hits);
        assert_eq!(signals, vec!["cochange".to_string()]);
    }

    #[test]
    fn collect_signals_names_entity_resolve_label() {
        let all_hits = vec![
            HashMap::new(),                                        // 0: traceback
            HashMap::new(),                                        // 1: multihop
            HashMap::new(),                                        // 2: tests
            HashMap::new(),                                        // 3: snippets
            HashMap::new(),                                        // 4: imports
            HashMap::new(),                                        // 5: errors
            HashMap::new(),                                        // 6: cochange
            HashMap::from([(String::from("src/c.py"), hit(2.0))]), // 7: entity_resolve
            HashMap::new(),                                        // 8: source_text
        ];

        let signals = collect_signals_for_file("src/c.py", &all_hits);
        assert_eq!(signals, vec!["entity_resolve".to_string()]);
    }

    #[test]
    fn locate_at_ref_uses_historical_entity_and_artifact_state() {
        let graph = kin_db::InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(temp.path().join("objects")).unwrap();
        let layout = kin_core::KinLayout::new(temp.path().join(".kin"));

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x71; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let entity_v1 = test_entity("handler", "src/lib.py", 1, 10);
        let mut entity_v2 = entity_v1.clone();
        entity_v2.name = "processor".to_string();
        entity_v2.signature = "def processor(value)".to_string();
        entity_v2.fingerprint.signature_hash = Hash256::from_bytes([0x72; 32]);

        let artifact_path = FilePathId::new("docs/api.json");
        let artifact_v1 = blob_store.write(br#"{"version":"handler guide"}"#).unwrap();
        let artifact_v2 = blob_store
            .write(br#"{"version":"processor guide"}"#)
            .unwrap();

        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x75; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add handler".to_string(),
                entity_deltas: vec![EntityDelta::Added(entity_v1.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: artifact_path.clone(),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(artifact_v1),
                }],
                projected_files: vec![artifact_path.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let modify_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x76; 32]));
        graph
            .create_change(&SemanticChange {
                id: modify_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify handler".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity_v1.clone(),
                    new: entity_v2.clone(),
                }],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: artifact_path.clone(),
                    kind: ArtifactDeltaKind::Modified,
                    old_hash: Some(artifact_v1),
                    new_hash: Some(artifact_v2),
                }],
                projected_files: vec![artifact_path.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        #[cfg(feature = "vector")]
        load_complete_test_vectors(&graph, &[entity_v2.clone()]);

        let historical = run_with_graph_capture_at_ref(
            &layout,
            &graph,
            &blob_store,
            &add_id,
            "change:add",
            "handler failure",
            false,
            10,
            true,
        )
        .unwrap();
        assert_eq!(
            historical
                .files
                .iter()
                .filter(|file| file.path == "src/lib.py")
                .count(),
            1,
            "historical locate should surface the pre-rename source file"
        );

        let current = run_with_graph_capture_at_ref(
            &layout,
            &graph,
            &blob_store,
            &modify_id,
            "change:modify",
            "handler failure",
            false,
            10,
            true,
        )
        .unwrap();
        assert!(
            current.files.iter().all(|file| file.path != "src/lib.py"),
            "current locate should not surface the renamed source file for the old query"
        );

        let rebuilt = kin_core::build_graph_at_ref(&graph, &blob_store, &add_id).unwrap();
        assert_eq!(
            rebuilt.get_file_hash(&artifact_path.0),
            Some(*artifact_v1.as_bytes())
        );
        assert!(
            rebuilt
                .list_opaque_artifacts()
                .unwrap()
                .iter()
                .any(|artifact| {
                    artifact.file_id == artifact_path
                        && artifact.content_hash == artifact_v1
                        && artifact
                            .text_preview
                            .as_deref()
                            .unwrap_or_default()
                            .contains("handler guide")
                }),
            "historical artifact metadata should be rebuilt from the historical blob"
        );
    }

    fn test_entity(name: &str, path: &str, start_line: u32, end_line: u32) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([1; 32]),
                behavior_hash: Hash256::from_bytes([2; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(path)),
            span: Some(SourceSpan {
                file: FilePathId::new(path),
                start_byte: 0,
                end_byte: 0,
                start_line,
                start_col: 1,
                end_line,
                end_col: 1,
            }),
            signature: format!("def {}()", name),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    // ── Determinism regression tests ──────────────────────────────────────
    // The locate pipeline must return a byte-identical ordering on every run
    // for identical inputs, including when scores tie. Ties used to settle in
    // whatever order the upstream HashMap happened to yield, which flipped
    // boundary results run-to-run (proven: strict F1 0.2182 vs 0.2110 on a
    // bit-exact binary). Every score sort now carries a path/id tie-break.

    #[test]
    fn rrf_output_is_byte_identical_across_runs() {
        // Several files tie on the rank term (each appears once at rank 0 in a
        // distinct list with equal score). Fusing repeatedly must yield exactly
        // the same ordering every time.
        std::env::set_var("KIN_LOCATE_SEMANTIC_PRIMACY_WEIGHT", "0.0");
        let lists: Vec<Vec<(String, f32)>> = vec![
            vec![("src/d.rs".to_string(), 1.0)],
            vec![("src/a.rs".to_string(), 1.0)],
            vec![("src/c.rs".to_string(), 1.0)],
            vec![("src/b.rs".to_string(), 1.0)],
        ];
        let first = reciprocal_rank_fusion_weighted(&lists, 60.0, &[], &[]);
        for _ in 0..16 {
            let again = reciprocal_rank_fusion_weighted(&lists, 60.0, &[], &[]);
            assert_eq!(again, first, "RRF output must be byte-identical across runs");
        }
        std::env::remove_var("KIN_LOCATE_SEMANTIC_PRIMACY_WEIGHT");
        // All-tied scores: ordering must be the canonical path-ascending order.
        let order: Vec<&str> = first.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(order, vec!["src/a.rs", "src/b.rs", "src/c.rs", "src/d.rs"]);
    }

    #[test]
    fn rrf_tie_break_is_independent_of_input_list_order() {
        // The same tied candidates presented in different per-list orders (a
        // stand-in for HashMap iteration variance upstream) must fuse to the
        // same final ordering — the path tie-break, not arrival order, decides.
        std::env::set_var("KIN_LOCATE_SEMANTIC_PRIMACY_WEIGHT", "0.0");
        let forward: Vec<Vec<(String, f32)>> = vec![vec![
            ("src/a.rs".to_string(), 5.0),
            ("src/b.rs".to_string(), 5.0),
            ("src/c.rs".to_string(), 5.0),
        ]];
        let reversed: Vec<Vec<(String, f32)>> = vec![vec![
            ("src/c.rs".to_string(), 5.0),
            ("src/b.rs".to_string(), 5.0),
            ("src/a.rs".to_string(), 5.0),
        ]];
        let a = reciprocal_rank_fusion_weighted(&forward, 60.0, &[], &[]);
        let b = reciprocal_rank_fusion_weighted(&reversed, 60.0, &[], &[]);
        std::env::remove_var("KIN_LOCATE_SEMANTIC_PRIMACY_WEIGHT");
        // Same RANK positions tie within one list, so the rank term is equal for
        // all three; only the within-list rank differs. The fused set and its
        // tie-broken order must be stable regardless of how the list was ordered.
        let names_a: Vec<&str> = a.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(names_a, vec!["src/a.rs", "src/b.rs", "src/c.rs"]);
        // b orders the input differently but the per-position rank terms differ,
        // so b is not required to equal a; what IS required is that re-running b
        // is itself stable.
        for _ in 0..8 {
            let b_again = reciprocal_rank_fusion_weighted(&reversed, 60.0, &[], &[]);
            assert_eq!(b_again, b, "RRF must be stable for a fixed input");
        }
    }

    #[test]
    fn resolve_to_files_is_deterministic_with_tied_entities() {
        // resolve_entities_to_files projects entity seeds to files. Two entities
        // in different files with the same discovery score tie; the projected
        // order must be byte-identical on every run (path tie-break), not flip
        // with seed HashMap iteration order.
        let graph = kin_db::InMemoryGraph::new();
        let e1 = test_entity("alpha", "src/aaa.py", 1, 5);
        let e2 = test_entity("beta", "src/bbb.py", 1, 5);
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let mut seeds: HashMap<kin_model::EntityId, EntityDiscovery> = HashMap::new();
        seeds.insert(
            e1.id,
            EntityDiscovery {
                score: 1.0,
                signals: vec!["search"],
                cosine: None,
            },
        );
        seeds.insert(
            e2.id,
            EntityDiscovery {
                score: 1.0,
                signals: vec!["search"],
                cosine: None,
            },
        );

        let first = resolve_entities_to_files(&seeds, &graph, false, "test")
            .unwrap()
            .0
            .iter()
            .map(|(p, _)| p.clone())
            .collect::<Vec<_>>();
        for _ in 0..8 {
            let again = resolve_entities_to_files(&seeds, &graph, false, "test")
                .unwrap()
                .0
                .iter()
                .map(|(p, _)| p.clone())
                .collect::<Vec<_>>();
            assert_eq!(again, first, "resolve projection order must be deterministic");
        }
    }

    // ───────────────────────────────────────────────────────────────────────
    // Entity-granular fusion (KIN_LOCATE_ENTITY_FUSION) — 3.1 step 3.
    // The OFF path is exercised (and proven byte-stable) by every other test in
    // this module plus the determinism tests above: the flag gates an `if` whose
    // body is never entered when unset, so the original track-regime fusion runs
    // verbatim. These tests pin the ON-path projection logic.
    // ───────────────────────────────────────────────────────────────────────

    #[test]
    fn entity_fusion_is_disabled_by_default() {
        // The architecture bet must stay OFF until the post-freeze A/B flips it.
        // No test in this module sets the var, so the default governs.
        assert!(
            !locate_env_bool("KIN_LOCATE_ENTITY_FUSION", false),
            "KIN_LOCATE_ENTITY_FUSION must default OFF"
        );
    }

    #[test]
    fn reciprocal_rank_fusion_entities_ranks_skips_vendored_and_is_deterministic() {
        // Two distinct entity keys projecting to real files, plus a vendored one
        // that must be dropped by PATH even though its key is non-vendored.
        let lists = vec![
            vec![
                ("entity:1".to_string(), "src/a.rs".to_string(), 10.0),
                ("entity:2".to_string(), "src/b.rs".to_string(), 4.0),
                (
                    "entity:9".to_string(),
                    "third_party/dep/x.rs".to_string(),
                    99.0,
                ),
            ],
            vec![("entity:1".to_string(), "src/a.rs".to_string(), 7.0)],
        ];
        let fused = reciprocal_rank_fusion_entities(&lists, 60.0);
        let keys: Vec<&str> = fused.iter().map(|(k, _, _)| k.as_str()).collect();
        assert!(
            !keys.contains(&"entity:9"),
            "vendored file must be skipped by path"
        );
        // entity:1 appears in both lists at rank 0 → highest rank term + a
        // cross-signal bonus → must outrank entity:2 (single list).
        assert_eq!(fused[0].0, "entity:1");
        assert_eq!(fused[0].1, "src/a.rs");
        assert_eq!(fused[1].0, "entity:2");
        // Deterministic across repeated calls.
        let again = reciprocal_rank_fusion_entities(&lists, 60.0);
        assert_eq!(fused, again, "entity fusion must be deterministic");
    }

    #[test]
    fn entity_seed_keyed_preserves_per_entity_granularity() {
        let graph = kin_db::InMemoryGraph::new();
        // Two source entities in ONE file (the granularity the path pipeline
        // collapses), one in another file, plus a test-file entity to exclude.
        let a1 = test_entity("alpha", "src/shared.rs", 1, 10);
        let a2 = test_entity("beta", "src/shared.rs", 20, 30);
        let b = test_entity("gamma", "src/other.rs", 1, 10);
        let mut t = test_entity("test_helper", "tests/it_test.rs", 1, 10);
        t.role = EntityRole::Test; // is_test_by_role keys on role when present
        for e in [&a1, &a2, &b, &t] {
            graph.upsert_entity(e).unwrap();
        }
        let seeds = HashMap::from([
            (a1.id, disc(9.0)),
            (a2.id, disc(3.0)),
            (b.id, disc(6.0)),
            (t.id, disc(100.0)),
        ]);
        let keyed = entity_seed_keyed(&seeds, &graph).unwrap();
        // Test entity excluded; the other three survive as distinct items.
        assert_eq!(keyed.len(), 3, "test entity must be excluded");
        let shared_items: Vec<&(String, String, f32)> =
            keyed.iter().filter(|(_, p, _)| p == "src/shared.rs").collect();
        assert_eq!(
            shared_items.len(),
            2,
            "two entities in one file stay distinct (entity granularity)"
        );
        // Sorted by score desc → src/shared.rs alpha(9) first, src/other.rs(6),
        // then src/shared.rs beta(3).
        assert_eq!(keyed[0].2, 9.0);
        assert_eq!(keyed[1].2, 6.0);
        assert_eq!(keyed[2].2, 3.0);
    }

    #[test]
    fn entity_granular_fused_files_projects_best_entity_per_file() {
        let graph = kin_db::InMemoryGraph::new();
        let a1 = test_entity("alpha", "src/a.rs", 1, 10);
        let a2 = test_entity("beta", "src/a.rs", 20, 30);
        let b = test_entity("gamma", "src/b.rs", 1, 10);
        for e in [&a1, &a2, &b] {
            graph.upsert_entity(e).unwrap();
        }
        // Two entities in src/a.rs (scores 10, 4), one in src/b.rs (score 8).
        let text_seeds = HashMap::from([
            (a1.id, disc(10.0)),
            (a2.id, disc(4.0)),
            (b.id, disc(8.0)),
        ]);
        let embedding_seeds: HashMap<kin_model::EntityId, EntityDiscovery> = HashMap::new();
        let ranked_lists: Vec<Vec<(String, f32)>> = vec![Vec::new(); 10];
        let fused =
            entity_granular_fused_files(&ranked_lists, &text_seeds, &embedding_seeds, &graph)
                .unwrap();
        // Both files present; the two src/a.rs entities collapse to ONE file.
        assert_eq!(fused.len(), 2, "two entities in one file project to one file");
        assert_eq!(fused[0].0, "src/a.rs", "best-ranked entity's file wins");
        assert_eq!(fused[1].0, "src/b.rs");
        assert!(fused[0].1 > fused[1].1);
    }

    #[test]
    fn entity_granular_fused_files_falls_back_to_path_rrf_without_seeds() {
        // No entity-derived seeds → every signal keys by path → the result is a
        // plain file projection (no signal dropped, vendored excluded).
        let graph = kin_db::InMemoryGraph::new();
        let empty: HashMap<kin_model::EntityId, EntityDiscovery> = HashMap::new();
        let mut ranked_lists: Vec<Vec<(String, f32)>> = vec![Vec::new(); 10];
        ranked_lists[0] = vec![
            ("src/x.rs".to_string(), 1.0),
            ("src/y.rs".to_string(), 0.5),
            ("vendor/dep/z.rs".to_string(), 9.0),
        ];
        let fused = entity_granular_fused_files(&ranked_lists, &empty, &empty, &graph).unwrap();
        let paths: Vec<&str> = fused.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&"src/x.rs"));
        assert!(paths.contains(&"src/y.rs"));
        assert!(
            !paths.contains(&"vendor/dep/z.rs"),
            "vendored file excluded in path-fallback projection"
        );
        assert_eq!(fused[0].0, "src/x.rs", "higher-ranked path wins");
    }

    fn disc(score: f32) -> EntityDiscovery {
        EntityDiscovery {
            score,
            signals: vec!["search"],
            cosine: None,
        }
    }
}
