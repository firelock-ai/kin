// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{
    ChangeStore, EntityFilter, EntityKind, EntityRole, EntityStore, GraphNodeId, RelationKind,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::capability::LocateProfile;

// ---------------------------------------------------------------------------
// JSON output types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct LocateResult {
    pub files: Vec<LocateFileEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct LocateFileEntry {
    pub path: String,
    pub score: f32,
    #[serde(default)]
    pub signals: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spans: Vec<[u32; 2]>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub explain: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<LocateFileProvenance>,
    /// Per-signal score breakdown (only with --explain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_scores: Option<std::collections::HashMap<String, f32>>,
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

// ---------------------------------------------------------------------------
// Phase 1: Entity-level discovery types
// ---------------------------------------------------------------------------

/// Entity-level score accumulated during Phase 1 discovery.
/// Multiple signals contribute scores to the same entity — they are summed.
#[derive(Clone, Default)]
struct EntityDiscovery {
    score: f32,
    signals: Vec<&'static str>,
}

#[derive(Clone)]
struct TrackedFileInfo {
    path: String,
    descriptor: String,
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

fn entity_id_from_retrieval_key(key: &kin_db::RetrievalKey) -> Option<kin_model::EntityId> {
    match key {
        kin_db::RetrievalKey::Entity(entity_id) => Some(*entity_id),
        kin_db::RetrievalKey::Artifact(_) => None,
    }
}

fn entity_from_retrieval_key(
    graph: &kin_db::InMemoryGraph,
    key: &kin_db::RetrievalKey,
) -> Result<Option<kin_model::Entity>> {
    let Some(entity_id) = entity_id_from_retrieval_key(key) else {
        return Ok(None);
    };
    Ok(graph.get_entity(&entity_id)?)
}

fn retrieval_file_hit(
    graph: &kin_db::InMemoryGraph,
    key: &kin_db::RetrievalKey,
) -> Result<Option<(String, Vec<[u32; 2]>, Option<kin_model::Entity>)>> {
    if let Some(entity) = entity_from_retrieval_key(graph, key)? {
        let Some(file_origin) = entity.file_origin.as_ref() else {
            return Ok(None);
        };
        return Ok(Some((
            file_origin.0.clone(),
            entity_span_pair(&entity),
            Some(entity),
        )));
    }

    let Some(item) = graph.resolve_retrieval_key(key) else {
        return Ok(None);
    };
    let Some(file_path) = item.file_path() else {
        return Ok(None);
    };
    Ok(Some((file_path.0, Vec::new(), None)))
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
) -> Result<()> {
    let _span = tracing::info_span!(
        "kin.locate",
        text_len = text.len(),
        json = json,
        explain = explain,
        max_files = max_files
    )
    .entered();
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    if let Some(result) =
        try_locate_via_daemon(&layout, text, explain, max_files, max_files_explicit).await?
    {
        output_result(&result, json);
        return Ok(());
    }

    let snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*snap.graph();
    run_with_graph(graph, text, json, explain, max_files, max_files_explicit)
}

async fn try_locate_via_daemon(
    layout: &kin_core::KinLayout,
    text: &str,
    explain: bool,
    max_files: usize,
    max_files_explicit: bool,
) -> Result<Option<LocateResult>> {
    let Some(base_url) = crate::daemon_client::resolve_daemon_url(layout).await? else {
        return Ok(None);
    };
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    let request = crate::daemon_client::LocateRequest {
        text: text.to_string(),
        explain,
        max_files,
        max_files_explicit,
    };
    Ok(Some(client.locate(&request).await?))
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
    let _span = tracing::info_span!(
        "kin.locate.run_with_graph",
        text_len = text.len(),
        explain = explain,
        max_files = max_files
    )
    .entered();
    // Strip HTML comments from issue text
    let text = &clean_issue_text(text);

    let pipeline_report = std::env::var("KIN_LOCATE_PIPELINE_REPORT").is_ok();
    let profile = LocateProfile::detect();

    // Extract priority files (explicit file paths mentioned in the text)
    let priority_files = extract_priority_files(text, graph);

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 1: Discovery — find candidate ENTITIES, not files.
    // Text search + embeddings discover which entities are relevant.
    // File resolution is deferred to Phase 2 (graph-based).
    // ═══════════════════════════════════════════════════════════════════════

    // Phase 1a: Entity-first signals — return entity seeds
    let (search_entity_seeds, search_direct_files) = extract_search_signals(text, graph)?;
    let embedding_entity_seeds = extract_embedding_signals(text, graph)?;

    // Phase 1b: File-based signals — these bypass entity resolution
    let traceback = extract_traceback_signals(text, graph)?;
    let tests = extract_test_signals(text, graph)?;
    let snippets = extract_snippet_signals(text, graph)?;
    let imports = extract_import_signals(text, graph)?;
    let errors = extract_error_signals(text, graph)?;

    // Merge all entity seeds from Phase 1a
    let mut all_entity_seeds: HashMap<kin_model::EntityId, EntityDiscovery> = search_entity_seeds;
    for (entity_id, discovery) in embedding_entity_seeds {
        let entry = all_entity_seeds.entry(entity_id).or_default();
        entry.score += discovery.score;
        for sig in discovery.signals {
            if !entry.signals.contains(&sig) {
                entry.signals.push(sig);
            }
        }
    }

    tracing::info!(
        entity_seeds = all_entity_seeds.len(),
        direct_file_hits = search_direct_files.len(),
        "Phase 1 discovery complete"
    );

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 2: Entity → File resolution via graph relations.
    // The graph is the authority for determining which files to modify.
    // LSP-resolved relations carry 2× weight (type-resolved, high confidence).
    // ═══════════════════════════════════════════════════════════════════════

    let (resolved_files, resolve_explain, resolve_signal_scores) =
        resolve_entities_to_files(&all_entity_seeds, graph, explain)?;

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

    // Phase 2b: Multihop expansion from resolved files (graph follow-up)
    let multihop = extract_multihop_signals(
        &[&resolved_hits, &traceback, &tests, &imports, &errors],
        graph,
        profile,
    )?;

    // Phase 2c: Cochange from all signals
    let cochange = extract_cochange_signals(
        &[&resolved_hits, &traceback, &tests, &imports, &errors],
        graph,
    )?;

    // ═══════════════════════════════════════════════════════════════════════
    // FUSION: Blend Phase 2 resolved files with file-based signals via RRF.
    // ═══════════════════════════════════════════════════════════════════════

    let signal_confidence_weights = [
        locate_env_f32("KIN_LOCATE_WEIGHT_TRACEBACK", 1.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_SEARCH", 1.2), // search: discovery → entity → file
        locate_env_f32("KIN_LOCATE_WEIGHT_MULTIHOP", 1.4), // multihop: graph expansion
        locate_env_f32("KIN_LOCATE_WEIGHT_TESTS", 1.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_SNIPPETS", 0.8),
        locate_env_f32("KIN_LOCATE_WEIGHT_IMPORTS", 1.2),
        locate_env_f32("KIN_LOCATE_WEIGHT_ERRORS", 1.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_COCHANGE", 1.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_PROJECTION", 2.0), // entity_resolve: the graph authority
    ];

    let mut ranked_lists: Vec<Vec<(String, f32)>> = vec![
        to_ranked(&traceback),
        to_ranked(&search_direct_files),
        to_ranked(&multihop),
        to_ranked(&tests),
        to_ranked(&snippets),
        to_ranked(&imports),
        to_ranked(&errors),
        to_ranked(&cochange),
        to_ranked(&resolved_hits), // Phase 2 entity resolution — the primary ranking
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
        "search",
        "multihop",
        "tests",
        "snippets",
        "imports",
        "errors",
        "cochange",
        "entity_resolve",
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
    // idx 0=traceback, 1=search_direct, 2=multihop, 3=tests, 4=snippets,
    // 5=imports, 6=errors, 7=cochange, 8=entity_resolve
    let traceback_top = ranked_lists[0].first().map(|(_, s)| *s).unwrap_or(0.0);
    let resolve_top = ranked_lists[8].first().map(|(_, s)| *s).unwrap_or(0.0);
    let resolve_gap = if ranked_lists[8].len() >= 2 {
        let first = ranked_lists[8][0].1;
        let second = ranked_lists[8][1].1;
        if first > 0.001 {
            (first - second) / first
        } else {
            0.0
        }
    } else {
        0.0
    };
    let multihop_top = ranked_lists[2].first().map(|(_, s)| *s).unwrap_or(0.0);

    #[derive(Debug, Clone, Copy)]
    enum ScoringTrack {
        TracebackDominant,
        EntityDominant,
        GraphStructural,
        BroadBlend,
    }

    // Check if the top resolved file is a generic module (__init__.py, __init__.rs, mod.rs)
    let resolve_top_is_generic = ranked_lists[8]
        .first()
        .map(|(p, _)| {
            p.ends_with("__init__.py") || p.ends_with("__init__.rs") || p.ends_with("mod.rs")
        })
        .unwrap_or(false);

    let tb_threshold = locate_env_f32("KIN_LOCATE_TRACEBACK_DOMINANT_THRESHOLD", 5.0);
    let ed_resolve_min = locate_env_f32("KIN_LOCATE_ENTITY_DOMINANT_RESOLVE_MIN", 20.0);
    let ed_gap_min = locate_env_f32("KIN_LOCATE_ENTITY_DOMINANT_GAP_MIN", 0.15);

    let track = if traceback_top > tb_threshold {
        ScoringTrack::TracebackDominant
    } else if resolve_top > ed_resolve_min && resolve_gap > ed_gap_min && !resolve_top_is_generic {
        ScoringTrack::EntityDominant
    } else if resolve_top < 1.0 && multihop_top > 1.0 {
        ScoringTrack::GraphStructural
    } else {
        ScoringTrack::BroadBlend
    };

    let mut fused = match track {
        ScoringTrack::TracebackDominant => {
            // Traceback explicitly names files — trust it as ground truth.
            // Entity resolve and multihop supplement but don't override.
            let mut weights = signal_confidence_weights;
            weights[0] = 10.0; // traceback dominates
            weights[8] = 2.0; // entity_resolve second
            for w in weights[2..8].iter_mut() {
                *w *= 0.3;
            } // suppress others
            for (list, weight) in ranked_lists.iter_mut().zip(weights.iter()) {
                for (_, score) in list.iter_mut() {
                    *score *= weight;
                }
            }
            reciprocal_rank_fusion(&ranked_lists, 60.0)
        }
        ScoringTrack::EntityDominant => {
            // Entity resolution has a clear winner with a score gap — trust it.
            // Use entity_resolve as primary ranking, supplement with other signals
            // only for files that DON'T appear in entity_resolve.
            let resolve_list = &ranked_lists[8];
            let mut result: Vec<(String, f32)> = Vec::new();
            let resolve_set: HashSet<String> =
                resolve_list.iter().map(|(p, _)| p.clone()).collect();

            // Entity-resolved files first, in resolve order
            for (path, score) in resolve_list {
                if !is_test_path(path) {
                    result.push((path.clone(), *score));
                }
            }

            // Supplement with non-test files from other signals that resolution missed
            let other_fused = reciprocal_rank_fusion(&ranked_lists[..8].to_vec(), 60.0);
            for (path, score) in other_fused {
                if !resolve_set.contains(&path) && !is_test_path(&path) {
                    result.push((path, score * 0.5));
                }
            }
            result
        }
        ScoringTrack::GraphStructural => {
            // No entity resolve — rely on graph expansion signals.
            // Boost multihop and imports, suppress test/snippet noise.
            reciprocal_rank_fusion(&ranked_lists, 60.0)
        }
        ScoringTrack::BroadBlend => {
            // Mixed signals — standard RRF blend, but penalize test files
            // in non-resolve signals to prevent test files from winning
            // via cross-signal count alone.
            for (idx, list) in ranked_lists.iter_mut().enumerate() {
                if idx == 8 {
                    continue;
                }
                for (path, score) in list.iter_mut() {
                    if is_test_path(path) {
                        *score *= locate_env_f32("KIN_LOCATE_BROAD_TEST_PENALTY", 0.1);
                    }
                }
            }
            reciprocal_rank_fusion(&ranked_lists, 60.0)
        }
    };

    if pipeline_report {
        eprintln!("  Scoring track: {:?}", track);
        eprintln!(
            "  (traceback_top={:.1} resolve_top={:.1} resolve_gap={:.2} multihop_top={:.1})",
            traceback_top, resolve_top, resolve_gap, multihop_top
        );
    }

    boost_priority_in_fused(&mut fused, &priority_files);

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
        fused.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    }

    // Non-source + internal path penalty (graph-native: uses entity_bearing_file_paths)
    let source_files: HashSet<String> = graph.entity_bearing_file_paths().into_iter().collect();
    let non_code_ext_penalty = locate_env_f32("KIN_LOCATE_NON_CODE_EXT_PENALTY", 0.005);
    let docs_path_penalty = locate_env_f32("KIN_LOCATE_DOCS_PATH_PENALTY", 0.01);
    let vendor_path_penalty = locate_env_f32("KIN_LOCATE_VENDOR_PATH_PENALTY", 0.01);
    for (path, score) in fused.iter_mut() {
        if path.starts_with(".kin") || path.contains("/.kin/") {
            *score = 0.0;
            continue;
        }
        if !source_files.contains(path.as_str()) {
            *score *= locate_env_f32("KIN_LOCATE_NON_SOURCE_PENALTY", 0.02);
        }
        if is_test_path(path) {
            *score *= locate_env_f32("KIN_LOCATE_POST_TEST_PENALTY", 0.5);
        }
        if is_non_code_ext(path) {
            *score *= non_code_ext_penalty;
        }
        if is_docs_or_locale_path(path) {
            *score *= docs_path_penalty;
        }
        if is_vendor_path(path) {
            *score *= vendor_path_penalty;
        }
    }

    // Re-sort by score after all penalties are applied.
    // Without this, the order from EntityDominant/BroadBlend is preserved even
    // when post-RRF penalties change the relative scores.
    fused.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

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

    // Merge signal labels for each file
    let search_direct_files_count = search_direct_files.len();
    let all_hits: Vec<HashMap<String, Vec<FileHit>>> = vec![
        traceback,
        search_direct_files,
        multihop,
        tests,
        snippets,
        imports,
        errors,
        cochange,
        resolved_hits,
    ];
    let projection_explain = resolve_explain;
    let projection_provenance: HashMap<String, LocateFileProvenance> = HashMap::new();

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
        eprintln!("  Direct file hits: {} files", search_direct_files_count);

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
            ("search_direct", &all_hits[1]),
            ("multihop", &all_hits[2]),
            ("tests", &all_hits[3]),
            ("snippets", &all_hits[4]),
            ("imports", &all_hits[5]),
            ("errors", &all_hits[6]),
            ("cochange", &all_hits[7]),
        ];
        for (name, hits) in &file_signals {
            if !hits.is_empty() {
                let mut top: Vec<_> = hits
                    .iter()
                    .map(|(p, h)| (p.as_str(), h.iter().map(|fh| fh.score).sum::<f32>()))
                    .collect();
                top.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
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
        eprintln!("  Weights: traceback={:.1} search={:.1} multihop={:.1} tests={:.1} snippets={:.1} imports={:.1} errors={:.1} cochange={:.1} resolve={:.1}",
            signal_confidence_weights[0], signal_confidence_weights[1],
            signal_confidence_weights[2], signal_confidence_weights[3],
            signal_confidence_weights[4], signal_confidence_weights[5],
            signal_confidence_weights[6], signal_confidence_weights[7],
            signal_confidence_weights[8]);
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
        ];
        eprintln!("=== LOCATE DEBUG ===");
        eprintln!("Query terms: {:?}", extract_search_terms(text));
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

    // ── Optional LTR reranking ──
    // If a trained model exists and profile allows, use it to rerank the fused results.
    if profile.ltr_enabled() && locate_env_bool("KIN_LOCATE_LTR_ENABLED", true) {
        let model_path = std::env::var("KIN_LOCATE_LTR_MODEL_PATH").unwrap_or_else(|_| {
            let layout =
                kin_core::KinLayout::discover(&std::env::current_dir().unwrap_or_default());
            layout.map_or_else(
                || ".kin/models/ltr_v1.json".to_string(),
                |l| {
                    l.root()
                        .join(".kin/models/ltr_v1.json")
                        .to_string_lossy()
                        .to_string()
                },
            )
        });

        if let Ok(model) =
            kin_ranking::ltr::GradientBoostedRanker::load(std::path::Path::new(&model_path))
        {
            let ltr_window = locate_env_usize("KIN_LOCATE_LTR_WINDOW", 30).min(fused.len());
            let search_terms = extract_search_terms(text);
            let search_terms_count = search_terms.len();
            let query_has_traceback = if text.contains("Traceback") || text.contains("File \"") {
                1.0
            } else {
                0.0
            };
            let query_has_path = if !extract_file_paths(text).is_empty() {
                1.0
            } else {
                0.0
            };
            let is_test_q = is_test_query(text);

            let signal_score_names = [
                "traceback_score",
                "search_score",
                "multihop_score",
                "test_score",
                "snippet_score",
                "import_score",
                "error_score",
                "embedding_score",
                "cochange_score",
                "projection_score",
            ];
            let _ = signal_score_names; // used for documentation, scores accessed by index

            let mut ltr_candidates: Vec<(String, f32, kin_ranking::features::LocateFeatureVector)> =
                Vec::new();

            for (rank, (path, score)) in fused.iter().take(ltr_window).enumerate() {
                let mut fv = kin_ranking::features::LocateFeatureVector::zeros();

                // Fill per-signal scores and presence from all_hits (9 runtime signals)
                // all_hits = [traceback, search, multihop, tests, snippets, imports, errors, cochange, resolved_hits]
                let per_signal_scores: Vec<f32> = (0..9)
                    .map(|idx| {
                        all_hits
                            .get(idx)
                            .and_then(|hits_map| hits_map.get(path))
                            .map_or(0.0, |h| h.iter().map(|fh| fh.score).sum())
                    })
                    .collect();

                fv.traceback_score = per_signal_scores[0];
                fv.search_score = per_signal_scores[1];
                fv.multihop_score = per_signal_scores[2];
                fv.test_score = per_signal_scores[3];
                fv.snippet_score = per_signal_scores[4];
                fv.import_score = per_signal_scores[5];
                fv.error_score = per_signal_scores[6];
                fv.embedding_score = 0.0;
                fv.cochange_score = per_signal_scores[7];
                fv.projection_score = per_signal_scores[8];

                fv.traceback_present = if per_signal_scores[0] > 0.0 { 1.0 } else { 0.0 };
                fv.search_present = if per_signal_scores[1] > 0.0 { 1.0 } else { 0.0 };
                fv.multihop_present = if per_signal_scores[2] > 0.0 { 1.0 } else { 0.0 };
                fv.test_present = if per_signal_scores[3] > 0.0 { 1.0 } else { 0.0 };
                fv.snippet_present = if per_signal_scores[4] > 0.0 { 1.0 } else { 0.0 };
                fv.import_present = if per_signal_scores[5] > 0.0 { 1.0 } else { 0.0 };
                fv.error_present = if per_signal_scores[6] > 0.0 { 1.0 } else { 0.0 };
                fv.embedding_present = 0.0;
                fv.cochange_present = if per_signal_scores[7] > 0.0 { 1.0 } else { 0.0 };
                fv.projection_present = if per_signal_scores[8] > 0.0 { 1.0 } else { 0.0 };

                fv.signal_count = per_signal_scores.iter().filter(|&&s| s > 0.0).count() as f32;
                fv.fused_rrf_score = *score;
                fv.rrf_rank = rank as f32;
                fv.path_depth = path.matches('/').count() as f32;
                let path_role = role_from_path(path);
                fv.is_test = if path_role == EntityRole::Test {
                    1.0
                } else {
                    0.0
                };
                fv.is_source = if path_role == EntityRole::Source {
                    1.0
                } else {
                    0.0
                };
                fv.is_external = if matches!(path_role, EntityRole::External | EntityRole::Vendored)
                {
                    1.0
                } else {
                    0.0
                };
                fv.file_tier = file_tier(path, is_test_q) as f32;
                fv.query_term_count = search_terms_count as f32;
                fv.query_has_traceback = query_has_traceback;
                fv.query_has_path = query_has_path;
                fv.query_length = text.len() as f32;

                ltr_candidates.push((path.clone(), *score, fv));
            }

            model.rerank(&mut ltr_candidates);

            // Replace fused with LTR-reranked results, appending remaining files
            let mut new_fused: Vec<(String, f32)> = ltr_candidates
                .into_iter()
                .map(|(path, score, _)| (path, score))
                .collect();
            for (path, score) in fused.iter().skip(ltr_window) {
                new_fused.push((path.clone(), *score));
            }
            fused = new_fused;
        }
    }

    // Signal-aware demotion: files with zero signal evidence are filler from
    // the EntityDominant supplement path (or tier-scored files that no signal
    // independently confirmed). Push them below signaled files so they only
    // fill slots when no signaled alternatives exist.
    {
        let no_signal_penalty = locate_env_f32("KIN_LOCATE_NO_SIGNAL_PENALTY", 0.001);
        for (path, score) in fused.iter_mut() {
            if *score <= 0.0 {
                continue;
            }
            let in_any_signal = all_hits.iter().any(|signal| signal.contains_key(path));
            if !in_any_signal {
                *score *= no_signal_penalty;
            }
        }
        fused.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    }

    // Adaptive cap
    let results = adaptive_cap(&fused, &all_hits, max_files, max_files_explicit);
    let file_provenance = if explain {
        collect_result_provenance(&results, &projection_provenance)
    } else {
        HashMap::new()
    };

    Ok(build_result(
        &results,
        &all_hits,
        &projection_explain,
        &file_provenance,
        &per_file_signals,
        explain,
    ))
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

// ---------------------------------------------------------------------------
// Priority file extraction
// ---------------------------------------------------------------------------

fn extract_priority_files(text: &str, graph: &kin_db::InMemoryGraph) -> Vec<(String, f32)> {
    let _span =
        tracing::info_span!("locate.extract_priority_files", text_len = text.len()).entered();
    let mut file_scores: HashMap<String, f32> = HashMap::new();
    let tracked_non_entity = tracked_non_entity_files(graph);
    let text_lower = text.to_ascii_lowercase();

    // (a) Explicit file paths from text — highest priority
    for file_path in extract_file_paths(text) {
        if let Some(path) = resolve_path_in_graph(graph, &file_path) {
            let entry = file_scores.entry(path).or_insert(0.0);
            *entry = entry.max(200.0);
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
            let entry = file_scores.entry(with_py).or_insert(0.0);
            *entry = entry.max(100.0);
        } else {
            // Suffix match: scan entities for file paths containing the fragment
            if let Ok(all) = graph.query_entities(&EntityFilter::default()) {
                let mut seen_paths = HashSet::new();
                for entity in all.iter().take(2000) {
                    if let Some(ref fo) = entity.file_origin {
                        if fo.0.contains(&fragment) && seen_paths.insert(fo.0.clone()) {
                            let entry = file_scores.entry(fo.0.clone()).or_insert(0.0);
                            *entry = entry.max(80.0);
                        }
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
                let score = if *is_title { 50.0 } else { 30.0 };
                for path in &unique_files {
                    if !is_test_path(path) {
                        let entry = file_scores.entry(path.clone()).or_insert(0.0);
                        *entry = entry.max(score);
                    }
                }
            }
        }
    }

    for tracked in &tracked_non_entity {
        let basename = tracked.path.rsplit('/').next().unwrap_or(&tracked.path);
        let basename_lower = basename.to_ascii_lowercase();
        let explicitly_named = text_lower.contains(&basename_lower)
            || text_lower.contains(&tracked.path.to_ascii_lowercase());
        // Only inject non-entity files when explicitly named in the query.
        // Descriptor-based fuzzy matching was too loose — a 4-letter word overlap
        // caused build artifacts (ChangeLog, Makefile, etc.) to outscore real source.
        if explicitly_named {
            let entry = file_scores.entry(tracked.path.clone()).or_insert(0.0);
            *entry = entry.max(120.0);
        }
    }

    // Build result: sorted by score desc, filtered to >=20.0, truncated to 12
    // Relaxed threshold (was 50.0) to increase seed diversity for better recall
    // Increased max (was 5) to provide more seeds for multihop expansion
    let mut result: Vec<(String, f32)> = file_scores
        .into_iter()
        .filter(|(_, s)| *s >= 20.0)
        .collect();
    result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    result.truncate(12);
    result
}

fn boost_priority_in_fused(fused: &mut Vec<(String, f32)>, priority: &[(String, f32)]) {
    if priority.is_empty() {
        return;
    }
    let priority_map: HashMap<String, f32> = priority.iter().cloned().collect();
    let rrf_max = fused.first().map(|(_, s)| *s).unwrap_or(1.0);

    // Boost existing entries
    for (path, score) in fused.iter_mut() {
        if let Some(ps) = priority_map.get(path) {
            let boost = 1.0 + (ps / 100.0).min(3.0);
            *score *= boost;
        }
    }

    // Inject priority files not in fused
    let existing: HashSet<String> = fused.iter().map(|(p, _)| p.clone()).collect();
    for (path, ps) in priority {
        if !existing.contains(path) && *ps >= 50.0 {
            let injected = rrf_max * (1.0 + (ps / 100.0).min(2.0));
            fused.push((path.clone(), injected));
        }
    }

    fused.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
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

    // Match dotted module paths like astropy.modeling.core, io.ascii, etc.
    let re_dotted = regex::Regex::new(r"\b([a-zA-Z_]\w*(?:\.\w+){1,})").unwrap();
    for cap in re_dotted.captures_iter(text) {
        let dotted = cap[1].to_string();
        // Convert dots to path separators: astropy.modeling.core -> astropy/modeling/core
        let as_path = dotted.replace('.', "/");
        if seen.insert(as_path.clone()) {
            fragments.push(as_path);
        }
    }

    fragments
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

/// Phase 1 entity-first search: returns entity seeds (scored entities) and
/// direct file hits (explicit paths from tracebacks/mentions in the issue text).
/// Entity seeds are resolved to files in Phase 2 via graph relations.
fn extract_search_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<(
    HashMap<kin_model::EntityId, EntityDiscovery>,
    HashMap<String, Vec<FileHit>>,
)> {
    let _span =
        tracing::info_span!("locate.extract_search_signals", text_len = text.len()).entered();
    let mut entity_seeds: HashMap<kin_model::EntityId, EntityDiscovery> = HashMap::new();
    let mut direct_file_hits: HashMap<String, Vec<FileHit>> = HashMap::new();
    let tracked_non_entity = tracked_non_entity_files(graph);
    // Context-aware test file penalty: if query is test-focused, don't penalize test files
    let _is_test_focused = is_test_query(text);

    // Explicit file paths from text → direct file hits (bypass entity resolution)
    for file_path in extract_file_paths(text) {
        if let Some(path) = resolve_path_in_graph(graph, &file_path) {
            direct_file_hits.entry(path).or_default().push(FileHit {
                score: 10.0,
                spans: vec![],
            });
        }
    }

    // Module path fragment matching → direct file hits
    let module_fragments = extract_module_path_fragments(text);
    for fragment in &module_fragments {
        if let Some(path) = resolve_path_in_graph(graph, fragment) {
            direct_file_hits.entry(path).or_default().push(FileHit {
                score: 8.0,
                spans: vec![],
            });
        }
        for ext in &[".py", ".rs", ".ts", ".js", ".go", ".java"] {
            let with_ext = format!("{}{}", fragment, ext);
            if let Some(path) = resolve_path_in_graph(graph, &with_ext) {
                direct_file_hits.entry(path).or_default().push(FileHit {
                    score: 8.0,
                    spans: vec![],
                });
            }
        }
    }

    let identifiers = curate_search_terms(text, graph)?;
    if identifiers.is_empty() {
        return Ok((entity_seeds, direct_file_hits));
    }

    // BM25F field-level weights: boost matches in high-signal fields
    let bm25f_name_weight = locate_env_f32("KIN_LOCATE_BM25F_NAME_WEIGHT", 5.0);
    let _bm25f_doc_weight = locate_env_f32("KIN_LOCATE_BM25F_DOC_WEIGHT", 2.0);
    let bm25f_body_weight = locate_env_f32("KIN_LOCATE_BM25F_BODY_WEIGHT", 1.0);

    // Determine which terms appear in the issue title (first line) for weighting
    let title_line = text.lines().next().unwrap_or("");
    let title_terms: HashSet<String> = extract_title_terms(title_line)
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect();

    for ident in &identifiers {
        let ident_lower = ident.to_lowercase();

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
                    _ => 1.0,
                };
                {
                    let score = kind_mult * name_mult * field_weight * title_mult;
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
        let mut all_text_hits = Vec::new();
        for variant in &name_variants {
            let hits =
                graph.text_search(variant, locate_env_usize("KIN_LOCATE_TEXT_HIT_LIMIT", 50))?;
            all_text_hits.extend(hits);
        }
        let text_hits = all_text_hits;
        for (rank, (retrieval_key, _score)) in text_hits.into_iter().enumerate() {
            if let Some(entity_id) = entity_id_from_retrieval_key(&retrieval_key) {
                // Entity result → entity seed score
                if let Some(entity) = graph.get_entity(&entity_id)? {
                    let name_match = score_name_match(ident, &entity.name);
                    let field_weight = if name_match >= 2.0 {
                        bm25f_name_weight
                    } else {
                        bm25f_body_weight
                    };
                    let score = field_weight * title_mult / ((rank + 1) as f32).sqrt();
                    {
                        let entry = entity_seeds.entry(entity.id).or_default();
                        entry.score += score;
                        if seen.insert(entity.id) && !entry.signals.contains(&"search") {
                            entry.signals.push("search");
                        }
                    }
                }
            } else {
                // Non-entity result (artifact/shallow file) → direct file hit
                if let Some((path, spans, _)) = retrieval_file_hit(graph, &retrieval_key)? {
                    direct_file_hits.entry(path).or_default().push(FileHit {
                        score: bm25f_body_weight * title_mult / ((rank + 1) as f32).sqrt(),
                        spans,
                    });
                }
            }
        }

        // Tracked non-entity files (configs, etc.) → direct file hits
        for tracked in &tracked_non_entity {
            let descriptor_lower = tracked.descriptor.to_ascii_lowercase();
            if descriptor_lower.contains(&ident_lower) {
                let source_mult = if is_source_path(&tracked.path) {
                    1.2
                } else {
                    1.0
                };
                let docs_mult = if is_docs_path(&tracked.path) {
                    0.2
                } else {
                    1.0
                };
                direct_file_hits
                    .entry(tracked.path.clone())
                    .or_default()
                    .push(FileHit {
                        score: 2.25 * title_mult * source_mult * docs_mult,
                        spans: vec![],
                    });
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

    Ok((entity_seeds, direct_file_hits))
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
    let re_call_suffix = regex::Regex::new(r"\(.*\)$").unwrap();

    let re_backtick = regex::Regex::new(r"`([^`]+)`").unwrap();
    for cap in re_backtick.captures_iter(text) {
        let raw = cap[1].trim();
        if raw.len() > 80
            || raw.contains('\n')
            || matches!(raw.chars().next(), Some('$' | '#' | '-' | '/'))
            || (raw.contains('/')
                && raw
                    .rsplit('/')
                    .next()
                    .is_some_and(|leaf| leaf.contains('.')))
        {
            continue;
        }

        let normalized = re_call_suffix.replace(raw, "").trim().to_string();
        if normalized.is_empty() || normalized.starts_with('.') {
            continue;
        }

        if normalized.contains('.') {
            let parts: Vec<&str> = normalized
                .split('.')
                .filter(|part| !part.is_empty())
                .collect();
            // Add each dot-separated component as an independent search term.
            // For "ascii.qdp" this produces both "ascii" and "qdp" individually,
            // enabling graph lookups that match module path segments.
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

    for term in extract_search_terms(text) {
        let canonical = term.to_ascii_lowercase();
        if seen.insert(canonical) {
            candidates.push((term, false));
        }
    }

    for term in extract_title_terms(text) {
        let canonical = term.to_ascii_lowercase();
        if seen.insert(canonical) {
            candidates.push((term, true));
        }
    }

    let term_limit = locate_env_usize("KIN_LOCATE_CURATED_TERM_LIMIT", 6);

    let mut compound_terms: Vec<(String, f32, bool)> = Vec::new();
    let mut scored_terms: Vec<(String, f32, bool)> = Vec::new();
    for (term, from_title) in candidates {
        // Compound identifiers (snake_case, CamelCase, dotted) are almost always
        // real code identifiers, not English prose.
        let upper_count = term.chars().filter(|c| c.is_uppercase()).count();
        let compound = term.contains('_') || term.contains('.') || upper_count >= 2;

        // Non-compound title terms must match entity names directly, not just
        // docstring text. Words like "instead" or "raising" match BM25 text
        // search on docstrings but aren't real code identifiers.
        let needs_name_match = from_title && !compound;

        if needs_name_match {
            if !term_has_name_support(graph, &term)? {
                continue;
            }
        } else if !term_has_graph_support(graph, &term, from_title)? {
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

        let noise_penalty = if is_common_english_word(&term.to_lowercase()) {
            0.1
        } else {
            1.0
        };

        let score = specificity * title_boost * length_boost * noise_penalty;

        if compound {
            compound_terms.push((term, score, from_title));
        } else {
            scored_terms.push((term, score, from_title));
        }
    }

    // Compound identifiers get guaranteed slots — they're almost certainly
    // real code identifiers (__array_ufunc__, FITSDiff, NdarrayMixin).
    compound_terms.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored_terms.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

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

    if curated.is_empty() {
        let mut fallback = extract_search_terms(text);
        if fallback.is_empty() {
            fallback = extract_title_terms(text);
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
        match entity.role {
            EntityRole::Docs => docs_hits += 1,
            EntityRole::Source => source_hits += 1,
            EntityRole::Test
            | EntityRole::External
            | EntityRole::Vendored
            | EntityRole::Generated => other_hits += 1,
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
        let Some(entity) = entity_from_retrieval_key(graph, &retrieval_key)? else {
            continue;
        };
        let Some(file_origin) = entity.file_origin.as_ref() else {
            continue;
        };
        let path = &file_origin.0;
        if !seen_files.insert(path.clone()) {
            continue;
        }
        match entity.role {
            EntityRole::Docs => docs_hits += 1,
            EntityRole::Source => source_hits += 1,
            EntityRole::Test
            | EntityRole::External
            | EntityRole::Vendored
            | EntityRole::Generated => other_hits += 1,
        }
    }

    if source_hits > 0 {
        return Ok(true);
    }
    let term_lower = term.to_ascii_lowercase();
    if tracked_non_entity_files(graph).into_iter().any(|tracked| {
        tracked.path.to_ascii_lowercase().contains(&term_lower)
            || tracked
                .descriptor
                .to_ascii_lowercase()
                .contains(&term_lower)
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
        e.file_origin.is_some() && e.role == EntityRole::Source
    });
    if has_source {
        return Ok(true);
    }
    // Also accept if any non-docs entity matches
    Ok(matched.iter().any(|e| {
        e.file_origin.is_some() && e.role != EntityRole::Docs
    }))
}

fn expand_search_terms_from_graph(
    graph: &kin_db::InMemoryGraph,
    base_terms: Vec<String>,
) -> Result<Vec<String>> {
    let _span = tracing::info_span!(
        "locate.expand_search_terms_from_graph",
        base_terms = base_terms.len()
    )
    .entered();
    let mut expanded = base_terms.clone();
    let mut seen: HashSet<String> = expanded
        .iter()
        .map(|term| term.to_ascii_lowercase())
        .collect();

    for term in &base_terms {
        for derived in derive_graph_backed_terms(graph, term)? {
            let canonical = derived.to_ascii_lowercase();
            if seen.insert(canonical) {
                expanded.push(derived);
                if expanded.len() >= locate_env_usize("KIN_LOCATE_CURATED_TERM_LIMIT", 8) {
                    return Ok(expanded);
                }
            }
        }
    }

    Ok(expanded)
}

fn derive_graph_backed_terms(graph: &kin_db::InMemoryGraph, seed: &str) -> Result<Vec<String>> {
    let _span = tracing::info_span!("locate.derive_graph_backed_terms", seed = %seed).entered();
    let mut candidates = Vec::new();
    let seed_lower = seed.to_ascii_lowercase();
    let mut seen_entities = HashSet::new();

    let mut consider_entity = |entity: &kin_model::Entity| {
        if entity.file_origin.is_none() {
            return;
        }
        if entity.role != EntityRole::Source {
            return;
        }

        let name = entity.name.trim();
        if name.is_empty() || name.eq_ignore_ascii_case(seed) || is_noise_term(name) {
            return;
        }

        let kind_score = match entity.kind {
            EntityKind::Function | EntityKind::Method => 5,
            EntityKind::Class
            | EntityKind::TraitDef
            | EntityKind::Interface
            | EntityKind::Module => 4,
            EntityKind::EnumDef => 3,
            EntityKind::Constant => 1,
            _ => 2,
        };
        let lexical_bonus = if name.to_ascii_lowercase().contains(&seed_lower) {
            2
        } else {
            0
        };
        candidates.push((kind_score + lexical_bonus, name.to_string()));
    };

    let filter = EntityFilter {
        name_pattern: Some(seed.to_string()),
        ..Default::default()
    };
    for entity in graph
        .query_entities(&filter)?
        .into_iter()
        .take(locate_env_usize("KIN_LOCATE_GRAPH_NAME_MATCH_LIMIT", 16))
    {
        if seen_entities.insert(entity.id) {
            consider_entity(&entity);
        }
    }

    for (retrieval_key, _) in graph.text_search(
        seed,
        locate_env_usize("KIN_LOCATE_GRAPH_EXPANSION_TEXT_LIMIT", 16),
    )? {
        let Some(entity_id) = entity_id_from_retrieval_key(&retrieval_key) else {
            continue;
        };
        if !seen_entities.insert(entity_id) {
            continue;
        }
        let Some(entity) = graph.get_entity(&entity_id)? else {
            continue;
        };
        consider_entity(&entity);
    }

    candidates.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.len().cmp(&b.1.len()))
            .then_with(|| a.1.cmp(&b.1))
    });
    candidates.dedup_by(|a, b| a.1.eq_ignore_ascii_case(&b.1));

    Ok(candidates
        .into_iter()
        .take(locate_env_usize("KIN_LOCATE_GRAPH_EXPANSION_TERMS", 2))
        .map(|(_, name)| name)
        .collect())
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
    )
}

fn is_noise_term(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "x86_64"
            | "amd64"
            | "arm64"
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
    seed_files.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    seed_files.truncate(locate_env_usize("KIN_LOCATE_MULTIHOP_SEED_FILES", 8));

    // Cache entity-count-based hub dampening per file path to avoid repeated queries
    let mut hub_dampening_cache: HashMap<String, f32> = HashMap::new();

    let allowed_kinds = [
        RelationKind::Calls,
        RelationKind::Imports,
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
                        if let Some(ref fo) = neighbor.file_origin {
                            let path = fo.0.clone();
                            let base_mult = match rel.kind {
                                RelationKind::Tests => 2.4,
                                RelationKind::Calls => 2.0,
                                RelationKind::Imports | RelationKind::DependsOn => 1.8,
                                RelationKind::Implements | RelationKind::Extends => 1.5,
                                RelationKind::References => 1.2,
                                _ => 1.0,
                            };
                            // Boost LSP-origin relations — they're type-resolved and more
                            // precise than tree-sitter's name-based matching.
                            let origin_mult = if rel.origin == kin_model::RelationOrigin::Lsp {
                                locate_env_f32("KIN_LOCATE_LSP_ORIGIN_BOOST", 1.5)
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
                            let score = rel_mult * test_mult * hop_decay * hub_dampen;

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

    let mut test_names: Vec<String> = Vec::new();

    for cap in re_test_func.captures_iter(text) {
        test_names.push(cap[1].to_string());
    }
    for cap in re_test_class.captures_iter(text) {
        test_names.push(format!("{}.{}", &cap[1], &cap[2]));
        test_names.push(cap[2].to_string());
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

    Ok(hits)
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
    let re_backtick = regex::Regex::new(r"`([\w]+(?:\.[\w]+){2,})`").unwrap();

    let mut import_targets: Vec<(String, String)> = Vec::new(); // (module_path, symbol)

    for cap in re_from.captures_iter(text) {
        let module = cap[1].to_string();
        let symbol = cap[2].to_string();
        import_targets.push((module, symbol));
    }
    for cap in re_import.captures_iter(text) {
        let module = cap[1].to_string();
        import_targets.push((module.clone(), module));
    }
    for cap in re_backtick.captures_iter(text) {
        let parts: Vec<&str> = cap[1].split('.').collect();
        if parts.len() >= 2 {
            import_targets.push((
                parts[..parts.len() - 1].join("."),
                parts[parts.len() - 1].to_string(),
            ));
        }
    }

    for (module, symbol) in &import_targets {
        // Convert module path to file path: astropy.modeling.core -> astropy/modeling/core.py
        let file_path = module.replace('.', "/") + ".py";

        // Search for the file path in the graph
        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(&file_path)),
            ..Default::default()
        };
        let entities_in_file = graph.query_entities(&filter)?;

        if !entities_in_file.is_empty() {
            hits.entry(file_path.clone()).or_default().push(FileHit {
                score: 5.0,
                spans: vec![],
            });
        }

        // Also search for the symbol
        let text_hits = graph.text_search(symbol, 5)?;
        for (retrieval_key, _) in &text_hits {
            if let Some(entity) = entity_from_retrieval_key(graph, retrieval_key)? {
                if let Some(ref fo) = entity.file_origin {
                    let path = fo.0.clone();
                    // Direct match in expected file
                    let score = if path == file_path { 5.0 } else { 2.0 };
                    hits.entry(path).or_default().push(FileHit {
                        score: score,

                        spans: entity_span_pair(&entity),
                    });
                }
            }
        }

        // Follow downstream impact for direct file matches
        if !entities_in_file.is_empty() {
            for entity in entities_in_file.iter().take(3) {
                if entity.name == *symbol {
                    let impacted = graph.get_downstream_impact(&entity.id, 1)?;
                    for dep in &impacted {
                        if let Some(ref fo) = dep.file_origin {
                            let path = fo.0.clone();
                            if path != file_path {
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
fn extract_embedding_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<kin_model::EntityId, EntityDiscovery>> {
    let _span =
        tracing::info_span!("locate.extract_embedding_signals", text_len = text.len()).entered();
    let mut entity_seeds: HashMap<kin_model::EntityId, EntityDiscovery> = HashMap::new();

    let status = graph.embedding_status();
    if status.indexed == 0 {
        return Ok(entity_seeds);
    }

    let mut queries: Vec<(String, f32)> = Vec::new();
    let mut seen_queries = HashSet::new();

    let title = text.lines().next().unwrap_or("").trim();
    push_semantic_query(&mut queries, &mut seen_queries, title, 1.35);
    push_semantic_query(
        &mut queries,
        &mut seen_queries,
        &text.chars().take(1200).collect::<String>(),
        1.0,
    );

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
        for term in search_terms.iter().take(3) {
            push_semantic_query(&mut queries, &mut seen_queries, term, 0.9);
        }
    }

    for (query, query_weight) in queries {
        let results = match graph.semantic_search(
            &query,
            locate_env_usize("KIN_LOCATE_SEMANTIC_RESULT_LIMIT", 24),
        ) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for (retrieval_key, distance) in &results {
            let Some(entity_id) = entity_id_from_retrieval_key(retrieval_key) else {
                continue;
            };
            let Some(entity) = graph.get_entity(&entity_id)? else {
                continue;
            };

            // Cosine distance → relevance
            let relevance = ((2.0 - distance) / 2.0).max(0.0);

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

            let score = relevance * kind_mult * 10.0 * query_weight;
            let entry = entity_seeds.entry(entity.id).or_default();
            entry.score += score;
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
    seed_files.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
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
) -> Result<(
    Vec<(String, f32)>,
    HashMap<String, Vec<String>>,
    HashMap<String, HashMap<String, f32>>,
)> {
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

    // Detect whether the graph has LSP-enriched relations. If not (e.g., init
    // ran with --no-lsp), the LSP-only filter would block ALL graph traversal
    // since every relation is Parsed origin. Auto-disable it in that case.
    let has_lsp_relations = entity_seeds.keys().take(20).any(|eid| {
        graph
            .get_all_relations_for_entity(eid)
            .unwrap_or_default()
            .iter()
            .any(|r| r.origin == kin_model::RelationOrigin::Lsp)
    });
    let lsp_only_resolve = locate_env_bool("KIN_LOCATE_LSP_ONLY_RESOLVE", true) && has_lsp_relations;

    // Separate score pools: direct attribution vs graph traversal.
    // These are normalized independently then blended so that graph traversal
    // (which inflates hub files via many paths) cannot drown direct attribution
    // (which tells us the entity IS in this specific file).
    let mut direct_scores: HashMap<String, f32> = HashMap::new();
    let mut graph_scores: HashMap<String, f32> = HashMap::new();
    let mut file_explain: HashMap<String, Vec<String>> = HashMap::new();
    let mut file_signal_scores: HashMap<String, HashMap<String, f32>> = HashMap::new();
    let mut file_entity_counts: HashMap<String, usize> = HashMap::new();

    // Sort seeds by score descending, then use greedy gap detection to find the
    // natural cluster boundary between relevant entities and noise.
    let mut seeds: Vec<_> = entity_seeds.iter().collect();
    seeds.sort_by(|a, b| {
        b.1.score
            .partial_cmp(&a.1.score)
            .unwrap_or(std::cmp::Ordering::Equal)
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
            tracing::debug!(
                "Seed gap detection: cut at {} (gap ratio {:.2}), {} → {} seeds",
                cut_at,
                max_gap_ratio,
                seeds.len(),
                cut_at
            );
            seeds.truncate(cut_at);
        }
    }

    let allowed_kinds = [
        RelationKind::Calls,
        RelationKind::Imports,
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

                let def_mult = if has_body { definition_authority } else { 1.0 };
                let score = discovery.score * def_mult;

                *direct_scores.entry(path.clone()).or_default() += score;
                if explain {
                    file_signal_scores
                        .entry(path.clone())
                        .or_default()
                        .entry("entity_resolve".to_string())
                        .and_modify(|s| *s += score)
                        .or_insert(score);

                    let body_tag = if has_body { "definition" } else { "reference" };
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

        // Graph traversal from ALL entities including test entities
        let mut visited = HashSet::from([entity_id]);
        let mut frontier = vec![(entity_id, 0usize)];

        while let Some((current_id, depth)) = frontier.pop() {
            if depth >= max_graph_hops {
                continue;
            }

            let rels = graph.get_all_relations_for_entity(&current_id)?;
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

                let origin_mult = match rel.origin {
                    kin_model::RelationOrigin::Lsp => lsp_boost,
                    kin_model::RelationOrigin::Parsed => parsed_weight,
                    kin_model::RelationOrigin::Inferred => inferred_weight,
                    kin_model::RelationOrigin::Manual => 1.0,
                };

                // Relation kind weighting
                let kind_mult = match rel.kind {
                    RelationKind::Calls => 2.0,
                    RelationKind::References => 1.5,
                    RelationKind::Implements | RelationKind::Extends => 1.8,
                    RelationKind::Imports | RelationKind::DependsOn => 1.2,
                    RelationKind::Contains => 1.0,
                    RelationKind::Tests => 2.0,
                    _ => 0.8,
                };

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

                *graph_scores.entry(path.clone()).or_default() += score;
                *file_entity_counts.entry(path.clone()).or_default() += 1;
                if explain {
                    file_signal_scores
                        .entry(path.clone())
                        .or_default()
                        .entry("graph_resolve".to_string())
                        .and_modify(|s| *s += score)
                        .or_insert(score);

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

    // Hub dampening for graph traversal only: files with many entity
    // contributions from graph BFS are hubs. Dampen by sqrt(entity_count).
    for (path, score) in graph_scores.iter_mut() {
        let entity_count = file_entity_counts.get(path).copied().unwrap_or(1) as f32;
        if entity_count > 2.0 {
            *score /= entity_count.sqrt();
        }
    }

    // Normalize direct and graph scores INDEPENDENTLY, then blend.
    // Direct attribution is the primary authority (entity IS in this file).
    // Graph traversal is supplementary (entity RELATES to things in this file).
    let direct_blend = locate_env_f32("KIN_LOCATE_DIRECT_BLEND", 0.75);
    let graph_blend = locate_env_f32("KIN_LOCATE_GRAPH_BLEND", 0.25);

    let direct_max = direct_scores
        .values()
        .copied()
        .fold(0.0f32, f32::max)
        .max(0.001);
    let graph_max = graph_scores
        .values()
        .copied()
        .fold(0.0f32, f32::max)
        .max(0.001);

    let all_files: HashSet<String> = direct_scores
        .keys()
        .chain(graph_scores.keys())
        .cloned()
        .collect();
    let mut file_scores: HashMap<String, f32> = HashMap::new();
    for path in all_files {
        let direct_norm = direct_scores.get(&path).copied().unwrap_or(0.0) / direct_max;
        let graph_norm = graph_scores.get(&path).copied().unwrap_or(0.0) / graph_max;
        let blended = direct_norm * direct_blend + graph_norm * graph_blend;
        file_scores.insert(path, blended * 100.0);
    }

    let mut result: Vec<(String, f32)> = file_scores.into_iter().collect();
    result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    Ok((result, file_explain, file_signal_scores))
}

// ---------------------------------------------------------------------------
// 9. Reciprocal Rank Fusion (hybrid: RRF + raw score bonus + cross-signal bonus)
// ---------------------------------------------------------------------------

fn reciprocal_rank_fusion(ranked_lists: &[Vec<(String, f32)>], k: f32) -> Vec<(String, f32)> {
    let _span = tracing::info_span!(
        "locate.reciprocal_rank_fusion",
        lists = ranked_lists.len(),
        k = k as f64
    )
    .entered();
    let mut rrf_scores: HashMap<String, f32> = HashMap::new();
    let mut raw_scores: HashMap<String, f32> = HashMap::new();
    let mut signal_counts: HashMap<String, usize> = HashMap::new();

    // Track which graph-derived signal indices each file appears in.
    // Graph-derived signals are: search (idx 1), multihop (idx 2),
    // tests (idx 3), and co-change (idx 8).
    // Embedding (idx 7) and followup (idx 9, when present) are not graph-structural.
    let graph_signal_indices: HashSet<usize> = [1, 2, 3, 8].iter().copied().collect();
    let mut graph_signal_counts: HashMap<String, usize> = HashMap::new();

    for (list_idx, list) in ranked_lists.iter().enumerate() {
        // Compute max score in this list for normalization
        let max_score = list.iter().map(|(_, s)| *s).fold(0.0f32, f32::max).max(1.0);

        let mut files_in_list = HashSet::new();
        for (rank, (file, score)) in list.iter().enumerate() {
            // Skip vendored/third-party files entirely
            if is_vendored_path(file) {
                continue;
            }
            *rrf_scores.entry(file.clone()).or_default() += 1.0 / (k + rank as f32 + 1.0);
            // Accumulate normalized raw scores
            *raw_scores.entry(file.clone()).or_default() += score / max_score;
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

    // Combine: RRF + normalized raw scores + cross-signal bonus + graph tiebreaker
    let mut combined: HashMap<String, f32> = HashMap::new();
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
        combined.insert(
            file.clone(),
            rrf + raw * raw_weight + cross_bonus + graph_bonus,
        );
    }

    let mut result: Vec<_> = combined.into_iter().collect();
    result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    result
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
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked
}

fn adaptive_cap(
    fused: &[(String, f32)],
    _all_hits: &[HashMap<String, Vec<FileHit>>],
    max_files: usize,
    max_files_explicit: bool,
) -> Vec<(String, f32)> {
    let _span = tracing::info_span!(
        "locate.adaptive_cap",
        fused = fused.len(),
        max_files = max_files,
        max_files_explicit = max_files_explicit,
    )
    .entered();
    if fused.is_empty() {
        return vec![];
    }
    if fused.len() <= 1 {
        return fused.to_vec();
    }

    let gap_threshold = locate_env_f32("KIN_LOCATE_CLUSTER_GAP_THRESHOLD", 3.0);
    let floor_pct = locate_env_f32("KIN_LOCATE_CLUSTER_FLOOR_PCT", 0.05);
    let min_cluster = locate_env_usize("KIN_LOCATE_MIN_CLUSTER", 1);
    let max_cluster = locate_env_usize("KIN_LOCATE_MAX_CLUSTER", 30);

    let top_score = fused[0].1;
    let floor = top_score * floor_pct;
    let mut cluster_size = 1usize;

    let scan_limit = fused.len().min(max_cluster);
    for i in 1..scan_limit {
        let score = fused[i].1;
        let prev_score = fused[i - 1].1;
        if score <= 0.0 || score < floor {
            break;
        }
        if prev_score > 0.0 && prev_score / score > gap_threshold {
            break;
        }
        cluster_size += 1;
    }

    let cap = if max_files_explicit {
        // User explicitly passed --max-files N: use it as a hard ceiling.
        cluster_size.max(min_cluster).min(max_files)
    } else {
        // No explicit --max-files: let the cluster grow up to max_cluster.
        // The elbow detection already found the natural boundary; don't
        // artificially shrink it to the default 10.
        cluster_size.max(min_cluster).min(max_cluster)
    };
    let cap = cap.min(fused.len());
    fused.iter().take(cap).cloned().collect()
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
        || (lower.ends_with(".c") || lower.ends_with(".h"))
            && (lower.contains("/cextern/")
                || lower.contains("/vendor/")
                || lower.contains("/extern/"))
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

fn entity_span_pair(entity: &kin_model::Entity) -> Vec<[u32; 2]> {
    entity
        .span
        .as_ref()
        .map(|s| vec![[s.start_line, s.end_line]])
        .unwrap_or_default()
}

fn collect_signals_for_file(file: &str, all_hits: &[HashMap<String, Vec<FileHit>>]) -> Vec<String> {
    let mut signals = Vec::new();
    let signal_names = [
        "traceback",
        "search",
        "multihop",
        "tests",
        "snippets",
        "imports",
        "errors",
        "cochange",
        "entity_resolve",
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
    spans.sort_by_key(|s| s[0]);
    spans
}

fn collect_explain_for_file(
    file: &str,
    projection_explain: &HashMap<String, Vec<String>>,
    all_hits: &[HashMap<String, Vec<FileHit>>],
) -> Vec<String> {
    if let Some(reasons) = projection_explain.get(file) {
        return reasons.clone();
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
    file_provenance: &HashMap<String, LocateFileProvenance>,
    per_file_signals: &HashMap<String, HashMap<String, f32>>,
    explain: bool,
) -> LocateResult {
    let files: Vec<LocateFileEntry> = results
        .iter()
        .map(|(path, score)| LocateFileEntry {
            path: path.clone(),
            score: *score,
            signals: collect_signals_for_file(path, all_hits),
            spans: collect_spans_for_file(path, all_hits),
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
        })
        .collect();

    LocateResult { files }
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
    use kin_model::{
        Entity, EntityId, EntityMetadata, EntityStore, FilePathId, FingerprintAlgorithm, Hash256,
        LanguageId, Relation, RelationId, RelationKind, RelationOrigin, SemanticFingerprint,
        SourceSpan, Visibility,
    };

    fn hit(score: f32) -> Vec<FileHit> {
        vec![FileHit {
            score,
            spans: vec![],
        }]
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

        let capped = adaptive_cap(&fused, &all_hits, 10, false);
        assert_eq!(capped.len(), 1);
        assert_eq!(capped[0].0, "src/main.py");
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

        let capped = adaptive_cap(&fused, &all_hits, 10, false);
        assert!(capped.len() >= 4, "cap was {}", capped.len());
    }

    #[test]
    fn adaptive_cap_respects_explicit_max_as_ceiling() {
        let fused: Vec<(String, f32)> = (0..8)
            .map(|i| (format!("src/f{i}.py"), 10.0 - i as f32 * 0.5))
            .collect();
        let all_hits: Vec<HashMap<String, Vec<FileHit>>> = (0..8).map(|_| HashMap::new()).collect();
        let capped = adaptive_cap(&fused, &all_hits, 3, true);
        assert_eq!(capped.len(), 3);
    }

    #[test]
    fn adaptive_cap_omitted_max_files_allows_larger_cluster() {
        // 15 files in a tight plateau (no gap > 3x between consecutive scores).
        // With max_files_explicit=false (user omitted --max-files), the cluster
        // should grow beyond the default 10 up to max_cluster (30).
        // With max_files_explicit=true and max_files=10, it should cap at 10.
        let fused: Vec<(String, f32)> = (0..15)
            .map(|i| (format!("src/f{i}.py"), 10.0 - i as f32 * 0.3))
            .collect();
        let all_hits: Vec<HashMap<String, Vec<FileHit>>> = (0..9).map(|_| HashMap::new()).collect();

        // Omitted --max-files: cluster grows to natural elbow (all 15, no cliff)
        let capped_adaptive = adaptive_cap(&fused, &all_hits, 10, false);
        assert_eq!(
            capped_adaptive.len(),
            15,
            "omitted --max-files should let cluster grow past 10"
        );

        // Explicit --max-files 10: hard ceiling at 10
        let capped_explicit = adaptive_cap(&fused, &all_hits, 10, true);
        assert_eq!(
            capped_explicit.len(),
            10,
            "explicit --max-files 10 should cap at 10"
        );
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
    fn boost_priority_injects_high_signal_files() {
        let mut fused = vec![("src/a.py".to_string(), 1.0), ("src/b.py".to_string(), 0.9)];
        let priority = vec![("django/core/validators.py".to_string(), 50.0)];

        boost_priority_in_fused(&mut fused, &priority);

        assert_eq!(fused[0].0, "django/core/validators.py");
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
            })
            .unwrap();

        let seeds = HashMap::from([(
            String::from("src/a.py"),
            vec![FileHit {
                score: 6.0,
                spans: vec![[1, 10]],
            }],
        )]);

        let hits = extract_multihop_signals(&[&seeds], &graph, LocateProfile::Standard).unwrap();
        assert!(hits.contains_key("src/b.py"));
        assert!(hits.contains_key("src/c.py"));
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
    fn collect_signals_names_cochange_label() {
        // all_hits has 9 elements matching runtime:
        // [traceback, search, multihop, tests, snippets, imports, errors, cochange, entity_resolve]
        let all_hits = vec![
            HashMap::new(),                                        // 0: traceback
            HashMap::new(),                                        // 1: search
            HashMap::new(),                                        // 2: multihop
            HashMap::new(),                                        // 3: tests
            HashMap::new(),                                        // 4: snippets
            HashMap::new(),                                        // 5: imports
            HashMap::new(),                                        // 6: errors
            HashMap::from([(String::from("src/b.py"), hit(1.0))]), // 7: cochange
            HashMap::new(),                                        // 8: entity_resolve
        ];

        let signals = collect_signals_for_file("src/b.py", &all_hits);
        assert_eq!(signals, vec!["cochange".to_string()]);
    }

    #[test]
    fn collect_signals_names_entity_resolve_label() {
        let all_hits = vec![
            HashMap::new(),                                        // 0: traceback
            HashMap::new(),                                        // 1: search
            HashMap::new(),                                        // 2: multihop
            HashMap::new(),                                        // 3: tests
            HashMap::new(),                                        // 4: snippets
            HashMap::new(),                                        // 5: imports
            HashMap::new(),                                        // 6: errors
            HashMap::new(),                                        // 7: cochange
            HashMap::from([(String::from("src/c.py"), hit(2.0))]), // 8: entity_resolve
        ];

        let signals = collect_signals_for_file("src/c.py", &all_hits);
        assert_eq!(signals, vec!["entity_resolve".to_string()]);
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
}
