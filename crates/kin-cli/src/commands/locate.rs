// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{
    ChangeStore, EntityFilter, EntityKind, EntityRole, EntityStore, GraphNodeId, RelationKind,
    SemanticChangeId,
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
    let require_daemon = locate_env_bool("KIN_LOCATE_REQUIRE_DAEMON", false);

    // Locate participates in the same daemon-first runtime model as other
    // read commands. Unless KIN_NO_DAEMON=1 is set, it may auto-start the
    // repo daemon instead of silently forcing a local snapshot path.
    if let Some(result) = try_locate_via_daemon(
        &layout,
        text,
        explain,
        max_files,
        max_files_explicit,
        reference.clone(),
        require_daemon,
    )
    .await?
    {
        return Ok(result);
    }
    if require_daemon {
        anyhow::bail!("KIN_LOCATE_REQUIRE_DAEMON=1 but no daemon was available for locate");
    }

    // Direct local snapshot — no daemon needed
    let snap = if reference.is_some() {
        crate::backend::open_snapshot_local(&layout)?
    } else {
        crate::backend::open_snapshot_local_for_locate(&layout)?
    };
    let graph = &*snap.graph();
    if let Some(reference) = reference.as_deref() {
        let head = crate::commands::ref_lookup::resolve_ref_importing_git_if_needed_for_locate(
            graph,
            &layout,
            Some(reference),
        )?;
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
            .map_err(|err| anyhow::anyhow!("open blob store: {}", err))?;
        run_with_graph_capture_at_ref(
            graph,
            &blob_store,
            &head,
            text,
            explain,
            max_files,
            max_files_explicit,
        )
    } else {
        run_with_graph_capture(graph, text, explain, max_files, max_files_explicit)
    }
}

async fn try_locate_via_daemon(
    layout: &kin_core::KinLayout,
    text: &str,
    explain: bool,
    max_files: usize,
    max_files_explicit: bool,
    reference: Option<String>,
    require_daemon: bool,
) -> Result<Option<LocateResult>> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let Some(base_url) = daemon_url else {
        return Ok(None);
    };
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    let request = crate::daemon_client::LocateRequest {
        text: text.to_string(),
        explain,
        max_files,
        max_files_explicit,
        reference,
    };
    match client.locate(&request).await {
        Ok(result) => Ok(Some(result)),
        Err(e) => {
            if require_daemon {
                return Err(e.context("daemon locate failed and local fallback is disabled"));
            }
            tracing::debug!(error = %e, "daemon locate failed, falling back to local");
            Ok(None)
        }
    }
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
    let test_query = is_test_query(text);

    // Extract priority files (explicit file paths mentioned in the text)
    let mut priority_files = extract_priority_files(text, graph);

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 1: Discovery — find candidate ENTITIES, not files.
    // Text search + embeddings discover which entities are relevant.
    // File resolution is deferred to Phase 2 (graph-based).
    // ═══════════════════════════════════════════════════════════════════════

    // Phase 1a: Entity-first signals — return entity seeds
    let search_entity_seeds = extract_search_signals(text, graph, test_query)?;
    let embedding_entity_seeds = extract_embedding_signals(text, graph, test_query)?;

    // Phase 1b: File-based signals — these bypass entity resolution
    let traceback = extract_traceback_signals(text, graph)?;
    let tests = extract_test_signals(text, graph)?;
    let snippets = extract_snippet_signals(text, graph)?;
    let source_text = extract_source_text_signals(text, graph)?;
    let imports = extract_import_signals(text, graph)?;
    let errors = extract_error_signals(text, graph)?;
    merge_priority_files_from_hits(&mut priority_files, &source_text);
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
    let multihop_seed_sets = vec![&resolved_hits, &traceback, &tests, &imports, &errors];
    let multihop = extract_multihop_signals(&multihop_seed_sets, graph, profile, test_query)?;

    // Phase 2c: Cochange from all signals
    let cochange_seed_sets = vec![&resolved_hits, &traceback, &tests, &imports, &errors];
    let cochange = extract_cochange_signals(&cochange_seed_sets, graph)?;

    // ═══════════════════════════════════════════════════════════════════════
    // FUSION: Blend Phase 2 resolved files with file-based signals via RRF.
    // ═══════════════════════════════════════════════════════════════════════

    let signal_confidence_weights = [
        locate_env_f32("KIN_LOCATE_WEIGHT_TRACEBACK", 1.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_MULTIHOP", 1.4),
        locate_env_f32("KIN_LOCATE_WEIGHT_TESTS", 1.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_SNIPPETS", 0.8),
        locate_env_f32("KIN_LOCATE_WEIGHT_IMPORTS", 1.2),
        locate_env_f32("KIN_LOCATE_WEIGHT_ERRORS", 1.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_COCHANGE", 1.0),
        locate_env_f32("KIN_LOCATE_WEIGHT_PROJECTION", 5.0),
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
    // 4=imports, 5=errors, 6=cochange, 7=entity_resolve
    let traceback_top = ranked_lists[0].first().map(|(_, s)| *s).unwrap_or(0.0);
    let resolve_top = ranked_lists[7].first().map(|(_, s)| *s).unwrap_or(0.0);
    let resolve_gap = if ranked_lists[7].len() >= 2 {
        let first = ranked_lists[7][0].1;
        let second = ranked_lists[7][1].1;
        if first > 0.001 {
            (first - second) / first
        } else {
            0.0
        }
    } else {
        0.0
    };
    let multihop_top = ranked_lists[1].first().map(|(_, s)| *s).unwrap_or(0.0);

    #[derive(Debug, Clone, Copy)]
    enum ScoringTrack {
        TracebackDominant,
        EntityDominant,
        GraphStructural,
        BroadBlend,
    }

    let resolve_top_is_generic = ranked_lists[7]
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
            weights[7] = 2.0; // entity_resolve second
            for w in weights[1..7].iter_mut() {
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
            let resolve_list = &ranked_lists[7];
            let mut result: Vec<(String, f32)> = Vec::new();
            let resolve_set: HashSet<String> =
                resolve_list.iter().map(|(p, _)| p.clone()).collect();
            let include_tests = test_query;

            // Entity-resolved files first, in resolve order
            for (path, score) in resolve_list {
                if include_tests || !is_test_path(path) {
                    result.push((path.clone(), *score));
                }
            }

            // Supplement with other signaled files that resolution missed. When
            // the query asks about tests, keep test files in play instead of
            // discarding them unconditionally.
            let other_fused = reciprocal_rank_fusion(&ranked_lists[..7].to_vec(), 60.0);
            for (path, score) in other_fused {
                if !resolve_set.contains(&path) && (include_tests || !is_test_path(&path)) {
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
                if idx == 7 {
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
    let cochange_seed_paths = top_cochange_seed_paths(&ranked_lists[6], &seed_file_support);
    boost_top_cochange_seed_support(
        &mut fused,
        &ranked_lists[6],
        &seed_file_support,
        &cochange_seed_paths,
    );

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

    let companion_signal_sets = [
        &traceback,
        &multihop,
        &tests,
        &snippets,
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

    // Non-source + internal path penalty (graph-native: uses entity_bearing_file_paths)
    let source_files = source_file_paths(graph);
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
        .collect();
    for (path, score) in fused.iter_mut() {
        *score *= post_rrf_path_penalty(
            path,
            source_files.contains(path.as_str()),
            tracked_artifact_paths.contains(path),
            test_query,
        );
    }

    // Re-sort by score after all penalties are applied.
    fused.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });

    // Signal-aware compression: when the top file has strong entity_resolve
    // evidence and subsequent files have NONE (pure multihop/test noise),
    // insert a score gap so adaptive_cap naturally cuts them off.
    // This improves precision on clear single-entity wins without affecting
    // multi-file tasks where multiple files have entity_resolve signal.
    {
        let resolve_set: HashSet<&str> = resolved_hits.keys().map(|s| s.as_str()).collect();
        let priority_set: HashSet<&str> = priority_files
            .iter()
            .map(|(path, _)| path.as_str())
            .collect();
        let compress_factor = locate_env_f32("KIN_LOCATE_NOISE_TAIL_COMPRESS", 0.4);
        // Only compress if #1 has entity_resolve evidence
        if fused
            .first()
            .map(|(p, _)| resolve_set.contains(p.as_str()))
            .unwrap_or(false)
        {
            let mut past_resolve_boundary = false;
            for (path, score) in fused.iter_mut().skip(1) {
                let has_resolve = resolve_set.contains(path.as_str());
                if !past_resolve_boundary && !has_resolve {
                    // First file without entity_resolve — mark the boundary
                    past_resolve_boundary = true;
                }
                if past_resolve_boundary && !has_resolve {
                    if (test_query && is_test_path(path)) || priority_set.contains(path.as_str()) {
                        continue;
                    }
                    // Files beyond the resolve boundary with no entity_resolve
                    // signal are likely noise from multihop/test expansion.
                    *score *= compress_factor;
                }
            }
            // Re-sort after compression
            fused.sort_by(|a, b| {
                b.1.partial_cmp(&a.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.0.cmp(&b.0))
            });
        }
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

    let all_hits: Vec<HashMap<String, Vec<FileHit>>> = vec![
        traceback,
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
        eprintln!(
            "  Weights: traceback={:.1} multihop={:.1} tests={:.1} snippets={:.1} imports={:.1} errors={:.1} cochange={:.1} resolve={:.1}",
            signal_confidence_weights[0],
            signal_confidence_weights[1],
            signal_confidence_weights[2],
            signal_confidence_weights[3],
            signal_confidence_weights[4],
            signal_confidence_weights[5],
            signal_confidence_weights[6],
            signal_confidence_weights[7]
        );
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
    demote_zero_signal_files(&mut fused, &all_hits, &priority_files);

    // Adaptive cap
    let results = adaptive_cap(
        &fused,
        &all_hits,
        max_files,
        max_files_explicit,
        &cochange_seed_paths,
    );
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

pub fn run_with_graph_capture_at_ref(
    graph: &kin_db::InMemoryGraph,
    blob_store: &kin_blobs::BlobStore,
    head: &SemanticChangeId,
    text: &str,
    explain: bool,
    max_files: usize,
    max_files_explicit: bool,
) -> Result<LocateResult> {
    let changes = kin_core::collect_changes_at_ref(graph, head)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let historical = kin_core::build_graph_at_ref(graph, blob_store, head)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let _ = crate::commands::cochange::refresh_from_changes(&historical, &changes);
    run_with_graph_capture(&historical, text, explain, max_files, max_files_explicit)
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

fn merge_priority_files_from_hits(
    priority_files: &mut Vec<(String, f32)>,
    hits: &HashMap<String, Vec<FileHit>>,
) {
    let mut merged: HashMap<String, f32> = priority_files
        .iter()
        .map(|(path, score)| (path.clone(), *score))
        .collect();
    for (path, file_hits) in hits {
        let score = file_hits
            .iter()
            .map(|hit| hit.score)
            .sum::<f32>()
            .min(140.0);
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

// ---------------------------------------------------------------------------
// Priority file extraction
// ---------------------------------------------------------------------------

fn extract_priority_files(text: &str, graph: &kin_db::InMemoryGraph) -> Vec<(String, f32)> {
    let _span =
        tracing::info_span!("locate.extract_priority_files", text_len = text.len()).entered();
    let mut file_scores: HashMap<String, f32> = HashMap::new();
    let tracked_non_entity = tracked_non_entity_files(graph);
    let tracked_non_entity_paths: HashSet<String> = tracked_non_entity
        .iter()
        .map(|tracked| tracked.path.clone())
        .collect();
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

        for (path, score) in matches.into_iter().take(4) {
            let entry = file_scores.entry(path).or_insert(0.0);
            *entry = entry.max(score);
        }
    }

    let tracked_text_hit_limit = locate_env_usize("KIN_LOCATE_TRACKED_TEXT_HIT_LIMIT", 64);
    let tracked_text_broad_limit = locate_env_usize("KIN_LOCATE_TRACKED_TEXT_BROAD_LIMIT", 10);
    let tracked_text_min_terms = locate_env_usize("KIN_LOCATE_TRACKED_TEXT_MIN_TERMS", 1);
    let mut tracked_text_candidates = extract_loose_query_terms(text);
    let mut seen_tracked_text_terms = HashSet::new();
    tracked_text_candidates
        .retain(|term| seen_tracked_text_terms.insert(term.to_ascii_lowercase()));
    let mut tracked_text_scores: HashMap<String, f32> = HashMap::new();
    let mut tracked_text_terms: HashMap<String, HashSet<String>> = HashMap::new();

    for term in tracked_text_candidates.iter().take(tracked_term_limit) {
        let term_lower = term.to_ascii_lowercase();
        if term_lower.len() < 4 || is_common_english_word(&term_lower) {
            continue;
        }

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
                .entry(path)
                .or_default()
                .insert(term_lower.clone());
        }
    }

    for (path, score) in tracked_text_scores {
        let term_count = tracked_text_terms.get(&path).map_or(0, HashSet::len);
        if term_count < tracked_text_min_terms {
            continue;
        }
        let entry = file_scores.entry(path).or_insert(0.0);
        *entry = entry.max(score.min(120.0));
    }

    // Build result: sorted by score desc, filtered to >=20.0, truncated to 12
    // Relaxed threshold (was 50.0) to increase seed diversity for better recall
    // Increased max (was 5) to provide more seeds for multihop expansion
    let mut result: Vec<(String, f32)> = file_scores
        .into_iter()
        .filter(|(_, s)| *s >= 20.0)
        .collect();
    result.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
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
            let injected = if *ps >= 50.0 {
                rrf_max * (1.0 + (ps / 100.0).min(2.0))
            } else {
                0.0
            };
            *score = (*score * boost).max(injected);
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

    fused.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
}

fn query_backed_tracked_file_score(path: &str, term_lower: &str) -> Option<f32> {
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
                if let Some(entity_id) = entity_id_from_retrieval_key(&retrieval_key) {
                    // Entity result → entity seed score
                    if let Some(entity) = graph.get_entity(&entity_id)? {
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
                        let score =
                            field_weight * title_mult * role_mult / ((rank + 1) as f32).sqrt();
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
        if seen.insert(canonical) {
            terms.push(term);
        }
    }
    terms
}

fn is_symbolic_search_term(term: &str) -> bool {
    term.contains('_')
        || term.contains('-')
        || term.contains('.')
        || term.chars().filter(|ch| ch.is_ascii_uppercase()).count() >= 2
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
    let has_source = matched
        .iter()
        .any(|e| e.file_origin.is_some() && e.role == EntityRole::Source);
    if has_source {
        return Ok(true);
    }
    // Also accept if any non-docs entity matches
    Ok(matched
        .iter()
        .any(|e| e.file_origin.is_some() && e.role != EntityRole::Docs))
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
) -> Result<HashMap<String, Vec<FileHit>>> {
    let _span =
        tracing::info_span!("locate.extract_source_text_signals", text_len = text.len()).entered();
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();
    let source_paths = source_file_paths(graph);
    if source_paths.is_empty() {
        return Ok(hits);
    }

    let term_limit = locate_env_usize("KIN_LOCATE_SOURCE_TEXT_TERM_LIMIT", 12);
    let hit_limit = locate_env_usize("KIN_LOCATE_SOURCE_TEXT_HIT_LIMIT", 64);
    let broad_limit = locate_env_usize("KIN_LOCATE_SOURCE_TEXT_BROAD_LIMIT", 4);
    let body_text = text.lines().skip(1).collect::<Vec<_>>().join("\n");
    let full_source_texts: HashMap<String, String> = graph
        .list_opaque_artifacts()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|artifact| {
            let path = artifact.file_id.0;
            if !source_paths.contains(&path) || is_test_path(&path) {
                return None;
            }
            let preview = artifact.text_preview?;
            if preview.len() <= 1024 {
                return None;
            }
            Some((path, preview.to_ascii_lowercase()))
        })
        .collect();

    let mut terms = extract_search_terms(text);
    terms.extend(extract_loose_query_terms(&body_text));

    let mut seen = HashSet::new();
    terms.retain(|term| seen.insert(term.to_ascii_lowercase()));
    terms.retain(|term| {
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
        let symbolic = is_symbolic_search_term(&term);
        let base_score = if symbolic { 120.0 } else { 72.0 };
        let max_hits = if symbolic { 6 } else { 3 };
        let mut per_path: HashMap<String, f32> = HashMap::new();

        for (rank, (retrieval_key, _score)) in
            graph.text_search(&term, hit_limit)?.into_iter().enumerate()
        {
            let kin_db::RetrievalKey::Artifact(_) = retrieval_key else {
                continue;
            };
            let Some(path) = file_path_from_retrieval_key(graph, &retrieval_key) else {
                continue;
            };
            if !source_paths.contains(&path) || is_test_path(&path) {
                continue;
            }
            if symbolic
                && full_source_texts
                    .get(&path)
                    .is_some_and(|source_text| !source_text.contains(&term.to_ascii_lowercase()))
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
        for (path, score) in ranked_paths.into_iter().take(max_hits) {
            hits.entry(path).or_default().push(FileHit {
                score,
                spans: vec![],
            });
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
fn extract_embedding_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
    test_query: bool,
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

            let role_mult = if !test_query && entity.role == EntityRole::Test {
                0.1
            } else {
                1.0
            };
            let score = relevance * kind_mult * 10.0 * query_weight * role_mult;
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
    let lsp_only_resolve =
        locate_env_bool("KIN_LOCATE_LSP_ONLY_RESOLVE", false) && has_lsp_relations;

    // Separate score pools: direct attribution vs graph traversal.
    // These are normalized independently then blended so that graph traversal
    // (which inflates hub files via many paths) cannot drown direct attribution
    // (which tells us the entity IS in this specific file).
    let mut direct_scores: HashMap<String, f32> = HashMap::new();
    let mut graph_scores: HashMap<String, f32> = HashMap::new();
    let mut file_explain: HashMap<String, Vec<String>> = HashMap::new();
    let mut file_signal_scores: HashMap<String, HashMap<String, f32>> = HashMap::new();
    let mut file_entity_counts: HashMap<String, usize> = HashMap::new();
    let mut direct_entity_counts: HashMap<String, usize> = HashMap::new();

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
                *direct_entity_counts.entry(path.clone()).or_default() += 1;
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

    for (path, score) in direct_scores.iter_mut() {
        let entity_count = direct_entity_counts.get(path).copied().unwrap_or(1) as f32;
        if entity_count > 1.0 {
            *score *=
                1.0 + entity_count.ln_1p() * locate_env_f32("KIN_LOCATE_DIRECT_MULTI_BONUS", 0.35);
        }
    }

    // Normalize direct and graph scores INDEPENDENTLY, then blend.
    // Direct attribution is the primary authority (entity IS in this file).
    // Graph traversal is supplementary (entity RELATES to things in this file).
    let direct_blend = locate_env_f32("KIN_LOCATE_DIRECT_BLEND", 0.90);
    let graph_blend = locate_env_f32("KIN_LOCATE_GRAPH_BLEND", 0.10);

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
    result.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });

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
    for (&entity_id, discovery) in entity_seeds {
        let Some(entity) = graph.get_entity(&entity_id)? else {
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

    let gap_threshold = locate_env_f32("KIN_LOCATE_CLUSTER_GAP_THRESHOLD", 1.5);
    let floor_pct = locate_env_f32("KIN_LOCATE_CLUSTER_FLOOR_PCT", 0.05);
    let min_cluster = locate_env_usize("KIN_LOCATE_MIN_CLUSTER", 1);
    let max_cluster = locate_env_usize("KIN_LOCATE_MAX_CLUSTER", 10);

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

    let support_floor_pct = locate_env_f32("KIN_LOCATE_MULTI_SIGNAL_FLOOR_PCT", 0.2);
    let retention_floor_pct = locate_env_f32(
        "KIN_LOCATE_RETENTION_FLOOR_PCT",
        support_floor_pct.min(0.15),
    );
    let default_support_floor_max = locate_env_usize("KIN_LOCATE_MULTI_SIGNAL_FLOOR_MAX", 3);
    let support_floor_limit = if max_files_explicit {
        scan_limit.min(max_files.max(1))
    } else {
        default_support_floor_max
    };
    let support_floor_min = min_cluster.min(support_floor_limit.max(1));
    let support_floor_max = support_floor_limit.max(support_floor_min);
    let support_floor = fused
        .iter()
        .take(scan_limit)
        .filter(|(path, score)| {
            let floor_pct = if cochange_seed_paths.contains(path) {
                retention_floor_pct
            } else {
                support_floor_pct
            };
            if *score < top_score * floor_pct {
                return false;
            }
            let has_entity_resolve = all_hits
                .get(7)
                .is_some_and(|er| er.contains_key(path.as_str()));
            has_entity_resolve
                || signal_support_count(path, all_hits) >= 3
                || cochange_seed_paths.contains(path.as_str())
        })
        .count()
        .clamp(support_floor_min, support_floor_max);

    let cap = if max_files_explicit {
        // User explicitly passed --max-files N: use it as a hard ceiling.
        cluster_size.max(support_floor).min(max_files)
    } else {
        // No explicit --max-files: let the cluster grow up to max_cluster.
        // The elbow detection already found the natural boundary; don't
        // artificially shrink it to the default 10.
        cluster_size.max(support_floor).min(max_cluster)
    };
    let cap = cap.min(fused.len());
    fused.iter().take(cap).cloned().collect()
}

fn demote_zero_signal_files(
    fused: &mut Vec<(String, f32)>,
    all_hits: &[HashMap<String, Vec<FileHit>>],
    priority_files: &[(String, f32)],
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
        if !in_any_signal && !priority_set.contains(path.as_str()) {
            *score *= no_signal_penalty;
        }
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

fn post_rrf_path_penalty(
    path: &str,
    is_entity_bearing: bool,
    is_tracked_artifact: bool,
    test_query: bool,
) -> f32 {
    if path.starts_with(".kin") || path.contains("/.kin/") {
        return 0.0;
    }

    let mut penalty = 1.0;
    if !is_entity_bearing {
        penalty *= if is_tracked_artifact {
            locate_env_f32("KIN_LOCATE_TRACKED_ARTIFACT_PENALTY", 0.4)
        } else {
            locate_env_f32("KIN_LOCATE_NON_SOURCE_PENALTY", 0.02)
        };
    }
    if is_test_path(path) {
        penalty *= if test_query {
            locate_env_f32("KIN_LOCATE_POST_TEST_QUERY_PENALTY", 1.0)
        } else {
            locate_env_f32("KIN_LOCATE_POST_TEST_PENALTY", 0.5)
        };
    }
    if is_non_code_ext(path) {
        penalty *= if is_tracked_artifact {
            locate_env_f32("KIN_LOCATE_TRACKED_ARTIFACT_NON_CODE_PENALTY", 0.9)
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

    penalty
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
        ArtifactDelta, ArtifactDeltaKind, AuthorId, ChangeStore, Entity, EntityDelta, EntityId,
        EntityMetadata, EntityStore, FilePathId, FingerprintAlgorithm, Hash256, LanguageId,
        OpaqueArtifact, Relation, RelationId, RelationKind, RelationOrigin, SemanticChange,
        SemanticChangeId, SemanticFingerprint, SourceSpan, Timestamp, Visibility,
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

        let capped = adaptive_cap(&fused, &all_hits, 10, false, &HashSet::new());
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

        let capped = adaptive_cap(&fused, &all_hits, 10, false, &HashSet::new());
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

        let capped = adaptive_cap(&fused, &all_hits, 10, false, &HashSet::new());
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

        let capped = adaptive_cap(&fused, &all_hits, 10, false, &retention);

        assert!(capped.iter().any(|(path, _)| path == "src/builtin.c"));
    }

    #[test]
    fn adaptive_cap_respects_explicit_max_as_ceiling() {
        let fused: Vec<(String, f32)> = (0..8)
            .map(|i| (format!("src/f{i}.py"), 10.0 - i as f32 * 0.5))
            .collect();
        let all_hits: Vec<HashMap<String, Vec<FileHit>>> = (0..8).map(|_| HashMap::new()).collect();
        let capped = adaptive_cap(&fused, &all_hits, 3, true, &HashSet::new());
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

        let capped = adaptive_cap(&fused, &all_hits, 10, true, &HashSet::new());

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

        let capped_adaptive = adaptive_cap(&fused, &all_hits, 10, false, &HashSet::new());
        assert!(
            capped_adaptive.len() <= 10,
            "omitted --max-files should still respect max_cluster (10)"
        );

        let capped_explicit = adaptive_cap(&fused, &all_hits, 10, true, &HashSet::new());
        assert_eq!(
            capped_explicit.len(),
            10,
            "explicit --max-files 10 should cap at 10"
        );
    }

    #[test]
    fn tracked_artifact_penalty_is_much_softer_than_generic_non_source_penalty() {
        let tracked = post_rrf_path_penalty("package.json", false, true, false);
        let generic = post_rrf_path_penalty("package.json", false, false, false);

        assert!(tracked > generic);
        assert!(tracked > 0.1, "tracked artifacts should remain rankable");
        assert!(
            generic < 0.01,
            "generic non-source json should stay heavily penalized"
        );
    }

    #[test]
    fn entity_bearing_source_file_avoids_artifact_penalties() {
        let source_penalty = post_rrf_path_penalty("src/lib.rs", true, false, false);
        assert_eq!(source_penalty, 1.0);
    }

    #[test]
    fn test_queries_do_not_post_penalize_test_paths() {
        let penalty = post_rrf_path_penalty("tests/test_models.py", true, false, true);
        assert_eq!(penalty, 1.0);
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

        demote_zero_signal_files(&mut fused, &all_hits, &priority);

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

        let hits =
            extract_multihop_signals(&[&seeds], &graph, LocateProfile::Standard, false).unwrap();
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
    fn historical_locate_rehydrates_cochange_relations_from_reachable_changes() {
        let graph = kin_db::InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(temp.path().join("objects")).unwrap();

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
    fn command_style_fragment_detection_requires_short_cli_paths() {
        assert!(is_command_style_fragment("auth/login"));
        assert!(is_command_style_fragment("repo/create/http"));
        assert!(!is_command_style_fragment("pkg/core/module"));
        assert!(!is_command_style_fragment("pkg.core.module"));
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
            })
            .unwrap();
        graph.flush_text_index().unwrap();

        let hits =
            extract_test_signals("Add tests for `instrument` with impl Trait", &graph).unwrap();

        assert!(hits.contains_key("tests/err.rs"));
        assert!(hits.contains_key("src/lib.rs"));
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
        )
        .unwrap();

        assert!(hits.contains_key("src/builtin.c"));
        assert!(hits.contains_key("src/main.c"));
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
    fn query_backed_tracked_file_score_ignores_directory_only_matches_for_non_manifests() {
        assert_eq!(
            query_backed_tracked_file_score("tracing-attributes/LICENSE", "attributes"),
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
        ];

        let signals = collect_signals_for_file("src/c.py", &all_hits);
        assert_eq!(signals, vec!["entity_resolve".to_string()]);
    }

    #[test]
    fn locate_at_ref_uses_historical_entity_and_artifact_state() {
        let graph = kin_db::InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(temp.path().join("objects")).unwrap();

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

        let historical = run_with_graph_capture_at_ref(
            &graph,
            &blob_store,
            &add_id,
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
            &graph,
            &blob_store,
            &modify_id,
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
}
