// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{ChangeStore, EntityFilter, EntityKind, EntityRole, EntityStore, GraphNodeId, RelationKind};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

use crate::capability::LocateProfile;

// ---------------------------------------------------------------------------
// JSON output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct LocateResult {
    files: Vec<LocateFileEntry>,
}

#[derive(Serialize)]
struct LocateFileEntry {
    path: String,
    score: f32,
    signals: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    spans: Vec<[u32; 2]>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    explain: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance: Option<LocateFileProvenance>,
}

#[derive(Serialize, Clone)]
struct LocateFileProvenance {
    objects: Vec<LocateGraphObject>,
    edges: Vec<LocateGraphEdge>,
}

#[derive(Serialize, Clone)]
struct LocateGraphObject {
    id: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
}

#[derive(Serialize, Clone)]
struct LocateGraphEdge {
    src: String,
    dst: String,
    kind: String,
}

// ---------------------------------------------------------------------------
// Scored file hit with signal provenance
// ---------------------------------------------------------------------------

struct FileHit {
    score: f32,
    spans: Vec<[u32; 2]>,
}

#[derive(Clone)]
struct TrackedFileInfo {
    path: String,
    descriptor: String,
}

#[derive(Clone, Copy, Default)]
struct SeedSignal {
    score: f32,
    lexical: bool,
    semantic: bool,
}

#[derive(Clone, Copy)]
struct ProjectionTrace {
    hops: u32,
    origin_seed: kin_model::EntityId,
    primary_kind: Option<RelationKind>,
    parent: Option<kin_model::EntityId>,
    edge_kind: Option<RelationKind>,
    edge_src: Option<kin_model::EntityId>,
    edge_dst: Option<kin_model::EntityId>,
}

#[derive(Clone, Copy)]
struct ProjectionAdjacency {
    neighbor: kin_model::EntityId,
    kind: RelationKind,
    relation_src: kin_model::EntityId,
    relation_dst: kin_model::EntityId,
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

pub async fn run(text: &str, json: bool, explain: bool, max_files: usize) -> Result<()> {
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

    let snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*snap.graph();
    run_with_graph(graph, text, json, explain, max_files)
}

fn run_with_graph(
    graph: &kin_db::InMemoryGraph,
    text: &str,
    json: bool,
    explain: bool,
    max_files: usize,
) -> Result<()> {
    let _span = tracing::info_span!(
        "kin.locate.run_with_graph",
        text_len = text.len(),
        json = json,
        explain = explain,
        max_files = max_files
    )
    .entered();
    // Strip HTML comments from issue text
    let text = &clean_issue_text(text);

    // Detect machine capability profile for adaptive behavior
    let profile = LocateProfile::detect();

    // Extract priority files (explicit file paths mentioned in the text)
    let priority_files = extract_priority_files(text, graph);

    // Run all signal extractors
    let traceback = extract_traceback_signals(text, graph)?;
    let search = extract_search_signals(text, graph)?;
    let tests = extract_test_signals(text, graph)?;
    let snippets = extract_snippet_signals(text, graph)?;
    let imports = extract_import_signals(text, graph)?;
    let errors = extract_error_signals(text, graph)?;
    let multihop =
        extract_multihop_signals(&[&traceback, &search, &tests, &imports, &errors], graph, profile)?;
    let embeddings = extract_embedding_signals(text, graph)?;
    let cochange =
        extract_cochange_signals(&[&traceback, &search, &tests, &imports, &errors], graph)?;
    let (projection, projection_explain, projection_provenance) =
        extract_projection_signals(text, graph)?;

    // Collect the first-pass signals before the iterative graph follow-up.
    // Apply signal-specific confidence boosting: search and multihop signals
    // are more precise (high confidence), so amplify them relative to others
    let signal_confidence_weights = [
        locate_env_f32("KIN_LOCATE_WEIGHT_TRACEBACK", 1.0),    // traceback: moderate confidence
        locate_env_f32("KIN_LOCATE_WEIGHT_SEARCH", 1.4),       // search: high confidence
        locate_env_f32("KIN_LOCATE_WEIGHT_MULTIHOP", 1.4),     // multihop: high confidence
        locate_env_f32("KIN_LOCATE_WEIGHT_TESTS", 1.0),        // tests: low-moderate confidence
        locate_env_f32("KIN_LOCATE_WEIGHT_SNIPPETS", 0.8),     // snippets: low confidence
        locate_env_f32("KIN_LOCATE_WEIGHT_IMPORTS", 1.2),      // imports: high confidence
        locate_env_f32("KIN_LOCATE_WEIGHT_ERRORS", 1.0),       // errors: low confidence
        locate_env_f32("KIN_LOCATE_WEIGHT_EMBEDDINGS", 0.7),   // embeddings: low confidence
        locate_env_f32("KIN_LOCATE_WEIGHT_COCHANGE", 1.0),     // cochange: moderate confidence
        locate_env_f32("KIN_LOCATE_WEIGHT_PROJECTION", 1.1),   // projection: moderate-high confidence
    ];

    let mut ranked_lists: Vec<Vec<(String, f32)>> = vec![
        to_ranked(&traceback),
        to_ranked(&search),
        to_ranked(&multihop),
        to_ranked(&tests),
        to_ranked(&snippets),
        to_ranked(&imports),
        to_ranked(&errors),
        to_ranked(&embeddings),
        to_ranked(&cochange),
        to_ranked(&projection),
    ];

    // Apply confidence weights: boost high-precision signals
    for (list, weight) in ranked_lists.iter_mut().zip(signal_confidence_weights.iter()) {
        if *weight != 1.0 {
            for (_, score) in list.iter_mut() {
                *score *= weight;
            }
        }
    }

    // Reciprocal rank fusion with hybrid scoring
    let mut fused = reciprocal_rank_fusion(&ranked_lists, locate_env_f32("KIN_LOCATE_RRF_K", 60.0));

    // Boost priority files (explicitly mentioned paths)
    boost_priority_in_fused(&mut fused, &priority_files);

    // ── Pseudo-Relevance Feedback (PRF) ──
    // Take top-K files from fused results, extract entity names as expansion terms,
    // re-run search with those terms, and merge back at reduced weight.
    let prf_enabled = locate_env_bool("KIN_LOCATE_PRF_ENABLED", profile.prf_enabled());
    if prf_enabled && !fused.is_empty() {
        let prf_top_k = locate_env_usize("KIN_LOCATE_PRF_TOP_K", 3);
        let prf_max_terms = locate_env_usize("KIN_LOCATE_PRF_MAX_TERMS", 10);
        let prf_weight = locate_env_f32("KIN_LOCATE_PRF_WEIGHT", 0.5);

        // Collect expansion terms from entities in top-K files
        let mut expansion_terms: Vec<String> = Vec::new();
        let mut seen_terms: HashSet<String> = HashSet::new();
        for (path, _score) in fused.iter().take(prf_top_k) {
            let filter = EntityFilter {
                file_path: Some(kin_model::FilePathId::new(path.as_str())),
                ..Default::default()
            };
            if let Ok(entities) = graph.query_entities(&filter) {
                for entity in &entities {
                    if expansion_terms.len() >= prf_max_terms {
                        break;
                    }
                    let name = entity.name.clone();
                    if name.len() >= 3 && seen_terms.insert(name.to_lowercase()) {
                        expansion_terms.push(name);
                    }
                }
            }
        }

        if !expansion_terms.is_empty() {
            // Re-run search with expansion terms
            let mut prf_hits: HashMap<String, Vec<FileHit>> = HashMap::new();
            for term in &expansion_terms {
                let term_lower = term.to_lowercase();
                let text_hits = graph.text_search(
                    term,
                    locate_env_usize("KIN_LOCATE_TEXT_HIT_LIMIT", 50),
                )?;
                for (rank, (retrieval_key, _score)) in text_hits.into_iter().enumerate() {
                    if let Some((path, spans, entity)) =
                        retrieval_file_hit(graph, &retrieval_key)?
                    {
                        let name_lower = entity
                            .as_ref()
                            .map(|e| e.name.to_lowercase())
                            .unwrap_or_default();
                        let base_score = if !name_lower.is_empty()
                            && name_lower.contains(&term_lower)
                        {
                            2.0
                        } else {
                            1.0
                        };
                        let test_mult = test_mult_by_role(&path, entity.as_ref(), 0.1);
                        prf_hits.entry(path).or_default().push(FileHit {
                            score: base_score * prf_weight * test_mult
                                / ((rank + 1) as f32).sqrt(),
                            spans,
                        });
                    }
                }
            }

            if !prf_hits.is_empty() {
                // Merge PRF results into fused list via weighted RRF
                let mut prf_ranked_lists = ranked_lists.clone();
                prf_ranked_lists.push(to_ranked(&prf_hits));
                fused = reciprocal_rank_fusion(
                    &prf_ranked_lists,
                    locate_env_f32("KIN_LOCATE_RRF_K", 60.0),
                );
                boost_priority_in_fused(&mut fused, &priority_files);
            }
        }
    }

    // Iterative follow-up: expand the current best file guesses through the graph
    // once more so multi-file tasks are not bottlenecked by the first-pass seeds.
    let followup_seed_hits = build_followup_seed_hits(&fused);
    let followup = if locate_env_bool("KIN_LOCATE_FOLLOWUP_ENABLED", true) {
        extract_multihop_signals(&[&followup_seed_hits], graph, profile)?
    } else {
        HashMap::new()
    };
    if !followup.is_empty() {
        let mut expanded_ranked_lists = ranked_lists.clone();
        expanded_ranked_lists.push(to_ranked(&followup));
        fused = reciprocal_rank_fusion(
            &expanded_ranked_lists,
            locate_env_f32("KIN_LOCATE_RRF_K", 60.0),
        );
        boost_priority_in_fused(&mut fused, &priority_files);
    }

    // Import centrality reranking: for top candidate files, add a small bonus
    // proportional to how many other candidate files import entities from them.
    // This is a post-RRF graph-native reranker, not a separate signal.
    let all_signal_sets: Vec<&HashMap<String, Vec<FileHit>>> = vec![
        &traceback,
        &search,
        &multihop,
        &tests,
        &snippets,
        &imports,
        &errors,
        &embeddings,
        &cochange,
        &projection,
    ];
    let centrality = compute_import_centrality(graph, &all_signal_sets)?;
    if !centrality.is_empty() {
        // Apply centrality as a small reranking bonus on the top ~15 fused results.
        for (path, score) in fused.iter_mut().take(15) {
            if let Some(cent_hits) = centrality.get(path) {
                let cent_score: f32 = cent_hits.iter().map(|h| h.score).sum();
                *score += locate_env_f32("KIN_LOCATE_IMPORT_CENTRALITY_BONUS", 0.005) * cent_score;
            }
        }
        fused.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    }

    // ── Post-RRF: non-source + internal path penalty ──
    // Files with parsed entities in the graph are source — the graph is the authority.
    // Unlike indexed_file_paths (all tracked files incl. build artifacts/configs),
    // entity_bearing_file_paths returns only files the parser extracted real
    // semantic entities from (functions, classes, etc.).
    let source_files: HashSet<String> = graph.entity_bearing_file_paths().into_iter().collect();
    let non_code_ext_penalty = locate_env_f32("KIN_LOCATE_NON_CODE_EXT_PENALTY", 0.005);
    let docs_path_penalty = locate_env_f32("KIN_LOCATE_DOCS_PATH_PENALTY", 0.01);
    let vendor_path_penalty = locate_env_f32("KIN_LOCATE_VENDOR_PATH_PENALTY", 0.01);
    for (path, score) in fused.iter_mut() {
        // Internal Kin paths should never appear
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
        // Non-code file types: docs, data, schemas, i18n, configs
        if is_non_code_ext(path) {
            *score *= non_code_ext_penalty;
        }
        // Documentation/locale/vendor paths
        if is_docs_or_locale_path(path) {
            *score *= docs_path_penalty;
        }
        if is_vendor_path(path) {
            *score *= vendor_path_penalty;
        }
    }

    // ── Post-RRF: direct entity→file boost ──
    // If the query text contains identifiers that exactly match entity names in
    // the graph, boost those entities' files to the top. This handles cases like
    // "SlicedLowLevelWCS" → directly find sliced_wcs.py without relying on text search.
    // Class/struct definitions get a smaller boost than functions/methods because
    // the file defining a class is less likely to be the fix site than the file
    // containing a function with the same name.
    {
        let entity_boost_fn = locate_env_f32("KIN_LOCATE_ENTITY_DIRECT_BOOST", 50.0);
        let entity_boost_class = locate_env_f32("KIN_LOCATE_ENTITY_CLASS_BOOST", 10.0);
        let search_terms = extract_search_terms(text);
        for term in &search_terms {
            let filter = EntityFilter {
                name_pattern: Some(term.clone()),
                ..Default::default()
            };
            if let Ok(entities) = graph.query_entities(&filter) {
                for entity in entities.iter().take(3) {
                    if let Some(ref fo) = entity.file_origin {
                        let path = &fo.0;
                        if !is_test_by_role(path, Some(entity)) && source_files.contains(path.as_str()) {
                            // Check if it's an exact or very close name match
                            let name_lower = entity.name.to_lowercase();
                            let term_lower = term.to_lowercase();
                            if name_lower == term_lower || name_lower.contains(&term_lower) {
                                let boost = match entity.kind {
                                    EntityKind::Class
                                    | EntityKind::Interface
                                    | EntityKind::TraitDef
                                    | EntityKind::Module
                                    | EntityKind::Package => entity_boost_class,
                                    _ => entity_boost_fn,
                                };
                                if let Some(entry) = fused.iter_mut().find(|(p, _)| p == path) {
                                    entry.1 += boost;
                                } else {
                                    fused.push((path.clone(), boost));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Post-RRF: nested module depth bonus ──
    // When multiple files from the same module match, prefer deeper (more specific) paths.
    // e.g., nddata/mixins/ndarithmetic.py should rank above nddata/nddata.py
    for (path, score) in fused.iter_mut() {
        let depth = path.matches('/').count();
        if depth >= 3 {
            *score *= 1.0 + locate_env_f32("KIN_LOCATE_DEPTH_BONUS_PER_LEVEL", 0.05) * (depth as f32 - 2.0);
        }
    }

    // ── Post-RRF: sibling specificity tiebreaker ──
    // Within the same directory, penalize generic module names (core.py, base.py,
    // __init__.py, utils.py) and boost files whose stem matches a query keyword.
    // e.g., for query "HTML output", ascii/html.py should beat ascii/core.py.
    {
        let generic_penalty = locate_env_f32("KIN_LOCATE_GENERIC_MODULE_PENALTY", 0.7);
        let keyword_boost = locate_env_f32("KIN_LOCATE_KEYWORD_FILE_BOOST", 1.3);
        let search_terms = extract_search_terms(text);
        let query_lower: Vec<String> = search_terms.iter().map(|t| t.to_lowercase()).collect();
        for (path, score) in fused.iter_mut() {
            if let Some(stem) = file_stem_lower(path) {
                if is_generic_module_name(&stem) {
                    *score *= generic_penalty;
                }
                if query_lower.iter().any(|q| stem.contains(q) || q.contains(&stem)) {
                    *score *= keyword_boost;
                }
            }
        }
    }

    // ── Negation penalty: demote files explicitly excluded by the query ──
    let excluded_files = extract_negation_penalties(text, graph);
    if !excluded_files.is_empty() {
        let negation_penalty = locate_env_f32("KIN_LOCATE_NEGATION_PENALTY", 0.01);
        for (path, score) in fused.iter_mut() {
            if excluded_files.contains(path.as_str()) {
                *score *= negation_penalty;
            }
        }
    }

    // Tiered sort: group by file role (source > external > test), then by score within tier.
    // This ensures source files always rank above test/external regardless of signal scores.
    // For test-focused queries, tiers are swapped so test files surface naturally.
    let is_test_q = is_test_query(text);
    fused.sort_by(|a, b| {
        let tier_a = file_tier(&a.0, is_test_q);
        let tier_b = file_tier(&b.0, is_test_q);
        tier_a.cmp(&tier_b)
            .then_with(|| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
    });

    // Merge signal labels for each file
    let all_hits: Vec<HashMap<String, Vec<FileHit>>> = vec![
        traceback, search, multihop, tests, snippets, imports, errors, embeddings, cochange,
        projection, followup,
    ];

    // Debug output: show top-20 files with per-signal score breakdown
    if std::env::var("KIN_LOCATE_DEBUG").is_ok() {
        let signal_names = [
            "traceback", "search", "multihop", "tests", "snippets",
            "imports", "errors", "embeddings", "cochange", "projection", "followup",
        ];
        eprintln!("=== LOCATE DEBUG ===");
        eprintln!("Query terms: {:?}", extract_search_terms(text));
        eprintln!(
            "{:<50} {:>8} | {}",
            "FILE",
            "FUSED",
            signal_names
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
        let model_path = std::env::var("KIN_LOCATE_LTR_MODEL_PATH")
            .unwrap_or_else(|_| {
                let layout = kin_core::KinLayout::discover(&std::env::current_dir().unwrap_or_default());
                layout.map_or_else(
                    || ".kin/models/ltr_v1.json".to_string(),
                    |l| l.root().join(".kin/models/ltr_v1.json").to_string_lossy().to_string(),
                )
            });

        if let Ok(model) = kin_ranking::ltr::GradientBoostedRanker::load(std::path::Path::new(&model_path)) {
            let ltr_window = locate_env_usize("KIN_LOCATE_LTR_WINDOW", 30).min(fused.len());
            let search_terms = extract_search_terms(text);
            let search_terms_count = search_terms.len();
            let query_has_traceback = if text.contains("Traceback") || text.contains("File \"") { 1.0 } else { 0.0 };
            let query_has_path = if !extract_file_paths(text).is_empty() { 1.0 } else { 0.0 };

            let signal_score_names = [
                "traceback_score", "search_score", "multihop_score", "test_score",
                "snippet_score", "import_score", "error_score", "embedding_score",
                "cochange_score", "projection_score",
            ];
            let _ = signal_score_names; // used for documentation, scores accessed by index

            let mut ltr_candidates: Vec<(String, f32, kin_ranking::features::LocateFeatureVector)> = Vec::new();

            for (rank, (path, score)) in fused.iter().take(ltr_window).enumerate() {
                let mut fv = kin_ranking::features::LocateFeatureVector::zeros();

                // Fill per-signal scores and presence from all_hits (indices 0..10)
                let per_signal_scores: Vec<f32> = (0..10)
                    .map(|idx| {
                        all_hits.get(idx)
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
                fv.embedding_score = per_signal_scores[7];
                fv.cochange_score = per_signal_scores[8];
                fv.projection_score = per_signal_scores[9];

                fv.traceback_present = if per_signal_scores[0] > 0.0 { 1.0 } else { 0.0 };
                fv.search_present = if per_signal_scores[1] > 0.0 { 1.0 } else { 0.0 };
                fv.multihop_present = if per_signal_scores[2] > 0.0 { 1.0 } else { 0.0 };
                fv.test_present = if per_signal_scores[3] > 0.0 { 1.0 } else { 0.0 };
                fv.snippet_present = if per_signal_scores[4] > 0.0 { 1.0 } else { 0.0 };
                fv.import_present = if per_signal_scores[5] > 0.0 { 1.0 } else { 0.0 };
                fv.error_present = if per_signal_scores[6] > 0.0 { 1.0 } else { 0.0 };
                fv.embedding_present = if per_signal_scores[7] > 0.0 { 1.0 } else { 0.0 };
                fv.cochange_present = if per_signal_scores[8] > 0.0 { 1.0 } else { 0.0 };
                fv.projection_present = if per_signal_scores[9] > 0.0 { 1.0 } else { 0.0 };

                fv.signal_count = per_signal_scores.iter().filter(|&&s| s > 0.0).count() as f32;
                fv.fused_rrf_score = *score;
                fv.rrf_rank = rank as f32;
                fv.path_depth = path.matches('/').count() as f32;
                let path_role = role_from_path(path);
                fv.is_test = if path_role == EntityRole::Test { 1.0 } else { 0.0 };
                fv.is_source = if path_role == EntityRole::Source { 1.0 } else { 0.0 };
                fv.is_external = if matches!(path_role, EntityRole::External | EntityRole::Vendored) { 1.0 } else { 0.0 };
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

    // Adaptive cap
    let results = adaptive_cap(&fused, &all_hits, max_files);
    let file_provenance = if explain {
        collect_result_provenance(&results, &projection_provenance)
    } else {
        HashMap::new()
    };

    if json {
        output_json(&results, &all_hits, &projection_explain, &file_provenance, explain);
    } else {
        output_text(&results, &all_hits, &projection_explain, explain);
    }

    Ok(())
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
                        if !is_test_by_role(&path, Some(&entity)) || rel_path.as_ref() == Some(&path) {
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
    // Try to extract relative path from common patterns
    // e.g. /home/user/project/astropy/modeling/core.py -> astropy/modeling/core.py
    let path = path.replace('\\', "/");

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

fn extract_search_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let _span =
        tracing::info_span!("locate.extract_search_signals", text_len = text.len()).entered();
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();
    let tracked_non_entity = tracked_non_entity_files(graph);
    // Context-aware test file penalty: if query is test-focused, don't penalize test files
    let is_test_focused = is_test_query(text);
    let test_penalty = if is_test_focused { 1.0 } else { 0.1 };

    for file_path in extract_file_paths(text) {
        if let Some(path) = resolve_path_in_graph(graph, &file_path) {
            hits.entry(path).or_default().push(FileHit {
                score: 10.0,
                spans: vec![],
            });
        }
    }

    // Module path fragment matching (e.g. "astropy.modeling.core" -> search for files containing "astropy/modeling/core")
    let module_fragments = extract_module_path_fragments(text);
    for fragment in &module_fragments {
        if let Some(path) = resolve_path_in_graph(graph, fragment) {
            hits.entry(path).or_default().push(FileHit {
                score: 8.0,
                spans: vec![],
            });
        }
        // Also try with common extensions
        for ext in &[".py", ".rs", ".ts", ".js", ".go", ".java"] {
            let with_ext = format!("{}{}", fragment, ext);
            if let Some(path) = resolve_path_in_graph(graph, &with_ext) {
                hits.entry(path).or_default().push(FileHit {
                    score: 8.0,
                    spans: vec![],
                });
            }
        }
    }

    let identifiers = curate_search_terms(text, graph)?;
    if identifiers.is_empty() {
        return Ok(hits);
    }

    // BM25F field-level weights: boost matches in high-signal fields
    let bm25f_name_weight = locate_env_f32("KIN_LOCATE_BM25F_NAME_WEIGHT", 5.0);
    let bm25f_doc_weight = locate_env_f32("KIN_LOCATE_BM25F_DOC_WEIGHT", 2.0);
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

        // Start with exact/pattern entity matches, then always blend in the
        // graph text index so body/doc/path matches can compete too.

        let mut seen = std::collections::HashSet::new();
        let mut entities_found = Vec::new();

        // Step 1: Pattern match (same as search.rs line 426-436)
        let filter = EntityFilter {
            name_pattern: Some(ident.clone()),
            ..Default::default()
        };
        for entity in graph.query_entities(&filter)? {
            if seen.insert(entity.id) {
                entities_found.push(entity);
            }
        }

        // Step 2: Always consult text search. This preserves graph lexical
        // evidence from doc summaries, body previews, and path text instead of
        // only using it as a fallback once name matches dry up.
        let text_hits =
            graph.text_search(ident, locate_env_usize("KIN_LOCATE_TEXT_HIT_LIMIT", 50))?;
        for (rank, (retrieval_key, _score)) in text_hits.into_iter().enumerate() {
            if let Some((path, spans, entity)) = retrieval_file_hit(graph, &retrieval_key)? {
                let test_mult = test_mult_by_role(&path, entity.as_ref(), 0.1);
                let path_lower = path.to_lowercase();
                let name_lower = entity
                    .as_ref()
                    .map(|value| value.name.to_lowercase())
                    .unwrap_or_default();
                // BM25F: apply field-level weight based on where the match occurred
                let (lexical_base, field_weight) =
                    if !name_lower.is_empty() && name_lower.contains(&ident_lower) {
                        (0.5, bm25f_name_weight)
                    } else if path_lower.contains(&ident_lower) {
                        // Path matches use doc weight (navigational signal)
                        (1.5, bm25f_doc_weight)
                    } else {
                        // Body/other text matches
                        (2.5, bm25f_body_weight)
                    };
                hits.entry(path).or_default().push(FileHit {
                    score: lexical_base * field_weight * title_mult * test_mult
                        / ((rank + 1) as f32).sqrt(),
                    spans,
                });

                if let Some(entity) = entity {
                    if entities_found.len() < locate_env_usize("KIN_LOCATE_NAME_MATCH_LIMIT", 5)
                        && seen.insert(entity.id)
                    {
                        entities_found.push(entity);
                    }
                }
            }
        }

        // Step 3: File stem / path matching — add a smaller bonus when the
        // file path itself contains the search term.
        if ident_lower.len() >= 3 {
            let text_path_hits = graph.text_search(
                &ident_lower,
                locate_env_usize("KIN_LOCATE_PATH_HIT_LIMIT", 100),
            )?;
            for (rank, (retrieval_key, _score)) in text_path_hits.into_iter().enumerate() {
                if let Some((path, spans, entity)) = retrieval_file_hit(graph, &retrieval_key)? {
                    let path_lower = path.to_lowercase();
                    if path_lower.contains(&ident_lower) {
                        let test_mult = test_mult_by_role(&path, entity.as_ref(), 0.1);
                        hits.entry(path).or_default().push(FileHit {
                            score: 1.25 * bm25f_doc_weight * title_mult * test_mult
                                / ((rank + 1) as f32).sqrt(),
                            spans,
                        });
                    }
                }
            }
        }

        // Score: definitions get 3x, test files get context-aware penalty, exact name match 5x
        // File path contains search term bonus, conjunctive multi-term bonus
        // BM25F: entity name matches get bm25f_name_weight applied
        for entity in &entities_found {
            if let Some(ref fo) = entity.file_origin {
                let path = fo.0.clone();
                let test_mult = test_mult_by_role(&path, Some(entity), test_penalty);

                let name_lower = entity.name.to_lowercase();
                let name_mult = if name_lower == ident_lower {
                    5.0 // Exact match
                } else if name_lower.contains(&ident_lower) {
                    2.0 // Substring match
                } else {
                    1.0 // Broad match
                };

                // BM25F: name-matched entities get the name field weight
                let field_weight = if name_lower.contains(&ident_lower) {
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

                // File path contains search term bonus
                let path_lower = path.to_lowercase();
                let path_mult = if path_lower.contains(&ident_lower) && ident_lower.len() >= 3 {
                    2.0
                } else {
                    1.0
                };
                hits.entry(path).or_default().push(FileHit {
                    score: kind_mult * name_mult * field_weight * test_mult * title_mult
                        * path_mult,
                    spans: entity_span_pair(entity),
                });
            }
        }

        for tracked in &tracked_non_entity {
            let path_lower = tracked.path.to_ascii_lowercase();
            let descriptor_lower = tracked.descriptor.to_ascii_lowercase();
            if path_lower.contains(&ident_lower) || descriptor_lower.contains(&ident_lower) {
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
                hits.entry(tracked.path.clone()).or_default().push(FileHit {
                    score: 2.25 * title_mult * source_mult * docs_mult,
                    spans: vec![],
                });
            }
        }
    }

    // Conjunctive multi-term bonus: files matching multiple search terms get a boost
    if identifiers.len() > 1 {
        let mut file_term_matches: HashMap<String, HashSet<String>> = HashMap::new();
        for ident in &identifiers {
            let ident_lower = ident.to_lowercase();
            let mut files_for_term = HashSet::new();
            for (path, _) in hits.iter() {
                let path_lower = path.to_lowercase();
                if path_lower.contains(&ident_lower) {
                    files_for_term.insert(path.clone());
                }
            }
            // Also check entity names in each file
            if let Ok(all_entities) = graph.list_all_entities() {
                for entity in &all_entities {
                    if entity.name.to_lowercase().contains(&ident_lower) {
                        if let Some(ref fo) = entity.file_origin {
                            if hits.contains_key(&fo.0) {
                                files_for_term.insert(fo.0.clone());
                            }
                        }
                    }
                }
            }
            for f in files_for_term {
                file_term_matches
                    .entry(f)
                    .or_insert_with(HashSet::new)
                    .insert(ident_lower.clone());
            }
        }
        for (path, matched_terms) in &file_term_matches {
            let term_count = matched_terms.len();
            if term_count > 1 {
                let bonus = match term_count {
                    2 => 5.0,
                    3 => 15.0,
                    _ => 30.0, // 4+
                };
                hits.entry(path.clone()).or_default().push(FileHit {
                    score: bonus,
                    spans: vec![],
                });
            }
        }
    }

    // File stem matching
    let all_file_paths = tracked_file_paths(graph);

    let common_stems: HashSet<&str> = [
        "base",
        "core",
        "utils",
        "util",
        "helpers",
        "helper",
        "types",
        "models",
        "views",
        "tests",
        "test",
        "conf",
        "config",
        "settings",
        "urls",
        "admin",
        "init",
        "main",
        "index",
        "common",
        "compat",
        "exceptions",
        "errors",
        "constants",
    ]
    .iter()
    .copied()
    .collect();

    for ident in &identifiers {
        let ident_lower = ident.to_lowercase();
        if ident_lower.len() < 4 || common_stems.contains(ident_lower.as_str()) {
            continue;
        }
        let is_title = title_terms.contains(&ident_lower);
        for file_path in &all_file_paths {
            let stem = file_path
                .rsplit('/')
                .next()
                .and_then(|f| f.rsplit('.').last())
                .unwrap_or("")
                .to_lowercase();
            if stem == ident_lower && !is_test_path(file_path) {
                let score = if is_title { 20.0 } else { 10.0 };
                hits.entry(file_path.clone()).or_default().push(FileHit {
                    score: score,
                    spans: vec![],
                });
            }
        }
    }

    Ok(hits)
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

    let mut curated = Vec::new();
    for (term, from_title) in candidates {
        if term_has_graph_support(graph, &term, from_title)? {
            curated.push(term);
        }
        if curated.len() >= locate_env_usize("KIN_LOCATE_CURATED_TERM_LIMIT", 8) {
            break;
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

    expand_search_terms_from_graph(graph, curated)
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
            EntityRole::Test | EntityRole::External | EntityRole::Vendored | EntityRole::Generated => other_hits += 1,
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
            EntityRole::Test | EntityRole::External | EntityRole::Vendored | EntityRole::Generated => other_hits += 1,
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
    let max_depth = locate_env_usize("KIN_LOCATE_MULTIHOP_MAX_DEPTH", profile_max_depth)
        .min(profile_max_depth);
    let frontier_limit =
        locate_env_usize("KIN_LOCATE_MULTIHOP_FRONTIER_LIMIT", profile.multihop_frontier_limit());
    let timeout = std::time::Duration::from_millis(
        locate_env_usize("KIN_LOCATE_MULTIHOP_TIMEOUT_MS", profile.multihop_timeout_ms() as usize)
            as u64,
    );
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
            tracing::debug!("multihop BFS timeout reached after {:?}", bfs_start.elapsed());
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
                            let rel_mult = match rel.kind {
                                RelationKind::Tests => 2.4,
                                RelationKind::Calls => 2.0,
                                RelationKind::Imports | RelationKind::DependsOn => 1.8,
                                RelationKind::Implements | RelationKind::Extends => 1.5,
                                RelationKind::References => 1.2,
                                _ => 1.0,
                            };
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
                            let hub_dampen = *hub_dampening_cache.entry(path.clone()).or_insert_with(|| {
                                let filter = EntityFilter {
                                    file_path: Some(kin_model::FilePathId::new(&path)),
                                    ..Default::default()
                                };
                                let entity_count = graph
                                    .query_entities(&filter)
                                    .map(|e| e.len())
                                    .unwrap_or(1);
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
            kinds: Some(vec![
                EntityKind::Function,
                EntityKind::Method,
            ]),
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
                        let score = if is_test_by_role(&path, Some(&target)) { 0.5 } else { 3.0 };
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

fn extract_embedding_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let _span =
        tracing::info_span!("locate.extract_embedding_signals", text_len = text.len()).entered();
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    // Only fire if the vector index has been populated (i.e., embeddings exist).
    let status = graph.embedding_status();
    if status.indexed == 0 {
        return Ok(hits);
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
            if let Some((path, spans, entity)) = retrieval_file_hit(graph, retrieval_key)? {
                // Cosine distance ranges 0..2 (0=identical, 2=opposite).
                // Map to relevance 0..1 so non-identical vectors still contribute.
                let relevance = ((2.0 - distance) / 2.0).max(0.0);

                // Weight by entity kind: definitions are more useful than constants.
                // Non-entity graph objects still get to contribute file-level hits,
                // but with a neutral multiplier until the Phase 8 planner rewrite.
                let kind_mult = match entity.as_ref().map(|value| value.kind) {
                    Some(
                        EntityKind::Function
                        | EntityKind::Method
                        | EntityKind::Class
                        | EntityKind::TraitDef
                        | EntityKind::Interface
                        | EntityKind::Module,
                    ) => 2.0,
                    Some(EntityKind::EnumDef) => 1.5,
                    Some(_) => 1.0,
                    None => 1.1,
                };

                let test_mult = test_mult_by_role(&path, entity.as_ref(), 0.1);

                // Role-based path scoring: demote docs/examples, boost source paths.
                let path_role = entity.as_ref().map(|e| e.role).unwrap_or_else(|| role_from_path(&path));
                let path_mult = match path_role {
                    EntityRole::Docs => 0.3,
                    EntityRole::Source => 1.2,
                    _ => 1.0,
                };
                hits.entry(path).or_default().push(FileHit {
                    score: relevance * kind_mult * test_mult * path_mult * 10.0 * query_weight,
                    spans,
                });
            }
        }
    }

    Ok(hits)
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

    let decay_halflife_days =
        locate_env_f32("KIN_LOCATE_COCHANGE_DECAY_HALFLIFE_DAYS", 365.0);
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
                    score: rel.confidence * 2.5 * seed_mult * test_mult * path_mult * temporal_decay,
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

fn extract_projection_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<(
    HashMap<String, Vec<FileHit>>,
    HashMap<String, Vec<String>>,
    HashMap<String, LocateFileProvenance>,
)> {
    let _span =
        tracing::info_span!("locate.extract_projection_signals", text_len = text.len()).entered();
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();
    let mut explain: HashMap<String, Vec<String>> = HashMap::new();
    let mut provenance: HashMap<String, LocateFileProvenance> = HashMap::new();
    let seed_signals = collect_projection_seed_signals(text, graph)?;

    if seed_signals.is_empty() {
        return Ok((hits, explain, provenance));
    }

    let mut entity_seeds: HashMap<kin_model::EntityId, SeedSignal> = HashMap::new();
    for (retrieval_key, signal) in seed_signals {
        let Some((path, spans, entity)) = retrieval_file_hit(graph, &retrieval_key)? else {
            continue;
        };
        let direct_score = signal.score
            * if entity.is_some() {
                1.35
            } else if is_source_path(&path) {
                1.15
            } else {
                1.0
            }
           ;
        hits.entry(path.clone()).or_default().push(FileHit {
            score: direct_score,
            spans,
        });
        merge_file_provenance(
            &mut provenance,
            &path,
            direct_file_provenance(&retrieval_key, entity.as_ref(), &path),
        );

        if let Some(entity) = entity {
            merge_seed_signal(&mut entity_seeds, entity.id, signal);
            push_projection_reason(
                &mut explain,
                &path,
                format!(
                    "entity `{}` matched {} retrieval",
                    entity.name,
                    seed_signal_labels(signal)
                ),
            );
        } else {
            push_projection_reason(
                &mut explain,
                &path,
                format!(
                    "graph-owned artifact projected from {} retrieval",
                    seed_signal_labels(signal)
                ),
            );
        }
    }

    if entity_seeds.is_empty() {
        return Ok((hits, explain, provenance));
    }

    let seed_ids: Vec<kin_model::EntityId> = entity_seeds.keys().copied().collect();
    let seed_id_set: HashSet<kin_model::EntityId> = seed_ids.iter().copied().collect();
    let subgraph = graph.expand_neighborhood(
        &seed_ids,
        &[
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::DependsOn,
            RelationKind::CoChanges,
            RelationKind::Contains,
            RelationKind::Tests,
        ],
        locate_env_usize("KIN_LOCATE_PLAN_DEPTH", 2) as u32,
    )?;

    let traces = projection_traces(&subgraph, &entity_seeds);
    for (&entity_id, trace) in &traces {
        if seed_id_set.contains(&entity_id) || trace.hops == 0 {
            continue;
        }
        let Some(entity) = subgraph.entities.get(&entity_id) else {
            continue;
        };
        let Some(file_origin) = entity.file_origin.as_ref() else {
            continue;
        };
        let Some(origin_signal) = entity_seeds.get(&trace.origin_seed) else {
            continue;
        };

        let path = file_origin.0.clone();
        let test_mult = test_mult_by_role(&path, Some(&entity), 0.35);
        let entity_role = entity.role;
        let path_mult = match entity_role {
            EntityRole::Docs => 0.45,
            EntityRole::Source => 1.2,
            _ => 1.0,
        };
        let edge_mult = trace
            .primary_kind
            .map(planner_relation_weight)
            .unwrap_or(1.0)
            / 5.0;
        let score =
            origin_signal.score * edge_mult * path_mult * test_mult / ((trace.hops + 1) as f32);
        hits.entry(path.clone()).or_default().push(FileHit {
            score,
            spans: entity_span_pair(entity),
        });
        if let Some(path_provenance) = projection_trace_provenance(entity_id, &traces, &subgraph) {
            merge_file_provenance(&mut provenance, &path, path_provenance);
        }

        let origin_name = subgraph
            .entities
            .get(&trace.origin_seed)
            .map(|value| value.name.as_str())
            .unwrap_or("seed");
        let via = trace
            .primary_kind
            .map(planner_relation_label)
            .unwrap_or("graph");
        push_projection_reason(
            &mut explain,
            &path,
            format!(
                "projected from entity `{}` via {} in {} hop{}",
                origin_name,
                via,
                trace.hops,
                if trace.hops == 1 { "" } else { "s" }
            ),
        );
    }

    // Dampen hub files in projection signals (same logic as multihop):
    // files accumulating many trace hits are hubs, not query-relevant.
    for file_hits in hits.values_mut() {
        let hit_count = file_hits.len() as f32;
        let dampening = 1.0 / (hit_count + 2.0).log2();
        for h in file_hits.iter_mut() {
            h.score *= dampening;
        }
    }

    Ok((hits, explain, provenance))
}

fn collect_projection_seed_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<kin_db::RetrievalKey, SeedSignal>> {
    let mut signals: HashMap<kin_db::RetrievalKey, SeedSignal> = HashMap::new();
    let identifiers = curate_search_terms(text, graph)?;
    let title_line = text.lines().next().unwrap_or("");
    let title_terms: HashSet<String> = extract_title_terms(title_line)
        .into_iter()
        .map(|value| value.to_lowercase())
        .collect();

    for ident in &identifiers {
        let ident_lower = ident.to_lowercase();
        let title_mult = if title_terms.contains(&ident_lower) {
            3.0
        } else {
            1.0
        };
        for (rank, (retrieval_key, _)) in graph
            .text_search(ident, locate_env_usize("KIN_LOCATE_PLAN_TEXT_LIMIT", 24))?
            .into_iter()
            .enumerate()
        {
            let score = 3.0 * title_mult / ((rank + 1) as f32).sqrt();
            add_seed_signal(&mut signals, retrieval_key, score, true, false);
        }
    }

    let status = graph.embedding_status();
    if status.indexed == 0 {
        return Ok(signals);
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
    if !identifiers.is_empty() {
        push_semantic_query(
            &mut queries,
            &mut seen_queries,
            &identifiers
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join(" "),
            1.15,
        );
        for ident in identifiers.iter().take(3) {
            push_semantic_query(&mut queries, &mut seen_queries, ident, 0.9);
        }
    }

    for (query, query_weight) in queries {
        for (retrieval_key, distance) in graph
            .semantic_search(
                &query,
                locate_env_usize("KIN_LOCATE_PLAN_SEMANTIC_LIMIT", 24),
            )?
            .into_iter()
        {
            let score = (1.0 - distance).max(0.0) * 5.0 * query_weight;
            add_seed_signal(&mut signals, retrieval_key, score, false, true);
        }
    }

    Ok(signals)
}

fn add_seed_signal(
    signals: &mut HashMap<kin_db::RetrievalKey, SeedSignal>,
    retrieval_key: kin_db::RetrievalKey,
    score: f32,
    lexical: bool,
    semantic: bool,
) {
    let entry = signals.entry(retrieval_key).or_default();
    entry.score += score;
    entry.lexical |= lexical;
    entry.semantic |= semantic;
}

fn merge_seed_signal(
    signals: &mut HashMap<kin_model::EntityId, SeedSignal>,
    entity_id: kin_model::EntityId,
    signal: SeedSignal,
) {
    let entry = signals.entry(entity_id).or_default();
    entry.score += signal.score;
    entry.lexical |= signal.lexical;
    entry.semantic |= signal.semantic;
}

fn seed_signal_labels(signal: SeedSignal) -> &'static str {
    match (signal.lexical, signal.semantic) {
        (true, true) => "lexical and semantic",
        (true, false) => "lexical",
        (false, true) => "semantic",
        (false, false) => "graph",
    }
}

fn projection_traces(
    subgraph: &kin_model::SubGraph,
    seed_signals: &HashMap<kin_model::EntityId, SeedSignal>,
) -> HashMap<kin_model::EntityId, ProjectionTrace> {
    use std::collections::VecDeque;

    let mut adjacency: HashMap<kin_model::EntityId, Vec<ProjectionAdjacency>> = HashMap::new();
    for relation in &subgraph.relations {
        let (Some(src), Some(dst)) = (relation.src.as_entity(), relation.dst.as_entity()) else {
            continue;
        };
        adjacency
            .entry(src)
            .or_default()
            .push(ProjectionAdjacency {
                neighbor: dst,
                kind: relation.kind,
                relation_src: src,
                relation_dst: dst,
            });
        adjacency
            .entry(dst)
            .or_default()
            .push(ProjectionAdjacency {
                neighbor: src,
                kind: relation.kind,
                relation_src: src,
                relation_dst: dst,
            });
    }

    let mut traces: HashMap<kin_model::EntityId, ProjectionTrace> = HashMap::new();
    let mut queue: VecDeque<(
        kin_model::EntityId,
        kin_model::EntityId,
        u32,
        Option<RelationKind>,
    )> = VecDeque::new();

    for entity_id in seed_signals.keys().copied() {
        traces.insert(
            entity_id,
            ProjectionTrace {
                hops: 0,
                origin_seed: entity_id,
                primary_kind: None,
                parent: None,
                edge_kind: None,
                edge_src: None,
                edge_dst: None,
            },
        );
        queue.push_back((entity_id, entity_id, 0, None));
    }

    while let Some((current, origin_seed, hops, primary_kind)) = queue.pop_front() {
        let Some(neighbors) = adjacency.get(&current) else {
            continue;
        };

        for connection in neighbors {
            let candidate = ProjectionTrace {
                hops: hops + 1,
                origin_seed,
                primary_kind: primary_kind.or(Some(connection.kind)),
                parent: Some(current),
                edge_kind: Some(connection.kind),
                edge_src: Some(connection.relation_src),
                edge_dst: Some(connection.relation_dst),
            };
            let replace = traces.get(&connection.neighbor).is_none_or(|existing| {
                candidate.hops < existing.hops
                    || (candidate.hops == existing.hops
                        && seed_signals
                            .get(&candidate.origin_seed)
                            .map(|value| value.score)
                            .unwrap_or_default()
                            > seed_signals
                                .get(&existing.origin_seed)
                                .map(|value| value.score)
                                .unwrap_or_default())
            });
            if replace {
                traces.insert(connection.neighbor, candidate);
                queue.push_back((
                    connection.neighbor,
                    origin_seed,
                    hops + 1,
                    candidate.primary_kind,
                ));
            }
        }
    }

    traces
}

fn planner_relation_weight(kind: RelationKind) -> f32 {
    match kind {
        RelationKind::Calls => 5.0,
        RelationKind::CoChanges => 3.5,
        RelationKind::DependsOn => 3.0,
        RelationKind::Implements => 3.0,
        RelationKind::Extends => 3.0,
        RelationKind::Tests => 2.5,
        RelationKind::Imports => 2.0,
        RelationKind::DefinesContract => 2.0,
        RelationKind::ConsumesContract => 2.0,
        RelationKind::EmitsEvent => 1.5,
        RelationKind::References => 1.0,
        RelationKind::DocumentedBy => 0.5,
        RelationKind::Contains => 0.5,
        RelationKind::OwnedBy => 0.5,
        RelationKind::Covers => 2.5,
        RelationKind::DerivedFrom => 1.5,
        RelationKind::OwnedByFile => 0.5,
        RelationKind::Overrides => 4.0,
        RelationKind::Instantiates => 4.0,
        RelationKind::UsesType => 2.5,
        RelationKind::SubscribesTo => 1.5,
        RelationKind::SendsMessage => 3.0,
        RelationKind::Spawns => 3.0,
    }
}

fn planner_relation_label(kind: RelationKind) -> &'static str {
    match kind {
        RelationKind::Calls => "calls",
        RelationKind::CoChanges => "co-change",
        RelationKind::DependsOn => "depends-on",
        RelationKind::Implements => "implements",
        RelationKind::Extends => "extends",
        RelationKind::Tests => "test",
        RelationKind::Imports => "import",
        RelationKind::DefinesContract => "defines-contract",
        RelationKind::ConsumesContract => "consumes-contract",
        RelationKind::EmitsEvent => "emits-event",
        RelationKind::References => "reference",
        RelationKind::DocumentedBy => "documentation",
        RelationKind::Contains => "contains",
        RelationKind::OwnedBy => "ownership",
        RelationKind::Covers => "covers",
        RelationKind::DerivedFrom => "derived-from",
        RelationKind::OwnedByFile => "owned-by-file",
        RelationKind::Overrides => "overrides",
        RelationKind::Instantiates => "instantiates",
        RelationKind::UsesType => "uses-type",
        RelationKind::SubscribesTo => "subscribes-to",
        RelationKind::SendsMessage => "sends-message",
        RelationKind::Spawns => "spawns",
    }
}

fn direct_file_provenance(
    key: &kin_db::RetrievalKey,
    entity: Option<&kin_model::Entity>,
    path: &str,
) -> LocateFileProvenance {
    match key {
        kin_db::RetrievalKey::Entity(entity_id) => LocateFileProvenance {
            objects: vec![entity
                .map(graph_object_for_entity)
                .unwrap_or_else(|| LocateGraphObject {
                    id: GraphNodeId::Entity(*entity_id).to_string(),
                    kind: "entity".to_string(),
                    name: None,
                    file_path: Some(path.to_string()),
                })],
            edges: Vec::new(),
        },
        kin_db::RetrievalKey::Artifact(artifact_id) => LocateFileProvenance {
            objects: vec![artifact_graph_object(*artifact_id, path)],
            edges: Vec::new(),
        },
    }
}

fn collect_result_provenance(
    results: &[(String, f32)],
    projection_provenance: &HashMap<String, LocateFileProvenance>,
) -> HashMap<String, LocateFileProvenance> {
    results
        .iter()
        .map(|(path, _)| {
            let provenance = projection_provenance
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

fn merge_file_provenance(
    provenance: &mut HashMap<String, LocateFileProvenance>,
    path: &str,
    candidate: LocateFileProvenance,
) {
    let replace = provenance.get(path).is_none_or(|existing| {
        candidate.edges.len() > existing.edges.len()
            || (candidate.edges.len() == existing.edges.len()
                && candidate.objects.len() > existing.objects.len())
    });
    if replace {
        provenance.insert(path.to_string(), candidate);
    }
}

fn graph_object_for_entity(entity: &kin_model::Entity) -> LocateGraphObject {
    LocateGraphObject {
        id: GraphNodeId::Entity(entity.id).to_string(),
        kind: "entity".to_string(),
        name: Some(entity.name.clone()),
        file_path: entity.file_origin.as_ref().map(|path| path.0.clone()),
    }
}

fn artifact_graph_object(artifact_id: kin_model::ArtifactId, path: &str) -> LocateGraphObject {
    LocateGraphObject {
        id: GraphNodeId::Artifact(artifact_id).to_string(),
        kind: "artifact".to_string(),
        name: None,
        file_path: Some(path.to_string()),
    }
}

fn projection_trace_provenance(
    entity_id: kin_model::EntityId,
    traces: &HashMap<kin_model::EntityId, ProjectionTrace>,
    subgraph: &kin_model::SubGraph,
) -> Option<LocateFileProvenance> {
    let mut objects = Vec::new();
    let mut edges = Vec::new();
    let mut entity_chain = Vec::new();
    let mut edge_chain = Vec::new();
    let mut current = entity_id;

    loop {
        let trace = traces.get(&current)?;
        entity_chain.push(current);
        if let (Some(src), Some(dst), Some(kind)) = (trace.edge_src, trace.edge_dst, trace.edge_kind) {
            edge_chain.push((src, dst, kind));
        }
        let Some(parent) = trace.parent else {
            break;
        };
        current = parent;
    }

    entity_chain.reverse();
    edge_chain.reverse();

    for current_entity in entity_chain {
        let entity = subgraph.entities.get(&current_entity)?;
        objects.push(graph_object_for_entity(entity));
    }

    for (src, dst, kind) in edge_chain {
        edges.push(LocateGraphEdge {
            src: GraphNodeId::Entity(src).to_string(),
            dst: GraphNodeId::Entity(dst).to_string(),
            kind: format!("{kind:?}"),
        });
    }

    Some(LocateFileProvenance { objects, edges })
}

fn push_projection_reason(explain: &mut HashMap<String, Vec<String>>, path: &str, reason: String) {
    let reasons = explain.entry(path.to_string()).or_default();
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn build_followup_seed_hits(fused: &[(String, f32)]) -> HashMap<String, Vec<FileHit>> {
    let _span =
        tracing::info_span!("locate.build_followup_seed_hits", fused = fused.len()).entered();
    fused
        .iter()
        .take(locate_env_usize("KIN_LOCATE_FOLLOWUP_SEED_LIMIT", 5))
        .map(|(path, score)| {
            (
                path.clone(),
                vec![FileHit {
                    score: (*score * 1.2).max(1.0),
                    spans: vec![],
                }],
            )
        })
        .collect()
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
        combined.insert(file.clone(), rrf + raw * 0.05 + cross_bonus + graph_bonus);
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
            let source_bonus = if role_from_path(path) == EntityRole::Source { 1.2 } else { 1.0 };

            (path.clone(), mean * source_bonus)
        })
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked
}

fn adaptive_cap(
    fused: &[(String, f32)],
    all_hits: &[HashMap<String, Vec<FileHit>>],
    max_files: usize,
) -> Vec<(String, f32)> {
    let _span = tracing::info_span!(
        "locate.adaptive_cap",
        fused = fused.len(),
        signals = all_hits.len(),
        max_files = max_files
    )
    .entered();
    if fused.is_empty() {
        return vec![];
    }
    if fused.len() <= 1 {
        return fused.to_vec();
    }

    // ── Smart cluster expansion ──
    // Start with the top result. Keep absorbing the next result if:
    //   1. The gap ratio to the previous score is ≤ threshold (no cliff)
    //   2. The score is ≥ floor_pct of the top score (not negligible)
    // Stop at the first cliff — that's where signal ends and noise begins.
    //
    // This is the elbow method applied to retrieval cutoff. The cluster
    // grows dynamically based on the score distribution, not fixed counts.
    let gap_threshold = locate_env_f32("KIN_LOCATE_CLUSTER_GAP_THRESHOLD", 3.0);
    let floor_pct = locate_env_f32("KIN_LOCATE_CLUSTER_FLOOR_PCT", 0.05);

    let top_score = fused[0].1;
    let floor = top_score * floor_pct;
    let mut cluster_size = 1usize; // always include #1

    for i in 1..fused.len().min(max_files) {
        let score = fused[i].1;
        let prev_score = fused[i - 1].1;

        // Below the noise floor — stop
        if score <= 0.0 || score < floor {
            break;
        }

        // Cliff detected — the gap from prev to current is too large
        if prev_score > 0.0 && prev_score / score > gap_threshold {
            break;
        }

        cluster_size += 1;
    }

    // When max_files was explicitly requested, use it as a minimum — the caller
    // asked for that many files and the adaptive cap shouldn't second-guess them.
    // The cluster expansion still stops at cliffs, but we guarantee at least
    // max_files results if enough scored files exist.
    let cap = cluster_size.max(max_files).min(fused.len());
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

fn tracked_file_paths(graph: &kin_db::InMemoryGraph) -> HashSet<String> {
    let mut paths: HashSet<String> = graph
        .query_entities(&EntityFilter::default())
        .map(|entities| {
            entities
                .into_iter()
                .filter_map(|entity| entity.file_origin.map(|file| file.0))
                .collect()
        })
        .unwrap_or_default();

    for tracked in tracked_non_entity_files(graph) {
        paths.insert(tracked.path);
    }

    paths
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
        "test", "unittest", "pytest", "testing", "spec", "fixture",
        "mock", "stub", "failing test", "test case", "test suite",
        "broken test", "failing assertion", "test error",
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
        ".yaml", ".yml", ".xsd", ".dtd", ".xsl", ".xslt",
        ".po", ".pot", ".mo",
        ".json", ".toml", ".ini", ".cfg", ".conf",
        ".csv", ".tsv", ".xml",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot",
        ".pdf", ".doc", ".docx",
        ".txt", ".log",
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
            && (lower.contains("/cextern/") || lower.contains("/vendor/") || lower.contains("/extern/"))
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
            if test_query { 2 } else { 1 }
        }
        EntityRole::Test => {
            if test_query { 0 } else { 2 }
        }
        EntityRole::Docs => {
            if test_query { 2 } else { 2 }
        }
        EntityRole::Source => {
            if test_query { 1 } else { 0 }
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
    if is_test_by_role(path, entity) { penalty } else { 1.0 }
}

fn file_stem_lower(path: &str) -> Option<String> {
    let leaf = path.rsplit('/').next()?;
    let stem = leaf.split('.').next()?;
    if stem.is_empty() { return None; }
    Some(stem.to_ascii_lowercase())
}

fn is_generic_module_name(stem: &str) -> bool {
    matches!(
        stem,
        "core" | "base" | "utils" | "util" | "helpers" | "helper"
            | "common" | "misc" | "main" | "index" | "mod"
            | "__init__" | "types" | "constants" | "config"
    )
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
        "test",
        "snippet",
        "import",
        "error",
        "embedding",
        "co-change",
        "projection",
        "followup",
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

fn output_json(
    results: &[(String, f32)],
    all_hits: &[HashMap<String, Vec<FileHit>>],
    projection_explain: &HashMap<String, Vec<String>>,
    file_provenance: &HashMap<String, LocateFileProvenance>,
    explain: bool,
) {
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
        })
        .collect();

    let result = LocateResult { files };
    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_default()
    );
}

fn output_text(
    results: &[(String, f32)],
    all_hits: &[HashMap<String, Vec<FileHit>>],
    projection_explain: &HashMap<String, Vec<String>>,
    explain: bool,
) {
    if results.is_empty() {
        println!("No relevant files found.");
        return;
    }

    for (path, score) in results {
        let signals = collect_signals_for_file(path, all_hits);
        println!(
            "  {:<50} (score: {:.2}, signals: {})",
            path,
            score,
            signals.join(", ")
        );
        if explain {
            for reason in collect_explain_for_file(path, projection_explain, all_hits) {
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

        let capped = adaptive_cap(&fused, &all_hits, 10);
        assert_eq!(capped.len(), 1);
        assert_eq!(capped[0].0, "src/main.py");
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

        let capped = adaptive_cap(&fused, &all_hits, 10);
        assert!(capped.len() >= 4, "cap was {}", capped.len());
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
        assert!(!terms.iter().any(|term| term == "CodeSandbox"));
    }

    #[test]
    fn curate_search_terms_expands_to_source_entity_names() {
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

        assert!(terms.iter().any(|term| term == "useAutocomplete"));
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
    fn projection_signals_expand_from_seed_entities() {
        let dir = tempfile::tempdir().unwrap();
        let graph = kin_db::InMemoryGraph::with_text_index(dir.path().join("text-index"));

        let mut caller = test_entity("caller", "src/a.py", 1, 10);
        caller.metadata.extra.insert(
            "file_surface_context".into(),
            serde_json::Value::String("surface caller graph seed".into()),
        );
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

        let (hits, explain, provenance) = extract_projection_signals("`caller`", &graph).unwrap();
        assert!(hits.contains_key("src/a.py"));
        assert!(hits.contains_key("src/b.py"));
        assert!(explain
            .get("src/b.py")
            .unwrap_or(&Vec::new())
            .iter()
            .any(|reason| reason.contains("projected from entity `caller` via co-change")));
        let projected = provenance.get("src/b.py").unwrap();
        assert_eq!(projected.edges.len(), 1);
        assert_eq!(projected.objects.len(), 2);
    }

    #[test]
    fn collect_signals_names_cochange_label() {
        let all_hits = vec![
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(String::from("src/b.py"), hit(1.0))]),
            HashMap::new(),
        ];

        let signals = collect_signals_for_file("src/b.py", &all_hits);
        assert_eq!(signals, vec!["co-change".to_string()]);
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
