// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_db::{ResolvedRetrievalItem, RetrievalKey};
use kin_model::EntityStore;
use kin_model::{Entity, EntityFilter, EntityKind, LanguageId};
#[cfg(feature = "vector")]
use kin_model::{GraphStore, VerificationStore, Visibility};
use serde::{Deserialize, Serialize};
#[cfg(feature = "vector")]
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;

/// Resolve session id from KIN_SESSION_ID env var.
///
/// Optional: returns None if unset/empty (commands behave as if no scope).
fn resolve_session_id_opt() -> Option<String> {
    std::env::var("KIN_SESSION_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// If a session id is present, look up its active scope from the daemon and log it.
///
/// Returns the active scope (if any) for downstream observability. The daemon-side
/// consumption of session scope in query handlers is being added in parallel by
/// `daemon-scope-consumer`; until that lands, this surface only logs and does not
/// alter query results.
async fn announce_active_scope(
    layout: &kin_core::KinLayout,
    command: &str,
) -> Result<Option<crate::daemon_client::ScopeResponse>> {
    let Some(session_id) = resolve_session_id_opt() else {
        return Ok(None);
    };
    let Some(daemon_url) = crate::daemon_client::resolve_daemon_url(layout).await? else {
        return Ok(None);
    };
    let client = crate::daemon_client::DaemonClient::from_base_url(daemon_url)?;
    let scope = client.get_scope(&session_id).await?;
    if let Some(ref scope) = scope {
        eprintln!(
            "[kin {}] session={} scope={} (head={}, age={}s)",
            command,
            session_id,
            scope.ref_string,
            &scope.head[..12.min(scope.head.len())],
            scope.created_at_secs_ago
        );
    }
    Ok(scope)
}

#[cfg(feature = "vector")]
fn embedding_status_complete(status: &kin_db::EmbeddingStatus) -> bool {
    status.total == 0 || (status.indexed == status.total && status.pending == 0)
}

#[cfg(feature = "vector")]
fn env_flag_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(false)
}

/// Strict-coverage mode is OFF by default for `kin search --semantic` too:
/// users get graceful degradation. Benchmarks opt into the hard gate via
/// `KIN_REQUIRE_COMPLETE_EMBEDDINGS=1`; an explicit
/// `KIN_BYPASS_EMBEDDING_COVERAGE_CHECK=1` forces degradation even under strict.
#[cfg(feature = "vector")]
fn embedding_strict_mode() -> bool {
    env_flag_truthy("KIN_REQUIRE_COMPLETE_EMBEDDINGS")
        && !env_flag_truthy("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK")
}

/// Evaluate embedding coverage for a semantic search. Default behavior never
/// errors and returns a coverage report; strict (benchmark) behavior bails on
/// incomplete coverage exactly as before.
#[cfg(feature = "vector")]
fn evaluate_semantic_coverage(
    graph: &kin_db::InMemoryGraph,
) -> Result<crate::commands::locate::SemanticCoverage> {
    let status = graph.embedding_status();
    let complete = embedding_status_complete(&status);

    if !complete && embedding_strict_mode() {
        anyhow::bail!(
            "semantic search requires complete embeddings; graph has {}/{} indexed, {} unindexed, {} pending. Run `kin embed` until `kin status --json` reports embeddingsIndexed == embeddingsTotal and embeddingsPending == 0. (Set KIN_REQUIRE_COMPLETE_EMBEDDINGS=0 to allow graceful degradation.)",
            status.indexed,
            status.total,
            status.total.saturating_sub(status.indexed),
            status.pending
        );
    }

    let note = if complete {
        None
    } else {
        Some(format!(
            "semantic signal partial: {}/{} embedded, {} pending. Vector hits over what is embedded, plus text fallback; run `kin embed` for full semantic search.",
            status.indexed, status.total, status.pending
        ))
    };

    Ok(crate::commands::locate::SemanticCoverage {
        supported: true,
        indexed: status.indexed,
        total: status.total,
        pending: status.pending,
        complete,
        note,
    })
}

#[derive(Serialize)]
struct SearchJsonEntity {
    id: String,
    kind: String,
    name: String,
    file: String,
    line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<f32>,
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
}

#[derive(Serialize)]
struct SearchJsonArtifact {
    kind: String,
    file: String,
    artifact_kind: String,
    line: u32,
    preview: Option<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum SearchJsonRecord {
    Entity(SearchJsonEntity),
    Artifact(SearchJsonArtifact),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonSearchRequest {
    pub query: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub semantic: bool,
    #[serde(default)]
    pub show_body: bool,
    #[serde(default)]
    pub body_limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonSearchResponse {
    pub query: String,
    pub semantic: bool,
    #[serde(default)]
    pub text_fallback: bool,
    pub total_matches: usize,
    pub records: Vec<DaemonSearchRecord>,
    /// Embedding (semantic signal) coverage at query time. On partial/zero
    /// coverage `kin search --semantic` degrades gracefully (vector hits over
    /// whatever is embedded, plus text fallback) instead of erroring; this
    /// field reports the incompleteness honestly. `None` for non-semantic
    /// searches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_coverage: Option<crate::commands::locate::SemanticCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
pub enum DaemonSearchRecord {
    Entity(DaemonSearchEntityRecord),
    Artifact(DaemonSearchArtifactRecord),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonSearchEntityRecord {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub language: String,
    pub file: Option<String>,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    pub start_byte: Option<usize>,
    pub end_byte: Option<usize>,
    pub signature: Option<String>,
    pub score: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub body_omitted_line_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonSearchArtifactRecord {
    pub title: String,
    pub context: String,
    pub file: Option<String>,
    pub artifact_kind: String,
    pub line: u32,
    pub preview: Option<String>,
    pub score: Option<f32>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Clone)]
enum SearchRecord {
    Entity(Entity),
    Resolved {
        key: RetrievalKey,
        item: ResolvedRetrievalItem,
    },
}

impl SearchRecord {
    /// Identity used to collapse search hits to one row per result.
    ///
    /// Whenever a record resolves to an entity we key on the entity id, so the
    /// multiple embedding records a single entity can own (e.g. chunked
    /// embeddings, or a vector hit plus a text hit) collapse to a single row
    /// instead of one row per retrieval key. Only genuinely entity-less
    /// artifacts fall back to the retrieval-key string, where one key really is
    /// one result.
    fn dedupe_key(&self) -> String {
        if let Some(entity) = record_entity(self) {
            return entity.id.to_string();
        }
        match self {
            SearchRecord::Entity(entity) => entity.id.to_string(),
            SearchRecord::Resolved { key, .. } => retrieval_key_string(key),
        }
    }
}

pub async fn run(
    pattern: String,
    kind: Option<String>,
    language: Option<String>,
    show_body: bool,
    body_limit: Option<usize>,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let _scope = announce_active_scope(&layout, "search").await?;

    let kind_ref = kind.as_deref();
    let sub_patterns: Vec<&str> = pattern
        .split('|')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    enforce_precise_search_mode(&pattern, &sub_patterns, kind_ref, show_body, body_limit)?;

    let response = run_daemon_search(
        &layout,
        &DaemonSearchRequest {
            query: pattern,
            kind,
            language,
            limit: None,
            semantic: false,
            show_body,
            body_limit,
        },
    )
    .await?;
    render_daemon_search_response(&layout, &response, show_body, body_limit)
}

pub async fn run_json(
    pattern: String,
    kind: Option<String>,
    language: Option<String>,
    _show_body: bool,
    _body_limit: Option<usize>,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let _scope = announce_active_scope(&layout, "search").await?;

    let response = run_daemon_search(
        &layout,
        &DaemonSearchRequest {
            query: pattern,
            kind,
            language,
            limit: None,
            semantic: false,
            show_body: _show_body,
            body_limit: _body_limit,
        },
    )
    .await?;
    let payload = response
        .records
        .iter()
        .map(daemon_record_to_json)
        .collect::<Vec<_>>();
    println!("{}", serde_json::to_string(&payload)?);
    Ok(())
}

#[cfg(not(feature = "vector"))]
pub async fn run_semantic(
    query: String,
    kind: Option<String>,
    language: Option<String>,
    limit: usize,
) -> anyhow::Result<()> {
    run_semantic_daemon(query, kind, language, limit).await
}

#[cfg(feature = "vector")]
pub async fn run_semantic(
    query: String,
    kind: Option<String>,
    language: Option<String>,
    limit: usize,
) -> Result<()> {
    run_semantic_daemon(query, kind, language, limit).await
}

#[cfg(not(feature = "vector"))]
pub async fn run_semantic_json(
    query: String,
    kind: Option<String>,
    language: Option<String>,
    limit: usize,
) -> anyhow::Result<()> {
    run_semantic_daemon_json(query, kind, language, limit).await
}

#[cfg(feature = "vector")]
pub async fn run_semantic_json(
    query: String,
    kind: Option<String>,
    language: Option<String>,
    limit: usize,
) -> Result<()> {
    run_semantic_daemon_json(query, kind, language, limit).await
}

async fn run_semantic_daemon(
    query: String,
    kind: Option<String>,
    language: Option<String>,
    limit: usize,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _scope = announce_active_scope(&layout, "search --semantic").await?;
    let response = run_daemon_search(
        &layout,
        &DaemonSearchRequest {
            query,
            kind,
            language,
            limit: Some(limit),
            semantic: true,
            show_body: false,
            body_limit: Some(limit),
        },
    )
    .await?;
    render_daemon_search_response(&layout, &response, false, Some(limit))
}

async fn run_semantic_daemon_json(
    query: String,
    kind: Option<String>,
    language: Option<String>,
    limit: usize,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _scope = announce_active_scope(&layout, "search --semantic --json").await?;
    let response = run_daemon_search(
        &layout,
        &DaemonSearchRequest {
            query,
            kind,
            language,
            limit: Some(limit),
            semantic: true,
            show_body: false,
            body_limit: Some(limit),
        },
    )
    .await?;
    let payload: Vec<_> = response.records.iter().map(daemon_record_to_json).collect();
    println!("{}", serde_json::to_string(&payload)?);
    Ok(())
}

async fn run_daemon_search(
    layout: &kin_core::KinLayout,
    request: &DaemonSearchRequest,
) -> Result<DaemonSearchResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for search but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.search(request).await.context("daemon search failed")
}

pub fn collect_daemon_search_response(
    graph: &kin_db::InMemoryGraph,
    request: &DaemonSearchRequest,
) -> Result<DaemonSearchResponse> {
    if request.semantic {
        return collect_daemon_semantic_search_response(graph, request);
    }

    let results = collect_search_results(
        graph,
        &request.query,
        request.kind.as_deref(),
        request.language.as_deref(),
    )?;
    let records = results
        .iter()
        .map(|record| record_to_daemon_record(record, None))
        .collect::<Vec<_>>();
    Ok(DaemonSearchResponse {
        query: request.query.clone(),
        semantic: false,
        text_fallback: false,
        total_matches: records.len(),
        records,
        semantic_coverage: None,
    })
}

#[cfg(not(feature = "vector"))]
fn collect_daemon_semantic_search_response(
    graph: &kin_db::InMemoryGraph,
    request: &DaemonSearchRequest,
) -> Result<DaemonSearchResponse> {
    let _ = graph;
    let _ = request;
    anyhow::bail!("semantic search requires vector-enabled Kin embeddings")
}

#[cfg(feature = "vector")]
fn collect_daemon_semantic_search_response(
    graph: &kin_db::InMemoryGraph,
    request: &DaemonSearchRequest,
) -> Result<DaemonSearchResponse> {
    let coverage = evaluate_semantic_coverage(graph)?;
    let limit = request.limit.unwrap_or(10);
    let vector_results = graph.semantic_search(&request.query, limit)?;

    if vector_results.is_empty() {
        let mut response = collect_daemon_search_response(
            graph,
            &DaemonSearchRequest {
                semantic: false,
                show_body: false,
                body_limit: None,
                ..request.clone()
            },
        )?;
        response.semantic = true;
        response.text_fallback = true;
        response.semantic_coverage = Some(coverage);
        return Ok(response);
    }

    let kind_ref = request.kind.as_deref();
    let kinds = kind_ref.and_then(parse_kinds);
    let languages = request.language.as_deref().and_then(parse_language);
    let role_filter = parse_role_filter(kind_ref);

    let mut raw_hits: Vec<kin_ranking::RawHit> = Vec::new();
    let mut item_map: HashMap<String, SearchRecord> = HashMap::new();
    let mut seen_ids: HashSet<String> = HashSet::new();

    for (retrieval_key, distance) in &vector_results {
        let Some(record) = resolve_retrieval_record(graph, *retrieval_key) else {
            continue;
        };
        if !record_matches_semantic_filters(
            &record,
            kinds.as_ref(),
            languages.as_ref(),
            role_filter,
        ) {
            continue;
        }
        // Key by entity identity (via `dedupe_key`) so several embedding
        // records for one entity collapse to a single row. When a duplicate
        // arrives, keep the best (smallest) cosine distance so ranking sees the
        // strongest semantic signal for that entity rather than an arbitrary one.
        let id_str = record.dedupe_key();
        if seen_ids.contains(&id_str) {
            if let Some(hit) = raw_hits.iter_mut().find(|h| h.entity_id == id_str) {
                if hit
                    .cosine_distance
                    .is_none_or(|existing| *distance < existing)
                {
                    hit.cosine_distance = Some(*distance);
                }
            }
            continue;
        }
        raw_hits.push(build_semantic_raw_hit(
            graph,
            &record,
            None,
            Some(*distance),
        )?);
        seen_ids.insert(id_str.clone());
        item_map.insert(id_str, record);
    }

    let text_hits = graph.text_search(&request.query, limit * 2)?;
    for (retrieval_key, bm25_score) in &text_hits {
        let Some(record) = resolve_retrieval_record(graph, *retrieval_key) else {
            continue;
        };
        if !record_matches_semantic_filters(
            &record,
            kinds.as_ref(),
            languages.as_ref(),
            role_filter,
        ) {
            continue;
        }
        // Same entity identity as the vector loop, so a text hit for an entity
        // already found semantically merges its lexical signal onto the existing
        // row instead of producing a second one. Keep the strongest bm25 when an
        // entity owns multiple text records.
        let id_str = record.dedupe_key();
        if seen_ids.contains(&id_str) {
            if let Some(hit) = raw_hits.iter_mut().find(|h| h.entity_id == id_str) {
                if hit.bm25_score.is_none_or(|existing| *bm25_score > existing) {
                    hit.bm25_score = Some(*bm25_score);
                }
            }
            continue;
        }
        raw_hits.push(build_semantic_raw_hit(
            graph,
            &record,
            Some(*bm25_score),
            None,
        )?);
        seen_ids.insert(id_str.clone());
        item_map.insert(id_str, record);
    }

    let search_query = kin_ranking::SearchQuery {
        text: request.query.clone(),
        require_proof: false,
        limit,
    };
    let ranked = kin_ranking::rank_raw_hits(&search_query, &raw_hits);
    let mut records = Vec::new();
    for result in &ranked {
        if let Some(record) = item_map.get(&result.id) {
            records.push(record_to_daemon_record(record, Some(result.score)));
        }
    }

    Ok(DaemonSearchResponse {
        query: request.query.clone(),
        semantic: true,
        text_fallback: false,
        total_matches: records.len(),
        records,
        semantic_coverage: Some(coverage),
    })
}

fn collect_search_results(
    graph: &kin_db::InMemoryGraph,
    pattern: &str,
    kind: Option<&str>,
    language: Option<&str>,
) -> Result<Vec<SearchRecord>> {
    let kinds = kind.and_then(parse_kinds);
    let languages = language.and_then(parse_language);
    // "test" is role-based, not kind-based (parsers never emit EntityKind::Test)
    let role_filter = parse_role_filter(kind);

    if pattern.trim().is_empty() {
        let mut all = graph.list_all_entities()?;
        all.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.0.cmp(&right.id.0)));
        if let Some(ref ks) = kinds {
            all.retain(|entity| ks.contains(&entity.kind));
        }
        if let Some(required_role) = role_filter {
            all.retain(|entity| entity.role == required_role);
        }
        if let Some(ref lang) = languages {
            all.retain(|entity| entity.language == *lang);
        }
        return Ok(all.into_iter().map(SearchRecord::Entity).collect());
    }

    let sub_patterns: Vec<&str> = pattern
        .split('|')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for sub in &sub_patterns {
        let filter = EntityFilter {
            name_pattern: Some(sub.to_string()),
            kinds: kinds.clone(),
            languages: languages.as_ref().map(|l| vec![*l]),
            roles: role_filter.map(|role| vec![role]),
            ..Default::default()
        };
        for entity in graph.query_entities(&filter)? {
            if seen.insert(entity.id.to_string()) {
                results.push(SearchRecord::Entity(entity));
            }
        }
    }

    // Full-text search fallback for JSON path too
    if results.len() < 5 {
        let text_hits = graph.text_search(pattern, 20)?;
        for (retrieval_key, _score) in text_hits {
            let Some(record) = resolve_retrieval_record(graph, retrieval_key) else {
                continue;
            };
            if record_matches_semantic_filters(
                &record,
                kinds.as_ref(),
                languages.as_ref(),
                role_filter,
            ) {
                // Dedupe by entity identity (`dedupe_key`) so a text hit for an
                // entity already matched by name above does not add a second
                // row, and multiple embedding records for one entity collapse.
                if seen.insert(record.dedupe_key()) {
                    results.push(record);
                }
            }
        }
    }

    if pattern.trim().is_empty() {
        results.sort_by_key(record_sort_key);
    }
    Ok(results)
}

#[cfg(feature = "vector")]
fn build_semantic_raw_hit(
    graph: &kin_db::InMemoryGraph,
    record: &SearchRecord,
    bm25_score: Option<f32>,
    cosine_distance: Option<f32>,
) -> Result<kin_ranking::RawHit> {
    let (entity_name, relation_count, proof_score, provenance_score) =
        if let Some(entity) = record_entity(record) {
            let relation_count = graph.get_all_relations_for_entity(&entity.id)?.len() as f32;
            let proof_count = graph.get_tests_for_entity(&entity.id)?.len() as f32;
            let proof_score = (proof_count / 3.0).min(1.0);
            let provenance_score = entity_provenance_signal(graph, entity)?;
            (
                entity.name.clone(),
                relation_count,
                proof_score,
                provenance_score,
            )
        } else {
            (record_display_title(record), 0.0, 0.0, 0.0)
        };

    Ok(kin_ranking::RawHit {
        entity_id: record.dedupe_key(),
        entity_name,
        bm25_score,
        cosine_distance,
        graph_score: Some(relation_count),
        proof_score: Some(proof_score),
        provenance_score: Some(provenance_score),
    })
}

#[cfg(feature = "vector")]
fn entity_provenance_signal(graph: &impl GraphStore, entity: &Entity) -> Result<f32> {
    let mut score: f32 = match entity.visibility {
        Visibility::Public => 1.0,
        Visibility::Internal | Visibility::Crate => 0.75,
        Visibility::Private => 0.55,
    };

    if let Some(path) = entity
        .file_origin
        .as_ref()
        .map(|origin| origin.0.to_ascii_lowercase())
    {
        if looks_non_production_path(&path) {
            score *= 0.35;
        }
    }

    if let Some(change_id) = entity.created_in.as_ref() {
        let approvals = graph.get_approvals_for_change(change_id)?;
        if !approvals.is_empty() {
            score = score.max(0.9);
        }
    }

    Ok(score.clamp(0.0, 1.0))
}

#[cfg(feature = "vector")]
fn looks_non_production_path(path: &str) -> bool {
    let markers = [
        "/test/",
        "/tests/",
        "/spec/",
        "/specs/",
        "/fixture/",
        "/fixtures/",
        "/example/",
        "/examples/",
        "/bench/",
        "/benches/",
        "__tests__",
    ];

    markers.iter().any(|marker| path.contains(marker))
        || path.ends_with("_test.rs")
        || path.ends_with(".spec.ts")
        || path.ends_with(".spec.tsx")
        || path.ends_with(".test.ts")
        || path.ends_with(".test.tsx")
        || path.ends_with(".spec.js")
        || path.ends_with(".test.js")
}

fn daemon_record_to_json(record: &DaemonSearchRecord) -> SearchJsonRecord {
    match record {
        DaemonSearchRecord::Entity(entity) => SearchJsonRecord::Entity(SearchJsonEntity {
            id: entity.id.clone(),
            kind: entity.kind.clone(),
            name: entity.name.clone(),
            file: entity.file.clone().unwrap_or_default(),
            line: entity.start_line.unwrap_or(1),
            end_line: entity.end_line,
            score: entity.score,
            signature: entity.signature.clone(),
            body: entity.body.clone(),
        }),
        DaemonSearchRecord::Artifact(artifact) => SearchJsonRecord::Artifact(SearchJsonArtifact {
            kind: "Artifact".to_string(),
            file: artifact.file.clone().unwrap_or_default(),
            artifact_kind: artifact.artifact_kind.clone(),
            line: artifact.line,
            preview: artifact.preview.clone(),
        }),
    }
}

fn record_to_daemon_record(record: &SearchRecord, score: Option<f32>) -> DaemonSearchRecord {
    match record {
        SearchRecord::Entity(entity) => {
            DaemonSearchRecord::Entity(entity_to_daemon_record(entity, score))
        }
        SearchRecord::Resolved {
            item: ResolvedRetrievalItem::Entity(entity),
            ..
        } => DaemonSearchRecord::Entity(entity_to_daemon_record(entity, score)),
        SearchRecord::Resolved { item, .. } => {
            DaemonSearchRecord::Artifact(resolved_item_to_daemon_record(item, score))
        }
    }
}

fn entity_to_daemon_record(entity: &Entity, score: Option<f32>) -> DaemonSearchEntityRecord {
    let span = entity.span.as_ref();
    DaemonSearchEntityRecord {
        id: entity.id.to_string(),
        name: entity.name.clone(),
        kind: format!("{:?}", entity.kind),
        language: entity.language.to_string(),
        file: entity.file_origin.as_ref().map(|f| f.0.clone()),
        start_line: span.map(|span| span.start_line),
        end_line: span.map(|span| span.end_line),
        start_byte: span.map(|span| span.start_byte),
        end_byte: span.map(|span| span.end_byte),
        signature: (!entity.signature.is_empty()).then(|| entity.signature.clone()),
        score,
        body: None,
        body_omitted_line_count: 0,
    }
}

fn resolved_item_to_daemon_record(
    item: &ResolvedRetrievalItem,
    score: Option<f32>,
) -> DaemonSearchArtifactRecord {
    let file = item.file_path().map(|f| f.0);
    match item {
        ResolvedRetrievalItem::Entity(entity) => DaemonSearchArtifactRecord {
            title: entity.name.clone(),
            context: format!("{:?}, {}", entity.kind, entity.language),
            file,
            artifact_kind: "entity".to_string(),
            line: entity
                .span
                .as_ref()
                .map(|span| span.start_line)
                .unwrap_or(1),
            preview: entity
                .doc_summary
                .clone()
                .filter(|summary| !summary.trim().is_empty()),
            score,
        },
        ResolvedRetrievalItem::ShallowFile(file_item) => DaemonSearchArtifactRecord {
            title: file_display_name(&file_item.file_id.0),
            context: format!("ShallowSyntax, {}", file_item.language_hint),
            file,
            artifact_kind: format!("shallow:{}", file_item.language_hint),
            line: 1,
            preview: if file_item.declaration_names.is_empty() && file_item.import_paths.is_empty()
            {
                None
            } else {
                Some(format!(
                    "declarations={} imports={}",
                    file_item.declaration_names.join(", "),
                    file_item.import_paths.join(", ")
                ))
            },
            score,
        },
        ResolvedRetrievalItem::StructuredArtifact(artifact) => DaemonSearchArtifactRecord {
            title: file_display_name(&artifact.file_id.0),
            context: format!("StructuredArtifact, {:?}", artifact.kind),
            file,
            artifact_kind: format!("{:?}", artifact.kind),
            line: 1,
            preview: artifact.text_preview.clone(),
            score,
        },
        ResolvedRetrievalItem::OpaqueArtifact(artifact) => DaemonSearchArtifactRecord {
            title: file_display_name(&artifact.file_id.0),
            context: format!(
                "OpaqueArtifact, {}",
                artifact.mime_type.as_deref().unwrap_or("opaque")
            ),
            file,
            artifact_kind: artifact
                .mime_type
                .clone()
                .unwrap_or_else(|| "opaque".to_string()),
            line: 1,
            preview: artifact.text_preview.clone(),
            score,
        },
    }
}

fn resolve_retrieval_record(
    graph: &kin_db::InMemoryGraph,
    key: RetrievalKey,
) -> Option<SearchRecord> {
    graph
        .resolve_retrieval_key(&key)
        .map(|item| SearchRecord::Resolved { key, item })
}

fn record_matches_semantic_filters(
    record: &SearchRecord,
    kinds: Option<&Vec<EntityKind>>,
    language: Option<&LanguageId>,
    role_filter: Option<kin_model::EntityRole>,
) -> bool {
    match record_entity(record) {
        Some(entity) => {
            if let Some(allowed_kinds) = kinds {
                if !allowed_kinds.contains(&entity.kind) {
                    return false;
                }
            }
            if let Some(allowed_language) = language {
                if entity.language != *allowed_language {
                    return false;
                }
            }
            if let Some(required_role) = role_filter {
                if entity.role != required_role {
                    return false;
                }
            }
            true
        }
        None => kinds.is_none() && language.is_none() && role_filter.is_none(),
    }
}

fn record_entity(record: &SearchRecord) -> Option<&Entity> {
    match record {
        SearchRecord::Entity(entity) => Some(entity),
        SearchRecord::Resolved {
            item: ResolvedRetrievalItem::Entity(entity),
            ..
        } => Some(entity),
        _ => None,
    }
}

#[cfg(feature = "vector")]
fn record_display_title(record: &SearchRecord) -> String {
    match record {
        SearchRecord::Entity(entity) => entity.name.clone(),
        SearchRecord::Resolved { item, .. } => match item {
            ResolvedRetrievalItem::Entity(entity) => entity.name.clone(),
            ResolvedRetrievalItem::ShallowFile(file) => file_display_name(&file.file_id.0),
            ResolvedRetrievalItem::StructuredArtifact(artifact) => {
                file_display_name(&artifact.file_id.0)
            }
            ResolvedRetrievalItem::OpaqueArtifact(artifact) => {
                file_display_name(&artifact.file_id.0)
            }
        },
    }
}

fn file_display_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(path)
        .to_string()
}

#[cfg(test)]
fn record_display_context(record: &SearchRecord) -> String {
    match record {
        SearchRecord::Entity(entity) => format!("{:?}, {}", entity.kind, entity.language),
        SearchRecord::Resolved { item, .. } => match item {
            ResolvedRetrievalItem::Entity(entity) => {
                format!("{:?}, {}", entity.kind, entity.language)
            }
            ResolvedRetrievalItem::ShallowFile(file) => {
                format!("ShallowSyntax, {}", file.language_hint)
            }
            ResolvedRetrievalItem::StructuredArtifact(artifact) => {
                format!("StructuredArtifact, {:?}", artifact.kind)
            }
            ResolvedRetrievalItem::OpaqueArtifact(artifact) => format!(
                "OpaqueArtifact, {}",
                artifact.mime_type.as_deref().unwrap_or("opaque")
            ),
        },
    }
}

#[cfg(test)]
fn record_preview(item: &ResolvedRetrievalItem) -> Option<String> {
    match item {
        ResolvedRetrievalItem::Entity(entity) => entity
            .doc_summary
            .clone()
            .filter(|summary| !summary.trim().is_empty()),
        ResolvedRetrievalItem::ShallowFile(file) => {
            if file.declaration_names.is_empty() && file.import_paths.is_empty() {
                None
            } else {
                Some(format!(
                    "declarations={} imports={}",
                    file.declaration_names.join(", "),
                    file.import_paths.join(", ")
                ))
            }
        }
        ResolvedRetrievalItem::StructuredArtifact(artifact) => artifact.text_preview.clone(),
        ResolvedRetrievalItem::OpaqueArtifact(artifact) => artifact.text_preview.clone(),
    }
}

fn record_sort_key(record: &SearchRecord) -> (String, String, String) {
    match record {
        SearchRecord::Entity(entity) => (
            entity.name.clone(),
            entity
                .file_origin
                .as_ref()
                .map(|f| f.0.clone())
                .unwrap_or_default(),
            entity.id.to_string(),
        ),
        SearchRecord::Resolved { item, .. } => match item {
            ResolvedRetrievalItem::Entity(entity) => (
                entity.name.clone(),
                entity
                    .file_origin
                    .as_ref()
                    .map(|f| f.0.clone())
                    .unwrap_or_default(),
                entity.id.to_string(),
            ),
            ResolvedRetrievalItem::ShallowFile(file) => (
                format!("ShallowSyntax({})", file.language_hint),
                file.file_id.0.clone(),
                file.file_id.0.clone(),
            ),
            ResolvedRetrievalItem::StructuredArtifact(artifact) => (
                format!("Artifact({:?})", artifact.kind),
                artifact.file_id.0.clone(),
                artifact.file_id.0.clone(),
            ),
            ResolvedRetrievalItem::OpaqueArtifact(artifact) => (
                format!(
                    "OpaqueArtifact({})",
                    artifact.mime_type.as_deref().unwrap_or("opaque")
                ),
                artifact.file_id.0.clone(),
                artifact.file_id.0.clone(),
            ),
        },
    }
}

fn retrieval_key_string(key: &RetrievalKey) -> String {
    serde_json::to_string(key).unwrap_or_else(|_| format!("{:?}", key))
}

fn render_daemon_search_response(
    layout: &kin_core::KinLayout,
    response: &DaemonSearchResponse,
    show_body: bool,
    body_limit: Option<usize>,
) -> Result<()> {
    if response.records.is_empty() {
        if response.semantic {
            println!("No matches for '{}'", response.query);
        } else {
            println!("No results matching '{}'", response.query);
        }
        return Ok(());
    }

    if response.semantic && response.text_fallback {
        println!(
            "No vector matches for '{}'; using graph text search fallback:",
            response.query
        );
    }

    if show_body {
        println!("Found {} results:", response.records.len());
        for record in &response.records {
            match record {
                DaemonSearchRecord::Entity(entity) => {
                    let file_str = entity
                        .file
                        .as_deref()
                        .map(|file| display_read_path(layout, file))
                        .unwrap_or_else(|| "unknown".to_string());
                    let line_num = entity.start_line.unwrap_or(0);
                    println!(
                        "{} ({}) @ {}:{}",
                        entity.name, entity.kind, file_str, line_num
                    );
                    if let Some(body) = entity.body.as_deref() {
                        for line in body.lines() {
                            println!("{}", line);
                        }
                        if entity.body_omitted_line_count > 0 {
                            println!("  ...(+{} lines)", entity.body_omitted_line_count);
                        }
                    }
                }
                DaemonSearchRecord::Artifact(artifact) => {
                    println!(
                        "{} ({}) - {}",
                        artifact.title,
                        artifact.context,
                        artifact
                            .file
                            .as_deref()
                            .map(|file| display_read_path(layout, file))
                            .unwrap_or_else(|| "no file".to_string())
                    );
                    if let Some(preview) = artifact.preview.as_deref() {
                        let max_lines = body_limit.unwrap_or(10);
                        for line in preview.lines().take(max_lines) {
                            println!("{}", line);
                        }
                        let line_count = preview.lines().count();
                        if line_count > max_lines {
                            println!("  ...(+{} lines)", line_count - max_lines);
                        }
                    }
                }
            }
        }
    } else {
        if response.semantic && !response.text_fallback {
            println!("Semantic matches for '{}':", response.query);
        } else {
            println!("Found {} results:", response.records.len());
        }
        for record in &response.records {
            match record {
                DaemonSearchRecord::Entity(entity) => {
                    if response.semantic && !response.text_fallback {
                        println!(
                            "  {:.3}  {} ({}, {}) - {}",
                            entity.score.unwrap_or(0.0),
                            entity.name,
                            entity.kind,
                            entity.language,
                            entity
                                .file
                                .as_deref()
                                .map(|file| display_read_path(layout, file))
                                .unwrap_or_else(|| "no file".to_string())
                        );
                    } else {
                        println!(
                            "  {} ({}, {}) - {}",
                            entity.name,
                            entity.kind,
                            entity.language,
                            entity
                                .file
                                .as_deref()
                                .map(|file| display_read_path(layout, file))
                                .unwrap_or_else(|| "no file".to_string())
                        );
                    }
                }
                DaemonSearchRecord::Artifact(artifact) => {
                    if response.semantic && !response.text_fallback {
                        println!(
                            "  {:.3}  {} ({}) - {}",
                            artifact.score.unwrap_or(0.0),
                            artifact.title,
                            artifact.context,
                            artifact
                                .file
                                .as_deref()
                                .map(|file| display_read_path(layout, file))
                                .unwrap_or_else(|| "no file".to_string())
                        );
                    } else {
                        println!(
                            "  {} ({}) - {}",
                            artifact.title,
                            artifact.context,
                            artifact
                                .file
                                .as_deref()
                                .map(|file| display_read_path(layout, file))
                                .unwrap_or_else(|| "no file".to_string())
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

fn enforce_precise_search_mode(
    pattern: &str,
    sub_patterns: &[&str],
    kind: Option<&str>,
    show_body: bool,
    body_limit: Option<usize>,
) -> Result<()> {
    let precise = matches!(
        std::env::var("KIN_SEARCH_MODE").ok().as_deref(),
        Some("precise")
    );
    if !precise || !show_body {
        return Ok(());
    }

    if body_limit.unwrap_or(5) > 5 {
        anyhow::bail!(
            "precise native search: `--show-body` is limited to `--limit 5`. Use `kin trace <ExactName>` first, or narrow with `--kind`."
        );
    }

    if sub_patterns.len() > 2 {
        anyhow::bail!(
            "precise native search: too many OR terms in `{}`. Use at most two exact names, or start with `kin trace <ExactName>`.",
            pattern
        );
    }

    let has_kind = kind.is_some();
    if let Some(bad) = sub_patterns
        .iter()
        .find(|sub| !looks_precise_name(sub, has_kind))
    {
        anyhow::bail!(
            "precise native search: `{}` is too broad for `--show-body`. Use an exact symbol like `MyString`, `$MyType`, `Router::route`, or add `--kind`.",
            bad
        );
    }

    Ok(())
}

fn looks_precise_name(pattern: &str, has_kind: bool) -> bool {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return false;
    }

    if trimmed.contains("::")
        || trimmed.contains('.')
        || trimmed.contains('/')
        || trimmed.contains('$')
    {
        return true;
    }

    let mut chars = trimmed.chars();
    if let Some(first) = chars.next() {
        if first.is_uppercase() {
            return true;
        }
    }

    if trimmed
        .chars()
        .skip(1)
        .any(|c| c.is_uppercase() || c.is_ascii_digit())
    {
        return true;
    }

    let len = trimmed.chars().count();
    if has_kind && len >= 6 {
        return true;
    }

    len >= 10
}

fn display_read_path(_layout: &kin_core::KinLayout, rel_path: &str) -> String {
    rel_path.to_string()
}

fn parse_kinds(s: &str) -> Option<Vec<EntityKind>> {
    match s.to_lowercase().as_str() {
        "function" | "fn" => Some(vec![EntityKind::Function, EntityKind::Method]),
        "class" => Some(vec![EntityKind::Class]),
        "interface" => Some(vec![EntityKind::Interface]),
        "trait" => Some(vec![EntityKind::TraitDef]),
        "type" => Some(vec![EntityKind::TypeAlias]),
        "module" | "mod" => Some(vec![EntityKind::Module]),
        // "test" is role-based, not kind-based. Return None here;
        // role filtering is handled separately in record_matches_semantic_filters.
        "test" => None,
        "method" => Some(vec![EntityKind::Method]),
        "enum" => Some(vec![EntityKind::EnumDef]),
        "const" => Some(vec![EntityKind::Constant]),
        _ => None,
    }
}

fn parse_role_filter(kind: Option<&str>) -> Option<kin_model::EntityRole> {
    match kind {
        Some(k) if k.eq_ignore_ascii_case("test") => Some(kin_model::EntityRole::Test),
        _ => None,
    }
}

fn parse_language(s: &str) -> Option<LanguageId> {
    match s.to_lowercase().as_str() {
        "typescript" | "ts" => Some(LanguageId::TypeScript),
        "javascript" | "js" => Some(LanguageId::JavaScript),
        "python" | "py" => Some(LanguageId::Python),
        "go" => Some(LanguageId::Go),
        "java" => Some(LanguageId::Java),
        "rust" | "rs" => Some(LanguageId::Rust),
        "c" => Some(LanguageId::C),
        "cpp" | "c++" | "hpp" | "cc" | "cxx" => Some(LanguageId::Cpp),
        "csharp" | "c#" | "cs" => Some(LanguageId::CSharp),
        "ruby" | "rb" => Some(LanguageId::Ruby),
        "kotlin" | "kt" | "kts" => Some(LanguageId::Kotlin),
        "hcl" | "terraform" | "tf" => Some(LanguageId::Hcl),
        _ => None,
    }
}

#[cfg(test)]
// Test fixtures construct artifact RetrievalKeys by path to assert on context
// rendering; graph-assigned IDs are path-derived for these in-test records, so
// the deprecated path constructor is the correct fixture tool here.
mod tests {
    use super::{
        enforce_precise_search_mode, looks_precise_name, parse_kinds, record_display_context,
        record_preview, SearchRecord,
    };
    use kin_db::ResolvedRetrievalItem;
    use kin_model::{
        ArtifactId, ArtifactKind, Entity, EntityId, EntityKind, EntityMetadata, EntityRevisionId,
        EntityRole, FilePathId, FingerprintAlgorithm, Hash256, LanguageId, OpaqueArtifact,
        RetrievalKey, SemanticFingerprint, ShallowTrackedFile, SourceSpan, StructuredArtifact,
        Visibility,
    };
    use serial_test::serial;

    /// Minimal source-function entity for dedupe-identity tests.
    fn dedupe_test_entity(name: &str, path: &str) -> Entity {
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
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(path)),
            span: Some(SourceSpan {
                file: FilePathId::new(path),
                start_byte: 0,
                end_byte: 0,
                start_line: 1,
                start_col: 1,
                end_line: 2,
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

    #[test]
    fn search_json_entity_carries_score_and_span() {
        use super::{
            daemon_record_to_json, DaemonSearchEntityRecord, DaemonSearchRecord, SearchJsonRecord,
        };
        let rec = DaemonSearchRecord::Entity(DaemonSearchEntityRecord {
            id: "e1".into(),
            name: "handler".into(),
            kind: "function".into(),
            language: "rust".into(),
            file: Some("src/handler.rs".into()),
            start_line: Some(10),
            end_line: Some(20),
            start_byte: None,
            end_byte: None,
            signature: Some("fn handler()".into()),
            score: Some(0.87),
            body: None,
            body_omitted_line_count: 0,
        });
        let SearchJsonRecord::Entity(entity) = daemon_record_to_json(&rec) else {
            panic!("expected entity record");
        };
        let json = serde_json::to_value(&entity).expect("serialize");
        // Agent surfaces must carry the span end and confidence, not just the start line.
        assert_eq!(json["line"].as_u64(), Some(10));
        assert_eq!(json["end_line"].as_u64(), Some(20));
        assert!((json["score"].as_f64().unwrap() - 0.87).abs() < 1e-6);
    }

    #[test]
    fn dedupe_key_collapses_multiple_embedding_records_for_one_entity() {
        // Regression: the vector and text indexes can hold several retrieval
        // keys for one entity (the entity itself plus one or more of its
        // revisions), so `semantic_search` can return more than one record per
        // entity. Before the fix each distinct retrieval key produced its own
        // row; now every record that resolves to a given entity must collapse to
        // a single dedupe identity — one entity, one search row.
        let entity = dedupe_test_entity("handler", "src/handler.rs");

        let by_entity = SearchRecord::Resolved {
            key: RetrievalKey::Entity(entity.id),
            item: ResolvedRetrievalItem::Entity(entity.clone()),
        };
        let by_revision = SearchRecord::Resolved {
            key: RetrievalKey::EntityRevision(EntityRevisionId::from_hash(Hash256::from_bytes(
                [9; 32],
            ))),
            item: ResolvedRetrievalItem::Entity(entity.clone()),
        };

        assert_eq!(
            by_entity.dedupe_key(),
            by_revision.dedupe_key(),
            "two embedding records for one entity must share a dedupe identity"
        );
        assert_eq!(by_entity.dedupe_key(), entity.id.to_string());

        // A genuinely different entity keeps a distinct identity (no
        // over-collapse that would hide real results).
        let other = dedupe_test_entity("other", "src/other.rs");
        let other_record = SearchRecord::Resolved {
            key: RetrievalKey::Entity(other.id),
            item: ResolvedRetrievalItem::Entity(other),
        };
        assert_ne!(by_entity.dedupe_key(), other_record.dedupe_key());
    }

    #[test]
    fn function_kind_includes_methods() {
        let kinds = parse_kinds("function").unwrap();
        assert!(kinds.contains(&EntityKind::Function));
        assert!(kinds.contains(&EntityKind::Method));
    }

    #[test]
    fn method_kind_is_specific() {
        let kinds = parse_kinds("method").unwrap();
        assert_eq!(kinds, vec![EntityKind::Method]);
    }

    #[test]
    fn precise_mode_accepts_exact_symbol_names() {
        assert!(looks_precise_name("MyString", false));
        assert!(looks_precise_name("parseStrict", false));
        assert!(looks_precise_name("$MyType", false));
        assert!(looks_precise_name("Router::route", false));
        assert!(looks_precise_name("src/parser.ts", false));
    }

    #[test]
    fn precise_mode_rejects_broad_lowercase_terms() {
        assert!(!looks_precise_name("run", false));
        assert!(!looks_precise_name("parse", false));
        assert!(!looks_precise_name("_parse", false));
    }

    #[test]
    fn precise_mode_allows_kind_narrowed_midlength_terms() {
        assert!(looks_precise_name("persist", true));
        assert!(!looks_precise_name("save", true));
    }

    #[test]
    #[serial]
    fn precise_mode_rejects_broad_show_body_searches() {
        std::env::set_var("KIN_SEARCH_MODE", "precise");
        let err = enforce_precise_search_mode(
            "parse|parseStrict|_parse|run",
            &["parse", "parseStrict", "_parse", "run"],
            None,
            true,
            Some(20),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("limited to `--limit 5`") || msg.contains("too many OR terms"));
        std::env::remove_var("KIN_SEARCH_MODE");
    }

    #[test]
    #[serial]
    fn precise_mode_accepts_small_exact_or_searches() {
        std::env::set_var("KIN_SEARCH_MODE", "precise");
        let result = enforce_precise_search_mode(
            "$MyType|$MyTypeInternals",
            &["$MyType", "$MyTypeInternals"],
            None,
            true,
            Some(5),
        );
        assert!(result.is_ok());
        std::env::remove_var("KIN_SEARCH_MODE");
    }

    #[test]
    fn artifact_context_strings_include_object_class() {
        let shallow = SearchRecord::Resolved {
            key: RetrievalKey::Artifact(ArtifactId::new()),
            item: ResolvedRetrievalItem::ShallowFile(ShallowTrackedFile {
                file_id: FilePathId::new("src/lib.rs"),
                language_hint: "rust".to_string(),
                declaration_count: 1,
                import_count: 1,
                syntax_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Some(Hash256::from_bytes([2; 32])),
                declaration_names: vec!["main".to_string()],
                import_paths: vec!["std::fmt".to_string()],
            }),
        };
        assert_eq!(record_display_context(&shallow), "ShallowSyntax, rust");
        assert_eq!(
            record_preview(match &shallow {
                SearchRecord::Resolved { item, .. } => item,
                _ => unreachable!(),
            })
            .as_deref(),
            Some("declarations=main imports=std::fmt")
        );

        let structured = SearchRecord::Resolved {
            key: RetrievalKey::Artifact(ArtifactId::new()),
            item: ResolvedRetrievalItem::StructuredArtifact(StructuredArtifact {
                file_id: FilePathId::new("Makefile"),
                kind: ArtifactKind::Makefile,
                content_hash: Hash256::from_bytes([3; 32]),
                text_preview: Some("build target".to_string()),
            }),
        };
        assert_eq!(
            record_display_context(&structured),
            "StructuredArtifact, Makefile"
        );
        assert_eq!(
            record_preview(match &structured {
                SearchRecord::Resolved { item, .. } => item,
                _ => unreachable!(),
            })
            .as_deref(),
            Some("build target")
        );

        let opaque = SearchRecord::Resolved {
            key: RetrievalKey::Artifact(ArtifactId::new()),
            item: ResolvedRetrievalItem::OpaqueArtifact(OpaqueArtifact {
                file_id: FilePathId::new("image.png"),
                content_hash: Hash256::from_bytes([4; 32]),
                mime_type: Some("image/png".to_string()),
                text_preview: None,
            }),
        };
        assert_eq!(record_display_context(&opaque), "OpaqueArtifact, image/png");
    }
}
