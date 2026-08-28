// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_db::{ResolvedRetrievalItem, RetrievalKey};
use kin_mcp::handlers::common::{entity_presentation_end_line, entity_presentation_start_line};
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
    let index_attached = crate::commands::locate::vector_index_attached(graph);
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
        // Search reads the same counters locate does and owes the same verdict.
        // The index has to be proven attached before the counters mean
        // anything: `embedding_status` answers zero indexed for every
        // retrievable object on a graph with no index, and search was reporting
        // that as a measured shortfall.
        embedding_state: crate::commands::locate::EmbeddingState::observe(
            true,
            index_attached,
            status.indexed,
            status.total,
            status.pending,
        ),
        limited_by: if !index_attached {
            vec![crate::commands::locate::COVERAGE_LIMIT_VECTOR_INDEX_ABSENT.to_string()]
        } else if complete {
            Vec::new()
        } else {
            vec![crate::commands::locate::COVERAGE_LIMIT_EMBEDDINGS_INCOMPLETE.to_string()]
        },
        read_at: crate::commands::locate::coverage_read_at_now(),
        note,
        // Search does not run locate's source-text phase, so it observes no
        // bodies. Absent means unobserved, never "no gap".
        graph_bodies: None,
    })
}

/// How a search row was found.
///
/// Name matching is conjunctive: the name index takes the exact name, then the
/// intersection of every query token, then a substring containment, so a row it
/// returns shares literal text with the query. The text fallback is disjunctive
/// BM25 over content, so a query naming nothing still returns that index's
/// highest-scoring documents — `zzz_this_symbol_does_not_exist` tokenizes into
/// words that do occur, and twenty unrelated entities come back.
///
/// Both used to render and serialize identically, so a caller could not tell a
/// hit from a guess. An agent acting on a typo, a stale name, or a symbol from
/// another version received twenty confident rows and no way to reject them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchMatchKind {
    /// The query matched this entity's name.
    Name,
    /// No name matched the query, so lexical search over content answered
    /// instead. The row shares content tokens with the query, not a name.
    TextFallback,
    /// Vector retrieval answered, ranked against the query's embedding.
    Semantic,
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
    /// Present whenever the surface that produced this row measured one.
    /// Comparable only against rows sharing a `match_kind`: a `text_fallback`
    /// score is BM25, a `semantic` score is the ranker's.
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<f32>,
    /// Absent only when the row came from a daemon predating the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    match_kind: Option<SearchMatchKind>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_kind: Option<SearchMatchKind>,
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
    /// Why an empty result is not evidence the repository holds no such
    /// declaration, or empty when the verdict certifies (FIR-2524).
    ///
    /// Carried as data rather than rendered at the source because this response
    /// is structured and printed client-side, so the verdict is computed where
    /// the graph and the daemon's substrate reading are and spoken where the
    /// reader is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub absence_qualifier: Vec<String>,
    /// Why the vector half of this answer is not fully trustworthy, or empty
    /// when it is. Populated when the runtime that produced the query vector
    /// disagrees with the runtimes that produced the index it was ranked
    /// against; the numbers alone cannot show that, because a mismatch ranks
    /// perfectly happily and just ranks wrong.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degradations: Vec<crate::commands::locate::RetrievalDegradation>,
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
    /// `default` rather than required so a CLI paired with a daemon predating
    /// the field reads `None` — unknown — instead of inheriting a provenance
    /// nobody recorded. Absent must not read as "matched by name".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_kind: Option<SearchMatchKind>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_kind: Option<SearchMatchKind>,
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
    let layout = crate::commands::require_repository_layout()?;

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
    let layout = crate::commands::require_repository_layout()?;

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
    let layout = crate::commands::require_repository_layout()?;
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
    let layout = crate::commands::require_repository_layout()?;
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
    let base_url =
        daemon_url.ok_or_else(|| crate::daemon_client::daemon_required_error("search", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.search(request).await.context("daemon search failed")
}

/// The absence qualifier for a search that matched nothing.
///
/// `semantic_search` declares NO edge class and is language-scoped instead, so
/// its gate reads the scope the extractor populated rather than cross-file
/// coverage, and its honest sentence is about what the index admitted rather
/// than about missing edges. Handing it the reference-coverage observation would
/// gate it on evidence it never gathers.
fn search_absence_qualifier(
    graph: &kin_db::InMemoryGraph,
    envelope: &kin_mcp::Envelope,
    degradations: &[crate::commands::locate::RetrievalDegradation],
) -> Vec<String> {
    let scoped = match graph.query_entities(&kin_model::graph::EntityFilter::default()) {
        Ok(scoped) => scoped,
        // An unreadable scope is not an empty one. Saying nothing here is the
        // conservative direction: the gate refuses on an unreported observation
        // anyway, and inventing a scope count would be the fabrication this
        // change exists to stop.
        Err(_) => return Vec::new(),
    };
    // The degradations this run reported travel with the payload. The absence
    // gate and the single verdict both read `degradations`, and a synthetic
    // payload that omitted them let a query-producer mismatch certify an
    // absence the mismatch had already made unproven.
    let payload = serde_json::json!({
        "results": [],
        "total_matches": 0,
        "degradations": degradations,
        kin_mcp::EDGE_COVERAGE_KEY: kin_mcp::edge_coverage::observe_absence_scope(
            &kin_mcp::edge_coverage::languages_of(&scoped),
            Some(scoped.len()),
        ),
    });
    crate::commands::absence_qualifier::qualify("semantic_search", &payload, envelope, "")
}

pub fn collect_daemon_search_response(
    graph: &kin_db::InMemoryGraph,
    request: &DaemonSearchRequest,
    envelope: &kin_mcp::Envelope,
) -> Result<DaemonSearchResponse> {
    if request.semantic {
        let mut response = collect_daemon_semantic_search_response(graph, request, envelope)?;
        if response.records.is_empty() {
            let reported = response.degradations.clone();
            response.absence_qualifier = search_absence_qualifier(graph, envelope, &reported);
        }
        return Ok(response);
    }

    let results = collect_search_results(
        graph,
        &request.query,
        request.kind.as_deref(),
        request.language.as_deref(),
    )?;
    // A name query that only the fallback answered is reported as a fallback at
    // the response level too, so a reader that never looks at a single row still
    // learns that nothing matched by name.
    let text_fallback = !results.is_empty()
        && results
            .iter()
            .all(|matched| matched.match_kind == SearchMatchKind::TextFallback);
    let records = results
        .iter()
        .map(|matched| record_to_daemon_record(&matched.record, matched.match_kind, matched.score))
        .collect::<Vec<_>>();
    let absence_qualifier = if records.is_empty() {
        search_absence_qualifier(graph, envelope, &[])
    } else {
        Vec::new()
    };
    Ok(DaemonSearchResponse {
        query: request.query.clone(),
        semantic: false,
        text_fallback,
        total_matches: records.len(),
        records,
        semantic_coverage: None,
        absence_qualifier,
        degradations: Vec::new(),
    })
}

#[cfg(not(feature = "vector"))]
fn collect_daemon_semantic_search_response(
    graph: &kin_db::InMemoryGraph,
    request: &DaemonSearchRequest,
    envelope: &kin_mcp::Envelope,
) -> Result<DaemonSearchResponse> {
    let _ = graph;
    let _ = request;
    let _ = envelope;
    anyhow::bail!("semantic search requires vector-enabled Kin embeddings")
}

#[cfg(feature = "vector")]
fn collect_daemon_semantic_search_response(
    graph: &kin_db::InMemoryGraph,
    request: &DaemonSearchRequest,
    envelope: &kin_mcp::Envelope,
) -> Result<DaemonSearchResponse> {
    let coverage = evaluate_semantic_coverage(graph)?;
    let limit = request.limit.unwrap_or(10);
    // The producer-aware variant, not the discarding wrapper: the caller has
    // to be able to compare the runtime that produced this query vector with
    // the lineage of the index it is about to rank against.
    let produced = graph.semantic_search_with_producers(&request.query, limit)?;
    let mut degradations: Vec<crate::commands::locate::RetrievalDegradation> = Vec::new();
    crate::commands::locate::record_query_producer_verdict(
        &mut degradations,
        graph,
        &produced.query_producers,
    );
    let vector_results = produced.matches;

    if vector_results.is_empty() {
        let mut response = collect_daemon_search_response(
            graph,
            &DaemonSearchRequest {
                semantic: false,
                show_body: false,
                body_limit: None,
                ..request.clone()
            },
            envelope,
        )?;
        response.semantic = true;
        response.text_fallback = true;
        response.semantic_coverage = Some(coverage);
        response.degradations = degradations;
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
            records.push(record_to_daemon_record(
                record,
                SearchMatchKind::Semantic,
                Some(result.score),
            ));
        }
    }

    let absence_qualifier = if records.is_empty() {
        search_absence_qualifier(graph, envelope, &degradations)
    } else {
        Vec::new()
    };
    Ok(DaemonSearchResponse {
        query: request.query.clone(),
        semantic: true,
        text_fallback: false,
        total_matches: records.len(),
        records,
        semantic_coverage: Some(coverage),
        absence_qualifier,
        degradations,
    })
}

/// One search row together with how it was found.
struct MatchedRecord {
    record: SearchRecord,
    match_kind: SearchMatchKind,
    score: Option<f32>,
}

fn collect_search_results(
    graph: &kin_db::InMemoryGraph,
    pattern: &str,
    kind: Option<&str>,
    language: Option<&str>,
) -> Result<Vec<MatchedRecord>> {
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
        return Ok(all
            .into_iter()
            .map(|entity| MatchedRecord {
                record: SearchRecord::Entity(entity),
                match_kind: SearchMatchKind::Name,
                score: None,
            })
            .collect());
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
                results.push(MatchedRecord {
                    record: SearchRecord::Entity(entity),
                    match_kind: SearchMatchKind::Name,
                    score: None,
                });
            }
        }
    }

    // Full-text search fallback for JSON path too.
    //
    // Everything below this line answered a question the caller did not ask: no
    // name matched, so BM25 over content answers instead, and BM25 is
    // disjunctive — a query whose tokens appear anywhere returns that index's
    // best documents whether or not the symbol exists. These rows are marked so
    // a caller can tell them from the name matches above, and they carry the
    // BM25 score the loop used to discard, which is the only number a consumer
    // can threshold on.
    if results.len() < 5 {
        let text_hits = graph.text_search(pattern, 20)?;
        for (retrieval_key, score) in text_hits {
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
                    results.push(MatchedRecord {
                        record,
                        match_kind: SearchMatchKind::TextFallback,
                        score: Some(score),
                    });
                }
            }
        }
    }

    if pattern.trim().is_empty() {
        results.sort_by_key(|matched| record_sort_key(&matched.record));
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

/// `path:line` for a search hit, or the path alone when the record carries no
/// line.
///
/// The record's `start_line` is already 1-based, converted at the one seam that
/// builds it, so this only decides how to render it. An entity the graph carries
/// no span for has no line to report, and the `:0` that used to appear here was a
/// position no editor can open. Extracted from the print so the rendering is
/// reachable from a test.
fn search_hit_location(file: String, start_line: Option<u32>) -> String {
    match start_line {
        Some(line) => format!("{file}:{line}"),
        None => file,
    }
}

fn daemon_record_to_json(record: &DaemonSearchRecord) -> SearchJsonRecord {
    match record {
        DaemonSearchRecord::Entity(entity) => SearchJsonRecord::Entity(SearchJsonEntity {
            id: entity.id.clone(),
            kind: entity.kind.clone(),
            name: entity.name.clone(),
            file: entity.file.clone().unwrap_or_default(),
            // Already 1-based: the record's lines are converted at the one seam
            // that builds it. This field is not optional in the JSON contract, so
            // an entity with no span keeps the "top of the file" fallback, which
            // in a 1-based world is a line a reader can actually open.
            line: entity.start_line.unwrap_or(1),
            end_line: entity.end_line,
            score: entity.score,
            match_kind: entity.match_kind,
            signature: entity.signature.clone(),
            body: entity.body.clone(),
        }),
        DaemonSearchRecord::Artifact(artifact) => SearchJsonRecord::Artifact(SearchJsonArtifact {
            kind: "Artifact".to_string(),
            file: artifact.file.clone().unwrap_or_default(),
            artifact_kind: artifact.artifact_kind.clone(),
            line: artifact.line,
            score: artifact.score,
            match_kind: artifact.match_kind,
            preview: artifact.preview.clone(),
        }),
    }
}

fn record_to_daemon_record(
    record: &SearchRecord,
    match_kind: SearchMatchKind,
    score: Option<f32>,
) -> DaemonSearchRecord {
    match record {
        SearchRecord::Entity(entity) => {
            DaemonSearchRecord::Entity(entity_to_daemon_record(entity, match_kind, score))
        }
        SearchRecord::Resolved {
            item: ResolvedRetrievalItem::Entity(entity),
            ..
        } => DaemonSearchRecord::Entity(entity_to_daemon_record(entity, match_kind, score)),
        SearchRecord::Resolved { item, .. } => {
            DaemonSearchRecord::Artifact(resolved_item_to_daemon_record(item, match_kind, score))
        }
    }
}

fn entity_to_daemon_record(
    entity: &Entity,
    match_kind: SearchMatchKind,
    score: Option<f32>,
) -> DaemonSearchEntityRecord {
    let span = entity.span.as_ref();
    DaemonSearchEntityRecord {
        id: entity.id.to_string(),
        name: entity.name.clone(),
        kind: format!("{:?}", entity.kind),
        language: entity.language.to_string(),
        file: entity.file_origin.as_ref().map(|f| f.0.clone()),
        // The graph stores tree-sitter rows, which are 0-based; every
        // agent-facing `file:line` is 1-based. This is the one seam a search
        // record's lines are built at, so both emitters downstream (the JSON
        // record and the `--body` human line) pass the converted value through
        // rather than each converting, or each forgetting to.
        //
        // `start_byte`/`end_byte` are deliberately NOT shifted. They are byte
        // offsets rather than line numbers, and the daemon slices a source blob
        // with them to build `body`.
        start_line: entity_presentation_start_line(entity),
        end_line: entity_presentation_end_line(entity),
        start_byte: span.map(|span| span.start_byte),
        end_byte: span.map(|span| span.end_byte),
        signature: (!entity.signature.is_empty()).then(|| entity.signature.clone()),
        score,
        match_kind: Some(match_kind),
        body: None,
        body_omitted_line_count: 0,
    }
}

/// Characters of artifact text a search record renders.
///
/// The stored preview is a retrieval retention (up to
/// `kin_index::artifacts::ARTIFACT_TEXT_RETENTION_CHARS`), not a display
/// string; a record that carried it whole would put an entire document on the
/// wire per row.
const ARTIFACT_PREVIEW_DISPLAY_CHARS: usize = 320;

fn artifact_display_preview(preview: Option<&str>) -> Option<String> {
    let text = preview?.trim();
    if text.is_empty() {
        return None;
    }
    Some(text.chars().take(ARTIFACT_PREVIEW_DISPLAY_CHARS).collect())
}

fn resolved_item_to_daemon_record(
    item: &ResolvedRetrievalItem,
    match_kind: SearchMatchKind,
    score: Option<f32>,
) -> DaemonSearchArtifactRecord {
    let file = item.file_path().map(|f| f.0);
    match item {
        ResolvedRetrievalItem::Entity(entity) => DaemonSearchArtifactRecord {
            title: entity.name.clone(),
            context: format!("{:?}, {}", entity.kind, entity.language),
            file,
            artifact_kind: "entity".to_string(),
            // 1-based, like the three whole-file arms below that report `line: 1`.
            // This row's `line` is not optional, so a spanless entity keeps that
            // same "top of the file" fallback rather than gaining a `0` no editor
            // can open.
            line: entity_presentation_start_line(entity).unwrap_or(1),
            preview: entity
                .doc_summary
                .clone()
                .filter(|summary| !summary.trim().is_empty()),
            score,
            match_kind: Some(match_kind),
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
            match_kind: Some(match_kind),
        },
        ResolvedRetrievalItem::StructuredArtifact(artifact) => DaemonSearchArtifactRecord {
            title: file_display_name(&artifact.file_id.0),
            context: format!("StructuredArtifact, {:?}", artifact.kind),
            file,
            artifact_kind: format!("{:?}", artifact.kind),
            line: 1,
            preview: artifact_display_preview(artifact.text_preview.as_deref()),
            score,
            match_kind: Some(match_kind),
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
            preview: artifact_display_preview(artifact.text_preview.as_deref()),
            score,
            match_kind: Some(match_kind),
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
        ResolvedRetrievalItem::StructuredArtifact(artifact) => {
            artifact_display_preview(artifact.text_preview.as_deref())
        }
        ResolvedRetrievalItem::OpaqueArtifact(artifact) => {
            artifact_display_preview(artifact.text_preview.as_deref())
        }
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

/// Row suffix marking a lexical fallback in the plain listing.
///
/// The response-level banner only fires when nothing matched by name. A query
/// with one or two name matches still triggers the fallback — it fills to five —
/// and those extra rows would otherwise print exactly like the real ones, which
/// is the same defect at smaller scale.
fn fallback_marker(match_kind: Option<SearchMatchKind>) -> &'static str {
    match match_kind {
        Some(SearchMatchKind::TextFallback) => "  [text-search fallback, no name match]",
        _ => "",
    }
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
        // The banner alone says a query matched nothing, never whether this index
        // could have matched it (FIR-2524).
        for line in &response.absence_qualifier {
            println!("{line}");
        }
        return Ok(());
    }

    if response.semantic && response.text_fallback {
        println!(
            "No vector matches for '{}'; using graph text search fallback:",
            response.query
        );
    } else if response.text_fallback {
        // Without this line the twenty rows below read as twenty matches. None
        // of them matched the query by name, and saying so is the difference
        // between a result and a guess.
        println!(
            "No name matched '{}'; the rows below are graph text search \
             fallbacks ranked by content, not name matches:",
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
                    println!(
                        "{} ({}) @ {}",
                        entity.name,
                        entity.kind,
                        search_hit_location(file_str, entity.start_line)
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
                            "  {} ({}, {}) - {}{}",
                            entity.name,
                            entity.kind,
                            entity.language,
                            entity
                                .file
                                .as_deref()
                                .map(|file| display_read_path(layout, file))
                                .unwrap_or_else(|| "no file".to_string()),
                            fallback_marker(entity.match_kind)
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
                            "  {} ({}) - {}{}",
                            artifact.title,
                            artifact.context,
                            artifact
                                .file
                                .as_deref()
                                .map(|file| display_read_path(layout, file))
                                .unwrap_or_else(|| "no file".to_string()),
                            fallback_marker(artifact.match_kind)
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
    /// A daemon whose substrate is sound, so the FIR-2524 absence qualifier
    /// answers on the scope observation rather than on the envelope.
    fn healthy_search_envelope() -> kin_mcp::Envelope {
        kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 2,
            "graph_generation": 1,
        }))
    }

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

    /// Every `kin search` emitter reports the line a human editor shows.
    ///
    /// The graph stores tree-sitter rows, which are 0-based, and
    /// `kin-mcp`'s `handlers::common` documents that every agent-facing
    /// `file:line` is 1-based, converted at exactly one seam per surface. `kin
    /// search` emitted the raw row from three places, so it disagreed with `kin
    /// refs`, `kin trace-data-flow`, and every MCP read surface about the same
    /// entity, and a reader acting on it edited the line above the hit.
    ///
    /// One test covering all three emitters on purpose: they are one contract
    /// stated once, and the wire record they share is the seam the conversion
    /// happens at, so asserting them apart would let the record and its renderers
    /// drift.
    #[test]
    fn every_search_emitter_reports_the_line_a_human_editor_shows() {
        use super::{
            daemon_record_to_json, entity_to_daemon_record, resolved_item_to_daemon_record,
            search_hit_location, SearchJsonRecord, SearchMatchKind,
        };

        const SOURCE: &str = "# header\n\ndef probe_handler():\n    return 1\n";
        // What a reader counting lines in an editor would say.
        let human_line = SOURCE
            .lines()
            .position(|line| line.contains("def probe_handler"))
            .map(|index| index + 1)
            .expect("the fixture declares the handler") as u32;
        let graph_row = human_line - 1;
        assert_eq!(
            graph_row, 2,
            "fixture sanity: the raw row differs from the line"
        );

        let mut entity = dedupe_test_entity("probe_handler", "src/probe.py");
        {
            let span = entity.span.as_mut().expect("fixture carries a span");
            span.start_line = graph_row;
            span.end_line = graph_row + 1;
        }
        let (start_byte, end_byte) = entity
            .span
            .as_ref()
            .map(|span| (span.start_byte, span.end_byte))
            .expect("fixture carries a span");

        // Emitter 1: the wire record every search surface is rendered from.
        let record = entity_to_daemon_record(&entity, SearchMatchKind::Semantic, Some(0.5));
        assert_eq!(
            record.start_line,
            Some(human_line),
            "the record must carry the 1-based line, not the raw row {graph_row}"
        );
        assert_eq!(record.end_line, Some(human_line + 1));
        // Byte offsets are not line numbers and must not be shifted: the daemon
        // slices a source blob with them to build `body`.
        assert_eq!(record.start_byte, Some(start_byte));
        assert_eq!(record.end_byte, Some(end_byte));

        // Emitter 2: `kin search --json`.
        let SearchJsonRecord::Entity(json_entity) =
            daemon_record_to_json(&super::DaemonSearchRecord::Entity(record.clone()))
        else {
            panic!("expected an entity record");
        };
        let json = serde_json::to_value(&json_entity).expect("serialize");
        assert_eq!(
            json["line"].as_u64(),
            Some(human_line as u64),
            "the JSON line must be the one a reader would count: {json}"
        );

        // Emitter 3: the `--body` human `file:line`.
        assert_eq!(
            search_hit_location("src/probe.py".to_string(), record.start_line),
            format!("src/probe.py:{human_line}")
        );
        // A hit the graph carries no span for names its file alone. `:0` was a
        // position no editor can open.
        assert_eq!(
            search_hit_location("src/probe.py".to_string(), None),
            "src/probe.py"
        );

        // Emitter 4: the artifact row, whose `line` is not optional and so keeps
        // the same "top of the file" fallback its three whole-file siblings use.
        let artifact = resolved_item_to_daemon_record(
            &ResolvedRetrievalItem::Entity(entity.clone()),
            SearchMatchKind::Semantic,
            Some(0.5),
        );
        assert_eq!(
            artifact.line, human_line,
            "the artifact row must carry the 1-based line"
        );
        let mut spanless = entity;
        spanless.span = None;
        assert_eq!(
            resolved_item_to_daemon_record(
                &ResolvedRetrievalItem::Entity(spanless),
                SearchMatchKind::Semantic,
                Some(0.5),
            )
            .line,
            1,
            "a spanless artifact row points at the top of the file, never line 0"
        );
    }

    #[test]
    fn search_json_entity_carries_score_and_span() {
        use super::{
            daemon_record_to_json, DaemonSearchEntityRecord, DaemonSearchRecord, SearchJsonRecord,
            SearchMatchKind,
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
            match_kind: Some(SearchMatchKind::Semantic),
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
        assert_eq!(json["match_kind"].as_str(), Some("semantic"));
    }

    /// The collector must label a guess as a guess against a real graph.
    ///
    /// This runs the mechanism rather than the serializer: a live text index, a
    /// name that exists, and a compound query that names nothing but shares
    /// content tokens — which is exactly how a nonsense string returned twenty
    /// rows. Asserting the fallback set is non-empty is deliberate: a fixture
    /// whose text index never answers would make every claim below vacuously
    /// true and the test unable to fail.
    #[test]
    fn the_collector_marks_rows_no_name_matched_as_fallbacks() {
        use super::{
            collect_daemon_search_response, DaemonSearchRecord, DaemonSearchRequest,
            SearchMatchKind,
        };
        use kin_model::EntityStore;

        let dir = tempfile::tempdir().expect("tempdir");
        let graph = kin_db::InMemoryGraph::with_text_index(dir.path().join("text-index"));

        let mut described = dedupe_test_entity("provide_context_for_failure", "src/context.rs");
        described.doc_summary = Some(
            "attach additional context to a failing operation before it propagates".to_string(),
        );
        let mut other = dedupe_test_entity("ensure_nonbool", "tests/ui/ensure-nonbool.rs");
        other.doc_summary =
            Some("this does not exist as a bool anywhere in the context".to_string());
        for entity in [&described, &other] {
            graph.upsert_entity(entity).expect("upsert");
        }
        graph.flush_text_index().expect("flush text index");

        let search = |query: &str| {
            collect_daemon_search_response(
                &graph,
                &DaemonSearchRequest {
                    query: query.to_string(),
                    kind: None,
                    language: None,
                    limit: None,
                    semantic: false,
                    show_body: false,
                    body_limit: None,
                },
                &healthy_search_envelope(),
            )
            .expect("search")
        };

        let real = search("provide_context_for_failure");
        let named: Vec<_> = real
            .records
            .iter()
            .filter_map(|record| match record {
                DaemonSearchRecord::Entity(entity) => Some(entity),
                DaemonSearchRecord::Artifact(_) => None,
            })
            .filter(|entity| entity.match_kind == Some(SearchMatchKind::Name))
            .collect();
        assert!(
            named
                .iter()
                .any(|e| e.name == "provide_context_for_failure"),
            "a symbol that exists must come back as a name match: {:?}",
            real.records
        );
        assert!(
            !real.text_fallback,
            "a query a name answered is not a fallback"
        );

        let nonsense = search("zzz_context_does_not_exist_anywhere_9f3a");
        // The fixture has to actually produce the defect, or the assertions
        // below prove nothing about it.
        assert!(
            !nonsense.records.is_empty(),
            "fixture inert: the text fallback returned nothing, so this test \
             cannot observe the behavior it exists to pin"
        );
        for record in &nonsense.records {
            let match_kind = match record {
                DaemonSearchRecord::Entity(entity) => entity.match_kind,
                DaemonSearchRecord::Artifact(artifact) => artifact.match_kind,
            };
            assert_eq!(
                match_kind,
                Some(SearchMatchKind::TextFallback),
                "a row no name matched must not claim to be a name match: {record:?}"
            );
        }
        assert!(
            nonsense.text_fallback,
            "a response only the fallback answered must say so"
        );
    }

    /// The JSON a machine consumer reads must say which surface answered.
    ///
    /// Name mode used to emit `id, kind, name, file, line, end_line, signature`
    /// and nothing else: no score, no provenance. A row the name index returned
    /// and a row BM25 guessed at serialized to the same shape, so an agent
    /// searching a typo, a renamed symbol, or a symbol from another version got
    /// twenty confident-looking results and no field to reject them by.
    #[test]
    fn name_mode_json_separates_a_match_from_a_fallback() {
        use super::{
            daemon_record_to_json, DaemonSearchEntityRecord, DaemonSearchRecord, SearchJsonRecord,
            SearchMatchKind,
        };

        let row = |match_kind, score| {
            let record = DaemonSearchRecord::Entity(DaemonSearchEntityRecord {
                id: "e1".into(),
                name: "NotBool".into(),
                kind: "Class".into(),
                language: "rust".into(),
                file: Some("tests/ui/ensure-nonbool.rs".into()),
                start_line: Some(3),
                end_line: Some(4),
                start_byte: None,
                end_byte: None,
                signature: None,
                score,
                match_kind: Some(match_kind),
                body: None,
                body_omitted_line_count: 0,
            });
            let SearchJsonRecord::Entity(entity) = daemon_record_to_json(&record) else {
                panic!("expected entity record");
            };
            serde_json::to_value(&entity).expect("serialize")
        };

        let matched = row(SearchMatchKind::Name, None);
        let guessed = row(SearchMatchKind::TextFallback, Some(2.5));

        // The acceptance: reading only the JSON, the two are distinguishable.
        assert_ne!(
            matched["match_kind"], guessed["match_kind"],
            "a fallback must not serialize the same as a name match"
        );
        assert_eq!(matched["match_kind"].as_str(), Some("name"));
        assert_eq!(guessed["match_kind"].as_str(), Some("text_fallback"));

        // And the fallback carries the BM25 score the collector used to discard,
        // so a consumer can threshold rather than only classify.
        assert!((guessed["score"].as_f64().unwrap() - 2.5).abs() < 1e-6);

        // A daemon predating the field reports unknown, never "name". Absent
        // provenance must not read as a confirmed match.
        let legacy: DaemonSearchEntityRecord = serde_json::from_value(serde_json::json!({
            "id": "e1", "name": "NotBool", "kind": "Class", "language": "rust",
            "file": null, "start_line": null, "end_line": null,
            "start_byte": null, "end_byte": null, "signature": null, "score": null
        }))
        .expect("deserialize a record from before the field existed");
        assert_eq!(legacy.match_kind, None);
    }

    /// The provenance has to survive the daemon hop, not just the struct.
    ///
    /// `kin search` reaches the graph through the daemon, so every field a
    /// consumer relies on crosses a `serde_json` round trip on the way back. A
    /// field that serialized but did not deserialize would leave the CLI reading
    /// `None` — unknown — for every row of a live search while every in-process
    /// test still passed.
    #[test]
    fn match_kind_and_score_survive_the_daemon_wire_format() {
        use super::{
            DaemonSearchArtifactRecord, DaemonSearchEntityRecord, DaemonSearchRecord,
            DaemonSearchResponse, SearchMatchKind,
        };

        let response = DaemonSearchResponse {
            absence_qualifier: Vec::new(),
            degradations: Vec::new(),
            query: "zzz_this_symbol_does_not_exist_anywhere_9f3a".into(),
            semantic: false,
            text_fallback: true,
            total_matches: 2,
            records: vec![
                DaemonSearchRecord::Entity(DaemonSearchEntityRecord {
                    id: "e1".into(),
                    name: "NotBool".into(),
                    kind: "Class".into(),
                    language: "rust".into(),
                    file: Some("tests/ui/ensure-nonbool.rs".into()),
                    start_line: Some(3),
                    end_line: Some(4),
                    start_byte: None,
                    end_byte: None,
                    signature: None,
                    score: Some(1.75),
                    match_kind: Some(SearchMatchKind::TextFallback),
                    body: None,
                    body_omitted_line_count: 0,
                }),
                DaemonSearchRecord::Artifact(DaemonSearchArtifactRecord {
                    title: "lib.rs".into(),
                    context: "StructuredArtifact, Doc".into(),
                    file: Some("src/lib.rs".into()),
                    artifact_kind: "Doc".into(),
                    line: 1,
                    preview: None,
                    score: Some(0.5),
                    match_kind: Some(SearchMatchKind::TextFallback),
                }),
            ],
            semantic_coverage: None,
        };

        let wire = serde_json::to_string(&response).expect("serialize");
        let back: DaemonSearchResponse = serde_json::from_str(&wire).expect("deserialize");

        assert!(back.text_fallback, "the response-level flag must survive");
        for record in &back.records {
            let match_kind = match record {
                DaemonSearchRecord::Entity(entity) => entity.match_kind,
                DaemonSearchRecord::Artifact(artifact) => artifact.match_kind,
            };
            assert_eq!(
                match_kind,
                Some(SearchMatchKind::TextFallback),
                "provenance must cross the wire: {record:?}"
            );
        }
        let DaemonSearchRecord::Entity(entity) = &back.records[0] else {
            panic!("expected an entity record");
        };
        assert!((entity.score.expect("score survives") - 1.75).abs() < 1e-6);
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
        let _mode = kin_core::test_env::EnvVarGuard::set("KIN_SEARCH_MODE", "precise");
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
    }

    #[test]
    #[serial]
    fn precise_mode_accepts_small_exact_or_searches() {
        let _mode = kin_core::test_env::EnvVarGuard::set("KIN_SEARCH_MODE", "precise");
        let result = enforce_precise_search_mode(
            "$MyType|$MyTypeInternals",
            &["$MyType", "$MyTypeInternals"],
            None,
            true,
            Some(5),
        );
        assert!(result.is_ok());
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
