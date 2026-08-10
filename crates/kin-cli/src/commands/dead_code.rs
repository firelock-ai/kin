// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{
    EntityId, EntityKind, EntityRole, EntityStore, GraphNodeId, GraphStore, RelationKind,
};
use serde::{Deserialize, Serialize};

use crate::commands::search::{
    collect_daemon_search_response, DaemonSearchRecord, DaemonSearchRequest,
};

const DEFAULT_SEEDED_LIMIT: usize = 20;
const MAX_SEEDED_LIMIT: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeadCodeRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeResponse {
    #[serde(default)]
    pub lines: Vec<String>,
}

/// Request shape for the seeded find-dead-code primitive.
///
/// Combines `semantic_search` + `bulk_check_references` + dead-filter into a
/// single substrate call so the agent doesn't burn the 24-round tool-call cap
/// looping `semantic_search` → `find_references` per entity on large repos.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeadCodeSeededRequest {
    pub query: String,
    #[serde(default)]
    pub limit: Option<usize>,
    /// Optional substring filter applied to each candidate's entity name AFTER
    /// the semantic search. Lets the caller pre-narrow to a known prefix or
    /// suffix (e.g., a planted-secret tag) without burning extra tool rounds.
    /// Case-insensitive; empty/missing means no filter.
    #[serde(default)]
    pub name_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeSeededCandidate {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub file: Option<String>,
    pub signature: Option<String>,
    pub reference_count: usize,
    pub dead: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeSeededResponse {
    pub query: String,
    pub total_searched: usize,
    pub candidates: Vec<DeadCodeSeededCandidate>,
}

pub async fn run() -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_dead_code(&layout).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

pub async fn run_seeded(
    query: String,
    limit: Option<usize>,
    name_pattern: Option<String>,
) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_dead_code_seeded(
        &layout,
        &DeadCodeSeededRequest {
            query,
            limit,
            name_pattern,
        },
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn run_daemon_dead_code(layout: &kin_core::KinLayout) -> Result<DeadCodeResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url
        .ok_or_else(|| crate::daemon_client::daemon_required_error("dead-code scan", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .dead_code(&DeadCodeRequest::default())
        .await
        .context("daemon dead-code scan failed")
}

async fn run_daemon_dead_code_seeded(
    layout: &kin_core::KinLayout,
    request: &DeadCodeSeededRequest,
) -> Result<DeadCodeSeededResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        crate::daemon_client::daemon_required_error("seeded dead-code scan", layout)
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .dead_code_seeded(request)
        .await
        .context("daemon seeded dead-code scan failed")
}

pub fn build_dead_code_response(graph: &kin_db::InMemoryGraph) -> Result<DeadCodeResponse> {
    let mut lines = vec!["Scanning for dead code...".to_string()];

    // A missing incoming edge is only evidence of deadness for an entity whose
    // callers would have produced one. A test is invoked by its harness and a
    // trait method is invoked through the trait, so neither is named by any
    // edge, and reporting both as unreferenced buries the genuine finds. Both
    // exclusions are read off graph truth, and the counts stay in the output so
    // the scan never quietly shrinks its own number.
    let mut unreferenced = Vec::new();
    let mut nonproduction = 0usize;
    let mut trait_satisfying = 0usize;
    for entity in graph.find_dead_code()? {
        if entity.role != EntityRole::Source {
            nonproduction += 1;
        } else if entity.kind == EntityKind::Method && satisfies_trait_contract(graph, &entity.id)?
        {
            trait_satisfying += 1;
        } else {
            unreferenced.push(entity);
        }
    }

    // The scan reads a randomly seeded hash map in parallel, so without an
    // explicit order the same repository lists its findings differently on every
    // run and two scans cannot be diffed against each other.
    unreferenced.sort_by(|left, right| {
        let file_of = |entity: &kin_model::Entity| {
            entity
                .file_origin
                .as_ref()
                .map(|file| file.to_string())
                .unwrap_or_default()
        };
        file_of(left)
            .cmp(&file_of(right))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.id.cmp(&right.id))
    });

    if unreferenced.is_empty() {
        lines.push("No dead code found.".to_string());
    } else {
        lines.push(format!(
            "Found {} unreferenced entities:",
            unreferenced.len()
        ));
    }
    if nonproduction > 0 || trait_satisfying > 0 {
        lines.push(format!(
            "  ({nonproduction} excluded as non-production entities, {trait_satisfying} as trait-implementation methods reached through their trait)"
        ));
    }
    for e in &unreferenced {
        lines.push(format!(
            "  {} ({:?}, {}) - {}",
            e.name,
            e.kind,
            e.language,
            e.file_origin
                .as_ref()
                .map(|f| f.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ));
    }

    Ok(DeadCodeResponse { lines })
}

/// Whether the entity declares that it satisfies a trait contract.
///
/// Ingestion records an `Implements` edge from a method declared in a trait
/// implementation to the trait it satisfies. A call through the trait names the
/// trait, never the implementation, so this edge is the only thing standing
/// between a dispatch-reached method and a dead-code report.
fn satisfies_trait_contract(graph: &impl GraphStore, entity_id: &EntityId) -> Result<bool> {
    Ok(graph
        .get_all_relations_for_entity(entity_id)?
        .into_iter()
        .any(|relation| {
            relation.kind == RelationKind::Implements
                && relation.src == GraphNodeId::Entity(*entity_id)
        }))
}

/// Build a seeded dead-code response: semantic_search(query) → top N candidates,
/// classify each by incoming Calls/Imports/References, sort dead-first.
///
/// This is the one-shot substrate primitive that closes the find-dead-code
/// accuracy gap (Fix #2). The agent calls this instead of looping
/// `semantic_search` then `find_references` per entity.
pub fn build_dead_code_seeded_response(
    graph: &kin_db::InMemoryGraph,
    request: &DeadCodeSeededRequest,
) -> Result<DeadCodeSeededResponse> {
    let query = request.query.trim();
    if query.is_empty() {
        anyhow::bail!("seeded dead-code requires a non-empty query");
    }
    let limit = request
        .limit
        .unwrap_or(DEFAULT_SEEDED_LIMIT)
        .clamp(1, MAX_SEEDED_LIMIT);
    let name_filter = request
        .name_pattern
        .as_ref()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());

    // When a name filter is supplied, widen the semantic-search pool so the
    // post-filter still has a reasonable candidate count. Keeps the caller's
    // `limit` as the OUTPUT cap on filtered candidates.
    let search_limit = if name_filter.is_some() {
        (limit * 5).min(MAX_SEEDED_LIMIT)
    } else {
        limit
    };

    let embedding_status = graph.embedding_status();
    let semantic_complete = embedding_status.total == 0
        || (embedding_status.indexed == embedding_status.total && embedding_status.pending == 0);

    let search_request = DaemonSearchRequest {
        query: query.to_string(),
        kind: None,
        language: None,
        limit: Some(search_limit),
        semantic: semantic_complete,
        show_body: false,
        body_limit: None,
    };
    let search_response = collect_daemon_search_response(graph, &search_request)?;

    let reference_kinds = [
        RelationKind::Calls,
        RelationKind::Imports,
        RelationKind::References,
    ];

    let mut candidates: Vec<DeadCodeSeededCandidate> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for record in search_response.records.iter() {
        if candidates.len() >= limit {
            break;
        }
        let entity_record = match record {
            DaemonSearchRecord::Entity(entity) => entity,
            DaemonSearchRecord::Artifact(_) => continue,
        };
        if !seen.insert(entity_record.id.clone()) {
            continue;
        }
        let Ok(uuid) = uuid::Uuid::parse_str(&entity_record.id) else {
            continue;
        };
        let entity_id = EntityId(uuid);
        let entity = match graph.get_entity(&entity_id)? {
            Some(entity) => entity,
            None => continue,
        };

        // Apply name_pattern filter (case-insensitive substring) if provided.
        if let Some(ref pat) = name_filter {
            if !entity.name.to_lowercase().contains(pat) {
                continue;
            }
        }

        let reference_count = count_incoming_references(graph, &entity_id, &reference_kinds)?;
        let dead = reference_count == 0;

        candidates.push(DeadCodeSeededCandidate {
            id: entity.id.to_string(),
            name: entity.name.clone(),
            kind: format!("{:?}", entity.kind),
            file: entity.file_origin.as_ref().map(|p| p.0.clone()),
            signature: (!entity.signature.is_empty()).then(|| entity.signature.clone()),
            reference_count,
            dead,
        });
    }

    candidates.sort_by(|a, b| {
        a.reference_count
            .cmp(&b.reference_count)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.id.cmp(&b.id))
    });

    Ok(DeadCodeSeededResponse {
        query: query.to_string(),
        total_searched: candidates.len(),
        candidates,
    })
}

/// Count incoming relations of the given kinds for an entity.
///
/// Mirrors the classification logic in `build_bulk_refs_response` so the
/// "dead" flag here matches what `kin refs --bulk-json` would report
/// (reference_count == 0 across Calls + Imports + References).
fn count_incoming_references(
    graph: &impl GraphStore,
    entity_id: &EntityId,
    kinds: &[RelationKind],
) -> Result<usize> {
    let allowed: std::collections::HashSet<RelationKind> = kinds.iter().copied().collect();
    let mut count = 0usize;
    for rel in graph.get_all_relations_for_entity(entity_id)? {
        let Some(src_entity_id) = rel.src.as_entity() else {
            continue;
        };
        if rel.dst != GraphNodeId::Entity(*entity_id) {
            continue;
        }
        if !allowed.contains(&rel.kind) {
            continue;
        }
        if src_entity_id == *entity_id {
            continue;
        }
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::ids::{FilePathId, Hash256, LanguageId, RelationId};
    use kin_model::relation::{Relation, RelationOrigin};

    fn make_entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn make_relation(src: EntityId, dst: EntityId, kind: RelationKind) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        }
    }

    #[test]
    fn count_incoming_references_filters_relation_kind_and_self_loops() {
        let graph = InMemoryGraph::new();
        let caller = make_entity("caller", "src/a.rs");
        let target = make_entity("target", "src/b.rs");
        let caller_id = caller.id;
        let target_id = target.id;

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&target).unwrap();
        graph
            .upsert_relation(&make_relation(caller_id, target_id, RelationKind::Calls))
            .unwrap();
        // Self-loop should be excluded.
        graph
            .upsert_relation(&make_relation(target_id, target_id, RelationKind::Calls))
            .unwrap();

        let count = count_incoming_references(
            &graph,
            &target_id,
            &[
                RelationKind::Calls,
                RelationKind::Imports,
                RelationKind::References,
            ],
        )
        .unwrap();
        assert_eq!(
            count, 1,
            "should count the single caller, not the self-loop"
        );
    }

    #[test]
    fn seeded_dead_code_marks_unreferenced_first_and_sets_dead_flag() {
        let graph = InMemoryGraph::new();
        let caller = make_entity("probe_caller_seed", "src/a.rs");
        let live = make_entity("probe_alpha_seed", "src/b.rs");
        let dead = make_entity("probe_delta_seed", "src/c.rs");
        let caller_id = caller.id;
        let live_id = live.id;
        let dead_id = dead.id;

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&live).unwrap();
        graph.upsert_entity(&dead).unwrap();
        graph
            .upsert_relation(&make_relation(caller_id, live_id, RelationKind::Calls))
            .unwrap();

        let response = build_dead_code_seeded_response(
            &graph,
            &DeadCodeSeededRequest {
                query: "probe".to_string(),
                limit: Some(10),
                name_pattern: None,
            },
        )
        .unwrap();

        // Both probe_* entities (live + dead) should be classified. The caller
        // also matches the substring "probe" so it lands in the candidate set;
        // accept that and validate the dead-first sort + dead flag.
        assert!(response.candidates.len() >= 2);
        let dead_idx = response
            .candidates
            .iter()
            .position(|c| c.id == dead_id.to_string())
            .expect("dead candidate must appear");
        let live_idx = response
            .candidates
            .iter()
            .position(|c| c.id == live_id.to_string())
            .expect("live candidate must appear");
        assert!(
            dead_idx < live_idx,
            "dead-first sort: {} (idx {}) should precede {} (idx {})",
            dead_id,
            dead_idx,
            live_id,
            live_idx
        );

        let dead_row = &response.candidates[dead_idx];
        assert_eq!(dead_row.reference_count, 0);
        assert!(dead_row.dead);

        let live_row = &response.candidates[live_idx];
        assert_eq!(live_row.reference_count, 1);
        assert!(!live_row.dead);
    }

    #[test]
    fn scan_excludes_tests_and_trait_methods_and_says_how_many() {
        let graph = InMemoryGraph::new();

        let orphan = make_entity("never_called", "src/orphan.rs");

        let mut harness_test = make_entity("checks_never_called", "src/orphan.rs");
        harness_test.role = EntityRole::Test;

        let mut dispatched = make_entity("Summary::matched", "src/summary.rs");
        dispatched.kind = EntityKind::Method;

        let mut inherent = make_entity("Summary::helper", "src/summary.rs");
        inherent.kind = EntityKind::Method;

        let mut sink = make_entity("Sink", "src/sink.rs");
        sink.kind = EntityKind::TraitDef;

        for entity in [&orphan, &harness_test, &dispatched, &inherent, &sink] {
            graph.upsert_entity(entity).unwrap();
        }
        graph
            .upsert_relation(&make_relation(
                dispatched.id,
                sink.id,
                RelationKind::Implements,
            ))
            .unwrap();

        let lines = build_dead_code_response(&graph).unwrap().lines;
        let joined = lines.join("\n");

        assert!(
            joined.contains("Found 2 unreferenced entities:"),
            "only the orphan and the inherent method are unreferenced: {joined}"
        );
        assert!(
            joined.contains("never_called"),
            "a function nothing calls is still reported: {joined}"
        );
        assert!(
            joined.contains("Summary::helper"),
            "an inherent method nothing calls is still reported: {joined}"
        );
        assert!(
            !joined.contains("checks_never_called"),
            "the harness invokes a test with no edge to record: {joined}"
        );
        assert!(
            !joined.contains("Summary::matched"),
            "a call through the trait never names the implementation: {joined}"
        );
        assert!(
            joined.contains("1 excluded as non-production entities, 1 as trait-implementation"),
            "the scan reports what it set aside: {joined}"
        );

        let orphan_line = lines
            .iter()
            .position(|line| line.contains("never_called"))
            .unwrap();
        let helper_line = lines
            .iter()
            .position(|line| line.contains("Summary::helper"))
            .unwrap();
        assert!(
            orphan_line < helper_line,
            "findings order by file so two scans of one repo can be diffed: {joined}"
        );
    }

    #[test]
    fn seeded_dead_code_rejects_empty_query() {
        let graph = InMemoryGraph::new();
        let err = build_dead_code_seeded_response(
            &graph,
            &DeadCodeSeededRequest {
                query: "  ".to_string(),
                limit: Some(5),
                name_pattern: None,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("non-empty query"));
    }
}
