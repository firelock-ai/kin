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
    /// Whether the graph this scan read can support an absence claim at all.
    ///
    /// False means every row is a candidate the graph cannot stand behind, and
    /// the rendered lines say so on each row. Defaulted so a new CLI reading an
    /// older daemon's response does not read a missing field as a verdict.
    #[serde(default)]
    pub verified: bool,
    /// Why the scan could not be verified, one reason per gap, in the same words
    /// the output prints.
    #[serde(default)]
    pub unverified_reasons: Vec<String>,
    /// The reference-edge completeness this verdict was reached on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_edge_coverage: Option<kin_core::reference_coverage::ReferenceEdgeCoverage>,
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

/// Scan for unreferenced entities against graph truth.
///
/// `binding` is the repository authority the declared entry points are read
/// through, from graph-owned blob storage. `None` means the caller has no
/// authority to read manifests with; a graph that tracks manifests then reports
/// them as unread rather than as declaring nothing.
pub fn build_dead_code_response(
    binding: Option<&kin_core::LocalRepositoryAuthorityBinding>,
    graph: &kin_db::InMemoryGraph,
) -> Result<DeadCodeResponse> {
    let entry_points = collect_declared_entry_points(binding, graph)?;
    let coverage = kin_core::reference_coverage::collect_reference_edge_coverage(graph)?;
    build_dead_code_report(graph, &entry_points, &coverage)
}

fn build_dead_code_report(
    graph: &kin_db::InMemoryGraph,
    entry_points: &kin_core::entry_points::DeclaredEntryPoints,
    coverage: &kin_core::reference_coverage::ReferenceEdgeCoverage,
) -> Result<DeadCodeResponse> {
    let mut lines = vec!["Scanning for dead code...".to_string()];

    // A missing incoming edge is only evidence of deadness for an entity whose
    // callers would have produced one. A test is invoked by its harness, a trait
    // method through the trait, and an entry point by the launcher its manifest
    // declares, so none of them is named by any edge, and reporting them as
    // unreferenced buries the genuine finds. Every exclusion is read off graph
    // truth, and the counts stay in the output so the scan never quietly
    // shrinks its own number.
    let mut unreferenced = Vec::new();
    let mut nonproduction = 0usize;
    let mut trait_satisfying = 0usize;
    let mut referenced_in_file = 0usize;
    let mut declared_entry_points = 0usize;
    for entity in graph.find_dead_code()? {
        if entity.role != EntityRole::Source {
            nonproduction += 1;
        } else if entity.kind == EntityKind::Method && satisfies_trait_contract(graph, &entity.id)?
        {
            trait_satisfying += 1;
        } else if has_incoming_reference(graph, &entity.id)? {
            // The candidate generator asks only whether an inbound edge crosses
            // a file boundary, so an entity whose only caller sits beside it in
            // the same file arrives here. `find_references` reads that caller
            // and reports it; consulting the same collector is what stops the
            // two surfaces from answering opposite things about one edge.
            referenced_in_file += 1;
        } else if is_entry_point(&entity, entry_points) {
            declared_entry_points += 1;
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

    // The gate. This output is a delete list, so it carries the strictest
    // completeness bar in the product: a graph that cannot support an absence
    // claim may still answer, but it may not answer confidently. Both halves of
    // the evidence are checked, the reference edges the verdict rests on and the
    // manifests the entry-point exclusion rests on.
    let mut unverified_reasons = coverage.unsupportable_absence_reasons();
    if !entry_points.manifests_unreadable.is_empty() {
        unverified_reasons.push(format!(
            "declared entry points could not be read from graph truth for {}, so an entry point \
             may be listed below",
            entry_points.manifests_unreadable.join(", ")
        ));
    }
    let verified = unverified_reasons.is_empty();

    if unreferenced.is_empty() {
        if verified {
            lines.push("No dead code found.".to_string());
        } else {
            lines.push(
                "No unreferenced entities found, and this scan could not have found one:"
                    .to_string(),
            );
        }
    } else if verified {
        lines.push(format!(
            "Found {} unreferenced entities:",
            unreferenced.len()
        ));
    } else {
        lines.push(format!(
            "UNVERIFIED: {} candidates. This graph cannot support a delete list:",
            unreferenced.len()
        ));
    }
    for reason in &unverified_reasons {
        lines.push(format!("  incomplete: {reason}"));
    }
    if !verified && !unreferenced.is_empty() {
        lines.push(
            "  Every row below is UNVERIFIED: an entity with no edge in this graph may still be \
             used. Do not delete on this evidence."
                .to_string(),
        );
    }
    if nonproduction > 0
        || trait_satisfying > 0
        || referenced_in_file > 0
        || declared_entry_points > 0
    {
        lines.push(format!(
            "  ({nonproduction} excluded as non-production entities, {trait_satisfying} as \
             trait-implementation methods reached through their trait, {referenced_in_file} as \
             referenced by an entity in their own file, {declared_entry_points} as declared entry \
             points)"
        ));
    }
    if !entry_points.manifests_read.is_empty() {
        lines.push(format!(
            "  (entry points read from {})",
            entry_points.manifests_read.join(", ")
        ));
    }
    let prefix = if verified { "  " } else { "  [unverified] " };
    for e in &unreferenced {
        lines.push(format!(
            "{prefix}{} ({:?}, {}) - {}",
            e.name,
            e.kind,
            e.language,
            e.file_origin
                .as_ref()
                .map(|f| f.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ));
    }

    Ok(DeadCodeResponse {
        lines,
        verified,
        unverified_reasons,
        reference_edge_coverage: Some(coverage.clone()),
    })
}

/// Whether the graph holds an inbound reference edge for this entity, read
/// through the same collector `kin refs` and `find_references` read.
///
/// An inbound edge whose caller record is missing still counts: the edge exists,
/// so absence cannot be claimed, and reporting the entity as deletable because
/// the caller's own record is absent is the least safe reading available.
fn has_incoming_reference(graph: &impl GraphStore, entity_id: &EntityId) -> Result<bool> {
    let collected = crate::commands::refs::collect_graph_references(
        graph,
        entity_id,
        &kin_core::reference_coverage::REFERENCE_RELATION_KINDS,
    )?;
    Ok(!collected.references.is_empty() || !collected.missing_source_ids.is_empty())
}

/// Whether this entity is an entry point, so no inbound edge was ever owed.
fn is_entry_point(
    entity: &kin_model::Entity,
    entry_points: &kin_core::entry_points::DeclaredEntryPoints,
) -> bool {
    kin_core::entry_points::is_conventional_entry_point(entity)
        || entry_points.declaration_for(entity).is_some()
}

/// Read the entry points declared by the package manifests the graph tracks.
///
/// Manifest paths come from graph-owned structured artifacts and the bytes from
/// graph-owned blob storage through the repository authority. Nothing here reads
/// the working tree: a manifest the graph does not carry is recorded as unread,
/// which makes the scan report itself unverified rather than conclude that no
/// entry point is declared.
fn collect_declared_entry_points(
    binding: Option<&kin_core::LocalRepositoryAuthorityBinding>,
    graph: &kin_db::InMemoryGraph,
) -> Result<kin_core::entry_points::DeclaredEntryPoints> {
    use kin_core::entry_points::{declares_entry_points, parse_manifest_entry_points};

    let mut declared = kin_core::entry_points::DeclaredEntryPoints::default();
    let mut manifests: Vec<String> = graph
        .list_structured_artifacts()?
        .into_iter()
        .filter(|artifact| artifact.kind == kin_model::ArtifactKind::PackageManifest)
        .map(|artifact| artifact.file_id.0)
        .filter(|path| declares_entry_points(path))
        .collect();
    manifests.sort();
    manifests.dedup();
    if manifests.is_empty() {
        return Ok(declared);
    }

    let authority = match binding {
        Some(binding) => {
            match super::repository_authority::ActiveRepositoryAuthority::open(binding) {
                Ok(authority) => Some(authority),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "dead-code could not open repository authority to read declared entry points"
                    );
                    None
                }
            }
        }
        None => None,
    };

    let tree = graph.resolved_tree();
    for manifest in manifests {
        let bytes = authority.as_ref().and_then(|authority| {
            kin_model::RepoPath::from_utf8(manifest.clone())
                .ok()
                .and_then(|path| tree.artifact_at_path(&path).cloned())
                .and_then(|artifact| match artifact.entry {
                    kin_model::TreeEntry::Blob { hash, .. } => {
                        authority.load_source_blob(hash).ok()
                    }
                    _ => None,
                })
        });
        match bytes {
            Some(bytes) => {
                declared
                    .entries
                    .extend(parse_manifest_entry_points(&manifest, &bytes));
                declared.manifests_read.push(manifest);
            }
            None => declared.manifests_unreadable.push(manifest),
        }
    }

    Ok(declared)
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

/// Count the entities that reference this one, of the given kinds.
///
/// Reads the collector `kin refs`, `kin refs --bulk-json` and the whole-repo
/// scan read, so the `dead` flag here means exactly what those surfaces report:
/// distinct referencing entities, self-edges excluded.
fn count_incoming_references(
    graph: &impl GraphStore,
    entity_id: &EntityId,
    kinds: &[RelationKind],
) -> Result<usize> {
    let collected = crate::commands::refs::collect_graph_references(graph, entity_id, kinds)?;
    Ok(collected.references.len() + collected.missing_source_ids.len())
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

    /// Stamp the graph-owned parse side onto an entity, the way ingestion does.
    ///
    /// A fixture without it reads as an unmeasured graph, which the scan refuses
    /// to answer confidently on — correct behavior, and not what the tests below
    /// that assert a confident answer are about.
    fn measured(mut entity: Entity, call_sites: u64, import_statements: u64) -> Entity {
        entity.metadata.extra.insert(
            kin_parser::FILE_PARSED_CALL_SITES_KEY.into(),
            serde_json::Value::from(call_sites),
        );
        entity.metadata.extra.insert(
            kin_parser::FILE_PARSED_IMPORT_STATEMENTS_KEY.into(),
            serde_json::Value::from(import_statements),
        );
        entity
    }

    fn scan(graph: &InMemoryGraph) -> DeadCodeResponse {
        let coverage =
            kin_core::reference_coverage::collect_reference_edge_coverage(graph).unwrap();
        let entry_points = collect_declared_entry_points(None, graph).unwrap();
        build_dead_code_report(graph, &entry_points, &coverage).unwrap()
    }

    /// Whether `kin refs --bulk-json` reports a caller for this entity.
    ///
    /// The shipped surface, not an internal helper, so the agreement asserted
    /// below is the agreement a user observes.
    fn bulk_refs_sees_references(graph: &InMemoryGraph, entity: &Entity) -> bool {
        let response = crate::commands::refs::build_bulk_refs_response(
            graph,
            &crate::commands::refs::BulkRefsRequest {
                entity_ids: vec![entity.id.to_string()],
                kind: "any".to_string(),
                compact: true,
            },
        )
        .unwrap();
        response.results[0]["has_references"]
            .as_bool()
            .unwrap_or(false)
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

        let orphan = measured(make_entity("never_called", "src/orphan.rs"), 0, 0);

        let mut harness_test = measured(make_entity("checks_never_called", "src/orphan.rs"), 0, 0);
        harness_test.role = EntityRole::Test;

        let mut dispatched = measured(make_entity("Summary::matched", "src/summary.rs"), 0, 0);
        dispatched.kind = EntityKind::Method;

        let mut inherent = measured(make_entity("Summary::helper", "src/summary.rs"), 0, 0);
        inherent.kind = EntityKind::Method;

        let mut sink = measured(make_entity("Sink", "src/sink.rs"), 0, 0);
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

        let response = scan(&graph);
        assert!(
            response.verified,
            "a graph whose files parsed no call sites and no imports has nothing unresolved: {:?}",
            response.unverified_reasons
        );
        let lines = response.lines;
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
        assert!(
            !joined.contains("[unverified]"),
            "a graph with nothing left to resolve answers plainly: {joined}"
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

    /// FIR-2356. `find_references` named a caller for `extract_tags`,
    /// `strip_code`, `normalize_title` and `Database.ingest_note` while
    /// `dead-code` called all four unreferenced, at one graph generation, because
    /// the scan's candidate rule asked only whether an inbound edge crossed a
    /// FILE boundary. Both surfaces now read one collector, and this asserts
    /// they agree entity by entity rather than only on the four.
    #[test]
    fn dead_code_and_bulk_refs_agree_on_every_entity_including_intra_file_callers() {
        let graph = InMemoryGraph::new();

        let parse_note = measured(make_entity("parse_note", "nk/parsing.py"), 2, 1);
        let extract_tags = measured(make_entity("extract_tags", "nk/parsing.py"), 2, 1);
        let strip_code = measured(make_entity("strip_code", "nk/parsing.py"), 2, 1);
        let ingest_dir = measured(make_entity("Database.ingest_dir", "nk/storage.py"), 1, 1);
        let ingest_note = measured(make_entity("Database.ingest_note", "nk/storage.py"), 1, 1);
        let orphan = measured(make_entity("legacy_helper", "nk/legacy.py"), 0, 0);

        let entities = [
            &parse_note,
            &extract_tags,
            &strip_code,
            &ingest_dir,
            &ingest_note,
            &orphan,
        ];
        for entity in entities {
            graph.upsert_entity(entity).unwrap();
        }
        // Intra-file callers, the edges the two surfaces disagreed about.
        graph
            .upsert_relation(&make_relation(
                parse_note.id,
                extract_tags.id,
                RelationKind::Calls,
            ))
            .unwrap();
        graph
            .upsert_relation(&make_relation(
                parse_note.id,
                strip_code.id,
                RelationKind::Calls,
            ))
            .unwrap();
        graph
            .upsert_relation(&make_relation(
                ingest_dir.id,
                ingest_note.id,
                RelationKind::Calls,
            ))
            .unwrap();
        // One cross-file edge, so the graph can support an absence claim at all
        // and this test is about agreement rather than about the gate.
        graph
            .upsert_relation(&make_relation(
                ingest_dir.id,
                parse_note.id,
                RelationKind::Calls,
            ))
            .unwrap();

        let response = scan(&graph);
        assert!(
            response.verified,
            "the fixture resolves cross-file edges: {:?}",
            response.unverified_reasons
        );
        let joined = response.lines.join("\n");

        for entity in entities {
            let referenced = bulk_refs_sees_references(&graph, entity);
            let listed = joined.contains(&format!("  {} (", entity.name));
            assert_ne!(
                referenced, listed,
                "kin refs and dead-code must agree about {}: refs says referenced={referenced}, \
                 dead-code listed={listed}\n{joined}",
                entity.name
            );
        }

        assert!(
            joined.contains("legacy_helper"),
            "the one entity nothing references is still reported: {joined}"
        );
        assert!(
            joined.contains("3 as referenced by an entity in their own file"),
            "the scan says how many candidates their own file already referenced: {joined}"
        );
    }

    /// FIR-2356 regression, in the exact shape of the founding failure: a
    /// multi-module project with a declared entry point and cross-file usage,
    /// ingested into a graph that resolved no cross-file edge. The scan may
    /// answer; it may not answer confidently, and it may never list the entry
    /// point.
    #[test]
    fn a_multi_module_project_never_yields_a_confident_delete_list() {
        let graph = InMemoryGraph::new();

        let main = measured(make_entity("main", "nk/cli.py"), 3, 2);
        let cmd_ingest = measured(make_entity("cmd_ingest", "nk/cli.py"), 3, 2);
        let parse_note = measured(make_entity("parse_note", "nk/parsing.py"), 4, 1);
        let extract_tags = measured(make_entity("extract_tags", "nk/parsing.py"), 4, 1);
        let ingest_dir = measured(make_entity("Database.ingest_dir", "nk/storage.py"), 2, 2);
        let ingest_note = measured(make_entity("Database.ingest_note", "nk/storage.py"), 2, 2);
        let mut suite = measured(make_entity("test_parse_note", "tests/test_parsing.py"), 6, 3);
        suite.role = EntityRole::Test;

        for entity in [
            &main,
            &cmd_ingest,
            &parse_note,
            &extract_tags,
            &ingest_dir,
            &ingest_note,
            &suite,
        ] {
            graph.upsert_entity(entity).unwrap();
        }
        // Only the intra-file calls resolved, exactly as the 0.5.36 graph held
        // them: 16 intra-file Calls edges and not one crossing a file.
        for (src, dst) in [
            (main.id, cmd_ingest.id),
            (parse_note.id, extract_tags.id),
            (ingest_dir.id, ingest_note.id),
        ] {
            graph
                .upsert_relation(&make_relation(src, dst, RelationKind::Calls))
                .unwrap();
        }

        let response = scan(&graph);
        let joined = response.lines.join("\n");

        assert!(
            !response.verified,
            "a graph holding no cross-file edge cannot support a delete list: {joined}"
        );
        assert!(
            !joined.contains("Found "),
            "the confident phrasing is what made this output actionable: {joined}"
        );
        assert!(
            joined.contains("UNVERIFIED"),
            "the output says what it is: {joined}"
        );
        assert!(
            joined.contains("Do not delete on this evidence"),
            "the output says what not to do with it: {joined}"
        );
        assert!(
            response
                .unverified_reasons
                .iter()
                .any(|reason| reason.contains("no cross-file reference edge")),
            "the reason is the measured gap, not a generic caveat: {:?}",
            response.unverified_reasons
        );
        assert!(
            !joined.contains("main ("),
            "a declared entry point is referenced by construction and is never listed: {joined}"
        );
        assert!(
            !joined.contains("extract_tags") && !joined.contains("Database.ingest_note"),
            "an entity its own file already calls is not unreferenced: {joined}"
        );
        for row in response
            .lines
            .iter()
            .filter(|line| line.contains(" (Function, ") || line.contains(" (Method, "))
        {
            assert!(
                row.contains("[unverified]"),
                "every row carries its own label, because a row read alone is what gets acted \
                 on: {row}"
            );
        }

        // Same project, cross-file edges resolved: the graph can now support the
        // claim, and there is nothing left to report.
        for (src, dst) in [
            (cmd_ingest.id, ingest_dir.id),
            (ingest_dir.id, parse_note.id),
            (suite.id, parse_note.id),
        ] {
            graph
                .upsert_relation(&make_relation(src, dst, RelationKind::Calls))
                .unwrap();
        }
        let repaired = scan(&graph);
        let repaired_joined = repaired.lines.join("\n");
        assert!(
            repaired.verified,
            "resolved cross-file edges support the claim: {:?}",
            repaired.unverified_reasons
        );
        assert!(
            repaired_joined.contains("No dead code found."),
            "every entity in the fixture is reachable once the edges resolve: {repaired_joined}"
        );
    }

    /// A manifest the graph tracks but this scan could not read is a hole in the
    /// entry-point evidence, so the scan reports itself unverified rather than
    /// concluding no entry point is declared.
    #[test]
    fn an_unread_manifest_makes_the_scan_unverified() {
        let graph = InMemoryGraph::new();
        let orphan = measured(make_entity("never_called", "nk/legacy.py"), 0, 0);
        graph.upsert_entity(&orphan).unwrap();

        let coverage =
            kin_core::reference_coverage::collect_reference_edge_coverage(&graph).unwrap();
        let entry_points = kin_core::entry_points::DeclaredEntryPoints {
            entries: Vec::new(),
            manifests_read: Vec::new(),
            manifests_unreadable: vec!["pyproject.toml".to_string()],
        };
        let response = build_dead_code_report(&graph, &entry_points, &coverage).unwrap();

        assert!(!response.verified, "{:?}", response.lines);
        assert!(
            response
                .unverified_reasons
                .iter()
                .any(|reason| reason.contains("pyproject.toml")),
            "the reason names the manifest it could not read: {:?}",
            response.unverified_reasons
        );
        let joined = response.lines.join("\n");
        assert!(joined.contains("[unverified] never_called"), "{joined}");
    }

    /// A console script bound to a function that is not named `main` is still an
    /// entry point, and the output says which manifest it was read from.
    #[test]
    fn a_declared_entry_point_is_never_listed_and_its_source_is_named() {
        let graph = InMemoryGraph::new();
        let launcher = measured(make_entity("run", "nk/cli.py"), 0, 0);
        let orphan = measured(make_entity("never_called", "nk/legacy.py"), 0, 0);
        graph.upsert_entity(&launcher).unwrap();
        graph.upsert_entity(&orphan).unwrap();

        let coverage =
            kin_core::reference_coverage::collect_reference_edge_coverage(&graph).unwrap();
        let entry_points = kin_core::entry_points::DeclaredEntryPoints {
            entries: kin_core::entry_points::parse_manifest_entry_points(
                "pyproject.toml",
                b"[project.scripts]\nnk = \"nk.cli:run\"\n",
            ),
            manifests_read: vec!["pyproject.toml".to_string()],
            manifests_unreadable: Vec::new(),
        };
        let response = build_dead_code_report(&graph, &entry_points, &coverage).unwrap();
        let joined = response.lines.join("\n");

        assert!(response.verified, "{:?}", response.unverified_reasons);
        assert!(
            !joined.contains("run ("),
            "the declared console script is referenced by its launcher: {joined}"
        );
        assert!(
            joined.contains("never_called"),
            "an entity no manifest declares is still reported: {joined}"
        );
        assert!(
            joined.contains("1 as declared entry points")
                && joined.contains("entry points read from pyproject.toml"),
            "the scan discloses what it excluded and where the evidence came from: {joined}"
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
