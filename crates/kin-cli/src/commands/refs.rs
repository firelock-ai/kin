// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{Entity, EntityId, EntityStore, GraphNodeId, GraphStore, RelationKind};
use kin_ranking::entity_ranking;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::commands::declaration_neighbors;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefsRequest {
    pub entity: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefsResponse {
    #[serde(default)]
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRefsRequest {
    pub entity_ids: Vec<String>,
    #[serde(default = "default_bulk_kind")]
    pub kind: String,
    #[serde(default = "default_bulk_compact")]
    pub compact: bool,
}

fn default_bulk_kind() -> String {
    "Any".to_string()
}

fn default_bulk_compact() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRefsResponse {
    pub total_checked: usize,
    pub classified_count: usize,
    pub error_count: usize,
    pub incomplete_verdict_count: usize,
    pub with_references: usize,
    pub without_references: usize,
    #[serde(default)]
    pub relation_kinds: Vec<String>,
    pub compact: bool,
    #[serde(default)]
    pub results: Vec<serde_json::Value>,
}

pub async fn run(entity: String, kind: String) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let _scope = announce_active_scope(&layout, "refs").await?;
    let response = run_daemon_refs(&layout, &RefsRequest { entity, kind }).await?;
    for line in response.lines {
        println!("{}", crate::output_style::paint_refs_line(&line));
    }
    Ok(())
}

pub async fn run_bulk(entities: String, kind: String, compact: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let _scope = announce_active_scope(&layout, "refs:bulk").await?;
    let entity_ids: Vec<String> = entities
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if entity_ids.is_empty() {
        anyhow::bail!("--entities must be a comma-separated list of one or more entity UUIDs");
    }
    let response = run_daemon_bulk_refs(
        &layout,
        &BulkRefsRequest {
            entity_ids,
            kind,
            compact,
        },
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn run_daemon_refs(
    layout: &kin_core::KinLayout,
    request: &RefsRequest,
) -> Result<RefsResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url =
        daemon_url.ok_or_else(|| crate::daemon_client::daemon_required_error("refs", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.refs(request).await.context("daemon refs failed")
}

async fn run_daemon_bulk_refs(
    layout: &kin_core::KinLayout,
    request: &BulkRefsRequest,
) -> Result<BulkRefsResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url
        .ok_or_else(|| crate::daemon_client::daemon_required_error("bulk refs", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .bulk_refs(request)
        .await
        .context("daemon bulk refs failed")
}

pub fn build_refs_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &RefsRequest,
) -> Result<RefsResponse> {
    let relation_kinds = parse_relation_kinds(&request.kind)?;
    let target = if let Ok(uuid) = uuid::Uuid::parse_str(request.entity.trim()) {
        graph.get_entity(&EntityId(uuid))?
    } else {
        entity_ranking::select_best_entity(graph, &request.entity)?
    };
    let Some(target) = target else {
        return Ok(RefsResponse {
            lines: refs_not_found_guidance(&request.entity),
        });
    };
    let target = &target;

    let refs = collect_references(graph, target, &relation_kinds)?;
    let target_path = target
        .file_origin
        .as_ref()
        .map(|f| display_read_path(layout, &f.0))
        .unwrap_or_else(|| "unknown".to_string());

    let mut lines = Vec::new();
    lines.push(format!(
        "References to '{}' -> {} ({:?}) @ {}",
        request.entity, target.name, target.kind, target_path
    ));

    if refs.is_empty() {
        lines.push(format!(
            "No incoming {} relations.",
            relation_kinds_label(&relation_kinds)
        ));
        let neighbors = declaration_neighbors::collect(graph, target, &relation_kinds)?;
        lines.extend(empty_result_context(target, &neighbors));
        return Ok(RefsResponse { lines });
    }

    lines.push(format!("referenced by {} entities:", refs.len()));
    for entry in refs {
        let file_path = entry
            .file_path
            .as_deref()
            .map(|path| display_read_path(layout, path))
            .unwrap_or_else(|| "unknown".to_string());
        let line = entry.start_line.unwrap_or(0);
        lines.push(format!(
            "  {} @ {}:{} [{}]",
            entry.name,
            file_path,
            line,
            relation_kinds_label(&entry.relation_kinds)
        ));
    }

    Ok(RefsResponse { lines })
}

/// What the graph still says about a target whose incoming relations are empty.
///
/// An empty answer on a type declaration is true of that entity and misleading
/// about the repository: the references went to entities the declaration's name
/// qualifies, and Kin holds exactly which ones. Naming them turns "no callers"
/// into "these are the callers, one level down", and naming the same-name
/// identities resolution passed over says which node was actually answered for.
///
/// The listing is scoped by name and says so, because the graph ties a
/// declaration only to its same-file members. Claiming ownership instead would
/// tell a same-named declaration that another's members are its own.
///
/// An entity with neither members nor same-name siblings adds nothing here, so
/// it keeps the plain empty answer. That is what stops this note from becoming
/// noise that a reader learns to skip.
fn empty_result_context(
    target: &Entity,
    neighbors: &declaration_neighbors::DeclarationNeighbors,
) -> Vec<String> {
    let mut lines = Vec::new();

    let referenced: Vec<_> = neighbors.referenced_members().collect();
    if let Some(first) = referenced.first() {
        lines.push(format!(
            "{} entit{} named '{}::*' carr{} them:",
            referenced.len(),
            if referenced.len() == 1 { "y" } else { "ies" },
            target.name,
            if referenced.len() == 1 { "ies" } else { "y" },
        ));
        for member in referenced.iter().take(declaration_neighbors::MAX_LISTED) {
            lines.push(format!(
                "  {} @ {} [{} referencing {}]",
                member.name,
                member.location,
                member.referencing_entities,
                if member.referencing_entities == 1 {
                    "entity"
                } else {
                    "entities"
                },
            ));
        }
        if let Some(more) = declaration_neighbors::and_more_suffix(
            declaration_neighbors::MAX_LISTED,
            referenced.len(),
        ) {
            lines.push(format!("  {more}"));
        }
        lines.push(format!("  try: kin refs {}", first.name));
    }

    if !neighbors.siblings.is_empty() {
        lines.push(format!(
            "{} other graph identit{} the name '{}':",
            neighbors.siblings.len(),
            if neighbors.siblings.len() == 1 {
                "y carries"
            } else {
                "ies carry"
            },
            target.name
        ));
        for sibling in neighbors
            .siblings
            .iter()
            .take(declaration_neighbors::MAX_LISTED)
        {
            lines.push(format!(
                "  {} ({}) @ {}",
                sibling.name, sibling.kind, sibling.location
            ));
        }
        if let Some(more) = declaration_neighbors::and_more_suffix(
            declaration_neighbors::MAX_LISTED,
            neighbors.siblings.len(),
        ) {
            lines.push(format!("  {more}"));
        }
    }

    lines
}

/// Distinct entities that reference `entity_id` over the given relation kinds.
///
/// Counted through the same collector the listing is built from, so a count
/// reported beside a suggested `kin refs <member>` is the number that command
/// will print. A source id the graph carries an edge for but no entity record
/// for is still a distinct referencing identity, so it counts here; the ordinary
/// listing path fails loud on that same gap rather than reporting the row.
pub(crate) fn distinct_referencing_entities(
    graph: &impl GraphStore,
    entity_id: &EntityId,
    relation_kinds: &[RelationKind],
) -> Result<usize> {
    let collected = collect_graph_references(graph, entity_id, relation_kinds)?;
    Ok(collected.references.len() + collected.missing_source_ids.len())
}

/// Actionable guidance when `kin refs <symbol>` misses in the current repo's
/// graph.
///
/// `refs` resolves references within the CURRENT repo only. A symbol defined in
/// a sibling/dependency repo (e.g. a `kin-db` symbol queried from the `kin/`
/// graph) legitimately misses here. Rather than dead-ending on a bare
/// "Entity not found", keep the not-found signal but point the agent at the
/// cross-repo surface (`kin xref`) as the concrete next step.
///
/// We do not fabricate a cross-repo *existence* claim: confirming a symbol lives
/// in another repo requires the spine xref query, which is keyed by an entity id
/// we don't have on a local miss. So we hand off to `kin xref` (which performs
/// that lookup) instead of guessing.
fn refs_not_found_guidance(entity: &str) -> Vec<String> {
    let mut lines = vec![format!(
        "Entity '{}' not found in this repo's graph.",
        entity
    )];
    if uuid::Uuid::parse_str(entity.trim()).is_ok() {
        // A UUID miss can't be re-queried by name; xref resolves by symbol name.
        lines.push(
            "hint: `kin refs` resolves references within the current repo only. For a symbol \
             defined in a sibling/dependency repo, look it up cross-repo with `kin xref \
             <symbol-name>` (xref resolves by name)."
                .to_string(),
        );
    } else {
        lines
            .push("hint: `kin refs` resolves references within the current repo only.".to_string());
        lines.push(format!(
            "      If '{entity}' is defined in a sibling/dependency repo, look it up cross-repo:"
        ));
        lines.push(format!("        kin xref {entity}"));
    }
    lines
}

pub fn build_bulk_refs_response(
    graph: &kin_db::InMemoryGraph,
    request: &BulkRefsRequest,
) -> Result<BulkRefsResponse> {
    const MAX_BULK_ENTITIES: usize = 200;

    if request.entity_ids.is_empty() {
        anyhow::bail!("bulk_refs requires at least one entity_id");
    }
    if request.entity_ids.len() > MAX_BULK_ENTITIES {
        anyhow::bail!(
            "bulk_refs accepts at most {} entity_ids (got {})",
            MAX_BULK_ENTITIES,
            request.entity_ids.len()
        );
    }

    let relation_kinds = parse_bulk_relation_kind(&request.kind)?;
    let mut results = Vec::with_capacity(request.entity_ids.len());
    let mut with_references = 0usize;
    let mut without_references = 0usize;
    let mut error_count = 0usize;
    let mut incomplete_verdict_count = 0usize;

    for raw_id in &request.entity_ids {
        let parsed = uuid::Uuid::parse_str(raw_id.trim());
        let Ok(uuid) = parsed else {
            error_count += 1;
            results.push(bulk_refs_error_row(
                raw_id,
                "invalid entity_id (not a UUID)",
                request.compact,
            ));
            continue;
        };
        let entity_id = EntityId(uuid);
        let entity = graph.get_entity(&entity_id)?;
        let Some(entity) = entity else {
            error_count += 1;
            results.push(bulk_refs_error_row(
                raw_id,
                "entity not found",
                request.compact,
            ));
            continue;
        };

        // Bulk mode reports the same unit as the ordinary `kin refs` surface:
        // distinct referencing entities, not raw relation edges. One caller
        // may carry Calls, Imports, and References edges to the same target,
        // and ingestion may retain duplicate observations of an edge. Counting
        // those edges here made the compact answer disagree with the rows the
        // human-readable command could actually enumerate. Keep one grouping
        // authority for both paths so the count cannot drift again.
        let collected = collect_graph_references(graph, &entity_id, &relation_kinds)?;
        let reference_count = collected.references.len();
        let matched_kinds = collected.matched_kinds;

        if !collected.missing_source_ids.is_empty() {
            incomplete_verdict_count += 1;
            let missing_source_count = collected.missing_source_ids.len();
            let known_reference_count = reference_count + missing_source_count;
            let mut row = serde_json::json!({
                "entity_id": entity_id.to_string(),
                "has_references": null,
                "reference_count": null,
                "known_reference_count": known_reference_count,
                "reference_count_complete": false,
                "verdict_complete": false,
                "verdict_reason": format!(
                    "graph reference authority incomplete: {missing_source_count} incoming source entity record(s) missing"
                ),
                "missing_source_entity_count": missing_source_count,
            });
            if !request.compact {
                row["name"] = serde_json::json!(entity.name);
                row["kind"] = serde_json::json!(format!("{:?}", entity.kind));
                row["file_path"] =
                    serde_json::json!(entity.file_origin.as_ref().map(|p| p.0.clone()));
                row["matched_kinds"] = serde_json::json!(matched_kinds
                    .into_iter()
                    .map(relation_kind_label)
                    .collect::<Vec<_>>());
            }
            results.push(row);
            continue;
        }

        let has_references = reference_count > 0;
        if has_references {
            with_references += 1;
        } else {
            without_references += 1;
        }

        if request.compact {
            results.push(serde_json::json!({
                "entity_id": entity_id.to_string(),
                "has_references": has_references,
                "reference_count": reference_count,
            }));
        } else {
            results.push(serde_json::json!({
                "entity_id": entity_id.to_string(),
                "name": entity.name,
                "kind": format!("{:?}", entity.kind),
                "file_path": entity.file_origin.as_ref().map(|p| p.0.clone()),
                "has_references": has_references,
                "reference_count": reference_count,
                "matched_kinds": matched_kinds
                    .into_iter()
                    .map(relation_kind_label)
                    .collect::<Vec<_>>(),
            }));
        }
    }

    let total_checked = request.entity_ids.len();
    let classified_count = with_references + without_references;
    debug_assert_eq!(
        total_checked,
        classified_count + error_count + incomplete_verdict_count
    );
    Ok(BulkRefsResponse {
        total_checked,
        classified_count,
        error_count,
        incomplete_verdict_count,
        with_references,
        without_references,
        relation_kinds: relation_kinds
            .iter()
            .copied()
            .map(relation_kind_label)
            .collect(),
        compact: request.compact,
        results,
    })
}

fn bulk_refs_error_row(entity_id: &str, error: &str, compact: bool) -> serde_json::Value {
    let mut row = serde_json::json!({
        "entity_id": entity_id,
        "error": error,
        "has_references": null,
        "reference_count": null,
        "known_reference_count": null,
        "reference_count_complete": false,
        "verdict_complete": false,
    });
    if !compact {
        row["name"] = serde_json::Value::Null;
        row["kind"] = serde_json::Value::Null;
        row["file_path"] = serde_json::Value::Null;
        row["matched_kinds"] = serde_json::json!([]);
    }
    row
}

fn parse_bulk_relation_kind(value: &str) -> Result<Vec<RelationKind>> {
    match value.trim().to_ascii_lowercase().as_str() {
        "any" | "all" | "" => Ok(vec![
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ]),
        "calls" | "call" => Ok(vec![RelationKind::Calls]),
        "imports" | "import" => Ok(vec![RelationKind::Imports]),
        "references" | "reference" | "refs" => Ok(vec![RelationKind::References]),
        other => anyhow::bail!(
            "invalid --kind '{}': use Calls, Imports, References, or Any",
            other
        ),
    }
}

fn relation_kind_label(kind: RelationKind) -> String {
    match kind {
        RelationKind::Calls => "Calls",
        RelationKind::Imports => "Imports",
        RelationKind::References => "References",
        _ => "Other",
    }
    .to_string()
}

#[derive(Debug, Clone)]
struct ReferenceEntry {
    entity_id: EntityId,
    name: String,
    file_path: Option<String>,
    start_line: Option<u32>,
    relation_kinds: Vec<RelationKind>,
}

#[derive(Debug, Clone)]
struct ReferenceCollection {
    references: Vec<ReferenceEntry>,
    missing_source_ids: Vec<EntityId>,
    matched_kinds: Vec<RelationKind>,
}

/// Collect incoming references to `target` from graph-owned relation edges.
///
/// The graph is the sole authority for what references an entity. There is no
/// raw source-tree scan: a reference the graph does not carry is a
/// graph-completeness gap to close in ingestion, never something reconstructed
/// by walking and grepping the working tree at query time.
fn collect_references(
    graph: &impl GraphStore,
    target: &Entity,
    relation_kinds: &[RelationKind],
) -> Result<Vec<ReferenceEntry>> {
    let collected = collect_graph_references(graph, &target.id, relation_kinds)?;
    if !collected.missing_source_ids.is_empty() {
        let sample = collected
            .missing_source_ids
            .iter()
            .take(3)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "graph reference authority incomplete for entity {}: {} incoming source entity \
             record(s) missing (sample: {})",
            target.id,
            collected.missing_source_ids.len(),
            sample
        );
    }
    let mut entries = collected.references;
    entries.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.entity_id.cmp(&right.entity_id))
    });
    Ok(entries)
}

fn collect_graph_references(
    graph: &impl GraphStore,
    entity_id: &EntityId,
    relation_kinds: &[RelationKind],
) -> Result<ReferenceCollection> {
    let allowed: std::collections::HashSet<_> = relation_kinds.iter().copied().collect();
    let mut grouped: HashMap<EntityId, Vec<RelationKind>> = HashMap::new();
    let mut matched_kinds = Vec::new();

    for rel in graph.get_all_relations_for_entity(entity_id)? {
        if rel.dst != GraphNodeId::Entity(*entity_id) || !allowed.contains(&rel.kind) {
            continue;
        }
        let Some(src_entity_id) = rel.src.as_entity() else {
            continue;
        };
        // A recursive/self relation does not establish reachability from
        // another entity. Bulk refs has always excluded it for dead-code and
        // caller classification; keeping that rule in the shared collector
        // makes the ordinary and bulk surfaces agree without turning a
        // self-recursive orphan into a referenced entity.
        if src_entity_id == *entity_id {
            continue;
        }
        push_relation_kind(grouped.entry(src_entity_id).or_default(), rel.kind);
        push_relation_kind(&mut matched_kinds, rel.kind);
    }

    let mut references = Vec::with_capacity(grouped.len());
    let mut missing_source_ids = Vec::new();
    for (source_id, mut source_kinds) in grouped {
        source_kinds.sort_by_key(relation_kind_rank);
        let Some(entity) = graph.get_entity(&source_id)? else {
            missing_source_ids.push(source_id);
            continue;
        };
        references.push(ReferenceEntry {
            entity_id: source_id,
            name: entity.name.clone(),
            file_path: entity.file_origin.as_ref().map(|f| f.0.clone()),
            start_line: entity.span.as_ref().map(|s| s.start_line),
            relation_kinds: source_kinds,
        });
    }
    missing_source_ids.sort();
    matched_kinds.sort_by_key(relation_kind_rank);
    Ok(ReferenceCollection {
        references,
        missing_source_ids,
        matched_kinds,
    })
}

fn push_relation_kind(kinds: &mut Vec<RelationKind>, kind: RelationKind) {
    if !kinds.contains(&kind) {
        kinds.push(kind);
    }
}

fn parse_relation_kinds(kind: &str) -> Result<Vec<RelationKind>> {
    match kind.to_ascii_lowercase().as_str() {
        "all" => Ok(vec![
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ]),
        "calls" | "call" => Ok(vec![RelationKind::Calls]),
        "imports" | "import" => Ok(vec![RelationKind::Imports]),
        "references" | "refs" | "reference" => Ok(vec![RelationKind::References]),
        other => anyhow::bail!(
            "invalid --kind '{}': use one of all, calls, imports, references",
            other
        ),
    }
}

fn relation_kinds_label(kinds: &[RelationKind]) -> String {
    kinds
        .iter()
        .map(|kind| match kind {
            RelationKind::Calls => "Calls",
            RelationKind::Imports => "Imports",
            RelationKind::References => "References",
            _ => "Other",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn relation_kind_rank(kind: &RelationKind) -> usize {
    entity_ranking::relation_kind_rank(kind)
}

fn display_read_path(_layout: &kin_core::KinLayout, rel_path: &str) -> String {
    rel_path.to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        build_bulk_refs_response, build_refs_response, parse_relation_kinds,
        refs_not_found_guidance, BulkRefsRequest, BulkRefsResponse, RefsRequest,
    };
    use kin_model::RelationKind;

    /// `kin refs` must answer only from graph-owned relation edges. A reference
    /// that exists in the working tree but is not linked into the graph must
    /// never be surfaced, because there is no raw source-tree scan fallback: the
    /// retired scan walked the source root and matched import/call lines, which
    /// is exactly the file-first drift the graph-first thesis forbids.
    #[test]
    fn refs_answer_comes_from_graph_relations_not_source_tree_scan() {
        use kin_db::InMemoryGraph;
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, SemanticFingerprint,
            Visibility,
        };

        fn entity(name: &str, rel_path: &str) -> Entity {
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
                file_origin: Some(FilePathId::new(rel_path)),
                span: None,
                signature: name.to_string(),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".kin")).unwrap();
        let layout = kin_core::KinLayout::new(repo.join(".kin"));

        // A caller that exists ONLY in the working tree, never linked into the
        // graph. The retired text scan would have surfaced it by matching the
        // `use ...::probe_symbol` import line under the source root.
        std::fs::write(
            repo.join("disk_only_caller.rs"),
            "use crate::target_mod::probe_symbol;\npub fn disk_only() -> i32 { probe_symbol() }\n",
        )
        .unwrap();

        let target = entity("probe_symbol", "target_mod.rs");
        let graph_caller = entity("graph_caller", "graph_caller.rs");

        let graph = InMemoryGraph::new();
        graph.upsert_entity(&target).unwrap();
        graph.upsert_entity(&graph_caller).unwrap();
        graph
            .upsert_relation(&Relation {
                id: kin_model::ids::RelationId::new(),
                kind: RelationKind::References,
                src: GraphNodeId::Entity(graph_caller.id),
                dst: GraphNodeId::Entity(target.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let response = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: "probe_symbol".to_string(),
                kind: "all".to_string(),
            },
        )
        .unwrap();
        let joined = response.lines.join("\n");

        // The graph-linked reference is reported...
        assert!(
            joined.contains("graph_caller"),
            "graph-owned reference must be reported: {joined}"
        );
        // ...and the working-tree-only reference is not, proving refs no longer
        // answers by scanning the raw source tree.
        assert!(
            !joined.contains("disk_only"),
            "refs must not surface a reference that exists only in the working tree: {joined}"
        );
    }

    #[test]
    fn refs_not_found_guidance_keeps_signal_and_points_at_xref() {
        let lines = refs_not_found_guidance("load_vector_index_into_graph_if_valid");
        // Not-found signal preserved (don't silently swallow the miss).
        assert!(
            lines[0].contains("not found"),
            "first line keeps the not-found signal: {:?}",
            lines
        );
        let joined = lines.join("\n");
        // Actionable next step: the cross-repo surface, with a runnable command.
        assert!(
            joined.contains("kin xref"),
            "should point at xref: {joined}"
        );
        assert!(
            joined.contains("kin xref load_vector_index_into_graph_if_valid"),
            "should include a runnable cross-repo command: {joined}"
        );
    }

    #[test]
    fn refs_not_found_guidance_handles_uuid_query() {
        let uuid = "00000000-0000-0000-0000-000000000000";
        let lines = refs_not_found_guidance(uuid);
        let joined = lines.join("\n");
        assert!(lines[0].contains("not found"));
        // A UUID can't be re-queried by name, so guide toward xref by symbol name
        // rather than emitting `kin xref <uuid>`.
        assert!(joined.contains("kin xref"), "should mention xref: {joined}");
        assert!(
            !joined.contains(&format!("kin xref {uuid}")),
            "should not suggest `kin xref <uuid>`: {joined}"
        );
    }

    #[test]
    fn parse_relation_kinds_defaults_to_all_reference_types() {
        let kinds = parse_relation_kinds("all").unwrap();
        assert_eq!(
            kinds,
            vec![
                RelationKind::Calls,
                RelationKind::Imports,
                RelationKind::References
            ]
        );
    }

    #[test]
    fn parse_relation_kinds_accepts_import_alias() {
        let kinds = parse_relation_kinds("import").unwrap();
        assert_eq!(kinds, vec![RelationKind::Imports]);
    }

    /// Distinct entity ids are distinct callers even when their display
    /// metadata is identical. Duplicate/multi-kind edges from one caller enrich
    /// that caller's row, and self-edges do not establish external reachability.
    #[test]
    fn refs_and_bulk_count_distinct_external_entities_not_relation_edges_or_self_edges() {
        use kin_db::InMemoryGraph;
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, SemanticFingerprint,
            Visibility,
        };

        fn entity(name: &str, rel_path: &str) -> Entity {
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
                file_origin: Some(FilePathId::new(rel_path)),
                span: None,
                signature: name.to_string(),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));

        let target = entity("probe_symbol", "target_mod.rs");
        // Same file and same name are deliberate: display metadata cannot be
        // the grouping key. These remain two semantic entities by id.
        let caller_a = entity("shared_caller", "callers.rs");
        let caller_b = entity("shared_caller", "callers.rs");

        let graph = InMemoryGraph::new();
        for e in [&target, &caller_a, &caller_b] {
            graph.upsert_entity(e).unwrap();
        }
        for caller in [&caller_a, &caller_b] {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind: RelationKind::References,
                    src: GraphNodeId::Entity(caller.id),
                    dst: GraphNodeId::Entity(target.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }
        // The same caller can carry multiple graph-owned observations of the
        // target. They enrich its row; they do not create more callers.
        for kind in [RelationKind::References, RelationKind::Calls] {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind,
                    src: GraphNodeId::Entity(caller_a.id),
                    dst: GraphNodeId::Entity(target.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }
        // A recursive-only edge does not make the target reachable from some
        // other entity and must not affect either count or matched_kinds.
        for kind in [
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ] {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind,
                    src: GraphNodeId::Entity(target.id),
                    dst: GraphNodeId::Entity(target.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }

        let response = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: "probe_symbol".to_string(),
                kind: "all".to_string(),
            },
        )
        .unwrap();
        let joined = response.lines.join("\n");

        assert!(
            joined.contains("referenced by 2 entities:"),
            "count line must count entities: {joined}"
        );
        assert!(
            joined.matches("shared_caller @ callers.rs:0").count() == 2,
            "both same-metadata entity ids must be listed separately: {joined}"
        );

        let compact = build_bulk_refs_response(
            &graph,
            &BulkRefsRequest {
                entity_ids: vec![target.id.to_string()],
                kind: "Any".to_string(),
                compact: true,
            },
        )
        .unwrap();
        assert_eq!(compact.classified_count, 1);
        assert_eq!(compact.error_count, 0);
        assert_eq!(compact.incomplete_verdict_count, 0);
        assert_eq!(compact.with_references, 1);
        assert_eq!(compact.without_references, 0);
        assert_eq!(compact.results[0]["reference_count"], 2);
        assert_eq!(compact.results[0]["has_references"], true);
        assert_eq!(compact.results[0]["entity_id"], target.id.to_string());
        assert!(compact.results[0].get("matched_kinds").is_none());
        assert!(compact.results[0].get("name").is_none());

        let verbose = build_bulk_refs_response(
            &graph,
            &BulkRefsRequest {
                entity_ids: vec![target.id.to_string()],
                kind: "Any".to_string(),
                compact: false,
            },
        )
        .unwrap();
        assert_eq!(verbose.results[0]["reference_count"], 2);
        assert_eq!(verbose.results[0]["has_references"], true);
        assert_eq!(verbose.results[0]["entity_id"], target.id.to_string());
        assert_eq!(verbose.results[0]["name"], "probe_symbol");
        assert_eq!(verbose.results[0]["kind"], "Function");
        assert_eq!(verbose.results[0]["file_path"], "target_mod.rs");
        assert_eq!(
            verbose.results[0]["matched_kinds"],
            serde_json::json!(["Calls", "References"])
        );

        let self_only_kind = build_bulk_refs_response(
            &graph,
            &BulkRefsRequest {
                entity_ids: vec![target.id.to_string()],
                kind: "Imports".to_string(),
                compact: true,
            },
        )
        .unwrap();
        assert_eq!(self_only_kind.results[0]["has_references"], false);
        assert_eq!(self_only_kind.results[0]["reference_count"], 0);
        assert_eq!(self_only_kind.classified_count, 1);
        assert_eq!(self_only_kind.error_count, 0);
        assert_eq!(self_only_kind.incomplete_verdict_count, 0);
        assert_eq!(self_only_kind.with_references, 0);
        assert_eq!(self_only_kind.without_references, 1);
    }

    #[test]
    fn bulk_invalid_and_missing_targets_are_errors_never_negative_verdicts() {
        let graph = kin_db::InMemoryGraph::new();
        let missing_id = kin_model::EntityId::new().to_string();

        for compact in [true, false] {
            let response = build_bulk_refs_response(
                &graph,
                &BulkRefsRequest {
                    entity_ids: vec!["not-a-uuid".to_string(), missing_id.clone()],
                    kind: "Any".to_string(),
                    compact,
                },
            )
            .unwrap();

            assert_eq!(response.total_checked, 2);
            assert_eq!(response.classified_count, 0);
            assert_eq!(response.error_count, 2);
            assert_eq!(response.incomplete_verdict_count, 0);
            assert_eq!(response.with_references, 0);
            assert_eq!(response.without_references, 0);
            assert_bulk_error_row(
                &response.results[0],
                compact,
                "invalid entity_id (not a UUID)",
            );
            assert_bulk_error_row(&response.results[1], compact, "entity not found");
        }
    }

    #[test]
    fn dangling_reference_source_is_explicitly_incomplete_in_both_modes() {
        use kin_db::InMemoryGraph;
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, SemanticFingerprint,
            Visibility,
        };

        fn entity(name: &str, rel_path: &str) -> Entity {
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
                    equivalence_hash: Hash256::from_bytes([0; 32]),
                    stability_score: 1.0,
                },
                file_origin: Some(FilePathId::new(rel_path)),
                span: None,
                signature: name.to_string(),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            }
        }

        let target = entity("target", "target.rs");
        let materialized_caller = entity("caller", "caller.rs");
        let missing_source_id = EntityId::new();
        let graph = InMemoryGraph::new();
        graph.upsert_entity(&target).unwrap();
        graph.upsert_entity(&materialized_caller).unwrap();

        for (source_id, kind) in [
            (materialized_caller.id, RelationKind::References),
            (missing_source_id, RelationKind::References),
            // Repeated/multi-kind observations from the missing source remain
            // one known caller identity while preserving the known kind union.
            (missing_source_id, RelationKind::References),
            (missing_source_id, RelationKind::Calls),
        ] {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind,
                    src: GraphNodeId::Entity(source_id),
                    dst: GraphNodeId::Entity(target.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }

        for compact in [true, false] {
            let response = build_bulk_refs_response(
                &graph,
                &BulkRefsRequest {
                    entity_ids: vec![target.id.to_string()],
                    kind: "Any".to_string(),
                    compact,
                },
            )
            .unwrap();

            assert_eq!(response.total_checked, 1);
            assert_eq!(response.classified_count, 0);
            assert_eq!(response.error_count, 0);
            assert_eq!(response.incomplete_verdict_count, 1);
            assert_eq!(response.with_references, 0);
            assert_eq!(response.without_references, 0);

            let row = &response.results[0];
            assert!(row["has_references"].is_null());
            assert!(row["reference_count"].is_null());
            assert_eq!(row["known_reference_count"], 2);
            assert_eq!(row["reference_count_complete"], false);
            assert_eq!(row["verdict_complete"], false);
            assert_eq!(row["missing_source_entity_count"], 1);
            assert!(row["verdict_reason"]
                .as_str()
                .unwrap()
                .contains("graph reference authority incomplete"));
            if compact {
                assert!(row.get("name").is_none());
                assert!(row.get("matched_kinds").is_none());
            } else {
                assert_eq!(row["name"], "target");
                assert_eq!(row["kind"], "Function");
                assert_eq!(row["file_path"], "target.rs");
                assert_eq!(
                    row["matched_kinds"],
                    serde_json::json!(["Calls", "References"])
                );
            }
        }

        let layout = kin_core::KinLayout::new(tempfile::tempdir().unwrap().path().join(".kin"));
        let error = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: target.id.to_string(),
                kind: "all".to_string(),
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("graph reference authority incomplete"),
            "ordinary refs must fail loud on the same gap: {error:#}"
        );
    }

    #[test]
    fn request_level_bulk_failures_return_no_classification_response() {
        let graph = kin_db::InMemoryGraph::new();
        assert!(build_bulk_refs_response(
            &graph,
            &BulkRefsRequest {
                entity_ids: Vec::new(),
                kind: "Any".to_string(),
                compact: true,
            },
        )
        .is_err());
        assert!(build_bulk_refs_response(
            &graph,
            &BulkRefsRequest {
                entity_ids: vec![kin_model::EntityId::new().to_string()],
                kind: "unsupported".to_string(),
                compact: false,
            },
        )
        .is_err());
    }

    #[test]
    fn legacy_bulk_response_without_completeness_counts_fails_closed() {
        let legacy = serde_json::json!({
            "total_checked": 1,
            "with_references": 0,
            "without_references": 1,
            "relation_kinds": ["Calls", "Imports", "References"],
            "compact": true,
            "results": [{
                "entity_id": kin_model::EntityId::new().to_string(),
                "has_references": false,
                "reference_count": 0
            }]
        });

        let error = serde_json::from_value::<BulkRefsResponse>(legacy).unwrap_err();
        assert!(
            error.to_string().contains("classified_count"),
            "a version-skewed response must fail instead of recovering unsafe negatives: {error}"
        );
    }

    fn assert_bulk_error_row(row: &serde_json::Value, compact: bool, expected_error: &str) {
        assert_eq!(row["error"], expected_error);
        assert!(row["has_references"].is_null());
        assert!(row["reference_count"].is_null());
        assert!(row["known_reference_count"].is_null());
        assert_eq!(row["reference_count_complete"], false);
        assert_eq!(row["verdict_complete"], false);
        if compact {
            assert!(row.get("name").is_none());
            assert!(row.get("kind").is_none());
            assert!(row.get("file_path").is_none());
            assert!(row.get("matched_kinds").is_none());
        } else {
            assert!(row["name"].is_null());
            assert!(row["kind"].is_null());
            assert!(row["file_path"].is_null());
            assert_eq!(row["matched_kinds"], serde_json::json!([]));
        }
    }
}
