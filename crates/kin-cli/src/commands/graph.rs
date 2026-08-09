// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use kin_mcp::handlers::common::presentation_span_lines;
use kin_model::{
    Entity, EntityId, EntityKind, EntityRole, EntityStore, GraphStore, Hash256, RelationKind,
};
use serde::{Deserialize, Serialize};

use super::graph_health::inspect_graph;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum GraphCommandRequest {
    Status,
    Validate,
    Inspect { name: String },
    Source { entity: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphCommandResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<GraphSourceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSourceRecord {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub language: String,
    pub file_path: String,
    /// 1-based inclusive presentation lines, converted from the graph's 0-based
    /// span rows at construction. This record is only ever printed or serialized
    /// to an agent, so it carries the editor convention; `start_byte`/`end_byte`
    /// stay in the graph's own domain because they are offsets, not positions.
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: usize,
    pub end_byte: usize,
    pub signature: String,
    pub body: String,
    /// Whether the span that cut `body` was proven to describe these exact bytes
    /// (`kin_mcp::handlers::common::SpanCoherence::label`).
    ///
    /// A provable mismatch never reaches here, because it fails the read. What this
    /// distinguishes is a verified pair from one the graph recorded no digest for,
    /// so a caller about to restate this body as an edit can tell which it has.
    pub span_coherence: String,
}

/// The three distinguishable results of resolving an entity's source for
/// `get_entity_source` / `get_entity_body`.
///
/// Callers (agents especially) must be able to tell these apart: a source they
/// can act on, an ID that does not exist (retrying it is pointless), and a real
/// entity that simply has no source body attached to graph truth. Collapsing
/// the latter two into one opaque "missing source" message makes agents retry
/// invented or stale IDs and probe adjacent ones, which burns their tool-call
/// budget for no gain.
#[derive(Debug, Clone)]
pub enum EntitySourceOutcome {
    /// The entity resolved and its source body was read from graph-owned truth.
    Found(GraphSourceRecord),
    /// The query resolved to no entity. Non-retryable: the ID is invalid or
    /// stale. The string is an agent-facing explanation.
    NotFound(String),
    /// The entity resolved but has no source body in graph truth (no file
    /// origin or no source span). Distinct from [`EntitySourceOutcome::NotFound`]
    /// — the ID is valid, there is simply nothing to return.
    NoSource(String),
}

/// `kin graph status` — quick health check of the semantic graph.
pub async fn status() -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    print_graph_response(run_daemon_graph(&layout, &GraphCommandRequest::Status).await?)
}

/// `kin graph validate` — structural integrity checks.
pub async fn validate() -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    print_graph_response(run_daemon_graph(&layout, &GraphCommandRequest::Validate).await?)
}

/// `kin graph inspect <entity>` — look up an entity (by name or UUID) and show its relations.
///
/// In `--json` mode, the full `GraphCommandResponse` ({lines, error}) is emitted
/// as JSON. A missing-entity response (response.error set) is emitted with exit
/// 0, matching the graceful behavior of `get_context_pack` and `graph source --json`.
/// This lets an LLM agent recover from a hallucinated UUID instead of treating
/// the tool call as a hard CLI failure.
pub async fn inspect(name: String, json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_graph(&layout, &GraphCommandRequest::Inspect { name }).await?;
    if json {
        // SP-23 graceful-error: emit the full response (lines + error) as JSON
        // with exit 0 even when entity is missing.
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "lines": response.lines,
                "error": response.error,
            }))?
        );
        return Ok(());
    }
    print_graph_response(response)
}

/// `kin graph source <entity>` — print the exact implementation body.
///
/// In `--json` mode, a missing-entity response (HTTP 200 with `error` set) is
/// emitted as `{"error": "..."}` on stdout with exit code 0, matching the
/// graceful behavior of `get_context_pack`. This lets an LLM agent recover from
/// a hallucinated UUID by treating the tool call as a structured "not found"
/// response rather than a hard CLI failure. Non-JSON mode keeps the existing
/// exit-1-on-error behavior for shell-script compatibility.
pub async fn source(entity: String, json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_graph(&layout, &GraphCommandRequest::Source { entity }).await?;
    if json {
        if let Some(error) = response.error {
            // SP-23 graceful-error: emit structured {"error": "..."} on stdout
            // and exit 0 so the model can recover from a fabricated UUID.
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "error": error }))?
            );
            return Ok(());
        }
        let source = response
            .source
            .ok_or_else(|| anyhow::anyhow!("daemon source response did not include source"))?;
        println!("{}", serde_json::to_string_pretty(&source)?);
        return Ok(());
    }
    print_graph_response(response)
}

/// `kin graph body <entity>` — alias for `kin graph source <entity>`.
pub async fn body(entity: String, json: bool) -> Result<()> {
    source(entity, json).await
}

async fn run_daemon_graph(
    layout: &kin_core::KinLayout,
    request: &GraphCommandRequest,
) -> Result<GraphCommandResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!(
            "Kin daemon is required for graph commands but no daemon endpoint is available"
        )
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .graph_command(request)
        .await
        .map_err(|e| anyhow::anyhow!("daemon graph command failed: {e:#}"))
}

fn print_graph_response(response: GraphCommandResponse) -> Result<()> {
    for line in response.lines {
        println!("{line}");
    }
    if let Some(error) = response.error {
        anyhow::bail!(error);
    }
    Ok(())
}

/// Render a graph command.
///
/// `reconcile` is the running daemon's account of what its reconciliation loop
/// has actually admitted. It is a separate argument rather than something
/// derived from the graph because it cannot be derived from the graph: a store
/// whose every admission has failed for two days holds a graph that is
/// internally perfect and simply out of date, and every content check here
/// passes on it. That is how `kin graph status` came to report no issues on a
/// store the daemon had been failing to admit since Aug 6.
pub fn execute_graph_command(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &kin_db::InMemoryGraph,
    request: &GraphCommandRequest,
    reconcile: &crate::commands::resources::ReconcileHealth,
) -> Result<GraphCommandResponse> {
    match request {
        GraphCommandRequest::Status => build_graph_status_response(binding, graph, reconcile),
        GraphCommandRequest::Validate => build_graph_validate_response(binding, graph),
        GraphCommandRequest::Inspect { name } => build_graph_inspect_response(graph, name),
        GraphCommandRequest::Source { entity } => build_graph_source_response(
            &super::repository_authority::RequestRepositoryAuthority::pinned(binding.clone()),
            graph,
            entity,
        ),
    }
}

fn build_graph_status_response(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &kin_db::InMemoryGraph,
    reconcile: &crate::commands::resources::ReconcileHealth,
) -> Result<GraphCommandResponse> {
    let health = inspect_graph(binding, graph)?;

    let entities = graph.list_all_entities()?;

    // An external reference target is a node this repository references without
    // owning: no file, no span, no signature, and a uniform kind. Counting it
    // among the entities this repository holds would report documentation
    // coverage falling with no change to documentation, put a fabricated bucket
    // in the kind histogram, and make the entity and file totals stop
    // corresponding. It is counted on its own line instead, so it is disclosed
    // rather than either hidden or folded into a claim about this repository's
    // own code.
    let (defined, external_targets): (Vec<&Entity>, Vec<&Entity>) = entities
        .iter()
        .partition(|e| !kin_index::is_external_reference_target(e));
    let entity_count = defined.len();

    // Role counts, over the entities this repository defines. Role
    // classification is a statement about a repository's own files, and the
    // warning below reads these counts to decide whether the classifier ran at
    // all.
    let mut role_counts: HashMap<EntityRole, usize> = HashMap::new();
    for e in &defined {
        *role_counts.entry(e.role).or_insert(0) += 1;
    }

    // Kind counts
    let mut kind_counts: HashMap<EntityKind, usize> = HashMap::new();
    for e in &defined {
        *kind_counts.entry(e.kind).or_insert(0) += 1;
    }

    // Relation counts by kind. Entity-rooted traversal only reaches edges whose
    // src and dst are both entities, so this total is narrower than the whole
    // relation table, which also carries artifact-, test-, contract-, work-, and
    // verification-run-anchored edges. Both totals are reported below, each
    // labeled with the scope it counts.
    let mut relation_counts: HashMap<RelationKind, usize> = HashMap::new();
    let mut seen_relation_ids = HashSet::new();
    let mut total_relations = 0usize;
    for e in &entities {
        for rel in graph.get_all_relations_for_entity(&e.id)? {
            if seen_relation_ids.insert(rel.id) {
                *relation_counts.entry(rel.kind).or_insert(0) += 1;
                total_relations += 1;
            }
        }
    }

    // File count
    let unique_files: HashSet<_> = entities
        .iter()
        .filter_map(|e| e.file_origin.as_ref().map(|f| f.0.clone()))
        .collect();

    // Embedding status
    let embed_status = graph.embedding_status();

    // Doc summary coverage
    let with_docs = defined.iter().filter(|e| e.doc_summary.is_some()).count();

    let mut lines = Vec::new();
    lines.push("=== Graph Health ===".to_string());
    lines.push(String::new());
    lines.push(format!(
        "Entities: {}  |  Entity-to-entity relations: {}  |  Files: {}",
        entity_count,
        total_relations,
        unique_files.len()
    ));
    lines.push(format!(
        "Entity-to-entity rels/entity: {:.2}",
        if entity_count == 0 {
            0.0
        } else {
            total_relations as f64 / entity_count as f64
        }
    ));
    lines.push(format!(
        "External reference targets: {}",
        external_targets.len()
    ));
    lines.push(String::new());

    // Roles
    let role_order = [
        (EntityRole::Source, "source"),
        (EntityRole::Test, "test"),
        (EntityRole::External, "external"),
        (EntityRole::Docs, "docs"),
        (EntityRole::Generated, "generated"),
        (EntityRole::Vendored, "vendored"),
    ];
    let role_parts: Vec<String> = role_order
        .iter()
        .filter_map(|(role, label)| role_counts.get(role).map(|c| format!("{label}: {c}")))
        .collect();
    lines.push(format!("Roles: {}", role_parts.join(", ")));

    // Relation types
    let mut rel_pairs: Vec<_> = relation_counts.iter().collect();
    rel_pairs.sort_by(|a, b| b.1.cmp(a.1));
    let rel_parts: Vec<String> = rel_pairs
        .iter()
        .map(|(kind, count)| format!("{:?}: {}", kind, count))
        .collect();
    lines.push(format!(
        "Entity-to-entity relation kinds: {}",
        rel_parts.join(", ")
    ));

    // Kind distribution
    let mut kind_pairs: Vec<_> = kind_counts.iter().collect();
    kind_pairs.sort_by(|a, b| b.1.cmp(a.1));
    let kind_parts: Vec<String> = kind_pairs
        .iter()
        .take(8)
        .map(|(kind, count)| format!("{:?}: {}", kind, count))
        .collect();
    lines.push(format!("Kinds: {}", kind_parts.join(", ")));

    lines.push(String::new());
    lines.push(format!(
        "Embeddings: {}/{} indexed ({} pending)",
        embed_status.indexed, embed_status.total, embed_status.pending
    ));
    lines.push(format!(
        "Doc summaries: {}/{} ({:.0}%)",
        with_docs,
        entity_count,
        if entity_count == 0 {
            0.0
        } else {
            (with_docs as f64 / entity_count as f64) * 100.0
        }
    ));
    lines.push(format!(
        "All graph relations excluding CoChanges: {} ({:.2}/entity)",
        health.semantic_relation_count, health.semantic_relation_density_excluding_cochanges
    ));
    lines.push(format!(
        "Supported inputs: {} full-adapter, {} shallow",
        health.supported_entity_source_file_count, health.supported_shallow_source_file_count
    ));
    lines.push(format!(
        "Contaminated paths: {}",
        health.contaminated_path_count
    ));
    if !health.contaminated_paths_sample.is_empty() {
        lines.push(format!(
            "Contamination sample: {}",
            health.contaminated_paths_sample.join(", ")
        ));
    }

    // Warnings
    let mut warnings = health.warnings.clone();
    let criticals = health.critical_issues.clone();
    let all_relation_count = health
        .semantic_relation_count
        .saturating_add(health.cochange_relation_count);
    if entity_count > 0 && all_relation_count == 0 {
        warnings.push("no relations in graph — cross-file linking may have failed".to_string());
    }
    if entity_count > 0 && role_counts.len() == 1 && role_counts.contains_key(&EntityRole::Source) {
        warnings
            .push("all entities are Source — role classification may not be working".to_string());
    }
    let entity_rels_per_ent = if entity_count == 0 {
        0.0
    } else {
        total_relations as f64 / entity_count as f64
    };
    if entity_rels_per_ent < 0.1 && entity_count > 100 {
        warnings.push(format!(
            "very low entity-to-entity relation density ({:.2} rels/entity) — entity linker may be failing",
            entity_rels_per_ent
        ));
    }
    // Reported as warnings rather than as criticals on purpose. A degraded
    // reconcile loop is a live runtime fault and not a defect in the graph this
    // command inspected, and criticals set the response error, which would turn
    // `kin graph status` nonzero for every caller scripting it. Killing the
    // false all-clear is the requirement; changing an exit code is not.
    for reason in reconcile.degraded_reasons() {
        warnings.push(format!("reconcile loop degraded — {reason}"));
    }
    if warnings.is_empty() && criticals.is_empty() {
        lines.push(String::new());
        lines.push("✓ No issues detected.".to_string());
    } else {
        lines.push(String::new());
        for issue in &criticals {
            lines.push(format!("✗ {}", issue));
        }
        for w in &warnings {
            lines.push(format!("⚠ {}", w));
        }
    }
    append_health_notes(&mut lines, &health.notes);

    Ok(GraphCommandResponse {
        lines,
        error: (!criticals.is_empty())
            .then(|| format!("{} critical graph health issue(s) found", criticals.len())),
        source: None,
    })
}

/// Render a health report's notes in the single form every graph reporting
/// surface uses.
///
/// Notes describe expected absences rather than defects, so they follow the
/// verdict instead of suppressing it. `status` and `validate` render them from
/// here so the two cannot drift: a surface that carries the verdict but drops
/// the notes reports a repository whose enrichment is still pending as
/// indistinguishable from a fully enriched one.
fn append_health_notes(lines: &mut Vec<String>, notes: &[String]) {
    for note in notes {
        lines.push(format!("ℹ {}", note));
    }
}

fn build_graph_validate_response(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &kin_db::InMemoryGraph,
) -> Result<GraphCommandResponse> {
    let health = inspect_graph(binding, graph)?;

    // Validation needs the complete relation table, including corrupt edges
    // whose source and destination are both absent. Entity-rooted traversal
    // cannot discover those edges. A live snapshot is a coherent, graph-owned
    // view of both tables; relation IDs are still deduplicated defensively
    // below before endpoint accounting.
    let snapshot = graph.to_snapshot();
    let entities: Vec<_> = snapshot.entities.into_values().collect();
    let relations = snapshot.relations.into_values();
    let mut issues = Vec::new();

    // Check for duplicate entities (same name + file + kind + byte position).
    // Using byte position distinguishes legitimate overloads (Python @overload,
    // Rust impl From<X>, C++ template specializations) from true duplicates: two
    // entities declared at different positions in one file are never duplicates.
    //
    // An entity with no span has no position to be distinguished by, and
    // collapsing that to byte zero makes the position discriminate nothing. An
    // external reference target is exactly that shape: it stands for a symbol
    // another repository owns, so it carries no file and no span, and its kind
    // is uniform. Name alone would then report two legitimately distinct
    // targets as one duplicated entity, which is what `use log::info` beside
    // `use tracing::info` produces on an ordinary repository. Its fingerprint
    // is derived from the facts that do identify it, the import source and the
    // symbol, so it stands in for the absent position and keeps the check
    // meaningful: two targets naming different import sources stay distinct,
    // while two entities claiming the same import source and symbol are still
    // reported. Entities that do carry a span keep the position key exactly as
    // before, so nothing this check used to catch stops being caught.
    let mut seen: HashMap<
        (String, Option<String>, EntityKind, usize, Option<Hash256>),
        Vec<kin_model::EntityId>,
    > = HashMap::new();
    for e in &entities {
        let start_byte = e.span.as_ref().map(|s| s.start_byte).unwrap_or(0);
        let placeless_identity = e.span.is_none().then_some(e.fingerprint.ast_hash);
        let key = (
            e.name.clone(),
            e.file_origin.as_ref().map(|f| f.0.clone()),
            e.kind,
            start_byte,
            placeless_identity,
        );
        seen.entry(key).or_default().push(e.id);
    }
    let duplicates: Vec<_> = seen.iter().filter(|(_, ids)| ids.len() > 1).collect();
    if !duplicates.is_empty() {
        issues.push(format!(
            "{} true duplicate entities (same name+file+kind, same position or same identity)",
            duplicates.len()
        ));
    }

    // Check for orphaned entities against graph-owned exact tree membership.
    // The working directory is only a projection and cannot invalidate graph
    // authority.
    let resolved_tree = graph.resolved_tree();
    let mut orphaned = 0usize;
    for e in &entities {
        if let Some(ref fo) = e.file_origin {
            let present = kin_model::RepoPath::from_utf8(fo.0.clone())
                .ok()
                .and_then(|path| resolved_tree.artifact_at_path(&path))
                .is_some();
            if !present {
                orphaned += 1;
            }
        }
    }
    if orphaned > 0 {
        issues.push(format!(
            "{} orphaned entities (file is absent from graph-owned exact tree)",
            orphaned
        ));
    }

    // Check relation integrity (src/dst entity IDs exist). Cross-repo Calls and
    // References intentionally point at a deterministic external placeholder
    // that is absent from this repo's entity set. The linker marks that exact
    // contract with a non-empty import source and external_import_reference
    // evidence; every other missing endpoint remains a validation failure.
    let entity_ids: std::collections::HashSet<_> = entities.iter().map(|e| e.id).collect();
    let mut seen_relation_ids = HashSet::new();
    let mut broken_relation_endpoints = 0usize;
    for rel in relations {
        if !seen_relation_ids.insert(rel.id) {
            continue;
        }
        if let kin_model::GraphNodeId::Entity(id) = rel.src {
            if !entity_ids.contains(&id) {
                broken_relation_endpoints += 1;
            }
        }
        if let kin_model::GraphNodeId::Entity(id) = rel.dst {
            if !entity_ids.contains(&id) && !kin_index::is_external_import_placeholder(&rel) {
                broken_relation_endpoints += 1;
            }
        }
    }
    let inspected_relation_count = seen_relation_ids.len();
    if broken_relation_endpoints > 0 {
        let (endpoint_label, verb) = if broken_relation_endpoints == 1 {
            ("relation endpoint", "references")
        } else {
            ("relation endpoints", "reference")
        };
        issues.push(format!(
            "{} {} {} non-existent entities",
            broken_relation_endpoints, endpoint_label, verb
        ));
    }

    issues.extend(health.critical_issues.clone());

    let mut lines = Vec::new();
    lines.push("=== Graph Validation ===".to_string());
    lines.push(String::new());
    let relation_label = if inspected_relation_count == 1 {
        "relation"
    } else {
        "relations"
    };
    lines.push(format!(
        "Checked {} entities, {} {}",
        entities.len(),
        inspected_relation_count,
        relation_label
    ));

    if issues.is_empty() {
        lines.push(String::new());
        lines.push("✓ All checks passed.".to_string());
    } else {
        lines.push(String::new());
        for issue in &issues {
            lines.push(format!("✗ {}", issue));
        }
    }
    append_health_notes(&mut lines, &health.notes);

    Ok(GraphCommandResponse {
        lines,
        error: (!issues.is_empty()).then(|| format!("{} issue(s) found", issues.len())),
        source: None,
    })
}

fn build_graph_inspect_response(
    graph: &kin_db::InMemoryGraph,
    name: &str,
) -> Result<GraphCommandResponse> {
    let entities = graph.list_all_entities()?;
    let matches: Vec<_> = if let Ok(uuid) = uuid::Uuid::parse_str(name.trim()) {
        graph.get_entity(&EntityId(uuid))?.into_iter().collect()
    } else {
        entities
            .into_iter()
            .filter(|e| e.name == name || e.name.ends_with(&format!(".{}", name)))
            .collect()
    };

    if matches.is_empty() {
        return Ok(GraphCommandResponse {
            lines: graph_entity_not_found_lines(name),
            error: Some(format!("no entity found matching '{}'", name)),
            source: None,
        });
    }

    let mut lines = Vec::new();
    for entity in matches {
        lines.push(format!("Entity: {} ({:?})", entity.name, entity.kind));
        lines.push(format!("  ID: {}", entity.id));
        lines.push(format!("  Language: {}", entity.language));
        lines.push(format!("  Role: {:?}", entity.role));
        if let Some(ref fo) = entity.file_origin {
            lines.push(format!("  File: {}", fo.0));
        }
        if let Some(ref span) = entity.span {
            let (start_line, end_line) = presentation_span_lines(span);
            lines.push(format!("  Span: lines {start_line}-{end_line}"));
        }
        lines.push(format!("  Signature: {}", entity.signature));
        if let Some(ref doc) = entity.doc_summary {
            lines.push(format!("  Doc: {}", doc));
        }
        lines.push(format!("  Visibility: {:?}", entity.visibility));

        // Show relations
        let rows = inspect_relation_rows(graph, &entity)?;
        if rows.total > 0 {
            lines.push(format!("  Relations ({}):", rows.total));
            for row in &rows.displayed {
                lines.push(format!(
                    "    {} {:?} {}",
                    row.direction, row.kind, row.peer_label
                ));
            }
            if rows.total > rows.displayed.len() {
                lines.push(format!(
                    "    ... and {} more",
                    rows.total - rows.displayed.len()
                ));
            }
        }
        lines.push(String::new());
    }

    Ok(GraphCommandResponse {
        lines,
        error: None,
        source: None,
    })
}

/// Peer rows rendered past this point are summarized as a remainder count.
const INSPECT_RELATION_LIMIT: usize = 20;

/// One peer row of a `kin graph inspect` relation list.
#[derive(Debug)]
struct InspectRelationRow {
    direction: &'static str,
    kind: RelationKind,
    peer_label: String,
}

/// Bounded rendered rows plus the full number of unique peer observations.
#[derive(Debug)]
struct InspectRelationRows {
    total: usize,
    displayed: Vec<InspectRelationRow>,
}

/// Build the deduplicated peer rows for one inspected entity.
///
/// Two rows are the same observation when they share direction marker, kind,
/// and peer node, so only one is rendered. Mixed-domain relations are included,
/// and entity labels carry their stable identity because overloads can share a
/// name, kind, and file. Relation identities determine display order, and peer
/// labels are resolved only for the bounded displayed prefix.
fn inspect_relation_rows(
    graph: &kin_db::InMemoryGraph,
    entity: &Entity,
) -> Result<InspectRelationRows> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    let self_node = kin_model::GraphNodeId::Entity(entity.id);
    let mut relations = graph.get_all_relations_for_node(&self_node)?;
    relations.sort_unstable_by_key(|rel| rel.id.0);

    for rel in relations {
        let src_is_self = matches!(rel.src, kin_model::GraphNodeId::Entity(id) if id == entity.id);
        let dst_is_self = matches!(rel.dst, kin_model::GraphNodeId::Entity(id) if id == entity.id);
        let (direction, peer) = match (src_is_self, dst_is_self) {
            (true, true) => ("<->", rel.src),
            (false, true) => ("<-", rel.src),
            (true, false) => ("->", rel.dst),
            (false, false) => continue,
        };
        if !seen.insert((direction, rel.kind, peer)) {
            continue;
        }
        if rows.len() >= INSPECT_RELATION_LIMIT {
            continue;
        }

        let peer_label = match peer {
            kin_model::GraphNodeId::Entity(peer_id) => graph
                .get_entity(&peer_id)?
                .map(|e| {
                    format!(
                        "{} [{:?}] ({}; entity:{})",
                        e.name,
                        e.kind,
                        e.file_origin.as_ref().map(|f| f.0.as_str()).unwrap_or("?"),
                        e.id
                    )
                })
                .unwrap_or_else(|| format!("{}", peer_id)),
            other => other.to_string(),
        };

        rows.push(InspectRelationRow {
            direction,
            kind: rel.kind,
            peer_label,
        });
    }

    Ok(InspectRelationRows {
        total: seen.len(),
        displayed: rows,
    })
}

/// Actionable lines when a `kin graph inspect|source <name>` lookup misses in
/// this repo's graph. Keeps the not-found signal (callers also set the
/// structured `error` field), then points at discovery commands instead of
/// dead-ending. Honest by construction — no claim the symbol exists elsewhere.
fn graph_entity_not_found_lines(name: &str) -> Vec<String> {
    vec![
        format!("Entity '{name}' not found in this repo's graph."),
        format!(
            "hint: try `kin search {name}` to find the symbol by name, or `kin graph status` to confirm the graph is populated."
        ),
    ]
}

/// Resolve an entity's source into a typed [`EntitySourceOutcome`].
///
/// This is the taxonomy authority for `get_entity_source` / `get_entity_body`:
/// it separates a non-existent/stale ID (`NotFound`, non-retryable) from a real
/// entity that has no source body (`NoSource`) from a genuine read/extraction
/// failure (`Err`, e.g. an out-of-bounds span or an unavailable blob). The
/// daemon MCP path consumes this directly so those cases surface distinctly to
/// agents instead of collapsing into one opaque message.
pub fn build_entity_source_outcome(
    repository_authority: &super::repository_authority::RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    entity_query: &str,
) -> Result<EntitySourceOutcome> {
    let entity = match resolve_source_entity(graph, entity_query)? {
        Some(e) => e,
        None => {
            return Ok(EntitySourceOutcome::NotFound(
                entity_source_not_found_message(entity_query),
            ));
        }
    };

    // A structurally sourceless entity (no file origin or no span) is a valid ID
    // with nothing to return — reported as `NoSource`, not as the genuine
    // extraction error below (which signals corrupt spans or unavailable blobs).
    if entity.file_origin.is_none() {
        return Ok(EntitySourceOutcome::NoSource(entity_no_source_message(
            &entity,
            "the entity has no file origin",
        )));
    }
    if entity.span.is_none() {
        return Ok(EntitySourceOutcome::NoSource(entity_no_source_message(
            &entity,
            "the entity has no source span",
        )));
    }

    let record = graph_source_record(repository_authority, graph, &entity)?;
    Ok(EntitySourceOutcome::Found(record))
}

pub fn build_graph_source_response(
    repository_authority: &super::repository_authority::RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    entity_query: &str,
) -> Result<GraphCommandResponse> {
    match build_entity_source_outcome(repository_authority, graph, entity_query)? {
        EntitySourceOutcome::Found(record) => {
            let mut lines = vec![
                format!(
                    "Entity source for '{}' -> {} ({})",
                    entity_query, record.name, record.kind
                ),
                format!("ID: {}", record.id),
                format!("File: {}", record.file_path),
                format!("Lines: {}-{}", record.start_line, record.end_line),
            ];
            if !record.signature.is_empty() {
                lines.push(format!("Signature: {}", record.signature));
            }
            lines.push("--- Source ---".to_string());
            lines.push(record.body.clone());

            Ok(GraphCommandResponse {
                lines,
                error: None,
                source: Some(record),
            })
        }
        EntitySourceOutcome::NotFound(message) => Ok(GraphCommandResponse {
            lines: graph_entity_not_found_lines(entity_query),
            error: Some(message),
            source: None,
        }),
        // A valid entity with no retrievable source is an error for the text/`?`
        // command paths (the CLI `kin graph source` and `trace_data_flow`, which
        // drops the step). The MCP path keeps the two apart via the typed outcome.
        EntitySourceOutcome::NoSource(message) => Err(anyhow::anyhow!(message)),
    }
}

/// Agent-facing message for a `get_entity_source` query that resolved to no
/// entity. When the query is a UUID — the shape MCP agents pass — the wording
/// states plainly that the ID does not exist so the agent stops retrying it and
/// probing adjacent IDs; for a name query it points at the discovery tools.
fn entity_source_not_found_message(entity_query: &str) -> String {
    let trimmed = entity_query.trim();
    if uuid::Uuid::parse_str(trimmed).is_ok() {
        format!(
            "no entity exists with ID '{trimmed}'. This entity ID is invalid or stale — it is \
             not present in the graph, so retrying the same ID will not succeed. Use \
             semantic_locate or semantic_search to obtain a current entity ID."
        )
    } else {
        format!(
            "no entity found matching '{trimmed}'. Use semantic_search or semantic_locate to \
             find the entity, then call get_entity_source with the ID it returns."
        )
    }
}

/// Agent-facing message for a real entity that has no source body to return.
/// Explicitly affirms the ID is valid so the agent does not treat it as a
/// missing/stale ID and retry or probe around it.
fn entity_no_source_message(entity: &Entity, reason: &str) -> String {
    format!(
        "entity '{}' ({}) exists in the graph but has no retrievable source: {reason}. The \
         entity ID is valid — this is not a missing or stale ID — there is simply no source \
         body attached to return.",
        entity.name, entity.id
    )
}

fn resolve_source_entity(
    graph: &kin_db::InMemoryGraph,
    entity_query: &str,
) -> Result<Option<Entity>> {
    let trimmed = entity_query.trim();
    if let Ok(uuid) = uuid::Uuid::parse_str(trimmed) {
        return Ok(graph.get_entity(&EntityId(uuid))?);
    }

    if let Some(entity) = kin_ranking::entity_ranking::select_best_entity(graph, trimmed)? {
        return Ok(Some(entity));
    }

    let matches = kin_core::query_trace_matches(graph, trimmed)?;
    Ok(matches.into_iter().next())
}

fn graph_source_record(
    repository_authority: &super::repository_authority::RequestRepositoryAuthority,
    _graph: &kin_db::InMemoryGraph,
    entity: &Entity,
) -> Result<GraphSourceRecord> {
    let authority = repository_authority.open()?;
    let workspace = authority.workspace()?;
    graph_source_record_from(&authority, &workspace, entity)
}

/// Build an entity's source record through an authority the caller already
/// holds open.
///
/// Opening authority verifies every stored body once, linear in store size, so
/// a caller that needs records for many entities must pay that once for the set
/// rather than once per entity. `graph_source_record` above is the single-record
/// convenience wrapper; batch callers own the open and pass it here.
pub(crate) fn graph_source_record_from(
    authority: &super::repository_authority::ActiveRepositoryAuthority,
    workspace: &kin_model::WorkspaceState,
    entity: &Entity,
) -> Result<GraphSourceRecord> {
    let file_origin = entity
        .file_origin
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("entity '{}' has no file origin", entity.name))?;
    let span = entity
        .span
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("entity '{}' has no source span", entity.name))?;
    let (bytes, blob) = read_entity_file_bytes_with_digest_from(authority, workspace, entity)?;
    // Bind the span to the bytes it is about to cut, through the SAME rule the MCP
    // resolver uses.
    //
    // This arm resolves its own bytes rather than routing through
    // `read_entity_source_excerpt_detailed`, and it is the arm the daemon serves
    // `get_entity_source` and `get_entity_sources` from, so in product mode it is
    // the arm agents actually read through. Leaving the check on the offline
    // resolver only would have protected the path used least. The bounds checks
    // below cannot substitute: a stale span normally still lands inside the file.
    let span_coherence =
        kin_mcp::handlers::common::span_source_coherence(entity, &blob, &file_origin.0)?;
    if span.start_byte >= span.end_byte {
        anyhow::bail!(
            "entity '{}' has an empty or invalid source span ({}..{})",
            entity.name,
            span.start_byte,
            span.end_byte
        );
    }
    if span.end_byte > bytes.len() {
        anyhow::bail!(
            "entity '{}' source span {}..{} is out of bounds for '{}' ({} bytes)",
            entity.name,
            span.start_byte,
            span.end_byte,
            file_origin.0,
            bytes.len()
        );
    }

    let body = std::str::from_utf8(&bytes[span.start_byte..span.end_byte])
        .with_context(|| {
            format!(
                "entity '{}' source span {}..{} in '{}' is not valid UTF-8",
                entity.name, span.start_byte, span.end_byte, file_origin.0
            )
        })?
        .to_string();
    let (start_line, end_line) = presentation_span_lines(span);
    Ok(GraphSourceRecord {
        id: entity.id.to_string(),
        name: entity.name.clone(),
        kind: format!("{:?}", entity.kind),
        language: entity.language.to_string(),
        file_path: file_origin.0.clone(),
        start_line,
        end_line,
        start_byte: span.start_byte,
        end_byte: span.end_byte,
        signature: entity.signature.clone(),
        body,
        span_coherence: span_coherence.label().to_string(),
    })
}

pub(crate) fn read_entity_file_bytes_from_graph(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &impl GraphStore,
    entity: &Entity,
) -> Result<Vec<u8>> {
    read_entity_file_bytes_with_digest(binding, graph, entity).map(|(bytes, _)| bytes)
}

/// The bytes at an entity's path in the exact workspace tree, plus the digest
/// they were loaded by.
///
/// Callers that go on to SLICE these bytes with the live entity's span need the
/// digest, because the span and the bytes come from two independently updated
/// stores and the digest is what binds them. Returning it here rather than
/// re-resolving the artifact keeps the pair from being sampled twice.
pub(crate) fn read_entity_file_bytes_with_digest(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    _graph: &impl GraphStore,
    entity: &Entity,
) -> Result<(Vec<u8>, kin_model::Hash256)> {
    let authority = super::repository_authority::ActiveRepositoryAuthority::open(binding)?;
    let workspace = authority.workspace()?;
    read_entity_file_bytes_with_digest_from(&authority, &workspace, entity)
}

/// The same read against an authority and workspace the caller already holds.
///
/// Split from [`read_entity_file_bytes_with_digest`] so a caller reading many
/// entities pays one authority open for the whole set. The workspace is passed
/// alongside rather than re-derived per entity so every read in a set resolves
/// against one coherent generation: re-deriving it per entity would let a
/// publication landing mid-walk serve some entities from the tree that replaced
/// the one the others came from.
pub(crate) fn read_entity_file_bytes_with_digest_from(
    authority: &super::repository_authority::ActiveRepositoryAuthority,
    workspace: &kin_model::WorkspaceState,
    entity: &Entity,
) -> Result<(Vec<u8>, kin_model::Hash256)> {
    let file_id = entity
        .file_origin
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("entity '{}' has no file origin", entity.name))?;
    let path = kin_model::RepoPath::from_utf8(file_id.0.clone()).with_context(|| {
        format!(
            "entity source path '{}' is not repository-relative",
            file_id.0
        )
    })?;
    let artifact = workspace.tree.artifact_at_path(&path).ok_or_else(|| {
        anyhow::anyhow!(
            "entity source '{}' is absent from repository-v6 workspace {} at generation {}",
            file_id.0,
            workspace.workspace_id,
            workspace.generation
        )
    })?;
    let kin_model::TreeEntry::Blob { hash, .. } = artifact.entry else {
        anyhow::bail!(
            "entity source '{}' resolves to non-source entry {:?} for artifact {:?} in repository-v6 workspace {}",
            file_id.0,
            artifact.entry,
            artifact.artifact_id,
            workspace.workspace_id
        );
    };
    let bytes = authority.load_source_blob(hash).with_context(|| {
        format!(
            "repository-v6 source body for artifact {:?} at '{}' is unavailable",
            artifact.artifact_id, file_id.0
        )
    })?;
    Ok((bytes, hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        ArtifactId, Entity, EntityMetadata, FilePathId, FingerprintAlgorithm, GraphNodeId, Hash256,
        LanguageId, Relation, RelationId, RelationOrigin, RepoPath, ResolvedArtifact, ResolvedTree,
        SemanticFingerprint, SourceSpan, TreeEntry, Visibility,
    };
    use std::fs;

    #[test]
    fn graph_entity_not_found_lines_keep_signal_and_offer_next_steps() {
        let lines = graph_entity_not_found_lines("frobnicate");
        assert!(
            lines[0].contains("not found"),
            "keeps not-found signal: {lines:?}"
        );
        let joined = lines.join("\n");
        assert!(
            joined.contains("kin search frobnicate"),
            "offers search: {joined}"
        );
        assert!(
            joined.contains("kin graph status"),
            "offers graph status: {joined}"
        );
    }

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
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

    fn test_relation(kind: RelationKind, src: EntityId, dst: EntityId) -> Relation {
        graph_relation(kind, GraphNodeId::Entity(src), GraphNodeId::Entity(dst))
    }

    fn graph_relation(kind: RelationKind, src: GraphNodeId, dst: GraphNodeId) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    fn external_placeholder_relation(kind: RelationKind) -> (Entity, Relation) {
        let mut caller = test_entity("run_task");
        let file_id = FilePathId::new("src/app.rs");
        caller.file_origin = Some(file_id.clone());
        caller.span = Some(SourceSpan {
            file: file_id,
            start_byte: 0,
            end_byte: 10,
            start_line: 1,
            start_col: 0,
            end_line: 1,
            end_col: 10,
        });
        let files = [kin_index::FileParseData {
            file_path: "src/app.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![kin_parser::ExtractedRelation {
                call_shape: None,
                kind,
                src_name: caller.name.clone(),
                dst_name: "InMemoryGraph".to_string(),
                import_source: Some("kin_db".to_string()),
            }],
            imports: Vec::new(),
        }];
        let artifact_ids =
            std::collections::HashMap::from([("src/app.rs".to_string(), ArtifactId::new())]);
        let relations = kin_index::link_cross_file(&files, &artifact_ids)
            .expect("test file has an admitted artifact identity");
        assert_eq!(relations.len(), 1);
        let relation = relations.into_iter().next().unwrap();
        assert!(kin_index::is_external_import_placeholder(&relation));
        // The validator fixture has no source file; remove file metadata after
        // the real linker has used it so this test isolates relation integrity
        // rather than also triggering the orphaned-entity check.
        caller.file_origin = None;
        caller.span = None;
        (caller, relation)
    }

    fn graph_validation_fixture() -> (
        tempfile::TempDir,
        kin_core::LocalRepositoryAuthorityBinding,
        kin_db::InMemoryGraph,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(temp.path()).unwrap();
        let binding =
            kin_core::LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();
        (temp, binding, kin_db::InMemoryGraph::new())
    }

    /// The exact reported failure. `kin graph status` on the umbrella store
    /// printed "No issues detected" while the daemon had failed every
    /// whole-tree admission since Aug 6, because every check this command runs
    /// reads the graph, and the graph a failing loop leaves behind is
    /// internally perfect and merely out of date.
    #[test]
    fn graph_status_refuses_no_issues_while_the_daemon_is_admitting_nothing() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let caller = test_entity("run_task");
        let callee = test_entity("finalize");
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph
            .upsert_relation(&test_relation(RelationKind::Calls, caller.id, callee.id))
            .unwrap();

        // The control. This fixture's graph raises unrelated warnings of its own
        // (pending embeddings, uniform roles), so the all-clear line is not what
        // separates the two halves here and asserting on it would pass whatever
        // the reconcile term did. What must differ is the reconcile warning
        // itself: absent on a healthy daemon, present on this one.
        let healthy = build_graph_status_response(&binding, &graph, &Default::default()).unwrap();
        assert!(
            !healthy
                .lines
                .iter()
                .any(|line| line.contains("reconcile loop degraded")),
            "a healthy daemon must not be reported as degraded: {:?}",
            healthy.lines
        );

        let degraded = build_graph_status_response(
            &binding,
            &graph,
            &crate::commands::resources::ReconcileHealth {
                admission_failure_streak: 412,
                admission_failures: 412,
                last_admission_error: Some("scan exceeded its budget".to_string()),
                last_admission_success_age_seconds: Some(172_800),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            !degraded
                .lines
                .iter()
                .any(|line| line.contains("No issues detected")),
            "this is the lie the ticket exists to kill: {:?}",
            degraded.lines
        );
        let warning = degraded
            .lines
            .iter()
            .find(|line| line.contains("reconcile loop degraded"))
            .expect("the fault must be named on the surface a user reads");
        assert!(warning.contains("412"), "{warning}");
        assert!(warning.contains("172800"), "{warning}");
        assert!(
            degraded.error.is_none(),
            "a live runtime fault is not a defect in the graph this command \
             inspected, and must not change the exit code"
        );
    }

    /// A dropped reconcile event reaches the same verdict. This is the FIR-2145
    /// shape, where events errored and were skipped while every surface read
    /// clean.
    #[test]
    fn graph_status_names_dropped_reconcile_events() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let entity = test_entity("run_task");
        graph.upsert_entity(&entity).unwrap();

        let response = build_graph_status_response(
            &binding,
            &graph,
            &crate::commands::resources::ReconcileHealth {
                skipped_events: 7,
                last_error: Some("src/lib.rs: parser rejected the transaction".to_string()),
                last_error_age_seconds: Some(90),
                ..Default::default()
            },
        )
        .unwrap();
        // The reconcile warning is the assertion that carries this test. The
        // all-clear line is checked below it rather than above it because this
        // fixture's graph raises warnings of its own, so its absence would hold
        // whether or not the reconcile term existed.
        assert!(
            response
                .lines
                .iter()
                .any(|line| line.contains("reconcile loop degraded")),
            "a dropped event must be named on the surface a user reads: {:?}",
            response.lines
        );
        assert!(
            response
                .lines
                .iter()
                .any(|line| line.contains("src/lib.rs: parser rejected the transaction")),
            "the daemon's own error must survive to the surface: {:?}",
            response.lines
        );
        assert!(
            !response
                .lines
                .iter()
                .any(|line| line.contains("No issues detected")),
            "{:?}",
            response.lines
        );
    }

    /// The all-clear line and a degraded reconcile loop are mutually exclusive
    /// by construction, and this is the assertion that proves it.
    ///
    /// No fixture in this module produces a warning-free graph, so a test that
    /// planted a degraded loop and checked the all-clear was gone would hold
    /// with the reconcile term deleted. Reading the suppression rule against the
    /// same reasons the surface renders is what cannot pass by accident: any
    /// non-empty reason set makes the warning list non-empty, and a non-empty
    /// warning list is exactly what withholds the all-clear at the call site.
    #[test]
    fn a_degraded_reconcile_loop_always_withholds_the_all_clear() {
        let degraded = crate::commands::resources::ReconcileHealth {
            admission_failure_streak: 412,
            last_admission_success_age_seconds: Some(172_800),
            ..Default::default()
        };
        assert!(
            !degraded.degraded_reasons().is_empty(),
            "the planted state must be degraded, or this proves nothing"
        );

        let clean = crate::commands::resources::ReconcileHealth::default();
        assert!(
            clean.degraded_reasons().is_empty(),
            "an untouched daemon contributes no warnings, so the all-clear is \
             still reachable for a graph that earns it"
        );
    }

    #[test]
    fn graph_status_labels_each_relation_total_with_its_scope() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let caller = test_entity("run_task");
        let callee = test_entity("finalize");
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph
            .upsert_relation(&test_relation(RelationKind::Calls, caller.id, callee.id))
            .unwrap();

        let response = build_graph_status_response(&binding, &graph, &Default::default()).unwrap();

        // The entity-rooted total and the whole-table total count different
        // scopes, so neither line may carry a bare "Relations" label.
        assert!(response
            .lines
            .iter()
            .any(|line| line.contains("Entity-to-entity relations: 1")));
        assert!(response
            .lines
            .iter()
            .any(|line| line.starts_with("Entity-to-entity rels/entity: ")));
        assert!(response
            .lines
            .iter()
            .any(|line| line.starts_with("Entity-to-entity relation kinds: ")));
        assert!(response
            .lines
            .iter()
            .any(|line| line.starts_with("All graph relations excluding CoChanges: ")));
        assert!(
            !response
                .lines
                .iter()
                .any(|line| line.starts_with("Relations: ") || line.contains("  |  Relations: ")),
            "{:?}",
            response.lines
        );
    }

    #[test]
    fn graph_status_does_not_call_a_mixed_relation_graph_relationless() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let entity = test_entity("run_task");
        graph.upsert_entity(&entity).unwrap();
        graph
            .upsert_relation(&graph_relation(
                RelationKind::Covers,
                GraphNodeId::Test(kin_model::TestId::new()),
                GraphNodeId::Entity(entity.id),
            ))
            .unwrap();

        let response = build_graph_status_response(&binding, &graph, &Default::default()).unwrap();

        assert!(response
            .lines
            .iter()
            .any(|line| line.contains("Entity-to-entity relations: 0")));
        assert!(response
            .lines
            .iter()
            .any(|line| line == "All graph relations excluding CoChanges: 1 (1.00/entity)"));
        assert!(
            !response
                .lines
                .iter()
                .any(|line| line.contains("no relations in graph")),
            "{:?}",
            response.lines
        );
    }

    #[test]
    fn graph_validate_accepts_external_import_placeholder_destination() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let (caller, relation) = external_placeholder_relation(RelationKind::Calls);
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_relation(&relation).unwrap();

        let response = build_graph_validate_response(&binding, &graph).unwrap();

        assert!(response.error.is_none(), "{:?}", response.lines);
        assert!(response
            .lines
            .iter()
            .any(|line| line == "✓ All checks passed."));
    }

    #[test]
    fn graph_validate_rejects_unmarked_dangling_destination() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let caller = test_entity("run_task");
        graph.upsert_entity(&caller).unwrap();
        graph
            .upsert_relation(&test_relation(
                RelationKind::Calls,
                caller.id,
                EntityId::new(),
            ))
            .unwrap();

        let response = build_graph_validate_response(&binding, &graph).unwrap();

        assert!(response.error.is_some(), "{:?}", response.lines);
        assert!(response
            .lines
            .iter()
            .any(|line| line == "✗ 1 relation endpoint references non-existent entities"));
    }

    #[test]
    fn graph_validate_rejects_relation_with_both_endpoints_absent() {
        let (_temp, binding, graph) = graph_validation_fixture();
        graph
            .upsert_relation(&test_relation(
                RelationKind::References,
                EntityId::new(),
                EntityId::new(),
            ))
            .unwrap();

        let response = build_graph_validate_response(&binding, &graph).unwrap();

        assert!(response.error.is_some(), "{:?}", response.lines);
        assert!(response
            .lines
            .iter()
            .any(|line| line == "Checked 0 entities, 1 relation"));
        assert!(response
            .lines
            .iter()
            .any(|line| line == "✗ 2 relation endpoints reference non-existent entities"));
    }

    #[test]
    fn graph_validate_rejects_missing_source_on_canonical_external_placeholder() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let (_caller, relation) = external_placeholder_relation(RelationKind::References);
        graph.upsert_relation(&relation).unwrap();

        let response = build_graph_validate_response(&binding, &graph).unwrap();

        assert!(response.error.is_some(), "{:?}", response.lines);
        assert!(response
            .lines
            .iter()
            .any(|line| line == "✗ 1 relation endpoint references non-existent entities"));
    }

    #[test]
    fn graph_inspect_collapses_repeated_peer_edges() {
        let graph = kin_db::InMemoryGraph::new();
        let mut container = test_entity("Stats");
        container.kind = EntityKind::Class;
        container.file_origin = Some(FilePathId::new("crates/printer/src/stats.rs"));
        let mut member = test_entity("Stats::elapsed");
        member.kind = EntityKind::Method;
        member.file_origin = Some(FilePathId::new("crates/printer/src/stats.rs"));
        graph.upsert_entity(&container).unwrap();
        graph.upsert_entity(&member).unwrap();

        // Two rows for one logical edge: distinct relation IDs, identical
        // (direction, kind, peer).
        for _ in 0..2 {
            graph
                .upsert_relation(&test_relation(
                    RelationKind::Contains,
                    container.id,
                    member.id,
                ))
                .unwrap();
        }

        let response = build_graph_inspect_response(&graph, "Stats::elapsed").unwrap();
        let peer_rows: Vec<_> = response
            .lines
            .iter()
            .filter(|line| line.starts_with("    <- Contains "))
            .collect();

        assert_eq!(peer_rows.len(), 1, "{:?}", response.lines);
        assert_eq!(
            peer_rows[0],
            &format!(
                "    <- Contains Stats [Class] (crates/printer/src/stats.rs; entity:{})",
                container.id
            )
        );
        assert!(response.lines.iter().any(|line| line == "  Relations (1):"));
    }

    #[test]
    fn graph_inspect_keeps_distinct_peers_that_share_a_name_and_file() {
        let graph = kin_db::InMemoryGraph::new();
        let mut member = test_entity("Stats::elapsed");
        member.kind = EntityKind::Method;
        graph.upsert_entity(&member).unwrap();

        let file = FilePathId::new("crates/printer/src/stats.rs");
        let mut declaration = test_entity("Stats");
        declaration.kind = EntityKind::Class;
        declaration.file_origin = Some(file.clone());
        let mut alias = test_entity("Stats");
        alias.kind = EntityKind::TypeAlias;
        alias.file_origin = Some(file);
        graph.upsert_entity(&declaration).unwrap();
        graph.upsert_entity(&alias).unwrap();

        for peer in [&declaration, &alias] {
            graph
                .upsert_relation(&test_relation(RelationKind::Contains, peer.id, member.id))
                .unwrap();
        }

        let response = build_graph_inspect_response(&graph, "Stats::elapsed").unwrap();
        let peer_rows: Vec<_> = response
            .lines
            .iter()
            .filter(|line| line.starts_with("    <- Contains "))
            .collect();

        assert_eq!(peer_rows.len(), 2, "{:?}", response.lines);
        assert!(peer_rows
            .iter()
            .any(|line| line.contains("Stats [Class] (crates/printer/src/stats.rs; entity:")));
        assert!(peer_rows
            .iter()
            .any(|line| line.contains("Stats [TypeAlias] (crates/printer/src/stats.rs; entity:")));
    }

    #[test]
    fn graph_inspect_disambiguates_overloads_with_the_same_name_kind_and_file() {
        let graph = kin_db::InMemoryGraph::new();
        let mut subject = test_entity("dispatch");
        subject.kind = EntityKind::Method;
        graph.upsert_entity(&subject).unwrap();

        let file = FilePathId::new("src/handlers.rs");
        let mut first = test_entity("Handler::run");
        first.kind = EntityKind::Method;
        first.file_origin = Some(file.clone());
        first.span = Some(SourceSpan {
            file: file.clone(),
            start_byte: 10,
            end_byte: 20,
            start_line: 2,
            start_col: 0,
            end_line: 4,
            end_col: 1,
        });
        let mut second = test_entity("Handler::run");
        second.kind = EntityKind::Method;
        second.file_origin = Some(file.clone());
        second.span = Some(SourceSpan {
            file,
            start_byte: 30,
            end_byte: 40,
            start_line: 6,
            start_col: 0,
            end_line: 8,
            end_col: 1,
        });
        graph.upsert_entity(&first).unwrap();
        graph.upsert_entity(&second).unwrap();

        for peer in [&first, &second] {
            graph
                .upsert_relation(&test_relation(RelationKind::Calls, subject.id, peer.id))
                .unwrap();
        }

        let response = build_graph_inspect_response(&graph, "dispatch").unwrap();
        let peer_rows: Vec<_> = response
            .lines
            .iter()
            .filter(|line| line.starts_with("    -> Calls Handler::run "))
            .collect();

        assert_eq!(peer_rows.len(), 2, "{:?}", response.lines);
        assert_ne!(peer_rows[0], peer_rows[1], "{:?}", response.lines);
        assert!(peer_rows
            .iter()
            .any(|line| line.contains(&format!("entity:{}", first.id))));
        assert!(peer_rows
            .iter()
            .any(|line| line.contains(&format!("entity:{}", second.id))));
    }

    #[test]
    fn graph_inspect_includes_mixed_domain_relations() {
        let graph = kin_db::InMemoryGraph::new();
        let subject = test_entity("dispatch");
        graph.upsert_entity(&subject).unwrap();

        let test_id = kin_model::TestId::new();
        let artifact_id = ArtifactId::new();
        graph
            .upsert_relation(&graph_relation(
                RelationKind::Covers,
                GraphNodeId::Test(test_id),
                GraphNodeId::Entity(subject.id),
            ))
            .unwrap();
        graph
            .upsert_relation(&graph_relation(
                RelationKind::OwnedByFile,
                GraphNodeId::Entity(subject.id),
                GraphNodeId::Artifact(artifact_id),
            ))
            .unwrap();

        let response = build_graph_inspect_response(&graph, "dispatch").unwrap();

        assert!(response.lines.iter().any(|line| line == "  Relations (2):"));
        assert!(response
            .lines
            .iter()
            .any(|line| line == &format!("    <- Covers test:{test_id}")));
        assert!(response
            .lines
            .iter()
            .any(|line| line == &format!("    -> OwnedByFile artifact:{}", artifact_id.0)));
    }

    #[test]
    fn graph_inspect_bounds_rendered_rows_but_reports_the_full_unique_count() {
        let graph = kin_db::InMemoryGraph::new();
        let subject = test_entity("dispatch");
        graph.upsert_entity(&subject).unwrap();

        for index in 0..=INSPECT_RELATION_LIMIT {
            let peer = test_entity(&format!("peer_{index}"));
            graph.upsert_entity(&peer).unwrap();
            graph
                .upsert_relation(&test_relation(RelationKind::Calls, subject.id, peer.id))
                .unwrap();
        }

        let response = build_graph_inspect_response(&graph, "dispatch").unwrap();
        let peer_rows = response
            .lines
            .iter()
            .filter(|line| line.starts_with("    -> Calls peer_"))
            .count();

        assert_eq!(peer_rows, INSPECT_RELATION_LIMIT, "{:?}", response.lines);
        assert!(response
            .lines
            .iter()
            .any(|line| line == &format!("  Relations ({}):", INSPECT_RELATION_LIMIT + 1)));
        assert!(response
            .lines
            .iter()
            .any(|line| line == "    ... and 1 more"));
    }

    #[test]
    fn graph_inspect_separates_incoming_and_outgoing_edges_of_one_kind() {
        let graph = kin_db::InMemoryGraph::new();
        let subject = test_entity("render");
        let caller = test_entity("main");
        let callee = test_entity("format_row");
        for entity in [&subject, &caller, &callee] {
            graph.upsert_entity(entity).unwrap();
        }
        graph
            .upsert_relation(&test_relation(RelationKind::Calls, caller.id, subject.id))
            .unwrap();
        graph
            .upsert_relation(&test_relation(RelationKind::Calls, subject.id, callee.id))
            .unwrap();

        let response = build_graph_inspect_response(&graph, "render").unwrap();

        assert!(response.lines.iter().any(|line| line == "  Relations (2):"));
        assert!(response
            .lines
            .iter()
            .any(|line| line.starts_with("    <- Calls main ")));
        assert!(response
            .lines
            .iter()
            .any(|line| line.starts_with("    -> Calls format_row ")));
    }

    #[test]
    fn graph_inspect_renders_self_relation_bidirectionally() {
        let graph = kin_db::InMemoryGraph::new();
        let subject = test_entity("render");
        graph.upsert_entity(&subject).unwrap();
        graph
            .upsert_relation(&test_relation(RelationKind::Calls, subject.id, subject.id))
            .unwrap();

        let response = build_graph_inspect_response(&graph, "render").unwrap();

        assert!(response.lines.iter().any(|line| line == "  Relations (1):"));
        assert!(response
            .lines
            .iter()
            .any(|line| line.starts_with("    <-> Calls render ")));
    }

    #[test]
    fn graph_inspect_accepts_entity_uuid() {
        let graph = kin_db::InMemoryGraph::new();
        let entity = test_entity("checkout");
        let id = entity.id;
        graph.upsert_entity(&entity).unwrap();

        let response = build_graph_inspect_response(&graph, &id.to_string()).unwrap();

        assert!(response
            .lines
            .iter()
            .any(|line| line == "Entity: checkout (Function)"));
        assert!(response
            .lines
            .iter()
            .any(|line| line == &format!("  ID: {id}")));
    }

    struct GraphSourceFixture {
        _temp: tempfile::TempDir,
        layout: kin_core::KinLayout,
        binding: kin_core::LocalRepositoryAuthorityBinding,
        graph: kin_db::InMemoryGraph,
        file_id: FilePathId,
    }

    impl GraphSourceFixture {
        /// The pinned arm, which is what a one-shot CLI invocation holds: these
        /// tests measure the source-resolution taxonomy, not authority sharing.
        fn authority(&self) -> super::super::repository_authority::RequestRepositoryAuthority {
            super::super::repository_authority::RequestRepositoryAuthority::pinned(
                self.binding.clone(),
            )
        }
    }

    /// A batch of source resolutions costs ONE authority open, not one each.
    ///
    /// `get_entity_sources` resolves source per entity, and every resolution
    /// used to open authority for itself: a batch of N entities paid N
    /// whole-store verifications. The shared arm makes the batch cost one, which
    /// also makes it coherent, since per-entity opens could straddle a
    /// publication and return rows from two different generations.
    ///
    /// Both arms are measured in one test on purpose. The bound is only evidence
    /// if the counter can tell them apart, and the pinned half is what proves it
    /// can: it still climbs with batch size, which is exactly right for a
    /// one-shot invocation and exactly what the daemon must not do.
    #[test]
    fn a_batch_of_source_resolutions_shares_one_authority_open() {
        const BATCH: usize = 4;
        const SOURCE: &[u8] = b"fn target() {}\n";
        let fixture = graph_source_fixture(Some(SOURCE));
        let entity = source_entity("target", fixture.file_id.clone(), 0, SOURCE.len() - 1);
        let id = entity.id;
        commit_source_entity(&fixture, &entity);
        let opens = super::super::repository_authority::repository_authority_opens_on_this_thread;

        let shared = std::sync::Arc::new(
            super::super::repository_authority::ActiveRepositoryAuthority::open(&fixture.binding)
                .expect("open authority for the batch"),
        );
        let shared_authority =
            super::super::repository_authority::RequestRepositoryAuthority::shared(
                fixture.binding.clone(),
                std::sync::Arc::new(move || Ok(std::sync::Arc::clone(&shared))),
            );

        let before = opens();
        for _ in 0..BATCH {
            let outcome =
                build_entity_source_outcome(&shared_authority, &fixture.graph, &id.to_string())
                    .expect("resolve source through the shared authority");
            assert!(
                matches!(outcome, EntitySourceOutcome::Found(_)),
                "each resolution must actually project a body, or the count proves nothing"
            );
        }
        assert_eq!(
            opens() - before,
            0,
            "a batch reading through one already-open authority must not open again, once per \
             item or at all"
        );

        let pinned = fixture.authority();
        let before = opens();
        for _ in 0..BATCH {
            build_entity_source_outcome(&pinned, &fixture.graph, &id.to_string())
                .expect("resolve source through the pinned authority");
        }
        assert_eq!(
            opens() - before,
            BATCH as u64,
            "the pinned arm opens per resolution, which is what a one-shot CLI invocation wants \
             and what proves this counter can see the difference"
        );
    }

    fn graph_source_fixture(source: Option<&[u8]>) -> GraphSourceFixture {
        // Publication proves the Git source three times and requires all three
        // proofs to agree, and the proof deliberately includes the contents of
        // the user's resolved global excludes file, which is addressed through
        // `HOME`. A neighbouring test that moves `HOME` between two of those
        // proofs therefore fails publication as uncertain. Holding the
        // environment mutation domain, without changing anything in it, is what
        // keeps `HOME` still for the width of the window.
        let _domain = kin_core::test_env::EnvVarGuard::new();
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let git = |args: &[&str]| {
            let output = crate::commands::test_subprocess::fixture_git(&repo)
                // This fixture consumes the committed repository immediately.
                // Prevent maintenance from detaching work that can leave
                // transient pack locks after `git commit` exits.
                .args(["-c", "maintenance.auto=false", "-c", "gc.auto=0"])
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?} failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        };
        git(&["init", "--initial-branch=main"]);
        git(&["config", "user.email", "kin@example.invalid"]);
        git(&["config", "user.name", "Kin"]);
        let file_id = FilePathId::new("src/lib.rs");
        if let Some(source) = source {
            fs::create_dir_all(repo.join("src")).unwrap();
            fs::write(repo.join(&file_id.0), source).unwrap();
        } else {
            fs::write(repo.join("README.md"), b"authority without source\n").unwrap();
        }
        git(&["add", "--all"]);
        git(&["commit", "--signoff", "-m", "seed exact source authority"]);
        let init = kin_core::init_from_git(&repo).unwrap();
        let layout = init.layout;
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap();
        let authority =
            crate::commands::repository_authority::ActiveRepositoryAuthority::open(&binding)
                .unwrap();
        let mut resolved_tree = authority.workspace().unwrap().tree;
        if source.is_none() {
            let mut artifacts = resolved_tree.into_artifacts().collect::<Vec<_>>();
            artifacts.push(ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8(file_id.0.clone()).unwrap(),
                TreeEntry::blob(Hash256::from_bytes([0x99; 32]), false),
            ));
            resolved_tree = ResolvedTree::from_artifacts(artifacts).unwrap();
        }
        let mut snapshot = kin_db::GraphSnapshot::empty();
        snapshot.resolved_tree = resolved_tree;
        let graph = kin_db::InMemoryGraph::from_snapshot(snapshot).unwrap();

        GraphSourceFixture {
            _temp: temp,
            layout,
            binding,
            graph,
            file_id,
        }
    }

    fn source_entity(name: &str, file_id: FilePathId, start: usize, end: usize) -> Entity {
        let mut entity = test_entity(name);
        entity.file_origin = Some(file_id);
        entity.span = Some(SourceSpan {
            file: entity.file_origin.clone().unwrap(),
            start_byte: start,
            end_byte: end,
            start_line: 2,
            start_col: 1,
            end_line: 4,
            end_col: 2,
        });
        entity.signature = format!("fn {name}()");
        entity
    }

    fn commit_source_entity(fixture: &GraphSourceFixture, entity: &Entity) {
        fixture.graph.upsert_entity(entity).unwrap();
    }

    #[test]
    fn graph_source_reads_exact_body_from_graph_blob_by_uuid() {
        let source = "fn before() {}\nfn target() {\n    2 + 2\n}\nfn after() {}\n";
        let body = "fn target() {\n    2 + 2\n}";
        let start = source.find(body).unwrap();
        let end = start + body.len();
        let fixture = graph_source_fixture(Some(source.as_bytes()));

        let entity = source_entity("target", fixture.file_id.clone(), start, end);
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        let response =
            build_graph_source_response(&fixture.authority(), &fixture.graph, &id.to_string())
                .unwrap();
        let source = response.source.unwrap();

        assert_eq!(source.body, body);
        assert_eq!(source.file_path, "src/lib.rs");
        assert_eq!(source.start_byte, start);
        assert_eq!(source.end_byte, end);
    }

    /// This arm enforces the span/bytes coherence rule too.
    ///
    /// It is not reached through `resolve_entity_source_authority`: it resolves its
    /// own bytes, and it is what the daemon serves `get_entity_source` and
    /// `get_entity_sources` from, so in product mode it is the arm agents actually
    /// read through. A rule enforced only on the offline resolver would have
    /// protected the least-used path and left the most-used one open.
    ///
    /// The two bounds checks below it cannot substitute: this fixture's stale span
    /// (0..14 of a 14-byte original) is comfortably inside the longer replacement,
    /// so a length test passes and the read would return a truncated fragment of a
    /// different function as this entity's body.
    #[test]
    fn graph_source_refuses_a_span_derived_from_different_bytes() {
        let original = b"fn target() {}\n";
        let fixture = graph_source_fixture(Some(original));
        let mut entity = source_entity("target", fixture.file_id.clone(), 0, original.len() - 1);
        // Stamp the digest of a DIFFERENT source: the reconciler records the digest
        // each span was derived from, and here it does not describe the tree's bytes.
        entity.metadata.extra.insert(
            "blob_hash".to_string(),
            serde_json::Value::String(Hash256::from_bytes([0x5a; 32]).to_string()),
        );
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        let error =
            build_graph_source_response(&fixture.authority(), &fixture.graph, &id.to_string())
                .expect_err("a span derived from other bytes must not serve a mis-sliced body");
        let message = format!("{error:#}");
        assert!(
            message.contains("does not describe these bytes"),
            "the refusal must name the incoherence, got: {message}"
        );
    }

    /// An entity whose recorded digest matches the tree is served AND says so, so
    /// a caller preparing an overwrite can tell a verified body from an unverified
    /// one on this arm as well.
    #[test]
    fn graph_source_reports_span_coherence_for_a_verified_read() {
        let original = b"fn target() {}\n";
        let fixture = graph_source_fixture(Some(original));
        let mut entity = source_entity("target", fixture.file_id.clone(), 0, original.len() - 1);

        // The digest the tree actually holds for this path.
        let blob = read_entity_file_bytes_with_digest(&fixture.binding, &fixture.graph, &entity)
            .unwrap()
            .1;
        entity.metadata.extra.insert(
            "blob_hash".to_string(),
            serde_json::Value::String(blob.to_string()),
        );
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        let response =
            build_graph_source_response(&fixture.authority(), &fixture.graph, &id.to_string())
                .unwrap();
        let record = response.source.unwrap();
        assert_eq!(record.body, "fn target() {}");
        assert_eq!(record.span_coherence, "digest_verified");
    }

    #[test]
    fn graph_source_ignores_checkout_path_reuse() {
        let original = b"fn target() {}\n";
        let fixture = graph_source_fixture(Some(original));
        let entity = source_entity("target", fixture.file_id.clone(), 0, original.len() - 1);
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        fs::write(
            fixture.layout.working_dir().join(&fixture.file_id.0),
            b"fn replacement() {}\n",
        )
        .unwrap();
        let response =
            build_graph_source_response(&fixture.authority(), &fixture.graph, &id.to_string())
                .unwrap();
        assert_eq!(response.source.unwrap().body, "fn target() {}");
    }

    #[test]
    fn graph_source_returns_error_on_oob_span() {
        let source = "fn target() {}\n";
        let fixture = graph_source_fixture(Some(source.as_bytes()));
        let end = source.len() + 10;
        let entity = source_entity("target", fixture.file_id.clone(), 0, end);
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        let err =
            build_graph_source_response(&fixture.authority(), &fixture.graph, &id.to_string())
                .unwrap_err()
                .to_string();

        assert!(
            err.contains(&format!("source span 0..{end} is out of bounds")),
            "{err}"
        );
        assert!(err.contains("src/lib.rs"), "{err}");
    }

    #[test]
    fn graph_source_returns_error_when_path_is_absent_from_authority() {
        let fixture = graph_source_fixture(None);
        let entity = source_entity("target", fixture.file_id.clone(), 0, 8);
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        let err =
            build_graph_source_response(&fixture.authority(), &fixture.graph, &id.to_string())
                .unwrap_err()
                .to_string();

        assert!(
            err.contains("source 'src/lib.rs' is absent from repository-v6 workspace"),
            "{err}"
        );
    }

    #[test]
    fn entity_source_outcome_found_returns_record() {
        let source = "fn before() {}\nfn target() {\n    2 + 2\n}\nfn after() {}\n";
        let body = "fn target() {\n    2 + 2\n}";
        let start = source.find(body).unwrap();
        let end = start + body.len();
        let fixture = graph_source_fixture(Some(source.as_bytes()));

        let entity = source_entity("target", fixture.file_id.clone(), start, end);
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        match build_entity_source_outcome(&fixture.authority(), &fixture.graph, &id.to_string())
            .unwrap()
        {
            EntitySourceOutcome::Found(record) => assert_eq!(record.body, body),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn entity_source_outcome_not_found_for_invented_uuid() {
        let fixture = graph_source_fixture(Some(b"fn x() {}\n"));
        let invented = uuid::Uuid::new_v4();

        match build_entity_source_outcome(
            &fixture.authority(),
            &fixture.graph,
            &invented.to_string(),
        )
        .unwrap()
        {
            EntitySourceOutcome::NotFound(message) => {
                assert!(message.contains(&invented.to_string()), "{message}");
                // Non-retryable signal for the agent.
                assert!(message.contains("invalid or stale"), "{message}");
                assert!(message.contains("will not succeed"), "{message}");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn entity_source_outcome_no_source_for_spanless_entity() {
        let fixture = graph_source_fixture(Some(b"fn x() {}\n"));
        let mut entity = source_entity("target", fixture.file_id.clone(), 0, 8);
        // A valid, resolvable entity that simply carries no source span.
        entity.span = None;
        let id = entity.id;
        fixture.graph.upsert_entity(&entity).unwrap();

        match build_entity_source_outcome(&fixture.authority(), &fixture.graph, &id.to_string())
            .unwrap()
        {
            EntitySourceOutcome::NoSource(message) => {
                assert!(message.contains("target"), "{message}");
                assert!(message.contains("no source span"), "{message}");
                assert!(message.contains("ID is valid"), "{message}");
            }
            other => panic!("expected NoSource, got {other:?}"),
        }
    }

    #[test]
    fn not_found_and_no_source_messages_are_distinguishable() {
        let fixture = graph_source_fixture(Some(b"fn x() {}\n"));

        let invented = uuid::Uuid::new_v4();
        let not_found = build_entity_source_outcome(
            &fixture.authority(),
            &fixture.graph,
            &invented.to_string(),
        )
        .unwrap();

        let mut spanless = source_entity("target", fixture.file_id.clone(), 0, 8);
        spanless.span = None;
        let spanless_id = spanless.id;
        fixture.graph.upsert_entity(&spanless).unwrap();
        let no_source = build_entity_source_outcome(
            &fixture.authority(),
            &fixture.graph,
            &spanless_id.to_string(),
        )
        .unwrap();

        let (nf, ns) = match (not_found, no_source) {
            (EntitySourceOutcome::NotFound(nf), EntitySourceOutcome::NoSource(ns)) => (nf, ns),
            other => panic!("unexpected taxonomy: {other:?}"),
        };
        assert_ne!(nf, ns);
    }

    #[test]
    fn graph_source_response_not_found_sets_error_and_leaves_source_none() {
        // Regression guard for the precedence bug: a not-found query must set the
        // structured `error` field (surfaced ahead of any missing-source text)
        // and leave `source` empty.
        let fixture = graph_source_fixture(Some(b"fn x() {}\n"));
        let invented = uuid::Uuid::new_v4();

        let response = build_graph_source_response(
            &fixture.authority(),
            &fixture.graph,
            &invented.to_string(),
        )
        .unwrap();

        assert!(response.source.is_none());
        let error = response.error.expect("not-found must populate error");
        assert!(error.contains(&invented.to_string()), "{error}");
    }

    /// Build a validate fixture whose graph carries exactly `tree_paths` in its
    /// resolved tree, independent of what the working directory holds.
    fn orphan_fixture(
        tree_paths: &[&str],
    ) -> (
        tempfile::TempDir,
        kin_core::KinLayout,
        kin_core::LocalRepositoryAuthorityBinding,
        kin_db::InMemoryGraph,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let layout = kin_core::init(temp.path()).unwrap().layout;
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap();
        let artifacts: Vec<_> = tree_paths
            .iter()
            .map(|path| {
                ResolvedArtifact::new(
                    ArtifactId::new(),
                    RepoPath::from_utf8((*path).to_string()).unwrap(),
                    TreeEntry::blob(Hash256::from_bytes([0x99; 32]), false),
                )
            })
            .collect();
        let mut snapshot = kin_db::GraphSnapshot::empty();
        snapshot.resolved_tree = ResolvedTree::from_artifacts(artifacts).unwrap();
        let graph = kin_db::InMemoryGraph::from_snapshot(snapshot).unwrap();
        (temp, layout, binding, graph)
    }

    fn orphan_line(response: &GraphCommandResponse) -> Option<&String> {
        response.lines.iter().find(|line| line.contains("orphaned"))
    }

    /// A file present in the working tree but absent from the graph's exact
    /// tree is still an orphan. Deciding orphan status by probing the working
    /// directory reports zero here, which is what this asserts against: the
    /// projection cannot vouch for an entity the graph does not carry.
    #[test]
    fn graph_validate_counts_orphans_absent_from_the_graph_tree_despite_the_file_on_disk() {
        let (_temp, layout, binding, graph) = orphan_fixture(&[]);
        let on_disk = layout.working_dir().join("src/present.rs");
        fs::create_dir_all(on_disk.parent().unwrap()).unwrap();
        fs::write(&on_disk, b"fn present() {}\n").unwrap();
        assert!(on_disk.exists(), "fixture must put the file on disk");

        let mut entity = test_entity("present");
        entity.file_origin = Some(FilePathId::new("src/present.rs"));
        graph.upsert_entity(&entity).unwrap();

        let response = build_graph_validate_response(&binding, &graph).unwrap();

        let line = orphan_line(&response).expect("graph tree lacks the file, so it is orphaned");
        assert!(line.contains('1'), "{line}");
    }

    fn note_lines(response: &GraphCommandResponse) -> Vec<&String> {
        response
            .lines
            .iter()
            .filter(|line| line.starts_with('ℹ'))
            .collect()
    }

    /// The shape admission binds for a symbol another repository owns. Two of
    /// them differ only in the fingerprint derived from their import source and
    /// symbol, which is what makes that fingerprint the identity the duplicate
    /// check has to read.
    fn external_target_entity(name: &str, import_identity: u8) -> Entity {
        let mut entity = test_entity(name);
        entity.kind = EntityKind::Module;
        entity.role = EntityRole::External;
        entity.signature = String::new();
        entity.fingerprint.ast_hash = Hash256::from_bytes([import_identity; 32]);
        entity
    }

    fn duplicate_line(response: &GraphCommandResponse) -> Option<&String> {
        response
            .lines
            .iter()
            .find(|line| line.contains("duplicate"))
    }

    /// Two external targets naming one symbol through different import sources
    /// are two entities, and reporting them as one duplicated entity makes
    /// validate assert corruption against a graph Kin wrote correctly. The
    /// converse still has to hold: two entities that make the same claim about
    /// one external target are a real duplicate, and the check that stops
    /// false-positiving must not stop detecting.
    #[test]
    fn graph_validate_separates_distinct_external_targets_from_duplicated_ones() {
        let (_temp, _layout, binding, graph) = orphan_fixture(&["src/tracked.rs"]);
        graph
            .upsert_entity(&external_target_entity("info", 0x11))
            .unwrap();
        graph
            .upsert_entity(&external_target_entity("info", 0x22))
            .unwrap();

        let distinct = build_graph_validate_response(&binding, &graph).unwrap();
        assert!(
            duplicate_line(&distinct).is_none(),
            "distinct import sources are distinct entities: {}",
            distinct.lines.join("\n")
        );

        // A third entity repeating the second one's claim: same name, same
        // import identity, its own entity id.
        graph
            .upsert_entity(&external_target_entity("info", 0x22))
            .unwrap();

        let duplicated = build_graph_validate_response(&binding, &graph).unwrap();
        let line = duplicate_line(&duplicated)
            .expect("two entities claiming one external target is a duplicate");
        assert!(line.contains('1'), "{line}");
    }

    /// Notes describe a healthy graph rather than a defect, so a surface that
    /// keeps the verdict but drops them under-reports the repository's real
    /// state. Both graph surfaces read one health report, so both must render
    /// the same notes for the same state, and a reported issue must not
    /// suppress them.
    #[test]
    fn graph_validate_and_status_report_the_same_health_notes() {
        let (_temp, _layout, binding, graph) = orphan_fixture(&["src/tracked.rs"]);
        let mut entity = test_entity("covered");
        entity.role = EntityRole::Test;
        entity.file_origin = Some(FilePathId::new("src/tracked.rs"));
        graph.upsert_entity(&entity).unwrap();

        let validate = build_graph_validate_response(&binding, &graph).unwrap();
        let status = build_graph_status_response(&binding, &graph, &Default::default()).unwrap();

        let validate_notes = note_lines(&validate);
        assert!(
            !validate_notes.is_empty(),
            "validate must carry the health notes: {:?}",
            validate.lines
        );
        assert_eq!(
            validate_notes,
            note_lines(&status),
            "the two surfaces must not drift on note reporting"
        );
        assert!(
            validate.lines.iter().any(|line| line.starts_with('✗')),
            "this fixture also diverges, so notes are proven to survive a verdict: {:?}",
            validate.lines
        );
    }

    /// The converse: a file the graph's exact tree carries is not an orphan
    /// even though nothing was ever written to the working directory. Together
    /// with the test above this pins the authority — the filesystem is neither
    /// necessary nor sufficient to decide orphan status.
    #[test]
    fn graph_validate_clears_orphans_carried_by_the_graph_tree_with_no_file_on_disk() {
        let (_temp, layout, binding, graph) = orphan_fixture(&["src/tracked.rs"]);
        assert!(
            !layout.working_dir().join("src/tracked.rs").exists(),
            "fixture must leave the working tree empty"
        );

        let mut entity = test_entity("tracked");
        entity.file_origin = Some(FilePathId::new("src/tracked.rs"));
        graph.upsert_entity(&entity).unwrap();

        let response = build_graph_validate_response(&binding, &graph).unwrap();

        assert!(
            orphan_line(&response).is_none(),
            "graph tree carries the file: {:?}",
            response.lines
        );
    }
}
