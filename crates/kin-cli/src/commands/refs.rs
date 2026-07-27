// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{Entity, EntityId, EntityStore, GraphNodeId, GraphStore, RelationKind};
use kin_ranking::entity_ranking;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub with_references: usize,
    pub without_references: usize,
    #[serde(default)]
    pub relation_kinds: Vec<String>,
    pub compact: bool,
    #[serde(default)]
    pub results: Vec<serde_json::Value>,
}

pub async fn run(entity: String, kind: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _scope = announce_active_scope(&layout, "refs").await?;
    let response = run_daemon_refs(&layout, &RefsRequest { entity, kind }).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

pub async fn run_bulk(entities: String, kind: String, compact: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
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
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for refs but no daemon endpoint is available")
    })?;
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
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for bulk refs but no daemon endpoint is available")
    })?;
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
    let allowed: std::collections::HashSet<RelationKind> = relation_kinds.iter().copied().collect();
    let mut results = Vec::with_capacity(request.entity_ids.len());
    let mut with_references = 0usize;

    for raw_id in &request.entity_ids {
        let parsed = uuid::Uuid::parse_str(raw_id.trim());
        let Ok(uuid) = parsed else {
            let mut row = serde_json::json!({
                "entity_id": raw_id,
                "error": "invalid entity_id (not a UUID)",
            });
            if !request.compact {
                row["has_references"] = serde_json::json!(false);
                row["reference_count"] = serde_json::json!(0);
            }
            results.push(row);
            continue;
        };
        let entity_id = EntityId(uuid);
        let entity = graph.get_entity(&entity_id)?;
        let Some(entity) = entity else {
            let mut row = serde_json::json!({
                "entity_id": raw_id,
                "error": "entity not found",
                "has_references": false,
                "reference_count": 0,
            });
            if !request.compact {
                row["name"] = serde_json::Value::Null;
                row["kind"] = serde_json::Value::Null;
                row["file_path"] = serde_json::Value::Null;
                row["matched_kinds"] = serde_json::json!([]);
            }
            results.push(row);
            continue;
        };

        let mut reference_count = 0usize;
        let mut matched_kinds: Vec<RelationKind> = Vec::new();
        for rel in graph.get_all_relations_for_entity(&entity_id)? {
            let Some(src_entity_id) = rel.src.as_entity() else {
                continue;
            };
            if rel.dst != GraphNodeId::Entity(entity_id) {
                continue;
            }
            if !allowed.contains(&rel.kind) {
                continue;
            }
            if src_entity_id == entity_id {
                continue;
            }
            reference_count += 1;
            if !matched_kinds.contains(&rel.kind) {
                matched_kinds.push(rel.kind);
            }
        }

        let has_references = reference_count > 0;
        if has_references {
            with_references += 1;
        }

        if request.compact {
            results.push(serde_json::json!({
                "entity_id": entity_id.to_string(),
                "has_references": has_references,
                "reference_count": reference_count,
            }));
        } else {
            matched_kinds.sort_by_key(relation_kind_rank);
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
    Ok(BulkRefsResponse {
        total_checked,
        with_references,
        without_references: total_checked - with_references,
        relation_kinds: relation_kinds
            .iter()
            .copied()
            .map(relation_kind_label)
            .collect(),
        compact: request.compact,
        results,
    })
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
    name: String,
    file_path: Option<String>,
    start_line: Option<u32>,
    relation_kinds: Vec<RelationKind>,
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
    let mut entries = collect_graph_references(graph, &target.id, relation_kinds)?;
    entries.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(entries)
}

fn collect_graph_references(
    graph: &impl GraphStore,
    entity_id: &EntityId,
    relation_kinds: &[RelationKind],
) -> Result<Vec<ReferenceEntry>> {
    let allowed: std::collections::HashSet<_> = relation_kinds.iter().copied().collect();
    let mut grouped: HashMap<String, ReferenceEntry> = HashMap::new();

    for rel in graph.get_all_relations_for_entity(entity_id)? {
        if rel.dst != GraphNodeId::Entity(*entity_id) || !allowed.contains(&rel.kind) {
            continue;
        }
        let Some(src_entity_id) = rel.src.as_entity() else {
            continue;
        };
        let Some(entity) = graph.get_entity(&src_entity_id)? else {
            continue;
        };

        let file_path = entity.file_origin.as_ref().map(|f| f.0.clone());
        let key = reference_key(file_path.as_deref(), &entity.name);
        let entry = grouped.entry(key).or_insert_with(|| ReferenceEntry {
            name: entity.name.clone(),
            file_path: file_path.clone(),
            start_line: entity.span.as_ref().map(|s| s.start_line),
            relation_kinds: Vec::new(),
        });
        if entry.file_path.is_none() {
            entry.file_path = file_path;
        }
        if entry.start_line.is_none() {
            entry.start_line = entity.span.as_ref().map(|s| s.start_line);
        }
        push_relation_kind(&mut entry.relation_kinds, rel.kind);
    }

    let mut entries = grouped.into_values().collect::<Vec<_>>();
    for entry in &mut entries {
        entry.relation_kinds.sort_by_key(relation_kind_rank);
    }
    Ok(entries)
}

fn push_relation_kind(kinds: &mut Vec<RelationKind>, kind: RelationKind) {
    if !kinds.contains(&kind) {
        kinds.push(kind);
    }
}

fn reference_key(file_path: Option<&str>, name: &str) -> String {
    // Keyed by (file, name), not by file alone: two entities in the same file
    // that both reference the target are two rows, not one row wearing the
    // first entity's name. The listing enumerates referencing entities, and
    // the count line above it says so.
    file_path
        .map(|path| format!("{path}\u{1f}{name}"))
        .unwrap_or_else(|| format!("name:{name}"))
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
    use super::{build_refs_response, parse_relation_kinds, refs_not_found_guidance, RefsRequest};
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

    /// Two callers in one file are two rows. The per-file grouping this
    /// replaces collapsed them into a single row wearing the first caller's
    /// name, under a count line that then miscounted the referencing entities.
    #[test]
    fn refs_lists_every_referencing_entity_not_one_per_file() {
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
        let caller_a = entity("caller_a", "callers.rs");
        let caller_b = entity("caller_b", "callers.rs");

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
            joined.contains("caller_a") && joined.contains("caller_b"),
            "both same-file callers must be listed: {joined}"
        );
    }
}
