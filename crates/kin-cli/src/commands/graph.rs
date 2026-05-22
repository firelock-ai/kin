// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use kin_model::{
    Entity, EntityId, EntityKind, EntityRole, EntityStore, FilePathId, GraphStore, RelationKind,
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
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: usize,
    pub end_byte: usize,
    pub signature: String,
    pub body: String,
}

/// `kin graph status` — quick health check of the semantic graph.
pub async fn status() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    print_graph_response(run_daemon_graph(&layout, &GraphCommandRequest::Status).await?)
}

/// `kin graph validate` — structural integrity checks.
pub async fn validate() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    print_graph_response(run_daemon_graph(&layout, &GraphCommandRequest::Validate).await?)
}

/// `kin graph inspect <entity_name>` — look up an entity and show its relations.
pub async fn inspect(name: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    print_graph_response(run_daemon_graph(&layout, &GraphCommandRequest::Inspect { name }).await?)
}

/// `kin graph source <entity>` — print the exact implementation body.
pub async fn source(entity: String, json: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_graph(&layout, &GraphCommandRequest::Source { entity }).await?;
    if json {
        if let Some(error) = response.error {
            anyhow::bail!(error);
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
        .context("daemon graph command failed")
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

pub fn execute_graph_command(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &GraphCommandRequest,
) -> Result<GraphCommandResponse> {
    match request {
        GraphCommandRequest::Status => build_graph_status_response(layout, graph),
        GraphCommandRequest::Validate => build_graph_validate_response(layout, graph),
        GraphCommandRequest::Inspect { name } => build_graph_inspect_response(graph, name),
        GraphCommandRequest::Source { entity } => {
            build_graph_source_response(layout, graph, entity)
        }
    }
}

fn build_graph_status_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
) -> Result<GraphCommandResponse> {
    let health = inspect_graph(layout, graph)?;

    let entities = graph.list_all_entities()?;
    let entity_count = entities.len();

    // Role counts
    let mut role_counts: HashMap<EntityRole, usize> = HashMap::new();
    for e in &entities {
        *role_counts.entry(e.role).or_insert(0) += 1;
    }

    // Kind counts
    let mut kind_counts: HashMap<EntityKind, usize> = HashMap::new();
    for e in &entities {
        *kind_counts.entry(e.kind).or_insert(0) += 1;
    }

    // Relation counts by kind
    let mut relation_counts: HashMap<RelationKind, usize> = HashMap::new();
    let mut seen_relation_ids = HashSet::new();
    let mut total_relations = 0usize;
    for e in &entities {
        for rel in graph.get_all_relations_for_entity(&e.id)? {
            if seen_relation_ids.insert(rel.id.clone()) {
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
    let with_docs = entities.iter().filter(|e| e.doc_summary.is_some()).count();

    let mut lines = Vec::new();
    lines.push("=== Graph Health ===".to_string());
    lines.push(String::new());
    lines.push(format!(
        "Entities: {}  |  Relations: {}  |  Files: {}",
        entity_count,
        total_relations,
        unique_files.len()
    ));
    lines.push(format!(
        "Rels/Entity: {:.2}",
        if entity_count == 0 {
            0.0
        } else {
            total_relations as f64 / entity_count as f64
        }
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
    lines.push(format!("Relations: {}", rel_parts.join(", ")));

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
        "Semantic rels (excluding CoChanges): {} ({:.2}/entity)",
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
    if entity_count > 0 && total_relations == 0 {
        warnings.push("no relations in graph — cross-file linking may have failed".to_string());
    }
    if entity_count > 0 && role_counts.len() == 1 && role_counts.contains_key(&EntityRole::Source) {
        warnings
            .push("all entities are Source — role classification may not be working".to_string());
    }
    let rels_per_ent = if entity_count == 0 {
        0.0
    } else {
        total_relations as f64 / entity_count as f64
    };
    if rels_per_ent < 0.1 && entity_count > 100 {
        warnings.push(format!(
            "very low relation density ({:.2} rels/entity) — linker may be failing",
            rels_per_ent
        ));
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

    Ok(GraphCommandResponse {
        lines,
        error: (!criticals.is_empty())
            .then(|| format!("{} critical graph health issue(s) found", criticals.len())),
        source: None,
    })
}

fn build_graph_validate_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
) -> Result<GraphCommandResponse> {
    let health = inspect_graph(layout, graph)?;
    let stats = graph.graph_stats();

    let entities = graph.list_all_entities()?;
    let mut issues = Vec::new();

    // Check for duplicate entities (same name + file + kind + byte position).
    // Using byte position distinguishes legitimate overloads (Python @overload,
    // Rust impl From<X>, C++ template specializations) from true duplicates.
    // Two entities at different positions in the same file are never duplicates.
    let mut seen: HashMap<(String, Option<String>, EntityKind, usize), Vec<kin_model::EntityId>> =
        HashMap::new();
    for e in &entities {
        let start_byte = e.span.as_ref().map(|s| s.start_byte).unwrap_or(0);
        let key = (
            e.name.clone(),
            e.file_origin.as_ref().map(|f| f.0.clone()),
            e.kind,
            start_byte,
        );
        seen.entry(key).or_default().push(e.id);
    }
    let duplicates: Vec<_> = seen.iter().filter(|(_, ids)| ids.len() > 1).collect();
    if !duplicates.is_empty() {
        issues.push(format!(
            "{} true duplicate entities (same name+file+kind+position)",
            duplicates.len()
        ));
    }

    // Check for orphaned entities (file_origin that doesn't exist on disk)
    let source_root = kin_core::source_dir(&layout);
    let mut orphaned = 0usize;
    for e in &entities {
        if let Some(ref fo) = e.file_origin {
            if !source_root.join(&fo.0).exists() {
                orphaned += 1;
            }
        }
    }
    if orphaned > 0 {
        issues.push(format!(
            "{} orphaned entities (file no longer exists on disk)",
            orphaned
        ));
    }

    // Check relation integrity (src/dst entity IDs exist)
    let entity_ids: std::collections::HashSet<_> = entities.iter().map(|e| e.id).collect();
    let mut broken_relations = 0usize;
    for e in &entities {
        for rel in graph.get_all_relations_for_entity(&e.id)? {
            if let kin_model::GraphNodeId::Entity(id) = rel.src {
                if !entity_ids.contains(&id) {
                    broken_relations += 1;
                }
            }
            if let kin_model::GraphNodeId::Entity(id) = rel.dst {
                if !entity_ids.contains(&id) {
                    broken_relations += 1;
                }
            }
        }
    }
    if broken_relations > 0 {
        issues.push(format!(
            "{} relations reference non-existent entities",
            broken_relations
        ));
    }

    issues.extend(health.critical_issues.clone());

    let mut lines = Vec::new();
    lines.push("=== Graph Validation ===".to_string());
    lines.push(String::new());
    lines.push(format!(
        "Checked {} entities, {} relations",
        entities.len(),
        stats.total_relations
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
        anyhow::bail!("no entity found matching '{}'", name);
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
            lines.push(format!(
                "  Span: lines {}-{}",
                span.start_line, span.end_line
            ));
        }
        lines.push(format!("  Signature: {}", entity.signature));
        if let Some(ref doc) = entity.doc_summary {
            lines.push(format!("  Doc: {}", doc));
        }
        lines.push(format!("  Visibility: {:?}", entity.visibility));

        // Show relations
        let relations = graph.get_all_relations_for_entity(&entity.id)?;
        if !relations.is_empty() {
            lines.push(format!("  Relations ({}):", relations.len()));
            for rel in relations.iter().take(20) {
                let target_name = match rel.dst {
                    kin_model::GraphNodeId::Entity(id) => {
                        if id == entity.id {
                            // Incoming relation — show source
                            match rel.src {
                                kin_model::GraphNodeId::Entity(src_id) => graph
                                    .get_entity(&src_id)?
                                    .map(|e| {
                                        format!(
                                            "{} ({})",
                                            e.name,
                                            e.file_origin
                                                .as_ref()
                                                .map(|f| f.0.as_str())
                                                .unwrap_or("?")
                                        )
                                    })
                                    .unwrap_or_else(|| format!("{}", src_id)),
                                _ => format!("{:?}", rel.src),
                            }
                        } else {
                            graph
                                .get_entity(&id)?
                                .map(|e| {
                                    format!(
                                        "{} ({})",
                                        e.name,
                                        e.file_origin.as_ref().map(|f| f.0.as_str()).unwrap_or("?")
                                    )
                                })
                                .unwrap_or_else(|| format!("{}", id))
                        }
                    }
                    _ => format!("{:?}", rel.dst),
                };
                let direction = if matches!(rel.dst, kin_model::GraphNodeId::Entity(id) if id == entity.id)
                {
                    "<-"
                } else {
                    "->"
                };
                lines.push(format!("    {} {:?} {}", direction, rel.kind, target_name));
            }
            if relations.len() > 20 {
                lines.push(format!("    ... and {} more", relations.len() - 20));
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

pub fn build_graph_source_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    entity_query: &str,
) -> Result<GraphCommandResponse> {
    let entity = resolve_source_entity(graph, entity_query)?
        .ok_or_else(|| anyhow::anyhow!("no entity found matching '{}'", entity_query))?;
    let record = graph_source_record(layout, graph, &entity)?;

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
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
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
    let bytes = read_entity_file_bytes_from_graph(layout, graph, file_origin)?;
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
    Ok(GraphSourceRecord {
        id: entity.id.to_string(),
        name: entity.name.clone(),
        kind: format!("{:?}", entity.kind),
        language: entity.language.to_string(),
        file_path: file_origin.0.clone(),
        start_line: span.start_line,
        end_line: span.end_line,
        start_byte: span.start_byte,
        end_byte: span.end_byte,
        signature: entity.signature.clone(),
        body,
    })
}

fn read_entity_file_bytes_from_graph(
    layout: &kin_core::KinLayout,
    graph: &impl GraphStore,
    file_id: &FilePathId,
) -> Result<Vec<u8>> {
    let branch_name = kin_core::read_current_branch(layout)?;
    let branch = graph
        .get_branch(&branch_name)?
        .ok_or_else(|| anyhow::anyhow!("current branch '{}' not found in graph", branch_name))?;
    let genesis = kin_core::build_genesis_change();
    let tree = kin_core::build_file_tree(graph, &genesis.id, &branch.head)?;
    let hash = tree
        .get(file_id)
        .ok_or_else(|| anyhow::anyhow!("file '{}' not found in graph file tree", file_id.0))?;
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())?;
    let blob_hash = kin_blobs::Hash256(*hash.as_bytes());
    blob_store
        .read(&blob_hash)
        .with_context(|| {
            format!(
                "graph blob for file '{}' is unavailable (hash {}, branch '{}', head {}); source body cannot be read from daemon-backed graph",
                file_id.0, blob_hash, branch_name, branch.head
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        ArtifactDelta, ArtifactDeltaKind, AuthorId, Branch, BranchName, ChangeStore, Entity,
        EntityMetadata, FingerprintAlgorithm, Hash256, LanguageId, SemanticChange,
        SemanticChangeId, SemanticFingerprint, SourceSpan, Timestamp, Visibility,
    };
    use std::fs;

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
        graph: kin_db::InMemoryGraph,
        file_id: FilePathId,
    }

    fn graph_source_fixture(source: Option<&[u8]>) -> GraphSourceFixture {
        let temp = tempfile::tempdir().unwrap();
        let kin_root = temp.path().join(".kin");
        fs::create_dir_all(kin_root.join("objects")).unwrap();
        let layout = kin_core::KinLayout::new(kin_root);
        let graph = kin_db::InMemoryGraph::new();

        let branch_name = BranchName::new("main");
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();

        let file_id = FilePathId::new("src/lib.rs");
        let blob_hash = if let Some(source) = source {
            let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();
            blob_store.write(source).unwrap()
        } else {
            Hash256::from_bytes([0x99; 32])
        };
        let change_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x42; 32]));
        graph
            .create_change(&SemanticChange {
                id: change_id,
                parents: vec![genesis.id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add source".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: file_id.clone(),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(blob_hash),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: Some(branch_name.clone()),
            })
            .unwrap();
        graph
            .create_branch(&Branch {
                name: branch_name.clone(),
                head: change_id,
            })
            .unwrap();
        kin_core::write_current_branch(&layout, &branch_name).unwrap();

        GraphSourceFixture {
            _temp: temp,
            layout,
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

    #[test]
    fn graph_source_reads_exact_body_from_graph_blob_by_uuid() {
        let source = "fn before() {}\nfn target() {\n    2 + 2\n}\nfn after() {}\n";
        let body = "fn target() {\n    2 + 2\n}";
        let start = source.find(body).unwrap();
        let end = start + body.len();
        let fixture = graph_source_fixture(Some(source.as_bytes()));

        let entity = source_entity("target", fixture.file_id.clone(), start, end);
        let id = entity.id;
        fixture.graph.upsert_entity(&entity).unwrap();

        let response =
            build_graph_source_response(&fixture.layout, &fixture.graph, &id.to_string()).unwrap();
        let source = response.source.unwrap();

        assert_eq!(source.body, body);
        assert_eq!(source.file_path, "src/lib.rs");
        assert_eq!(source.start_byte, start);
        assert_eq!(source.end_byte, end);
    }

    #[test]
    fn graph_source_returns_error_on_oob_span() {
        let source = "fn target() {}\n";
        let fixture = graph_source_fixture(Some(source.as_bytes()));
        let end = source.len() + 10;
        let entity = source_entity("target", fixture.file_id.clone(), 0, end);
        let id = entity.id;
        fixture.graph.upsert_entity(&entity).unwrap();

        let err = build_graph_source_response(&fixture.layout, &fixture.graph, &id.to_string())
            .unwrap_err()
            .to_string();

        assert!(
            err.contains(&format!("source span 0..{end} is out of bounds")),
            "{err}"
        );
        assert!(err.contains("src/lib.rs"), "{err}");
    }

    #[test]
    fn graph_source_returns_error_on_missing_blob() {
        let fixture = graph_source_fixture(None);
        let entity = source_entity("target", fixture.file_id.clone(), 0, 8);
        let id = entity.id;
        fixture.graph.upsert_entity(&entity).unwrap();

        let err = build_graph_source_response(&fixture.layout, &fixture.graph, &id.to_string())
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("graph blob for file 'src/lib.rs' is unavailable"),
            "{err}"
        );
        assert!(
            err.contains("source body cannot be read from daemon-backed graph"),
            "{err}"
        );
    }
}
