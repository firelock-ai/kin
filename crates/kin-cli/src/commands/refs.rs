// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{Entity, EntityId, EntityStore, GraphNodeId, GraphStore, RelationKind};
use kin_ranking::entity_ranking;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

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

pub async fn run(entity: String, kind: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_refs(&layout, &RefsRequest { entity, kind }).await?;
    for line in response.lines {
        println!("{line}");
    }
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
            lines: vec![format!("Entity '{}' not found", request.entity)],
        });
    };
    let target = &target;

    let refs = collect_references(layout, graph, target, &relation_kinds)?;
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

    lines.push(format!("{} upstream files:", refs.len()));
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

#[derive(Debug, Clone)]
struct ReferenceEntry {
    name: String,
    file_path: Option<String>,
    start_line: Option<u32>,
    relation_kinds: Vec<RelationKind>,
}

fn collect_references(
    layout: &kin_core::KinLayout,
    graph: &impl GraphStore,
    target: &Entity,
    relation_kinds: &[RelationKind],
) -> Result<Vec<ReferenceEntry>> {
    let mut entries = collect_graph_references(graph, &target.id, relation_kinds)?;
    let text_refs =
        kin_core::find_text_references(&kin_core::source_dir(layout), target, relation_kinds);
    merge_text_references(&mut entries, text_refs);
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

fn merge_text_references(
    entries: &mut Vec<ReferenceEntry>,
    text_refs: Vec<kin_core::TextReferenceMatch>,
) {
    let mut index_by_key = HashMap::new();
    for (index, entry) in entries.iter().enumerate() {
        index_by_key.insert(
            reference_key(entry.file_path.as_deref(), &entry.name),
            index,
        );
        if let Some(path) = entry.file_path.as_deref() {
            index_by_key.insert(path.to_string(), index);
        }
    }

    for text_ref in text_refs {
        let key = text_ref.file_path.clone();
        if let Some(existing) = index_by_key.get(&key).copied() {
            let entry = &mut entries[existing];
            if entry.start_line.is_none() {
                entry.start_line = text_ref.start_line;
            }
            for kind in text_ref.relation_kinds {
                push_relation_kind(&mut entry.relation_kinds, kind);
            }
            entry.relation_kinds.sort_by_key(relation_kind_rank);
            continue;
        }

        let index = entries.len();
        entries.push(ReferenceEntry {
            name: label_from_path(&text_ref.file_path),
            file_path: Some(text_ref.file_path.clone()),
            start_line: text_ref.start_line,
            relation_kinds: text_ref.relation_kinds,
        });
        index_by_key.insert(key, index);
    }
}

fn push_relation_kind(kinds: &mut Vec<RelationKind>, kind: RelationKind) {
    if !kinds.contains(&kind) {
        kinds.push(kind);
    }
}

fn reference_key(file_path: Option<&str>, name: &str) -> String {
    file_path
        .map(|path| path.to_string())
        .unwrap_or_else(|| format!("name:{name}"))
}

fn label_from_path(rel_path: &str) -> String {
    Path::new(rel_path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(rel_path)
        .to_string()
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
    use super::parse_relation_kinds;
    use kin_model::RelationKind;

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
}
