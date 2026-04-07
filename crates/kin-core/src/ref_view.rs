// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::path::Path;

use kin_blobs::BlobStore;
use kin_db::{GraphSnapshot, InMemoryGraph};
use kin_index::{extract_artifact, FileClassification, FileClassifier};
use kin_model::{
    BranchName, ChangeStore, FilePathId, GraphStore, Hash256, OpaqueArtifact, SemanticChange,
    SemanticChangeId, ShallowTrackedFile, StructuredArtifact,
};

use crate::{KinError, Result};

/// Build a read-only graph view resolved at a specific semantic ref.
///
/// The returned graph contains:
/// - entities and relations replayed as of `head`
/// - only changes reachable from `head`
/// - non-entity tracked files rebuilt from historical blob content
/// - a fresh in-memory text index aligned with the historical view
///
/// Embedding/vector state is intentionally not reconstructed yet.
pub fn build_graph_at_ref(
    graph: &InMemoryGraph,
    blob_store: &BlobStore,
    head: &SemanticChangeId,
) -> Result<InMemoryGraph> {
    let changes = collect_changes_topologically(graph, head)?;
    let resolved = graph
        .resolve_graph_at(head)
        .map_err(|err| KinError::Graph(err.to_string()))?;
    let file_tree = graph
        .resolve_file_tree_at(head)
        .map_err(|err| KinError::Graph(err.to_string()))?;

    let mut snapshot = graph.to_snapshot();
    snapshot.entities = resolved.entities;
    snapshot.relations = resolved.relations;
    snapshot.outgoing.clear();
    snapshot.incoming.clear();
    snapshot.changes = changes
        .iter()
        .map(|change| (change.id, change.clone()))
        .collect();
    snapshot.change_children = build_change_children(&changes);
    snapshot.branches = HashMap::<BranchName, kin_model::Branch>::new();
    snapshot.file_hashes = file_tree
        .iter()
        .map(|(file_id, hash)| (file_id.0.clone(), *hash.as_bytes()))
        .collect();
    snapshot.shallow_files.clear();
    snapshot.file_layouts.clear();
    snapshot.structured_artifacts.clear();
    snapshot.opaque_artifacts.clear();

    rebuild_non_entity_tracked_files(&mut snapshot, &file_tree, blob_store)?;

    Ok(InMemoryGraph::from_snapshot(snapshot))
}

fn collect_changes_topologically<G>(
    graph: &G,
    head: &SemanticChangeId,
) -> Result<Vec<SemanticChange>>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    fn visit<G>(
        graph: &G,
        id: &SemanticChangeId,
        seen: &mut HashSet<SemanticChangeId>,
        ordered: &mut Vec<SemanticChange>,
    ) -> Result<()>
    where
        G: GraphStore,
        <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
    {
        if !seen.insert(*id) {
            return Ok(());
        }
        let change = graph
            .get_change(id)
            .map_err(|err| KinError::Graph(err.to_string()))?
            .ok_or_else(|| KinError::Graph(format!("change {} not found", id)))?;
        for parent in &change.parents {
            visit(graph, parent, seen, ordered)?;
        }
        ordered.push(change);
        Ok(())
    }

    let mut seen = HashSet::new();
    let mut ordered = Vec::new();
    visit(graph, head, &mut seen, &mut ordered)?;
    Ok(ordered)
}

fn build_change_children(
    changes: &[SemanticChange],
) -> HashMap<SemanticChangeId, Vec<SemanticChangeId>> {
    let mut children: HashMap<SemanticChangeId, Vec<SemanticChangeId>> = HashMap::new();
    for change in changes {
        for parent in &change.parents {
            children.entry(*parent).or_default().push(change.id);
        }
    }
    children
}

fn rebuild_non_entity_tracked_files(
    snapshot: &mut GraphSnapshot,
    file_tree: &HashMap<FilePathId, Hash256>,
    blob_store: &BlobStore,
) -> Result<()> {
    let entity_paths: HashSet<String> = snapshot
        .entities
        .values()
        .filter_map(|entity| entity.file_origin.as_ref())
        .map(|file_id| file_id.0.clone())
        .collect();

    for (file_id, hash) in file_tree {
        if entity_paths.contains(&file_id.0) {
            continue;
        }

        let content = match blob_store.read(hash) {
            Ok(content) => content,
            Err(err) => {
                tracing::warn!(file = %file_id, hash = %hash, error = %err, "skipping historical tracked file with missing blob");
                continue;
            }
        };

        match FileClassifier::classify(Path::new(&file_id.0)) {
            FileClassification::EntitySource => {}
            FileClassification::ShallowSyntax { language_hint } => {
                if let Some(shallow) =
                    kin_parser::parse_shallow_file(&content, file_id, &language_hint)
                {
                    snapshot.shallow_files.push(ShallowTrackedFile {
                        file_id: file_id.clone(),
                        language_hint,
                        declaration_count: shallow.declarations.len(),
                        import_count: shallow.imports.len(),
                        syntax_hash: shallow.fingerprint.syntax_hash,
                        signature_hash: shallow.fingerprint.signature_hash,
                        declaration_names: summarize_shallow_items(
                            shallow.declarations.iter().map(|decl| decl.name.clone()),
                        ),
                        import_paths: summarize_shallow_items(
                            shallow.imports.iter().map(|import| import.raw_path.clone()),
                        ),
                    });
                } else {
                    snapshot
                        .opaque_artifacts
                        .push(build_opaque_artifact(file_id, *hash, None, &content));
                }
            }
            FileClassification::StructuredArtifact(kind) => {
                let artifact =
                    extract_artifact(kind, &content, file_id).unwrap_or(StructuredArtifact {
                        file_id: file_id.clone(),
                        kind,
                        content_hash: *hash,
                        text_preview: preview_text(&content),
                    });
                snapshot.structured_artifacts.push(artifact);
            }
            FileClassification::OpaqueArtifact { mime_hint } => {
                snapshot
                    .opaque_artifacts
                    .push(build_opaque_artifact(file_id, *hash, mime_hint, &content));
            }
        }
    }

    Ok(())
}

fn build_opaque_artifact(
    file_id: &FilePathId,
    content_hash: Hash256,
    mime_hint: Option<String>,
    content: &[u8],
) -> OpaqueArtifact {
    OpaqueArtifact {
        file_id: file_id.clone(),
        content_hash,
        mime_type: mime_hint.clone(),
        text_preview: preview_text_if_likely_text(content, mime_hint.as_deref()),
    }
}

fn preview_text(content: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(content).ok()?;
    let collapsed = text
        .split_whitespace()
        .take(64)
        .collect::<Vec<_>>()
        .join(" ");
    let trimmed = collapsed.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.chars().take(320).collect())
    }
}

fn preview_text_if_likely_text(content: &[u8], mime_hint: Option<&str>) -> Option<String> {
    let textual_mime = mime_hint.is_some_and(|mime| {
        mime.starts_with("text/")
            || mime.contains("json")
            || mime.contains("yaml")
            || mime.contains("toml")
            || mime.contains("xml")
            || mime.contains("javascript")
            || mime.contains("shell")
    });
    if textual_mime {
        return preview_text(content);
    }

    let printable = content
        .iter()
        .copied()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    if !content.is_empty() && printable * 100 / content.len() >= 92 {
        return preview_text(content);
    }

    None
}

fn summarize_shallow_items(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut result = Vec::new();
    for item in items {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            result.push(trimmed.to_string());
            if result.len() >= 16 {
                break;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_blobs::BlobStore;
    use kin_model::{
        ArtifactDelta, ArtifactDeltaKind, AuthorId, EntityStore, SemanticChange, Timestamp,
    };

    fn change(
        id: SemanticChangeId,
        parents: Vec<SemanticChangeId>,
        artifact_deltas: Vec<ArtifactDelta>,
    ) -> SemanticChange {
        SemanticChange {
            id,
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: format!("change {}", id),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    #[test]
    fn build_graph_at_ref_reconstructs_historical_tracked_files() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x11; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let readme_v1 = blob_store.write(b"Authentication guide for v1").unwrap();
        let cargo_v1 = blob_store.write(b"[package]\nname = \"kin\"\n").unwrap();
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x12; 32]));
        graph
            .create_change(&change(
                add_id,
                vec![genesis_id],
                vec![
                    ArtifactDelta {
                        file_id: FilePathId::new("README.md"),
                        kind: ArtifactDeltaKind::Added,
                        old_hash: None,
                        new_hash: Some(readme_v1),
                    },
                    ArtifactDelta {
                        file_id: FilePathId::new("Cargo.toml"),
                        kind: ArtifactDeltaKind::Added,
                        old_hash: None,
                        new_hash: Some(cargo_v1),
                    },
                ],
            ))
            .unwrap();

        let readme_v2 = blob_store.write(b"Deployment guide for v2").unwrap();
        let head_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x13; 32]));
        graph
            .create_change(&change(
                head_id,
                vec![add_id],
                vec![ArtifactDelta {
                    file_id: FilePathId::new("README.md"),
                    kind: ArtifactDeltaKind::Modified,
                    old_hash: Some(readme_v1),
                    new_hash: Some(readme_v2),
                }],
            ))
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &add_id).unwrap();

        let structured = historical.list_structured_artifacts().unwrap();
        assert_eq!(structured.len(), 1);
        assert_eq!(structured[0].file_id.0, "Cargo.toml");

        let opaque = historical.list_opaque_artifacts().unwrap();
        assert_eq!(opaque.len(), 1);
        assert_eq!(opaque[0].file_id.0, "README.md");
        assert!(opaque[0]
            .text_preview
            .as_deref()
            .unwrap_or_default()
            .contains("Authentication guide"));

        assert!(!historical
            .text_search("Authentication", 10)
            .unwrap()
            .is_empty());
        assert!(historical.text_search("Deployment", 10).unwrap().is_empty());
    }
}
