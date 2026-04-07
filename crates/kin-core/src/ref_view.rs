// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::path::Path;

use kin_blobs::BlobStore;
use kin_db::{GraphSnapshot, InMemoryGraph};
use kin_index::{
    extract_artifact, link_cross_file_against_entities, FileClassification, FileClassifier,
    FileParseData, IndexPipeline,
};
use kin_model::{
    BranchName, ChangeStore, EntityId, FileLayout, FilePathId, GraphStore, Hash256, ImportSection,
    OpaqueArtifact, ParseCompleteness, SemanticChange, SemanticChangeId, ShallowTrackedFile,
    SourceRegion, StructuredArtifact,
};

use crate::{KinError, Result};

/// Build a read-only graph view resolved at a specific semantic ref.
///
/// The returned graph contains:
/// - entities and relations replayed as of `head`
/// - only changes reachable from `head`
/// - entity-source file layouts derived from persisted historical entity spans
/// - non-entity tracked files rebuilt from historical blob content
/// - a fresh in-memory text index aligned with the historical view
///
/// Embedding/vector state is intentionally not reconstructed yet.
pub fn build_graph_at_ref(
    graph: &InMemoryGraph,
    blob_store: &BlobStore,
    head: &SemanticChangeId,
) -> Result<InMemoryGraph> {
    let changes = collect_changes_at_ref(graph, head)?;
    let resolved = graph
        .resolve_graph_at(head)
        .map_err(|err| KinError::Graph(err.to_string()))?;

    let mut snapshot = GraphSnapshot::empty();
    snapshot.entities = resolved.entities;
    snapshot.relations = resolved.relations;
    snapshot.changes = changes
        .iter()
        .map(|change| (change.id, change.clone()))
        .collect();
    snapshot.change_children = build_change_children(&changes);
    snapshot.file_hashes = resolved
        .file_tree
        .iter()
        .map(|(file_id, hash)| (file_id.0.clone(), *hash.as_bytes()))
        .collect();
    snapshot.branches = HashMap::<BranchName, kin_model::Branch>::new();

    rebuild_entity_source_file_layouts(&mut snapshot, &resolved.file_tree, blob_store)?;
    rebuild_non_entity_tracked_files(&mut snapshot, &resolved.file_tree, blob_store)?;

    Ok(InMemoryGraph::from_snapshot(snapshot))
}

pub fn collect_changes_at_ref<G>(
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

fn rebuild_entity_source_file_layouts(
    snapshot: &mut GraphSnapshot,
    file_tree: &HashMap<FilePathId, Hash256>,
    blob_store: &BlobStore,
) -> Result<()> {
    let pipeline = IndexPipeline::new();
    let mut parsed_entities = Vec::new();
    let mut parsed_relations = Vec::new();
    let mut parsed_files = Vec::new();
    let mut parsed_layouts = Vec::new();

    for (file_id, hash) in file_tree {
        if !matches!(
            FileClassifier::classify(Path::new(&file_id.0)),
            FileClassification::EntitySource
        ) {
            continue;
        }

        let content = match blob_store.read(hash) {
            Ok(content) => content,
            Err(err) => {
                tracing::warn!(
                    file = %file_id,
                    hash = %hash,
                    error = %err,
                    "skipping historical source layout with missing blob"
                );
                continue;
            }
        };

        let file_entities = snapshot
            .entities
            .values()
            .filter(|entity| entity.file_origin.as_ref() == Some(file_id))
            .cloned()
            .collect::<Vec<_>>();
        if file_entities.is_empty() {
            let indexed = match pipeline.index_file_content_with_tests(
                file_id,
                &content,
                kin_blobs::Hash256::from_bytes(*hash.as_bytes()),
            ) {
                Ok(indexed) => indexed,
                Err(err) => {
                    tracing::warn!(
                        file = %file_id,
                        hash = %hash,
                        error = %err,
                        "skipping historical source fallback parse that could not be indexed"
                    );
                    continue;
                }
            };

            parsed_relations.extend(indexed.indexed_file.relations.iter().cloned());
            parsed_files.push(FileParseData {
                file_path: indexed.indexed_file.file_id.0.clone(),
                entities: indexed.indexed_file.entities.clone(),
                relations: indexed.indexed_file.extracted_relations.clone(),
                imports: indexed.indexed_file.imports.clone(),
            });
            parsed_entities.extend(indexed.indexed_file.entities);
            parsed_layouts.push(indexed.indexed_file.file_layout);
            continue;
        }

        snapshot.file_layouts.push(build_entity_file_layout(
            file_id,
            &file_entities,
            content.len(),
            ParseCompleteness::Partial(
                "historical ref view layout derived from persisted entity spans".to_string(),
            ),
        ));
    }

    if !parsed_entities.is_empty() {
        snapshot.file_layouts.extend(parsed_layouts);
        for entity in parsed_entities {
            snapshot.entities.insert(entity.id, entity);
        }

        let universe_entities = snapshot.entities.values().cloned().collect::<Vec<_>>();
        parsed_relations.extend(link_cross_file_against_entities(
            &parsed_files,
            &universe_entities,
        ));
        for relation in parsed_relations {
            snapshot.relations.insert(relation.id, relation);
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

fn build_entity_file_layout(
    file_id: &FilePathId,
    entities: &[kin_model::Entity],
    file_len: usize,
    parse_completeness: ParseCompleteness,
) -> FileLayout {
    let mut entity_spans: Vec<(EntityId, Range<usize>)> = entities
        .iter()
        .filter_map(|entity| {
            entity
                .span
                .as_ref()
                .map(|span| (entity.id, span.start_byte..span.end_byte))
        })
        .collect();
    entity_spans.sort_by_key(|(_, range)| range.start);

    let mut regions = Vec::new();
    let mut cursor = 0;
    for (entity_id, byte_range) in entity_spans {
        if byte_range.start > cursor {
            regions.push(SourceRegion::Trivia {
                byte_range: cursor..byte_range.start,
            });
        }
        regions.push(SourceRegion::EntityRef {
            entity_id,
            byte_range: byte_range.clone(),
        });
        cursor = byte_range.end;
    }
    if cursor < file_len {
        regions.push(SourceRegion::Trivia {
            byte_range: cursor..file_len,
        });
    }

    FileLayout {
        file_id: file_id.clone(),
        parse_completeness,
        imports: ImportSection {
            byte_range: 0..0,
            items: Vec::new(),
        },
        regions,
    }
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
        ArtifactDelta, ArtifactDeltaKind, AuthorId, Entity, EntityDelta, EntityKind, EntityRole,
        EntityStore, FingerprintAlgorithm, LanguageId, SemanticChange, SemanticFingerprint,
        SourceSpan, Timestamp, Visibility,
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

    #[test]
    fn build_graph_at_ref_preserves_semantic_entity_identity_from_history() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x21; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let current_hash = blob_store
            .write(b"def processor():\n    return 'processor'\n")
            .unwrap();
        let auto_parse_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x22; 32]));
        let processor = test_entity("processor", "src/lib.py");
        graph
            .create_change(&SemanticChange {
                id: auto_parse_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "auto-parse".to_string(),
                entity_deltas: vec![EntityDelta::Added(processor.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: FilePathId::new("src/lib.py"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(current_hash),
                }],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let historical_hash = blob_store
            .write(b"def handler():\n    return 'handler'\n")
            .unwrap();
        let historical_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x23; 32]));
        graph
            .create_change(&change(
                historical_id,
                vec![auto_parse_id],
                vec![ArtifactDelta {
                    file_id: FilePathId::new("src/lib.py"),
                    kind: ArtifactDeltaKind::Modified,
                    old_hash: Some(current_hash),
                    new_hash: Some(historical_hash),
                }],
            ))
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &historical_id).unwrap();
        let entities = historical.list_all_entities().unwrap();
        assert_eq!(entities.len(), 1);
        assert!(
            entities
                .iter()
                .any(|entity| entity.id == processor.id && entity.name == "processor"),
            "historical views should preserve semantic entity identity from the change DAG"
        );
        assert!(
            entities.iter().all(|entity| entity.name != "handler"),
            "source blobs alone should not silently rewrite semantic history"
        );

        let layout = historical
            .get_file_layout(&FilePathId::new("src/lib.py"))
            .unwrap()
            .expect("historical entity-source file should still expose a layout");
        assert!(
            layout.regions.iter().any(|region| matches!(
                region,
                kin_model::SourceRegion::EntityRef { entity_id, .. } if *entity_id == processor.id
            )),
            "historical file layouts should point at the persisted entity IDs"
        );
    }

    #[test]
    fn build_graph_at_ref_falls_back_to_blob_parsing_for_artifact_only_history() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x31; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let historical_hash = blob_store
            .write(b"def handler():\n    return 'handler'\n")
            .unwrap();
        let historical_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x32; 32]));
        graph
            .create_change(&change(
                historical_id,
                vec![genesis_id],
                vec![ArtifactDelta {
                    file_id: FilePathId::new("src/lib.py"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(historical_hash),
                }],
            ))
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &historical_id).unwrap();
        let entities = historical.list_all_entities().unwrap();
        assert!(
            entities.iter().any(|entity| entity.name == "handler"),
            "artifact-only imported history should still expose source entities via blob parsing"
        );

        let layout = historical
            .get_file_layout(&FilePathId::new("src/lib.py"))
            .unwrap()
            .expect("artifact-only source file should expose a parsed layout");
        assert!(
            layout
                .regions
                .iter()
                .any(|region| matches!(region, kin_model::SourceRegion::EntityRef { .. })),
            "fallback parsed layouts should contain entity regions"
        );
    }

    fn test_entity(name: &str, path: &str) -> Entity {
        Entity {
            id: kin_model::EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(path)),
            span: Some(SourceSpan {
                file: FilePathId::new(path),
                start_byte: 0,
                end_byte: 0,
                start_line: 1,
                start_col: 1,
                end_line: 1,
                end_col: 1,
            }),
            signature: format!("def {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }
}
