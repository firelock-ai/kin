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
    BranchName, ChangeStore, EntityId, EntityKind, FileLayout, FilePathId, GraphStore, Hash256,
    ImportSection, OpaqueArtifact, ParseCompleteness, SemanticChange, SemanticChangeId,
    ShallowTrackedFile, SourceRegion, StructuredArtifact,
};
use kin_parser::extract::{EMBEDDING_BODY_PREVIEW_KEY, FILE_SURFACE_CONTEXT_KEY};

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
/// When `repo_path` is provided and a blob is missing from the blob store,
/// the function falls back to reading the blob from the Git object database.
///
/// Embedding/vector state is intentionally not reconstructed yet.
pub fn build_graph_at_ref(
    graph: &InMemoryGraph,
    blob_store: &BlobStore,
    head: &SemanticChangeId,
) -> Result<InMemoryGraph> {
    build_graph_at_ref_with_repo(graph, blob_store, head, None)
}

pub fn build_graph_at_ref_with_repo(
    graph: &InMemoryGraph,
    blob_store: &BlobStore,
    head: &SemanticChangeId,
    repo_path: Option<&Path>,
) -> Result<InMemoryGraph> {
    let changes = collect_changes_at_ref(graph, head)?;
    let resolved = graph
        .resolve_graph_at(head)
        .map_err(|err| KinError::Graph(err.to_string()))?;

    let git_fallback = repo_path.and_then(|path| {
        GitBlobFallback::new(path, head, &changes).ok()
    });
    let reader = BlobReader::new(blob_store, git_fallback.as_ref());

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

    normalize_entity_file_origins_to_historical_tree(&mut snapshot, &resolved.file_tree);
    rebuild_entity_source_file_layouts(&mut snapshot, &resolved.file_tree, &reader)?;
    rebuild_non_entity_tracked_files(&mut snapshot, &resolved.file_tree, &reader)?;

    Ok(InMemoryGraph::from_snapshot(snapshot))
}

/// Reads blob content, falling back to Git objects when the blob store misses.
struct BlobReader<'a> {
    blob_store: &'a BlobStore,
    git_fallback: Option<&'a GitBlobFallback>,
}

impl<'a> BlobReader<'a> {
    fn new(blob_store: &'a BlobStore, git_fallback: Option<&'a GitBlobFallback>) -> Self {
        Self { blob_store, git_fallback }
    }

    fn read(&self, hash: &kin_blobs::Hash256, file_path: &str) -> Option<Vec<u8>> {
        match self.blob_store.read(hash) {
            Ok(content) => return Some(content),
            Err(_) => {}
        }
        if let Some(fallback) = self.git_fallback {
            match fallback.read_blob(file_path) {
                Some(content) => {
                    let actual_hash = kin_blobs::digest(&content);
                    if actual_hash == *hash {
                        if let Err(err) = self.blob_store.write(&content) {
                            tracing::debug!(
                                file = %file_path,
                                error = %err,
                                "failed to back-fill blob store from git fallback"
                            );
                        }
                        return Some(content);
                    }
                    tracing::debug!(
                        file = %file_path,
                        expected = %hash,
                        actual = %actual_hash,
                        "git blob hash mismatch, skipping fallback"
                    );
                }
                None => {}
            }
        }
        None
    }
}

/// Git repository handle for looking up blobs by file path at a historical
/// commit. Constructed once per `build_graph_at_ref` call when a repo_path is
/// available and the head change maps to an imported git commit.
struct GitBlobFallback {
    repo: gix::Repository,
    tree_id: gix::ObjectId,
}

impl GitBlobFallback {
    fn new(
        repo_path: &Path,
        head: &SemanticChangeId,
        _changes: &[SemanticChange],
    ) -> std::result::Result<Self, String> {
        let repo = gix::open(repo_path).map_err(|e| e.to_string())?;
        let git_oid = find_git_oid_for_change(&repo, head)?;
        let tree_id = {
            let commit = repo.find_commit(git_oid).map_err(|e| e.to_string())?;
            let tree = commit.tree().map_err(|e| e.to_string())?;
            tree.id
        };
        Ok(Self { tree_id, repo })
    }

    fn read_blob(&self, file_path: &str) -> Option<Vec<u8>> {
        let tree = self.repo.find_tree(self.tree_id).ok()?;
        let entry = tree.lookup_entry_by_path(file_path).ok()??;
        let object = entry.object().ok()?;
        Some(object.data.to_vec())
    }
}

/// Find the git OID that corresponds to a SemanticChangeId by walking
/// reachable commits and re-computing the deterministic change-ID mapping.
fn find_git_oid_for_change(
    repo: &gix::Repository,
    head: &SemanticChangeId,
) -> std::result::Result<gix::ObjectId, String> {
    use sha2::{Digest, Sha256};

    let tip = repo
        .head_id()
        .map_err(|e| e.to_string())?
        .detach();

    let walk = repo
        .rev_walk([tip])
        .all()
        .map_err(|e| e.to_string())?;

    for info_result in walk {
        let info = info_result.map_err(|e| e.to_string())?;
        let oid = info.id;
        let mut hasher = Sha256::new();
        hasher.update(b"kin-git-import-v1:");
        hasher.update(oid.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        let candidate = SemanticChangeId::from_hash(Hash256::from_bytes(bytes));
        if candidate == *head {
            return Ok(oid);
        }
    }

    Err(format!("no git commit found for change {head}"))
}

pub fn collect_changes_at_ref<G>(graph: &G, head: &SemanticChangeId) -> Result<Vec<SemanticChange>>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut seen = HashSet::new();
    let mut ordered = Vec::new();
    enum Frame {
        Visit(SemanticChangeId),
        Emit(SemanticChange),
    }

    let mut stack = vec![Frame::Visit(*head)];
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Visit(id) => {
                if !seen.insert(id) {
                    continue;
                }
                let change = graph
                    .get_change(&id)
                    .map_err(|err| KinError::Graph(err.to_string()))?
                    .ok_or_else(|| KinError::Graph(format!("change {} not found", id)))?;
                stack.push(Frame::Emit(change.clone()));
                for parent in change.parents.iter().rev() {
                    stack.push(Frame::Visit(*parent));
                }
            }
            Frame::Emit(change) => ordered.push(change),
        }
    }
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

fn normalize_entity_file_origins_to_historical_tree(
    snapshot: &mut GraphSnapshot,
    file_tree: &HashMap<FilePathId, Hash256>,
) {
    let mut basename_targets = HashMap::<String, Option<FilePathId>>::new();
    for file_id in file_tree.keys() {
        let Some(basename) = Path::new(&file_id.0)
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string)
        else {
            continue;
        };

        basename_targets
            .entry(basename)
            .and_modify(|entry| *entry = None)
            .or_insert_with(|| Some(file_id.clone()));
    }

    for entity in snapshot.entities.values_mut() {
        if let Some(file_origin) = entity.file_origin.as_mut() {
            normalize_historical_file_id(file_origin, file_tree, &basename_targets);
        }
        if let Some(span) = entity.span.as_mut() {
            normalize_historical_file_id(&mut span.file, file_tree, &basename_targets);
        }
    }
}

fn normalize_historical_file_id(
    file_id: &mut FilePathId,
    file_tree: &HashMap<FilePathId, Hash256>,
    basename_targets: &HashMap<String, Option<FilePathId>>,
) {
    if file_tree.contains_key(file_id) {
        return;
    }

    let Some(basename) = Path::new(&file_id.0)
        .file_name()
        .and_then(|name| name.to_str())
    else {
        return;
    };

    if let Some(Some(canonical)) = basename_targets.get(basename) {
        *file_id = canonical.clone();
    }
}

fn rebuild_non_entity_tracked_files(
    snapshot: &mut GraphSnapshot,
    file_tree: &HashMap<FilePathId, Hash256>,
    reader: &BlobReader<'_>,
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

        let content = match reader.read(hash, &file_id.0) {
            Some(content) => content,
            None => {
                tracing::warn!(file = %file_id, hash = %hash, "skipping historical tracked file with missing blob");
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
    reader: &BlobReader<'_>,
) -> Result<()> {
    let pipeline = IndexPipeline::new();
    let mut rebuilt_entities = Vec::new();
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

        let content = match reader.read(hash, &file_id.0) {
            Some(content) => content,
            None => {
                tracing::warn!(
                    file = %file_id,
                    hash = %hash,
                    "skipping historical source layout with missing blob"
                );
                continue;
            }
        };

        // Keep raw historical source text searchable for ref-scoped locate,
        // even when semantic entity replay succeeds for the file.
        snapshot
            .opaque_artifacts
            .push(build_historical_source_artifact(file_id, *hash, &content));

        let file_entities = snapshot
            .entities
            .values()
            .filter(|entity| entity.file_origin.as_ref() == Some(file_id))
            .cloned()
            .collect::<Vec<_>>();
        let indexed = if file_entities.is_empty()
            || should_probe_sparse_historical_source(&file_entities, content.len())
        {
            match pipeline.index_file_content_with_tests(
                file_id,
                &content,
                kin_blobs::Hash256::from_bytes(*hash.as_bytes()),
            ) {
                Ok(indexed) => Some(indexed),
                Err(err) => {
                    tracing::warn!(
                        file = %file_id,
                        hash = %hash,
                        error = %err,
                        "skipping historical source fallback parse that could not be indexed"
                    );
                    None
                }
            }
        } else {
            None
        };

        if let Some(indexed) = indexed.as_ref() {
            if indexed.indexed_file.entities.is_empty() {
                if !file_entities.is_empty() {
                    let contextual_entities =
                        enrich_entities_with_historical_source_context(&file_entities, &content);
                    for entity in &contextual_entities {
                        snapshot.entities.insert(entity.id, entity.clone());
                    }
                    snapshot.file_layouts.push(build_entity_file_layout(
                        file_id,
                        &contextual_entities,
                        content.len(),
                        ParseCompleteness::Partial(
                            "historical ref view layout derived from persisted entity spans and file-surface lexical context"
                                .to_string(),
                        ),
                    ));
                    continue;
                }
            }
        }

        if file_entities.is_empty() {
            let Some(indexed) = indexed else {
                continue;
            };

            if indexed.indexed_file.entities.is_empty() {
                continue;
            }

            parsed_relations.extend(indexed.indexed_file.relations.iter().cloned());
            parsed_files.push(FileParseData {
                file_path: indexed.indexed_file.file_id.0.clone(),
                entities: indexed.indexed_file.entities.clone(),
                relations: indexed.indexed_file.extracted_relations.clone(),
                imports: indexed.indexed_file.imports.clone(),
            });
            rebuilt_entities.extend(indexed.indexed_file.entities);
            parsed_layouts.push(indexed.indexed_file.file_layout);
            continue;
        }

        if let Some(indexed) = indexed {
            if let Some(enriched) =
                enrich_sparse_historical_source_file(&file_entities, indexed.indexed_file)
            {
                parsed_files.push(enriched.parse_data);
                rebuilt_entities.extend(enriched.entities);
                parsed_layouts.push(enriched.file_layout);
                continue;
            }
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

    if !rebuilt_entities.is_empty() {
        snapshot.file_layouts.extend(parsed_layouts);
        for entity in rebuilt_entities {
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

fn should_probe_sparse_historical_source(
    persisted_entities: &[kin_model::Entity],
    file_len: usize,
) -> bool {
    if persisted_entities.is_empty() {
        return true;
    }

    let bytes_per_entity = file_len / persisted_entities.len().max(1);
    bytes_per_entity >= 512
        || (persisted_entities.len() <= 4 && file_len >= 1024)
        || (persisted_entities.len() <= 16 && file_len >= 4096)
}

fn enrich_sparse_historical_source_file(
    persisted_entities: &[kin_model::Entity],
    indexed_file: kin_index::IndexedFile,
) -> Option<HistoricalSourceFileEnrichment> {
    if !should_enrich_with_parsed_semantics(persisted_entities, &indexed_file.entities) {
        return None;
    }

    let stabilized_entities = stabilize_parsed_entities(persisted_entities, indexed_file.entities);
    let merged_entities = merge_historical_file_entities(persisted_entities, stabilized_entities);
    let file_layout = build_entity_file_layout(
        &indexed_file.file_id,
        &merged_entities,
        indexed_file
            .file_layout
            .regions
            .last()
            .map_or(0, |region| match region {
                SourceRegion::EntityRef { byte_range, .. }
                | SourceRegion::Trivia { byte_range } => byte_range.end,
            }),
        ParseCompleteness::Partial(
            "historical ref view layout enriched from parsed blob and persisted entity IDs"
                .to_string(),
        ),
    );

    Some(HistoricalSourceFileEnrichment {
        entities: merged_entities.clone(),
        file_layout,
        parse_data: FileParseData {
            file_path: indexed_file.file_id.0,
            entities: merged_entities,
            relations: indexed_file.extracted_relations,
            imports: indexed_file.imports,
        },
    })
}

fn should_enrich_with_parsed_semantics(
    persisted_entities: &[kin_model::Entity],
    parsed_entities: &[kin_model::Entity],
) -> bool {
    if persisted_entities.is_empty() || parsed_entities.len() <= persisted_entities.len() {
        return false;
    }

    let persisted_keys = persisted_entities
        .iter()
        .map(entity_match_key)
        .collect::<HashSet<_>>();
    let parsed_keys = parsed_entities
        .iter()
        .map(entity_match_key)
        .collect::<HashSet<_>>();

    let shared = parsed_keys.intersection(&persisted_keys).count();
    let parsed_only = parsed_keys.difference(&persisted_keys).count();

    shared > 0 && parsed_only >= 2
}

fn stabilize_parsed_entities(
    persisted_entities: &[kin_model::Entity],
    parsed_entities: Vec<kin_model::Entity>,
) -> Vec<kin_model::Entity> {
    let mut matched_persisted = HashSet::<EntityId>::new();

    parsed_entities
        .into_iter()
        .map(|mut parsed| {
            let existing = persisted_entities
                .iter()
                .filter(|candidate| !matched_persisted.contains(&candidate.id))
                .find(|candidate| entity_match_key(candidate) == entity_match_key(&parsed))
                .or_else(|| {
                    persisted_entities
                        .iter()
                        .filter(|candidate| !matched_persisted.contains(&candidate.id))
                        .find(|candidate| {
                            candidate.name == parsed.name
                                && candidate.file_origin == parsed.file_origin
                        })
                });

            if let Some(existing) = existing {
                matched_persisted.insert(existing.id);
                parsed.id = existing.id;
                parsed.created_in = existing.created_in;
                parsed.superseded_by = existing.superseded_by;
                parsed.lineage_parent = existing.lineage_parent;
            }

            parsed
        })
        .collect()
}

fn merge_historical_file_entities(
    persisted_entities: &[kin_model::Entity],
    parsed_entities: Vec<kin_model::Entity>,
) -> Vec<kin_model::Entity> {
    let mut merged = persisted_entities.to_vec();
    let mut positions = merged
        .iter()
        .enumerate()
        .map(|(idx, entity)| (entity.id, idx))
        .collect::<HashMap<_, _>>();

    for entity in parsed_entities {
        if let Some(existing_idx) = positions.get(&entity.id).copied() {
            merged[existing_idx] = entity;
        } else {
            positions.insert(entity.id, merged.len());
            merged.push(entity);
        }
    }

    merged
}

fn entity_match_key(entity: &kin_model::Entity) -> (EntityKind, String) {
    (entity.kind, entity.name.clone())
}

struct HistoricalSourceFileEnrichment {
    entities: Vec<kin_model::Entity>,
    file_layout: FileLayout,
    parse_data: FileParseData,
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

fn build_historical_source_artifact(
    file_id: &FilePathId,
    content_hash: Hash256,
    content: &[u8],
) -> OpaqueArtifact {
    OpaqueArtifact {
        file_id: file_id.clone(),
        content_hash,
        mime_type: Some("text/x-source".to_string()),
        text_preview: historical_source_text(content),
    }
}

fn enrich_entities_with_historical_source_context(
    entities: &[kin_model::Entity],
    content: &[u8],
) -> Vec<kin_model::Entity> {
    let Some(source_text) = historical_source_text(content) else {
        return entities.to_vec();
    };

    entities
        .iter()
        .cloned()
        .map(|mut entity| {
            entity.metadata.extra.insert(
                EMBEDDING_BODY_PREVIEW_KEY.to_string(),
                serde_json::Value::String(source_text.clone()),
            );
            entity.metadata.extra.insert(
                FILE_SURFACE_CONTEXT_KEY.to_string(),
                serde_json::Value::String(source_text.clone()),
            );
            entity
        })
        .collect()
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

fn historical_source_text(content: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(content).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(trimmed.chars().take(256_000).collect())
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
    fn build_graph_at_ref_indexes_historical_source_text_for_entity_files() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x14; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let source_hash = blob_store
            .write(
                b"int main(void) {\n  // --exit-status should return a distinct parse error code\n  return 0;\n}\n",
            )
            .unwrap();
        let main_entity = test_entity("main", "src/main.c");
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x15; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add main".to_string(),
                entity_deltas: vec![EntityDelta::Added(main_entity)],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: FilePathId::new("src/main.c"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(source_hash),
                }],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &add_id).unwrap();

        assert!(historical
            .list_opaque_artifacts()
            .unwrap()
            .iter()
            .any(|artifact| artifact.file_id.0 == "src/main.c"
                && artifact
                    .text_preview
                    .as_deref()
                    .unwrap_or_default()
                    .contains("--exit-status")));
        assert!(!historical
            .text_search("--exit-status", 10)
            .unwrap()
            .is_empty());
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

    #[test]
    fn build_graph_at_ref_normalizes_dangling_file_origin_aliases() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x39; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let source_hash = blob_store
            .write(b"def processor():\n    return 'processor'\n")
            .unwrap();
        let head_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x3a; 32]));
        let mut aliased = test_entity("processor", "lib.py");
        aliased.file_origin = Some(FilePathId::new("lib.py"));
        aliased.span = Some(SourceSpan {
            file: FilePathId::new("lib.py"),
            start_byte: 0,
            end_byte: 14,
            start_line: 1,
            start_col: 1,
            end_line: 1,
            end_col: 14,
        });
        graph
            .create_change(&SemanticChange {
                id: head_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "aliased historical file".to_string(),
                entity_deltas: vec![EntityDelta::Added(aliased.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: FilePathId::new("src/lib.py"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(source_hash),
                }],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &head_id).unwrap();
        let processor = historical
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|entity| entity.id == aliased.id)
            .expect("historical entity should still exist");
        assert_eq!(
            processor.file_origin,
            Some(FilePathId::new("src/lib.py")),
            "dangling basename aliases should normalize to the tracked historical file"
        );
        assert_eq!(
            processor.span.as_ref().map(|span| span.file.clone()),
            Some(FilePathId::new("src/lib.py")),
            "span file aliases should normalize alongside file origins"
        );
    }

    #[test]
    fn build_graph_at_ref_enriches_sparse_historical_source_overlap() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x41; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let historical_source = format!(
            "{}\n\
def processor(value):\n    return value + 1\n\n\
def helper_format(value):\n    return f\"fmt:{{value}}\"\n\n\
def uri_encoder(value):\n    return value.replace(' ', '%20')\n",
            "# preserved historical context\n".repeat(64)
        );
        let historical_hash = blob_store.write(historical_source.as_bytes()).unwrap();
        let sparse_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x42; 32]));
        let processor = test_entity("processor", "src/lib.py");
        graph
            .create_change(&SemanticChange {
                id: sparse_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "sparse imported history".to_string(),
                entity_deltas: vec![EntityDelta::Added(processor.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: FilePathId::new("src/lib.py"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(historical_hash),
                }],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &sparse_id).unwrap();
        let entities = historical.list_all_entities().unwrap();
        assert!(
            entities
                .iter()
                .any(|entity| entity.id == processor.id && entity.name == "processor"),
            "overlapping persisted entities should keep their semantic IDs"
        );
        assert!(
            entities.iter().any(|entity| entity.name == "helper_format"),
            "sparse historical files should be enriched with missing parsed entities"
        );
        assert!(
            entities.iter().any(|entity| entity.name == "uri_encoder"),
            "historical enrichment should expose additional parsed entities from the blob"
        );

        assert!(
            !historical
                .text_search("helper_format", 10)
                .unwrap()
                .is_empty(),
            "enriched historical entities should be searchable"
        );

        let layout = historical
            .get_file_layout(&FilePathId::new("src/lib.py"))
            .unwrap()
            .expect("sparse historical source file should expose a rebuilt layout");
        let entity_region_count = layout
            .regions
            .iter()
            .filter(|region| matches!(region, kin_model::SourceRegion::EntityRef { .. }))
            .count();
        assert!(
            entity_region_count >= 3,
            "enriched layout should include regions for parsed entities, got {entity_region_count}"
        );
    }

    #[test]
    fn collect_changes_at_ref_handles_deep_linear_history_iteratively() {
        let graph = InMemoryGraph::new();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x61; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let mut previous = genesis_id;
        let mut head = genesis_id;
        for idx in 0..3_000u16 {
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(&(idx + 1).to_be_bytes());
            let id = SemanticChangeId::from_hash(Hash256::from_bytes(bytes));
            graph
                .create_change(&change(id, vec![previous], vec![]))
                .unwrap();
            previous = id;
            head = id;
        }

        let ordered = collect_changes_at_ref(&graph, &head).unwrap();
        assert_eq!(ordered.len(), 3_001);
        assert_eq!(ordered.first().map(|change| change.id), Some(genesis_id));
        assert_eq!(ordered.last().map(|change| change.id), Some(head));
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
