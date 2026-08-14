// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::path::Path;

use kin_db::{GraphSnapshot, InMemoryGraph, RepositoryAuthorityManager, StorageBackend};
use kin_index::{
    build_projection_derived_relations_for_file, extract_artifact,
    link_cross_file_against_entities_with_completeness, FileClassification, FileClassifier,
    FileParseCompletenessMap, FileParseData, IndexPipeline,
};
use kin_model::{
    ArtifactId, ChangeStore, EntityId, EntityKind, FileLayout, FilePathId, GraphStore, Hash256,
    ImportSection, OpaqueArtifact, ParseCompleteness, RelationKind, RepoPath, ResolvedTree,
    SemanticChange, SemanticChangeId, ShallowTrackedFile, SourceRegion, StructuredArtifact,
    TreeEntry,
};
use kin_parser::extract::{EMBEDDING_BODY_PREVIEW_KEY, FILE_SURFACE_CONTEXT_KEY};

use crate::{KinError, Result};

/// Build a read-only graph view resolved at a specific semantic ref from one
/// coherent repository-authority generation.
///
/// The returned graph contains:
/// - entities and relations replayed as of `head`
/// - only changes reachable from `head`
/// - entity-source file layouts derived from persisted historical entity spans
/// - non-entity tracked files rebuilt from historical blob content
/// - a fresh in-memory text index aligned with the historical view
///
/// Embedding/vector state is intentionally not reconstructed yet.
pub fn build_graph_at_ref<B>(
    authority: &RepositoryAuthorityManager<B>,
    head: &SemanticChangeId,
) -> Result<InMemoryGraph>
where
    B: StorageBackend + ?Sized + 'static,
{
    let lease = authority.read_authority();
    let graph = InMemoryGraph::from_snapshot(lease.snapshot().clone())
        .map_err(|error| KinError::Graph(error.to_string()))?;
    build_graph_at_ref_from_graph(&graph, authority, head)
}

fn build_graph_at_ref_from_graph<B>(
    graph: &InMemoryGraph,
    authority: &RepositoryAuthorityManager<B>,
    head: &SemanticChangeId,
) -> Result<InMemoryGraph>
where
    B: StorageBackend + ?Sized + 'static,
{
    let build_start = std::time::Instant::now();
    let timing = std::env::var("KIN_SCOPE_TIMING").is_ok();
    let build_timeout_secs = std::env::var("KIN_BUILD_GRAPH_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(60.0);

    let changes = collect_changes_at_ref(graph, head)?;
    let material_history = collect_first_parent_changes_at_ref(graph, head)?;
    let resolved = graph
        .resolve_graph_at(head)
        .map_err(|err| KinError::Graph(err.to_string()))?;
    if timing {
        eprintln!(
            "[scope-timing] after collect+resolve: {}ms",
            build_start.elapsed().as_millis()
        );
    }

    let reader = BlobReader::new(authority);
    let ref_file_tree = resolved.tree.clone();
    if timing {
        eprintln!(
            "[scope-timing] after materialize_file_tree: {}ms",
            build_start.elapsed().as_millis()
        );
    }

    let mut snapshot = GraphSnapshot::empty();
    snapshot.entities = resolved.entities;
    snapshot.relations = resolved.relations;
    snapshot.entity_revisions = resolved.entity_revisions;
    snapshot.changes = changes
        .iter()
        .map(|change| (change.id, change.clone()))
        .collect();
    snapshot.change_children = build_change_children(&changes);
    snapshot.resolved_tree = ref_file_tree.clone();
    let lifecycle = RefLifecycle::from_changes(&material_history);
    rebuild_entity_source_file_layouts(
        &mut snapshot,
        &ref_file_tree,
        &reader,
        &lifecycle,
        build_start,
        build_timeout_secs,
    )?;
    rebuild_non_entity_tracked_files(
        &mut snapshot,
        &ref_file_tree,
        &reader,
        build_start,
        build_timeout_secs,
    )?;
    filter_temporal_cochange_relations(&mut snapshot);
    if timing {
        eprintln!(
            "[scope-timing] TOTAL build_graph_at_ref: {}ms",
            build_start.elapsed().as_millis()
        );
    }

    InMemoryGraph::from_snapshot(snapshot).map_err(|error| KinError::Graph(error.to_string()))
}

/// Post-filter vector search results to retain only entities present in a
/// scoped entity set.
///
/// Vector indices are global (they index the full HEAD graph) and cannot be
/// cheaply rebuilt for each historical scope. This function compensates by
/// over-fetching from the global vector index and retaining only entity keys
/// whose entity is present in the scoped snapshot. Non-entity keys are dropped:
/// artifact/vector keys are built from HEAD content today, so keeping them for
/// a historical scope can inject evidence from files that changed after the
/// scoped ref.
///
/// # Usage
///
/// ```ignore
/// let raw = vector_index.search_similar(&embedding, limit * 3)?;
/// let scoped = filter_vector_results_to_scope(raw, &scoped_entity_ids, limit);
/// ```
pub fn filter_vector_results_to_scope(
    results: Vec<(kin_model::RetrievalKey, f32)>,
    scoped_entity_ids: &HashSet<EntityId>,
    limit: usize,
) -> Vec<(kin_model::RetrievalKey, f32)> {
    results
        .into_iter()
        .filter(|(key, _score)| {
            matches!(key, kin_model::RetrievalKey::Entity(eid) if scoped_entity_ids.contains(eid))
        })
        .take(limit)
        .collect()
}

/// Reads graph-owned blob content from Kin's content-addressed store.
///
/// Historical query paths never repair or replace graph truth from Git or the
/// working tree. A missing blob is a graph-integrity error.
struct BlobReader<'a, B: StorageBackend + ?Sized + 'static> {
    authority: &'a RepositoryAuthorityManager<B>,
}

impl<'a, B: StorageBackend + ?Sized + 'static> BlobReader<'a, B> {
    fn new(authority: &'a RepositoryAuthorityManager<B>) -> Self {
        Self { authority }
    }

    fn read(&self, hash: &Hash256, path: &RepoPath) -> Result<Vec<u8>> {
        self.authority
            .load_source_blob(*hash)
            .map_err(|error| {
                KinError::Graph(format!(
                    "repository authority could not read source blob {hash} for {path}: {error}"
                ))
            })?
            .ok_or_else(|| {
                KinError::Graph(format!(
                    "graph tree references missing source blob {hash} for {path}"
                ))
            })
    }
}

/// Snapshot of which changes and entities are alive at the target ref.
///
/// Built from the change sequence reachable from the ref's HEAD. Provides
/// defensive validation during enrichment: when matching a parsed entity to a
/// persisted ID, we require that the persisted entity's `created_in` is in
/// the reachable change set. Without this, a parsed entity could silently
/// adopt an ID that belongs to an entity created on a side branch not part of
/// the ref's history, or to an entity recreated after the ref.
struct RefLifecycle {
    reachable_changes: HashSet<SemanticChangeId>,
    removed_entities: HashSet<EntityId>,
}

impl RefLifecycle {
    fn from_changes(changes: &[SemanticChange]) -> Self {
        let mut reachable_changes = HashSet::with_capacity(changes.len());
        let mut removed_entities = HashSet::new();
        for change in changes {
            reachable_changes.insert(change.id);
            for delta in &change.entity_deltas {
                if let kin_model::EntityDelta::Removed { old } = delta {
                    removed_entities.insert(old.id);
                }
                if let kin_model::EntityDelta::Added { new: entity } = delta {
                    // An entity re-added later overrides an earlier removal in
                    // the same reachable history.
                    removed_entities.remove(&entity.id);
                }
            }
        }
        Self {
            reachable_changes,
            removed_entities,
        }
    }

    /// Returns true when the entity was alive at the ref: created within the
    /// reachable change set and not removed by any reachable change.
    ///
    /// Entities with `created_in: None` are treated as alive — these come
    /// from in-memory overlays that pre-date a commit, or from test fixtures
    /// where lifecycle anchors haven't been backfilled.
    fn is_alive_at_ref(&self, entity: &kin_model::Entity) -> bool {
        if self.removed_entities.contains(&entity.id) {
            return false;
        }
        match entity.created_in {
            None => true,
            Some(change_id) => self.reachable_changes.contains(&change_id),
        }
    }
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
        Emit(Box<SemanticChange>),
    }

    let mut stack = vec![Frame::Visit(*head)];
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Visit(id) => {
                if !seen.insert(id) {
                    continue;
                }
                match graph
                    .get_change(&id)
                    .map_err(|err| KinError::Graph(err.to_string()))?
                {
                    Some(change) => {
                        let parents = change.parents.clone();
                        stack.push(Frame::Emit(Box::new(change)));
                        for parent in parents.iter().rev() {
                            stack.push(Frame::Visit(*parent));
                        }
                    }
                    None => {
                        return Err(KinError::Graph(format!(
                            "ref history is incomplete: change {id} is missing"
                        )));
                    }
                }
            }
            Frame::Emit(change) => ordered.push(*change),
        }
    }
    Ok(ordered)
}

/// Fetch the exact material lineage for `head`.
///
/// A merge result is always relative to its first declared parent. Additional
/// parents contribute ancestry and revision lineage, but never have their
/// repository or entity state implicitly folded into the historical view.
fn collect_first_parent_changes_at_ref<G>(
    graph: &G,
    head: &SemanticChangeId,
) -> Result<Vec<SemanticChange>>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut seen = HashSet::new();
    let mut reverse_history = Vec::new();
    let mut current = Some(*head);

    while let Some(change_id) = current {
        if !seen.insert(change_id) {
            return Err(KinError::Graph(format!(
                "cycle in first-parent history at change {change_id}"
            )));
        }
        let change = graph
            .get_change(&change_id)
            .map_err(|error| KinError::Graph(error.to_string()))?
            .ok_or_else(|| {
                KinError::Graph(format!(
                    "first-parent history is incomplete: change {change_id} is missing"
                ))
            })?;
        current = change.parents.first().copied();
        reverse_history.push(change);
    }

    reverse_history.reverse();
    Ok(reverse_history)
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

fn filter_temporal_cochange_relations(snapshot: &mut GraphSnapshot) {
    let change_ids: HashSet<SemanticChangeId> = snapshot.changes.keys().copied().collect();
    let before = snapshot.relations.len();
    snapshot.relations.retain(|_id, relation| {
        if relation.kind != RelationKind::CoChanges {
            return true;
        }
        match relation.created_in {
            Some(ref change_id) => change_ids.contains(change_id),
            None => false,
        }
    });
    let removed = before - snapshot.relations.len();
    if removed > 0 {
        tracing::debug!(
            removed,
            remaining = snapshot.relations.len(),
            "filtered out-of-scope cochange relations from historical snapshot"
        );
    }
}

fn rebuild_non_entity_tracked_files<B>(
    snapshot: &mut GraphSnapshot,
    file_tree: &ResolvedTree,
    reader: &BlobReader<'_, B>,
    build_start: std::time::Instant,
    build_timeout_secs: f64,
) -> Result<()>
where
    B: StorageBackend + ?Sized + 'static,
{
    let entity_paths: HashSet<String> = snapshot
        .entities
        .values()
        .filter_map(|entity| entity.file_origin.as_ref())
        .map(|file_id| file_id.0.clone())
        .collect();

    for artifact in file_tree.artifacts_by_path() {
        if build_start.elapsed().as_secs_f64() > build_timeout_secs {
            return Err(KinError::Other(format!(
                "historical graph reconstruction exceeded its {build_timeout_secs:.1}s deadline while rebuilding non-entity entries"
            )));
        }
        let Some(path) = artifact.path.as_utf8() else {
            // The exact artifact remains present in `snapshot.resolved_tree`.
            // Semantic enrichers are UTF-8 surfaces and must not invent a
            // lossy alias for byte-exact repository paths.
            continue;
        };
        let file_id = FilePathId::new(path);
        if entity_paths.contains(path) {
            continue;
        }
        let Some(content_hash) = artifact.entry.blob_identity() else {
            // Gitlinks have repository identity and history but no blob bytes
            // owned by this repository to classify or index.
            continue;
        };

        let content = reader.read(&content_hash, &artifact.path)?;

        match FileClassifier::classify_with_content(Path::new(path), &content) {
            FileClassification::EntitySource => {}
            FileClassification::ShallowSyntax { language_hint } => {
                if let Some(shallow) =
                    kin_parser::parse_shallow_file(&content, &file_id, &language_hint)
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
                    snapshot.opaque_artifacts.push(build_opaque_artifact(
                        &file_id,
                        content_hash,
                        None,
                        &content,
                    ));
                }
            }
            FileClassification::StructuredArtifact(kind) => {
                let artifact =
                    extract_artifact(kind, &content, &file_id).unwrap_or(StructuredArtifact {
                        file_id: file_id.clone(),
                        kind,
                        content_hash,
                        text_preview: preview_text(&content),
                    });
                snapshot.structured_artifacts.push(artifact);
            }
            FileClassification::OpaqueArtifact { mime_hint } => {
                snapshot.opaque_artifacts.push(build_opaque_artifact(
                    &file_id,
                    content_hash,
                    mime_hint,
                    &content,
                ));
            }
        }
    }

    Ok(())
}

fn rebuild_entity_source_file_layouts<B>(
    snapshot: &mut GraphSnapshot,
    file_tree: &ResolvedTree,
    reader: &BlobReader<'_, B>,
    lifecycle: &RefLifecycle,
    build_start: std::time::Instant,
    build_timeout_secs: f64,
) -> Result<()>
where
    B: StorageBackend + ?Sized + 'static,
{
    let pipeline = IndexPipeline::new();
    let mut rebuilt_entities = Vec::new();
    let mut parsed_relations = Vec::new();
    let mut parsed_files = Vec::new();
    let mut parsed_layouts = Vec::new();
    let mut projection_relations = Vec::new();
    let known_files: HashSet<String> = file_tree
        .artifacts_by_path()
        .filter_map(|artifact| artifact.path.as_utf8().map(ToOwned::to_owned))
        .collect();

    for artifact in file_tree.artifacts_by_path() {
        if build_start.elapsed().as_secs_f64() > build_timeout_secs {
            return Err(KinError::Other(format!(
                "historical graph reconstruction exceeded its {build_timeout_secs:.1}s deadline while rebuilding entity-source entries"
            )));
        }
        let Some(path) = artifact.path.as_utf8() else {
            continue;
        };
        let TreeEntry::Blob { hash, .. } = artifact.entry else {
            // Symlinks and gitlinks retain exact repository history but are
            // never parsed as source owned by the link path.
            continue;
        };
        let file_id = FilePathId::new(path);
        let content = reader.read(&hash, &artifact.path)?;
        if !matches!(
            FileClassifier::classify_with_content(Path::new(path), &content),
            FileClassification::EntitySource
        ) {
            continue;
        }

        // Keep raw historical source text searchable for ref-scoped locate,
        // even when semantic entity replay succeeds for the file.
        snapshot
            .opaque_artifacts
            .push(build_historical_source_artifact(&file_id, hash, &content));
        projection_relations.extend(build_projection_derived_relations_for_file(
            path,
            &content,
            &known_files,
            |path| snapshot_artifact_id_for_utf8_path(snapshot, path),
        ));

        let mut file_entities = snapshot
            .entities
            .values()
            .filter(|entity| entity.file_origin.as_ref() == Some(&file_id))
            .cloned()
            .collect::<Vec<_>>();
        // Sort for deterministic reparse-to-persisted entity binding.
        file_entities.sort_by(ref_entity_order);
        let indexed = if file_entities.is_empty()
            || should_probe_sparse_historical_source(&file_entities, content.len())
        {
            match pipeline.index_file_content_with_tests(
                &file_id,
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

        if indexed
            .as_ref()
            .is_some_and(|indexed| indexed.indexed_file.entities.is_empty())
            && !file_entities.is_empty()
        {
            let contextual_entities =
                enrich_entities_with_historical_source_context(&file_entities, &content);
            for entity in &contextual_entities {
                snapshot.entities.insert(entity.id, entity.clone());
            }
            snapshot.file_layouts.push(build_entity_file_layout(
                &file_id,
                &contextual_entities,
                content.len(),
                ParseCompleteness::Partial(
                    "historical ref view layout derived from persisted entity spans and file-surface lexical context"
                        .to_string(),
                ),
            ));
            continue;
        }

        if file_entities.is_empty() {
            let Some(indexed) = indexed else {
                continue;
            };

            if indexed.indexed_file.entities.is_empty() {
                snapshot.file_layouts.push(indexed.indexed_file.file_layout);
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
            if let Some(enriched) = enrich_sparse_historical_source_file(
                &file_entities,
                indexed.indexed_file,
                lifecycle,
            ) {
                parsed_files.push(enriched.parse_data);
                rebuilt_entities.extend(enriched.entities);
                parsed_layouts.push(enriched.file_layout);
                continue;
            }
        }

        snapshot.file_layouts.push(build_entity_file_layout(
            &file_id,
            &file_entities,
            content.len(),
            ParseCompleteness::Partial(
                "historical ref view layout derived from persisted entity spans".to_string(),
            ),
        ));
    }

    snapshot.file_layouts.extend(parsed_layouts);
    if !rebuilt_entities.is_empty() {
        for entity in rebuilt_entities {
            snapshot.entities.insert(entity.id, entity);
        }
    }

    let mut parse_completeness = FileParseCompletenessMap::new();
    let mut linked_file_paths = parsed_files
        .iter()
        .map(|file| file.file_path.clone())
        .collect::<HashSet<_>>();
    for layout in &snapshot.file_layouts {
        parse_completeness.insert(layout.file_id.0.clone(), layout.parse_completeness.clone());
        if known_files.contains(&layout.file_id.0)
            && linked_file_paths.insert(layout.file_id.0.clone())
        {
            parsed_files.push(FileParseData {
                file_path: layout.file_id.0.clone(),
                entities: Vec::new(),
                relations: Vec::new(),
                imports: Vec::new(),
            });
        }
    }

    if !parsed_files.is_empty() {
        let artifact_ids = snapshot
            .resolved_tree
            .artifacts_by_path()
            .filter_map(|artifact| {
                artifact
                    .path
                    .as_utf8()
                    .map(|path| (path.to_string(), artifact.artifact_id))
            })
            .collect::<HashMap<_, _>>();
        // Persisted entity origins that do not name an exact active artifact
        // remain visible as recorded, but cannot participate in artifact
        // linking. Never guess a suffix/basename match or allocate identity
        // merely to make a dangling historical origin linkable.
        let universe_entities = snapshot
            .entities
            .values()
            .filter(|entity| {
                entity
                    .file_origin
                    .as_ref()
                    .is_none_or(|file| artifact_ids.contains_key(&file.0))
            })
            .cloned()
            .collect::<Vec<_>>();
        parsed_relations.extend(
            link_cross_file_against_entities_with_completeness(
                &parsed_files,
                &universe_entities,
                &artifact_ids,
                &parse_completeness,
            )
            .map_err(|error| KinError::Other(format!("cross-file linking failed: {error}")))?,
        );
    }

    parsed_relations.extend(projection_relations);
    for relation in parsed_relations {
        snapshot.relations.insert(relation.id, relation);
    }

    Ok(())
}

fn snapshot_artifact_id_for_utf8_path(snapshot: &GraphSnapshot, path: &str) -> Option<ArtifactId> {
    let path = RepoPath::from_utf8(path).ok()?;
    snapshot.resolved_tree.artifact_id_at_path(&path)
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
    lifecycle: &RefLifecycle,
) -> Option<HistoricalSourceFileEnrichment> {
    if !should_enrich_with_parsed_semantics(persisted_entities, &indexed_file.entities) {
        return None;
    }

    // Gap 2: refuse to bind parsed entities to persisted IDs that were not
    // alive at the ref. When any persisted candidate fails the lifecycle
    // check, reparse the file fresh — keep newly minted IDs from the parser
    // rather than reusing potentially-recycled persisted IDs. This is the
    // safer semantic: a fresh-ID entity may miss continuity with HEAD, but
    // it never binds entity spans to the wrong historical identity.
    let any_stale = persisted_entities
        .iter()
        .any(|entity| !lifecycle.is_alive_at_ref(entity));
    if any_stale {
        let parse_completeness = ParseCompleteness::Partial(
            "historical ref view layout reparsed without binding because persisted entities were not alive at ref"
                .to_string(),
        );
        let file_layout = build_entity_file_layout(
            &indexed_file.file_id,
            &indexed_file.entities,
            indexed_file
                .file_layout
                .regions
                .last()
                .map_or(0, |region| match region {
                    SourceRegion::EntityRef { byte_range, .. }
                    | SourceRegion::Trivia { byte_range } => byte_range.end,
                }),
            parse_completeness.clone(),
        );
        return Some(HistoricalSourceFileEnrichment {
            entities: indexed_file.entities.clone(),
            file_layout,
            parse_data: FileParseData {
                file_path: indexed_file.file_id.0,
                entities: indexed_file.entities,
                relations: indexed_file.extracted_relations,
                imports: indexed_file.imports,
            },
        });
    }

    let stabilized_entities =
        stabilize_parsed_entities(persisted_entities, indexed_file.entities, lifecycle);
    let merged_entities = merge_historical_file_entities(persisted_entities, stabilized_entities);
    let parse_completeness = ParseCompleteness::Partial(
        "historical ref view layout enriched from parsed blob and persisted entity IDs".to_string(),
    );
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
        parse_completeness.clone(),
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
    lifecycle: &RefLifecycle,
) -> Vec<kin_model::Entity> {
    let mut matched_persisted = HashSet::<EntityId>::new();

    parsed_entities
        .into_iter()
        .map(|mut parsed| {
            // Gap 1: only match against persisted entities that were alive at
            // the ref. An entity created on an unreachable branch, or removed
            // before the ref, must not contribute its ID to a reparsed entity.
            let existing = persisted_entities
                .iter()
                .filter(|candidate| !matched_persisted.contains(&candidate.id))
                .filter(|candidate| lifecycle.is_alive_at_ref(candidate))
                .find(|candidate| entity_match_key(candidate) == entity_match_key(&parsed))
                .or_else(|| {
                    persisted_entities
                        .iter()
                        .filter(|candidate| !matched_persisted.contains(&candidate.id))
                        .filter(|candidate| lifecycle.is_alive_at_ref(candidate))
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

/// Total order over a file's entities for deterministic reparse binding.
fn ref_entity_order(a: &kin_model::Entity, b: &kin_model::Entity) -> std::cmp::Ordering {
    let line_a = a.span.as_ref().map(|s| s.start_line).unwrap_or(u32::MAX);
    let line_b = b.span.as_ref().map(|s| s.start_line).unwrap_or(u32::MAX);
    let col_a = a.span.as_ref().map(|s| s.start_col).unwrap_or(u32::MAX);
    let col_b = b.span.as_ref().map(|s| s.start_col).unwrap_or(u32::MAX);
    line_a
        .cmp(&line_b)
        .then_with(|| col_a.cmp(&col_b))
        .then_with(|| a.name.cmp(&b.name))
        .then_with(|| a.id.0.cmp(&b.id.0))
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
    kin_index::artifacts::opaque_text_preview(content, mime_hint)
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

    use std::sync::Arc;

    use kin_db::LocalFileBackend;
    use kin_model::{
        ArtifactId, AuthorId, Entity, EntityDelta, EntityKind, EntityRole, EntityStore,
        FingerprintAlgorithm, GitObjectId, LanguageId, LocatedEntry, RepositoryId, SemanticChange,
        SemanticFingerprint, SourceSpan, Timestamp, TreeDelta, Visibility,
    };

    fn test_authority(root: &Path) -> RepositoryAuthorityManager<LocalFileBackend> {
        let kindb = root.join("kindb");
        std::fs::create_dir(&kindb).unwrap();
        RepositoryAuthorityManager::open(
            RepositoryId::new("ref-view-test").unwrap(),
            Arc::new(LocalFileBackend::new(kindb)),
        )
        .unwrap()
    }

    fn save_source_blob(
        authority: &RepositoryAuthorityManager<LocalFileBackend>,
        data: &[u8],
    ) -> Hash256 {
        let digest = kin_blobs::digest(data);
        authority.save_source_blob(digest, data).unwrap();
        digest
    }

    #[test]
    fn public_ref_view_reads_the_manager_owned_generation() {
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());
        let absent = SemanticChangeId::from_hash(Hash256::from_bytes([0xa5; 32]));

        assert!(build_graph_at_ref(&authority, &absent).is_err());
    }

    fn create_fixture_change(
        graph: &InMemoryGraph,
        parents: Vec<SemanticChangeId>,
        message: impl Into<String>,
        entity_deltas: Vec<EntityDelta>,
        tree_deltas: Vec<TreeDelta>,
    ) -> SemanticChangeId {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: message.into(),
            entity_deltas,
            relation_deltas: vec![],
            tree_deltas,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };
        change.id = crate::compute_semantic_change_id(&change).unwrap();
        let id = change.id;
        graph.create_change(&change).unwrap();
        id
    }

    fn artifact_id(value: u128) -> ArtifactId {
        ArtifactId(uuid::Uuid::from_u128(value))
    }

    fn located(path: &str, hash: Hash256) -> LocatedEntry {
        LocatedEntry::new(
            RepoPath::from_utf8(path).unwrap(),
            TreeEntry::blob(hash, false),
        )
    }

    fn added(artifact: u128, path: &str, hash: Hash256) -> TreeDelta {
        TreeDelta::Added {
            artifact_id: artifact_id(artifact),
            new: located(path, hash),
        }
    }

    fn modified(artifact: u128, path: &str, old_hash: Hash256, new_hash: Hash256) -> TreeDelta {
        TreeDelta::Updated {
            artifact_id: artifact_id(artifact),
            old: located(path, old_hash),
            new: located(path, new_hash),
        }
    }

    #[test]
    fn build_graph_at_ref_reconstructs_historical_tracked_files() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());

        let genesis_id = create_fixture_change(&graph, vec![], "genesis", vec![], vec![]);

        let readme_v1 = save_source_blob(&authority, b"Authentication guide for v1");
        let cargo_v1 = save_source_blob(&authority, b"[package]\nname = \"kin\"\n");
        let add_id = create_fixture_change(
            &graph,
            vec![genesis_id],
            "add historical tracked files",
            vec![],
            vec![
                added(0x101, "README.md", readme_v1),
                added(0x102, "Cargo.toml", cargo_v1),
            ],
        );

        let readme_v2 = save_source_blob(&authority, b"Deployment guide for v2");
        let _head_id = create_fixture_change(
            &graph,
            vec![add_id],
            "update readme",
            vec![],
            vec![modified(0x101, "README.md", readme_v1, readme_v2)],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &add_id).unwrap();

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

    /// A historical docs artifact keeps its deep text, not a head-sized
    /// preview: FIR-2183's mechanism was that only the head of a document ever
    /// reached the text index, so any phrase past it was unfindable.
    #[test]
    fn build_graph_at_ref_keeps_deep_opaque_text() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());

        let genesis_id = create_fixture_change(&graph, vec![], "genesis", vec![], vec![]);

        let mut body = String::from("# Notes\n\n");
        for index in 0..40 {
            body.push_str(&format!(
                "Routine paragraph {index} about ordinary upkeep of the greenhouse ledger, \
                 nothing remarkable here.\n\n"
            ));
        }
        body.push_str("The quokka semaphore doctrine sits far past any head-sized preview.\n");
        assert!(body.find("quokka").unwrap() > 2_000);

        let notes_hash = save_source_blob(&authority, body.as_bytes());
        let add_id = create_fixture_change(
            &graph,
            vec![genesis_id],
            "add deep notes",
            vec![],
            vec![added(0x104, "NOTES.md", notes_hash)],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &add_id).unwrap();

        assert!(historical
            .list_opaque_artifacts()
            .unwrap()
            .iter()
            .any(|artifact| artifact.file_id.0 == "NOTES.md"
                && artifact
                    .text_preview
                    .as_deref()
                    .unwrap_or_default()
                    .contains("quokka semaphore doctrine")));
        assert!(!historical.text_search("quokka", 10).unwrap().is_empty());
    }

    #[test]
    fn build_graph_at_ref_indexes_historical_source_text_for_entity_files() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());

        let genesis_id = create_fixture_change(&graph, vec![], "genesis", vec![], vec![]);

        let source_hash = save_source_blob(
            &authority,
            b"int main(void) {\n  // --exit-status should return a distinct parse error code\n  return 0;\n}\n",
        );
        let main_entity = test_entity("main", "src/main.c");
        let add_id = create_fixture_change(
            &graph,
            vec![genesis_id],
            "add main",
            vec![EntityDelta::Added { new: main_entity }],
            vec![added(0x103, "src/main.c", source_hash)],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &add_id).unwrap();

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
        let authority = test_authority(temp.path());

        let genesis_id = create_fixture_change(&graph, vec![], "genesis", vec![], vec![]);

        let current_hash =
            save_source_blob(&authority, b"def processor():\n    return 'processor'\n");
        let processor = test_entity("processor", "src/lib.py");
        let auto_parse_id = create_fixture_change(
            &graph,
            vec![genesis_id],
            "auto-parse",
            vec![EntityDelta::Added {
                new: processor.clone(),
            }],
            vec![added(0x104, "src/lib.py", current_hash)],
        );

        let historical_hash =
            save_source_blob(&authority, b"def handler():\n    return 'handler'\n");
        let historical_id = create_fixture_change(
            &graph,
            vec![auto_parse_id],
            "replace historical source",
            vec![],
            vec![modified(0x104, "src/lib.py", current_hash, historical_hash)],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &historical_id).unwrap();
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
        let authority = test_authority(temp.path());

        let genesis_id = create_fixture_change(&graph, vec![], "genesis", vec![], vec![]);

        let historical_hash =
            save_source_blob(&authority, b"def handler():\n    return 'handler'\n");
        let historical_id = create_fixture_change(
            &graph,
            vec![genesis_id],
            "add artifact-only history",
            vec![],
            vec![added(0x105, "src/lib.py", historical_hash)],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &historical_id).unwrap();
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
    fn build_graph_at_ref_never_rewrites_dangling_file_origin_aliases() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());

        let genesis_id = create_fixture_change(&graph, vec![], "genesis", vec![], vec![]);

        let source_hash =
            save_source_blob(&authority, b"def processor():\n    return 'processor'\n");
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
        let head_id = create_fixture_change(
            &graph,
            vec![genesis_id],
            "aliased historical file",
            vec![EntityDelta::Added {
                new: aliased.clone(),
            }],
            vec![added(0x106, "src/lib.py", source_hash)],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &head_id).unwrap();
        let processor = historical
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|entity| entity.id == aliased.id)
            .expect("historical entity should still exist");
        assert_eq!(
            processor.file_origin,
            Some(FilePathId::new("lib.py")),
            "historical reads must not seed identity by guessing a tracked path"
        );
        assert_eq!(
            processor.span.as_ref().map(|span| span.file.clone()),
            Some(FilePathId::new("lib.py")),
            "historical reads must preserve persisted span authority"
        );
    }

    #[test]
    fn build_graph_at_ref_never_rewrites_suffix_path_aliases() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());

        let genesis_id = create_fixture_change(&graph, vec![], "genesis", vec![], vec![]);

        let source_hash =
            save_source_blob(&authority, b"def processor():\n    return 'processor'\n");
        let mut aliased = test_entity("processor", "src/lib.py");
        aliased.file_origin = Some(FilePathId::new("src/lib.py"));
        aliased.span = Some(SourceSpan {
            file: FilePathId::new("src/lib.py"),
            start_byte: 0,
            end_byte: 14,
            start_line: 1,
            start_col: 1,
            end_line: 1,
            end_col: 14,
        });
        let head_id = create_fixture_change(
            &graph,
            vec![genesis_id],
            "suffix-aliased historical file",
            vec![EntityDelta::Added {
                new: aliased.clone(),
            }],
            vec![added(0x107, "project/src/lib.py", source_hash)],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &head_id).unwrap();
        let processor = historical
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|entity| entity.id == aliased.id)
            .expect("historical entity should still exist");
        assert_eq!(
            processor.file_origin,
            Some(FilePathId::new("src/lib.py")),
            "suffix similarity is not artifact identity"
        );
    }

    #[test]
    fn build_graph_at_ref_enriches_sparse_historical_source_overlap() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());

        let genesis_id = create_fixture_change(&graph, vec![], "genesis", vec![], vec![]);

        let historical_source = format!(
            "{}\n\
def processor(value):\n    return value + 1\n\n\
def helper_format(value):\n    return f\"fmt:{{value}}\"\n\n\
def uri_encoder(value):\n    return value.replace(' ', '%20')\n",
            "# preserved historical context\n".repeat(64)
        );
        let historical_hash = save_source_blob(&authority, historical_source.as_bytes());
        let processor = test_entity("processor", "src/lib.py");
        let sparse_id = create_fixture_change(
            &graph,
            vec![genesis_id],
            "sparse imported history",
            vec![EntityDelta::Added {
                new: processor.clone(),
            }],
            vec![added(0x108, "src/lib.py", historical_hash)],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &sparse_id).unwrap();
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
        assert!(matches!(
            layout.parse_completeness,
            ParseCompleteness::Partial(_)
        ));
        let artifact_id = historical
            .artifact_id_at_path(&RepoPath::from_utf8("src/lib.py").unwrap())
            .expect("historical source artifact id");
        let coverage = historical
            .traverse(
                &kin_model::GraphNodeId::Artifact(artifact_id),
                &[RelationKind::DependsOn],
                1,
            )
            .unwrap();
        assert!(coverage.relations.iter().any(|relation| {
            relation.evidence.iter().any(|evidence| {
                evidence.parser_rule.as_deref()
                    == Some(kin_index::CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1)
                    && evidence.source_path.as_deref() == Some("src/lib.py")
            })
        }));
    }

    #[test]
    fn collect_changes_at_ref_handles_deep_linear_history_iteratively() {
        let graph = InMemoryGraph::new();
        let genesis_id = create_fixture_change(&graph, vec![], "genesis", vec![], vec![]);

        let mut previous = genesis_id;
        let mut head = genesis_id;
        for idx in 0..3_000u16 {
            let id = create_fixture_change(
                &graph,
                vec![previous],
                format!("deep history {idx}"),
                vec![],
                vec![],
            );
            previous = id;
            head = id;
        }

        let ordered = collect_changes_at_ref(&graph, &head).unwrap();
        assert_eq!(ordered.len(), 3_001);
        assert_eq!(ordered.first().map(|change| change.id), Some(genesis_id));
        assert_eq!(ordered.last().map(|change| change.id), Some(head));
    }

    #[test]
    fn collect_changes_at_ref_rejects_an_incomplete_history() {
        let graph = InMemoryGraph::new();
        let missing_ancestor = SemanticChangeId::from_hash(Hash256::from_bytes([0x77; 32]));

        // `missing_ancestor` is deliberately never inserted, so `boundary`'s
        // parent edge dangles exactly as a pre-fix truncated import would leave it.
        let boundary = create_fixture_change(
            &graph,
            vec![missing_ancestor],
            "truncated history boundary",
            vec![],
            vec![],
        );
        let head = create_fixture_change(
            &graph,
            vec![boundary],
            "head above truncated history",
            vec![],
            vec![],
        );

        let error = collect_changes_at_ref(&graph, &head).unwrap_err();
        assert!(
            error.to_string().contains(&missing_ancestor.to_string()),
            "the exact missing change must be reported: {error}"
        );
        assert!(collect_first_parent_changes_at_ref(&graph, &head).is_err());
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
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
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

    #[test]
    fn historical_reads_do_not_reclassify_persisted_entity_roles() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());
        let source_hash = save_source_blob(&authority, b"int addReporter(void);");
        let mut amalgamated = test_entity("addReporter", "single_include/catch.hpp");
        amalgamated.role = EntityRole::Source;
        let amalgamated_id = amalgamated.id;

        let change_id = create_fixture_change(
            &graph,
            vec![],
            "persist exact role",
            vec![EntityDelta::Added { new: amalgamated }],
            vec![added(0x109, "single_include/catch.hpp", source_hash)],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &change_id).unwrap();
        let entity = historical.get_entity(&amalgamated_id).unwrap().unwrap();
        assert_eq!(
            EntityRole::Source,
            entity.role,
            "classification changes belong in explicit enrichment writes, not ref reads"
        );
    }

    #[test]
    fn filter_vector_results_to_scope_retains_only_in_scope_entities() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let e3 = EntityId::new();
        let artifact_key = kin_model::RetrievalKey::Artifact(kin_model::ArtifactId::new());

        let mut scoped = HashSet::new();
        scoped.insert(e1);
        // e2 is NOT in scope

        let results = vec![
            (kin_model::RetrievalKey::Entity(e1), 0.9),
            (kin_model::RetrievalKey::Entity(e2), 0.8),
            (kin_model::RetrievalKey::Entity(e3), 0.7),
            (artifact_key, 0.6),
        ];

        let filtered = filter_vector_results_to_scope(results, &scoped, 10);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0, kin_model::RetrievalKey::Entity(e1));
    }

    #[test]
    fn filter_vector_results_to_scope_respects_limit() {
        let mut scoped = HashSet::new();
        let mut results = Vec::new();
        for i in 0..10 {
            let eid = EntityId::new();
            scoped.insert(eid);
            results.push((kin_model::RetrievalKey::Entity(eid), 1.0 - i as f32 * 0.1));
        }

        let filtered = filter_vector_results_to_scope(results, &scoped, 3);
        assert_eq!(filtered.len(), 3);
    }

    /// Gap 1: a persisted entity whose `created_in` falls outside the ref's
    /// reachable change set must not contribute its ID to a reparsed entity.
    #[test]
    fn stabilize_parsed_entities_skips_persisted_outside_ref_history() {
        let reachable_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xa1; 32]));
        let unreachable_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xa2; 32]));
        let lifecycle = RefLifecycle {
            reachable_changes: [reachable_id].into_iter().collect(),
            removed_entities: HashSet::new(),
        };

        let mut alive = test_entity("processor", "src/lib.py");
        alive.created_in = Some(reachable_id);
        let alive_id = alive.id;

        let mut stale = test_entity("processor", "src/lib.py");
        stale.created_in = Some(unreachable_id);

        let mut parsed = test_entity("processor", "src/lib.py");
        let original_parsed_id = parsed.id;
        // Use a stable parsed id so we can assert which persisted ID won.
        parsed.id = EntityId::new();
        let parsed_distinct_id = parsed.id;

        // Persisted list deliberately has the stale match first; lifecycle
        // filter must prefer the reachable match instead of taking the first.
        let stabilized = stabilize_parsed_entities(
            &[stale.clone(), alive.clone()],
            vec![parsed.clone()],
            &lifecycle,
        );
        assert_eq!(stabilized.len(), 1);
        assert_eq!(
            stabilized[0].id, alive_id,
            "should adopt the ref-alive persisted ID, not the stale one"
        );
        assert_ne!(stabilized[0].id, parsed_distinct_id);
        let _ = original_parsed_id;

        // Now omit the alive candidate — only the stale candidate is present.
        // The parsed entity should keep its own new ID instead of binding to
        // the stale persisted ID.
        let stabilized_no_alive =
            stabilize_parsed_entities(&[stale], vec![parsed.clone()], &lifecycle);
        assert_eq!(stabilized_no_alive.len(), 1);
        assert_eq!(
            stabilized_no_alive[0].id, parsed_distinct_id,
            "no alive persisted candidate should mean the parsed ID stays untouched"
        );
    }

    /// Gap 1: removed entities reachable from the ref must also be excluded
    /// even if their `created_in` is reachable — supersession bookkeeping.
    #[test]
    fn ref_lifecycle_excludes_removed_entities_within_reach() {
        let create_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xb1; 32]));
        let remove_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xb2; 32]));
        let mut victim = test_entity("legacy", "src/lib.py");
        victim.created_in = Some(create_id);
        let create_change = SemanticChange {
            id: create_id,
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "create".into(),
            entity_deltas: vec![EntityDelta::Added {
                new: victim.clone(),
            }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };
        let remove_change = SemanticChange {
            id: remove_id,
            parents: vec![create_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "remove".into(),
            entity_deltas: vec![EntityDelta::Removed {
                old: victim.clone(),
            }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let lifecycle = RefLifecycle::from_changes(&[create_change, remove_change]);
        assert!(!lifecycle.is_alive_at_ref(&victim));
    }

    /// Gap 2: if any persisted entity in a sparse historical source file is
    /// not alive at the ref, enrichment reparses fresh without binding —
    /// preserving parser-issued IDs rather than reusing potentially recycled
    /// persisted IDs.
    #[test]
    fn build_graph_at_ref_reparses_fresh_when_persisted_entity_deleted_at_ref() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());

        let genesis_id = create_fixture_change(&graph, vec![], "genesis", vec![], vec![]);

        // Stage 1: create `victim` and add a sparse source file.
        let stale_source = format!(
            "{}\n\
def victim():\n    return 1\n\n\
def helper_format(value):\n    return value\n\n\
def uri_encoder(value):\n    return value\n",
            "# preserved historical context\n".repeat(64)
        );
        let stale_hash = save_source_blob(&authority, stale_source.as_bytes());
        let mut victim = test_entity("victim", "src/lib.py");
        // `created_in` participates in change identity, so use a real reachable
        // ancestor rather than manufacturing a self-referential change ID.
        victim.created_in = Some(genesis_id);
        let create_id = create_fixture_change(
            &graph,
            vec![genesis_id],
            "create victim",
            vec![EntityDelta::Added {
                new: victim.clone(),
            }],
            vec![added(0x10a, "src/lib.py", stale_hash)],
        );

        // Stage 2: remove `victim` AND modify the source. This is the ref
        // we'll reconstruct: the source file no longer contains `victim`,
        // but the persisted historical entity record for `victim` (lineage)
        // would still be reachable if we didn't filter by lifecycle.
        let new_source = format!(
            "{}\n\
def helper_format(value):\n    return value\n\n\
def uri_encoder(value):\n    return value\n",
            "# preserved historical context\n".repeat(64)
        );
        let new_hash = save_source_blob(&authority, new_source.as_bytes());
        let ref_id = create_fixture_change(
            &graph,
            vec![create_id],
            "remove victim, update source",
            vec![EntityDelta::Removed {
                old: victim.clone(),
            }],
            vec![modified(0x10a, "src/lib.py", stale_hash, new_hash)],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &ref_id).unwrap();
        let entities = historical.list_all_entities().unwrap();
        assert!(
            entities.iter().all(|entity| entity.id != victim.id),
            "deleted entity must not appear in ref-reconstructed graph"
        );
        // Note: the new source doesn't contain `victim`, so it should not
        // exist by name either.
        assert!(
            entities.iter().all(|entity| entity.name != "victim"),
            "deleted entity name must not be revived by reparse"
        );
    }

    /// A basename collision must never trigger suffix/basename routing. An
    /// already-exact persisted entity origin remains unchanged.
    #[test]
    fn build_graph_at_ref_never_routes_basename_collisions_by_path_similarity() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());

        let genesis_id = create_fixture_change(&graph, vec![], "genesis", vec![], vec![]);

        let mod_a = save_source_blob(&authority, b"def alpha():\n    return 'a'\n");
        let mod_b = save_source_blob(&authority, b"def beta():\n    return 'b'\n");

        let mut entity_a = test_entity("alpha", "crates/a/src/mod.rs");
        entity_a.file_origin = Some(FilePathId::new("crates/a/src/mod.rs"));
        entity_a.span = Some(SourceSpan {
            file: FilePathId::new("crates/a/src/mod.rs"),
            start_byte: 0,
            end_byte: 14,
            start_line: 1,
            start_col: 1,
            end_line: 1,
            end_col: 14,
        });

        let head_id = create_fixture_change(
            &graph,
            vec![genesis_id],
            "collision",
            vec![EntityDelta::Added {
                new: entity_a.clone(),
            }],
            vec![
                added(0x10b, "crates/a/src/mod.rs", mod_a),
                added(0x10c, "crates/b/src/mod.rs", mod_b),
            ],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &head_id).unwrap();
        let alpha = historical
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|entity| entity.id == entity_a.id)
            .expect("alpha entity should exist in ref view");
        assert_eq!(
            alpha.file_origin,
            Some(FilePathId::new("crates/a/src/mod.rs")),
            "entity already pointed at a/src/mod.rs and must not be rerouted to b/src/mod.rs"
        );
    }

    #[test]
    fn historical_rename_keeps_artifact_identity_without_path_guessing() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());
        let resolver_blob = save_source_blob(&authority, b"exact bytes");
        let stable_id = ArtifactId(uuid::Uuid::from_u128(0xe1));
        let old = located("old/path/file.rs", resolver_blob);
        let new = located("new/path/file.rs", resolver_blob);

        let create_id = create_fixture_change(
            &graph,
            vec![],
            "create exact artifact",
            vec![],
            vec![TreeDelta::Added {
                artifact_id: stable_id,
                new: old.clone(),
            }],
        );
        let rename_id = create_fixture_change(
            &graph,
            vec![create_id],
            "rename exact artifact",
            vec![],
            vec![TreeDelta::Updated {
                artifact_id: stable_id,
                old,
                new: new.clone(),
            }],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &rename_id).unwrap();
        assert_eq!(historical.artifact_id_at_path(&new.path), Some(stable_id));
        assert_eq!(
            historical.artifact_id_at_path(&RepoPath::from_utf8("old/path/file.rs").unwrap()),
            None
        );
        let revision = graph
            .resolve_artifact_revision_at(&stable_id, &rename_id)
            .unwrap()
            .unwrap();
        assert_eq!(revision.artifact_id, stable_id);
        assert_eq!(revision.path, new.path);
    }

    #[test]
    fn blob_reader_fails_loud_when_graph_blob_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());
        let reader = BlobReader::new(&authority);
        let missing = kin_blobs::Hash256::from_bytes([0xfe; 32]);
        let path = RepoPath::from_utf8("any/path").unwrap();
        let error = reader.read(&missing, &path).unwrap_err().to_string();
        assert!(
            error.contains("graph tree references missing source blob")
                && error.contains("any/path"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn historical_view_preserves_non_utf8_paths_and_gitlinks_exactly() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());
        let blob_hash = save_source_blob(&authority, b"opaque bytes");
        let byte_path = RepoPath::from_bytes(b"assets/icon-\xff.bin".to_vec()).unwrap();
        let gitlink_path = RepoPath::from_utf8("vendor/runtime").unwrap();
        let blob_id = ArtifactId(uuid::Uuid::from_u128(0x91));
        let gitlink_id = ArtifactId(uuid::Uuid::from_u128(0x92));
        let git_target = GitObjectId::sha1([0x93; 20]);

        let head = create_fixture_change(
            &graph,
            vec![],
            "add byte path and gitlink",
            vec![],
            vec![
                TreeDelta::Added {
                    artifact_id: blob_id,
                    new: LocatedEntry::new(byte_path.clone(), TreeEntry::blob(blob_hash, false)),
                },
                TreeDelta::Added {
                    artifact_id: gitlink_id,
                    new: LocatedEntry::new(gitlink_path.clone(), TreeEntry::gitlink(git_target)),
                },
            ],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &head).unwrap();
        let byte_artifact = historical.resolved_artifact(&blob_id).unwrap();
        assert_eq!(byte_artifact.path, byte_path);
        assert_eq!(byte_artifact.entry, TreeEntry::blob(blob_hash, false));
        let gitlink = historical.resolved_artifact(&gitlink_id).unwrap();
        assert_eq!(gitlink.path, gitlink_path);
        assert_eq!(gitlink.entry, TreeEntry::gitlink(git_target));
        assert!(
            historical.list_opaque_artifacts().unwrap().is_empty(),
            "UTF-8-only enrichment must not invent a lossy path or gitlink blob"
        );
    }

    #[test]
    fn historical_path_reuse_keeps_replacement_identity_distinct() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());
        let old_hash = save_source_blob(&authority, b"old");
        let new_hash = save_source_blob(&authority, b"new");
        let old_id = ArtifactId(uuid::Uuid::from_u128(0xa1));
        let new_id = ArtifactId(uuid::Uuid::from_u128(0xa2));
        let path = RepoPath::from_utf8("config/runtime.bin").unwrap();
        let old = LocatedEntry::new(path.clone(), TreeEntry::blob(old_hash, false));
        let new = LocatedEntry::new(path.clone(), TreeEntry::blob(new_hash, false));

        let create = create_fixture_change(
            &graph,
            vec![],
            "create original path identity",
            vec![],
            vec![TreeDelta::Added {
                artifact_id: old_id,
                new: old.clone(),
            }],
        );
        let replace = create_fixture_change(
            &graph,
            vec![create],
            "replace path identity",
            vec![],
            vec![
                TreeDelta::Removed {
                    artifact_id: old_id,
                    old,
                },
                TreeDelta::Added {
                    artifact_id: new_id,
                    new,
                },
            ],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &replace).unwrap();
        assert_eq!(historical.artifact_id_at_path(&path), Some(new_id));
        assert!(historical.resolved_artifact(&old_id).is_none());
        assert!(graph
            .resolve_artifact_revision_at(&old_id, &replace)
            .unwrap()
            .is_none());
        assert_eq!(
            graph
                .resolve_artifact_revision_at(&new_id, &replace)
                .unwrap()
                .unwrap()
                .artifact_id,
            new_id
        );
    }

    #[test]
    fn merge_state_is_first_parent_relative_with_both_revision_predecessors() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let authority = test_authority(temp.path());
        let base_hash = save_source_blob(&authority, b"base");
        let first_hash = save_source_blob(&authority, b"first");
        let second_hash = save_source_blob(&authority, b"second");
        let merged_hash = save_source_blob(&authority, b"merged");
        let artifact_id = ArtifactId(uuid::Uuid::from_u128(0xb1));
        let path = RepoPath::from_utf8("compose.yaml").unwrap();
        let state = |hash| LocatedEntry::new(path.clone(), TreeEntry::blob(hash, false));

        let base = create_fixture_change(
            &graph,
            vec![],
            "base compose state",
            vec![],
            vec![TreeDelta::Added {
                artifact_id,
                new: state(base_hash),
            }],
        );
        let first = create_fixture_change(
            &graph,
            vec![base],
            "first-parent compose state",
            vec![],
            vec![TreeDelta::Updated {
                artifact_id,
                old: state(base_hash),
                new: state(first_hash),
            }],
        );
        let second = create_fixture_change(
            &graph,
            vec![base],
            "second-parent compose state",
            vec![],
            vec![TreeDelta::Updated {
                artifact_id,
                old: state(base_hash),
                new: state(second_hash),
            }],
        );
        let merge = create_fixture_change(
            &graph,
            vec![first, second],
            "merge compose state",
            vec![],
            vec![TreeDelta::Updated {
                artifact_id,
                old: state(first_hash),
                new: state(merged_hash),
            }],
        );

        let historical = build_graph_at_ref_from_graph(&graph, &authority, &merge).unwrap();
        assert_eq!(
            historical.resolved_artifact(&artifact_id).unwrap().entry,
            TreeEntry::blob(merged_hash, false)
        );

        let revisions = graph
            .get_artifact_revisions_at(&artifact_id, &merge)
            .unwrap();
        let first_revision = revisions
            .iter()
            .find(|revision| revision.introduced_by == first)
            .unwrap()
            .revision_id;
        let second_revision = revisions
            .iter()
            .find(|revision| revision.introduced_by == second)
            .unwrap()
            .revision_id;
        let merge_revision = revisions
            .iter()
            .find(|revision| revision.introduced_by == merge)
            .unwrap();
        assert_eq!(
            merge_revision.predecessor_revisions,
            vec![first_revision, second_revision]
        );
    }

    /// Gap 2 (audit follow-up): mixed binding — when only some persisted
    /// entities are alive at the ref, enrich_sparse_historical_source_file
    /// MUST reparse fresh and reuse NO persisted IDs. This guards against
    /// degrading the all-or-nothing semantic into a per-entity decision.
    #[test]
    fn enrich_sparse_reparses_fresh_when_any_persisted_entity_not_alive() {
        let reachable_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xb0; 32]));
        let unreachable_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xb1; 32]));

        let mut alive_one = test_entity("alive_one", "src/lib.py");
        alive_one.created_in = Some(reachable_id);
        let mut alive_two = test_entity("alive_two", "src/lib.py");
        alive_two.created_in = Some(reachable_id);
        let mut stale = test_entity("stale_dropped", "src/lib.py");
        stale.created_in = Some(unreachable_id);

        let persisted = vec![alive_one.clone(), alive_two.clone(), stale.clone()];
        let persisted_ids: HashSet<EntityId> = persisted.iter().map(|entity| entity.id).collect();

        // Parser sees four entities — two whose (kind, name) keys overlap
        // with persisted alive entries, plus two brand-new ones. This
        // satisfies `should_enrich_with_parsed_semantics` (parsed.len >
        // persisted.len, shared > 0, parsed_only >= 2).
        let parsed_alive_one = test_entity("alive_one", "src/lib.py");
        let parsed_alive_two = test_entity("alive_two", "src/lib.py");
        let parsed_new_one = test_entity("brand_new_one", "src/lib.py");
        let parsed_new_two = test_entity("brand_new_two", "src/lib.py");
        let parsed_ids: HashSet<EntityId> = [
            parsed_alive_one.id,
            parsed_alive_two.id,
            parsed_new_one.id,
            parsed_new_two.id,
        ]
        .into_iter()
        .collect();

        // Sanity: parser-issued IDs are distinct from any persisted ID.
        for parsed_id in &parsed_ids {
            assert!(
                !persisted_ids.contains(parsed_id),
                "test fixture invariant: parser IDs must not collide with persisted IDs"
            );
        }

        let indexed_file = kin_index::IndexedFile {
            file_id: FilePathId::new("src/lib.py"),
            language: kin_model::LanguageId::Python,
            entities: vec![
                parsed_alive_one,
                parsed_alive_two,
                parsed_new_one,
                parsed_new_two,
            ],
            relations: vec![],
            unresolved_relations: vec![],
            file_layout: FileLayout {
                file_id: FilePathId::new("src/lib.py"),
                parse_completeness: ParseCompleteness::Full,
                imports: ImportSection {
                    byte_range: 0..0,
                    items: vec![],
                },
                regions: vec![],
            },
            parse_state: kin_model::ParseState::Valid,
            blob_hash: Hash256::from_bytes([0xcc; 32]),
            extracted_relations: vec![],
            imports: vec![],
        };

        let lifecycle = RefLifecycle {
            reachable_changes: [reachable_id].into_iter().collect(),
            removed_entities: HashSet::new(),
        };

        let enrichment = enrich_sparse_historical_source_file(&persisted, indexed_file, &lifecycle)
            .expect("mixed-binding input should still enter the reparse-fresh branch");

        // All-or-nothing: no persisted ID may appear in the returned
        // enrichment. This is the load-bearing guarantee — flipping to a
        // per-entity decision would allow alive_one/alive_two to bind
        // while stale stays unbound, which we explicitly forbid here.
        for entity in &enrichment.entities {
            assert!(
                !persisted_ids.contains(&entity.id),
                "reparsed enrichment must not reuse persisted IDs (entity {} reused {})",
                entity.name,
                entity.id
            );
        }
        assert_eq!(
            enrichment.entities.len(),
            4,
            "reparse-fresh path returns parser entities verbatim"
        );
        // The file layout must reflect the partial-parse origin so callers
        // can observe that this enrichment is not a full historical bind.
        assert!(
            matches!(
                enrichment.file_layout.parse_completeness,
                ParseCompleteness::Partial(_)
            ),
            "reparse-fresh path must emit a Partial layout to signal lifecycle gap"
        );
    }
}
