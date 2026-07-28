// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Deterministic semantic enrichment for exact historical trees.
//!
//! This boundary never reads a checkout. It derives supported-language
//! entities and relations solely from graph-owned resolved trees and immutable
//! CAS bodies. Every other artifact remains represented by the exact tree even
//! when it has no language adapter.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use kin_blobs::BlobStore;
use kin_model::{
    ArtifactId, ChangeOrigin, Entity, EntityDelta, EntityId, FilePathId, ParseCompleteness,
    Relation, RelationDelta, RelationId, ResolvedTree, SemanticChange, SemanticChangeId, TreeEntry,
};
use kin_parser::is_call_extraction_incomplete_marker;
use sha2::{Digest, Sha256};

use crate::classifier::{FileClassification, FileClassifier};
use crate::error::{IndexError, Result};
use crate::linker::{
    bare_entity_name, build_link_context_from_refs, is_class_like, is_external_import_placeholder,
    known_file_paths, link_cross_file_with_completeness, make_artifact_import_relation,
    make_parse_coverage_relation, resolve_include_targets, resolve_module_path, resolve_one_file,
    split_owner_method, split_scoped_receiver_method, ArtifactIdentityMap,
    FileParseCompletenessMap, FileParseData, LinkContext,
};
use crate::pipeline::IndexPipeline;

/// Declared version of the replay semantics that author historical deltas.
///
/// Kin's deep history is not a stored fact. It is re-authored here from
/// graph-owned trees and CAS bodies, so editing any of the replay functions
/// pinned by `scripts/hydration-semantics-manifest.json` changes what Kin
/// reports about the past on repositories that were already ingested. A digest
/// mismatch in that guard is a decision to make, not a file to regenerate:
/// establish whether replay semantics actually changed, and if they did, bump
/// this constant and the manifest's recorded version together. Never
/// regenerate a digest silently.
pub const HYDRATION_SEMANTICS_VERSION: u32 = 5;

/// Semantic graph delta derived for one pre-enrichment change identity.
///
/// Callers apply these deltas to the matching change and then recompute change
/// identities, parent identities, and external aliases in parent-first order.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoricalSemanticDelta {
    pub change_id: SemanticChangeId,
    pub entity_deltas: Vec<EntityDelta>,
    pub relation_deltas: Vec<RelationDelta>,
}

struct ParsedFile {
    completeness: ParseCompleteness,
    entities: Vec<Entity>,
    relations: Vec<kin_parser::ExtractedRelation>,
    imports: Vec<kin_parser::FileImport>,
}

/// One semantic file at one exact content identity.
///
/// The parse payload is shared by `Arc` so that carrying an unchanged file
/// from a parent tree to a child tree is a pointer clone, never a deep copy of
/// its entities, relations, and imports.
struct SemanticFileState {
    artifact_id: ArtifactId,
    entry: TreeEntry,
    completeness: ParseCompleteness,
    parse: Arc<FileParseData>,
}

impl SemanticFileState {
    fn path(&self) -> &str {
        &self.parse.file_path
    }
}

/// The cross-file link output of one file under one tree's link context.
///
/// `relations` is the complete per-file share of the tree's linked relation
/// set: resolved entity relations, artifact-level import/include edges, and
/// the file's parse-coverage certificate, already validated against the
/// tree's entity set. `referenced_entities` and `dropped_placeholder_dsts`
/// back the fail-closed audit that proves a carried-forward output could not
/// have changed.
struct LinkedFile {
    relations: Vec<Relation>,
    referenced_entities: BTreeSet<EntityId>,
    dropped_placeholder_dsts: BTreeSet<EntityId>,
}

#[derive(Clone, Default)]
struct SemanticTreeState {
    files: BTreeMap<ArtifactId, Arc<SemanticFileState>>,
    linked: BTreeMap<ArtifactId, Arc<LinkedFile>>,
    entities: BTreeMap<EntityId, Arc<Entity>>,
    relations: BTreeMap<RelationId, Arc<Relation>>,
}

/// Derive semantic deltas for parent-first exact history.
///
/// `trees` is keyed by each input change's current identity. The input changes
/// must not already contain semantic deltas: this is a single, explicit build
/// phase, not a best-effort repair path.
pub fn derive_historical_semantic_deltas(
    changes: &[SemanticChange],
    trees: &BTreeMap<SemanticChangeId, ResolvedTree>,
    blob_store: &BlobStore,
) -> Result<Vec<HistoricalSemanticDelta>> {
    derive_historical_semantic_deltas_inner(changes, trees, blob_store, LinkEngine::new())
}

/// Derivation with the batch cross-check forced on for every commit,
/// regardless of `KIN_HISTORY_LINK_VERIFY`. Test-only: fixtures use the batch
/// path itself as the oracle for the incremental path.
#[cfg(test)]
fn derive_historical_semantic_deltas_verified(
    changes: &[SemanticChange],
    trees: &BTreeMap<SemanticChangeId, ResolvedTree>,
    blob_store: &BlobStore,
) -> Result<Vec<HistoricalSemanticDelta>> {
    let mut engine = LinkEngine::new();
    engine.verify = true;
    derive_historical_semantic_deltas_inner(changes, trees, blob_store, engine)
}

fn derive_historical_semantic_deltas_inner(
    changes: &[SemanticChange],
    trees: &BTreeMap<SemanticChangeId, ResolvedTree>,
    blob_store: &BlobStore,
    mut engine: LinkEngine,
) -> Result<Vec<HistoricalSemanticDelta>> {
    let pipeline = IndexPipeline::new();
    let mut states = BTreeMap::<SemanticChangeId, SemanticTreeState>::new();
    let mut known_changes = HashSet::with_capacity(changes.len());
    let mut remaining_child_uses = BTreeMap::<SemanticChangeId, usize>::new();
    let mut output = Vec::with_capacity(changes.len());

    for change in changes {
        if !known_changes.insert(change.id) {
            return Err(invalid(format!(
                "history repeats change identity {}",
                change.id
            )));
        }
        for parent in &change.parents {
            *remaining_child_uses.entry(*parent).or_default() += 1;
        }
    }
    if trees.len() != changes.len() {
        return Err(invalid(format!(
            "semantic tree map contains {} entries for {} enriched changes",
            trees.len(),
            changes.len()
        )));
    }

    for change in changes {
        if !matches!(change.origin, ChangeOrigin::GitCommit { .. }) {
            return Err(invalid(format!(
                "historical Git enrichment received native change {}",
                change.id
            )));
        }
        if !change.entity_deltas.is_empty() || !change.relation_deltas.is_empty() {
            return Err(invalid(format!(
                "change {} already carries semantic deltas",
                change.id
            )));
        }
        let parent_states = change
            .parents
            .iter()
            .map(|parent| {
                states.get(parent).ok_or_else(|| {
                    invalid(format!(
                        "parent {} of change {} was not enriched first",
                        parent, change.id
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let tree = trees.get(&change.id).ok_or_else(|| {
            invalid(format!(
                "change {} has no exact resolved tree for semantic enrichment",
                change.id
            ))
        })?;
        let (current, entity_deltas, relation_deltas) =
            semantic_state_for_tree(tree, &parent_states, blob_store, &pipeline, &mut engine)?;

        output.push(HistoricalSemanticDelta {
            change_id: change.id,
            entity_deltas,
            relation_deltas,
        });

        drop(parent_states);
        for parent in &change.parents {
            let remaining = remaining_child_uses.get_mut(parent).ok_or_else(|| {
                invalid(format!(
                    "parent {} of change {} has no child-use accounting",
                    parent, change.id
                ))
            })?;
            *remaining = remaining.checked_sub(1).ok_or_else(|| {
                invalid(format!(
                    "parent {} of change {} has invalid child-use accounting",
                    parent, change.id
                ))
            })?;
            if *remaining == 0 {
                states.remove(parent);
            }
        }
        if remaining_child_uses.get(&change.id).copied().unwrap_or(0) > 0 {
            states.insert(change.id, current);
        }
    }

    if !states.is_empty() {
        return Err(invalid(
            "semantic history retained parent state after every child was enriched",
        ));
    }
    Ok(output)
}

fn semantic_state_for_tree(
    tree: &ResolvedTree,
    parents: &[&SemanticTreeState],
    blob_store: &BlobStore,
    pipeline: &IndexPipeline,
    engine: &mut LinkEngine,
) -> Result<(SemanticTreeState, Vec<EntityDelta>, Vec<RelationDelta>)> {
    let empty_parent = SemanticTreeState::default();
    let first_parent = parents.first().copied().unwrap_or(&empty_parent);
    let mut files = BTreeMap::new();

    for artifact in tree.artifacts() {
        let Some(path) = artifact.path.as_utf8() else {
            continue;
        };
        let TreeEntry::Blob { hash, .. } = artifact.entry else {
            continue;
        };
        if !matches!(
            FileClassifier::classify(Path::new(path)),
            FileClassification::EntitySource
        ) {
            continue;
        }

        if let Some(existing) = parents.iter().find_map(|parent| {
            parent
                .files
                .get(&artifact.artifact_id)
                .filter(|file| file.path() == path && file.entry == artifact.entry)
        }) {
            if files
                .insert(artifact.artifact_id, Arc::clone(existing))
                .is_some()
            {
                return Err(invalid(format!(
                    "tree assigns artifact {:?} to multiple semantic files",
                    artifact.artifact_id
                )));
            }
            continue;
        }

        let body_hash = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
        let body = blob_store.read(&body_hash)?;
        if kin_blobs::digest_bytes(&body) != *hash.as_bytes() {
            return Err(invalid(format!(
                "CAS body for {path} does not match exact tree identity {hash}"
            )));
        }
        if !matches!(
            FileClassifier::classify_with_content(Path::new(path), &body),
            FileClassification::EntitySource
        ) {
            continue;
        }
        let indexed =
            pipeline.index_file_content_with_tests(&FilePathId::new(path), &body, body_hash)?;
        let indexed = indexed.indexed_file;
        let parsed = ParsedFile {
            completeness: indexed.file_layout.parse_completeness,
            entities: indexed.entities,
            relations: indexed.extracted_relations,
            imports: indexed.imports,
        };
        let old_entities = parents
            .iter()
            .filter_map(|parent| parent.files.get(&artifact.artifact_id))
            .flat_map(|file| file.parse.entities.iter())
            .collect::<Vec<_>>();
        let entities =
            stabilize_historical_entities(artifact.artifact_id, old_entities, &parsed.entities);
        let state = SemanticFileState {
            artifact_id: artifact.artifact_id,
            entry: artifact.entry,
            completeness: parsed.completeness,
            parse: Arc::new(FileParseData {
                file_path: path.to_string(),
                entities,
                relations: parsed.relations,
                imports: parsed.imports,
            }),
        };
        if files
            .insert(artifact.artifact_id, Arc::new(state))
            .is_some()
        {
            return Err(invalid(format!(
                "tree assigns artifact {:?} to multiple semantic files",
                artifact.artifact_id
            )));
        }
    }

    let (state, entity_deltas, relation_deltas) =
        derive_tree_semantics(files, first_parent, engine)?;

    if engine.verify {
        verify_against_reference(&state, first_parent, &entity_deltas, &relation_deltas)?;
    }
    Ok((state, entity_deltas, relation_deltas))
}

/// Recompute this tree's complete semantic state through the single-pass batch
/// path and require the incremental result to be identical, including the
/// emitted first-parent deltas. This is the `KIN_HISTORY_LINK_VERIFY` audit:
/// it proves on real histories that incremental replay authors byte-identical
/// truth, at full batch cost.
fn verify_against_reference(
    current: &SemanticTreeState,
    first_parent: &SemanticTreeState,
    entity_deltas: &[EntityDelta],
    relation_deltas: &[RelationDelta],
) -> Result<()> {
    let mut parse_data = Vec::with_capacity(current.files.len());
    let mut completeness = FileParseCompletenessMap::new();
    let mut artifact_ids = ArtifactIdentityMap::new();
    let mut entities = BTreeMap::new();
    for file in current.files.values() {
        artifact_ids.insert(file.path().to_string(), file.artifact_id);
        completeness.insert(file.path().to_string(), file.completeness.clone());
        for entity in &file.parse.entities {
            if entities.insert(entity.id, entity.clone()).is_some() {
                return Err(invalid(
                    "verification found a duplicated entity identity the incremental path admitted",
                ));
            }
        }
        parse_data.push((*file.parse).clone());
    }
    parse_data.sort_by(|left, right| left.file_path.cmp(&right.file_path));
    let linked = link_cross_file_with_completeness(&parse_data, &artifact_ids, &completeness)?;
    let mut relations = BTreeMap::new();
    for relation in linked {
        if let Some(absent) = absent_local_endpoint(&relation, &entities) {
            if absent.is_destination && is_external_import_placeholder(&relation) {
                continue;
            }
            return Err(invalid(format!(
                "verification relation {} names absent entity {}",
                relation.id, absent.entity_id
            )));
        }
        if relations.insert(relation.id, relation).is_some() {
            return Err(invalid(
                "verification found a duplicate relation identity the incremental path admitted",
            ));
        }
    }

    let entities_match = entities.len() == current.entities.len()
        && entities.iter().all(|(id, entity)| {
            current
                .entities
                .get(id)
                .is_some_and(|held| **held == *entity)
        });
    if !entities_match {
        return Err(invalid(
            "incremental enrichment diverged from the batch derivation in the tree entity set",
        ));
    }
    let relations_match = relations.len() == current.relations.len()
        && relations.iter().all(|(id, relation)| {
            current
                .relations
                .get(id)
                .is_some_and(|held| **held == *relation)
        });
    if !relations_match {
        return Err(invalid(
            "incremental enrichment diverged from the batch derivation in the tree relation set",
        ));
    }

    let parent_entities: BTreeMap<EntityId, Entity> = first_parent
        .entities
        .iter()
        .map(|(id, entity)| (*id, (**entity).clone()))
        .collect();
    let parent_relations: BTreeMap<RelationId, Relation> = first_parent
        .relations
        .iter()
        .map(|(id, relation)| (*id, (**relation).clone()))
        .collect();
    if diff_entities(&parent_entities, &entities).as_slice() != entity_deltas
        || diff_relations(&parent_relations, &relations).as_slice() != relation_deltas
    {
        return Err(invalid(
            "incremental enrichment diverged from the batch derivation in the emitted deltas",
        ));
    }
    Ok(())
}

/// Derive one tree's semantic state and its first-parent deltas, reusing every
/// carried-forward per-file link output the invalidation analysis proves
/// unchanged.
fn derive_tree_semantics(
    files: BTreeMap<ArtifactId, Arc<SemanticFileState>>,
    first_parent: &SemanticTreeState,
    engine: &mut LinkEngine,
) -> Result<(SemanticTreeState, Vec<EntityDelta>, Vec<RelationDelta>)> {
    // An exact first-parent tree carry is already fully linked. This covers
    // empty Git commits and merge commits that select the first parent's tree;
    // returning its immutable state avoids rebuilding every whole-tree index
    // when no semantic input changed at all.
    let exact_first_parent_carry = files.len() == first_parent.files.len()
        && files.iter().zip(first_parent.files.iter()).all(
            |((current_id, current), (parent_id, parent))| {
                current_id == parent_id && Arc::ptr_eq(current, parent)
            },
        );
    if exact_first_parent_carry {
        return Ok((first_parent.clone(), Vec::new(), Vec::new()));
    }

    // Any change to the artifact/path membership of the tree can change module
    // resolution, import targets, and default-export anchoring anywhere in the
    // repository, so those commits relink the whole tree. Content-only commits
    // take the incremental path below.
    let structural = files.len() != first_parent.files.len()
        || files.iter().zip(first_parent.files.iter()).any(
            |((current_id, current), (parent_id, parent))| {
                current_id != parent_id || current.path() != parent.path()
            },
        );

    // Duplicate-path refusal, artifact identities, and parse completeness are
    // per-tree inputs to linking and validation.
    let mut completeness = FileParseCompletenessMap::new();
    let mut artifact_ids = ArtifactIdentityMap::new();
    for file in files.values() {
        if artifact_ids
            .insert(file.path().to_string(), file.artifact_id)
            .is_some()
        {
            return Err(invalid(format!(
                "tree contains more than one semantic artifact at {}",
                file.path()
            )));
        }
        completeness.insert(file.path().to_string(), file.completeness.clone());
    }

    let file_refs: Vec<&FileParseData> = files.values().map(|file| file.parse.as_ref()).collect();
    let universe_refs: Vec<&Entity> = file_refs
        .iter()
        .flat_map(|file| file.entities.iter())
        .collect();
    let known_files = known_file_paths(&file_refs, &universe_refs);
    let era_signature = advance_link_era(engine, &files);
    refresh_link_analyses(engine, &files, era_signature, &known_files);

    // Assemble the include graph from the per-file resolved include targets.
    // `resolve_include_targets` is the same function batch include-graph
    // construction folds per file, and paths are unique per tree, so this is
    // the identical graph without re-resolving unchanged files' imports.
    let mut include_graph: HashMap<String, Vec<String>> = HashMap::new();
    for (artifact_id, file) in &files {
        let targets = &engine.analysis(artifact_id).era.include_targets;
        if !targets.is_empty() {
            include_graph.insert(file.path().to_string(), targets.clone());
        }
    }
    let ctx = build_link_context_from_refs(&file_refs, &universe_refs, include_graph);

    // The set of files whose link output must be recomputed under this tree.
    let relink: Vec<ArtifactId> = if structural {
        files.keys().copied().collect()
    } else {
        invalidated_files(engine, &files, first_parent, &known_files)?
    };

    // Entity map: carry the first parent's map and apply the changed files'
    // entity deltas, preserving the whole-tree duplicate-identity refusal.
    let mut entities = first_parent.entities.clone();
    let mut removed_entities = BTreeMap::<EntityId, Arc<Entity>>::new();
    let mut inserted_entities = BTreeMap::<EntityId, Arc<Entity>>::new();
    for (artifact_id, parent_file) in &first_parent.files {
        let changed = match files.get(artifact_id) {
            Some(current) => !Arc::ptr_eq(current, parent_file),
            None => true,
        };
        if changed {
            for entity in &parent_file.parse.entities {
                let Some(previous) = entities.remove(&entity.id) else {
                    return Err(invalid(format!(
                        "parent tree state lost entity {} during incremental carry-forward",
                        entity.id
                    )));
                };
                removed_entities.insert(entity.id, previous);
            }
        }
    }
    for (artifact_id, file) in &files {
        let changed = match first_parent.files.get(artifact_id) {
            Some(parent_file) => !Arc::ptr_eq(file, parent_file),
            None => true,
        };
        if !changed {
            continue;
        }
        let arcs = &engine.analysis(artifact_id).entity_arcs;
        for entity in arcs {
            if let Some(previous) = entities.insert(entity.id, Arc::clone(entity)) {
                return Err(invalid(format!(
                    "semantic entity identity {} is duplicated in one tree: {} {:?} from {:?} and {} {:?} from {}",
                    entity.id,
                    previous.name,
                    previous.kind,
                    previous.file_origin,
                    entity.name,
                    entity.kind,
                    file.path()
                )));
            }
            inserted_entities.insert(entity.id, Arc::clone(entity));
        }
    }

    // Link the invalidated files under the exact context of this tree.
    let mut linked = BTreeMap::new();
    let mut removed_relations = BTreeMap::<RelationId, Arc<Relation>>::new();
    let mut inserted_relations = BTreeMap::<RelationId, Arc<Relation>>::new();
    let mut relations = if structural {
        // Every file relinks, so every parent relation leaves the map and
        // every current relation re-enters it; the patch diff then compares
        // per identity exactly as a full first-parent diff would.
        removed_relations = first_parent.relations.clone();
        BTreeMap::new()
    } else {
        first_parent.relations.clone()
    };
    if !structural {
        // Remove every relinked or removed file's previous share first, so a
        // relation that survives a relink re-inserts cleanly.
        let mut drop_share = |artifact_id: &ArtifactId| -> Result<()> {
            if let Some(previous) = first_parent.linked.get(artifact_id) {
                for relation in &previous.relations {
                    let Some(removed) = relations.remove(&relation.id) else {
                        return Err(invalid(format!(
                            "parent tree state lost relation {} during incremental carry-forward",
                            relation.id
                        )));
                    };
                    removed_relations.insert(relation.id, removed);
                }
            }
            Ok(())
        };
        for artifact_id in &relink {
            drop_share(artifact_id)?;
        }
        for artifact_id in first_parent.files.keys() {
            if !files.contains_key(artifact_id) {
                drop_share(artifact_id)?;
            }
        }
    }
    // Per-file resolution is pure against the shared context, so a large
    // relink set (structural commits relink the whole tree) resolves in
    // parallel exactly like the batch path; results merge serially in
    // deterministic artifact order either way.
    let relinked_files = {
        use rayon::prelude::*;
        let link_one = |artifact_id: &ArtifactId| -> Result<(ArtifactId, LinkedFile)> {
            let file = files
                .get(artifact_id)
                .ok_or_else(|| invalid("relink set names an artifact absent from the tree"))?;
            let linked_file = link_single_file(
                file,
                &ctx,
                &known_files,
                &artifact_ids,
                &completeness,
                &entities,
            )?;
            Ok((*artifact_id, linked_file))
        };
        if relink.len() >= 16 {
            relink
                .par_iter()
                .map(link_one)
                .collect::<Result<Vec<_>>>()?
        } else {
            relink.iter().map(link_one).collect::<Result<Vec<_>>>()?
        }
    };
    for (artifact_id, linked_file) in relinked_files {
        for relation in &linked_file.relations {
            let value = Arc::new(relation.clone());
            if relations.insert(relation.id, Arc::clone(&value)).is_some() {
                return Err(invalid(
                    "cross-file linker returned a duplicate relation identity",
                ));
            }
            inserted_relations.insert(relation.id, value);
        }
        linked.insert(artifact_id, Arc::new(linked_file));
    }
    for (artifact_id, file) in &files {
        if linked.contains_key(artifact_id) {
            continue;
        }
        let carried = first_parent.linked.get(artifact_id).ok_or_else(|| {
            invalid(format!(
                "carried-forward file {} has no parent link output",
                file.path()
            ))
        })?;
        linked.insert(*artifact_id, Arc::clone(carried));
    }

    if !structural {
        audit_carried_link_outputs(
            &files,
            &linked,
            &relink,
            &removed_entities,
            &inserted_entities,
        )?;
    }

    let entity_deltas = deltas_from_entity_patch(&removed_entities, &inserted_entities);
    let relation_deltas = deltas_from_relation_patch(&removed_relations, &inserted_relations);

    Ok((
        SemanticTreeState {
            files,
            linked,
            entities,
            relations,
        },
        entity_deltas,
        relation_deltas,
    ))
}

/// Resolve, decorate, and validate one file's complete share of the tree's
/// linked relation set: its resolved entity relations, its artifact-level
/// import/include edges, and its parse-coverage certificate.
///
/// This is exactly the per-file share the batch entry point produces: per-file
/// resolution is pure, artifact edges depend only on this file's imports and
/// the tree's path set, and cross-file merge deduplication can never fire
/// because every relation's source node is owned by its emitting file.
fn link_single_file(
    file: &SemanticFileState,
    ctx: &LinkContext<'_>,
    known_files: &HashSet<&str>,
    artifact_ids: &ArtifactIdentityMap,
    completeness: &FileParseCompletenessMap,
    entities: &BTreeMap<EntityId, Arc<Entity>>,
) -> Result<LinkedFile> {
    let mut produced = resolve_one_file(&file.parse, ctx, Some(completeness));
    let mut seen_artifact = HashSet::new();
    for import in &file.parse.imports {
        if let Some(relation) =
            make_artifact_import_relation(file.path(), import, known_files, artifact_ids)
        {
            if seen_artifact.insert((relation.src, relation.dst, relation.kind)) {
                produced.push(relation);
            }
        }
    }
    let call_extraction_complete = !file
        .parse
        .relations
        .iter()
        .any(is_call_extraction_incomplete_marker);
    produced.push(make_parse_coverage_relation(
        file.path(),
        file.artifact_id,
        completeness.get(file.path()),
        call_extraction_complete,
    ));

    let mut relations = Vec::with_capacity(produced.len());
    let mut referenced_entities = BTreeSet::new();
    let mut dropped_placeholder_dsts = BTreeSet::new();
    for relation in produced {
        if let Some(absent) = absent_local_endpoint(&relation, entities) {
            // A change carries the entity set of its own tree, so replaying it
            // can only bind an edge whose endpoints that tree defines. The
            // linker's cross-repo placeholder destination is absent by
            // contract and stays a view-time inference rather than change-owned
            // history; every other absent endpoint is inconsistent state and
            // fails closed here instead of being admitted.
            if absent.is_destination && is_external_import_placeholder(&relation) {
                dropped_placeholder_dsts.insert(absent.entity_id);
                continue;
            }
            return Err(invalid(format!(
                "linked relation {} names {} entity {} that the tree does not define",
                relation.id,
                if absent.is_destination {
                    "destination"
                } else {
                    "source"
                },
                absent.entity_id
            )));
        }
        for node in [relation.src, relation.dst] {
            if let Some(entity_id) = node.as_entity() {
                referenced_entities.insert(entity_id);
            }
        }
        relations.push(relation);
    }
    Ok(LinkedFile {
        relations,
        referenced_entities,
        dropped_placeholder_dsts,
    })
}

/// Fail-closed audit that a carried-forward link output could not have
/// changed: it must not reference any entity this commit removed, and no
/// placeholder destination it dropped may have become a real entity. Either
/// condition would mean the invalidation analysis was not conservative, so
/// enrichment refuses loudly instead of admitting silently wrong history.
fn audit_carried_link_outputs(
    files: &BTreeMap<ArtifactId, Arc<SemanticFileState>>,
    linked: &BTreeMap<ArtifactId, Arc<LinkedFile>>,
    relink: &[ArtifactId],
    removed_entities: &BTreeMap<EntityId, Arc<Entity>>,
    inserted_entities: &BTreeMap<EntityId, Arc<Entity>>,
) -> Result<()> {
    let net_removed: Vec<&EntityId> = removed_entities
        .keys()
        .filter(|id| !inserted_entities.contains_key(id))
        .collect();
    let net_added: Vec<&EntityId> = inserted_entities
        .keys()
        .filter(|id| !removed_entities.contains_key(id))
        .collect();
    if net_removed.is_empty() && net_added.is_empty() {
        return Ok(());
    }
    let relinked: HashSet<&ArtifactId> = relink.iter().collect();
    for (artifact_id, output) in linked {
        if relinked.contains(artifact_id) {
            continue;
        }
        for removed in &net_removed {
            if output.referenced_entities.contains(removed) {
                return Err(invalid(format!(
                    "carried-forward link output for {} references removed entity {}; \
                     relink invalidation was not conservative",
                    files
                        .get(artifact_id)
                        .map(|file| file.path())
                        .unwrap_or("<unknown>"),
                    removed
                )));
            }
        }
        for added in &net_added {
            if output.dropped_placeholder_dsts.contains(added) {
                return Err(invalid(format!(
                    "carried-forward link output for {} dropped a placeholder that now \
                     names real entity {}; relink invalidation was not conservative",
                    files
                        .get(artifact_id)
                        .map(|file| file.path())
                        .unwrap_or("<unknown>"),
                    added
                )));
            }
        }
    }
    Ok(())
}

/// First-parent entity deltas from the incremental patch, identical to a full
/// map diff: an identity untouched by the patch carries the same shared value
/// on both sides, and a patched identity compares old against new exactly as
/// the full diff would.
fn deltas_from_entity_patch(
    removed: &BTreeMap<EntityId, Arc<Entity>>,
    inserted: &BTreeMap<EntityId, Arc<Entity>>,
) -> Vec<EntityDelta> {
    let mut deltas = Vec::new();
    for (id, old) in removed {
        match inserted.get(id) {
            Some(new) if **old == **new => {}
            Some(new) => deltas.push(EntityDelta::Modified {
                old: (**old).clone(),
                new: (**new).clone(),
            }),
            None => deltas.push(EntityDelta::Removed {
                old: (**old).clone(),
            }),
        }
    }
    for (id, new) in inserted {
        if !removed.contains_key(id) {
            deltas.push(EntityDelta::Added {
                new: (**new).clone(),
            });
        }
    }
    deltas.sort_by_key(EntityDelta::target_id);
    deltas
}

fn deltas_from_relation_patch(
    removed: &BTreeMap<RelationId, Arc<Relation>>,
    inserted: &BTreeMap<RelationId, Arc<Relation>>,
) -> Vec<RelationDelta> {
    let mut deltas = Vec::new();
    for (id, old) in removed {
        match inserted.get(id) {
            Some(new) if **old == **new => {}
            Some(new) => deltas.push(RelationDelta::Modified {
                old: (**old).clone(),
                new: (**new).clone(),
            }),
            None => deltas.push(RelationDelta::Removed {
                old: (**old).clone(),
            }),
        }
    }
    for (id, new) in inserted {
        if !removed.contains_key(id) {
            deltas.push(RelationDelta::Added {
                new: (**new).clone(),
            });
        }
    }
    deltas.sort_by_key(RelationDelta::target_id);
    deltas
}

/// Persistent cross-commit linking state.
///
/// Nothing in here is semantic truth: it is memoized analysis of file versions
/// (probe tokens, resolved module and include targets, hierarchy projections)
/// used to prove which files a commit's delta cannot have affected. Every
/// entry retains and compares the exact parse allocation and the exact
/// path-set era it was computed under, and is recomputed whenever either
/// changes.
struct LinkEngine {
    verify: bool,
    analyses: HashMap<ArtifactId, AnalysisSlot>,
    /// Monotonic identifier for the current path-set era, advanced whenever
    /// the sorted path membership actually differs from the previous tree.
    /// Compared exactly, never by hash: a stale era silently changes what the
    /// invalidation rules can see.
    era_counter: u64,
    era_paths: Vec<String>,
}

struct AnalysisSlot {
    /// Retaining the exact parse allocation makes pointer identity safe: an
    /// allocator cannot recycle its address while this slot exists. A raw
    /// pointer value alone allowed a dropped leaf-head parse to alias a later
    /// divergent head's distinct payload.
    parse: Arc<FileParseData>,
    entity_arcs: Vec<Arc<Entity>>,
    stat: Arc<FileStaticAnalysis>,
    era_signature: u64,
    era: Arc<FileEraAnalysis>,
}

/// Analysis of one file version that depends only on its own parse payload.
struct FileStaticAnalysis {
    /// Every name-shaped key this file's resolution can probe in the global
    /// entity indices: relation destinations plus their bare leaves, `::` and
    /// `.` segments, and adjacent type-qualified suffix pairs.
    tokens: BTreeSet<String>,
    /// Full and bare names this file contributes to the global entity indices.
    contributed_names: BTreeSet<String>,
    /// Class hierarchy shape other files' inheritance walks can traverse
    /// through this file.
    hierarchy: FileHierarchyProjection,
    /// Bare leaves of this file's declared Extends bases.
    base_leaves: BTreeSet<String>,
    /// Whether any call in this file can enter an inheritance walk at all.
    walk_capable: bool,
}

#[derive(PartialEq, Eq)]
struct FileHierarchyProjection {
    /// Sorted (class, base) pairs from parser-emitted Extends relations.
    extends: Vec<(String, String)>,
    /// Sorted class-like entity (name, kind) pairs: the anchors and waypoints
    /// an inheritance walk can locate in this file.
    class_like: Vec<(String, String)>,
    /// Sorted import specifiers, tracked only when the file declares Extends
    /// bases: a mid-walk `locate_base_class` resolves that file's bases
    /// through its own imports.
    imports: Vec<(String, String, String)>,
}

/// Analysis of one file version that also depends on the tree's path set.
struct FileEraAnalysis {
    /// Files this file's imports and parser-pinned import sources resolve to.
    module_targets: BTreeSet<String>,
    /// Include-like resolved targets, exactly as batch include-graph
    /// construction records them.
    include_targets: Vec<String>,
}

impl LinkEngine {
    fn new() -> Self {
        let verify = std::env::var("KIN_HISTORY_LINK_VERIFY")
            .map(|value| history_link_verify_enabled(&value))
            .unwrap_or(false);
        Self {
            verify,
            analyses: HashMap::new(),
            era_counter: 0,
            era_paths: Vec::new(),
        }
    }

    fn analysis(&self, artifact_id: &ArtifactId) -> &AnalysisSlot {
        self.analyses
            .get(artifact_id)
            .expect("analysis slots are refreshed for every file in the tree before use")
    }
}

fn history_link_verify_enabled(value: &str) -> bool {
    let value = value.trim();
    value == "1"
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("on")
}

/// Advance to `files`' exact sorted path-membership era. Module and include
/// target resolution consult the known-file set, so per-file era caches are
/// valid only while this membership holds; compare paths themselves, never a
/// digest that could collide.
fn advance_link_era(
    engine: &mut LinkEngine,
    files: &BTreeMap<ArtifactId, Arc<SemanticFileState>>,
) -> u64 {
    let mut paths: Vec<String> = files.values().map(|file| file.path().to_string()).collect();
    paths.sort_unstable();
    if paths != engine.era_paths {
        engine.era_counter += 1;
        engine.era_paths = paths;
    }
    engine.era_counter
}

/// Refresh exact per-file analysis inputs for one tree and discard analyses no
/// longer reachable from that tree.
///
/// Parent semantic states own every parse allocation a future child can reuse.
/// Dropping a cache slot therefore never drops semantic truth: revisiting a
/// live parent or another branch either finds the same retained allocation or
/// recomputes from that parent's exact parse payload. Retaining only the
/// current tree bounds cache memory while the `Arc` held by each live slot
/// prevents address reuse from impersonating a distinct divergent-head input.
fn refresh_link_analyses(
    engine: &mut LinkEngine,
    files: &BTreeMap<ArtifactId, Arc<SemanticFileState>>,
    era_signature: u64,
    known_files: &HashSet<&str>,
) {
    engine
        .analyses
        .retain(|artifact_id, _| files.contains_key(artifact_id));
    for (artifact_id, file) in files {
        let stale = match engine.analyses.get(artifact_id) {
            Some(slot) => !Arc::ptr_eq(&slot.parse, &file.parse),
            None => true,
        };
        if stale {
            let stat = Arc::new(analyze_file_static(&file.parse));
            let era = Arc::new(analyze_file_era(&file.parse, known_files));
            let entity_arcs = file
                .parse
                .entities
                .iter()
                .map(|entity| Arc::new(entity.clone()))
                .collect();
            engine.analyses.insert(
                *artifact_id,
                AnalysisSlot {
                    parse: Arc::clone(&file.parse),
                    entity_arcs,
                    stat,
                    era_signature,
                    era,
                },
            );
            continue;
        }
        let slot = engine
            .analyses
            .get_mut(artifact_id)
            .expect("slot presence checked above");
        if slot.era_signature != era_signature {
            slot.era = Arc::new(analyze_file_era(&file.parse, known_files));
            slot.era_signature = era_signature;
        }
    }
}

/// The conservative set of files whose link output must be recomputed for
/// a content-only commit. Everything a file's resolution can observe from
/// the rest of the tree is covered by one of the four rules below; the
/// per-rule reasoning lives with each block.
fn invalidated_files(
    engine: &LinkEngine,
    files: &BTreeMap<ArtifactId, Arc<SemanticFileState>>,
    first_parent: &SemanticTreeState,
    known_files: &HashSet<&str>,
) -> Result<Vec<ArtifactId>> {
    let mut relink = BTreeSet::new();
    let mut changed = Vec::new();
    for (artifact_id, file) in files {
        let Some(parent_file) = first_parent.files.get(artifact_id) else {
            return Err(invalid(
                "content-only commit gained an artifact; structural mode was required",
            ));
        };
        if !Arc::ptr_eq(file, parent_file) {
            changed.push((*artifact_id, Arc::clone(parent_file), Arc::clone(file)));
            relink.insert(*artifact_id);
        }
    }

    // Rule 1: names. A kept file's resolution reads the global indices only
    // at keys derivable from its own parse payload; the indices change only
    // at keys named by the changed files' old and new entity sets. Any
    // intersection forces a relink.
    let mut changed_names = BTreeSet::new();
    // Rule 2: module targets. Import, pin, namespace-member, and
    // default-export resolution reach other files through resolved module
    // paths; path resolution is stable while the path set is stable, so a
    // kept file is affected only when a changed file is one of its targets.
    let mut changed_paths = BTreeSet::new();
    // Rule 3: include topology. Macro reachability and include-closure
    // disambiguation read the transitive include graph, so a changed
    // include-target list invalidates every file that can reach the
    // changed file through either the old or the new graph.
    let mut include_seeds = BTreeSet::new();
    // Rule 4: hierarchy. Inheritance walks discover class names mid-walk
    // that no static token set can enumerate, so any change to a hierarchy
    // projection, or to any entity sharing a name with a declared base,
    // invalidates every file whose calls can enter a walk.
    let mut hierarchy_fire = false;
    let mut base_leaves: BTreeSet<String> = BTreeSet::new();
    for slot in files.keys().map(|id| engine.analysis(id)) {
        base_leaves.extend(slot.stat.base_leaves.iter().cloned());
    }

    // The changed files' old versions are analyzed once; the tree's path set
    // is identical to the parent's on this path, so the current known-file
    // set resolves the old imports exactly as the parent tree did.
    let old_analyses: Vec<(FileStaticAnalysis, FileEraAnalysis)> = changed
        .iter()
        .map(|(_, old_file, _)| {
            (
                analyze_file_static(&old_file.parse),
                analyze_file_era(&old_file.parse, known_files),
            )
        })
        .collect();
    // Base leaves must be complete (current tree plus every changed file's
    // old declarations) before any name is tested against them.
    for (old_stat, _) in &old_analyses {
        base_leaves.extend(old_stat.base_leaves.iter().cloned());
    }

    for ((artifact_id, _, new_file), (old_stat, old_era)) in changed.iter().zip(&old_analyses) {
        let new_slot = engine.analysis(artifact_id);
        changed_names.extend(old_stat.contributed_names.iter().cloned());
        changed_names.extend(new_slot.stat.contributed_names.iter().cloned());
        changed_paths.insert(new_file.path().to_string());
        if old_era.include_targets != new_slot.era.include_targets {
            include_seeds.insert(new_file.path().to_string());
        }
        if old_stat.hierarchy != new_slot.stat.hierarchy {
            hierarchy_fire = true;
        }
        if !hierarchy_fire {
            for name in old_stat
                .contributed_names
                .iter()
                .chain(new_slot.stat.contributed_names.iter())
            {
                if base_leaves.contains(name) {
                    hierarchy_fire = true;
                    break;
                }
            }
        }
    }

    let include_invalidated = if include_seeds.is_empty() {
        HashSet::new()
    } else {
        // Reverse reachability over the union of the old and new include
        // graphs, unbounded by the forward walk's depth cap: a superset of
        // every file whose bounded closure could contain a seed.
        let mut reverse: HashMap<String, Vec<String>> = HashMap::new();
        for (artifact_id, file) in files {
            for target in &engine.analysis(artifact_id).era.include_targets {
                reverse
                    .entry(target.clone())
                    .or_default()
                    .push(file.path().to_string());
            }
        }
        for ((_, old_file, _), (_, old_era)) in changed.iter().zip(&old_analyses) {
            for target in &old_era.include_targets {
                reverse
                    .entry(target.clone())
                    .or_default()
                    .push(old_file.path().to_string());
            }
        }
        let mut reached: HashSet<String> = HashSet::new();
        let mut stack: Vec<String> = include_seeds.iter().cloned().collect();
        while let Some(path) = stack.pop() {
            if !reached.insert(path.clone()) {
                continue;
            }
            if let Some(importers) = reverse.get(&path) {
                stack.extend(importers.iter().cloned());
            }
        }
        reached
    };

    for (artifact_id, file) in files {
        if relink.contains(artifact_id) {
            continue;
        }
        let slot = engine.analysis(artifact_id);
        let token_hit = intersects(&slot.stat.tokens, &changed_names);
        let module_hit = slot
            .era
            .module_targets
            .iter()
            .any(|target| changed_paths.contains(target));
        let include_hit = include_invalidated.contains(file.path());
        let hierarchy_hit = hierarchy_fire && slot.stat.walk_capable;
        if token_hit || module_hit || include_hit || hierarchy_hit {
            relink.insert(*artifact_id);
        }
    }
    Ok(relink.into_iter().collect())
}

fn intersects(a: &BTreeSet<String>, b: &BTreeSet<String>) -> bool {
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    small.iter().any(|item| large.contains(item))
}

/// Insert every index key `name` can be probed under, on both the probing and
/// the contributing side: the full name, its bare leaf, each `::` and `.`
/// segment, and the type-qualified adjacent suffix pair.
fn add_name_tokens(tokens: &mut BTreeSet<String>, name: &str) {
    if name.is_empty() {
        return;
    }
    tokens.insert(name.to_string());
    tokens.insert(bare_entity_name(name).to_string());
    let segments: Vec<&str> = name.split("::").collect();
    if segments.len() >= 2 {
        for segment in &segments {
            tokens.insert((*segment).to_string());
        }
        tokens.insert(format!(
            "{}::{}",
            segments[segments.len() - 2],
            segments[segments.len() - 1]
        ));
    }
    if name.contains('.') {
        for segment in name.split('.') {
            tokens.insert(segment.to_string());
        }
    }
}

fn analyze_file_static(parse: &FileParseData) -> FileStaticAnalysis {
    let mut tokens = BTreeSet::new();
    let mut walk_capable = false;
    for relation in &parse.relations {
        if is_call_extraction_incomplete_marker(relation) {
            continue;
        }
        add_name_tokens(&mut tokens, &relation.dst_name);
        if relation.kind == kin_model::RelationKind::Calls
            && (split_owner_method(&relation.dst_name).is_some()
                || split_scoped_receiver_method(&relation.dst_name).is_some())
        {
            walk_capable = true;
        }
    }

    let mut contributed_names = BTreeSet::new();
    for entity in &parse.entities {
        contributed_names.insert(entity.name.clone());
        contributed_names.insert(bare_entity_name(&entity.name).to_string());
    }

    let mut extends = Vec::new();
    let mut base_leaves = BTreeSet::new();
    for relation in &parse.relations {
        if relation.kind != kin_model::RelationKind::Extends {
            continue;
        }
        let pair = (relation.src_name.clone(), relation.dst_name.clone());
        if !extends.contains(&pair) {
            extends.push(pair);
        }
        base_leaves.insert(bare_entity_name(&relation.dst_name).to_string());
    }
    extends.sort();
    let mut class_like: Vec<(String, String)> = parse
        .entities
        .iter()
        .filter(|entity| is_class_like(Some(&entity.kind)))
        .map(|entity| (entity.name.clone(), format!("{:?}", entity.kind)))
        .collect();
    class_like.sort();
    class_like.dedup();
    let mut imports = Vec::new();
    if !extends.is_empty() {
        for import in &parse.imports {
            for spec in &import.specifiers {
                imports.push((
                    import.module_path.clone(),
                    spec.local_name.clone(),
                    spec.original_name.clone().unwrap_or_default(),
                ));
            }
        }
        imports.sort();
    }

    FileStaticAnalysis {
        tokens,
        contributed_names,
        hierarchy: FileHierarchyProjection {
            extends,
            class_like,
            imports,
        },
        base_leaves,
        walk_capable,
    }
}

fn analyze_file_era(parse: &FileParseData, known_files: &HashSet<&str>) -> FileEraAnalysis {
    let mut module_targets = BTreeSet::new();
    for import in &parse.imports {
        if let Some(target) =
            resolve_module_path(&parse.file_path, &import.module_path, known_files)
        {
            module_targets.insert(target);
        }
    }
    for relation in &parse.relations {
        if let Some(source) = relation
            .import_source
            .as_deref()
            .map(str::trim)
            .filter(|source| !source.is_empty())
        {
            if let Some(target) = resolve_module_path(&parse.file_path, source, known_files) {
                module_targets.insert(target);
            }
        }
    }
    let include_targets = resolve_include_targets(&parse.file_path, &parse.imports, known_files);
    FileEraAnalysis {
        module_targets,
        include_targets,
    }
}

/// An entity endpoint of a linked relation that the tree does not define.
struct AbsentEndpoint {
    entity_id: EntityId,
    is_destination: bool,
}

/// Report the first entity endpoint of `relation` that `entities` does not
/// define, source before destination. Non-entity endpoints are not part of the
/// entity state a change replays, so they are never reported.
fn absent_local_endpoint<V>(
    relation: &Relation,
    entities: &BTreeMap<EntityId, V>,
) -> Option<AbsentEndpoint> {
    [(relation.src, false), (relation.dst, true)]
        .into_iter()
        .find_map(|(node, is_destination)| {
            node.as_entity()
                .filter(|entity_id| !entities.contains_key(entity_id))
                .map(|entity_id| AbsentEndpoint {
                    entity_id,
                    is_destination,
                })
        })
}

fn stabilize_historical_entities(
    artifact_id: ArtifactId,
    old_entities: Vec<&Entity>,
    parsed_entities: &[Entity],
) -> Vec<Entity> {
    let mut matched = HashSet::<EntityId>::new();
    let mut in_use = HashSet::<EntityId>::new();
    let mut unmatched = Vec::new();
    let mut current = Vec::with_capacity(parsed_entities.len());

    for parsed in parsed_entities {
        let existing = old_entities
            .iter()
            .filter(|candidate| !matched.contains(&candidate.id))
            .copied()
            .find(|candidate| candidate.name == parsed.name && candidate.kind == parsed.kind)
            .or_else(|| {
                old_entities
                    .iter()
                    .filter(|candidate| !matched.contains(&candidate.id))
                    .copied()
                    .find(|candidate| {
                        candidate.name == parsed.name && candidate.file_origin == parsed.file_origin
                    })
            });
        let mut stabilized = parsed.clone();
        if let Some(old) = existing {
            stabilized.id = old.id;
            stabilized.lineage_parent = old.lineage_parent;
            stabilized.created_in = old.created_in;
            stabilized.superseded_by = old.superseded_by;
            matched.insert(old.id);
            in_use.insert(old.id);
        } else {
            unmatched.push(current.len());
        }
        current.push(stabilized);
    }

    // Deriving an identity from the parser identity alone can land on one this
    // same file already carries. Inheritance deliberately detaches an entity
    // from the position it was first parsed at, so a later definition that
    // takes over that position derives exactly the identity the moved entity
    // still holds: two conditionally compiled definitions of one name are
    // enough. Mint against the identities already in use so distinct
    // definitions can never collapse into one entity.
    for index in unmatched {
        let parser_id = parsed_entities[index].id;
        let mut identity = historical_entity_id(artifact_id, parser_id);
        let mut displacement = 0_u32;
        while !in_use.insert(identity) {
            displacement += 1;
            identity = displaced_historical_entity_id(artifact_id, parser_id, displacement);
        }
        current[index].id = identity;
    }

    current.sort_by_key(|entity| entity.id);
    current
}

fn historical_entity_id(artifact_id: ArtifactId, parser_id: EntityId) -> EntityId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin.historical-entity.v1\0");
    hasher.update(artifact_id.0.as_bytes());
    hasher.update(parser_id.0.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId(uuid::Uuid::from_bytes(bytes))
}

/// Derive the identity of a parsed entity whose primary derived identity is
/// already carried by another entity in the same file.
///
/// Kept separate from [`historical_entity_id`] so an identity only ever moves
/// when a collision actually forces it: every entity that can keep its primary
/// derivation keeps exactly the identity it had.
fn displaced_historical_entity_id(
    artifact_id: ArtifactId,
    parser_id: EntityId,
    displacement: u32,
) -> EntityId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin.historical-entity.displaced.v1\0");
    hasher.update(artifact_id.0.as_bytes());
    hasher.update(parser_id.0.as_bytes());
    hasher.update(displacement.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId(uuid::Uuid::from_bytes(bytes))
}

fn diff_entities(
    old: &BTreeMap<EntityId, Entity>,
    new: &BTreeMap<EntityId, Entity>,
) -> Vec<EntityDelta> {
    let mut deltas = Vec::new();
    for (id, old_entity) in old {
        match new.get(id) {
            Some(new_entity) if old_entity == new_entity => {}
            Some(new_entity) => deltas.push(EntityDelta::Modified {
                old: old_entity.clone(),
                new: new_entity.clone(),
            }),
            None => deltas.push(EntityDelta::Removed {
                old: old_entity.clone(),
            }),
        }
    }
    for (id, new_entity) in new {
        if !old.contains_key(id) {
            deltas.push(EntityDelta::Added {
                new: new_entity.clone(),
            });
        }
    }
    deltas.sort_by_key(EntityDelta::target_id);
    deltas
}

fn diff_relations(
    old: &BTreeMap<RelationId, Relation>,
    new: &BTreeMap<RelationId, Relation>,
) -> Vec<RelationDelta> {
    let mut deltas = Vec::new();
    for (id, old_relation) in old {
        match new.get(id) {
            Some(new_relation) if old_relation == new_relation => {}
            Some(new_relation) => deltas.push(RelationDelta::Modified {
                old: old_relation.clone(),
                new: new_relation.clone(),
            }),
            None => deltas.push(RelationDelta::Removed {
                old: old_relation.clone(),
            }),
        }
    }
    for (id, new_relation) in new {
        if !old.contains_key(id) {
            deltas.push(RelationDelta::Added {
                new: new_relation.clone(),
            });
        }
    }
    deltas.sort_by_key(RelationDelta::target_id);
    deltas
}

fn invalid(message: impl Into<String>) -> IndexError {
    IndexError::InvalidHistoricalSemantics(message.into())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use kin_git::{
        admit_semantic_git_import, capture_lossless_git_repository, plan_semantic_git_import,
    };
    use kin_model::{ChangeStore, EntityKind, RepositoryId};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn enriches_supported_languages_from_cas_without_semanticizing_other_artifacts() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);

        write(
            &repository,
            "src/lib.rs",
            b"pub fn helper() -> u8 { 1 }\npub fn answer() -> u8 { helper() }\n",
        );
        write(
            &repository,
            "service/app.py",
            b"def python_value():\n    return 9\n",
        );
        write(
            &repository,
            "compose.yaml",
            b"services:\n  app:\n    build: .\n",
        );
        write(&repository, "Dockerfile", b"FROM scratch\n");
        write(
            &repository,
            "archive/source.unknownlang",
            b"unsupported language remains exact\n",
        );
        write(&repository, "payload.rs", &[0, 255, 0, 128, 42]);
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "mixed exact tree"]);

        write(
            &repository,
            "src/lib.rs",
            b"pub fn helper() -> u8 { 1 }\npub fn answer() -> u8 { helper() + 1 }\n",
        );
        write(
            &repository,
            "compose.yaml",
            b"services:\n  app:\n    build:\n      context: .\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "change code and compose"]);

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-enrichment").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);

        let first = derive_historical_semantic_deltas(&plan.changes, &trees, &blob_store).unwrap();
        let second = derive_historical_semantic_deltas(&plan.changes, &trees, &blob_store).unwrap();
        assert_eq!(second, first);
        assert_eq!(first.len(), 2);

        let bindings = first
            .iter()
            .map(|delta| {
                (
                    delta.change_id,
                    delta.entity_deltas.clone(),
                    delta.relation_deltas.clone(),
                )
            })
            .collect::<Vec<_>>();
        let enriched = plan
            .clone()
            .with_historical_semantics(&blob_store, &bindings)
            .unwrap();
        enriched.validate(&blob_store).unwrap();
        let admitted = admit_semantic_git_import(&enriched, &blob_store).unwrap();
        admitted.validate(&blob_store).unwrap();
        assert_ne!(enriched.aliases, plan.aliases);
        assert_eq!(
            enriched.changes[1].parents,
            vec![enriched.changes[0].id],
            "semantic binding must reidentify parent edges"
        );
        assert_eq!(
            admitted.changes[0].entity_deltas,
            enriched.changes[0].entity_deltas
        );

        let initial_entities = first[0]
            .entity_deltas
            .iter()
            .filter_map(EntityDelta::new_state)
            .collect::<Vec<_>>();
        assert!(initial_entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Function && entity.name == "answer"));
        assert!(initial_entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Function && entity.name == "python_value"));
        assert!(initial_entities.iter().all(|entity| {
            entity
                .file_origin
                .as_ref()
                .is_some_and(|origin| origin.0 == "src/lib.rs" || origin.0 == "service/app.py")
        }));
        assert!(!first[0].relation_deltas.is_empty());

        let initial_answer = initial_entities
            .iter()
            .find(|entity| entity.name == "answer")
            .unwrap();
        let modified_answer = first[1]
            .entity_deltas
            .iter()
            .find_map(|delta| match delta {
                EntityDelta::Modified { old, new } if new.name == "answer" => Some((old, new)),
                _ => None,
            })
            .unwrap();
        assert_eq!(modified_answer.0.id, initial_answer.id);
        assert_eq!(modified_answer.1.id, initial_answer.id);

        let tip = trees.get(&plan.changes[1].id).unwrap();
        assert!(tip
            .artifact_at_path(&kin_model::RepoPath::from_utf8("compose.yaml").unwrap())
            .is_some());
        assert!(tip
            .artifact_at_path(
                &kin_model::RepoPath::from_utf8("archive/source.unknownlang").unwrap()
            )
            .is_some());
        assert!(tip
            .artifact_at_path(&kin_model::RepoPath::from_utf8("payload.rs").unwrap())
            .is_some());
    }

    #[test]
    fn preserves_secondary_parent_entity_identity_across_a_merge() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);
        write(&repository, "src/lib.rs", b"pub fn root() {}\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "root"]);

        git(&repository, &["checkout", "-b", "feature"]);
        write(&repository, "src/feature.rs", b"pub fn feature_only() {}\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "feature"]);

        git(&repository, &["checkout", "main"]);
        write(&repository, "src/main.rs", b"pub fn main_only() {}\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "main"]);
        git(
            &repository,
            &["merge", "--no-ff", "feature", "-m", "merge feature"],
        );

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-merge").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);
        let deltas = derive_historical_semantic_deltas(&plan.changes, &trees, &blob_store).unwrap();

        let feature_id = deltas
            .iter()
            .flat_map(|delta| &delta.entity_deltas)
            .filter_map(EntityDelta::new_state)
            .find(|entity| entity.name == "feature_only")
            .unwrap()
            .id;
        let merge_index = plan
            .changes
            .iter()
            .position(|change| change.parents.len() == 2)
            .unwrap();
        let merged_feature = deltas[merge_index]
            .entity_deltas
            .iter()
            .filter_map(EntityDelta::new_state)
            .find(|entity| entity.name == "feature_only")
            .unwrap();
        assert_eq!(merged_feature.id, feature_id);

        let bindings = deltas
            .iter()
            .map(|delta| {
                (
                    delta.change_id,
                    delta.entity_deltas.clone(),
                    delta.relation_deltas.clone(),
                )
            })
            .collect::<Vec<_>>();
        plan.with_historical_semantics(&blob_store, &bindings)
            .unwrap()
            .validate(&blob_store)
            .unwrap();
    }

    /// The shape that blocked every real repository: a commit that starts
    /// calling a symbol imported from another crate. The linker answers with a
    /// cross-repo placeholder destination that is absent from this repository's
    /// entity set by contract, so a change carrying that edge cannot be
    /// replayed. Admission must still bind the commit and the local call graph
    /// around it.
    #[test]
    fn calling_an_imported_external_symbol_stays_replayable() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);
        write(
            &repository,
            "src/main.rs",
            b"fn colored() -> bool {\n    true\n}\n\nfn main() {\n    let _ = colored();\n}\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "local call graph only"]);

        write(
            &repository,
            "src/main.rs",
            b"extern crate isatty;\n\nuse isatty::stdout_isatty;\n\nfn colored() -> bool {\n    true\n}\n\nfn main() {\n    let _ = colored() && stdout_isatty();\n}\n",
        );
        git(&repository, &["add", "--all"]);
        git(
            &repository,
            &["commit", "-m", "detect interactive terminal"],
        );

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-external-import").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);
        let deltas = derive_historical_semantic_deltas(&plan.changes, &trees, &blob_store).unwrap();

        let bindings = deltas
            .iter()
            .map(|delta| {
                (
                    delta.change_id,
                    delta.entity_deltas.clone(),
                    delta.relation_deltas.clone(),
                )
            })
            .collect::<Vec<_>>();
        let enriched = plan
            .with_historical_semantics(&blob_store, &bindings)
            .unwrap();
        enriched.validate(&blob_store).unwrap();
        let admitted = admit_semantic_git_import(&enriched, &blob_store).unwrap();

        let entity_ids = admitted
            .changes
            .iter()
            .flat_map(|change| &change.entity_deltas)
            .filter_map(EntityDelta::new_state)
            .map(|entity| entity.id)
            .collect::<HashSet<_>>();
        let bound_relations = admitted
            .changes
            .iter()
            .flat_map(|change| &change.relation_deltas)
            .filter_map(RelationDelta::new_state)
            .collect::<Vec<_>>();
        assert!(
            bound_relations
                .iter()
                .any(|relation| relation.kind == kin_model::RelationKind::Calls),
            "the local call graph must survive"
        );
        for relation in &bound_relations {
            for node in [relation.src, relation.dst] {
                if let kin_model::GraphNodeId::Entity(entity_id) = node {
                    assert!(
                        entity_ids.contains(&entity_id),
                        "relation {} names entity {entity_id}, which history never defines",
                        relation.id
                    );
                }
            }
        }

        let graph = kin_db::InMemoryGraph::new();
        for change in &admitted.changes {
            graph.create_change(change).unwrap();
        }
        let head = admitted
            .changes
            .iter()
            .map(|change| change.id)
            .find(|candidate| {
                !admitted
                    .changes
                    .iter()
                    .any(|change| change.parents.contains(candidate))
            })
            .unwrap();
        graph
            .resolve_graph_at(&head)
            .expect("admitted history must replay without a dangling relation");
    }

    /// Identity derivation is positional, inheritance is not. A definition that
    /// takes over the position an inherited entity was first parsed at derives
    /// that entity's identity, and two definitions of one name in one file must
    /// never collapse into a single entity because of it.
    #[test]
    fn a_definition_taking_an_inherited_position_keeps_its_own_identity() {
        let artifact_id = ArtifactId::new();
        let path = "src/output.rs";
        let moved = parsed_function(path, "print_entry_uncolorized", 2);
        let arrived = parsed_function(path, "print_entry_uncolorized", 6);
        let inherited = Entity {
            id: historical_entity_id(artifact_id, arrived.id),
            ..parsed_function(path, "print_entry_uncolorized", 6)
        };

        let stabilized =
            stabilize_historical_entities(artifact_id, vec![&inherited], &[moved, arrived]);

        assert_eq!(stabilized.len(), 2);
        assert_ne!(
            stabilized[0].id, stabilized[1].id,
            "two definitions must not share one identity"
        );
        assert!(
            stabilized.iter().any(|entity| entity.id == inherited.id),
            "the entity that matched must keep the identity it carried"
        );
    }

    /// The whole-history form of the same defect: one conditionally compiled
    /// pair is enough to make a tree claim one entity twice.
    #[test]
    fn conditionally_compiled_duplicates_of_one_name_enrich() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);
        write(
            &repository,
            "src/output.rs",
            b"fn head() {}\n\nfn tail() {}\n\nfn print_entry_uncolorized() {}\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "one definition"]);

        write(
            &repository,
            "src/output.rs",
            b"fn print_entry_uncolorized_base() {}\n#[cfg(not(unix))]\nfn print_entry_uncolorized() {}\n#[cfg(unix)]\nfn print_entry_uncolorized() {}\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "split by target"]);

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-conditional-duplicates").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);
        let deltas = derive_historical_semantic_deltas(&plan.changes, &trees, &blob_store).unwrap();

        let tip = deltas
            .last()
            .unwrap()
            .entity_deltas
            .iter()
            .filter_map(EntityDelta::new_state)
            .filter(|entity| entity.name == "print_entry_uncolorized")
            .map(|entity| entity.id)
            .collect::<HashSet<_>>();
        assert_eq!(
            tip.len(),
            2,
            "both definitions must reach history as distinct entities"
        );
    }

    fn parsed_function(path: &str, name: &str, start_line: u32) -> Entity {
        let pipeline = IndexPipeline::new();
        let body = format!("{}fn {name}() {{}}\n", "\n".repeat(start_line as usize - 1));
        let indexed = pipeline
            .index_file_content_with_tests(
                &FilePathId::new(path),
                body.as_bytes(),
                kin_blobs::Hash256::from_bytes(kin_blobs::digest_bytes(body.as_bytes())),
            )
            .unwrap()
            .indexed_file;
        indexed
            .entities
            .into_iter()
            .find(|entity| entity.name == name)
            .unwrap()
    }

    #[test]
    fn analysis_cache_retains_and_compares_the_exact_parse_allocation() {
        let artifact_id = ArtifactId::new();
        let path = "src/shared.rs";
        let first_parse = Arc::new(FileParseData {
            file_path: path.to_string(),
            entities: vec![parsed_function(path, "left_only", 1)],
            relations: Vec::new(),
            imports: Vec::new(),
        });
        let first_parse_weak = Arc::downgrade(&first_parse);
        let first_state = Arc::new(SemanticFileState {
            artifact_id,
            entry: TreeEntry::blob(kin_model::Hash256::from_bytes([1; 32]), false),
            completeness: ParseCompleteness::Full,
            parse: first_parse,
        });
        let mut first_files = BTreeMap::new();
        first_files.insert(artifact_id, first_state);
        let known_files = HashSet::from([path]);
        let mut engine = LinkEngine::new();
        let era = advance_link_era(&mut engine, &first_files);
        refresh_link_analyses(&mut engine, &first_files, era, &known_files);
        drop(first_files);

        assert!(
            first_parse_weak.upgrade().is_some(),
            "the cache must retain its identity allocation so its address cannot be recycled"
        );

        let second_state = Arc::new(SemanticFileState {
            artifact_id,
            entry: TreeEntry::blob(kin_model::Hash256::from_bytes([2; 32]), false),
            completeness: ParseCompleteness::Full,
            parse: Arc::new(FileParseData {
                file_path: path.to_string(),
                entities: vec![parsed_function(path, "right_only", 1)],
                relations: Vec::new(),
                imports: Vec::new(),
            }),
        });
        let mut second_files = BTreeMap::new();
        second_files.insert(artifact_id, second_state);
        let era = advance_link_era(&mut engine, &second_files);
        refresh_link_analyses(&mut engine, &second_files, era, &known_files);

        assert_eq!(engine.analyses.len(), 1);
        assert_eq!(
            engine.analysis(&artifact_id).entity_arcs[0].name,
            "right_only"
        );
        assert!(
            first_parse_weak.upgrade().is_none(),
            "replacing the exact input should release the stale cache allocation"
        );
    }

    #[test]
    fn history_link_verification_flag_is_case_insensitive() {
        for enabled in ["1", "true", "TRUE", "TrUe", "yes", "YES", "on", "ON"] {
            assert!(history_link_verify_enabled(enabled), "{enabled}");
        }
        for disabled in ["", "0", "false", "off", "no", "truthy"] {
            assert!(!history_link_verify_enabled(disabled), "{disabled}");
        }
    }

    #[test]
    fn fails_closed_when_history_is_not_parent_first() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);
        write(&repository, "src/lib.rs", b"pub fn one() {}\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "one"]);
        write(
            &repository,
            "src/lib.rs",
            b"pub fn one() {}\npub fn two() {}\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "two"]);

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-order").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);
        let reversed = plan.changes.iter().cloned().rev().collect::<Vec<_>>();

        let error = derive_historical_semantic_deltas(&reversed, &trees, &blob_store).unwrap_err();
        assert!(
            error.to_string().contains("was not enriched first"),
            "{error}"
        );
    }

    /// Build a Git fixture from parent-first (path, body) steps, where each
    /// step is one commit writing the given files, then enrich it with the
    /// batch cross-check forced on for every commit. The batch derivation is
    /// the oracle: any divergence in the incremental tree states or emitted
    /// deltas fails the derivation itself.
    fn enrich_verified(steps: &[&[(&str, &str)]]) -> Vec<HistoricalSemanticDelta> {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);
        for (index, step) in steps.iter().enumerate() {
            for (path, body) in *step {
                write(&repository, path, body.as_bytes());
            }
            git(&repository, &["add", "--all"]);
            git(&repository, &["commit", "-m", &format!("step {index}")]);
        }
        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-incremental-equivalence").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);
        derive_historical_semantic_deltas_verified(&plan.changes, &trees, &blob_store).unwrap()
    }

    /// Content-only commits: bodies change, cross-file callers must relink
    /// when their callee's name set changes, and untouched files carry
    /// forward. Every commit is cross-checked against the batch derivation.
    #[test]
    fn incremental_replay_matches_batch_on_content_edits() {
        let deltas = enrich_verified(&[
            &[
                ("src/a.rs", "pub fn alpha() -> u8 { 1 }\n"),
                ("src/b.rs", "pub fn beta() -> u8 { crate::a::alpha() }\n"),
                ("src/c.rs", "pub fn gamma() -> u8 { 3 }\n"),
            ],
            // Body-only edit: callers of alpha unaffected structurally.
            &[("src/a.rs", "pub fn alpha() -> u8 { 2 }\n")],
            // Rename alpha -> alpha_two: b's cross-file call must relink away.
            &[("src/a.rs", "pub fn alpha_two() -> u8 { 2 }\n")],
            // b now calls the new name; c stays untouched throughout.
            &[(
                "src/b.rs",
                "pub fn beta() -> u8 { crate::a::alpha_two() }\n",
            )],
        ]);
        assert_eq!(deltas.len(), 4);
    }

    /// A same-name definition appearing in another file changes ambiguity for
    /// an untouched caller; removing it changes it back.
    #[test]
    fn incremental_replay_matches_batch_on_ambiguity_shifts() {
        enrich_verified(&[
            &[
                ("src/caller.rs", "pub fn go() { helper(); }\n"),
                ("src/one.rs", "pub fn helper() {}\n"),
            ],
            // A second helper appears: the untouched caller's candidate set
            // widens and must relink.
            &[("src/two.rs", "pub fn helper() {}\npub fn other() {}\n")],
            // The second helper disappears again (content-only edit).
            &[("src/two.rs", "pub fn other() {}\n")],
        ]);
    }

    /// Structural commits: files added, removed, and renamed force whole-tree
    /// relinks that must still match the batch derivation exactly.
    #[test]
    fn incremental_replay_matches_batch_on_structural_commits() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);

        write(&repository, "src/lib.rs", b"pub fn one() {}\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "initial"]);

        write(
            &repository,
            "src/lib.rs",
            b"pub mod extra;\npub fn one() {}\n",
        );
        write(
            &repository,
            "src/extra.rs",
            b"pub fn two() { crate::one() }\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "add module"]);

        write(
            &repository,
            "src/extra.rs",
            b"pub fn two() { crate::one(); }\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "content edit"]);

        git(&repository, &["mv", "src/extra.rs", "src/renamed.rs"]);
        write(
            &repository,
            "src/lib.rs",
            b"pub mod renamed;\npub fn one() {}\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "rename module"]);

        fs::remove_file(repository.join("src/renamed.rs")).unwrap();
        write(
            &repository,
            "src/lib.rs",
            b"pub fn one() {}\npub fn three() {}\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "delete module"]);

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-structural-equivalence").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);
        let deltas =
            derive_historical_semantic_deltas_verified(&plan.changes, &trees, &blob_store).unwrap();
        assert_eq!(deltas.len(), 5);
    }

    /// Two reachable leaf heads can carry different versions of the same
    /// artifact after their temporary semantic states have been dropped. The
    /// persistent analysis cache must never confuse one head's parse payload
    /// for the other through allocator-address reuse.
    #[test]
    fn incremental_replay_matches_batch_across_divergent_leaf_heads() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);
        write(&repository, "src/shared.rs", b"pub fn root() {}\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "root"]);

        git(&repository, &["switch", "-c", "left"]);
        write(&repository, "src/shared.rs", b"pub fn left_only() {}\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "left leaf"]);

        git(&repository, &["switch", "main"]);
        git(&repository, &["switch", "-c", "right"]);
        write(&repository, "src/shared.rs", b"pub fn right_only() {}\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "right leaf"]);

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-divergent-leaf-heads").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);
        let deltas =
            derive_historical_semantic_deltas_verified(&plan.changes, &trees, &blob_store).unwrap();

        assert_eq!(deltas.len(), 3);
        let names = deltas
            .iter()
            .flat_map(|delta| &delta.entity_deltas)
            .filter_map(EntityDelta::new_state)
            .map(|entity| entity.name.as_str())
            .collect::<HashSet<_>>();
        assert!(names.contains("left_only"));
        assert!(names.contains("right_only"));
    }

    /// Python inheritance: an edit to a base class's hierarchy must relink the
    /// walk-capable caller even though the caller's own file never changed.
    #[test]
    fn incremental_replay_matches_batch_on_hierarchy_edits() {
        enrich_verified(&[
            &[
                (
                    "pkg/base.py",
                    "class Base:\n    def greet(self):\n        return 1\n",
                ),
                (
                    "pkg/mid.py",
                    "from base import Base\n\nclass Mid(Base):\n    pass\n",
                ),
                (
                    "pkg/use.py",
                    "from mid import Mid\n\nclass App(Mid):\n    def run(self):\n        return App.greet(self)\n",
                ),
            ],
            // Move greet out of Base: the walk from App must stop resolving.
            &[(
                "pkg/base.py",
                "class Base:\n    def farewell(self):\n        return 2\n",
            )],
            // Reintroduce greet.
            &[(
                "pkg/base.py",
                "class Base:\n    def greet(self):\n        return 3\n",
            )],
        ]);
    }

    /// Import rewiring: a caller's own import moves between modules, and a
    /// target module's exports change underneath an untouched importer.
    #[test]
    fn incremental_replay_matches_batch_on_import_rewiring() {
        enrich_verified(&[
            &[
                ("src/util.ts", "export function finalize() {}\n"),
                ("src/alt.ts", "export function finalize() {}\n"),
                (
                    "src/app.ts",
                    "import { finalize } from './util';\nexport function main() { finalize(); }\n",
                ),
            ],
            // The untouched importer's target module changes its exports.
            &[(
                "src/util.ts",
                "export function finalize() {}\nexport function extra() {}\n",
            )],
            // The importer itself rewires to the other module.
            &[(
                "src/app.ts",
                "import { finalize } from './alt';\nexport function main() { finalize(); }\n",
            )],
        ]);
    }

    /// Merge shape: two branches, both sides carrying semantic files, with the
    /// merge adopting each side's version. Parent-first replay must stay
    /// batch-identical through the merge commit.
    #[test]
    fn incremental_replay_matches_batch_across_merges() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);
        write(&repository, "src/shared.rs", b"pub fn shared() {}\n");
        write(&repository, "src/main_side.rs", b"pub fn main_side() {}\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "root"]);

        git(&repository, &["checkout", "-b", "feature"]);
        write(
            &repository,
            "src/feature.rs",
            b"pub fn feature() { crate::shared() }\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "feature"]);

        git(&repository, &["checkout", "main"]);
        write(
            &repository,
            "src/main_side.rs",
            b"pub fn main_side() { crate::shared() }\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "main work"]);
        git(
            &repository,
            &["merge", "--no-ff", "feature", "-m", "merge feature"],
        );
        write(
            &repository,
            "src/shared.rs",
            b"pub fn shared() -> u8 { 1 }\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "post-merge edit"]);

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-incremental-merge").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);
        derive_historical_semantic_deltas_verified(&plan.changes, &trees, &blob_store).unwrap();
    }

    fn trees_by_change(
        plan: &kin_git::SemanticGitImportPlan,
    ) -> BTreeMap<SemanticChangeId, ResolvedTree> {
        plan.aliases
            .iter()
            .map(|alias| {
                (
                    alias.change_id,
                    plan.commit_trees.get(&alias.oid).unwrap().clone(),
                )
            })
            .collect()
    }

    fn write(repository: &Path, relative: &str, body: &[u8]) {
        let path = repository.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn git(repository: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(repository)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", repository)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
