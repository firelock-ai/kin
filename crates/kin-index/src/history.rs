// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Deterministic semantic enrichment for exact historical trees.
//!
//! This boundary never reads a checkout. It derives supported-language
//! entities and relations solely from graph-owned resolved trees and immutable
//! CAS bodies. Every other artifact remains represented by the exact tree even
//! when it has no language adapter.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use kin_blobs::BlobStore;
use kin_model::{
    ArtifactId, ChangeOrigin, Entity, EntityDelta, EntityId, FilePathId, ParseCompleteness,
    Relation, RelationDelta, RelationId, ResolvedTree, SemanticChange, SemanticChangeId, TreeEntry,
};
use sha2::{Digest, Sha256};

use crate::classifier::{FileClassification, FileClassifier};
use crate::error::{IndexError, Result};
use crate::linker::{
    link_cross_file_with_completeness, ArtifactIdentityMap, FileParseCompletenessMap, FileParseData,
};
use crate::pipeline::IndexPipeline;

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

#[derive(Clone)]
struct SemanticFileState {
    artifact_id: ArtifactId,
    path: String,
    entry: TreeEntry,
    completeness: ParseCompleteness,
    entities: Vec<Entity>,
    relations: Vec<kin_parser::ExtractedRelation>,
    imports: Vec<kin_parser::FileImport>,
}

#[derive(Clone, Default)]
struct SemanticTreeState {
    files: BTreeMap<ArtifactId, SemanticFileState>,
    entities: BTreeMap<EntityId, Entity>,
    relations: BTreeMap<RelationId, Relation>,
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
        let empty_parent = SemanticTreeState::default();
        let first_parent = parent_states.first().copied().unwrap_or(&empty_parent);
        let tree = trees.get(&change.id).ok_or_else(|| {
            invalid(format!(
                "change {} has no exact resolved tree for semantic enrichment",
                change.id
            ))
        })?;
        let current = semantic_state_for_tree(tree, &parent_states, blob_store, &pipeline)?;
        let entity_deltas = diff_entities(&first_parent.entities, &current.entities);
        let relation_deltas = diff_relations(&first_parent.relations, &current.relations);

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
) -> Result<SemanticTreeState> {
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
                .filter(|file| file.path == path && file.entry == artifact.entry)
        }) {
            if files
                .insert(artifact.artifact_id, existing.clone())
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
            .flat_map(|file| file.entities.iter())
            .collect::<Vec<_>>();
        let entities =
            stabilize_historical_entities(artifact.artifact_id, old_entities, &parsed.entities);
        let state = SemanticFileState {
            artifact_id: artifact.artifact_id,
            path: path.to_string(),
            entry: artifact.entry,
            completeness: parsed.completeness,
            entities,
            relations: parsed.relations,
            imports: parsed.imports,
        };
        if files.insert(artifact.artifact_id, state).is_some() {
            return Err(invalid(format!(
                "tree assigns artifact {:?} to multiple semantic files",
                artifact.artifact_id
            )));
        }
    }

    let mut parse_data = Vec::with_capacity(files.len());
    let mut completeness = FileParseCompletenessMap::new();
    let mut artifact_ids = ArtifactIdentityMap::new();
    let mut entities = BTreeMap::new();
    for file in files.values() {
        if artifact_ids
            .insert(file.path.clone(), file.artifact_id)
            .is_some()
        {
            return Err(invalid(format!(
                "tree contains more than one semantic artifact at {}",
                file.path
            )));
        }
        completeness.insert(file.path.clone(), file.completeness.clone());
        for entity in &file.entities {
            if entities.insert(entity.id, entity.clone()).is_some() {
                return Err(invalid(format!(
                    "semantic entity identity {:?} is duplicated in one tree",
                    entity.id
                )));
            }
        }
        parse_data.push(FileParseData {
            file_path: file.path.clone(),
            entities: file.entities.clone(),
            relations: file.relations.clone(),
            imports: file.imports.clone(),
        });
    }
    parse_data.sort_by(|left, right| left.file_path.cmp(&right.file_path));

    let linked = link_cross_file_with_completeness(&parse_data, &artifact_ids, &completeness)?;
    let mut relations = BTreeMap::new();
    for relation in linked {
        if relations.insert(relation.id, relation).is_some() {
            return Err(invalid(
                "cross-file linker returned a duplicate relation identity",
            ));
        }
    }

    Ok(SemanticTreeState {
        files,
        entities,
        relations,
    })
}

fn stabilize_historical_entities(
    artifact_id: ArtifactId,
    old_entities: Vec<&Entity>,
    parsed_entities: &[Entity],
) -> Vec<Entity> {
    let mut matched = HashSet::<EntityId>::new();
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
        } else {
            stabilized.id = historical_entity_id(artifact_id, parsed.id);
        }
        current.push(stabilized);
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
    use kin_model::{EntityKind, RepositoryId};
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
