// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Display;
use std::path::Path;

use kin_model::{
    Entity, EntityFilter, EntityId, EntityStore, FilePathId, Relation, RelationId, RelationKind,
    RelationOrigin, SemanticChange,
};
use sha2::{Digest, Sha256};

use crate::error::{GitError, Result};
use crate::genesis::is_genesis_change;
use crate::import::commit_file_deltas;

const MAX_ENTITIES_PER_FILE: usize = 8;

pub fn mine_from_change_dag<G>(graph: &G, changes: &[SemanticChange]) -> Result<Vec<Relation>>
where
    G: EntityStore,
    G::Error: Display,
{
    let change_sets = changes
        .iter()
        .filter(|change| !is_genesis_change(change))
        .map(changed_files_from_change)
        .filter(|files| files.len() >= 2)
        .collect::<Vec<_>>();
    build_relations_from_change_sets(graph, &change_sets)
}

pub fn mine_from_git_log<G>(repo_path: &Path, graph: &G) -> Result<Vec<Relation>>
where
    G: EntityStore,
    G::Error: Display,
{
    let repo = gix::open(repo_path).map_err(|e| GitError::Git(e.to_string()))?;
    let head_ref = match repo.head_ref() {
        Ok(Some(head)) => head,
        Ok(None) => return Ok(Vec::new()),
        Err(err) => return Err(GitError::Git(err.to_string())),
    };
    let head_id = head_ref.id().detach();
    let walk = repo
        .rev_walk([head_id])
        .sorting(gix::revision::walk::Sorting::ByCommitTime(
            Default::default(),
        ))
        .all()
        .map_err(|e| GitError::Git(e.to_string()))?;

    let mut change_sets = Vec::new();
    for info_result in walk {
        let info = info_result.map_err(|e| GitError::Git(e.to_string()))?;
        let commit = info
            .id()
            .object()
            .map_err(|e| GitError::Git(e.to_string()))?
            .into_commit();
        let files = commit_file_deltas(&repo, &commit)?
            .into_iter()
            .map(|delta| delta.path)
            .collect::<BTreeSet<_>>();
        if files.len() >= 2 {
            change_sets.push(files);
        }
    }

    build_relations_from_change_sets(graph, &change_sets)
}

fn changed_files_from_change(change: &SemanticChange) -> BTreeSet<String> {
    change
        .artifact_deltas
        .iter()
        .map(|delta| delta.file_id.0.clone())
        .collect()
}

fn build_relations_from_change_sets<G>(
    graph: &G,
    change_sets: &[BTreeSet<String>],
) -> Result<Vec<Relation>>
where
    G: EntityStore,
    G::Error: Display,
{
    let mut touch_counts: HashMap<String, usize> = HashMap::new();
    let mut pair_counts: HashMap<(String, String), usize> = HashMap::new();

    for files in change_sets {
        let files = files.iter().collect::<Vec<_>>();
        for file in &files {
            *touch_counts.entry((**file).clone()).or_default() += 1;
        }
        for src in &files {
            for dst in &files {
                if src == dst {
                    continue;
                }
                *pair_counts
                    .entry(((**src).clone(), (**dst).clone()))
                    .or_default() += 1;
            }
        }
    }

    let mut entity_cache: HashMap<String, Vec<Entity>> = HashMap::new();
    let mut seen_relation_ids = HashSet::new();
    let mut relations = Vec::new();
    let mut sorted_pairs = pair_counts.into_iter().collect::<Vec<_>>();
    sorted_pairs.sort_by(|a, b| a.0.cmp(&b.0));

    for ((src_file, dst_file), pair_count) in sorted_pairs {
        let Some(src_touch_count) = touch_counts.get(&src_file).copied() else {
            continue;
        };
        if src_touch_count == 0 {
            continue;
        }

        let src_entities = entities_for_file(graph, &mut entity_cache, &src_file)?;
        let dst_entities = entities_for_file(graph, &mut entity_cache, &dst_file)?;
        if src_entities.is_empty() || dst_entities.is_empty() {
            continue;
        }

        let confidence = pair_count as f32 / src_touch_count as f32;
        for src_entity in src_entities {
            for dst_entity in &dst_entities {
                if src_entity.id == dst_entity.id {
                    continue;
                }
                let relation_id = cochange_relation_id(src_entity.id, dst_entity.id);
                if !seen_relation_ids.insert(relation_id) {
                    continue;
                }
                relations.push(Relation {
                    id: relation_id,
                    kind: RelationKind::CoChanges,
                    src: src_entity.id,
                    dst: dst_entity.id,
                    confidence,
                    origin: RelationOrigin::Inferred,
                    created_in: None,
                    import_source: None,
                });
            }
        }
    }

    Ok(relations)
}

fn entities_for_file<G>(
    graph: &G,
    cache: &mut HashMap<String, Vec<Entity>>,
    file: &str,
) -> Result<Vec<Entity>>
where
    G: EntityStore,
    G::Error: Display,
{
    if let Some(cached) = cache.get(file) {
        return Ok(cached.clone());
    }

    let filter = EntityFilter {
        file_path: Some(FilePathId::new(file)),
        ..Default::default()
    };
    let mut entities = graph
        .query_entities(&filter)
        .map_err(|e| GitError::Graph(e.to_string()))?;
    entities.sort_by(|a, b| {
        let a_parent = a.lineage_parent.is_some();
        let b_parent = b.lineage_parent.is_some();
        a_parent
            .cmp(&b_parent)
            .then_with(|| {
                a.span
                    .as_ref()
                    .map(|span| span.start_line)
                    .unwrap_or(u32::MAX)
                    .cmp(
                        &b.span
                            .as_ref()
                            .map(|span| span.start_line)
                            .unwrap_or(u32::MAX),
                    )
            })
            .then_with(|| a.name.cmp(&b.name))
    });
    if entities.len() > MAX_ENTITIES_PER_FILE {
        entities.truncate(MAX_ENTITIES_PER_FILE);
    }

    cache.insert(file.to_string(), entities.clone());
    Ok(entities)
}

fn cochange_relation_id(src: EntityId, dst: EntityId) -> RelationId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-cochange-v1:");
    hasher.update(src.0.as_bytes());
    hasher.update(dst.0.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    RelationId::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        ArtifactDelta, ArtifactDeltaKind, EntityKind, EntityMetadata, FingerprintAlgorithm,
        Hash256, LanguageId, SemanticFingerprint, SourceSpan, Visibility,
    };
    use std::process::Command;

    fn test_entity(name: &str, path: &str, line: u32) -> kin_model::Entity {
        kin_model::Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([1; 32]),
                behavior_hash: Hash256::from_bytes([2; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(path)),
            span: Some(SourceSpan {
                file: FilePathId::new(path),
                start_byte: 0,
                end_byte: 0,
                start_line: line,
                start_col: 1,
                end_line: line,
                end_col: 20,
            }),
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn init_git_repo(dir: &std::path::Path) -> bool {
        let git_init = Command::new("git").args(["init"]).current_dir(dir).output();
        match git_init {
            Ok(output) if output.status.success() => {
                let _ = Command::new("git")
                    .args(["config", "user.email", "test@test.com"])
                    .current_dir(dir)
                    .output();
                let _ = Command::new("git")
                    .args(["config", "user.name", "Test"])
                    .current_dir(dir)
                    .output();
                true
            }
            _ => false,
        }
    }

    #[test]
    fn change_dag_mining_emits_directional_file_scope_relations() {
        let graph = kin_db::InMemoryGraph::new();
        let alpha = test_entity("alpha", "src/a.rs", 1);
        let beta = test_entity("beta", "src/b.rs", 2);
        let gamma = test_entity("gamma", "src/c.rs", 3);
        graph.upsert_entity(&alpha).unwrap();
        graph.upsert_entity(&beta).unwrap();
        graph.upsert_entity(&gamma).unwrap();

        let changes = vec![
            SemanticChange {
                id: kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([1; 32])),
                parents: vec![],
                timestamp: kin_model::Timestamp::now(),
                author: kin_model::AuthorId::new("test"),
                message: "first".into(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![
                    ArtifactDelta {
                        file_id: FilePathId::new("src/a.rs"),
                        kind: ArtifactDeltaKind::Modified,
                        old_hash: None,
                        new_hash: None,
                    },
                    ArtifactDelta {
                        file_id: FilePathId::new("src/b.rs"),
                        kind: ArtifactDeltaKind::Modified,
                        old_hash: None,
                        new_hash: None,
                    },
                ],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            },
            SemanticChange {
                id: kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([2; 32])),
                parents: vec![kin_model::SemanticChangeId::from_hash(Hash256::from_bytes(
                    [1; 32],
                ))],
                timestamp: kin_model::Timestamp::now(),
                author: kin_model::AuthorId::new("test"),
                message: "second".into(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![
                    ArtifactDelta {
                        file_id: FilePathId::new("src/a.rs"),
                        kind: ArtifactDeltaKind::Modified,
                        old_hash: None,
                        new_hash: None,
                    },
                    ArtifactDelta {
                        file_id: FilePathId::new("src/c.rs"),
                        kind: ArtifactDeltaKind::Modified,
                        old_hash: None,
                        new_hash: None,
                    },
                ],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            },
        ];

        let relations = mine_from_change_dag(&graph, &changes).unwrap();
        let a_to_b = relations
            .iter()
            .find(|relation| relation.src == alpha.id && relation.dst == beta.id)
            .unwrap();
        let a_to_c = relations
            .iter()
            .find(|relation| relation.src == alpha.id && relation.dst == gamma.id)
            .unwrap();
        let b_to_a = relations
            .iter()
            .find(|relation| relation.src == beta.id && relation.dst == alpha.id)
            .unwrap();

        assert_eq!(a_to_b.kind, RelationKind::CoChanges);
        assert!((a_to_b.confidence - 0.5).abs() < f32::EPSILON);
        assert!((a_to_c.confidence - 0.5).abs() < f32::EPSILON);
        assert!((b_to_a.confidence - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn git_log_fallback_uses_real_changed_files() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping co-change git fallback test");
            return;
        }

        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/a.rs"), "fn alpha() {}\n").unwrap();
        std::fs::write(dir.path().join("src/b.rs"), "fn beta() {}\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        std::fs::write(
            dir.path().join("src/a.rs"),
            "fn alpha() { println!(\"a\"); }\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("src/c.rs"), "fn gamma() {}\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "followup"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        let graph = kin_db::InMemoryGraph::new();
        let alpha = test_entity("alpha", "src/a.rs", 1);
        let beta = test_entity("beta", "src/b.rs", 2);
        let gamma = test_entity("gamma", "src/c.rs", 3);
        graph.upsert_entity(&alpha).unwrap();
        graph.upsert_entity(&beta).unwrap();
        graph.upsert_entity(&gamma).unwrap();

        let relations = mine_from_git_log(dir.path(), &graph).unwrap();
        assert!(
            relations
                .iter()
                .any(|relation| relation.src == alpha.id && relation.dst == beta.id)
        );
        assert!(
            relations
                .iter()
                .any(|relation| relation.src == alpha.id && relation.dst == gamma.id)
        );
        assert!(
            !relations
                .iter()
                .any(|relation| relation.src == beta.id && relation.dst == gamma.id)
        );
    }
}
