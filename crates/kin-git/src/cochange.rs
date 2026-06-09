// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Display;
use std::path::Path;

use kin_model::{
    Entity, EntityFilter, EntityId, EntityStore, FilePathId, Relation, RelationId, RelationKind,
    RelationOrigin, SemanticChange,
};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::error::{GitError, Result};
use crate::genesis::is_genesis_change;
use crate::import::commit_file_deltas;

const MAX_ENTITIES_PER_FILE: usize = 8;

fn cochange_env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

pub fn mine_from_change_dag<G>(graph: &G, changes: &[SemanticChange]) -> Result<Vec<Relation>>
where
    G: EntityStore + Sync,
    G::Error: Display,
{
    let _span = tracing::info_span!(
        "kin.git.cochange.mine_from_change_dag",
        changes = changes.len()
    )
    .entered();
    let max_files_per_commit = cochange_env_usize("KIN_COCHANGE_MAX_FILES_PER_COMMIT", 20);
    let change_sets = {
        let _span = tracing::info_span!("kin.git.cochange.collect_change_sets").entered();
        changes
            .iter()
            .filter(|change| !is_genesis_change(change))
            .map(changed_files_from_change)
            .filter(|files| files.len() >= 2 && files.len() <= max_files_per_commit)
            .collect::<Vec<_>>()
    };
    build_relations_from_change_sets(graph, &change_sets)
}

fn open_repo(path: &Path) -> std::result::Result<gix::Repository, gix::open::Error> {
    let dot_git = path.join(".git");
    if dot_git.is_dir() {
        gix::open(dot_git)
    } else {
        gix::open(path)
    }
}

pub fn mine_from_git_log<G>(repo_path: &Path, graph: &G) -> Result<Vec<Relation>>
where
    G: EntityStore + Sync,
    G::Error: Display,
{
    mine_from_git_log_with_limit(repo_path, graph, 0)
}

pub fn mine_from_git_log_with_limit<G>(
    repo_path: &Path,
    graph: &G,
    max_commits: usize,
) -> Result<Vec<Relation>>
where
    G: EntityStore + Sync,
    G::Error: Display,
{
    let _span = tracing::info_span!(
        "kin.git.cochange.mine_from_git_log",
        repo = %repo_path.display(),
        max_commits = max_commits
    )
    .entered();
    let repo = open_repo(repo_path).map_err(|e| GitError::Git(e.to_string()))?;
    let head_id = match repo.head_ref() {
        Ok(Some(head)) => head.id().detach(),
        Ok(None) => {
            // Detached HEAD — resolve via head_id() instead
            match repo.head_id() {
                Ok(id) => id.detach(),
                Err(_) => return Ok(Vec::new()),
            }
        }
        Err(err) => return Err(GitError::Git(err.to_string())),
    };
    let walk = repo
        .rev_walk([head_id])
        .sorting(gix::revision::walk::Sorting::ByCommitTime(
            Default::default(),
        ))
        .all()
        .map_err(|e| GitError::Git(e.to_string()))?;

    // Phase 1: Collect OIDs (cheap sequential walk) — propagate walk errors
    let oids: Vec<gix::ObjectId> = {
        let _span = tracing::info_span!("kin.git.cochange.collect_oids").entered();
        let iter = walk.map(|r| {
            r.map(|info| info.id().detach())
                .map_err(|e| GitError::Git(e.to_string()))
        });
        if max_commits > 0 {
            iter.take(max_commits).collect::<Result<Vec<_>>>()?
        } else {
            iter.collect::<Result<Vec<_>>>()?
        }
    };

    // Phase 2: Parallel tree diffs — propagate object/diff errors
    let max_files_per_commit = cochange_env_usize("KIN_COCHANGE_MAX_FILES_PER_COMMIT", 20);
    let thread_safe = repo.into_sync();
    let change_sets: Vec<BTreeSet<String>> = {
        let _span =
            tracing::info_span!("kin.git.cochange.diff_commits", commits = oids.len()).entered();
        oids.par_iter()
            .map(|oid| {
                let local = thread_safe.to_thread_local();
                let commit = local
                    .find_object(*oid)
                    .map_err(|e| GitError::Git(e.to_string()))?
                    .into_commit();
                let files = commit_file_deltas(&local, &commit)?
                    .into_iter()
                    .map(|d| d.path)
                    .collect::<BTreeSet<_>>();
                Ok(files)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|files| files.len() >= 2 && files.len() <= max_files_per_commit)
            .collect()
    };

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
    G: EntityStore + Sync,
    G::Error: Display,
{
    let _span = tracing::info_span!(
        "kin.git.cochange.build_relations_from_change_sets",
        change_sets = change_sets.len()
    )
    .entered();
    let (touch_counts, pair_counts) = {
        let _span = tracing::info_span!("kin.git.cochange.count_pairs").entered();
        change_sets
            .par_iter()
            .fold(
                || {
                    (
                        HashMap::<String, usize>::new(),
                        HashMap::<(String, String), usize>::new(),
                    )
                },
                |(mut tc, mut pc), files| {
                    let files: Vec<_> = files.iter().collect();
                    for file in &files {
                        *tc.entry((**file).clone()).or_default() += 1;
                    }
                    for src in &files {
                        for dst in &files {
                            if src != dst {
                                *pc.entry(((**src).clone(), (**dst).clone())).or_default() += 1;
                            }
                        }
                    }
                    (tc, pc)
                },
            )
            .reduce(
                || (HashMap::new(), HashMap::new()),
                |(mut tc1, mut pc1), (tc2, pc2)| {
                    for (k, v) in tc2 {
                        *tc1.entry(k).or_default() += v;
                    }
                    for (k, v) in pc2 {
                        *pc1.entry(k).or_default() += v;
                    }
                    (tc1, pc1)
                },
            )
    };

    // Pre-populate entity cache in parallel
    let unique_files: HashSet<String> = pair_counts
        .keys()
        .flat_map(|(s, d)| [s.clone(), d.clone()])
        .collect();

    let entity_cache: HashMap<String, Vec<Entity>> = {
        let _span = tracing::info_span!(
            "kin.git.cochange.preload_entity_cache",
            files = unique_files.len()
        )
        .entered();
        unique_files
            .into_par_iter()
            .map(|file| {
                let filter = EntityFilter {
                    file_path: Some(FilePathId::new(&file)),
                    ..Default::default()
                };
                let mut entities = graph
                    .query_entities(&filter)
                    .map_err(|e| GitError::Graph(e.to_string()))?;
                entities.sort_by(|a, b| {
                    a.lineage_parent
                        .is_some()
                        .cmp(&b.lineage_parent.is_some())
                        .then_with(|| {
                            a.span
                                .as_ref()
                                .map(|s| s.start_line)
                                .unwrap_or(u32::MAX)
                                .cmp(&b.span.as_ref().map(|s| s.start_line).unwrap_or(u32::MAX))
                        })
                        .then_with(|| a.name.cmp(&b.name))
                });
                if entities.len() > MAX_ENTITIES_PER_FILE {
                    entities.truncate(MAX_ENTITIES_PER_FILE);
                }
                Ok((file, entities))
            })
            .collect::<Result<HashMap<_, _>>>()?
    };

    let mut seen_relation_ids = HashSet::new();
    let mut relations = Vec::new();
    let mut sorted_pairs = pair_counts.into_iter().collect::<Vec<_>>();
    sorted_pairs.sort_by(|a, b| a.0.cmp(&b.0));

    // Filter out hub files that co-change with too many unique partners
    let max_fan_out = cochange_env_usize("KIN_COCHANGE_MAX_FAN_OUT", 15);
    let mut partner_counts: HashMap<String, HashSet<String>> = HashMap::new();
    for ((src, dst), _count) in &sorted_pairs {
        partner_counts
            .entry(src.clone())
            .or_default()
            .insert(dst.clone());
        partner_counts
            .entry(dst.clone())
            .or_default()
            .insert(src.clone());
    }
    let hub_files: HashSet<String> = partner_counts
        .into_iter()
        .filter(|(_, partners)| partners.len() > max_fan_out)
        .map(|(file, _)| file)
        .collect();
    if !hub_files.is_empty() {
        tracing::info!(
            hub_files = hub_files.len(),
            "cochange: filtered hub files with >{max_fan_out} unique partners"
        );
    }
    sorted_pairs.retain(|((src, dst), _)| !hub_files.contains(src) && !hub_files.contains(dst));

    {
        let _span = tracing::info_span!(
            "kin.git.cochange.materialize_relations",
            pairs = sorted_pairs.len()
        )
        .entered();
        for ((src_file, dst_file), pair_count) in sorted_pairs {
            let Some(src_touch_count) = touch_counts.get(&src_file).copied() else {
                continue;
            };
            if src_touch_count == 0 {
                continue;
            }

            let (Some(src_entities), Some(dst_entities)) =
                (entity_cache.get(&src_file), entity_cache.get(&dst_file))
            else {
                continue;
            };
            if src_entities.is_empty() || dst_entities.is_empty() {
                continue;
            }

            let confidence = pair_count as f32 / src_touch_count as f32;
            for src_entity in src_entities {
                for dst_entity in dst_entities {
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
                        src: kin_model::GraphNodeId::Entity(src_entity.id),
                        dst: kin_model::GraphNodeId::Entity(dst_entity.id),
                        confidence,
                        origin: RelationOrigin::Inferred,
                        created_in: None,
                        import_source: None,
                        evidence: Vec::new(),
                    });
                }
            }
        }
    }

    Ok(relations)
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
        ArtifactDelta, ArtifactDeltaKind, EntityKind, EntityMetadata, EntityRole,
        FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, SemanticFingerprint, SourceSpan,
        Visibility,
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
            role: EntityRole::Source,
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
            .find(|relation| {
                relation.src == GraphNodeId::Entity(alpha.id)
                    && relation.dst == GraphNodeId::Entity(beta.id)
            })
            .unwrap();
        let a_to_c = relations
            .iter()
            .find(|relation| {
                relation.src == GraphNodeId::Entity(alpha.id)
                    && relation.dst == GraphNodeId::Entity(gamma.id)
            })
            .unwrap();
        let b_to_a = relations
            .iter()
            .find(|relation| {
                relation.src == GraphNodeId::Entity(beta.id)
                    && relation.dst == GraphNodeId::Entity(alpha.id)
            })
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
        assert!(relations.iter().any(|relation| {
            relation.src == GraphNodeId::Entity(alpha.id)
                && relation.dst == GraphNodeId::Entity(beta.id)
        }));
        assert!(relations.iter().any(|relation| {
            relation.src == GraphNodeId::Entity(alpha.id)
                && relation.dst == GraphNodeId::Entity(gamma.id)
        }));
        assert!(!relations.iter().any(|relation| {
            relation.src == GraphNodeId::Entity(beta.id)
                && relation.dst == GraphNodeId::Entity(gamma.id)
        }));
    }

    #[test]
    fn git_log_limit_restricts_cochange_to_recent_commits() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping co-change git limit test");
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

        std::fs::write(dir.path().join("src/c.rs"), "fn gamma() {}\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "middle"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        std::fs::write(
            dir.path().join("src/a.rs"),
            "fn alpha() { println!(\"latest\"); }\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("src/d.rs"), "fn delta() {}\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "latest"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        let graph = kin_db::InMemoryGraph::new();
        let alpha = test_entity("alpha", "src/a.rs", 1);
        let beta = test_entity("beta", "src/b.rs", 2);
        let gamma = test_entity("gamma", "src/c.rs", 3);
        let delta = test_entity("delta", "src/d.rs", 4);
        graph.upsert_entity(&alpha).unwrap();
        graph.upsert_entity(&beta).unwrap();
        graph.upsert_entity(&gamma).unwrap();
        graph.upsert_entity(&delta).unwrap();

        let relations = mine_from_git_log_with_limit(dir.path(), &graph, 1).unwrap();
        assert!(relations.iter().any(|relation| {
            relation.src == GraphNodeId::Entity(alpha.id)
                && relation.dst == GraphNodeId::Entity(delta.id)
        }));
        assert!(!relations.iter().any(|relation| {
            relation.src == GraphNodeId::Entity(alpha.id)
                && relation.dst == GraphNodeId::Entity(beta.id)
        }));
        assert!(!relations.iter().any(|relation| {
            relation.src == GraphNodeId::Entity(alpha.id)
                && relation.dst == GraphNodeId::Entity(gamma.id)
        }));
    }
}
