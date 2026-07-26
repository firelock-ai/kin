// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Reconstructive commit-delta computation for `command_commit`.
//!
//! Computes entity, relation, and exact tree deltas by diffing current graph
//! state against the last-committed change-DAG node.  This approach is
//! robust regardless of when the reconcile loop drained the working-copy
//! overlay — the overlay is never consulted here.
//!
//! ## Algorithm
//!
//! 1. Resolve the exact repository-authority parent state.
//! 2. Take one coherent snapshot of the live admitted graph workspace.
//! 3. Diff current vs committed to produce typed `EntityDelta`,
//!    `RelationDelta`, and `TreeDelta` slices.
//!
//! Because `apply_overlay_to_graph` folds reconcile mutations into the
//! primary graph before clearing the overlay, `graph.list_all_entities()`
//! already reflects the current working state — diffing against the DAG
//! baseline captures exactly what changed since the last commit.

use std::collections::BTreeMap;

use kin_db::{GraphSnapshot, InMemoryGraph};
use kin_model::{
    graph::ResolvedGraphState, ChangeStore, EntityDelta, Hash256, RelationDelta, RepoPath,
    ResolvedTree, SemanticChangeId, TreeDelta, TreeEntry,
};

use crate::error::{DaemonError, Result};

/// The three delta slices that constitute a semantic commit.
#[derive(Debug)]
pub struct CommitDeltas {
    pub entity_deltas: Vec<EntityDelta>,
    pub relation_deltas: Vec<RelationDelta>,
    pub tree_deltas: Vec<TreeDelta>,
    /// Exact graph-owned tree that the change must resolve to.
    pub expected_tree: ResolvedTree,
}

/// Compute commit deltas by diffing current graph state against the
/// last-committed change-DAG node (`branch_head`).
///
/// Returns empty delta slices when nothing has changed since the last commit,
/// and non-empty slices when entities, relations, or files have been modified.
pub fn compute_deltas_vs_last_commit(
    graph: &InMemoryGraph,
    branch_head: &SemanticChangeId,
) -> Result<CommitDeltas> {
    let committed = graph
        .resolve_graph_at(branch_head)
        .map_err(DaemonError::Graph)?;
    compute_deltas_from_resolved_state(graph, committed)
}

/// Diff the live admitted graph against one repository-v6 authority lease.
///
/// The baseline comes exclusively from the persisted semantic history. The
/// live side is the already-admitted graph workspace; no checkout is read and
/// no artifact identity is inferred here. `None` is an unborn repository and
/// therefore has an exact empty baseline.
pub fn compute_deltas_vs_repository_authority(
    graph: &InMemoryGraph,
    authority_snapshot: &GraphSnapshot,
    parent: Option<&SemanticChangeId>,
) -> Result<CommitDeltas> {
    let committed = match parent {
        Some(parent) => {
            let mut snapshot = authority_snapshot.clone();
            snapshot.repository_authority = None;
            InMemoryGraph::from_snapshot(snapshot)
                .map_err(DaemonError::Graph)?
                .resolve_graph_at(parent)
                .map_err(DaemonError::Graph)?
        }
        None => ResolvedGraphState {
            entities: Default::default(),
            relations: Default::default(),
            entity_revisions: Default::default(),
            tree: ResolvedTree::default(),
            entity_tombstones: Default::default(),
            relation_tombstones: Default::default(),
        },
    };
    compute_deltas_from_resolved_state(graph, committed)
}

fn compute_deltas_from_resolved_state(
    graph: &InMemoryGraph,
    committed: ResolvedGraphState,
) -> Result<CommitDeltas> {
    // One coherent live snapshot keeps entity, relation, and exact-tree deltas
    // on the same graph generation.
    let current = graph.to_snapshot();

    let mut entity_deltas = Vec::new();
    for entity in current.entities.values() {
        match committed.entities.get(&entity.id) {
            None => {
                entity_deltas.push(EntityDelta::Added {
                    new: entity.clone(),
                });
            }
            Some(committed) if kin_index::entity_semantics_changed(committed, entity) => {
                entity_deltas.push(EntityDelta::Modified {
                    old: committed.clone(),
                    new: entity.clone(),
                });
            }
            _ => {}
        }
    }
    for (entity_id, entity) in &committed.entities {
        if !current.entities.contains_key(entity_id) {
            entity_deltas.push(EntityDelta::Removed {
                old: entity.clone(),
            });
        }
    }
    entity_deltas.sort_by_key(EntityDelta::target_id);

    let mut relation_deltas = Vec::new();
    for relation in current.relations.values() {
        match committed.relations.get(&relation.id) {
            None => relation_deltas.push(RelationDelta::Added {
                new: relation.clone(),
            }),
            Some(old) if old != relation => {
                relation_deltas.push(RelationDelta::Modified {
                    old: old.clone(),
                    new: relation.clone(),
                });
            }
            _ => {}
        }
    }
    for (relation_id, relation) in &committed.relations {
        if !current.relations.contains_key(relation_id) {
            relation_deltas.push(RelationDelta::Removed {
                old: relation.clone(),
            });
        }
    }
    relation_deltas.sort_by_key(RelationDelta::target_id);

    let expected_tree = current.resolved_tree;
    let tree_deltas = kin_core::exact_tree_correction(&committed.tree, &expected_tree)?;

    Ok(CommitDeltas {
        entity_deltas,
        relation_deltas,
        tree_deltas,
        expected_tree,
    })
}

/// Turn one complete host scan into exact graph entries.
///
/// Graph-only entries (currently Gitlinks) are copied from the parent tree:
/// their host checkout is neither membership evidence nor an identity source.
pub(crate) fn observed_tree_from_complete_scan(
    blobs: &kin_blobs::BlobStore,
    scan: &kin_index::CompleteRepositoryScan,
    previous: &ResolvedTree,
) -> Result<BTreeMap<RepoPath, TreeEntry>> {
    let mut observed = previous
        .artifacts_by_path()
        .filter(|artifact| matches!(artifact.entry, TreeEntry::Gitlink { .. }))
        .map(|artifact| (artifact.path.clone(), artifact.entry))
        .collect::<BTreeMap<_, _>>();

    for scanned in scan.entries() {
        let content = read_scanned_entry(scanned)?;
        let blob_digest = blobs.write(&content).map_err(DaemonError::from)?;
        if blob_digest.0 != scanned.content_hash {
            return Err(DaemonError::Io(std::io::Error::other(format!(
                "repository entry changed after complete scan: {}",
                scanned.repo_path
            ))));
        }
        let entry = match scanned.kind {
            kin_index::ScannedEntryKind::Regular { executable } => {
                TreeEntry::blob(Hash256::from_bytes(blob_digest.0), executable)
            }
            kin_index::ScannedEntryKind::Symlink => {
                TreeEntry::symlink(Hash256::from_bytes(blob_digest.0))
            }
        };
        observed.insert(scanned.repo_path.clone(), entry);
    }

    Ok(observed)
}

fn read_scanned_entry(scanned: &kin_index::ScannedRepositoryEntry) -> Result<Vec<u8>> {
    kin_index::read_verified_scanned_entry(scanned).map_err(DaemonError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{ArtifactId, EntityStore, FilePathId, LocatedEntry};

    use std::sync::Arc;

    use kin_blobs::BlobStore;
    use kin_model::{
        AuthorId, EntityKind, EntityMetadata, FingerprintAlgorithm, LanguageId, ResolvedArtifact,
        SemanticFingerprint, Timestamp, Visibility,
    };

    #[test]
    fn exact_tree_scan_fails_loud_when_root_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        assert!(kin_index::scan_repository(
            &missing,
            &kin_index::RepositoryIgnore::default(),
            std::iter::empty()
        )
        .is_err());
    }

    fn resolved_tree(artifacts: Vec<(ArtifactId, RepoPath, TreeEntry)>) -> ResolvedTree {
        ResolvedTree::from_artifacts(
            artifacts
                .into_iter()
                .map(|(artifact_id, path, entry)| ResolvedArtifact::new(artifact_id, path, entry)),
        )
        .unwrap()
    }

    #[test]
    fn exact_tree_planner_preserves_artifact_identity_across_a_unique_move() {
        let artifact_id = ArtifactId::new();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x11; 32]), false);
        let old_path = RepoPath::from_utf8("src/old.rs").unwrap();
        let new_path = RepoPath::from_utf8("src/new.rs").unwrap();
        let previous = resolved_tree(vec![(artifact_id, old_path.clone(), entry)]);

        let deltas = kin_core::plan_observed_tree_deltas(
            &previous,
            BTreeMap::from([(new_path.clone(), entry)]),
        )
        .unwrap();

        assert_eq!(
            deltas,
            vec![TreeDelta::Updated {
                artifact_id,
                old: LocatedEntry::new(old_path, entry),
                new: LocatedEntry::new(new_path.clone(), entry),
            }]
        );
        let next = previous.apply(&deltas).unwrap();
        assert_eq!(next.get(&artifact_id).unwrap().path, new_path);
    }

    #[test]
    fn exact_tree_planner_handles_move_plus_path_reuse_atomically() {
        let moved_id = ArtifactId::new();
        let moved_entry = TreeEntry::blob(Hash256::from_bytes([0x22; 32]), false);
        let replacement_entry = TreeEntry::blob(Hash256::from_bytes([0x33; 32]), true);
        let reused_path = RepoPath::from_utf8("compose.yaml").unwrap();
        let destination = RepoPath::from_utf8("deploy/compose.yaml").unwrap();
        let previous = resolved_tree(vec![(moved_id, reused_path.clone(), moved_entry)]);

        let deltas = kin_core::plan_observed_tree_deltas(
            &previous,
            BTreeMap::from([
                (reused_path.clone(), replacement_entry),
                (destination.clone(), moved_entry),
            ]),
        )
        .unwrap();
        let next = previous.apply(&deltas).unwrap();

        assert_eq!(next.get(&moved_id).unwrap().path, destination);
        let replacement = next.artifact_at_path(&reused_path).unwrap();
        assert_ne!(replacement.artifact_id, moved_id);
        assert_eq!(replacement.entry, replacement_entry);
    }

    #[test]
    fn exact_tree_planner_supports_swaps_and_non_utf8_paths() {
        let left_id = ArtifactId::new();
        let right_id = ArtifactId::new();
        let left_entry = TreeEntry::blob(Hash256::from_bytes([0x44; 32]), false);
        let right_entry = TreeEntry::symlink(Hash256::from_bytes([0x55; 32]));
        let left_path = RepoPath::from_bytes(b"left-\xff".to_vec()).unwrap();
        let right_path = RepoPath::from_utf8("right-link").unwrap();
        let previous = resolved_tree(vec![
            (left_id, left_path.clone(), left_entry),
            (right_id, right_path.clone(), right_entry),
        ]);

        let deltas = kin_core::plan_observed_tree_deltas(
            &previous,
            BTreeMap::from([
                (left_path.clone(), right_entry),
                (right_path.clone(), left_entry),
            ]),
        )
        .unwrap();
        let next = previous.apply(&deltas).unwrap();

        assert_eq!(next.get(&left_id).unwrap().path, right_path);
        assert_eq!(next.get(&right_id).unwrap().path, left_path);
    }

    #[test]
    fn exact_tree_planner_fails_closed_on_duplicate_move_candidates() {
        let artifact_id = ArtifactId::new();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x66; 32]), false);
        let previous = resolved_tree(vec![(
            artifact_id,
            RepoPath::from_utf8("old").unwrap(),
            entry,
        )]);
        let observed = BTreeMap::from([
            (RepoPath::from_utf8("copy-a").unwrap(), entry),
            (RepoPath::from_utf8("copy-b").unwrap(), entry),
        ]);

        let error = kin_core::plan_observed_tree_deltas(&previous, observed)
            .expect_err("ambiguous move identity must never be guessed");
        assert!(error.to_string().contains("ambiguous repository identity"));
    }

    fn make_entity(name: &str, file_path: &str, ast_hash: [u8; 32]) -> kin_model::entity::Entity {
        kin_model::entity::Entity {
            id: kin_model::EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes(ast_hash),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file_path)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: kin_model::EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// Record a SemanticChange in the graph and advance the branch head.
    fn record_commit(
        graph: &InMemoryGraph,
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<RelationDelta>,
        tree_deltas: Vec<TreeDelta>,
        parent: &SemanticChangeId,
        branch: &str,
    ) -> SemanticChangeId {
        let mut change = kin_model::SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: kin_model::ChangeOrigin::Native,
            parents: vec![*parent],
            author: AuthorId::new("test".to_string()),
            message: "test commit".to_string(),
            timestamp: Timestamp::now(),
            entity_deltas,
            relation_deltas,
            tree_deltas,
            admission_policy_delta: None,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
        };
        change.id = kin_core::compute_semantic_change_id(&change).unwrap();
        let change_id = change.id;
        graph.create_change(&change).expect("create_change");
        graph
            .update_branch_head(&kin_model::BranchName::new(branch), &change_id)
            .expect("update_branch_head");
        let desired = graph
            .resolve_tree_at(&change_id)
            .expect("resolve committed tree");
        let correction = kin_core::exact_tree_correction(&graph.resolved_tree(), &desired)
            .expect("align live tree with committed test head");
        graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: correction,
                admission_policy_delta: None,
            })
            .expect("publish committed tree as live test authority");
        change_id
    }

    /// Simulate the serialized exact-tree admission that production performs
    /// before commit-delta construction.
    fn admit_working_tree(
        graph: &InMemoryGraph,
        blobs: &BlobStore,
        layout: &kin_core::KinLayout,
    ) -> Result<()> {
        let previous = graph.resolved_tree();
        let tracked_paths = previous
            .artifacts_by_path()
            .map(|artifact| artifact.path.clone())
            .collect::<Vec<_>>();
        let graph_only_paths = previous
            .artifacts_by_path()
            .filter(|artifact| matches!(artifact.entry, TreeEntry::Gitlink { .. }))
            .map(|artifact| artifact.path.clone())
            .collect::<Vec<_>>();
        let source = kin_core::source_dir(layout);
        let ignore =
            kin_index::RepositoryIgnore::load(&source).map_err(kin_index::IndexError::from)?;
        let scan = kin_index::scan_repository_preserving_graph_only(
            &source,
            &ignore,
            tracked_paths.iter(),
            graph_only_paths.iter(),
        )
        .map_err(kin_index::IndexError::from)?;
        let observed = observed_tree_from_complete_scan(blobs, &scan, &previous)?;
        let tree_deltas = kin_core::plan_observed_tree_deltas(&previous, observed)?;
        graph.apply_transaction_delta(&kin_model::TransactionDelta {
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas,
            admission_policy_delta: None,
        })?;
        Ok(())
    }

    // ── Entity delta tests ───────────────────────────────────────────────

    /// Adding a new entity to the graph (simulating reconcile applying an
    /// overlay) and then computing deltas against genesis should produce
    /// exactly one Added delta for that entity.
    #[test]
    fn entity_added_since_genesis_appears_in_deltas() {
        let graph = Arc::new(kin_db::InMemoryGraph::new());

        // Bootstrap genesis + branch so get_changes_since works.
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        // Simulate reconcile: entity upserted into primary graph (overlay cleared).
        let entity = make_entity("my_fn", "src/lib.rs", [1; 32]);
        graph.upsert_entity(&entity).unwrap();

        // No files on disk; tree deltas will be empty.
        let deltas = compute_deltas_vs_last_commit(&graph, &genesis.id).unwrap();

        assert_eq!(
            deltas.entity_deltas.len(),
            1,
            "expected one entity Added delta"
        );
        assert!(
            matches!(
                &deltas.entity_deltas[0],
                EntityDelta::Added { new } if new.id == entity.id
            ),
            "delta must be Added for the new entity"
        );
        assert!(deltas.relation_deltas.is_empty());
    }

    /// After a commit that records the current entity, computing deltas
    /// against the new head produces zero entity deltas (idempotent).
    #[test]
    fn no_deltas_after_commit_records_current_entity() {
        let graph = Arc::new(kin_db::InMemoryGraph::new());

        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        let entity = make_entity("stable_fn", "src/lib.rs", [42; 32]);
        graph.upsert_entity(&entity).unwrap();

        // Record a commit that contains this entity.
        let head = record_commit(
            &graph,
            vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            vec![],
            vec![],
            &genesis.id,
            "main",
        );

        // Now compute deltas against the new head: entity is committed, nothing changed.
        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();

        assert!(
            deltas.entity_deltas.is_empty(),
            "no entity changes since the commit — deltas must be empty"
        );
        assert!(deltas.tree_deltas.is_empty());
    }

    /// A fingerprint change on an existing committed entity produces a Modified
    /// delta with the correct old (from DAG) and new (from graph) entity.
    #[test]
    fn modified_entity_fingerprint_produces_modified_delta() {
        let graph = Arc::new(kin_db::InMemoryGraph::new());

        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        // Commit the entity with hash [1;32].
        let old_entity = make_entity("changing_fn", "src/lib.rs", [1; 32]);
        graph.upsert_entity(&old_entity).unwrap();
        let head = record_commit(
            &graph,
            vec![EntityDelta::Added {
                new: old_entity.clone(),
            }],
            vec![],
            vec![],
            &genesis.id,
            "main",
        );

        // Simulate reconcile applying a changed version (hash [2;32]) to graph.
        let mut new_entity = old_entity.clone();
        new_entity.fingerprint.ast_hash = Hash256::from_bytes([2; 32]);
        graph.upsert_entity(&new_entity).unwrap();

        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();

        assert_eq!(deltas.entity_deltas.len(), 1);
        match &deltas.entity_deltas[0] {
            EntityDelta::Modified { old, new } => {
                assert_eq!(old.fingerprint.ast_hash, Hash256::from_bytes([1; 32]));
                assert_eq!(new.fingerprint.ast_hash, Hash256::from_bytes([2; 32]));
            }
            other => panic!("expected Modified, got {other:?}"),
        }
    }

    /// Removing an entity from the graph after it was committed produces a Removed delta.
    #[test]
    fn removed_entity_produces_removed_delta() {
        let graph = Arc::new(kin_db::InMemoryGraph::new());

        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        let entity = make_entity("doomed_fn", "src/lib.rs", [7; 32]);
        graph.upsert_entity(&entity).unwrap();
        let head = record_commit(
            &graph,
            vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            vec![],
            vec![],
            &genesis.id,
            "main",
        );

        // Simulate reconcile removing the entity from the primary graph.
        graph.remove_entity(&entity.id).unwrap();

        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();

        assert_eq!(deltas.entity_deltas.len(), 1);
        assert!(
            matches!(
                &deltas.entity_deltas[0],
                EntityDelta::Removed { old } if old.id == entity.id
            ),
            "expected Removed delta for the deleted entity"
        );
    }

    // ── Exact tree delta tests ───────────────────────────────────────────

    /// A new file on disk that was not in the last commit appears as Added.
    #[test]
    fn new_file_on_disk_appears_as_added_tree_delta() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.objects_dir()).unwrap();

        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        // Write a file to the working directory.
        let src_dir = kin_core::source_dir(&layout);
        std::fs::create_dir_all(src_dir.join("src")).unwrap();
        std::fs::write(src_dir.join("src/new.rs"), b"pub fn new_fn() {}\n").unwrap();

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let live_tree = graph.resolved_tree();
        let live_artifact = live_tree
            .artifact_at_path(&RepoPath::from_utf8("src/new.rs").unwrap())
            .unwrap();
        let deltas = compute_deltas_vs_last_commit(&graph, &genesis.id).unwrap();

        assert_eq!(deltas.expected_tree, live_tree);
        assert!(
            !deltas.tree_deltas.is_empty(),
            "new file must produce a tree delta"
        );
        let added = deltas
            .tree_deltas
            .iter()
            .filter_map(|delta| match delta {
                TreeDelta::Added {
                    new:
                        LocatedEntry {
                            entry:
                                TreeEntry::Blob {
                                    executable: false, ..
                                },
                            ..
                        },
                    ..
                } => Some(()),
                _ => None,
            })
            .count();
        assert!(added >= 1, "at least one Added tree delta expected");
        assert!(deltas.tree_deltas.iter().any(|delta| {
            matches!(
                delta,
                TreeDelta::Added { artifact_id, new }
                    if *artifact_id == live_artifact.artifact_id
                        && new.path == live_artifact.path
            )
        }));
        assert_eq!(
            graph
                .resolve_tree_at(&genesis.id)
                .unwrap()
                .apply(&deltas.tree_deltas)
                .unwrap(),
            live_tree
        );
    }

    /// A file whose content changed since the last commit appears as Modified.
    #[test]
    fn changed_file_appears_as_modified_tree_delta() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.objects_dir()).unwrap();

        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        // Simulate a prior commit that recorded the file with old content.
        let src_dir = kin_core::source_dir(&layout);
        std::fs::create_dir_all(src_dir.join("src")).unwrap();
        let old_content = b"pub fn old() {}\n";
        std::fs::write(src_dir.join("src/lib.rs"), old_content).unwrap();
        let old_digest = blobs.write(old_content).unwrap();
        let old_hash = Hash256::from_bytes(old_digest.0);
        let path = RepoPath::from_utf8("src/lib.rs").unwrap();
        let artifact_id = ArtifactId::new();

        let head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![TreeDelta::Added {
                artifact_id,
                new: LocatedEntry::new(path.clone(), TreeEntry::blob(old_hash, false)),
            }],
            &genesis.id,
            "main",
        );

        // Change the file on disk.
        std::fs::write(src_dir.join("src/lib.rs"), b"pub fn new() {}\n").unwrap();

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();

        let (old_entry, new_entry) = deltas
            .tree_deltas
            .iter()
            .find_map(|delta| match delta {
                TreeDelta::Updated {
                    artifact_id: delta_artifact_id,
                    old,
                    new,
                } if *delta_artifact_id == artifact_id && new.path == path => {
                    Some((&old.entry, &new.entry))
                }
                _ => None,
            })
            .expect("changed file must produce an Updated tree delta");
        assert_eq!(*old_entry, TreeEntry::blob(old_hash, false));
        assert_ne!(new_entry.blob_identity(), Some(old_hash));
        assert!(matches!(
            new_entry,
            TreeEntry::Blob {
                executable: false,
                ..
            }
        ));
    }

    #[test]
    fn commit_preserves_live_identity_after_admitted_move_then_edit() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.objects_dir()).unwrap();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        let source = kin_core::source_dir(&layout);
        std::fs::create_dir_all(source.join("src")).unwrap();
        let old_path = RepoPath::from_utf8("src/old.rs").unwrap();
        let new_path = RepoPath::from_utf8("src/new.rs").unwrap();
        let old_bytes = b"pub fn value() -> u8 { 1 }\n";
        let old_hash = Hash256::from_bytes(blobs.write(old_bytes).unwrap().0);
        let artifact_id = ArtifactId::new();
        std::fs::write(source.join("src/old.rs"), old_bytes).unwrap();
        let head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![TreeDelta::Added {
                artifact_id,
                new: LocatedEntry::new(old_path.clone(), TreeEntry::blob(old_hash, false)),
            }],
            &genesis.id,
            "main",
        );

        std::fs::rename(source.join("src/old.rs"), source.join("src/new.rs")).unwrap();
        admit_working_tree(&graph, &blobs, &layout).unwrap();
        assert_eq!(
            graph
                .resolved_tree()
                .artifact_at_path(&new_path)
                .unwrap()
                .artifact_id,
            artifact_id
        );

        std::fs::write(source.join("src/new.rs"), b"pub fn value() -> u8 { 2 }\n").unwrap();
        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let live_tree = graph.resolved_tree();
        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();

        assert_eq!(deltas.expected_tree, live_tree);
        assert_eq!(deltas.tree_deltas.len(), 1);
        assert!(matches!(
            &deltas.tree_deltas[0],
            TreeDelta::Updated {
                artifact_id: id,
                old,
                new,
            } if *id == artifact_id && old.path == old_path && new.path == new_path
        ));
        assert_eq!(
            graph
                .resolve_tree_at(&head)
                .unwrap()
                .apply(&deltas.tree_deltas)
                .unwrap(),
            live_tree
        );
    }

    /// A file that was committed but no longer exists on disk appears as Removed.
    #[test]
    fn deleted_file_appears_as_removed_tree_delta() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.objects_dir()).unwrap();

        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        let content = b"pub fn gone() {}\n";
        let digest = blobs.write(content).unwrap();
        let committed_hash = Hash256::from_bytes(digest.0);
        let path = RepoPath::from_utf8("src/deleted.rs").unwrap();
        let artifact_id = ArtifactId::new();

        let head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![TreeDelta::Added {
                artifact_id,
                new: LocatedEntry::new(path.clone(), TreeEntry::blob(committed_hash, false)),
            }],
            &genesis.id,
            "main",
        );

        // File is NOT present on disk — simulate deletion.
        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();

        let old_entry = deltas
            .tree_deltas
            .iter()
            .find_map(|delta| match delta {
                TreeDelta::Removed {
                    artifact_id: delta_artifact_id,
                    old,
                } if *delta_artifact_id == artifact_id && old.path == path => Some(&old.entry),
                _ => None,
            })
            .expect("deleted file must produce a Removed tree delta");
        assert_eq!(*old_entry, TreeEntry::blob(committed_hash, false));
    }

    #[cfg(unix)]
    #[test]
    fn tree_deltas_preserve_modes_symlinks_and_mode_only_changes() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.objects_dir()).unwrap();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        let source = kin_core::source_dir(&layout);
        std::fs::create_dir_all(source.join("bin")).unwrap();
        let regular = source.join("plain.txt");
        let executable = source.join("bin/run");
        std::fs::write(&regular, b"plain\n").unwrap();
        std::fs::write(&executable, b"#!/bin/sh\n").unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();
        symlink("plain.txt", source.join("current")).unwrap();

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let initial = compute_deltas_vs_last_commit(&graph, &genesis.id).unwrap();
        let entries: std::collections::BTreeMap<_, _> = initial
            .tree_deltas
            .iter()
            .filter_map(|delta| match delta {
                TreeDelta::Added { new, .. } => {
                    Some((new.path.as_utf8().expect("UTF-8 fixture path"), new.entry))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            entries.get("plain.txt"),
            Some(&TreeEntry::blob(
                Hash256::from_bytes(blobs.write(b"plain\n").unwrap().0),
                false
            ))
        );
        assert!(matches!(
            entries.get("bin/run"),
            Some(TreeEntry::Blob {
                executable: true,
                ..
            })
        ));
        assert!(matches!(
            entries.get("current"),
            Some(TreeEntry::Symlink { .. })
        ));
        let link = initial
            .tree_deltas
            .iter()
            .find_map(|delta| match delta {
                TreeDelta::Added { new, .. } if new.path.as_utf8() == Some("current") => {
                    Some(new.entry)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(
            blobs
                .read(&kin_blobs::Hash256(
                    link.blob_identity().expect("symlink blob").0
                ))
                .unwrap(),
            b"plain.txt"
        );

        let head = record_commit(
            &graph,
            vec![],
            vec![],
            initial.tree_deltas,
            &genesis.id,
            "main",
        );
        let plain_hash = blobs.write(b"plain\n").unwrap();
        let mut permissions = std::fs::metadata(&regular).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&regular, permissions).unwrap();

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let mode_only = compute_deltas_vs_last_commit(&graph, &head).unwrap();
        assert_eq!(mode_only.tree_deltas.len(), 1);
        let TreeDelta::Updated {
            artifact_id: _,
            old,
            new,
        } = &mode_only.tree_deltas[0]
        else {
            panic!("mode-only change must be Updated");
        };
        assert_eq!(old.path.as_utf8(), Some("plain.txt"));
        assert_eq!(new.path, old.path);
        assert_eq!(
            old.entry,
            TreeEntry::blob(Hash256::from_bytes(plain_hash.0), false)
        );
        assert_eq!(
            new.entry,
            TreeEntry::blob(Hash256::from_bytes(plain_hash.0), true)
        );
    }

    #[test]
    fn commit_admits_mixed_codebase_membership_independent_of_language_support() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.objects_dir()).unwrap();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        let source = kin_core::source_dir(&layout);
        let files: &[(&str, &[u8])] = &[
            ("Dockerfile", b"FROM scratch"),
            ("compose.yaml", b"services: {}"),
            ("Cargo.lock", b"version = 4"),
            ("src/main.rs", b"fn main() {}"),
            ("web/app.ts", b"export const app = true"),
            ("tools/job.py", b"print('job')"),
            ("unsupported/program.xyzzy", b"opaque source"),
            ("assets/logo.bin", b"\x00\xff\x10"),
            ("vendor/lib/source.c", b"int vendored(void) { return 1; }"),
            ("generated/schema.pb", b"\x01\x02generated"),
            ("node_modules/pkg/index.js", b"export default 1"),
            ("target/debug/build.log", b"built"),
        ];
        for (relative, bytes) in files {
            let path = source.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let deltas = compute_deltas_vs_last_commit(&graph, &genesis.id).unwrap();
        let admitted = deltas
            .tree_deltas
            .iter()
            .filter_map(|delta| match delta {
                TreeDelta::Added { new, .. } => new.path.as_utf8(),
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        for (relative, _) in files {
            assert!(
                admitted.contains(*relative),
                "missing exact member {relative}"
            );
        }
    }

    #[test]
    fn commit_preserves_gitlink_without_expanding_materialized_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.objects_dir()).unwrap();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();
        let gitlink = TreeEntry::gitlink(kin_model::GitObjectId::sha1([0x61; 20]));
        let head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(RepoPath::from_utf8("submodule").unwrap(), gitlink),
            }],
            &genesis.id,
            "main",
        );
        let checkout_file = kin_core::source_dir(&layout).join("submodule/src/lib.rs");
        std::fs::create_dir_all(checkout_file.parent().unwrap()).unwrap();
        std::fs::write(checkout_file, b"materialized checkout").unwrap();

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();
        assert!(
            deltas.tree_deltas.is_empty(),
            "host checkout cannot update, remove, or expand graph-owned Gitlink truth"
        );
    }

    #[test]
    fn commit_ignore_hides_only_untracked_paths_and_retains_tracked_updates() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.objects_dir()).unwrap();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        let source = kin_core::source_dir(&layout);
        std::fs::create_dir_all(source.join("target")).unwrap();
        std::fs::create_dir_all(source.join("node_modules/pkg")).unwrap();
        std::fs::write(source.join(".kinignore"), b"target/\nnode_modules/\n.env\n").unwrap();
        std::fs::write(source.join("target/retained.bin"), b"new tracked bytes").unwrap();
        std::fs::write(source.join("target/untracked.bin"), b"build output").unwrap();
        std::fs::write(source.join("node_modules/pkg/index.js"), b"generated").unwrap();
        std::fs::write(source.join(".env"), b"SECRET=never-admit").unwrap();

        let old_hash = Hash256::from_bytes(blobs.write(b"old tracked bytes").unwrap().0);
        let retained = RepoPath::from_utf8("target/retained.bin").unwrap();
        let artifact_id = ArtifactId::new();
        let head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![TreeDelta::Added {
                artifact_id,
                new: LocatedEntry::new(retained.clone(), TreeEntry::blob(old_hash, false)),
            }],
            &genesis.id,
            "main",
        );

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();
        assert!(deltas.tree_deltas.iter().any(|delta| {
            matches!(
                delta,
                TreeDelta::Updated {
                    artifact_id: id,
                    new,
                    ..
                } if *id == artifact_id && new.path == retained
            )
        }));
        for ignored in [".env", "target/untracked.bin", "node_modules/pkg/index.js"] {
            assert!(
                !deltas.tree_deltas.iter().any(|delta| {
                    delta
                        .new_state()
                        .is_some_and(|entry| entry.path.as_utf8() == Some(ignored))
                }),
                "untracked ignored path entered commit truth: {ignored}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn tracked_special_entry_blocks_commit_before_missing_paths_become_removals() {
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.objects_dir()).unwrap();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        let missing = RepoPath::from_utf8("missing.txt").unwrap();
        let special = RepoPath::from_utf8("tracked.sock").unwrap();
        let old_hash = Hash256::from_bytes(blobs.write(b"old").unwrap().0);
        let _head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![
                TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: LocatedEntry::new(missing, TreeEntry::blob(old_hash, false)),
                },
                TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: LocatedEntry::new(special, TreeEntry::blob(old_hash, false)),
                },
            ],
            &genesis.id,
            "main",
        );
        let _listener =
            UnixListener::bind(kin_core::source_dir(&layout).join("tracked.sock")).unwrap();

        let error = admit_working_tree(&graph, &blobs, &layout)
            .expect_err("an incomplete exact scan cannot authorize any inferred removal");
        assert!(error.to_string().contains("tracked path changed"));
    }

    // ── End-to-end: zero deltas after recording current state ─────────────

    /// After recording all current entities + files in a commit, a second
    /// compute produces zero deltas across all three slices.  This is the
    /// non-zero → zero correctness gate — ensures the production path will
    /// emit empty deltas for a clean second commit.
    #[test]
    fn second_commit_with_no_changes_produces_zero_deltas() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.objects_dir()).unwrap();

        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&kin_model::Branch {
                name: kin_model::BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        // Write a file and add an entity.
        let src_dir = kin_core::source_dir(&layout);
        std::fs::create_dir_all(src_dir.join("src")).unwrap();
        let content = b"pub fn stable() {}\n";
        std::fs::write(src_dir.join("src/lib.rs"), content).unwrap();
        let digest = blobs.write(content).unwrap();
        let hash = Hash256::from_bytes(digest.0);
        let path = RepoPath::from_utf8("src/lib.rs").unwrap();

        let entity = make_entity("stable", "src/lib.rs", [99; 32]);
        graph.upsert_entity(&entity).unwrap();

        // First commit: record the current state.
        let head1 = record_commit(
            &graph,
            vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            vec![],
            vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(path, TreeEntry::blob(hash, false)),
            }],
            &genesis.id,
            "main",
        );

        // Second compute: nothing changed → all deltas empty.
        let deltas = compute_deltas_vs_last_commit(&graph, &head1).unwrap();

        assert!(
            deltas.entity_deltas.is_empty(),
            "no entity changes: expected 0, got {}",
            deltas.entity_deltas.len()
        );
        assert!(
            deltas.tree_deltas.is_empty(),
            "no file changes: expected 0, got {}",
            deltas.tree_deltas.len()
        );
        assert!(
            deltas.relation_deltas.is_empty(),
            "no relation changes: expected 0, got {}",
            deltas.relation_deltas.len()
        );
    }
}
