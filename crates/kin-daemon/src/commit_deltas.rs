// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Reconstructive commit-delta computation for `command_commit`.
//!
//! Computes entity / relation / artifact deltas by diffing current graph
//! state against the last-committed change-DAG node.  This approach is
//! robust regardless of when the reconcile loop drained the working-copy
//! overlay — the overlay is never consulted here.
//!
//! ## Algorithm
//!
//! 1. Walk the change DAG from genesis to `branch_head` via
//!    `get_changes_since`, reconstructing the committed entity map,
//!    relation set, and file tree.
//! 2. Read current state from the live graph (`list_all_entities`,
//!    `get_all_relations_for_entity`) and scan working-directory files.
//! 3. Diff current vs committed to produce typed `EntityDelta`,
//!    `RelationDelta`, and `ArtifactDelta` slices.
//!
//! Because `apply_overlay_to_graph` folds reconcile mutations into the
//! primary graph before clearing the overlay, `graph.list_all_entities()`
//! already reflects the current working state — diffing against the DAG
//! baseline captures exactly what changed since the last commit.

use std::collections::{HashMap, HashSet};

use kin_db::InMemoryGraph;
use kin_model::{
    relation::GraphNodeId, ArtifactDelta, ArtifactDeltaKind, ChangeStore, Entity, EntityDelta,
    EntityId, EntityStore, FilePathId, Hash256, RelationDelta, RelationId, SemanticChangeId,
    SourceEntryKind,
};

use crate::error::{DaemonError, Result};

/// The three delta slices that constitute a semantic commit.
pub struct CommitDeltas {
    pub entity_deltas: Vec<EntityDelta>,
    pub relation_deltas: Vec<RelationDelta>,
    pub artifact_deltas: Vec<ArtifactDelta>,
}

#[derive(Debug, Clone, Copy)]
struct CommittedSourceEntry {
    hash: Hash256,
    /// `None` identifies pre-0.3 mode-unknown history. An unchanged working
    /// entry then emits an exact modification to backfill its mode.
    kind: Option<SourceEntryKind>,
}

fn added_artifact_kind(kind: SourceEntryKind) -> ArtifactDeltaKind {
    match kind {
        SourceEntryKind::File { executable: false } => ArtifactDeltaKind::AddedRegularFile,
        SourceEntryKind::File { executable: true } => ArtifactDeltaKind::AddedExecutableFile,
        SourceEntryKind::Symlink => ArtifactDeltaKind::AddedSymlink,
    }
}

fn modified_artifact_kind(kind: SourceEntryKind) -> ArtifactDeltaKind {
    match kind {
        SourceEntryKind::File { executable: false } => ArtifactDeltaKind::ModifiedRegularFile,
        SourceEntryKind::File { executable: true } => ArtifactDeltaKind::ModifiedExecutableFile,
        SourceEntryKind::Symlink => ArtifactDeltaKind::ModifiedSymlink,
    }
}

/// Compute commit deltas by diffing current graph state against the
/// last-committed change-DAG node (`branch_head`).
///
/// Returns empty delta slices when nothing has changed since the last commit,
/// and non-empty slices when entities, relations, or files have been modified.
pub fn compute_deltas_vs_last_commit(
    graph: &InMemoryGraph,
    blobs: &kin_blobs::BlobStore,
    layout: &kin_core::KinLayout,
    branch_head: &SemanticChangeId,
) -> Result<CommitDeltas> {
    // ── Reconstruct the committed baseline from the change DAG ───────────
    let genesis = kin_core::build_genesis_change();
    let committed_changes = graph
        .get_changes_since(&genesis.id, branch_head)
        .map_err(DaemonError::Graph)?;

    // entity_id → Entity (state at last commit)
    let mut committed_entities: HashMap<EntityId, Entity> = HashMap::new();
    // file_id → content hash + exact source kind (state at last commit)
    let mut committed_files: HashMap<FilePathId, CommittedSourceEntry> = HashMap::new();
    // relation IDs present at last commit
    let mut committed_relation_ids: HashSet<RelationId> = HashSet::new();

    for change in &committed_changes {
        for delta in &change.entity_deltas {
            match delta {
                EntityDelta::Added(entity) => {
                    committed_entities.insert(entity.id, entity.clone());
                }
                EntityDelta::Modified { new, .. } => {
                    committed_entities.insert(new.id, new.clone());
                }
                EntityDelta::Removed(id) => {
                    committed_entities.remove(id);
                }
            }
        }
        for delta in &change.artifact_deltas {
            if delta.kind.is_removed() {
                committed_files.remove(&delta.file_id);
            } else if let Some(hash) = delta.new_hash {
                committed_files.insert(
                    delta.file_id.clone(),
                    CommittedSourceEntry {
                        hash,
                        kind: delta.kind.source_entry_kind(),
                    },
                );
            }
        }
        for delta in &change.relation_deltas {
            match delta {
                RelationDelta::Added(rel) => {
                    committed_relation_ids.insert(rel.id);
                }
                RelationDelta::Removed(id) => {
                    committed_relation_ids.remove(id);
                }
            }
        }
    }

    // ── Current entity state from live graph ─────────────────────────────
    let current_entities = graph.list_all_entities().map_err(DaemonError::Graph)?;

    // ── Entity deltas ─────────────────────────────────────────────────────
    let mut entity_deltas = Vec::new();
    let mut current_entity_ids: HashSet<EntityId> = HashSet::with_capacity(current_entities.len());

    for entity in &current_entities {
        current_entity_ids.insert(entity.id);
        match committed_entities.get(&entity.id) {
            None => {
                // Not in last commit → Added
                entity_deltas.push(EntityDelta::Added(entity.clone()));
            }
            Some(committed) if kin_index::entity_semantics_changed(committed, entity) => {
                // Fingerprint changed → Modified (old from DAG, new from graph)
                entity_deltas.push(EntityDelta::Modified {
                    old: committed.clone(),
                    new: entity.clone(),
                });
            }
            _ => {} // Unchanged
        }
    }

    // Entities in committed baseline but absent from live graph → Removed
    for id in committed_entities.keys() {
        if !current_entity_ids.contains(id) {
            entity_deltas.push(EntityDelta::Removed(*id));
        }
    }

    // ── Relation deltas ───────────────────────────────────────────────────
    let mut relation_deltas = Vec::new();
    let mut current_relation_ids: HashSet<RelationId> = HashSet::new();

    for entity in &current_entities {
        let relations = graph
            .get_all_relations_for_entity(&entity.id)
            .map_err(DaemonError::Graph)?;
        for rel in relations {
            // Only track outgoing relations to avoid double-counting.
            if rel.src == GraphNodeId::Entity(entity.id)
                && current_relation_ids.insert(rel.id)
                && !committed_relation_ids.contains(&rel.id)
            {
                relation_deltas.push(RelationDelta::Added(rel));
            }
        }
    }

    // Relations in committed baseline but absent from live graph → Removed
    for id in &committed_relation_ids {
        if !current_relation_ids.contains(id) {
            relation_deltas.push(RelationDelta::Removed(*id));
        }
    }

    // ── Artifact deltas (file content hashes) ────────────────────────────
    let artifact_deltas = compute_artifact_deltas(layout, blobs, committed_files)?;

    Ok(CommitDeltas {
        entity_deltas,
        relation_deltas,
        artifact_deltas,
    })
}

/// Compare working-directory source entries against the committed tree,
/// producing mode-faithful artifact deltas. A mode-only change and an exact
/// backfill over legacy mode-unknown history both produce a modification.
fn compute_artifact_deltas(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    committed_files: HashMap<FilePathId, CommittedSourceEntry>,
) -> Result<Vec<ArtifactDelta>> {
    let source_root = kin_core::source_dir(layout);
    let mut artifact_deltas = Vec::new();
    let mut current_file_ids: HashSet<FilePathId> = HashSet::new();

    for abs_path in collect_tracked_files(&source_root)? {
        let rel = match abs_path.strip_prefix(&source_root) {
            Ok(path) => path.to_str().ok_or_else(|| {
                DaemonError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("source path is not valid UTF-8: {}", path.display()),
                ))
            })?,
            Err(error) => {
                return Err(DaemonError::Io(std::io::Error::other(format!(
                    "tracked source path {} escaped source root {}: {error}",
                    abs_path.display(),
                    source_root.display()
                ))))
            }
        };
        let file_id = FilePathId::new(rel);
        current_file_ids.insert(file_id.clone());

        let metadata = std::fs::symlink_metadata(&abs_path).map_err(DaemonError::Io)?;
        let (content, source_kind) = if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(&abs_path).map_err(DaemonError::Io)?;
            let target = target.to_str().ok_or_else(|| {
                DaemonError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "symbolic link target is not valid UTF-8: {}",
                        abs_path.display()
                    ),
                ))
            })?;
            (target.as_bytes().to_vec(), SourceEntryKind::Symlink)
        } else if metadata.is_file() {
            #[cfg(unix)]
            let executable = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o111 != 0
            };
            #[cfg(not(unix))]
            let executable = false;
            (
                std::fs::read(&abs_path).map_err(DaemonError::Io)?,
                SourceEntryKind::File { executable },
            )
        } else {
            continue;
        };

        // A graph delta must never name bytes that failed to enter the local
        // object store: the backend persistence path relies on this object.
        let blob_digest = blobs.write(&content).map_err(DaemonError::from)?;
        let new_hash = Hash256::from_bytes(blob_digest.0);

        match committed_files.get(&file_id).copied() {
            None => {
                artifact_deltas.push(ArtifactDelta {
                    file_id,
                    kind: added_artifact_kind(source_kind),
                    old_hash: None,
                    new_hash: Some(new_hash),
                });
            }
            Some(committed)
                if committed.hash != new_hash || committed.kind != Some(source_kind) =>
            {
                artifact_deltas.push(ArtifactDelta {
                    file_id,
                    kind: modified_artifact_kind(source_kind),
                    old_hash: Some(committed.hash),
                    new_hash: Some(new_hash),
                });
            }
            _ => {} // Unchanged
        }
    }

    // Files in committed tree but missing from working directory → Removed
    for (file_id, committed) in &committed_files {
        if !current_file_ids.contains(file_id) {
            artifact_deltas.push(ArtifactDelta {
                file_id: file_id.clone(),
                kind: ArtifactDeltaKind::Removed,
                old_hash: Some(committed.hash),
                new_hash: None,
            });
        }
    }

    Ok(artifact_deltas)
}

/// Recursively collect all tracked (non-skip) files under `root`.
/// Uses `kin_index::should_skip_dir` for directory filtering, mirroring
/// the same skip rules applied by the reconcile loop.
fn collect_tracked_files(root: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    collect_tracked_files_recursive(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_tracked_files_recursive(
    dir: &std::path::Path,
    files: &mut Vec<std::path::PathBuf>,
) -> Result<()> {
    let entries = std::fs::read_dir(dir).map_err(DaemonError::Io)?;
    for entry in entries {
        let entry = entry.map_err(DaemonError::Io)?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_str().ok_or_else(|| {
            DaemonError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "source path component is not valid UTF-8: {}",
                    path.display()
                ),
            ))
        })?;
        let file_type = entry.file_type().map_err(DaemonError::Io)?;
        if file_type.is_dir() {
            if kin_index::should_skip_dir(name_str) {
                continue;
            }
            collect_tracked_files_recursive(&path, files)?;
        } else if file_type.is_file() || file_type.is_symlink() {
            files.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use kin_blobs::BlobStore;
    use kin_model::{
        ArtifactDeltaKind, AuthorId, EntityKind, EntityMetadata, FingerprintAlgorithm, LanguageId,
        SemanticFingerprint, Timestamp, Visibility,
    };

    #[test]
    fn tracked_file_scan_fails_loud_when_root_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        assert!(collect_tracked_files(&missing).is_err());
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
        artifact_deltas: Vec<ArtifactDelta>,
        parent: &SemanticChangeId,
        branch: &str,
    ) -> SemanticChangeId {
        let mut change = kin_model::SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents: vec![*parent],
            author: AuthorId::new("test".to_string()),
            message: "test commit".to_string(),
            timestamp: Timestamp::now(),
            entity_deltas,
            relation_deltas,
            artifact_deltas,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        change.id = kin_core::compute_semantic_change_id(&change).unwrap();
        let change_id = change.id;
        graph.create_change(&change).expect("create_change");
        graph
            .update_branch_head(&kin_model::BranchName::new(branch), &change_id)
            .expect("update_branch_head");
        change_id
    }

    // ── Entity delta tests ───────────────────────────────────────────────

    /// Adding a new entity to the graph (simulating reconcile applying an
    /// overlay) and then computing deltas against genesis should produce
    /// exactly one Added delta for that entity.
    #[test]
    fn entity_added_since_genesis_appears_in_deltas() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.objects_dir()).unwrap();

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

        // No files on disk; artifact deltas will be empty.
        let deltas = compute_deltas_vs_last_commit(&graph, &blobs, &layout, &genesis.id).unwrap();

        assert_eq!(
            deltas.entity_deltas.len(),
            1,
            "expected one entity Added delta"
        );
        assert!(
            matches!(&deltas.entity_deltas[0], EntityDelta::Added(e) if e.id == entity.id),
            "delta must be Added for the new entity"
        );
        assert!(deltas.relation_deltas.is_empty());
    }

    /// After a commit that records the current entity, computing deltas
    /// against the new head produces zero entity deltas (idempotent).
    #[test]
    fn no_deltas_after_commit_records_current_entity() {
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

        let entity = make_entity("stable_fn", "src/lib.rs", [42; 32]);
        graph.upsert_entity(&entity).unwrap();

        // Record a commit that contains this entity.
        let head = record_commit(
            &graph,
            vec![EntityDelta::Added(entity.clone())],
            vec![],
            vec![],
            &genesis.id,
            "main",
        );

        // Now compute deltas against the new head: entity is committed, nothing changed.
        let deltas = compute_deltas_vs_last_commit(&graph, &blobs, &layout, &head).unwrap();

        assert!(
            deltas.entity_deltas.is_empty(),
            "no entity changes since the commit — deltas must be empty"
        );
        assert!(deltas.artifact_deltas.is_empty());
    }

    /// A fingerprint change on an existing committed entity produces a Modified
    /// delta with the correct old (from DAG) and new (from graph) entity.
    #[test]
    fn modified_entity_fingerprint_produces_modified_delta() {
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

        // Commit the entity with hash [1;32].
        let old_entity = make_entity("changing_fn", "src/lib.rs", [1; 32]);
        graph.upsert_entity(&old_entity).unwrap();
        let head = record_commit(
            &graph,
            vec![EntityDelta::Added(old_entity.clone())],
            vec![],
            vec![],
            &genesis.id,
            "main",
        );

        // Simulate reconcile applying a changed version (hash [2;32]) to graph.
        let mut new_entity = old_entity.clone();
        new_entity.fingerprint.ast_hash = Hash256::from_bytes([2; 32]);
        graph.upsert_entity(&new_entity).unwrap();

        let deltas = compute_deltas_vs_last_commit(&graph, &blobs, &layout, &head).unwrap();

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

        let entity = make_entity("doomed_fn", "src/lib.rs", [7; 32]);
        graph.upsert_entity(&entity).unwrap();
        let head = record_commit(
            &graph,
            vec![EntityDelta::Added(entity.clone())],
            vec![],
            vec![],
            &genesis.id,
            "main",
        );

        // Simulate reconcile removing the entity from the primary graph.
        graph.remove_entity(&entity.id).unwrap();

        let deltas = compute_deltas_vs_last_commit(&graph, &blobs, &layout, &head).unwrap();

        assert_eq!(deltas.entity_deltas.len(), 1);
        assert!(
            matches!(&deltas.entity_deltas[0], EntityDelta::Removed(id) if *id == entity.id),
            "expected Removed delta for the deleted entity"
        );
    }

    // ── Artifact delta tests ─────────────────────────────────────────────

    /// A new file on disk that was not in the last commit appears as Added.
    #[test]
    fn new_file_on_disk_appears_as_added_artifact_delta() {
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

        let deltas = compute_deltas_vs_last_commit(&graph, &blobs, &layout, &genesis.id).unwrap();

        assert!(
            !deltas.artifact_deltas.is_empty(),
            "new file must produce artifact delta"
        );
        let added = deltas
            .artifact_deltas
            .iter()
            .filter(|d| d.kind == ArtifactDeltaKind::AddedRegularFile)
            .count();
        assert!(added >= 1, "at least one Added artifact delta expected");
    }

    /// A file whose content changed since the last commit appears as Modified.
    #[test]
    fn changed_file_appears_as_modified_artifact_delta() {
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
        let file_id = FilePathId::new("src/lib.rs");

        let head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![ArtifactDelta {
                file_id: file_id.clone(),
                kind: ArtifactDeltaKind::AddedRegularFile,
                old_hash: None,
                new_hash: Some(old_hash),
            }],
            &genesis.id,
            "main",
        );

        // Change the file on disk.
        std::fs::write(src_dir.join("src/lib.rs"), b"pub fn new() {}\n").unwrap();

        let deltas = compute_deltas_vs_last_commit(&graph, &blobs, &layout, &head).unwrap();

        let modified: Vec<_> = deltas
            .artifact_deltas
            .iter()
            .filter(|d| d.kind == ArtifactDeltaKind::ModifiedRegularFile && d.file_id == file_id)
            .collect();
        assert!(
            !modified.is_empty(),
            "changed file must produce a Modified artifact delta"
        );
        assert_eq!(
            modified[0].old_hash,
            Some(old_hash),
            "old hash must be the previously committed hash"
        );
    }

    /// A file that was committed but no longer exists on disk appears as Removed.
    #[test]
    fn deleted_file_appears_as_removed_artifact_delta() {
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
        let file_id = FilePathId::new("src/deleted.rs");

        let head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![ArtifactDelta {
                file_id: file_id.clone(),
                kind: ArtifactDeltaKind::AddedRegularFile,
                old_hash: None,
                new_hash: Some(committed_hash),
            }],
            &genesis.id,
            "main",
        );

        // File is NOT present on disk — simulate deletion.
        let deltas = compute_deltas_vs_last_commit(&graph, &blobs, &layout, &head).unwrap();

        let removed: Vec<_> = deltas
            .artifact_deltas
            .iter()
            .filter(|d| d.kind == ArtifactDeltaKind::Removed && d.file_id == file_id)
            .collect();
        assert!(
            !removed.is_empty(),
            "deleted file must produce a Removed artifact delta"
        );
    }

    #[cfg(unix)]
    #[test]
    fn artifact_deltas_preserve_modes_symlinks_and_mode_only_changes() {
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

        let initial = compute_deltas_vs_last_commit(&graph, &blobs, &layout, &genesis.id).unwrap();
        let kinds: std::collections::BTreeMap<_, _> = initial
            .artifact_deltas
            .iter()
            .map(|delta| (delta.file_id.0.as_str(), delta.kind))
            .collect();
        assert_eq!(
            kinds.get("plain.txt"),
            Some(&ArtifactDeltaKind::AddedRegularFile)
        );
        assert_eq!(
            kinds.get("bin/run"),
            Some(&ArtifactDeltaKind::AddedExecutableFile)
        );
        assert_eq!(kinds.get("current"), Some(&ArtifactDeltaKind::AddedSymlink));
        let link = initial
            .artifact_deltas
            .iter()
            .find(|delta| delta.file_id.0 == "current")
            .unwrap();
        assert_eq!(
            blobs
                .read(&kin_blobs::Hash256(link.new_hash.unwrap().0))
                .unwrap(),
            b"plain.txt"
        );

        let head = record_commit(
            &graph,
            vec![],
            vec![],
            initial.artifact_deltas,
            &genesis.id,
            "main",
        );
        let plain_hash = blobs.write(b"plain\n").unwrap();
        let mut permissions = std::fs::metadata(&regular).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&regular, permissions).unwrap();

        let mode_only = compute_deltas_vs_last_commit(&graph, &blobs, &layout, &head).unwrap();
        assert_eq!(mode_only.artifact_deltas.len(), 1);
        assert_eq!(
            mode_only.artifact_deltas[0].kind,
            ArtifactDeltaKind::ModifiedExecutableFile
        );
        assert_eq!(mode_only.artifact_deltas[0].file_id.0, "plain.txt");
        assert_eq!(
            mode_only.artifact_deltas[0].old_hash,
            Some(Hash256::from_bytes(plain_hash.0))
        );
        assert_eq!(
            mode_only.artifact_deltas[0].old_hash,
            mode_only.artifact_deltas[0].new_hash
        );
    }

    #[test]
    fn unchanged_legacy_file_emits_exact_mode_backfill() {
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
        std::fs::create_dir_all(&source).unwrap();
        let content = b"legacy bytes\n";
        std::fs::write(source.join("legacy.txt"), content).unwrap();
        let hash = Hash256::from_bytes(blobs.write(content).unwrap().0);
        let head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![ArtifactDelta {
                file_id: FilePathId::new("legacy.txt"),
                kind: ArtifactDeltaKind::Added,
                old_hash: None,
                new_hash: Some(hash),
            }],
            &genesis.id,
            "main",
        );

        let backfill = compute_deltas_vs_last_commit(&graph, &blobs, &layout, &head).unwrap();
        assert_eq!(backfill.artifact_deltas.len(), 1);
        assert_eq!(
            backfill.artifact_deltas[0].kind,
            ArtifactDeltaKind::ModifiedRegularFile
        );
        assert_eq!(backfill.artifact_deltas[0].old_hash, Some(hash));
        assert_eq!(backfill.artifact_deltas[0].new_hash, Some(hash));
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
        let file_id = FilePathId::new("src/lib.rs");

        let entity = make_entity("stable", "src/lib.rs", [99; 32]);
        graph.upsert_entity(&entity).unwrap();

        // First commit: record the current state.
        let head1 = record_commit(
            &graph,
            vec![EntityDelta::Added(entity.clone())],
            vec![],
            vec![ArtifactDelta {
                file_id,
                kind: ArtifactDeltaKind::AddedRegularFile,
                old_hash: None,
                new_hash: Some(hash),
            }],
            &genesis.id,
            "main",
        );

        // Second compute: nothing changed → all deltas empty.
        let deltas = compute_deltas_vs_last_commit(&graph, &blobs, &layout, &head1).unwrap();

        assert!(
            deltas.entity_deltas.is_empty(),
            "no entity changes: expected 0, got {}",
            deltas.entity_deltas.len()
        );
        assert!(
            deltas.artifact_deltas.is_empty(),
            "no file changes: expected 0, got {}",
            deltas.artifact_deltas.len()
        );
        assert!(
            deltas.relation_deltas.is_empty(),
            "no relation changes: expected 0, got {}",
            deltas.relation_deltas.len()
        );
    }
}
