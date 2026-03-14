use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::engine::InMemoryGraph;
use crate::error::KinDbError;
use crate::store::GraphStore;
use crate::storage::format::GraphSnapshot;
use crate::storage::mmap;
use crate::types::*;

/// Manages graph snapshots on disk with RCU-style concurrent access.
///
/// - Readers access the current `Arc<InMemoryGraph>` (cheap clone, no locking).
/// - Writer builds a new snapshot, serializes to disk atomically, then swaps the Arc.
/// - Old snapshot is freed when the last reader drops its Arc.
pub struct SnapshotManager {
    /// Path to the snapshot file.
    path: PathBuf,
    /// Current live graph behind an Arc for cheap sharing.
    current: RwLock<Arc<InMemoryGraph>>,
}

impl SnapshotManager {
    /// Create a new SnapshotManager with an empty in-memory graph.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            current: RwLock::new(Arc::new(InMemoryGraph::new())),
        }
    }

    /// Open an existing snapshot from disk, or create a new empty graph if
    /// the file doesn't exist.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, KinDbError> {
        let path = path.into();

        if path.exists() {
            let snapshot = mmap::MmapReader::open(&path)?;
            let graph = InMemoryGraph::new();

            // Hydrate the graph from the snapshot
            for entity in snapshot.entities.values() {
                graph.upsert_entity(entity)?;
            }
            for relation in snapshot.relations.values() {
                graph.upsert_relation(relation)?;
            }
            for change in snapshot.changes.values() {
                graph.create_change(change)?;
            }
            for branch in snapshot.branches.values() {
                graph.create_branch(branch)?;
            }

            Ok(Self {
                path,
                current: RwLock::new(Arc::new(graph)),
            })
        } else {
            Ok(Self::new(path))
        }
    }

    /// Get a shared reference to the current graph.
    /// The returned Arc can be held across async boundaries without blocking writers.
    pub fn graph(&self) -> Arc<InMemoryGraph> {
        Arc::clone(&self.current.read())
    }

    /// Get the underlying path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Save the current graph state to disk atomically.
    pub fn save(&self) -> Result<(), KinDbError> {
        let graph = self.graph();

        // Extract all data from the graph
        let entities: std::collections::HashMap<EntityId, Entity> = graph
            .list_all_entities()?
            .into_iter()
            .map(|e| (e.id, e))
            .collect();

        // We need to collect relations by iterating all entities
        let mut relations = std::collections::HashMap::new();
        let mut outgoing: std::collections::HashMap<EntityId, Vec<RelationId>> =
            std::collections::HashMap::new();
        let mut incoming: std::collections::HashMap<EntityId, Vec<RelationId>> =
            std::collections::HashMap::new();

        for entity_id in entities.keys() {
            let entity_rels = graph.get_all_relations_for_entity(entity_id)?;
            for rel in entity_rels {
                outgoing.entry(rel.src).or_default().push(rel.id);
                incoming.entry(rel.dst).or_default().push(rel.id);
                relations.insert(rel.id, rel);
            }
        }

        // Deduplicate outgoing/incoming entries
        for v in outgoing.values_mut() {
            let mut seen = std::collections::HashSet::new();
            v.retain(|id| seen.insert(*id));
        }
        for v in incoming.values_mut() {
            let mut seen = std::collections::HashSet::new();
            v.retain(|id| seen.insert(*id));
        }

        let branches: std::collections::HashMap<BranchName, Branch> = graph
            .list_branches()?
            .into_iter()
            .map(|b| (b.name.clone(), b))
            .collect();

        let snapshot = GraphSnapshot {
            version: GraphSnapshot::CURRENT_VERSION,
            entities,
            relations,
            outgoing,
            incoming,
            changes: std::collections::HashMap::new(), // TODO: extract changes
            change_children: std::collections::HashMap::new(),
            branches,
        };

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        mmap::atomic_write(&self.path, &snapshot)
    }

    /// Replace the current graph with a new one (RCU swap).
    pub fn swap(&self, new_graph: InMemoryGraph) {
        let mut current = self.current.write();
        *current = Arc::new(new_graph);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/main.rs")),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn save_and_reload() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        // Create and populate
        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let entity = test_entity("save_test");
        let id = entity.id;
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        // Reload from disk
        let mgr2 = SnapshotManager::open(&path).unwrap();
        let graph2 = mgr2.graph();
        let fetched = graph2.get_entity(&id).unwrap().unwrap();
        assert_eq!(fetched.name, "save_test");
    }

    #[test]
    fn rcu_swap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let mgr = SnapshotManager::new(&path);

        // Get a reference to the old graph
        let old_graph = mgr.graph();
        let e = test_entity("old");
        old_graph.upsert_entity(&e).unwrap();

        // Swap with a new graph
        let new = InMemoryGraph::new();
        let e2 = test_entity("new");
        new.upsert_entity(&e2).unwrap();
        mgr.swap(new);

        // Old reference still works
        assert_eq!(old_graph.entity_count(), 1);

        // New reference sees new data
        let new_graph = mgr.graph();
        assert_eq!(new_graph.entity_count(), 1);
        let fetched = new_graph.list_all_entities().unwrap();
        assert_eq!(fetched[0].name, "new");
    }

    #[test]
    fn open_nonexistent_creates_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does_not_exist.kndb");
        let mgr = SnapshotManager::open(&path).unwrap();
        assert_eq!(mgr.graph().entity_count(), 0);
    }

    #[test]
    fn save_with_relations() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();

        let e1 = test_entity("caller");
        let e2 = test_entity("callee");
        let rel = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: e1.id,
            dst: e2.id,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
        };

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();
        mgr.save().unwrap();

        // Reload
        let mgr2 = SnapshotManager::open(&path).unwrap();
        let g2 = mgr2.graph();
        assert_eq!(g2.entity_count(), 2);
        assert_eq!(g2.relation_count(), 1);
        let rels = g2.get_relations(&e1.id, &[RelationKind::Calls]).unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].dst, e2.id);
    }
}
