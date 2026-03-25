// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use fs2::FileExt;
use parking_lot::RwLock;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::engine::InMemoryGraph;
use crate::error::KinDbError;
use crate::storage::mmap;

/// Manages graph snapshots on disk with RCU-style concurrent access.
///
/// - Readers access the current `Arc<InMemoryGraph>` (cheap clone, no locking).
/// - Writer builds a new snapshot, serializes to disk atomically, then swaps the Arc.
/// - Old snapshot is freed when the last reader drops its Arc.
/// - An OS-level exclusive file lock prevents multiple processes from opening
///   the same snapshot simultaneously. The lock is released when the manager is dropped.
pub struct SnapshotManager {
    /// Path to the snapshot file.
    path: PathBuf,
    /// Current live graph behind an Arc for cheap sharing.
    current: RwLock<Arc<InMemoryGraph>>,
    /// OS-level lock file handle. Held for the lifetime of this manager;
    /// the exclusive flock is released automatically when the File is dropped.
    _lock_file: Option<File>,
}

fn normalize_snapshot_path(path: PathBuf) -> PathBuf {
    if path.extension().is_some() {
        return path;
    }

    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return path;
    };
    if name != "kindb" {
        return path;
    }

    let legacy_graph_dir = path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .map(|name| name == "graph")
        .unwrap_or(false);
    if legacy_graph_dir {
        if let Some(root) = path.parent().and_then(|parent| parent.parent()) {
            return root.join("kindb").join("graph.kndb");
        }
    }

    path.join("graph.kndb")
}

impl SnapshotManager {
    /// Acquire an exclusive OS-level file lock adjacent to the snapshot path.
    /// Returns the lock file handle on success.
    fn acquire_lock(path: &Path) -> Result<File, KinDbError> {
        let lock_path = path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create directory for lock file {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let lock_file = File::create(&lock_path).map_err(|e| {
            KinDbError::LockError(format!(
                "failed to create lock file {}: {e}",
                lock_path.display()
            ))
        })?;
        lock_file.try_lock_exclusive().map_err(|e| {
            KinDbError::LockError(format!(
                "failed to acquire exclusive lock on {}: {e} (another process may be using this database)",
                lock_path.display()
            ))
        })?;
        Ok(lock_file)
    }

    /// Create a new SnapshotManager with an empty in-memory graph.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = normalize_snapshot_path(path.into());
        Self {
            path,
            current: RwLock::new(Arc::new(InMemoryGraph::new())),
            _lock_file: None,
        }
    }

    fn recover_graph_from_tmp(
        path: &Path,
        primary_error: Option<&KinDbError>,
    ) -> Result<InMemoryGraph, KinDbError> {
        let tmp_path = mmap::recovery_tmp_path(path);
        if !tmp_path.exists() {
            return Err(match primary_error {
                Some(err) => KinDbError::StorageError(format!(
                    "failed to open {} and no recovery snapshot exists: {err}",
                    path.display()
                )),
                None => KinDbError::StorageError(format!(
                    "snapshot {} is missing and recovery snapshot {} is not present",
                    path.display(),
                    tmp_path.display()
                )),
            });
        }

        let snapshot = mmap::load_recovery_candidate(path).map_err(|tmp_err| {
            let prefix = match primary_error {
                Some(primary_err) => format!(
                    "failed to open primary snapshot {}: {primary_err}; ",
                    path.display()
                ),
                None => format!("primary snapshot {} is missing; ", path.display()),
            };
            KinDbError::StorageError(format!(
                "{prefix}recovery snapshot {} is invalid: {tmp_err}",
                tmp_path.display()
            ))
        })?;

        mmap::promote_recovery_candidate(path).map_err(|err| {
            KinDbError::StorageError(format!(
                "loaded recovery snapshot {} but failed to promote it to {}: {err}",
                tmp_path.display(),
                path.display()
            ))
        })?;

        Ok(InMemoryGraph::from_snapshot(snapshot))
    }

    fn open_graph(path: &Path) -> Result<InMemoryGraph, KinDbError> {
        if path.exists() {
            match mmap::MmapReader::open(path) {
                Ok(snapshot) => Ok(InMemoryGraph::from_snapshot(snapshot)),
                Err(err) => Self::recover_graph_from_tmp(path, Some(&err)),
            }
        } else {
            let tmp_path = mmap::recovery_tmp_path(path);
            if tmp_path.exists() {
                Self::recover_graph_from_tmp(path, None)
            } else {
                Ok(InMemoryGraph::new())
            }
        }
    }

    /// Open an existing snapshot from disk, or create a new empty graph if
    /// the file doesn't exist.
    ///
    /// Acquires an OS-level exclusive file lock to prevent concurrent access
    /// from other processes. Returns `LockError` if another process holds the lock.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, KinDbError> {
        let path = normalize_snapshot_path(path.into());
        let lock_file = Self::acquire_lock(&path)?;
        let graph = Self::open_graph(&path)?;

        Ok(Self {
            path,
            current: RwLock::new(Arc::new(graph)),
            _lock_file: Some(lock_file),
        })
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
        let snapshot = graph.to_snapshot();

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
    use crate::storage::merkle::{
        build_entity_hash_map, compute_graph_root_hash, verify_entity, verify_subgraph,
        EntityVerification,
    };
    use crate::storage::GraphSnapshot;
    use crate::store::GraphStore;
    use crate::types::*;
    #[cfg(feature = "vector")]
    use crate::VectorIndex;
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

    fn test_entity_with_language(name: &str, file_origin: &str, language: LanguageId) -> Entity {
        let mut entity = test_entity(name);
        entity.file_origin = Some(FilePathId::new(file_origin));
        entity.language = language;
        entity
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
    fn open_recovers_from_tmp_when_primary_is_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let tmp_path = mmap::recovery_tmp_path(&path);

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let entity = test_entity("recover_missing_primary");
        let entity_id = entity.id;
        graph.upsert_entity(&entity).unwrap();
        let snapshot = graph.to_snapshot();
        mmap::write_recovery_candidate(&path, &snapshot).unwrap();
        drop(mgr);

        let recovered = SnapshotManager::open(&path).unwrap();
        let recovered_graph = recovered.graph();
        let fetched = recovered_graph.get_entity(&entity_id).unwrap().unwrap();
        assert_eq!(fetched.name, "recover_missing_primary");
        assert!(path.exists(), "primary snapshot should be promoted");
        assert!(!tmp_path.exists(), "recovery tmp should be consumed");
    }

    #[test]
    fn open_recovers_from_valid_tmp_when_primary_is_corrupted() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let tmp_path = mmap::recovery_tmp_path(&path);

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let entity = test_entity("recover_corrupted_primary");
        let entity_id = entity.id;
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        let snapshot = graph.to_snapshot();
        mmap::write_recovery_candidate(&path, &snapshot).unwrap();
        drop(mgr);

        let mut corrupt_bytes = std::fs::read(&path).unwrap();
        let mid = corrupt_bytes.len() / 2;
        corrupt_bytes[mid] ^= 0xFF;
        std::fs::write(&path, corrupt_bytes).unwrap();

        let recovered = SnapshotManager::open(&path).unwrap();
        let recovered_graph = recovered.graph();
        let fetched = recovered_graph.get_entity(&entity_id).unwrap().unwrap();
        assert_eq!(fetched.name, "recover_corrupted_primary");
        assert!(!tmp_path.exists(), "recovery tmp should be consumed");
    }

    #[test]
    fn open_rejects_invalid_tmp_when_primary_is_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let tmp_path = mmap::recovery_tmp_path(&path);
        std::fs::write(&tmp_path, b"not a snapshot").unwrap();

        let err = match SnapshotManager::open(&path) {
            Ok(_) => panic!("expected invalid recovery snapshot to fail opening"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("primary snapshot") && msg.contains("recovery snapshot"),
            "expected explicit recovery error, got: {msg}"
        );
    }

    #[test]
    fn open_rejects_unproven_tmp_when_primary_is_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let tmp_path = mmap::recovery_tmp_path(&path);

        let mut snapshot = GraphSnapshot::empty();
        let entity = test_entity("unproven_tmp");
        snapshot.entities = [(entity.id, entity)].into_iter().collect();
        std::fs::write(&tmp_path, snapshot.to_bytes().unwrap()).unwrap();

        let err = match SnapshotManager::open(&path) {
            Ok(_) => panic!("expected unproven recovery snapshot to fail opening"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("unproven without a valid marker"));
    }

    #[test]
    fn open_legacy_graph_kindb_path_redirects_to_snapshot_file() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join(".kin").join("kindb").join("graph.kndb");
        let legacy_path = dir.path().join(".kin").join("graph").join("kindb");

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        graph.upsert_entity(&test_entity("legacy_path")).unwrap();
        mgr.save().unwrap();

        let redirected = SnapshotManager::open(&legacy_path).unwrap();
        let entities = redirected.graph().list_all_entities().unwrap();
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].name, "legacy_path");
        assert_eq!(redirected.path(), snapshot_path.as_path());
    }

    #[test]
    fn save_and_reload_preserves_extended_state() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();

        let entity = test_entity("extended");
        graph.upsert_entity(&entity).unwrap();

        let base_change = SemanticChangeId::from_hash(Hash256::from_bytes([1; 32]));
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([2; 32])),
            parents: vec![base_change],
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "snapshot roundtrip".into(),
            entity_deltas: vec![EntityDelta::Added(entity.clone())],
            relation_deltas: Vec::new(),
            artifact_deltas: Vec::new(),
            projected_files: vec![FilePathId::new("src/main.rs")],
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            authored_on: Some(BranchName::new("main")),
        };
        graph.create_change(&change).unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("main"),
                head: change.id,
            })
            .unwrap();

        let shallow = ShallowTrackedFile {
            file_id: FilePathId::new("src/main.rs"),
            language_hint: "rust".into(),
            declaration_count: 1,
            import_count: 0,
            syntax_hash: Hash256::from_bytes([3; 32]),
            signature_hash: Some(Hash256::from_bytes([4; 32])),
        };
        graph.upsert_shallow_file(&shallow).unwrap();
        graph.set_file_hash("src/main.rs", [9; 32]);

        let work = WorkItem {
            work_id: WorkId::new(),
            kind: WorkKind::Task,
            title: "Persist snapshot state".into(),
            description: "Ensure KinDB round-trips all CLI-visible state.".into(),
            status: WorkStatus::InProgress,
            priority: Priority::High,
            scopes: vec![WorkScope::Entity(entity.id)],
            acceptance_criteria: vec!["Roundtrip succeeds".into()],
            external_refs: Vec::new(),
            created_by: IdentityRef::assistant("codex"),
            created_at: Timestamp::now(),
        };
        graph.create_work_item(&work).unwrap();

        let annotation = Annotation {
            annotation_id: AnnotationId::new(),
            kind: AnnotationKind::Instruction,
            body: "Keep snapshot state complete.".into(),
            scopes: vec![WorkScope::Entity(entity.id)],
            anchored_fingerprint: None,
            authored_by: IdentityRef::assistant("codex"),
            created_at: Timestamp::now(),
            staleness: StalenessState::Fresh,
        };
        graph.create_annotation(&annotation).unwrap();
        graph
            .create_work_link(&WorkLink::AttachedTo {
                annotation_id: annotation.annotation_id,
                target: AnnotationTarget::Work(work.work_id),
            })
            .unwrap();

        let test = TestCase {
            test_id: TestId::new(),
            name: "snapshot_roundtrip".into(),
            language: "rust".into(),
            kind: TestKind::Unit,
            scopes: vec![WorkScope::Entity(entity.id)],
            runner: TestRunner::Cargo,
            file_origin: Some(FilePathId::new("tests/snapshot.rs")),
        };
        graph.create_test_case(&test).unwrap();
        graph
            .create_test_covers_entity(&test.test_id, &entity.id)
            .unwrap();

        let run = VerificationRun {
            run_id: VerificationRunId::new(),
            test_ids: vec![test.test_id],
            status: VerificationStatus::Passing,
            runner: TestRunner::Cargo,
            started_at: Timestamp::now(),
            finished_at: None,
            duration_ms: Some(12),
            evidence_blob: None,
            exit_code: Some(0),
        };
        graph.create_verification_run(&run).unwrap();
        graph
            .create_mock_hint(&MockHint {
                hint_id: MockHintId::new(),
                test_id: test.test_id,
                dependency_scope: WorkScope::Entity(entity.id),
                strategy: MockStrategy::Stub,
            })
            .unwrap();

        let actor = Actor {
            actor_id: ActorId::new(),
            kind: ActorKind::Assistant,
            display_name: "Codex".into(),
            external_refs: Vec::new(),
        };
        graph.create_actor(&actor).unwrap();
        graph
            .create_approval(&Approval {
                approval_id: ApprovalId::new(),
                change_id: change.id,
                approver: actor.actor_id,
                decision: ApprovalDecision::Approved,
                reason: "Looks correct".into(),
                timestamp: Timestamp::now(),
            })
            .unwrap();
        graph
            .record_audit_event(&AuditEvent {
                event_id: AuditEventId::new(),
                actor_id: actor.actor_id,
                action: "snapshot.save".into(),
                target_scope: Some(WorkScope::Entity(entity.id)),
                timestamp: Timestamp::now(),
                details: Some("roundtrip test".into()),
            })
            .unwrap();

        let session = AgentSession {
            session_id: SessionId::new(),
            vendor: "openai".into(),
            client_name: "codex".into(),
            transport: kin_model::SessionTransport::Cli,
            pid: Some(42),
            cwd: PathBuf::from("/tmp/kin"),
            started_at: Timestamp::now(),
            last_heartbeat: Timestamp::now(),
            capabilities: kin_model::SessionCapabilities::default(),
        };
        graph.upsert_session(&session).unwrap();

        let intent = Intent {
            intent_id: IntentId::new(),
            session_id: session.session_id,
            scopes: vec![IntentScope::Entity(entity.id)],
            lock_type: LockType::Hard,
            task_description: "Persist KinDB".into(),
            registered_at: Timestamp::now(),
            expires_at: None,
        };
        graph.register_intent(&intent).unwrap();
        graph
            .create_downstream_warning(&intent.intent_id, &entity.id, "watch downstream")
            .unwrap();

        mgr.save().unwrap();

        let reloaded = SnapshotManager::open(&path).unwrap();
        let graph = reloaded.graph();

        assert!(graph.get_change(&change.id).unwrap().is_some());
        assert_eq!(
            graph
                .get_branch(&BranchName::new("main"))
                .unwrap()
                .unwrap()
                .head,
            change.id
        );
        assert_eq!(graph.list_shallow_files().unwrap().len(), 1);
        assert_eq!(graph.get_file_hash("src/main.rs"), Some([9; 32]));
        assert_eq!(
            graph.list_work_items(&WorkFilter::default()).unwrap().len(),
            1
        );
        assert_eq!(
            graph
                .list_annotations(&AnnotationFilter::default())
                .unwrap()
                .len(),
            1
        );
        assert_eq!(graph.get_tests_for_entity(&entity.id).unwrap().len(), 1);
        assert_eq!(
            graph.get_mock_hints_for_test(&test.test_id).unwrap().len(),
            1
        );
        assert_eq!(graph.list_actors().unwrap().len(), 1);
        assert_eq!(graph.get_approvals_for_change(&change.id).unwrap().len(), 1);
        assert_eq!(graph.query_audit_events(None, 10).unwrap().len(), 1);
        assert_eq!(graph.list_sessions().unwrap().len(), 1);
        assert_eq!(graph.list_all_intents().unwrap().len(), 1);
        assert_eq!(
            graph
                .downstream_warnings_for_entity(&entity.id)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn save_and_reload_preserves_mixed_language_entities_and_verification() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();

        let rust_entity = test_entity_with_language("compileRust", "src/lib.rs", LanguageId::Rust);
        let ts_entity = test_entity_with_language("renderTs", "web/app.ts", LanguageId::TypeScript);
        let py_entity = test_entity_with_language("trainPy", "tools/train.py", LanguageId::Python);

        graph.upsert_entity(&rust_entity).unwrap();
        graph.upsert_entity(&ts_entity).unwrap();
        graph.upsert_entity(&py_entity).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: rust_entity.id,
                dst: ts_entity.id,
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
            })
            .unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: ts_entity.id,
                dst: py_entity.id,
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
            })
            .unwrap();

        let test_case = TestCase {
            test_id: TestId::new(),
            name: "test_render_ts".into(),
            language: "typescript".into(),
            kind: TestKind::Unit,
            scopes: vec![],
            runner: TestRunner::Jest,
            file_origin: Some(FilePathId::new("web/app.test.ts")),
        };

        graph.create_test_case(&test_case).unwrap();
        graph
            .create_test_covers_entity(&test_case.test_id, &ts_entity.id)
            .unwrap();
        let root_before = compute_graph_root_hash(&graph.to_snapshot());
        mgr.save().unwrap();

        let reloaded = SnapshotManager::open(&path).unwrap();
        let graph = reloaded.graph();

        let filter = EntityFilter {
            languages: Some(vec![LanguageId::Rust, LanguageId::TypeScript]),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        let names: std::collections::HashSet<_> =
            results.iter().map(|entity| entity.name.as_str()).collect();

        assert_eq!(results.len(), 2);
        assert!(names.contains("compileRust"));
        assert!(names.contains("renderTs"));
        assert!(!names.contains("trainPy"));

        let summary = graph.get_coverage_summary().unwrap();
        assert_eq!(summary.total_entities, 3);
        assert_eq!(summary.covered_entities, 1);

        let reloaded_snapshot = graph.to_snapshot();
        let root_after = compute_graph_root_hash(&reloaded_snapshot);
        assert_eq!(root_before, root_after);

        let hashes = build_entity_hash_map(&reloaded_snapshot);
        assert_eq!(
            verify_entity(&rust_entity.id, &reloaded_snapshot, &hashes),
            EntityVerification::Valid
        );
        assert_eq!(
            verify_entity(&ts_entity.id, &reloaded_snapshot, &hashes),
            EntityVerification::Valid
        );
        let subgraph_report =
            verify_subgraph(&rust_entity.id, &reloaded_snapshot, &hashes).unwrap();
        assert!(subgraph_report.is_valid);
        assert!(subgraph_report.tampered.is_empty());
    }

    #[test]
    #[cfg(feature = "vector")]
    fn save_and_reload_preserves_mixed_language_vector_search_contract() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = dir.path().join("vectors.usearch");

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();

        let rust_entity = test_entity_with_language("compileRust", "src/lib.rs", LanguageId::Rust);
        let ts_entity = test_entity_with_language("renderTs", "web/app.ts", LanguageId::TypeScript);
        let py_entity = test_entity_with_language("trainPy", "tools/train.py", LanguageId::Python);

        graph.upsert_entity(&rust_entity).unwrap();
        graph.upsert_entity(&ts_entity).unwrap();
        graph.upsert_entity(&py_entity).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: rust_entity.id,
                dst: ts_entity.id,
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
            })
            .unwrap();

        let root_before = compute_graph_root_hash(&graph.to_snapshot());

        let vectors = VectorIndex::new(4).unwrap();
        vectors
            .upsert(rust_entity.id, &[1.0, 0.0, 0.0, 0.0])
            .unwrap();
        vectors
            .upsert(ts_entity.id, &[0.92, 0.08, 0.0, 0.0])
            .unwrap();
        vectors.upsert(py_entity.id, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        let results_before = vectors.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();

        mgr.save().unwrap();
        vectors.save(&vector_path).unwrap();

        let reloaded = SnapshotManager::open(&snapshot_path).unwrap();
        let graph = reloaded.graph();
        let reloaded_snapshot = graph.to_snapshot();
        let root_after = compute_graph_root_hash(&reloaded_snapshot);
        assert_eq!(root_before, root_after);

        let filter = EntityFilter {
            languages: Some(vec![LanguageId::Rust, LanguageId::TypeScript]),
            ..Default::default()
        };
        let filtered = graph.query_entities(&filter).unwrap();
        let filtered_ids: std::collections::HashSet<_> =
            filtered.iter().map(|entity| entity.id).collect();
        assert_eq!(filtered_ids.len(), 2);
        assert!(filtered_ids.contains(&rust_entity.id));
        assert!(filtered_ids.contains(&ts_entity.id));
        assert!(!filtered_ids.contains(&py_entity.id));

        let loaded_vectors = VectorIndex::load(&vector_path, 4).unwrap();
        let results_after = loaded_vectors
            .search_similar(&[1.0, 0.0, 0.0, 0.0], 2)
            .unwrap();

        assert_eq!(results_after, results_before);
        assert_eq!(results_after[0].0, rust_entity.id);
        assert_eq!(results_after[1].0, ts_entity.id);
    }

    #[test]
    fn open_rejects_corrupted_snapshot_after_save() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let entity = test_entity("corrupt_me");
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        let mut bytes = std::fs::read(&path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();

        let err = match SnapshotManager::open(&path) {
            Ok(_) => panic!("expected corrupted snapshot to fail reopening"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("checksum mismatch") || msg.contains("corrupted"),
            "expected corruption detection, got: {msg}"
        );
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
            import_source: None,
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

    #[test]
    fn concurrent_open_returns_lock_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        // First manager acquires the lock
        let _mgr1 = SnapshotManager::open(&path).unwrap();

        // Second open on the same path should fail with LockError
        let result = SnapshotManager::open(&path);
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("lock"),
            "expected lock error, got: {err_msg}"
        );
    }

    #[test]
    fn lock_released_on_drop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        // Open and immediately drop
        {
            let _mgr = SnapshotManager::open(&path).unwrap();
        }

        // Should succeed now that the previous manager is dropped
        let _mgr2 = SnapshotManager::open(&path).unwrap();
        assert_eq!(_mgr2.graph().entity_count(), 0);
    }

    #[test]
    fn concurrent_open_from_threads_one_wins() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        std::thread::scope(|s| {
            let handle1 = s.spawn(|| SnapshotManager::open(&path));
            let handle2 = s.spawn(|| SnapshotManager::open(&path));

            let r1 = handle1.join().unwrap();
            let r2 = handle2.join().unwrap();

            // Exactly one should succeed and one should fail
            match (&r1, &r2) {
                (Ok(_), Ok(_)) => panic!("both opens succeeded — lock not working"),
                (Ok(_), Err(_)) | (Err(_), Ok(_)) => {} // expected
                (Err(_), Err(_)) => panic!("both opens failed — expected one to succeed"),
            };
        });
    }

    #[test]
    fn reader_unblocked_during_writer_save() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::open(&path).unwrap();
        let graph = mgr.graph();
        let e = test_entity("concurrent_read");
        graph.upsert_entity(&e).unwrap();

        std::thread::scope(|s| {
            // Writer thread: saves to disk
            let mgr_ref = &mgr;
            let writer = s.spawn(move || {
                mgr_ref.save().unwrap();
            });

            // Reader thread: reads the graph concurrently
            let reader = s.spawn(move || {
                let g = mgr_ref.graph();
                // The graph should be readable regardless of save state
                let _ = g.entity_count(); // just verify we can read without panic
            });

            writer.join().unwrap();
            reader.join().unwrap();
        });
    }
}
