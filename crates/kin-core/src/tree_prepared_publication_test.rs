// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;
use std::cell::Cell;

fn has_wal(root: &Path) -> bool {
    std::fs::read_dir(root.join(".kin/reconciliation"))
        .unwrap()
        .any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("tx-")
        })
}

#[cfg(feature = "test-support")]
#[test]
fn prepared_workspace_observers_report_actual_payload_ack_and_first_primary_boundaries() {
    use crate::session_publication_test_support as core_observer;
    use kin_db::session_publication_test_support as db_observer;
    use sha2::Digest;
    use std::cell::RefCell;
    use std::rc::Rc;

    for fail_first in [false, true] {
        let mut f = StorageFixture::new();
        let body = b"second: true\n";
        let kind = entry(body);
        f.authority
            .save_source_blob(kind.blob_identity().unwrap(), body)
            .unwrap();
        let mut artifacts = f.target.artifacts().cloned().collect::<Vec<_>>();
        artifacts.push(kin_model::ResolvedArtifact::new(
            kin_model::ArtifactId::new(),
            RepoPath::from_utf8("second.yaml").unwrap(),
            kind,
        ));
        f.target = ResolvedTree::from_artifacts(artifacts).unwrap();
        let mutation = f.transaction.workspace_mutation.as_mut().unwrap();
        mutation.tree_deltas =
            crate::exact_tree_correction(&f.observed.resolved_tree, &f.target).unwrap();
        mutation.new_tree_hash = compute_resolved_tree_hash(&f.target).unwrap();
        let operation = f.transaction.operation_id;
        let hash = f.transaction.transaction_hash().unwrap();
        // The retained storage capability reports the resolved namespace path,
        // so the observer root has to be the resolved one. A macOS temporary
        // root is reached through a symlinked ancestor, and an unresolved join
        // would simply never match the runtime's exact path.
        let db_root = std::fs::canonicalize(f.root.path())
            .unwrap()
            .join(".kin/kindb")
            .join(f.transaction.repository_id.as_str());
        let authority_path = db_root.join("authority.json");
        let prior: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&authority_path).unwrap()).unwrap();
        let old_generation = prior["head_generation"].clone();
        assert!(old_generation.is_u64());
        let seen = Rc::new(RefCell::new(Vec::new()));
        let primary = f.root.path().to_path_buf();
        let db_seen = Rc::clone(&seen);
        let payload_guard = db_observer::observe(db_root.clone(), operation, move |event| {
            assert_eq!(
                event.point,
                db_observer::Point::PayloadConfirmedBeforeAcknowledgement
            );
            assert_eq!(event.operation, operation);
            assert_eq!(event.transaction_hash, hash);
            let payload = std::fs::read(
                event
                    .root
                    .join("session-publications")
                    .join(format!("{operation}.ksp")),
            )
            .unwrap();
            assert_eq!(
                sha2::Sha256::digest(&payload)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                event.payload_sha256
            );
            let record: serde_json::Value =
                serde_json::from_slice(&std::fs::read(event.root.join("authority.json")).unwrap())
                    .unwrap();
            assert!(!record["session_publications"]
                .as_array()
                .is_some_and(|entries| entries
                    .iter()
                    .any(|entry| entry["operation"] == operation.to_string())));
            assert!(!has_wal(&primary));
            assert!(!primary.join("compose.yaml").exists());
            assert!(!primary.join("second.yaml").exists());
            db_seen.borrow_mut().push("payload");
        })
        .unwrap();
        let core_seen = Rc::clone(&seen);
        let primary_guard =
            core_observer::observe(f.root.path().to_path_buf(), operation, move |event| {
                assert_eq!(event.operation, operation);
                assert_eq!(event.transaction_hash, hash);
                assert_eq!(event.total_entries, 2);
                assert_projection_locked(&event.root);
                let record: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&authority_path).unwrap()).unwrap();
                assert_eq!(record["head_generation"], old_generation);
                let acknowledgement = record["session_publications"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|entry| entry["operation"] == operation.to_string())
                    .unwrap();
                assert!(acknowledgement["committed_generation"].is_null());
                match event.point {
                    core_observer::Point::PreparationReturnedBeforeWal => {
                        assert!(!has_wal(&event.root));
                        assert_eq!(event.published_entries, 0);
                        assert!(event.published_path.is_none());
                        assert!(!event.root.join("compose.yaml").exists());
                        assert!(!event.root.join("second.yaml").exists());
                        core_seen.borrow_mut().push("prepared");
                    }
                    core_observer::Point::FirstPrimaryEntryPublished => {
                        assert!(has_wal(&event.root));
                        assert_eq!(event.published_entries, 1);
                        let published = event.published_path.as_ref().unwrap().as_utf8().unwrap();
                        assert!(event.root.join(published).is_file());
                        assert_eq!(
                            ["compose.yaml", "second.yaml"]
                                .iter()
                                .filter(|path| event.root.join(path).is_file())
                                .count(),
                            1
                        );
                        core_seen.borrow_mut().push("primary");
                    }
                }
            })
            .unwrap();
        if fail_first {
            inject_next_publication_failure();
        }
        let result = f.publish(
            &f.observed,
            || Ok(()),
            |_| panic!("unexpected unacknowledged release"),
            |_, _, _| Ok(()),
        );
        if fail_first {
            assert!(result
                .err()
                .unwrap()
                .to_string()
                .contains("injected exact-source publication failure"));
            assert_eq!(&*seen.borrow(), &["payload", "prepared"]);
        } else {
            let (count, committed) = result.unwrap();
            assert_eq!(count, 2);
            drop(committed);
            assert_eq!(&*seen.borrow(), &["payload", "prepared", "primary"]);
            assert!(!has_wal(f.root.path()));
        }
        drop(primary_guard);
        drop(payload_guard);
    }
}

fn assert_projection_locked(root: &Path) {
    let contender = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join(".kin/reconciliation/projection.lock"))
        .unwrap();
    assert!(
        fs2::FileExt::try_lock_exclusive(&contender).is_err(),
        "another writer must not acquire projection custody during finalization"
    );
}

fn entry(body: &[u8]) -> TreeEntry {
    TreeEntry::Blob {
        hash: kin_blobs::digest(body),
        executable: false,
    }
}

#[test]
fn prepared_publication_refuses_identity_drift_before_acknowledgement() {
    let root = tempfile::tempdir().unwrap();
    let path = RepoPath::from_utf8("source.py").unwrap();
    let old = b"def old(): pass\n";
    let new = b"def new(): pass\n";
    std::fs::write(root.path().join("source.py"), old).unwrap();
    drop(ProjectionRoot::open(root.path()).unwrap());
    let previous = validated_source_entries([(&path, entry(old), old.as_slice())]).unwrap();
    let target = validated_source_entries([(&path, entry(new), new.as_slice())]).unwrap();
    let prepared = Cell::new(false);
    let error = project_reconciled_source_tree_and_publish(
        root.path(),
        &previous,
        &target,
        &should_preserve_checkout_path,
        ReconciledProjectionOptions {
            open_mode: ProjectionOpenMode::ExistingFrozen,
            ..ReconciledProjectionOptions::default()
        },
        || {
            std::fs::write(root.path().join("source.py"), b"external edit\n").unwrap();
        },
        || {},
        || {},
        None,
        None,
        || {
            prepared.set(true);
            Ok(())
        },
        |()| -> ProjectionAuthorityCommit<()> { panic!("commit after failed identity check") },
        |_| panic!("finalization after failed identity check"),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("differs from prior workspace source"),
        "{error}"
    );
    assert!(!prepared.get());
    assert!(!has_wal(root.path()));
    assert_eq!(
        std::fs::read(root.path().join("source.py")).unwrap(),
        b"external edit\n"
    );
}

#[test]
fn prepared_publication_prepare_refusal_does_not_create_wal_or_change_source() {
    let root = tempfile::tempdir().unwrap();
    let path = RepoPath::from_utf8("source.py").unwrap();
    let old = b"def old(): pass\n";
    let new = b"def new(): pass\n";
    std::fs::write(root.path().join("source.py"), old).unwrap();
    drop(ProjectionRoot::open(root.path()).unwrap());
    let previous = validated_source_entries([(&path, entry(old), old.as_slice())]).unwrap();
    let target = validated_source_entries([(&path, entry(new), new.as_slice())]).unwrap();
    let error = project_reconciled_source_tree_and_publish(
        root.path(),
        &previous,
        &target,
        &should_preserve_checkout_path,
        ReconciledProjectionOptions {
            open_mode: ProjectionOpenMode::ExistingFrozen,
            ..ReconciledProjectionOptions::default()
        },
        || {},
        || {},
        || {},
        None,
        None,
        || -> Result<()> {
            assert_projection_locked(root.path());
            assert!(!has_wal(root.path()));
            Err(KinError::Other("acknowledgement refused".into()))
        },
        |()| -> ProjectionAuthorityCommit<()> { panic!("commit after failed preparation") },
        |_| panic!("finalization after failed preparation"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("acknowledgement refused"));
    assert!(!has_wal(root.path()));
    assert_eq!(std::fs::read(root.path().join("source.py")).unwrap(), old);
}

fn finish_publication(fail_finalization: bool) {
    let root = tempfile::tempdir().unwrap();
    let path = RepoPath::from_utf8("source.py").unwrap();
    let old = b"def old(): pass\n";
    let new = b"def new(): pass\n";
    std::fs::write(root.path().join("source.py"), old).unwrap();
    drop(ProjectionRoot::open(root.path()).unwrap());
    let previous = validated_source_entries([(&path, entry(old), old.as_slice())]).unwrap();
    let target = validated_source_entries([(&path, entry(new), new.as_slice())]).unwrap();
    let finalized = Cell::new(false);
    let marker = ReconciliationAuthorityCommit {
        repository_id: RepositoryId::new("prepared-publication-lifecycle").unwrap(),
        operation_id: OperationId::new(),
        transaction_hash: Hash256::from_bytes([0x39; 32]),
    };
    let result = project_reconciled_source_tree_and_publish(
        root.path(),
        &previous,
        &target,
        &should_preserve_checkout_path,
        ReconciledProjectionOptions {
            open_mode: ProjectionOpenMode::ExistingFrozen,
            ..ReconciledProjectionOptions::default()
        },
        || {},
        || {},
        || {},
        Some(marker),
        None,
        || {
            assert_projection_locked(root.path());
            assert!(!has_wal(root.path()));
            assert_eq!(std::fs::read(root.path().join("source.py")).unwrap(), old);
            Ok(String::from("exact preparation"))
        },
        |prepared| {
            assert_eq!(prepared, "exact preparation");
            assert!(has_wal(root.path()));
            assert_eq!(std::fs::read(root.path().join("source.py")).unwrap(), new);
            ProjectionAuthorityCommit::Committed(prepared)
        },
        |committed| {
            assert_eq!(committed.as_str(), "exact preparation");
            assert_projection_locked(root.path());
            assert!(has_wal(root.path()));
            assert_eq!(std::fs::read(root.path().join("source.py")).unwrap(), new);
            finalized.set(true);
            if fail_finalization {
                Err(KinError::Other("live finalization refused".into()))
            } else {
                Ok(())
            }
        },
    );
    assert!(finalized.get());
    assert_eq!(std::fs::read(root.path().join("source.py")).unwrap(), new);
    assert_eq!(has_wal(root.path()), fail_finalization);
    if fail_finalization {
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("live finalization refused"));
    } else {
        assert_eq!(result.unwrap(), (1, String::from("exact preparation")));
    }
}

#[test]
fn prepared_publication_finalizes_under_custody_before_wal_cleanup() {
    finish_publication(false);
}

#[test]
fn prepared_publication_finalization_refusal_retains_committed_bytes_and_wal() {
    finish_publication(true);
}

struct StorageFixture {
    root: tempfile::TempDir,
    authority: RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
    observed: kin_db::GraphSnapshot,
    target: ResolvedTree,
}

impl StorageFixture {
    fn new() -> Self {
        use kin_model::{
            AuthorId, ResolvedArtifact, WorkspaceMutation, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        };
        let root = tempfile::tempdir().unwrap();
        let initialized = crate::init(root.path()).unwrap();
        let authority = RepositoryAuthorityManager::open(
            initialized.repository_id.clone(),
            Arc::new(LocalFileBackend::new(initialized.layout.kindb_dir())),
        )
        .unwrap();
        let lease = authority.read_authority();
        let roots = lease.roots().clone();
        let workspace = lease.metadata().workspaces.first().unwrap().clone();
        let observed = lease
            .workspace_graph_snapshot(&workspace.workspace_id)
            .unwrap()
            .unwrap();
        drop(lease);
        assert!(workspace.tree.is_empty());
        let body = b"services: {}\n";
        let kind = entry(body);
        authority
            .save_source_blob(kind.blob_identity().unwrap(), body)
            .unwrap();
        let target = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            kin_model::ArtifactId::new(),
            RepoPath::from_utf8("compose.yaml").unwrap(),
            kind,
        )])
        .unwrap();
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: initialized.repository_id,
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: AuthorId::new("prepared-core-control"),
            reason: "exact prepared projection".into(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: Some(WorkspaceMutation {
                workspace_id: workspace.workspace_id,
                expected: WorkspaceExpectation::MustEqual {
                    generation: workspace.generation,
                    head: workspace.head.clone(),
                    base_target: workspace.base_target.clone(),
                    base_tree_hash: workspace.base_tree_hash,
                    tree_hash: workspace.tree_hash,
                    semantic_overlay_hash: workspace.semantic_overlay_hash,
                    admission_policy: workspace.admission_policy,
                },
                new_generation: workspace.generation + 1,
                new_head: workspace.head,
                new_base_target: workspace.base_target,
                new_base_tree_hash: workspace.base_tree_hash,
                tree_deltas: crate::exact_tree_correction(&workspace.tree, &target).unwrap(),
                new_tree_hash: compute_resolved_tree_hash(&target).unwrap(),
                semantic_delta: kin_model::WorkspaceSemanticDelta::default(),
                new_shared_admission_policy: workspace.shared_admission_policy,
                new_admission_policy: workspace.admission_policy,
            }),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
            collaboration_delta: None,
        };
        Self {
            root,
            authority,
            transaction,
            observed,
            target,
        }
    }

    fn publish<C>(
        &self,
        observed: &kin_db::GraphSnapshot,
        arm: impl FnOnce() -> Result<C>,
        release: impl FnOnce(C),
        finalize: impl FnOnce(
            &RepositoryCommitReceipt,
            &LocalRepositoryAuthorityFreeze,
            &mut C,
        ) -> Result<()>,
    ) -> Result<(usize, PreparedSessionWorkspaceCommit<C>)> {
        use kin_db::storage::{SessionPublicationBinding, SessionPublicationLocator};
        publish_prepared_session_workspace(
            self.root.path(),
            &self.observed.resolved_tree,
            &self.target,
            &self.authority,
            self.transaction.clone(),
            self.transaction
                .workspace_mutation
                .as_ref()
                .unwrap()
                .workspace_id,
            SessionPublicationBinding {
                session_id: "core-custody-control".into(),
                base_identity: kin_blobs::digest(b"base"),
                control_identity: kin_blobs::digest(b"control"),
            },
            SessionPublicationLocator::RetainedUnixV1 {
                session_leaf: "session-core control".into(),
            },
            observed,
            arm,
            release,
            finalize,
        )
    }
}

/// Checks ordering only; this is not the daemon's process-stop guard.
struct CustodyProbe<'a> {
    root: &'a Path,
    dropped: &'a Cell<bool>,
    armed: bool,
}
impl Drop for CustodyProbe<'_> {
    fn drop(&mut self) {
        if self.armed {
            assert_projection_locked(self.root);
            assert!(has_wal(self.root));
        }
        self.dropped.set(true);
    }
}

#[test]
fn prepared_workspace_core_finalizes_exact_durable_receipt_before_cleanup() {
    let f = StorageFixture::new();
    let dropped = Cell::new(false);
    let (count, committed) = f
        .publish(
            &f.observed,
            || {
                assert_projection_locked(f.root.path());
                assert!(!has_wal(f.root.path()));
                Ok(CustodyProbe {
                    root: f.root.path(),
                    dropped: &dropped,
                    armed: true,
                })
            },
            |_| panic!("valid preparation was not acknowledged"),
            |receipt, freeze, _| {
                assert_projection_locked(f.root.path());
                assert!(has_wal(f.root.path()));
                assert_eq!(freeze.roots(), &receipt.roots_after);
                assert_eq!(
                    std::fs::read(f.root.path().join("compose.yaml")).unwrap(),
                    b"services: {}\n"
                );
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(count, 1);
    assert!(!dropped.get());
    assert!(!has_wal(f.root.path()));
    let (mut custody, receipt, freeze) = committed.into_parts();
    custody.armed = false;
    drop(custody);
    assert!(dropped.get());
    assert_eq!(receipt.operation_id, f.transaction.operation_id);
    assert_eq!(
        receipt.transaction_hash,
        f.transaction.transaction_hash().unwrap()
    );
    drop(freeze);
    assert!(f
        .authority
        .active_prepared_session_publication()
        .unwrap()
        .is_none());
    let retained = f
        .authority
        .load_prepared_session_publication(receipt.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(retained.expected_receipt(), &receipt);
}

#[test]
fn prepared_workspace_core_drops_unresolved_owner_before_projection_custody() {
    let f = StorageFixture::new();
    let dropped = Cell::new(false);
    let result = f.publish(
        &f.observed,
        || {
            Ok(CustodyProbe {
                root: f.root.path(),
                dropped: &dropped,
                armed: true,
            })
        },
        |_| panic!("valid preparation was not acknowledged"),
        |_, _, _| Err(KinError::Other("finalization refused".into())),
    );
    assert!(result.is_err());
    assert!(dropped.get());
    assert!(has_wal(f.root.path()));
    assert_eq!(
        std::fs::read(f.root.path().join("compose.yaml")).unwrap(),
        b"services: {}\n"
    );
    assert!(f
        .authority
        .active_prepared_session_publication()
        .unwrap()
        .is_none());
    assert!(f
        .authority
        .load_prepared_session_publication(f.transaction.operation_id)
        .unwrap()
        .is_some());
}

#[test]
fn prepared_workspace_core_only_releases_an_absent_acknowledgement() {
    let f = StorageFixture::new();
    let mut wrong = f.observed.clone();
    wrong.resolved_tree = f.target.clone();
    let released = Cell::new(false);
    let result = f.publish(
        &wrong,
        || Ok(()),
        |()| {
            released.set(true);
            assert!(!has_wal(f.root.path()));
        },
        |_, _, _| panic!("invalid predecessor was committed"),
    );
    assert!(result.is_err());
    assert!(released.get());
    assert!(!has_wal(f.root.path()));
    assert!(!f.root.path().join("compose.yaml").exists());
    assert_eq!(
        f.authority.read_authority().roots(),
        &f.transaction.expected_roots
    );
    assert!(f
        .authority
        .load_prepared_session_publication(f.transaction.operation_id)
        .unwrap()
        .is_none());
}
