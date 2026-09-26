// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;
use kin_db::storage::{
    PreparedSessionPublication, SessionPublicationBinding, SessionPublicationLocator,
};
use kin_model::{
    AuthorId, ResolvedArtifact, WorkspaceMutation, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use std::cell::Cell;

#[derive(Clone, Copy)]
enum SealFault {
    BeforeWatermark,
    AfterReplacement,
}

struct Fixture {
    root: tempfile::TempDir,
    authority: RepositoryAuthorityManager<LocalFileBackend>,
    observed: kin_db::GraphSnapshot,
    target: ResolvedTree,
    transaction: RepositoryTransaction,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let initialized = crate::init(root.path()).unwrap();
        let authority = RepositoryAuthorityManager::open(
            initialized.repository_id,
            Arc::new(LocalFileBackend::new(initialized.layout.kindb_dir())),
        )
        .unwrap();
        let selected = authority.read_authority();
        let workspace = &selected.metadata().workspaces[0];
        let observed = selected
            .workspace_graph_snapshot(&workspace.workspace_id)
            .unwrap()
            .unwrap();
        assert!(observed.resolved_tree.is_empty());
        drop(selected);
        let artifacts = [
            ("first.yaml", b"first: true\n".as_slice()),
            ("second.yaml", b"second: true\n".as_slice()),
        ]
        .map(|(path, body)| {
            let hash = kin_blobs::digest(body);
            authority.save_source_blob(hash, body).unwrap();
            ResolvedArtifact::new(
                kin_model::ArtifactId::new(),
                RepoPath::from_utf8(path).unwrap(),
                TreeEntry::Blob {
                    hash,
                    executable: false,
                },
            )
        });
        let target = ResolvedTree::from_artifacts(artifacts).unwrap();
        let transaction = Self::transaction(&authority, &target);
        Self {
            root,
            authority,
            observed,
            target,
            transaction,
        }
    }
    fn transaction(
        authority: &RepositoryAuthorityManager<LocalFileBackend>,
        target: &ResolvedTree,
    ) -> RepositoryTransaction {
        let selected = authority.read_authority();
        let w = &selected.metadata().workspaces[0];
        RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: selected.metadata().repository_id.clone(),
            expected_generation: selected.roots().generation,
            expected_roots: selected.roots().clone(),
            actor: AuthorId::new("prepared-recovery-control"),
            reason: "exact recovery control".into(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: Some(WorkspaceMutation {
                workspace_id: w.workspace_id,
                expected: WorkspaceExpectation::MustEqual {
                    generation: w.generation,
                    head: w.head.clone(),
                    base_target: w.base_target.clone(),
                    base_tree_hash: w.base_tree_hash,
                    tree_hash: w.tree_hash,
                    semantic_overlay_hash: w.semantic_overlay_hash,
                    admission_policy: w.admission_policy,
                },
                new_generation: w.generation + 1,
                new_head: w.head.clone(),
                new_base_target: w.base_target.clone(),
                new_base_tree_hash: w.base_tree_hash,
                tree_deltas: crate::exact_tree_correction(&w.tree, target).unwrap(),
                new_tree_hash: compute_resolved_tree_hash(target).unwrap(),
                semantic_delta: kin_model::WorkspaceSemanticDelta::default(),
                new_shared_admission_policy: w.shared_admission_policy.clone(),
                new_admission_policy: w.admission_policy,
            }),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
            collaboration_delta: None,
        }
    }
    fn reopen(self) -> Self {
        let Self {
            root,
            authority,
            observed,
            target,
            transaction,
        } = self;
        let repository_id = transaction.repository_id.clone();
        drop(authority);
        let layout = crate::layout::KinLayout::new(root.path().join(".kin"));
        let authority = RepositoryAuthorityManager::open(
            repository_id,
            Arc::new(LocalFileBackend::new(layout.kindb_dir())),
        )
        .unwrap();
        Self {
            root,
            authority,
            observed,
            target,
            transaction,
        }
    }

    fn prepare(&self) -> PreparedSessionPublication {
        self.authority
            .prepare_session_publication_with_locator(
                self.transaction.clone(),
                self.transaction
                    .workspace_mutation
                    .as_ref()
                    .unwrap()
                    .workspace_id,
                SessionPublicationBinding {
                    session_id: "recovery-control".into(),
                    base_identity: kin_blobs::digest(b"base"),
                    control_identity: kin_blobs::digest(b"control"),
                },
                SessionPublicationLocator::RetainedUnixV1 {
                    session_leaf: "session-missing-on-purpose".into(),
                },
                &self.observed,
                &kin_index::binding_history::LocalBindingHistoryVerifier,
            )
            .unwrap()
    }
    fn marker(&self) -> ReconciliationAuthorityCommit {
        ReconciliationAuthorityCommit {
            repository_id: self.transaction.repository_id.clone(),
            operation_id: self.transaction.operation_id,
            transaction_hash: self.transaction.transaction_hash().unwrap(),
        }
    }
    fn wal(&self, marker: ReconciliationAuthorityCommit, publish: usize) -> PathBuf {
        self.wal_with_seal_fault(marker, publish, None)
    }
    fn wal_with_seal_fault(
        &self,
        marker: ReconciliationAuthorityCommit,
        publish: usize,
        fault: Option<(usize, SealFault)>,
    ) -> PathBuf {
        let owned =
            load_repository_projection_entries(&self.authority, &self.target, "test target")
                .unwrap();
        let entries = validated_source_entries(
            owned
                .iter()
                .map(|e| (&e.path, e.kind, e.content.as_slice())),
        )
        .unwrap();
        let projection = ProjectionRoot::open_existing_for_replay_recovery(
            self.root.path(),
            PROJECTION_LOCK_WAIT_DEADLINE,
        )
        .unwrap();
        let mut transaction = projection
            .create_reconciliation_transaction_with_commit_markers(Some(marker), None)
            .unwrap();
        let staged = projection
            .stage_reconciliation_entries(&transaction.directory, &entries)
            .unwrap();
        let mut directories = Vec::new();
        projection
            .prepare_without_replacement_transactional(
                &mut transaction,
                &entries.iter().map(|e| e.file_id).collect::<Vec<_>>(),
                &mut directories,
                &HashSet::new(),
            )
            .unwrap();
        for (index, entry) in staged.iter().take(publish).enumerate() {
            let fault_here = fault.filter(|(at, _)| *at == index).map(|(_, fault)| fault);
            match fault_here {
                Some(SealFault::BeforeWatermark) => INJECT_ACTION_SEAL_FAILURE.set(true),
                Some(SealFault::AfterReplacement) => INJECT_MANIFEST_ERROR_AFTER_RENAME.set(true),
                None => {}
            }
            let result = projection.publish_staged_entry(&mut transaction, entry);
            if let Some(fault) = fault_here {
                let message = match fault {
                    SealFault::BeforeWatermark => "before action watermark",
                    SealFault::AfterReplacement => "after successful replacement",
                };
                let error = result.unwrap_err();
                assert!(error.to_string().contains(message), "{error}");
                let retry = projection
                    .publish_staged_entry(&mut transaction, entry)
                    .unwrap_err();
                assert!(
                    retry.to_string().contains("unresolved action seal"),
                    "{retry}"
                );
                assert_eq!(transaction.manifest.actions.len(), index + 1);
                break;
            }
            result.unwrap();
        }
        projection
            .reconciliation_control_path()
            .join(&transaction.name)
    }
    fn recover(
        &self,
        prepared: PreparedSessionPublication,
    ) -> PreparedSessionWorkspaceRecovery<()> {
        recover_prepared_session_workspace(
            self.root.path(),
            &self.authority,
            prepared,
            (),
            |freeze, _| {
                assert_locked(self.root.path());
                freeze.revalidate_namespace()
            },
            |_, receipt, freeze, _| {
                assert_locked(self.root.path());
                assert_eq!(freeze.roots(), &receipt.roots_after);
                Ok(())
            },
        )
        .unwrap_or_else(|e| panic!("{e}"))
    }
    fn source(&self, name: &str) -> Option<Vec<u8>> {
        std::fs::read(self.root.path().join(name)).ok()
    }
    fn assert_target(&self) {
        assert_eq!(self.source("first.yaml").unwrap(), b"first: true\n");
        assert_eq!(self.source("second.yaml").unwrap(), b"second: true\n");
    }
}
fn assert_locked(root: &Path) {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join(".kin/reconciliation/projection.lock"))
        .unwrap();
    assert!(
        fs2::FileExt::try_lock_exclusive(&f).is_err(),
        "projection custody released"
    );
}
fn assert_no_wal(root: &Path) {
    assert!(!std::fs::read_dir(root.join(".kin/reconciliation"))
        .unwrap()
        .any(|e| e.unwrap().file_name().to_string_lossy().starts_with("tx-")));
}

#[test]
fn prepared_recovery_no_wal_replays_original_manager_target() {
    let f = Fixture::new();
    let prepared = f.prepare();
    let f = f.reopen();
    let result = f.recover(prepared);
    let (_, receipt, freeze, disposition) = result.into_parts();
    assert_eq!(disposition, PreparedRecoveryDisposition::ActivePublished);
    assert_eq!(receipt.operation_id, f.transaction.operation_id);
    assert_eq!(freeze.roots(), &receipt.roots_after);
    drop(freeze);
    f.assert_target();
    assert_no_wal(f.root.path());
    assert!(f
        .authority
        .active_prepared_session_publication()
        .unwrap()
        .is_none());
}
#[test]
fn prepared_recovery_partial_wal_rolls_back_and_replays_under_same_lock() {
    let f = Fixture::new();
    let prepared = f.prepare();
    let wal = f.wal(f.marker(), 1);
    assert!(f.source("first.yaml").is_some());
    assert!(f.source("second.yaml").is_none());
    let f = f.reopen();
    let (_, _, freeze, disposition) = f.recover(prepared).into_parts();
    drop(freeze);
    assert_eq!(disposition, PreparedRecoveryDisposition::ActivePublished);
    assert!(!wal.exists());
    f.assert_target();
    assert_no_wal(f.root.path());
}
#[test]
fn prepared_recovery_completed_wal_ignores_missing_disposable_session() {
    let f = Fixture::new();
    let prepared = f.prepare();
    let wal = f.wal(f.marker(), 2);
    let (original, freeze) = f
        .authority
        .commit_prepared_session_publication(&prepared)
        .unwrap();
    drop(freeze);
    let result = recover_prepared_session_workspace(
        f.root.path(),
        &f.authority,
        prepared,
        (),
        |_, _| panic!("completed replay must not open session"),
        |disposition, receipt, freeze, _| {
            assert_eq!(disposition, PreparedRecoveryDisposition::CompletedCurrent);
            assert_eq!(receipt.operation, original.operation);
            assert_eq!(freeze.roots(), &original.roots_after);
            assert!(wal.exists());
            Ok(())
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    drop(result);
    f.assert_target();
    assert!(!wal.exists());
}
#[test]
fn prepared_recovery_historical_receipt_does_not_rewind_current_bytes_or_roots() {
    let f = Fixture::new();
    let prepared = f.prepare();
    let wal = f.wal(f.marker(), 2);
    let (original, freeze) = f
        .authority
        .commit_prepared_session_publication(&prepared)
        .unwrap();
    drop(freeze);
    let mut artifacts = f.target.artifacts().cloned().collect::<Vec<_>>();
    let body = b"first: later\n";
    let hash = kin_blobs::digest(body);
    f.authority.save_source_blob(hash, body).unwrap();
    artifacts
        .iter_mut()
        .find(|a| a.path.as_utf8() == Some("first.yaml"))
        .unwrap()
        .entry = TreeEntry::Blob {
        hash,
        executable: false,
    };
    let later = ResolvedTree::from_artifacts(artifacts).unwrap();
    let next = Fixture::transaction(&f.authority, &later);
    let later_receipt = f.authority.commit_repository_transaction(next).unwrap();
    std::fs::write(f.root.path().join("first.yaml"), body).unwrap();
    let result = recover_prepared_session_workspace(
        f.root.path(),
        &f.authority,
        prepared,
        (),
        |_, _| panic!("historical session check"),
        |disposition, receipt, freeze, _| {
            assert_eq!(disposition, PreparedRecoveryDisposition::HistoricalReceipt);
            assert_eq!(receipt.operation, original.operation);
            assert_eq!(freeze.roots(), &later_receipt.roots_after);
            Ok(())
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    drop(result);
    assert_eq!(f.source("first.yaml").unwrap(), body);
    assert_eq!(
        f.authority.read_authority().roots(),
        &later_receipt.roots_after
    );
    assert!(!wal.exists());
}
#[test]
fn prepared_recovery_startup_cleans_completed_wal_without_session_or_handle() {
    let f = Fixture::new();
    let prepared = f.prepare();
    let wal = f.wal(f.marker(), 2);
    let (_, freeze) = f
        .authority
        .commit_prepared_session_publication(&prepared)
        .unwrap();
    drop(freeze);
    recover_repository_projection_before_hydration(f.root.path(), &f.authority).unwrap();
    assert!(!wal.exists());
    f.assert_target();
}

#[test]
fn prepared_recovery_startup_session_callback_keeps_custody_without_lock_recursion() {
    const CHILD: &str = "KINTEST_COMPLETED_WAL_FINALIZER_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tree::prepared_recovery_tests::prepared_recovery_startup_session_callback_keeps_custody_without_lock_recursion",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!("owned finalizer subprocess exceeded lock-order deadline: {output:?}");
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    for historical in [false, true] {
        let f = Fixture::new();
        let prepared = f.prepare();
        let wal = f.wal(f.marker(), 2);
        let (receipt, freeze) = f
            .authority
            .commit_prepared_session_publication(&prepared)
            .unwrap();
        drop(freeze);
        let current = if historical {
            let body = b"first: later\n";
            let hash = kin_blobs::digest(body);
            f.authority.save_source_blob(hash, body).unwrap();
            let mut artifacts = f.target.artifacts().cloned().collect::<Vec<_>>();
            artifacts
                .iter_mut()
                .find(|a| a.path.as_utf8() == Some("first.yaml"))
                .unwrap()
                .entry = TreeEntry::Blob {
                hash,
                executable: false,
            };
            let later = ResolvedTree::from_artifacts(artifacts).unwrap();
            std::fs::write(f.root.path().join("first.yaml"), body).unwrap();
            f.authority
                .commit_repository_transaction(Fixture::transaction(&f.authority, &later))
                .unwrap()
                .roots_after
        } else {
            receipt.roots_after.clone()
        };
        let f = f.reopen();
        let calls = Cell::new(0);
        recover_repository_projection_before_hydration_with_session_finalizer(
            f.root.path(),
            &f.authority,
            |saved, frozen| {
                calls.set(calls.get() + 1);
                assert!(wal.exists(), "cleanup preceded session finalization");
                assert_locked(f.root.path());
                let backend_lock = std::fs::File::open(
                    f.root
                        .path()
                        .join(".kin/kindb")
                        .join(f.transaction.repository_id.as_str()),
                )
                .unwrap();
                assert!(fs2::FileExt::try_lock_exclusive(&backend_lock).is_err());
                frozen.ensure_no_active_session_publication().unwrap();
                assert_eq!(saved.transaction(), prepared.transaction());
                assert_eq!(saved.binding(), prepared.binding());
                assert_eq!(saved.expected_receipt().operation, receipt.operation);
                assert_eq!(frozen.roots(), &current);
                assert_eq!(frozen.roots() != &receipt.roots_after, historical);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert!(!wal.exists());
        assert_eq!(
            f.source("first.yaml").unwrap(),
            if historical {
                b"first: later\n".as_slice()
            } else {
                b"first: true\n".as_slice()
            }
        );
        assert_eq!(f.source("second.yaml").unwrap(), b"second: true\n");
        assert_eq!(f.authority.read_authority().roots(), &current);
        recover_repository_projection_before_hydration_with_session_finalizer(
            f.root.path(),
            &f.authority,
            |_, _| panic!("no-WAL restart invoked finalizer"),
        )
        .unwrap();
    }
}

#[test]
fn prepared_recovery_startup_session_callback_refusal_retains_every_wal_for_retry() {
    for unwind in [false, true] {
        let f = Fixture::new();
        let prepared = f.prepare();
        let wal = f.wal(f.marker(), 2);
        let extra_wal = f.wal(f.marker(), 0);
        let (receipt, freeze) = f
            .authority
            .commit_prepared_session_publication(&prepared)
            .unwrap();
        drop(freeze);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            recover_repository_projection_before_hydration_with_session_finalizer(
                f.root.path(),
                &f.authority,
                |_, frozen| {
                    assert!(wal.exists() && extra_wal.exists());
                    assert_eq!(frozen.roots(), &receipt.roots_after);
                    if unwind {
                        panic!("controlled startup finalizer unwind");
                    }
                    Err(KinError::Other(
                        "controlled startup finalizer refusal".into(),
                    ))
                },
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(wal.exists() && extra_wal.exists());
        f.assert_target();
        let f = f.reopen();
        let calls = Cell::new(0);
        recover_repository_projection_before_hydration_with_session_finalizer(
            f.root.path(),
            &f.authority,
            |_, _| {
                calls.set(calls.get() + 1);
                assert!(wal.exists() && extra_wal.exists());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 1, "same operation needs only one finalization");
        assert!(!wal.exists() && !extra_wal.exists());
        f.assert_target();
    }
}

#[test]
fn prepared_recovery_startup_ordinary_or_absent_wal_never_invokes_session_callback() {
    for case in [
        "no_wal",
        "prepared_no_wal",
        "ordinary_pending",
        "ordinary_committed",
    ] {
        let f = Fixture::new();
        let wal = if case.starts_with("ordinary_") {
            Some(f.wal(f.marker(), 2))
        } else {
            None
        };
        if case == "prepared_no_wal" {
            let prepared = f.prepare();
            drop(
                f.authority
                    .commit_prepared_session_publication(&prepared)
                    .unwrap(),
            );
        } else if case == "ordinary_committed" {
            f.authority
                .commit_repository_transaction(f.transaction.clone())
                .unwrap();
        }
        let f = f.reopen();
        let roots = f.authority.read_authority().roots().clone();
        recover_repository_projection_before_hydration_with_session_finalizer(
            f.root.path(),
            &f.authority,
            |_, _| panic!("{case} invoked session callback"),
        )
        .unwrap();
        if let Some(wal) = wal {
            assert!(!wal.exists(), "{case}");
        }
        if case == "ordinary_committed" {
            f.assert_target();
        } else {
            assert!(f.source("first.yaml").is_none());
            assert!(f.source("second.yaml").is_none());
        }
        assert_eq!(f.authority.read_authority().roots(), &roots);
    }
}

#[test]
fn prepared_recovery_startup_mismatched_session_marker_refuses_before_callback_or_cleanup() {
    for wrong_repository in [false, true] {
        let f = Fixture::new();
        let prepared = f.prepare();
        let mut marker = f.marker();
        if wrong_repository {
            marker.repository_id = RepositoryId::new("foreign-session-repository").unwrap();
        } else {
            marker.transaction_hash = Hash256::from_bytes([0x83; 32]);
        }
        let wal = f.wal(marker, 2);
        let (receipt, freeze) = f
            .authority
            .commit_prepared_session_publication(&prepared)
            .unwrap();
        drop(freeze);
        let error = recover_repository_projection_before_hydration_with_session_finalizer(
            f.root.path(),
            &f.authority,
            |_, _| panic!("mismatched marker invoked callback"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("marker differs"), "{error}");
        assert!(wal.exists());
        f.assert_target();
        assert_eq!(f.authority.read_authority().roots(), &receipt.roots_after);
    }
}

#[test]
fn prepared_recovery_startup_missing_required_session_payload_preserves_wal() {
    let f = Fixture::new();
    let prepared = f.prepare();
    let wal = f.wal(f.marker(), 2);
    let (receipt, freeze) = f
        .authority
        .commit_prepared_session_publication(&prepared)
        .unwrap();
    drop(freeze);
    let directory = f
        .root
        .path()
        .join(".kin/kindb")
        .join(f.transaction.repository_id.as_str())
        .join("session-publications");
    let records = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    std::fs::remove_file(&records[0]).unwrap();
    assert!(
        recover_repository_projection_before_hydration_with_session_finalizer(
            f.root.path(),
            &f.authority,
            |_, _| panic!("missing payload invoked callback"),
        )
        .is_err()
    );
    assert!(wal.exists());
    f.assert_target();
    assert_eq!(f.authority.read_authority().roots(), &receipt.roots_after);
}
#[test]
fn prepared_recovery_frozen_no_active_fact_detects_ack_without_root_change() {
    let f = Fixture::new();
    let roots = f.authority.read_authority().roots().clone();
    f.authority
        .freeze_current_authority(&roots)
        .unwrap()
        .ensure_no_active_session_publication()
        .unwrap();
    let prepared = f.prepare();
    assert_eq!(f.authority.read_authority().roots(), &roots);
    let frozen = f.authority.freeze_current_authority(&roots).unwrap();
    assert!(frozen
        .ensure_no_active_session_publication()
        .unwrap_err()
        .to_string()
        .contains("active prepared"));
    drop(frozen);
    assert!(
        recover_repository_projection_before_hydration(f.root.path(), &f.authority)
            .unwrap_err()
            .to_string()
            .contains("active prepared")
    );
    assert_no_wal(f.root.path());
    assert!(f.source("first.yaml").is_none());
    let (_, frozen) = f
        .authority
        .commit_prepared_session_publication(&prepared)
        .unwrap();
    frozen.ensure_no_active_session_publication().unwrap();
}
#[test]
fn prepared_recovery_rejects_foreign_operation_or_hash_before_rollback() {
    for wrong_hash in [false, true] {
        let f = Fixture::new();
        let prepared = f.prepare();
        let mut marker = f.marker();
        if wrong_hash {
            marker.transaction_hash = Hash256::from_bytes([9; 32]);
        } else {
            marker.operation_id = OperationId::new();
        }
        let wal = f.wal(marker, 1);
        let before = f.source("first.yaml");
        let error = recover_prepared_session_workspace(
            f.root.path(),
            &f.authority,
            prepared,
            (),
            |_, _| Ok(()),
            |_, _, _, _| Ok(()),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("operation/hash"), "{error}");
        assert_eq!(f.source("first.yaml"), before);
        assert!(wal.exists());
        assert_eq!(
            f.authority.read_authority().roots(),
            &f.transaction.expected_roots
        );
    }
}
#[test]
fn prepared_recovery_missing_or_corrupt_wal_evidence_is_retained() {
    for missing in [false, true] {
        let f = Fixture::new();
        let prepared = f.prepare();
        let wal = f.wal(f.marker(), 1);
        let before = f.source("first.yaml");
        if missing {
            std::fs::remove_file(wal.join(RECONCILIATION_MANIFEST_FILE)).unwrap();
        } else {
            let action = std::fs::read_dir(&wal)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| {
                    p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("action-")
                })
                .unwrap();
            std::fs::write(action, b"corrupt record").unwrap();
        }
        assert!(recover_prepared_session_workspace(
            f.root.path(),
            &f.authority,
            prepared,
            (),
            |_, _| Ok(()),
            |_, _, _, _| Ok(())
        )
        .is_err());
        assert_eq!(f.source("first.yaml"), before);
        assert!(wal.exists());
        assert!(f
            .authority
            .active_prepared_session_publication()
            .unwrap()
            .is_some());
    }
}
#[test]
fn prepared_recovery_competing_eject_refuses_before_any_wal_mutation() {
    let f = Fixture::new();
    let prepared = f.prepare();
    let wal = f.wal(f.marker(), 1);
    let before = f.source("first.yaml");
    let eject = f
        .root
        .path()
        .join(".kin/reconciliation")
        .join(EXACT_EJECT_JOURNAL_FILE);
    std::fs::write(&eject, b"invalid competing eject evidence").unwrap();
    assert!(recover_prepared_session_workspace(
        f.root.path(),
        &f.authority,
        prepared,
        (),
        |_, _| Ok(()),
        |_, _, _, _| Ok(())
    )
    .is_err());
    assert_eq!(f.source("first.yaml"), before);
    assert!(wal.exists());
    assert_eq!(
        std::fs::read(eject).unwrap(),
        b"invalid competing eject evidence"
    );
}
struct DropProbe<'a> {
    root: &'a Path,
    dropped: &'a Cell<bool>,
    authority_lock: Option<PathBuf>,
}
impl Drop for DropProbe<'_> {
    fn drop(&mut self) {
        assert_locked(self.root);
        if let Some(lock) = &self.authority_lock {
            // Unix KinDB locks the retained repository directory; .lock is
            // only its namespace-identity marker.
            let file = std::fs::File::open(lock).unwrap();
            assert!(
                fs2::FileExt::try_lock_exclusive(&file).is_err(),
                "authority custody released before armed Drop"
            );
        }
        self.dropped.set(true);
    }
}
#[test]
fn prepared_recovery_finalizer_error_and_unwind_drop_custody_before_authority_and_projection() {
    for (completed, unwind) in [(false, false), (false, true), (true, false), (true, true)] {
        let f = Fixture::new();
        let prepared = f.prepare();
        if completed {
            f.wal(f.marker(), 2);
            let (_, freeze) = f
                .authority
                .commit_prepared_session_publication(&prepared)
                .unwrap();
            drop(freeze);
        }
        let dropped = Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            recover_prepared_session_workspace(
                f.root.path(),
                &f.authority,
                prepared,
                DropProbe {
                    root: f.root.path(),
                    dropped: &dropped,
                    authority_lock: Some(
                        f.root
                            .path()
                            .join(".kin/kindb")
                            .join(f.transaction.repository_id.as_str()),
                    ),
                },
                |_, _| Ok(()),
                |_, _, _, _| {
                    if unwind {
                        panic!("controlled finalization unwind");
                    }
                    Err(KinError::Other("controlled finalization refusal".into()))
                },
            )
        }));
        assert!(dropped.get());
        assert!(result.is_err() || result.unwrap().is_err());
        f.assert_target();
        assert!(std::fs::read_dir(f.root.path().join(".kin/reconciliation"))
            .unwrap()
            .any(|e| e.unwrap().file_name().to_string_lossy().starts_with("tx-")));
    }
}
#[test]
fn prepared_recovery_active_input_refusal_keeps_required_record_and_projection() {
    let f = Fixture::new();
    let prepared = f.prepare();
    let wal = f.wal(f.marker(), 1);
    let before = f.source("first.yaml");
    let dropped = Cell::new(false);
    let result = recover_prepared_session_workspace(
        f.root.path(),
        &f.authority,
        prepared,
        DropProbe {
            root: f.root.path(),
            dropped: &dropped,
            authority_lock: None,
        },
        |_, _| Err(KinError::Other("session custody changed".into())),
        |_, _, _, _| panic!("finalize refused input"),
    );
    assert!(result.is_err());
    assert!(dropped.get());
    assert_eq!(f.source("first.yaml"), before);
    assert!(wal.exists());
    assert!(f
        .authority
        .active_prepared_session_publication()
        .unwrap()
        .is_some());
}

#[test]
fn prepared_recovery_startup_preserves_ordinary_pending_wal_rollback() {
    let f = Fixture::new();
    let wal = f.wal(f.marker(), 1);
    assert!(f.source("first.yaml").is_some());
    recover_repository_projection_before_hydration(f.root.path(), &f.authority).unwrap();
    assert!(!wal.exists());
    assert!(f.source("first.yaml").is_none());
    assert!(f.source("second.yaml").is_none());
    assert_eq!(
        f.authority.read_authority().roots(),
        &f.transaction.expected_roots
    );
}

#[test]
fn prepared_recovery_missing_action_tail_retains_wal_until_exact_preflight() {
    let f = Fixture::new();
    let prepared = f.prepare();
    let wal = f.wal(f.marker(), 2);
    let mut actions = std::fs::read_dir(&wal)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(RECONCILIATION_ACTION_FILE_PREFIX)
        })
        .collect::<Vec<_>>();
    actions.sort();
    assert_eq!(
        actions.len(),
        2,
        "the two actual publications each have one intent"
    );
    std::fs::remove_file(actions.pop().unwrap()).unwrap();
    let error = recover_prepared_session_workspace(
        f.root.path(),
        &f.authority,
        prepared,
        (),
        |_, _| Ok(()),
        |_, _, _, _| panic!("incomplete restored projection finalized"),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("sealed watermark"), "{error}");
    assert!(
        wal.exists(),
        "failed exact preflight must retain the incomplete authenticated WAL"
    );
    assert!(
        f.source("first.yaml").is_some(),
        "an incomplete sealed WAL must refuse before any rollback"
    );
    assert_eq!(f.source("second.yaml").unwrap(), b"second: true\n");
    assert_eq!(
        f.authority.read_authority().roots(),
        &f.transaction.expected_roots
    );
    assert!(f
        .authority
        .active_prepared_session_publication()
        .unwrap()
        .is_some());
}

#[test]
fn prepared_recovery_post_lock_open_refusal_drops_custody_while_lock_is_held() {
    let f = Fixture::new();
    let prepared = f.prepare();
    let key = f
        .root
        .path()
        .join(".kin/reconciliation")
        .join(RECONCILIATION_AUTHORITY_FILE);
    std::fs::write(&key, b"invalid authority key").unwrap();
    let dropped = Cell::new(false);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        recover_prepared_session_workspace(
            f.root.path(),
            &f.authority,
            prepared,
            DropProbe {
                root: f.root.path(),
                dropped: &dropped,
                authority_lock: None,
            },
            |_, _| panic!("invalid authority reached active input validation"),
            |_, _, _, _| panic!("invalid authority reached finalization"),
        )
    }));
    assert!(
        outcome.is_ok(),
        "armed custody observed an already released projection lock"
    );
    let error = outcome.unwrap().err().unwrap();
    assert!(error.to_string().contains("exact 32-byte"), "{error}");
    assert!(dropped.get());
    assert_eq!(std::fs::read(key).unwrap(), b"invalid authority key");
    assert_eq!(
        f.authority.read_authority().roots(),
        &f.transaction.expected_roots
    );
    assert!(f
        .authority
        .active_prepared_session_publication()
        .unwrap()
        .is_some());
}

// The causal regression for ordinary startup recovery: an otherwise valid
// authenticated WAL whose final action record is gone. Unlike the prepared
// control above it never calls prepare(), so there is no saved target to
// preflight against and refusal has to rest on the sealed watermark alone.
#[test]
fn ordinary_startup_missing_action_tail_must_retain_recovery_evidence() {
    let f = Fixture::new();
    let wal = f.wal(f.marker(), 2);
    assert!(f
        .authority
        .active_prepared_session_publication()
        .unwrap()
        .is_none());
    let roots = f.authority.read_authority().roots().clone();
    let mut actions = std::fs::read_dir(&wal)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(RECONCILIATION_ACTION_FILE_PREFIX)
        })
        .collect::<Vec<_>>();
    actions.sort();
    assert_eq!(actions.len(), 2);
    std::fs::remove_file(actions.pop().unwrap()).unwrap();
    let result = recover_repository_projection_before_hydration(f.root.path(), &f.authority);
    eprintln!(
        "ORDINARY_TAIL_OBSERVATION {}",
        serde_json::json!({
            "returned_success": result.is_ok(),
            "error": result.as_ref().err().map(ToString::to_string),
            "wal_retained": wal.exists(),
            "first_source": f.source("first.yaml").map(|v| String::from_utf8(v).unwrap()),
            "second_source": f.source("second.yaml").map(|v| String::from_utf8(v).unwrap()),
            "roots_unchanged": f.authority.read_authority().roots() == &roots,
            "active_preparation": f.authority.active_prepared_session_publication().unwrap().is_some(),
        })
    );
    assert!(
        result.is_err(),
        "a valid action prefix is not proof of complete rollback"
    );
    assert!(
        wal.exists(),
        "unresolved recovery evidence must not be erased"
    );
    assert_eq!(f.authority.read_authority().roots(), &roots);
    // The known source remains outside the predecessor authority; this test
    // intentionally makes no demand to guess or delete an unrecorded target.
    assert_eq!(f.source("second.yaml").unwrap(), b"second: true\n");
}

// The causal regression for ordinary startup recovery: an otherwise valid
// authenticated WAL whose final action record is gone. Unlike the prepared
// control above it never calls prepare(), so there is no saved target to
// preflight against and refusal has to rest on the sealed watermark alone.
#[test]
fn ordinary_startup_missing_action_tail_cold_must_retain_recovery_evidence() {
    let f = Fixture::new();
    let wal = f.wal(f.marker(), 2);
    assert!(f
        .authority
        .active_prepared_session_publication()
        .unwrap()
        .is_none());
    let roots = f.authority.read_authority().roots().clone();
    let mut actions = std::fs::read_dir(&wal)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(RECONCILIATION_ACTION_FILE_PREFIX)
        })
        .collect::<Vec<_>>();
    actions.sort();
    assert_eq!(actions.len(), 2);
    std::fs::remove_file(actions.pop().unwrap()).unwrap();
    let f = f.reopen();
    let result = recover_repository_projection_before_hydration(f.root.path(), &f.authority);
    eprintln!(
        "ORDINARY_TAIL_COLD_OBSERVATION {}",
        serde_json::json!({
            "returned_success": result.is_ok(),
            "error": result.as_ref().err().map(ToString::to_string),
            "wal_retained": wal.exists(),
            "first_source": f.source("first.yaml").map(|v| String::from_utf8(v).unwrap()),
            "second_source": f.source("second.yaml").map(|v| String::from_utf8(v).unwrap()),
            "roots_unchanged": f.authority.read_authority().roots() == &roots,
            "active_preparation": f.authority.active_prepared_session_publication().unwrap().is_some(),
        })
    );
    assert!(
        result.is_err(),
        "a valid action prefix is not proof of complete rollback"
    );
    assert!(
        wal.exists(),
        "unresolved recovery evidence must not be erased"
    );
    assert_eq!(f.authority.read_authority().roots(), &roots);
    // The known source remains outside the predecessor authority; this test
    // intentionally makes no demand to guess or delete an unrecorded target.
    assert_eq!(f.source("second.yaml").unwrap(), b"second: true\n");
}

#[test]
fn watermark_one_durable_unsealed_intent_recovers_without_namespace_mutation() {
    for stop in [0, 1] {
        let f = Fixture::new();
        let wal = f.wal_with_seal_fault(f.marker(), 2, Some((stop, SealFault::BeforeWatermark)));
        assert_eq!(f.source("first.yaml").is_some(), stop == 1);
        assert!(
            f.source("second.yaml").is_none(),
            "unsealed intent must not mutate namespace"
        );
        let f = f.reopen();
        recover_repository_projection_before_hydration(f.root.path(), &f.authority).unwrap();
        assert!(!wal.exists());
        assert!(f.source("first.yaml").is_none());
        assert!(f.source("second.yaml").is_none());
        assert_eq!(
            f.authority.read_authority().roots(),
            &f.transaction.expected_roots
        );
    }
}

#[test]
fn watermark_replaced_descriptor_error_blocks_mutation_and_recovers_new_seal() {
    for stop in [0, 1] {
        let f = Fixture::new();
        let wal = f.wal_with_seal_fault(f.marker(), 2, Some((stop, SealFault::AfterReplacement)));
        let descriptor: AuthenticatedReconciliationManifest =
            serde_json::from_slice(&std::fs::read(wal.join(RECONCILIATION_MANIFEST_FILE)).unwrap())
                .unwrap();
        assert_eq!(
            descriptor.manifest.action_watermark.unwrap().count,
            stop as u64 + 1,
            "replacement happened despite the returned error"
        );
        assert_eq!(f.source("first.yaml").is_some(), stop == 1);
        assert!(f.source("second.yaml").is_none());
        let f = f.reopen();
        recover_repository_projection_before_hydration(f.root.path(), &f.authority).unwrap();
        assert!(!wal.exists());
        assert!(f.source("first.yaml").is_none());
        assert!(f.source("second.yaml").is_none());
        assert_eq!(
            f.authority.read_authority().roots(),
            &f.transaction.expected_roots
        );
    }
}

#[test]
fn watermark_each_action_caller_stops_before_namespace_mutation_when_seal_fails() {
    for action in [
        "publish_directory",
        "backup_directory",
        "backup_existing_object",
        "displace_previous_entry",
        "publish_object",
    ] {
        let f = Fixture::new();
        std::fs::create_dir(f.root.path().join("old-dir")).unwrap();
        std::fs::write(f.root.path().join("old-dir/sentinel"), b"retained").unwrap();
        std::fs::write(f.root.path().join("old.yaml"), b"old: true\n").unwrap();
        let projection = ProjectionRoot::open_existing_for_replay_recovery(
            f.root.path(),
            PROJECTION_LOCK_WAIT_DEADLINE,
        )
        .unwrap();
        let mut transaction = projection.create_reconciliation_transaction().unwrap();
        let probe = RepoPath::from_utf8("probe.yaml").unwrap();
        let probe_entry = ValidatedSourceEntry {
            file_id: &probe,
            kind: TreeEntry::Blob {
                hash: kin_blobs::digest(b"probe: true\n"),
                executable: false,
            },
            content: b"probe: true\n",
        };
        let staged = projection
            .stage_reconciliation_entries(&transaction.directory, &[probe_entry])
            .unwrap();
        let existing = projection
            .inspect_named_existing_object(
                &projection.root,
                std::ffi::OsStr::new("old.yaml"),
                ExistingObjectKind::File,
                &f.root.path().join("old.yaml"),
            )
            .unwrap();
        INJECT_ACTION_SEAL_FAILURE.set(true);
        let result = match action {
            "publish_directory" => projection
                .stage_and_publish_directory(
                    &mut transaction,
                    &projection.root,
                    std::ffi::OsStr::new("new-dir"),
                    Path::new("new-dir"),
                    0,
                )
                .map(|_| ()),
            "backup_directory" => projection
                .back_up_directory(&mut transaction, Path::new("old-dir"), 0, false, None)
                .map(|_| ()),
            "backup_existing_object" => projection.back_up_existing_object(
                &mut transaction,
                &PlannedExistingObject {
                    relative: PathBuf::from("old.yaml"),
                    kind: ExistingObjectKind::File,
                    identity: existing.0,
                    state: existing.1,
                },
                0,
            ),
            "displace_previous_entry" => {
                let previous = RepoPath::from_utf8("old.yaml").unwrap();
                projection.displace_previous_entry(
                    &mut transaction,
                    ValidatedSourceEntry {
                        file_id: &previous,
                        kind: TreeEntry::Blob {
                            hash: kin_blobs::digest(b"old: true\n"),
                            executable: false,
                        },
                        content: b"old: true\n",
                    },
                    existing.0,
                    0,
                )
            }
            "publish_object" => projection.publish_staged_entry(&mut transaction, &staged[0]),
            _ => unreachable!(),
        };
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("before action watermark"),
            "{action}: {error}"
        );
        assert_eq!(transaction.manifest.actions.len(), 1, "{action}");
        let retry = projection
            .publish_staged_entry(&mut transaction, &staged[0])
            .unwrap_err();
        assert!(
            retry.to_string().contains("unresolved action seal"),
            "{action}: {retry}"
        );
        assert_eq!(transaction.manifest.actions.len(), 1, "{action}");
        assert_eq!(
            projection
                .inspect_named_existing_object(
                    &projection.root,
                    std::ffi::OsStr::new("old.yaml"),
                    ExistingObjectKind::File,
                    &f.root.path().join("old.yaml"),
                )
                .unwrap(),
            existing,
            "{action}: old object identity/content changed"
        );
        assert_eq!(
            f.source("old-dir/sentinel").unwrap(),
            b"retained",
            "{action}"
        );
        assert!(!f.root.path().join("new-dir").exists(), "{action}");
        assert!(f.source("probe.yaml").is_none(), "{action}");
        let wal = projection
            .reconciliation_control_path()
            .join(&transaction.name);
        drop(transaction);
        drop(projection);
        let f = f.reopen();
        recover_repository_projection_before_hydration(f.root.path(), &f.authority)
            .unwrap_or_else(|e| panic!("{action}: {e}"));
        assert!(!wal.exists(), "{action}");
        assert_eq!(f.source("old.yaml").unwrap(), b"old: true\n", "{action}");
        assert_eq!(
            f.source("old-dir/sentinel").unwrap(),
            b"retained",
            "{action}"
        );
        assert!(!f.root.path().join("new-dir").exists(), "{action}");
        assert!(f.source("probe.yaml").is_none(), "{action}");
        assert_eq!(
            f.authority.read_authority().roots(),
            &f.transaction.expected_roots,
            "{action}"
        );
    }
}

fn rewrite_watermark_descriptor(
    f: &Fixture,
    wal: &Path,
    change: impl FnOnce(&mut ReconciliationManifest),
    reauthenticate_legacy_actions: bool,
) {
    let projection = ProjectionRoot::open_existing_for_replay_recovery(
        f.root.path(),
        PROJECTION_LOCK_WAIT_DEADLINE,
    )
    .unwrap();
    let name = wal.file_name().unwrap().to_os_string();
    let directory = open_directory_nofollow_for_removal(&projection.control, &name).unwrap();
    let identity = tracked_open_directory_identity(&directory).unwrap();
    let mut manifest = projection
        .load_reconciliation_manifest(&name, &directory)
        .unwrap()
        .unwrap();
    change(&mut manifest);
    if reauthenticate_legacy_actions {
        assert_eq!(manifest.schema, LEGACY_RECONCILIATION_MANIFEST_SCHEMA);
        let mut names = std::fs::read_dir(wal)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(RECONCILIATION_ACTION_FILE_PREFIX)
            })
            .collect::<Vec<_>>();
        names.sort();
        let mut tail = Vec::new();
        for path in names {
            let mut record: AuthenticatedReconciliationAction =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            record.previous_authentication = tail;
            record.authentication = projection
                .authenticate_reconciliation_action(
                    &manifest,
                    record.sequence,
                    &record.previous_authentication,
                    &record.action,
                )
                .unwrap();
            tail = record.authentication.clone();
            std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
        }
    }
    let transaction = ReconciliationTransaction {
        name,
        directory,
        identity,
        manifest,
        action_log_bytes: 0,
        action_tail_authentication: Vec::new(),
        action_recording_failed: false,
    };
    projection
        .persist_reconciliation_manifest(&transaction)
        .unwrap();
}

fn convert_wal_to_legacy_codec(f: &Fixture, wal: &Path) {
    // Protocol compatibility fixture, not a claim of genuine old-writer IO.
    rewrite_watermark_descriptor(
        f,
        wal,
        |manifest| {
            manifest.schema = LEGACY_RECONCILIATION_MANIFEST_SCHEMA;
            manifest.action_watermark = None;
        },
        true,
    );
}

#[test]
fn watermark_missing_or_inconsistent_seal_refuses_without_rollback() {
    for case in ["missing", "count", "tail", "two_unsealed", "empty_tail"] {
        let f = Fixture::new();
        let wal = f.wal(f.marker(), 2);
        rewrite_watermark_descriptor(
            &f,
            &wal,
            |manifest| match case {
                "missing" => manifest.action_watermark = None,
                "count" => manifest.action_watermark.as_mut().unwrap().count = 3,
                "tail" => {
                    manifest
                        .action_watermark
                        .as_mut()
                        .unwrap()
                        .tail_authentication[0] ^= 1
                }
                "two_unsealed" => {
                    manifest.action_watermark = Some(ReconciliationActionWatermark::default())
                }
                "empty_tail" => manifest
                    .action_watermark
                    .as_mut()
                    .unwrap()
                    .tail_authentication
                    .clear(),
                _ => unreachable!(),
            },
            false,
        );
        let error = recover_repository_projection_before_hydration(f.root.path(), &f.authority)
            .unwrap_err();
        assert!(error.to_string().contains("watermark"), "{case}: {error}");
        assert!(wal.exists());
        assert_eq!(f.source("first.yaml").unwrap(), b"first: true\n");
        assert_eq!(f.source("second.yaml").unwrap(), b"second: true\n");
        assert_eq!(
            f.authority.read_authority().roots(),
            &f.transaction.expected_roots
        );
    }
}

#[test]
fn watermark_missing_first_or_all_records_refuses_before_rollback() {
    for remove_all in [false, true] {
        let f = Fixture::new();
        let wal = f.wal(f.marker(), 2);
        let mut actions = std::fs::read_dir(&wal)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(RECONCILIATION_ACTION_FILE_PREFIX)
            })
            .collect::<Vec<_>>();
        actions.sort();
        for action in actions.iter().take(if remove_all { 2 } else { 1 }) {
            std::fs::remove_file(action).unwrap();
        }
        assert!(
            recover_repository_projection_before_hydration(f.root.path(), &f.authority).is_err()
        );
        assert!(wal.exists());
        assert_eq!(f.source("first.yaml").unwrap(), b"first: true\n");
        assert_eq!(f.source("second.yaml").unwrap(), b"second: true\n");
    }
}

#[test]
fn watermark_foreign_transaction_unsealed_intent_is_not_admitted() {
    let f = Fixture::new();
    let first = f.wal(f.marker(), 1);
    let second = f.wal(f.marker(), 0);
    let action = format!("{RECONCILIATION_ACTION_FILE_PREFIX}{:020}.json", 0);
    std::fs::copy(first.join(&action), second.join(&action)).unwrap();
    let error =
        recover_repository_projection_before_hydration(f.root.path(), &f.authority).unwrap_err();
    assert!(error.to_string().contains("authentication"), "{error}");
    assert!(first.exists() && second.exists());
    assert_eq!(f.source("first.yaml").unwrap(), b"first: true\n");
    assert!(f.source("second.yaml").is_none());
}

#[test]
fn watermark_legacy_pending_is_retained_but_exact_prepared_target_can_recover() {
    for prepared_path in [false, true] {
        let f = Fixture::new();
        let prepared = prepared_path.then(|| f.prepare());
        let wal = f.wal(f.marker(), 1);
        convert_wal_to_legacy_codec(&f, &wal);
        let f = f.reopen();
        if let Some(prepared) = prepared {
            drop(f.recover(prepared));
            f.assert_target();
            assert!(!wal.exists());
        } else {
            let error = recover_repository_projection_before_hydration(f.root.path(), &f.authority)
                .unwrap_err();
            assert!(error.to_string().contains("legacy pending"), "{error}");
            assert!(wal.exists());
            assert_eq!(f.source("first.yaml").unwrap(), b"first: true\n");
            assert!(f.source("second.yaml").is_none());
        }
    }
}

#[test]
fn watermark_legacy_completed_requires_independent_authority_disposition() {
    for actually_committed in [false, true] {
        let f = Fixture::new();
        let prepared = actually_committed.then(|| f.prepare());
        let wal = f.wal(f.marker(), 2);
        convert_wal_to_legacy_codec(&f, &wal);
        // A legacy descriptor's own state is not an independently held receipt.
        rewrite_watermark_descriptor(
            &f,
            &wal,
            |m| m.state = ReconciliationTransactionState::Committed,
            false,
        );
        if let Some(prepared) = prepared {
            drop(
                f.authority
                    .commit_prepared_session_publication(&prepared)
                    .unwrap(),
            );
        }
        let f = f.reopen();
        let result = recover_repository_projection_before_hydration(f.root.path(), &f.authority);
        assert_eq!(result.is_ok(), actually_committed);
        assert_eq!(wal.exists(), !actually_committed);
        assert_eq!(f.source("first.yaml").unwrap(), b"first: true\n");
        assert_eq!(f.source("second.yaml").unwrap(), b"second: true\n");
    }
}

#[test]
fn watermark_legacy_ordinary_committed_descriptor_preserves_cleanup_only_contract() {
    // Schema 3 retained this reader disposition but did not have a production
    // Committed writer. These are authenticated codec fixtures, not old-writer IO.
    for generic_open in [false, true] {
        for state in ["pending", "committed", "tampered"] {
            let f = Fixture::new();
            let wal = f.wal(f.marker(), 2);
            convert_wal_to_legacy_codec(&f, &wal);
            rewrite_watermark_descriptor(
                &f,
                &wal,
                |m| {
                    m.authority_commit = None;
                    m.state = if state == "committed" {
                        ReconciliationTransactionState::Committed
                    } else {
                        ReconciliationTransactionState::Pending
                    };
                },
                false,
            );
            if state == "tampered" {
                let path = wal.join(RECONCILIATION_MANIFEST_FILE);
                let mut descriptor: AuthenticatedReconciliationManifest =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                descriptor.manifest.state = ReconciliationTransactionState::Committed;
                std::fs::write(path, serde_json::to_vec(&descriptor).unwrap()).unwrap();
            }
            let f = f.reopen();
            let result = if generic_open {
                ProjectionRoot::open_existing_for_reconciliation(
                    f.root.path(),
                    PROJECTION_LOCK_WAIT_DEADLINE,
                )
                .map(drop)
            } else {
                recover_repository_projection_before_hydration(f.root.path(), &f.authority)
            };
            assert_eq!(
                result.is_ok(),
                state == "committed",
                "{generic_open}/{state}: {result:?}"
            );
            assert_eq!(wal.exists(), state != "committed");
            assert_eq!(f.source("first.yaml").unwrap(), b"first: true\n");
            assert_eq!(f.source("second.yaml").unwrap(), b"second: true\n");
            assert_eq!(
                f.authority.read_authority().roots(),
                &f.transaction.expected_roots
            );
        }
    }
}

#[test]
fn watermark_generic_projection_open_refuses_truncated_pending_log() {
    let f = Fixture::new();
    let wal = f.wal(f.marker(), 2);
    rewrite_watermark_descriptor(&f, &wal, |m| m.authority_commit = None, false);
    std::fs::remove_file(wal.join(format!("{RECONCILIATION_ACTION_FILE_PREFIX}{:020}.json", 1)))
        .unwrap();
    let error = ProjectionRoot::open_existing_for_reconciliation(
        f.root.path(),
        PROJECTION_LOCK_WAIT_DEADLINE,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("sealed watermark"), "{error}");
    assert!(wal.exists());
    assert_eq!(f.source("first.yaml").unwrap(), b"first: true\n");
    assert_eq!(f.source("second.yaml").unwrap(), b"second: true\n");
}
