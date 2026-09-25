// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

mod prepared_session_tests {
    use super::*;
    use crate::storage::binding_history::{
        BindingHistoryDecision, BindingHistoryTransition, BindingHistoryVerifier,
    };
    use crate::storage::{PreparedSessionPublication, SessionPublicationBinding};

    /// These exercise the DB's trusted-verifier/custody boundary. They do not
    /// claim parser correctness, native session startup, or projection safety.
    struct SessionStorageVerifier;
    impl BindingHistoryVerifier for SessionStorageVerifier {
        fn verify_graph_transition(
            &self,
            before: &GraphSnapshot,
            after: &GraphSnapshot,
            _: &dyn Fn(Hash256) -> Result<Option<Vec<u8>>, KinDbError>,
        ) -> Result<bool, KinDbError> {
            Ok(before.resolved_tree == after.resolved_tree)
        }
        fn verify_transition(
            &self,
            transition: BindingHistoryTransition<'_>,
        ) -> Result<BindingHistoryDecision, KinDbError> {
            Ok(BindingHistoryDecision::Qualified {
                protocol: crate::storage::binding_history::BINDING_HISTORY_PROTOCOL,
                workspaces: transition
                    .successor()
                    .metadata()
                    .workspaces
                    .iter()
                    .filter(|workspace| transition.eligibility(workspace.workspace_id).is_some())
                    .map(|workspace| workspace.workspace_id)
                    .collect(),
            })
        }
    }

    struct Fixture {
        dir: tempfile::TempDir,
        backend: Arc<LocalFileBackend>,
        manager: RepositoryAuthorityManager<LocalFileBackend>,
        workspace: WorkspaceId,
    }
    impl Fixture {
        fn new(checked: bool) -> Self {
            let dir = tempfile::TempDir::new().unwrap();
            let backend = Arc::new(LocalFileBackend::new(dir.path()));
            let manager =
                RepositoryAuthorityManager::open(repository_id(), backend.clone()).unwrap();
            let init = unborn_workspace_transaction(&manager, 0xc000, 0xc001, b"main");
            if checked {
                manager
                    .commit_repository_transaction_with_binding_history(init, &StorageTestVerifier)
                    .unwrap();
            } else {
                manager.commit_repository_transaction(init).unwrap();
            }
            Self {
                dir,
                backend,
                manager,
                workspace: WorkspaceId::from_uuid(Uuid::from_u128(0xc001)),
            }
        }
        fn observation(&self) -> GraphSnapshot {
            self.manager
                .workspace_graph_snapshot(&repository_id(), &self.workspace)
                .unwrap()
                .unwrap()
        }
        fn transaction(&self, operation: u128) -> RepositoryTransaction {
            let mut transaction = semantic_workspace_transaction(
                &self.manager,
                operation,
                WorkspaceSemanticDelta::default(),
            );
            let body = b"def target():\n    return 1\n";
            self.manager.save_source_blob(digest(body), body).unwrap();
            let mutation = transaction.workspace_mutation.as_mut().unwrap();
            mutation.tree_deltas.push(TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(0xc004)),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("target.py").unwrap(),
                    TreeEntry::blob(digest(body), false),
                ),
            });
            mutation.new_tree_hash = compute_resolved_tree_hash(
                &self.manager.read_authority().metadata().workspaces[0]
                    .tree
                    .apply(&mutation.tree_deltas)
                    .unwrap(),
            )
            .unwrap();
            transaction
        }
        fn prepare(&self) -> PreparedSessionPublication {
            self.manager
                .prepare_session_publication(
                    self.transaction(0xc002),
                    self.workspace,
                    binding(),
                    &self.observation(),
                    &SessionStorageVerifier,
                )
                .unwrap()
        }
        fn reopen(&self) -> RepositoryAuthorityManager<LocalFileBackend> {
            RepositoryAuthorityManager::open(
                repository_id(),
                Arc::new(LocalFileBackend::new(self.dir.path())),
            )
            .unwrap()
        }
        fn authority(&self) -> std::path::PathBuf {
            self.dir
                .path()
                .join(repository_id().as_str())
                .join("authority.json")
        }
        fn record(&self) -> std::path::PathBuf {
            self.dir
                .path()
                .join(repository_id().as_str())
                .join("session-publications")
                .join(format!(
                    "{}.ksp",
                    OperationId::from_uuid(Uuid::from_u128(0xc002))
                ))
        }
    }
    fn binding() -> SessionPublicationBinding {
        SessionPublicationBinding {
            session_id: "owned-session".into(),
            base_identity: digest(b"base"),
            control_identity: digest(b"control"),
        }
    }

    fn locator(leaf: &str) -> crate::storage::SessionPublicationLocator {
        crate::storage::SessionPublicationLocator::RetainedUnixV1 {
            session_leaf: leaf.into(),
        }
    }

    #[test]
    fn prepared_session_v2_locator_survives_cold_commit_and_exact_replay() {
        let f = Fixture::new(true);
        let location = locator("session-actual space-東京");
        let prepared = f
            .manager
            .prepare_session_publication_with_locator(
                f.transaction(0xc002),
                f.workspace,
                binding(),
                location.clone(),
                &f.observation(),
                &SessionStorageVerifier,
            )
            .unwrap();
        assert_eq!(prepared.record.version, 2);
        assert_eq!(prepared.recovery_locator().unwrap(), &location);
        let cold = f.reopen();
        let loaded = cold.active_prepared_session_publication().unwrap().unwrap();
        assert_eq!(loaded.recovery_locator().unwrap(), &location);
        let (receipt, freeze) = cold.commit_prepared_session_publication(&loaded).unwrap();
        drop(freeze);
        let replay_manager = f.reopen();
        let replay = replay_manager
            .load_prepared_session_publication(prepared.operation_id())
            .unwrap()
            .unwrap();
        assert_eq!(replay.recovery_locator().unwrap(), &location);
        let (again, freeze) = replay_manager
            .commit_prepared_session_publication(&replay)
            .unwrap();
        drop(freeze);
        assert_eq!(
            again.outcome,
            kin_model::RepositoryCommitOutcome::IdempotentReplay
        );
        let mut expected = receipt;
        expected.outcome = kin_model::RepositoryCommitOutcome::IdempotentReplay;
        assert_eq!(again, expected);
    }

    #[test]
    fn prepared_session_v1_retains_exact_encoding_and_digest_without_locator() {
        use sha2::Digest;
        // The pre-extension record shape is kept here as a wire compatibility
        // oracle: order, omitted locator, and the v1 digest domain all matter.
        #[derive(serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LegacyRecord {
            version: u32,
            binding: SessionPublicationBinding,
            workspace: WorkspaceId,
            predecessor_authority: String,
            predecessor_backend_generation: u64,
            transaction: RepositoryTransaction,
            observed: crate::storage::session_publication::CapturedSessionGraph,
            observed_digest: Hash256,
            successor_graph_digest: Hash256,
            successor_history: Vec<crate::storage::binding_history::BindingHistoryWitness>,
            receipt: RepositoryCommitReceipt,
        }
        let f = Fixture::new(true);
        let prepared = f.prepare();
        let bytes = prepared.record.encode().unwrap();
        let legacy: LegacyRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&legacy).unwrap(), bytes);
        assert!(!String::from_utf8(bytes.clone())
            .unwrap()
            .contains("recovery_locator"));
        let mut original_hash = sha2::Sha256::new();
        original_hash.update(b"kin.prepared-session.record.v1\0");
        crate::storage::canonical_hash::canonical_hash_into(&mut original_hash, &legacy).unwrap();
        assert_eq!(
            prepared.record.content_digest().unwrap(),
            Hash256::from_bytes(original_hash.finalize().into())
        );
        assert!(prepared
            .recovery_locator()
            .unwrap_err()
            .to_string()
            .contains("unsupported runtime recovery identity"));
        let mut v2 = prepared.record.clone();
        v2.version = 2;
        v2.recovery_locator = Some(locator("session-space allowed"));
        assert!(
            serde_json::from_slice::<LegacyRecord>(&v2.encode().unwrap()).is_err(),
            "old reader must refuse the new field"
        );
        let mut v2_hash = sha2::Sha256::new();
        v2_hash.update(b"kin.prepared-session.record.v2\0");
        crate::storage::canonical_hash::canonical_hash_into(&mut v2_hash, &v2).unwrap();
        assert_eq!(
            v2.content_digest().unwrap(),
            Hash256::from_bytes(v2_hash.finalize().into())
        );
        assert!(
            crate::storage::session_publication::PreparedSessionRecord::decode(&bytes)
                .unwrap()
                .recovery_locator
                .is_none()
        );
    }

    #[test]
    fn prepared_session_version_locator_pairs_and_malformed_locations_refuse() {
        let f = Fixture::new(true);
        let prepared = f.prepare();
        for (version, location) in [(1, Some(locator("session-ok"))), (2, None), (3, None)] {
            let mut bad = prepared.record.clone();
            bad.version = version;
            bad.recovery_locator = location;
            let bytes = serde_json::to_vec(&bad).unwrap();
            assert!(
                crate::storage::session_publication::PreparedSessionRecord::decode(&bytes).is_err()
            );
            assert!(bad.encode().is_err());
            assert!(bad.content_digest().is_err());
        }
        for version in [1, 2] {
            let mut explicit_null = serde_json::to_value(&prepared.record).unwrap();
            explicit_null["version"] = version.into();
            explicit_null["recovery_locator"] = serde_json::Value::Null;
            assert!(
                crate::storage::session_publication::PreparedSessionRecord::decode(
                    &serde_json::to_vec(&explicit_null).unwrap()
                )
                .is_err()
            );
        }
        for leaf in [
            "session-",
            "other",
            "session-a/b",
            "session-a\0b",
            "../session-ok",
        ] {
            assert!(locator(leaf).validate().is_err(), "{leaf:?}");
        }
    }

    #[test]
    fn prepared_session_v2_retry_cannot_rebind_or_downgrade_locator() {
        let f = Fixture::new(true);
        let prepared = f
            .manager
            .prepare_session_publication_with_locator(
                f.transaction(0xc002),
                f.workspace,
                binding(),
                locator("session-original"),
                &f.observation(),
                &SessionStorageVerifier,
            )
            .unwrap();
        let original = std::fs::read(f.record()).unwrap();
        assert!(f
            .manager
            .prepare_session_publication_with_locator(
                f.transaction(0xc002),
                f.workspace,
                binding(),
                locator("session-other"),
                &f.observation(),
                &SessionStorageVerifier,
            )
            .is_err());
        assert!(f
            .manager
            .prepare_session_publication(
                f.transaction(0xc002),
                f.workspace,
                binding(),
                &f.observation(),
                &SessionStorageVerifier,
            )
            .is_err());
        assert_eq!(std::fs::read(f.record()).unwrap(), original);
        assert_eq!(
            f.reopen()
                .active_prepared_session_publication()
                .unwrap()
                .unwrap()
                .transaction_hash(),
            prepared.transaction_hash()
        );
    }

    #[test]
    fn prepared_session_v2_unacknowledged_retry_preserves_locator_and_payload() {
        use crate::storage::backend::PreparationFault;
        let f = Fixture::new(true);
        LocalFileBackend::fail_next_session_preparation(PreparationFault::BeforeAcknowledgement);
        assert!(f
            .manager
            .prepare_session_publication_with_locator(
                f.transaction(0xc002),
                f.workspace,
                binding(),
                locator("session-original"),
                &f.observation(),
                &SessionStorageVerifier,
            )
            .is_err());
        let original = std::fs::read(f.record()).unwrap();
        let cold = f.reopen();
        assert!(cold
            .prepare_session_publication_with_locator(
                f.transaction(0xc002),
                f.workspace,
                binding(),
                locator("session-other"),
                &f.observation(),
                &SessionStorageVerifier,
            )
            .is_err());
        let loaded = cold
            .prepare_session_publication_with_locator(
                f.transaction(0xc002),
                f.workspace,
                binding(),
                locator("session-original"),
                &f.observation(),
                &SessionStorageVerifier,
            )
            .unwrap();
        assert_eq!(
            loaded.recovery_locator().unwrap(),
            &locator("session-original")
        );
        assert_eq!(std::fs::read(f.record()).unwrap(), original);
    }

    #[test]
    fn prepared_session_cold_commit_keeps_exact_operation_and_checked_proof() {
        let f = Fixture::new(true);
        let before = f.manager.read_authority().roots().clone();
        let prepared = f.prepare();
        assert_eq!(*f.manager.read_authority().roots(), before);
        assert!(
            prepared
                .record
                .observed
                .graph()
                .verified_binding_history
                .is_none(),
            "no runtime capability is serialized"
        );
        let reopened = f.reopen();
        let loaded = reopened
            .active_prepared_session_publication()
            .unwrap()
            .unwrap();
        assert_eq!(loaded.expected_receipt(), prepared.expected_receipt());
        let (receipt, frozen) = reopened
            .commit_prepared_session_publication(&loaded)
            .unwrap();
        assert_eq!(receipt, *prepared.expected_receipt());
        assert_eq!(frozen.roots(), &receipt.roots_after);
        drop(frozen);
        let cold = f.reopen();
        assert!(cold
            .active_prepared_session_publication()
            .unwrap()
            .is_none());
        assert!(cold
            .workspace_graph_snapshot(&repository_id(), &f.workspace)
            .unwrap()
            .unwrap()
            .verified_binding_history
            .is_some());
        let replay = cold
            .load_prepared_session_publication(prepared.operation_id())
            .unwrap()
            .unwrap();
        let (replayed, freeze) = cold.commit_prepared_session_publication(&replay).unwrap();
        assert_eq!(replayed.operation, receipt.operation);
        assert_eq!(replayed.outcome, RepositoryCommitOutcome::IdempotentReplay);
        drop(freeze);
        assert_eq!(cold.read_authority().generation(), before.generation + 1);
    }

    #[test]
    fn prepared_session_fences_other_managers_writes_transfer_and_compaction() {
        let f = Fixture::new(true);
        let handle = f.prepare();
        let other = f.reopen();
        let before = std::fs::read(f.authority()).unwrap();
        let normal = binding_history_followup(&other, 0xc020);
        assert!(other
            .commit_repository_transaction(normal.clone())
            .unwrap_err()
            .to_string()
            .contains("fences ordinary"));
        assert!(other
            .commit_transferred_repository_transaction(normal, None)
            .is_err());
        let raw = other.read_authority().snapshot().to_bytes().unwrap();
        let cursor = f
            .backend
            .load_snapshot_cursor(repository_id().as_str())
            .unwrap()
            .unwrap();
        assert!(f
            .backend
            .save_snapshot(repository_id().as_str(), &raw, cursor.backend_generation())
            .unwrap_err()
            .to_string()
            .contains("fences ordinary"));
        assert!(matches!(
            f.backend
                .save_authority_frame(repository_id().as_str(), b"invalid", cursor, None),
            SnapshotSaveOutcome::NotCommitted(_)
        ));
        assert!(f
            .backend
            .save_delta(
                repository_id().as_str(),
                b"invalid",
                cursor.backend_generation()
            )
            .is_err());
        assert!(other
            .prepare_session_publication(
                semantic_workspace_transaction(&other, 0xc003, WorkspaceSemanticDelta::default()),
                f.workspace,
                binding(),
                &f.observation(),
                &SessionStorageVerifier
            )
            .is_err());
        assert_eq!(std::fs::read(f.authority()).unwrap(), before);
        let (_, freeze) = f
            .manager
            .commit_prepared_session_publication(&handle)
            .unwrap();
        drop(freeze);
        let after = f.reopen();
        after
            .commit_repository_transaction(binding_history_followup(&after, 0xc021))
            .unwrap();
        assert!(
            after.read_authority().metadata().binding_history.is_empty(),
            "ordinary invalidation remains intact"
        );
        // Full promotion must retain both the required version and completed
        // evidence after an intervening ordinary authority-frame append.
        let cursor = f
            .backend
            .load_snapshot_cursor(repository_id().as_str())
            .unwrap()
            .unwrap();
        f.backend
            .save_snapshot(
                repository_id().as_str(),
                &after.read_authority().snapshot().to_bytes().unwrap(),
                cursor.backend_generation(),
            )
            .unwrap();
        let cold = f.reopen();
        let replay = cold
            .load_prepared_session_publication(handle.operation_id())
            .unwrap()
            .unwrap();
        let (receipt, retained) = cold.commit_prepared_session_publication(&replay).unwrap();
        assert_eq!(receipt.operation, handle.expected_receipt().operation);
        drop(retained);
        assert_eq!(cold.read_authority().generation(), 3);
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.authority()).unwrap()).unwrap();
        assert_eq!(value["version"], 5);
        assert_eq!(value["session_publications"].as_array().unwrap().len(), 1);
        assert!(f.record().exists());
    }

    #[test]
    fn prepared_session_same_operation_is_immutable_and_identical_prepare_reuses_receipt() {
        let f = Fixture::new(true);
        let first = f.prepare();
        let before = std::fs::read(f.record()).unwrap();
        assert_eq!(f.prepare().expected_receipt(), first.expected_receipt());
        let mut changed = binding();
        changed.control_identity = digest(b"other control");
        assert!(f
            .manager
            .prepare_session_publication(
                f.transaction(0xc002),
                f.workspace,
                changed,
                &f.observation(),
                &SessionStorageVerifier
            )
            .is_err());
        let mut changed = f.transaction(0xc002);
        changed.reason = "changed intent".into();
        assert!(f
            .manager
            .prepare_session_publication(
                changed,
                f.workspace,
                binding(),
                &f.observation(),
                &SessionStorageVerifier
            )
            .is_err());
        assert_eq!(std::fs::read(f.record()).unwrap(), before);
    }

    #[test]
    fn prepared_session_unknown_history_cannot_be_laundered_by_cold_replay() {
        for checked_base in [false, true] {
            let f = Fixture::new(checked_base);
            let mut observed = f.observation();
            observed.verified_binding_history = None;
            let handle = f
                .manager
                .prepare_session_publication(
                    f.transaction(0xc002),
                    f.workspace,
                    binding(),
                    &observed,
                    &SessionStorageVerifier,
                )
                .unwrap();
            assert!(handle.record.successor_history.is_empty());
            let cold = f.reopen();
            let loaded = cold
                .load_prepared_session_publication(handle.operation_id())
                .unwrap()
                .unwrap();
            let (_, freeze) = cold.commit_prepared_session_publication(&loaded).unwrap();
            drop(freeze);
            assert!(f
                .reopen()
                .workspace_graph_snapshot(&repository_id(), &f.workspace)
                .unwrap()
                .unwrap()
                .verified_binding_history
                .is_none());
        }
    }

    #[test]
    fn prepared_session_failure_before_commit_retains_fence_and_cold_retry() {
        let f = Fixture::new(true);
        let handle = f.prepare();
        f.backend.fail_next_snapshot_before_authority_commit();
        assert!(f
            .manager
            .commit_prepared_session_publication(&handle)
            .is_err());
        assert_eq!(f.manager.read_authority().generation(), 1);
        let cold = f.reopen();
        let loaded = cold.active_prepared_session_publication().unwrap().unwrap();
        let (receipt, freeze) = cold.commit_prepared_session_publication(&loaded).unwrap();
        drop(freeze);
        assert_eq!(receipt, *handle.expected_receipt());
    }

    #[test]
    fn prepared_session_uncertain_authority_sync_replays_original_durable_receipt() {
        let f = Fixture::new(true);
        let handle = f.prepare();
        f.backend.fail_next_snapshot_parent_sync_after_install();
        let error = f
            .manager
            .commit_prepared_session_publication(&handle)
            .expect_err("injected sync uncertainty");
        assert!(
            matches!(error, KinDbError::SnapshotPersistenceIndeterminate(_)),
            "{error}"
        );
        let cold = f.reopen();
        let loaded = cold
            .load_prepared_session_publication(handle.operation_id())
            .unwrap()
            .unwrap();
        let (receipt, freeze) = cold.commit_prepared_session_publication(&loaded).unwrap();
        drop(freeze);
        assert_eq!(receipt.operation, handle.expected_receipt().operation);
        assert_eq!(cold.read_authority().generation(), 2);
    }

    #[test]
    fn prepared_session_missing_corrupt_or_unacknowledged_authority_refuses_recovery() {
        for damage in ["missing", "truncated", "missing-authority"] {
            let f = Fixture::new(true);
            f.prepare();
            match damage {
                "missing" => std::fs::remove_file(f.record()).unwrap(),
                "truncated" => std::fs::write(f.record(), b"{").unwrap(),
                _ => std::fs::remove_file(f.authority()).unwrap(),
            }
            let result = RepositoryAuthorityManager::open(
                repository_id(),
                Arc::new(LocalFileBackend::new(f.dir.path())),
            );
            assert!(
                result.is_err(),
                "{damage} must not recover genesis or drop the fence"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn prepared_session_rejects_symlink_and_hardlink_records() {
        for symlink in [true, false] {
            let f = Fixture::new(true);
            f.prepare();
            let outside = f.dir.path().join("outside");
            std::fs::copy(f.record(), &outside).unwrap();
            std::fs::remove_file(f.record()).unwrap();
            if symlink {
                std::os::unix::fs::symlink(&outside, f.record()).unwrap();
            } else {
                std::fs::hard_link(&outside, f.record()).unwrap();
            }
            assert!(RepositoryAuthorityManager::open(
                repository_id(),
                Arc::new(LocalFileBackend::new(f.dir.path()))
            )
            .is_err());
            assert!(outside.exists());
        }
    }
    #[test]
    fn prepared_session_changed_handle_and_foreign_repository_refuse() {
        let f = Fixture::new(true);
        let handle = f.prepare();
        let mut forged = handle.clone();
        forged.record.binding.control_identity = digest(b"forged");
        assert!(f
            .manager
            .commit_prepared_session_publication(&forged)
            .is_err());
        let another = Fixture::new(true);
        assert!(another
            .manager
            .commit_prepared_session_publication(&handle)
            .is_err());
        assert_eq!(f.manager.read_authority().generation(), 1);
        assert_eq!(another.manager.read_authority().generation(), 1);
    }

    #[test]
    fn prepared_session_compiled_source_refusal_and_stale_observation_install_nothing() {
        let f = Fixture::new(true);
        // The preexisting storage-only verifier has no graph/source admission
        // implementation. Qualification alone cannot authorize a preparation.
        assert!(f
            .manager
            .prepare_session_publication(
                f.transaction(0xc002),
                f.workspace,
                binding(),
                &f.observation(),
                &StorageTestVerifier
            )
            .is_err());
        let stale = f.transaction(0xc002);
        f.manager
            .commit_repository_transaction(binding_history_followup(&f.manager, 0xc099))
            .unwrap();
        assert!(f
            .manager
            .prepare_session_publication(
                stale,
                f.workspace,
                binding(),
                &f.observation(),
                &SessionStorageVerifier
            )
            .is_err());
        assert!(!f.record().exists());
        assert!(f
            .manager
            .active_prepared_session_publication()
            .unwrap()
            .is_none());
    }

    #[test]
    fn prepared_session_competing_publication_during_admission_refuses_acknowledgement() {
        struct RacingVerifier {
            writer: RepositoryAuthorityManager<LocalFileBackend>,
        }
        impl BindingHistoryVerifier for RacingVerifier {
            fn verify_graph_transition(
                &self,
                _: &GraphSnapshot,
                _: &GraphSnapshot,
                _: &dyn Fn(Hash256) -> Result<Option<Vec<u8>>, KinDbError>,
            ) -> Result<bool, KinDbError> {
                self.writer
                    .commit_repository_transaction(binding_history_followup(
                        &self.writer,
                        0xc090,
                    ))?;
                Ok(true)
            }
            fn verify_transition(
                &self,
                transition: BindingHistoryTransition<'_>,
            ) -> Result<BindingHistoryDecision, KinDbError> {
                SessionStorageVerifier.verify_transition(transition)
            }
        }
        let f = Fixture::new(true);
        let verifier = RacingVerifier { writer: f.reopen() };
        assert!(f
            .manager
            .prepare_session_publication(
                f.transaction(0xc002),
                f.workspace,
                binding(),
                &f.observation(),
                &verifier
            )
            .is_err());
        assert_eq!(verifier.writer.read_authority().generation(), 2);
        assert!(!f.record().exists());
        assert!(f
            .reopen()
            .active_prepared_session_publication()
            .unwrap()
            .is_none());
    }

    /// Manual bridge for the real prior-binary format gate. The caller first
    /// initializes an owned repository with the pinned old CLI. This test
    /// prepares through the genuine new manager API and leaves the real store
    /// in place for the old binary's refusal check. It never fabricates record
    /// version bytes or changes the product's manifest.
    #[test]
    #[ignore = "requires an explicitly owned old-CLI fixture path"]
    fn prepared_session_old_reader_fixture() {
        prepare_old_reader_fixture(false);
    }

    /// Separate v2 format gate using the same registered owned-fixture input.
    /// This emits a real acknowledged record; it does not establish that the
    /// synthetic locator names a runtime session or grade session recovery.
    #[test]
    #[ignore = "requires an explicitly owned old-CLI fixture path"]
    fn prepared_session_v2_old_reader_fixture() {
        prepare_old_reader_fixture(true);
    }

    fn prepare_old_reader_fixture(with_locator: bool) {
        let root = std::path::PathBuf::from(
            std::env::var("KIN_DB_PREPARED_SESSION_FIXTURE").expect("owned fixture path required"),
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(".kin/manifest.json")).unwrap())
                .unwrap();
        let repository = RepositoryId::new(manifest["repo_id"].as_str().unwrap()).unwrap();
        let manager = RepositoryAuthorityManager::open(
            repository.clone(),
            Arc::new(LocalFileBackend::new(root.join(".kin/kindb"))),
        )
        .unwrap();
        let workspace = manager.read_authority().metadata().workspaces[0].workspace_id;
        let observed = manager
            .workspace_graph_snapshot(&repository, &workspace)
            .unwrap()
            .unwrap();
        let mut transaction =
            semantic_workspace_transaction(&manager, 0xc200, WorkspaceSemanticDelta::default());
        transaction.repository_id = repository;
        let body = b"def prepared_target():\n    return 1\n";
        manager.save_source_blob(digest(body), body).unwrap();
        let mutation = transaction.workspace_mutation.as_mut().unwrap();
        mutation.tree_deltas.push(TreeDelta::Added {
            artifact_id: ArtifactId(Uuid::from_u128(0xc201)),
            new: LocatedEntry::new(
                RepoPath::from_utf8("prepared_target.py").unwrap(),
                TreeEntry::blob(digest(body), false),
            ),
        });
        mutation.new_tree_hash = compute_resolved_tree_hash(
            &observed.resolved_tree.apply(&mutation.tree_deltas).unwrap(),
        )
        .unwrap();
        let handle = if with_locator {
            manager.prepare_session_publication_with_locator(
                transaction,
                workspace,
                binding(),
                locator("session-owned-format-probe"),
                &observed,
                &SessionStorageVerifier,
            )
        } else {
            manager.prepare_session_publication(
                transaction,
                workspace,
                binding(),
                &observed,
                &SessionStorageVerifier,
            )
        }
        .unwrap();
        assert!(manager
            .active_prepared_session_publication()
            .unwrap()
            .is_some());
        println!(
            "prepared operation {} payload {}",
            handle.operation_id(),
            handle.payload_sha256
        );
    }
    #[test]
    fn prepared_session_prepare_interruption_before_ack_retries_exact_immutable_record() {
        use crate::storage::backend::PreparationFault;
        for fault in [
            PreparationFault::PayloadAfterRename,
            PreparationFault::BeforeAcknowledgement,
        ] {
            let f = Fixture::new(true);
            let transaction = f.transaction(0xc002);
            LocalFileBackend::fail_next_session_preparation(fault);
            assert!(f
                .manager
                .prepare_session_publication(
                    transaction,
                    f.workspace,
                    binding(),
                    &f.observation(),
                    &SessionStorageVerifier
                )
                .is_err());
            assert_eq!(f.manager.read_authority().generation(), 1);
            assert!(f
                .manager
                .active_prepared_session_publication()
                .unwrap()
                .is_none());
            let original = std::fs::read(f.record()).unwrap();
            let cold = f.reopen();
            let prepared = cold
                .prepare_session_publication(
                    f.transaction(0xc002),
                    f.workspace,
                    binding(),
                    &f.observation(),
                    &SessionStorageVerifier,
                )
                .unwrap();
            assert_eq!(std::fs::read(f.record()).unwrap(), original);
            let (receipt, freeze) = cold.commit_prepared_session_publication(&prepared).unwrap();
            drop(freeze);
            assert_eq!(receipt, *prepared.expected_receipt());
        }
    }

    #[test]
    fn prepared_session_unacknowledged_record_cannot_supply_qualification() {
        use crate::storage::backend::PreparationFault;
        let f = Fixture::new(true);
        LocalFileBackend::fail_next_session_preparation(PreparationFault::BeforeAcknowledgement);
        assert!(f
            .manager
            .prepare_session_publication(
                f.transaction(0xc002),
                f.workspace,
                binding(),
                &f.observation(),
                &SessionStorageVerifier,
            )
            .is_err());
        let authority_before = std::fs::read(f.authority()).unwrap();
        let mut candidate: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.record()).unwrap()).unwrap();
        assert!(!candidate["successor_history"]
            .as_array()
            .unwrap()
            .is_empty());
        candidate["successor_history"] = serde_json::json!([]);
        std::fs::write(f.record(), serde_json::to_vec(&candidate).unwrap()).unwrap();
        let cold = f.reopen();
        let error = cold
            .prepare_session_publication(
                f.transaction(0xc002),
                f.workspace,
                binding(),
                &f.observation(),
                &SessionStorageVerifier,
            )
            .expect_err("unacknowledged bytes cannot replace freshly verified history");
        assert!(
            error
                .to_string()
                .contains("immutable operation preparation"),
            "{error}"
        );
        assert_eq!(std::fs::read(f.authority()).unwrap(), authority_before);
        assert_eq!(cold.read_authority().generation(), 1);
        assert!(cold
            .active_prepared_session_publication()
            .unwrap()
            .is_none());
    }

    #[test]
    fn prepared_session_prepare_uncertain_ack_is_required_and_cold_loadable() {
        use crate::storage::backend::PreparationFault;
        let f = Fixture::new(true);
        let transaction = f.transaction(0xc002);
        LocalFileBackend::fail_next_session_preparation(
            PreparationFault::AcknowledgementAfterRename,
        );
        let error = f
            .manager
            .prepare_session_publication(
                transaction,
                f.workspace,
                binding(),
                &f.observation(),
                &SessionStorageVerifier,
            )
            .expect_err("acknowledgement fsync uncertainty");
        assert!(
            matches!(error, KinDbError::SnapshotPersistenceIndeterminate(_)),
            "{error}"
        );
        let cold = f.reopen();
        let handle = cold.active_prepared_session_publication().unwrap().unwrap();
        assert!(cold
            .commit_repository_transaction(binding_history_followup(&cold, 0xc040))
            .is_err());
        let (_, freeze) = cold.commit_prepared_session_publication(&handle).unwrap();
        drop(freeze);
    }
}
