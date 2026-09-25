// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

/// Deliberately trusted test verifier: these are storage/callback boundary
/// controls, not semantic genesis or obligation-accounting acceptance.
struct StorageTestVerifier;
fn binding_history_followup<B: StorageBackend + ?Sized + 'static>(
    manager: &RepositoryAuthorityManager<B>,
    operation: u128,
) -> RepositoryTransaction {
    let mut transaction = transaction_shell(manager, operation);
    transaction.ref_mutations.push(RefMutation {
        name: RefName::branch(format!("witness-{operation}").as_bytes()).unwrap(),
        expected: RefExpectation::MustNotExist,
        new_target: Some(RefTarget::symbolic(RefName::branch(b"main").unwrap())),
        policy: RefUpdatePolicy::FastForwardOnly,
    });
    transaction
}
impl crate::storage::binding_history::BindingHistoryVerifier for StorageTestVerifier {
    fn verify_transition(
        &self,
        transition: crate::storage::binding_history::BindingHistoryTransition<'_>,
    ) -> Result<crate::storage::binding_history::BindingHistoryDecision, KinDbError> {
        Ok(
            crate::storage::binding_history::BindingHistoryDecision::Qualified {
                protocol: crate::storage::binding_history::BINDING_HISTORY_PROTOCOL,
                workspaces: transition
                    .successor()
                    .metadata()
                    .workspaces
                    .iter()
                    .map(|workspace| workspace.workspace_id)
                    .collect(),
            },
        )
    }
}

#[test]
fn binding_history_checked_lineage_survives_cold_read_but_ordinary_and_transfer_clear() {
    use kin_model::EntityStore;
    for transferred in [false, true] {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction_with_binding_history(
                arbitrary_repository_transaction(&manager),
                &StorageTestVerifier,
            )
            .unwrap();
        manager
            .commit_repository_transaction_with_binding_history(
                binding_history_followup(&manager, 0xb105),
                &StorageTestVerifier,
            )
            .unwrap();
        let prior = manager.read_authority().metadata().binding_history.clone();
        assert_eq!(prior.len(), 1);
        drop(manager);
        let reopened = initial_manager(backend);
        assert_eq!(reopened.read_authority().metadata().binding_history, prior);
        let lease = reopened.read_authority();
        let workspace = lease.metadata().workspaces[0].workspace_id;
        let selected = lease.workspace_graph_snapshot(&workspace).unwrap().unwrap();
        let graph = InMemoryGraph::from_snapshot_without_text_index(selected).unwrap();
        assert!(matches!(
            graph.binding_history_observation(),
            kin_model::BindingHistoryObservation::Checked { .. }
        ));
        drop(lease);
        let transaction = binding_history_followup(&reopened, 0xb106);
        if transferred {
            reopened
                .commit_transferred_repository_transaction(transaction, None)
                .unwrap();
        } else {
            reopened.commit_repository_transaction(transaction).unwrap();
        }
        assert!(reopened
            .read_authority()
            .metadata()
            .binding_history
            .is_empty());
        let after = reopened
            .read_authority()
            .workspace_graph_snapshot(&workspace)
            .unwrap()
            .unwrap();
        assert!(after.verified_binding_history.is_none());
    }
}

#[test]
fn binding_history_same_state_fabricated_or_unqualified_lineage_refuses() {
    let backend = Arc::new(MemoryBackend::default());
    let manager = initial_manager(backend);
    manager
        .commit_repository_transaction_with_binding_history(
            arbitrary_repository_transaction(&manager),
            &StorageTestVerifier,
        )
        .unwrap();
    let lease = manager.read_authority();
    for field in ["lineage_digest", "proof"] {
        let mut value = serde_json::to_value(lease.metadata()).unwrap();
        value["binding_history"][0][field] = if field == "proof" {
            serde_json::json!([])
        } else {
            serde_json::to_value(Hash256::from_bytes([7; 32])).unwrap()
        };
        let forged: PersistedRepositoryAuthority = serde_json::from_value(value).unwrap();
        assert!(
            crate::storage::binding_history::validate_metadata(&forged).is_err(),
            "{field}"
        );
    }
}

#[test]
fn binding_history_checked_callback_cannot_launder_unknown_or_reopened_empty_store() {
    for persist_empty in [false, true] {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        if persist_empty {
            backend
                .save_snapshot(
                    repository_id().as_str(),
                    &manager.read_authority().snapshot().to_bytes().unwrap(),
                    0,
                )
                .unwrap();
        } else {
            manager
                .commit_repository_transaction(arbitrary_repository_transaction(&manager))
                .unwrap();
        }
        drop(manager);
        let reopened = initial_manager(backend);
        let before = reopened.read_authority().roots().clone();
        let transaction = if persist_empty {
            arbitrary_repository_transaction(&reopened)
        } else {
            binding_history_followup(&reopened, 0xb104)
        };
        let error = reopened
            .commit_repository_transaction_with_binding_history(transaction, &StorageTestVerifier)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unknown predecessor cannot be qualified"),
            "{error}"
        );
        assert_eq!(reopened.read_authority().roots(), &before);
        assert!(reopened
            .read_authority()
            .metadata()
            .binding_history
            .is_empty());
    }
}

#[test]
fn binding_history_new_authority_declares_required_capability() {
    let backend = Arc::new(MemoryBackend::default());
    let manager = initial_manager(Arc::clone(&backend));
    manager
        .commit_repository_transaction(receiver_ref_transaction(
            &manager,
            0xb100,
            "binding-history-test",
        ))
        .unwrap();
    let lease = manager.read_authority();
    assert_eq!(lease.metadata().schema_version, 5);
    assert!(
        lease.metadata().binding_history.is_empty(),
        "capability alone is not proof"
    );
    let bytes = lease.snapshot().to_bytes().unwrap();
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 17);
    let decoded = GraphSnapshot::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.repository_authority.unwrap(), *lease.metadata());
    drop(lease);
    let reopened = initial_manager(backend);
    assert!(reopened
        .read_authority()
        .metadata()
        .binding_history
        .is_empty());
}

#[test]
fn binding_history_legacy_rewrite_is_explicit_unknown_and_root_preserving() {
    let backend = Arc::new(MemoryBackend::default());
    let manager = initial_manager(Arc::clone(&backend));
    manager
        .commit_repository_transaction(receiver_ref_transaction(
            &manager,
            0xb101,
            "binding-history-test",
        ))
        .unwrap();
    let mut legacy = manager.read_authority().snapshot().clone();
    legacy.repository_authority.as_mut().unwrap().schema_version = 4;
    legacy.version = legacy.wire_version();
    assert_eq!(legacy.version, 15);
    let roots = legacy.repository_authority.as_ref().unwrap().roots.clone();
    let legacy_bytes = legacy.to_bytes().unwrap();
    let legacy_backend = Arc::new(MemoryBackend::default());
    legacy_backend
        .save_snapshot(repository_id().as_str(), &legacy_bytes, 0)
        .unwrap();
    let reader = initial_manager(Arc::clone(&legacy_backend));
    assert_eq!(
        reader.read_authority().metadata().schema_version,
        4,
        "opening does not migrate"
    );
    assert!(reader.require_binding_history_capability().unwrap());
    assert_eq!(reader.read_authority().roots(), &roots);
    assert!(reader
        .read_authority()
        .metadata()
        .binding_history
        .is_empty());
    assert!(!reader.require_binding_history_capability().unwrap());
    drop(reader);
    let reopened = initial_manager(legacy_backend);
    assert_eq!(reopened.read_authority().metadata().schema_version, 5);
    assert_eq!(reopened.read_authority().roots(), &roots);
    assert!(reopened
        .read_authority()
        .metadata()
        .binding_history
        .is_empty());
}

#[test]
fn binding_history_schema_3_and_4_remain_readable_and_do_not_upgrade_on_commit() {
    for schema in [3, 4] {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(receiver_ref_transaction(
                &manager,
                0xb102,
                "binding-history-test",
            ))
            .unwrap();
        let mut snapshot = manager.read_authority().snapshot().clone();
        snapshot
            .repository_authority
            .as_mut()
            .unwrap()
            .schema_version = schema;
        snapshot.version = snapshot.wire_version();
        let bytes = snapshot.to_bytes().unwrap();
        let legacy_backend = Arc::new(MemoryBackend::default());
        legacy_backend
            .save_snapshot(repository_id().as_str(), &bytes, 0)
            .unwrap();
        let opened = initial_manager(legacy_backend);
        let mut transaction = transaction_shell(&opened, 0xb103);
        transaction.default_ref_mutation = Some(DefaultRefMutation {
            expected: DefaultRefExpectation::MustEqual {
                name: RefName::branch(b"main").unwrap(),
            },
            new_default: None,
        });
        opened.commit_repository_transaction(transaction).unwrap();
        assert_eq!(opened.read_authority().metadata().schema_version, schema);
        assert!(opened
            .read_authority()
            .metadata()
            .binding_history
            .is_empty());
    }
}

/// Structural admission test, not a producer/genesis acceptance fixture.
#[test]
fn binding_history_binds_whole_scope_graph_and_invalidates_before_mutation() {
    use crate::storage::binding_history;
    use kin_model::EntityStore;
    let backend = Arc::new(MemoryBackend::default());
    let manager = initial_manager(backend);
    manager
        .commit_repository_transaction_with_binding_history(
            arbitrary_repository_transaction(&manager),
            &StorageTestVerifier,
        )
        .unwrap();
    let lease = manager.read_authority();
    let workspace = &lease.metadata().workspaces[0];
    let mut selected = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .unwrap()
        .unwrap();
    let metadata = lease.metadata().clone();
    binding_history::bind_selected_graph(&metadata, workspace.workspace_id, &mut selected).unwrap();
    let graph = InMemoryGraph::from_snapshot_without_text_index(selected.clone()).unwrap();
    assert!(matches!(
        graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));
    // Runtime capabilities are not a field a serialized input can assert.
    let raw = GraphSnapshot::from_bytes(&selected.to_bytes().unwrap()).unwrap();
    assert!(raw.verified_binding_history.is_none());
    let mut wrong_root_json = serde_json::to_value(&metadata).unwrap();
    wrong_root_json["binding_history"][0]["scope"]["roots"]["generation"] = 999.into();
    let wrong_root: PersistedRepositoryAuthority = serde_json::from_value(wrong_root_json).unwrap();
    assert!(binding_history::bind_selected_graph(
        &wrong_root,
        workspace.workspace_id,
        &mut selected
    )
    .is_err());
    let mut wrong_graph = selected.clone();
    wrong_graph.resolved_tree = ResolvedTree::default();
    assert!(binding_history::bind_selected_graph(
        &metadata,
        workspace.workspace_id,
        &mut wrong_graph
    )
    .is_err());
    graph
        .apply_transaction_delta(&kin_model::TransactionDelta {
            tree_deltas: vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("extra.txt").unwrap(),
                    TreeEntry::blob(digest(b"extra"), false),
                ),
            }],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Unproven
    );
}

#[test]
fn binding_history_observed_predecessor_cannot_reuse_a_stale_or_missing_capability() {
    for stale in [false, true] {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(backend);
        manager
            .commit_repository_transaction_with_binding_history(
                arbitrary_repository_transaction(&manager),
                &StorageTestVerifier,
            )
            .unwrap();
        let workspace = manager.read_authority().metadata().workspaces[0].workspace_id;
        let mut observed = manager
            .read_authority()
            .workspace_graph_snapshot(&workspace)
            .unwrap()
            .unwrap();
        if stale {
            manager
                .commit_repository_transaction_with_binding_history(
                    binding_history_followup(&manager, 0xb110),
                    &StorageTestVerifier,
                )
                .unwrap();
        } else {
            observed.verified_binding_history = None;
        }
        manager
            .commit_repository_transaction_with_observed_binding_history(
                binding_history_followup(&manager, 0xb111),
                workspace,
                &observed,
                &StorageTestVerifier,
            )
            .unwrap();
        assert!(
            manager
                .read_authority()
                .metadata()
                .binding_history
                .is_empty(),
            "even a trusted callback cannot bind an absent/stale runtime capability"
        );
    }
}

#[test]
fn binding_history_observed_predecessor_rejects_changed_bytes_before_publication() {
    let backend = Arc::new(MemoryBackend::default());
    let manager = initial_manager(backend);
    manager
        .commit_repository_transaction_with_binding_history(
            arbitrary_repository_transaction(&manager),
            &StorageTestVerifier,
        )
        .unwrap();
    let workspace = manager.read_authority().metadata().workspaces[0].workspace_id;
    let mut observed = manager
        .read_authority()
        .workspace_graph_snapshot(&workspace)
        .unwrap()
        .unwrap();
    observed.resolved_tree = ResolvedTree::default();
    let roots = manager.read_authority().roots().clone();
    let error = manager
        .commit_repository_transaction_with_observed_binding_history(
            binding_history_followup(&manager, 0xb112),
            workspace,
            &observed,
            &StorageTestVerifier,
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("runtime capability no longer names this graph"),
        "{error}"
    );
    assert_eq!(manager.read_authority().roots(), &roots);
}

/// A re-derivation verifier with a fixed answer that records every graph it
/// was offered, standing in for kin-index's, which re-derives the graph.
struct FixedRederivation {
    accepts: bool,
    offered: std::sync::Mutex<Vec<GraphSnapshot>>,
}

impl FixedRederivation {
    fn accepting() -> Self {
        Self {
            accepts: true,
            offered: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Stands in for a re-derivation that did not reproduce the committed
    /// graph.
    fn declining() -> Self {
        Self {
            accepts: false,
            offered: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl crate::storage::binding_history::RederivationVerifier for FixedRederivation {
    fn verify_rederived_graph(
        &self,
        after: &GraphSnapshot,
        _load_body: &dyn Fn(kin_model::Hash256) -> Result<Option<Vec<u8>>, KinDbError>,
    ) -> Result<bool, KinDbError> {
        self.offered.lock().unwrap().push(after.clone());
        Ok(self.accepts)
    }
}

/// The payment a re-derivation commit offers for the fixture's first
/// workspace. These followups leave the workspace as it was, so none of them
/// records it.
fn fixture_rederivation_payment<B: StorageBackend + ?Sized + 'static>(
    manager: &RepositoryAuthorityManager<B>,
) -> crate::storage::derivation_ledger::RederivationPayment {
    crate::storage::derivation_ledger::RederivationPayment {
        workspace_id: manager.read_authority().metadata().workspaces[0].workspace_id,
        hydration_version: 30,
    }
}

fn proof_qualifications(manager: &RepositoryAuthorityManager<MemoryBackend>) -> Vec<String> {
    let value = serde_json::to_value(manager.read_authority().metadata()).unwrap();
    value["binding_history"][0]["proof"]
        .as_array()
        .map(|steps| {
            steps
                .iter()
                .map(|step| step["qualification"].as_str().unwrap().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// A store whose operations were never checked can never be qualified by a
/// later transition, and a re-derivation commit starts a lineage at itself:
/// the proof names that operation alone, operations before it stay outside
/// it, the lineage survives a cold read, and ordinary checked commits extend
/// it afterwards.
#[test]
fn binding_history_rederivation_starts_a_lineage_where_the_store_had_none() {
    use kin_model::EntityStore;
    let backend = Arc::new(MemoryBackend::default());
    let manager = initial_manager(Arc::clone(&backend));
    manager
        .commit_repository_transaction(arbitrary_repository_transaction(&manager))
        .unwrap();
    manager
        .commit_repository_transaction(binding_history_followup(&manager, 0xb120))
        .unwrap();
    let error = manager
        .commit_repository_transaction_with_binding_history(
            binding_history_followup(&manager, 0xb121),
            &StorageTestVerifier,
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unknown predecessor cannot be qualified"),
        "{error}"
    );

    manager
        .commit_rederived_repository_transaction(
            binding_history_followup(&manager, 0xb122),
            &FixedRederivation::accepting(),
            fixture_rederivation_payment(&manager),
        )
        .unwrap();
    let operations = manager.read_authority().metadata().operation_log.len();
    assert!(operations >= 3, "the fixture made {operations} operations");
    assert_eq!(
        proof_qualifications(&manager),
        vec!["CheckedRederivation".to_string()],
        "the lineage must start at the re-derivation and name nothing before it"
    );
    let witnesses = manager.read_authority().metadata().binding_history.clone();
    drop(manager);

    let reopened = initial_manager(Arc::clone(&backend));
    assert_eq!(
        reopened.read_authority().metadata().binding_history,
        witnesses
    );
    let workspace = reopened.read_authority().metadata().workspaces[0].workspace_id;
    let selected = reopened
        .read_authority()
        .workspace_graph_snapshot(&workspace)
        .unwrap()
        .unwrap();
    let graph = InMemoryGraph::from_snapshot_without_text_index(selected).unwrap();
    assert!(matches!(
        graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));

    reopened
        .commit_repository_transaction_with_binding_history(
            binding_history_followup(&reopened, 0xb123),
            &StorageTestVerifier,
        )
        .unwrap();
    assert_eq!(
        proof_qualifications(&reopened),
        vec![
            "CheckedRederivation".to_string(),
            "CheckedTransition".to_string()
        ]
    );
}

/// A store written before binding history existed is raised to the schema
/// that carries it by the re-derivation commit itself, in one durable write,
/// with its roots moved only by that commit.
#[test]
fn binding_history_rederivation_raises_a_legacy_schema_in_the_same_commit() {
    let backend = Arc::new(MemoryBackend::default());
    let manager = initial_manager(Arc::clone(&backend));
    manager
        .commit_repository_transaction(arbitrary_repository_transaction(&manager))
        .unwrap();
    assert_eq!(
        manager.read_authority().metadata().workspaces.len(),
        1,
        "the fixture must hold a workspace for a lineage to qualify"
    );
    let mut legacy = manager.read_authority().snapshot().clone();
    legacy.repository_authority.as_mut().unwrap().schema_version = 4;
    legacy.version = legacy.wire_version();
    let legacy_backend = Arc::new(MemoryBackend::default());
    // The aged store keeps the source bodies its changes name, as a real one
    // does; opening an authority refuses a change whose body is absent.
    for (digest, body) in backend.blobs.lock().iter() {
        legacy_backend
            .save_source_blob(repository_id().as_str(), *digest, body)
            .unwrap();
    }
    legacy_backend
        .save_snapshot(repository_id().as_str(), &legacy.to_bytes().unwrap(), 0)
        .unwrap();
    let reader = initial_manager(Arc::clone(&legacy_backend));
    assert_eq!(reader.read_authority().metadata().schema_version, 4);
    let generation = reader.read_authority().roots().generation;

    reader
        .commit_rederived_repository_transaction(
            binding_history_followup(&reader, 0xb125),
            &FixedRederivation::accepting(),
            fixture_rederivation_payment(&reader),
        )
        .unwrap();
    assert_eq!(reader.read_authority().metadata().schema_version, 5);
    assert_eq!(reader.read_authority().roots().generation, generation + 1);
    assert_eq!(
        proof_qualifications(&reader),
        vec!["CheckedRederivation".to_string()]
    );
    drop(reader);

    let reopened = initial_manager(legacy_backend);
    assert_eq!(reopened.read_authority().metadata().schema_version, 5);
    assert_eq!(reopened.read_authority().roots().generation, generation + 1);
    assert_eq!(
        proof_qualifications(&reopened),
        vec!["CheckedRederivation".to_string()]
    );
}

/// The commit lands and the store stays unproven when the verifier finds no
/// workspace the re-derivation reproduced. What the verifier was offered is
/// the graph the committed successor selects, so the decision is about the
/// state that was published and not one the caller described.
#[test]
fn binding_history_rederivation_the_verifier_declines_leaves_the_store_unproven() {
    let backend = Arc::new(MemoryBackend::default());
    let manager = initial_manager(backend);
    manager
        .commit_repository_transaction(arbitrary_repository_transaction(&manager))
        .unwrap();
    let before = manager.read_authority().roots().generation;
    let verifier = FixedRederivation::declining();
    manager
        .commit_rederived_repository_transaction(
            binding_history_followup(&manager, 0xb126),
            &verifier,
            fixture_rederivation_payment(&manager),
        )
        .unwrap();
    assert_eq!(manager.read_authority().roots().generation, before + 1);
    assert!(manager
        .read_authority()
        .metadata()
        .binding_history
        .is_empty());
    let workspace = manager.read_authority().metadata().workspaces[0].workspace_id;
    let committed = manager
        .read_authority()
        .workspace_graph_snapshot(&workspace)
        .unwrap()
        .unwrap();
    let offered = verifier.offered.lock().unwrap();
    assert_eq!(offered.len(), 1, "one workspace, offered once");
    assert_eq!(
        offered[0].to_bytes().unwrap(),
        committed.to_bytes().unwrap(),
        "the verifier must judge the committed successor graph"
    );
}

/// A lineage that starts part way through the operation log is accepted only
/// when its first step is a checked re-derivation. Relabelling that step as
/// any other qualification is refused, and so is a re-derivation step placed
/// after the start of a lineage.
#[test]
fn binding_history_a_lineage_starting_part_way_must_start_with_a_rederivation() {
    let backend = Arc::new(MemoryBackend::default());
    let manager = initial_manager(backend);
    manager
        .commit_repository_transaction(arbitrary_repository_transaction(&manager))
        .unwrap();
    manager
        .commit_rederived_repository_transaction(
            binding_history_followup(&manager, 0xb127),
            &FixedRederivation::accepting(),
            fixture_rederivation_payment(&manager),
        )
        .unwrap();
    manager
        .commit_repository_transaction_with_binding_history(
            binding_history_followup(&manager, 0xb128),
            &StorageTestVerifier,
        )
        .unwrap();
    let value = serde_json::to_value(manager.read_authority().metadata()).unwrap();
    let valid: PersistedRepositoryAuthority = serde_json::from_value(value.clone()).unwrap();
    crate::storage::binding_history::validate_metadata(&valid).unwrap();
    for (step, qualification) in [
        (0, "CheckedTransition"),
        (0, "CheckedHistoryGenesis"),
        (0, "NewNativeGenesis"),
        (1, "CheckedRederivation"),
    ] {
        let mut forged = value.clone();
        forged["binding_history"][0]["proof"][step]["qualification"] = qualification.into();
        let forged: PersistedRepositoryAuthority = serde_json::from_value(forged).unwrap();
        assert!(
            crate::storage::binding_history::validate_metadata(&forged).is_err(),
            "step {step} relabelled {qualification} was accepted"
        );
    }
    // Dropping the re-derivation step leaves a lineage that starts part way
    // with an ordinary transition, which is refused.
    let mut truncated = value.clone();
    truncated["binding_history"][0]["proof"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    let truncated: PersistedRepositoryAuthority = serde_json::from_value(truncated).unwrap();
    assert!(crate::storage::binding_history::validate_metadata(&truncated).is_err());
}
