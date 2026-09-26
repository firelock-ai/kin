// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Resolution records in repository authority. A workspace overlay that holds
// records, or a logged operation that moved some, moves the snapshot and frame
// versions, so an older binary refuses such a store at the header instead of
// failing inside the envelope; a store that never carried records keeps its
// version and its bytes.

/// A workspace mutation that moves no tree and applies `semantic_delta` to the
/// first workspace.
fn resolution_records_transaction<B: StorageBackend + ?Sized + 'static>(
    manager: &RepositoryAuthorityManager<B>,
    operation: u128,
    semantic_delta: WorkspaceSemanticDelta,
) -> RepositoryTransaction {
    let current = manager.read_authority().metadata().workspaces[0].clone();
    let mutation = WorkspaceMutation {
        workspace_id: current.workspace_id,
        expected: WorkspaceExpectation::MustEqual {
            generation: current.generation,
            head: current.head.clone(),
            base_target: current.base_target.clone(),
            base_tree_hash: current.base_tree_hash,
            tree_hash: current.tree_hash,
            semantic_overlay_hash: current.semantic_overlay_hash,
            admission_policy: current.admission_policy,
        },
        new_generation: current.generation + 1,
        new_head: current.head.clone(),
        new_base_target: current.base_target.clone(),
        new_base_tree_hash: current.base_tree_hash,
        tree_deltas: Vec::new(),
        new_tree_hash: current.tree_hash,
        semantic_delta,
        new_shared_admission_policy: current.shared_admission_policy.clone(),
        new_admission_policy: current.admission_policy,
    };
    let mut transaction = transaction_shell(manager, operation);
    transaction.workspace_mutation = Some(mutation);
    transaction
}

fn resolution_context() -> kin_model::ResolutionRecord {
    kin_model::ResolutionRecord::ProofContext(kin_model::ProofContext {
        language: LanguageId::TypeScript,
        resolver: "lsp:tsserver".to_string(),
        resolver_version: "5.6.3".to_string(),
        configuration_hash: Hash256::from_bytes([0x5a; 32]),
        environment_hash: Hash256::from_bytes([0x5b; 32]),
        environment_summary: "typescript 5.6.3".to_string(),
    })
}

fn resolution_caller(id: u128, signature: &str) -> Entity {
    Entity {
        id: EntityId(Uuid::from_u128(id)),
        kind: EntityKind::Function,
        name: "caller".to_string(),
        language: LanguageId::TypeScript,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0x11; 32]),
            signature_hash: Hash256::from_bytes([0x12; 32]),
            behavior_hash: Hash256::from_bytes([0x13; 32]),
            equivalence_hash: Hash256::from_bytes([0x14; 32]),
            stability_score: 1.0,
        },
        file_origin: None,
        span: None,
        signature: signature.to_string(),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

fn resolution_ledger(
    caller: EntityId,
    context: kin_model::ResolutionRecordId,
) -> kin_model::ResolutionRecord {
    kin_model::ResolutionRecord::CallSites(kin_model::CallSiteLedger {
        caller,
        behavior_hash: Hash256::from_bytes([0x13; 32]),
        body_hash: Hash256::from_bytes([0x15; 32]),
        context,
        census: 1,
        sites: vec![kin_model::CallSite {
            offset: 7,
            length: 3,
            state: kin_model::CallSiteState::ProvenOutside,
        }],
    })
}

fn workspace_records<B: StorageBackend + ?Sized + 'static>(
    manager: &RepositoryAuthorityManager<B>,
) -> HashMap<kin_model::ResolutionRecordId, kin_model::ResolutionRecord> {
    let lease = manager.read_authority();
    let workspace = lease.metadata().workspaces[0].clone();
    lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .unwrap()
        .unwrap()
        .resolution_records
}

/// Records declare versions a binary older than them refuses at the header:
/// snapshot 23 (24 with a section), where the release before them reads at
/// most 22, and frame 7, where it reads at most 6. A store that never carried
/// records keeps its version and its bytes, and the same state without them
/// serializes exactly as that store.
#[test]
fn resolution_records_move_versions_and_a_store_without_them_moves_nothing() {
    let directory = TempDir::new().unwrap();
    let (backend, manager) = framed_local_repository(&directory);
    let quiet = manager.read_authority().snapshot().clone();
    let quiet_version = quiet.wire_version();
    assert!(
        quiet_version < GraphSnapshot::RESOLUTION_RECORDS_VERSION,
        "control: a store without records declares v{quiet_version}"
    );
    let quiet_bytes = quiet.to_bytes().unwrap();
    assert_eq!(
        GraphSnapshot::from_bytes(&quiet_bytes).unwrap().to_bytes().unwrap(),
        quiet_bytes,
        "a store without records round-trips byte for byte"
    );

    let context = resolution_context();
    manager
        .commit_repository_transaction(resolution_records_transaction(
            &manager,
            0x0e3b_0001,
            WorkspaceSemanticDelta::default()
                .with_resolution_records(vec![kin_model::ResolutionRecordDelta::Added {
                    new: context.clone(),
                }])
                .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        workspace_records(&manager).get(&context.id()),
        Some(&context),
        "the workspace graph holds the record"
    );
    let frame = std::fs::read(frame_path(&directory, 2)).unwrap();
    assert_eq!(
        header_version(&frame),
        crate::storage::AuthorityFrame::RESOLUTION_RECORDS_VERSION,
        "a frame that moves records declares version 7"
    );
    assert!(header_version(&frame) > crate::storage::AuthorityFrame::ENRICHMENT_MARKS_VERSION);
    let recorded = manager.read_authority().snapshot().clone();
    let recorded_bytes = recorded.to_bytes().unwrap();
    let expected = if recorded.materialized_graph.is_some() {
        GraphSnapshot::RESOLUTION_RECORDS_SECTION_VERSION
    } else {
        GraphSnapshot::RESOLUTION_RECORDS_VERSION
    };
    assert_eq!(header_version(&recorded_bytes), expected);
    assert!(
        header_version(&recorded_bytes) > GraphSnapshot::ENRICHMENT_MARKS_SECTION_VERSION,
        "a binary that reads at most snapshot version 22 must refuse this at the header"
    );
    assert_eq!(
        crate::storage::body_walk::top_level_element_ranges(&recorded_bytes[16..recorded_bytes.len() - 32])
            .unwrap()
            .len(),
        37,
        "a records body is 37 elements wide whether or not it carries a section"
    );
    GraphSnapshot::prove_pre_validated_round_trip(&recorded_bytes).unwrap();
    let decoded = GraphSnapshot::from_bytes(&recorded_bytes).unwrap();
    assert_eq!(
        decoded.repository_authority.as_ref().unwrap().workspaces[0]
            .semantic_overlay
            .resolution_record_deltas(),
        &[kin_model::ResolutionRecordDelta::Added {
            new: context.clone()
        }]
    );
    let envelope = crate::storage::format::AuthorityEnvelopeSnapshot::from_bytes(&recorded_bytes).unwrap();
    assert!(envelope
        .repository_authority
        .unwrap()
        .carries_resolution_records());
    drop(manager);
    let reopened = RepositoryAuthorityManager::open(repository_id(), backend).unwrap();
    assert_eq!(
        workspace_records(&reopened).get(&context.id()),
        Some(&context),
        "the journal replays the frame that moved the record"
    );

    // Without the overlay's records and the operation that moved them, the
    // same state serializes exactly as the store that never had any.
    let mut stripped = recorded.clone();
    let envelope = stripped.repository_authority.as_mut().unwrap();
    envelope.workspaces[0].semantic_overlay = WorkspaceSemanticOverlay::default();
    envelope
        .operation_log
        .retain(|operation| !operation.carries_resolution_records());
    assert!(!stripped.carries_resolution_records());
    assert_eq!(stripped.wire_version(), quiet_version);
}

/// A ledger is the record of one caller's sites, so it leaves the workspace in
/// the transaction that changes its caller, and the overlay says so
/// explicitly rather than leaving a replay to infer it.
#[test]
fn a_ledger_leaves_the_workspace_with_its_caller() {
    let directory = TempDir::new().unwrap();
    let (_backend, manager) = framed_local_repository(&directory);
    let context = resolution_context();
    let caller = resolution_caller(0x0e3b_00c0, "function caller()");
    let ledger = resolution_ledger(caller.id, context.id());
    manager
        .commit_repository_transaction(resolution_records_transaction(
            &manager,
            0x0e3b_0011,
            WorkspaceSemanticDelta::new(
                vec![kin_model::EntityDelta::Added {
                    new: caller.clone(),
                }],
                Vec::new(),
            )
            .unwrap()
            .with_resolution_records(vec![
                kin_model::ResolutionRecordDelta::Added {
                    new: context.clone(),
                },
                kin_model::ResolutionRecordDelta::Added {
                    new: ledger.clone(),
                },
            ])
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(workspace_records(&manager).get(&ledger.id()), Some(&ledger));

    let edited = resolution_caller(0x0e3b_00c0, "function caller(x)");
    manager
        .commit_repository_transaction(resolution_records_transaction(
            &manager,
            0x0e3b_0012,
            WorkspaceSemanticDelta::new(
                vec![kin_model::EntityDelta::Modified {
                    old: caller,
                    new: edited,
                }],
                Vec::new(),
            )
            .unwrap(),
        ))
        .unwrap();
    let held = workspace_records(&manager);
    assert!(
        !held.contains_key(&ledger.id()),
        "the ledger left with its caller's change"
    );
    assert!(held.contains_key(&context.id()), "the context stays");
    let lease = manager.read_authority();
    let overlay = &lease.metadata().workspaces[0].semantic_overlay;
    assert_eq!(
        overlay.resolution_record_deltas(),
        &[kin_model::ResolutionRecordDelta::Added { new: context }],
        "the cumulative overlay holds exactly what the workspace graph does"
    );
}

/// A record naming a node the workspace graph does not hold is refused, and
/// the refused transaction moves nothing.
#[test]
fn a_record_naming_an_absent_caller_is_refused() {
    let directory = TempDir::new().unwrap();
    let (_backend, manager) = framed_local_repository(&directory);
    let generation = manager.read_authority().generation();
    let context = resolution_context();
    let error = manager
        .commit_repository_transaction(resolution_records_transaction(
            &manager,
            0x0e3b_0021,
            WorkspaceSemanticDelta::default()
                .with_resolution_records(vec![
                    kin_model::ResolutionRecordDelta::Added {
                        new: context.clone(),
                    },
                    kin_model::ResolutionRecordDelta::Added {
                        new: resolution_ledger(EntityId(Uuid::from_u128(0xdead)), context.id()),
                    },
                ])
                .unwrap(),
        ))
        .unwrap_err();
    assert!(
        error.to_string().contains("which the graph does not hold"),
        "{error}"
    );
    assert_eq!(manager.read_authority().generation(), generation);
}
