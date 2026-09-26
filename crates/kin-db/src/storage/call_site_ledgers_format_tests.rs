// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Call-site ledgers in repository authority. A binary built before ledgers
// reads resolution records, so it would decode a store that carries a ledger
// and then mishandle the ledger. A workspace overlay that holds a ledger, a
// logged operation that moved one, or a frame that carries one therefore moves
// the snapshot and frame versions past the records rung, and that binary
// refuses the store at the header. A store whose records are proof contexts
// only keeps the records rung and its bytes. These reuse the fixtures of the
// resolution records format tests.

/// The ledger rung as a binary whose newest readable versions are the records
/// rung sees it: snapshot 24 and frame 7.
fn refused_by_a_reader_older_than_ledgers(snapshot_version: u32) -> String {
    let error = GraphSnapshot::check_readable_version(
        snapshot_version,
        GraphSnapshot::RESOLUTION_RECORDS_SECTION_VERSION,
    )
    .expect_err("a reader of at most v24 refuses a ledger store at the header");
    assert!(
        matches!(
            error,
            KinDbError::IncompatibleSnapshotVersion { found, max: 24, .. }
                if found == snapshot_version
        ),
        "{error:?}"
    );
    error.to_string()
}

/// A native change that moves `deltas` of resolution records and nothing else.
fn record_moving_change(deltas: Vec<kin_model::ResolutionRecordDelta>) -> SemanticChange {
    let mut change = SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
        parents: Vec::new(),
        timestamp: Timestamp::now(),
        author: AuthorId::new("ledger-format-test"),
        message: "move resolution records".to_string(),
        entity_deltas: Vec::new(),
        relation_deltas: Vec::new(),
        tree_deltas: Vec::new(),
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        origin: kin_model::ChangeOrigin::Native,
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
        resolution_record_deltas: deltas,
    };
    change.id = compute_semantic_change_id(&change).unwrap();
    change
}

/// A ledger declares versions a binary older than ledgers refuses at the
/// header: snapshot 25 (26 with a section), where that binary reads at most 24,
/// and frame 8, where it reads at most 7. The ledger reaches the refusal from
/// the workspace overlay that holds it and from the logged operation that
/// moved it, and the store reopens with the ledger intact.
#[test]
fn call_site_ledgers_move_versions_past_records() {
    let directory = TempDir::new().unwrap();
    let (backend, manager) = framed_local_repository(&directory);
    let context = resolution_context();
    manager
        .commit_repository_transaction(resolution_records_transaction(
            &manager,
            0x0e3c_0001,
            WorkspaceSemanticDelta::default()
                .with_resolution_records(vec![kin_model::ResolutionRecordDelta::Added {
                    new: context.clone(),
                }])
                .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        header_version(&std::fs::read(frame_path(&directory, 2)).unwrap()),
        crate::storage::AuthorityFrame::RESOLUTION_RECORDS_VERSION,
        "control: a frame that moves a proof context only is a records frame"
    );

    let caller = resolution_caller(0x0e3c_00c0, "function caller()");
    let ledger = resolution_ledger(caller.id, context.id());
    let ledger_operation = 0x0e3c_0002;
    manager
        .commit_repository_transaction(resolution_records_transaction(
            &manager,
            ledger_operation,
            WorkspaceSemanticDelta::new(
                vec![kin_model::EntityDelta::Added {
                    new: caller.clone(),
                }],
                Vec::new(),
            )
            .unwrap()
            .with_resolution_records(vec![kin_model::ResolutionRecordDelta::Added {
                new: ledger.clone(),
            }])
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        workspace_records(&manager).get(&ledger.id()),
        Some(&ledger),
        "the workspace graph holds the ledger"
    );

    // The frame: version 8, which this binary reads and a reader of at most
    // version 7 refuses by name before decoding its body.
    let frame = std::fs::read(frame_path(&directory, 3)).unwrap();
    assert_eq!(
        header_version(&frame),
        crate::storage::AuthorityFrame::CALL_SITE_LEDGERS_VERSION,
        "a frame that moves a ledger declares version 8"
    );
    crate::storage::AuthorityFrame::verify_frame_bytes(&frame).unwrap();
    let error = crate::storage::AuthorityFrame::check_readable_version(
        header_version(&frame),
        crate::storage::AuthorityFrame::RESOLUTION_RECORDS_VERSION,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error
            .contains("unsupported authority frame version: 8 (this kin-db reads versions 2 to 7)")
            && error.contains("reads frame version 8"),
        "{error}"
    );
    let decoded_frame = crate::storage::AuthorityFrame::from_bytes(&frame).unwrap();
    assert_eq!(decoded_frame.to_bytes().unwrap(), frame);

    // The snapshot: v25 (v26 with a section), 37 elements wide like v23.
    let ledgered = manager.read_authority().snapshot().clone();
    let bytes = ledgered.to_bytes().unwrap();
    let (expected, records_rung) = if ledgered.materialized_graph.is_some() {
        (
            GraphSnapshot::CALL_SITE_LEDGERS_SECTION_VERSION,
            GraphSnapshot::RESOLUTION_RECORDS_SECTION_VERSION,
        )
    } else {
        (
            GraphSnapshot::CALL_SITE_LEDGERS_VERSION,
            GraphSnapshot::RESOLUTION_RECORDS_VERSION,
        )
    };
    assert_eq!(header_version(&bytes), expected);
    assert_eq!(
        crate::storage::body_walk::top_level_element_ranges(&bytes[16..bytes.len() - 32])
            .unwrap()
            .len(),
        37,
        "a ledger body has the records layout"
    );
    let refusal = refused_by_a_reader_older_than_ledgers(header_version(&bytes));
    assert!(
        refusal.contains(&format!("version {expected} is newer than"))
            && refusal.contains("versions 13 through 24"),
        "{refusal}"
    );
    GraphSnapshot::prove_pre_validated_round_trip(&bytes).unwrap();
    let decoded = GraphSnapshot::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.to_bytes().unwrap(), bytes, "byte for byte");
    assert!(decoded.repository_authority.as_ref().unwrap().workspaces[0]
        .semantic_overlay
        .resolution_record_deltas()
        .contains(&kin_model::ResolutionRecordDelta::Added {
            new: ledger.clone()
        }));
    let envelope = crate::storage::format::AuthorityEnvelopeSnapshot::from_bytes(&bytes).unwrap();
    assert_eq!(envelope.version, expected);
    drop(manager);
    let reopened = RepositoryAuthorityManager::open(repository_id(), backend).unwrap();
    assert_eq!(
        workspace_records(&reopened).get(&ledger.id()),
        Some(&ledger),
        "the journal replays the frame that moved the ledger, ledger intact"
    );

    // The logged operation alone still carries the ledger; without it the
    // store is a records store again.
    let mut logged = ledgered.clone();
    let authority = logged.repository_authority.as_mut().unwrap();
    authority.workspaces[0].semantic_overlay = WorkspaceSemanticOverlay::default()
        .with_resolution_records(vec![kin_model::ResolutionRecordDelta::Added {
            new: context.clone(),
        }])
        .unwrap();
    assert_eq!(
        logged.wire_version(),
        expected,
        "the logged operation that moved the ledger carries it"
    );
    let authority = logged.repository_authority.as_mut().unwrap();
    authority.operation_log.retain(|operation| {
        operation.operation_id != OperationId::from_uuid(Uuid::from_u128(ledger_operation))
    });
    assert_eq!(logged.wire_version(), records_rung);
}

/// A frame carries a ledger through any of three places: its operation, a
/// successor workspace, or a change it appends. Each alone makes it version 8;
/// a change that moves only a proof context makes it version 7.
#[test]
fn a_frame_carries_a_ledger_in_its_operation_workspaces_or_changes() {
    let directory = TempDir::new().unwrap();
    let (_backend, manager) = framed_local_repository(&directory);
    let context = resolution_context();
    let caller = resolution_caller(0x0e3c_01c0, "function caller()");
    let ledger = resolution_ledger(caller.id, context.id());
    manager
        .commit_repository_transaction(resolution_records_transaction(
            &manager,
            0x0e3c_0101,
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
    let frame = crate::storage::AuthorityFrame::from_bytes(
        &std::fs::read(frame_path(&directory, 2)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        frame.wire_version(),
        crate::storage::AuthorityFrame::CALL_SITE_LEDGERS_VERSION
    );

    let mut operation_only = frame.clone();
    operation_only.workspaces.clear();
    assert_eq!(
        operation_only.wire_version(),
        crate::storage::AuthorityFrame::CALL_SITE_LEDGERS_VERSION,
        "the operation carries the ledger"
    );

    let mut workspace_only = frame.clone();
    workspace_only.operation.workspace_mutation = None;
    assert_eq!(
        workspace_only.wire_version(),
        crate::storage::AuthorityFrame::CALL_SITE_LEDGERS_VERSION,
        "the successor workspace carries the ledger"
    );

    let mut neither = workspace_only.clone();
    neither.workspaces.clear();
    let quiet = neither.wire_version();
    assert!(quiet < crate::storage::AuthorityFrame::RESOLUTION_RECORDS_VERSION);

    let mut proving = neither.clone();
    proving.changes.push(record_moving_change(vec![
        kin_model::ResolutionRecordDelta::Added {
            new: context.clone(),
        },
    ]));
    assert_eq!(
        proving.wire_version(),
        crate::storage::AuthorityFrame::RESOLUTION_RECORDS_VERSION,
        "a change that moves a proof context only is a records change"
    );

    let mut appended = neither;
    appended.changes.push(record_moving_change(vec![
        kin_model::ResolutionRecordDelta::Removed { old: ledger },
    ]));
    assert_eq!(
        appended.wire_version(),
        crate::storage::AuthorityFrame::CALL_SITE_LEDGERS_VERSION,
        "a change that carries a ledger, even one it removes, is a ledger change"
    );
}

/// A store whose records are proof contexts only keeps the records rung:
/// snapshot 23 (24 with a section) and frame 7, which a binary older than
/// ledgers opens, and both round-trip byte for byte. A store without records
/// keeps its own version, below the records rung, and its bytes.
#[test]
fn a_records_only_store_keeps_the_records_rung_and_its_bytes() {
    let directory = TempDir::new().unwrap();
    let (_backend, manager) = framed_local_repository(&directory);
    let quiet = manager.read_authority().snapshot().clone();
    let quiet_bytes = quiet.to_bytes().unwrap();
    assert!(header_version(&quiet_bytes) < GraphSnapshot::RESOLUTION_RECORDS_VERSION);
    GraphSnapshot::check_readable_version(
        header_version(&quiet_bytes),
        GraphSnapshot::ENRICHMENT_MARKS_SECTION_VERSION,
    )
    .expect("a binary older than records opens a store without them");
    assert_eq!(
        GraphSnapshot::from_bytes(&quiet_bytes)
            .unwrap()
            .to_bytes()
            .unwrap(),
        quiet_bytes
    );

    let context = resolution_context();
    manager
        .commit_repository_transaction(resolution_records_transaction(
            &manager,
            0x0e3c_0201,
            WorkspaceSemanticDelta::default()
                .with_resolution_records(vec![kin_model::ResolutionRecordDelta::Added {
                    new: context.clone(),
                }])
                .unwrap(),
        ))
        .unwrap();
    let frame = std::fs::read(frame_path(&directory, 2)).unwrap();
    assert_eq!(
        header_version(&frame),
        crate::storage::AuthorityFrame::RESOLUTION_RECORDS_VERSION
    );
    crate::storage::AuthorityFrame::check_readable_version(
        header_version(&frame),
        crate::storage::AuthorityFrame::RESOLUTION_RECORDS_VERSION,
    )
    .expect("a binary older than ledgers opens a records frame");
    assert_eq!(
        crate::storage::AuthorityFrame::from_bytes(&frame)
            .unwrap()
            .to_bytes()
            .unwrap(),
        frame
    );

    let recorded = manager.read_authority().snapshot().clone();
    let bytes = recorded.to_bytes().unwrap();
    let expected = if recorded.materialized_graph.is_some() {
        GraphSnapshot::RESOLUTION_RECORDS_SECTION_VERSION
    } else {
        GraphSnapshot::RESOLUTION_RECORDS_VERSION
    };
    assert_eq!(header_version(&bytes), expected);
    GraphSnapshot::check_readable_version(
        header_version(&bytes),
        GraphSnapshot::RESOLUTION_RECORDS_SECTION_VERSION,
    )
    .expect("a binary older than ledgers opens a records-only store");
    assert_eq!(
        GraphSnapshot::from_bytes(&bytes)
            .unwrap()
            .to_bytes()
            .unwrap(),
        bytes,
        "byte for byte"
    );
}
