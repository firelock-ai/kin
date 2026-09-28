// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Reuse the authority publication fixtures. Both validation states must survive
// durable publication, including when only a logged operation retains them.
fn authority_context_validations() -> [kin_model::ResolutionRecord; 2] {
    let context = resolution_context().as_proof_context().unwrap().clone();
    [
        kin_model::ResolutionRecord::ContextValidation(kin_model::ContextValidation {
            language: context.language,
            state: kin_model::ContextValidationState::Validated { context },
        }),
        kin_model::ResolutionRecord::ContextValidation(kin_model::ContextValidation {
            language: LanguageId::TypeScript,
            state: kin_model::ContextValidationState::Unverified {
                reason: "language server unavailable".into(),
            },
        }),
    ]
}

#[test]
fn context_validations_persist_in_authority_and_refuse_older_readers() {
    for record in authority_context_validations() {
        let directory = TempDir::new().unwrap();
        let (backend, manager) = framed_local_repository(&directory);
        let context = resolution_context();
        manager
            .commit_repository_transaction(resolution_records_transaction(
                &manager,
                0x0e3d_0001,
                WorkspaceSemanticDelta::default()
                    .with_resolution_records(vec![kin_model::ResolutionRecordDelta::Added {
                        new: context.clone(),
                    }])
                    .unwrap(),
            ))
            .unwrap();
        let records_bytes = std::fs::read(frame_path(&directory, 2)).unwrap();
        assert_eq!(header_version(&records_bytes), 7);

        manager
            .commit_repository_transaction(resolution_records_transaction(
                &manager,
                0x0e3d_0002,
                WorkspaceSemanticDelta::default()
                    .with_resolution_records(vec![kin_model::ResolutionRecordDelta::Added {
                        new: record.clone(),
                    }])
                    .unwrap(),
            ))
            .unwrap();
        assert_eq!(workspace_records(&manager).get(&record.id()), Some(&record));
        let bytes = std::fs::read(frame_path(&directory, 3)).unwrap();
        assert_eq!(header_version(&bytes), 9);
        let refusal = crate::storage::AuthorityFrame::check_readable_version(
            header_version(&bytes),
            crate::storage::AuthorityFrame::CALL_SITE_LEDGERS_VERSION,
        )
        .unwrap_err()
        .to_string();
        assert!(
            refusal.contains("unsupported authority frame version: 9")
                && refusal.contains("versions 2 to 8"),
            "{refusal}"
        );
        crate::storage::AuthorityFrame::verify_frame_bytes(&bytes).unwrap();
        let frame = crate::storage::AuthorityFrame::from_bytes(&bytes).unwrap();
        assert_eq!(frame.to_bytes().unwrap(), bytes);
        let mut relabeled = bytes.clone();
        relabeled[4..8].copy_from_slice(&8u32.to_le_bytes());
        assert!(crate::storage::AuthorityFrame::from_bytes(&relabeled)
            .unwrap_err()
            .to_string()
            .contains("declares version 8"));

        let snapshot = manager.read_authority().snapshot().clone();
        let expected = if snapshot.materialized_graph.is_some() {
            28
        } else {
            27
        };
        assert_eq!(snapshot.version, expected);
        let snapshot_bytes = snapshot.to_bytes().unwrap();
        assert_eq!(header_version(&snapshot_bytes), expected);
        assert!(
            matches!(GraphSnapshot::check_readable_version(expected, 26).unwrap_err(),
            KinDbError::IncompatibleSnapshotVersion { found, max: 26, .. } if found == expected)
        );
        GraphSnapshot::prove_pre_validated_round_trip(&snapshot_bytes).unwrap();
        assert_eq!(
            GraphSnapshot::from_bytes(&snapshot_bytes)
                .unwrap()
                .to_bytes()
                .unwrap(),
            snapshot_bytes
        );
        assert_eq!(
            crate::storage::format::AuthorityEnvelopeSnapshot::from_bytes(&snapshot_bytes)
                .unwrap()
                .version,
            expected
        );
        drop(manager);
        let reopened = RepositoryAuthorityManager::open(repository_id(), backend).unwrap();
        assert_eq!(
            workspace_records(&reopened).get(&record.id()),
            Some(&record),
            "the durable journal replays both validation states intact"
        );

        let mut operation_only = snapshot;
        operation_only
            .repository_authority
            .as_mut()
            .unwrap()
            .workspaces[0]
            .semantic_overlay = WorkspaceSemanticOverlay::default()
            .with_resolution_records(vec![kin_model::ResolutionRecordDelta::Added {
                new: context,
            }])
            .unwrap();
        assert_eq!(operation_only.wire_version(), expected);
        operation_only
            .repository_authority
            .as_mut()
            .unwrap()
            .operation_log
            .retain(|operation| {
                operation.operation_id != OperationId::from_uuid(Uuid::from_u128(0x0e3d_0002))
            });
        assert_eq!(
            operation_only.wire_version(),
            if expected == 28 { 24 } else { 23 },
            "a store with no remaining validation content keeps the records rung"
        );
    }
}

#[test]
fn a_frame_carries_context_validation_in_operation_workspace_or_history() {
    for record in authority_context_validations() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        manager
            .commit_repository_transaction(resolution_records_transaction(
                &manager,
                0x0e3d_0101,
                WorkspaceSemanticDelta::default()
                    .with_resolution_records(vec![kin_model::ResolutionRecordDelta::Added {
                        new: record.clone(),
                    }])
                    .unwrap(),
            ))
            .unwrap();
        let frame = crate::storage::AuthorityFrame::from_bytes(
            &std::fs::read(frame_path(&directory, 2)).unwrap(),
        )
        .unwrap();
        let mut operation_only = frame.clone();
        operation_only.workspaces.clear();
        assert_eq!(operation_only.wire_version(), 9);
        let mut workspace_only = frame;
        workspace_only.operation.workspace_mutation = None;
        assert_eq!(workspace_only.wire_version(), 9);
        workspace_only.workspaces.clear();
        assert!(workspace_only.wire_version() < 9);
        workspace_only.changes.push(record_moving_change(vec![
            kin_model::ResolutionRecordDelta::Removed { old: record },
        ]));
        assert_eq!(
            workspace_only.wire_version(),
            9,
            "a historical removal still carries the full validation record"
        );
    }
}
