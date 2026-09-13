// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

fn mcp_lifecycle_fixture() -> (tempfile::TempDir, Arc<DaemonState>) {
    install_test_registry_override();
    let dir = tempfile::tempdir().unwrap();
    let layout = kin_core::init(dir.path()).unwrap().layout;
    let state = Arc::new(DaemonState::open(layout).unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    (dir, state)
}

fn mcp_lifecycle_operation(name: &str) -> serde_json::Value {
    serde_json::json!({
        "verb": "create",
        "target": "",
        "payload": { "Entity": test_entity(name, "src/lib.rs") },
        "description": "retain staged work"
    })
}

async fn mcp_lifecycle_begin(state: &Arc<DaemonState>, session_id: &str) -> String {
    let begin = mcp_call(
        router(Arc::clone(state)),
        "kin_transaction_begin",
        serde_json::json!({ "session_id": session_id, "scope": "repository" }),
    )
    .await;
    assert_ne!(begin.is_error, Some(true), "{}", mcp_result_text(&begin));
    tool_result_payload(&begin)["transaction_id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn mcp_staging_ack_refuses_failed_persistence_and_preserves_acknowledged_work() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session_id = mcp_test_session(&state);
    let tx_id = mcp_lifecycle_begin(&state, &session_id).await;
    let first = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_stage",
            serde_json::json!({ "transaction_id": tx_id, "operations": [mcp_lifecycle_operation("first")] }),
        )
        .await;
    assert_ne!(first.is_error, Some(true), "{}", mcp_result_text(&first));
    let mirror = crate::state::mcp_transactions_disk_path(&state.layout);
    let acknowledged = std::fs::read(&mirror).unwrap();
    let temp_guard = crate::state::McpTransactionTempGuard::new(&mirror);
    let blocked_tmp = temp_guard.path();
    std::fs::create_dir(&blocked_tmp).unwrap();
    let failed = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_stage",
            serde_json::json!({ "transaction_id": tx_id, "operations": [mcp_lifecycle_operation("second")] }),
        )
        .await;
    std::fs::remove_dir(&blocked_tmp).unwrap();
    drop(temp_guard);
    assert_eq!(
        failed.is_error,
        Some(true),
        "a failed durable write was acknowledged: {}",
        mcp_result_text(&failed)
    );
    assert_eq!(std::fs::read(&mirror).unwrap(), acknowledged);
    assert_eq!(
        state.mcp_transactions.lock().unwrap()[&tx_id]
            .staged_operations
            .len(),
        1
    );
    let layout = state.layout.clone();
    drop(state);
    let reopened = DaemonState::open(layout).unwrap();
    assert_eq!(
        reopened.mcp_transactions.lock().unwrap()[&tx_id]
            .staged_operations
            .len(),
        1
    );
}

#[tokio::test]
async fn mcp_staging_ack_install_and_journal_failures_preserve_each_lifecycle_state() {
    use crate::state::McpTransactionWritePhase;
    for tool in [
        "kin_transaction_begin",
        "kin_transaction_stage",
        "kin_transaction_validate",
    ] {
        for phase in [
            McpTransactionWritePhase::Write,
            McpTransactionWritePhase::FileSync,
            McpTransactionWritePhase::Rename,
            McpTransactionWritePhase::DirectorySync,
            McpTransactionWritePhase::JournalWrite,
            McpTransactionWritePhase::JournalFileSync,
            McpTransactionWritePhase::JournalRename,
            McpTransactionWritePhase::JournalDirectorySync,
            McpTransactionWritePhase::JournalRemove,
            McpTransactionWritePhase::AcknowledgementDirectorySync,
        ] {
            let (_dir, state) = mcp_lifecycle_fixture();
            let session_id = mcp_test_session(&state);
            let tx_id = mcp_lifecycle_begin(&state, &session_id).await;
            let stage = mcp_call(router(Arc::clone(&state)), "kin_transaction_stage",
                    serde_json::json!({ "transaction_id": tx_id, "operations": [mcp_lifecycle_operation("first")] })).await;
            assert_ne!(stage.is_error, Some(true), "{}", mcp_result_text(&stage));
            let mirror = crate::state::mcp_transactions_disk_path(&state.layout);
            let previous = std::fs::read(&mirror).unwrap();
            let previous_value: serde_json::Value = serde_json::from_slice(&previous).unwrap();
            let args = match tool {
                "kin_transaction_begin" => {
                    serde_json::json!({ "session_id": session_id, "scope": "repository" })
                }
                "kin_transaction_stage" => {
                    serde_json::json!({ "transaction_id": tx_id, "operations": [mcp_lifecycle_operation("second")] })
                }
                _ => serde_json::json!({ "transaction_id": tx_id }),
            };
            state
                .mcp_lifecycle_persist_fail_once
                .store(phase as u8, std::sync::atomic::Ordering::SeqCst);
            let failed = mcp_call(router(Arc::clone(&state)), tool, args.clone()).await;
            assert_eq!(
                failed.is_error,
                Some(true),
                "{tool}/{phase:?}: {}",
                mcp_result_text(&failed)
            );
            assert!(mcp_result_text(&failed).contains("did not receive a durable acknowledgement"));
            assert_eq!(
                std::fs::read(&mirror).unwrap(),
                previous,
                "{tool}/{phase:?}"
            );
            assert_eq!(
                serde_json::to_value(&*state.mcp_transactions.lock().unwrap()).unwrap(),
                previous_value,
                "{tool}/{phase:?}"
            );
            // A failed journal directory sync can leave a pending record, but
            // no proposed mirror was installed. The next call recovers it.
            // Retry the identical call after storage recovers. It must apply once,
            // not duplicate operations left in the failed request's registry.
            let retried = mcp_call(router(Arc::clone(&state)), tool, args).await;
            assert_ne!(
                retried.is_error,
                Some(true),
                "{tool}/{phase:?}: {}",
                mcp_result_text(&retried)
            );
            let expected = serde_json::to_value(&*state.mcp_transactions.lock().unwrap()).unwrap();
            let layout = state.layout.clone();
            drop(state);
            let reopened = DaemonState::open(layout).unwrap();
            assert_eq!(
                serde_json::to_value(&*reopened.mcp_transactions.lock().unwrap()).unwrap(),
                expected
            );
            if tool == "kin_transaction_stage" {
                assert_eq!(
                    reopened.mcp_transactions.lock().unwrap()[&tx_id]
                        .staged_operations
                        .len(),
                    2
                );
            }
        }
    }
}

#[tokio::test]
async fn mcp_staging_ack_restart_rolls_back_interrupted_install() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session_id = mcp_test_session(&state);
    let tx_id = mcp_lifecycle_begin(&state, &session_id).await;
    let first = mcp_call(router(Arc::clone(&state)), "kin_transaction_stage",
            serde_json::json!({ "transaction_id": tx_id, "operations": [mcp_lifecycle_operation("first")] })).await;
    assert_ne!(first.is_error, Some(true));
    let mirror = crate::state::mcp_transactions_disk_path(&state.layout);
    let previous = std::fs::read(&mirror).unwrap();
    let mut next = state.mcp_transactions.lock().unwrap().clone();
    next.get_mut(&tx_id)
        .unwrap()
        .staged_operations
        .push(serde_json::from_value(mcp_lifecycle_operation("second")).unwrap());
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::state::write_mcp_transaction_lifecycle(&state.layout, &next, |phase| {
            if matches!(phase, crate::state::McpTransactionWritePhase::DirectorySync) {
                panic!("interrupt after installing the proposed mirror");
            }
            Ok(())
        })
        .unwrap();
    }));
    assert!(interrupted.is_err());
    assert_ne!(std::fs::read(&mirror).unwrap(), previous);
    assert!(state
        .layout
        .root()
        .join("mcp_transactions.lifecycle.json")
        .exists());
    let layout = state.layout.clone();
    drop(state);
    let reopened = DaemonState::open(layout).unwrap();
    assert_eq!(std::fs::read(&mirror).unwrap(), previous);
    assert_eq!(
        reopened.mcp_transactions.lock().unwrap()[&tx_id]
            .staged_operations
            .len(),
        1
    );
    assert!(!reopened
        .layout
        .root()
        .join("mcp_transactions.lifecycle.json")
        .exists());
}

#[tokio::test]
async fn mcp_staging_ack_recovery_failures_retain_retryable_evidence() {
    use crate::state::McpTransactionWritePhase;
    for failed_recovery_phase in [
        McpTransactionWritePhase::RecoveryWrite,
        McpTransactionWritePhase::RecoveryFileSync,
        McpTransactionWritePhase::RecoveryRename,
        McpTransactionWritePhase::RecoveryDirectorySync,
        McpTransactionWritePhase::RecoveryJournalRemove,
        McpTransactionWritePhase::RecoveryJournalDirectorySync,
    ] {
        let (_dir, state) = mcp_lifecycle_fixture();
        let session_id = mcp_test_session(&state);
        let tx_id = mcp_lifecycle_begin(&state, &session_id).await;
        let mirror = crate::state::mcp_transactions_disk_path(&state.layout);
        let previous = std::fs::read(&mirror).unwrap();
        let mut next = state.mcp_transactions.lock().unwrap().clone();
        next.get_mut(&tx_id)
            .unwrap()
            .staged_operations
            .push(serde_json::from_value(mcp_lifecycle_operation("first")).unwrap());
        let failure = crate::state::write_mcp_transaction_lifecycle(&state.layout, &next, |phase| {
            if matches!(phase, McpTransactionWritePhase::DirectorySync)
                || phase as u8 == failed_recovery_phase as u8
            {
                Err(std::io::Error::other(format!("injected {phase:?}")))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(failure.to_string().contains("transaction_recovery_required"));
        assert!(state
            .layout
            .root()
            .join("mcp_transactions.lifecycle.json")
            .exists(), "{failed_recovery_phase:?}: recovery must remain discoverable");
        // The next API call must complete recovery and reload the restored
        // registry before applying a retry. This covers the live-recovery gap
        // after a successful journal unlink whose directory sync then fails.
        let retried = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_stage",
            serde_json::json!({ "transaction_id": tx_id, "operations": [mcp_lifecycle_operation("first")] }),
        )
        .await;
        assert_ne!(retried.is_error, Some(true), "{}", mcp_result_text(&retried));
        assert_ne!(std::fs::read(&mirror).unwrap(), previous);
        assert_eq!(state.mcp_transactions.lock().unwrap()[&tx_id].staged_operations.len(), 1);
        let layout = state.layout.clone();
        drop(state);
        let reopened = DaemonState::open(layout).unwrap();
        assert_eq!(reopened.mcp_transactions.lock().unwrap()[&tx_id].staged_operations.len(), 1);
    }
}

#[tokio::test]
async fn mcp_staging_ack_first_begin_finalization_failure_restores_absence() {
    use crate::state::McpTransactionWritePhase;
    for phase in [
        McpTransactionWritePhase::JournalRemove,
        McpTransactionWritePhase::AcknowledgementDirectorySync,
    ] {
        let (_dir, state) = mcp_lifecycle_fixture();
        let session_id = mcp_test_session(&state);
        let mirror = crate::state::mcp_transactions_disk_path(&state.layout);
        assert!(!mirror.exists());
        state.mcp_lifecycle_persist_fail_once.store(phase as u8, std::sync::atomic::Ordering::SeqCst);
        let failed = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_begin",
            serde_json::json!({ "session_id": session_id, "scope": "repository" }),
        ).await;
        assert_eq!(failed.is_error, Some(true), "{}", mcp_result_text(&failed));
        assert!(!mirror.exists());
        assert!(state.mcp_transactions.lock().unwrap().is_empty());
        let tx_id = mcp_lifecycle_begin(&state, &session_id).await;
        let layout = state.layout.clone();
        drop(state);
        let reopened = DaemonState::open(layout).unwrap();
        let restored = reopened.mcp_transactions.lock().unwrap();
        assert_eq!(restored.len(), 1);
        assert!(restored.contains_key(&tx_id));
    }
}

#[tokio::test]
async fn mcp_staging_ack_finalization_interruption_preserves_possible_outcomes() {
    use crate::state::McpTransactionWritePhase;
    for (phase, pending, expected_operations) in [
        (McpTransactionWritePhase::JournalRemove, true, 0),
        (McpTransactionWritePhase::AcknowledgementDirectorySync, false, 1),
    ] {
        let (_dir, state) = mcp_lifecycle_fixture();
        let session_id = mcp_test_session(&state);
        let tx_id = mcp_lifecycle_begin(&state, &session_id).await;
        let mut next = state.mcp_transactions.lock().unwrap().clone();
        next.get_mut(&tx_id)
            .unwrap()
            .staged_operations
            .push(serde_json::from_value(mcp_lifecycle_operation("first")).unwrap());
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::state::write_mcp_transaction_lifecycle(&state.layout, &next, |observed| {
                if observed as u8 == phase as u8 {
                    panic!("interrupt at final acknowledgement boundary {phase:?}");
                }
                Ok(())
            })
            .unwrap();
        }));
        assert!(interrupted.is_err());
        assert_eq!(state.layout.root().join("mcp_transactions.lifecycle.json").exists(), pending);
        let layout = state.layout.clone();
        drop(state);
        let reopened = DaemonState::open(layout).unwrap();
        assert_eq!(reopened.mcp_transactions.lock().unwrap()[&tx_id].staged_operations.len(), expected_operations);
        // Before journal unlink, recovery restores the previous state. Once
        // unlink is observable, a lost response may have applied the stage.
        // A process interruption cannot emulate whether that unlink survives
        // power loss; either outcome retains previously acknowledged work.
    }
}

#[tokio::test]
async fn mcp_staging_ack_malformed_recovery_record_cannot_erase_the_mirror() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session_id = mcp_test_session(&state);
    let tx_id = mcp_lifecycle_begin(&state, &session_id).await;
    let mirror = crate::state::mcp_transactions_disk_path(&state.layout);
    let previous = std::fs::read(&mirror).unwrap();
    let record = state.layout.root().join("mcp_transactions.lifecycle.json");
    std::fs::write(&record, b"{}").unwrap();
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let read = mcp_call(
        router(Arc::clone(&reopened)),
        "kin_graph_status",
        serde_json::json!({}),
    )
    .await;
    assert_ne!(read.is_error, Some(true), "{}", mcp_result_text(&read));
    for tool in ["kin_transaction_validate", "kin_transaction_commit"] {
        let refused = mcp_call(
            router(Arc::clone(&reopened)),
            tool,
            serde_json::json!({ "transaction_id": tx_id }),
        )
        .await;
        assert_eq!(refused.is_error, Some(true));
        assert!(mcp_result_text(&refused).contains("transaction_recovery_required"));
    }
    assert!(reopened.mcp_transactions.lock().unwrap().is_empty());
    assert_eq!(std::fs::read(&mirror).unwrap(), previous);
    assert_eq!(std::fs::read(&record).unwrap(), b"{}");
}

#[tokio::test]
async fn mcp_staging_ack_corrupt_mirror_preserves_repository_receipt_replay() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let mut caller = test_entity("caller", "src/lib.rs");
    caller.file_origin = None;
    caller.span = None;
    let mut callee = test_entity("callee", "src/lib.rs");
    callee.file_origin = None;
    callee.span = None;
    install_repository_entities(&state, vec![caller.clone(), callee.clone()]);
    let session_id = mcp_test_session(&state);
    let tx_id = mcp_lifecycle_begin(&state, &session_id).await;
    let staged = mcp_call(router(Arc::clone(&state)), "kin_transaction_stage",
            serde_json::json!({ "transaction_id": tx_id, "operations": [{
                "verb": "add", "target": "", "description": "record call",
                "payload": { "Relation": { "from": caller.id, "to": callee.id, "kind": RelationKind::Calls } }
            }] })).await;
    assert_ne!(staged.is_error, Some(true), "{}", mcp_result_text(&staged));
    let committed = mcp_call(
        router(Arc::clone(&state)),
        "kin_transaction_commit",
        serde_json::json!({ "transaction_id": tx_id }),
    )
    .await;
    assert_ne!(
        committed.is_error,
        Some(true),
        "{}",
        mcp_result_text(&committed)
    );
    let receipt = tool_result_payload(&committed);
    let layout = state.layout.clone();
    let mirror = crate::state::mcp_transactions_disk_path(&layout);
    let corrupt = b"{retain receipt recovery evidence";
    std::fs::write(&mirror, corrupt).unwrap();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let replay = mcp_call(
        router(Arc::clone(&reopened)),
        "kin_transaction_commit",
        serde_json::json!({ "transaction_id": tx_id }),
    )
    .await;
    assert_ne!(replay.is_error, Some(true), "{}", mcp_result_text(&replay));
    let replayed = tool_result_payload(&replay);
    assert_eq!(replayed["already_applied"], true);
    assert_eq!(replayed["change_id"], receipt["change_id"]);
    assert_eq!(
        replayed["repository_generation"],
        receipt["repository_generation"]
    );
    assert_eq!(std::fs::read(&mirror).unwrap(), corrupt);
}

#[tokio::test]
async fn mcp_staging_ack_corrupt_mirror_requires_recovery_without_erasing_evidence() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session_id = mcp_test_session(&state);
    let tx_id = mcp_lifecycle_begin(&state, &session_id).await;
    let layout = state.layout.clone();
    let mirror = crate::state::mcp_transactions_disk_path(&layout);
    let prior = std::fs::read(&mirror).unwrap();
    let corrupt = b"{retained recovery evidence";
    std::fs::write(&mirror, corrupt).unwrap();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let refused = mcp_call(
        router(Arc::clone(&reopened)),
        "kin_transaction_validate",
        serde_json::json!({"transaction_id": tx_id}),
    )
    .await;
    assert_eq!(refused.is_error, Some(true));
    assert!(mcp_result_text(&refused).contains("transaction_recovery_required"));
    assert_eq!(std::fs::read(&mirror).unwrap(), corrupt);
    assert!(crate::state::write_persisted_mcp_transactions_checked(
        &reopened.layout,
        &HashMap::new()
    )
    .is_err());
    assert_eq!(std::fs::read(&mirror).unwrap(), corrupt);
    // The retained original bytes are sufficient for explicit repair.
    std::fs::write(&mirror, prior).unwrap();
    let layout = reopened.layout.clone();
    drop(reopened);
    let recovered = DaemonState::open(layout).unwrap();
    assert!(recovered
        .mcp_transactions
        .lock()
        .unwrap()
        .contains_key(&tx_id));
}

const MCP_RECOVERY_ACKNOWLEDGED_BODY: &str = "pub fn acknowledged() -> u8 { 42 }\n";

async fn mcp_after_compound_cold_recovery_failure() -> (tempfile::TempDir, Arc<DaemonState>, String)
{
    let (dir, state) = mcp_lifecycle_fixture();
    let session_id = mcp_test_session(&state);
    let tx_id = mcp_lifecycle_begin(&state, &session_id).await;
    let acknowledged_body = MCP_RECOVERY_ACKNOWLEDGED_BODY;
    let staged = mcp_call(
        router(Arc::clone(&state)),
        "kin_transaction_stage",
        serde_json::json!({ "transaction_id": tx_id, "operations": [{
            "verb": "create", "target": "src/acknowledged.rs", "body": acknowledged_body,
            "description": "retain the exact acknowledged source body"
        }] }),
    )
    .await;
    assert_ne!(staged.is_error, Some(true), "{}", mcp_result_text(&staged));
    let mirror = crate::state::mcp_transactions_disk_path(&state.layout);
    let previous = std::fs::read(&mirror).unwrap();
    let body_of = |store: &HashMap<String, kin_mcp::McpTransaction>| {
        store
            .get(&tx_id)
            .and_then(|tx| tx.staged_operations.first())
            .and_then(|op| op.body.clone())
    };
    assert_eq!(
        body_of(&state.mcp_transactions.lock().unwrap()).as_deref(),
        Some(acknowledged_body)
    );

    // Leave a real pending lifecycle journal and installed, unacknowledged
    // mirror. Cold recovery must restore the earlier acknowledged body.
    let mut proposed = state.mcp_transactions.lock().unwrap().clone();
    proposed.get_mut(&tx_id).unwrap().staged_operations[0].body =
        Some("pub fn acknowledged() -> u8 { 99 }\n".into());
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::state::write_mcp_transaction_lifecycle(&state.layout, &proposed, |phase| {
            if matches!(phase, crate::state::McpTransactionWritePhase::DirectorySync) {
                panic!("interrupt after the unacknowledged mirror install");
            }
            Ok(())
        })
        .unwrap();
    }));
    assert!(interrupted.is_err());
    assert_ne!(std::fs::read(&mirror).unwrap(), previous);
    let layout = state.layout.clone();
    let journal = layout.root().join("mcp_transactions.lifecycle.json");
    assert!(journal.is_file());
    drop(state);

    // Restore the old mirror, unlink the recovery journal, then fail both its
    // directory sync and journal re-creation during the actual cold-open path.
    let temp_guard = crate::state::McpTransactionTempGuard::new(&journal);
    crate::state::MCP_RECOVERY_FAIL_JOURNAL_RECREATION_ONCE.with(|fault| fault.set(true));
    let reopened = Arc::new(DaemonState::open(layout.clone()).unwrap());
    assert!(!crate::state::MCP_RECOVERY_FAIL_JOURNAL_RECREATION_ONCE.with(|fault| fault.get()));
    assert_eq!(
        std::fs::read(&mirror).unwrap(),
        previous,
        "the acknowledged mirror was restored"
    );
    assert!(!journal.exists(), "journal re-creation really failed");
    let blocked_tmp = temp_guard.path();
    assert!(
        blocked_tmp.is_dir(),
        "fault must reach the real filesystem writer"
    );

    // Storage recovers while this daemon remains live and its registry is
    // empty. Only the valid persisted mirror retains the acknowledged work.
    std::fs::remove_dir(blocked_tmp).unwrap();
    drop(temp_guard);
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(reopened.mcp_transactions.lock().unwrap().is_empty());
    assert_eq!(
        body_of(&crate::state::load_persisted_mcp_transactions_checked(&layout).unwrap())
            .as_deref(),
        Some(acknowledged_body)
    );
    (dir, reopened, tx_id)
}

#[tokio::test]
async fn mcp_staging_ack_compound_cold_recovery_failure_preserves_acknowledged_body() {
    let (_dir, reopened, tx_id) = mcp_after_compound_cold_recovery_failure().await;
    let layout = reopened.layout.clone();
    let acknowledged_body = MCP_RECOVERY_ACKNOWLEDGED_BODY;
    let body_of = |store: &HashMap<String, kin_mcp::McpTransaction>| {
        store
            .get(&tx_id)
            .and_then(|tx| tx.staged_operations.first())
            .and_then(|op| op.body.clone())
    };
    let next_session = mcp_test_session(&reopened);
    let next_id = mcp_lifecycle_begin(&reopened, &next_session).await;
    let live_body = body_of(&reopened.mcp_transactions.lock().unwrap());
    let disk_body =
        body_of(&crate::state::load_persisted_mcp_transactions_checked(&layout).unwrap());
    assert_ne!(next_id, tx_id);
    drop(reopened);
    let after_restart = DaemonState::open(layout).unwrap();
    let restarted_body = body_of(&after_restart.mcp_transactions.lock().unwrap());
    assert_eq!(
        (live_body, disk_body, restarted_body),
        (Some(acknowledged_body.to_string()), Some(acknowledged_body.to_string()), Some(acknowledged_body.to_string())),
        "a successful later begin must retain the previously acknowledged transaction and body in live state, on disk, and after another cold open"
    );
}

#[tokio::test]
async fn mcp_staging_ack_compound_cold_recovery_failure_can_commit_acknowledged_body() {
    let (_dir, reopened, tx_id) = mcp_after_compound_cold_recovery_failure().await;
    let layout = reopened.layout.clone();
    let committed = mcp_call(
        router(Arc::clone(&reopened)),
        "kin_transaction_commit",
        serde_json::json!({ "transaction_id": tx_id }),
    )
    .await;
    assert_ne!(
        committed.is_error,
        Some(true),
        "{}",
        mcp_result_text(&committed)
    );
    let receipt = tool_result_payload(&committed);
    assert_eq!(receipt["already_applied"], false);
    assert!(!reopened
        .mcp_transactions
        .lock()
        .unwrap()
        .contains_key(&tx_id));

    fn published_body(state: &DaemonState) -> Vec<u8> {
        let path = kin_model::RepoPath::from_utf8("src/acknowledged.rs".to_string()).unwrap();
        let tree = state.graph.resolved_tree();
        let kin_model::TreeEntry::Blob { hash, .. } = tree.artifact_at_path(&path).unwrap().entry
        else {
            panic!("committed source must be a blob");
        };
        let context =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)
                .unwrap();
        let authority = context.open().unwrap();
        crate::source_cas::read_publishable_source(&state.blobs, &authority, hash)
            .unwrap()
            .body()
            .to_vec()
    }
    assert_eq!(
        published_body(&reopened),
        MCP_RECOVERY_ACKNOWLEDGED_BODY.as_bytes()
    );
    drop(reopened);
    let after_restart = Arc::new(DaemonState::open(layout).unwrap());
    after_restart
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        published_body(&after_restart),
        MCP_RECOVERY_ACKNOWLEDGED_BODY.as_bytes()
    );
    let replay = mcp_call(
        router(Arc::clone(&after_restart)),
        "kin_transaction_commit",
        serde_json::json!({ "transaction_id": tx_id }),
    )
    .await;
    assert_ne!(replay.is_error, Some(true), "{}", mcp_result_text(&replay));
    let replayed = tool_result_payload(&replay);
    assert_eq!(replayed["already_applied"], true);
    assert_eq!(replayed["change_id"], receipt["change_id"]);
    assert_eq!(
        replayed["repository_generation"],
        receipt["repository_generation"]
    );
}

#[tokio::test]
async fn mcp_staging_temp_existing_regular_evidence_survives_restart() {
    for name in ["mcp_transactions.json", "mcp_transactions.lifecycle.json"] {
        let (_dir, state) = mcp_lifecycle_fixture();
        let session = mcp_test_session(&state);
        let tx = mcp_lifecycle_begin(&state, &session).await;
        let evidence = state.layout.root().join(name).with_extension("json.tmp");
        let original = b"retain preexisting unrelated temporary bytes";
        std::fs::write(&evidence, original).unwrap();
        let staged = mcp_call(router(Arc::clone(&state)), "kin_transaction_stage", serde_json::json!({"transaction_id":tx,"operations":[mcp_lifecycle_operation("retained")]})).await;
        assert_ne!(staged.is_error, Some(true), "{}", mcp_result_text(&staged));
        assert_eq!(
            std::fs::read(&evidence).unwrap(),
            original,
            "preexisting regular evidence was overwritten or removed"
        );
        let reopened = DaemonState::open(state.layout.clone()).unwrap();
        assert_eq!(
            reopened.mcp_transactions.lock().unwrap()[&tx]
                .staged_operations
                .len(),
            1
        );
        assert_eq!(std::fs::read(&evidence).unwrap(), original);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn mcp_staging_temp_symlink_victims_survive_real_stage_and_restart() {
    use std::os::unix::fs::PermissionsExt;
    for name in ["mcp_transactions.json", "mcp_transactions.lifecycle.json"] {
        let (dir, state) = mcp_lifecycle_fixture();
        let session = mcp_test_session(&state);
        let tx = mcp_lifecycle_begin(&state, &session).await;
        let target = dir.path().join("unrelated-victim.txt");
        let original = b"unrelated victim must not be truncated";
        std::fs::write(&target, original).unwrap();
        let link = state.layout.root().join(name).with_extension("json.tmp");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let staged = mcp_call(router(Arc::clone(&state)), "kin_transaction_stage", serde_json::json!({"transaction_id":tx,"operations":[mcp_lifecycle_operation("retained")]})).await;
        assert_ne!(staged.is_error, Some(true), "{}", mcp_result_text(&staged));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            original,
            "staging followed an unowned temporary symlink"
        );
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        let mirror = crate::state::mcp_transactions_disk_path(&state.layout);
        assert_eq!(
            std::fs::metadata(&mirror).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let reopened = DaemonState::open(state.layout.clone()).unwrap();
        assert_eq!(
            reopened.mcp_transactions.lock().unwrap()[&tx]
                .staged_operations
                .len(),
            1
        );
        assert_eq!(std::fs::read(&target).unwrap(), original);
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn mcp_staging_temp_exclusive_collision_refuses_without_removing_evidence() {
    for name in ["mcp_transactions.json", "mcp_transactions.lifecycle.json"] {
        for symlink in [false, true] {
            let (dir, state) = mcp_lifecycle_fixture();
            let session = mcp_test_session(&state);
            let tx = mcp_lifecycle_begin(&state, &session).await;
            let first = mcp_call(router(Arc::clone(&state)), "kin_transaction_stage", serde_json::json!({"transaction_id":tx,"operations":[mcp_lifecycle_operation("acknowledged")]})).await;
            assert_ne!(first.is_error, Some(true), "{}", mcp_result_text(&first));
            let mirror = crate::state::mcp_transactions_disk_path(&state.layout);
            let acknowledged = std::fs::read(&mirror).unwrap();
            let temp_guard =
                crate::state::McpTransactionTempGuard::new(&state.layout.root().join(name));
            let collision = temp_guard.path();
            let target = dir.path().join("collision-victim.txt");
            let original = b"unowned collision evidence";
            if symlink {
                std::fs::write(&target, original).unwrap();
                std::os::unix::fs::symlink(&target, &collision).unwrap();
            } else {
                std::fs::write(&collision, original).unwrap();
            }
            let refused = mcp_call(router(Arc::clone(&state)), "kin_transaction_stage", serde_json::json!({"transaction_id":tx,"operations":[mcp_lifecycle_operation("refused")]})).await;
            assert_eq!(
                refused.is_error,
                Some(true),
                "{}",
                mcp_result_text(&refused)
            );
            assert_eq!(std::fs::read(&mirror).unwrap(), acknowledged);
            assert_eq!(std::fs::read(&collision).unwrap(), original);
            assert_eq!(
                std::fs::symlink_metadata(&collision)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                symlink
            );
            assert_eq!(
                state.mcp_transactions.lock().unwrap()[&tx]
                    .staged_operations
                    .len(),
                1
            );
            drop(temp_guard);
            let reopened = Arc::new(DaemonState::open(state.layout.clone()).unwrap());
            assert_eq!(
                reopened.mcp_transactions.lock().unwrap()[&tx]
                    .staged_operations
                    .len(),
                1
            );
            reopened
                .is_initialized
                .store(true, std::sync::atomic::Ordering::Relaxed);
            let retry = mcp_call(router(Arc::clone(&reopened)), "kin_transaction_stage", serde_json::json!({"transaction_id":tx,"operations":[mcp_lifecycle_operation("retried")]})).await;
            assert_ne!(retry.is_error, Some(true), "{}", mcp_result_text(&retry));
            let second_open = DaemonState::open(reopened.layout.clone()).unwrap();
            assert_eq!(
                second_open.mcp_transactions.lock().unwrap()[&tx]
                    .staged_operations
                    .len(),
                2
            );
            assert_eq!(std::fs::read(&collision).unwrap(), original);
            if symlink {
                assert_eq!(std::fs::read(&target).unwrap(), original);
            }
        }
    }
}
