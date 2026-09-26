// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

/// Re-register a retained transaction's original identity through the served,
/// authenticated route. A registration is fresh capability resolution, not an
/// implicit resurrection caused by trying to publish an old transaction.
async fn reregister_transaction_owner(state: &Arc<DaemonState>, owner: &str) {
    let app = router_with_auth(Arc::clone(state), Some("owner-recovery-test".into()));
    let request = || {
        Request::post("/session")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer owner-recovery-test")
            .body(Body::from(serde_json::json!({
                "session_id": owner, "vendor": "codex", "client_name": "recovered-owner",
                "transport": "mcp", "cwd": state.layout.working_dir()
            }).to_string())).unwrap()
    };
    let response = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let registration: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(registration["session_id"], owner);
    assert_eq!(registration["capabilities"]["can_write"], true);
    assert_eq!(registration["capabilities"]["can_commit"], true);
    assert_eq!(app.oneshot(request()).await.unwrap().status(), StatusCode::CONFLICT);
}

fn retained_transaction_value(state: &DaemonState, tx: &str) -> serde_json::Value {
    serde_json::to_value(&state.mcp_transactions.lock().unwrap()[tx]).unwrap()
}

#[tokio::test]
async fn mcp_revoked_owner_restart_refuses_pending_work_then_explicit_registration_resumes() {
    use kin_mcp::CoordinationEnforcementMode::{Enforce, Off, Warn};
    for mode in [Off, Warn, Enforce] {
        for pending_state in ["active", "validated", "committing"] {
            let (dir, state, source) = source_base_fixture().await;
            let tx = source_base_stage(&state, source_base_operation(&source)).await;
            let owner = retained_transaction_value(&state, &tx)["session_id"].as_str().unwrap().to_string();
            let owner_id = SessionId(Uuid::parse_str(&owner).unwrap());
            if pending_state == "validated" {
                let result = mcp_call_as(router(Arc::clone(&state)), "kin_transaction_validate",
                    serde_json::json!({"transaction_id": tx}), owner_id).await;
                assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
            } else if pending_state == "committing" {
                crate::mcp_commit::tests::fence_unpublished_transaction_for_test(&state, &tx);
            }
            let before = retained_transaction_value(&state, &tx);
            let roots = source_base_roots(&state);
            let mirror = crate::state::mcp_transactions_disk_path(&state.layout);
            let persisted = std::fs::read(&mirror).unwrap();
            let layout = state.layout.clone();
            drop(state);
            let state = Arc::new(DaemonState::open(layout).unwrap());
            state.is_initialized.store(true, std::sync::atomic::Ordering::Relaxed);
            *state.coordination_mode.write().unwrap() = mode;
            assert!(state.coordinator.get_session(&owner_id).unwrap().is_none());
            for (tool, args) in [
                ("kin_transaction_stage", serde_json::json!({"transaction_id":tx,"operations":[source_base_operation(&source)]})),
                ("kin_transaction_validate", serde_json::json!({"transaction_id":tx})),
                ("kin_transaction_commit", serde_json::json!({"transaction_id":tx})),
            ] {
                let result = mcp_call_as(router(Arc::clone(&state)), tool, args, owner_id).await;
                assert_eq!(result.is_error, Some(true), "{mode:?}/{pending_state}/{tool}: {}",mcp_result_text(&result));
                assert_eq!(retained_transaction_value(&state, &tx), before);
                assert_eq!(std::fs::read(&mirror).unwrap(), persisted);
                assert_eq!(source_base_roots(&state), roots);
                assert_eq!(std::fs::read_to_string(dir.path().join("src/value.rs")).unwrap(), SOURCE_BASE_ORIGINAL);
                assert!(!dir.path().join("unexpected.py").exists());
            }
            reregister_transaction_owner(&state, &owner).await;
            assert_eq!(retained_transaction_value(&state, &tx), before);
            let commit = mcp_call_as(router(Arc::clone(&state)), "kin_transaction_commit",
                serde_json::json!({"transaction_id":tx}), owner_id).await;
            assert_ne!(commit.is_error, Some(true), "{mode:?}/{pending_state}: {}",mcp_result_text(&commit));
            let receipt = tool_result_payload(&commit);
            assert_eq!(receipt["already_applied"], false);
            assert_eq!(source_base_roots(&state).generation, roots.generation + 1);
            assert_eq!(std::fs::read_to_string(dir.path().join("src/value.rs")).unwrap(),
                SOURCE_BASE_ORIGINAL.replacen("{ 1 }", "{ 2 }", 1));
        }
    }
}

#[tokio::test]
async fn mcp_revoked_owner_enforced_published_fence_and_evicted_receipt_recover_without_republication() {
    for inline in [false, true] {
        let (dir, state, source) = source_base_fixture().await;
        let operation = source_base_operation(&source);
        let tx = source_base_stage(&state, operation.clone()).await;
        let owner = retained_transaction_value(&state, &tx)["session_id"].as_str().unwrap().to_string();
        let owner_id = SessionId(Uuid::parse_str(&owner).unwrap());
        *state.coordination_mode.write().unwrap() = kin_mcp::CoordinationEnforcementMode::Enforce;
        let mut args = serde_json::json!({"transaction_id":tx});
        if inline { args["operations"] = serde_json::json!([operation]); }
        // Already staged operations must not be appended a second time on the
        // initial active call. The identical inline payload is a retry control.
        state.mcp_fail_after_authority_once.store(true, std::sync::atomic::Ordering::SeqCst);
        let failed = mcp_call_as(router(Arc::clone(&state)), "kin_transaction_commit",
            serde_json::json!({"transaction_id":tx}), owner_id).await;
        assert_eq!(failed.is_error, Some(true), "{}",mcp_result_text(&failed));
        assert_eq!(retained_transaction_value(&state, &tx)["state"], "committing");
        let published_roots = source_base_roots(&state);
        let layout = state.layout.clone();
        drop(state);
        let state = Arc::new(DaemonState::open(layout).unwrap());
        state.is_initialized.store(true, std::sync::atomic::Ordering::Relaxed);
        *state.coordination_mode.write().unwrap() = kin_mcp::CoordinationEnforcementMode::Enforce;
        assert!(state.coordinator.get_session(&owner_id).unwrap().is_none());
        let recovered = mcp_call_as(router(Arc::clone(&state)), "kin_transaction_commit", args.clone(), owner_id).await;
        assert_ne!(recovered.is_error, Some(true), "{}",mcp_result_text(&recovered));
        let receipt = tool_result_payload(&recovered);
        assert_eq!(receipt["already_applied"], true);
        assert_eq!(receipt["repository_operation_id"], tx);
        assert_eq!(receipt["repository_generation"], published_roots.generation);
        assert_eq!(source_base_roots(&state), published_roots);
        let replay = mcp_call_as(router(Arc::clone(&state)), "kin_transaction_commit", args, owner_id).await;
        assert_ne!(replay.is_error, Some(true), "{}",mcp_result_text(&replay));
        let replayed = tool_result_payload(&replay);
        for key in ["change_id", "repository_generation", "repository_operation_id"] {
            assert_eq!(replayed[key], receipt[key]);
        }
        assert_eq!(replayed["already_applied"], true);
        assert_eq!(source_base_roots(&state), published_roots);
        assert_eq!(std::fs::read_to_string(dir.path().join("src/value.rs")).unwrap(),
            SOURCE_BASE_ORIGINAL.replacen("{ 1 }", "{ 2 }", 1));
    }
}

#[tokio::test]
async fn mcp_revoked_owner_live_wrong_caller_cannot_publish_or_reset_pending_fence() {
    for fenced in [false, true] {
        let (_dir, state, source) = source_base_fixture().await;
        let tx = source_base_stage(&state, source_base_operation(&source)).await;
        if fenced { crate::mcp_commit::tests::fence_unpublished_transaction_for_test(&state, &tx); }
        let wrong = SessionId(Uuid::parse_str(&mcp_test_session(&state)).unwrap());
        *state.coordination_mode.write().unwrap() = kin_mcp::CoordinationEnforcementMode::Enforce;
        let before = retained_transaction_value(&state, &tx);
        let roots = source_base_roots(&state);
        let refused = mcp_call_as(router(Arc::clone(&state)), "kin_transaction_commit",
            serde_json::json!({"transaction_id":tx}), wrong).await;
        assert_eq!(refused.is_error, Some(true));
        assert!(mcp_result_text(&refused).contains("does not own transaction"));
        assert_eq!(retained_transaction_value(&state, &tx), before);
        assert_eq!(source_base_roots(&state), roots);
    }
}
