// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

fn keyed_mutation(session_id: &str, request_id: &str, name: &str) -> serde_json::Value {
    serde_json::json!({
        "session_id": session_id,
        "request_id": request_id,
        "summary": "create a durable source fixture",
        "operations": [{
            "verb": "create", "target": format!("{name}.py"),
            "body": format!("def {name}():\n    return 1\n"),
            "description": "create source"
        }]
    })
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_keyed_retry_recovers_original_receipt_through_real_delegate() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session_id = mcp_test_session(&state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router_with_auth(Arc::clone(&state), Some("mutate-test-token".to_string()));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut env = kin_core::test_env::EnvVarGuard::set("KIN_DAEMON_URL", format!("http://{addr}"));
    env.apply("KIN_DAEMON_AUTH_TOKEN", Some("mutate-test-token"));
    let args: HashMap<String, serde_json::Value> =
        serde_json::from_value(keyed_mutation(&session_id, "receipt-é", "first")).unwrap();
    let first = kin_mcp::handlers::sessions::mutate_through_daemon(&args)
        .await
        .unwrap();
    let retried = kin_mcp::handlers::sessions::mutate_through_daemon(&args)
        .await
        .unwrap();
    server.abort();
    let _ = server.await;
    assert_ne!(first.is_error, Some(true), "{}", mcp_result_text(&first));
    assert_ne!(
        retried.is_error,
        Some(true),
        "identical keyed retry lost its original receipt: {}",
        mcp_result_text(&retried)
    );
    let original = tool_result_payload(&first);
    let replayed = tool_result_payload(&retried);
    assert_eq!(replayed["transaction_id"], original["transaction_id"]);
    assert_eq!(replayed["change_id"], original["change_id"]);
    assert_eq!(
        replayed["repository_generation"],
        original["repository_generation"]
    );
    assert_eq!(replayed["already_applied"], true);
}

async fn mutate_http(
    state: &Arc<DaemonState>,
    name: &str,
    arguments: serde_json::Value,
    session: &str,
) -> kin_mcp::ToolCallResult {
    let response = router_with_auth(Arc::clone(state), Some("mutate-test-token".to_string()))
        .oneshot(
            Request::post("/mcp/tools/call")
                .header("content-type", "application/json")
                .header("Authorization", "Bearer mutate-test-token")
                .header("X-Kin-Session", session)
                .body(Body::from(
                    serde_json::json!({ "name": name, "arguments": arguments }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn mutation_generation(state: &DaemonState) -> u64 {
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)
            .unwrap();
    let authority = context.open().unwrap();
    let generation = authority.read_authority().roots().generation;
    generation
}

fn mutation_record(
    state: &DaemonState,
    id: &str,
) -> Option<(std::path::PathBuf, serde_json::Value)> {
    std::fs::read_dir(state.layout.root().join("mutate_requests"))
        .ok()?
        .find_map(|entry| {
            let path = entry.ok()?.path();
            if path.extension()?.to_str()? != "json" {
                return None;
            }
            let record: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
            (record["identity"]["request_id"] == id).then_some((path, record))
        })
}

fn mutation_receipt(result: &kin_mcp::ToolCallResult) -> serde_json::Value {
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(result));
    let mut receipt = tool_result_payload(result);
    assert_eq!(receipt["schema"], "kin.mutate.receipt.v1");
    assert!(receipt.get("new_root_hash").is_none());
    receipt.as_object_mut().unwrap().remove("already_applied");
    receipt
}

fn mutation_published_body(state: &DaemonState, file: &str) -> String {
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)
            .unwrap();
    let base = crate::repository_commit::load_native_commit_base(&context).unwrap();
    let path = kin_model::RepoPath::from_utf8(file.to_string()).unwrap();
    let kin_model::TreeEntry::Blob { hash, .. } = base.tree.artifact_at_path(&path).unwrap().entry
    else {
        panic!("source must be a repository blob");
    };
    let authority = context.open().unwrap();
    let body = crate::source_cas::read_publishable_source(&state.blobs, &authority, hash).unwrap();
    String::from_utf8(body.body().to_vec()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn mcp_mutate_transport_drop_concurrent_retry_and_intervening_commit_recover_original() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&session, "dropped-response", "first");
    let before = mutation_generation(&state);
    let (release, hold) = std::sync::mpsc::channel();
    *state.mcp_mutate_publication_hold.lock().unwrap() = Some(hold);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router_with_auth(Arc::clone(&state), Some("mutate-test-token".to_string()));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let request = client
        .post(format!("http://{addr}/mcp/tools/call"))
        .bearer_auth("mutate-test-token")
        .header("X-Kin-Session", &session)
        .json(&serde_json::json!({"name": "kin_mutate", "arguments": args}));
    let first = tokio::spawn(async move {
        request
            .send()
            .await
            .unwrap()
            .json::<kin_mcp::ToolCallResult>()
            .await
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while !state
            .mcp_mutate_publication_reached
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(mutation_generation(&state), before + 1);
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let retry = tokio::spawn({
        let state = Arc::clone(&state);
        let session = session.clone();
        let args = args.clone();
        async move { mutate_http(&state, "kin_mutate", args, &session).await }
    });
    let mut changed = args.clone();
    changed["summary"] = serde_json::json!("different request while original runs");
    let mismatch = tokio::spawn({
        let state = Arc::clone(&state);
        let session = session.clone();
        async move { mutate_http(&state, "kin_mutate", changed, &session).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while state
            .inflight_mcp_commits
            .joined
            .load(std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    release.send(()).unwrap();
    let original = mutation_receipt(&retry.await.unwrap());
    let mismatch = mismatch.await.unwrap();
    assert_eq!(mismatch.is_error, Some(true));
    assert!(mcp_result_text(&mismatch).contains("request_id_payload_mismatch"));
    server.abort();
    let _ = server.await;
    assert_eq!(mutation_generation(&state), before + 1);
    assert_eq!(
        state
            .mcp_commit_attempts
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert!(state.mcp_transactions.lock().unwrap().is_empty());
    let mut intervening = keyed_mutation(&session, "intervening", "first");
    intervening["operations"][0]["verb"] = serde_json::json!("replace");
    intervening["operations"][0]["body"] = serde_json::json!("def first():\n    return 2\n");
    mutation_receipt(&mutate_http(&state, "kin_mutate", intervening, &session).await);
    let latest = mutation_generation(&state);
    assert_eq!(latest, before + 2);
    assert_eq!(
        mutation_receipt(&mutate_http(&state, "kin_mutate", args.clone(), &session).await),
        original
    );
    assert_eq!(mutation_generation(&state), latest);
    assert_eq!(
        mutation_published_body(&state, "first.py"),
        "def first():\n    return 2\n"
    );
    assert_eq!(
        std::fs::read_to_string(state.layout.working_dir().join("first.py")).unwrap(),
        "def first():\n    return 2\n"
    );
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        mutation_receipt(&mutate_http(&reopened, "kin_mutate", args, &session).await),
        original
    );
    assert_eq!(mutation_generation(&reopened), latest);
    assert_eq!(
        mutation_published_body(&reopened, "first.py"),
        "def first():\n    return 2\n"
    );
    assert_eq!(
        reopened
            .mcp_commit_attempts
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_full_payload_binding_and_lower_level_bypass_refusal() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session = mcp_test_session(&state);
    let mut args = keyed_mutation(&session, "bound-fields", "first");
    args["operations"]
        .as_array_mut()
        .unwrap()
        .push(keyed_mutation(&session, "unused", "second")["operations"][0].clone());
    let receipt =
        mutation_receipt(&mutate_http(&state, "kin_mutate", args.clone(), &session).await);
    let generation = mutation_generation(&state);
    let mut variants = Vec::new();
    for (field, value) in [
        ("body", serde_json::json!("different bytes")),
        ("target", serde_json::json!("elsewhere.py")),
        ("destination", serde_json::json!("moved.py")),
        ("payload", serde_json::json!({"metadata": "changed"})),
        ("description", serde_json::json!("changed")),
    ] {
        let mut changed = args.clone();
        changed["operations"][0][field] = value;
        variants.push(changed);
    }
    for (field, value) in [
        ("summary", serde_json::json!("different summary")),
        ("scope", serde_json::json!("different workspace")),
        ("workspace_id", serde_json::json!("different-workspace")),
        ("extra", serde_json::json!({"future": true})),
        ("token_budget", serde_json::json!(100)),
    ] {
        let mut changed = args.clone();
        changed[field] = value;
        variants.push(changed);
    }
    let mut reordered = args.clone();
    reordered["operations"].as_array_mut().unwrap().reverse();
    variants.push(reordered);
    for changed in variants {
        let refused = mutate_http(&state, "kin_mutate", changed, &session).await;
        assert_eq!(refused.is_error, Some(true));
        assert!(
            mcp_result_text(&refused).contains("request_id_payload_mismatch"),
            "{}",
            mcp_result_text(&refused)
        );
        assert_eq!(mutation_generation(&state), generation);
    }
    let mut defaulted = args.clone();
    defaulted["scope"] = serde_json::json!("repository");
    defaulted["session_id"] = serde_json::json!(session.to_uppercase());
    assert_eq!(
        mutation_receipt(&mutate_http(&state, "kin_mutate", defaulted, &session).await),
        receipt
    );
    for tool in [
        "kin_transaction_stage",
        "kin_transaction_validate",
        "kin_transaction_commit",
        "kin_transaction_abort",
    ] {
        let refused = mutate_http(&state, tool, serde_json::json!({"transaction_id": receipt["transaction_id"], "operations": args["operations"], "message": "bypass summary"}), &session).await;
        assert_eq!(refused.is_error, Some(true));
        assert!(mcp_result_text(&refused).contains("request_bound_transaction"));
    }
    let uppercase = receipt["transaction_id"].as_str().unwrap().to_uppercase();
    let refused = mutate_http(
        &state,
        "kin_transaction_commit",
        serde_json::json!({"transaction_id": uppercase}),
        &session,
    )
    .await;
    assert_eq!(refused.is_error, Some(true));
    assert!(mcp_result_text(&refused).contains("request_bound_transaction"));
    assert_eq!(mutation_generation(&state), generation);
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_ownership_expiry_and_key_validation_fail_closed() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session = mcp_test_session(&state);
    let other = mcp_test_session(&state);
    let args = keyed_mutation(&session, "owner", "first");
    let receipt =
        mutation_receipt(&mutate_http(&state, "kin_mutate", args.clone(), &session).await);
    let wrong = mutate_http(&state, "kin_mutate", args.clone(), &other).await;
    assert_eq!(wrong.is_error, Some(true));
    assert!(mcp_result_text(&wrong).contains("request_owner_mismatch"));
    let response = router_with_auth(Arc::clone(&state), Some("mutate-test-token".to_string()))
        .oneshot(
            Request::post("/mcp/tools/call")
                .header("content-type", "application/json")
                .header("X-Kin-Session", &session)
                .body(Body::from(
                    serde_json::json!({"name": "kin_mutate", "arguments": args}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let disabled = mcp_call_as(
        router(Arc::clone(&state)),
        "kin_mutate",
        args.clone(),
        SessionId(Uuid::parse_str(&session).unwrap()),
    )
    .await;
    assert_eq!(disabled.is_error, Some(true));
    assert!(mcp_result_text(&disabled).contains("durable_request_auth_required"));
    let generation = mutation_generation(&state);
    for id in [
        serde_json::Value::Null,
        serde_json::json!(123),
        serde_json::json!("   "),
        serde_json::json!("x".repeat(257)),
        serde_json::json!("é".repeat(129)),
    ] {
        let mut invalid = args.clone();
        invalid["request_id"] = id;
        let refused = mutate_http(&state, "kin_mutate", invalid, &session).await;
        assert_eq!(refused.is_error, Some(true));
        assert!(mcp_result_text(&refused).contains("invalid_request_id"));
    }
    state
        .coordinator
        .deregister_session(&SessionId(Uuid::parse_str(&session).unwrap()))
        .unwrap();
    assert_eq!(
        mutation_receipt(&mutate_http(&state, "kin_mutate", args.clone(), &session).await),
        receipt
    );
    let mut unpublished = args;
    unpublished["request_id"] = serde_json::json!("expired-new");
    let refused = mutate_http(&state, "kin_mutate", unpublished, &session).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(mcp_result_text(&refused).contains("request_session_expired"));
    assert_eq!(mutation_generation(&state), generation);
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_persistence_faults_reuse_reservation_across_restart() {
    for phase in [1_u8, 2, 3, 4, 5, 6, 8, 7, 11, 12, 13, 14] {
        let (_dir, state) = mcp_lifecycle_fixture();
        let session = mcp_test_session(&state);
        let args = keyed_mutation(&session, "persist-fault", "first");
        let before = mutation_generation(&state);
        state
            .mcp_mutate_fail_once
            .store(phase, std::sync::atomic::Ordering::SeqCst);
        let failed = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
        assert_eq!(
            failed.is_error,
            Some(true),
            "phase {phase}: {}",
            mcp_result_text(&failed)
        );
        let published = matches!(phase, 7 | 11 | 12 | 13 | 14);
        assert_eq!(
            mutation_generation(&state),
            before + u64::from(published),
            "phase {phase}"
        );
        let reserved_id = mutation_record(&state, "persist-fault")
            .map(|(_, record)| record["transaction_id"].clone());
        let layout = state.layout.clone();
        drop(state);
        let reopened = Arc::new(DaemonState::open(layout).unwrap());
        reopened
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if !published {
            let unregistered = mutate_http(&reopened, "kin_mutate", args.clone(), &session).await;
            assert_eq!(unregistered.is_error, Some(true), "phase {phase}");
            assert!(mcp_result_text(&unregistered).contains("request_session_expired"));
            // A restart may drop runtime registration. Restore the original
            // caller-owned UUID through the authenticated public registration
            // boundary, without manufacturing a new request or transaction.
            let response = router_with_auth(Arc::clone(&reopened), Some("mutate-test-token".to_string()))
                .oneshot(Request::post("/session")
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer mutate-test-token")
                    .body(Body::from(serde_json::json!({
                        "session_id": session, "vendor": "codex", "client_name": "resumed-owner",
                        "transport": "mcp", "cwd": reopened.layout.working_dir()
                    }).to_string())).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "phase {phase}");
        }
        let retry = mutate_http(&reopened, "kin_mutate", args, &session).await;
        assert_ne!(
            retry.is_error,
            Some(true),
            "phase {phase}: {}",
            mcp_result_text(&retry)
        );
        let receipt = mutation_receipt(&retry);
        if let Some(id) = reserved_id {
            assert_eq!(receipt["transaction_id"], id, "phase {phase}");
        }
        assert_eq!(mutation_generation(&reopened), before + 1, "phase {phase}");
        assert_eq!(
            mutation_published_body(&reopened, "first.py"),
            "def first():\n    return 1\n"
        );
        assert_eq!(
            std::fs::read_dir(reopened.layout.root().join("mutate_requests"))
                .unwrap()
                .count(),
            1
        );
    }
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_corruption_retains_binding_and_staging_evidence() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&session, "corrupt", "first");
    let receipt =
        mutation_receipt(&mutate_http(&state, "kin_mutate", args.clone(), &session).await);
    let mirror = crate::state::mcp_transactions_disk_path(&state.layout);
    let corrupt = b"{retained staging evidence";
    std::fs::write(&mirror, corrupt).unwrap();
    assert_eq!(
        mutation_receipt(&mutate_http(&state, "kin_mutate", args.clone(), &session).await),
        receipt
    );
    assert_eq!(std::fs::read(&mirror).unwrap(), corrupt);
    let (record, original) = mutation_record(&state, "corrupt").unwrap();
    std::fs::write(&record, b"{retained request evidence").unwrap();
    let refused = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(mcp_result_text(&refused).contains("request_recovery_required"));
    assert_eq!(
        std::fs::read(&record).unwrap(),
        b"{retained request evidence"
    );
    std::fs::write(&record, serde_json::to_vec(&original).unwrap()).unwrap();
    let journal = state.layout.root().join("mcp_transactions.lifecycle.json");
    std::fs::write(&journal, b"{}").unwrap();
    let refused = mutate_http(&state, "kin_mutate", args, &session).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(mcp_result_text(&refused).contains("transaction_recovery_required"));
    assert_eq!(std::fs::read(&journal).unwrap(), b"{}");
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_admission_config_and_saturation_preserve_old_keys() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session = mcp_test_session(&state);
    let mut env = kin_core::test_env::EnvVarGuard::set("KIN_MUTATE_MAX_REQUESTS", "1");
    let first = keyed_mutation(&session, "quota-first", "first");
    let receipt =
        mutation_receipt(&mutate_http(&state, "kin_mutate", first.clone(), &session).await);
    let second = keyed_mutation(&session, "quota-second", "second");
    let refused = mutate_http(&state, "kin_mutate", second.clone(), &session).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(mcp_result_text(&refused).contains("request_admission_quota_exceeded"));
    assert!(mutation_record(&state, "quota-second").is_none());
    for bad in ["0", "-1", "1000001", "not-a-number"] {
        env.apply("KIN_MUTATE_MAX_REQUESTS", Some(bad));
        let refused = mutate_http(&state, "kin_mutate", second.clone(), &session).await;
        assert_eq!(refused.is_error, Some(true));
        assert!(mcp_result_text(&refused).contains("request_admission_config_invalid"));
        assert_eq!(
            mutation_receipt(&mutate_http(&state, "kin_mutate", first.clone(), &session).await),
            receipt
        );
    }
    env.apply("KIN_MUTATE_MAX_REQUESTS", Some("2"));
    env.apply("KIN_MUTATE_MAX_STORAGE_BYTES", Some("1"));
    let refused = mutate_http(&state, "kin_mutate", second.clone(), &session).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(mcp_result_text(&refused).contains("request_admission_quota_exceeded"));
    env.apply("KIN_MUTATE_MAX_STORAGE_BYTES", Some("4194304"));
    mutation_receipt(&mutate_http(&state, "kin_mutate", second, &session).await);
    assert_eq!(
        mutation_receipt(&mutate_http(&state, "kin_mutate", first, &session).await),
        receipt
    );
    assert_eq!(
        std::fs::read_dir(state.layout.root().join("mutate_requests"))
            .unwrap()
            .count(),
        2
    );
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_bound_route_preserves_prior_staging_after_compound_recovery() {
    let (_dir, state, tx_id) = mcp_after_compound_cold_recovery_failure().await;
    let session = mcp_test_session(&state);
    mutation_receipt(
        &mutate_http(
            &state,
            "kin_mutate",
            keyed_mutation(&session, "after-recovery", "first"),
            &session,
        )
        .await,
    );
    let disk = crate::state::load_persisted_mcp_transactions_checked(&state.layout).unwrap();
    assert_eq!(
        disk[&tx_id].staged_operations[0].body.as_deref(),
        Some(MCP_RECOVERY_ACKNOWLEDGED_BODY)
    );
    let layout = state.layout.clone();
    drop(state);
    let reopened = DaemonState::open(layout).unwrap();
    assert_eq!(
        reopened.mcp_transactions.lock().unwrap()[&tx_id].staged_operations[0]
            .body
            .as_deref(),
        Some(MCP_RECOVERY_ACKNOWLEDGED_BODY)
    );
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_pending_expired_session_refuses_without_losing_reservation() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&session, "pending-expiry", "first");
    state
        .mcp_mutate_fail_once
        .store(5, std::sync::atomic::Ordering::SeqCst);
    let failed = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
    assert_eq!(failed.is_error, Some(true));
    let (record_path, reserved) = mutation_record(&state, "pending-expiry").unwrap();
    let before = mutation_generation(&state);
    let old: Timestamp = serde_json::from_str("\"2020-01-01T00:00:00Z\"").unwrap();
    state
        .graph
        .update_heartbeat(&SessionId(Uuid::parse_str(&session).unwrap()), &old)
        .unwrap();
    let refused = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(mcp_result_text(&refused).contains("request_session_expired"));
    assert_eq!(
        state
            .coordinator
            .get_session(&SessionId(Uuid::parse_str(&session).unwrap()))
            .unwrap()
            .unwrap()
            .last_heartbeat,
        old
    );
    assert_eq!(mutation_generation(&state), before);
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let refused = mutate_http(&reopened, "kin_mutate", args, &session).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(mcp_result_text(&refused).contains("request_session_expired"));
    let retained: serde_json::Value =
        serde_json::from_slice(&std::fs::read(record_path).unwrap()).unwrap();
    assert_eq!(retained["transaction_id"], reserved["transaction_id"]);
    assert_eq!(mutation_generation(&reopened), before);
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_session_repository_scopes_and_token_rotation_are_stable() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let first_session = mcp_test_session(&state);
    let second_session = mcp_test_session(&state);
    let first_args = keyed_mutation(&first_session, "shared-key", "first");
    let first = mutation_receipt(
        &mutate_http(&state, "kin_mutate", first_args.clone(), &first_session).await,
    );
    let second = mutation_receipt(
        &mutate_http(
            &state,
            "kin_mutate",
            keyed_mutation(&second_session, "shared-key", "second"),
            &second_session,
        )
        .await,
    );
    assert_ne!(first["transaction_id"], second["transaction_id"]);
    let (_other_dir, other) = mcp_lifecycle_fixture();
    other
        .coordinator
        .register_session_with_id(
            SessionId(Uuid::parse_str(&first_session).unwrap()),
            "codex",
            "other-repository",
            SessionTransport::Mcp,
            None,
            other.layout.working_dir().to_path_buf(),
            SessionCapabilities {
                can_write: true,
                can_commit: true,
                ..Default::default()
            },
        )
        .unwrap();
    let other_receipt = mutation_receipt(
        &mutate_http(&other, "kin_mutate", first_args.clone(), &first_session).await,
    );
    assert_ne!(first["repository_id"], other_receipt["repository_id"]);
    assert_ne!(first["transaction_id"], other_receipt["transaction_id"]);
    let rotated = router_with_auth(Arc::clone(&state), Some("rotated-token".to_string()))
        .oneshot(
            Request::post("/mcp/tools/call")
                .header("content-type", "application/json")
                .header("Authorization", "Bearer rotated-token")
                .header("X-Kin-Session", &first_session)
                .body(Body::from(
                    serde_json::json!({"name": "kin_mutate", "arguments": first_args}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotated.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(rotated.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    let rotated: kin_mcp::ToolCallResult = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(mutation_receipt(&rotated), first);
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_closed_schema_refuses_ignored_constraints_before_reservation() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session = mcp_test_session(&state);
    let base = keyed_mutation(&session, "closed", "first");
    let before = mutation_generation(&state);
    let mut unsupported = Vec::new();
    for field in [
        "expected_base",
        "expected_source_base",
        "workspace_id",
        "token_budget",
        "future",
    ] {
        let mut args = base.clone();
        args[field] = serde_json::json!({"generation": 0});
        unsupported.push(args);
    }
    let mut unsupported_scope = base.clone();
    unsupported_scope["scope"] = serde_json::json!("workspace:another-workspace");
    unsupported.push(unsupported_scope);
    let mut op_constraint = base.clone();
    op_constraint["operations"][0]["expected_base"] = serde_json::json!(0);
    unsupported.push(op_constraint);
    let mut nested = base.clone();
    nested["operations"] = serde_json::json!([mcp_lifecycle_operation("nested")]);
    nested["operations"][0]["payload"]["Entity"]["expected_base"] = serde_json::json!(0);
    unsupported.push(nested);
    let mut summary = base.clone();
    summary["summary"] = serde_json::json!({"condition": "must not be ignored"});
    unsupported.push(summary);
    for args in unsupported {
        let refused = mutate_http(&state, "kin_mutate", args, &session).await;
        assert_eq!(
            refused.is_error,
            Some(true),
            "{}",
            mcp_result_text(&refused)
        );
        assert_eq!(mutation_generation(&state), before);
        assert!(mutation_record(&state, "closed").is_none());
        assert!(state.mcp_transactions.lock().unwrap().is_empty());
    }
    // Invalid input did not burn the key. A supported corrected envelope
    // can still reserve it and publish exactly once.
    mutation_receipt(&mutate_http(&state, "kin_mutate", base, &session).await);
    assert_eq!(mutation_generation(&state), before + 1);
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_pending_restart_resumes_original_owner_through_real_mcp_delegate() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&session, "client-resume", "first");
    state
        .mcp_mutate_fail_once
        .store(8, std::sync::atomic::Ordering::SeqCst);
    let failed = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
    assert_eq!(failed.is_error, Some(true));
    let reserved = mutation_record(&state, "client-resume").unwrap().1["transaction_id"].clone();
    let before = mutation_generation(&state);
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router_with_auth(Arc::clone(&reopened), Some("mutate-test-token".to_string()));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut env = kin_core::test_env::EnvVarGuard::set("KIN_DAEMON_URL", format!("http://{addr}"));
    env.apply("KIN_DAEMON_AUTH_TOKEN", Some("mutate-test-token"));
    let args: HashMap<String, serde_json::Value> = serde_json::from_value(args).unwrap();
    let expired = kin_mcp::handlers::sessions::mutate_through_daemon(&args)
        .await
        .unwrap();
    let registration = HashMap::from([
        ("session_id".to_string(), serde_json::json!(session)),
        ("vendor".to_string(), serde_json::json!("codex")),
        (
            "client_name".to_string(),
            serde_json::json!("resumed-client"),
        ),
        (
            "cwd".to_string(),
            serde_json::json!(reopened.layout.working_dir()),
        ),
    ]);
    let registered =
        kin_mcp::daemon_delegate::forward_tool_call("kin_session_start", &registration)
            .await
            .unwrap()
            .unwrap();
    let retry = kin_mcp::handlers::sessions::mutate_through_daemon(&args)
        .await
        .unwrap();
    server.abort();
    let _ = server.await;
    assert_eq!(expired.is_error, Some(true));
    assert!(mcp_result_text(&expired).contains("request_session_expired"));
    assert_ne!(
        registered.is_error,
        Some(true),
        "{}",
        mcp_result_text(&registered)
    );
    assert_eq!(tool_result_payload(&registered)["session_id"], session);
    let receipt = mutation_receipt(&retry);
    assert_eq!(receipt["transaction_id"], reserved);
    assert_eq!(mutation_generation(&reopened), before + 1);
    assert_eq!(
        mutation_published_body(&reopened, "first.py"),
        "def first():\n    return 1\n"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_published_finalization_failure_reports_receipt_and_refuses_stale_writes() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&session, "finalization", "first");
    let before = mutation_generation(&state);
    state
        .mcp_fail_after_authority_once
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let incomplete = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
    assert_eq!(incomplete.is_error, Some(true));
    let notice = tool_result_payload(&incomplete);
    assert_eq!(notice["schema"], "kin.mutate.recovery.v1");
    assert_eq!(
        notice["code"],
        "publication_completed_daemon_recovery_required"
    );
    assert_eq!(notice["published"], true);
    assert_eq!(mutation_generation(&state), before + 1);
    assert_eq!(
        state
            .snapshot_generation
            .load(std::sync::atomic::Ordering::SeqCst),
        before
    );
    let original = notice["receipt"].clone();
    assert_eq!(
        mutation_receipt(&mutate_http(&state, "kin_mutate", args.clone(), &session).await),
        original
    );
    // Receipt retrieval must not pretend it completed derived graph recovery.
    assert_eq!(
        state
            .snapshot_generation
            .load(std::sync::atomic::Ordering::SeqCst),
        before
    );
    let fresh = mutate_http(
        &state,
        "kin_mutate",
        keyed_mutation(&session, "fresh-stale", "second"),
        &session,
    )
    .await;
    assert_eq!(fresh.is_error, Some(true), "{}", mcp_result_text(&fresh));
    assert!(
        mcp_result_text(&fresh).contains("reopen"),
        "{}",
        mcp_result_text(&fresh)
    );
    assert_eq!(mutation_generation(&state), before + 1);
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        reopened
            .snapshot_generation
            .load(std::sync::atomic::Ordering::SeqCst),
        before + 1
    );
    assert_eq!(
        mutation_receipt(&mutate_http(&reopened, "kin_mutate", args, &session).await),
        original
    );
    assert_eq!(mutation_generation(&reopened), before + 1);
    assert_eq!(
        mutation_published_body(&reopened, "first.py"),
        "def first():\n    return 1\n"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_completed_proof_is_bounded_and_tampering_refuses_without_erasing_it() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session = mcp_test_session(&state);
    let mut args = keyed_mutation(&session, "proof", "first");
    args["operations"]
        .as_array_mut()
        .unwrap()
        .push(keyed_mutation(&session, "unused", "second")["operations"][0].clone());
    let original =
        mutation_receipt(&mutate_http(&state, "kin_mutate", args.clone(), &session).await);
    let generation = mutation_generation(&state);
    let (path, mut record) = mutation_record(&state, "proof").unwrap();
    assert_eq!(record["receipt"]["schema"], "kin.mutate.publication.v1");
    assert!(record["request"].is_null());
    assert!(record["receipt"].get("modified_files").is_none());
    assert_eq!(original["modified_files"].as_array().unwrap().len(), 2);
    let intact = std::fs::read(&path).unwrap();
    record["receipt"]["generation"] = serde_json::json!(generation + 1);
    let corrupt = serde_json::to_vec(&record).unwrap();
    std::fs::write(&path, &corrupt).unwrap();
    let refused = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(mcp_result_text(&refused).contains("integrity digest mismatch"));
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    assert_eq!(mutation_generation(&state), generation);
    // Even a freshly checksummed record cannot replace the authoritative
    // publication proof. The checksum is corruption detection, not authority.
    let mut digest_input = record.clone();
    digest_input.as_object_mut().unwrap().remove("record_digest");
    use sha2::Digest;
    let mut checksum = sha2::Sha256::new();
    checksum.update(b"kin-mutate-binding-v2\0");
    crate::mcp_commit::hash_canonical_json(&mut checksum, &digest_input);
    record["record_digest"] = serde_json::json!(hex::encode(checksum.finalize()));
    let forged = serde_json::to_vec(&record).unwrap();
    std::fs::write(&path, &forged).unwrap();
    let refused = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(mcp_result_text(&refused).contains("disagrees with repository authority"));
    assert_eq!(std::fs::read(&path).unwrap(), forged);
    assert_eq!(mutation_generation(&state), generation);
    std::fs::write(&path, intact).unwrap();
    assert_eq!(
        mutation_receipt(&mutate_http(&state, "kin_mutate", args, &session).await),
        original
    );
    assert_eq!(mutation_generation(&state), generation);
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_record_integrity_pending_transaction_corruption_cannot_republish() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session = mcp_test_session(&state);
    mutation_receipt(
        &mutate_http(
            &state,
            "kin_mutate",
            keyed_mutation(&session, "seed", "first"),
            &session,
        )
        .await,
    );
    let mut args = keyed_mutation(&session, "uncached-publication", "first");
    args["operations"][0]["verb"] = serde_json::json!("replace");
    args["operations"][0]["body"] = serde_json::json!("def first():\n    return 2\n");
    state
        .mcp_mutate_fail_once
        .store(11, std::sync::atomic::Ordering::SeqCst);
    let uncertain = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
    assert_eq!(uncertain.is_error, Some(true));
    let original_generation = mutation_generation(&state);
    assert_eq!(
        mutation_published_body(&state, "first.py"),
        "def first():\n    return 2\n"
    );
    let (path, mut record) = mutation_record(&state, "uncached-publication").unwrap();
    assert!(record["request"].is_object());
    assert!(record["receipt"].is_null());
    let intact = std::fs::read(&path).unwrap();
    let original_transaction = record["transaction_id"].clone();
    let mut intervening = args.clone();
    intervening["request_id"] = serde_json::json!("intervening-after-uncached-publication");
    intervening["operations"][0]["body"] = serde_json::json!("def first():\n    return 3\n");
    mutation_receipt(&mutate_http(&state, "kin_mutate", intervening, &session).await);
    let latest = mutation_generation(&state);
    assert_eq!(latest, original_generation + 1);
    let mut alternate = original_transaction.as_str().unwrap().to_owned();
    alternate.replace_range(..1, if alternate.starts_with('a') { "b" } else { "a" });
    assert!(Uuid::parse_str(&alternate).is_ok());
    record["transaction_id"] = serde_json::json!(alternate);
    let corrupt = serde_json::to_vec(&record).unwrap();
    std::fs::write(&path, &corrupt).unwrap();
    let refused = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
    assert_eq!(refused.is_error, Some(true),
        "altered transaction identity reapplied old bytes: generation {} -> {}; current body {:?}; response {}",
        latest, mutation_generation(&state), mutation_published_body(&state, "first.py"), mcp_result_text(&refused));
    assert!(mcp_result_text(&refused).contains("request_recovery_required"));
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    assert_eq!(mutation_generation(&state), latest);
    assert_eq!(
        mutation_published_body(&state, "first.py"),
        "def first():\n    return 3\n"
    );
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let refused = mutate_http(&reopened, "kin_mutate", args.clone(), &session).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(mcp_result_text(&refused).contains("request_recovery_required"));
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    assert_eq!(mutation_generation(&reopened), latest);
    std::fs::write(&path, intact).unwrap();
    let original = mutation_receipt(&mutate_http(&reopened, "kin_mutate", args, &session).await);
    assert_eq!(original["transaction_id"], original_transaction);
    assert_eq!(original["repository_generation"], original_generation);
    assert_eq!(mutation_generation(&reopened), latest);
    assert_eq!(
        mutation_published_body(&reopened, "first.py"),
        "def first():\n    return 3\n"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_record_integrity_completed_count_corruption_cannot_change_receipt() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&session, "completed-count", "first");
    let original =
        mutation_receipt(&mutate_http(&state, "kin_mutate", args.clone(), &session).await);
    let generation = mutation_generation(&state);
    let (path, mut record) = mutation_record(&state, "completed-count").unwrap();
    assert!(record["request"].is_null());
    let intact = std::fs::read(&path).unwrap();
    record["operations_count"] = serde_json::json!(2);
    let corrupt = serde_json::to_vec(&record).unwrap();
    std::fs::write(&path, &corrupt).unwrap();
    let refused = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
    assert_eq!(
        refused.is_error,
        Some(true),
        "altered operation count changed a retained receipt: {}",
        mcp_result_text(&refused)
    );
    assert!(mcp_result_text(&refused).contains("request_recovery_required"));
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    assert_eq!(mutation_generation(&state), generation);
    std::fs::write(&path, intact).unwrap();
    assert_eq!(
        mutation_receipt(&mutate_http(&state, "kin_mutate", args, &session).await),
        original
    );
    assert_eq!(mutation_generation(&state), generation);
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_preexisting_temp_links_preserve_owned_sentinel_and_recovery_evidence() {
    for hard_link in [false, true] {
        let (_dir, state) = mcp_lifecycle_fixture();
        let session = mcp_test_session(&state);
        let args = keyed_mutation(&session, "temp-link", "first");
        state
            .mcp_mutate_fail_once
            .store(5, std::sync::atomic::Ordering::SeqCst);
        let reserved = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
        assert_eq!(reserved.is_error, Some(true));
        let (record, _) = mutation_record(&state, "temp-link").unwrap();
        let old_tmp = record.with_extension("json.tmp");
        let sentinel = state.layout.root().join("owned-sentinel.txt");
        let original = b"unrelated owned bytes must survive request persistence";
        std::fs::write(&sentinel, original).unwrap();
        if hard_link {
            std::fs::hard_link(&sentinel, &old_tmp).unwrap();
        } else {
            std::os::unix::fs::symlink(&sentinel, &old_tmp).unwrap();
        }
        let retry = mutate_http(&state, "kin_mutate", args, &session).await;
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            original,
            "pre-existing temp link clobbered a different file (hard_link={hard_link})"
        );
        assert_eq!(
            std::fs::read(&old_tmp).unwrap(),
            original,
            "unowned recovery evidence was removed"
        );
        mutation_receipt(&retry);
        assert_eq!(
            mutation_published_body(&state, "first.py"),
            "def first():\n    return 1\n"
        );
    }
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_record_integrity_checksum_free_legacy_records_require_explicit_recovery() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&session, "legacy-record", "first");
    let original =
        mutation_receipt(&mutate_http(&state, "kin_mutate", args.clone(), &session).await);
    let generation = mutation_generation(&state);
    let (path, mut record) = mutation_record(&state, "legacy-record").unwrap();
    assert_eq!(record["schema"], "kin.mutate.request.v2");
    assert_eq!(record["record_digest"].as_str().unwrap().len(), 64);
    let intact = std::fs::read(&path).unwrap();
    record["schema"] = serde_json::json!("kin.mutate.request.v1");
    record.as_object_mut().unwrap().remove("record_digest");
    let legacy = serde_json::to_vec(&record).unwrap();
    std::fs::write(&path, &legacy).unwrap();
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let refused = mutate_http(&reopened, "kin_mutate", args.clone(), &session).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(mcp_result_text(&refused)
        .contains("checksum-free records cannot be safely upgraded automatically"));
    assert_eq!(std::fs::read(&path).unwrap(), legacy);
    assert_eq!(mutation_generation(&reopened), generation);
    std::fs::write(&path, intact).unwrap();
    assert_eq!(
        mutation_receipt(&mutate_http(&reopened, "kin_mutate", args, &session).await),
        original
    );
    assert_eq!(mutation_generation(&reopened), generation);
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_non_directory_or_symlink_request_store_refuses_before_publication() {
    for symlink in [false, true] {
        let (_dir, state) = mcp_lifecycle_fixture();
        let session = mcp_test_session(&state);
        let store = state.layout.root().join("mutate_requests");
        let outside = state.layout.root().join("owned-external-directory");
        if symlink {
            std::fs::create_dir(&outside).unwrap();
            std::os::unix::fs::symlink(&outside, &store).unwrap();
        } else {
            std::fs::write(&store, b"retain non-directory evidence").unwrap();
        }
        let before = mutation_generation(&state);
        let refused = mutate_http(
            &state,
            "kin_mutate",
            keyed_mutation(&session, "directory", "first"),
            &session,
        )
        .await;
        assert_eq!(
            refused.is_error,
            Some(true),
            "non-regular request directory was accepted: {}",
            mcp_result_text(&refused)
        );
        assert_eq!(mutation_generation(&state), before);
        if symlink {
            assert!(std::fs::symlink_metadata(&store)
                .unwrap()
                .file_type()
                .is_symlink());
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        } else {
            assert_eq!(
                std::fs::read(&store).unwrap(),
                b"retain non-directory evidence"
            );
        }
    }
}
