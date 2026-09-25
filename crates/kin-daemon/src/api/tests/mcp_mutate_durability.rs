// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

async fn seed_keyed_entities(state: &Arc<DaemonState>) {
    for name in ["first", "second"] {
        let receipt = source_tree_conversion_fixture(state, serde_json::json!({
            "verb":"create", "target":format!("{name}.py"),
            "body":format!("def {name}():\n    return 0\n"), "description":"explicit conversion test fixture"
        })).await;
        forget_mcp_transaction(state, receipt["transaction_id"].as_str().unwrap());
    }
    state
        .mcp_commit_attempts
        .store(0, std::sync::atomic::Ordering::SeqCst);
}

async fn keyed_mutation_fixture() -> (tempfile::TempDir, Arc<DaemonState>) {
    let (dir, state) = mcp_lifecycle_fixture();
    seed_keyed_entities(&state).await;
    (dir, state)
}

/// A keyed request replacing the function `name` whole, guarded by the base of
/// the version current when the request is built. A base names one workspace
/// revision, so a request that must follow a commit is built after it, and a
/// replay resends the value first sent, base included, unchanged.
async fn keyed_mutation(
    state: &Arc<DaemonState>,
    session_id: &str,
    request_id: &str,
    name: &str,
) -> serde_json::Value {
    let source = source_base_read_named(state, name).await;
    serde_json::json!({
        "session_id": session_id,
        "request_id": request_id,
        "summary": "update a durable semantic fixture",
        "operations": [source_base_replacement(
            &source,
            &format!("def {name}():\n    return 1"),
            "update existing function",
        )]
    })
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_keyed_retry_recovers_original_receipt_through_real_delegate() {
    let (_dir, state) = keyed_mutation_fixture().await;
    let session_id = mcp_test_session(&state);
    let request = keyed_mutation(&state, &session_id, "receipt-é", "first").await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router_with_auth(Arc::clone(&state), Some("mutate-test-token".to_string()));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut env = kin_core::test_env::EnvVarGuard::set("KIN_DAEMON_URL", format!("http://{addr}"));
    env.apply("KIN_DAEMON_AUTH_TOKEN", Some("mutate-test-token"));
    let args: HashMap<String, serde_json::Value> = serde_json::from_value(request).unwrap();
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
    assert_eq!(original["publication_accounting"]["status"], "exact");
    assert_eq!(
        original["publication_accounting"]["requested"]["operation_count"],
        1
    );
    assert_eq!(
        replayed["publication_accounting"],
        original["publication_accounting"]
    );
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
    // Keep exact v1 receipt comparisons separate from response accounting.
    receipt
        .as_object_mut()
        .unwrap()
        .remove("publication_accounting");
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
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&state, &session, "dropped-response", "first").await;
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
    // Built after the original published, so it reads the version that
    // publication left. The original's replays below resend their first base.
    let mut intervening = keyed_mutation(&state, &session, "intervening", "first").await;
    intervening["operations"][0]["verb"] = serde_json::json!("update");
    intervening["operations"][0]["body"] = serde_json::json!("def first():\n    return 2");
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
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let mut args = keyed_mutation(&state, &session, "bound-fields", "first").await;
    let unused = keyed_mutation(&state, &session, "unused", "second").await;
    args["operations"]
        .as_array_mut()
        .unwrap()
        .push(unused["operations"][0].clone());
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
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let other = mcp_test_session(&state);
    let args = keyed_mutation(&state, &session, "owner", "first").await;
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
        let (_dir, state) = keyed_mutation_fixture().await;
        let session = mcp_test_session(&state);
        let args = keyed_mutation(&state, &session, "persist-fault", "first").await;
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
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&state, &session, "corrupt", "first").await;
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
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let mut env = kin_core::test_env::EnvVarGuard::set("KIN_MUTATE_MAX_REQUESTS", "1");
    let first = keyed_mutation(&state, &session, "quota-first", "first").await;
    let receipt =
        mutation_receipt(&mutate_http(&state, "kin_mutate", first.clone(), &session).await);
    let second = keyed_mutation(&state, &session, "quota-second", "second").await;
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
    seed_keyed_entities(&state).await;
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&state, &session, "after-recovery", "first").await;
    mutation_receipt(&mutate_http(&state, "kin_mutate", args, &session).await);
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
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&state, &session, "pending-expiry", "first").await;
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
    let (_dir, state) = keyed_mutation_fixture().await;
    let first_session = mcp_test_session(&state);
    let second_session = mcp_test_session(&state);
    let first_args = keyed_mutation(&state, &first_session, "shared-key", "first").await;
    let first = mutation_receipt(
        &mutate_http(&state, "kin_mutate", first_args.clone(), &first_session).await,
    );
    let second_args = keyed_mutation(&state, &second_session, "shared-key", "second").await;
    let second =
        mutation_receipt(&mutate_http(&state, "kin_mutate", second_args, &second_session).await);
    assert_ne!(first["transaction_id"], second["transaction_id"]);
    let (_other_dir, other) = keyed_mutation_fixture().await;
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
    // A source base names one repository, so the other repository's request
    // carries its own read. The session and request key are the same, and
    // they are what the scope is about.
    let other_args = keyed_mutation(&other, &first_session, "shared-key", "first").await;
    let other_receipt =
        mutation_receipt(&mutate_http(&other, "kin_mutate", other_args, &first_session).await);
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
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let base = keyed_mutation(&state, &session, "closed", "first").await;
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
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&state, &session, "client-resume", "first").await;
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
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&state, &session, "finalization", "first").await;
    // Read before the publication below, so no read has to be served while the
    // daemon lags authority. The daemon's freshness guard refuses this request
    // before its source base is ever compared.
    let fresh_args = keyed_mutation(&state, &session, "fresh-stale", "second").await;
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
    assert!(original.get("publication_accounting").is_none());
    let accounting = notice["publication_accounting"].clone();
    assert_eq!(accounting["status"], "exact");
    let replay = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
    assert_eq!(
        tool_result_payload(&replay)["publication_accounting"],
        accounting
    );
    assert_eq!(mutation_receipt(&replay), original);
    // Receipt retrieval must not pretend it completed derived graph recovery.
    assert_eq!(
        state
            .snapshot_generation
            .load(std::sync::atomic::Ordering::SeqCst),
        before
    );
    let fresh = mutate_http(&state, "kin_mutate", fresh_args, &session).await;
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
    let replay = mutate_http(&reopened, "kin_mutate", args, &session).await;
    assert_eq!(
        tool_result_payload(&replay)["publication_accounting"],
        accounting
    );
    assert_eq!(mutation_receipt(&replay), original);
    assert_eq!(mutation_generation(&reopened), before + 1);
    assert_eq!(
        mutation_published_body(&reopened, "first.py"),
        "def first():\n    return 1\n"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_completed_proof_is_bounded_and_tampering_refuses_without_erasing_it() {
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let mut args = keyed_mutation(&state, &session, "proof", "first").await;
    let unused = keyed_mutation(&state, &session, "unused", "second").await;
    args["operations"]
        .as_array_mut()
        .unwrap()
        .push(unused["operations"][0].clone());
    let original =
        mutation_receipt(&mutate_http(&state, "kin_mutate", args.clone(), &session).await);
    let generation = mutation_generation(&state);
    let (path, mut record) = mutation_record(&state, "proof").unwrap();
    assert_eq!(record["receipt"]["schema"], "kin.mutate.publication.v1");
    assert!(record["request"].is_null());
    assert!(record["receipt"].get("modified_files").is_none());
    assert!(record["receipt"].get("publication_accounting").is_none());
    assert!(record.get("publication_accounting").is_none());
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
    digest_input
        .as_object_mut()
        .unwrap()
        .remove("record_digest");
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
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let seed = keyed_mutation(&state, &session, "seed", "first").await;
    mutation_receipt(&mutate_http(&state, "kin_mutate", seed, &session).await);
    let mut args = keyed_mutation(&state, &session, "uncached-publication", "first").await;
    args["operations"][0]["verb"] = serde_json::json!("update");
    args["operations"][0]["body"] = serde_json::json!("def first():\n    return 2");
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
    // The uncertain publication moved the workspace, so the intervening edit
    // reads the version it replaces again rather than reusing the original's
    // base, which that publication made stale.
    let mut intervening = keyed_mutation(
        &state,
        &session,
        "intervening-after-uncached-publication",
        "first",
    )
    .await;
    intervening["operations"][0]["body"] = serde_json::json!("def first():\n    return 3");
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
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&state, &session, "completed-count", "first").await;
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
        let (_dir, state) = keyed_mutation_fixture().await;
        let session = mcp_test_session(&state);
        let args = keyed_mutation(&state, &session, "temp-link", "first").await;
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
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let args = keyed_mutation(&state, &session, "legacy-record", "first").await;
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
        let (_dir, state) = keyed_mutation_fixture().await;
        let session = mcp_test_session(&state);
        let args = keyed_mutation(&state, &session, "directory", "first").await;
        let store = state.layout.root().join("mutate_requests");
        let outside = state.layout.root().join("owned-external-directory");
        if symlink {
            std::fs::create_dir(&outside).unwrap();
            std::os::unix::fs::symlink(&outside, &store).unwrap();
        } else {
            std::fs::write(&store, b"retain non-directory evidence").unwrap();
        }
        let before = mutation_generation(&state);
        let refused = mutate_http(&state, "kin_mutate", args, &session).await;
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

fn legacy_keyed_arguments(session: &str, id: &str) -> serde_json::Value {
    serde_json::json!({"session_id":session,"request_id":id,"summary":"retained legacy file work",
        "operations":[{"verb":"create","target":"legacy.py","body":"def legacy():\n    return 7\n","description":"preserved legacy work"}]})
}

fn retain_legacy_keyed_request(
    state: &Arc<DaemonState>,
    arguments: &serde_json::Value,
    fenced: bool,
) -> kin_mcp::McpTransaction {
    let sessions = mcp_session_registry_snapshot(state).unwrap();
    let session = arguments["session_id"].as_str().unwrap();
    let transaction = sessions.begin_transaction(session, "repository").unwrap();
    let parsed = kin_mcp::session::parse_staged_operations(&arguments["operations"]).unwrap();
    sessions
        .stage_transaction(&transaction.transaction_id, parsed)
        .unwrap();
    if fenced {
        let transaction = sessions
            .get_transaction(&transaction.transaction_id)
            .unwrap();
        use sha2::Digest;
        let mut hash = sha2::Sha256::new();
        hash.update(b"kin-exact-mcp-transaction-v1\0");
        crate::mcp_commit::hash_canonical_json(
            &mut hash,
            &serde_json::json!({
            "transaction_id":transaction.transaction_id,"session_id":transaction.session_id,
            "scope":transaction.scope,"operations":transaction.staged_operations}),
        );
        sessions
            .prepare_transaction_commit(&transaction.transaction_id, &hex::encode(hash.finalize()))
            .unwrap();
    }
    persist_mcp_lifecycle_transactions(state, &sessions).unwrap();
    crate::mcp_mutate::retain_legacy_request_fixture(
        state,
        arguments.clone(),
        &transaction.transaction_id,
    );
    sessions
        .get_transaction(&transaction.transaction_id)
        .unwrap()
}

fn retained_refusal(result: &kin_mcp::ToolCallResult) -> serde_json::Value {
    assert_eq!(result.is_error, Some(true), "{}", mcp_result_text(result));
    let payload = tool_result_payload(result);
    assert_eq!(payload["schema"], "kin.mutate.refusal.v1");
    assert_eq!(payload["status"], "refused");
    assert_eq!(payload["published"], false);
    assert_eq!(payload["request_and_staging_preserved"], true);
    payload
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_legacy_refusal_preserves_exact_work_releases_slots_and_replays_after_restart() {
    for fenced in [false, true] {
        let (_dir, state) = keyed_mutation_fixture().await;
        let session = mcp_test_session(&state);
        let arguments = legacy_keyed_arguments(&session, "legacy-refused");
        let original = retain_legacy_keyed_request(&state, &arguments, fenced);
        let (record_path, binding) = mutation_record(&state, "legacy-refused").unwrap();
        assert!(
            binding.get("terminal_refusal").is_none(),
            "old v2 digest shape stays unchanged"
        );
        let before = mutation_generation(&state);
        // Fill the per-session quota around the preserved obsolete request.
        for _ in 1..kin_mcp::session::MAX_ACTIVE_TRANSACTIONS_PER_SESSION {
            mcp_lifecycle_begin(&state, &session).await;
        }
        let refused =
            retained_refusal(&mutate_http(&state, "kin_mutate", arguments.clone(), &session).await);
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
        assert_eq!(saved["request"], binding["request"]);
        assert_eq!(saved["request_hash"], binding["request_hash"]);
        assert_eq!(
            saved["terminal_refusal"]["transaction"],
            serde_json::to_value(&original).unwrap()
        );
        assert_eq!(saved["receipt"], serde_json::Value::Null);
        assert_eq!(mutation_generation(&state), before);
        assert!(!state.layout.working_dir().join("legacy.py").exists());
        let mirror = crate::state::load_persisted_mcp_transactions_checked(&state.layout).unwrap();
        assert_eq!(mirror[&original.transaction_id].state, "aborted");
        assert!(mirror[&original.transaction_id]
            .staged_operations
            .is_empty());
        // One unfinished slot and the unused reservation, not permanent identity,
        // become available. The full terminal record still consumes actual bytes.
        let retained_bytes = std::fs::metadata(&record_path).unwrap().len();
        let mut env = kin_core::test_env::EnvVarGuard::set(
            "KIN_MUTATE_MAX_STORAGE_BYTES",
            (retained_bytes + 2 * 1024 * 1024).to_string(),
        );
        env.apply("KIN_MUTATE_MAX_REQUESTS", Some("2"));
        let fresh = keyed_mutation(&state, &session, "fresh-semantic", "first").await;
        mutation_receipt(&mutate_http(&state, "kin_mutate", fresh, &session).await);
        assert_eq!(mutation_generation(&state), before + 1);
        let mut changed = arguments.clone();
        changed["summary"] = serde_json::json!("changed");
        let mismatch = mutate_http(&state, "kin_mutate", changed, &session).await;
        assert!(mcp_result_text(&mismatch).contains("request_id_payload_mismatch"));
        let frozen = std::fs::read(&record_path).unwrap();
        let layout = state.layout.clone();
        drop(state);
        let reopened = Arc::new(DaemonState::open(layout).unwrap());
        reopened
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            retained_refusal(&mutate_http(&reopened, "kin_mutate", arguments, &session).await),
            refused
        );
        assert_eq!(
            std::fs::read(&record_path).unwrap(),
            frozen,
            "replay does not rewrite refusal evidence"
        );
        assert_eq!(mutation_generation(&reopened), before + 1);
        let bytes_after_reload = std::fs::read_dir(reopened.layout.root().join("mutate_requests"))
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .sum::<u64>();
        env.apply("KIN_MUTATE_MAX_REQUESTS", Some("3"));
        env.apply(
            "KIN_MUTATE_MAX_STORAGE_BYTES",
            Some(&(bytes_after_reload + 2 * 1024 * 1024).to_string()),
        );
        let fresh_owner = mcp_test_session(&reopened);
        let fresh = keyed_mutation(&reopened, &fresh_owner, "fresh-after-restart", "second").await;
        mutation_receipt(&mutate_http(&reopened, "kin_mutate", fresh, &fresh_owner).await);
        assert_eq!(mutation_generation(&reopened), before + 2);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_legacy_refusal_persists_before_cleanup_and_recovers_faults() {
    for phase in [11_u8, 12, 13, 14, 21, 22, 23, 24] {
        let (_dir, state) = keyed_mutation_fixture().await;
        let session = mcp_test_session(&state);
        let arguments = legacy_keyed_arguments(&session, "legacy-fault");
        let original = retain_legacy_keyed_request(&state, &arguments, true);
        state
            .mcp_mutate_fail_once
            .store(phase, std::sync::atomic::Ordering::SeqCst);
        let failed = mutate_http(&state, "kin_mutate", arguments.clone(), &session).await;
        assert_eq!(failed.is_error, Some(true));
        assert!(
            mcp_result_text(&failed).contains("injected"),
            "phase {phase}: {}",
            mcp_result_text(&failed)
        );
        let mirror = crate::state::load_persisted_mcp_transactions_checked(&state.layout).unwrap();
        assert_eq!(
            serde_json::to_value(&mirror[&original.transaction_id]).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
        let (_, record) = mutation_record(&state, "legacy-fault").unwrap();
        assert!(record["request"].is_object());
        let before = mutation_generation(&state);
        let layout = state.layout.clone();
        drop(state);
        let reopened = Arc::new(DaemonState::open(layout).unwrap());
        reopened
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        retained_refusal(&mutate_http(&reopened, "kin_mutate", arguments, &session).await);
        assert_eq!(mutation_generation(&reopened), before);
        let (_, record) = mutation_record(&reopened, "legacy-fault").unwrap();
        assert_eq!(
            record["terminal_refusal"]["transaction"],
            serde_json::to_value(&original).unwrap()
        );
    }
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_legacy_published_key_recovers_authority_before_semantic_refusal() {
    for prior_refusal in [false, true] {
        let (_dir, state) = keyed_mutation_fixture().await;
        let session = mcp_test_session(&state);
        let arguments = legacy_keyed_arguments(&session, "legacy-published");
        let original = retain_legacy_keyed_request(&state, &arguments, true);
        if prior_refusal {
            retained_refusal(&mutate_http(&state, "kin_mutate", arguments.clone(), &session).await);
        }
        let saved_refusal = mutation_record(&state, "legacy-published").unwrap().1;
        let sessions = mcp_session_registry_snapshot(&state).unwrap();
        if prior_refusal {
            // Test-only authority publication models a receipt appearing after the
            // retained refusal. Recovery must still consult authority first.
            let mut transactions = sessions.list_transactions();
            *transactions
                .iter_mut()
                .find(|tx| tx.transaction_id == original.transaction_id)
                .unwrap() = original.clone();
            sessions.replace_transactions(transactions);
        }
        let commit = crate::mcp_commit::tests::commit_conversion_fixture(
            &state,
            &sessions,
            &HashMap::from([(
                "transaction_id".into(),
                serde_json::json!(original.transaction_id),
            )]),
            None,
        );
        assert_ne!(commit.is_error, Some(true), "{}", mcp_result_text(&commit));
        persist_mcp_lifecycle_transactions(&state, &sessions).unwrap();
        let generation = mutation_generation(&state);
        let first =
            mutation_receipt(&mutate_http(&state, "kin_mutate", arguments.clone(), &session).await);
        assert_eq!(first["transaction_id"], original.transaction_id);
        assert_eq!(first["repository_generation"], generation);
        assert_eq!(
            mutation_published_body(&state, "legacy.py"),
            "def legacy():\n    return 7\n"
        );
        let (_, record) = mutation_record(&state, "legacy-published").unwrap();
        if prior_refusal {
            assert_eq!(
                record, saved_refusal,
                "authoritative recovery preserves prior refusal evidence"
            );
        } else {
            assert!(record.get("terminal_refusal").is_none());
        }
        let layout = state.layout.clone();
        drop(state);
        let reopened = Arc::new(DaemonState::open(layout).unwrap());
        reopened
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            mutation_receipt(&mutate_http(&reopened, "kin_mutate", arguments, &session).await),
            first
        );
        assert_eq!(mutation_generation(&reopened), generation);
    }
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_legacy_refusal_overflow_or_cleanup_failure_preserves_work() {
    for overflow in [false, true] {
        let (_dir, state) = keyed_mutation_fixture().await;
        let session = mcp_test_session(&state);
        let arguments = legacy_keyed_arguments(&session, "legacy-preservation");
        let original = retain_legacy_keyed_request(&state, &arguments, true);
        let (record_path, _) = mutation_record(&state, "legacy-preservation").unwrap();
        let original_binding = std::fs::read(&record_path).unwrap();
        if overflow {
            let sessions = mcp_session_registry_snapshot(&state).unwrap();
            let mut transactions = sessions.list_transactions();
            let tx = transactions
                .iter_mut()
                .find(|tx| tx.transaction_id == original.transaction_id)
                .unwrap();
            tx.staged_operations[0].body = Some("retained staging bytes".repeat(110_000));
            sessions.replace_transactions(transactions);
            persist_mcp_lifecycle_transactions(&state, &sessions).unwrap();
        } else {
            state.mcp_lifecycle_persist_fail_once.store(
                crate::state::McpTransactionWritePhase::FileSync as u8,
                std::sync::atomic::Ordering::SeqCst,
            );
        }
        let mirror = crate::state::mcp_transactions_disk_path(&state.layout);
        let staged = std::fs::read(&mirror).unwrap();
        let before = mutation_generation(&state);
        let failed = mutate_http(&state, "kin_mutate", arguments.clone(), &session).await;
        assert_eq!(failed.is_error, Some(true));
        assert!(
            mcp_result_text(&failed).contains("request_recovery_required"),
            "{}",
            mcp_result_text(&failed)
        );
        assert_eq!(std::fs::read(&mirror).unwrap(), staged);
        assert_eq!(mutation_generation(&state), before);
        if overflow {
            assert!(mcp_result_text(&failed).contains("storage bound"));
            assert_eq!(std::fs::read(&record_path).unwrap(), original_binding);
        } else {
            let (_, record) = mutation_record(&state, "legacy-preservation").unwrap();
            assert_eq!(
                record["terminal_refusal"]["transaction"],
                serde_json::to_value(&original).unwrap()
            );
            retained_refusal(&mutate_http(&state, "kin_mutate", arguments, &session).await);
            assert_eq!(mutation_generation(&state), before);
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn mcp_mutate_publication_accounting_survives_later_roots_without_rewriting_historical_proof()
{
    let (_dir, state) = keyed_mutation_fixture().await;
    let session = mcp_test_session(&state);
    let mut args = keyed_mutation(&state, &session, "accounting-original", "first").await;
    let candidates = state
        .graph
        .query_entities(&kin_model::EntityFilter {
            name_pattern: Some("first".to_string()),
            ..Default::default()
        })
        .unwrap();
    // The converted first.py module and its function intentionally share a
    // name. The keyed entity UUID must identify the declaration being edited.
    assert!(candidates
        .iter()
        .any(|entity| { entity.name == "first" && entity.kind == kin_model::EntityKind::Module }));
    let entity = candidates
        .into_iter()
        .find(|entity| entity.name == "first" && entity.kind == kin_model::EntityKind::Function)
        .expect("the conversion fixture must contain the first function");
    args["operations"][0]["target"] = serde_json::json!(entity.id.to_string());
    let first = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
    let original = mutation_receipt(&first);
    let accounting = tool_result_payload(&first)["publication_accounting"].clone();
    assert_eq!(accounting["status"], "exact");
    assert_eq!(
        accounting["requested"]["sample_operations"][0]["target"]["entity_id"],
        entity.id.to_string()
    );
    assert_eq!(
        accounting["entities"]["published_total"],
        original["entity_deltas"]
    );
    assert_eq!(
        accounting["relationships"]["published_total"],
        original["relation_deltas"]
    );
    assert_eq!(accounting["source_units"]["publication_only"]["count"], 1);
    assert_eq!(accounting["source_units"]["carried_unchanged"]["count"], 0);
    let (path, _) = mutation_record(&state, "accounting-original").unwrap();
    let proof_bytes = std::fs::read(&path).unwrap();
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
            .unwrap();
    let operation = kin_model::OperationId::from_uuid(
        Uuid::parse_str(original["transaction_id"].as_str().unwrap()).unwrap(),
    );
    let mut historical = crate::repository_commit::recover_native_commit(&context, operation)
        .unwrap()
        .unwrap();
    historical.receipt.operation.workspace_mutation = None;
    let unavailable = crate::publication_accounting::project(&historical, args.get("operations"));
    assert_eq!(unavailable["status"], "unavailable");
    assert!(
        unavailable.get("entities").is_none(),
        "unknown historical accounting is not zero"
    );
    assert_eq!(std::fs::read(&path).unwrap(), proof_bytes);
    mutation_receipt(
        &mutate_http(
            &state,
            "kin_mutate",
            keyed_mutation(&state, &session, "accounting-later", "second").await,
            &session,
        )
        .await,
    );
    let replay = mutate_http(&state, "kin_mutate", args.clone(), &session).await;
    assert_eq!(mutation_receipt(&replay), original);
    assert_eq!(
        tool_result_payload(&replay)["publication_accounting"],
        accounting
    );
    assert_eq!(std::fs::read(&path).unwrap(), proof_bytes);
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let replay = mutate_http(&reopened, "kin_mutate", args, &session).await;
    assert_eq!(mutation_receipt(&replay), original);
    assert_eq!(
        tool_result_payload(&replay)["publication_accounting"],
        accounting
    );
    assert_eq!(std::fs::read(&path).unwrap(), proof_bytes);
}
