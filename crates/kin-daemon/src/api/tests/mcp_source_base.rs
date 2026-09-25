// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

const SOURCE_BASE_ORIGINAL: &str = "pub fn value() -> u8 { 1 }\npub fn sibling() -> u8 { 8 }\n";
const SOURCE_BASE_EDIT: &str = "pub fn value() -> u8 { 2 }";

async fn source_base_commit_operation(
    state: &Arc<DaemonState>,
    operation: serde_json::Value,
) -> serde_json::Value {
    let session = mcp_test_session(state);
    let tx = mcp_lifecycle_begin(state, &session).await;
    let result = mcp_call(
        router(Arc::clone(state)),
        "kin_transaction_commit",
        serde_json::json!({ "transaction_id": tx, "operations": [operation] }),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    tool_result_payload(&result)
}

/// Explicit legacy conversion fixture boundary, compiled only in daemon tests.
/// The production MCP route never accepts these source-tree operations.
async fn source_tree_conversion_fixture(
    state: &Arc<DaemonState>,
    operation: serde_json::Value,
) -> serde_json::Value {
    let session = mcp_test_session(state);
    let tx = mcp_lifecycle_begin(state, &session).await;
    let _coordination = state.coordination_gate.lock().await;
    let _authority = state.begin_graph_authority_mutation();
    let sessions = mcp_session_registry_snapshot(state).unwrap();
    let args = serde_json::from_value(serde_json::json!({
        "transaction_id": tx, "operations": [operation]
    })).unwrap();
    let result = crate::mcp_commit::tests::commit_conversion_fixture(
        state, &sessions, &args, None,
    );
    persist_mcp_lifecycle_transactions(state, &sessions).unwrap();
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    // Mirror the served API's terminal eviction after fixture publication.
    crate::api::forget_mcp_transaction(state, &tx);
    tool_result_payload(&result)
}

async fn source_base_fixture() -> (tempfile::TempDir, Arc<DaemonState>, serde_json::Value) {
    let (dir, state) = mcp_lifecycle_fixture();
    source_tree_conversion_fixture(&state, serde_json::json!({
        "verb": "create", "target": "src/value.rs", "body": SOURCE_BASE_ORIGINAL, "description": "original source"
    })).await;
    let entity = state
        .graph
        .query_entities(&kin_model::EntityFilter {
            name_pattern: Some("value".into()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == "value" && entity.kind != kin_model::EntityKind::Module)
        .unwrap();
    let source = mcp_call(
        router(Arc::clone(&state)),
        "get_entity_source",
        serde_json::json!({ "entity_id": entity.id.to_string() }),
    )
    .await;
    assert_ne!(source.is_error, Some(true), "{}", mcp_result_text(&source));
    let source = tool_result_payload(&source);
    assert_eq!(source["body"], "pub fn value() -> u8 { 1 }");
    assert_eq!(
        source["source_base"]["schema"], "kin.entity.source_base.v1",
        "{source}"
    );
    (dir, state, source)
}

fn source_base_operation(source: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "verb": "update", "target": source["id"], "body": SOURCE_BASE_EDIT,
        "payload": { "EntitySourceBase": source["source_base"] }, "description": "guarded editor change"
    })
}

/// Read an entity's current source through the agent route. The payload
/// carries its `id`, its `body` and the `source_base` a guarded whole-entity
/// replacement sends back unchanged. A base names one workspace revision, so
/// any commit after this read makes it stale.
async fn source_base_read(
    state: &Arc<DaemonState>,
    entity_id: &serde_json::Value,
) -> serde_json::Value {
    let source = mcp_call(
        router(Arc::clone(state)),
        "get_entity_source",
        serde_json::json!({ "entity_id": entity_id }),
    )
    .await;
    assert_ne!(source.is_error, Some(true), "{}", mcp_result_text(&source));
    let source = tool_result_payload(&source);
    assert_eq!(
        source["source_base"]["schema"], "kin.entity.source_base.v1",
        "{source}"
    );
    source
}

/// Resolve the one declaration named exactly `name` to its entity, then read
/// its current source. Resolving is the caller's step, as it is for an agent:
/// a whole-entity replacement names its entity by id and carries the base the
/// read returned.
async fn source_base_read_named(state: &Arc<DaemonState>, name: &str) -> serde_json::Value {
    let named = state
        .graph
        .query_entities(&kin_model::EntityFilter {
            name_pattern: Some(name.into()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .filter(|entity| entity.name == name && entity.kind != kin_model::EntityKind::Module)
        .collect::<Vec<_>>();
    assert_eq!(
        named.len(),
        1,
        "exactly one declaration is named {name}: {named:?}"
    );
    source_base_read(state, &serde_json::json!(named[0].id)).await
}

/// A guarded whole-entity replacement: `body` becomes the complete source of
/// the entity `source` was read from, admitted only while that read is current.
fn source_base_replacement(
    source: &serde_json::Value,
    body: &str,
    description: &str,
) -> serde_json::Value {
    serde_json::json!({
        "verb": "update", "target": source["id"], "body": body,
        "payload": { "EntitySourceBase": source["source_base"] }, "description": description
    })
}

/// Commit a guarded replacement of `entity_id` against a fresh read, the way an
/// agent lands an edit after other work has moved the workspace.
async fn source_base_commit_fresh(
    state: &Arc<DaemonState>,
    entity_id: &serde_json::Value,
    body: &str,
    description: &str,
) -> serde_json::Value {
    let current = source_base_read(state, entity_id).await;
    source_base_commit_operation(state, source_base_replacement(&current, body, description)).await
}

async fn source_base_stage(state: &Arc<DaemonState>, operation: serde_json::Value) -> String {
    let session = mcp_test_session(state);
    let tx = mcp_lifecycle_begin(state, &session).await;
    let result = mcp_call(
        router(Arc::clone(state)),
        "kin_transaction_stage",
        serde_json::json!({ "transaction_id": tx, "operations": [operation] }),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    tx
}

fn source_base_roots(state: &DaemonState) -> kin_model::RootBundle {
    crate::local_repository_authority::ActiveLocalRepositoryAuthority::open(state)
        .unwrap()
        .manager
        .read_authority()
        .roots()
        .clone()
}

async fn source_base_assert_conflict(
    state: &Arc<DaemonState>,
    tx: &str,
    operation: &serde_json::Value,
) {
    let before = source_base_roots(state);
    let result = mcp_call(
        router(Arc::clone(state)),
        "kin_transaction_commit",
        serde_json::json!({ "transaction_id": tx }),
    )
    .await;
    assert_eq!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    assert!(
        kin_mcp::source_base::is_source_base_conflict(&mcp_result_text(&result)),
        "{}",
        mcp_result_text(&result)
    );
    assert_eq!(
        source_base_roots(state),
        before,
        "conflict must not publish"
    );
    let retained = state.mcp_transactions.lock().unwrap();
    assert_eq!(retained[tx].state, "active");
    assert!(
        retained[tx].commit_payload_hash.is_none(),
        "conflict precedes the publication fence"
    );
    assert_eq!(
        retained[tx].staged_operations[0].body.as_deref(),
        Some(SOURCE_BASE_EDIT)
    );
    assert_eq!(
        serde_json::to_value(&retained[tx].staged_operations[0]).unwrap()["payload"],
        operation["payload"]
    );
    drop(retained);
    let reopened = DaemonState::open(state.layout.clone()).unwrap();
    let persisted = reopened.mcp_transactions.lock().unwrap();
    assert_eq!(
        persisted[tx].staged_operations[0].body.as_deref(),
        Some(SOURCE_BASE_EDIT)
    );
    assert_eq!(
        serde_json::to_value(&persisted[tx].staged_operations[0]).unwrap()["payload"],
        operation["payload"]
    );
    assert_eq!(source_base_roots(&reopened), before);
}

#[tokio::test]
async fn mcp_source_base_exact_read_stage_restart_commit_and_receipt_replay() {
    let (dir, state, source) = source_base_fixture().await;
    let tx = source_base_stage(&state, source_base_operation(&source)).await;
    let owner = retained_transaction_value(&state, &tx)["session_id"].as_str().unwrap().to_string();
    let layout = state.layout.clone();
    drop(state);
    let state = Arc::new(DaemonState::open(layout.clone()).unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    reregister_transaction_owner(&state, &owner).await;
    let result = mcp_call(
        router(Arc::clone(&state)),
        "kin_transaction_commit",
        serde_json::json!({"transaction_id": tx}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    let receipt = tool_result_payload(&result);
    let current = mcp_call(
        router(Arc::clone(&state)),
        "get_entity_source",
        serde_json::json!({"entity_id":source["id"]}),
    )
    .await;
    assert_eq!(tool_result_payload(&current)["body"], SOURCE_BASE_EDIT);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("src/value.rs")).unwrap(),
        SOURCE_BASE_ORIGINAL.replacen("{ 1 }", "{ 2 }", 1)
    );
    source_base_commit_fresh(
        &state,
        &source["id"],
        "pub fn value() -> u8 { 3 }",
        "later work",
    )
    .await;
    let later = source_base_roots(&state);
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let replay = mcp_call(
        router(Arc::clone(&reopened)),
        "kin_transaction_commit",
        serde_json::json!({"transaction_id":tx}),
    )
    .await;
    assert_ne!(replay.is_error, Some(true), "{}", mcp_result_text(&replay));
    assert_eq!(
        tool_result_payload(&replay)["change_id"],
        receipt["change_id"]
    );
    assert_eq!(tool_result_payload(&replay)["already_applied"], true);
    assert_eq!(
        source_base_roots(&reopened),
        later,
        "receipt replay bypasses the stale guard without publishing again"
    );
    let current = mcp_call(
        router(reopened),
        "get_entity_source",
        serde_json::json!({"entity_id":source["id"]}),
    )
    .await;
    assert_eq!(
        tool_result_payload(&current)["body"],
        "pub fn value() -> u8 { 3 }"
    );
}

#[tokio::test]
async fn mcp_source_base_refuses_stale_body_branch_and_deleted_entity_without_losing_work() {
    for change in ["body", "branch", "delete"] {
        let (_dir, state, source) = source_base_fixture().await;
        let operation = source_base_operation(&source);
        let tx = source_base_stage(&state, operation.clone()).await;
        match change {
            "body" => {
                source_base_commit_fresh(
                    &state,
                    &source["id"],
                    "pub fn value() -> u8 { 9 }",
                    "concurrent edit",
                )
                .await;
            }
            "delete" => {
                source_tree_conversion_fixture(&state, serde_json::json!({"verb":"delete", "target":"src/value.rs", "description":"retire source"})).await;
            }
            _ => {
                let name = kin_model::RefName::branch(b"other").unwrap();
                for request in [
                    kin_cli::commands::branch::BranchRequest::Create {
                        name: name.clone(),
                        operation_id: kin_model::OperationId::new(),
                        actor: AuthorId::new("guard-test"),
                    },
                    kin_cli::commands::branch::BranchRequest::Switch {
                        name,
                        operation_id: kin_model::OperationId::new(),
                        actor: AuthorId::new("guard-test"),
                    },
                ] {
                    let (status, body) =
                        post_branch_request(Arc::clone(&state), &request, None).await;
                    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
                }
            }
        }
        source_base_assert_conflict(&state, &tx, &operation).await;
    }
}

#[tokio::test]
async fn mcp_source_base_replaced_repository_and_unknown_protocol_fail_closed() {
    let (dir, state, source) = source_base_fixture().await;
    let old_namespace = tempfile::tempdir().unwrap();
    let old_kin = dir.path().join(".kin");
    drop(state);
    std::fs::rename(&old_kin, old_namespace.path().join("retained.kin")).unwrap();
    let layout = kin_core::init(dir.path()).unwrap().layout;
    let state = Arc::new(DaemonState::open(layout).unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let operation = source_base_operation(&source);
    let tx = source_base_stage(&state, operation.clone()).await;
    source_base_assert_conflict(&state, &tx, &operation).await;
    let before = source_base_roots(&state);
    for unsupported in [
        serde_json::json!({"EntitySourceBaseV2": source["source_base"]}),
        {
            let mut value = operation["payload"].clone();
            value["EntitySourceBase"]["schema"] = serde_json::json!("kin.entity.source_base.v2");
            value
        },
        {
            let mut value = operation["payload"].clone();
            value["EntitySourceBase"]["expected_base"] = serde_json::json!("must not be ignored");
            value
        },
    ] {
        let mut unknown = operation.clone();
        unknown["payload"] = unsupported;
        let result = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_stage",
            serde_json::json!({"transaction_id":tx,"operations":[unknown]}),
        )
        .await;
        assert_eq!(result.is_error, Some(true), "{}", mcp_result_text(&result));
        assert!(
            mcp_result_text(&result).contains("unknown"),
            "{}",
            mcp_result_text(&result)
        );
        assert_eq!(
            state.mcp_transactions.lock().unwrap()[&tx]
                .staged_operations
                .len(),
            1
        );
        assert_eq!(source_base_roots(&state), before);
    }
}

#[tokio::test]
async fn mcp_source_base_inline_conflict_durably_retains_the_attempted_body() {
    let (dir, state, source) = source_base_fixture().await;
    let operation = source_base_operation(&source);
    source_base_commit_fresh(
        &state,
        &source["id"],
        "pub fn value() -> u8 { 9 }",
        "concurrent edit before inline attempt",
    )
    .await;
    let tx = mcp_lifecycle_begin(&state, &mcp_test_session(&state)).await;
    let owner = retained_transaction_value(&state, &tx)["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let before = source_base_roots(&state);
    let result = mcp_call(
        router(Arc::clone(&state)),
        "kin_transaction_commit",
        serde_json::json!({ "transaction_id": tx, "operations": [operation.clone()] }),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    assert!(kin_mcp::source_base::is_source_base_conflict(
        &mcp_result_text(&result)
    ));
    assert_eq!(source_base_roots(&state), before);
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        reopened.mcp_transactions.lock().unwrap()[&tx]
            .staged_operations
            .len(),
        1
    );
    let retained = retained_transaction_value(&reopened, &tx);
    let mirror = crate::state::mcp_transactions_disk_path(&reopened.layout);
    let persisted = std::fs::read(&mirror).unwrap();
    let current_body = std::fs::read(dir.path().join("src/value.rs")).unwrap();
    let owner_id = SessionId(Uuid::parse_str(&owner).unwrap());
    assert!(reopened
        .coordinator
        .get_session(&owner_id)
        .unwrap()
        .is_none());
    let refused = mcp_call_as(
        router(Arc::clone(&reopened)),
        "kin_transaction_commit",
        serde_json::json!({"transaction_id":tx}),
        owner_id,
    )
    .await;
    assert_eq!(
        refused.is_error,
        Some(true),
        "{}",
        mcp_result_text(&refused)
    );
    assert!(mcp_result_text(&refused).contains("Session not found"));
    assert_eq!(retained_transaction_value(&reopened, &tx), retained);
    assert_eq!(std::fs::read(&mirror).unwrap(), persisted);
    assert_eq!(source_base_roots(&reopened), before);
    assert_eq!(
        std::fs::read(dir.path().join("src/value.rs")).unwrap(),
        current_body
    );
    reregister_transaction_owner(&reopened, &owner).await;
    assert_eq!(retained_transaction_value(&reopened, &tx), retained);
    assert_eq!(std::fs::read(&mirror).unwrap(), persisted);
    assert_eq!(source_base_roots(&reopened), before);
    // Fresh ownership does not authorize publishing the stale source base.
    source_base_assert_conflict(&reopened, &tx, &operation).await;
}

#[tokio::test]
async fn mcp_source_base_binds_artifact_span_and_body_even_at_the_same_workspace_revision() {
    let (_dir, state, source) = source_base_fixture().await;
    for field in ["artifact_id", "source_blob_hash", "body_hash", "start_byte"] {
        let mut operation = source_base_operation(&source);
        operation["payload"]["EntitySourceBase"][field] = match field {
            "artifact_id" => serde_json::json!(kin_model::ArtifactId::new()),
            "start_byte" => serde_json::json!(1),
            _ => serde_json::json!("0".repeat(64)),
        };
        let tx = source_base_stage(&state, operation.clone()).await;
        source_base_assert_conflict(&state, &tx, &operation).await;
    }
    // Refused expectations did not consume or alter the original valid base.
    source_base_commit_operation(&state, source_base_operation(&source)).await;
}

#[tokio::test]
async fn mcp_source_base_historical_sessions_never_receive_a_current_write_expectation() {
    let (_dir, state, source) = source_base_fixture().await;
    let historical_head = kin_cli::commands::ref_lookup::resolve_ref(
        state.graph.as_ref(),
        &state.local_repository_authority_binding().unwrap(),
        None,
    )
    .unwrap();
    // The historical focal body and span still match HEAD byte-for-byte.
    source_tree_conversion_fixture(
        &state,
        serde_json::json!({
            "verb": "create", "target": "src/later.rs", "body": "pub fn later() {}\n",
            "description": "advance history without changing the focal source"
        }),
    )
    .await;
    let session = mcp_test_session(&state);
    let session_id = SessionId(uuid::Uuid::parse_str(&session).unwrap());
    let response = router(Arc::clone(&state))
        .oneshot(
            Request::post(format!("/session/{session}/scope"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"ref_string": format!("kin:{historical_head}")}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(matches!(
        state
            .graph_for_request_with_authority(Some(&session_id))
            .await
            .1,
        RequestGraphAuthority::SessionScope
    ));
    let before = source_base_roots(&state);
    for name in ["get_entity_source", "get_entity_body"] {
        let historical = mcp_call_as(
            router(Arc::clone(&state)),
            name,
            serde_json::json!({"entity_id":source["id"]}),
            session_id,
        )
        .await;
        assert_ne!(
            historical.is_error,
            Some(true),
            "{}",
            mcp_result_text(&historical)
        );
        let historical = tool_result_payload(&historical);
        assert_eq!(historical["body"], source["body"]);
        assert!(
            historical["source_base"].is_null(),
            "historical body cannot authorize a current edit: {historical}"
        );
        let current = mcp_call(
            router(Arc::clone(&state)),
            name,
            serde_json::json!({"entity_id":source["id"]}),
        )
        .await;
        assert_eq!(
            tool_result_payload(&current)["source_base"]["schema"],
            "kin.entity.source_base.v1"
        );
    }
    for scoped in [false, true] {
        let batch_args = serde_json::json!({"entity_ids":[source["id"]]});
        let batch = if scoped {
            mcp_call_as(
                router(Arc::clone(&state)),
                "get_entity_sources",
                batch_args,
                session_id,
            )
            .await
        } else {
            mcp_call(router(Arc::clone(&state)), "get_entity_sources", batch_args).await
        };
        assert_ne!(batch.is_error, Some(true), "{}", mcp_result_text(&batch));
        assert!(!mcp_result_text(&batch).contains("source_base"));
    }
    assert_eq!(source_base_roots(&state), before);

    // The fixture's base predates the history advanced above, so the current
    // edit reads the version it replaces again, as HEAD rather than as the
    // historical session.
    source_base_commit_fresh(
        &state,
        &source["id"],
        "pub fn value() -> u8 { 9 }",
        "make current source diverge from the selected historical revision",
    )
    .await;
    let before = source_base_roots(&state);
    for name in ["get_entity_source", "get_entity_body"] {
        let historical = mcp_call_as(
            router(Arc::clone(&state)),
            name,
            serde_json::json!({"entity_id":source["id"]}),
            session_id,
        )
        .await;
        // Historical reconstruction may honestly refuse unavailable provenance;
        // neither a refusal nor a supported historical body can mint a HEAD base.
        assert!(!mcp_result_text(&historical).contains("kin.entity.source_base.v1"));
        if historical.is_error != Some(true) {
            let historical = tool_result_payload(&historical);
            assert_eq!(historical["body"], source["body"]);
            assert!(historical["source_base"].is_null());
        }
    }
    assert_eq!(source_base_roots(&state), before);
}

#[tokio::test]
async fn semantic_retained_conversion_refuses_validation_and_inline_append_without_growth() {
    let (_dir, state, source) = source_base_fixture().await;
    let session = mcp_test_session(&state);
    let tx = mcp_lifecycle_begin(&state, &session).await;
    let sessions = mcp_session_registry_snapshot(&state).unwrap();
    let old = kin_mcp::session::parse_staged_operations(&serde_json::json!([{
        "verb":"create", "target":"src/legacy.rs", "body":"pub fn legacy() {}\n",
        "description":"retained work from an older client"
    }])).unwrap();
    sessions.stage_transaction(&tx, old).unwrap();
    persist_mcp_lifecycle_transactions(&state, &sessions).unwrap();
    let retained = retained_transaction_value(&state, &tx);
    let mirror = crate::state::mcp_transactions_disk_path(&state.layout);
    let bytes = std::fs::read(&mirror).unwrap();
    let roots = source_base_roots(&state);
    for tool in ["kin_transaction_validate", "kin_transaction_commit", "kin_transaction_commit"] {
        let mut args = serde_json::json!({"transaction_id":tx});
        if tool == "kin_transaction_commit" {
            args["operations"] = serde_json::json!([source_base_operation(&source)]);
        }
        let result = mcp_call(router(Arc::clone(&state)), tool, args).await;
        assert_eq!(result.is_error, Some(true));
        assert!(mcp_result_text(&result).contains("semantic_operation_required"));
        assert_eq!(retained_transaction_value(&state, &tx), retained);
        assert_eq!(std::fs::read(&mirror).unwrap(), bytes);
        assert_eq!(source_base_roots(&state), roots);
    }
    let reopened = DaemonState::open(state.layout.clone()).unwrap();
    assert_eq!(serde_json::to_value(&reopened.mcp_transactions.lock().unwrap()[&tx]).unwrap(), retained);
}
