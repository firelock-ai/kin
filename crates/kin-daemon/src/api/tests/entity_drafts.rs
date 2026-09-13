// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

const DRAFT_TEST_AUTH: &str = "entity-draft-http-fixture";

async fn entity_draft_http(
    state: &Arc<DaemonState>,
    name: &str,
    arguments: serde_json::Value,
) -> kin_mcp::ToolCallResult {
    let response = router_with_auth(Arc::clone(state), Some(DRAFT_TEST_AUTH.into()))
        .oneshot(
            Request::post("/mcp/tools/call")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {DRAFT_TEST_AUTH}"))
                .body(Body::from(
                    serde_json::json!({"name":name,"arguments":arguments}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).unwrap()
}

fn entity_draft_create_args(source: &serde_json::Value, body: &str) -> serde_json::Value {
    serde_json::json!({"draft_id":Uuid::new_v4(),"original_source_base":source["source_base"],
        "original_body":source["body"],"body":body})
}

fn entity_draft_ok(result: &kin_mcp::ToolCallResult) -> serde_json::Value {
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(result));
    tool_result_payload(result)
}

fn entity_draft_file(state: &DaemonState, id: &str, revision: u64) -> std::path::PathBuf {
    state
        .layout
        .root()
        .join("entity-drafts-v1")
        .join(format!("{id}.{revision:020}.json"))
}

fn entity_draft_reopen(state: &Arc<DaemonState>) -> Arc<DaemonState> {
    let reopened = Arc::new(DaemonState::open(state.layout.clone()).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    reopened
}

#[tokio::test]
async fn durable_entity_draft_invalid_empty_utf8_survives_restart_session_loss_and_entity_deletion()
{
    let (_dir, state, source) = source_base_fixture().await;
    let invalid = "fn broken( {\r\n  🧭 café\0\t";
    let args = entity_draft_create_args(&source, invalid);
    let created =
        entity_draft_ok(&entity_draft_http(&state, "kin_draft_create", args.clone()).await);
    assert_eq!(created["draft"]["body"], invalid);
    let id = args["draft_id"].as_str().unwrap();
    let before = source_base_roots(&state);
    let first_bytes = std::fs::read(entity_draft_file(&state, id, 1)).unwrap();
    let saved = entity_draft_ok(
        &entity_draft_http(
            &state,
            "kin_draft_save",
            serde_json::json!({"draft_id":id,"expected_revision":1,"body":""}),
        )
        .await,
    );
    assert_eq!(saved["draft"]["body"], "");
    assert_eq!(saved["draft"]["revision"], 2);
    assert_eq!(
        saved["draft"]["original_source_base"],
        source["source_base"]
    );
    assert_eq!(saved["draft"]["original_body"], source["body"]);
    assert_eq!(
        source_base_roots(&state),
        before,
        "saving text must never publish source"
    );
    assert_eq!(
        std::fs::read(entity_draft_file(&state, id, 1)).unwrap(),
        first_bytes
    );

    // The draft tools require no session ID. Even deleting the target entity
    // must not remove the user's editing state or its original read.
    source_base_commit_operation(&state, serde_json::json!({"verb":"delete","target":"src/value.rs","description":"retire entity while its draft is open"})).await;
    let reopened = entity_draft_reopen(&state);
    drop(state);
    let current = entity_draft_ok(
        &entity_draft_http(
            &reopened,
            "kin_draft_read",
            serde_json::json!({"draft_id":id}),
        )
        .await,
    );
    assert_eq!(current["body"], "");
    assert_eq!(current["original_body"], source["body"]);
    let original = entity_draft_ok(
        &entity_draft_http(
            &reopened,
            "kin_draft_read",
            serde_json::json!({"draft_id":id,"revision":1}),
        )
        .await,
    );
    assert_eq!(original["body"], invalid);
    let list = entity_draft_ok(
        &entity_draft_http(
            &reopened,
            "kin_draft_list",
            serde_json::json!({"entity_id":source["id"]}),
        )
        .await,
    );
    assert_eq!(list["drafts"][0]["draft_id"], id);
    assert_eq!(list["drafts"][0]["revision"], 2);
}

#[tokio::test]
async fn durable_entity_draft_revision_cas_and_lost_response_replay_preserve_later_text() {
    let (_dir, state, source) = source_base_fixture().await;
    let create = entity_draft_create_args(&source, "first invalid {");
    let id = create["draft_id"].as_str().unwrap();
    entity_draft_ok(&entity_draft_http(&state, "kin_draft_create", create.clone()).await);
    let save = serde_json::json!({"draft_id":id,"expected_revision":1,"body":"second invalid ("});
    entity_draft_ok(&entity_draft_http(&state, "kin_draft_save", save.clone()).await);
    let conflict = entity_draft_http(
        &state,
        "kin_draft_save",
        serde_json::json!({"draft_id":id,"expected_revision":1,"body":"other editor text"}),
    )
    .await;
    assert_eq!(conflict.is_error, Some(true));
    assert_eq!(
        tool_result_payload(&conflict)["code"],
        "draft_revision_conflict"
    );
    entity_draft_ok(
        &entity_draft_http(
            &state,
            "kin_draft_save",
            serde_json::json!({"draft_id":id,"expected_revision":2,"body":"later third text"}),
        )
        .await,
    );
    let reopened = entity_draft_reopen(&state);
    drop(state);
    let replay = entity_draft_ok(&entity_draft_http(&reopened, "kin_draft_save", save).await);
    assert_eq!(replay["already_saved"], true);
    assert_eq!(replay["draft"]["revision"], 2);
    assert_eq!(replay["draft"]["body"], "second invalid (");
    let create_replay =
        entity_draft_ok(&entity_draft_http(&reopened, "kin_draft_create", create.clone()).await);
    assert_eq!(create_replay["already_saved"], true);
    assert_eq!(create_replay["draft"]["revision"], 1);
    let latest = entity_draft_ok(
        &entity_draft_http(
            &reopened,
            "kin_draft_read",
            serde_json::json!({"draft_id":id}),
        )
        .await,
    );
    assert_eq!(latest["revision"], 3);
    assert_eq!(latest["body"], "later third text");
}

#[tokio::test]
async fn durable_entity_draft_requires_bearer_and_refuses_unknown_or_foreign_source_identity() {
    let (_dir, state, source) = source_base_fixture().await;
    let args = entity_draft_create_args(&source, "draft");
    let unenforced = mcp_call(router(Arc::clone(&state)), "kin_draft_create", args.clone()).await;
    assert_eq!(
        tool_result_payload(&unenforced)["code"],
        "draft_authentication_required"
    );
    for token in [None, Some("wrong-fixture-token")] {
        let mut request =
            Request::post("/mcp/tools/call").header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = router_with_auth(Arc::clone(&state), Some(DRAFT_TEST_AUTH.into()))
            .oneshot(
                request
                    .body(Body::from(
                        serde_json::json!({"name":"kin_draft_create","arguments":args}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    for field in ["owner", "expected_base", "pending_apply"] {
        let mut unknown = args.clone();
        unknown[field] = serde_json::json!("must never be silently dropped");
        let result = entity_draft_http(&state, "kin_draft_create", unknown).await;
        assert_eq!(
            tool_result_payload(&result)["code"],
            "draft_invalid_request"
        );
    }
    for field in ["repository_id", "workspace_id"] {
        let mut foreign = args.clone();
        foreign["original_source_base"]["context"][field] = serde_json::json!(Uuid::new_v4());
        let result = entity_draft_http(&state, "kin_draft_create", foreign).await;
        assert_eq!(result.is_error, Some(true));
    }
    assert_eq!(
        entity_draft_ok(&entity_draft_http(&state, "kin_draft_list", serde_json::json!({})).await)
            ["drafts"],
        serde_json::json!([])
    );
}

#[tokio::test]
async fn durable_entity_draft_valid_json_identity_revision_base_and_content_corruption_refuses() {
    let (_dir, state, source) = source_base_fixture().await;
    let create = entity_draft_create_args(&source, "acknowledged text");
    let id = create["draft_id"].as_str().unwrap();
    entity_draft_ok(&entity_draft_http(&state, "kin_draft_create", create.clone()).await);
    entity_draft_ok(
        &entity_draft_http(
            &state,
            "kin_draft_save",
            serde_json::json!({"draft_id":id,"expected_revision":1,"body":"second text"}),
        )
        .await,
    );
    let first_path = entity_draft_file(&state, id, 1);
    let first = std::fs::read(&first_path).unwrap();
    let latest_path = entity_draft_file(&state, id, 2);
    let latest = std::fs::read(&latest_path).unwrap();
    for pointer in [
        "/draft/draft_id",
        "/draft/revision",
        "/draft/content_revision",
        "/draft/scope/repository_id",
        "/draft/scope/workspace_id",
        "/draft/scope/entity_id",
        "/draft/original_source_base/body_hash",
        "/draft/original_body",
        "/draft/body",
        "/draft/request_hash",
        "/draft/previous_record_hash",
        "/draft/pending_apply",
        "/draft/applied_receipt",
    ] {
        let mut damaged: serde_json::Value = serde_json::from_slice(&latest).unwrap();
        *damaged.pointer_mut(pointer).unwrap() = match pointer {
            "/draft/content_revision" => serde_json::json!(1),
            "/draft/revision" => serde_json::json!(3),
            "/draft/draft_id" | "/draft/scope/entity_id" | "/draft/scope/workspace_id" => {
                serde_json::json!(Uuid::new_v4())
            }
            "/draft/pending_apply" => {
                serde_json::json!({"requested_revision":1,"draft_revision":1,"session_id":Uuid::new_v4(),"request_id":"changed","arguments":{}})
            }
            "/draft/applied_receipt" => {
                serde_json::json!({"attempt":{"requested_revision":1,"draft_revision":1,"session_id":Uuid::new_v4(),"request_id":"changed","arguments":{}},"receipt":{"ops_applied":99}})
            }
            _ => serde_json::json!("0".repeat(64)),
        };
        let evidence = serde_json::to_vec(&damaged).unwrap();
        std::fs::write(&latest_path, &evidence).unwrap();
        let reopened = entity_draft_reopen(&state);
        for (tool, args) in [
            ("kin_draft_read", serde_json::json!({"draft_id":id})),
            (
                "kin_draft_save",
                serde_json::json!({"draft_id":id,"expected_revision":2,"body":"new caller text"}),
            ),
            ("kin_draft_list", serde_json::json!({})),
        ] {
            let result = entity_draft_http(&reopened, tool, args).await;
            assert_eq!(
                tool_result_payload(&result)["code"],
                "draft_corrupt",
                "{pointer}: {}",
                mcp_result_text(&result)
            );
        }
        let prior = entity_draft_ok(
            &entity_draft_http(
                &reopened,
                "kin_draft_read",
                serde_json::json!({"draft_id":id,"revision":1}),
            )
            .await,
        );
        assert_eq!(prior["body"], "acknowledged text");
        assert_eq!(std::fs::read(&latest_path).unwrap(), evidence);
        assert_eq!(std::fs::read(&first_path).unwrap(), first);
        std::fs::write(&latest_path, &latest).unwrap();
    }
}

#[tokio::test]
async fn durable_entity_draft_faults_never_ack_and_retries_preserve_the_acknowledged_revision() {
    use crate::entity_drafts::{DraftFaultGuard, DraftTestFault, DraftWritePhase::*};
    for phase in [
        ParentDirectorySync,
        CreateTemporary,
        Write,
        FileSync,
        Publish,
        DirectorySync,
    ] {
        let (_dir, state, source) = source_base_fixture().await;
        let create = entity_draft_create_args(&source, "acknowledged original draft");
        let id = create["draft_id"].as_str().unwrap();
        entity_draft_ok(&entity_draft_http(&state, "kin_draft_create", create.clone()).await);
        let prior = std::fs::read(entity_draft_file(&state, id, 1)).unwrap();
        let save = serde_json::json!({"draft_id":id,"expected_revision":1,"body":"attempted incomplete {"});
        let fault = DraftFaultGuard::set(
            &state.layout,
            DraftTestFault {
                phase: Some(phase),
                ..Default::default()
            },
        );
        let failed = entity_draft_http(&state, "kin_draft_save", save.clone()).await;
        assert_eq!(failed.is_error, Some(true), "{phase:?}");
        assert_ne!(
            tool_result_payload(&failed)["schema"],
            "kin.entity.draft.saved.v1"
        );
        drop(fault);
        let reopened = entity_draft_reopen(&state);
        drop(state);
        assert_eq!(
            std::fs::read(entity_draft_file(&reopened, id, 1)).unwrap(),
            prior
        );
        let retry = entity_draft_ok(&entity_draft_http(&reopened, "kin_draft_save", save).await);
        assert_eq!(retry["draft"]["revision"], 2);
        assert_eq!(retry["draft"]["body"], "attempted incomplete {");
        let second_open = entity_draft_reopen(&reopened);
        assert_eq!(
            entity_draft_ok(
                &entity_draft_http(
                    &second_open,
                    "kin_draft_read",
                    serde_json::json!({"draft_id":id})
                )
                .await
            )["body"],
            "attempted incomplete {"
        );
        assert_eq!(
            std::fs::read(entity_draft_file(&second_open, id, 1)).unwrap(),
            prior
        );
    }
}

#[tokio::test]
async fn durable_entity_draft_quota_and_unknown_recovery_evidence_keep_prior_bytes() {
    use crate::entity_drafts::{DraftFaultGuard, DraftLimits, DraftTestFault};
    let (_dir, state, source) = source_base_fixture().await;
    let create = entity_draft_create_args(&source, "acknowledged text");
    let id = create["draft_id"].as_str().unwrap();
    entity_draft_ok(&entity_draft_http(&state, "kin_draft_create", create.clone()).await);
    let prior = std::fs::read(entity_draft_file(&state, id, 1)).unwrap();
    let fault = DraftFaultGuard::set(
        &state.layout,
        DraftTestFault {
            limits: Some(DraftLimits {
                total_bytes: prior.len() as u64,
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let save =
        serde_json::json!({"draft_id":id,"expected_revision":1,"body":"retained caller draft"});
    assert_eq!(
        tool_result_payload(&entity_draft_http(&state, "kin_draft_save", save.clone()).await)
            ["code"],
        "draft_quota"
    );
    drop(fault);
    let evidence_name = format!(".pending-{}", Uuid::new_v4());
    let evidence_path = state
        .layout
        .root()
        .join("entity-drafts-v1")
        .join(&evidence_name);
    std::fs::write(&evidence_path, b"{partial unknown draft attempt").unwrap();
    let reopened = entity_draft_reopen(&state);
    assert_eq!(
        entity_draft_ok(
            &entity_draft_http(
                &reopened,
                "kin_draft_read",
                serde_json::json!({"draft_id":id})
            )
            .await
        )["body"],
        "acknowledged text"
    );
    let list = entity_draft_ok(
        &entity_draft_http(&reopened, "kin_draft_list", serde_json::json!({})).await,
    );
    assert_eq!(
        list["recovery_evidence"],
        serde_json::json!([evidence_name])
    );
    assert_eq!(
        tool_result_payload(&entity_draft_http(&reopened, "kin_draft_save", save).await)["code"],
        "draft_recovery_required"
    );
    assert_eq!(
        std::fs::read(&evidence_path).unwrap(),
        b"{partial unknown draft attempt"
    );
    assert_eq!(
        std::fs::read(entity_draft_file(&reopened, id, 1)).unwrap(),
        prior
    );
}

#[cfg(unix)]
#[tokio::test]
async fn durable_entity_draft_temporary_symlink_cannot_overwrite_outside_bytes() {
    use crate::entity_drafts::{DraftFaultGuard, DraftTestFault};
    let (dir, state, source) = source_base_fixture().await;
    let create = entity_draft_create_args(&source, "safe old draft");
    let id = create["draft_id"].as_str().unwrap();
    entity_draft_ok(&entity_draft_http(&state, "kin_draft_create", create.clone()).await);
    let outside = dir.path().join("unrelated-private-bytes");
    std::fs::write(&outside, b"preserve unrelated bytes").unwrap();
    let temporary_id = Uuid::new_v4();
    let fault = DraftFaultGuard::set(
        &state.layout,
        DraftTestFault {
            temporary_id: Some(temporary_id),
            symlink_target: Some(outside.clone()),
            ..Default::default()
        },
    );
    let result = entity_draft_http(
        &state,
        "kin_draft_save",
        serde_json::json!({"draft_id":id,"expected_revision":1,"body":"never overwrite outside"}),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    drop(fault);
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"preserve unrelated bytes"
    );
    assert!(!entity_draft_file(&state, id, 2).exists());
    assert!(std::fs::symlink_metadata(
        state
            .layout
            .root()
            .join("entity-drafts-v1")
            .join(format!(".pending-{temporary_id}"))
    )
    .unwrap()
    .file_type()
    .is_symlink());
}

#[tokio::test]
async fn durable_entity_draft_apply_replays_original_receipt_after_restart_and_later_edit() {
    let (_dir, state, source) = source_base_fixture().await;
    let create = entity_draft_create_args(&source, SOURCE_BASE_EDIT);
    let id = create["draft_id"].as_str().unwrap();
    entity_draft_ok(&entity_draft_http(&state, "kin_draft_create", create.clone()).await);
    let session = mcp_test_session(&state);
    let request = serde_json::json!({"draft_id":id,"expected_revision":1,"session_id":session});
    let first =
        entity_draft_ok(&entity_draft_http(&state, "kin_draft_apply", request.clone()).await);
    assert_eq!(first["schema"], "kin.entity.draft.applied.v1");
    assert_eq!(first["receipt_saved"], true);
    assert_eq!(first["current_text_applied"], true);
    assert_eq!(first["applied_draft_revision"], 1);
    assert_eq!(first["draft"]["revision"], 3);
    assert_eq!(first["draft"]["content_revision"], 1);
    assert_eq!(first["receipt"]["ops_applied"], 1);
    assert!(first["receipt"].get("already_applied").is_none());
    let later = "pub fn value() -> u8 { 3 }";
    source_base_commit_operation(
        &state,
        serde_json::json!({"verb":"update","target":source["id"],"description":"Intervening edit","body":later}),
    )
    .await;
    let roots = source_base_roots(&state);
    let reopened = entity_draft_reopen(&state);
    drop(state);
    let replay = entity_draft_ok(&entity_draft_http(&reopened, "kin_draft_apply", request).await);
    assert_eq!(replay["receipt"], first["receipt"]);
    assert_eq!(replay["draft"]["revision"], 3);
    assert_eq!(source_base_roots(&reopened), roots);
    let current = mcp_call(
        router(Arc::clone(&reopened)),
        "get_entity_source",
        serde_json::json!({"entity_id":source["id"]}),
    )
    .await;
    assert_eq!(tool_result_payload(&current)["body"], later);
}

#[tokio::test]
async fn durable_entity_draft_save_during_unresolved_apply_recovers_only_original_text() {
    let (_dir, state, source) = source_base_fixture().await;
    let create = entity_draft_create_args(&source, SOURCE_BASE_EDIT);
    let id = create["draft_id"].as_str().unwrap();
    entity_draft_ok(&entity_draft_http(&state, "kin_draft_create", create.clone()).await);
    let session = mcp_test_session(&state);
    let request = serde_json::json!({"draft_id":id,"expected_revision":1,"session_id":session});
    let roots = source_base_roots(&state);
    let fault = crate::entity_drafts::DraftFaultGuard::set(
        &state.layout,
        crate::entity_drafts::DraftTestFault {
            phase: Some(crate::entity_drafts::DraftWritePhase::BeforeApplyDispatch),
            ..Default::default()
        },
    );
    let held = entity_draft_http(&state, "kin_draft_apply", request.clone()).await;
    assert_eq!(held.is_error, Some(true));
    assert_eq!(source_base_roots(&state), roots);
    drop(fault);
    let pending = entity_draft_ok(
        &entity_draft_http(&state, "kin_draft_read", serde_json::json!({"draft_id":id})).await,
    );
    assert_eq!(pending["revision"], 2);
    assert_eq!(pending["pending_apply"]["draft_revision"], 1);
    assert_eq!(
        pending["pending_apply"]["arguments"]["operations"][0]["body"],
        SOURCE_BASE_EDIT
    );
    let newer = "fn newer broken( 🧭\r\n";
    let saved = entity_draft_ok(
        &entity_draft_http(
            &state,
            "kin_draft_save",
            serde_json::json!({"draft_id":id,"expected_revision":2,"body":newer}),
        )
        .await,
    );
    assert_eq!(saved["draft"]["pending_apply"], pending["pending_apply"]);
    assert_eq!(saved["draft"]["content_revision"], 3);
    let reopened = entity_draft_reopen(&state);
    drop(state);
    // A pending unpublished attempt needs fresh registration of its original UUID.
    reopened
        .coordinator
        .register_session_with_id(
            SessionId(Uuid::parse_str(&session).unwrap()),
            "codex",
            "resumed-draft",
            SessionTransport::Mcp,
            None,
            reopened.layout.working_dir().to_path_buf(),
            SessionCapabilities {
                can_write: true,
                can_commit: true,
                ..Default::default()
            },
        )
        .unwrap();
    let different = mcp_test_session(&reopened);
    let recovered = entity_draft_ok(
        &entity_draft_http(
            &reopened,
            "kin_draft_apply",
            serde_json::json!({"draft_id":id,"expected_revision":3,"session_id":different}),
        )
        .await,
    );
    assert_eq!(recovered["current_text_applied"], false);
    assert_eq!(recovered["applied_draft_revision"], 1);
    assert_eq!(recovered["draft"]["body"], newer);
    assert_eq!(recovered["draft"]["content_revision"], 3);
    assert_eq!(
        recovered["draft"]["applied_receipt"]["attempt"],
        pending["pending_apply"]
    );
    let current = mcp_call(
        router(Arc::clone(&reopened)),
        "get_entity_source",
        serde_json::json!({"entity_id":source["id"]}),
    )
    .await;
    assert_eq!(tool_result_payload(&current)["body"], SOURCE_BASE_EDIT);
    let again = entity_draft_reopen(&reopened);
    let read = entity_draft_ok(
        &entity_draft_http(&again, "kin_draft_read", serde_json::json!({"draft_id":id})).await,
    );
    assert_eq!(read["body"], newer);
    assert_eq!(
        read["applied_receipt"],
        recovered["draft"]["applied_receipt"]
    );
}

#[tokio::test]
async fn durable_entity_draft_apply_receipt_failure_recovers_without_republication() {
    let (_dir, state, source) = source_base_fixture().await;
    let create = entity_draft_create_args(&source, SOURCE_BASE_EDIT);
    let id = create["draft_id"].as_str().unwrap();
    entity_draft_ok(&entity_draft_http(&state, "kin_draft_create", create.clone()).await);
    let request = serde_json::json!({"draft_id":id,"expected_revision":1,"session_id":mcp_test_session(&state)});
    let fault = crate::entity_drafts::DraftFaultGuard::set(
        &state.layout,
        crate::entity_drafts::DraftTestFault {
            phase: Some(crate::entity_drafts::DraftWritePhase::BeforeApplyReceipt),
            ..Default::default()
        },
    );
    let uncertain = entity_draft_http(&state, "kin_draft_apply", request.clone()).await;
    assert_eq!(uncertain.is_error, Some(true));
    let uncertain = tool_result_payload(&uncertain);
    assert_eq!(uncertain["code"], "draft_apply_receipt_not_saved");
    assert_eq!(uncertain["repository_source_applied"], true);
    assert_eq!(uncertain["receipt_saved"], false);
    drop(fault);
    let pending = entity_draft_ok(
        &entity_draft_http(&state, "kin_draft_read", serde_json::json!({"draft_id":id})).await,
    );
    assert_eq!(pending["pending_apply"], uncertain["attempt"]);
    assert!(pending["applied_receipt"].is_null());
    source_base_commit_operation(&state, serde_json::json!({"verb":"update","target":source["id"],"description":"Intervening edit","body":"pub fn value() -> u8 { 9 }"})).await;
    let roots = source_base_roots(&state);
    let reopened = entity_draft_reopen(&state);
    drop(state);
    let recovered =
        entity_draft_ok(&entity_draft_http(&reopened, "kin_draft_apply", request).await);
    assert_eq!(recovered["receipt"], uncertain["receipt"]);
    assert_eq!(source_base_roots(&reopened), roots);
    let second = entity_draft_reopen(&reopened);
    let saved = entity_draft_ok(
        &entity_draft_http(
            &second,
            "kin_draft_read",
            serde_json::json!({"draft_id":id}),
        )
        .await,
    );
    assert_eq!(saved["applied_receipt"]["receipt"], uncertain["receipt"]);
    assert_eq!(source_base_roots(&second), roots);
}

#[tokio::test]
async fn durable_entity_draft_stale_and_invalid_apply_refuse_but_preserve_newer_saved_text() {
    for stale in [false, true] {
        let (_dir, state, source) = source_base_fixture().await;
        let text = if stale {
            SOURCE_BASE_EDIT
        } else {
            "fn broken( {"
        };
        let create = entity_draft_create_args(&source, text);
        let id = create["draft_id"].as_str().unwrap();
        entity_draft_ok(&entity_draft_http(&state, "kin_draft_create", create.clone()).await);
        if stale {
            source_base_commit_operation(&state, serde_json::json!({"verb":"update","target":source["id"],"description":"Intervening edit","body":"pub fn value() -> u8 { 4 }"})).await;
        }
        let roots = source_base_roots(&state);
        let request = serde_json::json!({"draft_id":id,"expected_revision":1,"session_id":mcp_test_session(&state)});
        let refused = entity_draft_http(&state, "kin_draft_apply", request).await;
        assert_eq!(refused.is_error, Some(true));
        assert_eq!(source_base_roots(&state), roots);
        let payload = tool_result_payload(&refused);
        assert_eq!(payload["code"], "draft_apply_unresolved");
        let pending = payload["attempt"].clone();
        assert_eq!(pending["arguments"]["operations"][0]["body"], text);
        if stale {
            assert!(mcp_result_text(&refused).contains("source_base_conflict"));
        }
        let saved = entity_draft_ok(
            &entity_draft_http(
                &state,
                "kin_draft_save",
                serde_json::json!({"draft_id":id,"expected_revision":2,"body":""}),
            )
            .await,
        );
        assert_eq!(saved["draft"]["pending_apply"], pending);
        let reopened = entity_draft_reopen(&state);
        let read = entity_draft_ok(
            &entity_draft_http(
                &reopened,
                "kin_draft_read",
                serde_json::json!({"draft_id":id}),
            )
            .await,
        );
        assert_eq!(read["body"], "");
        assert_eq!(read["pending_apply"], pending);
        assert_eq!(source_base_roots(&reopened), roots);
    }
}

#[tokio::test]
async fn durable_entity_draft_old_apply_retry_is_not_redirected_to_newer_pending_attempt() {
    let (_dir, state, source) = source_base_fixture().await;
    let create = entity_draft_create_args(&source, SOURCE_BASE_EDIT);
    let id = create["draft_id"].as_str().unwrap();
    entity_draft_ok(&entity_draft_http(&state, "kin_draft_create", create.clone()).await);
    let session = mcp_test_session(&state);
    let first_request =
        serde_json::json!({"draft_id":id,"expected_revision":1,"session_id":session});
    let first =
        entity_draft_ok(&entity_draft_http(&state, "kin_draft_apply", first_request.clone()).await);
    let newer = "pub fn value() -> u8 { 5 }";
    let saved = entity_draft_ok(
        &entity_draft_http(
            &state,
            "kin_draft_save",
            serde_json::json!({"draft_id":id,"expected_revision":3,"body":newer}),
        )
        .await,
    );
    assert_eq!(saved["draft"]["revision"], 4);
    let second = entity_draft_http(
        &state,
        "kin_draft_apply",
        serde_json::json!({"draft_id":id,"expected_revision":4,"session_id":session}),
    )
    .await;
    assert_eq!(second.is_error, Some(true));
    assert!(mcp_result_text(&second).contains("source_base_conflict"));
    let second_attempt = tool_result_payload(&second)["attempt"].clone();
    assert_ne!(
        second_attempt["request_id"],
        first["draft"]["applied_receipt"]["attempt"]["request_id"]
    );
    let roots = source_base_roots(&state);
    let reopened = entity_draft_reopen(&state);
    drop(state);
    let replay =
        entity_draft_ok(&entity_draft_http(&reopened, "kin_draft_apply", first_request).await);
    assert_eq!(replay["receipt"], first["receipt"]);
    assert_eq!(replay["applied_draft_revision"], 1);
    assert_eq!(replay["current_text_applied"], false);
    assert_eq!(replay["draft"]["pending_apply"], second_attempt);
    assert_eq!(replay["draft"]["body"], newer);
    assert_eq!(source_base_roots(&reopened), roots);
}

#[tokio::test]
async fn durable_entity_draft_admission_refusal_keeps_reads_and_quota_retry_available() {
    use crate::entity_drafts::{DraftFaultGuard, DraftLimits, DraftTestFault};
    let (_dir, state, source) = source_base_fixture().await;
    let create = entity_draft_create_args(&source, "original acknowledged text");
    let id = create["draft_id"].as_str().unwrap();
    entity_draft_ok(&entity_draft_http(&state, "kin_draft_create", create.clone()).await);
    let original = std::fs::read(entity_draft_file(&state, id, 1)).unwrap();
    let save = serde_json::json!({"draft_id":id,"expected_revision":1,"body":"new text"});
    for fault in [
        DraftTestFault {
            admission_error: Some("invalid KIN_DRAFT_MAX_REVISIONS".into()),
            ..Default::default()
        },
        DraftTestFault {
            limits: Some(DraftLimits {
                revisions: 1,
                ..Default::default()
            }),
            ..Default::default()
        },
    ] {
        let guard = DraftFaultGuard::set(&state.layout, fault);
        let refused = entity_draft_http(&state, "kin_draft_save", save.clone()).await;
        assert_eq!(refused.is_error, Some(true));
        assert_eq!(
            std::fs::read(entity_draft_file(&state, id, 1)).unwrap(),
            original
        );
        let read = entity_draft_ok(
            &entity_draft_http(&state, "kin_draft_read", serde_json::json!({"draft_id":id})).await,
        );
        assert_eq!(read["body"], "original acknowledged text");
        let listed = entity_draft_ok(
            &entity_draft_http(&state, "kin_draft_list", serde_json::json!({})).await,
        );
        assert_eq!(listed["drafts"].as_array().unwrap().len(), 1);
        drop(guard);
    }
    let retry = entity_draft_ok(&entity_draft_http(&state, "kin_draft_save", save).await);
    assert_eq!(retry["draft"]["revision"], 2);
    assert_eq!(retry["draft"]["body"], "new text");
    assert_eq!(
        std::fs::read(entity_draft_file(&state, id, 1)).unwrap(),
        original
    );
}
