// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

fn entity_patch_operation(source: &serde_json::Value, edits: &[(&str, &str)]) -> serde_json::Value {
    serde_json::json!({
        "verb":"patch", "target":source["id"], "description":"exact anchored entity edit",
        "payload":{"EntitySourcePatch":{
            "source_base":source["source_base"],
            "edits":edits.iter().map(|(old,new)| serde_json::json!({"old_text":old,"new_text":new})).collect::<Vec<_>>()
        }}
    })
}

async fn entity_patch_read(
    state: &Arc<DaemonState>,
    entity_id: &serde_json::Value,
) -> serde_json::Value {
    let result = mcp_call(
        router(Arc::clone(state)),
        "get_entity_source",
        serde_json::json!({"entity_id":entity_id}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    tool_result_payload(&result)
}

#[tokio::test]
#[serial_test::serial]
async fn entity_patch_mutate_publishes_exact_source_and_recovers_keyed_receipt() {
    let (dir, state, source) = source_base_fixture().await;
    let session = mcp_test_session(&state);
    let request = serde_json::json!({"session_id":session,"request_id":"anchored-edit",
        "operations":[entity_patch_operation(&source,&[("{ 1 }","{ 2 }")])],"summary":"Change the entity through an exact anchor"});
    let result = mutate_http(&state, "kin_mutate", request.clone(), &session).await;
    let receipt = mutation_receipt(&result);
    assert_eq!(receipt["ops_applied"], 1);
    assert_eq!(
        entity_patch_read(&state, &source["id"]).await["body"],
        SOURCE_BASE_EDIT
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("src/value.rs")).unwrap(),
        SOURCE_BASE_ORIGINAL.replacen("{ 1 }", "{ 2 }", 1)
    );
    source_base_commit_fresh(
        &state,
        &source["id"],
        "pub fn value() -> u8 { 3 }",
        "later change",
    )
    .await;
    let later_roots = source_base_roots(&state);
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let replay = mutate_http(&reopened, "kin_mutate", request, &session).await;
    assert_eq!(mutation_receipt(&replay), receipt);
    assert_eq!(tool_result_payload(&replay)["already_applied"], true);
    assert_eq!(source_base_roots(&reopened), later_roots);
    assert_eq!(
        entity_patch_read(&reopened, &source["id"]).await["body"],
        "pub fn value() -> u8 { 3 }"
    );
}

#[tokio::test]
async fn entity_patch_original_utf8_anchors_and_same_file_entities_commit_atomically() {
    let (dir, state, source) = source_base_fixture().await;
    let body = "pub fn value() -> u8 { let text = \"café\"; let a = 1; let b = 2; a + b }";
    source_base_commit_fresh(&state, &source["id"], body, "prepare multiple anchors").await;
    let source = entity_patch_read(&state, &source["id"]).await;
    let sibling = state
        .graph
        .query_entities(&kin_model::EntityFilter {
            name_pattern: Some("sibling".into()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|e| e.name == "sibling")
        .unwrap();
    let sibling = entity_patch_read(&state, &serde_json::json!(sibling.id)).await;
    assert_eq!(
        source["source_base"]["context"],
        sibling["source_base"]["context"]
    );
    let session = mcp_test_session(&state);
    let tx = mcp_lifecycle_begin(&state, &session).await;
    let result = mcp_call(
        router(Arc::clone(&state)),
        "kin_transaction_commit",
        serde_json::json!({"transaction_id":tx,"operations":[
            entity_patch_operation(&source,&[("1","2"),("2","3"),("café","😀")]),
            entity_patch_operation(&sibling,&[("{ 8 }","{ 9 }")])
        ]}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    let expected = body
        .replace("1", "2")
        .replace("let b = 2", "let b = 3")
        .replace("café", "😀");
    assert_eq!(
        entity_patch_read(&state, &source["id"]).await["body"],
        expected
    );
    assert_eq!(
        entity_patch_read(&state, &sibling["id"]).await["body"],
        "pub fn sibling() -> u8 { 9 }"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("src/value.rs")).unwrap(),
        format!("{expected}\npub fn sibling() -> u8 {{ 9 }}\n")
    );
}

#[tokio::test]
#[serial_test::serial]
async fn entity_patch_stale_mutation_retains_anchors_without_publication() {
    let (dir, state, source) = source_base_fixture().await;
    let operation = entity_patch_operation(&source, &[("{ 1 }", "{ 2 }")]);
    source_base_commit_fresh(
        &state,
        &source["id"],
        "pub fn value() -> u8 { 9 }",
        "concurrent edit",
    )
    .await;
    let before = source_base_roots(&state);
    let disk = std::fs::read(dir.path().join("src/value.rs")).unwrap();
    let session = mcp_test_session(&state);
    let result=mutate_http(&state,"kin_mutate",serde_json::json!({"session_id":session,"request_id":"stale-patch","operations":[operation.clone()]}),&session).await;
    assert_eq!(result.is_error, Some(true));
    assert!(
        kin_mcp::source_base::is_source_base_conflict(&mcp_result_text(&result)),
        "{}",
        mcp_result_text(&result)
    );
    assert_eq!(source_base_roots(&state), before);
    assert_eq!(
        std::fs::read(dir.path().join("src/value.rs")).unwrap(),
        disk
    );
    let tx = tool_result_payload(&result)["transaction_id"]
        .as_str()
        .unwrap()
        .to_string();
    let reopened = DaemonState::open(state.layout.clone()).unwrap();
    let retained = reopened.mcp_transactions.lock().unwrap();
    assert_eq!(retained[&tx].state, "active");
    assert!(retained[&tx].commit_payload_hash.is_none());
    assert_eq!(
        serde_json::to_value(&retained[&tx].staged_operations[0]).unwrap()["payload"],
        operation["payload"]
    );
    assert_eq!(source_base_roots(&reopened), before);
}

#[tokio::test]
async fn entity_patch_refusals_leave_batch_graph_tree_and_projection_unchanged() {
    for refusal in [
        "missing",
        "ambiguous",
        "overlap",
        "duplicate-entity",
        "semantic-identity",
    ] {
        let (dir, state, source) = source_base_fixture().await;
        let sibling = state
            .graph
            .query_entities(&kin_model::EntityFilter {
                name_pattern: Some("sibling".into()),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .find(|e| e.name == "sibling")
            .unwrap();
        let sibling = entity_patch_read(&state, &serde_json::json!(sibling.id)).await;
        let first = entity_patch_operation(&source, &[("{ 1 }", "{ 2 }")]);
        let second = match refusal {
            "missing" => entity_patch_operation(&sibling, &[("absent", "new")]),
            "ambiguous" => entity_patch_operation(&sibling, &[("u", "v")]),
            "overlap" => entity_patch_operation(&sibling, &[("-> u8", "-> u16"), ("u8", "i8")]),
            "duplicate-entity" => entity_patch_operation(&source, &[("{ 1 }", "{ 3 }")]),
            _ => entity_patch_operation(&sibling, &[("sibling", "renamed")]),
        };
        let session = mcp_test_session(&state);
        let tx = mcp_lifecycle_begin(&state, &session).await;
        let staged = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_stage",
            serde_json::json!({"transaction_id":tx,"operations":[first,second]}),
        )
        .await;
        assert_ne!(
            staged.is_error,
            Some(true),
            "{refusal}: {}",
            mcp_result_text(&staged)
        );
        let before = source_base_roots(&state);
        let disk = std::fs::read(dir.path().join("src/value.rs")).unwrap();
        let result = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_commit",
            serde_json::json!({"transaction_id":tx}),
        )
        .await;
        assert_eq!(
            result.is_error,
            Some(true),
            "{refusal}: {}",
            mcp_result_text(&result)
        );
        let expected = match refusal {
            "missing" => "absent",
            "duplicate-entity" => "edited more than once",
            "semantic-identity" => "create or remove",
            other => other,
        };
        assert!(
            mcp_result_text(&result).contains(expected),
            "{refusal}: {}",
            mcp_result_text(&result)
        );
        assert_eq!(source_base_roots(&state), before, "{refusal}");
        assert_eq!(
            std::fs::read(dir.path().join("src/value.rs")).unwrap(),
            disk,
            "{refusal}"
        );
        assert_eq!(
            entity_patch_read(&state, &source["id"]).await["body"],
            source["body"],
            "{refusal}"
        );
        assert_eq!(
            entity_patch_read(&state, &sibling["id"]).await["body"],
            sibling["body"],
            "{refusal}"
        );
        let reopened = DaemonState::open(state.layout.clone()).unwrap();
        assert_eq!(source_base_roots(&reopened), before, "{refusal}");
    }
}

#[tokio::test]
async fn entity_patch_noop_and_unknown_fields_refuse_before_staging() {
    let (_dir, state, source) = source_base_fixture().await;
    let before = source_base_roots(&state);
    for shape in [
        "noop",
        "empty-anchor",
        "empty-edits",
        "unknown",
        "missing-base",
        "wrong-target",
    ] {
        let mut operation = entity_patch_operation(&source, &[("{ 1 }", "{ 2 }")]);
        match shape {
            "noop" => {
                operation["payload"]["EntitySourcePatch"]["edits"][0]["new_text"] =
                    serde_json::json!("{ 1 }")
            }
            "empty-anchor" => {
                operation["payload"]["EntitySourcePatch"]["edits"][0]["old_text"] =
                    serde_json::json!("")
            }
            "empty-edits" => {
                operation["payload"]["EntitySourcePatch"]["edits"] = serde_json::json!([])
            }
            "unknown" => {
                operation["payload"]["EntitySourcePatch"]["edits"][0]["offset"] =
                    serde_json::json!(0)
            }
            "missing-base" => {
                operation["payload"]["EntitySourcePatch"]
                    .as_object_mut()
                    .unwrap()
                    .remove("source_base");
            }
            _ => operation["target"] = serde_json::json!(kin_model::EntityId::new()),
        }
        let session = mcp_test_session(&state);
        let tx = mcp_lifecycle_begin(&state, &session).await;
        let result = mcp_call(
            router(Arc::clone(&state)),
            "kin_transaction_stage",
            serde_json::json!({"transaction_id":tx,"operations":[operation]}),
        )
        .await;
        assert_eq!(
            result.is_error,
            Some(true),
            "{shape}: {}",
            mcp_result_text(&result)
        );
        assert!(
            state.mcp_transactions.lock().unwrap()[&tx]
                .staged_operations
                .is_empty(),
            "{shape}"
        );
        assert_eq!(source_base_roots(&state), before, "{shape}");
    }
}
