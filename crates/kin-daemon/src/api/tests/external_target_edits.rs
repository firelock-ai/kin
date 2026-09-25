// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

const EXTERNAL_EDIT_IMPORTS: &str =
    "const remote = require('external-one');\nconst second = require('external-two');\n";
const EXTERNAL_EDIT_FILE: &str = "src/app.js";

async fn external_edit_initialize(state: &Arc<DaemonState>) {
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    let (cancel, receiver) = tokio::sync::watch::channel(false);
    let mut task = tokio::spawn(crate::loop_runner::run_loop(
        Arc::clone(state),
        crate::loop_runner::LoopConfig {
            poll_interval_ms: 10,
            batch_size: 64,
        },
        receiver,
    ));
    let ready = tokio::time::timeout(Duration::from_secs(10), async {
        while !state.is_initialized.load(Ordering::Relaxed)
            || state
                .graph
                .get_file_layout(&kin_model::FilePathId::new(EXTERNAL_EDIT_FILE))
                .unwrap()
                .is_none()
        {
            if task.is_finished() {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
    })
    .await;
    let _ = cancel.send(true);
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task).await;
    if joined.is_err() {
        task.abort();
        let _ = task.await;
    }
    assert!(
        matches!(ready, Ok(true)),
        "real daemon loop did not initialize: {ready:?}"
    );
    joined
        .expect("owned loop must stop")
        .expect("owned loop must join")
        .expect("startup must succeed");
}

async fn external_edit_source(
    state: &Arc<DaemonState>,
    id: kin_model::EntityId,
) -> serde_json::Value {
    let result = mcp_call(
        router(Arc::clone(state)),
        "get_entity_source",
        json!({"entity_id": id.to_string()}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    let source = tool_result_payload(&result);
    assert_eq!(source["source_base"]["schema"], "kin.entity.source_base.v1");
    source
}

fn external_edit_entity(state: &DaemonState, name: &str) -> kin_model::Entity {
    state
        .graph
        .query_entities(&kin_model::EntityFilter {
            file_path: Some(kin_model::FilePathId::new(EXTERNAL_EDIT_FILE)),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == name)
        .unwrap()
}

fn external_edit_assert_published(
    state: &DaemonState,
    source_id: kin_model::EntityId,
    module: &str,
    expected_bytes: &str,
) -> kin_model::EntityId {
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)
            .unwrap();
    let base = crate::repository_commit::load_native_commit_base(&context).unwrap();
    let source = base.graph.get_entity(&source_id).unwrap().unwrap();
    let relations = base
        .graph
        .get_relations(&source_id, &[kin_model::RelationKind::Calls])
        .unwrap();
    let external: Vec<_> = relations
        .iter()
        .filter(|relation| kin_index::is_external_import_placeholder(relation))
        .collect();
    assert_eq!(
        external.len(),
        1,
        "exactly the currently called import is linked: {relations:?}"
    );
    let relation = external[0];
    assert_eq!(relation.import_source.as_deref(), Some(module));
    let id = relation.dst.as_entity().unwrap();
    let actual = base
        .graph
        .get_entity(&id)
        .unwrap()
        .expect("published edge must have a target");
    let mut expected = kin_index::placeholder_target_entity(relation, source.language).unwrap();
    expected.created_in = actual.created_in;
    assert_eq!(actual, expected);
    assert_eq!(state.graph.get_entity(&id).unwrap(), Some(actual));
    assert_eq!(
        state
            .graph
            .get_relations(&source_id, &[kin_model::RelationKind::Calls])
            .unwrap(),
        relations
    );
    let artifact = base
        .tree
        .artifact_at_path(&kin_model::RepoPath::from_utf8(EXTERNAL_EDIT_FILE).unwrap())
        .unwrap();
    let stored = crate::repository_commit::load_native_source_blob(
        &context,
        artifact.entry.blob_identity().unwrap(),
    )
    .unwrap();
    assert_eq!(stored, expected_bytes.as_bytes());
    assert_eq!(
        std::fs::read(state.layout.working_dir().join(EXTERNAL_EDIT_FILE)).unwrap(),
        stored
    );
    id
}

#[tokio::test]
async fn external_target_entity_body_first_use_and_retarget_persist() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let original = format!("{EXTERNAL_EDIT_IMPORTS}function run() {{ return 1; }}\n");
    source_tree_conversion_fixture(
        &state,
        json!({"verb":"create", "description":"install exact source", "target":EXTERNAL_EDIT_FILE, "body":original}),
    )
    .await;
    let entity = external_edit_entity(&state, "run");
    assert!(state
        .graph
        .get_relations(&entity.id, &[kin_model::RelationKind::Calls])
        .unwrap()
        .iter()
        .all(|r| !kin_index::is_external_import_placeholder(r)));
    let before = source_base_roots(&state);
    let source = external_edit_source(&state, entity.id).await;
    let first_body = "function run() { return remote(); }";
    source_base_commit_operation(
        &state,
        json!({
            "verb":"update", "description":"edit existing source", "target":entity.id.to_string(), "body":first_body,
            "payload":{"EntitySourceBase": source["source_base"]}
        }),
    )
    .await;
    assert!(source_base_roots(&state).generation > before.generation);
    let first_bytes = format!("{EXTERNAL_EDIT_IMPORTS}{first_body}\n");
    let first_target =
        external_edit_assert_published(&state, entity.id, "external-one", &first_bytes);
    assert_eq!(
        external_edit_source(&state, entity.id).await["body"],
        first_body
    );

    let layout = state.layout.clone();
    drop(state);
    let state = Arc::new(DaemonState::open(layout).unwrap());
    external_edit_initialize(&state).await;
    assert_eq!(
        external_edit_assert_published(&state, entity.id, "external-one", &first_bytes),
        first_target
    );
    let source = external_edit_source(&state, entity.id).await;
    let second_body = "function run() { return second(); }";
    source_base_commit_operation(
        &state,
        json!({
            "verb":"update", "description":"edit existing source", "target":entity.id.to_string(), "body":second_body,
            "payload":{"EntitySourceBase": source["source_base"]}
        }),
    )
    .await;
    let second_bytes = format!("{EXTERNAL_EDIT_IMPORTS}{second_body}\n");
    let second_target =
        external_edit_assert_published(&state, entity.id, "external-two", &second_bytes);
    assert_ne!(first_target, second_target);
    assert!(
        state.graph.get_entity(&first_target).unwrap().is_some(),
        "unreferenced external targets are not source deletions"
    );
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    external_edit_initialize(&reopened).await;
    assert_eq!(
        external_edit_assert_published(&reopened, entity.id, "external-two", &second_bytes),
        second_target
    );
    assert_eq!(
        external_edit_source(&reopened, entity.id).await["body"],
        second_body
    );
}

#[tokio::test]
async fn external_target_entity_body_still_refuses_new_source_declarations() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let original = format!("{EXTERNAL_EDIT_IMPORTS}function run() {{ return 1; }}\n");
    source_tree_conversion_fixture(
        &state,
        json!({"verb":"create", "description":"install exact source", "target":EXTERNAL_EDIT_FILE, "body":original}),
    )
    .await;
    let entity = external_edit_entity(&state, "run");
    let source = external_edit_source(&state, entity.id).await;
    let before = source_base_roots(&state);
    let tx = mcp_lifecycle_begin(&state, &mcp_test_session(&state)).await;
    let result = mcp_call(
        router(Arc::clone(&state)),
        "kin_transaction_commit",
        json!({
            "transaction_id":tx,
            "operations":[{"verb":"update", "description":"edit existing source", "target":entity.id.to_string(),
                "body":"function run() { return remote(); }\nfunction added() { return 1; }",
                "payload":{"EntitySourceBase":source["source_base"]}}]
        }),
    )
    .await;
    assert_eq!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    assert!(
        mcp_result_text(&result).contains("would create or remove source entities"),
        "{}",
        mcp_result_text(&result)
    );
    assert_eq!(source_base_roots(&state), before);
    assert_eq!(
        std::fs::read_to_string(state.layout.working_dir().join(EXTERNAL_EDIT_FILE)).unwrap(),
        original
    );
    let layout = state.layout.clone();
    drop(state);
    let reopened = DaemonState::open(layout).unwrap();
    assert_eq!(source_base_roots(&reopened), before);
    assert_eq!(external_edit_entity(&reopened, "run"), entity);
}

// Model an existing pre-admission store: real parsed declarations and exact source
// are committed, but the old live path omitted external placeholders and targets.
// No graph injection occurs during rename itself.
fn external_edit_legacy_rename_fixture(state: &DaemonState, bytes: &[u8]) -> kin_model::EntityId {
    use kin_model::{
        EntityDelta, LocatedEntry, RelationDelta, RepoPath, TransactionDelta, TreeDelta, TreeEntry,
    };
    let file = kin_model::FilePathId::new(EXTERNAL_EDIT_FILE);
    let hash = state.blobs.write(bytes).unwrap();
    let kin_index::IndexedAny::EntitySource(indexed) = kin_index::IndexPipeline::new()
        .index_any_content(&file, bytes, hash)
        .unwrap()
    else {
        panic!("source fixture");
    };
    let id = indexed
        .entities
        .iter()
        .find(|e| e.name == "run")
        .unwrap()
        .id;
    let artifact_id = kin_model::ArtifactId::new();
    let linked = kin_index::link_cross_file_with_completeness(
        &[kin_index::FileParseData {
            file_path: file.0.clone(),
            entities: indexed.entities.clone(),
            relations: indexed.extracted_relations.clone(),
            imports: indexed.imports.clone(),
        }],
        &kin_index::linker::ArtifactIdentityMap::from([(file.0.clone(), artifact_id)]),
        &kin_index::FileParseCompletenessMap::from([(
            file.0.clone(),
            indexed.file_layout.parse_completeness.clone(),
        )]),
    )
    .unwrap();
    assert!(linked.iter().any(kin_index::is_external_import_placeholder));
    state
        .graph
        .apply_transaction_delta(&TransactionDelta {
            entity_deltas: indexed
                .entities
                .into_iter()
                .map(|new| EntityDelta::Added { new })
                .collect(),
            relation_deltas: linked
                .into_iter()
                .filter(|relation| !kin_index::is_external_import_placeholder(relation))
                .map(|new| RelationDelta::Added { new })
                .collect(),
            tree_deltas: vec![TreeDelta::Added {
                artifact_id,
                new: LocatedEntry::new(
                    RepoPath::from_utf8(EXTERNAL_EDIT_FILE).unwrap(),
                    TreeEntry::blob(kin_model::Hash256::from_bytes(hash.0), false),
                ),
            }],
            ..Default::default()
        })
        .unwrap();
    state
        .graph
        .upsert_file_layout(&indexed.file_layout)
        .unwrap();
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)
            .unwrap();
    let plan = crate::repository_commit::plan_native_commit(
        &state.graph,
        state.blobs.as_ref(),
        &context,
        kin_model::OperationId::new(),
        kin_model::Timestamp::now(),
        kin_model::AuthorId::new("legacy-external-fixture"),
        "Install legacy exact source without external targets".into(),
    )
    .unwrap();
    let committed = crate::repository_commit::commit_native_plan_with_projection(
        &state.layout,
        state.blobs.as_ref(),
        &context,
        plan,
    )
    .unwrap();
    state.graph.create_changes(vec![committed.change]).unwrap();
    state
        .record_repository_authority_commit(committed.receipt.generation)
        .unwrap();
    id
}

async fn external_edit_rename(
    state: &Arc<DaemonState>,
    request: &kin_cli::commands::rename::RenameRequest,
) -> kin_cli::commands::rename::RenameResponse {
    let response = router(Arc::clone(state))
        .oneshot(
            Request::post("/commands/rename")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

async fn external_edit_rename_case(mode: &str) {
    let legacy = mode != "fresh";
    let (_dir, state) = mcp_lifecycle_fixture();
    let original = "const remote = require('external-one');\nfunction run() { return remote(); }\n";
    if mode == "held_target" {
        source_tree_conversion_fixture(&state, json!({"verb":"create", "description":"admit shared external target", "target":"src/shared.js", "body":"const remote = require('external-one');\nfunction use_shared() { return remote(); }\n"})).await;
    }
    let held = state
        .graph
        .query_entities(&Default::default())
        .unwrap()
        .into_iter()
        .find(kin_index::is_external_reference_target);
    assert_eq!(held.is_some(), mode == "held_target");
    let id = if legacy {
        external_edit_legacy_rename_fixture(&state, original.as_bytes())
    } else {
        source_tree_conversion_fixture(
            &state,
            json!({"verb":"create", "description":"install exact source", "target":EXTERNAL_EDIT_FILE, "body":original}),
        )
        .await;
        external_edit_entity(&state, "run").id
    };
    // The fixture is durably committed. Rename loads that exact authority;
    // this process also holds its parser-derived coverage layouts.
    let before = source_base_roots(&state);
    if legacy {
        assert!(state
            .graph
            .get_relations(&id, &[kin_model::RelationKind::Calls])
            .unwrap()
            .is_empty());
        if mode == "missing_target" {
            assert!(state
                .graph
                .query_entities(&Default::default())
                .unwrap()
                .iter()
                .all(|e| !kin_index::is_external_reference_target(e)));
        }
    } else {
        external_edit_assert_published(&state, id, "external-one", original);
    }
    let request = kin_cli::commands::rename::RenameRequest {
        symbol: "run".into(),
        new_name: "renamed_run".into(),
        file: Some(EXTERNAL_EDIT_FILE.into()),
        line: Some(2),
        column: None,
        json: true,
        operation_id: kin_model::OperationId::new(),
        actor: kin_model::AuthorId::new("external-rename-test"),
    };
    let response = external_edit_rename(&state, &request).await;
    let report = response.report.unwrap();
    assert_eq!(report.entity_id, id);
    assert!(!report.idempotent);
    assert!(source_base_roots(&state).generation > before.generation);
    let expected = original.replace("function run()", "function renamed_run()");
    let target = external_edit_assert_published(&state, id, "external-one", &expected);
    if let Some(held) = held {
        assert_eq!(target, held.id);
        assert_eq!(
            state.graph.get_entity(&target).unwrap(),
            Some(held),
            "shared target identity/provenance must not change"
        );
    }
    assert_eq!(external_edit_entity(&state, "renamed_run").id, id);
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    external_edit_initialize(&reopened).await;
    assert_eq!(
        external_edit_assert_published(&reopened, id, "external-one", &expected),
        target
    );
    let roots = source_base_roots(&reopened);
    let replay = external_edit_rename(&reopened, &request)
        .await
        .report
        .unwrap();
    assert!(replay.idempotent);
    assert_eq!(replay.change_id, report.change_id);
    assert_eq!(source_base_roots(&reopened), roots);
}

#[tokio::test]
async fn external_target_rename_admits_legacy_missing_target() {
    external_edit_rename_case("missing_target").await;
}

#[tokio::test]
async fn external_target_rename_admits_legacy_edge_to_held_target() {
    external_edit_rename_case("held_target").await;
}

#[tokio::test]
async fn external_target_rename_preserves_fresh_mcp_target() {
    external_edit_rename_case("fresh").await;
}

#[tokio::test]
async fn external_target_cold_rename_uses_real_startup_coverage() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let original = "const remote = require('external-one');\nfunction run() { return remote(); }\n";
    let id = external_edit_legacy_rename_fixture(&state, original.as_bytes());
    let layout = state.layout.clone();
    drop(state);
    let state = Arc::new(DaemonState::open(layout).unwrap());
    assert_eq!(
        state
            .graph
            .get_file_layout(&kin_model::FilePathId::new(EXTERNAL_EDIT_FILE))
            .unwrap()
            .is_some(),
        cfg!(feature = "embeddings"),
        "embedding startup restores canonical source layouts before validating vectors"
    );
    let request = kin_cli::commands::rename::RenameRequest {
        symbol: "run".into(),
        new_name: "cold_run".into(),
        file: Some(EXTERNAL_EDIT_FILE.into()),
        line: Some(2),
        column: None,
        json: true,
        operation_id: kin_model::OperationId::new(),
        actor: kin_model::AuthorId::new("cold-rename-test"),
    };
    let response = router(Arc::clone(&state))
        .oneshot(
            Request::post("/commands/rename")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    if cfg!(feature = "embeddings") {
        // Coverage is restored during open, so a cold rename can use it before
        // the background loop runs. The loop must not repeat this publication.
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let cold: kin_cli::commands::rename::RenameResponse =
            serde_json::from_slice(&body).unwrap();
        let report = cold.report.unwrap();
        assert_eq!(report.entity_id, id);
        assert!(!report.idempotent);
        external_edit_assert_published(
            &state,
            id,
            "external-one",
            &original.replace("function run()", "function cold_run()"),
        );
    } else {
        // Without embedding startup, the background loop still owns layout
        // restoration. A populated snapshot alone cannot authorize the edit.
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(String::from_utf8_lossy(&body).contains("no graph-owned file layout"));
    }
    external_edit_initialize(&state).await;
    assert!(
        state
            .graph
            .get_file_layout(&kin_model::FilePathId::new(EXTERNAL_EDIT_FILE))
            .unwrap()
            .is_some(),
        "real startup must derive coverage from canonical CAS"
    );
    let report = external_edit_rename(&state, &request).await.report.unwrap();
    assert_eq!(report.entity_id, id);
    assert_eq!(report.idempotent, cfg!(feature = "embeddings"));
    external_edit_assert_published(
        &state,
        id,
        "external-one",
        &original.replace("function run()", "function cold_run()"),
    );
}

#[tokio::test]
async fn external_target_create_accepts_function_matching_file_basename() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let bytes = "const remote = require('external-one');\nfunction shared() { return remote(); }\n";
    source_tree_conversion_fixture(&state, json!({"verb":"create", "description":"same file and function name", "target":"src/shared.js", "body":bytes})).await;
    let source = state
        .graph
        .query_entities(&kin_model::EntityFilter {
            file_path: Some(kin_model::FilePathId::new("src/shared.js")),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|e| e.name == "shared" && e.kind == kin_model::EntityKind::Function)
        .unwrap();
    let relations = state
        .graph
        .get_relations(&source.id, &[kin_model::RelationKind::Calls])
        .unwrap();
    assert_eq!(
        relations
            .iter()
            .filter(|r| kin_index::is_external_import_placeholder(r))
            .count(),
        1
    );
}

fn external_edit_has_full_certificate(state: &DaemonState) -> bool {
    let path = kin_model::RepoPath::from_utf8(EXTERNAL_EDIT_FILE).unwrap();
    let artifact =
        kin_model::GraphNodeId::Artifact(state.graph.artifact_id_at_path(&path).unwrap());
    state
        .graph
        .traverse(&artifact, &[kin_model::RelationKind::DependsOn], 1)
        .unwrap()
        .relations
        .iter()
        .filter(|relation| relation.src == artifact && relation.dst == artifact)
        .flat_map(|relation| &relation.evidence)
        .any(|evidence| {
            evidence.parser_rule.as_deref() == Some(kin_index::CALL_SHAPE_PARSE_COVERAGE_FULL_V1)
                && evidence.source_path.as_deref() == Some(EXTERNAL_EDIT_FILE)
        })
}

#[tokio::test]
async fn external_target_broken_admission_refuses_rename_and_recovers_after_cold_reopen() {
    use kin_review::ImpactGraph;

    let (_dir, state) = mcp_lifecycle_fixture();
    let original = "const remote = require('external-one');\nfunction run() { return remote(); }\n";
    source_tree_conversion_fixture(
        &state,
        json!({"verb":"create", "description":"install exact source", "target":EXTERNAL_EDIT_FILE, "body":original}),
    )
    .await;
    let entity = external_edit_entity(&state, "run");
    let target = external_edit_assert_published(&state, entity.id, "external-one", original);
    assert!(external_edit_has_full_certificate(&state));
    assert!(
        kin_review::impact::LiveGraph(state.graph.as_ref())
            .call_shape_parse_coverage_complete()
            .unwrap()
    );

    // Exercise the same explicit file-admission route as an editor between
    // keystrokes. The semantic graph must retain useful last-known-good work
    // while withdrawing its claim that these current bytes parsed completely.
    let broken = "const remote = require('external-one');\nfunction run( {\n// incomplete editor text keeps held spans within the body\n";
    std::fs::write(state.layout.working_dir().join(EXTERNAL_EDIT_FILE), broken).unwrap();
    let (_, admitted) = admit_through_api(&router(Arc::clone(&state))).await;
    assert_eq!(admitted["report"]["admitted"], true, "{admitted}");
    assert_eq!(admitted["report"]["tree_moved"], true, "{admitted}");
    assert!(!external_edit_has_full_certificate(&state));
    assert!(
        !kin_review::impact::LiveGraph(state.graph.as_ref())
            .call_shape_parse_coverage_complete()
            .unwrap()
    );
    assert_eq!(external_edit_entity(&state, "run"), entity);
    assert!(
        kin_core::retained_parse::read(&state.layout)
            .errors_for(EXTERNAL_EDIT_FILE)
            .is_some_and(|errors| errors > 0)
    );
    commit_through_api(
        &router(Arc::clone(&state)),
        kin_model::OperationId::new(),
        "Retain incomplete editing state",
    )
    .await;
    external_edit_assert_published(&state, entity.id, "external-one", broken);

    let layout = state.layout.clone();
    drop(state);
    let state = Arc::new(DaemonState::open(layout).unwrap());
    external_edit_initialize(&state).await;
    assert!(!external_edit_has_full_certificate(&state));
    assert!(
        !kin_review::impact::LiveGraph(state.graph.as_ref())
            .call_shape_parse_coverage_complete()
            .unwrap()
    );
    let before = source_base_roots(&state);
    let request = kin_cli::commands::rename::RenameRequest {
        symbol: "run".into(),
        new_name: "recovered_run".into(),
        file: Some(EXTERNAL_EDIT_FILE.into()),
        line: Some(2),
        column: None,
        json: true,
        operation_id: kin_model::OperationId::new(),
        actor: kin_model::AuthorId::new("broken-external-rename-test"),
    };
    let response = router(Arc::clone(&state))
        .oneshot(
            Request::post("/commands/rename")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let refusal = String::from_utf8_lossy(&bytes);
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert!(refusal.contains("coverage"), "{refusal}");
    assert_eq!(source_base_roots(&state), before);
    assert_eq!(
        std::fs::read_to_string(state.layout.working_dir().join(EXTERNAL_EDIT_FILE)).unwrap(),
        broken
    );

    std::fs::write(
        state.layout.working_dir().join(EXTERNAL_EDIT_FILE),
        original,
    )
    .unwrap();
    let (_, admitted) = admit_through_api(&router(Arc::clone(&state))).await;
    assert_eq!(admitted["report"]["admitted"], true, "{admitted}");
    assert_eq!(admitted["report"]["tree_moved"], true, "{admitted}");
    commit_through_api(
        &router(Arc::clone(&state)),
        kin_model::OperationId::new(),
        "Restore complete source",
    )
    .await;
    assert!(external_edit_has_full_certificate(&state));
    assert!(
        kin_review::impact::LiveGraph(state.graph.as_ref())
            .call_shape_parse_coverage_complete()
            .unwrap()
    );
    assert_eq!(
        kin_core::retained_parse::read(&state.layout).errors_for(EXTERNAL_EDIT_FILE),
        None
    );
    let report = external_edit_rename(&state, &request).await.report.unwrap();
    assert_eq!(report.entity_id, entity.id);
    let renamed = original.replace("function run()", "function recovered_run()");
    assert_eq!(
        external_edit_assert_published(&state, entity.id, "external-one", &renamed),
        target
    );
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    external_edit_initialize(&reopened).await;
    assert!(external_edit_has_full_certificate(&reopened));
    assert_eq!(
        external_edit_assert_published(&reopened, entity.id, "external-one", &renamed),
        target
    );
    assert_eq!(
        external_edit_source(&reopened, entity.id).await["body"],
        "function recovered_run() { return remote(); }"
    );
}
