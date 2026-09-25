// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;

#[tokio::test]
async fn cold_canonical_ready_restores_editable_source_without_pending_repair() {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    let (repo, state) = lsp_publication_fixture().await;
    let file = FilePathId::new("first.py");
    let original = state
        .graph
        .query_entities(&kin_db::EntityFilter {
            file_path: Some(file.clone()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == "first" && entity.kind == kin_model::EntityKind::Function)
        .unwrap();
    let body = b"def first():\n    return 1\n";
    let tree = state.graph.resolved_tree();
    let layout = state.layout.clone();
    drop(state);
    // An unadmitted host edit must not become the editable canonical cache.
    let unadmitted = b"def different():\n    return 900\n";
    std::fs::write(repo.path().join("first.py"), unadmitted).unwrap();
    let state = Arc::new(DaemonState::open(layout).unwrap());
    state
        .filesystem_reconcile_disabled
        .store(true, Ordering::Relaxed);
    assert!(crate::semantic_debt::outstanding(&state).is_empty());
    assert!(state
        .reconciler
        .read()
        .await
        .projection()
        .get_content(&file)
        .is_none());
    assert_eq!(
        state.graph.get_entity(&original.id).unwrap(),
        Some(original.clone())
    );
    let (cancel, receiver) = tokio::sync::watch::channel(false);
    let (watch_tx, watch_rx) = tokio::sync::oneshot::channel();
    let (canonical_tx, canonical_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(crate::loop_runner::run_loop_armed(
        Arc::clone(&state),
        crate::loop_runner::LoopConfig::default(),
        receiver.clone(),
        Some(crate::loop_runner::WatchArmed::with_canonical_ready(
            watch_tx,
            canonical_tx,
        )),
    ));
    assert_eq!(
        crate::daemon::await_watch_armed(watch_rx, Duration::from_secs(10)).await,
        crate::daemon::WatchArming::LoopGone
    );
    let ready = tokio::time::timeout(
        Duration::from_secs(10),
        crate::daemon::await_canonical_ready(canonical_rx, receiver),
    )
    .await;
    cancel.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    ready.unwrap().unwrap();
    assert_eq!(state.graph.resolved_tree(), tree);
    assert_eq!(
        state.graph.get_entity(&original.id).unwrap(),
        Some(original.clone())
    );
    assert_eq!(
        std::fs::read(repo.path().join("first.py")).unwrap(),
        unadmitted
    );
    let mut reconciler = state.reconciler.write().await;
    assert_eq!(
        reconciler.projection().get_content(&file),
        Some(body.as_slice())
    );
    assert!(
        reconciler
            .projection()
            .get_layout(&file)
            .unwrap()
            .regions
            .iter()
            .any(|region| matches!(region, kin_model::SourceRegion::EntityRef { entity_id, .. } if *entity_id == original.id)),
        "restored editable layout must carry canonical entity identity"
    );
    let mut modified = original.clone();
    modified
        .metadata
        .extra
        .insert("cold-projection-control".into(), json!(true));
    let edit = kin_model::TransactionDelta {
        entity_deltas: vec![kin_model::EntityDelta::Modified {
            old: original.clone(),
            new: modified,
        }],
        ..Default::default()
    };
    // The restored cache is canonical, so a working copy that disagrees with it
    // holds an unadmitted host edit. Projection skips that file rather than
    // overwriting bytes Kin never admitted, and the cache stays canonical.
    let (skipped, _) = reconciler
        .project_transaction_to_files(&edit, &std::collections::HashMap::new())
        .unwrap();
    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!(
        std::fs::read(repo.path().join("first.py")).unwrap(),
        unadmitted
    );
    assert_eq!(
        reconciler.projection().get_content(&file),
        Some(body.as_slice())
    );
    // With the working copy back in agreement the restored cache is editable:
    // the same transaction splices canonical bytes and rewrites the file after
    // a cold reopen, which an empty projection cache could not do.
    std::fs::write(repo.path().join("first.py"), body).unwrap();
    let (written, _) = reconciler
        .project_transaction_to_files(&edit, &std::collections::HashMap::new())
        .unwrap();
    assert_eq!(written, vec![file]);
    assert_eq!(std::fs::read(repo.path().join("first.py")).unwrap(), body);
}

#[tokio::test]
async fn completed_session_replay_preserves_fresh_lsp_lead_and_current_layouts() {
    use crate::daemon::lsp_publication::QueryInputs;
    let (_repo, state) = lsp_publication_fixture().await;
    let singleton = session_runtime_lock(&state);
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let app = router(Arc::clone(&state));
    let session = state.layout.runs_dir().join("session-completed-lsp-lead");
    materialize_session_through_api(&app, &session).await;
    std::fs::write(session.join("first.py"), b"def first():\n    return 19\n").unwrap();
    let original = reconcile_session_through_api(&app, &session).await;
    let caller = waiting_entity(&state, "caller.py", "run");
    let target = waiting_entity(&state, "target.py", "work");
    let mut relation = lsp_publication_call(caller.id, target.id);
    let span = relation.evidence[0].source_span.as_mut().unwrap();
    span.start_byte = LSP_PUBLICATION_CALLER.rfind("callback").unwrap();
    span.end_byte = span.start_byte + "callback".len();
    let inputs = QueryInputs::capture(&state).await.unwrap();
    let mut pending = crate::daemon::PendingEnrichment::default();
    inputs
        .absorb(&state, &mut pending, vec![relation.clone()])
        .await
        .unwrap();
    inputs.flush(&state, &mut pending).await.unwrap();
    assert!(state
        .graph
        .semantic_observation()
        .relations
        .contains_key(&relation.id));
    assert!(
        !lsp_publication_durable(&state)
            .relations
            .contains_key(&relation.id),
        "the test requires a valid live lead absent from durable authority"
    );
    let before = state.graph.semantic_observation();
    let before_json = state.graph.to_snapshot();
    let content_before = state
        .reconciler
        .read()
        .await
        .projection()
        .get_content(&FilePathId::new("first.py"))
        .unwrap()
        .to_vec();
    let replay = reconcile_session_through_api(&app, &session).await;
    assert!(replay.idempotent_replay);
    assert_eq!(replay.operation_id, original.operation_id);
    assert_eq!(replay.authority_generation, original.authority_generation);
    assert_eq!(
        replay.semantic_files_enriched,
        original.semantic_files_enriched
    );
    assert_session_snapshot_unchanged(&before_json, &state.graph.to_snapshot());
    assert_eq!(
        state.graph.semantic_observation().verified_binding_history,
        before.verified_binding_history
    );
    assert_eq!(
        state
            .reconciler
            .read()
            .await
            .projection()
            .get_content(&FilePathId::new("first.py"))
            .unwrap(),
        content_before.as_slice()
    );
}

#[tokio::test]
async fn historical_session_replay_preserves_later_graph_and_projection_cache() {
    let (repo, state) = lsp_publication_fixture().await;
    let singleton = session_runtime_lock(&state);
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let app = router(Arc::clone(&state));
    let session = state.layout.runs_dir().join("session-historical-receipt");
    materialize_session_through_api(&app, &session).await;
    std::fs::write(session.join("first.py"), b"def first():\n    return 19\n").unwrap();
    let original = reconcile_session_through_api(&app, &session).await;
    std::fs::write(
        repo.path().join("first.py"),
        b"def first():\n    return 23\n",
    )
    .unwrap();
    waiting_admit(&state, "newer unrelated authority than original session").await;
    waiting_commit(&state, "publish newer source before historical retry").await;
    let current_generation = state
        .snapshot_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(current_generation > original.authority_generation);
    let before = state.graph.semantic_observation();
    let before_json = state.graph.to_snapshot();
    let content_before = state
        .reconciler
        .read()
        .await
        .projection()
        .get_content(&FilePathId::new("first.py"))
        .unwrap()
        .to_vec();
    let replay = reconcile_session_through_api(&app, &session).await;
    assert!(replay.idempotent_replay);
    assert_eq!(replay.operation_id, original.operation_id);
    assert_eq!(replay.authority_generation, original.authority_generation);
    assert_eq!(replay.desired_tree_hash, original.desired_tree_hash);
    assert_eq!(
        replay.semantic_files_enriched,
        original.semantic_files_enriched
    );
    assert_eq!(
        state
            .snapshot_generation
            .load(std::sync::atomic::Ordering::SeqCst),
        current_generation
    );
    assert_session_snapshot_unchanged(&before_json, &state.graph.to_snapshot());
    assert_eq!(
        state.graph.semantic_observation().verified_binding_history,
        before.verified_binding_history
    );
    assert_eq!(
        state
            .reconciler
            .read()
            .await
            .projection()
            .get_content(&FilePathId::new("first.py"))
            .unwrap(),
        content_before.as_slice()
    );
    assert_eq!(
        std::fs::read(repo.path().join("first.py")).unwrap(),
        b"def first():\n    return 23\n"
    );
}

#[tokio::test]
async fn completed_session_changed_target_refuses_without_stopping_healthy_runtime() {
    let (_repo, state) = lsp_publication_fixture().await;
    let singleton = session_runtime_lock(&state);
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let app = router(Arc::clone(&state));
    let session = state
        .layout
        .runs_dir()
        .join("session-completed-changed-target");
    materialize_session_through_api(&app, &session).await;
    let first = b"def first():\n    return 19\n";
    std::fs::write(session.join("first.py"), first).unwrap();
    let original = reconcile_session_through_api(&app, &session).await;
    let before = state.graph.to_snapshot();
    std::fs::write(session.join("first.py"), b"def first():\n    return 999\n").unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::post("/reconcile")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"session_dir":session,"confirm_mass_deletion":false}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .unwrap();
    assert!(!status.is_success(), "{}", String::from_utf8_lossy(&body));
    assert_session_snapshot_unchanged(&before, &state.graph.to_snapshot());
    state.prepared_publication.ensure_serving().unwrap();
    std::fs::write(session.join("first.py"), first).unwrap();
    let replay = reconcile_session_through_api(&app, &session).await;
    assert!(replay.idempotent_replay);
    assert_eq!(replay.operation_id, original.operation_id);
}

#[tokio::test]
async fn fresh_session_retires_only_changed_completion_and_retained_parse_markers() {
    let (_repo, state) = lsp_publication_fixture().await;
    let singleton = session_runtime_lock(&state);
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    assert!(
        state.lsp_enrichment_tx.is_none(),
        "the test must not depend on incremental delivery"
    );
    let app = router(Arc::clone(&state));
    let session = state
        .layout
        .runs_dir()
        .join("session-retire-source-markers");
    materialize_session_through_api(&app, &session).await;
    let marked = vec![
        "first.py".to_owned(),
        "target.py".to_owned(),
        "second.py".to_owned(),
    ];
    let old_epoch = state
        .lsp_enriched_marker_epoch
        .load(std::sync::atomic::Ordering::SeqCst);
    crate::daemon::mark_files_enriched(&state, &marked, old_epoch);
    kin_core::retained_parse::record(
        &state.layout,
        &[
            kin_core::retained_parse::ObservedParse::retained("first.py", 1),
            kin_core::retained_parse::ObservedParse::retained("target.py", 1),
            kin_core::retained_parse::ObservedParse::retained("second.py", 1),
        ],
    );
    std::fs::write(session.join("first.py"), b"def first():\n    return 19\n").unwrap();
    std::fs::remove_file(session.join("target.py")).unwrap();
    reconcile_session_through_api(&app, &session).await;
    assert!(!crate::daemon::file_already_enriched(&state, "first.py"));
    assert!(!crate::daemon::file_already_enriched(&state, "target.py"));
    assert!(crate::daemon::file_already_enriched(&state, "second.py"));
    // A sweep that began before the session cannot restore its old skip.
    crate::daemon::mark_files_enriched(&state, &marked, old_epoch);
    assert!(!crate::daemon::file_already_enriched(&state, "first.py"));
    let retained = kin_core::retained_parse::read(&state.layout);
    assert_eq!(
        retained
            .paths()
            .iter()
            .map(|path| path.path.as_str())
            .collect::<Vec<_>>(),
        vec!["second.py"]
    );
    let durable = crate::daemon::decode_enriched_marker(
        &std::fs::read(state.layout.root().join("lsp-enriched-files.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(durable, vec!["second.py"]);
}

#[tokio::test]
async fn fresh_session_rewrites_disk_only_completion_markers() {
    let (_repo, state) = lsp_publication_fixture().await;
    let singleton = session_runtime_lock(&state);
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let app = router(Arc::clone(&state));
    let session = state.layout.runs_dir().join("session-disk-only-marker");
    materialize_session_through_api(&app, &session).await;
    // Match an old marker ignored at startup because its LSP evidence was lost.
    assert!(state.lsp_enriched_files.lock().unwrap().is_empty());
    let marker = state.layout.root().join("lsp-enriched-files.json");
    std::fs::write(
        &marker,
        crate::daemon::encode_enriched_marker(&["first.py".to_string(), "second.py".to_string()]),
    )
    .unwrap();
    std::fs::write(session.join("first.py"), b"def first():\n    return 19\n").unwrap();
    reconcile_session_through_api(&app, &session).await;
    let persisted =
        crate::daemon::decode_enriched_marker(&std::fs::read(&marker).unwrap()).unwrap();
    assert!(
        persisted.is_empty(),
        "unqualified disk-only markers must not become future skips"
    );
    assert!(state.lsp_enriched_files.lock().unwrap().is_empty());
}
