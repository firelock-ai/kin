// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[cfg(unix)]
async fn graph_only_repair_fixture() -> (tempfile::TempDir, Arc<DaemonState>, EntityId, Vec<u8>) {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    let host = repo.path().join("canonical.rs");
    let original = b"pub fn target() -> u32 { 7 }\n\npub fn caller() -> u32 { target() }\n";
    std::fs::write(&host, original).unwrap();
    sync_filesystem_with_graph(&state).await.unwrap();
    let target = state
        .graph
        .query_entities(&EntityFilter {
            name_pattern: Some("target".into()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == "target")
        .unwrap();
    assert!(!incoming_relations(&state, target.id).is_empty());
    let changed =
        b"// shifted\npub fn target() -> u32 { 11 }\n\npub fn caller() -> u32 { target() }\n"
            .to_vec();
    std::fs::write(&host, &changed).unwrap();
    let admission = exact_tree_admission(&state, None, TreePublication::Standalone).unwrap();
    crate::semantic_debt::record(&state, &crate::semantic_debt::owed_by(&admission.deltas));
    assert_eq!(
        state
            .graph
            .get_entity(&target.id)
            .unwrap()
            .unwrap()
            .span
            .unwrap()
            .start_line,
        0
    );
    state
        .filesystem_reconcile_disabled
        .store(true, Ordering::Relaxed);
    (repo, state, target.id, changed)
}

#[cfg(unix)]
async fn assert_graph_only_canonical_repair(startup: bool) {
    for missing in [true, false] {
        let (repo, state, target_id, changed) = graph_only_repair_fixture().await;
        let host = repo.path().join("canonical.rs");
        let divergent = b"pub fn unadmitted() -> u32 { 999 }\n";
        if missing {
            std::fs::remove_file(&host).unwrap();
        } else {
            std::fs::write(&host, divergent).unwrap();
        }
        std::fs::write(repo.path().join("untracked.rs"), b"pub fn untracked() {}\n").unwrap();
        let tree = state.graph.resolved_tree();
        let edges = incoming_relations(&state, target_id);
        let before = state.background_work.reconcile().report(Instant::now());
        if startup {
            let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
            let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(run_loop_armed(
                Arc::clone(&state),
                LoopConfig::default(),
                cancel_rx,
                Some(WatchArmed::new(armed_tx)),
            ));
            assert!(
                tokio::time::timeout(Duration::from_secs(5), armed_rx)
                    .await
                    .unwrap()
                    .is_err(),
                "graph-only startup must publish no watcher"
            );
            assert_eq!(
                state
                    .graph
                    .get_entity(&target_id)
                    .unwrap()
                    .unwrap()
                    .span
                    .unwrap()
                    .start_line,
                1,
                "graph-only readiness cannot precede canonical repair"
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            while state
                .graph
                .get_entity(&target_id)
                .unwrap()
                .unwrap()
                .span
                .unwrap()
                .start_line
                != 1
                && Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            cancel_tx.send(true).unwrap();
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        } else {
            sync_filesystem_with_graph(&state).await.unwrap();
        }
        let entity = state.graph.get_entity(&target_id).unwrap().unwrap();
        assert_eq!(
            entity.span.unwrap().start_line,
            1,
            "graph-only canonical repair must run without host admission"
        );
        assert_eq!(
            entity.metadata.extra["blob_hash"],
            kin_blobs::digest(&changed).to_string()
        );
        assert_eq!(
            state.graph.resolved_tree(),
            tree,
            "repair cannot change canonical membership or bytes"
        );
        assert_eq!(
            incoming_relations(&state, target_id),
            edges,
            "caller edges must retain stable endpoints and identity"
        );
        let after = state.background_work.reconcile().report(Instant::now());
        assert_eq!(
            after.last_admission_success_at,
            before.last_admission_success_at
        );
        assert_eq!(
            after.untracked_observed_at, before.untracked_observed_at,
            "canonical repair cannot scan the checkout"
        );
        assert!(
            !crate::semantic_debt::outstanding(&state).is_empty(),
            "only a history commit can settle this debt"
        );
        if missing {
            assert!(!host.exists(), "repair must not recreate the projection");
        } else {
            assert_eq!(std::fs::read(&host).unwrap(), divergent);
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn graph_only_local_startup_repairs_canonical_debt_without_host_admission() {
    assert_graph_only_canonical_repair(true).await;
}

#[cfg(unix)]
#[tokio::test]
async fn graph_only_local_sync_repairs_canonical_debt_without_host_admission() {
    assert_graph_only_canonical_repair(false).await;
}

#[tokio::test]
async fn graph_only_local_startup_backfills_withdrawn_artifact_without_debt() {
    assert_canonical_startup_repair_without_projection(false, true).await;
}

#[tokio::test]
async fn graph_only_local_startup_restores_unpublished_entities_without_projection() {
    assert_canonical_startup_repair_without_projection(true, true).await;
}

#[cfg(unix)]
#[tokio::test]
async fn graph_only_storage_backend_does_not_gain_local_repair_authority() {
    let (repo, mut state, target_id, _) = graph_only_repair_fixture().await;
    let backend_root = tempfile::tempdir().unwrap();
    Arc::get_mut(&mut state).unwrap().storage_backend =
        Some(Arc::new(kin_db::LocalFileBackend::new(backend_root.path())));
    std::fs::remove_file(repo.path().join("canonical.rs")).unwrap();
    let tree = state.graph.resolved_tree();
    let entity = state.graph.get_entity(&target_id).unwrap().unwrap();
    let edges = incoming_relations(&state, target_id);
    let debt = crate::semantic_debt::outstanding(&state);
    let before = state.background_work.reconcile().report(Instant::now());
    sync_filesystem_with_graph(&state).await.unwrap();
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig::default(),
        cancel_rx,
        Some(WatchArmed::new(armed_tx)),
    ));
    assert!(tokio::time::timeout(Duration::from_secs(5), armed_rx)
        .await
        .unwrap()
        .is_err());
    cancel_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let after_entity = state.graph.get_entity(&target_id).unwrap().unwrap();
    assert_eq!(
        after_entity.span, entity.span,
        "remote graph-only startup must not derive a new local graph"
    );
    assert_eq!(after_entity.metadata.extra, entity.metadata.extra);
    assert_eq!(state.graph.resolved_tree(), tree);
    assert_eq!(incoming_relations(&state, target_id), edges);
    assert_eq!(crate::semantic_debt::outstanding(&state), debt);
    let after = state.background_work.reconcile().report(Instant::now());
    assert_eq!(
        after.last_admission_success_at,
        before.last_admission_success_at
    );
    assert_eq!(after.untracked_observed_at, before.untracked_observed_at);
    assert!(!repo.path().join("canonical.rs").exists());
    assert_eq!(std::fs::read_dir(backend_root.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn graph_only_local_unreadable_canonical_debt_refuses_readiness_and_sync() {
    let (_repo, state, target_id, changed) = graph_only_repair_fixture().await;
    state.blobs.delete(&kin_blobs::digest(&changed)).unwrap();
    let error = sync_filesystem_with_graph(&state).await.unwrap_err();
    assert!(
        error.to_string().contains("semantics could not be"),
        "{error}"
    );
    let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig::default(),
        cancel_rx,
        Some(WatchArmed::new(armed_tx)),
    ));
    let readiness = crate::daemon::await_watch_armed(armed_rx, Duration::from_secs(5)).await;
    assert!(
        matches!(readiness, crate::daemon::WatchArming::Failed(ref error) if error.contains("local canonical startup repair is incomplete")),
        "{readiness:?}"
    );
    assert!(tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert_eq!(
        state
            .graph
            .get_entity(&target_id)
            .unwrap()
            .unwrap()
            .span
            .unwrap()
            .start_line,
        0
    );
    assert!(!crate::semantic_debt::outstanding(&state).is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn graph_only_local_repair_wait_is_bounded_and_cancellable_before_readiness() {
    let (_repo, state, target_id, _) = graph_only_repair_fixture().await;
    let _coordination = state.coordination_gate.lock().await;
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig::default(),
        cancel_rx,
        Some(WatchArmed::new(armed_tx)),
    ));
    assert_eq!(
        crate::daemon::await_watch_armed(armed_rx, Duration::from_millis(50)).await,
        crate::daemon::WatchArming::TimedOut,
        "blocked canonical repair cannot advertise no-watcher readiness"
    );
    cancel_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        state
            .graph
            .get_entity(&target_id)
            .unwrap()
            .unwrap()
            .span
            .unwrap()
            .start_line,
        0
    );
}
