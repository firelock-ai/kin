// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[cfg(unix)]
fn canonical_ready_mode(state: &DaemonState, mode: &str) {
    state
        .filesystem_reconcile_disabled
        .store(mode == "disabled", Ordering::Relaxed);
    if mode == "bare" {
        let root = state.layout.working_dir();
        std::fs::write(root.join("config"), "[core]\n\tbare = true\n").unwrap();
        std::fs::create_dir_all(root.join("objects")).unwrap();
        std::fs::create_dir_all(root.join("refs")).unwrap();
        assert!(is_bare_repository(root));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn canonical_ready_waits_for_real_cas_repair_in_watched_disabled_and_bare_modes() {
    for mode in ["watched", "disabled", "bare"] {
        let (_repo, state, target, changed) = graph_only_repair_fixture().await;
        canonical_ready_mode(&state, mode);
        let tree = state.graph.resolved_tree();
        let gate = state.coordination_gate.lock().await;
        let (cancel, receiver) = tokio::sync::watch::channel(false);
        let (watch_tx, watch_rx) = tokio::sync::oneshot::channel();
        let (canonical_tx, mut canonical_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_loop_armed(
            Arc::clone(&state),
            LoopConfig::default(),
            receiver.clone(),
            Some(WatchArmed::with_canonical_ready(watch_tx, canonical_tx)),
        ));
        let watch = crate::daemon::await_watch_armed(watch_rx, Duration::from_secs(10)).await;
        assert_eq!(
            watch,
            if mode == "watched" {
                crate::daemon::WatchArming::Armed
            } else {
                crate::daemon::WatchArming::LoopGone
            },
            "watch registration has its own boundary in {mode}"
        );
        assert_eq!(
            canonical_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty),
            "watch readiness must not certify blocked canonical repair in {mode}"
        );
        assert_eq!(
            state
                .graph
                .get_entity(&target)
                .unwrap()
                .unwrap()
                .span
                .unwrap()
                .start_line,
            0
        );
        drop(gate);
        tokio::time::timeout(
            Duration::from_secs(10),
            crate::daemon::await_canonical_ready(canonical_rx, receiver),
        )
        .await
        .unwrap()
        .unwrap();
        cancel.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let repaired = state.graph.get_entity(&target).unwrap().unwrap();
        assert_eq!(repaired.span.unwrap().start_line, 1, "{mode}");
        assert_eq!(
            repaired.metadata.extra["blob_hash"],
            kin_blobs::digest(&changed).to_string()
        );
        assert!(state
            .graph
            .get_file_layout(&FilePathId::new("canonical.rs"))
            .unwrap()
            .is_some());
        assert_eq!(state.graph.resolved_tree(), tree);
        let reconciler = state.reconciler.read().await;
        let file = FilePathId::new("canonical.rs");
        assert_eq!(
            reconciler.projection().get_content(&file),
            Some(changed.as_slice()),
            "canonical readiness must restore editable source bytes in {mode}"
        );
        assert!(
            reconciler
                .projection()
                .get_layout(&file)
                .unwrap()
                .regions
                .iter()
                .any(|region| matches!(region, kin_model::SourceRegion::EntityRef { entity_id, .. } if *entity_id == target)),
            "restored editable layout must retain canonical entity identity in {mode}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn canonical_ready_refuses_missing_cas_in_watched_disabled_and_bare_modes() {
    for mode in ["watched", "disabled", "bare"] {
        let (_repo, state, target, changed) = graph_only_repair_fixture().await;
        canonical_ready_mode(&state, mode);
        state.blobs.delete(&kin_blobs::digest(&changed)).unwrap();
        let (_cancel, receiver) = tokio::sync::watch::channel(false);
        let (watch_tx, watch_rx) = tokio::sync::oneshot::channel();
        let (canonical_tx, canonical_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_loop_armed(
            Arc::clone(&state),
            LoopConfig::default(),
            receiver.clone(),
            Some(WatchArmed::with_canonical_ready(watch_tx, canonical_tx)),
        ));
        let watch = crate::daemon::await_watch_armed(watch_rx, Duration::from_secs(10)).await;
        assert!(matches!(
            watch,
            crate::daemon::WatchArming::Armed | crate::daemon::WatchArming::LoopGone
        ));
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            crate::daemon::await_canonical_ready(canonical_rx, receiver),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(
            error.contains("canonical startup repair is incomplete"),
            "{mode}: {error}"
        );
        assert!(tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert_eq!(
            state
                .graph
                .get_entity(&target)
                .unwrap()
                .unwrap()
                .span
                .unwrap()
                .start_line,
            0
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn canonical_ready_cancellation_does_not_certify_blocked_repair() {
    let (_repo, state, target, _) = graph_only_repair_fixture().await;
    let gate = state.coordination_gate.lock().await;
    let (cancel, receiver) = tokio::sync::watch::channel(false);
    let (watch_tx, watch_rx) = tokio::sync::oneshot::channel();
    let (canonical_tx, canonical_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig::default(),
        receiver.clone(),
        Some(WatchArmed::with_canonical_ready(watch_tx, canonical_tx)),
    ));
    assert_eq!(
        crate::daemon::await_watch_armed(watch_rx, Duration::from_secs(10)).await,
        crate::daemon::WatchArming::LoopGone
    );
    cancel.send(true).unwrap();
    assert!(tokio::time::timeout(
        Duration::from_secs(5),
        crate::daemon::await_canonical_ready(canonical_rx, receiver)
    )
    .await
    .unwrap()
    .is_err());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(gate);
    assert_eq!(
        state
            .graph
            .get_entity(&target)
            .unwrap()
            .unwrap()
            .span
            .unwrap()
            .start_line,
        0
    );
}

#[tokio::test]
async fn canonical_ready_closed_loop_is_refusal_not_readiness() {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let (_cancel, cancellation) = tokio::sync::watch::channel(false);
    drop(sender);
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        crate::daemon::await_canonical_ready(receiver, cancellation),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        error.contains("loop ended before canonical repair completed"),
        "{error}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn canonical_ready_remote_backend_does_not_acquire_local_repair_authority() {
    let (_repo, mut state, target, _) = graph_only_repair_fixture().await;
    let remote = tempfile::tempdir().unwrap();
    Arc::get_mut(&mut state).unwrap().storage_backend =
        Some(Arc::new(kin_db::LocalFileBackend::new(remote.path())));
    let before = state.graph.get_entity(&target).unwrap().unwrap();
    let (cancel, receiver) = tokio::sync::watch::channel(false);
    let (watch_tx, watch_rx) = tokio::sync::oneshot::channel();
    let (canonical_tx, canonical_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig::default(),
        receiver.clone(),
        Some(WatchArmed::with_canonical_ready(watch_tx, canonical_tx)),
    ));
    assert_eq!(
        crate::daemon::await_watch_armed(watch_rx, Duration::from_secs(5)).await,
        crate::daemon::WatchArming::LoopGone
    );
    tokio::time::timeout(
        Duration::from_secs(5),
        crate::daemon::await_canonical_ready(canonical_rx, receiver),
    )
    .await
    .unwrap()
    .unwrap();
    cancel.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(state.graph.get_entity(&target).unwrap(), Some(before));
    assert_eq!(std::fs::read_dir(remote.path()).unwrap().count(), 0);
}
