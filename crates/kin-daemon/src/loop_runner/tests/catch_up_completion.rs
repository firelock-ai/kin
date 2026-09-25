// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Reproduction of the staleness-decay study's catch-up stop
// (`proof-20260917/studies/05-staleness-decay`, `logs/catchup-c942.json`): a
// working tree that moved far ahead of the graph while nothing watched, with
// more known-directory changes than one batch admits and part of the delta
// sitting under a directory the graph has never met. Included into
// `loop_runner::tests`.
//
// The never-met-directory delta was originally left declined here, disclosed
// as `waiting_deferred` rather than silently swept in
// (`the_catch_up_declines_a_directory_the_graph_has_never_met` in the parent
// module still proves `plan_catch_up_events` itself declines it). This test
// now proves the daemon's OTHER half admits that same content instead of
// leaving it to `kin admit`; see `catch_up_admits_a_directory_the_graph_has_never_met`
// below for the focused version of that proof, including the entity and the
// provenance record this one does not re-check.

/// The known-directory delta must still reach the full count the ordinary
/// catch-up owns, however many batches it takes. The new-directory delta
/// crosses the same boundary it always has (modification time cannot tell a
/// clone or a move from authored work for a directory arriving whole), but
/// that boundary now gates which MECHANISM admits the content rather than
/// whether it is admitted at all: the never-met-directory sweep admits it
/// under its own provenance instead of the ordinary modified-since window,
/// and the reconcile pass settles on `idle` once both halves have drained,
/// rather than latching onto `waiting_deferred` for content this fix now
/// takes automatically.
#[tokio::test]
async fn catch_up_admits_every_known_directory_path_across_several_batches_and_the_never_met_directory_besides(
) {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);

    // A directory the graph already knows, so its own catch-up is bounded by
    // the OTHER rule (drift, not sweep-in) and by nothing else.
    let known_dir = repo.path().join("known");
    std::fs::create_dir_all(&known_dir).unwrap();
    for i in 0..3 {
        let path = known_dir.join(format!("file_{i}.rs"));
        std::fs::write(&path, format!("pub fn f_{i}() -> u32 {{ {i} }}\n")).unwrap();
        admit_file_event_ambient(&state, &FileEvent::Changed(path)).unwrap();
    }
    assert!(
        tree_entry(&state, "known/file_0.rs").is_some(),
        "the fixture needs a directory the graph already knows before the window opens"
    );

    // Everything at or after this instant is the stretch nothing was
    // watching, the window `startup_catch_up_window` reads from the marker.
    let window = chrono::DateTime::from_timestamp(2_000_000, 0).unwrap();
    kin_core::last_admission::write(
        &state.layout,
        &kin_core::last_admission::LastAdmission::new(window, 3),
    )
    .unwrap();
    let after = SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000);

    // More known-directory edits than one batch of 2 admits, so the catch-up
    // needs several ticks to reach the full count -- the "exceeds one
    // cycle's worth" half of the reproduction.
    for i in 3..8 {
        let path = known_dir.join(format!("file_{i}.rs"));
        std::fs::write(&path, format!("pub fn f_{i}() -> u32 {{ {i} }}\n")).unwrap();
        stamp_modified(&path, after);
    }

    // A directory the graph has never met -- the same boundary, and the
    // staleness-decay study's actual 360-file gap in miniature.
    let arrived = repo.path().join("arrived_whole");
    std::fs::create_dir_all(&arrived).unwrap();
    let carried = arrived.join("carried.rs");
    std::fs::write(&carried, b"pub fn carried() -> u32 { 1 }\n").unwrap();
    stamp_modified(&carried, after);

    // The native watcher backend can report a create for a path written just
    // before it registers, folding it into ordinary live admission instead of
    // the startup catch-up this test means to exercise. A real pull settles on
    // disk long before a daemon next starts against it; this margin gives a
    // backend's own startup coalescing the same room without leaning on a
    // fixed sleep being long enough by luck.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
    let mut runner = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig {
            poll_interval_ms: 10,
            batch_size: 2,
        },
        cancel_rx,
        Some(WatchArmed::new(armed_tx)),
    ));
    crate::daemon::await_watch_armed(armed_rx, Duration::from_secs(5)).await;

    let reconcile_pass_state = |state: &DaemonState| -> Option<String> {
        state
            .background_work
            .reports(Instant::now())
            .into_iter()
            .find(|report| report.name == crate::background_work::PASS_RECONCILE)
            .map(|report| report.state)
    };

    // Wait for the known-directory catch-up to fully drain across its
    // several batches and for the tick that empties `pending_events` to
    // publish whatever the pass reports next.
    let settled = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let status = state.reconciliation_status.load(Ordering::Relaxed);
            let caught_up = tree_entry(&state, "known/file_7.rs").is_some();
            if caught_up && status != RECON_PROCESSING {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "the multi-batch known-directory catch-up must finish inside the timeout"
    );

    for i in 3..8 {
        assert!(
            tree_entry(&state, &format!("known/file_{i}.rs")).is_some(),
            "every known-directory path the catch-up owns must reach the full count, however \
             many batches it takes: file_{i}.rs"
        );
    }
    // The never-met-directory sweep runs beside the ordinary catch-up above,
    // on its own clock, so it may still be one tick behind the known-directory
    // batches this loop just finished draining; give it a short, bounded
    // window rather than asserting on the instant above.
    let admitted = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if tree_entry(&state, "arrived_whole/carried.rs").is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        admitted.is_ok(),
        "a directory the graph has never met is admitted by the catch-up sweep instead of being \
         left to `kin admit` (this is the staleness-decay study's stop: idle with 360 of 1,403 \
         files still outstanding, now taken automatically instead)"
    );

    // Once both halves of catch-up have drained, the pass has nothing left to
    // report and settles on `idle` rather than latching onto
    // `waiting_deferred`, which is the signal this same content used to leave
    // standing.
    let settled = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if reconcile_pass_state(&state).as_deref() == Some("idle") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "the reconcile pass must settle on idle once the never-met directory is admitted, not \
         latch onto waiting_deferred; last seen state: {:?}",
        reconcile_pass_state(&state)
    );
    assert_eq!(
        state.reconciliation_status_str(),
        "idle",
        "the status word stays idle throughout, matching \
         an_idle_loop_that_stopped_with_work_outstanding_says_so_and_names_the_command in \
         kin-mcp: two lifecycle callers already branch on it"
    );
    let report = state.background_work.reconcile().report(Instant::now());
    assert_eq!(
        report.untracked_path_count, 0,
        "nothing should still be disclosed as outstanding once catch-up's own sweep has admitted \
         the directory it used to decline: {report:?}"
    );

    cancel_tx.send(true).ok();
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut runner).await;
    if joined.is_err() {
        runner.abort();
        let _ = runner.await;
    }
    assert!(joined.is_ok(), "the owned loop must stop after cancellation");
    joined.unwrap().unwrap().unwrap();
}

/// This fix's own subject, isolated from the companion test's multi-batch
/// stress: a directory graph truth has never met is admitted, with no live
/// edit and no `kin admit`, its entity addressable through the store, the
/// pass settled on `idle` rather than latched onto `waiting_deferred`, and
/// the admission's own provenance recorded.
///
/// Shares the companion test's fixture shape -- a directory graph truth
/// already knows, and one it has never met, both inside the startup
/// catch-up window -- but does not need that test's multi-batch stress,
/// since this fix does not change how many batches ordinary catch-up takes;
/// it only changes what happens to the population that window was never
/// allowed to touch.
#[tokio::test]
async fn catch_up_admits_a_directory_the_graph_has_never_met() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);

    // A directory the graph already knows, purely as a baseline: the fixture
    // must have SOME admitted content before a "last complete admission"
    // marker naming an instant makes sense.
    let known_dir = repo.path().join("known");
    std::fs::create_dir_all(&known_dir).unwrap();
    let known_file = known_dir.join("file_0.rs");
    std::fs::write(&known_file, b"pub fn f_0() -> u32 { 0 }\n").unwrap();
    admit_file_event_ambient(&state, &FileEvent::Changed(known_file)).unwrap();

    let window = chrono::DateTime::from_timestamp(2_000_000, 0).unwrap();
    kin_core::last_admission::write(
        &state.layout,
        &kin_core::last_admission::LastAdmission::new(window, 1),
    )
    .unwrap();
    let after = SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000);

    // A pull's worth of a directory the graph has never met: the same
    // the staleness-decay shape, this fix's own subject.
    let arrived = repo.path().join("arrived_whole");
    std::fs::create_dir_all(&arrived).unwrap();
    let carried = arrived.join("carried.rs");
    std::fs::write(&carried, b"pub fn carried() -> u32 { 1 }\n").unwrap();
    stamp_modified(&carried, after);

    // See the companion test for why this margin exists: it keeps the native
    // watcher backend's own startup coalescing from folding this write into
    // ordinary ambient admission, which would exercise a different path than
    // the startup catch-up this test means to prove.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
    let mut runner = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig {
            poll_interval_ms: 10,
            batch_size: 2,
        },
        cancel_rx,
        Some(WatchArmed::new(armed_tx)),
    ));
    crate::daemon::await_watch_armed(armed_rx, Duration::from_secs(5)).await;

    let reconcile_pass_state = |state: &DaemonState| -> Option<String> {
        state
            .background_work
            .reports(Instant::now())
            .into_iter()
            .find(|report| report.name == crate::background_work::PASS_RECONCILE)
            .map(|report| report.state)
    };

    // Addressable through the store: not just a tree entry, but the entity a
    // real reader would go looking for, with no live edit after startup and
    // no explicit `kin admit`.
    let carried_file_id = FilePathId::new("arrived_whole/carried.rs");
    let entity_admitted = |state: &DaemonState| -> bool {
        tree_entry(state, "arrived_whole/carried.rs").is_some()
            && state
                .graph
                .list_all_entities()
                .map(|entities| {
                    entities.iter().any(|entity| {
                        entity.file_origin.as_ref() == Some(&carried_file_id)
                            && entity.name == "carried"
                            && entity.kind == kin_model::EntityKind::Function
                    })
                })
                .unwrap_or(false)
    };
    let admitted = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if entity_admitted(&state) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        admitted.is_ok(),
        "a directory this graph has never met must be admitted by startup catch-up on its own, \
         with its entity addressable through the store; last seen tree entry: {:?}",
        tree_entry(&state, "arrived_whole/carried.rs")
    );

    // The known-directory baseline must still be admitted too: this fix adds
    // a population, it does not take one away.
    assert!(
        tree_entry(&state, "known/file_0.rs").is_some(),
        "ordinary catch-up's own population must still be admitted"
    );

    // Reconciliation runs to completion on its own: the pass settles on
    // `idle`, never latching onto `waiting_deferred` for content this fix now
    // admits, and the disclosure this pass would otherwise still owe reads
    // zero.
    let settled = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let status = state.reconciliation_status.load(Ordering::Relaxed);
            if status != RECON_PROCESSING && reconcile_pass_state(&state).as_deref() == Some("idle")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "reconciliation must reach a settled idle state without a manual re-ingest; last seen \
         pass state: {:?}",
        reconcile_pass_state(&state)
    );
    let report = state.background_work.reconcile().report(Instant::now());
    assert_eq!(
        report.untracked_path_count, 0,
        "nothing should still be disclosed as outstanding once the never-met directory is \
         admitted: {report:?}"
    );

    // Provenance: a durable record names the admitted path under the new
    // word, distinguishing this bulk sweep-in from an ordinary watched edit.
    let marker_path = catch_up_arrival_marker_path(&state);
    let marker_bytes = std::fs::read(&marker_path).unwrap_or_else(|error| {
        panic!("the catch-up arrival marker must be written at {marker_path:?}: {error}")
    });
    let recorded: Vec<String> = serde_json::from_slice(&marker_bytes).unwrap();
    assert!(
        recorded.iter().any(|path| path.contains("carried.rs")),
        "the arrival marker must record the admitted path under provenance {:?}: {recorded:?}",
        CATCH_UP_ARRIVAL_PROVENANCE
    );

    cancel_tx.send(true).ok();
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut runner).await;
    if joined.is_err() {
        runner.abort();
        let _ = runner.await;
    }
    assert!(joined.is_ok(), "the owned loop must stop after cancellation");
    joined.unwrap().unwrap().unwrap();
}
