// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Reproduction of the staleness-decay study's catch-up stop
// (`proof-20260917/studies/05-staleness-decay`, `logs/catchup-c942.json`): a
// working tree that moved far ahead of the graph while nothing watched, with
// more known-directory changes than one batch admits and part of the delta
// sitting under a directory the graph has never met. Included into
// `loop_runner::tests`.

/// The known-directory delta must still reach the full count the ordinary
/// catch-up owns, however many batches it takes. The new-directory delta
/// crosses a deliberate boundary (modification time cannot tell a clone or a
/// move from authored work for a directory arriving whole) and must stay
/// unadmitted, but the reconcile pass must not describe itself as a pass with
/// nothing left to do while a fresh reading still finds it: it reports
/// `waiting_deferred`, the same signal already built for a retry ladder that
/// never converges, rather than settling into the same `idle` a truly
/// caught-up store would report. `reconciliation_status` itself is
/// deliberately left reading `idle` throughout, matching
/// `an_idle_loop_that_stopped_with_work_outstanding_says_so_and_names_the_command`
/// in kin-mcp: two lifecycle callers already branch on that word. A live edit
/// under the declined directory -- the ordinary watcher path, not the startup
/// scan -- then clears the pass back to `idle` on its own next quiet tick.
#[tokio::test]
async fn catch_up_admits_every_known_directory_path_and_the_pass_will_not_call_itself_idle_while_a_new_directory_remains(
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
    assert!(
        tree_entry(&state, "arrived_whole/carried.rs").is_none(),
        "the boundary must still hold: a directory the graph has never met is not silently \
         admitted at startup"
    );

    // The pass's deferred-work clock needs one more tick past the batch that
    // admitted the last known-directory file to read the fresh reading; give
    // it a short, bounded window rather than asserting on the instant above.
    let disclosed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if reconcile_pass_state(&state).as_deref() == Some("waiting_deferred") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        disclosed.is_ok(),
        "the reconcile pass must report waiting_deferred, not idle, while content the startup \
         scan declined is still unadmitted (this is the staleness-decay study's stop: idle with \
         360 of 1,403 files still outstanding, except now the pass says it still owes the work); \
         last seen state: {:?}",
        reconcile_pass_state(&state)
    );
    assert_eq!(
        state.reconciliation_status_str(),
        "idle",
        "the status word itself is unchanged on purpose, matching \
         an_idle_loop_that_stopped_with_work_outstanding_says_so_and_names_the_command in \
         kin-mcp: two lifecycle callers already branch on it"
    );
    let report = state.background_work.reconcile().report(Instant::now());
    assert!(
        report.untracked_path_count >= 1,
        "the disclosed count must name the outstanding content: {report:?}"
    );
    assert!(
        report
            .untracked_paths_sample
            .iter()
            .any(|path| path.contains("carried.rs")),
        "the sample must name a path an operator can act on: {report:?}"
    );

    // A live edit under the declined directory -- the ordinary watcher path,
    // which carries none of the startup scan's modification-time caution --
    // must still admit it and must clear the pass back to `idle` on this SAME
    // running loop's own next quiet tick, with no daemon restart and no
    // explicit `kin admit`.
    std::fs::write(&carried, b"pub fn carried() -> u32 { 2 }\n").unwrap();
    let cleared = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if tree_entry(&state, "arrived_whole/carried.rs").is_some()
                && reconcile_pass_state(&state).as_deref() == Some("idle")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        cleared.is_ok(),
        "admitting the declined content live must clear waiting_deferred back to idle on the \
         loop's own next quiet tick; last seen state: {:?}",
        reconcile_pass_state(&state)
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
