// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// A watcher round whose events name bytes the daemon already holds. Included
// into `loop_runner::tests`.

/// The reconcile pass's persisted-progress count.
#[cfg(unix)]
fn reconcile_progress(state: &DaemonState) -> u64 {
    state
        .background_work
        .reports(Instant::now())
        .into_iter()
        .find(|report| report.name == crate::background_work::PASS_RECONCILE)
        .map(|report| report.progress)
        .unwrap_or(0)
}

/// Wait until the loop has settled: idle, with no writer holding the graph,
/// and the authority epoch unchanged across a few polls.
#[cfg(unix)]
async fn settled_epoch(state: &DaemonState) -> u64 {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut last = None;
        let mut steady = 0;
        loop {
            let idle = state.reconciliation_status.load(Ordering::Relaxed) == RECON_IDLE;
            let epoch = state.stable_graph_authority_epoch();
            if idle && epoch.is_some() && epoch == last {
                steady += 1;
                if steady >= 10 {
                    return epoch.unwrap();
                }
            } else {
                steady = 0;
            }
            last = epoch;
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("the loop settles")
}

/// Wait until the reconcile pass records progress past `before`.
#[cfg(unix)]
async fn progress_past(state: &DaemonState, before: u64) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while reconcile_progress(state) <= before {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the loop takes the watcher's event");
}

/// A write that leaves a source file holding the bytes the daemon already
/// admitted and parsed, the way a commit's own projection reaches the watcher
/// a few seconds after the commit, changes nothing. The round that takes it
/// opens no graph mutation, so the authority epoch stays where it was and a
/// language-server pass captured before it can still publish.
///
/// The control writes different bytes and shows the same watch does move the
/// epoch and does refuse that pass, so the first half is not an assertion
/// about a round that never ran.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_round_that_finds_the_bytes_already_held_leaves_the_epoch_and_a_captured_pass_valid() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    let held = "def held():\n    return 1\n";
    admit_and_derive(&state, "pkg/held.py", held);

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
    let mut runner = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig {
            poll_interval_ms: 10,
            batch_size: 16,
        },
        cancel_rx,
        Some(WatchArmed::new(armed_tx)),
    ));
    crate::daemon::await_watch_armed(armed_rx, Duration::from_secs(5)).await;

    let epoch = settled_epoch(&state).await;
    let captured = crate::daemon::lsp_publication::QueryInputs::capture(&state)
        .await
        .unwrap_or_else(|refused| panic!("a settled graph can be captured: {refused:?}"));
    let progress = reconcile_progress(&state);

    std::fs::write(repo.path().join("pkg/held.py"), held).unwrap();
    progress_past(&state, progress).await;
    assert_eq!(
        settled_epoch(&state).await,
        epoch,
        "a round that found every byte already held moved the graph authority epoch"
    );
    assert!(
        captured.current(&state).await.is_ok(),
        "a pass captured before the round must still be publishable after it"
    );

    // The control: the same watch, different bytes.
    let progress = reconcile_progress(&state);
    std::fs::write(
        repo.path().join("pkg/held.py"),
        "def held():\n    return 2\n",
    )
    .unwrap();
    progress_past(&state, progress).await;
    assert_ne!(
        settled_epoch(&state).await,
        epoch,
        "control: a round that admits a change moves the epoch"
    );
    assert!(
        captured.current(&state).await.is_err(),
        "control: a pass captured before a real change is refused as stale"
    );

    cancel_tx.send(true).ok();
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut runner).await;
    if joined.is_err() {
        runner.abort();
        let _ = runner.await;
    }
    joined.expect("the loop stops").unwrap().unwrap();
}
