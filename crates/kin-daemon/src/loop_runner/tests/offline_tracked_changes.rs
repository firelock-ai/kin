// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Tracked files edited or deleted while no daemon watched, and the daemon that
// starts afterwards. Included into `loop_runner::tests`.

// Python rather than Rust on purpose: a reference read over a Rust entity
// waits on a language server this host may be cold-starting, and that wait
// is not what this case measures.
const OFFLINE_LIB_BEFORE: &str =
    "def old_name(value):\n    return value + 1\n\n\ndef caller():\n    return old_name(41)\n";
const OFFLINE_LIB_AFTER: &str =
    "def new_name(value):\n    return value + 1\n\n\ndef caller():\n    return new_name(41)\n";
const OFFLINE_DOOMED: &str = "def doomed_helper():\n    return 7\n";

/// The names graph truth holds for one file, read off the live graph.
fn offline_entity_names(state: &DaemonState, path: &str) -> BTreeSet<String> {
    state
        .graph
        .query_entities(&EntityFilter {
            file_path: Some(FilePathId::new(path)),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .map(|entity| entity.name)
        .collect()
}

/// One MCP answer as the stdio server hands it to an agent: the daemon's tool
/// result, wrapped in the envelope built from the daemon's own `/health` body.
async fn offline_enveloped_answer(
    state: &Arc<DaemonState>,
    tool: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    let health = tower::ServiceExt::oneshot(
        crate::api::router(Arc::clone(state)),
        axum::http::Request::get("/health")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(health.status(), axum::http::StatusCode::OK);
    let health: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(health.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let called = tower::ServiceExt::oneshot(
        crate::api::router(Arc::clone(state)),
        axum::http::Request::post("/mcp/tools/call")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({ "name": tool, "arguments": arguments }).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(called.status(), axum::http::StatusCode::OK);
    let result: kin_mcp::ToolCallResult = serde_json::from_slice(
        &axum::body::to_bytes(called.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let enveloped = kin_mcp::finalize_with_envelope_bounded(
        result,
        kin_mcp::Envelope::daemon().with_health(&health),
        tool,
        &kin_mcp::ResponseBudget::default(),
    );
    let kin_mcp::ContentBlock::Text { text } = &enveloped.content[0];
    serde_json::from_str(text).unwrap_or_else(|_| serde_json::json!({ "raw": text }))
}

/// Whether any block of an answer certifies that something is absent.
fn offline_certifies_an_absence(answer: &serde_json::Value) -> bool {
    let verdict = &answer["_kin"]["verdict"];
    verdict["safe_to_conclude_absent"] == serde_json::json!(true)
        || answer["negative"]["safe_to_conclude_absent"] == serde_json::json!(true)
}

/// A store whose two tracked files were edited and deleted while no daemon
/// watched: `lib.py` renames `old_name` to `new_name`, and `doomed.py` is
/// removed. The store records a complete admission before the edits, which is
/// the window a restarted daemon opens its catch-up at.
async fn offline_edited_store(repo: &tempfile::TempDir) -> Arc<DaemonState> {
    let state = open_test_state(repo);
    let src = repo.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("lib.py"), OFFLINE_LIB_BEFORE).unwrap();
    std::fs::write(src.join("doomed.py"), OFFLINE_DOOMED).unwrap();
    sync_filesystem_with_graph(&state).await.unwrap();
    state.is_initialized.store(true, Ordering::Relaxed);
    let (status, body) = startup_diagnostic_commit(&state).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(
        offline_entity_names(&state, "src/lib.py").contains("old_name")
            && offline_entity_names(&state, "src/doomed.py").contains("doomed_helper"),
        "the fixture needs both files admitted and parsed before nothing watches them"
    );
    crate::background_work::record_durable_admission(
        &state.layout,
        state.graph.resolved_tree().len() as u64,
    );
    std::fs::write(src.join("lib.py"), OFFLINE_LIB_AFTER).unwrap();
    std::fs::remove_file(src.join("doomed.py")).unwrap();
    // A native watcher backend can report a write made just before it
    // registers, which would fold these edits into ordinary live admission
    // instead of the startup catch-up this case is about. A real edit made
    // while no daemon ran settles long before the next daemon starts.
    tokio::time::sleep(Duration::from_secs(1)).await;
    state
}

/// The whole contract on one daemon start, in the order a client meets it.
///
/// Before the endpoint is published, the daemon already names the two tracked
/// files it owes, so every surface built from its report withholds its
/// all-clear from the first request. Once the catch-up lands, the old name is
/// gone, the new name is found, the deleted file is served by nothing, nothing
/// is owed, and the last-admission marker moves past the stretch nothing
/// watched. What the answers say while it is owed is the case below this one.
///
/// Breaking it: restore the startup decline of tracked paths, and the owed
/// count reads zero at readiness and the graph never learns the new name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tracked_edit_and_deletion_made_while_no_daemon_watched_are_owed_then_admitted() {
    let repo = tempfile::tempdir().unwrap();
    let state = offline_edited_store(&repo).await;
    let window_opened_at = kin_core::last_admission::read(&state.layout)
        .recorded()
        .map(|recorded| recorded.at)
        .expect("the fixture records the admission the window opens at");

    // Hold the catch-up's admission back long enough to read the report at
    // readiness; the pause is taken inside the admission, after readiness.
    let _guard = AdmissionPauseGuard;
    *ADMISSION_PAUSE_FOR_TEST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some((Arc::as_ptr(&state) as usize, Duration::from_secs(3)));

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (watch_tx, watch_rx) = tokio::sync::oneshot::channel();
    let (canonical_tx, canonical_rx) = tokio::sync::oneshot::channel();
    let mut runner = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig {
            poll_interval_ms: 10,
            batch_size: 64,
        },
        cancel_rx.clone(),
        Some(WatchArmed::with_canonical_ready(watch_tx, canonical_tx)),
    ));
    crate::daemon::await_watch_armed(watch_rx, Duration::from_secs(10)).await;
    crate::daemon::await_canonical_ready(canonical_rx, cancel_rx)
        .await
        .expect("canonical readiness is what releases the endpoint");

    // The endpoint would be published now. What a client can read already
    // names both files.
    let owed = state.background_work.reconcile().report(Instant::now());
    assert_eq!(
        owed.changed_path_count, 2,
        "readiness must not precede the record of what the catch-up owes: {owed:?}"
    );
    assert_eq!(
        owed.changed_paths_sample,
        vec!["src/doomed.py".to_string(), "src/lib.py".to_string()],
        "{owed:?}"
    );
    assert!(
        !owed.working_copy_behind_reasons().is_empty(),
        "status surfaces withhold their all-clear while the catch-up is owed: {owed:?}"
    );

    // Released by the pause elapsing. The catch-up lands and settles.
    let settled = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            // The report is read before the graph: a tick settles what it owed
            // only after it applied it, so a path the report no longer owes is
            // one the graph already reflects.
            let report = state.background_work.reconcile().report(Instant::now());
            let admitted = offline_entity_names(&state, "src/lib.py").contains("new_name");
            assert!(
                admitted
                    || report
                        .changed_paths_sample
                        .iter()
                        .any(|owed| owed == "src/lib.py"),
                "the edited file stopped being owed before the graph took its new bytes, so an \
                 answer over the old ones could certify: {report:?}"
            );
            if report.changed_path_count == 0
                && admitted
                && state.reconciliation_status.load(Ordering::Relaxed) != RECON_PROCESSING
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "the catch-up must admit what it owed; report: {:?}",
        state.background_work.reconcile().report(Instant::now())
    );

    let lib = offline_entity_names(&state, "src/lib.py");
    assert!(
        lib.contains("new_name") && !lib.contains("old_name"),
        "the edit is admitted: the new name is found and the old one is gone: {lib:?}"
    );
    assert!(
        offline_entity_names(&state, "src/doomed.py").is_empty(),
        "the deleted file serves nothing"
    );
    assert!(
        tree_entry(&state, "src/doomed.py").is_none(),
        "and its artifact left the tree"
    );
    // The same enumeration that was withheld above now names the new
    // function and nothing is owed, so nothing qualifies it. A resolved
    // reference read is left to the end-to-end suite: in this harness one
    // takes minutes, as it does in the reference-read case beside this one,
    // and that wait is not what this case measures.
    let listed = offline_enveloped_answer(
        &state,
        "semantic_search",
        serde_json::json!({ "query": "new_name" }),
    )
    .await;
    assert!(
        listed["results"]
            .as_array()
            .is_some_and(|entities| entities.iter().any(|entity| entity["name"] == "new_name")),
        "the semantic query finds the new function: {listed}"
    );
    assert!(
        !listed["_kin"]["verdict"]["limiting_factor"]
            .as_str()
            .unwrap_or_default()
            .contains("tracked_changes")
            && listed["_kin"]["behind"]["changed_paths"].is_null(),
        "nothing is owed any more, so nothing is qualified by it: {listed}"
    );
    let marker = kin_core::last_admission::read(&state.layout);
    let stamped = marker.recorded().map(|recorded| recorded.at);
    assert!(
        stamped.is_some_and(|at| at > window_opened_at),
        "the marker moves past the stretch nothing watched once the catch-up drained: \
         {marker:?}"
    );

    cancel_tx.send(true).ok();
    let joined = tokio::time::timeout(Duration::from_secs(10), &mut runner).await;
    if joined.is_err() {
        runner.abort();
        let _ = runner.await;
    }
    assert!(joined.is_ok(), "the owned loop must stop after cancellation");
}

/// What an agent is told while the catch-up is owed, asked with no admission
/// running, so no read waits on a writer and every answer is one the graph
/// gives from the bytes the host no longer holds.
///
/// The deleted file's entities are still in the graph and are served under an
/// inconclusive verdict that names the tracked files; the renamed function's
/// new name is not in the graph and is not an authoritative absence. The same
/// store with nothing owed is the control: the enumeration certifies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_while_the_catch_up_is_owed_certify_nothing() {
    let repo = tempfile::tempdir().unwrap();
    let state = offline_edited_store(&repo).await;

    let level = offline_enveloped_answer(
        &state,
        "semantic_search",
        serde_json::json!({ "query": "doomed_helper" }),
    )
    .await;
    assert!(
        !level["_kin"]["verdict"]["limiting_factor"]
            .as_str()
            .unwrap_or_default()
            .contains("tracked_changes"),
        "the control: before the plan names anything, nothing is qualified by it: {level}"
    );

    let since = startup_catch_up_window(&state).expect("the fixture records a window");
    let plan = plan_startup_catch_up(&state, since).expect("the plan runs");
    assert_eq!(plan.tracked.len(), 2, "{plan:?}");

    let doomed = offline_enveloped_answer(
        &state,
        "semantic_search",
        serde_json::json!({ "query": "doomed_helper" }),
    )
    .await;
    assert!(
        doomed["results"].as_array().is_some_and(|entities| entities
            .iter()
            .any(|entity| entity["name"] == "doomed_helper")),
        "the graph still holds the deleted file's entities, which is why the verdict matters: \
         {doomed}"
    );
    assert_eq!(
        doomed["_kin"]["verdict"]["state"], "inconclusive",
        "a file the host deleted is not served under a certified verdict: {doomed}"
    );
    assert!(
        doomed["_kin"]["verdict"]["limiting_factor"]
            .as_str()
            .unwrap_or_default()
            .contains("tracked_changes_unadmitted"),
        "and the verdict says why: {doomed}"
    );
    assert_eq!(
        doomed["_kin"]["behind"]["changed_paths"], 2,
        "the envelope counts what is owed: {doomed}"
    );

    let new_name = offline_enveloped_answer(
        &state,
        "find_references",
        serde_json::json!({ "query": "new_name", "answer_only": false }),
    )
    .await;
    assert!(
        !offline_certifies_an_absence(&new_name),
        "the renamed function's new name is not an authoritative absence while its file is \
         owed: {new_name}"
    );
}

/// A daemon that starts over a working copy nobody touched owes nothing, and
/// its answers certify exactly as before. Without this control the case above
/// is satisfied by a daemon that qualifies every answer it gives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_starting_over_an_untouched_working_copy_owes_nothing() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    let src = repo.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("lib.py"), OFFLINE_LIB_AFTER).unwrap();
    sync_filesystem_with_graph(&state).await.unwrap();
    state.is_initialized.store(true, Ordering::Relaxed);
    crate::background_work::record_durable_admission(
        &state.layout,
        state.graph.resolved_tree().len() as u64,
    );
    tokio::time::sleep(Duration::from_secs(1)).await;

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (watch_tx, watch_rx) = tokio::sync::oneshot::channel();
    let (canonical_tx, canonical_rx) = tokio::sync::oneshot::channel();
    let mut runner = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig {
            poll_interval_ms: 10,
            batch_size: 64,
        },
        cancel_rx.clone(),
        Some(WatchArmed::with_canonical_ready(watch_tx, canonical_tx)),
    ));
    crate::daemon::await_watch_armed(watch_rx, Duration::from_secs(10)).await;
    crate::daemon::await_canonical_ready(canonical_rx, cancel_rx)
        .await
        .expect("canonical readiness");
    let report = state.background_work.reconcile().report(Instant::now());
    assert_eq!(report.changed_path_count, 0, "{report:?}");
    assert!(report.changed_paths_unchecked.is_none(), "{report:?}");
    assert!(report.working_copy_behind_reasons().is_empty(), "{report:?}");

    cancel_tx.send(true).ok();
    let joined = tokio::time::timeout(Duration::from_secs(10), &mut runner).await;
    if joined.is_err() {
        runner.abort();
        let _ = runner.await;
    }
    assert!(joined.is_ok(), "the owned loop must stop after cancellation");
}

/// A marker that will not parse names no window, and the daemon says so for as
/// long as nothing has read the working copy whole.
///
/// It once recorded an admission, so the stretch since then is one nothing can
/// vouch for: the tracked edit and deletion this fixture made while no daemon
/// watched are real, and no plan can name them. At readiness the check is
/// reported as one that could not run, and an ordinary tick that lands after
/// that must not stamp the marker, or the next daemon would open its window
/// after those edits and serve their old bytes certified.
///
/// Breaking it: drop the record in the unreadable arm of
/// `startup_catch_up_window`, and readiness reports nothing unchecked; drop the
/// unchecked hold on the tick's stamp, and the live edit below writes a fresh
/// marker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_marker_is_reported_unchecked_and_holds_until_a_complete_admission() {
    let repo = tempfile::tempdir().unwrap();
    let state = offline_edited_store(&repo).await;
    // What a power loss leaves behind in a file it was writing.
    std::fs::write(state.layout.kindb_last_admission_path(), [0_u8; 64]).unwrap();
    assert!(
        matches!(
            kin_core::last_admission::read(&state.layout),
            kin_core::last_admission::LastAdmissionRead::Unreadable(_)
        ),
        "the fixture needs a marker that will not parse"
    );

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (watch_tx, watch_rx) = tokio::sync::oneshot::channel();
    let (canonical_tx, canonical_rx) = tokio::sync::oneshot::channel();
    let mut runner = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig {
            poll_interval_ms: 10,
            batch_size: 64,
        },
        cancel_rx.clone(),
        Some(WatchArmed::with_canonical_ready(watch_tx, canonical_tx)),
    ));
    crate::daemon::await_watch_armed(watch_rx, Duration::from_secs(10)).await;
    crate::daemon::await_canonical_ready(canonical_rx, cancel_rx)
        .await
        .expect("canonical readiness");
    let at_readiness = state.background_work.reconcile().report(Instant::now());
    assert!(
        at_readiness.changed_paths_unchecked.is_some()
            && !at_readiness.working_copy_behind_reasons().is_empty(),
        "an unreadable marker is a check that could not run, reported before the first \
         request: {at_readiness:?}"
    );

    // An ordinary live edit, admitted by an ordinary tick.
    std::fs::write(
        repo.path().join("src").join("live.py"),
        "def live_edit():\n    return 3\n",
    )
    .unwrap();
    let landed = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if offline_entity_names(&state, "src/live.py").contains("live_edit")
                && state.reconciliation_status.load(Ordering::Relaxed) != RECON_PROCESSING
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(landed.is_ok(), "the live edit must be admitted by a tick");
    assert!(
        matches!(
            kin_core::last_admission::read(&state.layout),
            kin_core::last_admission::LastAdmissionRead::Unreadable(_)
        ),
        "a tick that follows an unchecked startup must not stamp the marker past edits \
         nothing took"
    );
    let after_tick = state.background_work.reconcile().report(Instant::now());
    assert!(
        after_tick.changed_paths_unchecked.is_some(),
        "and the check stays unchecked until a complete admission: {after_tick:?}"
    );

    cancel_tx.send(true).ok();
    let joined = tokio::time::timeout(Duration::from_secs(10), &mut runner).await;
    if joined.is_err() {
        runner.abort();
        let _ = runner.await;
    }
    assert!(joined.is_ok(), "the owned loop must stop after cancellation");
}
