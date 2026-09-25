// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// A reference read that arrives while an edit admission holds graph authority.
// Included into `loop_runner::tests`.

#[cfg(unix)]
async fn admission_window_find_references(
    state: Arc<DaemonState>,
    entity_id: EntityId,
) -> kin_mcp::ToolCallResult {
    admission_window_tool_call(
        state,
        "find_references",
        serde_json::json!({"entity_id": entity_id.to_string()}),
    )
    .await
}

#[cfg(unix)]
async fn admission_window_tool_call(
    state: Arc<DaemonState>,
    tool: &'static str,
    arguments: serde_json::Value,
) -> kin_mcp::ToolCallResult {
    let request = axum::http::Request::post("/mcp/tools/call")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({
                "name": tool,
                "arguments": arguments,
            })
            .to_string(),
        ))
        .unwrap();
    let response = tower::ServiceExt::oneshot(crate::api::router(state), request)
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// `POST /commands/xref`, returning the status and the body as text, because a
/// refusal comes back as plain text and an answer as JSON.
#[cfg(unix)]
async fn admission_window_xref(
    state: Arc<DaemonState>,
    entity: &'static str,
) -> (axum::http::StatusCode, String) {
    admission_window_post(
        state,
        "/commands/xref",
        serde_json::json!({ "entity": entity }),
    )
    .await
}

/// `POST` one command route, returning the status and the body as text.
#[cfg(unix)]
async fn admission_window_post(
    state: Arc<DaemonState>,
    route: &'static str,
    body: serde_json::Value,
) -> (axum::http::StatusCode, String) {
    let request = axum::http::Request::post(route)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = tower::ServiceExt::oneshot(crate::api::router(state), request)
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

/// `work` and `helper` in one file and `run` calling `work` from another,
/// derived by a real admission and committed, because find_references reads
/// committed history. Nothing calls `helper` yet.
///
/// No reference read runs here, so nothing is certified for a settled replay
/// to answer from. A test that wants one takes it itself.
#[cfg(unix)]
async fn admission_window_fixture(
    repo: &tempfile::TempDir,
) -> (Arc<DaemonState>, kin_model::Entity) {
    isolate_repository_registry();
    let state = open_test_state(repo);
    std::fs::write(
        repo.path().join("target.py"),
        "def work(value):\n    return value\n\n\ndef helper():\n    return 0\n",
    )
    .unwrap();
    std::fs::write(
        repo.path().join("caller.py"),
        "from target import work\n\ndef run():\n    return work(1)\n",
    )
    .unwrap();
    sync_filesystem_with_graph(&state).await.unwrap();
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let (status, body) = startup_diagnostic_commit(&state).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let work = admission_window_entity(&state, "target.py", "work");
    (state, work)
}

#[cfg(unix)]
fn admission_window_entity(state: &DaemonState, file: &str, name: &str) -> kin_model::Entity {
    state
        .graph
        .query_entities(&EntityFilter {
            file_path: Some(FilePathId::new(file)),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == name)
        .unwrap_or_else(|| panic!("the graph holds `{name}` in {file}"))
}

/// The edit every held admission below takes: `again`, a second caller of
/// `work`, and `later`, which calls `again` and gives `helper` its first
/// caller.
#[cfg(unix)]
const ADMISSION_WINDOW_EDIT: &str = "\
from target import helper, work

def run():
    return work(1)


def again():
    return work(2)


def later():
    return again() + helper()
";

/// An edit admission held open right after its publication, while it holds
/// graph authority and before it applies its delta to the live graph, until
/// the test lets it go.
#[cfg(unix)]
struct HeldAdmission {
    release: std::sync::mpsc::Sender<()>,
    admission: tokio::task::JoinHandle<Result<()>>,
    _fault: SplitPublicationFaultGuard,
}

#[cfg(unix)]
impl HeldAdmission {
    /// Write `contents` to `path` and hold the admission that takes it.
    async fn begin(state: &Arc<DaemonState>, path: std::path::PathBuf, contents: &str) -> Self {
        let (held, holding) = std::sync::mpsc::channel::<()>();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let fault = split_publication_fault(
            state,
            Box::new(move |_| {
                held.send(()).unwrap();
                // Bounded so a failed test cannot hang the suite.
                let _ = released.recv_timeout(std::time::Duration::from_secs(30));
            }),
        );
        std::fs::write(path, contents).unwrap();
        let admission = tokio::spawn({
            let state = Arc::clone(state);
            async move { sync_filesystem_with_graph(&state).await }
        });
        tokio::task::spawn_blocking(move || {
            holding.recv_timeout(std::time::Duration::from_secs(60))
        })
        .await
        .unwrap()
        .expect("the edit admission reaches its publication");
        assert!(
            state.stable_graph_authority_epoch().is_none(),
            "the admission must be holding graph authority while it is held open"
        );
        Self {
            release,
            admission,
            _fault: fault,
        }
    }

    async fn release(self) {
        self.release.send(()).unwrap();
        self.admission
            .await
            .unwrap()
            .expect("the held admission finishes once released");
    }
}

/// The `graph_authority` disclosure with `reason`, from an answer's own
/// `degradations[]`.
#[cfg(unix)]
fn admission_window_disclosure<'a>(
    body: &'a serde_json::Value,
    reason: &str,
) -> Option<&'a serde_json::Value> {
    body["degradations"].as_array().and_then(|entries| {
        entries
            .iter()
            .find(|entry| entry["component"] == "graph_authority" && entry["reason"] == reason)
    })
}

/// The reconcile pass holds graph authority from its walk of the working copy
/// through publication and apply, and one publication on a loaded host was
/// measured at 37 s. A find_references call that met it used to spend its
/// whole retry budget inside that window, under a second, and refuse with "no
/// settled graph authority". An edit loop saw that on 10 of 69 calls.
///
/// Here a real edit admission is held open at its publication, where it holds
/// authority, until the test lets it go. The read issued inside that window
/// must still be waiting after a hold several times longer than the old
/// budget, then answer from the graph the admission left, certified current
/// and labelled as a read that waited.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn a_reference_read_waits_out_an_admission_that_holds_graph_authority() {
    isolate_repository_registry();
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    std::fs::write(
        repo.path().join("target.py"),
        "def work(value):\n    return value\n",
    )
    .unwrap();
    std::fs::write(
        repo.path().join("caller.py"),
        "from target import work\n\ndef run():\n    return work(1)\n",
    )
    .unwrap();
    sync_filesystem_with_graph(&state).await.unwrap();
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    // find_references reads committed history, so the fixture needs a head.
    let (status, body) = startup_diagnostic_commit(&state).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let work = state
        .graph
        .query_entities(&EntityFilter {
            file_path: Some(FilePathId::new("target.py")),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == "work")
        .expect("the fixture derives `work`");

    // Hold the next admission open right after its publication, while it
    // still holds graph authority, until the test releases it.
    let (held, holding) = std::sync::mpsc::channel::<()>();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let _fault = split_publication_fault(
        &state,
        Box::new(move |_| {
            held.send(()).unwrap();
            // Bounded so a failed test cannot hang the suite.
            let _ = released.recv_timeout(std::time::Duration::from_secs(30));
        }),
    );
    std::fs::write(
        repo.path().join("caller.py"),
        "from target import work\n\ndef run():\n    return work(1)\n\n\ndef again():\n    return work(2)\n",
    )
    .unwrap();
    let admission = tokio::spawn({
        let state = Arc::clone(&state);
        async move { sync_filesystem_with_graph(&state).await }
    });
    tokio::task::spawn_blocking(move || holding.recv_timeout(std::time::Duration::from_secs(60)))
        .await
        .unwrap()
        .expect("the edit admission reaches its publication");
    assert!(
        state.stable_graph_authority_epoch().is_none(),
        "the admission must be holding graph authority while it is held open"
    );

    let read = tokio::spawn(admission_window_find_references(
        Arc::clone(&state),
        work.id,
    ));
    // Several times the old retry budget, which gave up after under a second.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let answered_inside_the_window = read.is_finished();
    release.send(()).unwrap();
    admission
        .await
        .unwrap()
        .expect("the held admission finishes once released");
    let result = read.await.unwrap();
    let kin_mcp::ContentBlock::Text { text } = &result.content[0];

    assert!(
        !answered_inside_the_window,
        "a read issued while an admission holds graph authority must wait for it, not give up \
         inside the window: {text}"
    );
    assert_ne!(result.is_error, Some(true), "{text}");
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["focal_entity"]["id"], work.id.to_string(), "{body}");
    let mut expected_callers = state
        .graph
        .query_entities(&EntityFilter {
            file_path: Some(FilePathId::new("caller.py")),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .filter(|entity| matches!(entity.name.as_str(), "run" | "again" | "caller"))
        .map(|entity| entity.id.to_string())
        .collect::<Vec<_>>();
    expected_callers.sort();
    assert_eq!(
        expected_callers.len(),
        3,
        "the admission must derive both callers and their module import owner"
    );
    let mut actual_callers = body["references"]
        .as_array()
        .expect("a successful reference answer must contain rows")
        .iter()
        .map(|row| {
            row["entity_id"]
                .as_str()
                .expect("caller identity")
                .to_owned()
        })
        .collect::<Vec<_>>();
    actual_callers.sort();
    assert_eq!(
        actual_callers, expected_callers,
        "the answer must include the newly admitted caller: {body}"
    );
    assert_eq!(body["total_upstream"], 3, "{body}");
    let retry = body["degradations"]
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry["component"] == "graph_authority" && entry["reason"] == "retry")
        })
        .unwrap_or_else(|| panic!("an answer that waited must say it did: {body}"));
    assert!(
        retry["waited_for_writer_ms"]
            .as_u64()
            .is_some_and(|ms| ms > 0),
        "the retry disclosure must carry the wait: {retry}"
    );
    assert!(
        !body["degradations"]
            .as_array()
            .is_some_and(|entries| entries
                .iter()
                .any(|entry| entry["reason"] == "mutation_in_flight"
                    || entry["reason"] == "settled_replay")),
        "the read waited for the writer, so it answers current, not stale: {body}"
    );
}

/// An agent that adds a function and asks for its references by name while the
/// edit is still admitting must never be told the function does not exist.
///
/// The name early-out answered "Entity not found" from the live name index,
/// with no writer or epoch check, and the index does not hold a name the
/// admission is adding until the admission applies its delta. Here the read is
/// issued while the admission that adds `again` is held open, after a reference
/// read certified the graph as it stood before the edit, which is the order an
/// agent works in. That leaves a settled replay available inside the window,
/// and the replay does not hold `again` either, so it must not answer.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn a_reference_read_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, work) = admission_window_fixture(&repo).await;
    // Long enough that the answer never depends on the production limit.
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let certified = admission_window_find_references(Arc::clone(&state), work.id).await;
    assert_ne!(certified.is_error, Some(true), "{:?}", certified.content);
    let certified_root = state.graph.compute_root_hash();
    let certified_version = state.vfs_version.load(std::sync::atomic::Ordering::SeqCst);

    let held =
        HeldAdmission::begin(&state, repo.path().join("caller.py"), ADMISSION_WINDOW_EDIT).await;
    assert!(
        state.graph.compute_root_hash() == certified_root
            && state.vfs_version.load(std::sync::atomic::Ordering::SeqCst) == certified_version,
        "held before it applies its delta, the admission has not moved the graph, so the settled \
         replay of the certified read is available inside the window"
    );
    let read = tokio::spawn(admission_window_tool_call(
        Arc::clone(&state),
        "find_references",
        serde_json::json!({"query": "again"}),
    ));
    // Several times the old retry budget, which gave up after under a second.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let answered_inside_the_window = read.is_finished();
    held.release().await;
    let result = read.await.unwrap();
    let kin_mcp::ContentBlock::Text { text } = &result.content[0];

    assert!(
        !text.contains(kin_mcp::handlers::entities::FIND_REFERENCES_FOCAL_MISS),
        "a name the admission is adding must never be answered as absent while it admits: {text}"
    );
    assert!(
        !answered_inside_the_window,
        "a read by name issued while an admission holds graph authority must wait for it: {text}"
    );
    assert_ne!(result.is_error, Some(true), "{text}");
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    let again = admission_window_entity(&state, "caller.py", "again");
    let later = admission_window_entity(&state, "caller.py", "later");
    assert_eq!(body["focal_entity"]["id"], again.id.to_string(), "{body}");
    assert!(
        body["references"].as_array().is_some_and(|rows| rows
            .iter()
            .any(|row| row["entity_id"] == later.id.to_string())),
        "the answer must be read from the graph the admission left: {body}"
    );
    let retry = admission_window_disclosure(&body, "retry")
        .unwrap_or_else(|| panic!("an answer that waited must say it did: {body}"));
    assert!(
        retry["waited_for_writer_ms"]
            .as_u64()
            .is_some_and(|ms| ms > 0),
        "the retry disclosure must carry the wait: {retry}"
    );
    // Inside the window the read took the settled replay, which could not
    // place `again`, and threw it away. The disclosure says so rather than
    // claiming nothing was read.
    let detail = retry["detail"]
        .as_str()
        .expect("the disclosure carries a detail");
    assert!(
        detail.contains("read the graph as last certified, and did not serve that answer"),
        "the discarded replay is part of what happened: {detail}"
    );
    assert!(
        !detail.contains("abandoned"),
        "no attempt captured a graph that moved, so none was abandoned: {detail}"
    );
    assert!(
        admission_window_disclosure(&body, "mutation_in_flight").is_none()
            && admission_window_disclosure(&body, "settled_replay").is_none(),
        "the read waited for the writer, so it answers current, not stale: {body}"
    );
}

/// bulk_check_references takes the same wait as find_references, and its
/// retry disclosure says what happened: nothing was read and thrown away while
/// the admission held authority, so the read waited and did not abandon one.
///
/// No reference read runs before the hold, so there is no settled replay to
/// answer from, and the read has to wait out the admission to answer at all.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn bulk_check_references_waits_out_an_admission_and_says_it_waited() {
    let repo = tempfile::tempdir().unwrap();
    let (state, work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let arguments = serde_json::json!({
        "entity_ids": [work.id.to_string()],
        "relation_kind": "Any",
    });

    let held =
        HeldAdmission::begin(&state, repo.path().join("caller.py"), ADMISSION_WINDOW_EDIT).await;
    let read = tokio::spawn(admission_window_tool_call(
        Arc::clone(&state),
        "bulk_check_references",
        arguments.clone(),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let answered_inside_the_window = read.is_finished();
    held.release().await;
    let result = read.await.unwrap();
    let kin_mcp::ContentBlock::Text { text } = &result.content[0];

    assert!(
        !answered_inside_the_window,
        "a read issued while an admission holds graph authority must wait for it: {text}"
    );
    assert_ne!(result.is_error, Some(true), "{text}");
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    // The graph the admission left, read again with nothing writing, is what
    // the waited answer has to match. The admission added a caller of `work`,
    // so an answer read from the graph before it would not.
    let settled =
        admission_window_tool_call(Arc::clone(&state), "bulk_check_references", arguments).await;
    let kin_mcp::ContentBlock::Text { text: settled_text } = &settled.content[0];
    let settled_body: serde_json::Value = serde_json::from_str(settled_text).unwrap();
    assert!(
        admission_window_disclosure(&settled_body, "retry").is_none(),
        "the control read must be uncontended: {settled_body}"
    );
    assert_eq!(body["results"], settled_body["results"], "{body}");
    assert_eq!(body["results"][0]["has_references"], true, "{body}");

    let retry = admission_window_disclosure(&body, "retry")
        .unwrap_or_else(|| panic!("an answer that waited must say it did: {body}"));
    assert!(
        retry["waited_for_writer_ms"]
            .as_u64()
            .is_some_and(|ms| ms > 0),
        "the retry disclosure must carry the wait: {retry}"
    );
    let detail = retry["detail"]
        .as_str()
        .expect("the disclosure carries a detail");
    assert!(
        !detail.contains("abandoned"),
        "no attempt read the graph while the admission held authority, so none was abandoned: \
         {detail}"
    );
    assert!(
        detail.contains("held graph authority while this read ran"),
        "the disclosure must say a writer held authority: {detail}"
    );
    assert!(
        admission_window_disclosure(&body, "mutation_in_flight").is_none()
            && admission_window_disclosure(&body, "settled_replay").is_none(),
        "the read waited for the writer, so it answers current, not stale: {body}"
    );
}

/// Command xref waits out an admission the same way, and it has no labelled
/// stale answer to fall back on, so when its limit runs out first it refuses,
/// and the refusal says what is still in the way.
///
/// The reconcile loop reports `reconciliation_status` as `processing` for the
/// pass that runs an edit admission. This test runs the admission directly,
/// so it sets the status the loop would have set.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_xref_waits_out_an_admission_and_names_a_writer_still_holding_authority() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state
        .reconciliation_status
        .store(RECON_PROCESSING, std::sync::atomic::Ordering::Relaxed);

    let held =
        HeldAdmission::begin(&state, repo.path().join("caller.py"), ADMISSION_WINDOW_EDIT).await;

    // A limit shorter than the hold: the read refuses while the admission
    // still holds authority.
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_millis(800));
    let (status, refusal) = admission_window_xref(Arc::clone(&state), "again").await;
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "{refusal}"
    );
    assert!(
        refusal.contains("reached its 800 ms limit for waiting out graph-authority writers"),
        "the refusal must state the limit it ran into: {refusal}"
    );
    assert!(
        refusal.contains("a writer still held graph authority when that limit ran out"),
        "the refusal must say the writer still holds authority: {refusal}"
    );
    assert!(
        refusal.contains("not an absent or unresolved symbol"),
        "the refusal must separate a write window from an absence: {refusal}"
    );
    assert!(
        refusal.contains("reconciliation_status processing"),
        "with a reconcile pass running, the refusal must point at it and not only at the \
         enrichment sweep: {refusal}"
    );

    // A limit longer than the hold: a read issued inside the same window waits
    // and answers from the graph the admission leaves.
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let read = tokio::spawn(admission_window_xref(Arc::clone(&state), "again"));
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let answered_inside_the_window = read.is_finished();
    held.release().await;
    state
        .reconciliation_status
        .store(RECON_IDLE, std::sync::atomic::Ordering::Relaxed);
    let (status, answer) = read.await.unwrap();

    assert!(
        !answered_inside_the_window,
        "a read issued while an admission holds graph authority must wait for it: {answer}"
    );
    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: kin_cli::commands::xref::XrefResponse = serde_json::from_str(&answer).unwrap();
    assert!(response.error.is_none(), "{answer}");
    assert_eq!(
        response.lines.first().map(String::as_str),
        Some("Cross-repo references (xrefs) for 'again':"),
        "the answer must resolve the name the admission added: {answer}"
    );
}

/// Issue `read` while the edit admission holds graph authority, and report
/// whether it had answered after a hold several times longer than the old
/// retry budget, before the admission is let go, and what it answered.
#[cfg(unix)]
async fn read_inside_a_held_admission<T: Send + 'static>(
    state: &Arc<DaemonState>,
    repo: &tempfile::TempDir,
    read: impl std::future::Future<Output = T> + Send + 'static,
) -> (bool, T) {
    let held =
        HeldAdmission::begin(state, repo.path().join("caller.py"), ADMISSION_WINDOW_EDIT).await;
    let read = tokio::spawn(read);
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let answered_inside_the_window = read.is_finished();
    held.release().await;
    (answered_inside_the_window, read.await.unwrap())
}

/// `/commands/refs` asked for a name the held admission adds must wait for the
/// admission and list the caller it adds, never report the name as missing.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_refs_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/commands/refs",
            serde_json::json!({"entity": "again", "kind": "all"}),
        ),
    )
    .await;

    assert!(
        !answered_inside_the_window,
        "a refs read by name issued while an admission holds graph authority must wait for it: \
         {answer}"
    );
    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: kin_cli::commands::refs::RefsResponse = serde_json::from_str(&answer).unwrap();
    assert!(
        response.error.is_none(),
        "a name the admission is adding must never be answered as missing: {answer}"
    );
    assert!(
        response.lines.iter().any(|line| line.contains("later")),
        "the answer must be read from the graph the admission left: {answer}"
    );
}

/// `/commands/bulk-refs` for an entity whose first caller the held admission
/// adds must wait for it, never answer that the entity has no references.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_bulk_refs_waits_for_the_admission_adding_a_first_caller() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let helper = admission_window_entity(&state, "target.py", "helper");
    let request = serde_json::json!({"entity_ids": [helper.id.to_string()]});
    let has_references = |answer: &str| {
        let response: kin_cli::commands::refs::BulkRefsResponse =
            serde_json::from_str(answer).unwrap();
        response.results[0]["has_references"].clone()
    };

    // The control: with nothing writing, nothing calls `helper` yet, and a
    // settled read says so.
    let (status, before) =
        admission_window_post(Arc::clone(&state), "/commands/bulk-refs", request.clone()).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{before}");
    assert_eq!(has_references(&before), false, "{before}");

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(Arc::clone(&state), "/commands/bulk-refs", request),
    )
    .await;

    assert!(
        !answered_inside_the_window,
        "a bulk-refs read issued while an admission holds graph authority must wait for it: \
         {answer}"
    );
    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    assert_eq!(
        has_references(&answer),
        true,
        "an entity the admission gives a caller must never be answered as unreferenced: {answer}"
    );
}

/// `/commands/trace-data-flow` asked for a focal the held admission adds must
/// wait for it and walk from it, never report the focal as missing.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_trace_data_flow_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/commands/trace-data-flow",
            serde_json::json!({"focal": "again", "include_body": false}),
        ),
    )
    .await;

    assert!(
        !answered_inside_the_window,
        "a trace by name issued while an admission holds graph authority must wait for it: \
         {answer}"
    );
    assert!(
        !answer.contains("no entity found"),
        "a focal the admission is adding must never be answered as missing: {answer}"
    );
    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: serde_json::Value = serde_json::from_str(&answer).unwrap();
    assert_eq!(response["focal_name"], "again", "{response}");
}

/// The MCP trace_data_flow route takes the same wait as the command route.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_trace_data_flow_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, result) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_tool_call(
            Arc::clone(&state),
            "trace_data_flow",
            serde_json::json!({"focal": "again", "include_body": false}),
        ),
    )
    .await;
    let kin_mcp::ContentBlock::Text { text } = &result.content[0];

    assert!(
        !answered_inside_the_window,
        "a trace by name issued while an admission holds graph authority must wait for it: \
         {text}"
    );
    assert!(
        !text.contains("no entity found"),
        "a focal the admission is adding must never be answered as missing: {text}"
    );
    assert_ne!(result.is_error, Some(true), "{text}");
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["focal_name"], "again", "{body}");
}

/// Whether a trace answer says the target it was asked to rank toward
/// resolved to nothing.
#[cfg(unix)]
fn trace_answer_missed_its_target(body: &serde_json::Value) -> bool {
    body["degradations"].as_array().is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry["component"] == "target_reachability" && entry["reason"] == "target_not_resolved"
        })
    })
}

/// A trace from a focal that exists, asked to rank toward a target the held
/// admission adds, must wait for the admission and rank toward that target,
/// never say that no entity matches it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_trace_data_flow_target_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/commands/trace-data-flow",
            serde_json::json!({
                "focal": "work",
                "direction": "callers",
                "target": "again",
                "include_body": false,
            }),
        ),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: serde_json::Value = serde_json::from_str(&answer).unwrap();
    assert!(
        !trace_answer_missed_its_target(&response),
        "a target the admission is adding must never be answered as unresolved: {response}"
    );
    assert!(
        !answered_inside_the_window,
        "a trace toward a target issued while an admission holds graph authority must wait for \
         it: {response}"
    );
    assert_eq!(response["focal_name"], "work", "{response}");
    assert_eq!(response["target_name"], "again", "{response}");
}

/// The MCP trace_data_flow route waits for a target the held admission adds the
/// same way.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_trace_data_flow_target_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, result) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_tool_call(
            Arc::clone(&state),
            "trace_data_flow",
            serde_json::json!({
                "focal": "work",
                "direction": "callers",
                "target": "again",
                "include_body": false,
            }),
        ),
    )
    .await;
    let kin_mcp::ContentBlock::Text { text } = &result.content[0];

    assert_ne!(result.is_error, Some(true), "{text}");
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert!(
        !trace_answer_missed_its_target(&body),
        "a target the admission is adding must never be answered as unresolved: {body}"
    );
    assert!(
        !answered_inside_the_window,
        "a trace toward a target issued while an admission holds graph authority must wait for \
         it: {body}"
    );
    assert_eq!(body["focal_name"], "work", "{body}");
    assert_eq!(body["target_name"], "again", "{body}");
}

/// Assert that an exact-name source read for `name` waited for the held
/// admission that adds it and answered with its body.
#[cfg(unix)]
fn assert_source_read_waited_for_the_name(
    state: &DaemonState,
    result: &kin_mcp::ToolCallResult,
    answered_inside_the_window: bool,
    name: &str,
) {
    let kin_mcp::ContentBlock::Text { text } = &result.content[0];
    assert!(
        !text.contains("no entity found matching"),
        "a name the admission is adding must never be answered as missing: {text}"
    );
    assert!(
        !answered_inside_the_window,
        "a source read by name issued while an admission holds graph authority must wait for \
         it: {text}"
    );
    assert_ne!(result.is_error, Some(true), "{text}");
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    let entity = admission_window_entity(state, "caller.py", name);
    assert_eq!(body["id"], entity.id.to_string(), "{body}");
    assert_eq!(body["name"], name, "{body}");
    assert!(
        body["body"]
            .as_str()
            .is_some_and(|source| source.contains(&format!("def {name}("))),
        "the answer must carry the body the admission wrote: {body}"
    );
}

/// `get_entity_source` by exact name for a function the held admission adds
/// must wait for the admission and return its body, never report that no
/// entity matches the name.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_get_entity_source_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, result) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_tool_call(
            Arc::clone(&state),
            "get_entity_source",
            serde_json::json!({"entity_id": "again"}),
        ),
    )
    .await;

    assert_source_read_waited_for_the_name(&state, &result, answered_inside_the_window, "again");
}

/// `get_entity_body` shares the source read and waits the same way.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_get_entity_body_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, result) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_tool_call(
            Arc::clone(&state),
            "get_entity_body",
            serde_json::json!({"entity_id": "later"}),
        ),
    )
    .await;

    assert_source_read_waited_for_the_name(&state, &result, answered_inside_the_window, "later");
}

/// The batched `get_entity_sources` must wait for a held admission that adds a
/// name it was asked for, never answer that row as not found.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_get_entity_sources_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, result) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_tool_call(
            Arc::clone(&state),
            "get_entity_sources",
            serde_json::json!({"entity_ids": [work.id.to_string(), "again"]}),
        ),
    )
    .await;
    let kin_mcp::ContentBlock::Text { text } = &result.content[0];

    assert_ne!(result.is_error, Some(true), "{text}");
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    let rows = body["results"].as_array().expect("one row per request");
    assert!(
        rows.iter().all(|row| row["reason"] != "not_found"),
        "a name the admission is adding must never be answered as not found: {body}"
    );
    assert!(
        !answered_inside_the_window,
        "a batched source read by name issued while an admission holds graph authority must \
         wait for it: {body}"
    );
    let again = admission_window_entity(&state, "caller.py", "again");
    assert_eq!(body["returned"], 2, "{body}");
    assert_eq!(rows[0]["id"], work.id.to_string(), "{body}");
    assert_eq!(rows[1]["id"], again.id.to_string(), "{body}");
}

/// `kin source` posts `/commands/graph` with the source command. By exact
/// name, for a function the held admission adds, it must wait for the
/// admission and print its body, never report that no entity matches.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_graph_source_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/commands/graph",
            serde_json::json!({"command": "source", "entity": "again"}),
        ),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: kin_cli::commands::graph::GraphCommandResponse =
        serde_json::from_str(&answer).unwrap();
    assert!(
        response.error.is_none(),
        "a name the admission is adding must never be answered as missing: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "a source read by name issued while an admission holds graph authority must wait for \
         it: {answer}"
    );
    let again = admission_window_entity(&state, "caller.py", "again");
    let source = response.source.expect("a found entity carries its source");
    assert_eq!(source.id, again.id.to_string(), "{answer}");
    assert!(source.body.contains("def again("), "{answer}");
}

/// `kin graph inspect` by exact name waits for the held admission adding that
/// name the same way.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_graph_inspect_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/commands/graph",
            serde_json::json!({"command": "inspect", "name": "later"}),
        ),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: kin_cli::commands::graph::GraphCommandResponse =
        serde_json::from_str(&answer).unwrap();
    assert!(
        response.error.is_none(),
        "a name the admission is adding must never be answered as missing: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "an inspect by name issued while an admission holds graph authority must wait for it: \
         {answer}"
    );
    let later = admission_window_entity(&state, "caller.py", "later");
    assert!(
        response
            .lines
            .iter()
            .any(|line| line.contains(&later.id.to_string())),
        "the answer must describe the entity the admission added: {answer}"
    );
}

/// `kin path` posts `/commands/path`. Asked for a route from a function the
/// held admission adds, it must wait for the admission and walk the route the
/// edit wrote, never refuse the end as one no entity matches.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_path_from_a_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/commands/path",
            serde_json::json!({"from": "later", "to": "work"}),
        ),
    )
    .await;

    assert!(
        !answer.contains("no entity found for"),
        "an end the admission is adding must never be answered as missing: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "a route query issued while an admission holds graph authority must wait for it: \
         {answer}"
    );
    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: serde_json::Value = serde_json::from_str(&answer).unwrap();
    assert_eq!(
        response["found"], true,
        "the route the admission wrote, later -> again -> work, must be found: {response}"
    );
}

/// `kin context` posts `/context`. By exact name, for a function the held
/// admission adds, it must wait for the admission and build the pack, never
/// report that the entity is not in the graph.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_context_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/context",
            serde_json::json!({"entity": "again", "budget": "8k"}),
        ),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: kin_cli::commands::context::ContextResponse =
        serde_json::from_str(&answer).unwrap();
    assert!(
        response.error.is_none(),
        "a name the admission is adding must never be answered as missing: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "a context read by name issued while an admission holds graph authority must wait for \
         it: {answer}"
    );
    assert!(
        response.pack.is_some(),
        "the answer must be the pack: {answer}"
    );
}

/// `kin trace` posts `/trace`. By exact name, for a function the held admission
/// adds, it must wait for the admission and trace it, never report that the
/// entity is not in the graph.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_trace_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/trace",
            serde_json::json!({
                "entity": "again",
                "json": true,
                "compact": false,
                "budget": "8k",
                "max_lines": 20,
                "nearby_limit": 2,
                "transitive_limit": 1,
            }),
        ),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: kin_cli::commands::trace::TraceResponse =
        serde_json::from_str(&answer).unwrap();
    assert!(
        response.error.is_none(),
        "a name the admission is adding must never be answered as missing: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "a trace by name issued while an admission holds graph authority must wait for it: \
         {answer}"
    );
    assert!(
        response.entities.iter().any(|entity| entity.name == "again"),
        "the answer must trace the entity the admission added: {answer}"
    );
}

/// `kin impact` posts `/impact`. By exact name, for a function the held
/// admission adds, it must wait for the admission and analyse it, never report
/// that the name resolved to nothing.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_impact_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/impact",
            serde_json::json!({"entity": "again", "depth": 3}),
        ),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: kin_cli::commands::impact::ImpactResponse =
        serde_json::from_str(&answer).unwrap();
    assert_eq!(
        response.resolution, "resolved",
        "a name the admission is adding must never be answered as missing: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "an impact read by name issued while an admission holds graph authority must wait for \
         it: {answer}"
    );
    assert!(
        response.lines.iter().any(|line| line.contains("later")),
        "the answer must list the dependent the admission added: {answer}"
    );
}

/// `/impact` for an entity whose first dependent the held admission adds must
/// wait for it, never answer that nothing depends on the entity.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_impact_waits_for_the_admission_adding_a_first_dependent() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let request = serde_json::json!({"entity": "helper", "depth": 3});

    // The control: with nothing writing, nothing calls `helper` yet, and a
    // settled read says so.
    let (status, before) =
        admission_window_post(Arc::clone(&state), "/impact", request.clone()).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{before}");
    let before: kin_cli::commands::impact::ImpactResponse =
        serde_json::from_str(&before).unwrap();
    assert!(
        before
            .lines
            .iter()
            .any(|line| line.contains("No local downstream impact found."))
            && before.negative.is_some(),
        "a settled answer with no dependents carries its absence verdict: {before:?}"
    );

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(Arc::clone(&state), "/impact", request),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: kin_cli::commands::impact::ImpactResponse =
        serde_json::from_str(&answer).unwrap();
    assert!(
        response.negative.is_none()
            && response.lines.iter().any(|line| line.contains("later")),
        "an entity the admission gives a dependent must never be answered as having none: \
         {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "an impact read issued while an admission holds graph authority must wait for it: \
         {answer}"
    );
}

/// `GET` one route, returning the status and the body as text.
#[cfg(unix)]
async fn admission_window_get(
    state: Arc<DaemonState>,
    uri: String,
) -> (axum::http::StatusCode, String) {
    let request = axum::http::Request::get(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(crate::api::router(state), request)
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

/// A file the fixture does not hold, which the held admission of
/// [`read_inside_a_held_new_file_admission`] adds whole.
#[cfg(unix)]
const ADMISSION_WINDOW_NEW_FILE: &str = "\
from target import work

def fresh():
    return work(3)
";

/// [`read_inside_a_held_admission`] for an edit that adds a new file,
/// `fresh.py`, rather than changing one the graph already tracks.
#[cfg(unix)]
async fn read_inside_a_held_new_file_admission<T: Send + 'static>(
    state: &Arc<DaemonState>,
    repo: &tempfile::TempDir,
    read: impl std::future::Future<Output = T> + Send + 'static,
) -> (bool, T) {
    let held = HeldAdmission::begin(
        state,
        repo.path().join("fresh.py"),
        ADMISSION_WINDOW_NEW_FILE,
    )
    .await;
    let read = tokio::spawn(read);
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let answered_inside_the_window = read.is_finished();
    held.release().await;
    (answered_inside_the_window, read.await.unwrap())
}

/// A tool answer's text and, when it is JSON, its payload.
#[cfg(unix)]
fn tool_answer(result: &kin_mcp::ToolCallResult) -> (String, serde_json::Value) {
    let kin_mcp::ContentBlock::Text { text } = &result.content[0];
    (
        text.clone(),
        serde_json::from_str(text).unwrap_or(serde_json::Value::Null),
    )
}

/// A trace from an entity with no caller yet, walking its callers, must wait
/// for the held admission that adds its first caller, never answer that no
/// flow reaches it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_trace_data_flow_empty_chain_waits_for_the_admission_adding_a_first_step() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let request = serde_json::json!({
        "focal": "helper",
        "direction": "callers",
        "include_body": false,
    });
    let (status, before) = admission_window_post(
        Arc::clone(&state),
        "/commands/trace-data-flow",
        request.clone(),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{before}");
    let before: serde_json::Value = serde_json::from_str(&before).unwrap();
    assert_eq!(
        before["chain"].as_array().map(Vec::len),
        Some(0),
        "nothing calls `helper` before the edit: {before}"
    );

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(Arc::clone(&state), "/commands/trace-data-flow", request),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: serde_json::Value = serde_json::from_str(&answer).unwrap();
    assert!(
        response["chain"]
            .as_array()
            .is_some_and(|chain| chain.iter().any(|step| step["entity_name"] == "later")),
        "an entity the admission gives a caller must never be answered as reached by no flow: \
         {response}"
    );
    assert!(
        !answered_inside_the_window,
        "a trace issued while an admission holds graph authority must wait for it: {response}"
    );
}

/// The MCP trace_data_flow route waits for a first step the same way.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_trace_data_flow_empty_chain_waits_for_the_admission_adding_a_first_step() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, result) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_tool_call(
            Arc::clone(&state),
            "trace_data_flow",
            serde_json::json!({
                "focal": "helper",
                "direction": "callers",
                "include_body": false,
            }),
        ),
    )
    .await;
    let (text, body) = tool_answer(&result);

    assert_ne!(result.is_error, Some(true), "{text}");
    assert!(
        body["chain"]
            .as_array()
            .is_some_and(|chain| chain.iter().any(|step| step["entity_name"] == "later")),
        "an entity the admission gives a caller must never be answered as reached by no flow: \
         {body}"
    );
    assert!(
        !answered_inside_the_window,
        "a trace issued while an admission holds graph authority must wait for it: {body}"
    );
}

/// `/context` asked for two focals, one of which the held admission adds, must
/// wait for it and build the pack from both, never quietly build it from the
/// one that resolved.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_context_with_a_focal_the_admission_adds_waits_for_it() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/context",
            serde_json::json!({"entities": ["work", "again"], "budget": "8k"}),
        ),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: kin_cli::commands::context::ContextResponse =
        serde_json::from_str(&answer).unwrap();
    assert!(
        response.unresolved.is_empty() && response.error.is_none(),
        "a focal the admission is adding must never be answered as unresolved: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "a context read issued while an admission holds graph authority must wait for it: \
         {answer}"
    );
}

/// `kin blame` by exact name, for a function the held admission adds, must
/// wait for the admission, never answer 404 that no entity matches.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_blame_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/blame",
            serde_json::json!({"entity": "again"}),
        ),
    )
    .await;

    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "a name the admission is adding must never be answered as missing: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "a blame by name issued while an admission holds graph authority must wait for it: \
         {answer}"
    );
    let response: kin_cli::commands::blame::BlameResponse =
        serde_json::from_str(&answer).unwrap();
    assert!(
        response
            .lines
            .first()
            .is_some_and(|line| line.starts_with("Blame for 'again'")),
        "{answer}"
    );
}

/// `kin history` by exact name waits the same way.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_history_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/history",
            serde_json::json!({"entity": "later"}),
        ),
    )
    .await;

    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "a name the admission is adding must never be answered as missing: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "a history by name issued while an admission holds graph authority must wait for it: \
         {answer}"
    );
    let response: kin_cli::commands::history::HistoryResponse =
        serde_json::from_str(&answer).unwrap();
    assert!(
        response.lines.iter().any(|line| line.contains("later")),
        "{answer}"
    );
}

/// `kin locate` for the one name the held admission adds must wait for it and
/// rank the entity that carries the name, never answer with a ranking that
/// holds nothing by that name.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_locate_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/locate",
            serde_json::json!({
                "text": "again",
                "max_files": 10,
                "max_files_explicit": false,
                "entity_surface": true,
            }),
        ),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: serde_json::Value = serde_json::from_str(&answer).unwrap();
    assert!(
        response["entities"]
            .as_array()
            .is_some_and(|entities| entities.iter().any(|entity| entity["name"] == "again")),
        "a name the admission is adding must be ranked once it admits: {response}"
    );
    assert!(
        !answered_inside_the_window,
        "a locate by name issued while an admission holds graph authority must wait for it: \
         {response}"
    );
}

/// `kin search` for the name the held admission adds must wait for it, never
/// answer that nothing matches.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_search_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/search",
            serde_json::json!({"query": "again"}),
        ),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: serde_json::Value = serde_json::from_str(&answer).unwrap();
    assert!(
        response["total_matches"].as_u64().is_some_and(|n| n > 0)
            && response["records"].to_string().contains("again"),
        "a name the admission is adding must never be answered as matching nothing: {response}"
    );
    assert!(
        !answered_inside_the_window,
        "a search issued while an admission holds graph authority must wait for it: {response}"
    );
}

/// `kin dead-code` lists entities nothing references, so every answer it gives
/// claims an absence. Issued while the held admission adds `helper`'s first
/// caller, it must wait and not list `helper`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_dead_code_waits_for_the_admission_adding_a_reference() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let lists_helper = |answer: &str| {
        let response: kin_cli::commands::dead_code::DeadCodeResponse =
            serde_json::from_str(answer).unwrap();
        response.lines.iter().any(|line| line.contains("helper"))
    };
    let (status, before) =
        admission_window_post(Arc::clone(&state), "/commands/dead-code", serde_json::json!({}))
            .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{before}");
    assert!(
        lists_helper(&before),
        "nothing calls `helper` before the edit: {before}"
    );

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(Arc::clone(&state), "/commands/dead-code", serde_json::json!({})),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    assert!(
        !lists_helper(&answer),
        "an entity the admission gives a caller must never be listed as unreferenced: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "a dead-code scan issued while an admission holds graph authority must wait for it: \
         {answer}"
    );
}

/// `kin dead-code <query>` waits the same way for a candidate the held
/// admission gives its first caller.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_dead_code_seeded_waits_for_the_admission_adding_a_reference() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let request = serde_json::json!({"query": "helper"});
    let helper_dead = |answer: &str| {
        let response: kin_cli::commands::dead_code::DeadCodeSeededResponse =
            serde_json::from_str(answer).unwrap();
        response
            .candidates
            .iter()
            .any(|candidate| candidate.name == "helper" && candidate.dead)
    };
    let (status, before) = admission_window_post(
        Arc::clone(&state),
        "/commands/dead-code-seeded",
        request.clone(),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{before}");
    assert!(
        helper_dead(&before),
        "nothing calls `helper` before the edit: {before}"
    );

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(Arc::clone(&state), "/commands/dead-code-seeded", request),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    assert!(
        !helper_dead(&answer),
        "an entity the admission gives a caller must never be answered as dead: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "a seeded dead-code read issued while an admission holds graph authority must wait for \
         it: {answer}"
    );
}

/// `kin verify <entity>` by the name the held admission adds must wait for it,
/// never answer that no entity matches.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_verify_entity_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/commands/verify",
            serde_json::json!({"command": "entity", "entity": "again"}),
        ),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    assert!(
        !answer.contains("No entity matching"),
        "a name the admission is adding must never be answered as missing: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "a verify read by name issued while an admission holds graph authority must wait for \
         it: {answer}"
    );
    assert!(answer.contains("again"), "{answer}");
}

/// `kin verify plan` by the name the held admission adds waits the same way.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_verify_plan_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/commands/verify",
            serde_json::json!({"command": "plan", "entity": "again", "depth": 1}),
        ),
    )
    .await;

    assert!(
        !answer.contains("No entity matching"),
        "a name the admission is adding must never be answered as missing: {answer}"
    );
    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    assert!(
        !answered_inside_the_window,
        "a verify plan by name issued while an admission holds graph authority must wait for \
         it: {answer}"
    );
}

/// `kin verify run` by the name the held admission adds must wait for it
/// before it resolves, never refuse that no entity matches. The runner named
/// here carries shell syntax, so once the entity resolves the run refuses the
/// runner before it runs anything, which is the answer that proves it
/// resolved.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn verify_run_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (_status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/verify/run",
            serde_json::json!({"entity": "again", "runner": "not;a-runner", "depth": 1}),
        ),
    )
    .await;

    assert!(
        !answer.contains("No entity matching"),
        "a name the admission is adding must never be refused as missing: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "a verify run by name issued while an admission holds graph authority must wait for \
         it: {answer}"
    );
    assert!(
        answer.contains("refusing the test runner"),
        "the run resolved the entity and refused only its runner: {answer}"
    );
}

/// `kin review run --files` for a file the held admission adds must wait for
/// it, never answer that the file holds no change.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_review_of_files_waits_for_the_admission_adding_the_file() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_new_file_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/review",
            serde_json::json!({"op": "run", "files": "fresh.py"}),
        ),
    )
    .await;

    assert!(
        !answer.contains("no changes between base and head"),
        "a file the admission is adding must never be answered as holding no change: {answer}"
    );
    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    assert!(
        !answered_inside_the_window,
        "a review of files issued while an admission holds graph authority must wait for it: \
         {answer}"
    );
}

/// `kin security` reports a public function nothing calls. Issued while the
/// held admission adds `helper`'s first caller, it must wait and not report
/// `helper`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn command_security_waits_for_the_admission_adding_a_caller() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let reports_helper = |answer: &str| {
        let response: kin_cli::commands::security::SecurityResponse =
            serde_json::from_str(answer).unwrap();
        response
            .lines
            .iter()
            .any(|line| line.contains(" helper (orphaned-public)"))
    };
    let (status, before) = admission_window_post(
        Arc::clone(&state),
        "/commands/security",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{before}");
    assert!(
        reports_helper(&before),
        "nothing calls `helper` before the edit: {before}"
    );

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_post(
            Arc::clone(&state),
            "/commands/security",
            serde_json::json!({}),
        ),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    assert!(
        !reports_helper(&answer),
        "an entity the admission gives a caller must never be reported as having none: {answer}"
    );
    assert!(
        !answered_inside_the_window,
        "a security scan issued while an admission holds graph authority must wait for it: \
         {answer}"
    );
}

/// On a local daemon `/repos/{repo_id}/entities` reads the live graph, so a
/// name query for an entity the held admission adds must wait for it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn repo_entities_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let uri = format!("/repos/{}/entities?query=again", state.cached_repo_id);

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_get(Arc::clone(&state), uri),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: serde_json::Value = serde_json::from_str(&answer).unwrap();
    assert!(
        response["entities"]
            .as_array()
            .is_some_and(|entities| entities.iter().any(|entity| entity["name"] == "again")),
        "a name the admission is adding must never be answered as matching nothing: {response}"
    );
    assert!(
        !answered_inside_the_window,
        "an entity query issued while an admission holds graph authority must wait for it: \
         {response}"
    );
}

/// Point the machine-wide repository registry at an empty scratch registry for
/// this test process.
///
/// A local spine initializes from every workspace the registry names, and the
/// registry defaults to the one on this machine, so a test that reads the spine
/// without this loads and validates whatever real repositories are registered
/// here rather than only its fixture.
#[cfg(unix)]
fn isolate_repository_registry() {
    static REGISTRY: std::sync::OnceLock<(tempfile::TempDir, std::path::PathBuf)> =
        std::sync::OnceLock::new();
    let _guard = crate::test_env_lock();
    let (_root, path) = REGISTRY.get_or_init(|| {
        let root = tempfile::tempdir().expect("a scratch directory for the test registry");
        let path = root.path().join("registry.toml");
        kin_core::registry::KinRegistry { repos: Vec::new() }
            .save_to(&path)
            .unwrap();
        (root, path)
    });
    kin_core::test_env::install_process_wide("KIN_REGISTRY_PATH", path);
}

/// On a local daemon the spine captures this repository from the live graph,
/// so `/spine/resolve` for a name the held admission adds must wait for it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn spine_resolve_by_name_waits_for_the_admission_adding_that_name() {
    isolate_repository_registry();
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    // A spine read re-captures this repository whenever the live graph has
    // moved past its registration, and a capture cannot be taken while a
    // writer holds authority. Reading once first brings the registration level
    // with the graph, so the read inside the hold answers from it rather than
    // being refused for a capture it cannot take.
    let (status, control) =
        admission_window_get(Arc::clone(&state), "/spine/resolve?name=work".to_string()).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{control}");
    assert!(
        control.contains("work"),
        "the spine registers `work` before the edit: {control}"
    );

    let (answered_inside_the_window, (status, answer)) = read_inside_a_held_admission(
        &state,
        &repo,
        admission_window_get(
            Arc::clone(&state),
            "/spine/resolve?name=again".to_string(),
        ),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK, "{answer}");
    let response: serde_json::Value = serde_json::from_str(&answer).unwrap();
    assert!(
        response["results"]
            .as_array()
            .is_some_and(|results| !results.is_empty()),
        "a name the admission is adding must never be answered as resolving to nothing: \
         {response}"
    );
    assert!(
        !answered_inside_the_window,
        "a spine resolve issued while an admission holds graph authority must wait for it: \
         {response}"
    );
}

/// Issue one MCP tool call inside a held admission and assert it waited for
/// the admission and then did not answer with the absence `claims_absence`
/// recognises.
#[cfg(unix)]
async fn assert_tool_waited_for_the_admission(
    state: &Arc<DaemonState>,
    repo: &tempfile::TempDir,
    new_file: bool,
    tool: &'static str,
    arguments: serde_json::Value,
    answer_is_current: impl Fn(&str, &serde_json::Value) -> bool,
) {
    let read = admission_window_tool_call(Arc::clone(state), tool, arguments);
    let (answered_inside_the_window, result) = if new_file {
        read_inside_a_held_new_file_admission(state, repo, read).await
    } else {
        read_inside_a_held_admission(state, repo, read).await
    };
    let (text, body) = tool_answer(&result);
    assert!(
        answer_is_current(&text, &body),
        "{tool} must answer from the graph the admission left, never with the absence it read \
         before: {text}"
    );
    assert!(
        !answered_inside_the_window,
        "{tool} issued while an admission holds graph authority must wait for it: {text}"
    );
}

/// `semantic_search` for the name the held admission adds waits for it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_semantic_search_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        false,
        "semantic_search",
        serde_json::json!({"query": "again"}),
        |_, body| {
            body["total_matches"].as_u64().is_some_and(|n| n > 0)
                && body["results"].to_string().contains("again")
        },
    )
    .await;
}

/// `semantic_locate` for the one name the held admission adds waits for it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_semantic_locate_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        false,
        "semantic_locate",
        serde_json::json!({"query": "again"}),
        |_, body| body["all_fallback"] != true && body["entities"].to_string().contains("again"),
    )
    .await;
}

/// `get_context_pack` naming two focals, one of which the held admission adds,
/// waits for it and packs both.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_get_context_pack_with_a_focal_the_admission_adds_waits_for_it() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let again_mentioned =
        |text: &str, _: &serde_json::Value| text.contains("again") && !text.contains("Kin daemon");
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        false,
        "get_context_pack",
        serde_json::json!({"entities": ["work", "again"]}),
        again_mentioned,
    )
    .await;
}

/// `get_context_pack` naming only a focal the held admission adds waits for it
/// rather than refusing that nothing resolved.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_get_context_pack_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        false,
        "get_context_pack",
        serde_json::json!({"entities": ["again"]}),
        |text, _| text.contains("again") && !text.contains("cannot resolve"),
    )
    .await;
}

/// `trace_computation` by the name the held admission adds waits for it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_trace_computation_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        false,
        "trace_computation",
        serde_json::json!({"query": "again"}),
        |text, _| !text.contains("no entity matches") && text.contains("again"),
    )
    .await;
}

/// `trace_path` from the name the held admission adds waits for it and finds
/// the route the edit wrote.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_trace_path_from_a_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        false,
        "trace_path",
        serde_json::json!({"from": "later", "to": "work"}),
        |_, body| body["found"] == true,
    )
    .await;
}

/// `explore_codebase` for the name the held admission adds waits for it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_explore_codebase_by_name_waits_for_the_admission_adding_that_name() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        false,
        "explore_codebase",
        serde_json::json!({"query": "again"}),
        |_, body| {
            body["content"].as_str().is_some_and(|content| {
                !content.starts_with("No entities found matching") && content.contains("again")
            })
        },
    )
    .await;
}

/// `dead_code` issued while the held admission adds `helper`'s first caller
/// waits for it and does not list `helper`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_dead_code_waits_for_the_admission_adding_a_reference() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    // The rows, whether the answer carries them bare or under the `result` key
    // the source-derivation disclosure files a bare list under.
    let rows = |body: &serde_json::Value| -> Option<Vec<serde_json::Value>> {
        body.as_array()
            .or_else(|| body["result"].as_array())
            .cloned()
    };
    let lists_helper = move |body: &serde_json::Value| {
        rows(body).is_some_and(|rows| rows.iter().any(|row| row["name"] == "helper"))
    };
    let before =
        admission_window_tool_call(Arc::clone(&state), "dead_code", serde_json::json!({})).await;
    let (before_text, before) = tool_answer(&before);
    assert!(
        lists_helper(&before),
        "nothing calls `helper` before the edit: {before_text}"
    );
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        false,
        "dead_code",
        serde_json::json!({}),
        |_, body| rows(body).is_some() && !lists_helper(body),
    )
    .await;
}

/// `find_dead_code_seeded` waits the same way.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_find_dead_code_seeded_waits_for_the_admission_adding_a_reference() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        false,
        "find_dead_code_seeded",
        serde_json::json!({"query": "helper"}),
        |_, body| {
            body["candidates"].as_array().is_some_and(|candidates| {
                !candidates
                    .iter()
                    .any(|candidate| candidate["name"] == "helper" && candidate["dead"] == true)
            })
        },
    )
    .await;
}

/// `graph_neighborhood` of an entity with no incoming relation yet waits for
/// the held admission that adds its first caller.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_graph_neighborhood_waits_for_the_admission_adding_a_first_relation() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let helper = admission_window_entity(&state, "target.py", "helper");
    let arguments = serde_json::json!({"entity_id": helper.id.to_string(), "direction": "in"});
    let before =
        admission_window_tool_call(Arc::clone(&state), "graph_neighborhood", arguments.clone())
            .await;
    let (before_text, before) = tool_answer(&before);
    assert_eq!(
        before["relation_count"].as_u64(),
        Some(0),
        "nothing reaches `helper` before the edit: {before_text}"
    );
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        false,
        "graph_neighborhood",
        arguments,
        |text, body| body["relation_count"].as_u64().is_some_and(|n| n > 0) && text.contains("later"),
    )
    .await;
}

/// Semantic discovery of an entity in a newly admitted source unit waits for
/// that admission rather than publishing a premature absence.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_semantic_search_waits_for_the_admission_adding_a_source_unit() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        true,
        "semantic_search",
        serde_json::json!({"query": "fresh"}),
        |_, body| {
            body["total_matches"].as_u64().is_some_and(|n| n > 0)
                && body["results"]
                    .as_array()
                    .is_some_and(|rows| rows.iter().any(|row| row["name"] == "fresh"))
        },
    )
    .await;
}

/// `lexical_lookup` for a literal only the held admission's edit carries waits
/// for it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_lexical_lookup_waits_for_the_admission_adding_the_literal() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        false,
        "lexical_lookup",
        serde_json::json!({"literal": "again"}),
        |_, body| body["total_matching"].as_u64().is_some_and(|n| n > 0),
    )
    .await;
}

/// `semantic_diff` over a file the held admission adds waits for it rather
/// than answering that the file resolved to no entity.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_semantic_diff_of_files_waits_for_the_admission_adding_the_file() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        true,
        "semantic_diff",
        serde_json::json!({"files": ["fresh.py"]}),
        |text, _| !text.contains("no entity resolved from the given files"),
    )
    .await;
}

/// `semantic_review` over a file the held admission adds waits the same way.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_semantic_review_of_files_waits_for_the_admission_adding_the_file() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        true,
        "semantic_review",
        serde_json::json!({"files": ["fresh.py"]}),
        |text, _| !text.contains("no entity resolved from the given files"),
    )
    .await;
}

/// `impact_analysis` of an entity with no consumer yet waits for the held
/// admission that adds its first.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_impact_analysis_waits_for_the_admission_adding_a_first_consumer() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let helper = admission_window_entity(&state, "target.py", "helper");
    let arguments = serde_json::json!({"entity_ids": [helper.id.to_string()]});
    let before =
        admission_window_tool_call(Arc::clone(&state), "impact_analysis", arguments.clone()).await;
    let (before_text, before) = tool_answer(&before);
    assert!(
        before["entity_impacts"].as_array().is_some_and(|rows| rows
            .iter()
            .any(|row| row["consumer_count"].as_u64() == Some(0))),
        "nothing consumes `helper` before the edit: {before_text}"
    );
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        false,
        "impact_analysis",
        arguments,
        |_, body| {
            body["entity_impacts"].as_array().is_some_and(|rows| {
                !rows.is_empty()
                    && rows
                        .iter()
                        .all(|row| row["consumer_count"].as_u64().is_some_and(|n| n > 0))
            })
        },
    )
    .await;
}

/// `kin_security_scan` issued while the held admission adds `helper`'s first
/// caller waits for it and does not report `helper` as uncalled.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn mcp_security_scan_waits_for_the_admission_adding_a_caller() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let reports_helper = |body: &serde_json::Value| {
        body["findings"].as_array().is_some_and(|findings| {
            findings.iter().any(|finding| {
                finding["name"] == "helper" && finding["finding_type"] == "orphaned-public"
            })
        })
    };
    let before =
        admission_window_tool_call(Arc::clone(&state), "kin_security_scan", serde_json::json!({}))
            .await;
    let (before_text, before) = tool_answer(&before);
    assert!(
        reports_helper(&before),
        "nothing calls `helper` before the edit: {before_text}"
    );
    assert_tool_waited_for_the_admission(
        &state,
        &repo,
        false,
        "kin_security_scan",
        serde_json::json!({}),
        |_, body| body["findings"].is_array() && !reports_helper(body),
    )
    .await;
}

/// `POST` one route as `session`, returning the status and the body as text.
#[cfg(unix)]
async fn admission_window_post_as(
    state: Arc<DaemonState>,
    route: &'static str,
    body: serde_json::Value,
    session: kin_model::SessionId,
) -> (axum::http::StatusCode, String) {
    let request = axum::http::Request::post(route)
        .header("content-type", "application/json")
        .header("X-Kin-Session", session.to_string())
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = tower::ServiceExt::oneshot(crate::api::router(state), request)
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

/// A session scoped to the fixture's committed head, the state before any edit
/// the test makes, built the way `POST /session/{id}/scope` builds one.
#[cfg(unix)]
async fn admission_window_historical_session(state: &Arc<DaemonState>) -> kin_model::SessionId {
    let binding = state.local_repository_authority_binding().unwrap();
    let head = kin_cli::commands::ref_lookup::resolve_ref(
        state.graph.as_ref(),
        &binding,
        Some("HEAD"),
    )
    .unwrap();
    let manager = crate::api::held_repository_authority(state).unwrap();
    let historical = Arc::new(kin_core::build_graph_at_ref(manager.as_ref(), &head).unwrap());
    let session = kin_model::SessionId::new();
    state
        .set_session_scope(&session, head.to_string(), head, historical)
        .await;
    session
}

/// A session's temporal scope is a historical graph no edit admission writes,
/// so a read of it that finds a name missing answers at once, even while a
/// writer holds the live graph's authority and the reconcile loop holds edits
/// it picked up. Waiting would wait on work that cannot put the name into
/// that graph, and at the limit it would refuse a correct historical answer.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn a_historical_scope_answers_its_miss_while_the_live_graph_is_being_written() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let session = admission_window_historical_session(&state).await;

    let writer = state.begin_graph_authority_mutation();
    let pending = state.begin_pending_admission();
    let source = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        admission_window_tool_call_as(
            Arc::clone(&state),
            "get_entity_source",
            serde_json::json!({"entity_id": "again"}),
            session,
        ),
    )
    .await;
    let search = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        admission_window_post_as(
            Arc::clone(&state),
            "/search",
            serde_json::json!({"query": "again"}),
            session,
        ),
    )
    .await;
    drop(pending);
    drop(writer);

    let source = source.expect(
        "a historical source read must answer its miss at once, not wait on the live graph",
    );
    let (text, _) = tool_answer(&source);
    assert!(
        text.contains("no entity found matching 'again'"),
        "the historical graph holds no `again`, and says so: {text}"
    );
    assert!(
        !text.contains("no settled graph authority"),
        "a historical read is never refused for a write to the live graph: {text}"
    );
    let (status, search) = search
        .expect("a historical search must answer its miss at once, not wait on the live graph");
    assert_eq!(status, axum::http::StatusCode::OK, "{search}");
    let search: serde_json::Value = serde_json::from_str(&search).unwrap();
    assert_eq!(search["total_matches"], 0, "{search}");
}

/// The negative control: a session whose scope was cleared reads the live
/// graph, so the same miss read by the same session waits for the writer and
/// the pending edits like any other live read.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn a_cleared_scope_reads_the_live_graph_and_waits_like_one() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let session = admission_window_historical_session(&state).await;
    state.clear_session_scope(&session).await;

    let writer = state.begin_graph_authority_mutation();
    let pending = state.begin_pending_admission();
    let read = tokio::spawn(admission_window_tool_call_as(
        Arc::clone(&state),
        "get_entity_source",
        serde_json::json!({"entity_id": "again"}),
        session,
    ));
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let answered_while_held = read.is_finished();
    drop(pending);
    drop(writer);
    let result = read.await.unwrap();
    let (text, _) = tool_answer(&result);

    assert!(
        !answered_while_held,
        "a read of the live graph must wait while its authority is held: {text}"
    );
    assert!(
        text.contains("no entity found matching 'again'"),
        "once nothing writes, the settled miss is served: {text}"
    );
}

/// A malformed argument is the caller's to fix, and no admission changes it.
/// A context pack call with an entity id that is not a uuid, beside one name
/// the graph holds and one it does not, answers with the invalid-id error at
/// once while edits are pending, rather than waiting on the missing name.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn a_malformed_context_pack_argument_is_refused_at_once_while_edits_are_pending() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));

    let pending = state.begin_pending_admission();
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        admission_window_tool_call(
            Arc::clone(&state),
            "get_context_pack",
            serde_json::json!({
                "entity_id": "not-a-uuid",
                "entities": ["work", "new_missing_name"],
            }),
        ),
    )
    .await;
    drop(pending);

    let answer =
        answer.expect("a malformed argument must be refused at once, not held behind edits");
    let (text, _) = tool_answer(&answer);
    assert_eq!(answer.is_error, Some(true), "{text}");
    assert!(
        text.contains("invalid entity_id"),
        "the refusal is the caller's own invalid id: {text}"
    );
    assert!(
        !text.contains("no settled graph authority"),
        "a malformed argument is never replaced with a write-window refusal: {text}"
    );
}

/// [`admission_window_tool_call`] as `session`.
#[cfg(unix)]
async fn admission_window_tool_call_as(
    state: Arc<DaemonState>,
    tool: &'static str,
    arguments: serde_json::Value,
    session: kin_model::SessionId,
) -> kin_mcp::ToolCallResult {
    let request = axum::http::Request::post("/mcp/tools/call")
        .header("content-type", "application/json")
        .header("X-Kin-Session", session.to_string())
        .body(axum::body::Body::from(
            serde_json::json!({
                "name": tool,
                "arguments": arguments,
            })
            .to_string(),
        ))
        .unwrap();
    let response = tower::ServiceExt::oneshot(crate::api::router(state), request)
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// The real reconcile loop, armed on a fixture's repository and settled after
/// startup, so the next round that finds work is the one the test causes.
#[cfg(unix)]
struct ArmedAdmissionLoop {
    cancel: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<()>>,
}

#[cfg(unix)]
impl ArmedAdmissionLoop {
    async fn start(state: &Arc<DaemonState>, config: LoopConfig) -> Self {
        let (cancel, receiver) = tokio::sync::watch::channel(false);
        let (armed, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_loop_armed(
            Arc::clone(state),
            config,
            receiver,
            Some(WatchArmed::new(armed)),
        ));
        let arming =
            crate::daemon::await_watch_armed(ready, std::time::Duration::from_secs(10)).await;
        assert_eq!(arming, crate::daemon::WatchArming::Armed);
        // Let any startup work finish first, so the round under test is the
        // one that picks the test's edit up.
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if state.reconciliation_status_str() == "idle" {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    if state.reconciliation_status_str() == "idle" {
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the loop settles after startup");
        Self { cancel, task }
    }

    /// Stop the loop, and say how it ended for the test to check last, after
    /// the assertions that say more about a failure.
    async fn stop(self) -> std::result::Result<(), String> {
        let Self { cancel, mut task } = self;
        let _ = cancel.send(true);
        match tokio::time::timeout(std::time::Duration::from_secs(30), &mut task).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(format!("the owned loop failed: {error}")),
            Ok(Err(error)) => Err(format!("the owned loop did not join: {error}")),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err("the owned loop did not stop within 30 s".to_string())
            }
        }
    }
}

/// Assert that a find_references by name for `name` waited for the edit that
/// adds it and answered from the graph the edit left.
#[cfg(unix)]
fn assert_waited_for_the_name(
    state: &DaemonState,
    result: &kin_mcp::ToolCallResult,
    answered_early: bool,
    file: &str,
    name: &str,
    window: &str,
) {
    let kin_mcp::ContentBlock::Text { text } = &result.content[0];
    assert!(
        !text.contains(kin_mcp::handlers::entities::FIND_REFERENCES_FOCAL_MISS),
        "a name in an edit the loop has drained must never be answered as absent {window}: {text}"
    );
    assert!(
        !answered_early,
        "a read by name issued {window} must wait for the edit: {text}"
    );
    assert_ne!(result.is_error, Some(true), "{text}");
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    let focal = admission_window_entity(state, file, name);
    assert_eq!(body["focal_entity"]["id"], focal.id.to_string(), "{body}");
    let retry = admission_window_disclosure(&body, "retry")
        .unwrap_or_else(|| panic!("an answer that waited must say it did: {body}"));
    assert!(
        retry["waited_for_writer_ms"]
            .as_u64()
            .is_some_and(|ms| ms > 0),
        "the retry disclosure must carry the wait: {retry}"
    );
    assert!(
        admission_window_disclosure(&body, "mutation_in_flight").is_none()
            && admission_window_disclosure(&body, "settled_replay").is_none(),
        "the read waited for the edit, so it answers current, not stale: {body}"
    );
}

/// A read by name that lands while the loop waits out the grace for an
/// imminent commit must wait for the edit the loop has drained, not certify
/// the name absent.
///
/// A round that finds events holds off for a share of what the last
/// publication cost, in case a commit is about to make its publication
/// redundant. The loop had drained the edit by then, but nothing marked it
/// until the pass started after the grace, so a find_references by name issued
/// inside it met no writer and no pending admission and answered "Entity not
/// found" for a function the agent had just saved. Here the loop is held at
/// the start of that grace while the read is issued, then let go to sit out
/// the rest of it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn a_reference_read_by_name_waits_through_the_commit_grace_for_a_drained_edit() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let running = ArmedAdmissionLoop::start(
        &state,
        LoopConfig {
            poll_interval_ms: 200,
            batch_size: 64,
        },
    )
    .await;
    // The grace is a share of what the last publication cost, capped at five
    // poll intervals and at a second. A publication this dear makes the round
    // sit out the whole second once the test lets it go, so the mark has to
    // hold through the real sleep as well as through the hold.
    state.record_authority_publication(std::time::Duration::from_secs(8));
    let (reached, release) = hold_next_round_at_for_test(&state, RoundHoldPoint::CommitGrace);
    std::fs::write(repo.path().join("caller.py"), ADMISSION_WINDOW_EDIT).unwrap();
    let in_the_grace = tokio::time::timeout(std::time::Duration::from_secs(30), reached).await;

    let read = tokio::spawn(admission_window_tool_call(
        Arc::clone(&state),
        "find_references",
        serde_json::json!({"query": "again"}),
    ));
    // Several times the old retry budget, which gave up after under a second.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let answered_inside_the_grace = read.is_finished();
    let _ = release.send(());
    let result = read.await.unwrap();
    let stopped = running.stop().await;

    assert!(
        in_the_grace.is_ok(),
        "the loop never reached the grace with the edit drained"
    );
    assert_waited_for_the_name(
        &state,
        &result,
        answered_inside_the_grace,
        "caller.py",
        "again",
        "while the round waits out the grace for an imminent commit",
    );
    stopped.unwrap();
}

/// A reference read by id that returns rows is served through the reconcile
/// loop's mark, and one that finds nothing waits for it.
///
/// The mark stands for files on their way into the graph, which bears only on
/// an answer that claims something is absent. It used to keep every reference
/// read from taking its snapshot, so a read by id for an entity with callers
/// waited out the whole grace and the pass behind it. Here the loop is held in
/// the grace with the edit drained. find_references by id for `work`, which
/// `run` already calls, must answer at once from the graph as it stands. The
/// same read for `helper`, which nothing calls until the held edit adds
/// `later`, claims an absence, so it must wait and then answer with `later`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn a_reference_read_by_id_with_rows_is_served_through_a_pending_admission() {
    let repo = tempfile::tempdir().unwrap();
    let (state, work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let helper = admission_window_entity(&state, "target.py", "helper");
    let running = ArmedAdmissionLoop::start(
        &state,
        LoopConfig {
            poll_interval_ms: 200,
            batch_size: 64,
        },
    )
    .await;
    let (reached, release) = hold_next_round_at_for_test(&state, RoundHoldPoint::CommitGrace);
    std::fs::write(repo.path().join("caller.py"), ADMISSION_WINDOW_EDIT).unwrap();
    let in_the_grace = tokio::time::timeout(std::time::Duration::from_secs(30), reached).await;
    let mark_up_before = state.pending_admission_active();

    let with_rows = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        admission_window_find_references(Arc::clone(&state), work.id),
    )
    .await;
    let without_rows = tokio::spawn(admission_window_find_references(
        Arc::clone(&state),
        helper.id,
    ));
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let answered_inside_the_grace = without_rows.is_finished();
    let mark_up_after = state.pending_admission_active();
    let _ = release.send(());
    let without_rows = without_rows.await.unwrap();
    let stopped = running.stop().await;

    assert!(
        in_the_grace.is_ok(),
        "the loop never reached the grace with the edit drained"
    );
    assert!(
        mark_up_before && mark_up_after,
        "the mark must be up across both reads, or neither read went through it"
    );
    let with_rows = with_rows.expect(
        "a read by id that returns rows must answer while the mark is up, not wait for it",
    );
    let kin_mcp::ContentBlock::Text { text } = &with_rows.content[0];
    assert_ne!(with_rows.is_error, Some(true), "{text}");
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["focal_entity"]["id"], work.id.to_string(), "{body}");
    let run = admission_window_entity(&state, "caller.py", "run");
    let rows = body["references"]
        .as_array()
        .expect("an answer with rows lists them");
    assert!(
        rows.iter().any(|row| row["entity_id"] == run.id.to_string()),
        "the answer is read from the graph as it stands: {body}"
    );
    assert!(
        admission_window_disclosure(&body, "retry").is_none()
            && admission_window_disclosure(&body, "mutation_in_flight").is_none()
            && admission_window_disclosure(&body, "settled_replay").is_none(),
        "no writer held authority, so the first attempt answered, current and unlabelled: \
         {body}"
    );

    let kin_mcp::ContentBlock::Text { text } = &without_rows.content[0];
    assert!(
        !answered_inside_the_grace,
        "a read by id that finds nothing must wait for the edit the loop has drained: {text}"
    );
    assert_ne!(without_rows.is_error, Some(true), "{text}");
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["focal_entity"]["id"], helper.id.to_string(), "{body}");
    let later = admission_window_entity(&state, "caller.py", "later");
    assert!(
        body["references"].as_array().is_some_and(|rows| rows
            .iter()
            .any(|row| row["entity_id"] == later.id.to_string())),
        "the answer must be read from the graph the edit left: {body}"
    );
    let retry = admission_window_disclosure(&body, "retry")
        .unwrap_or_else(|| panic!("an answer that waited must say it did: {body}"));
    assert!(
        retry["waited_for_writer_ms"]
            .as_u64()
            .is_some_and(|ms| ms > 0),
        "the retry disclosure must carry the wait: {retry}"
    );
    let detail = retry["detail"]
        .as_str()
        .expect("the disclosure carries a detail");
    assert!(
        detail.contains("answered that something is absent while the reconcile loop held"),
        "the disclosure must say an absence was held back for the loop: {detail}"
    );
    stopped.unwrap();
}

/// A read by name that lands while the loop stands down for a commit that has
/// announced itself must wait for the edit the loop has drained, for as many
/// rounds as the loop stands down.
///
/// A commit announces itself when its handler is entered, before it waits for
/// the coordination gate, and the loop leaves its queued events to that commit
/// rather than publish them twice. Nothing marked those events through the
/// stand-down, so a find_references by name issued before the commit published
/// answered "Entity not found". Here a commit is announced inside the daemon,
/// the loop is held at its first stand-down while the read is issued, and it
/// is then let go to stand down round after round until the commit leaves.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn a_reference_read_by_name_waits_through_a_commit_stand_down_for_a_drained_edit() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let running = ArmedAdmissionLoop::start(
        &state,
        LoopConfig {
            poll_interval_ms: 100,
            batch_size: 64,
        },
    )
    .await;
    let commit = state.pending_commits.announce();
    let (reached, release) =
        hold_next_round_at_for_test(&state, RoundHoldPoint::CommitStandDown);
    std::fs::write(repo.path().join("caller.py"), ADMISSION_WINDOW_EDIT).unwrap();
    let standing_down = tokio::time::timeout(std::time::Duration::from_secs(30), reached).await;

    let read = tokio::spawn(admission_window_tool_call(
        Arc::clone(&state),
        "find_references",
        serde_json::json!({"query": "again"}),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let answered_at_the_first_stand_down = read.is_finished();
    // Let the loop go on standing down for the commit, one round per poll
    // interval, with the read still waiting across the rounds.
    let _ = release.send(());
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let answered_across_the_stand_downs = read.is_finished();
    drop(commit);
    let result = read.await.unwrap();
    let stopped = running.stop().await;

    assert!(
        standing_down.is_ok(),
        "the loop never stood down for the announced commit with the edit drained"
    );
    assert_waited_for_the_name(
        &state,
        &result,
        answered_at_the_first_stand_down,
        "caller.py",
        "again",
        "while the loop stands down for an announced commit",
    );
    assert!(
        !answered_across_the_stand_downs,
        "the mark must hold across every round the loop stands down, not only the first"
    );
    stopped.unwrap();
}

/// The tail of a burst larger than one round's batch keeps the mark between
/// the rounds that admit it.
///
/// A round takes a bounded batch and leaves the rest queued. The next round
/// first waits on the coordination gate to sweep expired intents, then waits
/// out the grace before its pass, and the queued tail was unmarked for all of
/// that, so a read by name for a function in a file still queued answered
/// "Entity not found". Here each round takes one event, both files reach the
/// same round, and the read is issued while the second round waits out its
/// grace, for whichever file the first round did not take.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn a_reference_read_by_name_waits_for_the_queued_tail_of_a_burst() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let running = ArmedAdmissionLoop::start(
        &state,
        LoopConfig {
            poll_interval_ms: 100,
            batch_size: 1,
        },
    )
    .await;
    let burst = [("first.py", "alpha"), ("second.py", "omega")];
    // Every round opens with the intent sweep, under the coordination gate, and
    // drains the watcher after it. With the gate held here the loop parks at
    // the sweep, so both files are waiting when the next round drains.
    let coordination = state.coordination_gate.lock().await;
    for (file, name) in burst {
        std::fs::write(
            repo.path().join(file),
            format!("from target import work\n\ndef {name}():\n    return work(3)\n"),
        )
        .unwrap();
    }
    // Time for the watcher to deliver both notifications.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let (first_reached, first_release) =
        hold_next_round_at_for_test(&state, RoundHoldPoint::CommitGrace);
    drop(coordination);
    let first_round =
        tokio::time::timeout(std::time::Duration::from_secs(30), first_reached).await;
    // Asked for while the first round is held, so it can only be a later one.
    let (second_reached, second_release) =
        hold_next_round_at_for_test(&state, RoundHoldPoint::CommitGrace);
    let _ = first_release.send(());
    let second_round =
        tokio::time::timeout(std::time::Duration::from_secs(30), second_reached).await;
    // A pass that leaves a backlog stays `processing` and one that drains the
    // queue goes idle, so this says the second round is working through the
    // first round's tail rather than through a notification that came late.
    let working_through_the_tail = state.reconciliation_status_str() == "processing";
    let still_queued = burst
        .into_iter()
        .filter(|(file, name)| {
            !state
                .graph
                .query_entities(&EntityFilter {
                    file_path: Some(FilePathId::new(*file)),
                    ..Default::default()
                })
                .unwrap()
                .iter()
                .any(|entity| entity.name == *name)
        })
        .collect::<Vec<_>>();
    let (queued_file, queued_name) = still_queued.first().copied().unwrap_or(burst[1]);

    let read = tokio::spawn(admission_window_tool_call(
        Arc::clone(&state),
        "find_references",
        serde_json::json!({"query": queued_name}),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let answered_between_the_rounds = read.is_finished();
    let _ = second_release.send(());
    let result = read.await.unwrap();
    let stopped = running.stop().await;

    assert!(
        first_round.is_ok() && second_round.is_ok(),
        "the loop never reached two rounds' grace for the burst"
    );
    assert!(
        working_through_the_tail,
        "the first round must leave the second file queued, or this is no burst's tail"
    );
    assert_eq!(
        still_queued.len(),
        1,
        "one round took one file, so exactly one is still on its way: {still_queued:?}"
    );
    assert_waited_for_the_name(
        &state,
        &result,
        answered_between_the_rounds,
        queued_file,
        queued_name,
        "while the rest of a burst waits for the next round",
    );
    stopped.unwrap();
}

/// A file the ambient pass has picked up counts as an active write from the
/// moment the pass marks itself processing, not only once it takes its writer
/// guard.
///
/// The pass marks itself processing, then waits for the coordination gate and
/// the reconciler lock, and only then takes the guard. Here the real reconcile
/// loop is armed on the repository and the test holds the coordination gate,
/// the way a commit in flight would, so the pass that picks the edit up stops
/// at the gate holding no writer guard. A read by name for the function the
/// edit adds, issued in that window, used to find no writer, trust the
/// unchanged epoch and answer "Entity not found".
///
/// Every round opens by sweeping expired intents under that same gate, so a
/// gate taken before the edit is drained stops the loop at the sweep, where it
/// never sees the edit at all. The test takes it only once the round that
/// drained the edit is past the sweep and waiting out its grace.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial(commit_phase_capture)]
async fn a_reference_read_by_name_waits_for_a_file_the_ambient_pass_picked_up() {
    let repo = tempfile::tempdir().unwrap();
    let (state, _work) = admission_window_fixture(&repo).await;
    state.set_xref_writer_drain_ceiling_for_test(std::time::Duration::from_secs(120));
    let running = ArmedAdmissionLoop::start(
        &state,
        LoopConfig {
            poll_interval_ms: 20,
            batch_size: 64,
        },
    )
    .await;

    let (reached, release) = hold_next_round_at_for_test(&state, RoundHoldPoint::CommitGrace);
    std::fs::write(repo.path().join("caller.py"), ADMISSION_WINDOW_EDIT).unwrap();
    let drained = tokio::time::timeout(std::time::Duration::from_secs(30), reached).await;
    // Held the way a commit in flight holds it. The pass that picks the edit
    // up marks itself processing and then waits here, before its writer guard.
    let coordination = state.coordination_gate.lock().await;
    let _ = release.send(());
    let picked_up = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while state.reconciliation_status_str() != "processing" {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;

    let read = tokio::spawn(admission_window_tool_call(
        Arc::clone(&state),
        "find_references",
        serde_json::json!({"query": "again"}),
    ));
    // Several times the old retry budget, which gave up after under a second.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let answered_inside_the_window = read.is_finished();
    drop(coordination);
    let result = read.await.unwrap();

    // Always stop the owned loop before any assertion.
    let stopped = running.stop().await;
    assert!(drained.is_ok(), "the loop never drained the edit");
    assert!(
        picked_up.is_ok(),
        "the ambient pass never picked the edit up"
    );
    let kin_mcp::ContentBlock::Text { text } = &result.content[0];
    assert!(
        !text.contains(kin_mcp::handlers::entities::FIND_REFERENCES_FOCAL_MISS),
        "a name in a file the pass has picked up must never be answered as absent: {text}"
    );
    assert!(
        !answered_inside_the_window,
        "a read by name issued while the pass holds picked-up changes must wait for it: {text}"
    );
    assert_ne!(result.is_error, Some(true), "{text}");
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    let again = admission_window_entity(&state, "caller.py", "again");
    assert_eq!(body["focal_entity"]["id"], again.id.to_string(), "{body}");
    stopped.unwrap();
}
