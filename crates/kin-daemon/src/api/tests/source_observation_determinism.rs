// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// A source-derived query asked again over a graph that did not change must
// answer with the same bytes, disclosures included. The Go reference bench asks
// 75 questions three times and requires byte identity. One of its runs added
// `derived_source_unproven` to one answer the other two runs did not, over the
// same store, because the source inspection behind that clause could be
// refused by a 25 ms clock on a loaded host or by a writer overlapping it.

#[tokio::test]
async fn repeated_source_queries_disclose_the_same_settled_observation() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "settled source").await;
    waiting_commit(&state, "Commit settled source").await;
    let target = waiting_entity(&state, "local.py", "work").id.to_string();
    for (tool, arguments) in [
        ("find_references", json!({"entity_id": target})),
        (
            "graph_neighborhood",
            json!({"entity_id": target, "direction": "in", "depth": 1}),
        ),
        ("get_entity", json!({"entity_id": target})),
    ] {
        let mut served = Vec::new();
        let mut disclosed = Vec::new();
        for _ in 0..3 {
            let result = mcp_call(router(Arc::clone(&state)), tool, arguments.clone()).await;
            assert_ne!(
                result.is_error,
                Some(true),
                "{tool}: {}",
                mcp_result_text(&result)
            );
            served.push(mcp_result_text(&result));
            // The stdio finalizer builds the verdict an agent reads. Its
            // envelope also carries admission ages, which move with the clock
            // by design, so compare what it discloses rather than every byte.
            let envelope = kin_mcp::envelope::Envelope::daemon()
                .with_health(&daemon_health_snapshot(&state).await);
            let value = tool_result_payload(&kin_mcp::envelope::finalize(result, envelope, tool));
            disclosed.push(json!({
                "verdict": value["_kin"]["verdict"],
                "source_derivation": value["_kin"]["source_derivation"],
                "negative": value["negative"],
            }));
        }
        assert!(
            served.iter().all(|bytes| *bytes == served[0]),
            "{tool} served different bytes: {served:#?}"
        );
        assert!(
            disclosed.iter().all(|value| *value == disclosed[0]),
            "{tool} disclosed differently: {disclosed:#?}"
        );
        let settled = &disclosed[0];
        assert_eq!(
            settled["source_derivation"]["report"]["body_binding"], "current",
            "{tool}: {settled}"
        );
        assert!(
            !settled["verdict"]["limiting_factor"]
                .as_str()
                .unwrap_or_default()
                .contains("derived_source_unproven"),
            "{tool}: {settled}"
        );
    }

    // A writer in flight when the observation starts may delay it and nothing
    // more. This one holds the lock four times longer than the old clock and
    // writes nothing, so any change in the observation would be timing's.
    let settled =
        serde_json::to_string(&observe_live_head_sources(&state, &state.graph, None)).unwrap();
    let graph = Arc::clone(&state.graph);
    let (held, holding) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let _writer = graph.hold_entity_writer_for_test();
        held.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
    });
    holding.recv().unwrap();
    let delayed =
        serde_json::to_string(&observe_live_head_sources(&state, &state.graph, None)).unwrap();
    writer.join().unwrap();
    assert_eq!(delayed, settled);
}

// The observation waits for a write in flight, and it has to wait on the
// blocking pool. On a runtime with one worker, a wait on that worker would
// keep every other task from running until the writer let go.
#[tokio::test]
async fn a_write_in_flight_delays_the_observation_without_holding_the_runtime() {
    let (_repo, state) = mcp_lifecycle_fixture();
    let settled =
        serde_json::to_string(&observe_live_head_sources(&state, &state.graph, None)).unwrap();
    let graph = Arc::clone(&state.graph);
    let (held, holding) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let writer = std::thread::spawn(move || {
        let _writer = graph.hold_entity_writer_for_test();
        held.send(()).unwrap();
        // Released by the test. The bound turns a wait that took the only
        // worker into a failure below instead of a hang.
        let _ = released.recv_timeout(std::time::Duration::from_secs(10));
    });
    holding.recv().unwrap();
    let observation = tokio::spawn(observe_live_refs_sources_off_runtime(
        Arc::clone(&state),
        Arc::clone(&state.graph),
        kin_cli::commands::refs::RefsRequest {
            entity: "unused for an all-relations source observation".to_string(),
            kind: "all".to_string(),
        },
    ));
    // This task runs again only if the observation's wait left the worker free.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !observation.is_finished(),
        "the observation must still be waiting for the writer, on the blocking pool"
    );
    release.send(()).unwrap();
    let delayed = observation.await.unwrap().unwrap();
    writer.join().unwrap();
    assert_eq!(serde_json::to_string(&delayed).unwrap(), settled);
}
