// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

/// A start that owes parses beside a declaration this build no longer derives
/// serves after one repair.
///
/// A store an older build wrote, holding edits no commit recorded, carries
/// both. Repaired one cause at a time, each pass read the other cause's file
/// through the strict dependency reader and was refused by it, so the repair
/// reported incomplete and the daemon exited without ever serving.
#[cfg(unix)]
#[tokio::test]
async fn startup_rederives_owed_parses_beside_declarations_an_older_parser_minted() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    for (path, body) in [
        ("legacy.py", "def legacy():\n    return 1\n"),
        ("first.py", "def first():\n    return 2\n"),
        ("second.py", "def second():\n    return 3\n"),
    ] {
        std::fs::write(repo.path().join(path), body).unwrap();
    }
    sync_filesystem_with_graph(&state).await.unwrap();
    // A standalone observation owes durability for every admitted file. Record
    // the baseline before simulating the edits the old store did not record.
    let (status, body) = startup_diagnostic_commit(&state).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(crate::semantic_debt::outstanding(&state).is_empty());
    let declared = |file: &str, name: &str| {
        state
            .graph
            .query_entities(&EntityFilter {
                file_path: Some(FilePathId::new(file)),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .find(|entity| entity.name == name)
    };

    // One declaration more than this build derives from these bytes, stamped
    // with the file's own blob, which is what an older parser leaves behind.
    let legacy = declared("legacy.py", "legacy").unwrap();
    let mut retired = legacy.clone();
    retired.id = EntityId::new();
    retired.name = "retired_surface".into();
    state.graph.upsert_entity(&retired).unwrap();

    // Two edits whose bytes reached authority without their parse. A blank
    // line moves the declaration; a leading comment belongs to its span.
    let first = b"\ndef first():\n    return 20\n".to_vec();
    let second = b"\ndef second():\n    return 30\n".to_vec();
    std::fs::write(repo.path().join("first.py"), &first).unwrap();
    std::fs::write(repo.path().join("second.py"), &second).unwrap();
    exact_tree_admission(&state, None, TreePublication::Standalone).unwrap();
    assert_eq!(crate::semantic_debt::outstanding(&state).len(), 2);

    let (cancel, receiver) = tokio::sync::watch::channel(false);
    let (watch_tx, watch_rx) = tokio::sync::oneshot::channel();
    let (canonical_tx, canonical_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig::default(),
        receiver.clone(),
        Some(WatchArmed::with_canonical_ready(watch_tx, canonical_tx)),
    ));
    crate::daemon::await_watch_armed(watch_rx, Duration::from_secs(10)).await;
    let ready = tokio::time::timeout(
        Duration::from_secs(60),
        crate::daemon::await_canonical_ready(canonical_rx, receiver),
    )
    .await
    .expect("the startup repair must finish within its bound");
    cancel.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
    ready.expect("a start owing parses beside a stale declaration must serve after one repair");

    for (file, name, body) in [
        ("first.py", "first", &first),
        ("second.py", "second", &second),
    ] {
        let entity = declared(file, name).unwrap();
        assert_eq!(
            entity.span.unwrap().start_line,
            1,
            "{file} answers at its current bytes"
        );
        assert_eq!(
            entity.metadata.extra["blob_hash"],
            kin_blobs::digest(body).to_string()
        );
    }
    assert!(
        declared("legacy.py", "retired_surface").is_none(),
        "the declaration this build does not derive is retired"
    );
    assert_eq!(
        declared("legacy.py", "legacy").map(|entity| entity.id),
        Some(legacy.id),
        "the declaration it does derive keeps its identity"
    );

    let report = state.background_work.reconcile().report(Instant::now());
    let rederived = report
        .startup_rederivation
        .clone()
        .expect("the start must disclose what it re-derived");
    assert_eq!(
        (
            rederived.files,
            rederived.owed_parse,
            rederived.missing_entities,
            rederived.stale_declarations
        ),
        (3, 2, 0, 1)
    );
    assert!(
        report
            .notices()
            .iter()
            .any(|notice| notice.starts_with("At startup, this daemon re-derived 3 source file(s)")),
        "{:?}",
        report.notices()
    );
}

/// A rename no commit recorded, across two files, left for a restart.
///
/// The store the daemon loads still holds the old declaration and both of its
/// callers' bindings to it. The edited caller's own derivation is stale, so the
/// loaded store cannot ground a withdrawal record for its binding: it is dropped
/// and counted. The unchanged caller is one that store certifies, so its binding
/// keeps its withdrawal record, exactly as a live edit's would.
#[cfg(unix)]
#[tokio::test]
async fn startup_rederivation_keeps_certified_callers_debt_and_counts_the_stale_callers() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    for (path, body) in [
        ("b.py", "def double(value):\n    return value * 2\n"),
        (
            "a.py",
            "from b import double\n\n\ndef run(value):\n    return double(value) + 1\n",
        ),
        (
            "c.py",
            "from b import double\n\n\ndef other(value):\n    return double(value)\n",
        ),
    ] {
        std::fs::write(repo.path().join(path), body).unwrap();
    }
    sync_filesystem_with_graph(&state).await.unwrap();
    // A standalone observation owes durability for every admitted file. Record
    // the baseline before simulating the edits the old store did not record.
    let (status, body) = startup_diagnostic_commit(&state).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(crate::semantic_debt::outstanding(&state).is_empty());

    std::fs::write(
        repo.path().join("b.py"),
        "def twice(value):\n    return value * 2\n",
    )
    .unwrap();
    std::fs::write(
        repo.path().join("a.py"),
        "from b import twice\n\n\ndef run(value):\n    return twice(value) + 1\n",
    )
    .unwrap();
    exact_tree_admission(&state, None, TreePublication::Standalone).unwrap();

    let (cancel, receiver) = tokio::sync::watch::channel(false);
    let (watch_tx, watch_rx) = tokio::sync::oneshot::channel();
    let (canonical_tx, canonical_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig::default(),
        receiver.clone(),
        Some(WatchArmed::with_canonical_ready(watch_tx, canonical_tx)),
    ));
    crate::daemon::await_watch_armed(watch_rx, Duration::from_secs(10)).await;
    let ready = tokio::time::timeout(
        Duration::from_secs(60),
        crate::daemon::await_canonical_ready(canonical_rx, receiver),
    )
    .await
    .expect("the startup repair must finish within its bound");
    cancel.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
    ready.expect("a rename no commit recorded must not stop the daemon serving");

    let named = |name: &str| {
        state
            .graph
            .query_entities(&EntityFilter {
                name_pattern: Some(name.into()),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .filter(|entity| entity.name == name)
            .count()
    };
    assert_eq!(named("double"), 0, "the renamed declaration is retired");
    assert_eq!(named("twice"), 1);

    let report = state.background_work.reconcile().report(Instant::now());
    let rederived = report
        .startup_rederivation
        .expect("the start must disclose what it re-derived");
    assert!(
        rederived.withdrawn_bindings_unrecorded > 0,
        "the edited caller's stale binding is dropped and counted: {rederived:?}"
    );

    let file = FilePathId::new("c.py");
    let artifact = state
        .graph
        .artifact_id_at_path(&RepoPath::from_utf8("c.py").unwrap())
        .unwrap();
    let Some(TreeEntry::Blob { hash, .. }) = state.graph.get_tree_entry(&file).unwrap() else {
        panic!("c.py is admitted source");
    };
    let relations = state
        .graph
        .get_all_relations_for_node(&kin_model::GraphNodeId::Artifact(artifact))
        .unwrap();
    let debt = kin_index::binding_debt::inspect_local_binding_debt(
        &file,
        artifact,
        hash,
        &relations.iter().collect::<Vec<_>>(),
    )
    .unwrap()
    .expect("the unchanged caller keeps the record that it still calls the retired name");
    assert!(debt
        .obligations
        .iter()
        .any(|obligation| obligation.target_file.0 == "b.py"));
}

/// A start that retires a stored external-import edge on a failed recount
/// counts it and says so.
///
/// The edge carries an occurrence count this build's parser does not reproduce
/// from the bytes it was recorded against, which is what an older parser that
/// counted differently leaves behind, and its file's current bytes no longer
/// make the call. The start retires it rather than refusing to serve, and the
/// retirement reaches the startup record and the status notice.
#[cfg(unix)]
#[tokio::test]
async fn startup_rederivation_counts_the_external_edges_it_retired_on_a_failed_recount() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    for (path, body) in [
        (
            "caller.js",
            "const remote = require('external-one');\nfunction run() { return remote(); }\n",
        ),
        ("other.js", "function other() { return 2; }\n"),
    ] {
        std::fs::write(repo.path().join(path), body).unwrap();
    }
    sync_filesystem_with_graph(&state).await.unwrap();
    let (status, body) = startup_diagnostic_commit(&state).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(crate::semantic_debt::outstanding(&state).is_empty());

    let run = state
        .graph
        .query_entities(&EntityFilter {
            file_path: Some(FilePathId::new("caller.js")),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == "run")
        .unwrap();
    let mut edge = state
        .graph
        .get_all_relations_for_entity(&run.id)
        .unwrap()
        .into_iter()
        .find(|relation| {
            relation.src.as_entity() == Some(run.id)
                && kin_index::is_external_import_placeholder(relation)
        })
        .expect("the required module's call is an external-import edge");
    edge.evidence[0].occurrence_count = 2;
    state.graph.upsert_relation(&edge).unwrap();

    // Two edits no commit recorded, so the start re-derives both files in one
    // coherent pass. The caller no longer makes the external call.
    std::fs::write(
        repo.path().join("caller.js"),
        "function run() { return 1; }\n",
    )
    .unwrap();
    std::fs::write(
        repo.path().join("other.js"),
        "function other() { return 20; }\n",
    )
    .unwrap();
    exact_tree_admission(&state, None, TreePublication::Standalone).unwrap();
    assert_eq!(crate::semantic_debt::outstanding(&state).len(), 2);

    let (cancel, receiver) = tokio::sync::watch::channel(false);
    let (watch_tx, watch_rx) = tokio::sync::oneshot::channel();
    let (canonical_tx, canonical_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig::default(),
        receiver.clone(),
        Some(WatchArmed::with_canonical_ready(watch_tx, canonical_tx)),
    ));
    crate::daemon::await_watch_armed(watch_rx, Duration::from_secs(10)).await;
    let ready = tokio::time::timeout(
        Duration::from_secs(60),
        crate::daemon::await_canonical_ready(canonical_rx, receiver),
    )
    .await
    .expect("the startup repair must finish within its bound");
    cancel.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
    ready.expect("a start that retires an edge it cannot recount must still serve");

    assert!(
        state.graph.get_relation_by_id(&edge.id).is_none(),
        "the edge the current parser does not reproduce is retired"
    );
    let report = state.background_work.reconcile().report(Instant::now());
    let rederived = report
        .startup_rederivation
        .clone()
        .expect("the start must disclose what it re-derived");
    assert_eq!(rederived.external_edges_unreproduced, 1, "{rederived:?}");
    assert!(
        report
            .notices()
            .iter()
            .any(|notice| notice.contains("1 stored external-import edge(s) were retired")),
        "{:?}",
        report.notices()
    );
}

/// An entity loaded with no recorded source digest is stamped again at startup.
///
/// Stores derived before source digests were recorded hold entities whose span
/// names no blob, so their bodies read as unverified and no guarded change can
/// cite them. A daemon start compares every source entity with the blob its
/// file was admitted as, reads the missing digest as stale metadata, and
/// re-derives the file, so the entity it serves is stamped with its bytes and
/// keeps its identity.
#[cfg(unix)]
#[tokio::test]
async fn startup_restamps_a_source_entity_loaded_without_its_digest() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    let bytes = b"def unstamped():\n    return 1\n".to_vec();
    std::fs::write(repo.path().join("unstamped.py"), &bytes).unwrap();
    sync_filesystem_with_graph(&state).await.unwrap();
    let (status, body) = startup_diagnostic_commit(&state).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let declared = || {
        state
            .graph
            .query_entities(&EntityFilter {
                file_path: Some(FilePathId::new("unstamped.py")),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .find(|entity| entity.name == "unstamped")
    };

    // The state a pre-digest store loads into: the declaration without the
    // blob its span was cut from.
    let stamped = declared().expect("the declaration is admitted");
    assert_eq!(
        stamped.metadata.extra["blob_hash"],
        kin_blobs::digest(&bytes).to_string(),
        "the control: this build stamps what it derives"
    );
    let mut unstamped = stamped.clone();
    unstamped.metadata.extra.remove("blob_hash");
    state.graph.upsert_entity(&unstamped).unwrap();
    assert!(!declared()
        .unwrap()
        .metadata
        .extra
        .contains_key("blob_hash"));

    let (cancel, receiver) = tokio::sync::watch::channel(false);
    let (watch_tx, watch_rx) = tokio::sync::oneshot::channel();
    let (canonical_tx, canonical_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig::default(),
        receiver.clone(),
        Some(WatchArmed::with_canonical_ready(watch_tx, canonical_tx)),
    ));
    crate::daemon::await_watch_armed(watch_rx, Duration::from_secs(10)).await;
    let ready = tokio::time::timeout(
        Duration::from_secs(60),
        crate::daemon::await_canonical_ready(canonical_rx, receiver),
    )
    .await
    .expect("the startup repair must finish within its bound");
    cancel.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
    ready.expect("a start holding an unstamped entity must serve after one repair");

    let served = declared().expect("the declaration is still served");
    assert_eq!(served.id, stamped.id, "re-derivation keeps its identity");
    assert_eq!(
        served
            .metadata
            .extra
            .get("blob_hash")
            .and_then(|value| value.as_str()),
        Some(kin_blobs::digest(&bytes).to_string().as_str()),
        "the served entity is stamped with its file's bytes again"
    );
}
