// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

async fn binding_disclosure_impact(
    state: &Arc<DaemonState>,
    caller: kin_model::EntityId,
    outstanding: bool,
    stage: &str,
) {
    let result = mcp_call(
        router(Arc::clone(state)),
        "impact_analysis",
        json!({"entity_ids":[caller.to_string()], "include_traffic":false}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    let raw = tool_result_payload(&result);
    println!("binding disclosure {stage}: {raw}");
    let report = &raw["source_derivation"]["report"];
    assert_eq!(report["body_binding"], "current", "{stage}: {raw}");
    assert_eq!(report["parse_coverage"], "complete", "{stage}: {raw}");
    assert_eq!(
        report["call_shape_parse_coverage_complete"], true,
        "{stage}: {raw}"
    );
    assert_eq!(
        report["prior_local_binding"],
        if outstanding {
            "outstanding"
        } else {
            "no_recorded_debt"
        },
        "{stage}: {raw}"
    );
    let count = report["outstanding_local_binding_obligations"]
        .as_u64()
        .unwrap();
    assert_eq!(count > 0, outstanding, "{stage}: {raw}");
    if outstanding {
        assert_eq!(
            raw["entity_impacts"][0]["call_shapes"]["all_consumers_shaped_calls"], false,
            "{stage}: {raw}"
        );
    }
    // Exercise the production stdio finalizer with the actual served response
    // and health. This is not an OS-stdio process or agent-lifetime proof.
    let envelope =
        kin_mcp::envelope::Envelope::daemon().with_health(&daemon_health_snapshot(state).await);
    let value = tool_result_payload(&kin_mcp::envelope::finalize(
        result,
        envelope,
        "impact_analysis",
    ));
    assert_eq!(
        value["_kin"]["source_derivation"]["report"], *report,
        "{stage}: {value}"
    );
    if outstanding {
        assert_eq!(
            value["_kin"]["verdict"]["state"], "inconclusive",
            "{stage}: {value}"
        );
        assert!(
            value["_kin"]["verdict"]["limiting_factor"]
                .as_str()
                .unwrap()
                .contains("local_binding_outstanding"),
            "{stage}: {value}"
        );
    }
}

#[tokio::test]
async fn local_binding_disclosure_first_publication_strips_checked_source_qualification() {
    use kin_model::EntityStore as _;
    use kin_remote::first_publication::{
        publish_first_repository_observed, read_pinned_published_authority, FirstPublicationMode,
    };

    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "publication target").await;
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "publication caller").await;
    waiting_commit(&state, "Commit checked publication source").await;
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
            .unwrap();
    let source = Arc::new(context.open().unwrap());
    let source_backend = kin_db::LocalFileBackend::new(state.layout.kindb_dir());
    let before =
        kin_db::StorageBackend::load_snapshot(&source_backend, context.repository_id().as_str())
            .unwrap();
    let selected = source
        .read_authority()
        .workspace_graph_snapshot(&context.workspace_id())
        .unwrap()
        .unwrap();
    let source_graph = kin_db::InMemoryGraph::from_snapshot_without_text_index(selected).unwrap();
    assert!(matches!(
        source_graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));
    let destination_root = tempfile::tempdir().unwrap();
    let destination: Arc<dyn kin_db::StorageBackend> =
        Arc::new(kin_db::LocalFileBackend::new(destination_root.path()));
    let mut closure = None;
    let receipt = publish_first_repository_observed(
        Arc::clone(&source),
        context.repository_id(),
        FirstPublicationMode::Native,
        Arc::clone(&destination),
        |intent| {
            closure = Some((
                intent.source_closure.body_count(),
                intent.source_closure.total_bytes(),
                intent.source_closure.digest(),
            ));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(&receipt.roots, source.read_authority().roots());
    assert_eq!(
        kin_db::StorageBackend::load_snapshot(&source_backend, context.repository_id().as_str())
            .unwrap(),
        before
    );
    let (wire, _) = destination
        .load_snapshot(context.repository_id().as_str())
        .unwrap()
        .unwrap();
    let pinned = read_pinned_published_authority(
        context.repository_id(),
        Arc::clone(&destination),
        Arc::new(wire),
    )
    .unwrap();
    assert!(pinned.authority.binding_history.is_empty());
    assert!(pinned.source_closure.body_count() > 0);
    assert_eq!(
        closure.unwrap(),
        (
            pinned.source_closure.body_count(),
            pinned.source_closure.total_bytes(),
            pinned.source_closure.digest(),
        )
    );
    for _ in 0..2 {
        let reopened = kin_db::RepositoryAuthorityManager::open(
            context.repository_id().clone(),
            Arc::clone(&destination),
        )
        .unwrap();
        let lease = reopened.read_authority();
        assert_eq!(lease.roots(), &receipt.roots);
        let selected = lease
            .workspace_graph_snapshot(&context.workspace_id())
            .unwrap()
            .unwrap();
        let graph = kin_db::InMemoryGraph::from_snapshot_without_text_index(selected).unwrap();
        assert_eq!(
            graph.binding_history_observation(),
            kin_model::BindingHistoryObservation::Unproven
        );
    }
    let fresh_source = context.open().unwrap();
    let selected = fresh_source
        .read_authority()
        .workspace_graph_snapshot(&context.workspace_id())
        .unwrap()
        .unwrap();
    let graph = kin_db::InMemoryGraph::from_snapshot_without_text_index(selected).unwrap();
    assert!(matches!(
        graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));
}

#[tokio::test]
async fn local_binding_disclosure_preserves_checked_history_on_review_publication() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "review history caller").await;
    waiting_commit(&state, "Commit review history baseline").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    binding_disclosure_impact(&state, caller, false, "before review publication").await;
    let before = state
        .snapshot_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    let created = mcp_call(
        router(Arc::clone(&state)),
        "kin_review_create",
        json!({"title":"Binding history control", "base":"main", "head":"HEAD"}),
    )
    .await;
    assert_ne!(
        created.is_error,
        Some(true),
        "{}",
        mcp_result_text(&created)
    );
    assert!(
        state
            .snapshot_generation
            .load(std::sync::atomic::Ordering::SeqCst)
            > before
    );
    let after = state
        .snapshot_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        kin_model::EntityStore::binding_history_observation(state.graph.as_ref()),
        kin_model::BindingHistoryObservation::Checked { generation, .. } if generation == after
    ), "review publication must extend the actual checked predecessor to its new authority generation");
    let layout = state.layout.clone();
    for view in [state, waiting_cold_start(layout).await] {
        binding_disclosure_impact(&view, caller, false, "after checked review publication").await;
    }
}

#[tokio::test]
async fn local_binding_disclosure_survives_real_commit_cold_distraction_and_repair() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "disclosure target").await;
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "disclosure caller").await;
    waiting_commit(&state, "Commit binding disclosure fixture").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    binding_disclosure_impact(&state, caller, false, "resolved").await;
    std::fs::remove_file(repo.path().join("local.py")).unwrap();
    waiting_admit(&state, "disclosure remove target").await;
    binding_disclosure_impact(&state, caller, true, "removed").await;
    waiting_commit(&state, "Commit outstanding local binding").await;
    let layout = state.layout.clone();
    drop(state);
    let state = waiting_cold_start(layout).await;
    binding_disclosure_impact(&state, caller, true, "cold").await;
    std::fs::write(
        repo.path().join("unrelated.py"),
        "def work(value):\n    return value + 100\n",
    )
    .unwrap();
    waiting_admit(&state, "disclosure unrelated declaration").await;
    binding_disclosure_impact(&state, caller, true, "distracted").await;
    waiting_commit(&state, "Commit unresolved binding after distraction").await;
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "disclosure intended target restored").await;
    waiting_assert_recovered(
        &state,
        "caller.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        "disclosure recovered",
    )
    .await;
    binding_disclosure_impact(&state, caller, false, "repaired").await;
    waiting_commit(&state, "Commit repaired local binding").await;
    let layout = state.layout.clone();
    drop(state);
    let state = waiting_cold_start(layout).await;
    binding_disclosure_impact(&state, caller, false, "cold repaired").await;
}

/// Leave `file`'s current parse live and never durable, through the paths
/// production takes.
///
/// The parser refusing a body outright (a hard indexing error, not a partial
/// parse) makes the one-source batch hand the file back and the sequential
/// reconciler record the failure, so the bytes cross authority with their parse
/// owed. The test-only readmission index failure stands in for that fault: it
/// fails a one-source batch's indexing as well as the sequential readmission's,
/// which is the case this needs. Once the fault clears, the next admission's
/// drain re-derives the owed parse into the live graph and publishes nothing,
/// because only a commit pays owed work. A file whose parse was refused while
/// an edit landed sits in exactly this state until the next commit or the next
/// tree-moving admission, whose live observation carries it, with or without
/// one-source batches.
async fn admit_parse_live_only(state: &Arc<DaemonState>, file: &str, stage: &str) {
    *state.readmission_index_failure.lock().unwrap() = Some(kin_model::FilePathId::new(file));
    let (_, refused) = admit_through_api(&router(Arc::clone(state))).await;
    *state.readmission_index_failure.lock().unwrap() = None;
    println!("{stage}, indexing refused: {refused}");
    assert_eq!(refused["report"]["admitted"], false, "{stage}: {refused}");
    assert!(
        crate::semantic_debt::outstanding(state)
            .iter()
            .any(|entry| entry.path == file),
        "{stage}: the published bytes must leave their parse owed"
    );
    // The ledger records every moved path, so read authority itself: the
    // bytes must be there and their parse must not.
    let durable = durable_workspace_graph(state);
    let published = durable
        .resolved_tree
        .artifact_at_path(&kin_model::RepoPath::from_utf8(file).unwrap())
        .and_then(|artifact| artifact.entry.blob_identity())
        .expect("the refused admission still publishes the bytes");
    assert_ne!(
        certified_body(&durable, file),
        Some(published),
        "{stage}: the refused parse must not reach persisted authority"
    );
    waiting_admit(state, &format!("{stage}, owed parse drained")).await;
}

/// Whether `state` holds a call out of `caller` live, and whether persisted
/// authority holds one, read from the store rather than the live graph.
fn live_and_durable_calls_from(state: &DaemonState, caller: kin_model::EntityId) -> (bool, bool) {
    let calls = |graph: &kin_db::GraphSnapshot| {
        graph.relations.values().any(|relation| {
            relation.kind == kin_model::RelationKind::Calls && relation.src.as_entity() == Some(caller)
        })
    };
    let live = state.graph.semantic_observation();
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)
            .unwrap();
    let durable = context
        .open()
        .unwrap()
        .read_authority()
        .workspace_graph_snapshot(&context.workspace_id())
        .unwrap()
        .unwrap();
    (calls(&live), calls(&durable))
}

fn binding_history_len(state: &DaemonState) -> usize {
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)
            .unwrap();
    context
        .open()
        .unwrap()
        .read_authority()
        .metadata()
        .binding_history
        .len()
}

fn binding_observation_label(state: &DaemonState) -> &'static str {
    match state.graph.binding_history_observation() {
        kin_model::BindingHistoryObservation::Checked { .. } => "checked",
        kin_model::BindingHistoryObservation::Unproven => "unproven",
    }
}

#[tokio::test]
async fn local_binding_absence_stays_authoritative_after_an_offline_directory_is_committed() {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    // The acceptance seed is a package with a real cross-file call, not two
    // loose modules. The control commits a directory written while the daemon
    // is down and then asks for a name nothing declares.
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::create_dir_all(repo.path().join("notekeeper")).unwrap();
    std::fs::write(repo.path().join("notekeeper/__init__.py"), "").unwrap();
    std::fs::write(
        repo.path().join("notekeeper/parsing.py"),
        "STEM_SPLIT = \"#\"\n\n\ndef parse_key(raw):\n    return raw.split(STEM_SPLIT)[0]\n",
    )
    .unwrap();
    std::fs::write(
        repo.path().join("notekeeper/storage.py"),
        "from notekeeper.parsing import parse_key\n\n\ndef store(rows, raw):\n    \
         rows.append(parse_key(raw))\n    return rows\n",
    )
    .unwrap();
    waiting_admit(&state, "notekeeper seed").await;
    waiting_commit(&state, "seed the modules the graph knows").await;
    let seeded_history = binding_history_len(&state);
    assert!(
        seeded_history > 0,
        "the seed commit must leave a checked binding witness"
    );

    let layout = state.layout.clone();
    drop(state);
    std::fs::create_dir_all(repo.path().join("linkgraph")).unwrap();
    std::fs::write(
        repo.path().join("linkgraph/predicates.py"),
        "RESOLVE_PREDICATE = \"(notes.key = links.target_key)\"\n\n\
         def dangling_links(conn):\n    return conn.execute(\"SELECT 1 FROM notes WHERE \" + RESOLVE_PREDICATE)\n\n\
         def resolve_key(conn, key):\n    return conn.execute(\"SELECT 1 FROM notes WHERE key = ?\", (key,))\n",
    )
    .unwrap();
    let state = Arc::new(DaemonState::open(layout).unwrap());
    state.is_initialized.store(true, Ordering::Relaxed);
    assert_eq!(
        binding_observation_label(&state),
        "checked",
        "reopen must keep the seed witness"
    );
    let (cancel, receiver) = tokio::sync::watch::channel(false);
    let (armed, ready) = tokio::sync::oneshot::channel();
    let mut task = tokio::spawn(crate::loop_runner::run_loop_armed(
        Arc::clone(&state),
        crate::loop_runner::LoopConfig {
            poll_interval_ms: 20,
            batch_size: 8,
        },
        receiver,
        Some(crate::loop_runner::WatchArmed::new(armed)),
    ));
    crate::daemon::await_watch_armed(ready, Duration::from_secs(10)).await;
    let path = kin_model::RepoPath::from_utf8("linkgraph/predicates.py").unwrap();
    let derived = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let entities = state
                .graph
                .query_entities(&kin_db::EntityFilter {
                    file_path: Some(kin_model::FilePathId::new("linkgraph/predicates.py")),
                    ..Default::default()
                })
                .unwrap_or_default();
            if entities.iter().any(|entity| entity.name == "dangling_links") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        derived.is_ok(),
        "startup catch-up must derive the directory written while the daemon was down; tree={:?} history={} observation={}",
        state.graph.resolved_tree().artifact_at_path(&path).is_some(),
        binding_history_len(&state),
        binding_observation_label(&state)
    );
    // Leave the loop running through the commit, which is what `kin commit`
    // does against a daemon that graph status already started.
    tokio::time::sleep(Duration::from_millis(200)).await;
    waiting_commit(&state, "land the stranded module").await;
    assert_eq!(
        binding_observation_label(&state),
        "checked",
        "the commit must keep the witness"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The acceptance daemon queues a language-server sweep, and a sweep over a
    // store it has already enriched re-offers the edges the graph is holding.
    // That is not a write, so it must not take the truth lock and must not
    // drop the witness. The control's absence is read after that re-offer.
    let parse_key = waiting_entity(&state, "notekeeper/parsing.py", "parse_key");
    let store_fn = waiting_entity(&state, "notekeeper/storage.py", "store");
    let held = kin_model::EntityStore::get_all_relations_for_entity(&*state.graph, &store_fn.id)
        .unwrap()
        .into_iter()
        .find(|relation| relation.dst == kin_model::GraphNodeId::Entity(parse_key.id))
        .expect("the seeded package holds the cross-file call this control re-offers");
    crate::daemon::install_lsp_relations(&state, std::slice::from_ref(&held));
    assert_eq!(
        binding_observation_label(&state),
        "checked",
        "re-offering an edge the graph already holds is not a write and keeps the witness"
    );

    let result = mcp_call(
        router(Arc::clone(&state)),
        "find_references",
        json!({
            "query": "NOTHING_IN_THIS_REPOSITORY_CARRIES_THIS_NAME",
            "answer_only": false
        }),
    )
    .await;
    let envelope =
        kin_mcp::envelope::Envelope::daemon().with_health(&daemon_health_snapshot(&state).await);
    let finalized = tool_result_payload(&kin_mcp::envelope::finalize(
        result,
        envelope,
        "find_references",
    ));
    let negative = finalized
        .get("negative")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    assert_eq!(
        negative["safe_to_conclude_absent"], true,
        "a name nothing declares, over the committed tree, must stay authoritative: history={} observation={} finalized={finalized}",
        binding_history_len(&state),
        binding_observation_label(&state)
    );
    let reason = negative["trust_reason"].as_str().unwrap_or("");
    assert!(
        !reason.contains("local_binding_unproven"),
        "absence must not be withheld for an unproven local binding: {finalized}"
    );

    // The negative control, last because it is destructive, and the reason this
    // test no longer asks for more than the re-offer. A language-server edge the
    // graph does NOT hold is unverified input, and the interval that takes it
    // stops being checked; that is what `local_binding_unproven` means, and the
    // late-fresh-call and crash-prefix controls already on main require it.
    // Asserting that the witness survives such a write would state the opposite.
    let mut fresh = held;
    fresh.id = kin_model::RelationId::new();
    fresh.kind = kin_model::RelationKind::References;
    crate::daemon::install_lsp_relations(&state, &[fresh]);
    assert_eq!(
        binding_observation_label(&state),
        "unproven",
        "an edge the graph did not hold is unverified input and unsettles the interval"
    );

    let _ = cancel.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), &mut task).await;
}

#[tokio::test]
async fn local_binding_disclosure_does_not_invent_debt_for_initial_external_import() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "initial external import").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    binding_disclosure_impact(&state, caller, false, "initial external").await;
    waiting_commit(&state, "Commit ordinary external import").await;
    let layout = state.layout.clone();
    drop(state);
    let state = waiting_cold_start(layout).await;
    binding_disclosure_impact(&state, caller, false, "cold external").await;
}

#[tokio::test]
async fn local_binding_disclosure_retains_never_committed_binding_through_removal_and_cold_open() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "uncommitted target arrival").await;
    // Settle the target before introducing the caller so a coherent admission
    // cannot durably publish the call this fixture must leave live-only. The
    // caller's parse is refused while its bytes land and derived by the drain
    // after, so the call is live and never durable, as production leaves it
    // until the next commit or tree-moving admission.
    waiting_commit(&state, "Commit target before uncommitted call observation").await;
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    admit_parse_live_only(&state, "caller.py", "uncommitted call observation").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    assert_eq!(
        live_and_durable_calls_from(&state, caller),
        (true, false),
        "the call must be live and absent from persisted authority"
    );
    let target = waiting_entity(&state, "local.py", "work").id;
    assert!(
        state
            .graph
            .get_all_relations_for_node(&kin_model::GraphNodeId::Entity(caller))
            .unwrap()
            .iter()
            .any(|r| r.kind == kin_model::RelationKind::Calls && r.dst.as_entity() == Some(target)),
        "the actual live parser/linker must have observed this local call"
    );
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
            .unwrap();
    let authority = context.open().unwrap();
    let before = authority
        .read_authority()
        .workspace_graph_snapshot(&context.workspace_id())
        .unwrap()
        .unwrap();
    assert!(
        !before
            .relations
            .values()
            .any(|r| r.kind == kin_model::RelationKind::Calls && r.src.as_entity() == Some(caller)),
        "this regression must exercise a local call absent from durable authority"
    );
    let initial_changes = before.changes.len();
    let initial_generation = authority.read_authority().roots().generation;
    drop(before);
    drop(authority);
    std::fs::remove_file(repo.path().join("local.py")).unwrap();
    waiting_admit(&state, "never-committed target removed").await;
    let authority = context.open().unwrap();
    assert!(
        authority.read_authority().roots().generation > initial_generation,
        "read the newly published authority, not a retained predecessor manager"
    );
    let durable = authority
        .read_authority()
        .workspace_graph_snapshot(&context.workspace_id())
        .unwrap()
        .unwrap();
    assert_eq!(
        durable.changes.len(),
        initial_changes,
        "no native commit may hide the publication gap"
    );
    assert!(
        durable
            .relations
            .values()
            .any(kin_index::binding_debt::claims_local_binding_debt),
        "the exact tree admission must durably retain the observed never-committed binding debt"
    );
    binding_disclosure_impact(&state, caller, true, "uncommitted removal warm").await;
    let layout = state.layout.clone();
    drop(authority);
    drop(state);
    let state = waiting_cold_start(layout).await;
    binding_disclosure_impact(&state, caller, true, "uncommitted removal cold").await;
}

async fn binding_review_call(
    state: &Arc<DaemonState>,
    tool: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    let result = mcp_call(router(Arc::clone(state)), tool, arguments).await;
    assert_ne!(
        result.is_error,
        Some(true),
        "{tool}: {}",
        mcp_result_text(&result)
    );
    tool_result_payload(&result)
}

fn binding_review_plan(
    state: &Arc<DaemonState>,
    title: &str,
) -> (crate::review_write::ReviewPublication, String) {
    let args = json!({"title":title,"base":"main","head":"HEAD"})
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let planned = kin_mcp::handlers::review::plan_review_mutation(
        "kin_review_create",
        &args,
        state.graph.as_ref(),
    )
    .unwrap()
    .unwrap();
    let id = tool_result_payload(&planned.answer)["review_id"]
        .as_str()
        .unwrap()
        .to_string();
    let authority =
        crate::local_repository_authority::ActiveLocalRepositoryAuthority::open(state).unwrap();
    let publication = crate::review_write::ReviewPublication::prepare(
        state,
        &authority,
        planned.write.to_delta().unwrap(),
        "retained review publication control",
        &AuthorId::new("review-capture-test"),
    )
    .unwrap();
    (publication, id)
}

#[tokio::test]
async fn local_binding_disclosure_review_routes_capture_never_committed_calls_and_removal() {
    let (repo, mut state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "review target without native commit").await;
    // Only the later call must be absent from durable authority; the target
    // baseline must be settled before the caller is admitted on its own.
    waiting_commit(&state, "Commit target before uncommitted review call").await;
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    // The caller's parse is refused while its bytes land and derived by the
    // drain after, so the call is live and never durable, as production
    // leaves it until the next commit or tree-moving admission.
    admit_parse_live_only(&state, "caller.py", "review caller without native commit").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    assert_eq!(
        live_and_durable_calls_from(&state, caller),
        (true, false),
        "the call must be live and absent from persisted authority"
    );
    let source = kin_model::GraphNodeId::Entity(caller);
    assert!(state
        .graph
        .get_all_relations_for_node(&source)
        .unwrap()
        .iter()
        .any(|relation| relation.src == source && relation.kind == kin_model::RelationKind::Calls));
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
            .unwrap();
    let authority = context.open().unwrap();
    let lease = authority.read_authority();
    let before = lease
        .workspace_graph_snapshot(&context.workspace_id())
        .unwrap()
        .unwrap();
    assert!(
        !before
            .relations
            .values()
            .any(|relation| relation.src == source
                && relation.kind == kin_model::RelationKind::Calls),
        "the review must capture a binding that the durable selected graph did not yet hold"
    );
    let changes_before = lease.snapshot().changes.len();
    let tree_before = before.resolved_tree;
    drop(lease);
    drop(authority);
    let created = binding_review_call(
        &state,
        "kin_review_create",
        json!({"title":"retained uncommitted calls","base":"main","head":"HEAD"}),
    )
    .await;
    let review = created["review_id"].as_str().unwrap().to_string();
    let authority = context.open().unwrap();
    let lease = authority.read_authority();
    let after = lease
        .workspace_graph_snapshot(&context.workspace_id())
        .unwrap()
        .unwrap();
    assert_eq!(
        after.resolved_tree, tree_before,
        "review may not admit source bytes"
    );
    assert_eq!(
        lease.snapshot().changes.len(),
        changes_before,
        "review creates no native source commit"
    );
    assert!(after
        .relations
        .values()
        .any(|relation| relation.src == source && relation.kind == kin_model::RelationKind::Calls));
    drop(lease);
    drop(authority);
    binding_disclosure_impact(&state, caller, false, "created review").await;
    state = waiting_cold_start(state.layout.clone()).await;
    binding_disclosure_impact(&state, caller, false, "created review cold").await;
    for (tool, arguments) in [
        (
            "kin_review_discuss",
            json!({"review_id":review,"body":"Keep this actual binding"}),
        ),
        (
            "kin_review_assign",
            json!({"review_id":review,"reviewer":"binding-reviewer"}),
        ),
        (
            "kin_review_decide",
            json!({"review_id":review,"state":"approved","reviewer":"binding-reviewer"}),
        ),
    ] {
        binding_review_call(&state, tool, arguments).await;
        binding_disclosure_impact(&state, caller, false, tool).await;
        let previous = review_surfaces(&state, &review).await;
        state = waiting_cold_start(state.layout.clone()).await;
        assert_eq!(review_surfaces(&state, &review).await, previous);
        binding_disclosure_impact(&state, caller, false, &format!("{tool} cold")).await;
    }
    std::fs::remove_file(repo.path().join("local.py")).unwrap();
    waiting_admit(&state, "withdraw captured review target").await;
    binding_disclosure_impact(&state, caller, true, "withdraw after reviews").await;
    state = waiting_cold_start(state.layout.clone()).await;
    binding_disclosure_impact(&state, caller, true, "withdraw after reviews cold").await;
}

#[tokio::test]
async fn local_binding_disclosure_review_does_not_requalify_unknown_or_transfer() {
    for transferred in [false, true] {
        let (repo, state) = mcp_lifecycle_fixture();
        std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
        waiting_admit(&state, "unknown review source").await;
        waiting_commit(&state, "Commit unknown review baseline").await;
        let caller = waiting_entity(&state, "caller.py", "run").id;
        binding_disclosure_impact(&state, caller, false, "before qualification lost").await;
        let state = if transferred {
            let authority =
                crate::local_repository_authority::ActiveLocalRepositoryAuthority::open(&state)
                    .unwrap();
            let roots = authority.manager.read_authority().roots().clone();
            authority
                .manager
                .commit_transferred_repository_transaction(
                    kin_model::RepositoryTransaction {
                        schema_version: kin_model::REPOSITORY_TRANSACTION_SCHEMA_VERSION,
                        operation_id: kin_model::OperationId::new(),
                        repository_id: authority.repository_id.clone(),
                        expected_generation: roots.generation,
                        expected_roots: roots,
                        actor: AuthorId::new("transferred-control"),
                        reason: "unqualified transferred operation".into(),
                        external_objects: vec![],
                        git_authority_delta: None,
                        changes: vec![],
                        aliases: vec![],
                        ref_mutations: vec![kin_model::RefMutation {
                            name: kin_model::RefName::branch(b"transferred-reference").unwrap(),
                            expected: kin_model::RefExpectation::MustNotExist,
                            new_target: Some(kin_model::RefTarget::symbolic(
                                kin_model::RefName::branch(b"main").unwrap(),
                            )),
                            policy: kin_model::RefUpdatePolicy::FastForwardOnly,
                        }],
                        default_ref_mutation: None,
                        workspace_mutation: None,
                        local_overlay_delta: None,
                        merge_transaction_delta: None,
                        sealed_observation: None,
                        collaboration_delta: None,
                    },
                    None,
                )
                .unwrap();
            waiting_cold_start(state.layout.clone()).await
        } else {
            // An unobserved live interval must not be repaired from matching
            // current bytes just because durable authority is still Checked.
            state.graph.invalidate_binding_history();
            state
        };
        assert_eq!(
            kin_model::EntityStore::binding_history_observation(state.graph.as_ref()),
            kin_model::BindingHistoryObservation::Unproven
        );
        binding_review_call(
            &state,
            "kin_review_create",
            json!({"title":"unknown remains unknown","base":"main","head":"HEAD"}),
        )
        .await;
        let layout = state.layout.clone();
        for view in [state, waiting_cold_start(layout).await] {
            assert_eq!(
                kin_model::EntityStore::binding_history_observation(view.graph.as_ref()),
                kin_model::BindingHistoryObservation::Unproven
            );
            let result = binding_review_call(
                &view,
                "impact_analysis",
                json!({"entity_ids":[caller.to_string()],"include_traffic":false}),
            )
            .await;
            let report = &result["source_derivation"]["report"];
            assert_eq!(report["body_binding"], "current");
            assert_eq!(report["parse_coverage"], "complete");
            assert_eq!(report["prior_local_binding"], "unproven");
            assert!(report["outstanding_local_binding_obligations"].is_null());
        }
    }
}

#[tokio::test]
async fn local_binding_disclosure_review_capture_refuses_changed_roots() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "conflict source").await;
    waiting_commit(&state, "Commit conflict baseline").await;
    let (pending, pending_id) = binding_review_plan(&state, "stale capture must not publish");
    binding_review_call(
        &state,
        "kin_review_create",
        json!({"title":"intervening publication","base":"main","head":"HEAD"}),
    )
    .await;
    let authority =
        crate::local_repository_authority::ActiveLocalRepositoryAuthority::open(&state).unwrap();
    let roots = authority.manager.read_authority().roots().clone();
    assert!(matches!(
        pending.commit(&authority),
        Err(kin_db::KinDbError::Model(kin_model::ModelError::Conflict(
            _
        )))
    ));
    assert_eq!(authority.manager.read_authority().roots(), &roots);
    let result = mcp_call(
        router(Arc::clone(&state)),
        "kin_review_get",
        json!({"review_id":pending_id}),
    )
    .await;
    assert_eq!(
        result.is_error,
        Some(true),
        "stale review must remain absent"
    );
}

#[tokio::test]
async fn local_binding_disclosure_review_reply_loss_replays_exact_checked_operation() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "lost reply source").await;
    waiting_commit(&state, "Commit lost reply baseline").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    let (pending, review) = binding_review_plan(&state, "durable reply loss control");
    let authority =
        crate::local_repository_authority::ActiveLocalRepositoryAuthority::open(&state).unwrap();
    let first = pending.commit(&authority).unwrap();
    let layout = state.layout.clone();
    drop(authority);
    drop(state); // Durable CAS occurred; live apply/response deliberately did not.
    let state = waiting_cold_start(layout).await;
    binding_review_call(&state, "kin_review_get", json!({"review_id":review})).await;
    binding_disclosure_impact(&state, caller, false, "lost reply cold").await;
    let authority =
        crate::local_repository_authority::ActiveLocalRepositoryAuthority::open(&state).unwrap();
    let roots = authority.manager.read_authority().roots().clone();
    let replay = pending.commit(&authority).unwrap();
    assert_eq!(replay.operation_id, first.operation_id);
    assert_eq!(replay.transaction_hash, first.transaction_hash);
    assert_eq!(replay.roots_before, first.roots_before);
    assert_eq!(replay.roots_after, first.roots_after);
    assert_eq!(authority.manager.read_authority().roots(), &roots);
    assert_eq!(
        replay.outcome,
        kin_model::RepositoryCommitOutcome::IdempotentReplay
    );
}
