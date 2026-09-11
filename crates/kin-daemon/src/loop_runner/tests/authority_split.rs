// The live graph falling behind repository authority, and the levelling that
// brings it back level. Included into `loop_runner::tests`.

/// Plant the edge a late enrichment write can leave: a relation whose source
/// entity the graph does not hold.
///
/// `upsert_relation` does not judge entity endpoints, while kin-db's
/// transaction gate refuses every later transaction as long as one stands.
/// Returns the relation and the endpoint it is filed under.
#[cfg(unix)]
fn split_plant_relation_from_a_missing_entity(
    state: &Arc<DaemonState>,
    target_file: &str,
) -> (kin_model::RelationId, kin_model::GraphNodeId) {
    let target = state
        .graph
        .query_entities(&EntityFilter {
            file_path: Some(FilePathId::new(target_file)),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| entity.kind == kin_model::EntityKind::Function)
        .expect("the fixture file derives a function");
    let endpoint = kin_model::GraphNodeId::Entity(target.id);
    let relation = kin_model::Relation {
        id: kin_model::RelationId::new(),
        kind: kin_model::RelationKind::Calls,
        src: kin_model::GraphNodeId::Entity(EntityId::new()),
        dst: endpoint,
        confidence: 0.95,
        origin: kin_model::RelationOrigin::Lsp,
        created_in: None,
        import_source: None,
        evidence: Vec::new(),
    };
    state.graph.upsert_relation(&relation).unwrap();
    (relation.id, endpoint)
}

#[cfg(unix)]
fn split_relation_is_held(
    state: &DaemonState,
    relation: kin_model::RelationId,
    endpoint: kin_model::GraphNodeId,
) -> bool {
    state
        .graph
        .get_all_relations_for_node(&endpoint)
        .unwrap()
        .iter()
        .any(|held| held.id == relation)
}

#[cfg(unix)]
fn split_function_start_line(state: &DaemonState, name: &str) -> u32 {
    state
        .graph
        .query_entities(&EntityFilter::default())
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == name && entity.kind == kin_model::EntityKind::Function)
        .and_then(|entity| entity.span)
        .map(|span| span.start_line)
        .expect("the function is in the graph with a span")
}

/// Move repository authority to new bytes at `rel_path` without the live graph
/// hearing of it, which is the state a split leaves: authority one generation
/// ahead of the graph.
#[cfg(unix)]
fn split_publish_behind_the_graphs_back(state: &Arc<DaemonState>, rel_path: &str, content: &[u8]) {
    std::fs::write(state.layout.working_dir().join(rel_path), content).unwrap();
    let digest = state.blobs.write(content).unwrap();
    let previous = state.graph.resolved_tree();
    let path = test_repo_path(rel_path);
    let desired = kin_model::ResolvedTree::from_artifacts(previous.artifacts_by_path().map(
        |artifact| {
            if artifact.path == path {
                kin_model::ResolvedArtifact::new(
                    artifact.artifact_id,
                    artifact.path.clone(),
                    TreeEntry::blob(Hash256::from_bytes(digest.0), false),
                )
            } else {
                artifact.clone()
            }
        },
    ))
    .unwrap();
    let (roots, _) = current_authority_admission(state).unwrap();
    let admitted = crate::repository_commit::admitted_workspace_tree_for_test(
        state.layout.working_dir(),
        roots,
        previous,
        desired,
    );
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)
            .unwrap();
    crate::repository_commit::publish_workspace_tree(
        state.blobs.as_ref(),
        &context,
        &admitted,
        kin_model::OperationId::new(),
        kin_model::AuthorId::new("a writer this daemon never heard from"),
    )
    .unwrap()
    .expect("authority moves to the new bytes");
}

/// An admission whose tree authority accepts and whose graph apply is refused is
/// finished in the same round: the graph is levelled with authority, the relation
/// that refused it is dropped with a record, and the next admission plans from
/// the tree authority holds.
///
/// This is the split reproduced through its real trigger, a relation whose
/// source entity the graph does not hold. Without the levelling the round hands
/// back the refusal with authority one generation ahead of the graph, and every
/// later round is refused as a stale plan, one full authority open each.
#[cfg(unix)]
#[test]
#[serial_test::serial(commit_phase_capture)]
fn a_graph_apply_refused_after_authority_moved_is_levelled_in_the_same_round() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    admit_and_derive(&state, "a.py", "def a():\n    return 1\n");
    admit_and_derive(&state, "b.py", "def b():\n    return 2\n");
    let (dangling, endpoint) = split_plant_relation_from_a_missing_entity(&state, "a.py");
    let generation = authority_generation(&state);

    std::fs::write(repo.path().join("b.py"), "def b():\n    return 3\n").unwrap();
    let observation = BTreeSet::from([test_repo_path("b.py")]);
    let admission = exact_tree_admission(&state, Some(&observation), TreePublication::Standalone)
        .expect("a round whose tree authority accepted must finish, not leave the graph behind");

    assert_eq!(
        authority_generation(&state),
        generation + 1,
        "the round published its tree"
    );
    assert_eq!(
        state.graph.resolved_tree(),
        authority_tree(&state),
        "the live graph must be level with authority when the round returns"
    );
    assert!(
        !split_relation_is_held(&state, dangling, endpoint),
        "the relation that refused the transition is dropped"
    );
    let levelled = state
        .background_work
        .reconcile()
        .report(Instant::now())
        .authority_levelled
        .expect("a levelling that dropped a relation is recorded, not only logged");
    assert_eq!(levelled.dropped_relations, 1);
    assert_eq!(levelled.dropped_relations_sample, vec![dangling.to_string()]);
    assert!(
        admission
            .semantic_events
            .iter()
            .any(|event| matches!(event, FileEvent::Changed(path) if path.ends_with("b.py"))),
        "the path the round moved is still re-derived: {:?}",
        admission.semantic_events
    );

    std::fs::write(repo.path().join("a.py"), "def a():\n    return 4\n").unwrap();
    let next = BTreeSet::from([test_repo_path("a.py")]);
    exact_tree_admission(&state, Some(&next), TreePublication::Standalone)
        .expect("the next admission plans from authority's tree and is not refused as stale");
    assert_eq!(authority_generation(&state), generation + 2);
}

/// A graph already behind authority is levelled on the first stale-plan refusal
/// and the observation is planned again, so the file it names is admitted and
/// re-derived at its new position.
///
/// The shape of a store left split: authority holds a newer tree the graph never
/// took, and a file whose function has moved down its file waits in the startup
/// catch-up. Before the levelling every round was refused and the graph kept
/// answering at the function's old line.
#[cfg(unix)]
#[test]
#[serial_test::serial(commit_phase_capture)]
fn a_plan_from_a_graph_behind_authority_is_levelled_and_planned_again() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    let original = "def human_bytes(n):\n    return n\n";
    admit_and_derive(&state, "cache.py", original);
    admit_and_derive(&state, "other.py", "def other():\n    return 1\n");
    let before = split_function_start_line(&state, "human_bytes");

    split_publish_behind_the_graphs_back(&state, "other.py", b"def other():\n    return 2\n");
    assert_ne!(
        state.graph.resolved_tree(),
        authority_tree(&state),
        "the fixture must leave the graph behind authority or nothing below is tested"
    );

    let moved = format!("{}{original}", "# moved down\n".repeat(6));
    std::fs::write(repo.path().join("cache.py"), &moved).unwrap();
    let observation = BTreeSet::from([test_repo_path("cache.py")]);
    let admission = exact_tree_admission(&state, Some(&observation), TreePublication::Standalone)
        .expect("a plan from a graph behind authority is levelled and planned again, not refused");

    assert_eq!(
        state.graph.resolved_tree(),
        authority_tree(&state),
        "graph and authority agree after the round"
    );
    assert!(
        admission
            .semantic_events
            .iter()
            .any(|event| matches!(event, FileEvent::Changed(path) if path.ends_with("other.py"))),
        "the path the levelling moved is re-derived with the round's own: {:?}",
        admission.semantic_events
    );
    derive_semantics(&state, "cache.py");
    assert_eq!(
        split_function_start_line(&state, "human_bytes"),
        before + 6,
        "the admission observed the file at its new position"
    );
    let levelled = state
        .background_work
        .reconcile()
        .report(Instant::now())
        .authority_levelled
        .expect("the levelling is recorded");
    assert_eq!(levelled.paths, 1, "one path was behind: {levelled:?}");
    assert_eq!(levelled.dropped_relations, 0);
}

/// A levelling that fails is published with its count, reaches the restart
/// ceiling the surfaces name, and is cleared by the first levelling that lands.
#[test]
fn a_failed_levelling_counts_toward_the_restart_ceiling_and_one_that_lands_clears_it() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    let refused = || -> Result<Option<AuthorityLevelling>> {
        Err(DaemonError::IncompatibleRepo(
            "transaction relation r1 has unadmitted source endpoint entity:e1".to_string(),
        ))
    };
    for attempt in 1..=kin_cli::commands::resources::AUTHORITY_SPLIT_WEDGE_ATTEMPTS {
        assert!(settle_levelling(&state, refused()).is_err());
        let split = state
            .background_work
            .reconcile()
            .report(Instant::now())
            .authority_split
            .expect("a failed levelling is published, not only logged");
        assert_eq!(split.attempts, attempt);
        assert!(split.error.contains("unadmitted source endpoint"), "{split:?}");
    }
    let wedged = state.background_work.reconcile().report(Instant::now());
    assert!(
        wedged.degraded_reasons()[0].starts_with("restart required"),
        "{:?}",
        wedged.degraded_reasons()
    );

    let landed = settle_levelling(
        &state,
        Ok(Some(AuthorityLevelling {
            deltas: Vec::new(),
            dropped_relations: Vec::new(),
            generation: 9,
        })),
    )
    .unwrap();
    assert!(landed.is_some());
    let report = state.background_work.reconcile().report(Instant::now());
    assert!(
        report.authority_split.is_none(),
        "a levelling that landed ends the split"
    );
    assert_eq!(report.authority_levelled.unwrap().generation, 9);
}
