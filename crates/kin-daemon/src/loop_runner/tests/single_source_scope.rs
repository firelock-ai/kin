// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

/// Only exact-tree admission forms a coherent batch around one source. The
/// readmission after a publication, the drain and the startup repair all reach
/// `prepare` through `try_readmit_from`, and they still leave a single path to
/// the sequential reconciler, so their outcomes and refusals are what they were.
/// Two paths still batch through the same calls, which is what keeps the
/// single-path assertions from passing over nothing.
#[cfg(unix)]
#[test]
fn a_single_path_readmission_outside_exact_admission_stays_sequential() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    state.is_initialized.store(true, Ordering::Relaxed);
    admit_and_derive(&state, "src/one.py", "def one():\n    return 1\n");
    admit_and_derive(&state, "src/two.py", "def two():\n    return 2\n");
    let one = BTreeSet::from([test_repo_path("src/one.py")]);
    let both = BTreeSet::from([test_repo_path("src/one.py"), test_repo_path("src/two.py")]);
    let mut reconciler = state.reconciler.blocking_write();
    let mut pass = crate::state::PassDelta::default();
    let mark = prepared_batch_mark_for_test();

    // The drain's call, and the readmission after a publication that prepared
    // nothing: an observed predecessor or none, and one path.
    let drained = source_batch::try_readmit(
        &state,
        &mut reconciler,
        &one,
        None,
        &BTreeSet::new(),
        &mut pass,
    )
    .unwrap();
    assert!(
        drained.is_empty(),
        "a single drained path stays sequential: {drained:?}"
    );
    // The startup repair's call.
    let (repaired, retirements) =
        source_batch::try_readmit_at_startup(&state, &mut reconciler, &one, &mut pass).unwrap();
    assert!(
        repaired.is_empty(),
        "a single repaired path stays sequential: {repaired:?}"
    );
    assert_eq!(retirements, source_batch::StartupRetirements::default());
    assert!(prepared_batches_since_for_test(&state, mark).is_empty());

    let batched = source_batch::try_readmit(
        &state,
        &mut reconciler,
        &both,
        None,
        &BTreeSet::new(),
        &mut pass,
    )
    .unwrap();
    assert_eq!(batched, both);
    assert_eq!(prepared_batches_since_for_test(&state, mark), vec![both]);
}

/// A one-source batch that cannot be prepared hands its source back to the
/// sequential reconciler, which publishes the bytes and leaves the parse owed,
/// exactly as it did before one source could form a batch.
///
/// A hard intent on the file's only declaration makes the batch's traffic
/// preflight refuse. The admission must still publish the edited bytes, with
/// the parse recorded as owed and authority's certificate still bound to the
/// earlier body, and no coherent batch may have formed. Falsify by letting a
/// one-source preparation failure fail the admission: the bytes then never
/// reach authority and the generation does not move.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn a_one_source_batch_that_cannot_be_prepared_takes_the_sequential_path() {
    let repo = tempfile::tempdir().unwrap();
    let state = startup_diagnostic_committed_orphan(&repo).await;
    let generation = authority_generation(&state);
    let committed = state
        .graph
        .get_tree_entry(&FilePathId::new("orphan.py"))
        .unwrap()
        .and_then(|entry| entry.blob_identity())
        .unwrap();
    startup_diagnostic_lease_orphan(&state);
    let edited = format!("{}def orphan():\n    return 8\n", "\n".repeat(17));
    std::fs::write(repo.path().join("orphan.py"), &edited).unwrap();
    let body = Hash256::from_bytes(kin_blobs::digest(edited.as_bytes()).0);
    let mark = prepared_batch_mark_for_test();

    let outcome = sync_filesystem_with_graph(&state).await;

    assert!(
        prepared_batches_since_for_test(&state, mark).is_empty(),
        "the refused one-source batch forms nothing: {outcome:?}"
    );
    assert_eq!(
        authority_generation(&state),
        generation + 1,
        "the sequential path still publishes the edited bytes: {outcome:?}"
    );
    assert_eq!(state.graph.resolved_tree(), authority_tree(&state));
    assert_eq!(
        state
            .graph
            .get_tree_entry(&FilePathId::new("orphan.py"))
            .unwrap()
            .and_then(|entry| entry.blob_identity()),
        Some(body)
    );
    assert!(
        crate::semantic_debt::outstanding(&state)
            .iter()
            .any(|entry| entry.path == "orphan.py" && entry.body == body.to_string()),
        "the publication records the parse it could not carry"
    );
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
            .unwrap();
    let durable = context
        .open()
        .unwrap()
        .read_authority()
        .workspace_graph_snapshot(&context.workspace_id())
        .unwrap()
        .unwrap();
    let artifact = durable
        .resolved_tree
        .artifact_at_path(&test_repo_path("orphan.py"))
        .unwrap()
        .artifact_id;
    let certificate = kin_index::build_parse_coverage_relation(
        &kin_index::FileParseData {
            file_path: "orphan.py".to_string(),
            entities: Vec::new(),
            relations: Vec::new(),
            imports: Vec::new(),
        },
        artifact,
        &kin_model::ParseCompleteness::Full,
        &std::collections::HashSet::<String>::new(),
    )
    .id;
    assert_eq!(
        durable
            .relations
            .get(&certificate)
            .and_then(kin_index::parse_coverage_source_digest),
        Some(committed),
        "authority keeps the parse of the committed body, not a parse the batch never made"
    );
}
