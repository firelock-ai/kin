/// Additions the pending snapshot delta is carrying for the three artifact
/// facets, as `(shallow, structured, opaque)`.
///
/// This is the exact instrument for "was the record written", and the two
/// obvious alternatives are both checks that cannot fail. The artifact
/// embedding queue is a set keyed by `ArtifactId`, so the second and every
/// later invalidation of one artifact leave its depth unchanged, and nothing
/// short of a real embedder can drain it. A count of
/// `invalidate_artifact_for_embedding` calls is not separately observable at
/// all, and does not need to be: kin-db's three artifact upserts each end in
/// one (0.7.107 `src/engine/graph.rs:8520`, `:8551`, `:8606`), so invalidations
/// per tick equal rewrites per tick by construction.
///
/// The delta is also where the cost is sharpest. `delta_vec_upsert_by_key`
/// (`graph.rs:1579`) drops a key's pending `added` entry BEFORE it returns
/// early on an identical value, so re-persisting an unchanged record does not
/// merely record nothing: it erases that record's creation from the delta the
/// daemon may persist (`state.rs` -> `backend.save_delta`).
///
/// Gated with the tests that call it, all four of which are `#[cfg(unix)]`
/// because their fixtures publish through the host filesystem. Without the gate
/// this helper is dead code on the Windows cross-check, which builds test
/// targets under `-D warnings`.
#[cfg(unix)]
fn pending_artifact_additions(state: &DaemonState) -> (usize, usize, usize) {
    match state.graph.pending_delta_snapshot(0) {
        Some(delta) => (
            delta.shallow_files.added.len(),
            delta.structured_artifacts.added.len(),
            delta.opaque_artifacts.added.len(),
        ),
        None => (0, 0, 0),
    }
}

/// An idle tick must not rewrite the enrichment record of a source-NAMED path
/// whose BYTES are not source.
///
/// #1630 stopped `semantic_debt::owed_by` recording a path that is not entity
/// source, but it classifies by NAME, because a tree delta carries no body. A
/// source-named path whose bytes are binary is still recorded, is still handed
/// to [`readmit_semantics_for_paths`] by every drain, and there is re-classified
/// WITH content into the non-source branch. Nothing but a commit settles a debt
/// entry, so on a store that never commits that is every tick, forever.
///
/// Measured on 6697b8f9 before the fix, three drains over this fixture: three
/// rewrites, three vector invalidations, three `vfs_version` bumps, and the
/// opaque record's creation already erased from the pending delta by the drain
/// that runs inside `sync_filesystem_with_graph` itself.
///
/// The fixture carries no ordinary source file on purpose. A source file's debt
/// is unsettled too and is legitimately re-parsed on every tick, which moves
/// `vfs_version` and would make every assertion here vacuous.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn an_idle_drain_does_not_rewrite_an_unchanged_opaque_record_under_a_source_name() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    // `.py` is an entity-source extension, so `classify` says parse me; a NUL
    // makes `classify_with_content` route the same path to the opaque facet.
    std::fs::write(repo.path().join("probe.py"), b"\x00\x01binary payload\n").unwrap();
    sync_filesystem_with_graph(&state).await.unwrap();

    let probe = FilePathId::new("probe.py");
    assert!(
        state.graph.get_opaque_artifact(&probe).unwrap().is_some(),
        "the fixture must reach the opaque facet or every assertion below is vacuous"
    );
    let recorded = crate::semantic_debt::outstanding(&state);
    let (owed, _spent) = crate::semantic_debt::partition_against_tree(&state, &recorded);
    assert!(
        owed.iter().any(|path| path.as_utf8() == Some("probe.py")),
        "the drain must actually be handed this path, or nothing here is being exercised: \
         {owed:?}"
    );
    let version = state.vfs_version.load(Ordering::SeqCst);
    for tick in 1..=3 {
        drain_semantic_debt(&state).await.unwrap();
        assert_eq!(
            state.vfs_version.load(Ordering::SeqCst),
            version,
            "tick {tick} claimed a graph change for a record nothing wrote, which retires every \
             VFS client's cached materialization and arms a persistence pass for a graph that \
             did not move"
        );
        assert_eq!(
            pending_artifact_additions(&state).2,
            1,
            "tick {tick} re-persisted the unchanged opaque record, which discards its vector and \
             erases its creation from the pending delta"
        );
    }
    assert!(
        state.graph.get_opaque_artifact(&probe).unwrap().is_some(),
        "skipping the rewrite must not lose the record"
    );
}

/// The control for the arm above: when the bytes really do move, the record
/// follows them.
///
/// Without this, a comparison that always answered "already current" would pass
/// every assertion in the test above while silently freezing every artifact
/// record in the store at its first body.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn a_changed_opaque_body_under_a_source_name_is_still_rewritten() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    let probe_path = repo.path().join("probe.py");
    std::fs::write(&probe_path, b"\x00\x01binary payload\n").unwrap();
    sync_filesystem_with_graph(&state).await.unwrap();

    let probe = FilePathId::new("probe.py");
    let first = state
        .graph
        .get_opaque_artifact(&probe)
        .unwrap()
        .expect("the fixture must reach the opaque facet");

    std::fs::write(&probe_path, b"\x00\x02a different binary payload\n").unwrap();
    sync_filesystem_with_graph(&state).await.unwrap();
    let second = state
        .graph
        .get_opaque_artifact(&probe)
        .unwrap()
        .expect("the record must survive the second admission");
    assert_ne!(
        second.content_hash, first.content_hash,
        "an additive persist must still write a record whose body moved"
    );
    assert_eq!(
        second.content_hash.to_string(),
        kin_blobs::digest(b"\x00\x02a different binary payload\n").to_string(),
        "and the record it writes must describe the bytes the tree now holds"
    );
}

/// The same additive rule for a structured artifact, driven through the seam
/// that can be handed one with an unchanged body.
///
/// A structured artifact is not entity source by NAME either, so #1630 already
/// keeps it out of the debt record and the drain never reaches it from there.
/// `readmit_semantics_for_paths` is still called with whole published path sets
/// elsewhere (`api.rs`, the reconcile gate), so the arm has a live caller and
/// pays the same cost when the body has not moved.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn readmitting_an_unchanged_structured_artifact_writes_nothing() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    let makefile_path = repo.path().join("Makefile");
    std::fs::write(&makefile_path, b"build:\n\tcargo build\n").unwrap();
    sync_filesystem_with_graph(&state).await.unwrap();

    let makefile = FilePathId::new("Makefile");
    let first = state
        .graph
        .get_structured_artifact(&makefile)
        .unwrap()
        .expect("the fixture must reach the structured facet");
    assert_eq!(
        pending_artifact_additions(&state).1,
        1,
        "the delta must be carrying the record's creation before a rewrite could erase it"
    );

    let version = state.vfs_version.load(Ordering::SeqCst);
    let artifacts = BTreeSet::from([test_repo_path("Makefile")]);
    for tick in 1..=3 {
        let readmitted = readmit_semantics_for_paths(&state, &artifacts).await;
        assert_eq!(
            readmitted.enriched, 1,
            "tick {tick}: the path must actually reach the non-entity persist seam, or this \
             test asserts nothing"
        );
        assert!(readmitted.failed.is_empty(), "{:?}", readmitted.failed);
        assert_eq!(
            state.vfs_version.load(Ordering::SeqCst),
            version,
            "tick {tick} claimed a graph change for a record nothing wrote"
        );
        assert_eq!(
            pending_artifact_additions(&state).1,
            1,
            "tick {tick} re-persisted the unchanged structured record, which discards its vector \
             and erases its creation from the pending delta"
        );
    }

    // The control, as above: a body that moves is still written.
    std::fs::write(&makefile_path, b"build:\n\tcargo build --release\n").unwrap();
    sync_filesystem_with_graph(&state).await.unwrap();
    let second = state
        .graph
        .get_structured_artifact(&makefile)
        .unwrap()
        .expect("the record must survive the second admission");
    assert_ne!(
        second.content_hash, first.content_hash,
        "an additive persist must still write a record whose body moved"
    );
}

/// The same additive rule for the shallow arm.
///
/// This one is driven at the seam rather than through a fixture file, because
/// the arm has no live producer: `SHALLOW_SYNTAX_EXTENSIONS` is empty by design
/// (`kin-index/src/classifier.rs`), so no path classifies as `ShallowSyntax`
/// today and `index_any_content` cannot produce one. The arm is still reachable
/// the moment an extension is added there, and `ShallowTrackedFile` is the one
/// record of the three that carries no `content_hash`, so its comparison is a
/// whole-value one and needs a guard of its own.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn persisting_an_unchanged_shallow_record_writes_nothing() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    // Any admitted path will do; the graph needs an artifact id for it before
    // an enrichment record can be written against it.
    std::fs::write(repo.path().join("notes.dat"), b"opaque by name\n").unwrap();
    sync_filesystem_with_graph(&state).await.unwrap();

    let file_id = FilePathId::new("notes.dat");
    let shallow = |name: &str| {
        IndexedAny::ShallowSyntax(kin_parser::ShallowFile {
            file_id: file_id.clone(),
            language_hint: Some("erlang".to_string()),
            parse_state: kin_model::ParseState::Valid,
            declarations: vec![kin_parser::ShallowDecl {
                kind: kin_parser::ShallowDeclKind::FunctionLike,
                name: name.to_string(),
                start_line: 1,
                end_line: 2,
            }],
            imports: Vec::new(),
            fingerprint: kin_parser::ShallowFingerprint {
                syntax_hash: Hash256::from_bytes([7; 32]),
                signature_hash: None,
            },
        })
    };

    persist_non_entity_enrichment(&state, shallow("run")).unwrap();
    assert!(
        state.graph.get_shallow_file(&file_id).unwrap().is_some(),
        "the first persist must write the record or nothing below is being exercised"
    );
    assert_eq!(
        pending_artifact_additions(&state).0,
        1,
        "the delta must be carrying the record's creation before a rewrite could erase it"
    );

    persist_non_entity_enrichment(&state, shallow("run")).unwrap();
    assert_eq!(
        pending_artifact_additions(&state).0,
        1,
        "re-persisting the unchanged shallow record discards its vector and erases its creation \
         from the pending delta"
    );

    // The control: a shallow record whose declarations moved is still written,
    // and `ShallowTrackedFile` carries no content hash, so only the whole-value
    // comparison can tell these two apart.
    persist_non_entity_enrichment(&state, shallow("walk")).unwrap();
    assert_eq!(
        state
            .graph
            .get_shallow_file(&file_id)
            .unwrap()
            .expect("the record must survive")
            .declaration_names,
        vec!["walk".to_string()],
        "an additive persist must still write a shallow record whose declarations moved"
    );
}
