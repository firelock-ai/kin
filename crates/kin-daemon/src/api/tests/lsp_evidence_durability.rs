// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Accepted language-server evidence larger than the crash record's old 16 MiB
// limit, carried through a crash, a publication and a restart, over parsed and
// committed declarations. No external language server is started.

/// The size the accepted-evidence record used to refuse new evidence at.
const OLD_ACCEPTED_EVIDENCE_LIMIT: u64 = 16 * 1024 * 1024;

/// A reference from `caller` to `target` carrying `sites` evidence records, so
/// a few thousand of them cross the old limit the way one cold sweep of a
/// mid-size Go repository did.
fn wide_lsp_reference(
    caller: kin_model::EntityId,
    target: kin_model::EntityId,
    sites: usize,
) -> kin_model::Relation {
    let mut relation = lsp_publication_call(caller, target);
    relation.kind = RelationKind::References;
    relation.id = kin_lsp::relation_identity::language_server_relation_id(
        RelationKind::References,
        caller,
        target,
    );
    let site = relation.evidence[0].clone();
    relation.evidence = vec![site; sites];
    relation
}

fn accepted_evidence_record_len(state: &DaemonState) -> u64 {
    std::fs::metadata(state.layout.root().join("lsp-accepted-evidence.jsonl"))
        .map(|meta| meta.len())
        .unwrap_or(0)
}

#[tokio::test]
async fn accepted_evidence_past_the_old_record_limit_survives_a_restart_and_marks_its_file() {
    let (repo, state) = lsp_publication_fixture().await;
    let caller = waiting_entity(&state, "caller.py", "run");
    let target = waiting_entity(&state, "target.py", "work");

    // Different ids over the same ends are now correctly merged as one edge.
    // Admit enough distinct declarations for every stress row to have its own
    // canonical identity. A serialized relation is a lower bound on its crash
    // record line, so this reserves at least twice the bytes installed below.
    const BATCH_SIZE: usize = 256;
    let relation_bytes = serde_json::to_vec(&wide_lsp_reference(caller.id, target.id, 64))
        .unwrap()
        .len() as u64;
    let target_count = (4 * OLD_ACCEPTED_EVIDENCE_LIMIT)
        .div_ceil(relation_bytes)
        .div_ceil(BATCH_SIZE as u64) as usize
        * BATCH_SIZE;
    let mut source = "def work():\n    return 7\n".to_owned();
    for n in 0..target_count {
        source.push_str(&format!("\ndef work_{n:05}():\n    return 7\n"));
    }
    std::fs::write(repo.path().join("target.py"), source).unwrap();
    waiting_admit(&state, "distinct evidence targets").await;
    waiting_commit(&state, "Admit distinct evidence targets").await;
    let mut targets: Vec<_> = state
        .graph
        .query_entities(&kin_db::EntityFilter {
            file_path: Some(kin_model::FilePathId::new("target.py")),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .filter(|entity| entity.name.starts_with("work_"))
        .collect();
    targets.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(targets.len(), target_count);

    // Accept evidence the way the sweep does, in write batches, until the crash
    // record holds twice what it used to refuse at. The count is fixed from
    // the first batch's size rather than read back from the record, so batches
    // keep arriving after the old limit is crossed, which is the case the
    // refusal broke.
    let mut accepted = Vec::new();
    let install = |accepted: &mut Vec<kin_model::Relation>, targets: &[kin_model::Entity]| {
        let batch: Vec<_> = targets
            .iter()
            .map(|target| wide_lsp_reference(caller.id, target.id, 64))
            .collect();
        crate::daemon::install_lsp_relations(&state, &batch);
        assert!(
            batch
                .iter()
                .all(|relation| state.graph.get_relation_by_id(&relation.id).is_some()),
            "the graph takes every relation"
        );
        accepted.extend(batch);
    };
    install(&mut accepted, &targets[..BATCH_SIZE]);
    let batch_bytes = accepted_evidence_record_len(&state).max(1);
    let batches = (2 * OLD_ACCEPTED_EVIDENCE_LIMIT).div_ceil(batch_bytes) as usize;
    assert!(batches * BATCH_SIZE <= targets.len());
    for batch in 1..batches {
        install(
            &mut accepted,
            &targets[batch * BATCH_SIZE..(batch + 1) * BATCH_SIZE],
        );
    }
    assert_eq!(
        accepted
            .iter()
            .map(|relation| relation.id)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        accepted.len(),
        "the stress record must contain distinct canonical edges"
    );
    let record_len = accepted_evidence_record_len(&state);
    println!(
        "accepted {} relations in {batches} batches, record {record_len} bytes",
        accepted.len()
    );
    assert!(record_len > OLD_ACCEPTED_EVIDENCE_LIMIT);
    assert!(
        state.lsp_evidence_unrecorded.lock().unwrap().is_empty(),
        "every accepted relation must be recorded"
    );

    // A crash before the sweep's publication: nothing reached authority, so
    // everything the reopened graph holds of this came from the record.
    let layout = state.layout.clone();
    drop(state);
    let state = Arc::new(DaemonState::open(layout.clone()).unwrap());
    let missing: Vec<_> = accepted
        .iter()
        .filter(|relation| state.graph.get_relation_by_id(&relation.id).is_none())
        .map(|relation| relation.id)
        .collect();
    assert!(
        missing.is_empty(),
        "{} of {} accepted relations did not survive the restart; the record past {} bytes \
         must keep every one",
        missing.len(),
        accepted.len(),
        OLD_ACCEPTED_EVIDENCE_LIMIT
    );

    // The sweep's own publication makes the evidence durable in authority,
    // which empties the record.
    assert!(matches!(
        state.save_snapshot_reporting_enrichment().unwrap(),
        crate::state::EnrichmentFlush::Proceeded
    ));
    let durable = lsp_publication_durable(&state);
    assert!(
        accepted
            .iter()
            .all(|relation| durable.relations.contains_key(&relation.id)),
        "the publication must carry every accepted relation into authority"
    );
    assert_eq!(
        accepted_evidence_record_len(&state),
        0,
        "an authority commit empties the record"
    );

    // Recorded as enriched, and still recorded after a restart.
    let epoch = crate::daemon::current_marker_epoch(&state);
    crate::daemon::mark_files_enriched(&state, &["caller.py".to_string()], epoch);
    drop(state);
    let state = Arc::new(DaemonState::open(layout).unwrap());
    crate::daemon::load_lsp_enriched_marker(&state);
    assert!(
        crate::daemon::file_already_enriched(&state, "caller.py"),
        "the completion marker must survive the restart"
    );
    assert!(
        accepted
            .iter()
            .all(|relation| state.graph.get_relation_by_id(&relation.id).is_some()),
        "and so must the evidence, now from authority"
    );
}
