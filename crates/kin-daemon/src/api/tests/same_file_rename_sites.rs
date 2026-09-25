// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// A renamed declaration that both calls into its own file and is called from
// it. Each of those edges carries occurrence certificates bound to the
// parser's id for the declaration, and the rename must rebind them with the
// retained identity or admission refuses the reparse. The other rename
// fixtures rename a declaration with no same-file edge, so none of them would
// notice.

const SAME_FILE_RENAME_FILE: &str = "src/sites.py";
const SAME_FILE_RENAME_SOURCE: &str =
    "def helper():\n    return 1\n\n\ndef before():\n    return helper()\n\n\ndef caller():\n    return before()\n";

/// Run the real daemon loop until startup has restored this file's coverage,
/// as a reopened daemon does before it serves a read.
async fn same_file_rename_initialize(state: &Arc<DaemonState>) {
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    let (cancel, receiver) = tokio::sync::watch::channel(false);
    let mut task = tokio::spawn(crate::loop_runner::run_loop(
        Arc::clone(state),
        crate::loop_runner::LoopConfig {
            poll_interval_ms: 10,
            batch_size: 64,
        },
        receiver,
    ));
    let ready = tokio::time::timeout(Duration::from_secs(10), async {
        while !state.is_initialized.load(Ordering::Relaxed)
            || state
                .graph
                .get_file_layout(&kin_model::FilePathId::new(SAME_FILE_RENAME_FILE))
                .unwrap()
                .is_none()
        {
            if task.is_finished() {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
    })
    .await;
    let _ = cancel.send(true);
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task).await;
    if joined.is_err() {
        task.abort();
        let _ = task.await;
    }
    assert!(
        matches!(ready, Ok(true)),
        "real daemon loop did not initialize: {ready:?}"
    );
    joined
        .expect("owned loop must stop")
        .expect("owned loop must join")
        .expect("startup must succeed");
}

fn same_file_rename_entities(state: &DaemonState, name: &str) -> Vec<kin_model::Entity> {
    state
        .graph
        .query_entities(&kin_model::EntityFilter {
            file_path: Some(kin_model::FilePathId::new(SAME_FILE_RENAME_FILE)),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .filter(|entity| entity.name == name && entity.kind != kin_model::EntityKind::Module)
        .collect()
}

fn same_file_rename_entity(state: &DaemonState, name: &str) -> kin_model::Entity {
    let found = same_file_rename_entities(state, name);
    let [entity] = found.as_slice() else {
        panic!("exactly one {name} in {SAME_FILE_RENAME_FILE}: {found:?}");
    };
    entity.clone()
}

/// The one call edge from `src` to `dst`, after checking that it carries
/// occurrence certificates and that every one of them validates against the
/// edge's own sites, with the sites it proves as (start byte, end byte, row).
fn same_file_rename_call(
    state: &DaemonState,
    src: kin_model::EntityId,
    dst: kin_model::EntityId,
) -> (kin_model::Relation, Vec<(usize, usize, u32)>) {
    let calls: Vec<_> = state
        .graph
        .get_relations(&src, &[kin_model::RelationKind::Calls])
        .unwrap()
        .into_iter()
        .filter(|relation| {
            relation.src == kin_model::GraphNodeId::Entity(src)
                && relation.dst == kin_model::GraphNodeId::Entity(dst)
        })
        .collect();
    let [call] = calls.as_slice() else {
        panic!("exactly one call edge from {src} to {dst}: {calls:?}");
    };
    assert!(
        call.evidence
            .iter()
            .any(kin_index::occurrence::is_certificate),
        "the call carries occurrence certificates: {call:?}"
    );
    assert!(
        kin_index::occurrence::original_evidence(call).is_some(),
        "every certificate validates against the edge's own sites: {call:?}"
    );
    let (sites, withheld) = kin_index::occurrence::proven_sites(call);
    assert!(!withheld, "no site of the call is withheld: {call:?}");
    (
        call.clone(),
        sites
            .iter()
            .map(|site| (site.start_byte, site.end_byte, site.start_line))
            .collect(),
    )
}

/// Where the call a `return` statement makes is written: the call expression
/// itself, as (start byte, end byte, 0-based row).
fn same_file_rename_site(source: &str, statement: &str) -> (usize, usize, u32) {
    let keyword = "return ".len();
    let start = source
        .find(statement)
        .unwrap_or_else(|| panic!("{statement:?} in {source:?}"))
        + keyword;
    let end = start + statement.len() - keyword;
    let row = u32::try_from(source[..start].matches('\n').count()).unwrap();
    (start, end, row)
}

/// Everything the rename promises, read back through the served source read
/// and the graph's own edges.
async fn same_file_rename_assert_renamed(
    state: &Arc<DaemonState>,
    target: kin_model::EntityId,
    helper: kin_model::EntityId,
    caller: kin_model::EntityId,
    edges: (kin_model::RelationId, kin_model::RelationId),
    renamed: &str,
) {
    assert_eq!(
        same_file_rename_entity(state, "renamed").id,
        target,
        "the renamed declaration keeps its entity id"
    );
    assert!(same_file_rename_entities(state, "before").is_empty());
    assert_eq!(same_file_rename_entity(state, "helper").id, helper);
    assert_eq!(same_file_rename_entity(state, "caller").id, caller);
    let source = external_edit_source(state, target).await;
    assert_eq!(
        source["body"].as_str().unwrap().trim_end(),
        "def renamed():\n    return helper()",
        "the declaration's source reads back under its new name: {source}"
    );
    let (outgoing, outgoing_sites) = same_file_rename_call(state, target, helper);
    let (incoming, incoming_sites) = same_file_rename_call(state, caller, target);
    assert_eq!((outgoing.id, incoming.id), edges);
    assert_eq!(
        outgoing_sites,
        vec![same_file_rename_site(renamed, "return helper()")],
        "the outgoing call is proven at the site the renamed source writes it"
    );
    assert_eq!(
        incoming_sites,
        vec![same_file_rename_site(renamed, "return renamed()")],
        "the incoming call is proven at the caller's rewritten site"
    );
}

#[tokio::test]
async fn a_rename_keeps_identity_and_exact_sites_for_same_file_calls_both_ways() {
    let (_dir, state) = mcp_lifecycle_fixture();
    source_tree_conversion_fixture(
        &state,
        json!({"verb":"create", "description":"install exact source", "target":SAME_FILE_RENAME_FILE, "body":SAME_FILE_RENAME_SOURCE}),
    )
    .await;
    let target = same_file_rename_entity(&state, "before").id;
    let helper = same_file_rename_entity(&state, "helper").id;
    let caller = same_file_rename_entity(&state, "caller").id;
    let (outgoing, outgoing_sites) = same_file_rename_call(&state, target, helper);
    let (incoming, incoming_sites) = same_file_rename_call(&state, caller, target);
    assert_eq!(
        outgoing_sites,
        vec![same_file_rename_site(
            SAME_FILE_RENAME_SOURCE,
            "return helper()"
        )]
    );
    assert_eq!(
        incoming_sites,
        vec![same_file_rename_site(
            SAME_FILE_RENAME_SOURCE,
            "return before()"
        )]
    );
    let edges = (outgoing.id, incoming.id);

    let roots = source_base_roots(&state);
    let request = kin_cli::commands::rename::RenameRequest {
        symbol: "before".into(),
        new_name: "renamed".into(),
        file: Some(SAME_FILE_RENAME_FILE.into()),
        line: Some(5),
        column: None,
        json: true,
        operation_id: kin_model::OperationId::new(),
        actor: kin_model::AuthorId::new("same-file-rename-test"),
    };
    let report = external_edit_rename(&state, &request).await.report.unwrap();
    assert_eq!(report.entity_id, target);
    assert!(!report.idempotent);
    assert!(source_base_roots(&state).generation > roots.generation);
    let renamed = SAME_FILE_RENAME_SOURCE.replace("before", "renamed");
    assert_eq!(
        std::fs::read_to_string(state.layout.working_dir().join(SAME_FILE_RENAME_FILE)).unwrap(),
        renamed
    );
    same_file_rename_assert_renamed(&state, target, helper, caller, edges, &renamed).await;

    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    same_file_rename_initialize(&reopened).await;
    same_file_rename_assert_renamed(&reopened, target, helper, caller, edges, &renamed).await;
}
