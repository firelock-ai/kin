// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
// Included inside mcp_commit::tests to reuse exact publication fixtures.

/// Every `Calls` edge `caller` sources in `graph`, as (destination name, origin, id).
fn calls_from(
    graph: &kin_db::InMemoryGraph,
    caller: &Entity,
) -> Vec<(String, String, kin_model::RelationId)> {
    let mut calls = graph
        .get_all_relations_for_entity(&caller.id)
        .unwrap()
        .into_iter()
        .filter(|relation| {
            relation.kind == kin_model::RelationKind::Calls
                && relation.src == kin_model::GraphNodeId::Entity(caller.id)
        })
        .map(|relation| {
            let name = relation
                .dst
                .as_entity()
                .and_then(|id| graph.get_entity(&id).unwrap())
                .map(|entity| entity.name)
                .unwrap_or_else(|| relation.dst.to_string());
            (name, format!("{:?}", relation.origin), relation.id)
        })
        .collect::<Vec<_>>();
    calls.sort();
    calls
}

/// Whether `graph` holds relation `id`, which `caller` sources.
fn holds_call(graph: &kin_db::InMemoryGraph, caller: &Entity, id: &kin_model::RelationId) -> bool {
    calls_from(graph, caller).iter().any(|(_, _, held)| held == id)
}

/// The workspace graph repository authority holds now.
fn authority_workspace_graph(state: &Arc<DaemonState>) -> kin_db::InMemoryGraph {
    load_native_commit_base(&state.layout).unwrap().graph
}

/// Two classes each declare `remove`, and `run` in `src/a.ts` calls `.remove()`
/// on a receiver nothing types, so the linker binds that call to both by name.
/// `src/b.ts` imports another module, so a reconcile of it runs the cross-file
/// linker. Returns `run`, the guess into `C.remove` and `B.remove`.
fn guessed_call_fixture(state: &Arc<DaemonState>) -> (Entity, kin_model::Relation, Entity) {
    install_exact_source(
        state,
        "src/y.ts",
        b"export function y(): number {\n    return 1;\n}\n",
        "y",
    );
    let (b_remove, _) = install_exact_source(
        state,
        "src/b.ts",
        b"import { y } from \"./y\";\nexport class B {\n    remove(): number {\n        return y();\n    }\n}\n",
        "B.remove",
    );
    let (c_remove, _) = install_exact_source(
        state,
        "src/c.ts",
        b"export class C {\n    remove(): number {\n        return 2;\n    }\n}\n",
        "C.remove",
    );
    let (run, _) = install_exact_source(
        state,
        "src/a.ts",
        b"import { y } from \"./y\";\nexport function run(target: any) {\n    return target.make().remove() + y();\n}\n",
        "run",
    );
    let guess = state
        .graph
        .get_all_relations_for_entity(&run.id)
        .unwrap()
        .into_iter()
        .find(|relation| {
            relation.kind == kin_model::RelationKind::Calls
                && relation.src == kin_model::GraphNodeId::Entity(run.id)
                && relation.dst == kin_model::GraphNodeId::Entity(c_remove.id)
        })
        .unwrap_or_else(|| {
            panic!(
                "the linker guesses run -> C.remove by name: {:?}",
                calls_from(state.graph.as_ref(), &run)
            )
        });
    assert_eq!(
        kin_index::RelationResolution::of(&guess),
        kin_index::RelationResolution::NameOnly,
        "{guess:?}"
    );
    (run, guess, b_remove)
}

/// Settle the guess the way an enrichment pass does: a language server proved
/// the call site names `B.remove`, the guess into `C.remove` leaves the live
/// graph, the proof goes in, and the next flush publishes both.
fn settle_guess(
    state: &Arc<DaemonState>,
    run: &Entity,
    guess: &kin_model::Relation,
    proven: &Entity,
) -> kin_model::Relation {
    let site = guess
        .evidence
        .iter()
        .find_map(|evidence| evidence.source_span.clone())
        .expect("a guess records its call site");
    let proof = kin_model::Relation {
        id: kin_model::RelationId::new(),
        kind: kin_model::RelationKind::Calls,
        src: kin_model::GraphNodeId::Entity(run.id),
        dst: kin_model::GraphNodeId::Entity(proven.id),
        confidence: 0.95,
        origin: kin_model::RelationOrigin::Lsp,
        created_in: None,
        import_source: None,
        evidence: vec![kin_model::RelationEvidence {
            source_span: Some(site),
            parser_rule: Some("lsp_definition".to_string()),
            ..Default::default()
        }],
    };
    state.graph.remove_relation(&guess.id).unwrap();
    state.graph.upsert_relation(&proof).unwrap();
    state.lsp_settled_guesses.lock().unwrap().insert(guess.id);
    state.save_snapshot().unwrap();
    assert!(
        !holds_call(&authority_workspace_graph(state), run, &guess.id),
        "the flush publishes the retirement"
    );
    proof
}

/// A commit that edits one file leaves the call guesses a language server
/// retired in another file retired, without a sweep. The edited file imports
/// a module, so its reconcile runs the cross-file linker, and the linker
/// re-binds every file waiting on a name the edited file declares. The file
/// holding the settled call is one of them, and its bytes did not change.
#[test]
fn a_commit_to_one_file_keeps_the_guesses_proof_retired_in_another() {
    let (_dir, state) = test_state();
    let (run, guess, b_remove) = guessed_call_fixture(&state);
    let proof = settle_guess(&state, &run, &guess, &b_remove);

    let sessions = test_sessions();
    let (_, arguments) = stage_entity_edit(
        &state,
        &sessions,
        &b_remove,
        "remove(): number {\n        return y() + 1;\n    }",
    );
    let result = commit_exact_transaction(&state, &sessions, &arguments, None);
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));

    let live = calls_from(state.graph.as_ref(), &run);
    assert!(
        !holds_call(state.graph.as_ref(), &run, &guess.id),
        "the live graph brought back the guess proof retired: {live:?}"
    );
    assert!(
        holds_call(state.graph.as_ref(), &run, &proof.id),
        "the proof stays: {live:?}"
    );
    let authority = authority_workspace_graph(&state);
    assert!(
        !holds_call(&authority, &run, &guess.id),
        "authority brought back the guess proof retired: {:?}",
        calls_from(&authority, &run)
    );
    assert!(holds_call(&authority, &run, &proof.id));

    // The published change carries the retirement itself, so a graph folded
    // from history, with no overlay and no section, keeps it too.
    let change_id = commit_reply(&result)["change_id"]
        .as_str()
        .expect("a commit names its change")
        .to_string();
    let context = authority_context(&state).unwrap();
    let opened = context.open().unwrap();
    let lease = opened.read_authority();
    let change = lease
        .snapshot()
        .changes
        .values()
        .find(|change| change.id.to_string() == change_id)
        .expect("authority holds the published change");
    assert!(
        change.relation_deltas.iter().any(|delta| matches!(
            delta,
            kin_model::RelationDelta::Removed { old } if old.id == guess.id
        )),
        "the change must publish the retirement the overlay held"
    );
}

