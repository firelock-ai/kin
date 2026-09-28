// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Every read tool that answers about calls serves one `call_sites` block,
//! read through the one site-state reading, and the verdict reads that block
//! the same way on each of them.
//!
//! The store below holds a Python module `pkg/storage.py` and a test file that
//! imports it. Each test asks one tool about it, with and without the
//! call-site ledgers a finished sweep writes.
//!
//! `note_body` carries its text span and no file of origin, so a pack can read
//! its sites without repository authority, as the external-symbol tests do.
//! `find_note` is the module's reference target: it has a file, so the files
//! that import its file are its family, and no span, so no answer about it
//! reads a body.

use std::collections::HashMap;

use kin_db::InMemoryGraph;
use kin_model::graph::EntityStore as _;
use kin_model::relation::{Relation, RelationOrigin};
use kin_model::{
    CallSiteState, Entity, EntityKind, GraphNodeId, LanguageId, RelationId, RelationKind,
    UnresolvedReason,
};
use serde_json::{json, Value};

use super::entities::{handle_find_references, handle_get_context_pack, handle_graph_neighborhood};
use crate::call_sites::fixture::{admit, id_of, ledger, proof_context, spanned_entity};
use crate::session::SessionRegistry;
use crate::types::{ContentBlock, ToolCallResult};

const FOCAL_FILE: &str = "pkg/storage.py";
const CALLER_FILE: &str = "tests/test_storage.py";
const FOCAL_BODY: &str =
    "def note_body(db, id):\n    row = fetch(db, id)\n    text = row.get(id)\n    return render(text)\n";
const CALLER_BODY: &str = "def test_round_trip(db):\n    print(db)\n";
const MODULE_BODY: &str = "import storage\n";

fn payload(result: &ToolCallResult) -> Value {
    let ContentBlock::Text { text } = result.content.first().expect("one content block");
    serde_json::from_str(text).expect("the payload is JSON")
}

fn finalized(result: ToolCallResult, tool: &str) -> Value {
    payload(&crate::finalize_with_envelope(
        result,
        crate::Envelope::daemon().with_health(&json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_generation": 12,
        })),
        tool,
    ))
}

/// One parse-side call count on every entity of a file, the way the extractor
/// stamps it.
fn counted(mut entity: Entity, parsed: u64) -> Entity {
    entity.metadata.extra.insert(
        kin_parser::FILE_PARSED_CALL_SITES_KEY.to_string(),
        json!(parsed),
    );
    entity
}

fn imports(src: &Entity, dst: &Entity) -> Relation {
    Relation {
        id: RelationId::from_content(&src.id.0.to_string(), &dst.id.0.to_string(), "Imports"),
        kind: RelationKind::Imports,
        src: GraphNodeId::Entity(src.id),
        dst: GraphNodeId::Entity(dst.id),
        confidence: 1.0,
        origin: RelationOrigin::Parsed,
        created_in: None,
        import_source: None,
        evidence: Vec::new(),
    }
}

struct Store {
    graph: InMemoryGraph,
    focal: Entity,
    target: Entity,
    caller: Entity,
    caller_module: Entity,
}

/// The two files and the import between them, with no ledger yet.
fn store() -> Store {
    let graph = InMemoryGraph::new();
    let mut focal = spanned_entity("note_body", FOCAL_FILE, LanguageId::Python, 20, FOCAL_BODY);
    focal.file_origin = None;
    let mut target = counted(
        spanned_entity(
            "find_note",
            FOCAL_FILE,
            LanguageId::Python,
            200,
            "def find_note():\n",
        ),
        0,
    );
    target.span = None;
    let mut target_module = counted(
        spanned_entity("storage", FOCAL_FILE, LanguageId::Python, 0, "import db\n"),
        0,
    );
    target_module.kind = EntityKind::Module;
    target_module.span = None;
    let caller = counted(
        spanned_entity(
            "test_round_trip",
            CALLER_FILE,
            LanguageId::Python,
            20,
            CALLER_BODY,
        ),
        1,
    );
    let mut caller_module = counted(
        spanned_entity(
            "test_storage",
            CALLER_FILE,
            LanguageId::Python,
            0,
            MODULE_BODY,
        ),
        1,
    );
    caller_module.kind = EntityKind::Module;
    for entity in [&focal, &target, &target_module, &caller, &caller_module] {
        graph.upsert_entity(entity).unwrap();
    }
    graph
        .upsert_relation(&imports(&caller_module, &target_module))
        .unwrap();
    Store {
        graph,
        focal,
        target,
        caller,
        caller_module,
    }
}

/// The ledgers a finished sweep writes for the test file's callers: the
/// module's with no call, and the test's one call settled outside the
/// repository. The parse side counts that call and the graph holds no edge
/// for it, which the arithmetic alone reads as a call that went nowhere.
fn ledger_the_callers(store: &Store) {
    let context = proof_context(LanguageId::Python, "1.1.400");
    let context_id = id_of(&context);
    admit(
        &store.graph,
        &[],
        vec![
            context,
            ledger(&store.caller_module, MODULE_BODY, context_id, Vec::new()),
            ledger(
                &store.caller,
                CALLER_BODY,
                context_id,
                vec![("print", CallSiteState::ProvenOutside)],
            ),
        ],
    );
}

/// The focal's own ledger: `fetch` proven into the repository, `get` settled
/// outside it, and `render` answered with nothing a resolver could place.
fn ledger_the_focal(store: &Store) {
    let context = proof_context(LanguageId::Python, "1.1.400");
    let context_id = id_of(&context);
    admit(
        &store.graph,
        &[],
        vec![
            context,
            ledger(
                &store.focal,
                FOCAL_BODY,
                context_id,
                vec![
                    (
                        "fetch",
                        CallSiteState::ProvenTarget {
                            target: store.target.id,
                        },
                    ),
                    ("get", CallSiteState::ProvenOutside),
                    (
                        "render",
                        CallSiteState::Unresolved {
                            reason: UnresolvedReason::NoAnswer,
                        },
                    ),
                ],
            ),
        ],
    );
}

fn args_for(entity: &Entity) -> HashMap<String, Value> {
    HashMap::from([("entity_id".to_string(), json!(entity.id.to_string()))])
}

fn clause_codes(block: &Value) -> Vec<String> {
    block["clauses"]
        .as_array()
        .map(|clauses| {
            clauses
                .iter()
                .filter_map(Value::as_str)
                .map(|clause| clause.split(':').next().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_context_pack_serves_the_focal_s_own_sites_and_the_verdict_reads_them() {
    let store = store();
    ledger_the_focal(&store);
    let sessions = SessionRegistry::empty_for_test();
    let result =
        handle_get_context_pack(&args_for(&store.focal), &store.graph, &sessions, None).unwrap();
    let value = finalized(result, "get_context_pack");
    let block = &value[crate::call_sites::CALL_SITES_KEY];
    assert_eq!(block["scope"], crate::call_sites::FOCAL_SCOPE, "{value}");
    assert_eq!(block["reading"], "current", "{block}");
    assert_eq!(block["sites"], 3, "{block}");
    let states: Vec<&str> = block["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .filter_map(|row| row["state"].as_str())
        .collect();
    assert_eq!(
        states,
        ["proven_target", "proven_outside", "unresolved"],
        "{block}"
    );
    assert_eq!(block["rows"][2]["reason"], "no_answer", "{block}");
    assert_eq!(clause_codes(block), ["call_sites_unresolved"], "{block}");
    let verdict = &value["_kin"]["verdict"];
    assert_eq!(verdict["inputs"]["call_sites"], "inconclusive", "{verdict}");
    assert!(
        verdict["limiting_factor"]
            .as_str()
            .is_some_and(|factor| factor.contains("call_sites_unresolved")),
        "{verdict}"
    );
    assert!(
        value["_kin"].get("self_check").is_none(),
        "the response agrees with itself: {value}"
    );
}

#[test]
fn a_spanned_focal_with_no_ledger_reports_owed_enrichment_on_every_focal_tool() {
    let store = store();
    let sessions = SessionRegistry::empty_for_test();
    let pack = payload(
        &handle_get_context_pack(&args_for(&store.focal), &store.graph, &sessions, None).unwrap(),
    );
    let neighborhood =
        payload(&handle_graph_neighborhood(&args_for(&store.focal), &store.graph).unwrap());
    for (tool, value) in [
        ("get_context_pack", &pack),
        ("graph_neighborhood", &neighborhood),
    ] {
        let block = &value[crate::call_sites::CALL_SITES_KEY];
        assert_eq!(block["reading"], "owed_enrichment", "{tool}: {value}");
        assert_eq!(block["callers_owed_enrichment"], 1, "{tool}: {block}");
        assert_eq!(block["rows"], json!([]), "{tool}: {block}");
        assert_eq!(clause_codes(block), ["call_sites_owed"], "{tool}: {block}");
    }
}

/// A focal no ledger describes is owed only while a resolver can still prove
/// its sites. When none can on this host now, because enrichment is switched
/// off, its language's server is missing, or that server cannot start, it
/// reads as unproven for want of a resolver: its own clause, naming why, and
/// never `call_sites_owed`, so waiting is not offered as the remedy. The
/// store's status counts such callers apart from the owed ones, and names no
/// owed file for them.
#[test]
fn a_focal_no_resolver_can_prove_reads_unproven_not_owed_on_every_focal_tool() {
    use kin_core::reference_coverage::LanguageServerReadiness;
    let store = store();
    let sessions = SessionRegistry::empty_for_test();
    let unusable = "no Python environment for this workspace".to_string();
    let cases = [
        (false, LanguageServerReadiness::Usable, None),
        (
            true,
            LanguageServerReadiness::Usable,
            Some(kin_model::NoResolver::EnrichmentOff),
        ),
        (
            false,
            LanguageServerReadiness::Disabled,
            Some(kin_model::NoResolver::EnrichmentOff),
        ),
        (
            false,
            LanguageServerReadiness::Absent,
            Some(kin_model::NoResolver::NoLanguageServer),
        ),
        (
            false,
            LanguageServerReadiness::Unusable {
                reason: unusable.clone(),
            },
            Some(kin_model::NoResolver::ServerCannotStart { reason: unusable }),
        ),
    ];
    for (switched_off, readiness, why) in cases {
        let why = why.map(|why| why.sentence(LanguageId::Python));
        let why = why.as_deref();
        let _off = crate::call_sites::test_support::scoped_enrichment_switched_off(switched_off);
        let _host = crate::edge_coverage::test_support::scoped_language_server_readiness(&[(
            LanguageId::Python,
            readiness.clone(),
        )]);
        let pack = finalized(
            handle_get_context_pack(&args_for(&store.focal), &store.graph, &sessions, None)
                .unwrap(),
            "get_context_pack",
        );
        let neighborhood =
            payload(&handle_graph_neighborhood(&args_for(&store.focal), &store.graph).unwrap());
        let status = crate::call_sites::store_block(&store.graph).unwrap();
        for (tool, block) in [
            ("get_context_pack", &pack[crate::call_sites::CALL_SITES_KEY]),
            (
                "graph_neighborhood",
                &neighborhood[crate::call_sites::CALL_SITES_KEY],
            ),
            ("kin_graph_status", &status),
        ] {
            let case = format!("{tool} with {readiness:?}, switched off {switched_off}");
            match why {
                Some(why) => {
                    assert_eq!(block["callers_owed_enrichment"], 0, "{case}: {block}");
                    assert!(
                        block["callers_unproven_no_resolver"].as_u64() >= Some(1),
                        "{case}: {block}"
                    );
                    assert_eq!(
                        clause_codes(block),
                        ["call_sites_unproven_no_resolver"],
                        "{case}: {block}"
                    );
                    assert!(
                        block["clauses"][0]
                            .as_str()
                            .is_some_and(|clause| clause.contains(why)),
                        "{case}: the clause names why: {block}"
                    );
                    assert!(
                        block["no_resolver"][why].as_u64() >= Some(1),
                        "{case}: {block}"
                    );
                }
                None => {
                    assert_eq!(block["callers_unproven_no_resolver"], 0, "{case}: {block}");
                    assert_eq!(clause_codes(block), ["call_sites_owed"], "{case}: {block}");
                }
            }
        }
        if why.is_some() {
            assert_eq!(
                pack[crate::call_sites::CALL_SITES_KEY]["reading"],
                "unproven_no_resolver"
            );
            assert_eq!(status["callers_owed"], 0, "{status}");
            assert_eq!(
                status["owed_file_count"], 0,
                "no sweep will reach them: {status}"
            );
            // The other inputs this fixture's host declaration wakes (edge
            // coverage, caller arrival) add their own codes; the call-site
            // input's is this one, and waiting is not among them.
            let verdict = &pack["_kin"]["verdict"];
            assert_eq!(verdict["state"], "inconclusive", "{verdict}");
            assert_eq!(verdict["inputs"]["call_sites"], "inconclusive", "{verdict}");
            let codes: Vec<&str> = verdict["limiting_factor"]
                .as_str()
                .unwrap_or_default()
                .split("; ")
                .collect();
            assert!(
                codes.contains(&"call_sites_unproven_no_resolver")
                    && !codes.contains(&"call_sites_owed"),
                "{verdict}"
            );
            assert!(
                pack["_kin"].get("self_check").is_none(),
                "the response agrees with itself: {pack}"
            );
        } else {
            assert!(status["owed_file_count"].as_u64() >= Some(1), "{status}");
        }
    }
}

#[test]
fn a_neighborhood_carries_the_focal_s_sites_only_when_it_walks_the_focal_s_calls() {
    let store = store();
    ledger_the_focal(&store);
    for direction in ["out", "both"] {
        let mut args = args_for(&store.focal);
        args.insert("direction".to_string(), json!(direction));
        let value = payload(&handle_graph_neighborhood(&args, &store.graph).unwrap());
        let block = &value[crate::call_sites::CALL_SITES_KEY];
        assert_eq!(block["reading"], "current", "{direction}: {value}");
        assert_eq!(block["rows"].as_array().map(Vec::len), Some(3), "{block}");
    }
    let mut args = args_for(&store.focal);
    args.insert("direction".to_string(), json!("in"));
    let value = payload(&handle_graph_neighborhood(&args, &store.graph).unwrap());
    assert!(
        value.get(crate::call_sites::CALL_SITES_KEY).is_none(),
        "an incoming walk reads the callers' edges, not the focal's own sites: {value}"
    );
}

#[test]
fn a_multi_focal_pack_tallies_every_focal_without_rows() {
    let store = store();
    ledger_the_focal(&store);
    // A second focal whose sweep has not reached it yet.
    let mut pending = spanned_entity(
        "pending",
        FOCAL_FILE,
        LanguageId::Python,
        400,
        "def pending():\n    go()\n",
    );
    pending.file_origin = None;
    store.graph.upsert_entity(&pending).unwrap();
    let args = HashMap::from([(
        "question_focals".to_string(),
        json!([
            {"entity_id": store.focal.id.to_string(), "route": "name", "query": "note_body"},
            {"entity_id": pending.id.to_string(), "route": "name", "query": "pending"},
        ]),
    )]);
    let sessions = SessionRegistry::empty_for_test();
    let value = payload(&handle_get_context_pack(&args, &store.graph, &sessions, None).unwrap());
    let block = &value[crate::call_sites::CALL_SITES_KEY];
    assert_eq!(block["scope"], crate::call_sites::FOCALS_SCOPE, "{value}");
    assert_eq!(block["callers"], 2, "{block}");
    assert_eq!(block["callers_owed_enrichment"], 1, "{block}");
    assert_eq!(block["sites"], 3, "{block}");
    assert!(block.get("rows").is_none(), "{block}");
}

#[tokio::test]
async fn find_references_counts_a_ledgered_family_without_certifying_unread_callers() {
    let store = store();
    ledger_the_callers(&store);
    let value = finalized(
        handle_find_references(&args_for(&store.target), &store.graph, None)
            .await
            .unwrap(),
        "find_references",
    );
    let arrival = &value[crate::caller_arrival::CALLER_ARRIVAL_KEY];
    assert_eq!(arrival["state"], "accounted", "{arrival}");
    assert_eq!(arrival["count_exact"], true, "{arrival}");
    assert_eq!(arrival["files_counted_from_site_ledgers"], 1, "{arrival}");
    let block = &value[crate::call_sites::CALL_SITES_KEY];
    assert_eq!(block["scope"], crate::call_sites::NAMED_SCOPE, "{value}");
    assert_eq!(block["callers"], 3, "{block}");
    assert_eq!(block["callers_owed_enrichment"], 1, "{block}");
    assert_eq!(block["focal_escape"]["escape"], "unknown", "{block}");
    assert_eq!(block["settled"], false, "{block}");
    assert_eq!(
        value["_kin"]["verdict"]["inputs"]["call_sites"], "inconclusive",
        "{value}"
    );
    assert!(value["_kin"].get("self_check").is_none(), "{value}");
}

/// A caller that reaches the focal without importing its file, the way Flask's
/// `views.py` reaches `ensure_sync` through `current_app`.
const PROXY_FILE: &str = "pkg/views.py";
const PROXY_BODY: &str = "def dispatch_request(self):\n    return current_app.ensure_sync(self)\n";

/// A caller in a file that imports nothing from the focal's file, with call
/// sites the sweep has not reached.
fn add_owed_proxy_caller(store: &Store) -> Entity {
    let proxy = counted(
        spanned_entity(
            "dispatch_request",
            PROXY_FILE,
            LanguageId::Python,
            20,
            PROXY_BODY,
        ),
        1,
    );
    store.graph.upsert_entity(&proxy).unwrap();
    proxy
}

/// A settled family is not a settled answer while a caller outside it is
/// owed its sites. Measured on Flask right after `kin init`: `kin refs
/// ensure_sync` listed 10 of 12 callers under "every site in scope is
/// settled" while the sweep still owed the file that reaches it through
/// `current_app`.
#[tokio::test]
async fn find_references_reads_an_owed_caller_outside_the_family_as_unsettled() {
    let store = store();
    ledger_the_callers(&store);
    add_owed_proxy_caller(&store);
    let value = finalized(
        handle_find_references(&args_for(&store.target), &store.graph, None)
            .await
            .unwrap(),
        "find_references",
    );
    let arrival = &value[crate::caller_arrival::CALLER_ARRIVAL_KEY];
    // The family itself is still counted exactly; the gap is outside it.
    assert_eq!(arrival["state"], "accounted", "{arrival}");
    assert_eq!(arrival["count_exact"], true, "{arrival}");
    assert_eq!(arrival["owed_outside_scope"]["file_count"], 1, "{arrival}");
    let block = &value[crate::call_sites::CALL_SITES_KEY];
    assert_eq!(block["settled"], false, "{block}");
    assert_eq!(clause_codes(block), ["call_sites_owed"], "{block}");
    assert_eq!(block["scope"], crate::call_sites::NAMED_SCOPE, "{block}");
    assert_eq!(block["callers_owed_enrichment"], 2, "{block}");
    assert_eq!(
        arrival["owed_outside_scope"]["files"][0]["file"], PROXY_FILE,
        "{arrival}"
    );
    let text = crate::call_sites::text_lines(block).join("\n");
    assert!(!text.contains("every site in scope is settled"), "{text}");
    assert!(text.contains("  not settled: call_sites_owed: "), "{text}");
    let verdict = &value["_kin"]["verdict"];
    assert_eq!(verdict["state"], "inconclusive", "{verdict}");
    assert_eq!(verdict["inputs"]["call_sites"], "inconclusive", "{verdict}");
}

/// Once the sweep settles every potential caller, the call-site component
/// certifies. Other missing graph evidence still bounds the overall answer.
#[tokio::test]
async fn find_references_certifies_once_the_caller_outside_the_family_is_ledgered() {
    let store = store();
    ledger_the_callers(&store);
    let proxy = add_owed_proxy_caller(&store);
    let context = proof_context(LanguageId::Python, "1.1.400");
    let context_id = id_of(&context);
    admit(
        &store.graph,
        &[],
        vec![
            context,
            ledger(
                &proxy,
                PROXY_BODY,
                context_id,
                vec![("current_app.ensure_sync", CallSiteState::ProvenOutside)],
            ),
            ledger(
                &store.focal,
                FOCAL_BODY,
                context_id,
                vec![
                    ("fetch", CallSiteState::ProvenOutside),
                    ("get", CallSiteState::ProvenOutside),
                    ("render", CallSiteState::ProvenOutside),
                ],
            ),
        ],
    );
    let value = finalized(
        handle_find_references(&args_for(&store.target), &store.graph, None)
            .await
            .unwrap(),
        "find_references",
    );
    let block = &value[crate::call_sites::CALL_SITES_KEY];
    assert_eq!(block["settled"], true, "{block}");
    assert!(block.get("owed_outside_scope").is_none(), "{block}");
    assert!(
        value[crate::caller_arrival::CALLER_ARRIVAL_KEY]
            .get("owed_outside_scope")
            .is_none(),
        "{value}"
    );
    assert_eq!(
        value["_kin"]["verdict"]["inputs"]["call_sites"], "certified",
        "{value}"
    );
    assert_eq!(
        value["negative"]["safe_to_conclude_absent"], false,
        "{value}"
    );
}

#[tokio::test]
async fn find_references_keeps_the_arithmetic_for_a_family_with_owed_callers() {
    let store = store();
    let value = finalized(
        handle_find_references(&args_for(&store.target), &store.graph, None)
            .await
            .unwrap(),
        "find_references",
    );
    let arrival = &value[crate::caller_arrival::CALLER_ARRIVAL_KEY];
    assert_eq!(arrival["state"], "unaccounted", "{arrival}");
    assert_eq!(arrival["count_exact"], false, "{arrival}");
    assert_eq!(arrival["owed_caller_count"], 2, "{arrival}");
    let named: Vec<&str> = arrival["owed_callers"]
        .as_array()
        .expect("owed callers")
        .iter()
        .filter_map(|caller| caller["name"].as_str())
        .collect();
    assert!(
        named.contains(&"test_round_trip") && named.contains(&"test_storage"),
        "{arrival}"
    );
    let block = &value[crate::call_sites::CALL_SITES_KEY];
    assert_eq!(clause_codes(block), ["call_sites_owed"], "{block}");
    let verdict = &value["_kin"]["verdict"];
    assert_eq!(verdict["state"], "inconclusive", "{verdict}");
    assert_eq!(verdict["inputs"]["call_sites"], "inconclusive", "{verdict}");
    assert!(value["_kin"].get("self_check").is_none(), "{value}");
}

/// Give `entity` the parse-time preview of `body`, which the parser keeps
/// whole for a body this short.
fn previewed(store: &Store, entity: &Entity, body: &str) {
    let mut entity = entity.clone();
    entity.metadata.extra.insert(
        kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY.to_string(),
        json!(body.split_whitespace().collect::<Vec<_>>().join(" ")),
    );
    store.graph.upsert_entity(&entity).unwrap();
}

/// Name-only previews cannot rule out a call through an alias while the
/// selected source tree is unavailable. Family arrival may still report its
/// narrower name count, but the call proof must preserve the broader debt.
#[tokio::test]
async fn find_references_keeps_owed_callers_without_selected_escape_evidence() {
    let store = store();
    previewed(&store, &store.caller, CALLER_BODY);
    previewed(&store, &store.caller_module, MODULE_BODY);
    let value = finalized(
        handle_find_references(&args_for(&store.target), &store.graph, None)
            .await
            .unwrap(),
        "find_references",
    );
    let arrival = &value[crate::caller_arrival::CALLER_ARRIVAL_KEY];
    assert_eq!(arrival["owed_caller_count"], 2, "{arrival}");
    assert_eq!(arrival["owed_callers_cannot_name_focal"], 2, "{arrival}");
    let block = &value[crate::call_sites::CALL_SITES_KEY];
    assert_eq!(block["settled"], false, "{block}");
    assert_eq!(block["callers"], 3, "{block}");
    assert_eq!(block["callers_owed_enrichment"], 3, "{block}");
    assert_eq!(block["focal_escape"]["escape"], "unknown", "{block}");
    assert_eq!(clause_codes(block), ["call_sites_owed"], "{block}");
    assert_eq!(
        value["_kin"]["verdict"]["inputs"]["call_sites"], "inconclusive",
        "{value}"
    );
}

/// An import that binds the focal under another name spells it in the file's
/// module, so the module stays counted as owed and the answer stays unsettled
/// until the sweep proves its sites.
#[tokio::test]
async fn an_owed_module_that_imports_the_focal_under_another_name_still_counts() {
    let store = store();
    previewed(&store, &store.caller, CALLER_BODY);
    previewed(
        &store,
        &store.caller_module,
        "from storage import find_note as lookup\n",
    );
    let value = finalized(
        handle_find_references(&args_for(&store.target), &store.graph, None)
            .await
            .unwrap(),
        "find_references",
    );
    let block = &value[crate::call_sites::CALL_SITES_KEY];
    assert_eq!(block["callers_owed_enrichment"], 3, "{block}");
    assert_eq!(block["focal_escape"]["escape"], "unknown", "{block}");
    assert_eq!(clause_codes(block), ["call_sites_owed"], "{block}");
    assert_eq!(
        value["_kin"]["verdict"]["inputs"]["call_sites"], "inconclusive",
        "{value}"
    );
}

#[test]
fn a_site_row_names_its_target_by_an_id_the_entity_tools_accept() {
    let store = store();
    ledger_the_focal(&store);
    let sessions = SessionRegistry::empty_for_test();
    let pack = payload(
        &handle_get_context_pack(&args_for(&store.focal), &store.graph, &sessions, None).unwrap(),
    );
    let target = pack[crate::call_sites::CALL_SITES_KEY]["rows"][0]["target"]
        .as_str()
        .expect("a proven site names its target")
        .to_string();
    assert_eq!(target, format!("entity:{}", store.target.id));
    let by_address = HashMap::from([("entity_id".to_string(), json!(target))]);
    let neighborhood = payload(&handle_graph_neighborhood(&by_address, &store.graph).unwrap());
    assert_eq!(
        neighborhood["focal_id"],
        store.target.id.to_string(),
        "graph_neighborhood takes the row's target as it is spelled: {neighborhood}"
    );
}

#[test]
fn graph_status_carries_the_store_s_site_shares_and_its_owed_callers() {
    use super::entities::{
        handle_daemon_graph_status_observation, with_call_site_status, GraphStatusObservation,
        GraphStatusReport, GraphStatusScope,
    };
    let store = store();
    ledger_the_focal(&store);
    ledger_the_callers(&store);
    let status = handle_daemon_graph_status_observation(
        GraphStatusScope::Head,
        GraphStatusObservation {
            details: None,
            authority_epoch: 1,
            entity_count: 5,
            relation_count: 1,
            embeddings_indexed: 0,
            embeddings_pending: 0,
            embeddings_total: 0,
            embedding_index_keys: None,
            durable_entity_count: None,
            durable_relation_count: None,
        },
    )
    .unwrap();
    let result = with_call_site_status(status, &store.graph);
    let report: GraphStatusReport =
        serde_json::from_value(payload(&result)).expect("the report still reads as a report");
    let block = report
        .call_sites
        .expect("the store's sites ride the status");
    assert_eq!(block["scope"], crate::call_sites::STORE_SCOPE, "{block}");
    assert_eq!(block["census"], 4, "{block}");
    let shares = block["shares"].as_object().expect("shares");
    let total: u64 = shares
        .values()
        .map(|share| share["sites"].as_u64().unwrap_or(0))
        .sum();
    assert_eq!(total, 4, "the shares add up to the census: {block}");
    assert_eq!(shares["proven_outside"]["sites"], 2, "{block}");
    assert_eq!(shares["proven_outside"]["share"], 0.5, "{block}");
    // `find_note` and the module it lives in carry no text, so they hold no
    // site and owe nothing.
    assert_eq!(block["callers_owed"], 0, "{block}");
    assert_eq!(clause_codes(&block), ["call_sites_unresolved"], "{block}");

    let value = finalized(result, "kin_graph_status");
    assert_eq!(
        value["_kin"]["verdict"]["inputs"]["call_sites"], "inconclusive",
        "{value}"
    );
}
