// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The composed path: a daemon tool result, the disclosure, and the verdict read
//! off it.
//!
//! The first version of this disclosure was attached in `kin_mcp`'s dispatcher,
//! and the express case still read `certified`, `exact`, `complete`, because the
//! daemon never reaches that dispatcher for the tools the case was found on.
//! `semantic_locate` returns out of the fused pipeline, `find_references` out of
//! its stable-authority path, and the hosted route serves three tools from its
//! own view. A test on the observation alone cannot see any of that, which is
//! why these arms run the function the routes actually call, on a payload shaped
//! like the one they actually build, and then compute the response's real
//! verdict over the result.

use std::collections::HashMap;

use serde_json::{json, Value};

use kin_db::InMemoryGraph;
use kin_model::entity::{
    Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
    Visibility,
};
use kin_model::graph::EntityStore as _;
use kin_model::ids::{EntityId, FilePathId, Hash256, LanguageId};

use crate::api::disclose_outside_graph;

/// The express question, verbatim from the run that found this.
const EXPRESS_QUESTION: &str = "where router.param callbacks are registered and stored, and how a \
                                request is dispatched through the middleware stack";
/// A question about code this repository owns, on the same store.
const LOCAL_QUESTION: &str = "where does app.handle prepare the response object";

fn entity(name: &str, file: Option<&str>, role: EntityRole, kind: EntityKind) -> Entity {
    Entity {
        id: EntityId::new(),
        kind,
        name: name.to_string(),
        language: LanguageId::JavaScript,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0; 32]),
            signature_hash: Hash256::from_bytes([0; 32]),
            behavior_hash: Hash256::from_bytes([0; 32]),
            equivalence_hash: Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        },
        file_origin: file.map(FilePathId::new),
        span: None,
        signature: String::new(),
        visibility: Visibility::Public,
        role,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

/// A store shaped like the express graph the stranger asked: one function this
/// repository owns, and one symbol reached through a package it never admitted.
fn express_graph() -> InMemoryGraph {
    let graph = InMemoryGraph::new();
    graph
        .upsert_entity(&entity(
            "app.handle",
            Some("lib/application.js"),
            EntityRole::Source,
            EntityKind::Function,
        ))
        .expect("the local definition admits");
    graph
        .upsert_entity(&entity(
            "Router",
            None,
            EntityRole::External,
            EntityKind::Module,
        ))
        .expect("the external reference target admits");
    graph
}

/// A result carrying one tool's payload, as the routes hand it to the
/// disclosure.
fn result_with(payload: Value) -> kin_mcp::ToolCallResult {
    kin_mcp::ToolCallResult::text(
        serde_json::to_string_pretty(&payload).expect("the fixture payload serializes"),
    )
}

fn payload_of(result: &kin_mcp::ToolCallResult) -> Value {
    let kin_mcp::ContentBlock::Text { text } = result
        .content
        .first()
        .expect("a tool result carries one content block");
    serde_json::from_str(text).expect("the disclosed payload is still JSON")
}

/// The verdict a response carrying this payload would publish.
fn verdict_over(payload: &Value) -> Value {
    kin_mcp::Verdict::compute(
        "semantic_locate",
        payload,
        &kin_mcp::Envelope::daemon(),
        Some(&json!({ "interpretation": "qualified_answer" })),
    )
    .expect("a retrieval payload carries a verdict")
    .to_value()
}

/// A payload with nothing wrong with it: every input that could qualify it
/// agrees, so it certifies unless something new refuses.
fn certifiable_payload(collection: &str) -> Value {
    json!({
        collection: [{ "name": "app.handle", "file_path": "lib/application.js" }],
        "degradations": [],
        "counts": { "receiver_name_candidates": 0 },
    })
}

/// The arguments each daemon route carries its question in.
fn arguments_with(name: &str, question: &str) -> HashMap<String, Value> {
    HashMap::from([(name.to_string(), json!(question))])
}

/// The reported case, on each tool the daemon serves off its own path.
///
/// `semantic_locate` and `find_references` return from the local route before
/// the shared dispatcher; `get_context_pack` and `trace_data_flow` are served by
/// the hosted route from its own view. Every one of them ends on the line this
/// disclosure sits on, and every one of them must stop certifying.
#[test]
fn every_daemon_served_tool_stops_certifying_the_express_question() {
    let graph = express_graph();
    for (tool, collection) in [
        ("semantic_locate", "results"),
        ("find_references", "references"),
        ("get_context_pack", "focals"),
        ("trace_data_flow", "records"),
    ] {
        let before = certifiable_payload(collection);
        assert_eq!(
            verdict_over(&before)["state"],
            json!("certified"),
            "{tool}: the fixture has to certify before the disclosure, or this arm proves nothing"
        );

        let after = payload_of(&disclose_outside_graph(
            Some(&graph),
            Some(EXPRESS_QUESTION),
            result_with(before),
        ));
        let block = after
            .get("outside_graph")
            .unwrap_or_else(|| panic!("{tool}: the disclosure reaches this tool's payload"));
        assert_eq!(block["scan"], json!("complete"), "{tool}");
        assert_eq!(
            block["symbols"],
            json!([{ "symbol": "Router", "modules": [] }]),
            "{tool}: the symbol the question named is the one reported"
        );

        let verdict = verdict_over(&after);
        assert_eq!(
            verdict["state"],
            json!("inconclusive"),
            "{tool}: a question whose answer may live outside this graph cannot be certified: \
             {verdict}"
        );
        assert_eq!(verdict["inputs"]["outside_graph"], json!("inconclusive"));
        let factor = verdict["limiting_factor"]
            .as_str()
            .unwrap_or_else(|| panic!("{tool}: an inconclusive verdict names its factor"));
        assert!(
            factor.contains("dependency_outside_graph"),
            "{tool}: the clause carries its own label: {factor}"
        );
        assert!(
            factor.contains("`Router`"),
            "{tool}: and names the symbol: {factor}"
        );
    }
}

/// The control. The same store, which does hold an unadmitted package, and a
/// question about code this repository owns: the payload comes back untouched
/// and the verdict still certifies.
#[test]
fn a_question_about_local_code_leaves_every_daemon_payload_untouched() {
    let graph = express_graph();
    for collection in ["results", "references", "focals", "records"] {
        let before = certifiable_payload(collection);
        let after = payload_of(&disclose_outside_graph(
            Some(&graph),
            Some(LOCAL_QUESTION),
            result_with(before.clone()),
        ));
        assert_eq!(
            after, before,
            "a question naming nothing outside the graph must change nothing"
        );
        assert_eq!(
            verdict_over(&after)["state"],
            json!("certified"),
            "and the verdict keeps its ability to say yes"
        );
    }
}

/// A call with no question at all reaches the graph for nothing and changes
/// nothing, which is most calls on this route.
#[test]
fn a_call_carrying_no_question_is_left_exactly_as_built() {
    let graph = express_graph();
    let before = certifiable_payload("results");
    let after = disclose_outside_graph(Some(&graph), None, result_with(before.clone()));
    assert_eq!(payload_of(&after), before);

    // And with no graph resolved, which is what the route hands over when the
    // call carried no question.
    let after = disclose_outside_graph(None, Some(EXPRESS_QUESTION), result_with(before.clone()));
    assert_eq!(payload_of(&after), before);
}

/// A payload that is not a JSON object survives untouched. An error result is
/// human text, and a disclosure pass may only ever add.
#[test]
fn a_non_json_result_is_returned_verbatim() {
    let graph = express_graph();
    let message = "no entity matched the name 'Router'";
    let disclosed = disclose_outside_graph(
        Some(&graph),
        Some(EXPRESS_QUESTION),
        kin_mcp::ToolCallResult::error(message),
    );
    let kin_mcp::ContentBlock::Text { text } = disclosed
        .content
        .first()
        .expect("the error text survives");
    assert_eq!(text, message);
    assert_eq!(disclosed.is_error, Some(true));
}

/// Both argument names reach the disclosure, because `get_context_pack` carries
/// its question as `question` where the rest carry `query`.
#[test]
fn the_route_reads_the_question_from_either_argument_name() {
    for name in ["query", "question"] {
        let arguments = arguments_with(name, EXPRESS_QUESTION);
        assert_eq!(
            kin_mcp::outside_graph::question_argument(&arguments),
            Some(EXPRESS_QUESTION),
            "{name} is a question this route must act on"
        );
    }
}
