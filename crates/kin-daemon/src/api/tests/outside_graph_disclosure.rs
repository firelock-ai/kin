// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The composed path: a daemon tool result, the disclosure, and the verdict read
//! off it.
//!
//! The first version of this disclosure was attached in `kin_mcp`'s dispatcher,
//! and the express case still read `certified`, `exact`, `complete`, because the
//! daemon never reaches that dispatcher for the tools the case was found on:
//! `semantic_locate` returns out of the fused pipeline and `find_references` out
//! of its stable-authority path. A test on the observation alone cannot see any
//! of that, which is why four of these arms run the function the local route
//! actually calls, on a payload shaped like the one it actually builds, and then
//! compute the response's real verdict over the result. The fifth posts to the
//! route itself, because the claim it makes is about the route's own read of the
//! question rather than about the function that read is handed to.
//!
//! Scope is the LOCAL route, `POST /mcp/tools/call`. The repo-scoped hosted
//! route serves `semantic_locate`, `get_context_pack` and `trace_data_flow` from
//! its own view and deliberately does NOT disclose, because its handlers
//! finalize their own envelope before the point a block could be inserted.
//! Nothing in this file covers that route.

use serde_json::{json, Value};

use kin_db::InMemoryGraph;
use kin_model::entity::{
    Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
    Visibility,
};
use kin_model::graph::EntityStore as _;
use kin_model::ids::{EntityId, FilePathId, Hash256, LanguageId};

use crate::api::{bound_mcp_tool_result, disclose_outside_graph};

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

/// One function this repository owns, and one symbol reached through a package
/// it never admitted: the express graph the stranger asked, in two entities.
///
/// Taken as a store rather than returning one, because the route arms have to
/// seed the store the daemon already owns and the function arms build their own.
fn seed_express_entities(graph: &InMemoryGraph) {
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
}

/// A standalone store shaped like the express graph, for the arms that call the
/// disclosure directly.
fn express_graph() -> InMemoryGraph {
    let graph = InMemoryGraph::new();
    seed_express_entities(&graph);
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

/// The reported case, on each tool the local route serves off its own path.
///
/// `semantic_locate` and `find_references` return from that route before the
/// shared dispatcher, and `get_context_pack` and `trace_data_flow` reach it
/// through the dispatcher. All four end on the line this disclosure sits on,
/// because it sits after the inner dispatch rather than inside it, and all four
/// must stop certifying. The hosted route serves three of these tools from its
/// own view, discloses nothing, and is not graded here.
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
        // Envelope v2 sends the code alone; the symbol is a fact of the
        // `outside_graph` block, asserted above, and never restated in prose.
        assert!(
            factor
                .split("; ")
                .all(|code| !code.contains('`') && !code.contains(' ')),
            "{tool}: the factor is codes, and the symbol lives in outside_graph.symbols: {factor}"
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
    let kin_mcp::ContentBlock::Text { text } =
        disclosed.content.first().expect("the error text survives");
    assert_eq!(text, message);
    assert_eq!(disclosed.is_error, Some(true));
}

/// One tool call served by the local MCP route, and the payload it answered
/// with.
///
/// The store is the daemon's own, seeded before the call, so the graph the route
/// resolves for the disclosure is the graph this fixture built.
async fn payload_served_by_the_local_route(tool: &str, arguments: Value) -> Value {
    let state = super::test_state();
    seed_express_entities(&state.graph);
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);

    let request = axum::http::Request::post("/mcp/tools/call")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({ "name": tool, "arguments": arguments }).to_string(),
        ))
        .expect("the fixture request builds");
    let response = tower::ServiceExt::oneshot(crate::api::router(state), request)
        .await
        .expect("the router answers");
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "{tool}: the route must serve this call for the disclosure to be gradeable"
    );

    let body = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("the served body reads");
    let result: kin_mcp::ToolCallResult =
        serde_json::from_slice(&body).expect("the route answers a tool result");
    let kin_mcp::ContentBlock::Text { text } = result
        .content
        .first()
        .expect("a served tool result carries one content block");
    assert_ne!(
        result.is_error,
        Some(true),
        "{tool}: the tool itself must succeed, or this arm grades an error string: {text}"
    );
    serde_json::from_str(text).unwrap_or_else(|_| panic!("{tool}: served a JSON payload: {text}"))
}

/// A question carried under either argument name is disclosed on the response the
/// route served. Both names exist because `get_context_pack` carries its
/// question as `question` where the rest carry `query`.
///
/// Named for what it observes rather than for what attached the block, and the
/// distinction is load-bearing. This test used to call
/// `kin_mcp::outside_graph::question_argument` on a hand-built map under the
/// name `the_route_reads_the_question_from_either_argument_name`. That function
/// is covered where it lives, the call stayed green with the route's own read of
/// it deleted, and so the name claimed coverage the body did not have. It now
/// posts to `POST /mcp/tools/call` and reads what the route served.
///
/// What each arm pins is different. `semantic_locate` returns out of the fused
/// pipeline without reaching `kin_mcp::handlers::handle_tool_call`, so a block
/// on that payload can only have come from this route's own disclosure: delete
/// either the route's `question_argument` read or its `disclose_outside_graph`
/// call and that arm goes red. `get_context_pack` does reach the shared
/// dispatcher, which attaches the same block from the same observation, so that
/// arm pins that the `question` name is served disclosed without saying which of
/// the two attached it. No arm can say, because the two blocks are identical.
///
/// `get_context_pack` is also given `entities`, which the route never reads.
/// Question resolution needs a live daemon index, so without a focal the tool
/// answers an error string and there is no payload to disclose into.
#[tokio::test]
async fn a_question_under_either_argument_name_is_disclosed_on_the_route() {
    for (tool, argument, extra) in [
        ("semantic_locate", "query", json!({})),
        (
            "get_context_pack",
            "question",
            json!({ "entities": ["app.handle"] }),
        ),
    ] {
        let arguments = |question: &str| {
            let mut arguments = extra.clone();
            arguments[argument] = json!(question);
            arguments
        };

        let payload = payload_served_by_the_local_route(tool, arguments(EXPRESS_QUESTION)).await;
        let block = payload.get("outside_graph").unwrap_or_else(|| {
            panic!("{tool}: a question carried as `{argument}` reaches the disclosure: {payload}")
        });
        assert_eq!(
            block["symbols"],
            json!([{ "symbol": "Router", "modules": [] }]),
            "{tool}: the symbol the question named is the one reported"
        );

        // The control, on the same route and the same store. Without it this
        // test passes against a route that discloses unconditionally, which is
        // the failure mode a disclosure pass is most likely to acquire.
        let local = payload_served_by_the_local_route(tool, arguments(LOCAL_QUESTION)).await;
        assert!(
            local.get("outside_graph").is_none(),
            "{tool}: a question naming nothing outside the graph is served untouched: {local}"
        );
    }
}

/// Fitting a disclosed payload preserves its coverage block.
#[test]
fn a_disclosed_payload_is_refitted_rather_than_shipped_over_its_ceiling() {
    let graph = express_graph();
    let budget = kin_mcp::budget::ResponseBudget {
        max_chars: 4_000,
        ..kin_mcp::budget::ResponseBudget::default()
    };
    let payload = json!({
        "total_upstream": 24,
        "references": (0..24).map(|index| json!({
            "entity_id": format!("reference-{index}"),
            "name": format!("caller_{index}"),
            "file_path": "lib/application.js",
            "reference_lines": (0..40).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "degradations": [],
        "counts": { "receiver_name_candidates": 0 },
    });
    let built = result_with(payload);
    let kin_mcp::ContentBlock::Text { text: raw } =
        built.content.first().expect("one content block");
    assert!(
        raw.len() > budget.max_chars,
        "the fixture must start over its ceiling: {}",
        raw.len()
    );

    let fitted = bound_mcp_tool_result(built, "find_references", &budget);
    let kin_mcp::ContentBlock::Text { text: after_fit } =
        fitted.content.first().expect("one content block");
    assert!(after_fit.len() <= budget.max_chars, "{}", after_fit.len());

    let disclosed = disclose_outside_graph(Some(&graph), Some(EXPRESS_QUESTION), fitted);
    let block = payload_of(&disclosed);
    assert!(
        block.get("outside_graph").is_some(),
        "the disclosure must fire, or the ceiling below is never pressured: {block}"
    );

    let emitted = bound_mcp_tool_result(disclosed, "find_references", &budget);
    let kin_mcp::ContentBlock::Text { text } = emitted.content.first().expect("one content block");
    assert!(
        text.len() <= budget.max_chars,
        "a disclosed response still fits its ceiling: {} > {}",
        text.len(),
        budget.max_chars
    );
    let shipped: Value = serde_json::from_str(text).expect("the emitted payload is JSON");
    assert!(shipped.get("outside_graph").is_some(), "{shipped}");
    assert!(
        shipped.get("_kin_json_format").is_none(),
        "the serialization control field does not ship: {shipped}"
    );
}

/// The emitted HTTP payload includes the disclosure and still fits its ceiling.
#[tokio::test]
async fn a_disclosed_payload_is_refitted_on_the_http_route() {
    let state = super::test_state();
    seed_express_entities(&state.graph);
    for index in 0..24 {
        state
            .graph
            .upsert_entity(&entity(
                &format!("router_param_callback_{index}"),
                Some("lib/application.js"),
                EntityRole::Source,
                EntityKind::Function,
            ))
            .unwrap();
    }
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let tool = "semantic_locate";
    let mut pressured = 0;
    // Coverage metadata varies by host. Find a ceiling that refitting can meet,
    // while proving the disclosure alone pushes the emitted payload over it.
    for ceiling in (4_000..=12_000).step_by(100) {
        let arguments: std::collections::HashMap<String, Value> = serde_json::from_value(json!({
            "query": EXPRESS_QUESTION,
            "max_response_chars": ceiling,
            "limit": 24,
        }))
        .unwrap();
        let budget = kin_mcp::budget::ResponseBudget::from_arguments(&arguments);
        let axum::Json(raw) = crate::api::mcp_tools_call_inner(
            axum::http::HeaderMap::new(),
            axum::extract::State(state.clone()),
            axum::Json(crate::api::McpToolCallRequest {
                name: tool.into(),
                arguments: arguments.clone(),
            }),
        )
        .await
        .unwrap();
        assert_ne!(raw.is_error, Some(true));
        let fitted = bound_mcp_tool_result(raw, tool, &budget);
        let kin_mcp::ContentBlock::Text { text: initial } = &fitted.content[0];
        if initial.len() > ceiling {
            continue;
        }
        let before_disclosure = payload_of(&fitted);
        assert!(before_disclosure.get("outside_graph").is_none());
        let disclosed =
            disclose_outside_graph(Some(state.graph.as_ref()), Some(EXPRESS_QUESTION), fitted);
        let block = payload_of(&disclosed);
        assert!(block.get("outside_graph").is_some());
        let kin_mcp::ContentBlock::Text { text: unfitted } = &disclosed.content[0];
        if unfitted.len() <= ceiling {
            continue;
        }
        let control = bound_mcp_tool_result(disclosed.clone(), tool, &budget);
        let kin_mcp::ContentBlock::Text { text: fitted } = &control.content[0];
        if fitted.len() > ceiling {
            continue;
        }
        pressured += 1;
        let request = axum::http::Request::post("/mcp/tools/call")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({"name":tool,"arguments":arguments}).to_string(),
            ))
            .unwrap();
        let response = tower::ServiceExt::oneshot(crate::api::router(state.clone()), request)
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        let result: kin_mcp::ToolCallResult = serde_json::from_slice(&body).unwrap();
        let kin_mcp::ContentBlock::Text { text } = &result.content[0];
        assert_ne!(result.is_error, Some(true), "{text}");
        assert!(
            text.len() <= ceiling,
            "HTTP payload is {} bytes against {ceiling}; without the final fit it was {}",
            text.len(),
            unfitted.len()
        );
        let payload: Value = serde_json::from_str(text).unwrap();
        assert!(payload.get("outside_graph").is_some(), "{payload}");
        assert!(payload.get("_kin_json_format").is_none());
        break;
    }
    assert!(
        pressured > 0,
        "the fixture must exceed at least one ceiling after disclosure"
    );
}
