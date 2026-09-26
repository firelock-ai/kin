// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

const IMPORTED_GETTER_SOURCE: &str = "var Channel = require('external-wire');\n\
var service = {};\n\
service.initialize = function() {\n\
 var held = null;\n\
 Object.defineProperty(this, 'transport', { get: function() {\n\
  if (held === null) { held = new Channel(); }\n\
  return held;\n\
 }});\n\
};\n\
service.dispatch = function(request) { this.transport.send(request); };\n";

async fn imported_getter_trace(state: &Arc<DaemonState>, expected: bool) {
    let caller = external_edit_entity(state, "service.dispatch");
    let result = mcp_call(
        router(Arc::clone(state)),
        "trace_data_flow",
        json!({"focal": caller.id.to_string(), "depth": 1, "direction": "calls", "include_body": true}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    let payload = tool_result_payload(&result);
    let external: Vec<_> = payload["chain"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|step| step["entity_name"] == "transport.send")
        .collect();
    assert_eq!(external.len(), usize::from(expected), "{payload}");
    if expected {
        let step = external[0];
        assert_eq!(step["entity_role"], "external");
        assert_eq!(step["external"], true);
        assert_eq!(step["resolution"], "name_only");
        assert_eq!(step["terminal"], "external_reference");
        assert_eq!(step["crossing"]["status"], "named");
        assert_eq!(step["crossing"]["specifier"], "external-wire");
        for field in ["entity_file", "signature", "body", "start_line", "end_line"] {
            assert!(step[field].is_null(), "external identity must not fabricate {field}: {step}");
        }
        // The call on line 10 is certain, but its target is an external
        // placeholder resolved by name alone. Trace views disclose such an
        // occurrence instead of folding it into the step's lines, and reference
        // surfaces are where candidates are exposed.
        assert_eq!(step["reference_lines"], json!([]), "{step}");
        assert_eq!(
            step["reference_lines_partial_reason"], "unconfirmed_sites_withheld",
            "{step}"
        );
    }
}

#[tokio::test]
async fn imported_getter_mcp_trace_edit_withdrawal_recovery_and_cold_reopen() {
    let (_dir, state) = mcp_lifecycle_fixture();
    source_tree_conversion_fixture(&state, json!({
        "verb":"create", "target":EXTERNAL_EDIT_FILE,
        "description":"install imported getter source", "body":IMPORTED_GETTER_SOURCE
    })).await;
    let caller = external_edit_entity(&state, "service.dispatch");
    external_edit_assert_published(&state, caller.id, "external-wire", IMPORTED_GETTER_SOURCE);
    imported_getter_trace(&state, true).await;

    // Modify only the initializer through its graph-bound source base. The
    // unchanged caller must lose its derived crossing when that proof is gone.
    let initializer = external_edit_entity(&state, "service.initialize");
    let source = external_edit_source(&state, initializer.id).await;
    let body = source["body"].as_str().unwrap();
    let changed = body.replace("held = new Channel();", "held = unknown;");
    assert_ne!(changed, body);
    source_base_commit_operation(&state, json!({
        "verb":"update", "target":initializer.id.to_string(),
        "description":"withdraw imported receiver proof", "body":changed,
        "payload":{"EntitySourceBase":source["source_base"]}
    })).await;
    imported_getter_trace(&state, false).await;
    let layout = state.layout.clone();
    drop(state);
    let state = Arc::new(DaemonState::open(layout).unwrap());
    external_edit_initialize(&state).await;
    imported_getter_trace(&state, false).await;

    let initializer = external_edit_entity(&state, "service.initialize");
    let changed_source = external_edit_source(&state, initializer.id).await;
    source_base_commit_operation(&state, json!({
        "verb":"update", "target":initializer.id.to_string(),
        "description":"restore imported receiver proof", "body":body,
        "payload":{"EntitySourceBase":changed_source["source_base"]}
    })).await;
    external_edit_assert_published(&state, caller.id, "external-wire", IMPORTED_GETTER_SOURCE);
    imported_getter_trace(&state, true).await;
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    external_edit_initialize(&reopened).await;
    external_edit_assert_published(&reopened, caller.id, "external-wire", IMPORTED_GETTER_SOURCE);
    imported_getter_trace(&reopened, true).await;
}

#[tokio::test]
async fn imported_getter_local_module_gap_keeps_mcp_absence_unproven() {
    use kin_review::ImpactGraph;
    let (_dir, state) = mcp_lifecycle_fixture();
    source_tree_conversion_fixture(&state, json!({
        "verb":"create", "target":"packages/wire/src/index.js",
        "description":"admit local workspace module", "body":"function Channel() {}\nChannel.prototype.send = function(request) { return request; };\nmodule.exports = Channel;\n"
    })).await;
    source_tree_conversion_fixture(&state, json!({
        "verb":"create", "target":EXTERNAL_EDIT_FILE,
        "description":"admit getter whose module is local", "body":IMPORTED_GETTER_SOURCE.replace("external-wire", "wire")
    })).await;
    imported_getter_trace(&state, false).await;
    let target = state.graph.query_entities(&kin_model::EntityFilter {
        file_path: Some(kin_model::FilePathId::new("packages/wire/src/index.js")),
        ..Default::default()
    }).unwrap().into_iter().find(|entity| entity.name == "Channel.send").unwrap();
    let result = mcp_call(router(Arc::clone(&state)), "impact_analysis", json!({
        "entity_ids":[target.id.to_string()], "include_traffic":false
    })).await;
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    let payload = tool_result_payload(&result);
    println!("LOCAL_GETTER_IMPACT_OBSERVATION {}", json!({
        "parse_coverage_complete": kin_review::impact::LiveGraph(state.graph.as_ref()).call_shape_parse_coverage_complete().unwrap(),
        "payload":payload
    }));
    assert_eq!(payload["edge_coverage"]["classes"]["calls"], "unproduced");
    // The daemon serves the tool payload; the stdio MCP server applies this
    // production finalizer with daemon health to attach the canonical verdict.
    let health = router(Arc::clone(&state)).oneshot(Request::get("/health").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    let health: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(health.into_body(), 256 * 1024).await.unwrap()).unwrap();
    let finalized = kin_mcp::envelope::finalize(result, kin_mcp::Envelope::daemon().with_health(&health), "impact_analysis");
    let finalized = tool_result_payload(&finalized);
    println!("LOCAL_GETTER_IMPACT_FINALIZED {finalized}");
    assert_eq!(finalized["negative"]["safe_to_conclude_absent"], false, "the unbound local member does not prove no consumer: {finalized}");
}
