// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Included into `api.rs`'s test module, beside the source-base tests whose
// commit helper it reuses.

const NAME_CANDIDATES_SOURCE: &str = "class Scaffold:\n    def get(self, rule):\n        return rule\n\n    def route(self, rule):\n        return rule\n\n\nclass Globals:\n    def get(self, name):\n        return name\n\n\ndef get_db():\n    return {}\n";

#[tokio::test]
async fn daemon_trace_ambiguity_public_route_fits_8000_bytes() {
    let (_dir, state) = mcp_lifecycle_fixture();
    let mut source =
        "def finish():\n    return 1\n\ndef start():\n    return finish()\n\n".to_string();
    for n in 0..200 {
        source.push_str(&format!(
            "class Owner{n:03}:\n    def get(self):\n        return {n}\n\n"
        ));
    }
    source_tree_conversion_fixture(&state, serde_json::json!({
        "verb":"create","target":"src/owners.py","body":source,"description":"trace ambiguity budget fixture",
    })).await;
    for focal in [true, false] {
        let mut args = serde_json::json!({"focal":if focal {"get"} else {"start"},"include_body":false,"max_response_chars":8000});
        if !focal {
            args["target"] = serde_json::json!("get");
        }
        let result = mcp_call(router(Arc::clone(&state)), "trace_data_flow", args).await;
        assert_ne!(result.is_error, Some(true), "{result:?}");
        let kin_mcp::ContentBlock::Text { text } = &result.content[0];
        assert!(text.len() <= 8000, "{} bytes", text.len());
        let value = tool_result_payload(&result);
        let listing = if focal {
            &value
        } else {
            &value["target_ambiguity"]
        };
        assert_eq!(listing["candidate_count"], 200, "{listing}");
        assert_eq!(listing["resolution"], "shared_member_name");
        let count = listing["candidates"].as_array().map_or(0, Vec::len)
            + listing["more_candidates"].as_array().map_or(0, Vec::len)
            + listing["omitted_candidates"].as_u64().unwrap_or(0) as usize;
        assert_eq!(count, 200);
        if focal {
            assert_eq!(value["ambiguous_focal"], true);
            for key in [
                "body",
                "source_base",
                "chain",
                "focal_entity",
                "bodies_included",
            ] {
                assert!(value.get(key).is_none(), "unexpected {key}: {value}");
            }
        } else {
            assert!(!value["chain"].as_array().unwrap().is_empty(), "{value}");
            assert!(value.get("target_name").is_none() || value["target_name"].is_null());
        }
    }
}

async fn name_candidates_fixture() -> (tempfile::TempDir, Arc<DaemonState>) {
    let (dir, state) = mcp_lifecycle_fixture();
    source_tree_conversion_fixture(
        &state,
        serde_json::json!({
            "verb": "create",
            "target": "src/app.py",
            "body": NAME_CANDIDATES_SOURCE,
            "description": "name candidates fixture",
        }),
    )
    .await;
    (dir, state)
}

async fn name_candidates_call(
    state: &Arc<DaemonState>,
    tool: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    tool_result_payload(&mcp_call(router(Arc::clone(state)), tool, arguments).await)
}

fn name_candidate_names(payload: &serde_json::Value) -> Vec<String> {
    let mut names: Vec<String> = payload["candidates"]
        .as_array()
        .unwrap_or_else(|| panic!("no candidates: {payload}"))
        .iter()
        .map(|row| row["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

/// Every name-accepting route of the daemon answers a name by the rule every
/// surface shares: a member name two owners share lists both and reads no
/// body, a partial name lists its candidates and reads no body, a lone member
/// and an exact name read their own body, the batch row names candidates
/// instead of claiming absence, the walks and the pack answer with the
/// candidates, and `find_references` sections the two owners.
#[tokio::test]
async fn daemon_routes_answer_a_name_the_way_every_surface_does() {
    let (_dir, state) = name_candidates_fixture().await;

    let shared = name_candidates_call(
        &state,
        "get_entity_source",
        serde_json::json!({ "entity_id": "get" }),
    )
    .await;
    assert_eq!(shared["ambiguous_focal"], true, "{shared}");
    assert_eq!(shared["resolution"], "shared_member_name", "{shared}");
    assert_eq!(
        name_candidate_names(&shared),
        vec!["Globals.get", "Scaffold.get"]
    );
    assert!(
        shared.get("body").is_none() && shared.get("source_base").is_none(),
        "{shared}"
    );

    let partial = name_candidates_call(
        &state,
        "get_entity_source",
        serde_json::json!({ "entity_id": "get_d" }),
    )
    .await;
    assert_eq!(partial["resolution"], "partial_name", "{partial}");
    assert!(
        name_candidate_names(&partial).contains(&"get_db".to_string()),
        "{partial}"
    );
    assert!(
        partial.get("body").is_none() && partial.get("source_base").is_none(),
        "a partial name must never hand back a body or an edit base: {partial}"
    );

    let lone = name_candidates_call(
        &state,
        "get_entity_source",
        serde_json::json!({ "entity_id": "route" }),
    )
    .await;
    assert_eq!(lone["name"], "Scaffold.route", "{lone}");
    assert!(
        lone["body"]
            .as_str()
            .unwrap_or_default()
            .contains("def route"),
        "{lone}"
    );

    let exact = name_candidates_call(
        &state,
        "get_entity_source",
        serde_json::json!({ "entity_id": "get_db" }),
    )
    .await;
    assert_eq!(exact["name"], "get_db", "{exact}");

    let batch = name_candidates_call(
        &state,
        "get_entity_sources",
        serde_json::json!({ "entity_ids": ["get", "get_db"] }),
    )
    .await;
    assert_eq!(batch["results"][0]["reason"], "ambiguous_name", "{batch}");
    assert_eq!(batch["results"][0]["candidate_count"], 2, "{batch}");
    assert!(batch["results"][1]["body"].is_string(), "{batch}");

    let flow = name_candidates_call(
        &state,
        "trace_data_flow",
        serde_json::json!({ "focal": "get", "include_body": false }),
    )
    .await;
    assert_eq!(flow["ambiguous_focal"], true, "{flow}");
    assert_eq!(
        name_candidate_names(&flow),
        vec!["Globals.get", "Scaffold.get"]
    );

    let pack = name_candidates_call(
        &state,
        "get_context_pack",
        serde_json::json!({ "entities": ["get"] }),
    )
    .await;
    assert_eq!(pack["ambiguous_focal"], true, "{pack}");

    let path = name_candidates_call(
        &state,
        "trace_path",
        serde_json::json!({ "from": "get", "to": "get_db" }),
    )
    .await;
    assert_eq!(path["ambiguous_focal"], true, "{path}");
    assert_eq!(path["end"], "from", "{path}");
    assert_eq!(
        name_candidate_names(&path),
        vec!["Globals.get", "Scaffold.get"]
    );

    let references = name_candidates_call(
        &state,
        "find_references",
        serde_json::json!({ "query": "get" }),
    )
    .await;
    assert_eq!(
        references["candidates_by_owner"].as_array().map(Vec::len),
        Some(2),
        "{references}"
    );
}
