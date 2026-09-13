// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[tokio::test]
async fn durable_entity_draft_capabilities_expose_platform_refusal_before_save() {
    let (_dir, state, _source) = source_base_fixture().await;
    let root = state.layout.root().join("entity-drafts-v1");
    let auth = "draft-platform-fixture";
    let app = router_with_auth(Arc::clone(&state), Some(auth.into()));
    let mut operations = vec![("kin_draft_capabilities", serde_json::json!({}))];
    if !cfg!(unix) {
        operations.extend([
            ("kin_draft_create", serde_json::json!({})),
            ("kin_draft_save", serde_json::json!({})),
        ]);
    }
    for (name, arguments) in operations {
        let response = app
            .clone()
            .oneshot(
                Request::post("/mcp/tools/call")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {auth}"))
                    .body(Body::from(
                        serde_json::json!({"name":name,"arguments":arguments}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let result: kin_mcp::ToolCallResult = serde_json::from_slice(&bytes).unwrap();
        let payload = tool_result_payload(&result);
        if name == "kin_draft_capabilities" {
            assert_ne!(result.is_error, Some(true));
            assert_eq!(payload["schema"], "kin.entity.draft.capabilities.v1");
            assert_eq!(payload["durable_save_supported"], cfg!(unix));
            assert_eq!(payload["apply_supported"], cfg!(unix));
            assert_eq!(payload["limits"]["revisions"], 65_536);
            if !cfg!(unix) {
                assert_eq!(payload["refusal"]["code"], "draft_durability_unsupported");
            }
        } else {
            assert_eq!(result.is_error, Some(true));
            assert_eq!(payload["code"], "draft_durability_unsupported");
        }
        assert!(
            !root.exists(),
            "capability probe or unsupported Save created editing state"
        );
    }
}
