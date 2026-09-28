// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;

fn selected_observation() -> Value {
    json!({
        "schema":"kin.enrichment-status.v1",
        "snapshot_id":"a".repeat(64),
        "truth_epoch":17,
        "scope":{"kind":"workspace_head"},
        "current":true,
        "proof_scope":"recorded_call_site_census",
        "all_relationships_attested":false,
        "requested_dependencies":[],
        "files":[],
    })
}

fn bounded_observation(kind: &str, limit: u64) -> Value {
    let mut value = selected_observation();
    let reason = format!("enrichment metadata exceeds the deterministic {kind} limit ({limit})");
    value["status"] = json!("bounded");
    value["limitation"] = json!(format!("enrichment_metadata_unavailable: {reason}"));
    value["unavailable"] = json!({"reason":reason,"limit_kind":kind,"limit":limit});
    value
}

fn response(observation: Value) -> Value {
    json!({
        "entity_count":7213,
        "enrichment":observation,
        "_kin":{
            "verdict":{"state":"inconclusive","safe_to_conclude_absent":false},
            "negative":{"safe_to_conclude_absent":false},
            "repository":{"id":"selected-repository","root":"/selected/repository"},
        },
    })
}

fn text(result: &ToolCallResult) -> &str {
    let ContentBlock::Text { text } = &result.content[0];
    text
}

fn transactions(count: usize) -> crate::session::OpenTransactionObservation {
    let created = kin_model::Timestamp::now();
    crate::session::OpenTransactionObservation {
        observed_at: created.clone(),
        items: (0..count)
            .map(|index| crate::session::OpenStagedTransaction {
                transaction_id: format!("transaction-{index:03}"),
                session_id: "owner".into(),
                scope: "selected-entity-λ".repeat(15),
                state: "active".into(),
                staged_count: 1,
                staged_digest: format!("{index:064x}"),
                created_at: Some(created.clone()),
                age_seconds: Some(0),
            })
            .collect(),
    }
}

#[test]
fn unavailable_inventory_survives_transaction_pages_without_claiming_file_coverage() {
    let full = response(bounded_observation("bytes", 8_388_608));
    let observation = transactions(30);
    let expected_transactions = serde_json::to_value(&observation.items).unwrap();
    let mut request = StatusRequest {
        dependencies: vec!["src/not-observed.py".into()],
        max_chars: Some(12_000),
        ..Default::default()
    };
    let mut expected_enrichment = full["enrichment"].clone();
    expected_enrichment["requested_dependencies"] = json!(request.paths().unwrap());
    let mut reconstructed = Vec::new();
    let mut pages = 0;
    loop {
        let with_transactions = with_open_transactions(
            ToolCallResult::text(full.to_string()),
            &observation,
            &json!({"daemon":"selected-instance"}),
        )
        .unwrap();
        let paged = page(with_transactions, &request, &[3; 32]).unwrap();
        let result = enforce_ceiling(paged, request.ceiling());
        assert_ne!(result.is_error, Some(true));
        assert!(text(&result).len() <= request.ceiling());
        let value: Value = serde_json::from_str(text(&result)).unwrap();
        assert_eq!(value["entity_count"], full["entity_count"]);
        assert_eq!(value["_kin"], full["_kin"]);
        assert_eq!(value["enrichment"], expected_enrichment);
        assert!(value["enrichment"].get("page").is_none());
        validate_observation(
            &value["enrichment"],
            true,
            crate::handlers::entities::GraphStatusScope::Head,
        )
        .unwrap();
        validate_collections(
            value.get("enrichment"),
            value.get("open_transactions"),
            value.get("status_page"),
        )
        .unwrap();
        assert_eq!(value["status_page"]["total"], 30);
        assert_eq!(value["status_page"]["start"], json!(reconstructed.len()));
        let rows = value["open_transactions"]["items"].as_array().unwrap();
        assert!(
            !rows.is_empty(),
            "a continuation must advance transaction rows"
        );
        reconstructed.extend(rows.iter().cloned());
        request.cursor = value["status_page"]["next_cursor"]
            .as_str()
            .map(str::to_owned);
        pages += 1;
        assert!(pages <= observation.items.len());
        if request.cursor.is_none() {
            break;
        }
    }
    assert!(pages > 1);
    assert_eq!(json!(reconstructed), expected_transactions);
}

#[test]
fn unavailable_inventory_discloses_requested_dependencies_without_inventing_missing_rows() {
    for (kind, limit) in [
        ("bytes", 8_388_608),
        ("path_bytes", 8_388_608),
        ("records", 1_000_000),
    ] {
        for current in [true, false] {
            let mut full = response(bounded_observation(kind, limit));
            full["enrichment"]["current"] = json!(current);
            if !current {
                full["stale"] = json!({"reason":"selected_graph_changing"});
            }
            let mut request = StatusRequest {
                dependencies: vec!["src/not-observed.py".into()],
                max_chars: Some(12_000),
                ..Default::default()
            };
            let result = page(ToolCallResult::text(full.to_string()), &request, &[7; 32]).unwrap();
            let result = enforce_ceiling(result, request.ceiling());
            assert_ne!(result.is_error, Some(true));
            let value: Value = serde_json::from_str(text(&result)).unwrap();
            let mut expected = full["enrichment"].clone();
            expected["requested_dependencies"] = json!(request.paths().unwrap());
            assert_eq!(value["enrichment"], expected);
            assert_eq!(value["_kin"], full["_kin"]);
            assert!(value["enrichment"].get("page").is_none());
            validate_observation(
                &value["enrichment"],
                current,
                crate::handlers::entities::GraphStatusScope::Head,
            )
            .unwrap();
            request.cursor = Some("cannot-resume-an-unavailable-inventory".into());
            assert!(page(ToolCallResult::text(full.to_string()), &request, &[7; 32]).is_err());
        }
    }
}

#[test]
fn unavailable_inventory_rejects_malformed_limits_or_inventory_completion_claims() {
    let valid = bounded_observation("bytes", 8_388_608);
    for (pointer, replacement) in [
        ("/unavailable/limit", json!(0)),
        ("/unavailable/limit", json!(1_000_000)),
        ("/unavailable/limit", json!("8388608")),
        ("/unavailable/limit_kind", json!("unknown")),
        ("/unavailable/reason", json!("")),
        ("/status", json!("complete")),
        ("/limitation", json!("")),
        ("/files", json!([{"projection_path":"src/unobserved.py"}])),
    ] {
        let mut invalid = valid.clone();
        *invalid.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            validate_observation(
                &invalid,
                true,
                crate::handlers::entities::GraphStatusScope::Head,
            )
            .is_err(),
            "accepted malformed observation: {invalid}"
        );
    }
    for claimed_page in [
        Value::Null,
        json!({"start":0,"returned":0,"total":0,"complete":true,"next_cursor":null}),
    ] {
        let mut invalid = valid.clone();
        invalid["page"] = claimed_page;
        assert!(validate_observation(
            &invalid,
            true,
            crate::handlers::entities::GraphStatusScope::Head,
        )
        .is_err());
    }
}

#[test]
fn available_inventory_keeps_its_existing_page_contract() {
    let full = response(selected_observation());
    validate_observation(
        &full["enrichment"],
        true,
        crate::handlers::entities::GraphStatusScope::Head,
    )
    .unwrap();
    let result = page(
        ToolCallResult::text(full.to_string()),
        &StatusRequest::default(),
        &[1; 32],
    )
    .unwrap();
    let value: Value = serde_json::from_str(text(&result)).unwrap();
    assert!(value["enrichment"].get("unavailable").is_none());
    assert_eq!(value["enrichment"]["page"]["complete"], true);
    assert_eq!(value["enrichment"]["page"]["total"], 0);
    validate_observation(
        &value["enrichment"],
        true,
        crate::handlers::entities::GraphStatusScope::Head,
    )
    .unwrap();
    let request = StatusRequest {
        dependencies: vec!["src/not-observed.py".into()],
        ..Default::default()
    };
    assert!(page(ToolCallResult::text(full.to_string()), &request, &[1; 32]).is_err());
}
