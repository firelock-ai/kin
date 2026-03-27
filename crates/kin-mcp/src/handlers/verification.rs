// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::graph::GraphStore;

use crate::error::{McpError, Result};
use crate::types::ToolCallResult;

use super::common::*;

pub fn handle_verify_entity<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;
    let runner_filter = args
        .get("runner")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut tests = store
        .get_tests_for_entity(&entity_id)
        .map_err(McpError::graph)?;
    if let Some(ref runner) = runner_filter {
        tests.retain(|t| t.runner.to_string().eq_ignore_ascii_case(runner));
    }

    let coverage = store.get_coverage_summary().map_err(McpError::graph)?;
    let entity_covered = !tests.is_empty();

    let result = serde_json::json!({
        "entity_id": id_str,
        "covered": entity_covered,
        "test_count": tests.len(),
        "tests": tests,
        "coverage_summary": {
            "total_entities": coverage.total_entities,
            "covered_entities": coverage.covered_entities,
            "coverage_ratio": coverage.coverage_ratio,
        }
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_coverage_summary<G: GraphStore>(store: &G) -> Result<ToolCallResult> {
    let coverage = store.get_coverage_summary().map_err(McpError::graph)?;

    let result = serde_json::json!({
        "total_entities": coverage.total_entities,
        "covered_entities": coverage.covered_entities,
        "coverage_ratio": coverage.coverage_ratio,
        "missing_proof_count": coverage.missing_proof.len(),
        "missing_proof": coverage.missing_proof,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_security_scan<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let propagate = get_optional_bool(args, "propagate", false);

    let dead = store.find_dead_code().map_err(McpError::graph)?;

    let findings: Vec<serde_json::Value> = dead
        .into_iter()
        .map(|entity| {
            let mut finding = serde_json::json!({
                "entity_id": entity.id,
                "name": entity.name,
                "kind": entity.kind,
                "file_path": entity.file_origin.as_ref().map(|p| p.to_string()),
                "finding_type": "dead_code",
                "severity": "low",
            });
            if propagate {
                if let Ok(impacted) = store.get_downstream_impact(&entity.id, 3) {
                    finding["downstream_impact_count"] = serde_json::json!(impacted.len());
                    finding["downstream_entities"] = serde_json::json!(impacted
                        .iter()
                        .map(|e| serde_json::json!({
                            "id": e.id,
                            "name": e.name,
                        }))
                        .collect::<Vec<_>>());
                }
            }
            finding
        })
        .collect();

    let result = serde_json::json!({
        "finding_count": findings.len(),
        "findings": findings,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_release_check<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let require_proof = get_optional_bool(args, "require_proof", false);
    let require_approval = get_optional_bool(args, "require_approval", false);

    let coverage = store.get_coverage_summary().map_err(McpError::graph)?;

    let mut pass = true;
    let mut blockers: Vec<String> = Vec::new();

    if require_proof && !coverage.missing_proof.is_empty() {
        pass = false;
        blockers.push(format!(
            "{} entities missing test proof",
            coverage.missing_proof.len()
        ));
    }

    if require_approval {
        // Check if there are any approvals at all by querying recent audit events
        let events = store.query_audit_events(None, 1).map_err(McpError::graph)?;
        if events.is_empty() {
            pass = false;
            blockers.push("no audit events found — approval status unknown".into());
        }
    }

    let result = serde_json::json!({
        "pass": pass,
        "blockers": blockers,
        "coverage": {
            "total_entities": coverage.total_entities,
            "covered_entities": coverage.covered_entities,
            "coverage_ratio": coverage.coverage_ratio,
            "missing_proof_count": coverage.missing_proof.len(),
        }
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_contract_check<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "contract_id")?;
    let uuid = uuid::Uuid::parse_str(&id_str)
        .map_err(|_| McpError::InvalidParams(format!("invalid contract_id: {}", id_str)))?;
    let contract_id = kin_model::ContractId(uuid);

    let tests = store
        .get_tests_covering_contract(&contract_id)
        .map_err(McpError::graph)?;

    let result = serde_json::json!({
        "contract_id": id_str,
        "covered": !tests.is_empty(),
        "test_count": tests.len(),
        "tests": tests,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}
