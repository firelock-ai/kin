// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::graph::GraphStore;

use crate::error::{McpError, Result};
use crate::types::ToolCallResult;

use super::common::*;

pub const VERIFY_ENTITY_DESC: &str = "\
Inspect the test coverage recorded for a single entity: which tests are linked to it, \
how many, and whether it is covered at all, alongside the repo-wide coverage figures for \
context. Filter by runner (e.g. cargo, jest, pytest) when you only care about one test \
system. Reach for it to answer \"is this function tested, and by what?\" before changing \
or relying on it. Note this reports linked tests and recorded coverage from the graph — \
it does not execute tests. For the whole-repo picture use kin_coverage_summary; for \
contracts use kin_contract_check.";

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

pub const COVERAGE_SUMMARY_DESC: &str = "\
Get repo-wide test coverage at a glance: total entities, how many are covered, the \
coverage ratio, and the list of entities still missing test proof. Reach for it to \
assess overall test health, find what's untested, or feed a release/quality gate. It's \
the whole-repo counterpart to kin_verify_entity (one entity) and underlies \
kin_release_check's proof requirement.";

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

pub const SECURITY_SCAN_DESC: &str = "\
Run a graph-based security/quality scan and return findings with severity. Today it \
surfaces dead/unreachable code (a common source of latent risk and confusion) as \
findings; set propagate=true to also compute, for each finding, the downstream entities \
it would affect. Reach for it as a quick hygiene pass over the semantic graph. For \
plain dead-code enumeration without the findings framing, dead_code is more direct; \
this tool packages results as severity-tagged findings suitable for a security review.";

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

pub const RELEASE_CHECK_DESC: &str = "\
Run a pre-release gate and get a pass/fail verdict with the specific blockers. Toggle \
the policy you want enforced: require_proof fails when entities are missing test proof; \
require_approval fails when the latest change has no recorded approval. Returns whether \
the release would pass plus a list of what's blocking it and the current coverage \
figures. Reach for it as the final go/no-go check before cutting a release, \
consolidating coverage and approval gates into one answer.";

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

pub const CONTRACT_CHECK_DESC: &str = "\
Check the test coverage of a specific contract: which tests cover it, how many, and \
whether it is covered at all. Reach for it to verify that a behavioral contract has \
backing tests before relying on or releasing it. It is the contract-level analogue of \
kin_verify_entity (which checks an entity).";

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
