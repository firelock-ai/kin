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
Run a graph-based security/quality scan and return severity-tagged findings. It surfaces \
untested API endpoints, orphaned public surface area, high-fan-out blast radius, dead \
event contracts, and encapsulation leaks (public entities calling private internals); \
set propagate=true to also emit transitive-dependency findings for everything downstream \
of a flagged entity. This mirrors the `kin security` CLI scan. Reach for it as a hygiene \
pass over the semantic graph before relying on or releasing code. For plain dead-code \
enumeration, dead_code is more direct.";

pub fn handle_security_scan<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let propagate = get_optional_bool(args, "propagate", false);

    let findings = kin_review::security_findings(store, propagate)
        .map_err(|e| McpError::Review(e.to_string()))?;
    let counts = kin_review::SecurityFindingCounts::of(&findings);

    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "entity_id": finding.entity_id,
                "name": finding.entity_name,
                "finding_type": finding.category,
                "severity": finding.severity.to_string().to_lowercase(),
                "message": finding.message,
            })
        })
        .collect();

    let result = serde_json::json!({
        "finding_count": findings_json.len(),
        "severity_counts": {
            "high": counts.high,
            "medium": counts.medium,
            "low": counts.low,
            "info": counts.info,
        },
        "findings": findings_json,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const RELEASE_CHECK_DESC: &str = "\
Run a pre-release gate and get a pass/fail verdict with the specific blockers. Toggle \
the policy you want enforced: require_proof fails when entities are missing test proof; \
require_approval fails when any agent-authored change in recent history lacks a recorded \
approval (the same gate as `kin release --require-approval`). Returns whether the release \
would pass plus a list of what's blocking it and the current coverage figures. Reach for \
it as the final go/no-go check before cutting a release, consolidating coverage and \
approval gates into one answer.";

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
        // Match `kin release --require-approval`: walk change history from each
        // branch head and block on any agent-authored change that lacks a
        // recorded `Approved` approval. The store has no working-tree HEAD file,
        // so heads are resolved from the branch graph (graph truth). A branch is
        // walked over its first-parent linear history.
        let branches = store.list_branches().map_err(McpError::graph)?;
        let mut seen: std::collections::HashSet<kin_model::SemanticChangeId> =
            std::collections::HashSet::new();
        let mut unapproved: Vec<kin_review::UnapprovedAgentChange> = Vec::new();
        for branch in &branches {
            for change in kin_review::unapproved_agent_changes(store, &branch.head, 50)
                .map_err(|e| McpError::Review(e.to_string()))?
            {
                if seen.insert(change.change_id) {
                    unapproved.push(change);
                }
            }
        }
        // Total-order the blockers by change id so the emitted list is byte-stable
        // across identical-state runs regardless of branch iteration order — agents
        // diffing gate output must not see phantom reorderings.
        unapproved.sort_by(|a, b| a.change_id.to_string().cmp(&b.change_id.to_string()));
        if !unapproved.is_empty() {
            pass = false;
            let detail = unapproved
                .iter()
                .map(|c| format!("{} ({})", c.change_id, c.author))
                .collect::<Vec<_>>()
                .join(", ");
            blockers.push(format!(
                "{} unapproved agent change(s): {}",
                unapproved.len(),
                detail
            ));
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
