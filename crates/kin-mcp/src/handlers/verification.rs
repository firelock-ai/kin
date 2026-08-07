// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use super::repository_authority::RequestRepositoryAuthority;
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
Get repo-wide proof coverage at a glance: total entities, how many carry a passing \
verification run, the coverage ratio, and the list of entities still missing proof. \
Reach for it to assess recorded test health or find what's unproven. Verification runs \
are not yet bound to immutable source changes, so this advisory live view does not \
authorize a release. It's the whole-repo counterpart to kin_verify_entity (one entity) \
and underlies kin_release_check's proof requirement. \
Read `coverage_trust` BEFORE treating a low or zero number as a fact about the \
repository: this tool counts RECORDED VERIFICATION RUNS, never the repository's test \
files, so a graph with no runs reports zero coverage while the code may be thoroughly \
tested. `safe_to_conclude_uncovered` is false in exactly that case, which is the normal \
state of a freshly-initialised repo. `population` names what `total_entities` counts — \
the current-generation entity map, which is NOT the set retrieval ranks over, so it is \
the wrong denominator for a completeness claim about everything semantic_locate can \
return.";

pub fn handle_coverage_summary<G: GraphStore>(store: &G) -> Result<ToolCallResult> {
    let (coverage, provenance) = kin_review::passing_proof_coverage_with_provenance(store)
        .map_err(|error| McpError::Review(error.to_string()))?;
    let (safe_to_conclude_uncovered, reason) = provenance.coverage_trust();

    let result = serde_json::json!({
        "total_entities": coverage.total_entities,
        "covered_entities": coverage.covered_entities,
        "coverage_ratio": coverage.coverage_ratio,
        "missing_proof_count": coverage.missing_proof.len(),
        "missing_proof": coverage.missing_proof,
        // What the coverage number was derived from. A zero with
        // runs_observed == 0 counted nothing; it is not a finding about the
        // repository, and the sibling retrieval tools already set this bar with
        // their `negative.safe_to_conclude_absent` contract.
        "coverage_trust": {
            "safe_to_conclude_uncovered": safe_to_conclude_uncovered,
            "reason": reason,
            "trust": if safe_to_conclude_uncovered { "recorded" } else { "inconclusive" },
            "runs_observed": provenance.runs_observed,
            "entities_with_any_run": provenance.entities_with_any_run,
            "counts": "recorded verification runs, never the repository's test files",
        },
        // What the denominator is. total_entities is the live current-generation
        // entity map; retrieval ranks over the vector index, a separate
        // structure that can retain entities this map no longer holds.
        "population": {
            "total_entities_counts": "current_generation_entities",
            "note": "total_entities is the graph's live entity map. Retrieval (semantic_locate) ranks over the vector index, which is a separate structure and may contain entities absent from this map, so this is not the denominator for 'everything locate can return'.",
        },
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
Run a graph-only pre-release advisory against one named branch and immutable source change. \
force overrides only the baseline coverage threshold; require_proof fails closed for every \
non-empty source because verification runs do not yet carry immutable source authority; \
require_approval requires human approval for every reachable non-root change. The result \
binds its source, rechecks the branch-head/source match before returning, and checks exact \
graph history, source-tree completeness, and the optional expected entity count. It is not \
daemon admission: object availability and the final mutation CAS are enforced only by \
`kin release`.";

fn release_optional_bool(
    args: &HashMap<String, serde_json::Value>,
    key: &str,
    default: bool,
) -> Result<bool> {
    match args.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| McpError::InvalidParams(format!("{key} must be a boolean"))),
    }
}

fn release_optional_string(
    args: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<Option<String>> {
    match args.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_string()))
            .ok_or_else(|| McpError::InvalidParams(format!("{key} must be a string"))),
    }
}

fn release_optional_entity_count(
    args: &HashMap<String, serde_json::Value>,
) -> Result<Option<usize>> {
    match args.get("expected_entity_count") {
        None => Ok(None),
        Some(value) => {
            let count = value.as_u64().ok_or_else(|| {
                McpError::InvalidParams(
                    "expected_entity_count must be a non-negative integer".to_string(),
                )
            })?;
            usize::try_from(count)
                .map(Some)
                .map_err(|_| McpError::InvalidParams("expected_entity_count exceeds usize".into()))
        }
    }
}

pub fn handle_release_check<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    let require_proof = release_optional_bool(args, "require_proof", false)?;
    let require_approval = release_optional_bool(args, "require_approval", false)?;
    let force = release_optional_bool(args, "force", false)?;
    let requested_branch = release_optional_string(args, "branch")?;
    let requested_source = release_optional_string(args, "source_change_id")?
        .map(|value| parse_change_id(&value))
        .transpose()?;
    let expected_entity_count = release_optional_entity_count(args)?;

    let repository_authority = repository_authority.ok_or_else(|| {
        McpError::Context(
            "graph authority gap: release checks require a startup-pinned local repository \
             authority binding"
                .to_string(),
        )
    })?;
    // Both opens on this path load from storage rather than reading through an
    // authority a server already holds. The pair exists to compare the branch
    // head before the source checks against the head after them, and two reads
    // of one shared open are the same read: it describes the publication its
    // owner sampled, so a move that landed since could not appear in either.
    let authority = repository_authority.open_fresh()?;
    let mut branches = authority
        .repository_refs()
        .into_iter()
        .filter(|repository_ref| repository_ref.name.is_branch())
        .collect::<Vec<_>>();
    branches.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    let branch = if let Some(name) = requested_branch {
        let name = super::repository_authority::parse_branch_ref(&name)?;
        authority
            .repository_ref(&name)
            .ok_or_else(|| McpError::InvalidParams(format!("branch not found: {name}")))?
    } else if let Some(default_ref) = authority.default_ref() {
        branches
            .iter()
            .find(|branch| branch.name == default_ref)
            .cloned()
            .or_else(|| {
                branches
                    .iter()
                    .find(|branch| branch.name.as_bytes() == b"refs/heads/main")
                    .cloned()
            })
            .or_else(|| match branches.as_slice() {
                [only] => Some(only.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                McpError::InvalidParams(
                    "kin_release_check requires branch when the default ref is unborn and \
                     repository authority has zero or multiple branches"
                        .to_string(),
                )
            })?
    } else if let Some(main) = branches
        .iter()
        .find(|branch| branch.name.as_bytes() == b"refs/heads/main")
    {
        main.clone()
    } else if let [only] = branches.as_slice() {
        only.clone()
    } else {
        return Err(McpError::InvalidParams(
            "kin_release_check requires branch when repository authority has zero or multiple \
             branches"
                .to_string(),
        ));
    };
    let branch_head = authority.resolve_target(&branch.target)?;
    let source_head = requested_source.unwrap_or(branch_head);
    store
        .get_change(&source_head)
        .map_err(McpError::graph)?
        .ok_or_else(|| {
            McpError::Review(format!(
                "release source change {source_head} is not materialized"
            ))
        })?;
    let source_state = store
        .resolve_graph_at(&source_head)
        .map_err(|error| McpError::Review(error.to_string()))?;
    let coverage = kin_review::source_bound_release_proof_coverage_for_entities(
        source_state.entities.values(),
    );

    let mut blockers: Vec<String> = Vec::new();

    if let Some(expected) = expected_entity_count {
        if expected != source_state.entities.len() {
            blockers.push(format!(
                "expected entity count {expected} does not match immutable source count {}",
                source_state.entities.len()
            ));
        }
    }

    store
        .resolve_tree_at(&source_head)
        .map_err(McpError::graph)?;

    if coverage.coverage_ratio < 0.5 && !force {
        blockers.push(format!(
            "immutable source-bound proof coverage {:.1}% is below 50%",
            coverage.coverage_ratio * 100.0
        ));
    }

    if require_proof && !coverage.missing_proof.is_empty() {
        blockers.push(format!(
            "{} entities missing immutable source-bound test proof",
            coverage.missing_proof.len()
        ));
    }

    if require_approval {
        let mut unapproved = kin_review::unapproved_changes(store, &source_head, usize::MAX)
            .map_err(|error| McpError::Review(error.to_string()))?;
        unapproved.sort_by(|a, b| a.change_id.to_string().cmp(&b.change_id.to_string()));
        if !unapproved.is_empty() {
            let detail = unapproved
                .iter()
                .map(|c| format!("{} ({})", c.change_id, c.author))
                .collect::<Vec<_>>()
                .join(", ");
            blockers.push(format!(
                "{} non-root change(s) lack human approval: {}",
                unapproved.len(),
                detail
            ));
        }
    }

    // This tool is advisory and cannot hold the daemon's mutation gate, but it
    // must at least detect a branch move that happened while the source checks
    // above were running. Publication still performs the authoritative CAS.
    let final_authority = repository_authority.open_fresh()?;
    let final_branch = final_authority.repository_ref(&branch.name);
    let final_branch_head = final_branch
        .as_ref()
        .map(|repository_ref| final_authority.resolve_target(&repository_ref.target))
        .transpose()?;
    match final_branch_head {
        Some(head) if head == source_head => {}
        Some(head) => blockers.push(format!(
            "branch {} moved: expected source {}, current head {}",
            branch.name, source_head, head
        )),
        None => blockers.push(format!(
            "branch {} disappeared while checking source {}",
            branch.name, source_head
        )),
    }

    let result = serde_json::json!({
        "pass": blockers.is_empty(),
        "blockers": blockers,
        "branch": branch.name.to_string(),
        "branch_ref": branch.name,
        "branch_head": final_branch_head.map(|head| head.to_string()),
        "source_change_id": source_head.to_string(),
        "source_entity_count": source_state.entities.len(),
        "coverage": {
            "total_entities": coverage.total_entities,
            "covered_entities": coverage.covered_entities,
            "coverage_ratio": coverage.coverage_ratio,
            "missing_proof_count": coverage.missing_proof.len(),
        },
        "authority": "repository_v6_advisory",
        "daemon_admission_required": true,
        "proof_authority": if source_state.entities.is_empty() {
            "empty_source_vacuous"
        } else {
            "strict_source_bound_proof_unavailable"
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

#[cfg(test)]
mod tests {
    use super::super::tests::{release_check_result, EmptyStore};
    use super::*;

    #[test]
    fn release_check_fails_closed_for_unborn_repository_authority() {
        let store = EmptyStore::default();
        let args = HashMap::from([("require_approval".to_string(), serde_json::json!(true))]);

        let error = release_check_result(&store, &args)
            .expect_err("MCP release gate must not pass an unborn repository authority");

        assert!(matches!(error, McpError::InvalidParams(_)));
        assert!(error.to_string().contains("requires branch"));
    }

    #[test]
    fn release_check_rejects_present_parameters_with_wrong_json_types() {
        let store = kin_db::InMemoryGraph::new();
        let cases = [
            ("branch", serde_json::json!(false)),
            ("source_change_id", serde_json::json!([])),
            ("expected_entity_count", serde_json::json!("1")),
            ("force", serde_json::json!("false")),
            ("require_proof", serde_json::json!(1)),
            ("require_approval", serde_json::Value::Null),
        ];

        for (key, value) in cases {
            let args = HashMap::from([(key.to_string(), value)]);
            let error = handle_release_check(&args, &store, None)
                .expect_err("present release parameters must not silently default on bad types");
            assert!(matches!(error, McpError::InvalidParams(_)));
            assert!(
                error.to_string().contains(key),
                "wrong-type error must name {key}: {error}"
            );
        }
    }
}
