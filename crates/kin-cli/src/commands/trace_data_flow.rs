// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin trace-data-flow` — return the actual call/data-flow chain rooted at a
//! focal entity in a single substrate call.
//!
//! Fix #3 in the per-family accuracy plan. The v4 `trace_computation` primitive
//! aliases `get_context_pack` and returns a flat snippet pack — not a chain.
//! When the LLM has to "trace computation step by step" it falls back to
//! calling `get_entity_source` per step, which hits the 24-round tool-call cap
//! on large repos.
//!
//! This primitive walks the relation graph from the focal entity in the
//! requested direction (callees, callers, or both), recursing to a bounded
//! depth and capping per-step branching, and inlines each step's body so the
//! model can read the chain without further tool calls.

use anyhow::{Context, Result};
use kin_model::{Entity, EntityId, EntityStore, GraphNodeId, RelationKind};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::commands::graph::{build_graph_source_response, GraphSourceRecord};

const DEFAULT_DEPTH: usize = 3;
const MAX_DEPTH: usize = 8;
const DEFAULT_LIMIT_PER_STEP: usize = 5;
const MAX_LIMIT_PER_STEP: usize = 25;
const MAX_TOTAL_STEPS: usize = 200;

/// Direction of traversal from the focal entity.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TraceDirection {
    /// Walk outgoing edges (the focal calls / imports / references these).
    Calls,
    /// Walk incoming edges (these call / import / reference the focal).
    Callers,
    /// Walk both directions and merge into a single chain.
    #[default]
    Both,
}

impl TraceDirection {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_lowercase().as_str() {
            "calls" | "callee" | "callees" | "out" | "outgoing" => Ok(TraceDirection::Calls),
            "callers" | "caller" | "in" | "incoming" => Ok(TraceDirection::Callers),
            "both" | "all" => Ok(TraceDirection::Both),
            other => anyhow::bail!(
                "invalid direction '{}': expected calls, callers, or both",
                other
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TraceDirection::Calls => "calls",
            TraceDirection::Callers => "callers",
            TraceDirection::Both => "both",
        }
    }
}

/// Request shape for the trace-data-flow primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataFlowRequest {
    /// Focal entity to start tracing from. Accepts an entity UUID or an exact
    /// entity name (resolved via the same ranking path as `graph source`).
    pub focal: String,
    /// Maximum traversal depth from the focal (default 3, capped at 8).
    #[serde(default)]
    pub depth: Option<usize>,
    /// Direction of traversal (default `both`).
    #[serde(default)]
    pub direction: Option<TraceDirection>,
    /// Maximum number of relations expanded per step (default 5, capped at 25).
    #[serde(default)]
    pub limit_per_step: Option<usize>,
}

/// One step in the data-flow chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStep {
    /// 1-based step index (0 is reserved for the focal entity).
    pub step: usize,
    /// `caller` when this step reached focal via an incoming edge, `callee`
    /// when via an outgoing edge.
    pub role: String,
    /// Relation kind that linked this step to its parent (e.g., `Calls`,
    /// `Imports`, `References`).
    pub relation_kind: String,
    /// Step index of the parent that introduced this step into the chain.
    /// `0` means "directly attached to the focal entity".
    pub parent_step: usize,
    /// Depth from the focal (1 = direct neighbor of focal, 2 = neighbor of
    /// neighbor, etc.).
    pub depth: usize,
    /// Source record for this entity, including the inlined body. Optional
    /// because some entities (external symbols, headers without spans) may
    /// not be readable from the graph.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity: Option<GraphSourceRecord>,
    /// Fallback fields for entities without a readable body. Always present
    /// so the consumer can render even when `entity` is None.
    pub entity_id: String,
    pub entity_name: String,
    pub entity_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_file: Option<String>,
}

/// Response from the trace-data-flow primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataFlowResponse {
    /// Focal entity. When the entity has a readable body, the record is
    /// populated; otherwise the fallback identity fields below are used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focal: Option<GraphSourceRecord>,
    pub focal_id: String,
    pub focal_name: String,
    pub focal_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focal_file: Option<String>,
    /// Direction that was traversed.
    pub direction: String,
    /// Depth that was traversed.
    pub depth: usize,
    /// The ordered chain of steps reached from the focal. Already deduplicated
    /// (each entity appears at most once).
    pub chain: Vec<TraceStep>,
    /// Total number of steps in the chain (excludes the focal).
    pub total_steps: usize,
    /// True when the traversal was cut off because per-step or total caps
    /// were hit. Lets callers detect when they need to widen the limit.
    pub truncated: bool,
}

/// CLI entry: `kin trace-data-flow --focal <e> [--depth N] [--direction D]
/// [--limit-per-step M]`.
pub async fn run_seeded(
    focal: String,
    depth: Option<usize>,
    direction: Option<String>,
    limit_per_step: Option<usize>,
) -> Result<()> {
    let direction = match direction {
        Some(value) => Some(TraceDirection::parse(&value)?),
        None => None,
    };
    let request = TraceDataFlowRequest {
        focal,
        depth,
        direction,
        limit_per_step,
    };
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_trace_data_flow(&layout, &request).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn run_daemon_trace_data_flow(
    layout: &kin_core::KinLayout,
    request: &TraceDataFlowRequest,
) -> Result<TraceDataFlowResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!(
            "Kin daemon is required for trace-data-flow but no daemon endpoint is available"
        )
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .trace_data_flow(request)
        .await
        .context("daemon trace-data-flow command failed")
}

/// Build a trace-data-flow response from the live graph.
///
/// This is the single substrate primitive used by both the CLI route and the
/// MCP tool dispatcher so the chain construction stays in one place.
pub fn build_trace_data_flow_response(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &kin_db::InMemoryGraph,
    request: &TraceDataFlowRequest,
) -> Result<TraceDataFlowResponse> {
    let trimmed = request.focal.trim();
    if trimmed.is_empty() {
        anyhow::bail!("trace_data_flow requires a non-empty focal");
    }
    let depth = request.depth.unwrap_or(DEFAULT_DEPTH).clamp(1, MAX_DEPTH);
    let direction = request.direction.unwrap_or_default();
    let limit_per_step = request
        .limit_per_step
        .unwrap_or(DEFAULT_LIMIT_PER_STEP)
        .clamp(1, MAX_LIMIT_PER_STEP);

    let focal_entity = match resolve_trace_focal(graph, trimmed)? {
        Some(entity) => entity,
        None => anyhow::bail!("no entity found matching '{}'", trimmed),
    };

    // Try to load the focal source record. Failures (missing span, OOB blob)
    // degrade gracefully to the identity-only payload — the chain still works.
    let focal_record = source_record_or_none(binding, graph, &focal_entity);

    let reference_kinds = [
        RelationKind::Calls,
        RelationKind::Imports,
        RelationKind::References,
    ];
    let allowed: HashSet<RelationKind> = reference_kinds.iter().copied().collect();

    let mut chain: Vec<TraceStep> = Vec::new();
    let mut visited: HashSet<EntityId> = HashSet::new();
    visited.insert(focal_entity.id);
    let mut truncated = false;

    // Frontier: (parent_step, parent_entity, parent_depth).
    let mut frontier: Vec<(usize, EntityId, usize)> = vec![(0, focal_entity.id, 0)];
    let mut next_frontier: Vec<(usize, EntityId, usize)>;

    while !frontier.is_empty() {
        next_frontier = Vec::new();

        for (parent_step, parent_id, parent_depth) in frontier.drain(..) {
            if parent_depth >= depth {
                continue;
            }

            let relations = graph
                .get_all_relations_for_entity(&parent_id)
                .context("read relations for trace step")?;

            // Expand outgoing edges (parent calls these) when direction allows.
            let want_callees = matches!(direction, TraceDirection::Calls | TraceDirection::Both);
            // Expand incoming edges (these call parent) when direction allows.
            let want_callers = matches!(direction, TraceDirection::Callers | TraceDirection::Both);

            // Independent budgets per direction so `direction=both` doesn't
            // starve callers when callees are listed first (or vice versa).
            let mut callee_count = 0usize;
            let mut caller_count = 0usize;
            for rel in &relations {
                if !allowed.contains(&rel.kind) {
                    continue;
                }
                let src_entity = rel.src.as_entity();
                let dst_entity = match rel.dst {
                    GraphNodeId::Entity(id) => Some(id),
                    _ => None,
                };

                // Decide which side of the relation is the "next" node.
                let (next_id, role) = if want_callees
                    && src_entity == Some(parent_id)
                    && dst_entity.is_some()
                    && dst_entity != Some(parent_id)
                {
                    (dst_entity.unwrap(), "callee")
                } else if want_callers
                    && dst_entity == Some(parent_id)
                    && src_entity.is_some()
                    && src_entity != Some(parent_id)
                {
                    (src_entity.unwrap(), "caller")
                } else {
                    continue;
                };

                // Independent per-direction budget — cap callees and callers
                // separately so `direction=both` doesn't starve one side.
                // Check budget BEFORE marking visited so the next relation
                // (potentially in the other direction) can still consider
                // this entity if appropriate.
                if role == "callee" && callee_count >= limit_per_step {
                    truncated = true;
                    continue;
                }
                if role == "caller" && caller_count >= limit_per_step {
                    truncated = true;
                    continue;
                }

                if !visited.insert(next_id) {
                    continue;
                }

                if role == "callee" {
                    callee_count += 1;
                } else {
                    caller_count += 1;
                }

                if chain.len() >= MAX_TOTAL_STEPS {
                    truncated = true;
                    break;
                }

                let next_entity = match graph
                    .get_entity(&next_id)
                    .context("load trace step entity")?
                {
                    Some(entity) => entity,
                    None => continue,
                };
                let next_record = source_record_or_none(binding, graph, &next_entity);
                let next_depth = parent_depth + 1;
                let step_index = chain.len() + 1;

                chain.push(TraceStep {
                    step: step_index,
                    role: role.to_string(),
                    relation_kind: format!("{:?}", rel.kind),
                    parent_step,
                    depth: next_depth,
                    entity: next_record,
                    entity_id: next_entity.id.to_string(),
                    entity_name: next_entity.name.clone(),
                    entity_kind: format!("{:?}", next_entity.kind),
                    entity_file: next_entity.file_origin.as_ref().map(|p| p.0.clone()),
                });

                if next_depth < depth {
                    next_frontier.push((step_index, next_id, next_depth));
                }
            }

            if chain.len() >= MAX_TOTAL_STEPS {
                truncated = true;
                break;
            }
        }

        if chain.len() >= MAX_TOTAL_STEPS {
            truncated = true;
            break;
        }

        frontier = next_frontier;
    }

    Ok(TraceDataFlowResponse {
        focal: focal_record,
        focal_id: focal_entity.id.to_string(),
        focal_name: focal_entity.name.clone(),
        focal_kind: format!("{:?}", focal_entity.kind),
        focal_file: focal_entity.file_origin.as_ref().map(|p| p.0.clone()),
        direction: direction.as_str().to_string(),
        depth,
        total_steps: chain.len(),
        chain,
        truncated,
    })
}

/// Resolve a trace focal by UUID, exact name, or the entity-ranking fallback.
///
/// Mirrors `resolve_source_entity` in graph.rs so trace_data_flow and
/// `graph source` agree on which entity a name maps to.
fn resolve_trace_focal(graph: &kin_db::InMemoryGraph, query: &str) -> Result<Option<Entity>> {
    let trimmed = query.trim();
    if let Ok(uuid) = uuid::Uuid::parse_str(trimmed) {
        return Ok(graph.get_entity(&EntityId(uuid))?);
    }
    if let Some(entity) = kin_ranking::entity_ranking::select_best_entity(graph, trimmed)? {
        return Ok(Some(entity));
    }
    let matches = kin_core::query_trace_matches(graph, trimmed)?;
    Ok(matches.into_iter().next())
}

/// Try to read an entity's source record; fall back to None for entities
/// without a readable span / blob so the chain still includes their identity.
fn source_record_or_none(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &kin_db::InMemoryGraph,
    entity: &Entity,
) -> Option<GraphSourceRecord> {
    let response = build_graph_source_response(binding, graph, &entity.id.to_string()).ok()?;
    response.source
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::{InMemoryGraph, LocalFileBackend};
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::ids::{FilePathId, Hash256, LanguageId, RelationId, RepositoryId, WorkspaceId};
    use kin_model::relation::{Relation, RelationOrigin};
    use std::sync::Arc;

    fn make_entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn make_relation(src: EntityId, dst: EntityId, kind: RelationKind) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        }
    }

    /// Synthesize an absent repository authority. The body itself isn't
    /// required for the chain-shape tests; we only assert on identity fields.
    fn empty_binding() -> (tempfile::TempDir, kin_core::LocalRepositoryAuthorityBinding) {
        let temp = tempfile::tempdir().unwrap();
        let kin_root = temp.path().join(".kin");
        std::fs::create_dir_all(kin_root.join("objects")).unwrap();
        let layout = kin_core::KinLayout::new(kin_root);
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_parts(
            RepositoryId::new("trace-data-flow-test").unwrap(),
            WorkspaceId::new(),
            Arc::new(LocalFileBackend::new(layout.kindb_dir())),
        );
        (temp, binding)
    }

    #[test]
    fn rejects_empty_focal() {
        let graph = InMemoryGraph::new();
        let (_t, binding) = empty_binding();
        let err = build_trace_data_flow_response(
            &binding,
            &graph,
            &TraceDataFlowRequest {
                focal: "   ".to_string(),
                depth: None,
                direction: None,
                limit_per_step: None,
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("non-empty focal"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_missing_focal_entity() {
        let graph = InMemoryGraph::new();
        let (_t, binding) = empty_binding();
        let err = build_trace_data_flow_response(
            &binding,
            &graph,
            &TraceDataFlowRequest {
                focal: "does_not_exist".to_string(),
                depth: None,
                direction: None,
                limit_per_step: None,
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("no entity found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn callee_direction_walks_outgoing_calls() {
        let graph = InMemoryGraph::new();
        let (_t, binding) = empty_binding();

        let focal = make_entity("focal", "src/focal.rs");
        let callee_a = make_entity("callee_a", "src/a.rs");
        let callee_b = make_entity("callee_b", "src/b.rs");
        let leaf = make_entity("leaf", "src/leaf.rs");
        let focal_id = focal.id;
        let callee_a_id = callee_a.id;
        let callee_b_id = callee_b.id;
        let leaf_id = leaf.id;

        graph.upsert_entity(&focal).unwrap();
        graph.upsert_entity(&callee_a).unwrap();
        graph.upsert_entity(&callee_b).unwrap();
        graph.upsert_entity(&leaf).unwrap();

        // focal -> callee_a, focal -> callee_b, callee_a -> leaf
        graph
            .upsert_relation(&make_relation(focal_id, callee_a_id, RelationKind::Calls))
            .unwrap();
        graph
            .upsert_relation(&make_relation(focal_id, callee_b_id, RelationKind::Calls))
            .unwrap();
        graph
            .upsert_relation(&make_relation(callee_a_id, leaf_id, RelationKind::Calls))
            .unwrap();

        let response = build_trace_data_flow_response(
            &binding,
            &graph,
            &TraceDataFlowRequest {
                focal: focal_id.to_string(),
                depth: Some(2),
                direction: Some(TraceDirection::Calls),
                limit_per_step: Some(5),
            },
        )
        .unwrap();

        assert_eq!(response.focal_id, focal_id.to_string());
        assert_eq!(response.direction, "calls");
        assert_eq!(response.depth, 2);
        // 2 direct callees + 1 transitive (leaf) = 3 steps
        assert_eq!(response.total_steps, 3);
        assert_eq!(response.chain.len(), 3);
        assert!(
            response.chain.iter().all(|step| step.role == "callee"),
            "all steps must be callees in calls-only direction"
        );
        let leaf_step = response
            .chain
            .iter()
            .find(|s| s.entity_id == leaf_id.to_string())
            .expect("leaf must be reached at depth 2");
        assert_eq!(leaf_step.depth, 2);
        assert!(leaf_step.parent_step >= 1, "leaf's parent must be a step");
    }

    #[test]
    fn caller_direction_walks_incoming_calls() {
        let graph = InMemoryGraph::new();
        let (_t, binding) = empty_binding();

        let focal = make_entity("target", "src/target.rs");
        let caller_a = make_entity("caller_a", "src/a.rs");
        let caller_b = make_entity("caller_b", "src/b.rs");
        let focal_id = focal.id;
        let caller_a_id = caller_a.id;
        let caller_b_id = caller_b.id;

        graph.upsert_entity(&focal).unwrap();
        graph.upsert_entity(&caller_a).unwrap();
        graph.upsert_entity(&caller_b).unwrap();

        // caller_a -> focal, caller_b -> focal
        graph
            .upsert_relation(&make_relation(caller_a_id, focal_id, RelationKind::Calls))
            .unwrap();
        graph
            .upsert_relation(&make_relation(caller_b_id, focal_id, RelationKind::Calls))
            .unwrap();

        let response = build_trace_data_flow_response(
            &binding,
            &graph,
            &TraceDataFlowRequest {
                focal: focal_id.to_string(),
                depth: Some(1),
                direction: Some(TraceDirection::Callers),
                limit_per_step: Some(5),
            },
        )
        .unwrap();

        assert_eq!(response.direction, "callers");
        assert_eq!(response.total_steps, 2);
        assert!(
            response.chain.iter().all(|step| step.role == "caller"),
            "all steps must be callers in callers-only direction"
        );
        let names: Vec<_> = response
            .chain
            .iter()
            .map(|s| s.entity_name.clone())
            .collect();
        assert!(names.contains(&"caller_a".to_string()));
        assert!(names.contains(&"caller_b".to_string()));
    }

    #[test]
    fn limit_per_step_truncates_branching() {
        let graph = InMemoryGraph::new();
        let (_t, binding) = empty_binding();

        let focal = make_entity("hub", "src/hub.rs");
        let focal_id = focal.id;
        graph.upsert_entity(&focal).unwrap();
        for i in 0..10 {
            let callee = make_entity(&format!("callee_{i}"), &format!("src/c_{i}.rs"));
            let callee_id = callee.id;
            graph.upsert_entity(&callee).unwrap();
            graph
                .upsert_relation(&make_relation(focal_id, callee_id, RelationKind::Calls))
                .unwrap();
        }

        let response = build_trace_data_flow_response(
            &binding,
            &graph,
            &TraceDataFlowRequest {
                focal: focal_id.to_string(),
                depth: Some(1),
                direction: Some(TraceDirection::Calls),
                limit_per_step: Some(3),
            },
        )
        .unwrap();

        assert_eq!(response.total_steps, 3, "limit_per_step caps the fan-out");
        assert!(response.truncated, "truncated flag must be set when capped");
    }

    #[test]
    fn direction_parse_accepts_aliases() {
        assert_eq!(
            TraceDirection::parse("calls").unwrap(),
            TraceDirection::Calls
        );
        assert_eq!(
            TraceDirection::parse("callees").unwrap(),
            TraceDirection::Calls
        );
        assert_eq!(
            TraceDirection::parse("caller").unwrap(),
            TraceDirection::Callers
        );
        assert_eq!(TraceDirection::parse("BOTH").unwrap(), TraceDirection::Both);
        assert!(TraceDirection::parse("sideways").is_err());
    }
}
