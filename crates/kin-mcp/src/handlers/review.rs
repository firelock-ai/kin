// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::graph::GraphStore;
use kin_review::{format_review, SemanticReview};

use crate::error::{McpError, Result};
use crate::session::SessionRegistry;
use crate::types::ToolCallResult;

use super::common::*;

pub fn handle_semantic_diff<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let diff = resolve_diff(args, store)?;
    let formatted = kin_review::format_diff(&diff);
    Ok(ToolCallResult::text(formatted))
}

pub fn handle_impact_analysis<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let include_traffic = get_optional_bool(args, "include_traffic", true);
    let diff = resolve_diff(args, store)?;

    let impact =
        kin_review::analyze_impact(store, &diff).map_err(|e| McpError::Review(e.to_string()))?;

    let mut result = serde_json::to_value(&impact).map_err(McpError::Json)?;

    if include_traffic {
        // Collect traffic for all changed entities.
        let mut all_traffic = Vec::new();
        for change in &diff.entity_changes {
            let traffic = sessions.get_traffic_near_entity(&change.entity_id);
            for summary in traffic {
                if !all_traffic
                    .iter()
                    .any(|t: &kin_model::session::IntentSummary| t.intent_id == summary.intent_id)
                {
                    all_traffic.push(summary);
                }
            }
        }
        if !all_traffic.is_empty() {
            result["active_traffic"] =
                serde_json::to_value(&all_traffic).map_err(McpError::Json)?;
        }
    }

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_semantic_review<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let include_traffic = get_optional_bool(args, "include_traffic", true);
    let diff = resolve_diff(args, store)?;

    let review = SemanticReview::review_from_diff(diff, store)
        .map_err(|e| McpError::Review(e.to_string()))?;

    let formatted = format_review(&review);

    if include_traffic {
        // Collect traffic for all entities in the diff.
        let mut traffic_lines = Vec::new();
        for change in &review.diff.entity_changes {
            let traffic = sessions.get_traffic_near_entity(&change.entity_id);
            for summary in &traffic {
                traffic_lines.push(format!(
                    "  {} ({}) is {} entity {} [{}]",
                    summary.vendor,
                    summary.session_id,
                    summary.task_description,
                    change.entity_id,
                    summary.lock_type_label(),
                ));
            }
        }

        if traffic_lines.is_empty() {
            Ok(ToolCallResult::text(formatted))
        } else {
            let with_traffic = format!(
                "{}\n\n--- Active Traffic ---\n{}",
                formatted,
                traffic_lines.join("\n")
            );
            Ok(ToolCallResult::text(with_traffic))
        }
    } else {
        Ok(ToolCallResult::text(formatted))
    }
}

pub fn handle_entity_history<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;

    let history = store
        .get_entity_history(&entity_id)
        .map_err(McpError::graph)?;

    let json = serde_json::to_string_pretty(&history).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}
