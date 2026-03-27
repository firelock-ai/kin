// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::graph::GraphStore;

use crate::error::{McpError, Result};
use crate::types::ToolCallResult;

use super::common::*;

pub fn handle_provenance_query<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;

    // Get the entity's history to find the latest change
    let history = store
        .get_entity_history(&entity_id)
        .map_err(McpError::graph)?;

    let mut approvals_json = serde_json::json!([]);
    if let Some(latest_change) = history.first() {
        let approvals = store
            .get_approvals_for_change(&latest_change.id)
            .map_err(McpError::graph)?;
        approvals_json = serde_json::json!(approvals);
    }

    // Get recent audit events (not actor-filtered, just recent)
    let events = store
        .query_audit_events(None, 20)
        .map_err(McpError::graph)?;

    let result = serde_json::json!({
        "entity_id": id_str,
        "change_count": history.len(),
        "latest_change": history.first(),
        "approvals": approvals_json,
        "recent_audit_events": events,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}
