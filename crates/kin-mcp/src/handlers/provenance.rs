// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::graph::GraphStore;

use crate::error::{McpError, Result};
use crate::types::ToolCallResult;

use super::common::*;

pub const PROVENANCE_QUERY_DESC: &str = "\
Answer who-and-whether-approved for an entity: it returns the entity's change count, \
its latest change, any approvals recorded on that change, and recent audit events. \
Reach for it to establish accountability and trust before relying on a piece of code — \
\"who last touched this, and has it been signed off?\" — or when assembling an audit \
trail. It builds on entity_history (the raw change list) by adding approval status and \
audit context in one call.";

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
