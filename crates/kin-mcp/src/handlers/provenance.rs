// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::collections::HashSet;

use kin_model::graph::GraphStore;
use kin_model::work::WorkScope;

use crate::error::{McpError, Result};
use crate::types::ToolCallResult;

use super::common::*;

/// How many recent audit events to consider before narrowing them to the
/// queried entity.
///
/// The store filters by actor, never by scope, so narrowing by scope has to
/// happen here, which means taking a window of recent events first and filtering
/// second. The consequence is stated in the tool description rather than hidden:
/// an entity whose last write is older than this many events returns an empty
/// list even though it was written. Filtering before limiting would need a
/// scope-aware query in the store, which is kin-db's surface, not this one.
///
/// Bounded so one entity's answer does not grow with the repository's whole
/// audit history, and wide enough that an entity's own recent activity survives
/// a busy period from other lanes.
const AUDIT_SCAN: usize = 512;

/// How many of the queried entity's own events to return.
const AUDIT_RETURNED: usize = 20;

pub const PROVENANCE_QUERY_DESC: &str = "\
Answer who-and-whether-approved for an entity: it returns the entity's change count, \
its latest change, any approvals recorded on that change, and recent audit events \
recorded against that entity. Reach for it to establish accountability and trust before \
relying on a piece of code, to answer \"who last touched this, and has it been signed \
off?\", or when assembling an audit trail. It builds on entity_history (the raw change \
list) by adding approval status and audit context in one call. Every field is scoped to \
the entity you asked about: recent_audit_events never carries another entity's writes. It \
is drawn from the repository's recent audit activity and then narrowed, so it is the \
entity's own recent writes rather than its complete write history, and an entity whose \
last write is older than the scan window comes back with an empty list. Treat a populated \
list as authoritative about who wrote this entity, and an empty one as no recent record \
rather than as proof nothing ever wrote it; change_count and latest_change are the \
complete-history fields.";

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

    // Audit events for THIS entity, not the repository's most recent activity.
    //
    // The store has no scope filter, so an unnarrowed query returns whatever
    // happened last anywhere. Returning that under an `entity_id` key answers
    // "who touched this entity" with a different entity's commit, by a different
    // agent, and nothing in the response says otherwise. The events carry the
    // scope needed to narrow them, so narrow them here.
    //
    // A commit that changed no entity is scoped to its change instead, so those
    // are kept when the change is one of this entity's own.
    let entity_changes = history
        .iter()
        .map(|change| change.id)
        .collect::<HashSet<_>>();
    let events = store
        .query_audit_events(None, AUDIT_SCAN)
        .map_err(McpError::graph)?
        .into_iter()
        .filter(|event| match &event.target_scope {
            Some(WorkScope::Entity(id)) => *id == entity_id,
            Some(WorkScope::Change(id)) => entity_changes.contains(id),
            _ => false,
        })
        .take(AUDIT_RETURNED)
        .collect::<Vec<_>>();

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
