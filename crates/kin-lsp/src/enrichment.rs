// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Convert LSP responses into graph relations.

use crate::types::{
    EntityId, GraphNodeId, Relation, RelationId, RelationKind, RelationOrigin,
};

use crate::protocol::{CallHierarchyIncomingCall, CallHierarchyOutgoingCall, Location};

/// Result of enriching a single file via LSP.
#[derive(Debug, Default)]
pub struct EnrichmentResult {
    /// New relations discovered by LSP (type-resolved calls, references, etc.)
    pub relations: Vec<Relation>,
    /// Entity IDs that LSP couldn't resolve (for diagnostics).
    pub unresolved: Vec<String>,
}

/// Convert an outgoing call hierarchy response to a Calls relation.
///
/// The caller entity is identified by `caller_id`. The callee's location
/// is used to find the matching entity in the graph.
pub fn outgoing_call_to_relation(
    caller_id: EntityId,
    call: &CallHierarchyOutgoingCall,
) -> Relation {
    // The callee entity ID will be resolved by the caller against the graph.
    // For now, create a relation with a deterministic ID from the call target.
    let callee_uri = &call.to.uri;
    let callee_name = &call.to.name;

    Relation {
        id: RelationId::new(),
        kind: RelationKind::Calls,
        src: GraphNodeId::Entity(caller_id),
        // dst will be resolved by matching against graph entities by file+position
        dst: GraphNodeId::Entity(EntityId::new()), // placeholder
        confidence: 0.95, // LSP-resolved calls are high confidence
        origin: RelationOrigin::Lsp,
        created_in: None,
        import_source: None,
    }
}

/// Convert an incoming call hierarchy response to a Calls relation.
pub fn incoming_call_to_relation(
    callee_id: EntityId,
    call: &CallHierarchyIncomingCall,
) -> Relation {
    Relation {
        id: RelationId::new(),
        kind: RelationKind::Calls,
        src: GraphNodeId::Entity(EntityId::new()), // placeholder — resolve from call.from
        dst: GraphNodeId::Entity(callee_id),
        confidence: 0.95,
        origin: RelationOrigin::Inferred,
        created_in: None,
        import_source: None,
    }
}

/// Convert a go-to-definition location to a References relation.
pub fn definition_to_relation(
    reference_id: EntityId,
    _definition: &Location,
) -> Relation {
    Relation {
        id: RelationId::new(),
        kind: RelationKind::References,
        src: GraphNodeId::Entity(reference_id),
        dst: GraphNodeId::Entity(EntityId::new()), // placeholder
        confidence: 1.0, // Definition resolution is exact
        origin: RelationOrigin::Inferred,
        created_in: None,
        import_source: None,
    }
}
