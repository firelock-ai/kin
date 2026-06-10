// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::conflict::ConflictObject;
use crate::entity::Entity;
use crate::ids::*;
use crate::relation::Relation;

/// A lightweight named pointer to a SemanticChange node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    pub name: BranchName,
    /// Always valid -- genesis change is the floor.
    pub head: SemanticChangeId,
}

/// The developer's in-progress state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingCopy {
    /// Genesis change after kin init, advances on commit.
    pub base_change: SemanticChangeId,
    /// In-memory diff layer over the base graph.
    pub uncommitted_mutations: GraphOverlay,
}

/// In-memory diff applied on top of the current branch head.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphOverlay {
    pub entity_adds: HashMap<EntityId, Entity>,
    pub entity_mods: HashMap<EntityId, Entity>,
    pub entity_removes: Vec<EntityId>,
    pub relation_adds: HashMap<RelationId, Relation>,
    pub relation_removes: Vec<RelationId>,
    /// Entity bodies for modified/added entities.
    /// Used by VFS to project overlay changes without re-reading files.
    #[serde(default)]
    pub entity_bodies: HashMap<EntityId, Vec<u8>>,
}

/// State of a merge operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MergeState {
    Clean,
    Conflicted(Vec<ConflictObject>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_overlay_default_is_empty() {
        let overlay = GraphOverlay::default();
        assert!(overlay.entity_adds.is_empty());
        assert!(overlay.entity_mods.is_empty());
        assert!(overlay.entity_removes.is_empty());
        assert!(overlay.relation_adds.is_empty());
        assert!(overlay.relation_removes.is_empty());
        assert!(overlay.entity_bodies.is_empty());
    }

    #[test]
    fn merge_state_roundtrip() {
        let clean = MergeState::Clean;
        let json = serde_json::to_string(&clean).unwrap();
        let parsed: MergeState = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, MergeState::Clean));
    }
}
