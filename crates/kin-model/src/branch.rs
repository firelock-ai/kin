// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::change::TreeDelta;
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WorkingCopy {
    /// Genesis change after kin init, advances on commit.
    pub base_change: SemanticChangeId,
    /// In-memory diff layer over the base graph.
    pub uncommitted_mutations: GraphOverlay,
}

/// In-memory diff applied on top of the current branch head.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GraphOverlay {
    pub entity_adds: HashMap<EntityId, Entity>,
    pub entity_mods: HashMap<EntityId, Entity>,
    pub entity_removes: Vec<EntityId>,
    pub relation_adds: HashMap<RelationId, Relation>,
    pub relation_removes: Vec<RelationId>,
    /// Exact repository-tree transitions staged in this working copy.
    pub tree_deltas: Vec<TreeDelta>,
    /// Entity bodies for modified/added entities.
    /// Used by VFS to project overlay changes without re-reading files.
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
        assert!(overlay.tree_deltas.is_empty());
        assert!(overlay.entity_bodies.is_empty());
    }

    #[test]
    fn working_copy_carries_exact_tree_deltas() {
        let artifact_id = crate::ArtifactId::new();
        let entry = crate::TreeEntry::blob(Hash256::from_bytes([0x71; 32]), false);
        let working_copy = WorkingCopy {
            base_change: SemanticChangeId::from_hash(Hash256::from_bytes([0x72; 32])),
            uncommitted_mutations: GraphOverlay {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: crate::LocatedEntry::new(
                        crate::RepoPath::from_utf8("compose.yaml").unwrap(),
                        entry,
                    ),
                }],
                ..GraphOverlay::default()
            },
        };

        let encoded = serde_json::to_string(&working_copy).unwrap();
        let decoded: WorkingCopy = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            decoded.uncommitted_mutations.tree_deltas[0]
                .new_state()
                .map(|located| located.entry),
            Some(entry)
        );
    }

    #[test]
    fn merge_state_roundtrip() {
        let clean = MergeState::Clean;
        let json = serde_json::to_string(&clean).unwrap();
        let parsed: MergeState = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, MergeState::Clean));
    }
}
