// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::entity::Entity;
use crate::ids::*;
use crate::review::RiskSummary;
use crate::timestamp::Timestamp;

/// Kin's native commit — the unit of semantic history.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SemanticChange {
    /// Content-addressed hash.
    pub id: SemanticChangeId,
    /// 0 = genesis, 1 = normal, 2 = merge.
    pub parents: Vec<SemanticChangeId>,
    pub timestamp: Timestamp,
    /// Human or assistant.
    pub author: AuthorId,
    pub message: String,
    pub entity_deltas: Vec<EntityDelta>,
    pub relation_deltas: Vec<RelationDelta>,
    /// Non-entity file changes.
    pub artifact_deltas: Vec<ArtifactDelta>,
    pub projected_files: Vec<FilePathId>,
    pub spec_link: Option<SpecId>,
    pub evidence: Vec<EvidenceId>,
    pub risk_summary: Option<RiskSummary>,
    /// Informational: branch name at creation time.
    pub authored_on: Option<BranchName>,
}

/// Delta for a single entity within a SemanticChange.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[allow(clippy::large_enum_variant)]
pub enum EntityDelta {
    Added(Entity),
    Modified { old: Entity, new: Entity },
    Removed(EntityId),
}

/// Delta for a single relation within a SemanticChange.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum RelationDelta {
    Added(crate::relation::Relation),
    Removed(RelationId),
}

/// Delta for a batch of transactional graph changes.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TransactionDelta {
    pub entity_deltas: Vec<EntityDelta>,
    pub relation_deltas: Vec<RelationDelta>,
}

/// Delta for a non-entity file within a SemanticChange.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactDelta {
    pub file_id: FilePathId,
    pub kind: ArtifactDeltaKind,
    pub old_hash: Option<Hash256>,
    pub new_hash: Option<Hash256>,
}

/// Classification of an artifact delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ArtifactDeltaKind {
    Added,
    Modified,
    Removed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_delta_kind_roundtrip() {
        let kind = ArtifactDeltaKind::Modified;
        let json = serde_json::to_string(&kind).unwrap();
        let parsed: ArtifactDeltaKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, kind);
    }
}
