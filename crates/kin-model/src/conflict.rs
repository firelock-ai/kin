// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};

use crate::ids::*;

/// First-class conflict artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictObject {
    pub id: ConflictId,
    pub kind: ConflictKind,
    pub desired_state: String,
    pub current_state: String,
    pub divergence_reason: String,
    pub affected_entities: Vec<EntityId>,
    pub affected_files: Vec<FilePathId>,
    pub suggested_resolutions: Vec<String>,
    pub requires_human_review: bool,
}

/// Classification of conflict types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConflictKind {
    StructuralCollision,
    SemanticViolation,
    ArtifactCollision,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_kind_roundtrip() {
        let kind = ConflictKind::SemanticViolation;
        let json = serde_json::to_string(&kind).unwrap();
        let parsed: ConflictKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, kind);
    }
}
