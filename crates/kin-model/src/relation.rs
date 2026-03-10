use serde::{Deserialize, Serialize};

use crate::ids::*;

/// A typed edge in the semantic graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relation {
    pub id: RelationId,
    pub kind: RelationKind,
    pub src: EntityId,
    pub dst: EntityId,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f32,
    pub origin: RelationOrigin,
    /// None while in overlay; set on kin commit.
    pub created_in: Option<SemanticChangeId>,
}

/// Classification of a relation edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationKind {
    Calls,
    Imports,
    Contains,
    References,
    Implements,
    Extends,
    Tests,
    DependsOn,
    DefinesContract,
    ConsumesContract,
    EmitsEvent,
    OwnedBy,
    DocumentedBy,
}

/// How a relation was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationOrigin {
    Parsed,
    Inferred,
    Manual,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_kind_roundtrip() {
        let kinds = vec![
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::Contains,
            RelationKind::References,
            RelationKind::Implements,
            RelationKind::Extends,
            RelationKind::Tests,
            RelationKind::DependsOn,
            RelationKind::DefinesContract,
            RelationKind::ConsumesContract,
            RelationKind::EmitsEvent,
            RelationKind::OwnedBy,
            RelationKind::DocumentedBy,
        ];
        for k in kinds {
            let json = serde_json::to_string(&k).unwrap();
            let parsed: RelationKind = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, k);
        }
    }
}
