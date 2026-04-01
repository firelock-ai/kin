// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::SemanticChange;

/// Check whether a SemanticChange is the synthetic genesis change.
///
/// The genesis change is defined as having zero parents and message "kin init".
pub fn is_genesis_change(change: &SemanticChange) -> bool {
    change.parents.is_empty() && change.message == "kin init"
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::*;

    fn make_genesis() -> SemanticChange {
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("kin"),
            message: "kin init".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    #[test]
    fn genesis_is_detected() {
        let genesis = make_genesis();
        assert!(is_genesis_change(&genesis));
    }

    #[test]
    fn non_genesis_is_not_detected() {
        let mut change = make_genesis();
        change.parents = vec![SemanticChangeId::from_hash(Hash256::from_bytes([1; 32]))];
        assert!(!is_genesis_change(&change));
    }

    #[test]
    fn wrong_message_is_not_genesis() {
        let mut change = make_genesis();
        change.message = "some other commit".to_string();
        assert!(!is_genesis_change(&change));
    }
}
