// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::graph::GraphStore;
use kin_model::ids::SemanticChangeId;
use kin_model::review::RiskSummary;
use serde::{Deserialize, Serialize};

use kin_model::change::SemanticChange as SemanticChangeModel;
use kin_model::ids::EntityId;

use crate::diff::{self, SemanticDiff};
use crate::error::ReviewError;
use crate::impact::{self, ImpactReport};
use crate::inline::{self, InlineComment};
use crate::ref_graph::GraphAtRef;
use crate::risk;

/// A complete semantic review: diff + impact + risk + inline comments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub base: Option<SemanticChangeId>,
    pub head: Option<SemanticChangeId>,
    pub diff: SemanticDiff,
    pub impact: ImpactReport,
    pub risk: RiskSummary,
    pub inline_comments: Vec<InlineComment>,
}

/// The main entry point for creating a semantic review.
pub struct SemanticReview;

impl SemanticReview {
    /// Create a full semantic review between a base and head change.
    ///
    /// This computes:
    /// 1. Entity-level diff between base and head
    /// 2. Impact analysis (callers, dependents, contracts, tests) against
    ///    the graph state materialized at `head`
    /// 3. Risk assessment (breaking changes, coverage gaps, violations)
    ///
    /// Fails with [`ReviewError::RefStateUnavailable`] when the graph state
    /// at `head` cannot be materialized; it never answers impact from the
    /// live adjacency for a committed range.
    pub fn create_review<G: GraphStore>(
        base: &SemanticChangeId,
        head: &SemanticChangeId,
        store: &G,
    ) -> Result<Review, ReviewError> {
        let at_head = GraphAtRef::materialize(store, head)?;
        Self::create_review_at(base, head, store, &at_head)
    }

    /// Create a full semantic review between a base and head change, with
    /// impact analysis answered by an already-materialized head state.
    ///
    /// Callers evaluating the same head repeatedly can materialize the
    /// [`GraphAtRef`] once and reuse it across evaluations.
    pub fn create_review_at<G: GraphStore>(
        base: &SemanticChangeId,
        head: &SemanticChangeId,
        store: &G,
        at_head: &GraphAtRef<'_, G>,
    ) -> Result<Review, ReviewError> {
        Self::create_review_scoped(base, head, store, at_head, |_| true)
    }

    /// Create a review whose diff accumulates only the walked changes
    /// `in_range` accepts — the DAG-true `base..head` membership test for
    /// range-aware callers. See [`diff::compute_diff_scoped`].
    pub fn create_review_scoped<G: GraphStore>(
        base: &SemanticChangeId,
        head: &SemanticChangeId,
        store: &G,
        at_head: &GraphAtRef<'_, G>,
        in_range: impl Fn(&SemanticChangeId) -> bool,
    ) -> Result<Review, ReviewError> {
        let semantic_diff = diff::compute_diff_scoped(store, base, head, in_range)?;
        let impact_report = impact::analyze_impact_at(at_head, &semantic_diff)?;
        let risk_summary = risk::assess_risk(&semantic_diff, &impact_report);
        let inline_comments = inline::collect_inline_comments(&semantic_diff, &impact_report);

        Ok(Review {
            base: Some(*base),
            head: Some(*head),
            diff: semantic_diff,
            impact: impact_report,
            risk: risk_summary,
            inline_comments,
        })
    }

    /// Create a review from a pre-computed diff (useful when you already
    /// have the SemanticChange objects).
    pub fn review_from_diff<G: GraphStore>(
        semantic_diff: SemanticDiff,
        store: &G,
    ) -> Result<Review, ReviewError> {
        let impact_report = impact::analyze_impact(store, &semantic_diff)?;
        let risk_summary = risk::assess_risk(&semantic_diff, &impact_report);
        let inline_comments = inline::collect_inline_comments(&semantic_diff, &impact_report);

        Ok(Review {
            base: semantic_diff.base,
            head: semantic_diff.head,
            diff: semantic_diff,
            impact: impact_report,
            risk: risk_summary,
            inline_comments,
        })
    }

    /// Create a review from an arbitrary set of entity IDs.
    ///
    /// This is the primary API for user-specified change sets: the caller
    /// provides entity IDs they want reviewed, and the engine looks up
    /// current state + history to produce the diff, impact, and risk.
    pub fn review_entities<G: GraphStore>(
        entity_ids: &[EntityId],
        store: &G,
    ) -> Result<Review, ReviewError> {
        let semantic_diff = diff::diff_from_entity_ids(store, entity_ids)?;
        Self::review_from_diff(semantic_diff, store)
    }

    /// Create a review from file paths.
    ///
    /// Resolves each file path to its constituent entities, then produces
    /// a full review of all entities in those files.
    pub fn review_files<G: GraphStore>(files: &[String], store: &G) -> Result<Review, ReviewError> {
        let semantic_diff = diff::diff_from_files(store, files)?;
        Self::review_from_diff(semantic_diff, store)
    }

    /// Create a review from an explicit list of SemanticChange objects.
    ///
    /// Allows cherry-picking arbitrary changes from anywhere in the DAG
    /// — across branches, non-contiguous history, or hand-curated sets —
    /// and reviewing them as a single unit.
    pub fn review_changes<G: GraphStore>(
        changes: &[SemanticChangeModel],
        store: &G,
    ) -> Result<Review, ReviewError> {
        let semantic_diff = diff::diff_from_changes(changes);
        if semantic_diff.is_empty() {
            return Err(ReviewError::NoChanges);
        }
        Self::review_from_diff(semantic_diff, store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::diff_from_change;
    use kin_db::InMemoryGraph;
    use kin_model::change::{EntityDelta, SemanticChange};
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::ids::*;
    use kin_model::timestamp::Timestamp;

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {}()", name),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn test_change_id(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    #[test]
    fn review_from_diff_with_mock_store() {
        let entity = test_entity("my_func");
        let change = SemanticChange {
            id: test_change_id(1),
            parents: vec![test_change_id(0)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "add my_func".into(),
            entity_deltas: vec![EntityDelta::Added { new: entity }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let diff = diff_from_change(&change);
        let store = InMemoryGraph::new();
        let review = SemanticReview::review_from_diff(diff, &store).unwrap();

        assert_eq!(review.diff.entity_changes.len(), 1);
        assert!(review.impact.is_empty());
        assert_eq!(review.risk.overall_risk, kin_model::review::RiskLevel::Low);
    }
}
