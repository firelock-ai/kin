// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::BTreeMap;

use kin_model::graph::GraphStore;
use kin_model::ids::SemanticChangeId;
use kin_model::review::{RiskLevel, RiskSummary};
use serde::{Deserialize, Serialize};

use kin_model::change::SemanticChange as SemanticChangeModel;
use kin_model::ids::EntityId;

use crate::diff::{self, EntityChangeKind, SemanticDiff};
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

/// A review of a DAG-true range: every change `head` reaches that `base` does
/// not. See [`SemanticReview::create_range_review`].
#[derive(Debug, Clone)]
pub struct RangeReview {
    pub review: Review,
    /// How many changes the range holds: the head's ancestry less the base's.
    /// Zero means the head adds nothing the base lacks, and the review is
    /// empty because the range is, not because anything was skipped.
    pub changes_in_range: usize,
    /// Each changed entity's own risk level, read by
    /// [`crate::risk::entity_risk_levels`] from the same findings the review's
    /// overall risk is read from. One entry per changed entity.
    pub entity_risk: BTreeMap<EntityId, RiskLevel>,
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

    /// Review the DAG-true range `base..head`: every change `head` reaches
    /// that `base` does not, with impact read at head and a removed entity's
    /// consumers read at base.
    ///
    /// This is the range shadow review evaluates, packaged for a caller that
    /// wants the review rather than the gate. The membership test answers the
    /// same set whether or not `base` is an ancestor of `head`, but a caller
    /// comparing two branches should pass their merge base: the store's range
    /// walk stops only at the literal base node, so any other base makes it
    /// visit everything `head` reaches before the filter drops it.
    ///
    /// Risk is assessed after the base-side overlay, so the breaking-removal
    /// rule reads the consumers a removed entity had where it still existed.
    /// Fails with [`ReviewError::RefStateUnavailable`] when either side's
    /// ancestry is not fully present in the store.
    pub fn create_range_review<G: GraphStore>(
        store: &G,
        base: &SemanticChangeId,
        head: &SemanticChangeId,
    ) -> Result<RangeReview, ReviewError> {
        let at_head = GraphAtRef::materialize(store, head)?;
        let base_ancestry = crate::ref_graph::collect_ancestry(store, base)?;
        let changes_in_range = at_head
            .ancestry()
            .iter()
            .filter(|id| !base_ancestry.contains(id))
            .count();
        if changes_in_range == 0 {
            // The head adds nothing the base lacks. That is a real, empty
            // review, and it answers as one rather than as the diff's
            // `NoChanges` error, which a caller would read as a failure.
            let diff = SemanticDiff {
                base: Some(*base),
                head: Some(*head),
                ..Default::default()
            };
            let impact = ImpactReport::default();
            let risk = risk::assess_risk(&diff, &impact);
            return Ok(RangeReview {
                review: Review {
                    base: Some(*base),
                    head: Some(*head),
                    diff,
                    impact,
                    risk,
                    inline_comments: Vec::new(),
                },
                changes_in_range,
                entity_risk: BTreeMap::new(),
            });
        }
        let in_range =
            |id: &SemanticChangeId| at_head.ancestry_contains(id) && !base_ancestry.contains(id);
        let mut review = Self::create_review_scoped(base, head, store, &at_head, in_range)?;
        let removes_an_entity = review
            .diff
            .entity_changes
            .iter()
            .any(|change| matches!(change.kind, EntityChangeKind::Removed { .. }));
        if removes_an_entity {
            let at_base = GraphAtRef::materialize(store, base)?;
            crate::shadow::overlay_removed_entity_impact_from_base(&mut review, &at_base)?;
            review.risk = risk::assess_risk(&review.diff, &review.impact);
            review.inline_comments = inline::collect_inline_comments(&review.diff, &review.impact);
        }
        let entity_risk = risk::entity_risk_levels(&review.diff, &review.impact);
        Ok(RangeReview {
            review,
            changes_in_range,
            entity_risk,
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

    fn calls(src: &Entity, dst: &Entity) -> kin_model::relation::Relation {
        kin_model::relation::Relation {
            id: RelationId::new(),
            kind: kin_model::relation::RelationKind::Calls,
            src: kin_model::relation::GraphNodeId::Entity(src.id),
            dst: kin_model::relation::GraphNodeId::Entity(dst.id),
            confidence: 1.0,
            origin: kin_model::relation::RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        }
    }

    fn committed(
        parents: Vec<SemanticChangeId>,
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<kin_model::change::RelationDelta>,
    ) -> SemanticChange {
        let mut change = SemanticChange {
            id: test_change_id(0),
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "range review fixture".into(),
            entity_deltas,
            relation_deltas,
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };
        change.id = kin_model::compute_semantic_change_id(&change).unwrap();
        change
    }

    /// A review of a branch is the branch's own changes, from the merge base.
    ///
    /// Root adds three functions, `caller` calling `doomed`. The base line adds
    /// `only_on_main`; the branch widens `shared`'s signature and deletes
    /// `doomed` while `caller` still calls it. The range is the branch alone,
    /// so `only_on_main` must not appear, and the deletion is breaking because
    /// its caller survives. A base off the head's ancestry must answer the same
    /// range, and the range from the head to itself is empty, not an error.
    #[test]
    fn a_range_review_covers_the_head_side_only_and_ranks_each_entity() {
        use kin_model::change::RelationDelta;
        use kin_model::ChangeStore;
        use std::collections::BTreeSet;

        let graph = InMemoryGraph::new();
        let shared = test_entity("shared");
        let doomed = test_entity("doomed");
        let caller = test_entity("caller");
        let only_on_main = test_entity("only_on_main");
        let edge = calls(&caller, &doomed);
        let root = committed(
            vec![],
            vec![
                EntityDelta::Added {
                    new: shared.clone(),
                },
                EntityDelta::Added {
                    new: doomed.clone(),
                },
                EntityDelta::Added {
                    new: caller.clone(),
                },
            ],
            vec![RelationDelta::Added { new: edge.clone() }],
        );
        let main = committed(
            vec![root.id],
            vec![EntityDelta::Added {
                new: only_on_main.clone(),
            }],
            vec![],
        );
        let mut widened = shared.clone();
        widened.signature = "fn shared(flag: bool)".to_string();
        let branch = committed(
            vec![root.id],
            vec![
                EntityDelta::Modified {
                    old: shared.clone(),
                    new: widened,
                },
                EntityDelta::Removed {
                    old: doomed.clone(),
                },
            ],
            vec![RelationDelta::Removed { old: edge }],
        );
        for change in [&root, &main, &branch] {
            graph.create_change(change).unwrap();
        }
        let changed_in = |range: &RangeReview| -> BTreeSet<EntityId> {
            range
                .review
                .diff
                .entity_changes
                .iter()
                .map(|change| change.entity_id)
                .collect()
        };

        let range = SemanticReview::create_range_review(&graph, &root.id, &branch.id).unwrap();
        assert_eq!(range.changes_in_range, 1);
        assert_eq!(
            changed_in(&range),
            [shared.id, doomed.id].into_iter().collect::<BTreeSet<_>>(),
            "the base line's own change is outside the range"
        );
        assert_eq!(range.entity_risk.len(), 2);
        assert_eq!(
            range.entity_risk[&doomed.id],
            RiskLevel::High,
            "deleting what a surviving caller calls is breaking: {:?}",
            range.review.risk
        );
        assert_eq!(
            range.entity_risk[&shared.id],
            RiskLevel::Medium,
            "a widened signature with no consumers and no tests is a coverage gap: {:?}",
            range.review.risk
        );
        assert_eq!(range.review.risk.overall_risk, RiskLevel::High);

        let from_sibling =
            SemanticReview::create_range_review(&graph, &main.id, &branch.id).unwrap();
        assert_eq!(from_sibling.changes_in_range, 1);
        assert_eq!(
            changed_in(&from_sibling),
            changed_in(&range),
            "the membership test must not depend on the base being an ancestor"
        );

        let empty = SemanticReview::create_range_review(&graph, &branch.id, &branch.id).unwrap();
        assert_eq!(empty.changes_in_range, 0);
        assert!(empty.review.diff.is_empty());
        assert!(empty.entity_risk.is_empty());
        assert_eq!(empty.review.risk.overall_risk, RiskLevel::Low);
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
