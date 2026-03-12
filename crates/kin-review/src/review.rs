use kin_model::graph::GraphStore;
use kin_model::ids::SemanticChangeId;
use kin_model::review::RiskSummary;
use serde::{Deserialize, Serialize};

use crate::diff::{self, SemanticDiff};
use crate::error::ReviewError;
use crate::impact::{self, ImpactReport};
use crate::risk;

/// A complete semantic review: diff + impact + risk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub base: Option<SemanticChangeId>,
    pub head: Option<SemanticChangeId>,
    pub diff: SemanticDiff,
    pub impact: ImpactReport,
    pub risk: RiskSummary,
}

/// The main entry point for creating a semantic review.
pub struct SemanticReview;

impl SemanticReview {
    /// Create a full semantic review between a base and head change.
    ///
    /// This computes:
    /// 1. Entity-level diff between base and head
    /// 2. Impact analysis (callers, dependents, contracts, tests)
    /// 3. Risk assessment (breaking changes, coverage gaps, violations)
    pub fn create_review<G: GraphStore>(
        base: &SemanticChangeId,
        head: &SemanticChangeId,
        store: &G,
    ) -> Result<Review, ReviewError> {
        let semantic_diff = diff::compute_diff(store, base, head)?;
        let impact_report = impact::analyze_impact(store, &semantic_diff)?;
        let risk_summary = risk::assess_risk(&semantic_diff, &impact_report);

        Ok(Review {
            base: Some(*base),
            head: Some(*head),
            diff: semantic_diff,
            impact: impact_report,
            risk: risk_summary,
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

        Ok(Review {
            base: semantic_diff.base,
            head: semantic_diff.head,
            diff: semantic_diff,
            impact: impact_report,
            risk: risk_summary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::diff_from_change;
    use kin_model::branch::Branch;
    use kin_model::change::{EntityDelta, SemanticChange};
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, FingerprintAlgorithm, SemanticFingerprint, Visibility,
    };
    use kin_model::graph::{EntityFilter, SubGraph};
    use kin_model::ids::*;
    use kin_model::relation::{Relation, RelationKind};
    use kin_model::timestamp::Timestamp;

    // A minimal mock GraphStore for testing
    struct MockGraphStore;

    impl GraphStore for MockGraphStore {
        type Error = std::io::Error;

        fn get_entity(&self, _id: &EntityId) -> Result<Option<Entity>, Self::Error> {
            Ok(None)
        }

        fn get_relations(
            &self,
            _id: &EntityId,
            _kinds: &[RelationKind],
        ) -> Result<Vec<Relation>, Self::Error> {
            Ok(vec![])
        }

        fn get_all_relations_for_entity(
            &self,
            _id: &EntityId,
        ) -> Result<Vec<Relation>, Self::Error> {
            Ok(vec![])
        }

        fn get_downstream_impact(
            &self,
            _id: &EntityId,
            _max_depth: u32,
        ) -> Result<Vec<Entity>, Self::Error> {
            Ok(vec![])
        }

        fn get_dependency_neighborhood(
            &self,
            _id: &EntityId,
            _depth: u32,
        ) -> Result<SubGraph, Self::Error> {
            Ok(SubGraph::default())
        }

        fn find_dead_code(&self) -> Result<Vec<Entity>, Self::Error> {
            Ok(vec![])
        }

        fn get_entity_history(&self, _id: &EntityId) -> Result<Vec<SemanticChange>, Self::Error> {
            Ok(vec![])
        }

        fn find_merge_bases(
            &self,
            _a: &SemanticChangeId,
            _b: &SemanticChangeId,
        ) -> Result<Vec<SemanticChangeId>, Self::Error> {
            Ok(vec![])
        }

        fn query_entities(&self, _filter: &EntityFilter) -> Result<Vec<Entity>, Self::Error> {
            Ok(vec![])
        }

        fn list_all_entities(&self) -> Result<Vec<Entity>, Self::Error> {
            Ok(vec![])
        }

        fn upsert_entity(&self, _entity: &Entity) -> Result<(), Self::Error> {
            Ok(())
        }

        fn upsert_relation(&self, _relation: &Relation) -> Result<(), Self::Error> {
            Ok(())
        }

        fn remove_entity(&self, _id: &EntityId) -> Result<(), Self::Error> {
            Ok(())
        }

        fn remove_relation(&self, _id: &RelationId) -> Result<(), Self::Error> {
            Ok(())
        }

        fn create_change(&self, _change: &SemanticChange) -> Result<(), Self::Error> {
            Ok(())
        }

        fn get_change(
            &self,
            _id: &SemanticChangeId,
        ) -> Result<Option<SemanticChange>, Self::Error> {
            Ok(None)
        }

        fn get_changes_since(
            &self,
            _base: &SemanticChangeId,
            _head: &SemanticChangeId,
        ) -> Result<Vec<SemanticChange>, Self::Error> {
            Ok(vec![])
        }

        fn get_branch(&self, _name: &BranchName) -> Result<Option<Branch>, Self::Error> {
            Ok(None)
        }

        fn create_branch(&self, _branch: &Branch) -> Result<(), Self::Error> {
            Ok(())
        }

        fn update_branch_head(
            &self,
            _name: &BranchName,
            _new_head: &SemanticChangeId,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn delete_branch(&self, _name: &BranchName) -> Result<(), Self::Error> {
            Ok(())
        }

        fn list_branches(&self) -> Result<Vec<Branch>, Self::Error> {
            Ok(vec![])
        }
        fn create_work_item(&self, _: &kin_model::WorkItem) -> Result<(), Self::Error> {
            Ok(())
        }
        fn get_work_item(
            &self,
            _: &kin_model::WorkId,
        ) -> Result<Option<kin_model::WorkItem>, Self::Error> {
            Ok(None)
        }
        fn list_work_items(
            &self,
            _: &kin_model::WorkFilter,
        ) -> Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn update_work_status(
            &self,
            _: &kin_model::WorkId,
            _: kin_model::WorkStatus,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
        fn delete_work_item(&self, _: &kin_model::WorkId) -> Result<(), Self::Error> {
            Ok(())
        }
        fn create_annotation(&self, _: &kin_model::Annotation) -> Result<(), Self::Error> {
            Ok(())
        }
        fn get_annotation(
            &self,
            _: &kin_model::AnnotationId,
        ) -> Result<Option<kin_model::Annotation>, Self::Error> {
            Ok(None)
        }
        fn list_annotations(
            &self,
            _: &kin_model::AnnotationFilter,
        ) -> Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
        fn update_annotation_staleness(
            &self,
            _: &kin_model::AnnotationId,
            _: kin_model::StalenessState,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
        fn delete_annotation(&self, _: &kin_model::AnnotationId) -> Result<(), Self::Error> {
            Ok(())
        }
        fn create_work_link(&self, _: &kin_model::WorkLink) -> Result<(), Self::Error> {
            Ok(())
        }
        fn delete_work_link(&self, _: &kin_model::WorkLink) -> Result<(), Self::Error> {
            Ok(())
        }
        fn get_work_for_scope(
            &self,
            _: &kin_model::WorkScope,
        ) -> Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_annotations_for_scope(
            &self,
            _: &kin_model::WorkScope,
        ) -> Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
        fn get_child_work_items(
            &self,
            _: &kin_model::WorkId,
        ) -> Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_implementors(
            &self,
            _: &kin_model::WorkId,
        ) -> Result<Vec<kin_model::WorkScope>, Self::Error> {
            Ok(vec![])
        }
        fn create_test_case(&self, _: &kin_model::verification::TestCase) -> Result<(), Self::Error> {
            Ok(())
        }
        fn get_test_case(&self, _: &kin_model::verification::TestId) -> Result<Option<kin_model::verification::TestCase>, Self::Error> {
            Ok(None)
        }
        fn get_tests_for_entity(&self, _: &EntityId) -> Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn delete_test_case(&self, _: &kin_model::verification::TestId) -> Result<(), Self::Error> {
            Ok(())
        }
        fn create_assertion(&self, _: &kin_model::verification::Assertion) -> Result<(), Self::Error> {
            Ok(())
        }
        fn get_assertion(&self, _: &kin_model::verification::AssertionId) -> Result<Option<kin_model::verification::Assertion>, Self::Error> {
            Ok(None)
        }
        fn get_coverage_summary(&self) -> Result<kin_model::verification::CoverageSummary, Self::Error> {
            Ok(kin_model::verification::CoverageSummary {
                total_entities: 0,
                covered_entities: 0,
                coverage_ratio: 0.0,
                missing_proof: vec![],
            })
        }
        // Phase 9 completion stubs
        fn create_verification_run(&self, _: &kin_model::verification::VerificationRun) -> Result<(), Self::Error> { Ok(()) }
        fn get_verification_run(&self, _: &kin_model::verification::VerificationRunId) -> Result<Option<kin_model::verification::VerificationRun>, Self::Error> { Ok(None) }
        fn list_runs_for_test(&self, _: &kin_model::verification::TestId) -> Result<Vec<kin_model::verification::VerificationRun>, Self::Error> { Ok(vec![]) }
        fn create_test_covers_entity(&self, _: &kin_model::verification::TestId, _: &kin_model::EntityId) -> Result<(), Self::Error> { Ok(()) }
        fn create_test_covers_contract(&self, _: &kin_model::verification::TestId, _: &kin_model::ContractId) -> Result<(), Self::Error> { Ok(()) }
        fn create_test_verifies_work(&self, _: &kin_model::verification::TestId, _: &kin_model::WorkId) -> Result<(), Self::Error> { Ok(()) }
        fn get_tests_covering_contract(&self, _: &kin_model::ContractId) -> Result<Vec<kin_model::verification::TestCase>, Self::Error> { Ok(vec![]) }
        fn get_tests_verifying_work(&self, _: &kin_model::WorkId) -> Result<Vec<kin_model::verification::TestCase>, Self::Error> { Ok(vec![]) }
        fn create_mock_hint(&self, _: &kin_model::verification::MockHint) -> Result<(), Self::Error> { Ok(()) }
        fn get_mock_hints_for_test(&self, _: &kin_model::verification::TestId) -> Result<Vec<kin_model::verification::MockHint>, Self::Error> { Ok(vec![]) }
        fn link_run_proves_entity(&self, _: &kin_model::verification::VerificationRunId, _: &kin_model::EntityId) -> Result<(), Self::Error> { Ok(()) }
        fn link_run_proves_work(&self, _: &kin_model::verification::VerificationRunId, _: &kin_model::WorkId) -> Result<(), Self::Error> { Ok(()) }
        fn get_contract_coverage_summary(&self) -> Result<kin_model::verification::ContractCoverageSummary, Self::Error> {
            Ok(kin_model::verification::ContractCoverageSummary { total_contracts: 0, covered_contracts: 0, coverage_ratio: 0.0, uncovered_contract_ids: vec![] })
        }
        fn create_actor(&self, _: &kin_model::provenance::Actor) -> Result<(), Self::Error> { Ok(()) }
        fn get_actor(&self, _: &kin_model::provenance::ActorId) -> Result<Option<kin_model::provenance::Actor>, Self::Error> { Ok(None) }
        fn list_actors(&self) -> Result<Vec<kin_model::provenance::Actor>, Self::Error> { Ok(vec![]) }
        fn create_delegation(&self, _: &kin_model::provenance::Delegation) -> Result<(), Self::Error> { Ok(()) }
        fn get_delegations_for_actor(&self, _: &kin_model::provenance::ActorId) -> Result<Vec<kin_model::provenance::Delegation>, Self::Error> { Ok(vec![]) }
        fn create_approval(&self, _: &kin_model::provenance::Approval) -> Result<(), Self::Error> { Ok(()) }
        fn get_approvals_for_change(&self, _: &SemanticChangeId) -> Result<Vec<kin_model::provenance::Approval>, Self::Error> { Ok(vec![]) }
        fn record_audit_event(&self, _: &kin_model::provenance::AuditEvent) -> Result<(), Self::Error> { Ok(()) }
        fn query_audit_events(&self, _: Option<&kin_model::provenance::ActorId>, _: usize) -> Result<Vec<kin_model::provenance::AuditEvent>, Self::Error> { Ok(vec![]) }
        fn upsert_shallow_file(&self, _: &kin_model::ShallowTrackedFile) -> Result<(), Self::Error> { Ok(()) }
        fn list_shallow_files(&self) -> Result<Vec<kin_model::ShallowTrackedFile>, Self::Error> { Ok(vec![]) }
        fn create_contract(&self, _: &kin_model::contract::Contract) -> Result<(), Self::Error> { Ok(()) }
        fn get_contract(&self, _: &kin_model::ids::ContractId) -> Result<Option<kin_model::contract::Contract>, Self::Error> { Ok(None) }
        fn list_contracts(&self) -> Result<Vec<kin_model::contract::Contract>, Self::Error> { Ok(vec![]) }
    }

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
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {}()", name),
            visibility: Visibility::Public,
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
            entity_deltas: vec![EntityDelta::Added(entity)],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };

        let diff = diff_from_change(&change);
        let store = MockGraphStore;
        let review = SemanticReview::review_from_diff(diff, &store).unwrap();

        assert_eq!(review.diff.entity_changes.len(), 1);
        assert!(review.impact.is_empty());
        assert_eq!(review.risk.overall_risk, kin_model::review::RiskLevel::Low);
    }
}
