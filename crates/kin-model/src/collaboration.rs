// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The replicated collaboration domain, in the form a repository transaction
//! can carry.
//!
//! [`RootBundle::collaboration`](crate::RootBundle) is documented as
//! "Replicated collaboration authority" and
//! [`RootBundle::has_same_replicated_truth`](crate::RootBundle::has_same_replicated_truth)
//! compares it alongside `history`, `ref_state` and `replication`. Until this
//! module existed, nothing could move it: no field of
//! [`RepositoryTransaction`](crate::RepositoryTransaction) named a collaboration
//! record, so two replicas could complete a successful transfer and still
//! disagree on a root the model says must match, with nothing erroring and no
//! test failing.
//!
//! # The collection list is a seam, and it is graded on the other side
//!
//! The seventeen collections below are the seventeen kin-db folds into the
//! collaboration root, in that order. Neither repository can see the other's
//! list at compile time, so the agreement between them is exactly the kind of
//! invariant that passes review on both sides and fails only where they meet.
//! [`COLLABORATION_COLLECTIONS`] exists so kin-db can assert the two lists name
//! the same things rather than trusting that they do. Adding a collection here
//! without adding it there, or the reverse, is meant to fail that assertion.
//!
//! # Canonical order, and why validation enforces it rather than sorting
//!
//! A transaction's identity is a persisted digest: it is stored in every commit
//! receipt and compared on idempotent replay, so two receivers that assemble
//! the same records in different orders must not produce two identities. The
//! crate has two ways to guarantee that, and this module uses the second.
//! [`CanonicalTransaction`](crate::repository) sorts `changes`,
//! `external_objects`, `aliases` and `ref_mutations` before it encodes them.
//! `WorkspaceSemanticDelta::validate` instead REFUSES a delta that is not
//! already in canonical order, so there is exactly one legal encoding and
//! sorting is unnecessary.
//!
//! Refusing is the better fit here. Sorting seventeen heterogeneous collections
//! needs a total order on seventeen value types, none of which derives one, and
//! it would put the canonicalization further away from the validation that has
//! to agree with it. Refusing needs one rule, stated once and applied
//! seventeen times: entries are STRICTLY INCREASING by the canonical encoding of
//! their key, where an unkeyed collection is its own key. Strictly, not merely
//! non-decreasing, so the same rule that fixes the order also rejects a
//! duplicate. `a_delta_out_of_canonical_order_is_refused_on_both_collection_kinds`
//! is what holds the two together.
//!
//! # Application is upsert by key, and replay is a no-op
//!
//! A keyed entry replaces whatever the receiver holds under that key. An
//! unkeyed entry is admitted if the receiver does not already hold an identical
//! one. Both are idempotent by construction, which is what a transfer needs:
//! kin-db reports `IdempotentReplay` for a pack it has already applied, and a
//! second application of the same delta must move no root.
//!
//! # What this deliberately cannot express
//!
//! There is no removal. A transfer that would have to DELETE a collaboration
//! record on the receiver cannot be described here, and the honest consequence
//! is that the two replicas' collaboration roots stay different and every
//! caller of `has_same_replicated_truth` says so. That is a loud failure rather
//! than a silent one, which is the property this whole module exists to
//! restore, and it is the boundary to revisit first if collaboration ever grows
//! a real tombstone.

use serde::{Deserialize, Serialize};

use schemars::JsonSchema;

use crate::contract::Contract;
use crate::error::{ModelError, Result};
use crate::identity::canonical_json_bytes;
use crate::ids::ContractId;
use crate::provenance::{Actor, ActorId, Approval, AuditEvent, Delegation};
use crate::review::{
    Review, ReviewAssignment, ReviewDecision, ReviewDiscussion, ReviewId, ReviewNote,
};
use crate::verification::{
    Assertion, AssertionId, MockHint, TestCase, TestId, VerificationRun, VerificationRunId,
};
use crate::work::{Annotation, AnnotationId, WorkId, WorkItem, WorkLink};

/// Every collection folded into the collaboration authority root, in fold
/// order.
///
/// kin-db's `collaboration_root` hashes exactly these, under the domain
/// separator `kin-repository-collaboration-root-v1`. This array is the half of
/// that agreement this crate can state; the assertion that both halves name the
/// same seventeen things lives in kin-db, because kin-db is the side that owns
/// the fold and can read both.
///
/// The order is the fold order rather than the field order of
/// [`CollaborationDelta`], and they are deliberately the same, so a reader
/// comparing the two sees one list rather than two.
pub const COLLABORATION_COLLECTIONS: [&str; 17] = [
    "work_items",
    "annotations",
    "work_links",
    "reviews",
    "review_decisions",
    "review_notes",
    "review_discussions",
    "review_assignments",
    "test_cases",
    "assertions",
    "verification_runs",
    "mock_hints",
    "contracts",
    "actors",
    "delegations",
    "approvals",
    "audit_events",
];

/// One entry of a keyed collaboration collection, carrying its key explicitly.
///
/// The receiver's snapshot holds these collections as maps, and this type is
/// one entry of one such map. The key travels rather than being re-derived on
/// arrival, which is not a convenience: `contracts` is keyed by `ContractId`
/// while [`Contract::id`] is an `EntityId`, so kin-db already derives that key
/// from the value at its own write site. A delta that shipped values alone
/// would make every receiver repeat that derivation, and a receiver that
/// derived it differently would land the record under a key the sender never
/// used, moving the collaboration root to a value the sender never had.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Keyed<K, V> {
    pub key: K,
    pub value: V,
}

impl<K, V> Keyed<K, V> {
    pub fn new(key: K, value: V) -> Self {
        Self { key, value }
    }
}

/// The collaboration records one repository transaction admits.
///
/// Seventeen collections, mirroring the receiver's own snapshot layout: a
/// keyed collection travels as [`Keyed`] entries, an unkeyed one as bare
/// values. Every collection is empty in the common case, and an entirely empty
/// delta is refused by [`Self::validate`] rather than admitted as a no-op, so a
/// transaction either carries collaboration or omits the field.
///
/// This type is persisted through the same positional MessagePack encoding as
/// the transaction that carries it, so a field added here must be appended
/// after every existing field, exactly as on
/// [`RepositoryTransaction`](crate::RepositoryTransaction). Adding one in the
/// middle reassigns every field after it and silently mis-decodes stores
/// already on disk.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollaborationDelta {
    pub work_items: Vec<Keyed<WorkId, WorkItem>>,
    pub annotations: Vec<Keyed<AnnotationId, Annotation>>,
    pub work_links: Vec<WorkLink>,
    pub reviews: Vec<Keyed<ReviewId, Review>>,
    /// A review's decision history, whole.
    ///
    /// The receiver holds this as `ReviewId -> Vec<ReviewDecision>` and a
    /// [`ReviewDecision`] carries no identity of its own, not even the review
    /// it belongs to. So the unit that travels is the whole history under its
    /// review, and the inner order is the history's own and is preserved
    /// rather than canonicalized.
    pub review_decisions: Vec<Keyed<ReviewId, Vec<ReviewDecision>>>,
    pub review_notes: Vec<ReviewNote>,
    pub review_discussions: Vec<ReviewDiscussion>,
    /// A review's assignments, whole, for the reason above. A
    /// [`ReviewAssignment`] does carry its `review_id`, but the receiver still
    /// holds them grouped, and shipping the group keeps the delta's shape and
    /// the snapshot's shape the same.
    pub review_assignments: Vec<Keyed<ReviewId, Vec<ReviewAssignment>>>,
    pub test_cases: Vec<Keyed<TestId, TestCase>>,
    pub assertions: Vec<Keyed<AssertionId, Assertion>>,
    pub verification_runs: Vec<Keyed<VerificationRunId, VerificationRun>>,
    pub mock_hints: Vec<MockHint>,
    /// Keyed by `ContractId` while [`Contract::id`] is a [`crate::ids::EntityId`]. See
    /// [`Keyed`] for why the key travels rather than being re-derived.
    pub contracts: Vec<Keyed<ContractId, Contract>>,
    pub actors: Vec<Keyed<ActorId, Actor>>,
    pub delegations: Vec<Delegation>,
    pub approvals: Vec<Approval>,
    pub audit_events: Vec<AuditEvent>,
}

impl CollaborationDelta {
    /// Whether this delta admits nothing at all.
    ///
    /// Kept separate from [`Self::validate`] because the transaction's own
    /// "did this transaction do anything" check asks the question before it
    /// knows whether the delta is valid.
    pub fn is_empty(&self) -> bool {
        self.record_count() == 0
    }

    /// How many records this delta admits, across every collection.
    ///
    /// A keyed group counts as one record, not as its inner length, because one
    /// group is one thing the receiver upserts.
    pub fn record_count(&self) -> usize {
        self.work_items.len()
            + self.annotations.len()
            + self.work_links.len()
            + self.reviews.len()
            + self.review_decisions.len()
            + self.review_notes.len()
            + self.review_discussions.len()
            + self.review_assignments.len()
            + self.test_cases.len()
            + self.assertions.len()
            + self.verification_runs.len()
            + self.mock_hints.len()
            + self.contracts.len()
            + self.actors.len()
            + self.delegations.len()
            + self.approvals.len()
            + self.audit_events.len()
    }

    /// Refuse a delta that admits nothing, or that is not in the one canonical
    /// order.
    ///
    /// The order check is the load-bearing half. See the module header: it is
    /// what makes transaction identity independent of the order a sender
    /// happened to assemble records in, without any sorting, and rejecting
    /// duplicates falls out of requiring STRICT increase.
    pub fn validate(&self) -> Result<()> {
        if self.is_empty() {
            return Err(ModelError::InvalidOperation(
                "collaboration delta admits no records".to_string(),
            ));
        }

        keyed_order("work_items", &self.work_items)?;
        keyed_order("annotations", &self.annotations)?;
        value_order("work_links", &self.work_links)?;
        keyed_order("reviews", &self.reviews)?;
        keyed_order("review_decisions", &self.review_decisions)?;
        value_order("review_notes", &self.review_notes)?;
        value_order("review_discussions", &self.review_discussions)?;
        keyed_order("review_assignments", &self.review_assignments)?;
        keyed_order("test_cases", &self.test_cases)?;
        keyed_order("assertions", &self.assertions)?;
        keyed_order("verification_runs", &self.verification_runs)?;
        value_order("mock_hints", &self.mock_hints)?;
        keyed_order("contracts", &self.contracts)?;
        keyed_order("actors", &self.actors)?;
        value_order("delegations", &self.delegations)?;
        value_order("approvals", &self.approvals)?;
        value_order("audit_events", &self.audit_events)?;

        if self
            .review_decisions
            .iter()
            .any(|entry| entry.value.is_empty())
        {
            return Err(ModelError::InvalidOperation(
                "collaboration delta carries a review with an empty decision history".to_string(),
            ));
        }
        if self
            .review_assignments
            .iter()
            .any(|entry| entry.value.is_empty())
        {
            return Err(ModelError::InvalidOperation(
                "collaboration delta carries a review with an empty assignment set".to_string(),
            ));
        }
        Ok(())
    }
}

/// Every entry strictly increasing by the canonical encoding of its KEY.
///
/// Keying on the key alone rather than on the whole entry is deliberate: two
/// entries under one key are ambiguous on arrival whatever their values are,
/// and ordering by the whole entry would admit that pair as strictly
/// increasing.
fn keyed_order<K: Serialize, V>(collection: &str, entries: &[Keyed<K, V>]) -> Result<()> {
    let mut previous: Option<Vec<u8>> = None;
    for entry in entries {
        let encoded = canonical_json_bytes(&entry.key)?;
        if let Some(previous) = &previous {
            if *previous >= encoded {
                return Err(ModelError::InvalidOperation(format!(
                    "collaboration delta `{collection}` is not strictly increasing by key, so \
                     either it repeats a key or two senders holding the same records would \
                     produce two transaction identities"
                )));
            }
        }
        previous = Some(encoded);
    }
    Ok(())
}

/// Every value strictly increasing by its own canonical encoding.
///
/// An unkeyed collection is its own key, so strict increase rejects an exact
/// duplicate, which for a set-shaped collection is the whole of uniqueness.
fn value_order<V: Serialize>(collection: &str, values: &[V]) -> Result<()> {
    let mut previous: Option<Vec<u8>> = None;
    for value in values {
        let encoded = canonical_json_bytes(value)?;
        if let Some(previous) = &previous {
            if *previous >= encoded {
                return Err(ModelError::InvalidOperation(format!(
                    "collaboration delta `{collection}` is not strictly increasing, so either it \
                     repeats a record or two senders holding the same records would produce two \
                     transaction identities"
                )));
            }
        }
        previous = Some(encoded);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use uuid::Uuid;

    use crate::ids::{EntityId, Hash256, SemanticChangeId};
    use crate::provenance::{ActorKind, ApprovalDecision, ApprovalId, AuditEventId, DelegationId};
    use crate::review::{
        ReviewCompletionState, ReviewDecisionState, ReviewDiscussionId, ReviewDiscussionState,
        ReviewNoteId,
    };
    use crate::timestamp::Timestamp;
    use crate::verification::{MockHintId, MockStrategy, TestKind, TestRunner, VerificationStatus};
    use crate::work::{
        AnnotationKind, IdentityRef, Priority, StalenessState, WorkKind, WorkScope, WorkStatus,
    };
    use crate::ContractKind;

    fn at() -> Timestamp {
        Timestamp::from(chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap())
    }

    fn who() -> IdentityRef {
        IdentityRef::human("reviewer")
    }

    fn uuid(byte: u128) -> Uuid {
        Uuid::from_u128(byte)
    }

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn scope() -> WorkScope {
        WorkScope::Entity(EntityId(uuid(0x5c0)))
    }

    pub(crate) fn work_item(byte: u128) -> WorkItem {
        WorkItem {
            work_id: WorkId(uuid(byte)),
            kind: WorkKind::Task,
            title: "title".to_string(),
            description: "description".to_string(),
            status: WorkStatus::Proposed,
            priority: Priority::Medium,
            scopes: vec![scope()],
            acceptance_criteria: Vec::new(),
            external_refs: Vec::new(),
            created_by: who(),
            created_at: at(),
        }
    }

    fn annotation(byte: u128) -> Annotation {
        Annotation {
            annotation_id: AnnotationId(uuid(byte)),
            kind: AnnotationKind::Comment,
            body: "body".to_string(),
            scopes: vec![scope()],
            anchored_fingerprint: None,
            authored_by: who(),
            created_at: at(),
            staleness: StalenessState::Fresh,
        }
    }

    fn review(byte: u128) -> Review {
        Review {
            review_id: ReviewId(uuid(byte)),
            title: "review".to_string(),
            base_ref: "main".to_string(),
            head_ref: "topic".to_string(),
            state: ReviewDecisionState::Pending,
            completion: ReviewCompletionState::InReview,
            created_by: who(),
            created_at: at(),
            updated_at: at(),
            scopes: vec![scope()],
        }
    }

    pub(crate) fn review_note(byte: u128) -> ReviewNote {
        ReviewNote {
            note_id: ReviewNoteId(uuid(byte)),
            review_id: ReviewId(uuid(0xc0_11_ab_00)),
            body: "note".to_string(),
            scope: Some(scope()),
            authored_by: who(),
            created_at: at(),
        }
    }

    fn test_case(byte: u8) -> TestCase {
        TestCase {
            test_id: TestId(hash(byte)),
            name: "case".to_string(),
            language: "rust".to_string(),
            kind: TestKind::Unit,
            scopes: vec![scope()],
            runner: TestRunner::Cargo,
            file_origin: None,
        }
    }

    /// One populated instance of every collection, with distinct ids, so a case
    /// table can seed exactly one collection at a time.
    fn seeded() -> CollaborationDelta {
        CollaborationDelta {
            work_items: vec![Keyed::new(WorkId(uuid(1)), work_item(1))],
            annotations: vec![Keyed::new(AnnotationId(uuid(2)), annotation(2))],
            work_links: vec![WorkLink::Affects {
                work_id: WorkId(uuid(1)),
                scope: scope(),
            }],
            reviews: vec![Keyed::new(ReviewId(uuid(4)), review(4))],
            review_decisions: vec![Keyed::new(
                ReviewId(uuid(4)),
                vec![ReviewDecision {
                    reviewer: who(),
                    state: ReviewDecisionState::Approved,
                    comment: None,
                    decided_at: at(),
                }],
            )],
            review_notes: vec![review_note(6)],
            review_discussions: vec![ReviewDiscussion {
                discussion_id: ReviewDiscussionId(uuid(7)),
                review_id: ReviewId(uuid(4)),
                scope: None,
                state: ReviewDiscussionState::Open,
                comments: Vec::new(),
                created_at: at(),
            }],
            review_assignments: vec![Keyed::new(
                ReviewId(uuid(4)),
                vec![ReviewAssignment {
                    review_id: ReviewId(uuid(4)),
                    reviewer: who(),
                    assigned_at: at(),
                    assigned_by: who(),
                }],
            )],
            test_cases: vec![Keyed::new(TestId(hash(9)), test_case(9))],
            assertions: vec![Keyed::new(
                AssertionId(hash(10)),
                Assertion {
                    assertion_id: AssertionId(hash(10)),
                    summary: "summary".to_string(),
                    expected_behavior: "behaviour".to_string(),
                    target_scope: scope(),
                },
            )],
            verification_runs: vec![Keyed::new(
                VerificationRunId(hash(11)),
                VerificationRun {
                    run_id: VerificationRunId(hash(11)),
                    test_ids: vec![TestId(hash(9))],
                    status: VerificationStatus::Passing,
                    runner: TestRunner::Cargo,
                    started_at: at(),
                    finished_at: None,
                    duration_ms: None,
                    evidence_blob: None,
                    exit_code: None,
                },
            )],
            mock_hints: vec![MockHint {
                hint_id: MockHintId(hash(12)),
                test_id: TestId(hash(9)),
                dependency_scope: scope(),
                strategy: MockStrategy::Stub,
            }],
            contracts: vec![Keyed::new(
                ContractId(uuid(13)),
                Contract {
                    id: EntityId(uuid(13)),
                    kind: ContractKind::OpenApi,
                    name: "contract".to_string(),
                    schema_hash: hash(13),
                    producers: Vec::new(),
                    consumers: Vec::new(),
                    version: None,
                },
            )],
            actors: vec![Keyed::new(
                ActorId(hash(14)),
                Actor {
                    actor_id: ActorId(hash(14)),
                    kind: ActorKind::Human,
                    display_name: "actor".to_string(),
                    external_refs: Vec::new(),
                },
            )],
            delegations: vec![Delegation {
                delegation_id: DelegationId(hash(15)),
                principal: ActorId(hash(14)),
                delegate: ActorId(hash(0x8e)),
                scope: vec![scope()],
                started_at: at(),
                ended_at: None,
            }],
            approvals: vec![Approval {
                approval_id: ApprovalId(hash(16)),
                change_id: SemanticChangeId::from_hash(hash(0x81)),
                approver: ActorId(hash(14)),
                decision: ApprovalDecision::Approved,
                reason: "reason".to_string(),
                timestamp: at(),
            }],
            audit_events: vec![AuditEvent {
                event_id: AuditEventId(hash(17)),
                actor_id: ActorId(hash(14)),
                action: "action".to_string(),
                target_scope: None,
                timestamp: at(),
                details: None,
            }],
        }
    }

    /// A minimal valid delta: one review note and nothing else.
    ///
    /// `repository.rs` builds its transaction fixtures from this, so the shape
    /// that reaches the transaction encoding tests is the same shape a real
    /// `kin review note` produces rather than a maximal one only a test builds.
    pub(crate) fn sample_delta() -> CollaborationDelta {
        CollaborationDelta {
            review_notes: vec![review_note(6)],
            ..CollaborationDelta::default()
        }
    }

    fn messagepack_array_len(bytes: &[u8]) -> usize {
        match bytes.first() {
            Some(marker) if (0x90..=0x9f).contains(marker) => usize::from(marker & 0x0f),
            Some(0xdc) => usize::from(u16::from_be_bytes([bytes[1], bytes[2]])),
            other => panic!("not a MessagePack array: {other:?}"),
        }
    }

    /// Every collection the collaboration root folds is carried, reaches the
    /// wire distinctly, and is named in [`COLLABORATION_COLLECTIONS`].
    ///
    /// This is the arity guard, and it is the one that has to fail closed. The
    /// defect this whole module exists to close was a domain classified as
    /// replicated truth that no transaction could move, and the way it stayed
    /// invisible was that no test ever populated it. So a collection added to
    /// the struct without a case here stops this test on the arity assertion
    /// rather than slipping past with the same silence.
    ///
    /// Each case seeds exactly one collection and requires the encoding to
    /// differ from the empty delta AND from every other case. Differing from
    /// empty alone would pass for a field that serializes but is never read;
    /// differing from every sibling is what proves the field occupies its own
    /// position rather than aliasing a neighbour's.
    ///
    /// Falsify by deleting any one arm of `seeded()`, which leaves that case's
    /// delta equal to the empty one, or by giving two collections the same
    /// content, which collides their encodings.
    #[test]
    fn every_collaboration_collection_is_carried_and_reaches_the_wire() {
        type Case = (&'static str, fn(&mut CollaborationDelta));
        let cases: [Case; 17] = [
            ("work_items", |d| d.work_items = seeded().work_items),
            ("annotations", |d| d.annotations = seeded().annotations),
            ("work_links", |d| d.work_links = seeded().work_links),
            ("reviews", |d| d.reviews = seeded().reviews),
            ("review_decisions", |d| {
                d.review_decisions = seeded().review_decisions
            }),
            ("review_notes", |d| d.review_notes = seeded().review_notes),
            ("review_discussions", |d| {
                d.review_discussions = seeded().review_discussions
            }),
            ("review_assignments", |d| {
                d.review_assignments = seeded().review_assignments
            }),
            ("test_cases", |d| d.test_cases = seeded().test_cases),
            ("assertions", |d| d.assertions = seeded().assertions),
            ("verification_runs", |d| {
                d.verification_runs = seeded().verification_runs
            }),
            ("mock_hints", |d| d.mock_hints = seeded().mock_hints),
            ("contracts", |d| d.contracts = seeded().contracts),
            ("actors", |d| d.actors = seeded().actors),
            ("delegations", |d| d.delegations = seeded().delegations),
            ("approvals", |d| d.approvals = seeded().approvals),
            ("audit_events", |d| d.audit_events = seeded().audit_events),
        ];

        let empty = CollaborationDelta::default();
        let empty_wire = rmp_serde::to_vec(&empty).unwrap();
        assert_eq!(
            messagepack_array_len(&empty_wire),
            cases.len(),
            "CollaborationDelta gained or lost a field; give it a case here, a name in \
             COLLABORATION_COLLECTIONS, and an apply arm in kin-db, or the collaboration root \
             moves for a reason no transaction can carry"
        );
        assert_eq!(
            COLLABORATION_COLLECTIONS.len(),
            cases.len(),
            "COLLABORATION_COLLECTIONS and this case table describe different domains"
        );
        for (index, (field, _)) in cases.iter().enumerate() {
            assert_eq!(
                COLLABORATION_COLLECTIONS[index], *field,
                "case {index} names `{field}` where COLLABORATION_COLLECTIONS names `{}`; kin-db \
                 folds the root in that order and reads this list to check its own",
                COLLABORATION_COLLECTIONS[index]
            );
        }

        assert!(
            empty.validate().is_err(),
            "an empty delta must be refused rather than admitted as a no-op"
        );

        let mut seen: Vec<(&str, Vec<u8>)> = Vec::new();
        for (field, seed) in cases {
            let mut candidate = CollaborationDelta::default();
            seed(&mut candidate);
            assert!(
                !candidate.is_empty(),
                "the `{field}` case seeded nothing, so it proves nothing about `{field}`"
            );
            candidate
                .validate()
                .unwrap_or_else(|error| panic!("the `{field}` case must be valid: {error}"));
            let wire = rmp_serde::to_vec(&candidate).unwrap();
            assert_ne!(
                wire, empty_wire,
                "seeding `{field}` did not change the encoding, so `{field}` never reaches the \
                 wire and a receiver can never learn about it"
            );
            for (other, other_wire) in &seen {
                assert_ne!(
                    wire, *other_wire,
                    "`{field}` and `{other}` encode identically, so one of them is not in its own \
                     position"
                );
            }
            seen.push((field, wire));
        }
    }

    /// A round trip through both encodings, for a delta that populates
    /// everything at once.
    #[test]
    fn a_fully_populated_delta_round_trips_through_both_encodings() {
        let delta = seeded();
        delta.validate().unwrap();
        assert_eq!(delta.record_count(), 17);

        let positional: CollaborationDelta =
            rmp_serde::from_slice(&rmp_serde::to_vec(&delta).unwrap()).unwrap();
        assert_eq!(positional, delta);

        let named: CollaborationDelta =
            serde_json::from_slice(&serde_json::to_vec(&delta).unwrap()).unwrap();
        assert_eq!(named, delta);
    }

    /// The order rule, on both collection kinds.
    ///
    /// This is the property that makes transaction identity independent of the
    /// order a sender assembled records in without any sorting. If it ever
    /// stops holding, either the delta has to be sorted inside
    /// `CanonicalTransaction` or two receivers holding the same records will
    /// disagree on one transaction hash and idempotent replay will stop
    /// recognising its own work.
    #[test]
    fn a_delta_out_of_canonical_order_is_refused_on_both_collection_kinds() {
        let ordered = |mut delta: CollaborationDelta| {
            delta.work_items = vec![
                Keyed::new(WorkId(uuid(1)), work_item(1)),
                Keyed::new(WorkId(uuid(2)), work_item(2)),
            ];
            delta.review_notes = vec![review_note(1), review_note(2)];
            delta
        };

        let good = ordered(CollaborationDelta::default());
        good.validate()
            .expect("the control: the ascending fixture must be valid");

        let mut keyed_descending = good.clone();
        keyed_descending.work_items.reverse();
        let error = keyed_descending.validate().unwrap_err().to_string();
        assert!(
            error.contains("work_items") && error.contains("strictly increasing"),
            "a descending keyed collection must be refused by name, got: {error}"
        );

        let mut value_descending = good.clone();
        value_descending.review_notes.reverse();
        let error = value_descending.validate().unwrap_err().to_string();
        assert!(
            error.contains("review_notes") && error.contains("strictly increasing"),
            "a descending unkeyed collection must be refused by name, got: {error}"
        );

        let mut repeated_key = good.clone();
        repeated_key.work_items = vec![
            Keyed::new(WorkId(uuid(1)), work_item(1)),
            Keyed::new(WorkId(uuid(1)), work_item(2)),
        ];
        assert!(
            repeated_key.validate().is_err(),
            "two entries under one key are ambiguous on arrival and must be refused, even though \
             their values differ and the whole entries are strictly increasing"
        );

        let mut repeated_value = good;
        repeated_value.review_notes = vec![review_note(1), review_note(1)];
        assert!(
            repeated_value.validate().is_err(),
            "an exact duplicate in an unkeyed collection must be refused"
        );
    }

    /// A keyed group that carries no members is refused.
    ///
    /// An empty group would upsert an empty vector over whatever the receiver
    /// holds, which is a deletion wearing an admission's clothes, and this delta
    /// deliberately cannot express deletion.
    #[test]
    fn a_keyed_group_with_no_members_is_refused() {
        let decisions = CollaborationDelta {
            review_decisions: vec![Keyed::new(ReviewId(uuid(4)), Vec::new())],
            ..CollaborationDelta::default()
        };
        assert!(decisions.validate().is_err());

        let assignments = CollaborationDelta {
            review_assignments: vec![Keyed::new(ReviewId(uuid(4)), Vec::new())],
            ..CollaborationDelta::default()
        };
        assert!(assignments.validate().is_err());
    }
}
