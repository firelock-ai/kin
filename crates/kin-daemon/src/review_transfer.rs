// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Review records a repository transfer admits into this daemon's replica.
//!
//! A collaboration pack lands in repository authority like any other pack. What
//! is particular to it is the live graph. Review writes are planned against the
//! live graph, so records that reached authority without reaching the graph
//! under the locks a review write holds could be overwritten by the next write
//! planned from it. A received review record therefore lands the way a review
//! write does: the caller holds the coordination gate and a graph-authority
//! mutation guard, this takes the persistence lock, and the live graph follows
//! authority before any of them is released.

use std::collections::HashMap;

use kin_db::{RepositoryAuthorityManager, StorageBackend};
use kin_model::review::ReviewId;
use kin_model::{AuthorId, CollaborationDelta, RefName, RepositoryId};
use kin_remote::repository_transfer::{
    RepositoryTransferApplyOutcome, RepositoryTransferError, RepositoryTransferPack,
    RepositoryTransferReceipt,
};
use kin_review::write::{ReviewGroup, ReviewWrite};

use crate::state::{DaemonEvent, DaemonState};

/// Admit one collaboration pack and bring the live graph to what authority now
/// holds.
///
/// The caller holds `coordination_gate` and a graph-authority mutation guard.
/// Returns the receipt and, when authority moved but the live graph could not
/// follow it, what went wrong. The records are durable either way, and a caller
/// told the admission failed would retry a publication that already happened.
pub(crate) fn admit_review_records(
    state: &DaemonState,
    authority: &RepositoryAuthorityManager<dyn StorageBackend>,
    repository_id: &RepositoryId,
    destination_ref: &RefName,
    actor: AuthorId,
    pack: &RepositoryTransferPack,
) -> Result<(RepositoryTransferReceipt, Option<String>), RepositoryTransferError> {
    let _persistence = state.persist_lock.lock().map_err(|_| {
        RepositoryTransferError::Storage("daemon persistence lock poisoned".to_string())
    })?;
    let receipt = crate::api::apply_received_repository_transfer_pack(
        state,
        authority,
        repository_id,
        destination_ref,
        actor,
        pack,
    )?;
    // A replay was followed when it first landed.
    if receipt.outcome != RepositoryTransferApplyOutcome::Committed {
        return Ok((receipt, None));
    }
    let stale = follow_review_records(state, &receipt, pack.collaboration.as_ref()).err();
    Ok((receipt, stale))
}

fn follow_review_records(
    state: &DaemonState,
    receipt: &RepositoryTransferReceipt,
    records: Option<&CollaborationDelta>,
) -> Result<(), String> {
    let committed = &receipt.authority_receipt;
    state
        .record_repository_authority_commit(committed.generation)
        .map_err(|error| format!("record repository authority generation: {error}"))?;
    for write in records.map(review_writes).unwrap_or_default() {
        write
            .apply_to(state.graph.as_ref())
            .map_err(|error| format!("bring the daemon's review state to authority: {error}"))?;
    }
    state.bump_version();
    state.mark_dirty();
    state.emit_event(DaemonEvent::GraphRootChanged {
        old_root_hash: None,
        new_root_hash: "review-state".to_string(),
    });
    state.emit_event(DaemonEvent::RepositoryAuthorityChanged {
        repository_id: committed.repository_id.to_string(),
        operation_id: committed.operation_id,
        previous_generation: committed.roots_before.generation,
        new_generation: committed.generation,
    });
    Ok(())
}

/// `records` as the review writes the live graph applies: the provenance they
/// carry first, so every actor an audit event names exists before any review
/// does, then one write per review.
fn review_writes(records: &CollaborationDelta) -> Vec<ReviewWrite> {
    let mut by_review: HashMap<ReviewId, ReviewWrite> = HashMap::new();
    for entry in &records.reviews {
        by_review.entry(entry.key).or_default().review = Some(entry.value.clone());
    }
    for entry in &records.review_decisions {
        by_review.entry(entry.key).or_default().decisions = Some(ReviewGroup {
            review_id: entry.key,
            entries: entry.value.clone(),
        });
    }
    for note in &records.review_notes {
        by_review
            .entry(note.review_id)
            .or_default()
            .notes
            .push(note.clone());
    }
    for discussion in &records.review_discussions {
        by_review
            .entry(discussion.review_id)
            .or_default()
            .discussions
            .push(discussion.clone());
    }
    for entry in &records.review_assignments {
        by_review.entry(entry.key).or_default().assignments = Some(ReviewGroup {
            review_id: entry.key,
            entries: entry.value.clone(),
        });
    }
    let provenance = ReviewWrite {
        actors: records
            .actors
            .iter()
            .map(|entry| entry.value.clone())
            .collect(),
        audit_events: records.audit_events.clone(),
        ..ReviewWrite::default()
    };
    std::iter::once(provenance)
        .chain(by_review.into_values())
        .filter(|write| !write.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::review::{
        Review, ReviewCompletionState, ReviewDecision, ReviewDecisionState, ReviewNote,
        ReviewNoteId,
    };
    use kin_model::{IdentityRef, Keyed, ReviewStore, Timestamp};

    fn review(id: ReviewId, state: ReviewDecisionState) -> Review {
        Review {
            review_id: id,
            title: "Carry reviews through a pull".to_string(),
            base_ref: "main".to_string(),
            head_ref: "feature/reviews".to_string(),
            state,
            completion: ReviewCompletionState::InReview,
            created_by: IdentityRef::human("troy"),
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
            scopes: vec![],
        }
    }

    /// Records a pull admits reach the live graph whole: a new review with its
    /// note, and a decision appended to a review the graph already held, which
    /// is how the holder's history arrives in a pack, as its prefix.
    ///
    /// Falsify by dropping the decisions arm of `review_writes`: the held
    /// review keeps one decision and the assertion on two goes red.
    #[test]
    fn admitted_records_bring_the_live_graph_to_authority() {
        let graph = kin_db::InMemoryGraph::new();
        let held = ReviewId::new();
        let first = ReviewDecision {
            reviewer: IdentityRef::human("alice"),
            state: ReviewDecisionState::NeedsWork,
            comment: None,
            decided_at: Timestamp::now(),
        };
        graph
            .create_review(&review(held, ReviewDecisionState::NeedsWork))
            .unwrap();
        graph.add_review_decision(&held, &first).unwrap();

        let arrived = ReviewId::new();
        let second = ReviewDecision {
            reviewer: IdentityRef::human("bob"),
            state: ReviewDecisionState::Approved,
            comment: None,
            decided_at: Timestamp::now(),
        };
        let note = ReviewNote {
            note_id: ReviewNoteId::new(),
            review_id: arrived,
            body: "looks right".to_string(),
            scope: None,
            authored_by: IdentityRef::human("bob"),
            created_at: Timestamp::now(),
        };
        let records = CollaborationDelta {
            reviews: vec![
                Keyed::new(held, review(held, ReviewDecisionState::Approved)),
                Keyed::new(arrived, review(arrived, ReviewDecisionState::Pending)),
            ],
            review_decisions: vec![Keyed::new(held, vec![first, second])],
            review_notes: vec![note.clone()],
            ..CollaborationDelta::default()
        };

        for write in review_writes(&records) {
            write.apply_to(&graph).unwrap();
        }

        assert_eq!(
            graph.get_review(&held).unwrap().unwrap().state,
            ReviewDecisionState::Approved
        );
        assert_eq!(graph.get_review_decisions(&held).unwrap().len(), 2);
        assert!(graph.get_review(&arrived).unwrap().is_some());
        assert_eq!(graph.get_review_notes(&arrived).unwrap(), vec![note]);
    }
}
