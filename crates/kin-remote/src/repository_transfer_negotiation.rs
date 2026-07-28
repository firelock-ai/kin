// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Negotiation and orchestration for exact repository-v6 transfer.
//!
//! [`crate::repository_transfer`] owns the pack: what it contains, how it is
//! validated, and how it is published. This module owns the two questions that
//! sit on either side of it. Before a pack exists: which exact changes are
//! missing on the receiving replica, and is that gap a fast-forward at all.
//! After a pack is published: does the returned receipt actually bind the pack
//! that was sent, or is the caller being told a transfer happened that did not.
//!
//! Both directions run the same negotiation with the roles swapped. A push
//! makes the remote the receiver, so the local replica holds the history and
//! computes the closure itself. A pull makes the local replica the receiver, so
//! the remote holds the history and its export computes the closure. Neither
//! direction has force semantics: a gap that is not a fast-forward is refused
//! with the two heads named, never rewritten.
//!
//! Negotiation reads exact semantic history only. It never consults a checkout,
//! a Git object directory, or a filesystem heuristic to decide what a replica
//! holds.

use std::collections::{HashMap, HashSet};

use kin_db::{RepositoryAuthorityManager, StorageBackend};
use kin_model::{AuthorId, RefName, RepositoryId, SemanticChange, SemanticChangeId};
use serde::{Deserialize, Serialize};

use crate::repository_transfer::{
    apply_repository_transfer_pack, build_repository_transfer_pack, repository_transfer_status,
    RepositoryRefAdvertisement, RepositoryTransferError, RepositoryTransferExpectation,
    RepositoryTransferPack, RepositoryTransferReceipt, RepositoryTransferStatus, Result,
    REPOSITORY_TRANSFER_PROTOCOL, REPOSITORY_TRANSFER_SCHEMA_VERSION,
};

fn invalid(message: impl Into<String>) -> RepositoryTransferError {
    RepositoryTransferError::Invalid(message.into())
}

fn conflict(message: impl Into<String>) -> RepositoryTransferError {
    RepositoryTransferError::Conflict(message.into())
}

fn storage(error: impl std::fmt::Display) -> RepositoryTransferError {
    RepositoryTransferError::Storage(error.to_string())
}

/// Which replica receives the transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryTransferDirection {
    /// The local replica sends; the remote publishes.
    Push,
    /// The remote sends; the local replica publishes.
    Pull,
}

impl RepositoryTransferDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Pull => "pull",
        }
    }
}

/// How an advertised head sits against exact local history.
///
/// This is deliberately the only question local history can answer on its own.
/// A replica knows its own ancestors; it cannot know whether a head it has
/// never admitted is a descendant of its own or an unrelated line. Callers turn
/// [`Self::Unreachable`] into a direction-specific refusal rather than guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAncestry {
    /// The advertised head is the local head.
    Same,
    /// The advertised head is a proper ancestor of the local head, with
    /// `distance` exact changes between them.
    Ancestor { distance: usize },
    /// The local replica has never admitted the advertised head, so the
    /// advertised head is not an ancestor of the local head.
    Unreachable,
}

/// What negotiation decided before any authority moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepositoryTransferPlan {
    /// Both replicas resolve the ref to the same exact change. Nothing moves.
    UpToDate { head: Option<SemanticChangeId> },
    /// The receiving head is an ancestor of the sending head. `change_count` is
    /// the exact number of changes the sender will pack, and is `None` when the
    /// sender is the remote, because only the exporting replica can count them.
    FastForward {
        source_head: SemanticChangeId,
        destination_head: Option<SemanticChangeId>,
        change_count: Option<usize>,
    },
}

/// One completed negotiation, including the receipt when history moved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepositoryTransferOutcome {
    pub direction: RepositoryTransferDirection,
    pub repository_id: RepositoryId,
    pub source_ref: RefName,
    pub destination_ref: RefName,
    pub plan: RepositoryTransferPlan,
    /// Absent exactly when the plan was [`RepositoryTransferPlan::UpToDate`].
    pub receipt: Option<RepositoryTransferReceipt>,
}

impl RepositoryTransferOutcome {
    /// True when this negotiation published a repository transaction.
    pub fn moved_history(&self) -> bool {
        self.receipt.is_some()
    }
}

/// The wire seam a negotiation drives.
///
/// The trait exists so negotiation can be proven against a real peer without
/// being written against one specific host. Implementations are transport only:
/// they carry exact envelopes and surface peer refusals unchanged. They do not
/// build packs, relax limits, or decide what a replica holds.
pub trait RepositoryTransferTransport {
    /// Every published ref, plus the default ref a fresh replica adopts.
    fn advertise_refs(&self, repository_id: &RepositoryId) -> Result<RepositoryRefAdvertisement>;

    /// The peer's exact lease for one destination ref.
    fn transfer_status(
        &self,
        repository_id: &RepositoryId,
        destination_ref: &RefName,
    ) -> Result<RepositoryTransferStatus>;

    /// Ask the peer to build the pack that closes `expectation`'s gap.
    fn export_pack(
        &self,
        repository_id: &RepositoryId,
        source_ref: &RefName,
        expectation: &RepositoryTransferExpectation,
    ) -> Result<RepositoryTransferPack>;

    /// Ask the peer to validate and publish one exact pack.
    fn receive_pack(
        &self,
        repository_id: &RepositoryId,
        destination_ref: &RefName,
        pack: &RepositoryTransferPack,
    ) -> Result<RepositoryTransferReceipt>;
}

/// Classify `advertised` against `local_head` using exact local history only.
///
/// An absent `local_head` makes any advertised head unreachable: a replica with
/// no history on the ref has admitted nothing.
pub fn classify_local_ancestry(
    changes: &HashMap<SemanticChangeId, SemanticChange>,
    local_head: Option<SemanticChangeId>,
    advertised: SemanticChangeId,
) -> Result<LocalAncestry> {
    let Some(local_head) = local_head else {
        return Ok(LocalAncestry::Unreachable);
    };
    if local_head == advertised {
        return Ok(LocalAncestry::Same);
    }

    // Walk back from the local head and stop at the advertised change, which is
    // exactly how the fast-forward closure is collected when the pack is built.
    // Counting "reachable from the local head but not from the advertised head"
    // instead would under-count a merge: a shared ancestor reachable from the
    // local head by a path that never passes through the advertised change is
    // carried by the pack, and a plan that omitted it would report a smaller
    // transfer than the one that actually runs.
    let mut distance = 0usize;
    let mut visited = HashSet::new();
    let mut stack = vec![local_head];
    let mut reached_advertised = false;
    while let Some(id) = stack.pop() {
        if id == advertised {
            reached_advertised = true;
            continue;
        }
        if !visited.insert(id) {
            continue;
        }
        let change = changes.get(&id).ok_or_else(|| {
            invalid(format!(
                "exact local history is missing change {id} while classifying {advertised}"
            ))
        })?;
        distance += 1;
        stack.extend(change.parents.iter().copied());
    }
    if !reached_advertised {
        // The advertised change is on no path back from the local head, whether
        // because this replica has never admitted it or because the two lines
        // share ancestry and then part. Local history cannot tell those apart,
        // and neither is a fast-forward.
        return Ok(LocalAncestry::Unreachable);
    }
    Ok(LocalAncestry::Ancestor { distance })
}

/// Refuse a peer envelope that names a different repository.
fn require_same_repository(
    expected: &RepositoryId,
    advertised: &RepositoryId,
    what: &str,
) -> Result<()> {
    if expected == advertised {
        return Ok(());
    }
    Err(invalid(format!(
        "remote {what} belongs to repository {advertised}, not requested repository {expected}"
    )))
}

fn require_protocol(schema_version: u32, protocol: &str, what: &str) -> Result<()> {
    if schema_version != REPOSITORY_TRANSFER_SCHEMA_VERSION {
        return Err(invalid(format!(
            "remote {what} declares schema version {schema_version}; expected {REPOSITORY_TRANSFER_SCHEMA_VERSION}"
        )));
    }
    if protocol != REPOSITORY_TRANSFER_PROTOCOL {
        return Err(invalid(format!(
            "remote {what} declares protocol {protocol:?}; expected {REPOSITORY_TRANSFER_PROTOCOL:?}"
        )));
    }
    Ok(())
}

/// Refuse a receipt that does not bind the exact pack that was sent.
///
/// A receipt is the only evidence a caller has that a transfer was published.
/// A peer that returns a well-formed receipt for some other transfer, or that
/// reports a destination head other than the head this pack carried, has not
/// proven this transfer and must not be reported as success.
pub fn verify_receipt_binds_pack(
    pack: &RepositoryTransferPack,
    receipt: &RepositoryTransferReceipt,
) -> Result<()> {
    require_protocol(
        receipt.schema_version,
        &receipt.protocol,
        "transfer receipt",
    )?;
    if receipt.transfer_id != pack.transfer_id {
        return Err(conflict(format!(
            "receipt binds transfer {} but this replica sent transfer {}",
            receipt.transfer_id, pack.transfer_id
        )));
    }
    if receipt.repository_id != pack.repository_id {
        return Err(conflict(format!(
            "receipt binds repository {} but this replica sent repository {}",
            receipt.repository_id, pack.repository_id
        )));
    }
    if receipt.destination_ref != pack.destination_ref {
        return Err(conflict(format!(
            "receipt binds destination ref {} but this replica sent {}",
            receipt.destination_ref, pack.destination_ref
        )));
    }
    if receipt.destination_head != pack.source_head {
        return Err(conflict(format!(
            "receipt reports destination head {} but this pack publishes {}",
            receipt.destination_head, pack.source_head
        )));
    }
    Ok(())
}

/// The ref a replica with no history of its own should adopt from a peer.
///
/// A fresh replica cannot name a ref from its own state, and the per-ref
/// transfer status cannot be asked about a ref nobody has named yet. The
/// advertisement is the only surface that answers this, which is why an unborn
/// repository still publishes a default ref.
pub fn remote_default_ref<T>(transport: &T, repository_id: &RepositoryId) -> Result<RefName>
where
    T: RepositoryTransferTransport + ?Sized,
{
    let advertisement = transport.advertise_refs(repository_id)?;
    require_protocol(
        advertisement.schema_version,
        &advertisement.protocol,
        "ref advertisement",
    )?;
    require_same_repository(
        repository_id,
        &advertisement.repository_id,
        "ref advertisement",
    )?;
    advertisement.default_ref.ok_or_else(|| {
        invalid(format!(
            "remote publishes no default ref for {repository_id}; name one explicitly"
        ))
    })
}

/// Read the remote's exact lease for one destination ref, refusing a peer that
/// answers for a different repository or a different ref than the one asked
/// about.
fn negotiated_destination_lease<T>(
    transport: &T,
    repository_id: &RepositoryId,
    destination_ref: &RefName,
) -> Result<RepositoryTransferExpectation>
where
    T: RepositoryTransferTransport + ?Sized,
{
    let status = transport.transfer_status(repository_id, destination_ref)?;
    require_protocol(status.schema_version, &status.protocol, "transfer status")?;
    require_same_repository(repository_id, &status.repository_id, "transfer status")?;
    if &status.destination_ref != destination_ref {
        return Err(invalid(format!(
            "remote transfer status answers for ref {} but this replica asked about {}",
            status.destination_ref, destination_ref
        )));
    }
    RepositoryTransferExpectation::try_from(status)
}

/// Classify the local publication gap against an already-read remote lease.
fn classify_push<B>(
    local: &RepositoryAuthorityManager<B>,
    source_ref: &RefName,
    destination_ref: &RefName,
    destination_head: Option<SemanticChangeId>,
) -> Result<(SemanticChangeId, RepositoryTransferPlan)>
where
    B: StorageBackend + ?Sized + 'static,
{
    let lease = local.read_authority();
    let source_target = lease
        .resolve_ref_target(source_ref)
        .map_err(storage)?
        .ok_or_else(|| invalid(format!("local source ref {source_ref} is absent")))?;
    let source_head = lease
        .resolve_target_change_id(&source_target)
        .map_err(storage)?;
    let Some(head) = destination_head else {
        return Ok((
            source_head,
            RepositoryTransferPlan::FastForward {
                source_head,
                destination_head: None,
                change_count: None,
            },
        ));
    };
    let plan = match classify_local_ancestry(&lease.snapshot().changes, Some(source_head), head)? {
        LocalAncestry::Same => RepositoryTransferPlan::UpToDate {
            head: Some(source_head),
        },
        LocalAncestry::Ancestor { distance } => RepositoryTransferPlan::FastForward {
            source_head,
            destination_head: Some(head),
            change_count: Some(distance),
        },
        LocalAncestry::Unreachable => {
            return Err(conflict(format!(
                "remote head {head} on {destination_ref} is not an ancestor of local head {source_head}; \
                 the remote holds exact changes this replica has not admitted. Integrate with a pull first. \
                 This transport publishes fast-forwards only and has no force path"
            )));
        }
    };
    Ok((source_head, plan))
}

/// A negotiated publication plan, and whether this protocol version can carry
/// it in one envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryPushPlan {
    pub plan: RepositoryTransferPlan,
    /// The most changes one negotiated envelope carries.
    pub max_changes_per_envelope: u32,
    /// False when the gap needs more changes than one envelope holds.
    ///
    /// Transfer v1 has no continuation packs, so a gap this large is refused at
    /// pack-build time rather than split. Reporting it from the plan is what
    /// makes that refusal predictable instead of a surprise mid-publication.
    pub fits_one_envelope: bool,
}

/// Negotiate a publication without moving any history.
///
/// This is the read-only half of [`push_to_remote`]: it reads the remote lease
/// and classifies the gap, and refuses exactly what a push would refuse, but it
/// never builds a pack or contacts the receive seam. A plan that reports a
/// fast-forward is a statement about the two leases it just read, not a promise
/// that they will still hold when a push runs.
pub fn plan_push_to_remote<B, T>(
    local: &RepositoryAuthorityManager<B>,
    transport: &T,
    repository_id: &RepositoryId,
    source_ref: &RefName,
    destination_ref: &RefName,
) -> Result<RepositoryPushPlan>
where
    B: StorageBackend + ?Sized + 'static,
    T: RepositoryTransferTransport + ?Sized,
{
    let expectation = negotiated_destination_lease(transport, repository_id, destination_ref)?;
    let max_changes_per_envelope = expectation.limits.max_changes;
    let (_, plan) = classify_push(
        local,
        source_ref,
        destination_ref,
        expectation.destination_head,
    )?;
    // An unborn destination has no counted closure yet, because counting it
    // means walking the whole line. Treat unknown as "not yet known to fit"
    // rather than asserting it fits.
    let fits_one_envelope = match &plan {
        RepositoryTransferPlan::UpToDate { .. } => true,
        RepositoryTransferPlan::FastForward { change_count, .. } => change_count
            .map(|count| u32::try_from(count).is_ok_and(|count| count <= max_changes_per_envelope))
            .unwrap_or(false),
    };
    Ok(RepositoryPushPlan {
        plan,
        max_changes_per_envelope,
        fits_one_envelope,
    })
}

/// Negotiate and run one exact publication to a remote replica.
///
/// The local replica holds the history, so it classifies the gap itself and
/// refuses a non-fast-forward before building anything. There is no force
/// path: a remote head this replica has not admitted is reported with both
/// heads named so the operator integrates instead of overwriting.
pub fn push_to_remote<B, T>(
    local: &RepositoryAuthorityManager<B>,
    transport: &T,
    repository_id: &RepositoryId,
    source_ref: &RefName,
    destination_ref: &RefName,
) -> Result<RepositoryTransferOutcome>
where
    B: StorageBackend + ?Sized + 'static,
    T: RepositoryTransferTransport + ?Sized,
{
    let expectation = negotiated_destination_lease(transport, repository_id, destination_ref)?;
    let destination_head = expectation.destination_head;
    let (source_head, plan) = classify_push(
        local,
        source_ref,
        destination_ref,
        expectation.destination_head,
    )?;

    if matches!(plan, RepositoryTransferPlan::UpToDate { .. }) {
        return Ok(RepositoryTransferOutcome {
            direction: RepositoryTransferDirection::Push,
            repository_id: repository_id.clone(),
            source_ref: source_ref.clone(),
            destination_ref: destination_ref.clone(),
            plan,
            receipt: None,
        });
    }

    let pack = build_repository_transfer_pack(local, source_ref, &expectation)?;
    if pack.source_head != source_head {
        return Err(conflict(format!(
            "local authority moved during negotiation: planned head {source_head}, packed head {}",
            pack.source_head
        )));
    }
    let plan = RepositoryTransferPlan::FastForward {
        source_head,
        destination_head,
        change_count: Some(pack.changes.len()),
    };
    let receipt = transport.receive_pack(repository_id, destination_ref, &pack)?;
    verify_receipt_binds_pack(&pack, &receipt)?;

    Ok(RepositoryTransferOutcome {
        direction: RepositoryTransferDirection::Push,
        repository_id: repository_id.clone(),
        source_ref: source_ref.clone(),
        destination_ref: destination_ref.clone(),
        plan,
        receipt: Some(receipt),
    })
}

/// What a pull negotiation produced, before anything is admitted locally.
#[derive(Debug, Clone)]
pub enum PullNegotiation {
    /// Both replicas resolve the ref to the same exact change.
    UpToDate { head: Option<SemanticChangeId> },
    /// The exact pack the remote exported to close the gap.
    Pack(Box<RepositoryTransferPack>),
}

/// Negotiate a pull and fetch the pack, without admitting it.
///
/// A receiver that owns derived state beyond repository authority needs to
/// apply the pack itself, so that publication and the refresh of everything
/// derived from it stay on one path. This is that seam: everything up to and
/// including the exported pack, and nothing that moves local history.
pub fn fetch_pull_pack<B, T>(
    local: &RepositoryAuthorityManager<B>,
    transport: &T,
    repository_id: &RepositoryId,
    source_ref: &RefName,
    destination_ref: &RefName,
) -> Result<PullNegotiation>
where
    B: StorageBackend + ?Sized + 'static,
    T: RepositoryTransferTransport + ?Sized,
{
    let advertisement = transport.advertise_refs(repository_id)?;
    require_protocol(
        advertisement.schema_version,
        &advertisement.protocol,
        "ref advertisement",
    )?;
    require_same_repository(
        repository_id,
        &advertisement.repository_id,
        "ref advertisement",
    )?;
    let source_head = advertisement
        .refs
        .iter()
        .find(|entry| &entry.name == source_ref)
        .map(|entry| entry.head)
        .ok_or_else(|| invalid(format!("remote does not publish source ref {source_ref}")))?;

    let status = repository_transfer_status(local, repository_id, destination_ref)?;
    let destination_head = status.destination_head;
    let expectation = RepositoryTransferExpectation::try_from(status)?;

    {
        let lease = local.read_authority();
        match classify_local_ancestry(&lease.snapshot().changes, destination_head, source_head)? {
            LocalAncestry::Same => {
                return Ok(PullNegotiation::UpToDate {
                    head: destination_head,
                });
            }
            LocalAncestry::Ancestor { distance } => {
                let local_head = destination_head.expect("an ancestor implies a local head");
                return Err(conflict(format!(
                    "remote head {source_head} on {source_ref} is already an exact ancestor of local head \
                     {local_head}, {distance} changes behind; there is nothing to admit in this direction"
                )));
            }
            LocalAncestry::Unreachable => {}
        }
    }

    let pack = transport.export_pack(repository_id, source_ref, &expectation)?;
    if pack.source_head != source_head {
        return Err(conflict(format!(
            "remote authority moved during negotiation: advertised head {source_head}, exported head {}",
            pack.source_head
        )));
    }
    if &pack.destination_ref != destination_ref {
        return Err(invalid(format!(
            "remote exported a pack for destination ref {} but this replica asked for {destination_ref}",
            pack.destination_ref
        )));
    }
    Ok(PullNegotiation::Pack(Box::new(pack)))
}

/// Negotiate, fetch, and admit one exact publication from a remote replica.
///
/// The remote holds the history here, so its export computes the closure and is
/// the authority on whether the gap is a fast-forward. The local pre-check only
/// rules out the two cases local history can settle on its own: an identical
/// head, and a remote head this replica already contains.
pub fn pull_from_remote<B, T>(
    local: &RepositoryAuthorityManager<B>,
    transport: &T,
    repository_id: &RepositoryId,
    source_ref: &RefName,
    destination_ref: &RefName,
    actor: AuthorId,
) -> Result<RepositoryTransferOutcome>
where
    B: StorageBackend + ?Sized + 'static,
    T: RepositoryTransferTransport + ?Sized,
{
    let negotiation =
        fetch_pull_pack(local, transport, repository_id, source_ref, destination_ref)?;
    let pack = match negotiation {
        PullNegotiation::UpToDate { head } => {
            return Ok(RepositoryTransferOutcome {
                direction: RepositoryTransferDirection::Pull,
                repository_id: repository_id.clone(),
                source_ref: source_ref.clone(),
                destination_ref: destination_ref.clone(),
                plan: RepositoryTransferPlan::UpToDate { head },
                receipt: None,
            });
        }
        PullNegotiation::Pack(pack) => pack,
    };

    let destination_head = pack.expected_destination_head;
    let source_head = pack.source_head;
    let change_count = pack.changes.len();
    let receipt =
        apply_repository_transfer_pack(local, repository_id, destination_ref, actor, &pack)?;
    verify_receipt_binds_pack(&pack, &receipt)?;

    Ok(RepositoryTransferOutcome {
        direction: RepositoryTransferDirection::Pull,
        repository_id: repository_id.clone(),
        source_ref: source_ref.clone(),
        destination_ref: destination_ref.clone(),
        plan: RepositoryTransferPlan::FastForward {
            source_head,
            destination_head,
            change_count: Some(change_count),
        },
        receipt: Some(receipt),
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::sync::Arc;

    use kin_db::LocalFileBackend;
    use kin_model::{
        compute_semantic_change_id, ChangeOrigin, DefaultRefExpectation, DefaultRefMutation,
        Hash256, OperationId, RefExpectation, RefMutation, RefTarget, RefUpdatePolicy,
        RepositoryTransaction, Timestamp, TreeDelta, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };
    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::repository_transfer::{
        repository_ref_advertisement, RepositoryTransferApplyOutcome,
    };

    use super::*;

    type TestManager = RepositoryAuthorityManager<LocalFileBackend>;

    fn manager(directory: &TempDir, repository_id: &RepositoryId) -> TestManager {
        let storage_root = directory.path().join("kindb");
        std::fs::create_dir_all(&storage_root).unwrap();
        RepositoryAuthorityManager::open(
            repository_id.clone(),
            Arc::new(LocalFileBackend::new(storage_root)),
        )
        .unwrap()
    }

    fn native_change(
        parents: Vec<SemanticChangeId>,
        message: &str,
        tree_deltas: Vec<TreeDelta>,
    ) -> SemanticChange {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("negotiation-fixture"),
            message: message.to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas,
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        change.id = compute_semantic_change_id(&change).unwrap();
        change
    }

    /// Publish one native change onto `ref_name`, advancing from `previous`.
    ///
    /// The changes carry no tree deltas on purpose. Introducing an artifact
    /// binds a workspace admission context that has nothing to do with
    /// negotiation, and pack contents are already proven exactly in
    /// `repository_transfer`'s own suite. What these fixtures need to be real
    /// about is history shape: which changes exist, which ref resolves where,
    /// and what the closure between two heads is.
    fn publish(
        manager: &TestManager,
        repository_id: &RepositoryId,
        ref_name: &RefName,
        previous: Option<SemanticChangeId>,
        operation: u128,
        message: &str,
    ) -> SemanticChangeId {
        publish_with_parents(
            manager,
            repository_id,
            ref_name,
            previous.into_iter().collect(),
            previous,
            operation,
            message,
        )
    }

    /// Publish a change with arbitrary parents onto `ref_name`.
    ///
    /// `previous` is the ref's current target, which is what the publication
    /// expects, and is independent of the change's parents once merges exist.
    fn publish_with_parents(
        manager: &TestManager,
        repository_id: &RepositoryId,
        ref_name: &RefName,
        parents: Vec<SemanticChangeId>,
        previous: Option<SemanticChangeId>,
        operation: u128,
        message: &str,
    ) -> SemanticChangeId {
        let change = native_change(parents, message, Vec::new());
        let lease = manager.read_authority();
        // A repository adopts its default ref once. A second ref published
        // later must not try to claim it again.
        let adopts_default_ref = lease
            .snapshot()
            .repository_authority
            .as_ref()
            .is_some_and(|metadata| metadata.ref_state.default_ref.is_none());
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(Uuid::from_u128(operation)),
            repository_id: repository_id.clone(),
            expected_generation: lease.roots().generation,
            expected_roots: lease.roots().clone(),
            actor: AuthorId::new("negotiation-fixture"),
            reason: format!("publish {message}"),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: vec![change.clone()],
            aliases: Vec::new(),
            ref_mutations: vec![RefMutation {
                name: ref_name.clone(),
                expected: match previous {
                    None => RefExpectation::MustNotExist,
                    Some(head) => RefExpectation::MustEqual {
                        target: RefTarget::change(head),
                    },
                },
                new_target: Some(RefTarget::change(change.id)),
                policy: RefUpdatePolicy::FastForwardOnly,
            }],
            default_ref_mutation: adopts_default_ref.then_some(DefaultRefMutation {
                expected: DefaultRefExpectation::MustBeUnset,
                new_default: Some(ref_name.clone()),
            }),
            workspace_mutation: None,
            local_overlay_delta: None,
        };
        drop(lease);
        manager.commit_repository_transaction(transaction).unwrap();
        change.id
    }

    /// A peer reached in-process rather than over HTTP.
    ///
    /// Every call runs the same `repository_transfer` entry point the daemon's
    /// route runs, against a second real authority on real storage. What this
    /// double leaves unproven is the wire itself, which the daemon suite covers
    /// separately over a bound socket.
    struct LocalPeer<'a> {
        authority: &'a TestManager,
        actor: AuthorId,
        /// Corrupt the receipt on the way back, to prove the caller checks it.
        forge_receipt: bool,
        received: RefCell<usize>,
    }

    impl<'a> LocalPeer<'a> {
        fn new(authority: &'a TestManager) -> Self {
            Self {
                authority,
                actor: AuthorId::new("local-peer"),
                forge_receipt: false,
                received: RefCell::new(0),
            }
        }

        fn forging_receipts(authority: &'a TestManager) -> Self {
            Self {
                forge_receipt: true,
                ..Self::new(authority)
            }
        }
    }

    impl RepositoryTransferTransport for LocalPeer<'_> {
        fn advertise_refs(
            &self,
            repository_id: &RepositoryId,
        ) -> Result<RepositoryRefAdvertisement> {
            repository_ref_advertisement(self.authority, repository_id)
        }

        fn transfer_status(
            &self,
            repository_id: &RepositoryId,
            destination_ref: &RefName,
        ) -> Result<RepositoryTransferStatus> {
            repository_transfer_status(self.authority, repository_id, destination_ref)
        }

        fn export_pack(
            &self,
            _repository_id: &RepositoryId,
            source_ref: &RefName,
            expectation: &RepositoryTransferExpectation,
        ) -> Result<RepositoryTransferPack> {
            build_repository_transfer_pack(self.authority, source_ref, expectation)
        }

        fn receive_pack(
            &self,
            repository_id: &RepositoryId,
            destination_ref: &RefName,
            pack: &RepositoryTransferPack,
        ) -> Result<RepositoryTransferReceipt> {
            *self.received.borrow_mut() += 1;
            let mut receipt = apply_repository_transfer_pack(
                self.authority,
                repository_id,
                destination_ref,
                self.actor.clone(),
                pack,
            )?;
            if self.forge_receipt {
                receipt.transfer_id = Hash256::from_bytes([0xab; 32]);
            }
            Ok(receipt)
        }
    }

    struct Fixture {
        _source_dir: TempDir,
        _destination_dir: TempDir,
        source: TestManager,
        destination: TestManager,
        repository_id: RepositoryId,
        main: RefName,
        source_head: SemanticChangeId,
    }

    /// A source holding two exact native changes, and an unborn destination.
    fn fixture() -> Fixture {
        let repository_id = RepositoryId::new(format!("negotiation-{}", Uuid::new_v4())).unwrap();
        let source_dir = TempDir::new().unwrap();
        let destination_dir = TempDir::new().unwrap();
        let source = manager(&source_dir, &repository_id);
        let destination = manager(&destination_dir, &repository_id);
        let main = RefName::branch(b"main").unwrap();

        let first = publish(
            &source,
            &repository_id,
            &main,
            None,
            1,
            "root the exact line",
        );
        let source_head = publish(
            &source,
            &repository_id,
            &main,
            Some(first),
            2,
            "advance the exact line",
        );

        Fixture {
            _source_dir: source_dir,
            _destination_dir: destination_dir,
            source,
            destination,
            repository_id,
            main,
            source_head,
        }
    }

    fn head_of(manager: &TestManager, ref_name: &RefName) -> Option<SemanticChangeId> {
        let lease = manager.read_authority();
        let target = lease.resolve_ref_target(ref_name).unwrap()?;
        Some(lease.resolve_target_change_id(&target).unwrap())
    }

    #[test]
    fn push_publishes_the_whole_gap_and_binds_the_returned_receipt() {
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.destination);

        let outcome = push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .unwrap();

        assert_eq!(outcome.direction, RepositoryTransferDirection::Push);
        assert_eq!(
            outcome.plan,
            RepositoryTransferPlan::FastForward {
                source_head: fixture.source_head,
                destination_head: None,
                change_count: Some(2),
            }
        );
        let receipt = outcome.receipt.expect("a moved head produces a receipt");
        assert_eq!(receipt.outcome, RepositoryTransferApplyOutcome::Committed);
        assert_eq!(receipt.destination_head, fixture.source_head);
        assert_eq!(
            head_of(&fixture.destination, &fixture.main),
            Some(fixture.source_head),
            "the remote replica now resolves the ref to the exact source head"
        );
    }

    #[test]
    fn a_second_push_of_the_same_head_moves_nothing_and_sends_no_pack() {
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.destination);
        push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .unwrap();
        assert_eq!(*peer.received.borrow(), 1);

        let outcome = push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .unwrap();

        assert_eq!(
            outcome.plan,
            RepositoryTransferPlan::UpToDate {
                head: Some(fixture.source_head),
            }
        );
        assert!(!outcome.moved_history());
        assert_eq!(
            *peer.received.borrow(),
            1,
            "an up-to-date negotiation must not build or ship a pack at all"
        );
    }

    #[test]
    fn the_planned_distance_is_exactly_what_the_pack_carries() {
        // The plan counts the gap by walking local history; the pack counts it
        // by building the fast-forward closure. Those are two separate walks,
        // and a caller acts on the first while the second is what actually
        // moves. If they can disagree, every reported change count is a guess.
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.destination);
        push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .unwrap();

        let advanced = publish(
            &fixture.source,
            &fixture.repository_id,
            &fixture.main,
            Some(fixture.source_head),
            3,
            "advance past the published head",
        );

        let planned = plan_push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .unwrap();
        assert_eq!(
            planned.plan,
            RepositoryTransferPlan::FastForward {
                source_head: advanced,
                destination_head: Some(fixture.source_head),
                change_count: Some(1),
            }
        );
        assert_eq!(planned.max_changes_per_envelope, 512);
        assert!(planned.fits_one_envelope);

        let outcome = push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .unwrap();
        assert_eq!(
            outcome.plan, planned.plan,
            "the executed push must move exactly what the plan reported"
        );
        assert_eq!(head_of(&fixture.destination, &fixture.main), Some(advanced));
    }

    #[test]
    fn a_merge_plan_counts_every_change_the_pack_carries() {
        // A shared ancestor can be reachable from the source head by a path that
        // never passes through the destination head. The pack carries it, so a
        // plan that counted "reachable from the source but not from the
        // destination" would under-report the transfer. Both walks must agree.
        let repository_id = RepositoryId::new(format!("merge-{}", Uuid::new_v4())).unwrap();
        let source_dir = TempDir::new().unwrap();
        let destination_dir = TempDir::new().unwrap();
        let source = manager(&source_dir, &repository_id);
        let destination = manager(&destination_dir, &repository_id);
        let main = RefName::branch(b"main").unwrap();
        let side = RefName::branch(b"side").unwrap();

        let root = publish(&source, &repository_id, &main, None, 1, "root");
        let published = publish(&source, &repository_id, &main, Some(root), 2, "mainline");
        // The side line forks from the root, so the root is reachable from the
        // merge without passing through the published mainline head.
        let sibling = publish_with_parents(
            &source,
            &repository_id,
            &side,
            vec![root],
            None,
            3,
            "side line",
        );

        // Bring the destination to the mainline head, then merge the side line.
        let peer = LocalPeer::new(&destination);
        push_to_remote(&source, &peer, &repository_id, &main, &main).unwrap();
        assert_eq!(head_of(&destination, &main), Some(published));

        let merged = publish_with_parents(
            &source,
            &repository_id,
            &main,
            vec![published, sibling],
            Some(published),
            4,
            "merge the side line",
        );

        let planned = plan_push_to_remote(&source, &peer, &repository_id, &main, &main).unwrap();
        let RepositoryTransferPlan::FastForward { change_count, .. } = planned.plan else {
            panic!("a merge past the published head is a fast-forward");
        };

        let outcome = push_to_remote(&source, &peer, &repository_id, &main, &main).unwrap();
        let RepositoryTransferPlan::FastForward {
            change_count: packed,
            ..
        } = outcome.plan
        else {
            panic!("the executed push is the same fast-forward");
        };
        assert_eq!(
            change_count, packed,
            "the planned count must equal what the pack carried"
        );
        assert_eq!(
            packed,
            Some(3),
            "the merge, the side change, and the root all reach the destination by this path"
        );
        assert_eq!(head_of(&destination, &main), Some(merged));
    }

    #[test]
    fn pull_admits_the_same_gap_from_the_other_side() {
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.source);

        let outcome = pull_from_remote(
            &fixture.destination,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
            AuthorId::new("pulling-replica"),
        )
        .unwrap();

        assert_eq!(outcome.direction, RepositoryTransferDirection::Pull);
        assert_eq!(
            outcome.plan,
            RepositoryTransferPlan::FastForward {
                source_head: fixture.source_head,
                destination_head: None,
                change_count: Some(2),
            }
        );
        assert_eq!(
            head_of(&fixture.destination, &fixture.main),
            Some(fixture.source_head)
        );
        let receipt = outcome.receipt.expect("a moved head produces a receipt");
        assert_eq!(receipt.outcome, RepositoryTransferApplyOutcome::Committed);
    }

    #[test]
    fn push_refuses_a_remote_head_this_replica_has_not_admitted() {
        let fixture = fixture();
        // The remote admits its own independent line on the same ref.
        let remote_head = publish(
            &fixture.destination,
            &fixture.repository_id,
            &fixture.main,
            None,
            9,
            "admitted only on the remote replica",
        );
        let peer = LocalPeer::new(&fixture.destination);

        let error = push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .expect_err("a non-fast-forward publication must be refused");

        let RepositoryTransferError::Conflict(message) = error else {
            panic!("a divergent remote is a conflict, not an invalid envelope");
        };
        assert!(
            message.contains(&remote_head.to_string())
                && message.contains(&fixture.source_head.to_string()),
            "the refusal must name both heads so the operator can act on it: {message}"
        );
        assert!(
            message.contains("no force path"),
            "the refusal must say force is unavailable rather than imply a retry: {message}"
        );
        assert_eq!(
            head_of(&fixture.destination, &fixture.main),
            Some(remote_head),
            "a refused push must leave the remote head exactly where it was"
        );
        assert_eq!(
            *peer.received.borrow(),
            0,
            "a refusal must happen before any pack reaches the remote"
        );
    }

    #[test]
    fn pull_refuses_a_remote_this_replica_already_contains() {
        let fixture = fixture();
        // Give the destination the full source history, then rewind the peer to
        // the first change so the remote is strictly behind.
        let peer = LocalPeer::new(&fixture.source);
        pull_from_remote(
            &fixture.destination,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
            AuthorId::new("pulling-replica"),
        )
        .unwrap();

        // A third replica that holds only the first change now advertises it.
        let behind_dir = TempDir::new().unwrap();
        let behind = manager(&behind_dir, &fixture.repository_id);
        let behind_head = publish(
            &behind,
            &fixture.repository_id,
            &fixture.main,
            None,
            1,
            "root the exact line",
        );
        let behind_peer = LocalPeer::new(&behind);

        let error = pull_from_remote(
            &fixture.destination,
            &behind_peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
            AuthorId::new("pulling-replica"),
        )
        .expect_err("there is nothing to admit from a replica we already contain");

        let RepositoryTransferError::Conflict(message) = error else {
            panic!("an already-contained remote is a conflict");
        };
        assert!(
            message.contains(&behind_head.to_string()),
            "the refusal must name the remote head: {message}"
        );
        assert_eq!(
            head_of(&fixture.destination, &fixture.main),
            Some(fixture.source_head),
            "a refused pull must leave the local head exactly where it was"
        );
    }

    #[test]
    fn a_receipt_that_binds_another_transfer_is_refused_even_though_history_moved() {
        let fixture = fixture();
        let peer = LocalPeer::forging_receipts(&fixture.destination);

        let error = push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .expect_err("a receipt that does not bind the sent pack is not proof of this transfer");

        assert!(matches!(error, RepositoryTransferError::Conflict(_)));
        // The remote genuinely published; what is refused is the claim that the
        // returned receipt proves it. Reporting success here would let a peer
        // acknowledge transfers it never performed.
        assert_eq!(
            head_of(&fixture.destination, &fixture.main),
            Some(fixture.source_head)
        );
    }

    #[test]
    fn an_advertisement_for_another_repository_is_refused_before_any_export() {
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.source);
        let other = RepositoryId::new("some-other-repository").unwrap();

        let error = pull_from_remote(
            &fixture.destination,
            &peer,
            &other,
            &fixture.main,
            &fixture.main,
            AuthorId::new("pulling-replica"),
        )
        .expect_err("a peer serving a different repository must be refused");

        assert!(matches!(error, RepositoryTransferError::Invalid(_)));
    }

    #[test]
    fn push_refuses_a_source_ref_this_replica_does_not_publish() {
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.destination);
        let absent = RefName::branch(b"never-published").unwrap();

        let error = push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &absent,
            &fixture.main,
        )
        .expect_err("a source ref that does not exist cannot be published");

        assert!(matches!(error, RepositoryTransferError::Invalid(_)));
        assert_eq!(*peer.received.borrow(), 0);
    }

    #[test]
    fn ancestry_classification_separates_behind_from_unrelated() {
        let fixture = fixture();
        let lease = fixture.source.read_authority();
        let changes = &lease.snapshot().changes;
        let first = changes
            .values()
            .find(|change| change.parents.is_empty())
            .expect("the fixture roots one change");

        assert_eq!(
            classify_local_ancestry(changes, Some(fixture.source_head), fixture.source_head)
                .unwrap(),
            LocalAncestry::Same
        );
        assert_eq!(
            classify_local_ancestry(changes, Some(fixture.source_head), first.id).unwrap(),
            LocalAncestry::Ancestor { distance: 1 }
        );
        assert_eq!(
            classify_local_ancestry(
                changes,
                Some(fixture.source_head),
                SemanticChangeId::from_hash(Hash256::from_bytes([0x5c; 32])),
            )
            .unwrap(),
            LocalAncestry::Unreachable,
            "a head this replica has never admitted is unreachable, not an ancestor"
        );
        assert_eq!(
            classify_local_ancestry(changes, None, fixture.source_head).unwrap(),
            LocalAncestry::Unreachable,
            "a replica with no head on the ref has admitted nothing"
        );
    }

    #[test]
    fn a_sibling_line_present_in_local_history_is_not_an_ancestor() {
        // A change can be known locally and still not be on any path from the
        // local head. Counting "do I have this id" instead of "is it behind my
        // head" would call that a fast-forward and silently drop the sibling.
        let fixture = fixture();
        let lease = fixture.source.read_authority();
        let mut changes = lease.snapshot().changes.clone();
        let root = changes
            .values()
            .find(|change| change.parents.is_empty())
            .expect("the fixture roots one change")
            .id;
        drop(lease);

        let sibling = native_change(vec![root], "a second child of the same root", Vec::new());
        let sibling_id = sibling.id;
        changes.insert(sibling_id, sibling);

        assert_eq!(
            classify_local_ancestry(&changes, Some(fixture.source_head), sibling_id).unwrap(),
            LocalAncestry::Unreachable
        );
        assert_eq!(
            classify_local_ancestry(&changes, Some(sibling_id), fixture.source_head).unwrap(),
            LocalAncestry::Unreachable
        );
    }
}
