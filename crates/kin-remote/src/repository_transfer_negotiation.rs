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
use kin_model::{AuthorId, RefName, RepositoryId, RootBundle, SemanticChange, SemanticChangeId};
use serde::{Deserialize, Serialize};

use crate::repository_transfer::{
    apply_repository_transfer_pack_with_pre_commit, build_repository_transfer_segment,
    count_repository_transfer_packs, model, repository_transfer_status,
    require_negotiated_features, validate_limits, verify_transfer_source_readiness,
    RepositoryAuthorityMetadata, RepositoryRefAdvertisement, RepositoryTransferError,
    RepositoryTransferExpectation, RepositoryTransferLimits, RepositoryTransferPack,
    RepositoryTransferReceipt, RepositoryTransferStatus, Result, REPOSITORY_TRANSFER_PROTOCOL,
    REPOSITORY_TRANSFER_SCHEMA_VERSION,
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

/// One completed negotiation, including a receipt per published pack.
///
/// Atomicity contract for a transfer that needed more than one pack: each pack
/// is published in one repository transaction and proven by its own receipt,
/// and the packs are ordered. There is no transaction spanning them, and this
/// protocol does not claim one. A transfer interrupted between packs leaves
/// the destination ref on the last head that was receipted, which is always an
/// exact ancestor of the head the transfer was moving toward, so re-running it
/// resumes from there rather than restarting or rewinding. `receipts` is the
/// complete evidence of what actually moved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepositoryTransferOutcome {
    pub direction: RepositoryTransferDirection,
    pub repository_id: RepositoryId,
    pub source_ref: RefName,
    pub destination_ref: RefName,
    pub plan: RepositoryTransferPlan,
    /// One receipt per published pack, in publication order. Empty exactly
    /// when the plan was [`RepositoryTransferPlan::UpToDate`].
    pub receipts: Vec<RepositoryTransferReceipt>,
}

impl RepositoryTransferOutcome {
    /// True when this negotiation published at least one repository
    /// transaction.
    pub fn moved_history(&self) -> bool {
        !self.receipts.is_empty()
    }

    /// The receipt for the pack that landed the transfer's final head.
    pub fn final_receipt(&self) -> Option<&RepositoryTransferReceipt> {
        self.receipts.last()
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
    read_ref_advertisement(transport, repository_id)?
        .default_ref
        .ok_or_else(|| {
            invalid(format!(
                "remote publishes no default ref for {repository_id}; name one explicitly"
            ))
        })
}

/// Read one ref advertisement and refuse a peer that is not speaking this
/// protocol, or is answering for another repository.
///
/// These two checks are the floor every advertisement reader shares. Anything
/// stricter belongs to the caller: [`remote_default_ref`] runs on a replica
/// that already holds this repository's authority, while
/// [`negotiate_replica_identity`] runs before any local authority exists and so
/// has to validate what a fresh replica is about to be built from.
fn read_ref_advertisement<T>(
    transport: &T,
    repository_id: &RepositoryId,
) -> Result<RepositoryRefAdvertisement>
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
    Ok(advertisement)
}

/// The identity and starting layout a fresh replica adopts from a peer.
///
/// A replica that mints its own repository identity can never exchange history
/// with the repository it was cloned from: the ref advertisement, the transfer
/// expectation, and pack admission each refuse an identity other than the one
/// the receiving authority records. So a clone has to learn identity before it
/// has any authority of its own, and the advertisement is the only surface that
/// answers before history moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteReplicaIdentity {
    /// The identity the new replica adopts verbatim.
    pub repository_id: RepositoryId,
    /// The ref the replica is created against, so it reproduces the remote's
    /// layout instead of synthesizing a ref the remote does not publish.
    pub default_ref: RefName,
    /// The exact change the default ref resolved to when the advertisement was
    /// read, or `None` for a remote whose default ref is unborn.
    ///
    /// This is a statement about the advertisement, not a reservation: the
    /// remote may move before any history is admitted. Adoption is verified
    /// against local history reaching this head, never against it still being
    /// the remote head.
    pub default_ref_head: Option<SemanticChangeId>,
    /// The remote's authority roots as advertised, carried so a caller can
    /// record what identity was adopted against.
    pub roots: RootBundle,
}

/// Learn, over the native transport, the identity a fresh replica should adopt.
///
/// The peer is asked about one repository and must answer for that repository:
/// an advertisement naming a different identity is refused rather than adopted,
/// because adopting it would silently point a clone at a repository nobody
/// asked for. The envelope is validated as strictly as a transfer's is, since a
/// replica created from an advertisement this build cannot transfer against
/// would be born unable to pull.
///
/// This proves nothing about history on its own. It reads one envelope the peer
/// wrote, which is why [`verify_adopted_replica_identity`] exists and why an
/// adoption is not complete until history has been admitted under the adopted
/// identity.
pub fn negotiate_replica_identity<T>(
    transport: &T,
    repository_id: &RepositoryId,
) -> Result<RemoteReplicaIdentity>
where
    T: RepositoryTransferTransport + ?Sized,
{
    let advertisement = read_ref_advertisement(transport, repository_id)?;
    advertisement.roots.validate().map_err(model)?;
    validate_limits(&advertisement.limits)?;
    require_negotiated_features(&advertisement.supported_features)?;

    let default_ref = advertisement.default_ref.clone().ok_or_else(|| {
        invalid(format!(
            "remote publishes no default ref for {repository_id}, so a replica has no ref to \
             adopt; a repository that has admitted nothing still publishes the ref its history \
             will land on"
        ))
    })?;
    let default_ref_head = advertisement
        .refs
        .iter()
        .find(|entry| entry.name == default_ref)
        .map(|entry| entry.head);

    Ok(RemoteReplicaIdentity {
        repository_id: advertisement.repository_id,
        default_ref,
        default_ref_head,
        roots: advertisement.roots,
    })
}

/// Prove an adopted identity against the authority a replica actually
/// committed, after the remote's history has been admitted into it.
///
/// Writing an identity into a manifest establishes nothing: it is one local
/// file naming what a peer claimed. What makes the adoption real is that the
/// remote's history admitted cleanly under it, and every step of that admission
/// is identity-exact. The pack declares a repository and [`validate_pack`]
/// refuses one whose replicated alias records name a different repository than
/// the pack header, so a peer serving repository A cannot export Git-origin
/// history as repository B. `apply_repository_transfer_pack` then refuses a
/// pack whose repository is not the one the receiving authority records.
///
/// What is left, and what this checks, is that the replica ended where it
/// claims: the committed authority records the adopted identity, the receipts
/// bind it, and this replica's own history reaches the head the identity
/// advertisement published. That last check is the one that separates a replica
/// that adopted an identity from one that merely wrote it down.
///
/// The advertised head is required to be reachable, not to be the current head.
/// A remote that moved between the advertisement and the transfer is ordinary,
/// and the replica has still admitted the history it was told about.
///
/// This does not claim the identity is cryptographically bound to the changes.
/// A semantic change id is a hash of the change alone and carries no repository
/// identity, so natively authored history with no external alias records is
/// bound to a repository only by the authority records that carry it.
pub fn verify_adopted_replica_identity<B>(
    local: &RepositoryAuthorityManager<B>,
    adopted: &RepositoryId,
    identity: &RemoteReplicaIdentity,
    outcome: &RepositoryTransferOutcome,
) -> Result<()>
where
    B: StorageBackend + ?Sized + 'static,
{
    if &identity.repository_id != adopted {
        return Err(invalid(format!(
            "replica adopted repository {adopted} but the remote identity names {}",
            identity.repository_id
        )));
    }
    if &outcome.repository_id != adopted {
        return Err(invalid(format!(
            "transfer ran against repository {} on a replica that adopted {adopted}",
            outcome.repository_id
        )));
    }
    for receipt in &outcome.receipts {
        if &receipt.repository_id != adopted {
            return Err(conflict(format!(
                "a transfer receipt binds repository {} on a replica that adopted {adopted}",
                receipt.repository_id
            )));
        }
    }

    let lease = local.read_authority();
    let committed = lease.committed_authority_metadata().ok_or_else(|| {
        conflict(format!(
            "this replica's authority carries no repository envelope, so nothing records it \
             adopting {adopted}"
        ))
    })?;
    if &committed.repository_id != adopted {
        return Err(conflict(format!(
            "this replica committed its authority under repository {}, not the adopted {adopted}",
            committed.repository_id
        )));
    }

    let Some(advertised_head) = identity.default_ref_head else {
        return Ok(());
    };
    let local_head = lease
        .resolve_ref_target(&identity.default_ref)
        .map_err(storage)?
        .map(|target| lease.resolve_target_change_id(&target).map_err(storage))
        .transpose()?;
    match classify_local_ancestry(&lease.snapshot().changes, local_head, advertised_head)? {
        LocalAncestry::Same | LocalAncestry::Ancestor { .. } => Ok(()),
        LocalAncestry::Unreachable => Err(conflict(format!(
            "this replica adopted repository {adopted} but has not admitted {advertised_head}, \
             the head that identity advertised on {}. Adopting an identity does not import \
             history; the transfer that would have is what did not complete",
            identity.default_ref
        ))),
    }
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

/// A negotiated publication plan, and how many packs carrying it will take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryPushPlan {
    pub plan: RepositoryTransferPlan,
    /// The most changes one negotiated envelope carries.
    pub max_changes_per_envelope: u32,
    /// How many packs this publication needs, each published atomically.
    ///
    /// `None` when the count is not knowable from the local lease alone, which
    /// is the case for an unborn destination: counting its closure means
    /// walking the whole line.
    pub pack_count: Option<usize>,
}

/// Negotiate a publication without moving any history.
///
/// This is the read-only half of [`push_to_remote`]: it reads the remote lease
/// and classifies the gap, and refuses what a push would refuse, but it never
/// publishes anything and never contacts the receive seam. A plan that reports
/// a fast-forward is a statement about the two leases it just read, not a
/// promise that they will still hold when a push runs.
///
/// Parity with a push is checked, not assumed. Everything a push decides
/// before it ships bytes is decided here too: the destination lease, the
/// fast-forward classification, the imported-Git authority baseline, and the
/// presence and identity of every immutable source body the publication head's
/// tree depends on. What is left to the push itself is the per-pack byte
/// arithmetic, which is only knowable once the packs are assembled; the plan
/// reports the pack count and the negotiated bound instead of predicting it.
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
    let (source_head, plan) = classify_push(
        local,
        source_ref,
        destination_ref,
        expectation.destination_head,
    )?;
    let _ = source_head;
    verify_transfer_source_readiness(local, source_ref, &expectation)?;
    // Counted even when the destination is unborn and `change_count` is not.
    // Walking the whole line is what the push is about to do anyway, and an
    // operator deciding whether to start it needs the number most in exactly
    // that case.
    let pack_count = match &plan {
        RepositoryTransferPlan::UpToDate { .. } => Some(0),
        RepositoryTransferPlan::FastForward { .. } => Some(count_repository_transfer_packs(
            local,
            source_ref,
            &expectation,
        )?),
    };
    Ok(RepositoryPushPlan {
        plan,
        max_changes_per_envelope,
        pack_count,
    })
}

/// Negotiate and run one exact publication to a remote replica.
///
/// The local replica holds the history, so it classifies the gap itself and
/// refuses a non-fast-forward before building anything. There is no force
/// path: a remote head this replica has not admitted is reported with both
/// heads named so the operator integrates instead of overwriting.
///
/// A gap larger than one negotiated envelope is published as an ordered
/// sequence of packs rather than refused. Each round re-reads the remote lease,
/// so every pack is built against the head the remote actually holds at that
/// moment, and each is published in its own repository transaction with its own
/// receipt. See [`RepositoryTransferOutcome`] for what that does and does not
/// promise across packs.
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
    let mut receipts = Vec::new();
    let mut originally_at = None;
    let mut published_changes = 0usize;
    let mut previous_head: Option<Option<SemanticChangeId>> = None;

    let (source_head, plan) = loop {
        let expectation = negotiated_destination_lease(transport, repository_id, destination_ref)?;
        if receipts.is_empty() {
            originally_at = expectation.destination_head;
        }
        // Every round must find the remote further along than the last one
        // left it. Without this a peer that receipts a pack and then keeps
        // reporting its old head would have this loop republish the same
        // segment forever, which is a hang standing in for a refusal.
        if let Some(previous) = previous_head {
            if expectation.destination_head == previous {
                return Err(conflict(format!(
                    "remote reported the same head on {destination_ref} after publishing a \
                     continuation pack, so the transfer toward {} made no progress",
                    previous
                        .map(|head| head.to_string())
                        .unwrap_or_else(|| "an unborn ref".to_string())
                )));
            }
        }
        previous_head = Some(expectation.destination_head);
        let (source_head, plan) = classify_push(
            local,
            source_ref,
            destination_ref,
            expectation.destination_head,
        )?;
        if matches!(plan, RepositoryTransferPlan::UpToDate { .. }) {
            break (source_head, plan);
        }

        let segment = build_repository_transfer_segment(local, source_ref, &expectation)?;
        if segment.pack.transfer_target_head != source_head {
            return Err(conflict(format!(
                "local authority moved during negotiation: planned head {source_head}, packed transfer toward {}",
                segment.pack.transfer_target_head
            )));
        }
        published_changes += segment.pack.changes.len();

        let receipt = transport.receive_pack(repository_id, destination_ref, &segment.pack)?;
        verify_receipt_binds_pack(&segment.pack, &receipt)?;
        receipts.push(receipt);

        if segment.is_final() {
            break (
                source_head,
                RepositoryTransferPlan::FastForward {
                    source_head,
                    destination_head: originally_at,
                    change_count: Some(published_changes),
                },
            );
        }
    };

    let plan = match (receipts.is_empty(), plan) {
        // A publication that took several packs reports the whole move, not
        // the last one: the operator asked to publish a head, not a segment.
        (false, RepositoryTransferPlan::UpToDate { .. }) => RepositoryTransferPlan::FastForward {
            source_head,
            destination_head: originally_at,
            change_count: Some(published_changes),
        },
        (_, plan) => plan,
    };
    Ok(RepositoryTransferOutcome {
        direction: RepositoryTransferDirection::Push,
        repository_id: repository_id.clone(),
        source_ref: source_ref.clone(),
        destination_ref: destination_ref.clone(),
        plan,
        receipts,
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
    // A pack that publishes something other than the advertised head is either
    // one segment of a continuation toward it, or a remote whose authority
    // moved under the negotiation. The declared target is what separates them,
    // and it has to be the head this replica negotiated for.
    if pack.transfer_target_head != source_head {
        return Err(conflict(format!(
            "remote authority moved during negotiation: advertised head {source_head}, exported transfer toward {}",
            pack.transfer_target_head
        )));
    }
    if &pack.destination_ref != destination_ref {
        return Err(invalid(format!(
            "remote exported a pack for destination ref {} but this replica asked for {destination_ref}",
            pack.destination_ref
        )));
    }
    // A segment that publishes the head this replica already holds moves
    // nothing, so admitting it would let a remote keep a continuation loop
    // running without ever closing the gap.
    if Some(pack.source_head) == destination_head {
        return Err(conflict(format!(
            "remote exported a pack publishing {}, which this replica already holds; \
             the transfer toward {source_head} made no progress",
            pack.source_head
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
    pull_from_remote_with(
        local,
        transport,
        repository_id,
        source_ref,
        destination_ref,
        |pack| {
            // The compiled ceilings, deliberately. This convenience wrapper has
            // no deployment configuration to consult and no production caller;
            // the hosted receiver is the daemon's own route, which reads the
            // configured value and passes it. A caller that wants a raised
            // ceiling uses `pull_from_remote_with` and supplies an admit
            // closure carrying its own limits.
            //
            // The empty admission-provenance policy is stated rather than
            // inherited. A generic `StorageBackend` cannot be assumed to sit
            // behind a local `.kin` layout, so this helper has no local
            // creation record it can honestly claim to own. A receiver that
            // does own one supplies its own policy through
            // `pull_from_remote_with`, which is the path the daemon takes.
            apply_repository_transfer_pack_with_pre_commit(
                local,
                repository_id,
                destination_ref,
                actor.clone(),
                pack,
                &RepositoryTransferLimits::default(),
                || Ok(()),
            )
        },
    )
}

/// Run a pull, admitting each pack through a caller-supplied publication step.
///
/// A receiver that owns derived state beyond repository authority has to admit
/// packs itself, so that publication and the refresh of everything derived from
/// it stay on one path. `admit` is that step. It is called once per pack, in
/// order, and this function verifies each returned receipt binds the pack it
/// was given before asking for the next one.
///
/// A remote gap larger than one negotiated envelope arrives as several packs.
/// Each is admitted and receipted on its own; see [`RepositoryTransferOutcome`]
/// for the contract that spans them.
pub fn pull_from_remote_with<B, T, A>(
    local: &RepositoryAuthorityManager<B>,
    transport: &T,
    repository_id: &RepositoryId,
    source_ref: &RefName,
    destination_ref: &RefName,
    mut admit: A,
) -> Result<RepositoryTransferOutcome>
where
    B: StorageBackend + ?Sized + 'static,
    T: RepositoryTransferTransport + ?Sized,
    A: FnMut(&RepositoryTransferPack) -> Result<RepositoryTransferReceipt>,
{
    let mut receipts = Vec::new();
    let mut originally_at = None;
    let mut admitted_changes = 0usize;

    loop {
        let negotiation =
            fetch_pull_pack(local, transport, repository_id, source_ref, destination_ref)?;
        let pack = match negotiation {
            PullNegotiation::UpToDate { head: current } => {
                if receipts.is_empty() {
                    return Ok(RepositoryTransferOutcome {
                        direction: RepositoryTransferDirection::Pull,
                        repository_id: repository_id.clone(),
                        source_ref: source_ref.clone(),
                        destination_ref: destination_ref.clone(),
                        plan: RepositoryTransferPlan::UpToDate { head: current },
                        receipts,
                    });
                }
                break;
            }
            PullNegotiation::Pack(pack) => pack,
        };

        if receipts.is_empty() {
            originally_at = pack.expected_destination_head;
        }
        let is_final = pack.source_head == pack.transfer_target_head;
        admitted_changes += pack.changes.len();

        let receipt = admit(&pack)?;
        verify_receipt_binds_pack(&pack, &receipt)?;
        receipts.push(receipt);

        if is_final {
            break;
        }
    }

    // The head this pull admitted is the one the last receipt was verified to
    // bind, not a head tracked alongside it.
    let source_head = receipts
        .last()
        .map(|receipt| receipt.destination_head)
        .ok_or_else(|| invalid("a pull that moved history produces at least one receipt"))?;
    Ok(RepositoryTransferOutcome {
        direction: RepositoryTransferDirection::Pull,
        repository_id: repository_id.clone(),
        source_ref: source_ref.clone(),
        destination_ref: destination_ref.clone(),
        plan: RepositoryTransferPlan::FastForward {
            source_head,
            destination_head: originally_at,
            change_count: Some(admitted_changes),
        },
        receipts,
    })
}

#[cfg(test)]
mod tests {
    use crate::repository_transfer::apply_repository_transfer_pack;

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
            external_reference_deltas: Vec::new(),
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
            merge_transaction_delta: None,
            sealed_observation: None,
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
        /// Rewrite the repository this peer's discovery envelopes claim to
        /// answer for, to prove the caller checks identity itself rather than
        /// trusting a peer to refuse on its behalf.
        claimed_repository: Option<RepositoryId>,
        /// Rewrite the ref the transfer status answers about, for the same
        /// reason: a peer that answers a question nobody asked is refused.
        claimed_destination_ref: Option<RefName>,
        /// Advertise a smaller envelope than the protocol maximum, so
        /// continuation behaviour is exercised on histories a test can build.
        /// The bound a peer publishes is negotiated, not fixed, so a small one
        /// is a legal peer rather than a test-only shortcut.
        advertised_max_changes: Option<u32>,
        /// Advertise a small bound the sender's change budget cannot reach, so
        /// a step that is unsplittable on a non-change bound is exercised on a
        /// history a test can build.
        advertised_max_trees: Option<u32>,
        /// Publish no default ref, to prove a clone refuses rather than
        /// synthesizing a ref the remote does not publish.
        strip_default_ref: bool,
        exported: RefCell<usize>,
        received: RefCell<usize>,
    }

    impl<'a> LocalPeer<'a> {
        fn new(authority: &'a TestManager) -> Self {
            Self {
                authority,
                actor: AuthorId::new("local-peer"),
                forge_receipt: false,
                claimed_repository: None,
                claimed_destination_ref: None,
                advertised_max_changes: None,
                advertised_max_trees: None,
                strip_default_ref: false,
                exported: RefCell::new(0),
                received: RefCell::new(0),
            }
        }

        fn advertising_max_changes(authority: &'a TestManager, max_changes: u32) -> Self {
            Self {
                advertised_max_changes: Some(max_changes),
                ..Self::new(authority)
            }
        }

        fn advertising_max_trees(authority: &'a TestManager, max_trees: u32) -> Self {
            Self {
                advertised_max_trees: Some(max_trees),
                ..Self::new(authority)
            }
        }

        fn forging_receipts(authority: &'a TestManager) -> Self {
            Self {
                forge_receipt: true,
                ..Self::new(authority)
            }
        }

        fn claiming_repository(authority: &'a TestManager, claimed: RepositoryId) -> Self {
            Self {
                claimed_repository: Some(claimed),
                ..Self::new(authority)
            }
        }

        fn claiming_destination_ref(authority: &'a TestManager, claimed: RefName) -> Self {
            Self {
                claimed_destination_ref: Some(claimed),
                ..Self::new(authority)
            }
        }

        fn without_default_ref(authority: &'a TestManager) -> Self {
            Self {
                strip_default_ref: true,
                ..Self::new(authority)
            }
        }
    }

    impl RepositoryTransferTransport for LocalPeer<'_> {
        fn advertise_refs(
            &self,
            repository_id: &RepositoryId,
        ) -> Result<RepositoryRefAdvertisement> {
            let mut advertisement = repository_ref_advertisement(self.authority, repository_id)?;
            if let Some(claimed) = &self.claimed_repository {
                advertisement.repository_id = claimed.clone();
            }
            if self.strip_default_ref {
                advertisement.default_ref = None;
            }
            Ok(advertisement)
        }

        fn transfer_status(
            &self,
            repository_id: &RepositoryId,
            destination_ref: &RefName,
        ) -> Result<RepositoryTransferStatus> {
            let mut status =
                repository_transfer_status(self.authority, repository_id, destination_ref)?;
            if let Some(claimed) = &self.claimed_repository {
                status.repository_id = claimed.clone();
            }
            if let Some(claimed) = &self.claimed_destination_ref {
                status.destination_ref = claimed.clone();
            }
            if let Some(max_changes) = self.advertised_max_changes {
                status.limits.max_changes = max_changes;
            }
            if let Some(max_trees) = self.advertised_max_trees {
                status.limits.max_trees = max_trees;
            }
            Ok(status)
        }

        fn export_pack(
            &self,
            _repository_id: &RepositoryId,
            source_ref: &RefName,
            expectation: &RepositoryTransferExpectation,
        ) -> Result<RepositoryTransferPack> {
            *self.exported.borrow_mut() += 1;
            // A sender may segment more finely than the receiver's bound
            // requires; the receiver's limits are ceilings, not quotas.
            let mut expectation = expectation.clone();
            if let Some(max_changes) = self.advertised_max_changes {
                expectation.limits.max_changes = expectation.limits.max_changes.min(max_changes);
            }
            if let Some(max_trees) = self.advertised_max_trees {
                expectation.limits.max_trees = expectation.limits.max_trees.min(max_trees);
            }
            build_repository_transfer_segment(self.authority, source_ref, &expectation)
                .map(|segment| segment.pack)
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
                &RepositoryTransferLimits::default(),
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
        let receipt = outcome
            .final_receipt()
            .expect("a moved head produces a receipt");
        assert_eq!(receipt.outcome, RepositoryTransferApplyOutcome::Committed);
        assert_eq!(receipt.destination_head, fixture.source_head);
        assert_eq!(
            outcome.receipts.len(),
            1,
            "a gap inside one envelope is published as one pack"
        );
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
        assert_eq!(planned.pack_count, Some(1));

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
        let receipt = outcome
            .final_receipt()
            .expect("a moved head produces a receipt");
        assert_eq!(receipt.outcome, RepositoryTransferApplyOutcome::Committed);
    }

    /// A line `count` changes longer than the base fixture, and every exact
    /// head on it in order.
    fn line_of(count: u128) -> (Fixture, Vec<SemanticChangeId>) {
        let mut fixture = fixture();
        let lease = fixture.source.read_authority();
        let root = lease
            .snapshot()
            .changes
            .values()
            .find(|change| change.parents.is_empty())
            .expect("the fixture roots one change")
            .id;
        drop(lease);
        let mut heads = vec![root, fixture.source_head];
        let mut previous = Some(fixture.source_head);
        for step in 0..count {
            let head = publish(
                &fixture.source,
                &fixture.repository_id,
                &fixture.main,
                previous,
                100 + step,
                &format!("extend the exact line {step}"),
            );
            heads.push(head);
            previous = Some(head);
        }
        fixture.source_head = previous.expect("the line has a head");
        (fixture, heads)
    }

    #[test]
    fn a_push_past_the_negotiated_envelope_lands_the_whole_gap_across_continuation_packs() {
        // The bound is the envelope, not the history. Six exact changes across
        // an envelope that carries two must arrive whole, and the remote must
        // end on the same head the local replica publishes.
        let (fixture, _) = line_of(4);
        let peer = LocalPeer::advertising_max_changes(&fixture.destination, 2);

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
            RepositoryTransferPlan::FastForward {
                source_head: fixture.source_head,
                destination_head: None,
                change_count: Some(6),
            },
            "the reported move is the whole publication, not its last segment"
        );
        assert_eq!(
            outcome.receipts.len(),
            3,
            "six changes across a two-change envelope take three packs"
        );
        assert_eq!(*peer.received.borrow(), 3);
        assert_eq!(
            head_of(&fixture.destination, &fixture.main),
            Some(fixture.source_head),
            "the remote resolves the ref to the exact head the local replica holds"
        );
        for receipt in &outcome.receipts {
            assert_eq!(receipt.outcome, RepositoryTransferApplyOutcome::Committed);
        }
        assert_eq!(
            outcome.final_receipt().unwrap().destination_head,
            fixture.source_head,
            "the last receipt binds the head the transfer was moving toward"
        );
    }

    #[test]
    fn an_interrupted_multi_pack_push_resumes_from_the_pack_that_landed() {
        // This is the whole per-pack contract. Nothing spans the packs, so an
        // interruption has to leave the remote on a real ancestor of the target
        // and a re-run has to carry only what is left.
        let (fixture, heads) = line_of(4);
        let peer = LocalPeer::advertising_max_changes(&fixture.destination, 2);

        // Publish the first pack alone, exactly as the loop would.
        let expectation =
            negotiated_destination_lease(&peer, &fixture.repository_id, &fixture.main)
                .expect("the remote lease is readable");
        let segment =
            build_repository_transfer_segment(&fixture.source, &fixture.main, &expectation)
                .unwrap();
        assert!(!segment.is_final());
        let receipt = peer
            .receive_pack(&fixture.repository_id, &fixture.main, &segment.pack)
            .unwrap();
        verify_receipt_binds_pack(&segment.pack, &receipt).unwrap();
        let landed = head_of(&fixture.destination, &fixture.main).expect("one pack landed");
        assert_eq!(landed, segment.pack.source_head);
        assert!(
            heads.contains(&landed),
            "an interrupted transfer leaves the remote on an exact change of the line"
        );
        assert_ne!(
            landed, fixture.source_head,
            "the interruption is before the target head"
        );

        // A re-run resumes rather than restarting or rewinding.
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
            RepositoryTransferPlan::FastForward {
                source_head: fixture.source_head,
                destination_head: Some(landed),
                change_count: Some(4),
            },
            "the resumed push carries only what the interrupted one did not"
        );
        assert_eq!(
            head_of(&fixture.destination, &fixture.main),
            Some(fixture.source_head)
        );
    }

    #[test]
    fn a_pull_past_the_negotiated_envelope_admits_the_whole_gap_across_continuation_packs() {
        let (fixture, _) = line_of(4);
        let peer = LocalPeer::advertising_max_changes(&fixture.source, 2);

        let outcome = pull_from_remote(
            &fixture.destination,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
            AuthorId::new("pulling-replica"),
        )
        .unwrap();

        assert_eq!(
            outcome.plan,
            RepositoryTransferPlan::FastForward {
                source_head: fixture.source_head,
                destination_head: None,
                change_count: Some(6),
            }
        );
        assert_eq!(outcome.receipts.len(), 3);
        assert_eq!(*peer.exported.borrow(), 3);
        assert_eq!(
            head_of(&fixture.destination, &fixture.main),
            Some(fixture.source_head)
        );
    }

    #[test]
    fn a_continuation_segment_publishes_a_head_the_destination_ref_can_reach() {
        // A topological prefix is not a valid segment boundary on its own.
        // Merging a side line puts that line's changes ahead of the merge in
        // the closure, and neither of them descends from the head the
        // destination holds. Ending a segment there would ask the destination
        // ref to move sideways onto an unrelated change, so the smallest step
        // that lands a reachable head is the merge itself even though it is
        // bigger than the envelope asked for. Refusing instead would strand a
        // publication partway through.
        let repository_id = RepositoryId::new(format!("segment-merge-{}", Uuid::new_v4())).unwrap();
        let source_dir = TempDir::new().unwrap();
        let destination_dir = TempDir::new().unwrap();
        let source = manager(&source_dir, &repository_id);
        let destination = manager(&destination_dir, &repository_id);
        let main = RefName::branch(b"main").unwrap();
        let side = RefName::branch(b"side").unwrap();

        let root = publish(&source, &repository_id, &main, None, 1, "root");
        let published = publish(&source, &repository_id, &main, Some(root), 2, "mainline");
        let sibling = publish_with_parents(
            &source,
            &repository_id,
            &side,
            vec![root],
            None,
            3,
            "side line",
        );

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
        let after_merge = publish(
            &source,
            &repository_id,
            &main,
            Some(merged),
            5,
            "advance past the merge",
        );

        // One change per envelope. Nothing before the merge can end a segment,
        // so the first pack is the merge closure and the second is the single
        // change after it.
        let narrow = LocalPeer::advertising_max_changes(&destination, 1);
        let outcome = push_to_remote(&source, &narrow, &repository_id, &main, &main)
            .expect("an unsplittable step is taken whole, not refused");

        assert_eq!(
            outcome.receipts.len(),
            2,
            "the merge closure is one step and the change after it is another"
        );
        assert_eq!(
            outcome.receipts[0].destination_head, merged,
            "the first pack lands the merge, the earliest head this ref can reach"
        );
        assert_eq!(outcome.receipts[1].destination_head, after_merge);
        assert_eq!(head_of(&destination, &main), Some(after_merge));
        assert_eq!(
            outcome.plan,
            RepositoryTransferPlan::FastForward {
                source_head: after_merge,
                destination_head: Some(published),
                // The merge closure carries the root a second time: it reaches
                // the merge by a path that never passes through the head the
                // destination held, so the fast-forward closure collects it.
                // The receiver accepts a change it already has when the bytes
                // are identical, which is why this is redundancy rather than a
                // conflict.
                change_count: Some(4),
            }
        );
    }

    /// Run `work` on its own thread and fail the test if it does not finish.
    ///
    /// What these tests assert is termination, and a test that simply called
    /// the segment builder would hang the suite instead of failing it. The
    /// deadline is a liveness bound rather than a performance one: the
    /// fixtures below finish in milliseconds, so it is set far above any
    /// plausible slow machine.
    fn within_deadline<T: Send + 'static>(
        what: &str,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(work());
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(60))
            .unwrap_or_else(|_| panic!("{what} did not terminate"))
    }

    /// Publish a merge whose smallest publishable step is two changes.
    ///
    /// The destination is left holding the mainline change before the merge,
    /// so the closure is the side line followed by the merge and only the
    /// merge descends from the head the destination holds.
    fn merge_past_a_published_head(
        source: &TestManager,
        destination: &TestManager,
        repository_id: &RepositoryId,
        main: &RefName,
    ) {
        let side = RefName::branch(b"side").unwrap();
        let root = publish(source, repository_id, main, None, 1, "root");
        let published = publish(source, repository_id, main, Some(root), 2, "mainline");
        let sibling = publish_with_parents(
            source,
            repository_id,
            &side,
            vec![root],
            None,
            3,
            "side line",
        );

        let peer = LocalPeer::new(destination);
        push_to_remote(source, &peer, repository_id, main, main).unwrap();

        publish_with_parents(
            source,
            repository_id,
            main,
            vec![published, sibling],
            Some(published),
            4,
            "merge the side line",
        );
    }

    #[test]
    fn a_step_that_cannot_be_split_is_refused_by_name_rather_than_replanned() {
        // The smallest step that lands a head this ref can reach is bigger
        // than the envelope on every bound, not only on the change count. The
        // planner reaches past the change budget to take that step, so a
        // smaller budget cannot produce a smaller segment: replanning returns
        // the same one. Refusing and naming the bound is the answer; halving
        // the budget again is a hang standing in for a refusal.
        let outcome = within_deadline("a segment over a non-change bound", || {
            let repository_id =
                RepositoryId::new(format!("unsplittable-{}", Uuid::new_v4())).unwrap();
            let source_dir = TempDir::new().unwrap();
            let destination_dir = TempDir::new().unwrap();
            let source = manager(&source_dir, &repository_id);
            let destination = manager(&destination_dir, &repository_id);
            let main = RefName::branch(b"main").unwrap();
            merge_past_a_published_head(&source, &destination, &repository_id, &main);

            let status = repository_transfer_status(&destination, &repository_id, &main).unwrap();
            let mut expectation = RepositoryTransferExpectation::try_from(status).unwrap();
            // Leave the change bound at the protocol default and clamp only a
            // bound the change budget cannot reach. This is the shape a merge
            // step of more than MAX_TRANSFER_CHANGES changes has under
            // entirely default limits, where max_trees equals max_changes.
            expectation.limits.max_trees = 1;

            build_repository_transfer_segment(&source, &main, &expectation)
                .map(|segment| segment.pack.changes.len())
        });

        let error = outcome.expect_err("a step that cannot be split is refused, not replanned");
        let RepositoryTransferError::Invalid(message) = error else {
            panic!("an envelope too small for the smallest step is a refusal: {error:?}");
        };
        // Three, not two: the merge reaches its side line by a path that never
        // passes through the head the destination holds, so the fast-forward
        // closure collects the root a second time.
        assert!(
            message.contains("carries 3 trees, over negotiated limit 1"),
            "the refusal must name the negotiated bound the step exceeds: {message}"
        );
        assert!(
            message.contains("cannot be split"),
            "the refusal must say why no smaller step is available: {message}"
        );
    }

    #[test]
    fn a_peer_whose_envelope_cannot_carry_the_smallest_step_is_refused_rather_than_looped_on() {
        // The same refusal over the negotiation loop a push actually drives.
        // The bound arrives from the peer's own advertisement, which is where
        // it comes from on the export route, so this is the shape a remote can
        // put a sender in rather than one only a direct caller can build.
        let outcome = within_deadline("a push into an envelope below the smallest step", || {
            let repository_id =
                RepositoryId::new(format!("narrow-peer-{}", Uuid::new_v4())).unwrap();
            let source_dir = TempDir::new().unwrap();
            let destination_dir = TempDir::new().unwrap();
            let source = manager(&source_dir, &repository_id);
            let destination = manager(&destination_dir, &repository_id);
            let main = RefName::branch(b"main").unwrap();
            merge_past_a_published_head(&source, &destination, &repository_id, &main);

            let narrow = LocalPeer::advertising_max_trees(&destination, 1);
            push_to_remote(&source, &narrow, &repository_id, &main, &main)
                .map(|outcome| outcome.receipts.len())
        });

        let error = outcome.expect_err("a peer that cannot carry the smallest step is refused");
        let RepositoryTransferError::Invalid(message) = error else {
            panic!("an envelope too small for the smallest step is a refusal: {error:?}");
        };
        assert!(
            message.contains("over negotiated limit 1"),
            "the refusal must name the negotiated bound the step exceeds: {message}"
        );
    }

    #[test]
    fn an_envelope_that_can_carry_nothing_is_refused_before_a_pack_is_built() {
        // An exporter takes its limits from the request it was handed, not
        // from a status it built, so the numbers are the caller's word. A
        // bound of zero is already refused when a peer advertises one; it is
        // refused on the way in for the same reason, rather than becoming
        // work that can only end in a refusal.
        let (fixture, _) = line_of(2);
        let status =
            repository_transfer_status(&fixture.destination, &fixture.repository_id, &fixture.main)
                .unwrap();
        let mut expectation = RepositoryTransferExpectation::try_from(status).unwrap();
        expectation.limits.max_trees = 0;

        let error = build_repository_transfer_segment(&fixture.source, &fixture.main, &expectation)
            .expect_err("an envelope that can carry nothing is refused");

        let RepositoryTransferError::Invalid(message) = error else {
            panic!("a bound that can carry nothing is a refusal: {error:?}");
        };
        assert!(
            message.contains("the negotiated max_trees is zero"),
            "the refusal must name the bound that can carry nothing: {message}"
        );
    }

    #[test]
    fn a_peer_that_never_advances_is_refused_rather_than_looped_on() {
        // The continuation loop asks the remote where it is, publishes the next
        // step, and asks again. A peer that receipts a pack and then reports the
        // same head has not moved, and there is no number of retries that fixes
        // it. Reporting that as a refusal is the difference between an error and
        // a hang.
        let (fixture, _) = line_of(4);
        let peer = FrozenPeer {
            inner: LocalPeer::advertising_max_changes(&fixture.destination, 2),
        };

        let error = push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .expect_err("a remote that never advances is refused");

        let RepositoryTransferError::Conflict(message) = error else {
            panic!("a peer that will not advance is a conflict: {error:?}");
        };
        assert!(
            message.contains("made no progress"),
            "the refusal must say the remote did not move: {message}"
        );
    }

    /// A peer whose transfer status keeps reporting the head it had before any
    /// pack was published.
    struct FrozenPeer<'a> {
        inner: LocalPeer<'a>,
    }

    impl RepositoryTransferTransport for FrozenPeer<'_> {
        fn advertise_refs(
            &self,
            repository_id: &RepositoryId,
        ) -> Result<RepositoryRefAdvertisement> {
            self.inner.advertise_refs(repository_id)
        }

        fn transfer_status(
            &self,
            repository_id: &RepositoryId,
            destination_ref: &RefName,
        ) -> Result<RepositoryTransferStatus> {
            let mut status = self.inner.transfer_status(repository_id, destination_ref)?;
            status.destination_target = None;
            status.destination_head = None;
            Ok(status)
        }

        fn export_pack(
            &self,
            repository_id: &RepositoryId,
            source_ref: &RefName,
            expectation: &RepositoryTransferExpectation,
        ) -> Result<RepositoryTransferPack> {
            self.inner
                .export_pack(repository_id, source_ref, expectation)
        }

        fn receive_pack(
            &self,
            repository_id: &RepositoryId,
            destination_ref: &RefName,
            pack: &RepositoryTransferPack,
        ) -> Result<RepositoryTransferReceipt> {
            self.inner
                .receive_pack(repository_id, destination_ref, pack)
        }
    }

    #[test]
    fn a_plan_counts_the_packs_a_push_will_take() {
        let (fixture, _) = line_of(4);
        let peer = LocalPeer::advertising_max_changes(&fixture.destination, 2);

        let planned = plan_push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .unwrap();

        assert_eq!(planned.max_changes_per_envelope, 2);
        assert_eq!(
            planned.pack_count,
            Some(3),
            "the plan must say how many packs the operator is about to publish"
        );

        let outcome = push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .unwrap();
        assert_eq!(
            outcome.receipts.len(),
            planned.pack_count.unwrap(),
            "the executed push must take exactly the packs the plan counted"
        );
    }

    #[test]
    fn a_plan_refuses_a_divergent_imported_git_baseline_the_way_a_push_would() {
        // Parity is the point of the plan. A push refuses a Git-authority
        // baseline the two replicas do not share, so a plan that reported a
        // clean fast-forward there would be telling the operator a push will
        // work when it cannot.
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.destination);
        let mut expectation =
            negotiated_destination_lease(&peer, &fixture.repository_id, &fixture.main).unwrap();
        expectation.git_authority_hash = Some(Hash256::from_bytes([0x71; 32]));

        let error = verify_transfer_source_readiness(&fixture.source, &fixture.main, &expectation)
            .expect_err("a Git-authority baseline mismatch is refused before any pack is built");

        assert!(
            matches!(error, RepositoryTransferError::Conflict(_)),
            "a divergent imported-Git baseline is a conflict: {error:?}"
        );
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
    fn a_peer_asked_about_a_repository_it_does_not_serve_refuses_the_advertisement() {
        // This is the peer-side half. The peer refuses because its authority
        // does not belong to the requested repository, so the caller never
        // reaches its own identity check. The caller-side guards are proven
        // separately against a peer that lies instead of refusing.
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
        assert_eq!(*peer.exported.borrow(), 0);
    }

    #[test]
    fn a_default_ref_from_an_advertisement_naming_another_repository_is_refused() {
        // A fresh replica adopts this ref before it holds anything of its own,
        // so the advertisement is the only surface that can be checked at all.
        let fixture = fixture();
        let other = RepositoryId::new("some-other-repository").unwrap();
        let peer = LocalPeer::claiming_repository(&fixture.source, other.clone());

        let error = remote_default_ref(&peer, &fixture.repository_id).expect_err(
            "an advertisement that names another repository answers a different question",
        );

        let RepositoryTransferError::Invalid(message) = error else {
            panic!("a peer answering for another repository is an invalid envelope");
        };
        assert!(
            message.contains(other.as_str()) && message.contains(fixture.repository_id.as_str()),
            "the refusal must name both repositories so the operator can act on it: {message}"
        );
    }

    #[test]
    fn a_pull_refuses_an_advertisement_naming_another_repository_before_any_export() {
        // The peer here holds this repository and answers correctly about its
        // refs, but labels the envelope with another repository. Only the
        // caller can catch that, and it has to catch it at discovery rather
        // than leaving it to the admission check after a pack is already here.
        let fixture = fixture();
        let other = RepositoryId::new("some-other-repository").unwrap();
        let peer = LocalPeer::claiming_repository(&fixture.source, other.clone());

        let error = pull_from_remote(
            &fixture.destination,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
            AuthorId::new("pulling-replica"),
        )
        .expect_err("a peer answering for another repository has not answered for this one");

        let RepositoryTransferError::Invalid(message) = error else {
            panic!("a peer answering for another repository is an invalid envelope");
        };
        assert!(
            message.contains("remote ref advertisement belongs to repository"),
            "the caller's own check must be what refuses, not the peer's: {message}"
        );
        assert_eq!(
            *peer.exported.borrow(),
            0,
            "a refusal must happen before any pack is exported"
        );
        assert_eq!(
            head_of(&fixture.destination, &fixture.main),
            None,
            "a refused pull must admit nothing"
        );
    }

    #[test]
    fn a_push_refuses_a_transfer_status_naming_another_repository() {
        // The pack builder compares the two repository ids as well, so the
        // refusal is asserted on the caller's own message: reaching the pack
        // builder at all means this replica read a lease it should have
        // refused, and acted on its head and limits.
        let fixture = fixture();
        let other = RepositoryId::new("some-other-repository").unwrap();
        let peer = LocalPeer::claiming_repository(&fixture.destination, other.clone());

        let error = push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .expect_err("a lease labelled for another repository is not this repository's lease");

        let RepositoryTransferError::Invalid(message) = error else {
            panic!("a peer answering for another repository is an invalid envelope");
        };
        assert!(
            message.contains("remote transfer status belongs to repository")
                && message.contains(other.as_str()),
            "the caller's own check must be what refuses, not the pack builder's: {message}"
        );
        assert_eq!(*peer.received.borrow(), 0);
        assert_eq!(
            head_of(&fixture.destination, &fixture.main),
            None,
            "a refused push must move nothing"
        );
    }

    #[test]
    fn a_push_refuses_a_transfer_status_answering_for_another_ref() {
        // A lease read for one ref says nothing about another. Accepting it
        // would publish against a head and a policy that were never asked for.
        let fixture = fixture();
        let elsewhere = RefName::branch(b"elsewhere").unwrap();
        let peer = LocalPeer::claiming_destination_ref(&fixture.destination, elsewhere);

        let error = push_to_remote(
            &fixture.source,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .expect_err("a status for another ref does not answer the question this replica asked");

        let RepositoryTransferError::Invalid(message) = error else {
            panic!("a status answering for another ref is an invalid envelope");
        };
        assert!(
            message.contains("remote transfer status answers for ref"),
            "the refusal must say the peer answered a different question: {message}"
        );
        assert_eq!(
            *peer.received.borrow(),
            0,
            "a refusal must happen before any pack reaches the remote"
        );
        assert_eq!(
            head_of(&fixture.destination, &fixture.main),
            None,
            "a refused push must move nothing"
        );
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

    /// What a fresh replica has to learn before it has any authority of its
    /// own: whose repository this is, and which ref to be created against.
    #[test]
    fn replica_identity_is_read_from_the_remote_advertisement() {
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.source);

        let identity = negotiate_replica_identity(&peer, &fixture.repository_id).unwrap();

        assert_eq!(identity.repository_id, fixture.repository_id);
        assert_eq!(identity.default_ref, fixture.main);
        assert_eq!(identity.default_ref_head, Some(fixture.source_head));
        assert_eq!(&identity.roots, fixture.source.read_authority().roots());
    }

    /// A peer answering for another repository must be refused rather than
    /// adopted: adopting it would silently point a clone at a repository
    /// nobody asked for.
    #[test]
    fn a_peer_answering_for_another_repository_is_never_adopted() {
        let fixture = fixture();
        let other = RepositoryId::new(format!("other-{}", Uuid::new_v4())).unwrap();
        let peer = LocalPeer::claiming_repository(&fixture.source, other.clone());

        let error = negotiate_replica_identity(&peer, &fixture.repository_id).unwrap_err();
        let message = error.to_string();
        assert!(
            matches!(error, RepositoryTransferError::Invalid(_)),
            "{message}"
        );
        assert!(message.contains(other.as_str()), "{message}");
        assert!(
            message.contains(fixture.repository_id.as_str()),
            "{message}"
        );
    }

    /// An unborn repository still publishes the ref its history will land on.
    /// One that publishes none leaves a clone nothing to adopt, and inventing
    /// `main` would leave a ghost ref no transfer can reconcile.
    #[test]
    fn a_peer_publishing_no_default_ref_leaves_a_replica_nothing_to_adopt() {
        let fixture = fixture();
        let peer = LocalPeer::without_default_ref(&fixture.source);

        let error = negotiate_replica_identity(&peer, &fixture.repository_id).unwrap_err();
        let message = error.to_string();
        assert!(
            matches!(error, RepositoryTransferError::Invalid(_)),
            "{message}"
        );
        assert!(
            message.contains(fixture.repository_id.as_str()),
            "{message}"
        );
    }

    /// A repository that has admitted nothing is a legal clone source: the
    /// replica adopts its identity and its declared default ref, and there is
    /// no head to reach.
    #[test]
    fn an_unborn_remote_advertises_an_identity_with_no_head() {
        let fixture = fixture();
        let unborn_dir = TempDir::new().unwrap();
        let unborn_id = RepositoryId::new(format!("unborn-{}", Uuid::new_v4())).unwrap();
        let unborn = manager(&unborn_dir, &unborn_id);
        adopt_default_ref(&unborn, &unborn_id, &fixture.main);
        let peer = LocalPeer::new(&unborn);

        let identity = negotiate_replica_identity(&peer, &unborn_id).unwrap();

        assert_eq!(identity.repository_id, unborn_id);
        assert_eq!(identity.default_ref, fixture.main);
        assert_eq!(identity.default_ref_head, None);

        // Nothing to reach, so the adoption verifies on identity alone.
        verify_adopted_replica_identity(
            &unborn,
            &unborn_id,
            &identity,
            &up_to_date_outcome(&unborn_id, &fixture.main, None),
        )
        .unwrap();
    }

    /// The adoption is proven by history arriving under the adopted identity,
    /// not by the identity having been written down.
    #[test]
    fn an_adoption_verifies_once_the_advertised_head_is_admitted() {
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.source);
        let identity = negotiate_replica_identity(&peer, &fixture.repository_id).unwrap();

        let outcome = pull_from_remote(
            &fixture.destination,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
            AuthorId::new("clone-identity-test"),
        )
        .unwrap();

        verify_adopted_replica_identity(
            &fixture.destination,
            &fixture.repository_id,
            &identity,
            &outcome,
        )
        .unwrap();
        assert_eq!(
            head_of(&fixture.destination, &fixture.main),
            Some(fixture.source_head)
        );
    }

    /// A replica that adopted an identity and admitted nothing is exactly the
    /// state a half-finished clone leaves behind. Reporting it as an adopted
    /// replica would claim history it does not hold.
    #[test]
    fn an_adoption_that_admitted_no_history_is_refused_by_name() {
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.source);
        let identity = negotiate_replica_identity(&peer, &fixture.repository_id).unwrap();

        let error = verify_adopted_replica_identity(
            &fixture.destination,
            &fixture.repository_id,
            &identity,
            &up_to_date_outcome(&fixture.repository_id, &fixture.main, None),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(
            matches!(error, RepositoryTransferError::Conflict(_)),
            "{message}"
        );
        assert!(
            message.contains(&fixture.source_head.to_string()),
            "{message}"
        );
    }

    /// The committed authority is what decides, not the identity a caller
    /// passes in. A replica whose authority records another repository has not
    /// adopted this one, however the call was spelled.
    #[test]
    fn a_replica_whose_authority_records_another_repository_is_refused() {
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.source);
        let identity = negotiate_replica_identity(&peer, &fixture.repository_id).unwrap();
        let other_dir = TempDir::new().unwrap();
        let other_id = RepositoryId::new(format!("other-{}", Uuid::new_v4())).unwrap();
        let other = manager(&other_dir, &other_id);
        adopt_default_ref(&other, &other_id, &fixture.main);

        let error = verify_adopted_replica_identity(
            &other,
            &fixture.repository_id,
            &identity,
            &up_to_date_outcome(&fixture.repository_id, &fixture.main, None),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(
            matches!(error, RepositoryTransferError::Conflict(_)),
            "{message}"
        );
        assert!(message.contains(other_id.as_str()), "{message}");
        assert!(
            message.contains(fixture.repository_id.as_str()),
            "{message}"
        );
    }

    /// The identity a replica adopted and the identity a caller passes in have
    /// to be the same repository. They disagree exactly when a caller verified
    /// one adoption against another's advertisement, and reporting that as
    /// verified would claim a peer said something it never said.
    #[test]
    fn an_identity_naming_another_repository_is_refused() {
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.source);
        let mut identity = negotiate_replica_identity(&peer, &fixture.repository_id).unwrap();
        let other = RepositoryId::new(format!("other-{}", Uuid::new_v4())).unwrap();
        identity.repository_id = other.clone();

        let error = verify_adopted_replica_identity(
            &fixture.destination,
            &fixture.repository_id,
            &identity,
            &up_to_date_outcome(&fixture.repository_id, &fixture.main, None),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(
            matches!(error, RepositoryTransferError::Invalid(_)),
            "{message}"
        );
        assert!(message.contains(other.as_str()), "{message}");
        assert!(
            message.contains(fixture.repository_id.as_str()),
            "{message}"
        );
    }

    /// A transfer that ran against another repository proves nothing about this
    /// adoption, however it was reached. Accepting it would let a replica
    /// report itself cloned on the strength of a transfer that never touched
    /// the repository it adopted.
    #[test]
    fn a_transfer_that_ran_against_another_repository_is_refused() {
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.source);
        let identity = negotiate_replica_identity(&peer, &fixture.repository_id).unwrap();
        let other = RepositoryId::new(format!("other-{}", Uuid::new_v4())).unwrap();

        let error = verify_adopted_replica_identity(
            &fixture.destination,
            &fixture.repository_id,
            &identity,
            &up_to_date_outcome(&other, &fixture.main, None),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(
            matches!(error, RepositoryTransferError::Invalid(_)),
            "{message}"
        );
        assert!(message.contains(other.as_str()), "{message}");
        assert!(
            message.contains(fixture.repository_id.as_str()),
            "{message}"
        );
    }

    /// The receipts are what bind admitted history to the adopted identity, so
    /// a receipt naming another repository is the one arm where the transfer
    /// really did move history and it landed bound to something else. The
    /// outcome here is a real pull's, mutated in one field, so nothing but the
    /// binding can be what refuses it.
    #[test]
    fn a_receipt_binding_another_repository_is_refused() {
        let fixture = fixture();
        let peer = LocalPeer::new(&fixture.source);
        let identity = negotiate_replica_identity(&peer, &fixture.repository_id).unwrap();
        let mut outcome = pull_from_remote(
            &fixture.destination,
            &peer,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
            AuthorId::new("clone-identity-test"),
        )
        .unwrap();
        let other = RepositoryId::new(format!("other-{}", Uuid::new_v4())).unwrap();
        outcome
            .receipts
            .first_mut()
            .expect("a pull that moved history returns a receipt")
            .repository_id = other.clone();

        let error = verify_adopted_replica_identity(
            &fixture.destination,
            &fixture.repository_id,
            &identity,
            &outcome,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(
            matches!(error, RepositoryTransferError::Conflict(_)),
            "{message}"
        );
        assert!(message.contains(other.as_str()), "{message}");
        assert!(
            message.contains(fixture.repository_id.as_str()),
            "{message}"
        );
    }

    /// Declare a repository's default ref without publishing any history, which
    /// is the state an unborn remote and a freshly adopted replica share.
    fn adopt_default_ref(manager: &TestManager, repository_id: &RepositoryId, ref_name: &RefName) {
        let lease = manager.read_authority();
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(Uuid::new_v4()),
            repository_id: repository_id.clone(),
            expected_generation: lease.roots().generation,
            expected_roots: lease.roots().clone(),
            actor: AuthorId::new("negotiation-fixture"),
            reason: "adopt the default ref".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: Some(DefaultRefMutation {
                expected: DefaultRefExpectation::MustBeUnset,
                new_default: Some(ref_name.clone()),
            }),
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        drop(lease);
        manager.commit_repository_transaction(transaction).unwrap();
    }

    /// An outcome for a negotiation that moved nothing, which is what a caller
    /// holds when the transfer half of a clone did not run.
    fn up_to_date_outcome(
        repository_id: &RepositoryId,
        ref_name: &RefName,
        head: Option<SemanticChangeId>,
    ) -> RepositoryTransferOutcome {
        RepositoryTransferOutcome {
            direction: RepositoryTransferDirection::Pull,
            repository_id: repository_id.clone(),
            source_ref: ref_name.clone(),
            destination_ref: ref_name.clone(),
            plan: RepositoryTransferPlan::UpToDate { head },
            receipts: Vec::new(),
        }
    }
}
