// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact, bounded repository-v6 fast-forward transfer.
//!
//! This protocol never reads a checkout, Git object directory, or legacy
//! semantic-delta stream. A sender builds a pack from one coherent repository
//! authority lease and its immutable CAS. A receiver validates the complete
//! change closure, exact tree identities, body identities, destination
//! ref/root lease, and protocol features before publishing one repository
//! transaction. CAS writes that precede publication are immutable and carry no
//! authority by themselves.

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use kin_db::{
    KinDbError, PersistedRepositoryAuthority, RepositoryAuthorityManager, RepositoryAuthorityState,
    StorageBackend,
};
use kin_model::{
    compute_resolved_tree_hash, validate_semantic_change_id, AuthorId, ChangeOrigin, ChangeStore,
    DefaultRefExpectation, DefaultRefMutation, ExternalChangeAlias, ExternalObjectId,
    ExternalObjectKind, ExternalObjectRecord, GitExternalAuthority, GitExternalAuthorityDelta,
    Hash256, ModelError, OperationId, RefExpectation, RefMutation, RefName, RefTarget,
    RefUpdatePolicy, RepositoryCommitOutcome, RepositoryCommitReceipt, RepositoryId,
    RepositoryTransaction, RootBundle, SemanticChange, SemanticChangeId, TreeEntry,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Read repository-v6 authority metadata under a name that cannot be mistaken
/// for filesystem metadata.
///
/// `AuthorityReadLease` exposes this state as `metadata()`, which reads at a
/// call site exactly like `std::fs::Metadata` access and trips the zero
/// file-search guard's filesystem heuristic. The guard is deliberately blunt,
/// so the fix is to make authority reads unmistakable rather than to teach the
/// guard an exception that a real filesystem probe could later hide behind.
pub(crate) trait RepositoryAuthorityMetadata {
    fn authority_metadata(&self) -> &PersistedRepositoryAuthority;

    /// The same state, read where the caller can refuse instead of abort.
    ///
    /// The envelope is a kin-db invariant rather than a local one: opening
    /// authority refuses a persisted snapshot that carries none, constructs one
    /// for a store that has never been written, and every commit re-sets it. So
    /// this returns `None` only if that invariant is broken, and no test here
    /// can produce that state.
    ///
    /// Adoption verification reads this anyway. It runs against a replica this
    /// process just created, it is the one caller whose whole job is deciding
    /// whether an adoption is recorded, and a refusal naming the replica is
    /// strictly more useful there than a panic in the middle of a clone.
    fn committed_authority_metadata(&self) -> Option<&PersistedRepositoryAuthority>;
}

impl RepositoryAuthorityMetadata for RepositoryAuthorityState {
    fn authority_metadata(&self) -> &PersistedRepositoryAuthority {
        self.committed_authority_metadata()
            .expect("repository authority lease always carries authority metadata")
    }

    fn committed_authority_metadata(&self) -> Option<&PersistedRepositoryAuthority> {
        self.snapshot().repository_authority.as_ref()
    }
}

pub const REPOSITORY_TRANSFER_PROTOCOL: &str = "kin-repository-v6-fast-forward";
/// Version 2 adds `transfer_target_head`, which is what lets a receiver tell a
/// deliberate continuation segment apart from a peer whose authority moved
/// under the negotiation. A version 1 peer is refused by name rather than
/// through a field-shape parse error.
///
/// Version 3 adds `git_authority_bootstrap`, which is what lets a Git-admitted
/// replica publish into an EMPTY one. Transfer v1 carries a fast-forward only
/// between replicas whose imported-Git authority already matches, and no push
/// could establish one, so a repository that came from Git had no route into a
/// hosted store at all. A version 2 peer is refused by name, same as version 1.
///
/// Version 4 makes the transfer identity a deterministic manifest over the
/// content-addressed identities the receiver independently verifies. Version
/// 3 hashed raw JSON for the whole pack, including unordered entity metadata
/// maps. A receiver reconstructing one of those maps could therefore reject a
/// semantically identical pack under a different byte order.
pub const REPOSITORY_TRANSFER_SCHEMA_VERSION: u32 = 4;
pub const FEATURE_EXACT_TREES: &str = "exact-trees-v1";
pub const FEATURE_IMMUTABLE_SOURCE_CAS: &str = "immutable-source-cas-v1";
pub const FEATURE_REF_CAS: &str = "ref-cas-v1";
pub const FEATURE_RAW_REPOSITORY_PATHS: &str = "raw-repository-paths-v1";

pub const MAX_TRANSFER_CHANGES: usize = 512;
pub const MAX_TRANSFER_TREES: usize = MAX_TRANSFER_CHANGES;
pub const MAX_TRANSFER_BODIES: usize = 4096;
pub const MAX_TRANSFER_EXTERNAL_OBJECTS: usize = 4096;
pub const MAX_TRANSFER_ALIASES: usize = 512;
/// The decoded-closure ceiling a receiver enforces unless its deployment says
/// otherwise.
///
/// It is a TRANSPORT bound and never the product's answer to repository size.
/// A repository larger than one envelope is segmentation's problem; this number
/// only decides how much a single envelope may carry, and raising it does not
/// make a large repository publishable, it makes a slightly larger one fit.
///
/// 64 MiB rather than the 16 MiB it replaces. `kin`'s own tip closure is 982
/// objects and 27.77 MiB, so 16 MiB refused the repository this product is
/// built in, and 32 MiB would have cleared it by about 15 percent, which is no
/// margin for something that grows. The cost of the number is memory: the
/// decoded closure is held in one map while a pack is validated, so this
/// ceiling IS the peak allocation of a receive and a host pays it per
/// concurrent receive.
///
/// A deployment with more headroom raises it without a release. See
/// [`RepositoryTransferLimits::bounded_by`], and note that a raised local
/// ceiling never overrides a peer that advertised less.
pub const MAX_TRANSFER_DECODED_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// The environment variable a deployment raises the decoded-closure ceiling
/// with, named here so the refusal message and the reader cannot drift apart.
///
/// kin-remote does not read it. The library takes limits and the deployment
/// decides them, so the read lives in the daemon, which is the layer that
/// already owns configuration. What lives here is the NAME, because a refusal
/// that names a knob and a knob that lives elsewhere is exactly the pair that
/// goes stale.
pub const DECODED_BODY_CEILING_ENV: &str = "KIN_TRANSFER_MAX_DECODED_BODY_BYTES";
pub const MAX_TRANSFER_BODY_BYTES: u64 = 8 * 1024 * 1024;

const REQUIRED_FEATURES: [&str; 4] = [
    FEATURE_EXACT_TREES,
    FEATURE_IMMUTABLE_SOURCE_CAS,
    FEATURE_REF_CAS,
    FEATURE_RAW_REPOSITORY_PATHS,
];

#[derive(Debug, Error)]
pub enum RepositoryTransferError {
    #[error("invalid repository transfer: {0}")]
    Invalid(String),
    #[error("repository transfer conflict: {0}")]
    Conflict(String),
    #[error("repository transfer storage failed: {0}")]
    Storage(String),
}

pub type Result<T> = std::result::Result<T, RepositoryTransferError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryTransferLimits {
    pub max_changes: u32,
    pub max_trees: u32,
    pub max_bodies: u32,
    pub max_external_objects: u32,
    pub max_aliases: u32,
    pub max_decoded_body_bytes: u64,
    pub max_single_body_bytes: u64,
}

impl Default for RepositoryTransferLimits {
    fn default() -> Self {
        Self {
            max_changes: MAX_TRANSFER_CHANGES as u32,
            max_trees: MAX_TRANSFER_TREES as u32,
            max_bodies: MAX_TRANSFER_BODIES as u32,
            max_external_objects: MAX_TRANSFER_EXTERNAL_OBJECTS as u32,
            max_aliases: MAX_TRANSFER_ALIASES as u32,
            max_decoded_body_bytes: MAX_TRANSFER_DECODED_BODY_BYTES,
            max_single_body_bytes: MAX_TRANSFER_BODY_BYTES,
        }
    }
}

impl RepositoryTransferLimits {
    /// Bound peer- or request-supplied ceilings by what this implementation can
    /// construct and validate locally.
    ///
    /// Transfer limits are ceilings rather than quotas, so choosing the
    /// smaller local value remains compatible with a peer that can accept a
    /// larger envelope. It also keeps an untrusted advertisement or export
    /// request from making this process assemble a pack its own receiver would
    /// reject, or from turning one bounded transfer step into unbounded work.
    fn bounded_by_local(self) -> Self {
        self.bounded_by(&Self::default())
    }

    /// The same rule against an arbitrary other ceiling rather than the
    /// compiled-in one.
    ///
    /// A deployment may raise its own decoded-closure ceiling above the
    /// default, so "bound by local" can no longer mean "bound by the constant":
    /// that would clamp a deliberately raised host straight back down. The
    /// receiver computes its effective bound as its CONFIGURED limits bounded
    /// by whatever the peer advertised, which keeps both halves honest. A host
    /// with headroom can accept more without a release, and a peer that cannot
    /// take it still wins, because the minimum of the two is what either side
    /// can actually construct and validate.
    #[must_use]
    pub fn bounded_by(self, other: &Self) -> Self {
        Self {
            max_changes: self.max_changes.min(other.max_changes),
            max_trees: self.max_trees.min(other.max_trees),
            max_bodies: self.max_bodies.min(other.max_bodies),
            max_external_objects: self.max_external_objects.min(other.max_external_objects),
            max_aliases: self.max_aliases.min(other.max_aliases),
            max_decoded_body_bytes: self
                .max_decoded_body_bytes
                .min(other.max_decoded_body_bytes),
            max_single_body_bytes: self.max_single_body_bytes.min(other.max_single_body_bytes),
        }
    }

    /// This process's limits with the decoded-closure ceiling replaced.
    ///
    /// The one knob a deployment turns. Everything else stays at the compiled
    /// value, because the ruling that produced this is about the byte ceiling
    /// and nothing else, and moving five unrelated bounds while passing through
    /// would be a change nobody asked for.
    #[must_use]
    pub fn with_decoded_body_ceiling(self, max_decoded_body_bytes: u64) -> Self {
        Self {
            max_decoded_body_bytes,
            ..self
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryTransferStatus {
    pub schema_version: u32,
    pub protocol: String,
    pub repository_id: RepositoryId,
    pub destination_ref: RefName,
    pub destination_target: Option<RefTarget>,
    pub destination_head: Option<SemanticChangeId>,
    pub destination_tree_hash: Option<Hash256>,
    pub roots: RootBundle,
    pub default_ref: Option<RefName>,
    pub git_authority_hash: Option<Hash256>,
    pub supported_features: Vec<String>,
    pub limits: RepositoryTransferLimits,
    /// This peer applies a publication whose closure is larger than one
    /// envelope, by receiving the continuation packs it is split into.
    ///
    /// What this does not claim is freedom from every bound. A single change
    /// whose new bodies exceed the negotiated byte limit is indivisible and is
    /// refused by name, because there is no smaller step that still lands a
    /// valid head. The bound that continuation packs removed is the one that
    /// scaled with history length.
    pub push_apply_ready: bool,
    /// The server can export this bounded exact seam. The name deliberately
    /// avoids advertising a general pull capability.
    pub bounded_envelope_export_ready: bool,
    /// This peer admits an exported closure larger than one envelope, pack by
    /// pack, under the same bound as [`Self::push_apply_ready`].
    pub pull_apply_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryTransferExpectation {
    pub repository_id: RepositoryId,
    pub destination_ref: RefName,
    pub destination_target: Option<RefTarget>,
    pub destination_head: Option<SemanticChangeId>,
    pub roots: RootBundle,
    pub default_ref: Option<RefName>,
    pub git_authority_hash: Option<Hash256>,
    pub supported_features: Vec<String>,
    pub limits: RepositoryTransferLimits,
}

impl TryFrom<RepositoryTransferStatus> for RepositoryTransferExpectation {
    type Error = RepositoryTransferError;

    fn try_from(status: RepositoryTransferStatus) -> Result<Self> {
        validate_status(&status)?;
        let limits = status.limits.bounded_by_local();
        Ok(Self {
            repository_id: status.repository_id,
            destination_ref: status.destination_ref,
            destination_target: status.destination_target,
            destination_head: status.destination_head,
            roots: status.roots,
            default_ref: status.default_ref,
            git_authority_hash: status.git_authority_hash,
            supported_features: status.supported_features,
            limits,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryTransferTreeIdentity {
    pub change_id: SemanticChangeId,
    pub tree_hash: Hash256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryTransferBody {
    pub hash: Hash256,
    pub byte_len: u64,
    pub bytes_base64: String,
}

impl RepositoryTransferBody {
    pub fn from_bytes(hash: Hash256, bytes: &[u8]) -> Result<Self> {
        verify_body(hash, bytes)?;
        let byte_len = u64::try_from(bytes.len())
            .map_err(|_| invalid("source body length does not fit u64"))?;
        Ok(Self {
            hash,
            byte_len,
            bytes_base64: BASE64.encode(bytes),
        })
    }

    pub fn decode(&self) -> Result<Vec<u8>> {
        if self.byte_len > MAX_TRANSFER_BODY_BYTES {
            return Err(invalid(format!(
                "source body {} declares {} bytes, over the {} byte limit",
                self.hash, self.byte_len, MAX_TRANSFER_BODY_BYTES
            )));
        }
        let bytes = BASE64.decode(&self.bytes_base64).map_err(|error| {
            invalid(format!(
                "source body {} is not canonical base64: {error}",
                self.hash
            ))
        })?;
        if BASE64.encode(&bytes) != self.bytes_base64 {
            return Err(invalid(format!(
                "source body {} base64 encoding is not canonical",
                self.hash
            )));
        }
        let actual_len = u64::try_from(bytes.len())
            .map_err(|_| invalid("decoded source body length does not fit u64"))?;
        if actual_len != self.byte_len {
            return Err(invalid(format!(
                "source body {} declares {} bytes but decodes to {}",
                self.hash, self.byte_len, actual_len
            )));
        }
        verify_body(self.hash, &bytes)?;
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryTransferPack {
    pub schema_version: u32,
    pub protocol: String,
    pub transfer_id: Hash256,
    pub operation_id: OperationId,
    pub repository_id: RepositoryId,
    pub source_ref: RefName,
    pub destination_ref: RefName,
    /// The exact head this one pack publishes.
    ///
    /// For a transfer that fits a single envelope this is the source ref head.
    /// For a continuation segment it is an intermediate checkpoint: an exact
    /// ancestor of [`Self::transfer_target_head`] that the destination ref can
    /// fast-forward to on its own.
    pub source_head: SemanticChangeId,
    /// The head the whole transfer is moving toward.
    ///
    /// A receiver needs this to tell two very different things apart. A pack
    /// whose `source_head` is not the head the peer advertised is either one
    /// segment of a deliberate continuation, or a peer whose authority moved
    /// mid-negotiation. Without a declared target those are indistinguishable,
    /// and the safe reading of the second one is to refuse.
    pub transfer_target_head: SemanticChangeId,
    pub source_tree_hash: Hash256,
    pub expected_destination_target: Option<RefTarget>,
    pub expected_destination_head: Option<SemanticChangeId>,
    pub expected_destination_roots: RootBundle,
    pub expected_destination_default_ref: Option<RefName>,
    /// Clean-slate v1 supports native fast-forwards over an identical imported
    /// Git baseline. A changed Git authority is rejected rather than adapted.
    pub source_git_authority_hash: Option<Hash256>,
    pub expected_destination_git_authority_hash: Option<Hash256>,
    /// The imported-Git authority this pack ESTABLISHES on a destination that
    /// has none.
    ///
    /// Present only for a bootstrap, which is the one case where the two
    /// replicas' Git authority is allowed to differ: the destination's is
    /// absent and this pack is what gives it one. Every other pack leaves this
    /// `None` and the equality rule above stands unchanged.
    ///
    /// A bootstrap is admitted only into a replica that is empty in five
    /// respects at once, and it declares all five in the `expected_destination`
    /// fields, which the receiver compare-and-swaps against its own live lease
    /// before it commits. So the guard against a second publisher rebinding an
    /// established repository is the lease check that already exists, not
    /// anything this field introduces. kin-db refuses the same thing again
    /// underneath, because an `initialize` delta carries `old: None` and the
    /// storage layer compares it against what is actually there.
    pub git_authority_bootstrap: Option<GitExternalAuthority>,
    pub required_features: Vec<String>,
    /// Parent-before-child exact semantic closure.
    pub changes: Vec<SemanticChange>,
    /// One independently recomputed resolved-tree identity per included change.
    pub trees: Vec<RepositoryTransferTreeIdentity>,
    /// Exact external records needed by included Git-origin changes.
    pub external_objects: Vec<ExternalObjectRecord>,
    pub aliases: Vec<ExternalChangeAlias>,
    /// Deduplicated immutable bytes needed by new tree states and external
    /// records. Gitlinks deliberately have no body.
    pub bodies: Vec<RepositoryTransferBody>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryTransferApplyOutcome {
    Committed,
    IdempotentReplay,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryTransferReceipt {
    pub schema_version: u32,
    pub protocol: String,
    pub transfer_id: Hash256,
    pub repository_id: RepositoryId,
    pub destination_ref: RefName,
    pub destination_head: SemanticChangeId,
    pub outcome: RepositoryTransferApplyOutcome,
    pub authority_receipt: RepositoryCommitReceipt,
}

pub fn repository_transfer_status<B: StorageBackend + ?Sized + 'static>(
    authority: &RepositoryAuthorityManager<B>,
    repository_id: &RepositoryId,
    destination_ref: &RefName,
) -> Result<RepositoryTransferStatus> {
    let lease = authority.read_authority();
    if &lease.authority_metadata().repository_id != repository_id {
        return Err(invalid(format!(
            "authority belongs to {}, not requested repository {}",
            lease.authority_metadata().repository_id,
            repository_id
        )));
    }
    let destination_target = lease
        .authority_metadata()
        .ref_state
        .refs
        .iter()
        .find(|entry| &entry.name == destination_ref)
        .map(|entry| entry.target.clone());
    let destination_head = destination_target
        .as_ref()
        .map(|target| lease.resolve_target_change_id(target).map_err(storage))
        .transpose()?;
    let destination_tree_hash = destination_head
        .map(|head| {
            let store = TransferChangeStore::new(lease.snapshot().changes.values().cloned());
            store
                .resolve_tree_at(&head)
                .map_err(model)
                .and_then(|tree| compute_resolved_tree_hash(&tree).map_err(model))
        })
        .transpose()?;
    let git_authority_hash =
        hash_git_authority(lease.authority_metadata().git_external_authority.as_ref())?;

    Ok(RepositoryTransferStatus {
        schema_version: REPOSITORY_TRANSFER_SCHEMA_VERSION,
        protocol: REPOSITORY_TRANSFER_PROTOCOL.to_string(),
        repository_id: repository_id.clone(),
        destination_ref: destination_ref.clone(),
        destination_target,
        destination_head,
        destination_tree_hash,
        roots: lease.roots().clone(),
        default_ref: lease.authority_metadata().ref_state.default_ref.clone(),
        git_authority_hash,
        supported_features: required_features(),
        limits: RepositoryTransferLimits::default(),
        push_apply_ready: true,
        bounded_envelope_export_ready: true,
        pull_apply_ready: true,
    })
}

/// One advertised ref and the change it resolves to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRefAdvertisementEntry {
    pub name: RefName,
    pub target: RefTarget,
    pub head: SemanticChangeId,
}

/// What a repository publishes before any history moves.
///
/// A clone starts here: it has no ref of its own to ask about yet, so it
/// cannot use the per-ref transfer status, and it needs the default ref
/// before it can initialize a replica that adopts the remote layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRefAdvertisement {
    pub schema_version: u32,
    pub protocol: String,
    pub repository_id: RepositoryId,
    /// Published refs ordered by name, so the advertisement is one spelling
    /// per repository state rather than a function of storage order.
    pub refs: Vec<RepositoryRefAdvertisementEntry>,
    /// The ref a fresh clone adopts.
    ///
    /// An unborn repository publishes a default ref that is absent from
    /// `refs`: it has declared where history will land without having any.
    /// A clone must reproduce that state rather than treat it as an error.
    pub default_ref: Option<RefName>,
    pub roots: RootBundle,
    pub supported_features: Vec<String>,
    pub limits: RepositoryTransferLimits,
}

/// Advertise every published ref for `repository_id`.
pub fn repository_ref_advertisement<B: StorageBackend + ?Sized + 'static>(
    authority: &RepositoryAuthorityManager<B>,
    repository_id: &RepositoryId,
) -> Result<RepositoryRefAdvertisement> {
    let lease = authority.read_authority();
    if &lease.authority_metadata().repository_id != repository_id {
        return Err(invalid(format!(
            "authority belongs to {}, not requested repository {}",
            lease.authority_metadata().repository_id,
            repository_id
        )));
    }

    let mut refs = Vec::with_capacity(lease.authority_metadata().ref_state.refs.len());
    for entry in &lease.authority_metadata().ref_state.refs {
        refs.push(RepositoryRefAdvertisementEntry {
            name: entry.name.clone(),
            target: entry.target.clone(),
            head: lease
                .resolve_target_change_id(&entry.target)
                .map_err(storage)?,
        });
    }
    refs.sort_by(|left, right| left.name.cmp(&right.name));
    if let Some(duplicate) = refs
        .windows(2)
        .find(|pair| pair[0].name == pair[1].name)
        .map(|pair| pair[0].name.clone())
    {
        return Err(invalid(format!(
            "repository publishes ref {duplicate} more than once"
        )));
    }

    Ok(RepositoryRefAdvertisement {
        schema_version: REPOSITORY_TRANSFER_SCHEMA_VERSION,
        protocol: REPOSITORY_TRANSFER_PROTOCOL.to_string(),
        repository_id: repository_id.clone(),
        refs,
        default_ref: lease.authority_metadata().ref_state.default_ref.clone(),
        roots: lease.roots().clone(),
        supported_features: required_features(),
        limits: RepositoryTransferLimits::default(),
    })
}

/// One pack of a transfer that may need more than one, and what is left after
/// it is published.
///
/// A segment is a complete, self-validating transfer in its own right: it
/// carries a parent-closed change closure, publishes one exact head, and comes
/// back with one receipt. What makes it a segment rather than the whole
/// transfer is only that [`Self::remaining_changes`] is not zero.
#[derive(Debug, Clone)]
pub struct RepositoryTransferSegment {
    pub pack: RepositoryTransferPack,
    /// Exact changes still to move after this pack is published.
    pub remaining_changes: usize,
}

impl RepositoryTransferSegment {
    /// True when this pack lands the transfer target head, so nothing follows.
    pub fn is_final(&self) -> bool {
        self.remaining_changes == 0
    }
}

/// The changes one pack carries, and how many are left behind it.
struct SegmentPlan {
    ordered: Vec<SemanticChangeId>,
    remaining: usize,
    /// The plan had to reach past the change budget to end on a change the
    /// destination ref can fast-forward to.
    ///
    /// This is what tells a caller whether a refusal can be answered by trying
    /// a smaller step. Nothing inside this segment can end one, so replanning
    /// under any smaller budget rebuilds exactly this segment.
    is_smallest_publishable_step: bool,
}

/// A pack that could not be assembled inside the negotiated bounds.
///
/// This is separated from a genuine error because it is the one refusal a
/// segmented transfer can answer by trying a smaller step. Every other failure
/// means the history or the lease is wrong, and retrying would only repeat it.
enum Assembled {
    Pack(Box<RepositoryTransferPack>),
    OverNegotiatedBound(String),
}

pub fn build_repository_transfer_pack<B: StorageBackend + ?Sized + 'static>(
    authority: &RepositoryAuthorityManager<B>,
    source_ref: &RefName,
    expectation: &RepositoryTransferExpectation,
) -> Result<RepositoryTransferPack> {
    let expectation = locally_bounded_expectation(expectation)?;
    let context = TransferSourceContext::read(authority, source_ref, &expectation)?;
    let ordered = collect_fast_forward_closure(
        &context.all_changes,
        context.source_head,
        expectation.destination_head,
    )?;
    enforce_count("changes", ordered.len(), expectation.limits.max_changes)?;
    let plan = SegmentPlan {
        ordered,
        remaining: 0,
        is_smallest_publishable_step: false,
    };
    match assemble_segment_pack(authority, &context, &expectation, source_ref, &plan)? {
        Assembled::Pack(pack) => Ok(*pack),
        Assembled::OverNegotiatedBound(reason) => Err(invalid(reason)),
    }
}

/// Build the largest pack that fits the negotiated bounds and still publishes a
/// head the destination ref can fast-forward to.
///
/// The bound this works around is the negotiated envelope, not the history. A
/// closure past the envelope is split into a sequence of packs, each of which
/// is published atomically on its own. What it cannot split is one change: a
/// single change whose new bodies exceed the negotiated byte bound is refused
/// by name, because there is no smaller step that still lands a valid head.
pub fn build_repository_transfer_segment<B: StorageBackend + ?Sized + 'static>(
    authority: &RepositoryAuthorityManager<B>,
    source_ref: &RefName,
    expectation: &RepositoryTransferExpectation,
) -> Result<RepositoryTransferSegment> {
    let expectation = locally_bounded_expectation(expectation)?;
    let context = TransferSourceContext::read(authority, source_ref, &expectation)?;
    let closure = collect_fast_forward_closure(
        &context.all_changes,
        context.source_head,
        expectation.destination_head,
    )?;
    if closure.is_empty() {
        return Err(invalid(format!(
            "source head {} is already the destination head; there is no segment to build",
            context.source_head
        )));
    }

    let mut budget = expectation.limits.max_changes;
    loop {
        let plan = plan_transfer_segment(
            &context.all_changes,
            &closure,
            expectation.destination_head,
            &expectation.limits,
            budget,
        )?;
        let planned = plan.ordered.len();
        match assemble_segment_pack(authority, &context, &expectation, source_ref, &plan)? {
            Assembled::Pack(pack) => {
                return Ok(RepositoryTransferSegment {
                    pack: *pack,
                    remaining_changes: plan.remaining,
                })
            }
            Assembled::OverNegotiatedBound(reason) => {
                if planned <= 1 {
                    return Err(invalid(format!(
                        "the next publishable step of this transfer is one exact change and it {reason}; \
                         a single change cannot be split across continuation packs"
                    )));
                }
                // A smaller budget is only worth trying when it can produce a
                // smaller segment, and here it cannot: the planner already had
                // to reach past the budget to end on a change this ref can
                // fast-forward to, so every replan rebuilds this same segment.
                // Refusing by name is the answer the caller needs; shrinking
                // the budget again would be a hang standing in for a refusal.
                //
                // This is also what bounds the loop. A plan that stayed inside
                // its budget is never longer than it, so the next budget is
                // strictly smaller than the segment just refused, and a plan
                // that reached past its budget stops here.
                if plan.is_smallest_publishable_step {
                    return Err(invalid(format!(
                        "the next publishable step of this transfer is {planned} changes and it \
                         {reason}; no smaller part of it ends on a change this destination ref can \
                         fast-forward to, so it cannot be split across continuation packs"
                    )));
                }
                // Halve rather than step down one change at a time: the bound
                // that was hit is a byte or object total, so the useful search
                // is over magnitudes, and this converges in log steps instead
                // of rebuilding the pack once per change.
                budget = u32::try_from(planned / 2).unwrap_or(1).max(1);
            }
        }
    }
}

/// Check everything a publication decides before it assembles a pack.
///
/// This exists so a plan can refuse what a push refuses without publishing
/// anything: the repository identity, the negotiated features, the source ref,
/// the imported-Git authority baseline, and the presence and identity of every
/// immutable body the publication head's tree depends on. It deliberately does
/// not build packs, so it says nothing about per-pack byte totals.
pub fn verify_transfer_source_readiness<B: StorageBackend + ?Sized + 'static>(
    authority: &RepositoryAuthorityManager<B>,
    source_ref: &RefName,
    expectation: &RepositoryTransferExpectation,
) -> Result<()> {
    let expectation = locally_bounded_expectation(expectation)?;
    let context = TransferSourceContext::read(authority, source_ref, &expectation)?;
    let store = TransferChangeStore::new(context.all_changes.values().cloned());
    let tree = store.resolve_tree_at(&context.source_head).map_err(model)?;
    for hash in resolved_tree_body_identities(&tree)? {
        let bytes = authority
            .load_source_blob(hash)
            .map_err(storage)?
            .ok_or_else(|| invalid(format!("source tree CAS body {hash} is absent")))?;
        verify_body(hash, &bytes)?;
    }
    Ok(())
}

/// How many packs the gap in `expectation` takes, counting nothing that needs
/// bytes to be read.
///
/// This is a floor, not a promise. Segmentation also splits on the negotiated
/// byte bounds, and those are only known once bodies are loaded, so a
/// publication can take more packs than this and never fewer.
pub fn count_repository_transfer_packs<B: StorageBackend + ?Sized + 'static>(
    authority: &RepositoryAuthorityManager<B>,
    source_ref: &RefName,
    expectation: &RepositoryTransferExpectation,
) -> Result<usize> {
    let expectation = locally_bounded_expectation(expectation)?;
    let context = TransferSourceContext::read(authority, source_ref, &expectation)?;
    let mut boundary = expectation.destination_head;
    let mut packs = 0usize;
    loop {
        let closure =
            collect_fast_forward_closure(&context.all_changes, context.source_head, boundary)?;
        if closure.is_empty() {
            return Ok(packs);
        }
        let plan = plan_transfer_segment(
            &context.all_changes,
            &closure,
            boundary,
            &expectation.limits,
            expectation.limits.max_changes,
        )?;
        packs += 1;
        if plan.remaining == 0 {
            return Ok(packs);
        }
        boundary = plan.ordered.last().copied();
    }
}

/// Everything one coherent authority lease contributes to a pack.
struct TransferSourceContext {
    all_changes: std::collections::HashMap<SemanticChangeId, SemanticChange>,
    source_head: SemanticChangeId,
    source_git_authority_hash: Option<Hash256>,
    /// The authority this transfer will ESTABLISH, present only when the
    /// destination has none and is otherwise empty.
    ///
    /// Carrying the value rather than only its hash is what lets the pack ship
    /// it. Every other transfer leaves this `None` and the two replicas' hashes
    /// must already agree.
    bootstrap_authority: Option<GitExternalAuthority>,
    aliases: Vec<ExternalChangeAlias>,
    external_objects: Vec<ExternalObjectRecord>,
}

/// Whether the destination this expectation describes has admitted anything at
/// all.
///
/// Five fields, not one. A replica with no Git authority but a native history
/// is not a bootstrap target: giving it an imported-Git baseline would claim
/// its existing changes came from a Git lineage they never came from.
fn destination_is_unborn(expectation: &RepositoryTransferExpectation) -> bool {
    expectation.git_authority_hash.is_none()
        && expectation.destination_head.is_none()
        && expectation.destination_target.is_none()
        && expectation.default_ref.is_none()
        && expectation.roots.generation == 0
}

impl TransferSourceContext {
    fn read<B: StorageBackend + ?Sized + 'static>(
        authority: &RepositoryAuthorityManager<B>,
        source_ref: &RefName,
        expectation: &RepositoryTransferExpectation,
    ) -> Result<Self> {
        validate_expectation(expectation)?;
        let lease = authority.read_authority();
        if lease.authority_metadata().repository_id != expectation.repository_id {
            return Err(invalid(format!(
                "source repository {} does not match destination repository {}",
                lease.authority_metadata().repository_id,
                expectation.repository_id
            )));
        }
        require_negotiated_features(&expectation.supported_features)?;

        let source_target = lease
            .resolve_ref_target(source_ref)
            .map_err(storage)?
            .ok_or_else(|| invalid(format!("source ref {source_ref} is absent")))?;
        let source_head = lease
            .resolve_target_change_id(&source_target)
            .map_err(storage)?;
        let source_authority = lease.authority_metadata().git_external_authority.clone();
        let source_git_authority_hash = hash_git_authority(source_authority.as_ref())?;
        // Three outcomes, and only the middle one is new. Matching authority is
        // an ordinary fast-forward. A source with authority publishing into a
        // replica that has admitted nothing is a bootstrap, which establishes
        // the baseline instead of requiring one. Anything else is the
        // divergence transfer v1 has never carried and still does not.
        let bootstrap_authority = if source_git_authority_hash == expectation.git_authority_hash {
            None
        } else if source_authority.is_some() && destination_is_unborn(expectation) {
            source_authority
        } else {
            return Err(RepositoryTransferError::Conflict(
                "repository-v6 transfer requires identical imported-Git authority on both replicas, or a destination that has admitted nothing; Git-authority divergence is not adapted"
                    .to_string(),
            ));
        };

        Ok(Self {
            all_changes: lease.snapshot().changes.clone(),
            source_head,
            source_git_authority_hash,
            bootstrap_authority,
            aliases: lease.authority_metadata().aliases.clone(),
            external_objects: lease.authority_metadata().external_objects.clone(),
        })
    }
}

/// The earliest change in `closure` the destination ref can fast-forward to.
fn smallest_publishable_step(
    closure: &[SemanticChangeId],
    descends: &BTreeMap<SemanticChangeId, bool>,
) -> Option<usize> {
    closure
        .iter()
        .position(|id| descends.get(id) == Some(&true))
}

/// Choose the longest parent-closed prefix of `closure` that stays inside the
/// negotiated bounds and ends on a change the destination ref can fast-forward
/// to.
///
/// Both conditions matter and only one of them is obvious. The prefix is
/// parent-closed because the closure is ordered parent-before-child. The
/// endpoint has to be a descendant of the destination head as well, which a
/// prefix does not give for free: merging a side line puts that line's changes
/// in the closure ahead of the merge, and none of them descend from the
/// destination head. Ending a segment there would ask the destination ref to
/// move sideways onto an unrelated change.
fn plan_transfer_segment(
    changes: &std::collections::HashMap<SemanticChangeId, SemanticChange>,
    closure: &[SemanticChangeId],
    destination_head: Option<SemanticChangeId>,
    limits: &RepositoryTransferLimits,
    change_budget: u32,
) -> Result<SegmentPlan> {
    let mut descends = BTreeMap::new();
    let mut bodies = BTreeSet::new();
    let mut last_publishable: Option<usize> = None;

    for (index, id) in closure.iter().enumerate() {
        let change = changes
            .get(id)
            .ok_or_else(|| invalid(format!("source closure is missing change {id}")))?;
        descends.insert(
            *id,
            destination_head.is_none()
                || change.parents.iter().any(|parent| {
                    Some(*parent) == destination_head || descends.get(parent) == Some(&true)
                }),
        );
        for delta in &change.tree_deltas {
            if let Some(new) = delta.new_state() {
                if let Some(hash) = new.entry.blob_identity() {
                    bodies.insert(hash);
                }
            }
        }
        let count = u32::try_from(index + 1).unwrap_or(u32::MAX);
        let within_budget = count <= change_budget
            && u32::try_from(bodies.len()).unwrap_or(u32::MAX) <= limits.max_bodies;
        if within_budget && descends.get(id) == Some(&true) {
            last_publishable = Some(index);
        }
    }

    // No boundary fits the budget. That does not mean the transfer is stuck:
    // it means the smallest step that lands a head this ref can reach is
    // bigger than the envelope asked for. Merging a side line does this, and
    // it does it partway through a publication that has already moved history,
    // so refusing here would strand a transfer rather than bound it. Take the
    // smallest publishable step there is and let the pack limits refuse it if
    // it genuinely cannot be built.
    let (end, is_smallest_publishable_step) = match last_publishable {
        Some(end) => (end, false),
        None => (
            smallest_publishable_step(closure, &descends).ok_or_else(|| {
                invalid(format!(
                    "no change in this closure descends from destination head {}, so no pack can \
                     publish a head this ref reaches",
                    destination_head
                        .map(|head| head.to_string())
                        .unwrap_or_else(|| "an unborn ref".to_string()),
                ))
            })?,
            true,
        ),
    };
    // Carry exactly the endpoint's own ancestry rather than the whole scanned
    // prefix. A topological prefix can hold a change that is not an ancestor
    // of the change it ends on: order a merge's two lines the other way and
    // the far line lands ahead of the near one. Sending it in this segment
    // would leave the next segment's closure carrying it a second time.
    let ordered = collect_fast_forward_closure(changes, closure[end], destination_head)?;
    let remaining = closure.len().saturating_sub(ordered.len());
    Ok(SegmentPlan {
        ordered,
        remaining,
        is_smallest_publishable_step,
    })
}

fn assemble_segment_pack<B: StorageBackend + ?Sized + 'static>(
    authority: &RepositoryAuthorityManager<B>,
    context: &TransferSourceContext,
    expectation: &RepositoryTransferExpectation,
    source_ref: &RefName,
    plan: &SegmentPlan,
) -> Result<Assembled> {
    // An empty closure means the two replicas already resolve the ref to the
    // same change. The pack then publishes that head and carries nothing,
    // which is what a caller that asked for a pack anyway should get back.
    let segment_head = plan.ordered.last().copied().unwrap_or(context.source_head);
    // A bootstrap cannot be a segment. The authority it installs describes the
    // repository's whole ref set and every commit reachable from it, and kin-db
    // refuses an authority whose projections name changes the snapshot does not
    // hold. So a partial bootstrap is not a smaller bootstrap, it is one that
    // cannot commit, and the honest answer is to refuse here by name rather
    // than to send a pack whose failure would surface from three layers down as
    // a missing alias.
    if context.bootstrap_authority.is_some() && segment_head != context.source_head {
        return Ok(Assembled::OverNegotiatedBound(format!(
            "a bootstrap publishes the whole imported history in one pack and this one does not \
             fit the negotiated envelope: {} of {} changes",
            plan.ordered.len(),
            context.all_changes.len()
        )));
    }
    let store = TransferChangeStore::new(context.all_changes.values().cloned());
    let segment_tree = store.resolve_tree_at(&segment_head).map_err(model)?;
    let segment_tree_hash = compute_resolved_tree_hash(&segment_tree).map_err(model)?;
    for hash in resolved_tree_body_identities(&segment_tree)? {
        let bytes = authority
            .load_source_blob(hash)
            .map_err(storage)?
            .ok_or_else(|| invalid(format!("source tree CAS body {hash} is absent")))?;
        verify_body(hash, &bytes)?;
    }

    let mut changes = Vec::with_capacity(plan.ordered.len());
    let mut trees = Vec::with_capacity(plan.ordered.len());
    let mut required_body_hashes = BTreeSet::new();
    let included = plan.ordered.iter().copied().collect::<BTreeSet<_>>();
    let mut required_git_oids = BTreeSet::new();
    for change_id in &plan.ordered {
        let change = context
            .all_changes
            .get(change_id)
            .cloned()
            .ok_or_else(|| invalid(format!("source closure is missing change {change_id}")))?;
        validate_semantic_change_id(&change).map_err(model)?;
        for delta in &change.tree_deltas {
            if let Some(new) = delta.new_state() {
                if let Some(hash) = new.entry.blob_identity() {
                    required_body_hashes.insert(hash);
                }
            }
        }
        if let ChangeOrigin::GitCommit { oid } = change.origin {
            required_git_oids.insert(oid);
        }
        let tree = store.resolve_tree_at(&change.id).map_err(model)?;
        trees.push(RepositoryTransferTreeIdentity {
            change_id: change.id,
            tree_hash: compute_resolved_tree_hash(&tree).map_err(model)?,
        });
        changes.push(change);
    }

    // Same reasoning as the external objects below: an installed authority
    // projects every commit in its closure, and kin-db requires each projection
    // to have an alias, so a bootstrap carries all of them rather than only the
    // ones its included changes name.
    let aliases = if context.bootstrap_authority.is_some() {
        context.aliases.clone()
    } else {
        context
            .aliases
            .iter()
            .filter(|alias| {
                included.contains(&alias.change_id) || required_git_oids.contains(&alias.oid)
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    // An ordinary pack carries only the objects its own Git-origin changes name,
    // because the destination already holds the baseline. A bootstrap carries
    // the WHOLE closure, because the authority it installs describes every one
    // of them and kin-db refuses an authority whose closure names an object the
    // repository's external-object set does not hold.
    let external_objects = if context.bootstrap_authority.is_some() {
        context.external_objects.clone()
    } else {
        context
            .external_objects
            .iter()
            .filter(|record| required_git_oids.contains(&record.object.oid))
            .cloned()
            .collect::<Vec<_>>()
    };
    for record in &external_objects {
        required_body_hashes.insert(record.body_hash);
    }

    for (label, actual, limit) in [
        ("trees", trees.len(), expectation.limits.max_trees),
        (
            "external objects",
            external_objects.len(),
            expectation.limits.max_external_objects,
        ),
        ("aliases", aliases.len(), expectation.limits.max_aliases),
        (
            "source bodies",
            required_body_hashes.len(),
            expectation.limits.max_bodies,
        ),
    ] {
        if let Some(reason) = over_count(label, actual, limit) {
            return Ok(Assembled::OverNegotiatedBound(reason));
        }
    }

    let mut total_bytes = 0_u64;
    let mut bodies = Vec::with_capacity(required_body_hashes.len());
    for hash in required_body_hashes {
        let bytes = authority
            .load_source_blob(hash)
            .map_err(storage)?
            .ok_or_else(|| invalid(format!("source CAS body {hash} is absent")))?;
        let byte_len = u64::try_from(bytes.len())
            .map_err(|_| invalid("source body length does not fit u64"))?;
        if byte_len > expectation.limits.max_single_body_bytes {
            return Ok(Assembled::OverNegotiatedBound(format!(
                "carries source body {hash} at {byte_len} bytes, over negotiated limit {}",
                expectation.limits.max_single_body_bytes
            )));
        }
        total_bytes = total_bytes
            .checked_add(byte_len)
            .ok_or_else(|| invalid("source body byte total overflow"))?;
        if total_bytes > expectation.limits.max_decoded_body_bytes {
            return Ok(Assembled::OverNegotiatedBound(format!(
                "carries a {total_bytes} byte source body closure, over negotiated limit {}",
                expectation.limits.max_decoded_body_bytes
            )));
        }
        bodies.push(RepositoryTransferBody::from_bytes(hash, &bytes)?);
    }

    let mut pack = RepositoryTransferPack {
        schema_version: REPOSITORY_TRANSFER_SCHEMA_VERSION,
        protocol: REPOSITORY_TRANSFER_PROTOCOL.to_string(),
        transfer_id: Hash256::from_bytes([0; 32]),
        operation_id: OperationId::new(),
        repository_id: expectation.repository_id.clone(),
        source_ref: source_ref.clone(),
        destination_ref: expectation.destination_ref.clone(),
        source_head: segment_head,
        transfer_target_head: context.source_head,
        source_tree_hash: segment_tree_hash,
        expected_destination_target: expectation.destination_target.clone(),
        expected_destination_head: expectation.destination_head,
        expected_destination_roots: expectation.roots.clone(),
        expected_destination_default_ref: expectation.default_ref.clone(),
        source_git_authority_hash: context.source_git_authority_hash,
        expected_destination_git_authority_hash: expectation.git_authority_hash,
        git_authority_bootstrap: context.bootstrap_authority.clone(),
        required_features: required_features(),
        changes,
        trees,
        external_objects,
        aliases,
        bodies,
    };
    pack.transfer_id = compute_transfer_id(&pack)?;
    // The sender checks its own work against the ceilings it ASSEMBLED under,
    // not against the constants. Those are the negotiated limits already
    // bounded by this process's own, so a pack that passes here is one the
    // peer said it would take.
    validate_pack(&pack, &expectation.limits)?;
    Ok(Assembled::Pack(Box::new(pack)))
}

/// Every immutable CAS body one resolved tree depends on.
fn resolved_tree_body_identities(tree: &kin_model::ResolvedTree) -> Result<BTreeSet<Hash256>> {
    let mut identities = BTreeSet::new();
    for artifact in tree.artifacts() {
        if let Some(hash) = artifact.entry.blob_identity() {
            identities.insert(hash);
        } else if !matches!(artifact.entry, TreeEntry::Gitlink { .. }) {
            return Err(invalid(format!(
                "source tree entry at {} has neither CAS body nor Gitlink identity",
                artifact.path
            )));
        }
    }
    Ok(identities)
}

/// Apply a received pack with no admission-provenance policy.
///
/// Crate-visible on purpose. A receiver that owns local state derived from the
/// history it is admitting has a policy to run at the commit boundary, and the
/// hydration-semantics creation record is exactly that: the wire carries no
/// authoring version, so a local receiver has to discard its own creation stamp
/// before the transported history becomes visible. Leaving a policy-free entry
/// point reachable from another crate is how that step gets skipped by a path
/// nobody remembered to route. Out-of-crate callers take
/// [`apply_repository_transfer_pack_with_pre_commit`] and say what their policy
/// is, including when it is nothing.
///
/// Test-only, because after the daemon and the negotiation convenience both
/// state their policy there is no production caller left. Keeping it compiled
/// into the product would leave a policy-free admission one `use` away from
/// being reachable again.
#[cfg(test)]
pub(crate) fn apply_repository_transfer_pack<B: StorageBackend + ?Sized + 'static>(
    authority: &RepositoryAuthorityManager<B>,
    expected_repository_id: &RepositoryId,
    expected_destination_ref: &RefName,
    actor: AuthorId,
    pack: &RepositoryTransferPack,
    limits: &RepositoryTransferLimits,
) -> Result<RepositoryTransferReceipt> {
    apply_repository_transfer_pack_with_pre_commit(
        authority,
        expected_repository_id,
        expected_destination_ref,
        actor,
        pack,
        limits,
        || Ok(()),
    )
}

/// Apply a received pack under the ceilings this receiver actually enforces,
/// running `before_authority_commit` at the commit boundary.
///
/// `limits` is the receiver's EFFECTIVE bound: its configured limits bounded by
/// whatever the peer advertised. Passing `RepositoryTransferLimits::default()`
/// is the compiled behaviour and is what a caller with no deployment
/// configuration should send.
///
/// `before_authority_commit` runs exactly once, after every validation and
/// after the immutable CAS prewrites, immediately before the authority
/// transaction. That position is the whole point of the hook. Earlier would
/// degrade local state over a pack this receiver then refuses; later reopens the
/// crash window where transported history is durable and the receiver still
/// describes itself by a record that no longer speaks for its contents. Its
/// failure is returned as [`RepositoryTransferError::Storage`] and the commit is
/// not started.
///
/// It does not run on an idempotent replay. A replay of a transfer this code
/// committed already ran the policy before that original commit, and running it
/// again would mutate local state for a transfer that moves nothing.
pub fn apply_repository_transfer_pack_with_pre_commit<B, P>(
    authority: &RepositoryAuthorityManager<B>,
    expected_repository_id: &RepositoryId,
    expected_destination_ref: &RefName,
    actor: AuthorId,
    pack: &RepositoryTransferPack,
    limits: &RepositoryTransferLimits,
    before_authority_commit: P,
) -> Result<RepositoryTransferReceipt>
where
    B: StorageBackend + ?Sized + 'static,
    P: FnOnce() -> std::io::Result<()>,
{
    validate_pack(pack, limits)?;
    if &pack.repository_id != expected_repository_id {
        return Err(invalid(format!(
            "pack repository {} does not match receiver repository {}",
            pack.repository_id, expected_repository_id
        )));
    }
    if &pack.destination_ref != expected_destination_ref {
        return Err(invalid(format!(
            "pack destination ref {} does not match route ref {}",
            pack.destination_ref, expected_destination_ref
        )));
    }

    let transaction = transfer_transaction(pack, actor)?;
    let transaction_hash = transaction.transaction_hash().map_err(model)?;
    let lease = authority.read_authority();
    if let Some(receipt) = lease
        .authority_metadata()
        .receipts
        .iter()
        .find(|receipt| receipt.operation_id == pack.operation_id)
    {
        if receipt.transaction_hash != transaction_hash {
            return Err(RepositoryTransferError::Conflict(format!(
                "operation {} was already committed with a different exact transaction",
                pack.operation_id
            )));
        }
        return Ok(transfer_receipt(
            pack,
            receipt.clone(),
            RepositoryTransferApplyOutcome::IdempotentReplay,
        ));
    }

    if lease.roots() != &pack.expected_destination_roots {
        return Err(RepositoryTransferError::Conflict(
            "destination repository roots/generation moved from the pack lease".to_string(),
        ));
    }
    if lease.authority_metadata().ref_state.default_ref != pack.expected_destination_default_ref {
        return Err(RepositoryTransferError::Conflict(
            "destination default ref moved from the pack lease".to_string(),
        ));
    }
    let current_target = lease
        .authority_metadata()
        .ref_state
        .refs
        .iter()
        .find(|entry| entry.name == pack.destination_ref)
        .map(|entry| entry.target.clone());
    if current_target != pack.expected_destination_target {
        return Err(RepositoryTransferError::Conflict(
            "destination ref target moved from the pack lease".to_string(),
        ));
    }
    let current_head = current_target
        .as_ref()
        .map(|target| lease.resolve_target_change_id(target).map_err(storage))
        .transpose()?;
    if current_head != pack.expected_destination_head {
        return Err(RepositoryTransferError::Conflict(
            "destination semantic head moved from the pack lease".to_string(),
        ));
    }
    let current_git_hash =
        hash_git_authority(lease.authority_metadata().git_external_authority.as_ref())?;
    // Both arms compare against what this replica actually holds right now,
    // read from the lease rather than from anything the sender said during the
    // negotiation. That is what decides a race between two publishers: the
    // second one finds a non-empty replica here and is refused, whatever it
    // declared.
    // These two are a BACKSTOP, not the reachable guard, and the difference is
    // worth writing down because an unreachable check that looks load-bearing
    // is how a guard stops being evidence.
    //
    // A replica holding authority is past generation zero, since installing any
    // authority advances the generation. So an honest publisher declares the
    // live non-zero generation and `validate_pack` refuses it before this point,
    // and a publisher declaring stale generation-zero roots is refused by the
    // roots compare-and-swap above. Neither reaches here. What these two buy is
    // failing closed if that ordering ever changes, and they are deliberately
    // not the thing any test asserts, because a test cannot reach them either.
    if pack.git_authority_bootstrap.is_some() {
        if current_git_hash.is_some() {
            return Err(RepositoryTransferError::Conflict(
                "this replica already holds imported-Git authority and cannot be bootstrapped again"
                    .to_string(),
            ));
        }
        if !lease.snapshot().changes.is_empty() {
            return Err(RepositoryTransferError::Conflict(
                "this replica already holds history and cannot be bootstrapped".to_string(),
            ));
        }
    } else if current_git_hash != pack.expected_destination_git_authority_hash
        || current_git_hash != pack.source_git_authority_hash
    {
        return Err(RepositoryTransferError::Conflict(
            "imported-Git authority differs from the exact baseline bound by transfer v1"
                .to_string(),
        ));
    }

    let required_source_bodies =
        validate_change_and_tree_closure(lease.snapshot().changes.values(), pack)?;
    let decoded = decode_and_validate_bodies(pack, authority)?;
    validate_body_coverage(authority, &required_source_bodies, &decoded)?;
    drop(lease);

    // Immutable CAS prewrites intentionally precede the authority transaction.
    // A conflict after this point leaves only unreachable, content-addressed
    // bytes and never advances a ref or root bundle.
    for (hash, bytes) in decoded {
        authority.save_source_blob(hash, &bytes).map_err(storage)?;
    }
    // The receiver's admission-provenance policy, at the last point before this
    // history becomes visible and after everything that could still refuse the
    // pack. A failure here returns without starting the commit, so the receiver
    // is never left describing history it now holds by a record that predates
    // it.
    before_authority_commit().map_err(storage)?;
    let receipt = authority
        .commit_repository_transaction(transaction)
        .map_err(repository_commit)?;
    let outcome = match receipt.outcome {
        RepositoryCommitOutcome::Committed => RepositoryTransferApplyOutcome::Committed,
        RepositoryCommitOutcome::IdempotentReplay => {
            RepositoryTransferApplyOutcome::IdempotentReplay
        }
    };
    Ok(transfer_receipt(pack, receipt, outcome))
}

/// Validate a pack against the ceilings the RECEIVER is willing to enforce.
///
/// The limits are a parameter rather than the compiled constants, and that is
/// the whole point of the change that introduced it. Enforcement used to read
/// `MAX_TRANSFER_*` directly, so a deployment could advertise a raised ceiling
/// during negotiation and then refuse the pack it had just invited. The caller
/// computes the effective bound as its configured limits bounded by whatever
/// the peer advertised, and this function enforces exactly that.
pub fn validate_pack(
    pack: &RepositoryTransferPack,
    limits: &RepositoryTransferLimits,
) -> Result<()> {
    if pack.schema_version != REPOSITORY_TRANSFER_SCHEMA_VERSION {
        return Err(invalid(format!(
            "unsupported schema version {}; expected {}",
            pack.schema_version, REPOSITORY_TRANSFER_SCHEMA_VERSION
        )));
    }
    if pack.protocol != REPOSITORY_TRANSFER_PROTOCOL {
        return Err(invalid(format!("unsupported protocol {:?}", pack.protocol)));
    }
    pack.expected_destination_roots.validate().map_err(model)?;
    validate_git_authority_shape(pack)?;
    validate_required_features(&pack.required_features)?;
    enforce_count("changes", pack.changes.len(), MAX_TRANSFER_CHANGES as u32)?;
    enforce_count("trees", pack.trees.len(), MAX_TRANSFER_TREES as u32)?;
    enforce_count("bodies", pack.bodies.len(), MAX_TRANSFER_BODIES as u32)?;
    enforce_count(
        "external objects",
        pack.external_objects.len(),
        limits.max_external_objects,
    )?;
    enforce_count("aliases", pack.aliases.len(), MAX_TRANSFER_ALIASES as u32)?;

    let expected_id = compute_transfer_id(pack)?;
    if expected_id != pack.transfer_id {
        return Err(invalid(format!(
            "transfer identity {} recomputes to {}",
            pack.transfer_id, expected_id
        )));
    }

    let mut known = pack
        .expected_destination_head
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut change_ids = BTreeSet::new();
    for change in &pack.changes {
        validate_semantic_change_id(change).map_err(model)?;
        if !change_ids.insert(change.id) {
            return Err(invalid(format!("duplicate semantic change {}", change.id)));
        }
        for parent in &change.parents {
            if !known.contains(parent) {
                return Err(invalid(format!(
                    "change {} appears before or without parent {}",
                    change.id, parent
                )));
            }
        }
        known.insert(change.id);
    }
    if !known.contains(&pack.source_head) {
        return Err(invalid(format!(
            "source head {} is absent from the transferred/boundary closure",
            pack.source_head
        )));
    }
    // The head a pack publishes is the last change it carries. A pack that
    // carried changes past its own publish head would be describing a segment
    // boundary that its ref mutation does not match, which is exactly the
    // ambiguity continuation packs exist to remove.
    if let Some(last) = pack.changes.last() {
        if last.id != pack.source_head {
            return Err(invalid(format!(
                "pack publishes {} but its closure ends at {}",
                pack.source_head, last.id
            )));
        }
    }
    // A pack that already carries the transfer target has nothing left to
    // continue toward, so it must be publishing it.
    if pack.transfer_target_head != pack.source_head
        && pack
            .changes
            .iter()
            .any(|change| change.id == pack.transfer_target_head)
    {
        return Err(invalid(format!(
            "pack carries transfer target {} but publishes {} instead",
            pack.transfer_target_head, pack.source_head
        )));
    }

    if pack.trees.len() != pack.changes.len() {
        return Err(invalid(
            "tree identity count must equal semantic change count",
        ));
    }
    for (change, tree) in pack.changes.iter().zip(&pack.trees) {
        if tree.change_id != change.id {
            return Err(invalid(format!(
                "tree identity {} is out of order for change {}",
                tree.change_id, change.id
            )));
        }
    }

    // Bodies are a deduplicated set, and the sender emits them ordered by
    // identity. Pack identity is computed over the serialized pack, so a
    // permuted body array describes the same transfer under a different
    // transfer id. Pinning the order here keeps that identity a function of
    // content alone.
    let mut body_hashes = BTreeSet::new();
    let mut previous_body: Option<Hash256> = None;
    let mut total = 0_u64;
    for body in &pack.bodies {
        if !body_hashes.insert(body.hash) {
            return Err(invalid(format!("duplicate source body {}", body.hash)));
        }
        if let Some(previous) = previous_body {
            if body.hash < previous {
                return Err(invalid(format!(
                    "source body {} breaks ascending pack order after {}",
                    body.hash, previous
                )));
            }
        }
        previous_body = Some(body.hash);
        let bytes = body.decode()?;
        total = total
            .checked_add(body.byte_len)
            .ok_or_else(|| invalid("decoded body byte total overflow"))?;
        if total > limits.max_decoded_body_bytes {
            // The message names the bound that actually applied and the knob
            // that moves it. A refusal quoting a compiled constant sent an
            // operator looking for a release when a restart would have done,
            // and one quoting no number at all left them guessing which of
            // seven ceilings refused. It promises nothing beyond the knob: the
            // transport bound is not the product's answer to repository size.
            return Err(invalid(format!(
                "decoded body closure is {total} bytes and exceeds the effective ceiling of {} \
                 bytes; a receiver raises its own with {DECODED_BODY_CEILING_ENV}, and the \
                 effective bound is the smaller of that and what the peer advertised",
                limits.max_decoded_body_bytes
            )));
        }
        drop(bytes);
    }

    let mut external_ids = BTreeSet::<ExternalObjectId>::new();
    for record in &pack.external_objects {
        if !external_ids.insert(record.object) {
            return Err(invalid(format!(
                "duplicate external object {}",
                record.object.oid
            )));
        }
        // Deliberately NOT requiring the body here any more. This function has
        // no authority handle, so it cannot tell "absent" from "already in the
        // destination's CAS", and refusing on the first meaning made a sender
        // unable to omit a body the receiver already holds.
        //
        // The requirement did not disappear, it moved to where it can be
        // answered: `decode_and_validate_bodies` takes the authority, resolves
        // each external body from the pack OR from CAS, and runs the full
        // `validate_raw` against whichever bytes it got. Nothing is trusted
        // that was not verified; what changed is where the bytes may come from.
    }
    let mut alias_oids = BTreeSet::new();
    for alias in &pack.aliases {
        if alias.repository_id != pack.repository_id {
            return Err(invalid(format!(
                "alias {} belongs to repository {}, not {}",
                alias.oid, alias.repository_id, pack.repository_id
            )));
        }
        if !alias_oids.insert(alias.oid) {
            return Err(invalid(format!("duplicate external alias {}", alias.oid)));
        }
    }
    for change in &pack.changes {
        if let ChangeOrigin::GitCommit { oid } = change.origin {
            if !external_ids.contains(&ExternalObjectId::new(ExternalObjectKind::Commit, oid)) {
                return Err(invalid(format!(
                    "Git-origin change {} lacks commit object {}",
                    change.id, oid
                )));
            }
            if !pack
                .aliases
                .iter()
                .any(|alias| alias.oid == oid && alias.change_id == change.id)
            {
                return Err(invalid(format!(
                    "Git-origin change {} lacks exact alias {}",
                    change.id, oid
                )));
            }
        }
    }
    Ok(())
}

/// Decide whether this pack's imported-Git authority story is coherent, which
/// is two different rules depending on whether it bootstraps.
///
/// Without a bootstrap the old rule stands exactly: both replicas' authority
/// must already hash the same. With one, exactly one divergence is legal, the
/// one from absent to present, and every other property of an empty
/// destination has to hold too. The five emptiness declarations here are
/// checked again in `apply_repository_transfer_pack` against the live lease,
/// which is what makes them a guard rather than an assertion: a sender can
/// declare anything, and the receiver believes its own storage.
fn validate_git_authority_shape(pack: &RepositoryTransferPack) -> Result<()> {
    let Some(bootstrap) = pack.git_authority_bootstrap.as_ref() else {
        if pack.source_git_authority_hash != pack.expected_destination_git_authority_hash {
            return Err(RepositoryTransferError::Conflict(
                "transfer v1 cannot carry imported-Git authority divergence".to_string(),
            ));
        }
        return Ok(());
    };

    if pack.expected_destination_git_authority_hash.is_some() {
        return Err(RepositoryTransferError::Conflict(
            "a bootstrap establishes imported-Git authority and cannot be applied to a replica that already has one"
                .to_string(),
        ));
    }
    if bootstrap.repository_id != pack.repository_id {
        return Err(invalid(format!(
            "bootstrap authority belongs to repository {}, not {}",
            bootstrap.repository_id, pack.repository_id
        )));
    }
    // The hash the sender advertised has to be the hash of the authority it
    // actually shipped, or the negotiation and the payload describe different
    // repositories and only one of them was agreed to.
    let shipped = hash_git_authority(Some(bootstrap))?;
    if shipped != pack.source_git_authority_hash {
        return Err(invalid(
            "bootstrap authority does not hash to the source Git authority this pack declares"
                .to_string(),
        ));
    }
    // An empty replica is empty in five respects, not one. Declaring fewer
    // would let a bootstrap land on a replica that already holds history under
    // a different lineage.
    if pack.expected_destination_head.is_some()
        || pack.expected_destination_target.is_some()
        || pack.expected_destination_default_ref.is_some()
    {
        return Err(RepositoryTransferError::Conflict(
            "a bootstrap is admitted only into a replica with no head, no ref target and no default ref"
                .to_string(),
        ));
    }
    if pack.expected_destination_roots.generation != 0 {
        return Err(RepositoryTransferError::Conflict(format!(
            "a bootstrap is admitted only at generation zero, not generation {}",
            pack.expected_destination_roots.generation
        )));
    }
    Ok(())
}

fn validate_status(status: &RepositoryTransferStatus) -> Result<()> {
    if status.schema_version != REPOSITORY_TRANSFER_SCHEMA_VERSION
        || status.protocol != REPOSITORY_TRANSFER_PROTOCOL
    {
        return Err(invalid("unsupported repository transfer status protocol"));
    }
    status.roots.validate().map_err(model)?;
    validate_limits(&status.limits)?;
    require_negotiated_features(&status.supported_features)
}

/// Refuse an envelope that cannot carry anything.
///
/// A continuation loop asks the peer how much it accepts and then sends that
/// much until the gap closes. A peer advertising a zero-sized envelope would
/// make every segment empty, so the loop has to refuse it here rather than
/// discover it as a lack of progress after the first round trip.
///
/// The same numbers come back the other way on the export route, where they
/// arrive in a request body rather than from a status this process built, so
/// an exporter checks them too rather than trusting the sender to have asked
/// for something it can answer.
pub(crate) fn validate_limits(limits: &RepositoryTransferLimits) -> Result<()> {
    for (label, value) in [
        ("max_changes", u64::from(limits.max_changes)),
        ("max_trees", u64::from(limits.max_trees)),
        ("max_bodies", u64::from(limits.max_bodies)),
        ("max_single_body_bytes", limits.max_single_body_bytes),
        ("max_decoded_body_bytes", limits.max_decoded_body_bytes),
    ] {
        if value == 0 {
            return Err(invalid(format!(
                "the negotiated {label} is zero, which can never carry a transfer"
            )));
        }
    }
    Ok(())
}

fn validate_expectation(expectation: &RepositoryTransferExpectation) -> Result<()> {
    expectation.roots.validate().map_err(model)?;
    validate_limits(&expectation.limits)?;
    if expectation.destination_head.is_some() != expectation.destination_target.is_some() {
        return Err(invalid(
            "destination target and resolved head must both be present or absent",
        ));
    }
    require_negotiated_features(&expectation.supported_features)
}

fn locally_bounded_expectation(
    expectation: &RepositoryTransferExpectation,
) -> Result<RepositoryTransferExpectation> {
    validate_expectation(expectation)?;
    let mut bounded = expectation.clone();
    bounded.limits = bounded.limits.bounded_by_local();
    Ok(bounded)
}

fn required_features() -> Vec<String> {
    REQUIRED_FEATURES
        .iter()
        .map(|value| (*value).to_string())
        .collect()
}

pub(crate) fn require_negotiated_features(supported: &[String]) -> Result<()> {
    let supported = supported
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for required in REQUIRED_FEATURES {
        if !supported.contains(required) {
            return Err(invalid(format!(
                "destination does not advertise required feature {required}"
            )));
        }
    }
    Ok(())
}

fn validate_required_features(required: &[String]) -> Result<()> {
    let expected = required_features();
    if required != expected {
        let known = REQUIRED_FEATURES.into_iter().collect::<BTreeSet<_>>();
        if let Some(unknown) = required
            .iter()
            .map(String::as_str)
            .find(|feature| !known.contains(feature))
        {
            return Err(invalid(format!(
                "unknown required repository transfer feature {unknown}"
            )));
        }
        return Err(invalid(
            "required repository transfer features are missing, duplicated, or out of canonical order",
        ));
    }
    Ok(())
}

fn collect_fast_forward_closure(
    changes: &std::collections::HashMap<SemanticChangeId, SemanticChange>,
    source_head: SemanticChangeId,
    boundary: Option<SemanticChangeId>,
) -> Result<Vec<SemanticChangeId>> {
    if boundary == Some(source_head) {
        return Ok(Vec::new());
    }
    let mut ordered = Vec::new();
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut reached_boundary = boundary.is_none();

    fn visit(
        id: SemanticChangeId,
        boundary: Option<SemanticChangeId>,
        changes: &std::collections::HashMap<SemanticChangeId, SemanticChange>,
        visiting: &mut BTreeSet<SemanticChangeId>,
        visited: &mut BTreeSet<SemanticChangeId>,
        ordered: &mut Vec<SemanticChangeId>,
        reached_boundary: &mut bool,
    ) -> Result<()> {
        if Some(id) == boundary {
            *reached_boundary = true;
            return Ok(());
        }
        if visited.contains(&id) {
            return Ok(());
        }
        if !visiting.insert(id) {
            return Err(invalid(format!(
                "semantic history contains a cycle at {id}"
            )));
        }
        let change = changes
            .get(&id)
            .ok_or_else(|| invalid(format!("semantic history is missing change {id}")))?;
        for parent in &change.parents {
            visit(
                *parent,
                boundary,
                changes,
                visiting,
                visited,
                ordered,
                reached_boundary,
            )?;
        }
        visiting.remove(&id);
        visited.insert(id);
        ordered.push(id);
        Ok(())
    }

    visit(
        source_head,
        boundary,
        changes,
        &mut visiting,
        &mut visited,
        &mut ordered,
        &mut reached_boundary,
    )?;
    if !reached_boundary {
        return Err(RepositoryTransferError::Conflict(format!(
            "destination head {} is not an ancestor of source head {}",
            boundary.expect("boundary is present when not reached"),
            source_head
        )));
    }
    Ok(ordered)
}

fn validate_change_and_tree_closure<'a>(
    current: impl Iterator<Item = &'a SemanticChange>,
    pack: &RepositoryTransferPack,
) -> Result<BTreeSet<Hash256>> {
    let mut combined = current
        .cloned()
        .map(|change| (change.id, change))
        .collect::<BTreeMap<_, _>>();
    for change in &pack.changes {
        match combined.get(&change.id) {
            Some(existing) if existing != change => {
                return Err(RepositoryTransferError::Conflict(format!(
                    "destination already has different bytes for semantic change {}",
                    change.id
                )));
            }
            Some(_) => {}
            None => {
                combined.insert(change.id, change.clone());
            }
        }
    }
    let store = TransferChangeStore { changes: combined };
    for identity in &pack.trees {
        let tree = store.resolve_tree_at(&identity.change_id).map_err(model)?;
        let actual = compute_resolved_tree_hash(&tree).map_err(model)?;
        if actual != identity.tree_hash {
            return Err(invalid(format!(
                "change {} tree identity {} recomputes to {}",
                identity.change_id, identity.tree_hash, actual
            )));
        }
    }
    let source_tree = store.resolve_tree_at(&pack.source_head).map_err(model)?;
    let actual_source = compute_resolved_tree_hash(&source_tree).map_err(model)?;
    if actual_source != pack.source_tree_hash {
        return Err(invalid(format!(
            "source head {} tree identity {} recomputes to {}",
            pack.source_head, pack.source_tree_hash, actual_source
        )));
    }
    let mut required_source_bodies = BTreeSet::new();
    for artifact in source_tree.artifacts() {
        if let Some(hash) = artifact.entry.blob_identity() {
            required_source_bodies.insert(hash);
        } else if !matches!(artifact.entry, TreeEntry::Gitlink { .. }) {
            return Err(invalid(format!(
                "source tree entry at {} has neither CAS body nor Gitlink identity",
                artifact.path
            )));
        }
    }
    Ok(required_source_bodies)
}

/// Decode the pack's bodies and prove every external object against real bytes.
///
/// An external body may be satisfied from the destination's own CAS rather than
/// carried in the pack, the way a tree body already may. The bytes are LOADED
/// and validated, never assumed: `validate_raw` runs against whichever copy was
/// resolved, so a receiver that skips the transfer of a body it already has
/// still verifies it.
///
/// That distinction is the whole design. `validate_raw` checks three things,
/// and only two of them are about Kin's own address: the declared length, the
/// sha256 the CAS is keyed by, and a recomputation of the GIT object id from
/// the bytes. The sha256 is tautological on a CAS read, since a
/// content-addressed store returns bytes with the key it was asked for. The
/// Git-object recomputation is not, and it is the check a receiver would lose
/// by skipping validation for a CAS-satisfied body instead of loading it. A
/// corrupted or substituted CAS entry fails it.
fn decode_and_validate_bodies<B: StorageBackend + ?Sized + 'static>(
    pack: &RepositoryTransferPack,
    authority: &RepositoryAuthorityManager<B>,
) -> Result<BTreeMap<Hash256, Vec<u8>>> {
    let mut decoded = BTreeMap::new();
    for body in &pack.bodies {
        decoded.insert(body.hash, body.decode()?);
    }
    for record in &pack.external_objects {
        match decoded.get(&record.body_hash) {
            Some(bytes) => record.validate_raw(bytes).map_err(model)?,
            None => {
                let bytes = authority
                    .load_source_blob(record.body_hash)
                    .map_err(storage)?
                    .ok_or_else(|| {
                        invalid(format!(
                            "external object {} body {} is absent from the pack and from the \
                             destination CAS",
                            record.object.oid, record.body_hash
                        ))
                    })?;
                record.validate_raw(&bytes).map_err(model)?;
            }
        }
    }
    Ok(decoded)
}

fn validate_body_coverage<B: StorageBackend + ?Sized + 'static>(
    authority: &RepositoryAuthorityManager<B>,
    required: &BTreeSet<Hash256>,
    decoded: &BTreeMap<Hash256, Vec<u8>>,
) -> Result<()> {
    for hash in required {
        if decoded.contains_key(hash) {
            continue;
        }
        if authority
            .load_source_blob(*hash)
            .map_err(storage)?
            .is_none()
        {
            return Err(invalid(format!(
                "required immutable source body {hash} is absent from pack and destination CAS"
            )));
        }
    }
    Ok(())
}

/// Where a pack's published head lives, which is not the same answer for a
/// Git-origin head as for a native one.
///
/// A native change is named by its own identity. A Git-origin change's ref
/// points at the external commit object, which is what a Git import commits
/// and what the authority's own projections describe. Publishing a Git-origin
/// head as `RefTarget::change` would name a target the resulting authority does
/// not project, and the transaction would be refused for a reason that reads
/// like a bug in the sender.
fn published_ref_target(pack: &RepositoryTransferPack) -> RefTarget {
    match pack
        .changes
        .iter()
        .find(|change| change.id == pack.source_head)
        .map(|change| change.origin)
    {
        Some(ChangeOrigin::GitCommit { oid }) => {
            RefTarget::external_object(ExternalObjectId::new(ExternalObjectKind::Commit, oid))
        }
        _ => RefTarget::change(pack.source_head),
    }
}

fn transfer_transaction(
    pack: &RepositoryTransferPack,
    actor: AuthorId,
) -> Result<RepositoryTransaction> {
    let expected = pack
        .expected_destination_target
        .clone()
        .map_or(RefExpectation::MustNotExist, |target| {
            RefExpectation::MustEqual { target }
        });
    let default_ref_mutation = if pack.expected_destination_default_ref.is_none() {
        Some(DefaultRefMutation {
            expected: DefaultRefExpectation::MustBeUnset,
            new_default: Some(pack.destination_ref.clone()),
        })
    } else {
        None
    };
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: pack.operation_id,
        repository_id: pack.repository_id.clone(),
        expected_generation: pack.expected_destination_roots.generation,
        expected_roots: pack.expected_destination_roots.clone(),
        actor,
        reason: format!(
            "receive exact repository-v6 fast-forward {} into {}",
            pack.transfer_id, pack.destination_ref
        ),
        external_objects: pack.external_objects.clone(),
        // A bootstrap and a fast-forward differ here and nowhere else in this
        // transaction. Bound 4 is why they cannot be two transactions: the
        // resulting authority has to project every Git-origin change this
        // transaction admits, and the changes have to alias every projection
        // that authority carries, so neither half validates without the other.
        git_authority_delta: pack
            .git_authority_bootstrap
            .clone()
            .map(GitExternalAuthorityDelta::initialize),
        changes: pack.changes.clone(),
        aliases: pack.aliases.clone(),
        ref_mutations: vec![RefMutation {
            name: pack.destination_ref.clone(),
            expected,
            new_target: Some(published_ref_target(pack)),
            policy: RefUpdatePolicy::FastForwardOnly,
        }],
        default_ref_mutation,
        workspace_mutation: None,
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    transaction.validate().map_err(model)?;
    Ok(transaction)
}

fn transfer_receipt(
    pack: &RepositoryTransferPack,
    authority_receipt: RepositoryCommitReceipt,
    outcome: RepositoryTransferApplyOutcome,
) -> RepositoryTransferReceipt {
    RepositoryTransferReceipt {
        schema_version: REPOSITORY_TRANSFER_SCHEMA_VERSION,
        protocol: REPOSITORY_TRANSFER_PROTOCOL.to_string(),
        transfer_id: pack.transfer_id,
        repository_id: pack.repository_id.clone(),
        destination_ref: pack.destination_ref.clone(),
        destination_head: pack.source_head,
        outcome,
        authority_receipt,
    }
}

#[derive(Serialize)]
struct RepositoryTransferIdentity<'a> {
    schema_version: u32,
    protocol: &'a str,
    operation_id: &'a OperationId,
    repository_id: &'a RepositoryId,
    source_ref: &'a RefName,
    destination_ref: &'a RefName,
    source_head: SemanticChangeId,
    transfer_target_head: SemanticChangeId,
    source_tree_hash: Hash256,
    expected_destination_target: &'a Option<RefTarget>,
    expected_destination_head: Option<SemanticChangeId>,
    expected_destination_roots: &'a RootBundle,
    expected_destination_default_ref: &'a Option<RefName>,
    source_git_authority_hash: Option<Hash256>,
    expected_destination_git_authority_hash: Option<Hash256>,
    git_authority_bootstrap_hash: Option<Hash256>,
    required_features: &'a [String],
    changes: Vec<SemanticChangeId>,
    trees: &'a [RepositoryTransferTreeIdentity],
    external_objects: &'a [ExternalObjectRecord],
    aliases: &'a [ExternalChangeAlias],
    bodies: Vec<RepositoryTransferBodyIdentity>,
}

#[derive(Serialize)]
struct RepositoryTransferBodyIdentity {
    hash: Hash256,
    byte_len: u64,
}

fn compute_transfer_id(pack: &RepositoryTransferPack) -> Result<Hash256> {
    // Semantic changes and bodies are already content-addressed objects. Their
    // declared identities are recomputed below by `validate_pack`, so carrying
    // those identities here binds the exact content without serializing an
    // unordered metadata map or copying every base64 body into a second large
    // allocation. The remaining envelope fields are ordered model values.
    let identity = RepositoryTransferIdentity {
        schema_version: pack.schema_version,
        protocol: &pack.protocol,
        operation_id: &pack.operation_id,
        repository_id: &pack.repository_id,
        source_ref: &pack.source_ref,
        destination_ref: &pack.destination_ref,
        source_head: pack.source_head,
        transfer_target_head: pack.transfer_target_head,
        source_tree_hash: pack.source_tree_hash,
        expected_destination_target: &pack.expected_destination_target,
        expected_destination_head: pack.expected_destination_head,
        expected_destination_roots: &pack.expected_destination_roots,
        expected_destination_default_ref: &pack.expected_destination_default_ref,
        source_git_authority_hash: pack.source_git_authority_hash,
        expected_destination_git_authority_hash: pack.expected_destination_git_authority_hash,
        git_authority_bootstrap_hash: hash_git_authority(pack.git_authority_bootstrap.as_ref())?,
        required_features: &pack.required_features,
        changes: pack.changes.iter().map(|change| change.id).collect(),
        trees: &pack.trees,
        external_objects: &pack.external_objects,
        aliases: &pack.aliases,
        bodies: pack
            .bodies
            .iter()
            .map(|body| RepositoryTransferBodyIdentity {
                hash: body.hash,
                byte_len: body.byte_len,
            })
            .collect(),
    };
    let payload = serde_json::to_vec(&identity)
        .map_err(|error| invalid(format!("serialize transfer identity: {error}")))?;
    Ok(domain_hash(b"kin-repository-transfer-v2\0", &payload))
}

fn hash_git_authority(authority: Option<&GitExternalAuthority>) -> Result<Option<Hash256>> {
    authority
        .map(|authority| {
            let payload = serde_json::to_vec(authority)
                .map_err(|error| invalid(format!("serialize Git authority identity: {error}")))?;
            Ok(domain_hash(b"kin-transfer-git-authority-v1\0", &payload))
        })
        .transpose()
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    Hash256::from_bytes(hasher.finalize().into())
}

fn verify_body(expected: Hash256, bytes: &[u8]) -> Result<()> {
    let actual = Hash256::from_bytes(Sha256::digest(bytes).into());
    if actual != expected {
        return Err(invalid(format!(
            "source body identity {expected} recomputes to {actual}"
        )));
    }
    Ok(())
}

/// Describe a count past its negotiated limit, or `None` when it fits.
///
/// Separate from [`enforce_count`] because a segmented transfer answers this
/// by building a smaller pack rather than by failing.
fn over_count(label: &str, actual: usize, limit: u32) -> Option<String> {
    let fits = u32::try_from(actual).is_ok_and(|actual| actual <= limit);
    (!fits).then(|| format!("carries {actual} {label}, over negotiated limit {limit}"))
}

fn enforce_count(label: &str, actual: usize, limit: u32) -> Result<()> {
    if actual > limit as usize {
        return Err(invalid(format!(
            "{label} count {actual} exceeds limit {limit}"
        )));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> RepositoryTransferError {
    RepositoryTransferError::Invalid(message.into())
}

fn storage(error: impl std::fmt::Display) -> RepositoryTransferError {
    RepositoryTransferError::Storage(error.to_string())
}

pub(crate) fn model(error: impl std::fmt::Display) -> RepositoryTransferError {
    invalid(error.to_string())
}

fn repository_commit(error: KinDbError) -> RepositoryTransferError {
    match error {
        KinDbError::Model(ModelError::Conflict(message))
        | KinDbError::ConcurrentAccessError(message) => RepositoryTransferError::Conflict(message),
        KinDbError::Model(error) => RepositoryTransferError::Invalid(error.to_string()),
        error => RepositoryTransferError::Storage(error.to_string()),
    }
}

struct TransferChangeStore {
    changes: BTreeMap<SemanticChangeId, SemanticChange>,
}

impl TransferChangeStore {
    fn new(changes: impl IntoIterator<Item = SemanticChange>) -> Self {
        Self {
            changes: changes
                .into_iter()
                .map(|change| (change.id, change))
                .collect(),
        }
    }
}

impl ChangeStore for TransferChangeStore {
    type Error = ModelError;

    fn get_entity_history(
        &self,
        _id: &kin_model::EntityId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
        Err(ModelError::InvalidOperation(
            "entity history is unavailable in repository transfer replay".to_string(),
        ))
    }

    fn find_merge_bases(
        &self,
        _a: &SemanticChangeId,
        _b: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChangeId>, Self::Error> {
        Err(ModelError::InvalidOperation(
            "merge-base search is unavailable in repository transfer replay".to_string(),
        ))
    }

    fn create_change(&self, _change: &SemanticChange) -> std::result::Result<(), Self::Error> {
        Err(ModelError::InvalidOperation(
            "repository transfer replay is immutable".to_string(),
        ))
    }

    fn get_change(
        &self,
        id: &SemanticChangeId,
    ) -> std::result::Result<Option<SemanticChange>, Self::Error> {
        Ok(self.changes.get(id).cloned())
    }

    fn get_changes_since(
        &self,
        _base: &SemanticChangeId,
        _head: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
        Err(ModelError::InvalidOperation(
            "range queries are unavailable in repository transfer replay".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;

    use kin_db::LocalFileBackend;
    use kin_model::{
        compute_semantic_change_id, ArtifactId, Entity, EntityDelta, EntityId, EntityKind,
        EntityMetadata, EntityRole, ExternalObjectKind, FingerprintAlgorithm,
        GitExternalAuthorityDelta, GitObjectBodyLoader, GitObjectFormat, GitObjectId, GitRawRef,
        GitRawTarget, LanguageId, LocatedEntry, RepoPath, SemanticFingerprint, Timestamp,
        TreeDelta, Visibility,
    };
    use sha1::{Digest as _, Sha1};
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;

    type TestManager = RepositoryAuthorityManager<LocalFileBackend>;

    struct TransferFixture {
        _source_dir: TempDir,
        _destination_dir: TempDir,
        source: TestManager,
        destination: TestManager,
        repository_id: RepositoryId,
        main: RefName,
        pack: RepositoryTransferPack,
        body_hashes: Vec<Hash256>,
        gitlink_target: GitObjectId,
        /// The external objects committed into BOTH replicas' baseline.
        ///
        /// The advance pack is a native fast-forward and carries none, so a
        /// test about external-object validation has to build its own pack from
        /// these. Their bodies are already in the destination's CAS, which is
        /// exactly the state a CAS-satisfied body arrives in.
        baseline_external_objects: Vec<ExternalObjectRecord>,
    }

    fn digest(bytes: &[u8]) -> Hash256 {
        Hash256::from_bytes(Sha256::digest(bytes).into())
    }

    fn entity_with_metadata(extra: HashMap<String, serde_json::Value>) -> Entity {
        Entity {
            id: EntityId(Uuid::from_u128(9_001)),
            kind: EntityKind::Function,
            name: "metadata_order_probe".to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0x11; 32]),
                signature_hash: Hash256::from_bytes([0x22; 32]),
                behavior_hash: Hash256::from_bytes([0x33; 32]),
                equivalence_hash: Hash256::from_bytes([0x44; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: "fn metadata_order_probe()".to_string(),
            visibility: Visibility::Private,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata { extra },
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn pack_with_metadata(
        base: &RepositoryTransferPack,
        extra: HashMap<String, serde_json::Value>,
    ) -> RepositoryTransferPack {
        let mut pack = base.clone();
        assert_eq!(pack.changes.len(), 1);
        assert_eq!(pack.trees.len(), 1);
        assert!(pack.aliases.is_empty());

        let old_change_id = pack.changes[0].id;
        pack.changes[0].entity_deltas.push(EntityDelta::Added {
            new: entity_with_metadata(extra),
        });
        let new_change_id = compute_semantic_change_id(&pack.changes[0]).unwrap();
        pack.changes[0].id = new_change_id;
        pack.source_head = new_change_id;
        pack.transfer_target_head = new_change_id;
        assert_eq!(pack.trees[0].change_id, old_change_id);
        pack.trees[0].change_id = new_change_id;
        pack.transfer_id = Hash256::from_bytes([0; 32]);
        pack.transfer_id = compute_transfer_id(&pack).unwrap();
        pack
    }

    fn manager(
        directory: &TempDir,
        repository_id: &RepositoryId,
    ) -> RepositoryAuthorityManager<LocalFileBackend> {
        let storage_root = directory.path().join("kindb");
        std::fs::create_dir_all(&storage_root).unwrap();
        RepositoryAuthorityManager::open(
            repository_id.clone(),
            Arc::new(LocalFileBackend::new(storage_root)),
        )
        .unwrap()
    }

    fn limits_above_every_local_ceiling() -> RepositoryTransferLimits {
        let local = RepositoryTransferLimits::default();
        RepositoryTransferLimits {
            max_changes: local.max_changes.checked_add(1).unwrap(),
            max_trees: local.max_trees.checked_add(1).unwrap(),
            max_bodies: local.max_bodies.checked_add(1).unwrap(),
            max_external_objects: local.max_external_objects.checked_add(1).unwrap(),
            max_aliases: local.max_aliases.checked_add(1).unwrap(),
            max_decoded_body_bytes: local.max_decoded_body_bytes.checked_add(1).unwrap(),
            max_single_body_bytes: local.max_single_body_bytes.checked_add(1).unwrap(),
        }
    }

    /// Commit one artifact-free native root change, so a publisher exists that
    /// has history and no imported-Git authority at all.
    ///
    /// Artifact-free on purpose: a Native change that introduces an artifact
    /// needs a bound workspace admission context and a transfer's receive
    /// transaction carries none, which is a different bound entirely and not
    /// what this control is about.
    fn seed_native_line(manager: &TestManager, main: &RefName) {
        let change = native_change(Vec::new(), "native root", Vec::new());
        let lease = manager.read_authority();
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(Uuid::from_u128(701)),
            repository_id: lease.metadata().repository_id.clone(),
            expected_generation: lease.roots().generation,
            expected_roots: lease.roots().clone(),
            actor: AuthorId::new("native-seed"),
            reason: "seed a publisher with no imported-Git authority".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: vec![change.clone()],
            aliases: Vec::new(),
            ref_mutations: vec![RefMutation {
                name: main.clone(),
                expected: RefExpectation::MustNotExist,
                new_target: Some(RefTarget::change(change.id)),
                policy: RefUpdatePolicy::FastForwardOnly,
            }],
            default_ref_mutation: Some(DefaultRefMutation {
                expected: DefaultRefExpectation::MustBeUnset,
                new_default: Some(main.clone()),
            }),
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        drop(lease);
        manager.commit_repository_transaction(transaction).unwrap();
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
            author: AuthorId::new("transfer-source"),
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

    #[derive(Clone, Default)]
    struct GitBodies(BTreeMap<Hash256, Vec<u8>>);

    impl GitObjectBodyLoader for GitBodies {
        type Error = std::convert::Infallible;

        fn load_body(
            &mut self,
            body_hash: &Hash256,
        ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.0.get(body_hash).cloned())
        }
    }

    fn git_object_id(kind: ExternalObjectKind, body: &[u8]) -> GitObjectId {
        let mut hasher = Sha1::new();
        hasher.update(kind.git_header());
        hasher.update(b" ");
        hasher.update(body.len().to_string().as_bytes());
        hasher.update([0]);
        hasher.update(body);
        GitObjectId::sha1(hasher.finalize().into())
    }

    fn git_record(
        kind: ExternalObjectKind,
        body: Vec<u8>,
        bodies: &mut GitBodies,
    ) -> ExternalObjectRecord {
        let object_id = git_object_id(kind, &body);
        let record = ExternalObjectRecord::from_raw(kind, object_id, &body).unwrap();
        bodies.0.insert(record.body_hash, body);
        record
    }

    fn git_tree_body(entries: &[(&[u8], &[u8], GitObjectId)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, mode, object_id) in entries {
            body.extend_from_slice(mode);
            body.push(b' ');
            body.extend_from_slice(name);
            body.push(0);
            body.extend_from_slice(object_id.as_bytes());
        }
        body
    }

    fn git_commit_body(tree: GitObjectId, parents: &[GitObjectId], message: &[u8]) -> Vec<u8> {
        let mut body = format!("tree {tree}\n").into_bytes();
        for parent in parents {
            body.extend_from_slice(format!("parent {parent}\n").as_bytes());
        }
        body.extend_from_slice(
            b"author Kin <kin@example.com> 1700000000 +0000\n\
              committer Kin <kin@example.com> 1700000000 +0000\n\n",
        );
        body.extend_from_slice(message);
        body
    }

    #[allow(clippy::too_many_arguments)]
    fn install_imported_baseline(
        manager: &TestManager,
        repository_id: &RepositoryId,
        main: &RefName,
        bodies: &GitBodies,
        external_objects: Vec<ExternalObjectRecord>,
        authority: GitExternalAuthority,
        changes: Vec<SemanticChange>,
        aliases: Vec<ExternalChangeAlias>,
        head_object: ExternalObjectId,
        operation: u128,
    ) {
        for record in &external_objects {
            manager
                .save_source_blob(
                    record.body_hash,
                    bodies
                        .0
                        .get(&record.body_hash)
                        .expect("fixture retains every exact Git object body"),
                )
                .unwrap();
        }
        let lease = manager.read_authority();
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(Uuid::from_u128(operation)),
            repository_id: repository_id.clone(),
            expected_generation: lease.roots().generation,
            expected_roots: lease.roots().clone(),
            actor: AuthorId::new("transfer-fixture"),
            reason: "install identical exact imported-Git baseline".to_string(),
            external_objects,
            git_authority_delta: Some(GitExternalAuthorityDelta::initialize(authority)),
            changes,
            aliases,
            ref_mutations: vec![RefMutation {
                name: main.clone(),
                expected: RefExpectation::MustNotExist,
                new_target: Some(RefTarget::external_object(head_object)),
                policy: RefUpdatePolicy::FastForwardOnly,
            }],
            default_ref_mutation: Some(DefaultRefMutation {
                expected: DefaultRefExpectation::MustBeUnset,
                new_default: Some(main.clone()),
            }),
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        drop(lease);
        manager.commit_repository_transaction(transaction).unwrap();
    }

    fn fixture() -> TransferFixture {
        let repository_id = RepositoryId::new("repository-transfer-test").unwrap();
        let main = RefName::branch(b"main").unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let source = manager(&source_dir, &repository_id);
        let destination = manager(&destination_dir, &repository_id);

        let compose_v1 = b"services:\n  api:\n    build: .\n".to_vec();
        let compose_v2 =
            b"services:\n  api:\n    build: .\n    environment:\n      KIN: native\n".to_vec();
        let dockerfile = b"FROM scratch\nCOPY payload.bin /payload.bin\n".to_vec();
        let executable = b"#!/bin/sh\nexec kin doctor\n".to_vec();
        let unsupported = b"pub fn main() void {}\n".to_vec();
        let binary = vec![0, 1, 2, 0xff, 0, 0x80];
        let symlink = b"compose.yaml".to_vec();
        let mut git_bodies = GitBodies::default();
        let compose = git_record(
            ExternalObjectKind::Blob,
            compose_v1.clone(),
            &mut git_bodies,
        );
        let docker = git_record(
            ExternalObjectKind::Blob,
            dockerfile.clone(),
            &mut git_bodies,
        );
        let check = git_record(
            ExternalObjectKind::Blob,
            executable.clone(),
            &mut git_bodies,
        );
        let zig = git_record(
            ExternalObjectKind::Blob,
            unsupported.clone(),
            &mut git_bodies,
        );
        let payload = git_record(ExternalObjectKind::Blob, binary.clone(), &mut git_bodies);
        let link = git_record(ExternalObjectKind::Blob, symlink.clone(), &mut git_bodies);
        let gitlink_target = GitObjectId::sha1([0x5a; 20]);
        let compose_artifact = ArtifactId(Uuid::from_u128(1));
        let compose_v1_entry = LocatedEntry::new(
            RepoPath::from_utf8("compose.yaml").unwrap(),
            TreeEntry::blob(compose.body_hash, false),
        );
        let tree_deltas = vec![
            TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(2)),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("Dockerfile").unwrap(),
                    TreeEntry::blob(docker.body_hash, false),
                ),
            },
            TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(3)),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("check").unwrap(),
                    TreeEntry::blob(check.body_hash, true),
                ),
            },
            TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(6)),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("compose-current").unwrap(),
                    TreeEntry::symlink(link.body_hash),
                ),
            },
            TreeDelta::Added {
                artifact_id: compose_artifact,
                new: compose_v1_entry.clone(),
            },
            TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(5)),
                new: LocatedEntry::new(
                    RepoPath::from_bytes(b"data-\xff.bin".to_vec()).unwrap(),
                    TreeEntry::blob(payload.body_hash, false),
                ),
            },
            TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(7)),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("dependency").unwrap(),
                    TreeEntry::gitlink(gitlink_target),
                ),
            },
            TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(4)),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("plugin.zig").unwrap(),
                    TreeEntry::blob(zig.body_hash, false),
                ),
            },
        ];
        let empty_tree = git_record(ExternalObjectKind::Tree, Vec::new(), &mut git_bodies);
        let root_tree = git_record(
            ExternalObjectKind::Tree,
            git_tree_body(&[
                (b"Dockerfile", b"100644", docker.object.oid),
                (b"check", b"100755", check.object.oid),
                (b"compose-current", b"120000", link.object.oid),
                (b"compose.yaml", b"100644", compose.object.oid),
                (b"data-\xff.bin", b"100644", payload.object.oid),
                (b"dependency", b"160000", gitlink_target),
                (b"plugin.zig", b"100644", zig.object.oid),
            ]),
            &mut git_bodies,
        );
        let parent_commit = git_record(
            ExternalObjectKind::Commit,
            git_commit_body(empty_tree.object.oid, &[], b"empty parent"),
            &mut git_bodies,
        );
        let head_commit = git_record(
            ExternalObjectKind::Commit,
            git_commit_body(
                root_tree.object.oid,
                &[parent_commit.object.oid],
                b"exact mixed repository baseline",
            ),
            &mut git_bodies,
        );
        let external_objects = vec![
            compose.clone(),
            docker,
            check,
            zig,
            payload,
            link,
            empty_tree,
            root_tree,
            parent_commit.clone(),
            head_commit.clone(),
        ];
        let raw_refs = vec![GitRawRef {
            name: main.clone(),
            target: GitRawTarget::Direct {
                object: head_commit.object,
            },
        }];
        let mut loader = git_bodies.clone();
        let authority = GitExternalAuthority::from_raw_parts(
            repository_id.clone(),
            GitObjectFormat::Sha1,
            raw_refs,
            GitRawTarget::Symbolic {
                target: main.clone(),
            },
            external_objects.clone(),
            &mut loader,
        )
        .unwrap();
        let timestamp = Timestamp(
            chrono::DateTime::parse_from_rfc3339("2026-07-26T14:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        let mut parent = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::GitCommit {
                oid: parent_commit.object.oid,
            },
            parents: Vec::new(),
            timestamp: timestamp.clone(),
            author: AuthorId::new("transfer-import"),
            message: "import exact empty parent".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            external_reference_deltas: Vec::new(),
        };
        parent.id = compute_semantic_change_id(&parent).unwrap();
        let mut imported_head = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::GitCommit {
                oid: head_commit.object.oid,
            },
            parents: vec![parent.id],
            timestamp,
            author: AuthorId::new("transfer-import"),
            message: "import exact mixed repository baseline".to_string(),
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
        imported_head.id = compute_semantic_change_id(&imported_head).unwrap();
        let aliases = vec![
            ExternalChangeAlias::new(repository_id.clone(), parent_commit.object.oid, parent.id),
            ExternalChangeAlias::new(
                repository_id.clone(),
                head_commit.object.oid,
                imported_head.id,
            ),
        ];
        for (manager, operation) in [(&source, 1_u128), (&destination, 2_u128)] {
            install_imported_baseline(
                manager,
                &repository_id,
                &main,
                &git_bodies,
                external_objects.clone(),
                authority.clone(),
                vec![parent.clone(), imported_head.clone()],
                aliases.clone(),
                head_commit.object,
                operation,
            );
        }

        let compose_v2_hash = digest(&compose_v2);
        source
            .save_source_blob(compose_v2_hash, &compose_v2)
            .unwrap();
        let child = native_change(
            vec![imported_head.id],
            "update non-language Compose configuration",
            vec![TreeDelta::Updated {
                artifact_id: compose_artifact,
                old: compose_v1_entry,
                new: LocatedEntry::new(
                    RepoPath::from_utf8("compose.yaml").unwrap(),
                    TreeEntry::blob(compose_v2_hash, false),
                ),
            }],
        );
        let source_lease = source.read_authority();
        let source_advance = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(Uuid::from_u128(3)),
            repository_id: repository_id.clone(),
            expected_generation: source_lease.roots().generation,
            expected_roots: source_lease.roots().clone(),
            actor: AuthorId::new("transfer-source"),
            reason: "advance source with exact Compose edit".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: vec![child.clone()],
            aliases: Vec::new(),
            ref_mutations: vec![RefMutation {
                name: main.clone(),
                expected: RefExpectation::MustEqual {
                    target: RefTarget::external_object(head_commit.object),
                },
                new_target: Some(RefTarget::change(child.id)),
                policy: RefUpdatePolicy::FastForwardOnly,
            }],
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        drop(source_lease);
        source
            .commit_repository_transaction(source_advance)
            .unwrap();

        let body_hashes = external_objects
            .iter()
            .map(|record| record.body_hash)
            .chain(std::iter::once(compose_v2_hash))
            .collect::<Vec<_>>();

        let status = repository_transfer_status(&destination, &repository_id, &main).unwrap();
        let expectation = RepositoryTransferExpectation::try_from(status).unwrap();
        let pack = build_repository_transfer_pack(&source, &main, &expectation).unwrap();
        TransferFixture {
            _source_dir: source_dir,
            _destination_dir: destination_dir,
            source,
            destination,
            repository_id,
            main,
            pack,
            body_hashes,
            gitlink_target,
            baseline_external_objects: external_objects,
        }
    }

    /// Build the bootstrap pack a Git-admitted publisher would send into a
    /// replica that has never held anything.
    ///
    /// The publisher here is the fixture's source, whose imported baseline is a
    /// real two-commit Git history. The destination is a THIRD replica of the
    /// same repository rather than the fixture's own, because the fixture
    /// installs the identical baseline on both of its replicas, which is
    /// exactly the state a bootstrap does not apply to.
    fn bootstrap_pack_from(
        fixture: &TransferFixture,
        destination: &TestManager,
        operation: u128,
    ) -> RepositoryTransferPack {
        // The lease the pack binds to is the DESTINATION's own, read from its
        // storage rather than assumed, which is what makes the receiver's
        // compare-and-swap a real check rather than a restatement.
        let destination_roots = destination.read_authority().roots().clone();
        let lease = fixture.source.read_authority();
        let metadata = lease.metadata();
        let authority = metadata
            .git_external_authority
            .clone()
            .expect("the fixture source carries an imported Git baseline");
        let external_objects = metadata.external_objects.clone();
        let aliases = metadata.aliases.clone();
        // Only the Git-origin half of the publisher's history. The fixture also
        // holds a native child, and a bootstrap carries the imported baseline.
        let mut git_changes: Vec<SemanticChange> = lease
            .snapshot()
            .changes
            .values()
            .filter(|change| matches!(change.origin, ChangeOrigin::GitCommit { .. }))
            .cloned()
            .collect();
        git_changes.sort_by_key(|change| change.parents.len());
        let head = git_changes
            .last()
            .expect("the imported baseline has at least one change")
            .clone();
        let store = TransferChangeStore::new(git_changes.iter().cloned());
        let trees: Vec<RepositoryTransferTreeIdentity> = git_changes
            .iter()
            .map(|change| {
                let tree = store.resolve_tree_at(&change.id).unwrap();
                RepositoryTransferTreeIdentity {
                    change_id: change.id,
                    tree_hash: compute_resolved_tree_hash(&tree).unwrap(),
                }
            })
            .collect();
        let source_tree_hash =
            compute_resolved_tree_hash(&store.resolve_tree_at(&head.id).unwrap()).unwrap();

        // Every external object ships its own bytes: a pack is self-validating
        // and refuses a record whose body it does not carry.
        let mut body_hashes = BTreeSet::new();
        for record in &external_objects {
            body_hashes.insert(record.body_hash);
        }
        for change in &git_changes {
            for delta in &change.tree_deltas {
                if let Some(state) = delta.new_state() {
                    if let Some(hash) = state.entry.blob_identity() {
                        body_hashes.insert(hash);
                    }
                }
            }
        }
        let bodies: Vec<RepositoryTransferBody> = body_hashes
            .iter()
            .map(|hash| {
                let bytes = fixture
                    .source
                    .load_source_blob(*hash)
                    .unwrap()
                    .expect("the publisher holds every body its authority names");
                RepositoryTransferBody::from_bytes(*hash, &bytes).unwrap()
            })
            .collect();

        let mut pack = RepositoryTransferPack {
            schema_version: REPOSITORY_TRANSFER_SCHEMA_VERSION,
            protocol: REPOSITORY_TRANSFER_PROTOCOL.to_string(),
            transfer_id: Hash256::from_bytes([0; 32]),
            operation_id: OperationId::from_uuid(Uuid::from_u128(operation)),
            repository_id: fixture.repository_id.clone(),
            source_ref: fixture.main.clone(),
            destination_ref: fixture.main.clone(),
            source_head: head.id,
            transfer_target_head: head.id,
            source_tree_hash,
            expected_destination_target: None,
            expected_destination_head: None,
            expected_destination_roots: destination_roots,
            expected_destination_default_ref: None,
            source_git_authority_hash: hash_git_authority(Some(&authority)).unwrap(),
            expected_destination_git_authority_hash: None,
            git_authority_bootstrap: Some(authority),
            required_features: required_features(),
            changes: git_changes,
            trees,
            external_objects,
            aliases,
            bodies,
        };
        pack.transfer_id = compute_transfer_id(&pack).unwrap();
        pack
    }

    /// The gate this closes: a Git-admitted publisher can put its history into
    /// a replica that has never held anything.
    ///
    /// Before this, transfer v1 carried a fast-forward only between replicas
    /// whose imported-Git authority already matched, and no push could
    /// establish one, so a repository that came from Git had no route into an
    /// empty hosted store at all.
    #[test]
    fn a_bootstrap_pack_establishes_git_authority_on_a_replica_that_had_none() {
        let fixture = fixture();
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = manager(&empty_dir, &fixture.repository_id);
        let pack = bootstrap_pack_from(&fixture, &empty, 91);

        let receipt = apply_repository_transfer_pack(
            &empty,
            &fixture.repository_id,
            &fixture.main,
            AuthorId::new("bootstrap-test"),
            &pack,
            &RepositoryTransferLimits::default(),
        )
        .expect("an empty replica admits a bootstrap");
        assert_eq!(receipt.outcome, RepositoryTransferApplyOutcome::Committed);

        let lease = empty.read_authority();
        let metadata = lease.metadata();
        assert!(
            metadata.git_external_authority.is_some(),
            "the replica must hold imported-Git authority after the bootstrap"
        );
        assert_eq!(
            hash_git_authority(metadata.git_external_authority.as_ref()).unwrap(),
            pack.source_git_authority_hash,
            "the replica's authority must be exactly the one the pack shipped, not a re-derivation"
        );
        assert_eq!(
            metadata.ref_state.default_ref.as_ref(),
            Some(&fixture.main),
            "the replica must adopt the published default ref"
        );
        assert_eq!(
            lease.snapshot().changes.len(),
            pack.changes.len(),
            "the replica must hold every change the bootstrap carried"
        );
    }

    /// The control that makes the test above mean something: a replica that
    /// already holds authority refuses a second publisher, so a bootstrap is
    /// a first publication and never a rebinding.
    ///
    /// Which guard answers is asserted rather than left to whichever fires
    /// first, because five of them can refuse this and they are not
    /// interchangeable. A publisher negotiating honestly against a replica that
    /// has moved reads its live roots, so it declares a non-zero generation and
    /// meets the generation-zero rule in `validate_pack` before any lease is
    /// consulted. A publisher declaring stale generation-zero roots gets past
    /// that and meets the roots compare-and-swap in
    /// `apply_repository_transfer_pack` instead. Both are refusals and only one
    /// of them is this test's.
    #[test]
    fn an_honest_second_publisher_is_refused_by_the_generation_zero_rule() {
        let fixture = fixture();
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = manager(&empty_dir, &fixture.repository_id);

        apply_repository_transfer_pack(
            &empty,
            &fixture.repository_id,
            &fixture.main,
            AuthorId::new("bootstrap-test"),
            &bootstrap_pack_from(&fixture, &empty, 92),
            &RepositoryTransferLimits::default(),
        )
        .expect("the first bootstrap is admitted");

        // A DIFFERENT operation id, so this is a genuine second publication
        // rather than the idempotent replay of the first.
        let error = apply_repository_transfer_pack(
            &empty,
            &fixture.repository_id,
            &fixture.main,
            AuthorId::new("second-publisher"),
            &bootstrap_pack_from(&fixture, &empty, 93),
            &RepositoryTransferLimits::default(),
        )
        .expect_err("a replica that already holds authority is not bootstrappable");
        assert!(
            matches!(error, RepositoryTransferError::Conflict(_)),
            "rebinding is a conflict, not a validation error: {error}"
        );
        assert!(
            error
                .to_string()
                .contains("admitted only at generation zero"),
            "this test is about the generation-zero rule; another guard answering \
             means the layering moved and the test now proves something else: {error}"
        );
    }

    /// The sender half: a Git-admitted publisher negotiating with a
    /// replica that has admitted nothing decides to bootstrap on its own, from
    /// the advertisement alone.
    ///
    /// This is the case the whole capability exists for and the one that was
    /// refused by construction before it. The publisher here carries a real
    /// imported Git baseline AND a native change on top of it, which is what a
    /// converted repository looks like the moment anyone works in it, so the
    /// pack proves the two kinds of history travel together rather than only
    /// the Git half.
    #[test]
    fn a_publisher_decides_to_bootstrap_from_an_unborn_advertisement_alone() {
        let fixture = fixture();
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = manager(&empty_dir, &fixture.repository_id);

        // The expectation an unborn replica publishes about itself. Read from
        // the replica rather than constructed, so the sender is reacting to the
        // real advertisement and not to a fixture's idea of one.
        let status =
            repository_transfer_status(&empty, &fixture.repository_id, &fixture.main).unwrap();
        assert!(
            status.git_authority_hash.is_none() && status.destination_head.is_none(),
            "the destination must actually be unborn or this test is about something else"
        );
        let expectation = RepositoryTransferExpectation::try_from(status).unwrap();

        let segment =
            build_repository_transfer_segment(&fixture.source, &fixture.main, &expectation)
                .expect("a publisher with Git authority may bootstrap an unborn replica");
        let pack = segment.pack;
        assert_eq!(
            segment.remaining_changes, 0,
            "a bootstrap publishes the whole history in one pack or refuses"
        );
        assert!(
            pack.git_authority_bootstrap.is_some(),
            "the sender must decide to bootstrap on its own, from the advertisement alone"
        );
        assert!(
            pack.changes
                .iter()
                .any(|change| matches!(change.origin, ChangeOrigin::GitCommit { .. }))
                && pack
                    .changes
                    .iter()
                    .any(|change| matches!(change.origin, ChangeOrigin::Native)),
            "the pack must carry both the imported baseline and the native work on top of it"
        );

        // Landing this exact pack is a different test, because this fixture's
        // tree carries a gitlink and what a bootstrap may do with one is a
        // pair of bounds of its own, recorded immediately below. What a
        // bootstrap lands when no gitlink is involved at all is proven by
        // `a_bootstrap_pack_establishes_git_authority_on_a_replica_that_had_none`,
        // whose history is Git-origin throughout.
    }

    /// A converted repository holding a submodule DOES bootstrap, once the
    /// gitlink its native history inherits is one the same transaction's own
    /// Git authority projects.
    ///
    /// This test asserted the opposite refusal until kin-db 0.7.66, and the
    /// refusal was correct on its own terms and impossible to satisfy.
    /// `verify_native_change_admission` read `authenticated_gitlinks` from the
    /// state BEFORE the transaction, so a bootstrap's own authority install
    /// could authenticate nothing: at the moment of the check the replica still
    /// held no authority at all. One rule requires the two halves to arrive
    /// together and this one was broken by their arriving together, so every
    /// repository carrying a submodule and any native change at all was
    /// unbootstrappable. From 0.7.66 the check reads the persisted index plus
    /// the gitlinks carried by the Git-origin changes the SUCCESSOR authority
    /// projects, and a Git-origin change earns that only by surviving the raw
    /// tree replay, which requires its semantic tree to equal the raw Git tree
    /// exactly. The refusal moved to the case below rather than disappearing.
    ///
    /// The width the old test recorded is still real and is what this fixture
    /// exercises: the check walks the whole RESOLVED TREE of each native change
    /// rather than its deltas, so a native change inherits every gitlink in the
    /// tree. Here the gitlink sits at `dependency` and the native change only
    /// edits `compose.yaml`, so the child is admitted on authority it never
    /// touched.
    ///
    /// The assertions name the child and the landed gitlink rather than the
    /// outcome alone, because a transaction that admitted the imported baseline
    /// and dropped the native change would report Committed too.
    #[test]
    fn a_bootstrap_carrying_native_history_over_a_gitlink_its_authority_projects_lands() {
        let fixture = fixture();
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = manager(&empty_dir, &fixture.repository_id);
        let status =
            repository_transfer_status(&empty, &fixture.repository_id, &fixture.main).unwrap();
        let expectation = RepositoryTransferExpectation::try_from(status).unwrap();
        let pack = build_repository_transfer_segment(&fixture.source, &fixture.main, &expectation)
            .expect("a publisher with Git authority may bootstrap an unborn replica")
            .pack;
        let native_child = pack
            .changes
            .iter()
            .find(|change| matches!(change.origin, ChangeOrigin::Native))
            .expect("the bootstrap carries the native work on top of the imported baseline")
            .id;

        let receipt = apply_repository_transfer_pack(
            &empty,
            &fixture.repository_id,
            &fixture.main,
            AuthorId::new("bootstrap-sender-test"),
            &pack,
            &RepositoryTransferLimits::default(),
        )
        .expect("a gitlink this transaction's own Git authority projects authenticates the native child that inherits it");
        assert_eq!(receipt.outcome, RepositoryTransferApplyOutcome::Committed);
        assert_eq!(receipt.destination_head, pack.source_head);

        let lease = empty.read_authority();
        assert!(
            lease.snapshot().changes.contains_key(&native_child),
            "the native child must be persisted, not merely tolerated by a transaction \
             that admitted the imported baseline and dropped it"
        );
        let store = TransferChangeStore::new(lease.snapshot().changes.values().cloned());
        let landed = store.resolve_tree_at(&pack.source_head).unwrap();
        let inherited = landed
            .artifact_at_path(&RepoPath::from_utf8("dependency").unwrap())
            .expect("the landed tree must still carry the submodule the baseline imported");
        assert!(
            matches!(
                inherited.entry,
                TreeEntry::Gitlink { target } if target == fixture.gitlink_target
            ),
            "the landed entry must be the exact gitlink the imported authority projects: {:?}",
            inherited.entry
        );
    }

    /// The refusal that did NOT move: a gitlink no authority projects.
    ///
    /// The allowance above is bound to the successor authority's own exact
    /// targets, so it cannot widen into "any gitlink inside a transaction that
    /// happens to carry Git authority". This drives the same real sender and
    /// then retargets the inherited submodule to a commit the imported history
    /// never contained, which is the shape a hostile publisher would send, and
    /// the receiver must refuse it by the same name it used to refuse
    /// everything.
    ///
    /// The pack is edited rather than published from a second source replica on
    /// purpose: the source would refuse to commit this change for the same
    /// reason the destination refuses to admit it, so the only way to put a
    /// hostile pack on the wire is to build one.
    #[test]
    fn a_bootstrap_carrying_a_gitlink_no_authority_projects_is_refused_by_name() {
        let fixture = fixture();
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = manager(&empty_dir, &fixture.repository_id);
        let status =
            repository_transfer_status(&empty, &fixture.repository_id, &fixture.main).unwrap();
        let expectation = RepositoryTransferExpectation::try_from(status).unwrap();
        let mut pack =
            build_repository_transfer_segment(&fixture.source, &fixture.main, &expectation)
                .expect("the sender builds the bootstrap; the refusal is the receiver's")
                .pack;

        // Read the submodule out of the pack's own head tree rather than
        // restating the fixture's artifact id here, so this follows the fixture
        // instead of agreeing with it by coincidence.
        let sent = TransferChangeStore::new(pack.changes.iter().cloned());
        let inherited = sent
            .resolve_tree_at(&pack.source_head)
            .unwrap()
            .artifact_at_path(&RepoPath::from_utf8("dependency").unwrap())
            .expect("the bootstrap's head tree carries the imported submodule")
            .clone();
        assert!(
            matches!(
                inherited.entry,
                TreeEntry::Gitlink { target } if target == fixture.gitlink_target
            ),
            "this test retargets a gitlink, so what it starts from must be one: {:?}",
            inherited.entry
        );

        let unauthenticated = GitObjectId::sha1([0x66; 20]);
        assert_ne!(
            unauthenticated, fixture.gitlink_target,
            "the retargeted commit must be one the imported authority does not project"
        );
        let retarget = native_change(
            vec![pack.source_head],
            "retarget the imported submodule to a commit no authority projects",
            vec![TreeDelta::Updated {
                artifact_id: inherited.artifact_id,
                old: inherited.located_entry(),
                new: LocatedEntry::new(inherited.path.clone(), TreeEntry::gitlink(unauthenticated)),
            }],
        );
        pack.changes.push(retarget.clone());
        pack.source_head = retarget.id;
        pack.transfer_target_head = retarget.id;
        let rewritten = TransferChangeStore::new(pack.changes.iter().cloned());
        pack.trees = pack
            .changes
            .iter()
            .map(|change| RepositoryTransferTreeIdentity {
                change_id: change.id,
                tree_hash: compute_resolved_tree_hash(
                    &rewritten.resolve_tree_at(&change.id).unwrap(),
                )
                .unwrap(),
            })
            .collect();
        pack.source_tree_hash =
            compute_resolved_tree_hash(&rewritten.resolve_tree_at(&pack.source_head).unwrap())
                .unwrap();
        pack.transfer_id = compute_transfer_id(&pack).unwrap();

        let error = apply_repository_transfer_pack(
            &empty,
            &fixture.repository_id,
            &fixture.main,
            AuthorId::new("bootstrap-sender-test"),
            &pack,
            &RepositoryTransferLimits::default(),
        )
        .expect_err("a gitlink this transaction's own authority does not project cannot land");
        assert!(
            error
                .to_string()
                .contains("without verified Git external authority"),
            "the refusal must name the gitlink authentication bound rather than a tree \
             identity, a body or a limit the pack edit disturbed: {error}"
        );

        let after =
            repository_transfer_status(&empty, &fixture.repository_id, &fixture.main).unwrap();
        assert!(
            after.destination_head.is_none() && after.git_authority_hash.is_none(),
            "a refused bootstrap leaves the replica exactly as unborn as it found it"
        );
    }

    /// The control: a publisher with NO Git authority negotiating with the same
    /// unborn replica builds an ordinary pack, not a bootstrap.
    ///
    /// Without this, the test above would pass equally well against a sender
    /// that stamped a bootstrap onto everything, and the field would be
    /// decoration rather than a decision.
    #[test]
    fn a_publisher_without_git_authority_builds_no_bootstrap() {
        let fixture = fixture();
        let native_dir = tempfile::tempdir().unwrap();
        let native = manager(&native_dir, &fixture.repository_id);
        seed_native_line(&native, &fixture.main);

        let empty_dir = tempfile::tempdir().unwrap();
        let empty = manager(&empty_dir, &fixture.repository_id);
        let status =
            repository_transfer_status(&empty, &fixture.repository_id, &fixture.main).unwrap();
        let expectation = RepositoryTransferExpectation::try_from(status).unwrap();

        let segment = build_repository_transfer_segment(&native, &fixture.main, &expectation)
            .expect("a native publisher may publish into an unborn replica");
        assert!(
            segment.pack.git_authority_bootstrap.is_none(),
            "a publisher with no imported-Git authority has nothing to bootstrap"
        );
    }

    /// A transport that answers straight out of a local manager, so a pull can
    /// be negotiated against a Git-admitted remote without a socket.
    struct GitAdmittedPeer<'a>(&'a TestManager);

    impl crate::repository_transfer_negotiation::RepositoryTransferTransport for GitAdmittedPeer<'_> {
        fn advertise_refs(
            &self,
            repository_id: &RepositoryId,
        ) -> Result<RepositoryRefAdvertisement> {
            repository_ref_advertisement(self.0, repository_id)
        }

        fn transfer_status(
            &self,
            repository_id: &RepositoryId,
            destination_ref: &RefName,
        ) -> Result<RepositoryTransferStatus> {
            repository_transfer_status(self.0, repository_id, destination_ref)
        }

        fn export_pack(
            &self,
            _repository_id: &RepositoryId,
            source_ref: &RefName,
            expectation: &RepositoryTransferExpectation,
        ) -> Result<RepositoryTransferPack> {
            build_repository_transfer_segment(self.0, source_ref, expectation)
                .map(|segment| segment.pack)
        }

        fn receive_pack(
            &self,
            repository_id: &RepositoryId,
            destination_ref: &RefName,
            pack: &RepositoryTransferPack,
        ) -> Result<RepositoryTransferReceipt> {
            apply_repository_transfer_pack(
                self.0,
                repository_id,
                destination_ref,
                AuthorId::new("peer"),
                pack,
                &RepositoryTransferLimits::default(),
            )
        }
    }

    /// The pull direction reaches a bootstrap too, and this is the composition
    /// the push tests do not cover.
    ///
    /// Every piece was already proven separately: an unborn replica's status is
    /// the five-field empty signature, and a Git-admitted source handed that
    /// expectation builds a bootstrap. What had no test was the negotiation
    /// joining them, which is where a short-circuit for a replica holding no
    /// ref would have hidden. So this drives the real `fetch_pull_pack` and
    /// asserts the pack it comes back with is a bootstrap.
    ///
    /// It stops at the pack rather than admitting it, because what an admitted
    /// bootstrap lands is a separate question with its own assertions, proven
    /// immediately below on the pack this negotiation produces.
    #[test]
    fn an_unborn_replica_negotiating_a_pull_is_offered_a_bootstrap() {
        use crate::repository_transfer_negotiation::{fetch_pull_pack, PullNegotiation};

        let fixture = fixture();
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = manager(&empty_dir, &fixture.repository_id);
        let remote = GitAdmittedPeer(&fixture.source);

        let negotiation = fetch_pull_pack(
            &empty,
            &remote,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .expect("an unborn replica may negotiate a pull from a Git-admitted remote");

        let PullNegotiation::Pack(pack) = negotiation else {
            panic!("an unborn replica has everything to admit, so the remote must offer a pack");
        };
        assert!(
            pack.git_authority_bootstrap.is_some(),
            "the remote must offer a BOOTSTRAP, not a fast-forward the puller cannot apply"
        );
        assert_eq!(
            pack.expected_destination_git_authority_hash, None,
            "the pack must be bound to the unborn lease this replica actually has"
        );
    }

    /// The admit step on the pull path, which nothing covered end to end.
    ///
    /// The negotiation above proved the offer and stopped, because until
    /// kin-db 0.7.66 admitting this fixture's pack met the gitlink bound
    /// instead of anything about pulling. It no longer does, so the sequence a
    /// native clone would actually run, negotiate then admit, is exercised here
    /// as one run rather than as two halves that were never joined.
    ///
    /// This is the same receive function the push direction proves, reached
    /// from the other side, and the assertions name what landed rather than the
    /// outcome alone.
    #[test]
    fn an_unborn_replica_admits_the_bootstrap_a_pull_offers_it() {
        use crate::repository_transfer_negotiation::{fetch_pull_pack, PullNegotiation};

        let fixture = fixture();
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = manager(&empty_dir, &fixture.repository_id);
        let remote = GitAdmittedPeer(&fixture.source);

        let PullNegotiation::Pack(pack) = fetch_pull_pack(
            &empty,
            &remote,
            &fixture.repository_id,
            &fixture.main,
            &fixture.main,
        )
        .expect("an unborn replica may negotiate a pull from a Git-admitted remote") else {
            panic!("an unborn replica has everything to admit, so the remote must offer a pack");
        };

        let receipt = apply_repository_transfer_pack(
            &empty,
            &fixture.repository_id,
            &fixture.main,
            AuthorId::new("pull-admit-test"),
            &pack,
            &RepositoryTransferLimits::default(),
        )
        .expect("the replica admits the bootstrap it was offered");
        assert_eq!(receipt.outcome, RepositoryTransferApplyOutcome::Committed);

        let status =
            repository_transfer_status(&empty, &fixture.repository_id, &fixture.main).unwrap();
        assert_eq!(
            status.destination_head,
            Some(pack.source_head),
            "the puller must stand on the head it admitted"
        );
        assert_eq!(
            status.destination_tree_hash,
            Some(pack.source_tree_hash),
            "and on that head's exact tree"
        );
        assert!(
            status.git_authority_hash.is_some(),
            "a bootstrap installs the publisher's imported-Git authority, which is what \
             makes the replica able to pull again"
        );
    }

    /// The other reachable layer: a publisher that LIES about the destination
    /// being empty.
    ///
    /// An honest publisher reads the destination's live roots and so declares a
    /// non-zero generation once the replica has moved. One that declares stale
    /// generation-zero roots gets past the generation rule and is refused by the
    /// compare-and-swap against the lease instead, which is the guard that does
    /// not depend on the sender telling the truth. Together the two cover the
    /// honest case and the dishonest one, and neither alone does.
    #[test]
    fn a_publisher_declaring_a_stale_empty_lease_is_refused_by_the_compare_and_swap() {
        let fixture = fixture();
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = manager(&empty_dir, &fixture.repository_id);

        // Capture the genuinely-empty lease BEFORE the first bootstrap, which
        // is what a stale publisher would still be holding.
        let stale = bootstrap_pack_from(&fixture, &empty, 95);
        apply_repository_transfer_pack(
            &empty,
            &fixture.repository_id,
            &fixture.main,
            AuthorId::new("first-publisher"),
            &bootstrap_pack_from(&fixture, &empty, 96),
            &RepositoryTransferLimits::default(),
        )
        .expect("the first bootstrap is admitted");

        let error = apply_repository_transfer_pack(
            &empty,
            &fixture.repository_id,
            &fixture.main,
            AuthorId::new("stale-publisher"),
            &stale,
            &RepositoryTransferLimits::default(),
        )
        .expect_err("a stale empty-lease declaration is refused");
        assert!(
            error.to_string().contains("moved from the pack lease"),
            "the refusal must come from the lease compare-and-swap, not from the \
             sender's own declaration: {error}"
        );
    }

    /// A bootstrap whose shipped authority is not the one it advertised is
    /// refused, because the negotiation and the payload would then describe
    /// different repositories and only one of them was agreed to.
    #[test]
    fn a_bootstrap_whose_authority_does_not_match_its_declared_hash_is_refused() {
        let fixture = fixture();
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = manager(&empty_dir, &fixture.repository_id);
        let mut pack = bootstrap_pack_from(&fixture, &empty, 94);
        pack.source_git_authority_hash = Some(Hash256::from_bytes([0x11; 32]));
        pack.transfer_id = compute_transfer_id(&pack).unwrap();

        let error = validate_pack(&pack, &RepositoryTransferLimits::default())
            .expect_err("a mismatched bootstrap hash is refused");
        assert!(
            error
                .to_string()
                .contains("does not hash to the source Git authority"),
            "the refusal must name the mismatch: {error}"
        );
    }

    /// A pack over the effective ceiling refuses, and the refusal is useful.
    ///
    /// The message names the bound that actually applied and the knob that
    /// moves it. A refusal quoting a compiled constant sends an operator
    /// looking for a release when a restart would do; one quoting no number
    /// leaves them guessing which of seven ceilings refused.
    #[test]
    fn an_oversized_closure_refuses_by_naming_the_effective_bound_and_the_knob() {
        let fixture = fixture();
        // The default is pinned here so the arms below, which use small
        // ceilings to stay cheap, cannot drift away from what ships.
        assert_eq!(
            MAX_TRANSFER_DECODED_BODY_BYTES,
            64 * 1024 * 1024,
            "the shipped default ceiling"
        );

        let tiny = RepositoryTransferLimits::default().with_decoded_body_ceiling(1);
        let error = validate_pack(&fixture.pack, &tiny).unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("exceeds the effective ceiling of 1 bytes"),
            "the refusal names the bound that applied, not a constant: {text}"
        );
        assert!(
            text.contains(DECODED_BODY_CEILING_ENV),
            "and the knob that moves it: {text}"
        );
    }

    /// The config arm. A raised ceiling admits a pack the smaller one refuses.
    ///
    /// This is what falsifies the THREADING rather than the arithmetic: the
    /// limits have to reach `validate_pack` for the two verdicts to differ. A
    /// version that kept reading the constant gives the same answer twice.
    #[test]
    fn a_raised_ceiling_admits_the_pack_a_smaller_one_refuses() {
        let fixture = fixture();
        let decoded: u64 = fixture.pack.bodies.iter().map(|body| body.byte_len).sum();
        assert!(
            decoded > 0,
            "the fixture must carry bodies or this proves nothing"
        );

        let under = RepositoryTransferLimits::default().with_decoded_body_ceiling(decoded - 1);
        let over = RepositoryTransferLimits::default().with_decoded_body_ceiling(decoded);

        assert!(
            validate_pack(&fixture.pack, &under).is_err(),
            "a ceiling below the closure refuses"
        );
        validate_pack(&fixture.pack, &over)
            .expect("the same pack passes once the ceiling reaches the closure");
    }

    /// The negotiation arm. A peer advertising less wins over a raised local
    /// ceiling, because the effective bound is the smaller of the two.
    ///
    /// A host with headroom may raise what it accepts. It may not raise what
    /// the other side can build or validate, and `bounded_by` is what keeps
    /// those two facts from being confused.
    #[test]
    fn a_peer_advertising_less_beats_a_raised_local_ceiling() {
        let fixture = fixture();
        let decoded: u64 = fixture.pack.bodies.iter().map(|body| body.byte_len).sum();

        let raised_local =
            RepositoryTransferLimits::default().with_decoded_body_ceiling(decoded * 16);
        let cautious_peer =
            RepositoryTransferLimits::default().with_decoded_body_ceiling(decoded - 1);

        let effective = raised_local.clone().bounded_by(&cautious_peer);
        assert_eq!(
            effective.max_decoded_body_bytes,
            decoded - 1,
            "the smaller of the two is what applies"
        );
        assert!(
            validate_pack(&fixture.pack, &effective).is_err(),
            "so the pack refuses even though this host would have taken it"
        );
        // And the control in the other direction: the local ceiling still binds
        // when the peer is the generous one, or "minimum" would mean "peer".
        let generous_peer =
            RepositoryTransferLimits::default().with_decoded_body_ceiling(decoded * 64);
        let cautious_local =
            RepositoryTransferLimits::default().with_decoded_body_ceiling(decoded - 1);
        assert_eq!(
            cautious_local
                .bounded_by(&generous_peer)
                .max_decoded_body_bytes,
            decoded - 1
        );
    }

    /// The poisoned-CAS arm, which is 3b's reason to exist.
    ///
    /// An external body may be satisfied from the destination's own CAS rather
    /// than carried in the pack. The bytes are LOADED and validated, so a CAS
    /// entry that is not the object it claims to be is caught. A design that
    /// skipped validation for a CAS-satisfied body would admit every failing
    /// case below, which is why that design was refused.
    #[test]
    fn a_cas_satisfied_external_body_is_validated_not_trusted() {
        let fixture = fixture();
        let record = fixture.baseline_external_objects[0].clone();
        let other = fixture
            .baseline_external_objects
            .iter()
            .find(|candidate| candidate.body_hash != record.body_hash)
            .expect("the baseline carries more than one external object")
            .clone();

        // A pack naming one external object and carrying NO body for it. The
        // destination already holds that body from the shared baseline, which
        // is the state this whole option exists to exploit.
        let cas_satisfied = |external: Vec<ExternalObjectRecord>| {
            let mut pack = fixture.pack.clone();
            pack.external_objects = external;
            pack.bodies = Vec::new();
            pack.transfer_id = compute_transfer_id(&pack).unwrap();
            pack
        };

        // The healthy CAS-satisfied path, first, or the failures below could be
        // satisfied by a validator that refuses every absent body.
        decode_and_validate_bodies(&cas_satisfied(vec![record.clone()]), &fixture.destination)
            .expect("a body the destination already holds resolves and validates");

        // The store will not let a substituted body in. Writing bytes that do
        // not hash to the key is refused at the CAS itself:
        //
        //   immutable source blob digest mismatch for repo ...: requested <a>, found <b>
        //
        // So "a poisoned CAS entry" is not reachable through this API at all,
        // and an arm that tried to build one would be testing the store rather
        // than the receiver. Asserted here rather than dropped, because the
        // fact that this is impossible is load-bearing for the design: it is
        // why the remaining risk is a MISFILED record rather than a corrupted
        // store, and the case below is that risk.
        let refused = fixture
            .destination
            .save_source_blob(record.body_hash, b"not the object this claims to be")
            .expect_err("the CAS verifies its own key on write");
        assert!(
            refused.to_string().contains("digest mismatch"),
            "and says so: {refused}"
        );

        // The real risk, then. Claim the FIRST object's Git identity over
        // the SECOND object's bytes. The declared length and the sha256 both
        // agree with what the CAS holds, so only the Git-object recomputation
        // can see it, and that is precisely the check a skip-validation design
        // would have given up.
        let mut mismatched = record.clone();
        mismatched.body_hash = other.body_hash;
        mismatched.body_len = other.body_len;
        let error =
            decode_and_validate_bodies(&cas_satisfied(vec![mismatched]), &fixture.destination)
                .expect_err("a body filed under a Git identity that is not its own");
        assert!(
            error.to_string().contains("recomputes to"),
            "the Git-object recomputation is what catches this: {error}"
        );

        // And a body in neither place still refuses, naming both.
        let mut absent = record.clone();
        absent.body_hash = digest(b"a body no store anywhere has ever held");
        let error = decode_and_validate_bodies(&cas_satisfied(vec![absent]), &fixture.destination)
            .expect_err("a body in neither the pack nor the CAS");
        assert!(
            error
                .to_string()
                .contains("absent from the pack and from the destination CAS"),
            "and the refusal says it looked in both: {error}"
        );
    }

    /// The healthy path, at zero refusals.
    ///
    /// Without this the four arms above are satisfied by a validator that
    /// refuses everything.
    #[test]
    fn a_healthy_pack_passes_at_the_shipped_default_with_no_refusals() {
        let fixture = fixture();
        validate_pack(&fixture.pack, &RepositoryTransferLimits::default())
            .expect("the fixture pack is valid at the shipped ceiling");
        decode_and_validate_bodies(&fixture.pack, &fixture.destination)
            .expect("and every external object validates against real bytes");
    }

    #[test]
    fn exact_fast_forward_transfers_every_repository_member_and_retries_idempotently() {
        let fixture = fixture();
        let advertised =
            repository_transfer_status(&fixture.destination, &fixture.repository_id, &fixture.main)
                .unwrap();
        assert!(advertised.push_apply_ready);
        assert!(advertised.bounded_envelope_export_ready);
        assert!(advertised.pull_apply_ready);
        assert_eq!(fixture.pack.changes.len(), 1);
        assert_eq!(fixture.pack.trees.len(), 1);
        assert_eq!(
            fixture.pack.bodies.len(),
            1,
            "the identical imported baseline stays destination-owned while the native Compose edit transfers"
        );
        assert!(!fixture.pack.bodies.iter().any(|body| {
            body.hash
                == Hash256::from_bytes(Sha256::digest(fixture.gitlink_target.as_bytes()).into())
        }));

        let actor = AuthorId::new("authenticated-user");
        let receipt = apply_repository_transfer_pack(
            &fixture.destination,
            &fixture.repository_id,
            &fixture.main,
            actor.clone(),
            &fixture.pack,
            &RepositoryTransferLimits::default(),
        )
        .unwrap();
        assert_eq!(receipt.outcome, RepositoryTransferApplyOutcome::Committed);
        assert_eq!(receipt.destination_head, fixture.pack.source_head);

        let status =
            repository_transfer_status(&fixture.destination, &fixture.repository_id, &fixture.main)
                .unwrap();
        assert_eq!(status.destination_head, Some(fixture.pack.source_head));
        assert_eq!(
            status.destination_tree_hash,
            Some(fixture.pack.source_tree_hash)
        );
        let lease = fixture.destination.read_authority();
        let store = TransferChangeStore::new(lease.snapshot().changes.values().cloned());
        let tree = store.resolve_tree_at(&fixture.pack.source_head).unwrap();
        assert!(tree.artifacts().any(|artifact| {
            matches!(
                artifact.entry,
                TreeEntry::Gitlink { target } if target == fixture.gitlink_target
            )
        }));
        drop(lease);
        for hash in &fixture.body_hashes {
            assert_eq!(
                fixture.destination.load_source_blob(*hash).unwrap(),
                fixture.source.load_source_blob(*hash).unwrap()
            );
        }

        let replay = apply_repository_transfer_pack(
            &fixture.destination,
            &fixture.repository_id,
            &fixture.main,
            actor,
            &fixture.pack,
            &RepositoryTransferLimits::default(),
        )
        .unwrap();
        assert_eq!(
            replay.outcome,
            RepositoryTransferApplyOutcome::IdempotentReplay
        );
        assert_eq!(
            replay.authority_receipt.transaction_hash,
            receipt.authority_receipt.transaction_hash
        );

        let error = apply_repository_transfer_pack(
            &fixture.destination,
            &fixture.repository_id,
            &fixture.main,
            AuthorId::new("different-authenticated-user"),
            &fixture.pack,
            &RepositoryTransferLimits::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("different exact transaction"));
    }

    #[test]
    fn status_advertisement_above_local_caps_is_bounded_before_negotiation() {
        let fixture = fixture();
        let mut advertised =
            repository_transfer_status(&fixture.destination, &fixture.repository_id, &fixture.main)
                .unwrap();
        advertised.limits = limits_above_every_local_ceiling();

        let expectation = RepositoryTransferExpectation::try_from(advertised).unwrap();

        assert_eq!(
            expectation.limits,
            RepositoryTransferLimits::default(),
            "a peer's larger ceilings must not enlarge this process's bounded envelope"
        );
    }

    #[test]
    fn export_expectation_above_local_caps_is_bounded_before_assembly() {
        let fixture = fixture();
        let status =
            repository_transfer_status(&fixture.destination, &fixture.repository_id, &fixture.main)
                .unwrap();
        let mut expectation = RepositoryTransferExpectation::try_from(status).unwrap();
        expectation.limits = limits_above_every_local_ceiling();

        let bounded = locally_bounded_expectation(&expectation).unwrap();
        assert_eq!(
            bounded.limits,
            RepositoryTransferLimits::default(),
            "request-body ceilings must be bounded before an export is planned"
        );

        let segment =
            build_repository_transfer_segment(&fixture.source, &fixture.main, &expectation)
                .unwrap();
        validate_pack(&segment.pack, &RepositoryTransferLimits::default())
            .expect("the locally bounded exporter must build a valid pack");
    }

    #[test]
    fn receiver_rejects_missing_unchanged_source_tree_body() {
        let fixture = fixture();
        let missing = fixture.body_hashes[1];
        assert!(
            !fixture.pack.bodies.iter().any(|body| body.hash == missing),
            "the regression requires an unchanged baseline body"
        );
        let digest = missing.to_string();
        std::fs::remove_file(
            fixture
                ._destination_dir
                .path()
                .join("kindb")
                .join(fixture.repository_id.to_string())
                .join("source-blobs")
                .join("sha256")
                .join(&digest[..2])
                .join(&digest),
        )
        .unwrap();

        let error = apply_repository_transfer_pack(
            &fixture.destination,
            &fixture.repository_id,
            &fixture.main,
            AuthorId::new("receiver"),
            &fixture.pack,
            &RepositoryTransferLimits::default(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("required immutable source body"),
            "{error}"
        );
    }

    #[test]
    fn advertisement_publishes_ordered_refs_with_resolved_heads() {
        let fixture = fixture();
        let advertised =
            repository_ref_advertisement(&fixture.source, &fixture.repository_id).unwrap();

        assert_eq!(advertised.protocol, REPOSITORY_TRANSFER_PROTOCOL);
        assert_eq!(
            advertised.schema_version,
            REPOSITORY_TRANSFER_SCHEMA_VERSION
        );
        assert_eq!(advertised.repository_id, fixture.repository_id);

        let main = advertised
            .refs
            .iter()
            .find(|entry| entry.name == fixture.main)
            .expect("source publishes the transferred ref");
        let status =
            repository_transfer_status(&fixture.source, &fixture.repository_id, &fixture.main)
                .unwrap();
        assert_eq!(Some(main.head), status.destination_head);
        assert_eq!(Some(main.target.clone()), status.destination_target);
        assert_eq!(advertised.default_ref, status.default_ref);

        // Publish two more refs in an order the advertisement must not keep,
        // so the ordering assertion below has something to sort.
        let head = status.destination_head.unwrap();
        let zulu = RefName::branch(b"zulu").unwrap();
        let alpha = RefName::branch(b"alpha").unwrap();
        let lease = fixture.source.read_authority();
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: fixture.repository_id.clone(),
            expected_generation: lease.roots().generation,
            expected_roots: lease.roots().clone(),
            actor: AuthorId::new("transfer-fixture"),
            reason: "publish additional refs out of advertised order".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: vec![
                RefMutation {
                    name: zulu.clone(),
                    expected: RefExpectation::MustNotExist,
                    new_target: Some(RefTarget::change(head)),
                    policy: RefUpdatePolicy::FastForwardOnly,
                },
                RefMutation {
                    name: alpha.clone(),
                    expected: RefExpectation::MustNotExist,
                    new_target: Some(RefTarget::change(head)),
                    policy: RefUpdatePolicy::FastForwardOnly,
                },
            ],
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        drop(lease);
        fixture
            .source
            .commit_repository_transaction(transaction)
            .unwrap();

        let advertised =
            repository_ref_advertisement(&fixture.source, &fixture.repository_id).unwrap();
        assert_eq!(advertised.refs.len(), 3);
        assert!(advertised
            .refs
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name));
        assert_eq!(advertised.refs.first().unwrap().name, alpha);
        assert_eq!(advertised.refs.last().unwrap().name, zulu);
        assert!(advertised
            .refs
            .iter()
            .all(|entry| entry.head == head || entry.name == fixture.main));
    }

    #[test]
    fn advertisement_rejects_a_repository_it_was_not_asked_for() {
        let fixture = fixture();
        let other = RepositoryId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        let error = repository_ref_advertisement(&fixture.source, &other).unwrap_err();
        assert!(error.to_string().contains("not requested repository"));
    }

    #[test]
    fn unborn_repository_advertises_a_default_ref_it_has_no_history_for() {
        let directory = TempDir::new().unwrap();
        let repository_id = RepositoryId::new(uuid::Uuid::new_v4().to_string()).unwrap();
        let authority = manager(&directory, &repository_id);
        let trunk = RefName::branch(b"trunk").unwrap();

        // Declare where history will land without landing any, which is the
        // state an empty repository is published in.
        let lease = authority.read_authority();
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: repository_id.clone(),
            expected_generation: lease.roots().generation,
            expected_roots: lease.roots().clone(),
            actor: AuthorId::new("transfer-fixture"),
            reason: "declare an unborn default ref".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: Some(DefaultRefMutation {
                expected: DefaultRefExpectation::MustBeUnset,
                new_default: Some(trunk.clone()),
            }),
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        drop(lease);
        authority
            .commit_repository_transaction(transaction)
            .unwrap();

        let advertised = repository_ref_advertisement(&authority, &repository_id).unwrap();

        // A clone of an empty repository has to reproduce exactly this: a
        // declared landing place with nothing in it. Treating the advertised
        // default as a ref that must resolve would make empty repositories
        // uncloneable.
        assert!(advertised.refs.is_empty());
        assert_eq!(advertised.default_ref, Some(trunk));
    }

    #[test]
    fn pack_identity_is_a_function_of_body_content_not_body_order() {
        let fixture = fixture();
        let status =
            repository_transfer_status(&fixture.destination, &fixture.repository_id, &fixture.main)
                .unwrap();
        let mut full = RepositoryTransferExpectation::try_from(status).unwrap();
        full.destination_target = None;
        full.destination_head = None;
        let pack = build_repository_transfer_pack(&fixture.source, &fixture.main, &full).unwrap();
        assert!(pack.bodies.len() >= 2);

        // The sender deduplicates bodies through an ordered set, so a pack it
        // builds is always ascending by body identity.
        assert!(pack
            .bodies
            .windows(2)
            .all(|pair| pair[0].hash < pair[1].hash));
        validate_pack(&pack, &RepositoryTransferLimits::default()).unwrap();

        // Reordering bodies preserves every byte of transferred content but
        // changes the serialized pack, and with it the recomputed transfer
        // identity. Accepting both spellings would let one transfer carry two
        // identities, so the receiver pins the canonical order instead.
        let mut permuted = pack.clone();
        permuted.bodies.reverse();
        permuted.transfer_id = compute_transfer_id(&permuted).unwrap();
        assert_ne!(permuted.transfer_id, pack.transfer_id);
        let error = validate_pack(&permuted, &RepositoryTransferLimits::default()).unwrap_err();
        assert!(
            error.to_string().contains("ascending"),
            "unexpected error: {error}"
        );

        let mut duplicate = pack.clone();
        duplicate.bodies.push(pack.bodies[0].clone());
        duplicate.transfer_id = compute_transfer_id(&duplicate).unwrap();
        let error = validate_pack(&duplicate, &RepositoryTransferLimits::default()).unwrap_err();
        assert!(error.to_string().contains("duplicate source body"));
    }

    #[test]
    fn transfer_identity_survives_metadata_map_reconstruction() {
        let fixture = fixture();

        // Entity metadata is intentionally extensible and therefore uses a
        // HashMap. Find two maps with the same values and observably different
        // iteration orders, as happens when a receiver deserializes a pack.
        let entries = (0..16)
            .map(|index| {
                (
                    format!("metadata_key_{index:02}"),
                    serde_json::json!({ "index": index, "stable": true }),
                )
            })
            .collect::<Vec<_>>();
        let first = entries.iter().cloned().collect::<HashMap<_, _>>();
        let first_bytes = serde_json::to_vec(&EntityMetadata {
            extra: first.clone(),
        })
        .unwrap();
        let second = (0..256)
            .map(|rotation| {
                entries
                    .iter()
                    .cycle()
                    .skip(rotation % entries.len())
                    .take(entries.len())
                    .cloned()
                    .collect::<HashMap<_, _>>()
            })
            .find(|candidate| {
                serde_json::to_vec(&EntityMetadata {
                    extra: candidate.clone(),
                })
                .unwrap()
                    != first_bytes
            })
            .expect("independent HashMaps expose a different JSON key order");
        assert_eq!(first, second);

        let first_pack = pack_with_metadata(&fixture.pack, first);
        let second_pack = pack_with_metadata(&fixture.pack, second);

        // The semantic change contract already canonicalizes metadata keys, so
        // both spellings declare one exact change and differ only in map order.
        assert_eq!(first_pack.changes[0].id, second_pack.changes[0].id);
        assert_ne!(
            serde_json::to_vec(&first_pack).unwrap(),
            serde_json::to_vec(&second_pack).unwrap(),
            "the control must exercise different raw pack bytes"
        );
        assert_eq!(
            first_pack.transfer_id, second_pack.transfer_id,
            "reconstructing an unordered metadata map must not change transfer identity"
        );

        let reconstructed: RepositoryTransferPack =
            serde_json::from_slice(&serde_json::to_vec(&first_pack).unwrap()).unwrap();
        validate_pack(&reconstructed, &RepositoryTransferLimits::default()).unwrap();
    }

    #[test]
    fn strict_pack_rejects_tampering_unknowns_missing_parents_and_duplicates() {
        let fixture = fixture();

        let mut body_tamper = fixture.pack.clone();
        body_tamper.bodies[0].bytes_base64 = BASE64.encode(b"tampered");
        body_tamper.bodies[0].byte_len = 8;
        body_tamper.transfer_id = compute_transfer_id(&body_tamper).unwrap();
        let error = validate_pack(&body_tamper, &RepositoryTransferLimits::default()).unwrap_err();
        assert!(error.to_string().contains("source body identity"));

        let mut tree_tamper = fixture.pack.clone();
        tree_tamper.trees[0].tree_hash = Hash256::from_bytes([0x44; 32]);
        tree_tamper.transfer_id = compute_transfer_id(&tree_tamper).unwrap();
        let error = apply_repository_transfer_pack(
            &fixture.destination,
            &fixture.repository_id,
            &fixture.main,
            AuthorId::new("authenticated-user"),
            &tree_tamper,
            &RepositoryTransferLimits::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("tree identity"));

        let status =
            repository_transfer_status(&fixture.destination, &fixture.repository_id, &fixture.main)
                .unwrap();
        let mut full_expectation = RepositoryTransferExpectation::try_from(status).unwrap();
        full_expectation.destination_target = None;
        full_expectation.destination_head = None;
        let mut missing_parent =
            build_repository_transfer_pack(&fixture.source, &fixture.main, &full_expectation)
                .unwrap();
        assert!(missing_parent.changes.len() >= 3);
        missing_parent.changes.remove(0);
        missing_parent.trees.remove(0);
        missing_parent.transfer_id = compute_transfer_id(&missing_parent).unwrap();
        let error =
            validate_pack(&missing_parent, &RepositoryTransferLimits::default()).unwrap_err();
        assert!(error.to_string().contains("before or without parent"));

        let mut duplicate = fixture.pack.clone();
        duplicate.changes.push(duplicate.changes[0].clone());
        duplicate.transfer_id = compute_transfer_id(&duplicate).unwrap();
        let error = validate_pack(&duplicate, &RepositoryTransferLimits::default()).unwrap_err();
        assert!(error.to_string().contains("duplicate semantic change"));

        let mut unknown_feature = fixture.pack.clone();
        unknown_feature
            .required_features
            .push("filesystem-fallback-v1".to_string());
        unknown_feature.transfer_id = compute_transfer_id(&unknown_feature).unwrap();
        let error =
            validate_pack(&unknown_feature, &RepositoryTransferLimits::default()).unwrap_err();
        assert!(error.to_string().contains("unknown required"));

        let mut unknown_field = serde_json::to_value(&fixture.pack).unwrap();
        unknown_field
            .as_object_mut()
            .unwrap()
            .insert("semanticChanges".to_string(), serde_json::json!([]));
        assert!(serde_json::from_value::<RepositoryTransferPack>(unknown_field).is_err());

        let mut unsupported_version = fixture.pack.clone();
        unsupported_version.schema_version += 1;
        let error =
            validate_pack(&unsupported_version, &RepositoryTransferLimits::default()).unwrap_err();
        assert!(error.to_string().contains("unsupported schema version"));

        let mut oversized = fixture.pack.clone();
        oversized.changes = (0..=MAX_TRANSFER_CHANGES)
            .map(|_| fixture.pack.changes[0].clone())
            .collect();
        let error = validate_pack(&oversized, &RepositoryTransferLimits::default()).unwrap_err();
        assert!(error.to_string().contains("exceeds limit"));
    }

    #[test]
    fn receiver_binds_repository_ref_actor_and_lease() {
        let fixture = fixture();
        let wrong_repository = RepositoryId::new("wrong-repository").unwrap();
        let error = apply_repository_transfer_pack(
            &fixture.destination,
            &wrong_repository,
            &fixture.main,
            AuthorId::new("authenticated-user"),
            &fixture.pack,
            &RepositoryTransferLimits::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not match receiver"));

        let wrong_ref = RefName::branch(b"other").unwrap();
        let error = apply_repository_transfer_pack(
            &fixture.destination,
            &fixture.repository_id,
            &wrong_ref,
            AuthorId::new("authenticated-user"),
            &fixture.pack,
            &RepositoryTransferLimits::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not match route ref"));

        let lease = fixture.destination.read_authority();
        let current_target = lease
            .authority_metadata()
            .ref_state
            .refs
            .iter()
            .find(|entry| entry.name == fixture.main)
            .unwrap()
            .target
            .clone();
        let current_head = lease.resolve_target_change_id(&current_target).unwrap();
        let concurrent_body = b"services:\n  api:\n    image: remote-only\n";
        let concurrent_hash = digest(concurrent_body);
        fixture
            .destination
            .save_source_blob(concurrent_hash, concurrent_body)
            .unwrap();
        let concurrent_change = native_change(
            vec![current_head],
            "advance destination after sender lease",
            vec![TreeDelta::Updated {
                artifact_id: ArtifactId(Uuid::from_u128(1)),
                old: LocatedEntry::new(
                    RepoPath::from_utf8("compose.yaml").unwrap(),
                    TreeEntry::blob(fixture.body_hashes[0], false),
                ),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("compose.yaml").unwrap(),
                    TreeEntry::blob(concurrent_hash, false),
                ),
            }],
        );
        let concurrent_transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(Uuid::from_u128(0xbeef)),
            repository_id: fixture.repository_id.clone(),
            expected_generation: lease.roots().generation,
            expected_roots: lease.roots().clone(),
            actor: AuthorId::new("concurrent-writer"),
            reason: "advance durable authority receipt generation".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: vec![concurrent_change.clone()],
            aliases: Vec::new(),
            ref_mutations: vec![RefMutation {
                name: fixture.main.clone(),
                expected: RefExpectation::MustEqual {
                    target: current_target.clone(),
                },
                new_target: Some(RefTarget::change(concurrent_change.id)),
                policy: RefUpdatePolicy::FastForwardOnly,
            }],
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        drop(lease);
        fixture
            .destination
            .commit_repository_transaction(concurrent_transaction)
            .unwrap();
        let error = apply_repository_transfer_pack(
            &fixture.destination,
            &fixture.repository_id,
            &fixture.main,
            AuthorId::new("authenticated-user"),
            &fixture.pack,
            &RepositoryTransferLimits::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("roots/generation moved"));
    }

    #[test]
    fn sender_rejects_non_fast_forward_and_missing_negotiated_features() {
        let fixture = fixture();
        let status =
            repository_transfer_status(&fixture.destination, &fixture.repository_id, &fixture.main)
                .unwrap();
        let mut non_fast_forward = RepositoryTransferExpectation::try_from(status).unwrap();
        let unrelated = SemanticChangeId::from_hash(Hash256::from_bytes([0xaa; 32]));
        non_fast_forward.destination_target = Some(RefTarget::change(unrelated));
        non_fast_forward.destination_head = Some(unrelated);
        let error =
            build_repository_transfer_pack(&fixture.source, &fixture.main, &non_fast_forward)
                .unwrap_err();
        assert!(error.to_string().contains("is not an ancestor"));

        non_fast_forward.destination_target = None;
        non_fast_forward.destination_head = None;
        non_fast_forward
            .supported_features
            .retain(|feature| feature != FEATURE_RAW_REPOSITORY_PATHS);
        let error =
            build_repository_transfer_pack(&fixture.source, &fixture.main, &non_fast_forward)
                .unwrap_err();
        assert!(error.to_string().contains(FEATURE_RAW_REPOSITORY_PATHS));
    }

    /// The pre-commit hook's whole reason to exist sits at one instruction
    /// boundary, so these four arms fix it there: it runs once, after the last
    /// refusal, before the commit, and never on a replay.
    mod admission_provenance_policy {
        use super::*;
        use std::cell::Cell;

        /// What the receiver could observe about its own authority before and
        /// after, so an arm can assert nothing moved without listing the fields
        /// at every call site.
        #[derive(Debug, PartialEq)]
        struct AuthorityShape {
            generation: u64,
            roots: RootBundle,
            default_ref: Option<RefName>,
            refs: Vec<(RefName, Option<RefTarget>)>,
            receipts: usize,
        }

        fn shape_of<B: StorageBackend + ?Sized + 'static>(
            authority: &RepositoryAuthorityManager<B>,
        ) -> AuthorityShape {
            let lease = authority.read_authority();
            let metadata = lease.authority_metadata();
            AuthorityShape {
                generation: lease.roots().generation,
                roots: lease.roots().clone(),
                default_ref: metadata.ref_state.default_ref.clone(),
                refs: metadata
                    .ref_state
                    .refs
                    .iter()
                    .map(|entry| (entry.name.clone(), Some(entry.target.clone())))
                    .collect(),
                receipts: metadata.receipts.len(),
            }
        }

        /// A policy failure must cost the receiver nothing. If the commit ran
        /// anyway, the receiver would hold transported history while its local
        /// record still described only its own creation, which is the exact
        /// false all-clear the hook exists to end.
        #[test]
        fn a_failing_policy_returns_its_error_and_moves_no_authority() {
            let fixture = fixture();
            let before = shape_of(&fixture.destination);

            let error = apply_repository_transfer_pack_with_pre_commit(
                &fixture.destination,
                &fixture.repository_id,
                &fixture.main,
                AuthorId::new("policy-test"),
                &fixture.pack,
                &RepositoryTransferLimits::default(),
                || Err(std::io::Error::other("sentinel policy refusal")),
            )
            .expect_err("a refused policy admitted the pack");

            assert!(
                matches!(error, RepositoryTransferError::Storage(_)),
                "a policy failure is a storage failure: {error:?}"
            );
            assert!(
                error.to_string().contains("sentinel policy refusal"),
                "the receiver's own refusal must survive to the caller: {error}"
            );
            assert_eq!(
                shape_of(&fixture.destination),
                before,
                "a refused policy still advanced authority"
            );
        }

        /// The ordering the crash table rests on: the policy runs before the
        /// generation moves, so any visible admitted history was preceded by a
        /// durable policy step.
        #[test]
        fn a_committed_pack_runs_the_policy_exactly_once_and_before_the_commit() {
            let fixture = fixture();
            let before = shape_of(&fixture.destination);
            let calls = Cell::new(0u32);
            let generation_at_policy = Cell::new(u64::MAX);

            let receipt = apply_repository_transfer_pack_with_pre_commit(
                &fixture.destination,
                &fixture.repository_id,
                &fixture.main,
                AuthorId::new("policy-test"),
                &fixture.pack,
                &RepositoryTransferLimits::default(),
                || {
                    calls.set(calls.get() + 1);
                    generation_at_policy
                        .set(fixture.destination.read_authority().roots().generation);
                    Ok(())
                },
            )
            .expect("a valid pack with a passing policy");

            assert_eq!(receipt.outcome, RepositoryTransferApplyOutcome::Committed);
            assert_eq!(calls.get(), 1, "the policy did not run exactly once");
            assert_eq!(
                generation_at_policy.get(),
                before.generation,
                "the policy observed an already-advanced generation, so it ran after the commit"
            );
            assert!(
                shape_of(&fixture.destination).generation > before.generation,
                "the commit did not advance authority"
            );
        }

        /// A pack this receiver refuses must not move local state either. The
        /// mirror of the arm above: running the policy early would degrade a
        /// perfectly good store over a transfer that never happened.
        #[test]
        fn a_refused_pack_never_runs_the_policy() {
            let fixture = fixture();
            let mut wrong_repository = fixture.pack.clone();
            wrong_repository.repository_id = RepositoryId::new("some-other-repository").unwrap();
            let calls = Cell::new(0u32);

            let error = apply_repository_transfer_pack_with_pre_commit(
                &fixture.destination,
                &fixture.repository_id,
                &fixture.main,
                AuthorId::new("policy-test"),
                &wrong_repository,
                &RepositoryTransferLimits::default(),
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            )
            .expect_err("a pack for another repository was admitted");

            assert!(
                matches!(error, RepositoryTransferError::Invalid(_)),
                "expected the identity refusal: {error:?}"
            );
            assert_eq!(calls.get(), 0, "the policy ran for a refused pack");
        }

        /// A replay moves nothing, so it must not re-run the policy. The
        /// original commit already ran it, and a second run would mutate local
        /// state for a transfer that changed no history.
        #[test]
        fn an_idempotent_replay_never_runs_the_policy() {
            let fixture = fixture();
            let calls = Cell::new(0u32);
            let receipt = apply_repository_transfer_pack_with_pre_commit(
                &fixture.destination,
                &fixture.repository_id,
                &fixture.main,
                AuthorId::new("policy-test"),
                &fixture.pack,
                &RepositoryTransferLimits::default(),
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            )
            .expect("the first admission");
            assert_eq!(receipt.outcome, RepositoryTransferApplyOutcome::Committed);
            assert_eq!(calls.get(), 1, "the first admission did not run the policy");

            let replay = apply_repository_transfer_pack_with_pre_commit(
                &fixture.destination,
                &fixture.repository_id,
                &fixture.main,
                AuthorId::new("policy-test"),
                &fixture.pack,
                &RepositoryTransferLimits::default(),
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            )
            .expect("the replay");

            assert_eq!(
                replay.outcome,
                RepositoryTransferApplyOutcome::IdempotentReplay
            );
            assert_eq!(calls.get(), 1, "the replay re-ran the policy");
        }
    }
}
