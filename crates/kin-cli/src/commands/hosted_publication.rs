// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Executable adapter for the first publication of a reserved hosted repository.
//!
//! An orchestrator that has reserved a repository identity needs a way to turn a
//! trusted materialized source into that repository's durable graph authority,
//! and to be told, in checkable values, exactly what it got. The library
//! primitive for the publication itself already exists
//! (`kin_remote::first_publication`). What did not exist is a transport to it:
//! no subcommand, no route, no tool. This module is that transport, and nothing
//! more.
//!
//! Four rules shape everything below.
//!
//! Measured state and echoed input never share a field. The evidence record has
//! a `measured` object, whose every value was read back out of destination
//! storage through a backend handle this process did not publish through, and an
//! `echoed` object, whose every value came from the manifest and was verified by
//! nothing here. An orchestrator assembling a receipt needs to know which is
//! which, and a record that blurs them is worse than one that omits them.
//!
//! Nothing here signs anything. The receipts a hosted control plane stores are
//! minted by a trusted signer holding a key this process must never see. This
//! adapter reports observations; turning an observation into an attestation is
//! somebody else's authority, deliberately.
//!
//! A lost response is not permission to overwrite. The intended snapshot, roots,
//! ref bindings and body closure are made durable before the compare-and-swap
//! that makes the publication permanent, and the recovery path compares what is
//! on the destination against that record. It agrees, or it is a conflict that
//! keeps the reserved identity and changes nothing. The recovery path contains
//! no write call at all, which is how that promise is kept rather than merely
//! stated.
//!
//! A ref is its target, not its name. Two imports can carry the same ref names
//! and the same `HEAD` while a second branch or an annotated tag points
//! somewhere else, so the manifest states an exact binding for every ref it
//! claims and those bindings are checked against the imported authority before
//! publication and against the fresh readback afterwards.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use kin_db::{
    GraphSnapshot, LocalFileBackend, PersistedRepositoryAuthority, RepositoryAuthorityManager,
    StorageBackend,
};
use kin_model::{
    AuthorityRoot, ExternalObjectKind, GitMaterialHead, GitObjectFormat, GitObjectId, Hash256,
    RefName, RefTarget, RepositoryId, RepositoryRef, RootBundle,
};
use kin_remote::first_publication::{
    publish_first_repository_observed, read_pinned_published_authority, FirstPublicationError,
    FirstPublicationIntent, FirstPublicationMode, SourceBodyClosure,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Exit status for a destination that holds no publication.
///
/// Distinct from every failure below it, because it is the one outcome a caller
/// may safely retry: nothing was installed, the reserved identity is untouched,
/// and a later attempt is the correct next move.
pub const EXIT_ABSENT: i32 = 3;

/// Exit status for a destination that holds a publication which is not the one
/// this operation intended. Never retryable and never resolved here: the
/// reserved identity is retained and a person decides.
pub const EXIT_CONFLICT: i32 = 4;

/// Exit status for a destination whose state could not be established either
/// way. Unknown is not absent, and the difference is most of the reason this
/// code exists, so it gets its own status rather than sharing one with either
/// neighbour.
pub const EXIT_INDETERMINATE: i32 = 5;

const MANIFEST_SCHEMA: &str = "kin.hosted-first-publication-manifest.v1";
const INTENT_SCHEMA: &str = "kin.hosted-first-publication-intent.v1";
const EVIDENCE_SCHEMA: &str = "kin.hosted-first-publication-evidence.v1";
const CLOSURE_ALGORITHM: &str = "kin.first-publication-body-closure.v1";
const ARTIFACT_ID_PREFIX: &str = "kin.first-publication.v1";

/// Domain separator for the canonical binding over a complete root bundle.
const AUTHORITY_ROOT_DOMAIN: &[u8] = b"kin.first-publication-authority-root.v1\0";

/// Ceiling on the composed artifact identifier.
///
/// A hosted control plane stores this as bounded text with a 256-byte limit, so
/// a long destination prefix has to be refused here, where the reason is
/// visible, rather than at a store that can only say the field was invalid.
const ARTIFACT_ID_MAX_BYTES: usize = 256;

/// Hops a symbolic ref may take before resolution gives up.
///
/// A symbolic target is resolvable state, not an error, so it is followed
/// rather than refused. A cycle or a chain this long is neither resolvable nor
/// worth guessing at.
const MAX_SYMBOLIC_HOPS: usize = 8;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Which boundary the reserved repository was created from.
///
/// Stated by the manifest rather than inferred from the source directory. The
/// publication primitive independently refuses a mode that disagrees with the
/// authority's own external-Git metadata, so a lie here fails loudly instead of
/// publishing the wrong shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicationMode {
    NativeEmpty,
    ExactGit,
}

impl PublicationMode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "native-empty" => Ok(Self::NativeEmpty),
            "exact-git" => Ok(Self::ExactGit),
            other => Err(anyhow!(
                "unknown publication mode {other:?}: expected native-empty or exact-git"
            )),
        }
    }

    fn as_primitive(self) -> FirstPublicationMode {
        match self {
            Self::NativeEmpty => FirstPublicationMode::Native,
            Self::ExactGit => FirstPublicationMode::GitImported,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::NativeEmpty => "native-empty",
            Self::ExactGit => "exact-git",
        }
    }
}

/// The operation this publication belongs to, carried through unchanged.
///
/// None of its meaning is verified here. Kin has no view of an orchestrator's
/// operation truth, and pretending otherwise would put a second, weaker copy of
/// that authority in this process. Its shape is another matter: every value
/// below is copied verbatim into a receipt that a hosted store decodes, so a
/// value this process accepts and that store refuses would fail at the far end
/// of a publication that had already happened. The grammars are therefore
/// checked here, where a refusal costs nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationBinding {
    pub org_id: String,
    pub operation_id: String,
    pub operation_revision: u64,
    pub request_hash: String,
    pub holder_id: String,
    pub fencing_token: u64,
}

impl OperationBinding {
    /// Whether two bindings name the same operation.
    ///
    /// Revision, holder and fencing token are excluded deliberately. A worker
    /// lease is renewable and a reclaimed operation gets a new holder and a new
    /// fence, so a resumption under a renewed lease legitimately carries a
    /// different revision for the same operation. Treating any of the three as
    /// part of the identity would turn every honest resumption into a conflict,
    /// which is the opposite of what a durable intent is for. What does not move
    /// is the org, the operation and the request digest the reservation was
    /// created from, so those are the identity.
    fn names_same_operation(&self, other: &Self) -> bool {
        let Self {
            org_id,
            operation_id,
            operation_revision: _,
            request_hash,
            holder_id: _,
            fencing_token: _,
        } = self;
        org_id == &other.org_id
            && operation_id == &other.operation_id
            && request_hash == &other.request_hash
    }

    fn validate(&self) -> Result<()> {
        require_segment(&self.org_id, "operation.org_id")?;
        require_segment(&self.holder_id, "operation.holder_id")?;
        require_uuid(&self.operation_id, "operation.operation_id")?;
        require_digest(&self.request_hash, "operation.request_hash")?;
        if self.operation_revision < 1 {
            bail!("operation.operation_revision must be at least 1");
        }
        if self.fencing_token < 1 {
            bail!("operation.fencing_token must be at least 1");
        }
        Ok(())
    }
}

/// A portable identifier: at most 128 characters of `[A-Za-z0-9_-]`, opening on
/// an alphanumeric.
///
/// Narrower than "bounded text without control characters", deliberately. A dot
/// or a colon would pass a looser check here and be refused at the store, after
/// the publication it describes had already landed.
fn require_segment(value: &str, label: &str) -> Result<()> {
    let mut characters = value.chars();
    let opens = characters
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric());
    let rest = characters.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !opens || !rest || value.len() > 128 {
        bail!(
            "{label} must open on an alphanumeric and carry only letters, digits, underscores              and hyphens, within 128 characters"
        );
    }
    Ok(())
}

/// A lowercase RFC 4122 UUID.
///
/// Lowercase rather than either case. A hosted store lowercases what it decodes
/// and then compares receipts to stored operations by exact string, so emitting
/// an uppercase value would produce a receipt that decodes and then fails to
/// bind, which is a much harder failure to read than this one.
fn require_uuid(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let shaped = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
        })
        && matches!(bytes[14], b'1'..=b'8')
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b');
    if !shaped {
        bail!("{label} must be a lowercase RFC 4122 UUID");
    }
    Ok(())
}

/// A canonical 256-bit digest as sixty-four lowercase hex characters.
fn require_digest(value: &str, label: &str) -> Result<()> {
    let shaped = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if !shaped {
        bail!("{label} must be a canonical 256-bit digest in lowercase hex");
    }
    Ok(())
}

/// Exactly where one ref points.
///
/// Rendered rather than reused from `kin_model::RefTarget`, whose derived
/// encoding writes a digest as a JSON array of thirty-two numbers. This is the
/// same information as hex, which is what the other side of this contract reads
/// and writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RefTargetRecord {
    /// A Kin semantic change, named directly.
    Change { change_id: String },
    /// A raw Git object, named by kind and object id. The object id keeps its
    /// format: a forty-character value is a SHA-1 identity and a
    /// sixty-four-character value is a SHA-256 one, and the two never compare
    /// equal.
    ExternalObject {
        object_kind: String,
        object_format: String,
        oid: String,
    },
    /// Another ref in the same repository.
    Symbolic { target: String },
}

impl RefTargetRecord {
    fn from_target(target: &RefTarget) -> Result<Self> {
        Ok(match target {
            RefTarget::Change { change_id } => Self::Change {
                change_id: change_id.to_string(),
            },
            RefTarget::ExternalObject { object } => Self::ExternalObject {
                object_kind: external_object_kind_name(object.kind).to_string(),
                object_format: match object.oid {
                    GitObjectId::Sha1(_) => "sha1".to_string(),
                    GitObjectId::Sha256(_) => "sha256".to_string(),
                },
                oid: object.oid.to_string(),
            },
            RefTarget::Symbolic { target } => Self::Symbolic {
                target: exact_ref_name(target)?,
            },
        })
    }
}

fn external_object_kind_name(kind: ExternalObjectKind) -> &'static str {
    match kind {
        ExternalObjectKind::Commit => "commit",
        ExternalObjectKind::Tree => "tree",
        ExternalObjectKind::Blob => "blob",
        ExternalObjectKind::Tag => "tag",
    }
}

/// One ref and the exact thing it points at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefBinding {
    pub name: String,
    pub target: RefTargetRecord,
}

/// How completely a set of ref bindings describes the imported authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefScope {
    /// The bindings are the whole ref set. Any extra ref is a refusal.
    Complete,
    /// The bindings must each be present and exact. Other refs may exist.
    ///
    /// This is what an import of a narrower scope than the provider's current
    /// state records, so a partial import is never described as a full mirror.
    NamedSubset,
}

/// The exact refs an import claims, and how completely it claims them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedRefs {
    pub scope: RefScope,
    pub bindings: Vec<RefBinding>,
}

/// What the source must be, as distinct from where it currently is.
///
/// A filesystem path is machine-local, so it is a command-line argument rather
/// than a manifest field: a manifest recovered onto a different host would
/// otherwise name a path that does not exist there, or one that does and holds
/// something else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SourceSpec {
    NativeEmpty {
        default_branch: String,
    },
    ExactGit {
        provider: String,
        object_format: String,
        source_commit_oid: String,
        default_branch: String,
        expected_refs: ExpectedRefs,
    },
}

impl SourceSpec {
    fn mode(&self) -> PublicationMode {
        match self {
            Self::NativeEmpty { .. } => PublicationMode::NativeEmpty,
            Self::ExactGit { .. } => PublicationMode::ExactGit,
        }
    }

    fn default_branch(&self) -> &str {
        match self {
            Self::NativeEmpty { default_branch } | Self::ExactGit { default_branch, .. } => {
                default_branch
            }
        }
    }
}

/// Where the published authority is to live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DestinationSpec {
    Filesystem { root: PathBuf },
    Gcs { bucket: String, prefix: String },
}

impl DestinationSpec {
    /// Open a backend for this destination.
    ///
    /// Called more than once per run on purpose. The measurement pass builds its
    /// own handle rather than reusing the one the publication went through, so a
    /// backend answering from a cache it populated while writing cannot satisfy
    /// the readback.
    fn open(&self) -> Result<Arc<dyn StorageBackend>> {
        match self {
            Self::Filesystem { root } => {
                if !root.is_absolute() {
                    bail!(
                        "destination root must be an absolute path, got {}",
                        root.display()
                    );
                }
                fs::create_dir_all(root)
                    .with_context(|| format!("create destination root {}", root.display()))?;
                Ok(Arc::new(LocalFileBackend::new(root.clone())))
            }
            Self::Gcs { .. } => bail!(
                "destination_backend_unavailable: this build publishes to a filesystem \
                 destination only, and hosted object-store publication is a separate acceptance"
            ),
        }
    }

    fn scope(&self) -> String {
        match self {
            Self::Filesystem { root } => format!("fs:{}", root.display()),
            Self::Gcs { bucket, prefix } => format!("gcs:{bucket}/{prefix}"),
        }
    }
}

/// One authority root, rendered as hex rather than as a byte array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRootRecord {
    pub version: u32,
    pub hash: String,
}

impl From<&AuthorityRoot> for AuthorityRootRecord {
    fn from(root: &AuthorityRoot) -> Self {
        Self {
            version: root.version,
            hash: root.hash.to_string(),
        }
    }
}

/// A complete root bundle, losslessly, in a shape another language can read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootBundleRecord {
    pub version: u32,
    pub generation: u64,
    pub history: AuthorityRootRecord,
    pub ref_state: AuthorityRootRecord,
    pub ref_log: AuthorityRootRecord,
    pub collaboration: AuthorityRootRecord,
    pub replication: AuthorityRootRecord,
    pub local_state: AuthorityRootRecord,
}

impl From<&RootBundle> for RootBundleRecord {
    fn from(bundle: &RootBundle) -> Self {
        // Destructured rather than read field by field on purpose. Both this
        // record and the binding digest beneath enumerate the roots by hand, so
        // a seventh root added upstream has to break this build. Read field by
        // field it would be dropped silently by both, and the digest would not
        // change to say so.
        let RootBundle {
            version,
            generation,
            history,
            ref_state,
            ref_log,
            collaboration,
            replication,
            local_state,
        } = bundle;
        Self {
            version: *version,
            generation: *generation,
            history: history.into(),
            ref_state: ref_state.into(),
            ref_log: ref_log.into(),
            collaboration: collaboration.into(),
            replication: replication.into(),
            local_state: local_state.into(),
        }
    }
}

/// One canonical digest over a complete root bundle.
///
/// A hosted receipt carries a single authority-root field, and a Kin root bundle
/// is a version, a generation and six separate roots. Sending one of the six
/// would silently drop the other five, so this binds all of them, in the order
/// they are declared upstream, domain-separated and length-fixed. The whole
/// bundle also ships beside this value, so the digest stays checkable rather
/// than merely trusted.
fn authority_root_binding(bundle: &RootBundle) -> Hash256 {
    let RootBundle {
        version,
        generation,
        history,
        ref_state,
        ref_log,
        collaboration,
        replication,
        local_state,
    } = bundle;
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_ROOT_DOMAIN);
    hasher.update(version.to_le_bytes());
    hasher.update(generation.to_le_bytes());
    for root in [
        history,
        ref_state,
        ref_log,
        collaboration,
        replication,
        local_state,
    ] {
        hasher.update(root.version.to_le_bytes());
        hasher.update(root.hash.as_bytes());
    }
    Hash256::from_bytes(hasher.finalize().into())
}

/// The referenced source-body closure, as three checkable numbers and a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureRecord {
    pub algorithm: String,
    pub digest: String,
    pub body_count: u64,
    pub total_bytes: u64,
}

impl From<&SourceBodyClosure> for ClosureRecord {
    fn from(closure: &SourceBodyClosure) -> Self {
        Self {
            algorithm: CLOSURE_ALGORITHM.to_string(),
            digest: closure.digest().to_string(),
            body_count: closure.body_count(),
            total_bytes: closure.total_bytes(),
        }
    }
}

/// The operation-bound input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub operation: OperationBinding,
    pub repository_id: String,
    pub source: SourceSpec,
    /// The orchestrator's own canonical digest over its source record.
    ///
    /// Carried, never recomputed. Reproducing another system's canonical JSON
    /// encoder here would put the definition of this value in two languages, and
    /// the day they disagree is the day a correct publication is refused for a
    /// reason nobody can see. It lands in the echoed half of the evidence, where
    /// it cannot be mistaken for something this process checked.
    pub source_input_hash: String,
    pub destination: DestinationSpec,
    /// The exact authority this run expects to find, or `None` for a first
    /// attempt, which expects to find nothing at all.
    pub expected_authority: Option<IntentRecord>,
}

/// What is about to be published, made durable before it becomes permanent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentRecord {
    pub schema: String,
    pub repository_id: String,
    pub operation: OperationBinding,
    pub mode: PublicationMode,
    pub intended_snapshot_sha256: String,
    pub intended_roots: RootBundleRecord,
    pub intended_source_closure: ClosureRecord,
    pub intended_default_branch: String,
    pub intended_head_change_id: Option<String>,
    pub intended_ref_bindings: Vec<RefBinding>,
    pub destination: DestinationSpec,
    pub written_at: String,
}

impl IntentRecord {
    /// Whether two intents describe the same publication.
    ///
    /// `written_at` is excluded deliberately. A second attempt at the same
    /// publication writes a new timestamp and is still the same intent, and
    /// making the clock part of the identity would turn every honest retry into
    /// a conflict. Both sides are destructured so that a field added later has
    /// to be classified here rather than silently ignored.
    fn describes_same_publication(&self, other: &Self) -> bool {
        let Self {
            schema,
            repository_id,
            operation,
            mode,
            intended_snapshot_sha256,
            intended_roots,
            intended_source_closure,
            intended_default_branch,
            intended_head_change_id,
            intended_ref_bindings,
            destination,
            written_at: _,
        } = self;
        let Self {
            schema: other_schema,
            repository_id: other_repository_id,
            operation: other_operation,
            mode: other_mode,
            intended_snapshot_sha256: other_snapshot,
            intended_roots: other_roots,
            intended_source_closure: other_closure,
            intended_default_branch: other_branch,
            intended_head_change_id: other_head,
            intended_ref_bindings: other_bindings,
            destination: other_destination,
            written_at: _,
        } = other;
        schema == other_schema
            && repository_id == other_repository_id
            && operation.names_same_operation(other_operation)
            && mode == other_mode
            && intended_snapshot_sha256 == other_snapshot
            && intended_roots == other_roots
            && intended_source_closure == other_closure
            && intended_default_branch == other_branch
            && intended_head_change_id == other_head
            && intended_ref_bindings == other_bindings
            && destination == other_destination
    }
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// This run installed the publication.
    Published,
    /// The publication was already there and is exactly the intended one.
    Recovered,
    /// The destination holds no publication.
    Absent,
    /// The destination holds a publication that is not the intended one.
    Conflict,
    /// The destination's state could not be established either way.
    Indeterminate,
}

impl Outcome {
    fn exit_code(self) -> i32 {
        match self {
            // A recovery is a success the caller proceeds from, so it shares an
            // exit status with a fresh publication and the record's own outcome
            // field is what tells them apart. A distinct non-zero status would
            // abort an ordinary shell runner on a correct result.
            Self::Published | Self::Recovered => 0,
            Self::Absent => EXIT_ABSENT,
            Self::Conflict => EXIT_CONFLICT,
            Self::Indeterminate => EXIT_INDETERMINATE,
        }
    }
}

/// Where a reported digest came from, stated rather than assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotDigestSource {
    /// The publication primitive's own digest over the bytes it installed.
    Receipt,
    /// The durable intent written before the compare-and-swap.
    Intent,
}

/// Everything this process read back out of destination storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredAuthority {
    pub artifact_id: String,
    /// Digest over the bytes a fresh handle read back from the destination.
    pub artifact_sha256: String,
    /// The publisher's digest over the bytes it meant to install.
    pub snapshot_sha256: String,
    pub snapshot_sha256_source: SnapshotDigestSource,
    pub storage_generation: String,
    pub authority_root_binding: String,
    pub roots: RootBundleRecord,
    pub source_closure: ClosureRecord,
    pub mode: PublicationMode,
    pub git_external_authority_present: bool,
    pub default_branch: String,
    pub head_change_id: Option<String>,
    pub ref_bindings: Vec<RefBinding>,
    pub observed_at: String,
}

/// Everything carried in from the manifest and checked by nothing here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EchoedInput {
    pub source_input_hash: String,
    pub requested_default_branch: String,
    pub expected_refs: Option<ExpectedRefs>,
}

/// One field on which the destination disagreed with the intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Difference {
    pub field: String,
    pub intended: String,
    pub observed: String,
}

/// The record a trusted signer reads to build a preparation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub schema: String,
    pub outcome: Outcome,
    pub repository_id: String,
    pub operation: OperationBinding,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub measured: Option<MeasuredAuthority>,
    pub echoed: EchoedInput,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub differences: Vec<Difference>,
    /// Why a run without measured authority ended the way it did, verbatim.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<String>,
}

// ---------------------------------------------------------------------------
// Reading the authority
// ---------------------------------------------------------------------------

/// A ref name as exact UTF-8, or a refusal.
///
/// Kin ref names are bytes, and a hosted contract carries them as strings. A
/// name that is not UTF-8 is refused rather than rendered lossily, because a
/// lossy name would compare unequal to itself on the next read and would be
/// impossible to act on.
fn exact_ref_name(name: &RefName) -> Result<String> {
    name.as_utf8().map(str::to_string).ok_or_else(|| {
        anyhow!(
            "ref name is not exact UTF-8 and cannot be carried in a hosted binding: {}",
            hex::encode(name.as_bytes())
        )
    })
}

/// The short branch name behind a default ref, or a refusal.
fn default_branch_name(name: &RefName) -> Result<String> {
    if !name.is_branch() {
        bail!(
            "default ref {} is not a branch, so it names no default branch",
            exact_ref_name(name).unwrap_or_else(|_| hex::encode(name.as_bytes()))
        );
    }
    let exact = exact_ref_name(name)?;
    exact
        .strip_prefix("refs/heads/")
        .map(str::to_string)
        .ok_or_else(|| anyhow!("branch ref {exact} does not carry the refs/heads/ prefix"))
}

/// Every ref the published authority holds, with its exact target.
fn measure_ref_bindings(metadata: &PersistedRepositoryAuthority) -> Result<Vec<RefBinding>> {
    let mut bindings = Vec::with_capacity(metadata.ref_state.refs.len());
    for repository_ref in &metadata.ref_state.refs {
        bindings.push(RefBinding {
            name: exact_ref_name(&repository_ref.name)?,
            target: RefTargetRecord::from_target(&repository_ref.target)?,
        });
    }
    bindings.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(bindings)
}

/// The semantic change the default ref resolves to, or `None` when unborn.
///
/// An imported Git ref points at a raw external object rather than at a change,
/// so the graph's own external-change aliases are what resolve it. `GitObjectId`
/// carries its object format in its own identity, so a SHA-1 object id can never
/// match a SHA-256 alias and nothing here casts one identity into the other. A
/// target with no alias, or one that somehow carries more than one, is refused
/// rather than guessed at. A default ref with no entry at all is unborn, which
/// repository ref state permits and which a native empty repository always is.
fn resolve_head_change_id(
    metadata: &PersistedRepositoryAuthority,
    repository_id: &RepositoryId,
) -> Result<Option<String>> {
    let Some(default_ref) = metadata.ref_state.default_ref.as_ref() else {
        return Ok(None);
    };
    let mut name = default_ref.clone();
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    for _ in 0..MAX_SYMBOLIC_HOPS {
        if !seen.insert(name.as_bytes().to_vec()) {
            bail!(
                "default ref {} resolves through a symbolic cycle",
                exact_ref_name(&name).unwrap_or_else(|_| hex::encode(name.as_bytes()))
            );
        }
        let Some(found) = find_ref(&metadata.ref_state.refs, &name) else {
            // Unborn. The ref state's own contract allows a default ref whose
            // target does not exist yet, and a repository created empty is
            // exactly that.
            return Ok(None);
        };
        match &found.target {
            RefTarget::Change { change_id } => return Ok(Some(change_id.to_string())),
            RefTarget::ExternalObject { object } => {
                let mut matches = metadata.aliases.iter().filter(|alias| {
                    alias.oid == object.oid && &alias.repository_id == repository_id
                });
                let Some(alias) = matches.next() else {
                    bail!(
                        "default ref target {} has no semantic change alias in the published \
                         authority, so its head cannot be named",
                        object.oid
                    );
                };
                if matches.next().is_some() {
                    bail!(
                        "default ref target {} carries more than one semantic change alias",
                        object.oid
                    );
                }
                return Ok(Some(alias.change_id.to_string()));
            }
            RefTarget::Symbolic { target } => name = target.clone(),
        }
    }
    bail!(
        "default ref {} did not resolve within {MAX_SYMBOLIC_HOPS} symbolic hops",
        exact_ref_name(default_ref).unwrap_or_else(|_| hex::encode(default_ref.as_bytes()))
    )
}

fn find_ref<'a>(refs: &'a [RepositoryRef], name: &RefName) -> Option<&'a RepositoryRef> {
    refs.iter().find(|candidate| &candidate.name == name)
}

/// Check measured ref bindings against the exact set an import claimed.
fn verify_expected_refs(expected: &ExpectedRefs, measured: &[RefBinding]) -> Result<()> {
    let observed: BTreeMap<&str, &RefTargetRecord> = measured
        .iter()
        .map(|binding| (binding.name.as_str(), &binding.target))
        .collect();
    for binding in &expected.bindings {
        let Some(target) = observed.get(binding.name.as_str()) else {
            bail!(
                "expected ref {} is not present in the imported authority",
                binding.name
            );
        };
        if *target != &binding.target {
            bail!(
                "expected ref {} points at {:?} rather than the claimed {:?}",
                binding.name,
                target,
                binding.target
            );
        }
    }
    if expected.scope == RefScope::Complete {
        let claimed: BTreeSet<&str> = expected
            .bindings
            .iter()
            .map(|binding| binding.name.as_str())
            .collect();
        let extra: Vec<&str> = observed
            .keys()
            .copied()
            .filter(|name| !claimed.contains(name))
            .collect();
        if !extra.is_empty() {
            bail!(
                "import claims a complete ref scope but the authority also holds {}",
                extra.join(", ")
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Durable files
// ---------------------------------------------------------------------------

/// Read one JSON document, refusing a symlink at the path.
///
/// A path an orchestrator supplies is not automatically a regular file, and
/// following a link here would let whoever can create one decide what this
/// process reads.
fn read_json<T: serde::de::DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("read {label} at {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("{label} path is a symlink: {}", path.display());
    }
    let bytes = fs::read(path).with_context(|| format!("read {label} at {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {label} at {}", path.display()))
}

/// Install one JSON document so that a later read sees all of it or none of it.
///
/// Written to a private temporary beside the target, flushed, then renamed. The
/// containing directory is flushed too on Unix, because a rename that the
/// directory entry has not recorded is not durable; `File::open` on a directory
/// is not available on Windows, and the guarantee this function offers there is
/// the file's own flush plus an atomic rename.
fn write_json_atomically(path: &Path, value: &impl Serialize, label: &str) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("{label} path {} has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create {label} directory {}", parent.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("{label} path {} names no file", path.display()))?;
    // Named by this process, because a shared scratch name is a race with every
    // other publication running on the same box.
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut bytes = serde_json::to_vec_pretty(value)
        .with_context(|| format!("encode {label} for {}", path.display()))?;
    bytes.push(b'\n');
    {
        // `create_new` refuses anything already at the temporary path,
        // including a symlink, so nothing this writes can be redirected.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("create {label} temporary {}", temporary.display()))?;
        file.write_all(&bytes)
            .with_context(|| format!("write {label} temporary {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("flush {label} temporary {}", temporary.display()))?;
    }
    fs::rename(&temporary, path).with_context(|| {
        format!(
            "install {label} {} from {}",
            path.display(),
            temporary.display()
        )
    })?;
    #[cfg(unix)]
    {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("flush {label} directory {}", parent.display()))?;
    }
    Ok(())
}

/// Distinguishes one staging file from every other in this process.
static STAGING_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Install one JSON document only if nothing is at the path, atomically.
///
/// Returns whether this call is the one that installed it.
///
/// The install is a `link`, not a `rename`, and the difference is the whole
/// point. A rename replaces whatever is at the destination, so checking for
/// absence and then renaming leaves a window in which another writer's document
/// is installed and then destroyed by this one. `link` fails when the
/// destination exists, so the check and the install are the same operation and
/// there is no window to lose. A symlink at the destination is a directory entry
/// like any other, so it makes this fail too rather than being followed.
pub fn install_no_replace(path: &Path, bytes: &[u8], label: &str) -> Result<bool> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("{label} path {} has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create {label} directory {}", parent.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("{label} path {} names no file", path.display()))?;
    // Named by this process AND by a per-call sequence. The process id alone
    // was not enough and the concurrent test is what said so: two callers inside
    // one process shared a staging name, so one deleted the other's staged file
    // and the link that followed had nothing to install. A live peer can never
    // hold this name, because no two live processes share a pid and no two calls
    // in this one share a sequence number, which is what makes the pre-emptive
    // remove below safe: the only file it can ever delete is a stale one this
    // caller's own name was left on.
    let staged = parent.join(format!(
        ".{}.staged-{}-{}",
        file_name.to_string_lossy(),
        std::process::id(),
        STAGING_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = fs::remove_file(&staged);
    let install = (|| -> Result<bool> {
        {
            // `create_new` refuses anything already at the staged path,
            // including a symlink, so nothing written here can be redirected.
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staged)
                .with_context(|| format!("create {label} staging file {}", staged.display()))?;
            file.write_all(bytes)
                .with_context(|| format!("write {label} staging file {}", staged.display()))?;
            file.sync_all()
                .with_context(|| format!("flush {label} staging file {}", staged.display()))?;
        }
        match fs::hard_link(&staged, path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => {
                Err(error).with_context(|| format!("install {label} at {}", path.display()))
            }
        }
    })();
    let _ = fs::remove_file(&staged);
    let installed = install?;
    if installed {
        #[cfg(unix)]
        {
            // A link the directory entry has not recorded is not durable.
            // `File::open` on a directory is unavailable on Windows, where the
            // guarantee is the file's own flush plus the atomic link.
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .with_context(|| format!("flush {label} directory {}", parent.display()))?;
        }
    }
    Ok(installed)
}

/// Make the intended publication durable, never replacing a different one.
///
/// The install itself is what refuses: it cannot overwrite, so a document that
/// is already there was put there by somebody, and this reads it back to decide
/// who. This same publication means the file is already durable and there is
/// nothing left to do. A different one means another attempt or another writer
/// got here first, and its record is the only evidence that could ever resolve
/// that attempt, so this run stops rather than destroying it.
fn write_intent_durably(path: &Path, record: &IntentRecord) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(record).context("encode the durable intent")?;
    bytes.push(b'\n');
    if install_no_replace(path, &bytes, "intent")? {
        return Ok(());
    }
    let existing: IntentRecord = read_json(path, "existing intent")?;
    if existing.describes_same_publication(record) {
        return Ok(());
    }
    bail!(
        "intent path {} already records a different publication, which this run will not replace",
        path.display()
    )
}

fn now_utc() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

// ---------------------------------------------------------------------------
// The source
// ---------------------------------------------------------------------------

/// Open the reserved repository's source authority, initializing it once.
///
/// A store that already exists is reused rather than rebuilt. Running init a
/// second time after a crash can mint different workspace and initialization
/// metadata under the same repository identity, and a recovery comparing that
/// fresh candidate against the durable intent would call the difference a
/// conflict when nothing was actually wrong.
fn open_or_initialize_source(
    source_dir: &Path,
    repository_id: &RepositoryId,
    spec: &SourceSpec,
) -> Result<Arc<RepositoryAuthorityManager<dyn StorageBackend>>> {
    let kin_dir = source_dir.join(".kin");
    let already_initialized = match fs::symlink_metadata(&kin_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("source store marker is a symlink: {}", kin_dir.display())
        }
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error).with_context(|| format!("inspect source {}", kin_dir.display()))
        }
    };
    let kindb_dir = if already_initialized {
        kin_core::KinLayout::new(kin_dir).kindb_dir()
    } else {
        let result = match spec {
            SourceSpec::NativeEmpty { default_branch } => {
                fs::create_dir_all(source_dir).with_context(|| {
                    format!("create native source directory {}", source_dir.display())
                })?;
                kin_core::init_replica_adopting(source_dir, default_branch, repository_id)
                    .with_context(|| {
                        format!(
                            "initialize an unborn native authority on {default_branch} adopting \
                             {repository_id}"
                        )
                    })?
            }
            SourceSpec::ExactGit { .. } => {
                kin_core::init_from_git_adopting(source_dir, repository_id).with_context(|| {
                    format!("admit exact Git repository authority adopting {repository_id}")
                })?
            }
        };
        result.layout.kindb_dir()
    };
    let backend: Arc<dyn StorageBackend> = Arc::new(LocalFileBackend::new(kindb_dir));
    Ok(Arc::new(
        RepositoryAuthorityManager::open(repository_id.clone(), backend)
            .with_context(|| format!("open the source authority for {repository_id}"))?,
    ))
}

/// Check the source authority against everything the manifest claims about it.
///
/// Kin does not re-authorize the source; that boundary belongs to whoever
/// materialized it. What this does is refuse to publish a source that is not the
/// one the manifest describes, reading the claim off graph-owned authority
/// rather than off the working directory.
fn verify_source_authority(
    metadata: &PersistedRepositoryAuthority,
    snapshot: &GraphSnapshot,
    repository_id: &RepositoryId,
    spec: &SourceSpec,
) -> Result<Vec<RefBinding>> {
    if &metadata.repository_id != repository_id {
        bail!(
            "source authority owns {} rather than the reserved {repository_id}",
            metadata.repository_id
        );
    }
    // Ahead of the mode match on purpose. "This source is not unborn" is a fact
    // about the request's own claim, and absent Git metadata is only evidence
    // that a store was not imported, never that it is empty. An existing store
    // is reused rather than rebuilt, so without this a committed native
    // repository would publish under a reservation that promised an empty one.
    if matches!(spec, SourceSpec::NativeEmpty { .. }) {
        if !snapshot.entities.is_empty() {
            bail!(
                "a native-empty publication requires an unborn source, and this one already \
                 holds {} entities",
                snapshot.entities.len()
            );
        }
        if !snapshot.changes.is_empty() {
            bail!(
                "a native-empty publication requires an unborn source, and this one already \
                 holds {} semantic changes",
                snapshot.changes.len()
            );
        }
        if !metadata.ref_state.refs.is_empty() {
            bail!(
                "a native-empty publication requires an unborn source, and this one already \
                 holds {} refs",
                metadata.ref_state.refs.len()
            );
        }
    }
    let git = metadata.git_external_authority.as_ref();
    match (spec, git) {
        (SourceSpec::NativeEmpty { .. }, Some(_)) => {
            bail!("a native-empty publication cannot be built from an imported Git authority")
        }
        (SourceSpec::ExactGit { .. }, None) => {
            bail!("an exact-Git publication requires an imported Git authority")
        }
        (SourceSpec::NativeEmpty { .. }, None) => {}
        (
            SourceSpec::ExactGit {
                provider,
                object_format,
                source_commit_oid,
                ..
            },
            Some(git),
        ) => {
            if provider != "github" {
                bail!("unsupported exact-Git provider {provider:?}");
            }
            let imported_format = match git.object_format {
                GitObjectFormat::Sha1 => "sha1",
                GitObjectFormat::Sha256 => "sha256",
            };
            if imported_format != object_format {
                bail!(
                    "imported Git authority uses {imported_format} object identity rather than \
                     the claimed {object_format}"
                );
            }
            match &git.material_head {
                GitMaterialHead::Commit { commit_oid, .. } => {
                    let observed = commit_oid.to_string();
                    if &observed != source_commit_oid {
                        bail!(
                            "imported Git authority resolves HEAD to {observed} rather than the \
                             claimed {source_commit_oid}"
                        );
                    }
                }
                GitMaterialHead::Unborn { .. } => {
                    bail!("imported Git authority has an unborn HEAD and names no source commit")
                }
                GitMaterialHead::NonMaterializable { .. } => {
                    bail!("imported Git HEAD cannot seed a workspace, so it names no source commit")
                }
            }
        }
    }
    let Some(default_ref) = metadata.ref_state.default_ref.as_ref() else {
        bail!("source authority carries no default ref and cannot be published");
    };
    let observed_branch = default_branch_name(default_ref)?;
    if observed_branch != spec.default_branch() {
        bail!(
            "source authority defaults to {observed_branch} rather than the requested {}",
            spec.default_branch()
        );
    }
    let bindings = measure_ref_bindings(metadata)?;
    if let SourceSpec::ExactGit { expected_refs, .. } = spec {
        verify_expected_refs(expected_refs, &bindings)
            .context("imported refs do not match the exact bindings this import claims")?;
    }
    Ok(bindings)
}

// ---------------------------------------------------------------------------
// Measuring the destination
// ---------------------------------------------------------------------------

/// What a fresh look at the destination found.
enum DestinationReading {
    /// Nothing is published under this identity.
    Absent,
    /// The destination could not be read either way.
    Indeterminate(String),
    /// A publication is there, measured through a handle that never wrote.
    Present(Box<MeasuredAuthority>),
}

/// Read the published authority back through a handle that never wrote to it.
///
/// The publication primitive already compares what it installed against what it
/// reads back, but it does so through the handle it published through. This
/// opens a new one from the destination specification, so a backend that would
/// answer from state it cached while writing cannot satisfy this readback.
fn measure_destination(
    destination: &DestinationSpec,
    repository_id: &RepositoryId,
    mode: PublicationMode,
    snapshot_sha256: String,
    snapshot_sha256_source: SnapshotDigestSource,
) -> Result<DestinationReading> {
    let backend = destination.open()?;
    match backend.load_snapshot_cursor(repository_id.as_str()) {
        Ok(None) => return Ok(DestinationReading::Absent),
        Ok(Some(_)) => {}
        // An inspection failure is not an absence. Reporting it as one is the
        // exact mistake that turns an unknown storage state into a second
        // publication under the same reserved identity.
        Err(error) => return Ok(DestinationReading::Indeterminate(error.to_string())),
    }
    // ONE read. Everything below is derived from exactly these bytes, because
    // three separate selections are three separate authorities: the backend
    // releases its lock on each read, and an opened manager recovers over
    // acknowledged journal frames while a snapshot load returns only the base.
    // A writer advancing the destination between them would otherwise produce a
    // reading whose digest belongs to one authority and whose roots and refs
    // belong to another, with every field of it looking measured.
    let (bytes, generation) = match backend.load_snapshot(repository_id.as_str()) {
        Ok(Some(found)) => found,
        Ok(None) => {
            return Ok(DestinationReading::Indeterminate(
                "destination reported a publication cursor and then no snapshot".to_string(),
            ))
        }
        Err(error) => return Ok(DestinationReading::Indeterminate(error.to_string())),
    };
    let pinned = Arc::new(bytes);
    let artifact_sha256 = Hash256::from_bytes(Sha256::digest(pinned.as_slice()).into()).to_string();
    let reading = read_pinned_published_authority(repository_id, backend, pinned)
        .with_context(|| format!("read the published authority for {repository_id}"))?;
    let metadata = &reading.authority;
    if &metadata.repository_id != repository_id {
        bail!(
            "published authority owns {} rather than the reserved {repository_id}",
            metadata.repository_id
        );
    }
    let roots = reading.roots.clone();
    let default_ref = metadata
        .ref_state
        .default_ref
        .as_ref()
        .ok_or_else(|| anyhow!("published authority carries no default ref"))?;
    let default_branch = default_branch_name(default_ref)?;
    let head_change_id = resolve_head_change_id(metadata, repository_id)?;
    let ref_bindings = measure_ref_bindings(metadata)?;
    let git_external_authority_present = metadata.git_external_authority.is_some();
    let closure = reading.source_closure;
    let artifact_id = compose_artifact_id(destination, repository_id, generation)?;
    Ok(DestinationReading::Present(Box::new(MeasuredAuthority {
        artifact_id,
        artifact_sha256,
        snapshot_sha256,
        snapshot_sha256_source,
        storage_generation: generation.to_string(),
        authority_root_binding: authority_root_binding(&roots).to_string(),
        roots: RootBundleRecord::from(&roots),
        source_closure: ClosureRecord::from(&closure),
        mode,
        git_external_authority_present,
        default_branch,
        head_change_id,
        ref_bindings,
        observed_at: now_utc(),
    })))
}

/// Name the exact durable object the authority landed in.
///
/// Composed rather than reconstructed by a reader from three other fields, and
/// refused here when it would exceed what a hosted store accepts, so the reason
/// is visible in this process rather than as an invalid field at the store.
fn compose_artifact_id(
    destination: &DestinationSpec,
    repository_id: &RepositoryId,
    generation: u64,
) -> Result<String> {
    let artifact_id = format!(
        "{ARTIFACT_ID_PREFIX}:{}/{repository_id}@{generation}",
        destination.scope()
    );
    // A hosted store trims what it stores here, so a value with surrounding
    // whitespace would be silently normalized into something that is no longer
    // the identifier this process reported. Control characters it refuses
    // outright. Both are refused here instead, where the destination that
    // produced them can be named.
    if artifact_id != artifact_id.trim() {
        bail!("composed artifact identifier carries surrounding whitespace: {artifact_id:?}");
    }
    if artifact_id.chars().any(char::is_control) {
        bail!("composed artifact identifier carries a control character");
    }
    if artifact_id.len() > ARTIFACT_ID_MAX_BYTES {
        bail!(
            "composed artifact identifier is {} bytes, over the {ARTIFACT_ID_MAX_BYTES} a hosted \
             record accepts; shorten the destination scope",
            artifact_id.len()
        );
    }
    Ok(artifact_id)
}

/// Every way the destination can disagree with what was intended.
///
/// Named field by field rather than as one equality, because a caller resolving
/// a conflict needs to know which value moved.
fn compare_with_intent(intent: &IntentRecord, measured: &MeasuredAuthority) -> Vec<Difference> {
    let mut differences = Vec::new();
    let mut note = |field: &str, intended: String, observed: String| {
        if intended != observed {
            differences.push(Difference {
                field: field.to_string(),
                intended,
                observed,
            });
        }
    };
    note(
        "snapshot_sha256",
        intent.intended_snapshot_sha256.clone(),
        measured.artifact_sha256.clone(),
    );
    note(
        "mode",
        intent.mode.as_str().to_string(),
        measured.mode.as_str().to_string(),
    );
    note(
        "default_branch",
        intent.intended_default_branch.clone(),
        measured.default_branch.clone(),
    );
    note(
        "head_change_id",
        format!("{:?}", intent.intended_head_change_id),
        format!("{:?}", measured.head_change_id),
    );
    note(
        "roots",
        format!("{:?}", intent.intended_roots),
        format!("{:?}", measured.roots),
    );
    note(
        "source_closure",
        format!("{:?}", intent.intended_source_closure),
        format!("{:?}", measured.source_closure),
    );
    note(
        "ref_bindings",
        format!("{:?}", intent.intended_ref_bindings),
        format!("{:?}", measured.ref_bindings),
    );
    differences
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// Where the caller says the source is now and where the evidence goes.
pub struct PublishArgs {
    pub manifest: PathBuf,
    pub source: PathBuf,
    pub intent_out: PathBuf,
    pub evidence_out: PathBuf,
    pub expect_repository_id: String,
    pub expect_mode: String,
}

/// A read-only look at a destination, against a durable intent.
pub struct VerifyArgs {
    pub manifest: PathBuf,
    pub intent: Option<PathBuf>,
    pub evidence_out: PathBuf,
    pub expect_repository_id: String,
    pub expect_mode: String,
}

/// A manifest, checked against the identity the caller believes it holds.
///
/// The manifest is authoritative and the flags are a cross-check, refused on any
/// disagreement. This is not redundancy for its own sake. A worker recovering
/// after a crash reconstructs its own state, and the failure that costs a tenant
/// its repository is a recovered worker picking up the previous operation's
/// manifest file. The flags are what the recovering caller believes; the
/// manifest is what some earlier process wrote. Making them agree turns that
/// into a refusal.
fn read_checked_manifest(
    path: &Path,
    expect_repository_id: &str,
    expect_mode: &str,
) -> Result<(Manifest, RepositoryId, PublicationMode)> {
    let manifest: Manifest = read_json(path, "manifest")?;
    if manifest.schema != MANIFEST_SCHEMA {
        bail!(
            "manifest declares schema {:?}, and this build reads only {MANIFEST_SCHEMA}",
            manifest.schema
        );
    }
    if manifest.repository_id != expect_repository_id {
        bail!(
            "manifest reserves {:?} but this invocation expects {expect_repository_id:?}",
            manifest.repository_id
        );
    }
    let expected_mode = PublicationMode::parse(expect_mode)?;
    let manifest_mode = manifest.source.mode();
    if manifest_mode != expected_mode {
        bail!(
            "manifest describes a {} source but this invocation expects {}",
            manifest_mode.as_str(),
            expected_mode.as_str()
        );
    }
    require_uuid(&manifest.repository_id, "repository_id")?;
    manifest.operation.validate()?;
    require_digest(&manifest.source_input_hash, "source_input_hash")?;
    let repository_id = RepositoryId::new(manifest.repository_id.clone())
        .map_err(|error| anyhow!("reserved repository identity is unusable: {error}"))?;
    Ok((manifest, repository_id, manifest_mode))
}

/// Bring the inline expected authority and the on-disk intent to one value, and
/// refuse one that does not belong to this operation.
///
/// The two sources are never ranked. Two records that disagree are two accounts
/// of the same attempt, and choosing between them would decide, silently, which
/// crash to believe.
///
/// The binding check is not a formality. An intent path is supplied by the
/// caller and an intent file outlives the run that wrote it, so a worker that
/// reused a path, or recovered onto a machine that still held an earlier
/// operation's file, would otherwise be handed a stranger's intent, find the
/// destination matching it, and report a recovery for work this operation never
/// did.
fn reconcile_expected_intent(
    manifest: &Manifest,
    path: Option<&Path>,
) -> Result<Option<IntentRecord>> {
    let inline = manifest.expected_authority.as_ref();
    let on_disk = match path {
        Some(path) if path.exists() => Some(read_json::<IntentRecord>(path, "intent")?),
        _ => None,
    };
    let resolved = match (inline, on_disk) {
        (Some(inline), Some(on_disk)) => {
            if !inline.describes_same_publication(&on_disk) {
                bail!(
                    "the manifest's expected authority and the intent file describe different \
                     publications, and this run will not choose between them"
                );
            }
            Some(on_disk)
        }
        (Some(inline), None) => Some(inline.clone()),
        (None, on_disk) => on_disk,
    };
    if let Some(intent) = resolved.as_ref() {
        if intent.schema != INTENT_SCHEMA {
            bail!(
                "durable intent declares schema {:?}, and this build reads only {INTENT_SCHEMA}",
                intent.schema
            );
        }
        if intent.repository_id != manifest.repository_id {
            bail!(
                "the durable intent records repository {:?} and this manifest reserves {:?}",
                intent.repository_id,
                manifest.repository_id
            );
        }
        if !intent.operation.names_same_operation(&manifest.operation) {
            bail!(
                "the durable intent belongs to another operation, so it cannot say what this \
                 one published"
            );
        }
        // Same class as the check above. The reading this intent is compared
        // against comes from the manifest's destination, so an intent recording
        // a different one would have its intended values checked against
        // somewhere it never wrote, and a coincidental match would be reported
        // as a recovery.
        if intent.destination != manifest.destination {
            bail!(
                "the durable intent records a different destination than this manifest, so it \
                 cannot say what is published there"
            );
        }
    }
    Ok(resolved)
}

fn echoed_input(manifest: &Manifest) -> EchoedInput {
    EchoedInput {
        source_input_hash: manifest.source_input_hash.clone(),
        requested_default_branch: manifest.source.default_branch().to_string(),
        expected_refs: match &manifest.source {
            SourceSpec::NativeEmpty { .. } => None,
            SourceSpec::ExactGit { expected_refs, .. } => Some(expected_refs.clone()),
        },
    }
}

fn finish(evidence_out: &Path, record: EvidenceRecord) -> Result<i32> {
    let rendered = serde_json::to_string_pretty(&record).context("encode the evidence record")?;
    write_json_atomically(evidence_out, &record, "evidence")?;
    println!("{rendered}");
    Ok(record.outcome.exit_code())
}

/// Decide what a destination reading means against a durable intent.
fn resolve_against_intent(
    manifest: &Manifest,
    intent: &IntentRecord,
    reading: DestinationReading,
) -> EvidenceRecord {
    let base = EvidenceRecord {
        schema: EVIDENCE_SCHEMA.to_string(),
        outcome: Outcome::Absent,
        repository_id: manifest.repository_id.clone(),
        operation: manifest.operation.clone(),
        measured: None,
        echoed: echoed_input(manifest),
        differences: Vec::new(),
        detail: None,
    };
    match reading {
        DestinationReading::Absent => EvidenceRecord {
            detail: Some(
                "destination holds no publication under the reserved identity".to_string(),
            ),
            ..base
        },
        DestinationReading::Indeterminate(detail) => EvidenceRecord {
            outcome: Outcome::Indeterminate,
            detail: Some(detail),
            ..base
        },
        DestinationReading::Present(measured) => {
            let differences = compare_with_intent(intent, &measured);
            if differences.is_empty() {
                EvidenceRecord {
                    outcome: Outcome::Recovered,
                    measured: Some(*measured),
                    ..base
                }
            } else {
                EvidenceRecord {
                    outcome: Outcome::Conflict,
                    measured: Some(*measured),
                    differences,
                    detail: Some(
                        "destination holds a publication that is not the intended one; the \
                         reserved identity is retained and nothing was changed"
                            .to_string(),
                    ),
                    ..base
                }
            }
        }
    }
}

/// Build the reserved repository's durable graph authority.
pub fn run_publish(args: PublishArgs) -> Result<i32> {
    let (manifest, repository_id, mode) = read_checked_manifest(
        &args.manifest,
        &args.expect_repository_id,
        &args.expect_mode,
    )?;
    let expected_intent = reconcile_expected_intent(&manifest, Some(args.intent_out.as_path()))?;
    // Opened before any source work, so an unavailable destination is reported
    // without first spending an import on it.
    manifest.destination.open()?;

    if let Some(intent) = expected_intent.as_ref() {
        let reading = measure_destination(
            &manifest.destination,
            &repository_id,
            mode,
            intent.intended_snapshot_sha256.clone(),
            SnapshotDigestSource::Intent,
        )?;
        if !matches!(reading, DestinationReading::Absent) {
            let record = resolve_against_intent(&manifest, intent, reading);
            return finish(&args.evidence_out, record);
        }
    } else if let Some(record) = refuse_a_stranger(&manifest, &repository_id)? {
        return finish(&args.evidence_out, record);
    }

    let source = open_or_initialize_source(&args.source, &repository_id, &manifest.source)?;
    let (intended_branch, intended_head, intended_bindings) = {
        let lease = source.read_authority();
        let metadata = lease.metadata();
        let bindings =
            verify_source_authority(metadata, lease.snapshot(), &repository_id, &manifest.source)?;
        let branch = metadata
            .ref_state
            .default_ref
            .as_ref()
            .map(default_branch_name)
            .transpose()?
            .ok_or_else(|| anyhow!("source authority carries no default ref"))?;
        let head = resolve_head_change_id(metadata, &repository_id)?;
        (branch, head, bindings)
    };

    let destination = manifest.destination.open()?;
    let mut written_intent: Option<IntentRecord> = None;
    let result = publish_first_repository_observed(
        source,
        &repository_id,
        mode.as_primitive(),
        destination,
        |intent: &FirstPublicationIntent<'_>| {
            let record = IntentRecord {
                schema: INTENT_SCHEMA.to_string(),
                repository_id: manifest.repository_id.clone(),
                operation: manifest.operation.clone(),
                mode,
                intended_snapshot_sha256: intent.snapshot_sha256.to_string(),
                intended_roots: RootBundleRecord::from(intent.roots),
                intended_source_closure: ClosureRecord::from(intent.source_closure),
                intended_default_branch: intended_branch.clone(),
                intended_head_change_id: intended_head.clone(),
                intended_ref_bindings: intended_bindings.clone(),
                destination: manifest.destination.clone(),
                written_at: now_utc(),
            };
            if let Some(expected) = expected_intent.as_ref() {
                if !expected.describes_same_publication(&record) {
                    return Err(FirstPublicationError::Refused(
                        "the prepared source no longer produces the publication this operation \
                         already intended, so it will not be published under that identity"
                            .to_string(),
                    ));
                }
            }
            write_intent_durably(&args.intent_out, &record)
                .map_err(|error| FirstPublicationError::Refused(format!("{error:#}")))?;
            written_intent = Some(record);
            Ok(())
        },
    );

    match (&result, &written_intent) {
        (Ok(receipt), _) => {
            let reading = measure_destination(
                &manifest.destination,
                &repository_id,
                mode,
                receipt.snapshot_sha256.to_string(),
                SnapshotDigestSource::Receipt,
            )?;
            let DestinationReading::Present(measured) = reading else {
                bail!(
                    "the publication reported success and a fresh handle then found no authority \
                     for {repository_id}"
                );
            };
            if measured.artifact_sha256 != receipt.snapshot_sha256.to_string() {
                bail!(
                    "a fresh handle read back {} where the publication installed {}",
                    measured.artifact_sha256,
                    receipt.snapshot_sha256
                );
            }
            if measured.storage_generation != receipt.cursor.backend_generation().to_string() {
                bail!(
                    "a fresh handle read generation {} where the publication committed {}",
                    measured.storage_generation,
                    receipt.cursor.backend_generation()
                );
            }
            // Every field against the durable intent, on success as much as on
            // recovery. A publication that returned cleanly and then found a
            // later authority in front of it has not published what it intended,
            // and saying so is the only truthful answer; a success whose fields
            // were never compared is how a mixed reading would be reported as
            // one.
            let intent = written_intent
                .as_ref()
                .ok_or_else(|| anyhow!("a completed publication always wrote its intent"))?;
            let differences = compare_with_intent(intent, &measured);
            let (outcome, detail) = if differences.is_empty() {
                (Outcome::Published, None)
            } else {
                (
                    Outcome::Conflict,
                    Some(
                        "the publication committed and the destination then disagreed with the \
                         intent it committed, so this is not a first-publication success"
                            .to_string(),
                    ),
                )
            };
            finish(
                &args.evidence_out,
                EvidenceRecord {
                    schema: EVIDENCE_SCHEMA.to_string(),
                    outcome,
                    repository_id: manifest.repository_id.clone(),
                    operation: manifest.operation.clone(),
                    measured: Some(*measured),
                    echoed: echoed_input(&manifest),
                    differences,
                    detail,
                },
            )
        }
        // The intent was made durable, so this failure is at or after the
        // boundary that can leave state behind. What the destination holds now
        // decides the outcome, not the error text.
        (Err(error), Some(intent)) => {
            let reading = measure_destination(
                &manifest.destination,
                &repository_id,
                mode,
                intent.intended_snapshot_sha256.clone(),
                SnapshotDigestSource::Intent,
            )?;
            let mut record = resolve_against_intent(&manifest, intent, reading);
            record.detail = Some(match record.detail.take() {
                Some(detail) => format!("{detail}; publication reported: {error}"),
                None => format!("publication reported: {error}"),
            });
            finish(&args.evidence_out, record)
        }
        // The observer never ran, so nothing was installed and there is nothing
        // to recover. This is a refusal, not an outcome.
        (Err(error), None) => Err(anyhow!("{error}"))
            .with_context(|| format!("publish the reserved repository {repository_id}")),
    }
}

/// Report a destination that already holds something this run cannot account for.
///
/// A first attempt carries no intent, so a publication already under the
/// reserved identity cannot be shown to be this operation's work. It is
/// therefore a conflict rather than a recovery, and it is reported instead of
/// republished.
fn refuse_a_stranger(
    manifest: &Manifest,
    repository_id: &RepositoryId,
) -> Result<Option<EvidenceRecord>> {
    let backend = manifest.destination.open()?;
    let (outcome, detail) = match backend.load_snapshot_cursor(repository_id.as_str()) {
        Ok(None) => return Ok(None),
        Ok(Some(_)) => (
            Outcome::Conflict,
            "destination already holds a publication and this run carries no intent to compare \
             it against; the reserved identity is retained and nothing was changed"
                .to_string(),
        ),
        Err(error) => (Outcome::Indeterminate, error.to_string()),
    };
    Ok(Some(EvidenceRecord {
        schema: EVIDENCE_SCHEMA.to_string(),
        outcome,
        repository_id: manifest.repository_id.clone(),
        operation: manifest.operation.clone(),
        measured: None,
        echoed: echoed_input(manifest),
        differences: Vec::new(),
        detail: Some(detail),
    }))
}

/// Read a destination against a durable intent, and write nothing.
pub fn run_verify(args: VerifyArgs) -> Result<i32> {
    let (manifest, repository_id, mode) = read_checked_manifest(
        &args.manifest,
        &args.expect_repository_id,
        &args.expect_mode,
    )?;
    let intent =
        reconcile_expected_intent(&manifest, args.intent.as_deref())?.ok_or_else(|| {
            anyhow!(
                "verification needs the durable intent it is verifying against, in the manifest's \
             expected authority or in an intent file"
            )
        })?;
    let reading = measure_destination(
        &manifest.destination,
        &repository_id,
        mode,
        intent.intended_snapshot_sha256.clone(),
        SnapshotDigestSource::Intent,
    )?;
    let record = resolve_against_intent(&manifest, &intent, reading);
    finish(&args.evidence_out, record)
}
