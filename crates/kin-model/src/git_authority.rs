// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical, independently verifiable Git import authority.
//!
//! Git remains an exact transport and migration format at this boundary. The
//! raw refs and raw `HEAD` are preserved separately from the result of peeling
//! and deciding whether `HEAD` can seed a materialized Kin workspace. Object
//! bodies stay in caller-owned CAS storage and are supplied through
//! [`GitObjectBodyLoader`].

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use schemars::{gen::SchemaGenerator, schema::Schema, JsonSchema};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{
    ExternalObjectId, ExternalObjectKind, ExternalObjectRecord, GitObjectId, Hash256, RefName,
    RepositoryId,
};

/// Clean-slate Git external-authority schema.
///
/// Version 1 was never a supported public contract. There is deliberately no
/// compatibility decoder: an authority document must be exactly version 2.
pub const GIT_EXTERNAL_AUTHORITY_SCHEMA_VERSION: u32 = 2;

/// Hash algorithm used by one Git object database.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum GitObjectFormat {
    Sha1,
    Sha256,
}

impl GitObjectFormat {
    pub const fn from_oid(oid: GitObjectId) -> Self {
        match oid {
            GitObjectId::Sha1(_) => Self::Sha1,
            GitObjectId::Sha256(_) => Self::Sha256,
        }
    }

    pub const fn oid_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    pub const fn matches(self, oid: GitObjectId) -> bool {
        matches!(
            (self, oid),
            (Self::Sha1, GitObjectId::Sha1(_)) | (Self::Sha256, GitObjectId::Sha256(_))
        )
    }

    fn gix_kind(self) -> gix_hash::Kind {
        match self {
            Self::Sha1 => gix_hash::Kind::Sha1,
            Self::Sha256 => gix_hash::Kind::Sha256,
        }
    }

    const fn identity_tag(self) -> u8 {
        match self {
            Self::Sha1 => 1,
            Self::Sha256 => 2,
        }
    }
}

impl fmt::Display for GitObjectFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha1 => formatter.write_str("sha1"),
            Self::Sha256 => formatter.write_str("sha256"),
        }
    }
}

/// Exact raw target stored by a Git ref or by `HEAD`.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GitRawTarget {
    Direct { object: ExternalObjectId },
    Symbolic { target: RefName },
}

/// One exact `refs/*` entry before peeling or semantic conversion.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct GitRawRef {
    pub name: RefName,
    pub target: GitRawTarget,
}

/// Valid Git tree-entry modes accepted by the authority boundary.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GitTreeEntryMode {
    Tree,
    Blob,
    BlobExecutable,
    Symlink,
    Gitlink,
}

impl GitTreeEntryMode {
    pub const fn target_kind(self) -> ExternalObjectKind {
        match self {
            Self::Tree => ExternalObjectKind::Tree,
            Self::Blob | Self::BlobExecutable | Self::Symlink => ExternalObjectKind::Blob,
            Self::Gitlink => ExternalObjectKind::Commit,
        }
    }

    pub const fn requires_closure_object(self) -> bool {
        !matches!(self, Self::Gitlink)
    }

    const fn canonical_mode(self) -> &'static [u8] {
        match self {
            Self::Tree => b"40000",
            Self::Blob => b"100644",
            Self::BlobExecutable => b"100755",
            Self::Symlink => b"120000",
            Self::Gitlink => b"160000",
        }
    }
}

/// A byte-exact, single-component Git tree-entry name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GitTreeEntryName(Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GitTreeEntryNameError {
    #[error("Git tree-entry name must not be empty")]
    Empty,
    #[error("Git tree-entry name must not be '.' or '..'")]
    Relative,
    #[error("Git tree-entry name must not be the reserved '.git' component")]
    DotGit,
    #[error("Git tree-entry name must not contain '/' or NUL")]
    Separator,
    #[error("Git tree-entry name hex encoding is not canonical lowercase hex")]
    NonCanonicalHex,
    #[error("invalid Git tree-entry name hex: {0}")]
    InvalidHex(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct GitTreeEntryNameWire {
    bytes_hex: String,
}

impl GitTreeEntryName {
    pub fn from_bytes(
        bytes: impl Into<Vec<u8>>,
    ) -> std::result::Result<Self, GitTreeEntryNameError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(GitTreeEntryNameError::Empty);
        }
        if bytes == b"." || bytes == b".." {
            return Err(GitTreeEntryNameError::Relative);
        }
        if bytes.eq_ignore_ascii_case(b".git") {
            return Err(GitTreeEntryNameError::DotGit);
        }
        if bytes.iter().any(|byte| matches!(*byte, b'/' | 0)) {
            return Err(GitTreeEntryNameError::Separator);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Display for GitTreeEntryName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            match byte {
                b'\\' => formatter.write_str("\\\\")?,
                0x20..=0x7e => write!(formatter, "{}", char::from(*byte))?,
                _ => write!(formatter, "\\x{byte:02x}")?,
            }
        }
        Ok(())
    }
}

impl Serialize for GitTreeEntryName {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        GitTreeEntryNameWire {
            bytes_hex: hex::encode(&self.0),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GitTreeEntryName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = GitTreeEntryNameWire::deserialize(deserializer)?;
        let bytes = hex::decode(&wire.bytes_hex).map_err(|error| {
            D::Error::custom(GitTreeEntryNameError::InvalidHex(error.to_string()))
        })?;
        if hex::encode(&bytes) != wire.bytes_hex {
            return Err(D::Error::custom(GitTreeEntryNameError::NonCanonicalHex));
        }
        Self::from_bytes(bytes).map_err(D::Error::custom)
    }
}

impl JsonSchema for GitTreeEntryName {
    fn schema_name() -> String {
        "GitTreeEntryName".to_string()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        GitTreeEntryNameWire::json_schema(generator)
    }
}

/// Semantic role of one exact object-to-object dependency.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GitObjectDependencyKind {
    CommitTree,
    CommitParent {
        position: u32,
    },
    TreeEntry {
        position: u32,
        mode: GitTreeEntryMode,
        name: GitTreeEntryName,
    },
    TagTarget,
}

/// One typed dependency decoded from an exact raw Git object body.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct GitObjectDependency {
    pub kind: GitObjectDependencyKind,
    pub target: ExternalObjectId,
}

impl GitObjectDependency {
    pub const fn requires_closure_object(&self) -> bool {
        match self.kind {
            GitObjectDependencyKind::TreeEntry { mode, .. } => mode.requires_closure_object(),
            _ => true,
        }
    }
}

/// Origin of a closure root.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GitObjectRootSource {
    Head,
    Ref { name: RefName },
}

/// A direct object reached by resolving one raw ref or raw `HEAD`.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct GitObjectRoot {
    pub source: GitObjectRootSource,
    pub target: ExternalObjectId,
}

/// One exact object record and the ordered dependencies decoded from its body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitObjectClosureEntry {
    pub record: ExternalObjectRecord,
    pub dependencies: Vec<GitObjectDependency>,
}

/// Exact reachable Git object closure rooted at refs and `HEAD`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitObjectClosureManifest {
    /// Canonically ordered by root source. `HEAD` sorts before named refs.
    pub roots: Vec<GitObjectRoot>,
    /// Canonically ordered by typed external object identity.
    pub objects: Vec<GitObjectClosureEntry>,
}

/// Kin-canonical identity of one parsed raw Git commit projection.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct GitCommitCanonicalIdentity(pub Hash256);

impl GitCommitCanonicalIdentity {
    pub const fn from_hash(hash: Hash256) -> Self {
        Self(hash)
    }

    pub const fn as_hash(&self) -> Hash256 {
        self.0
    }
}

impl fmt::Display for GitCommitCanonicalIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Parsed fields that define Git commit ancestry and tree identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitCommitProjection {
    pub commit_oid: GitObjectId,
    pub raw_tree_oid: GitObjectId,
    /// Exact order from the raw commit body, including repeated parents.
    pub parent_oids: Vec<GitObjectId>,
    pub canonical_identity: GitCommitCanonicalIdentity,
}

/// Result of resolving and peeling raw `HEAD`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GitMaterialHead {
    /// A symbolic `HEAD` whose final named ref does not yet exist.
    Unborn { missing_ref: RefName },
    /// A commit can seed later workspace admission, but is not itself a
    /// `WorkspaceState` and carries no admission-policy proof.
    Commit {
        direct_target: ExternalObjectId,
        tag_chain: Vec<ExternalObjectId>,
        commit_oid: GitObjectId,
        raw_tree_oid: GitObjectId,
    },
    /// The raw target is valid Git authority but cannot seed a workspace.
    NonMaterializable {
        direct_target: ExternalObjectId,
        tag_chain: Vec<ExternalObjectId>,
        peeled_target: ExternalObjectId,
    },
}

/// Complete external Git authority admitted at the migration boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitExternalAuthority {
    pub schema_version: u32,
    pub repository_id: RepositoryId,
    pub object_format: GitObjectFormat,
    /// Canonically ordered by exact raw ref name.
    pub raw_refs: Vec<GitRawRef>,
    /// Exact raw `HEAD`, before symbolic resolution or tag peeling.
    pub raw_head: GitRawTarget,
    /// Separately derived decision about workspace materializability.
    pub material_head: GitMaterialHead,
    pub closure: GitObjectClosureManifest,
    /// Canonically ordered by raw commit OID.
    pub commit_projections: Vec<GitCommitProjection>,
}

/// Exact, self-inverting mutation of one repository's external Git authority.
///
/// The complete old and new values make this a compare-and-swap contract for
/// storage. Object bodies remain in the caller-owned CAS and closure records
/// may refer to bodies admitted by earlier transactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitExternalAuthorityDelta {
    pub old: Option<GitExternalAuthority>,
    pub new: Option<GitExternalAuthority>,
}

/// Caller-provided access to exact raw bodies in Kin's blob CAS.
pub trait GitObjectBodyLoader {
    type Error: fmt::Display;

    fn load_body(
        &mut self,
        body_hash: &Hash256,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error>;
}

/// One object decoded by the shared authority parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedGitObject {
    pub object: ExternalObjectId,
    pub dependencies: Vec<GitObjectDependency>,
    pub commit_projection: Option<GitCommitProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GitExternalAuthorityError {
    #[error("unsupported Git external-authority schema {actual}; expected {expected}")]
    UnsupportedSchema { actual: u32, expected: u32 },
    #[error("{context} uses {actual} while the authority declares {expected}")]
    MixedObjectFormat {
        context: String,
        expected: GitObjectFormat,
        actual: GitObjectFormat,
    },
    #[error("raw refs are not in canonical unique name order")]
    NonCanonicalRawRefs,
    #[error("duplicate raw ref {name}")]
    DuplicateRawRef { name: RefName },
    #[error("symbolic ref cycle includes {name}")]
    SymbolicRefCycle { name: RefName },
    #[error("closure roots do not exactly match raw refs and HEAD")]
    NonCanonicalRoots,
    #[error("closure objects are not in canonical unique identity order")]
    NonCanonicalObjects,
    #[error("object {oid} is repeated in the closure")]
    DuplicateObject { oid: GitObjectId },
    #[error("object {oid} is assigned both {first:?} and {second:?}")]
    DuplicateObjectKind {
        oid: GitObjectId,
        first: ExternalObjectKind,
        second: ExternalObjectKind,
    },
    #[error("failed to load body for {object:?}: {reason}")]
    BodyLoad {
        object: ExternalObjectId,
        reason: String,
    },
    #[error("body for {object:?} is absent")]
    MissingBody { object: ExternalObjectId },
    #[error("invalid {object:?}: {reason}")]
    InvalidObject {
        object: ExternalObjectId,
        reason: String,
    },
    #[error("dependencies for {object:?} are not canonical for its kind")]
    NonCanonicalDependencies { object: ExternalObjectId },
    #[error(
        "{source_object:?} requires {expected:?} object {oid}, but the closure declares {actual:?}"
    )]
    WrongDependencyKind {
        source_object: ExternalObjectId,
        oid: GitObjectId,
        expected: ExternalObjectKind,
        actual: ExternalObjectKind,
    },
    #[error("{source_object:?} requires missing object {target:?}")]
    MissingDependency {
        source_object: ExternalObjectId,
        target: ExternalObjectId,
    },
    #[error("closure contains unreachable object {object:?}")]
    ExtraObject { object: ExternalObjectId },
    #[error("annotated tag cycle includes {object:?}")]
    TagCycle { object: ExternalObjectId },
    #[error("tree {object:?} repeats raw entry name {name}")]
    DuplicateTreeEntryName {
        object: ExternalObjectId,
        name: GitTreeEntryName,
    },
    #[error("tree {object:?} entries are not in canonical Git order")]
    NonCanonicalTreeOrder { object: ExternalObjectId },
    #[error("commit projections are not the canonical decoded projection set")]
    NonCanonicalCommitProjections,
    #[error("material HEAD does not match raw HEAD, refs, and decoded objects")]
    NonCanonicalMaterialHead,
    #[error("Git external-authority delta has no old or new state")]
    EmptyDelta,
    #[error("Git external-authority delta is a no-op")]
    NoOpDelta,
    #[error("Git external-authority delta changes repository identity from {old} to {new}")]
    DeltaRepositoryMismatch {
        old: RepositoryId,
        new: RepositoryId,
    },
    #[error("Git external-authority delta changes object format from {old} to {new}")]
    DeltaObjectFormatMismatch {
        old: GitObjectFormat,
        new: GitObjectFormat,
    },
    #[error(
        "Git external-authority repository {actual} does not match enclosing repository {expected}"
    )]
    EnclosingRepositoryMismatch {
        actual: RepositoryId,
        expected: RepositoryId,
    },
    #[error("canonical commit identity input exceeds u64")]
    IdentityOverflow,
}

impl GitExternalAuthorityDelta {
    pub fn initialize(new: GitExternalAuthority) -> Self {
        Self {
            old: None,
            new: Some(new),
        }
    }

    pub fn update(old: GitExternalAuthority, new: GitExternalAuthority) -> Self {
        Self {
            old: Some(old),
            new: Some(new),
        }
    }

    pub fn remove(old: GitExternalAuthority) -> Self {
        Self {
            old: Some(old),
            new: None,
        }
    }

    pub fn inverse(&self) -> Self {
        Self {
            old: self.new.clone(),
            new: self.old.clone(),
        }
    }

    pub fn repository_id(&self) -> Option<&RepositoryId> {
        self.new
            .as_ref()
            .or(self.old.as_ref())
            .map(|authority| &authority.repository_id)
    }

    /// Validate initial, update, or removal shape without loading object bodies.
    ///
    /// This deliberately does not require closure records to appear in the
    /// enclosing transaction's newly admitted object list. Durable storage
    /// validates the old value and resolves the new closure against the union
    /// of existing and newly written CAS records.
    pub fn validate(&self) -> std::result::Result<(), GitExternalAuthorityError> {
        if self.old.is_none() && self.new.is_none() {
            return Err(GitExternalAuthorityError::EmptyDelta);
        }
        if self.old == self.new {
            return Err(GitExternalAuthorityError::NoOpDelta);
        }
        if let Some(old) = &self.old {
            old.validate_shape()?;
        }
        if let Some(new) = &self.new {
            new.validate_shape()?;
        }
        if let (Some(old), Some(new)) = (&self.old, &self.new) {
            if old.repository_id != new.repository_id {
                return Err(GitExternalAuthorityError::DeltaRepositoryMismatch {
                    old: old.repository_id.clone(),
                    new: new.repository_id.clone(),
                });
            }
            if old.object_format != new.object_format {
                return Err(GitExternalAuthorityError::DeltaObjectFormatMismatch {
                    old: old.object_format,
                    new: new.object_format,
                });
            }
        }
        Ok(())
    }

    pub fn validate_for_repository(
        &self,
        repository_id: &RepositoryId,
    ) -> std::result::Result<(), GitExternalAuthorityError> {
        self.validate()?;
        let actual = self
            .repository_id()
            .expect("a validated authority delta has one side");
        if actual != repository_id {
            return Err(GitExternalAuthorityError::EnclosingRepositoryMismatch {
                actual: actual.clone(),
                expected: repository_id.clone(),
            });
        }
        Ok(())
    }
}

impl GitExternalAuthority {
    /// Construct schema v2 from exact raw refs, raw `HEAD`, object records, and
    /// caller-owned CAS bodies. Input order is canonicalized; duplicate or
    /// unreachable input is rejected rather than repaired.
    pub fn from_raw_parts<L: GitObjectBodyLoader>(
        repository_id: RepositoryId,
        object_format: GitObjectFormat,
        mut raw_refs: Vec<GitRawRef>,
        raw_head: GitRawTarget,
        records: Vec<ExternalObjectRecord>,
        body_loader: &mut L,
    ) -> std::result::Result<Self, GitExternalAuthorityError> {
        ensure_no_duplicate_raw_refs(&raw_refs)?;
        raw_refs.sort_by(|left, right| left.name.cmp(&right.name));

        let decoded = load_and_decode_records(object_format, &records, body_loader)?;
        let records_by_id = records
            .into_iter()
            .map(|record| (record.object, record))
            .collect::<BTreeMap<_, _>>();
        let mut objects = decoded
            .values()
            .map(|decoded| GitObjectClosureEntry {
                record: records_by_id
                    .get(&decoded.object)
                    .expect("decoded records retain their source descriptor")
                    .clone(),
                dependencies: decoded.dependencies.clone(),
            })
            .collect::<Vec<_>>();
        objects.sort_by_key(|entry| entry.record.object);

        let roots = derive_roots(&raw_refs, &raw_head)?;
        let closure = GitObjectClosureManifest { roots, objects };
        validate_closure_structure(object_format, &closure)?;

        let material_head = derive_material_head(&raw_refs, &raw_head, &decoded)?;
        let mut commit_projections = decoded
            .values()
            .filter_map(|object| object.commit_projection.clone())
            .collect::<Vec<_>>();
        commit_projections.sort_by_key(|projection| projection.commit_oid);

        let authority = Self {
            schema_version: GIT_EXTERNAL_AUTHORITY_SCHEMA_VERSION,
            repository_id,
            object_format,
            raw_refs,
            raw_head,
            material_head,
            closure,
            commit_projections,
        };
        authority.validate_shape()?;
        authority.validate_against_decoded(&decoded)?;
        Ok(authority)
    }

    /// Validate every authority field that can be proven without loading CAS
    /// bodies.
    ///
    /// This covers schema, canonical ordering, typed closure reachability,
    /// commit projection identity, and material-HEAD derivation. Use
    /// [`Self::validate_with_body_loader`] when raw bodies are available to
    /// additionally prove every record and decoded dependency.
    pub fn validate_shape(&self) -> std::result::Result<(), GitExternalAuthorityError> {
        if self.schema_version != GIT_EXTERNAL_AUTHORITY_SCHEMA_VERSION {
            return Err(GitExternalAuthorityError::UnsupportedSchema {
                actual: self.schema_version,
                expected: GIT_EXTERNAL_AUTHORITY_SCHEMA_VERSION,
            });
        }
        validate_raw_ref_order(&self.raw_refs)?;
        validate_target_format(self.object_format, &self.raw_head, "raw HEAD")?;
        for raw_ref in &self.raw_refs {
            validate_target_format(
                self.object_format,
                &raw_ref.target,
                &format!("raw ref {}", raw_ref.name),
            )?;
        }

        let expected_roots = derive_roots(&self.raw_refs, &self.raw_head)?;
        if self.closure.roots != expected_roots {
            return Err(GitExternalAuthorityError::NonCanonicalRoots);
        }
        validate_closure_structure(self.object_format, &self.closure)?;
        let declared = decoded_from_manifest(self)?;
        self.validate_against_decoded(&declared)
    }

    /// Independently re-load, decode, and validate every authority field.
    pub fn validate_with_body_loader<L: GitObjectBodyLoader>(
        &self,
        body_loader: &mut L,
    ) -> std::result::Result<(), GitExternalAuthorityError> {
        self.validate_shape()?;

        let records = self
            .closure
            .objects
            .iter()
            .map(|entry| entry.record.clone())
            .collect::<Vec<_>>();
        let decoded = load_and_decode_records(self.object_format, &records, body_loader)?;
        self.validate_against_decoded(&decoded)
    }

    fn validate_against_decoded(
        &self,
        decoded: &BTreeMap<ExternalObjectId, DecodedGitObject>,
    ) -> std::result::Result<(), GitExternalAuthorityError> {
        for entry in &self.closure.objects {
            let actual = decoded.get(&entry.record.object).ok_or({
                GitExternalAuthorityError::MissingDependency {
                    source_object: entry.record.object,
                    target: entry.record.object,
                }
            })?;
            if entry.dependencies != actual.dependencies {
                return Err(GitExternalAuthorityError::NonCanonicalDependencies {
                    object: entry.record.object,
                });
            }
        }

        let mut expected_projections = decoded
            .values()
            .filter_map(|object| object.commit_projection.clone())
            .collect::<Vec<_>>();
        expected_projections.sort_by_key(|projection| projection.commit_oid);
        if self.commit_projections != expected_projections {
            return Err(GitExternalAuthorityError::NonCanonicalCommitProjections);
        }

        let expected_material_head = derive_material_head(&self.raw_refs, &self.raw_head, decoded)?;
        if self.material_head != expected_material_head {
            return Err(GitExternalAuthorityError::NonCanonicalMaterialHead);
        }
        Ok(())
    }
}

fn decoded_from_manifest(
    authority: &GitExternalAuthority,
) -> std::result::Result<BTreeMap<ExternalObjectId, DecodedGitObject>, GitExternalAuthorityError> {
    let mut decoded = BTreeMap::new();
    for entry in &authority.closure.objects {
        let commit_projection = if entry.record.object.kind == ExternalObjectKind::Commit {
            let Some((tree, parents)) = entry.dependencies.split_first() else {
                return Err(GitExternalAuthorityError::NonCanonicalDependencies {
                    object: entry.record.object,
                });
            };
            if !matches!(tree.kind, GitObjectDependencyKind::CommitTree) {
                return Err(GitExternalAuthorityError::NonCanonicalDependencies {
                    object: entry.record.object,
                });
            }
            let parent_oids = parents
                .iter()
                .map(|parent| parent.target.oid)
                .collect::<Vec<_>>();
            Some(GitCommitProjection {
                commit_oid: entry.record.object.oid,
                raw_tree_oid: tree.target.oid,
                parent_oids: parent_oids.clone(),
                canonical_identity: compute_commit_identity(
                    authority.object_format,
                    &entry.record,
                    tree.target.oid,
                    &parent_oids,
                )?,
            })
        } else {
            None
        };
        decoded.insert(
            entry.record.object,
            DecodedGitObject {
                object: entry.record.object,
                dependencies: entry.dependencies.clone(),
                commit_projection,
            },
        );
    }
    Ok(decoded)
}

/// Decode and validate one exact raw object without repository or filesystem
/// access.
pub fn decode_git_external_object(
    object_format: GitObjectFormat,
    record: &ExternalObjectRecord,
    body: &[u8],
) -> std::result::Result<DecodedGitObject, GitExternalAuthorityError> {
    ensure_oid_format(
        object_format,
        record.object.oid,
        format!("object {}", record.object.oid),
    )?;
    record
        .validate_raw(body)
        .map_err(|error| GitExternalAuthorityError::InvalidObject {
            object: record.object,
            reason: error.to_string(),
        })?;

    let hash_kind = object_format.gix_kind();
    let mut dependencies = Vec::new();
    let mut commit_projection = None;

    match record.object.kind {
        ExternalObjectKind::Commit => {
            let commit = gix_object::CommitRef::from_bytes(body, hash_kind).map_err(|error| {
                GitExternalAuthorityError::InvalidObject {
                    object: record.object,
                    reason: format!("decode commit: {error}"),
                }
            })?;
            ensure_lower_hex(record.object, "commit tree", commit.tree.as_ref())?;
            let raw_tree_oid = model_oid(record.object, commit.tree())?;
            ensure_non_null_dependency(record.object, raw_tree_oid, "commit tree")?;
            dependencies.push(GitObjectDependency {
                kind: GitObjectDependencyKind::CommitTree,
                target: ExternalObjectId::new(ExternalObjectKind::Tree, raw_tree_oid),
            });

            let mut parent_oids = Vec::with_capacity(commit.parents.len());
            for (position, raw_parent) in commit.parents.iter().enumerate() {
                ensure_lower_hex(record.object, "commit parent", raw_parent.as_ref())?;
                let parent_oid = model_oid(
                    record.object,
                    gix_hash::ObjectId::from_hex(raw_parent.as_ref()).map_err(|error| {
                        GitExternalAuthorityError::InvalidObject {
                            object: record.object,
                            reason: format!("decode parent OID: {error}"),
                        }
                    })?,
                )?;
                ensure_non_null_dependency(record.object, parent_oid, "commit parent")?;
                let position = u32::try_from(position)
                    .map_err(|_| GitExternalAuthorityError::IdentityOverflow)?;
                dependencies.push(GitObjectDependency {
                    kind: GitObjectDependencyKind::CommitParent { position },
                    target: ExternalObjectId::new(ExternalObjectKind::Commit, parent_oid),
                });
                parent_oids.push(parent_oid);
            }
            commit_projection = Some(GitCommitProjection {
                commit_oid: record.object.oid,
                raw_tree_oid,
                canonical_identity: compute_commit_identity(
                    object_format,
                    record,
                    raw_tree_oid,
                    &parent_oids,
                )?,
                parent_oids,
            });
        }
        ExternalObjectKind::Tree => {
            let tree = gix_object::TreeRef::from_bytes(body, hash_kind).map_err(|error| {
                GitExternalAuthorityError::InvalidObject {
                    object: record.object,
                    reason: format!("decode tree: {error}"),
                }
            })?;
            let raw_modes = raw_tree_entry_modes(record.object, body, hash_kind.len_in_bytes())?;
            if raw_modes.len() != tree.entries.len() {
                return Err(GitExternalAuthorityError::InvalidObject {
                    object: record.object,
                    reason: format!(
                        "tree body walks to {} entries but decodes to {}",
                        raw_modes.len(),
                        tree.entries.len()
                    ),
                });
            }
            let mut previous = None;
            let mut names = BTreeSet::new();
            for (position, entry) in tree.entries.iter().copied().enumerate() {
                let mode = exact_tree_mode(record.object, entry.mode, raw_modes[position])?;
                let name =
                    GitTreeEntryName::from_bytes(entry.filename.to_vec()).map_err(|error| {
                        GitExternalAuthorityError::InvalidObject {
                            object: record.object,
                            reason: format!("invalid tree-entry name: {error}"),
                        }
                    })?;
                if !names.insert(name.clone()) {
                    return Err(GitExternalAuthorityError::DuplicateTreeEntryName {
                        object: record.object,
                        name,
                    });
                }
                if previous
                    .as_ref()
                    .is_some_and(|previous: &gix_object::tree::EntryRef<'_>| previous >= &entry)
                {
                    return Err(GitExternalAuthorityError::NonCanonicalTreeOrder {
                        object: record.object,
                    });
                }
                previous = Some(entry);
                let position = u32::try_from(position)
                    .map_err(|_| GitExternalAuthorityError::IdentityOverflow)?;
                let target_oid = model_oid(record.object, entry.oid.to_owned())?;
                ensure_non_null_dependency(record.object, target_oid, "tree entry")?;
                dependencies.push(GitObjectDependency {
                    kind: GitObjectDependencyKind::TreeEntry {
                        position,
                        mode,
                        name,
                    },
                    target: ExternalObjectId::new(mode.target_kind(), target_oid),
                });
            }
        }
        ExternalObjectKind::Blob => {}
        ExternalObjectKind::Tag => {
            let tag = gix_object::TagRef::from_bytes(body, hash_kind).map_err(|error| {
                GitExternalAuthorityError::InvalidObject {
                    object: record.object,
                    reason: format!("decode tag: {error}"),
                }
            })?;
            ensure_lower_hex(record.object, "tag target", tag.target.as_ref())?;
            let target_oid = model_oid(record.object, tag.target())?;
            ensure_non_null_dependency(record.object, target_oid, "tag target")?;
            dependencies.push(GitObjectDependency {
                kind: GitObjectDependencyKind::TagTarget,
                target: ExternalObjectId::new(external_kind(tag.target_kind), target_oid),
            });
        }
    }

    Ok(DecodedGitObject {
        object: record.object,
        dependencies,
        commit_projection,
    })
}

fn load_and_decode_records<L: GitObjectBodyLoader>(
    object_format: GitObjectFormat,
    records: &[ExternalObjectRecord],
    body_loader: &mut L,
) -> std::result::Result<BTreeMap<ExternalObjectId, DecodedGitObject>, GitExternalAuthorityError> {
    validate_record_set(object_format, records)?;
    let mut decoded = BTreeMap::new();
    for record in records {
        let body = body_loader
            .load_body(&record.body_hash)
            .map_err(|error| GitExternalAuthorityError::BodyLoad {
                object: record.object,
                reason: error.to_string(),
            })?
            .ok_or(GitExternalAuthorityError::MissingBody {
                object: record.object,
            })?;
        let object = decode_git_external_object(object_format, record, &body)?;
        decoded.insert(record.object, object);
    }
    Ok(decoded)
}

fn validate_record_set(
    object_format: GitObjectFormat,
    records: &[ExternalObjectRecord],
) -> std::result::Result<(), GitExternalAuthorityError> {
    let mut identities = BTreeSet::new();
    let mut kinds_by_oid = BTreeMap::new();
    for record in records {
        ensure_oid_format(
            object_format,
            record.object.oid,
            format!("object {}", record.object.oid),
        )?;
        if !identities.insert(record.object) {
            return Err(GitExternalAuthorityError::DuplicateObject {
                oid: record.object.oid,
            });
        }
        if let Some(first) = kinds_by_oid.insert(record.object.oid, record.object.kind) {
            return Err(GitExternalAuthorityError::DuplicateObjectKind {
                oid: record.object.oid,
                first,
                second: record.object.kind,
            });
        }
    }
    Ok(())
}

fn validate_closure_structure(
    object_format: GitObjectFormat,
    closure: &GitObjectClosureManifest,
) -> std::result::Result<(), GitExternalAuthorityError> {
    for pair in closure.roots.windows(2) {
        if pair[0] >= pair[1] {
            return Err(GitExternalAuthorityError::NonCanonicalRoots);
        }
    }
    for root in &closure.roots {
        ensure_oid_format(
            object_format,
            root.target.oid,
            format!("closure root {:?}", root.source),
        )?;
    }

    for pair in closure.objects.windows(2) {
        if pair[0].record.object >= pair[1].record.object {
            return Err(GitExternalAuthorityError::NonCanonicalObjects);
        }
    }
    let records = closure
        .objects
        .iter()
        .map(|entry| entry.record.clone())
        .collect::<Vec<_>>();
    validate_record_set(object_format, &records)?;

    let by_identity = closure
        .objects
        .iter()
        .map(|entry| (entry.record.object, entry))
        .collect::<BTreeMap<_, _>>();
    let by_oid = closure
        .objects
        .iter()
        .map(|entry| (entry.record.object.oid, entry.record.object))
        .collect::<BTreeMap<_, _>>();

    for entry in &closure.objects {
        validate_dependency_shape(entry)?;
        for dependency in &entry.dependencies {
            ensure_oid_format(
                object_format,
                dependency.target.oid,
                format!("dependency of {}", entry.record.object.oid),
            )?;
            if !dependency.requires_closure_object() {
                continue;
            }
            if by_identity.contains_key(&dependency.target) {
                continue;
            }
            if let Some(actual) = by_oid.get(&dependency.target.oid) {
                return Err(GitExternalAuthorityError::WrongDependencyKind {
                    source_object: entry.record.object,
                    oid: dependency.target.oid,
                    expected: dependency.target.kind,
                    actual: actual.kind,
                });
            }
            return Err(GitExternalAuthorityError::MissingDependency {
                source_object: entry.record.object,
                target: dependency.target,
            });
        }
    }
    validate_tag_acyclic(&by_identity)?;

    let mut pending = VecDeque::new();
    let mut visited = BTreeSet::new();
    for root in &closure.roots {
        let Some(entry) = by_identity.get(&root.target) else {
            if let Some(actual) = by_oid.get(&root.target.oid) {
                return Err(GitExternalAuthorityError::WrongDependencyKind {
                    source_object: root.target,
                    oid: root.target.oid,
                    expected: root.target.kind,
                    actual: actual.kind,
                });
            }
            return Err(GitExternalAuthorityError::MissingDependency {
                source_object: root.target,
                target: root.target,
            });
        };
        pending.push_back(entry.record.object);
    }

    while let Some(object) = pending.pop_front() {
        if !visited.insert(object) {
            continue;
        }
        let entry = by_identity
            .get(&object)
            .expect("closure edges were validated before traversal");
        for dependency in &entry.dependencies {
            if dependency.requires_closure_object() {
                pending.push_back(dependency.target);
            }
        }
    }

    if let Some(extra) = closure
        .objects
        .iter()
        .map(|entry| entry.record.object)
        .find(|object| !visited.contains(object))
    {
        return Err(GitExternalAuthorityError::ExtraObject { object: extra });
    }
    Ok(())
}

fn validate_dependency_shape(
    entry: &GitObjectClosureEntry,
) -> std::result::Result<(), GitExternalAuthorityError> {
    let valid =
        match entry.record.object.kind {
            ExternalObjectKind::Blob => entry.dependencies.is_empty(),
            ExternalObjectKind::Tag => {
                matches!(
                    entry.dependencies.as_slice(),
                    [GitObjectDependency {
                        kind: GitObjectDependencyKind::TagTarget,
                        ..
                    }]
                )
            }
            ExternalObjectKind::Commit => {
                let Some((tree, parents)) = entry.dependencies.split_first() else {
                    return Err(GitExternalAuthorityError::NonCanonicalDependencies {
                        object: entry.record.object,
                    });
                };
                matches!(tree.kind, GitObjectDependencyKind::CommitTree)
                    && tree.target.kind == ExternalObjectKind::Tree
                    && parents.iter().enumerate().all(|(position, dependency)| {
                        matches!(
                            dependency.kind,
                            GitObjectDependencyKind::CommitParent {
                                position: actual
                            } if usize::try_from(actual).ok() == Some(position)
                        ) && dependency.target.kind == ExternalObjectKind::Commit
                    })
            }
            ExternalObjectKind::Tree => {
                let mut names = BTreeSet::new();
                entry.dependencies.iter().enumerate().all(
                    |(position, dependency)| match &dependency.kind {
                        GitObjectDependencyKind::TreeEntry {
                            position: actual,
                            mode,
                            name,
                        } => {
                            usize::try_from(*actual).ok() == Some(position)
                                && dependency.target.kind == mode.target_kind()
                                && names.insert(name.clone())
                        }
                        _ => false,
                    },
                )
            }
        };
    if valid {
        Ok(())
    } else {
        Err(GitExternalAuthorityError::NonCanonicalDependencies {
            object: entry.record.object,
        })
    }
}

fn validate_tag_acyclic(
    objects: &BTreeMap<ExternalObjectId, &GitObjectClosureEntry>,
) -> std::result::Result<(), GitExternalAuthorityError> {
    for start in objects
        .keys()
        .filter(|object| object.kind == ExternalObjectKind::Tag)
    {
        let mut current = *start;
        let mut seen = BTreeSet::new();
        while current.kind == ExternalObjectKind::Tag {
            if !seen.insert(current) {
                return Err(GitExternalAuthorityError::TagCycle { object: current });
            }
            let Some(entry) = objects.get(&current) else {
                break;
            };
            let Some(dependency) = entry.dependencies.first() else {
                break;
            };
            current = dependency.target;
        }
    }
    Ok(())
}

fn derive_roots(
    raw_refs: &[GitRawRef],
    raw_head: &GitRawTarget,
) -> std::result::Result<Vec<GitObjectRoot>, GitExternalAuthorityError> {
    let refs = raw_refs
        .iter()
        .map(|raw_ref| (raw_ref.name.clone(), raw_ref.target.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut roots = Vec::new();
    if let SymbolicResolution::Object(target) = resolve_target(raw_head, &refs)? {
        roots.push(GitObjectRoot {
            source: GitObjectRootSource::Head,
            target,
        });
    }
    for raw_ref in raw_refs {
        if let SymbolicResolution::Object(target) = resolve_target(&raw_ref.target, &refs)? {
            roots.push(GitObjectRoot {
                source: GitObjectRootSource::Ref {
                    name: raw_ref.name.clone(),
                },
                target,
            });
        }
    }
    roots.sort();
    Ok(roots)
}

enum SymbolicResolution {
    Object(ExternalObjectId),
    Missing(RefName),
}

fn resolve_target(
    target: &GitRawTarget,
    refs: &BTreeMap<RefName, GitRawTarget>,
) -> std::result::Result<SymbolicResolution, GitExternalAuthorityError> {
    match target {
        GitRawTarget::Direct { object } => Ok(SymbolicResolution::Object(*object)),
        GitRawTarget::Symbolic { target } => {
            let mut current = target.clone();
            let mut seen = BTreeSet::new();
            loop {
                if !seen.insert(current.clone()) {
                    return Err(GitExternalAuthorityError::SymbolicRefCycle { name: current });
                }
                match refs.get(&current) {
                    Some(GitRawTarget::Direct { object }) => {
                        return Ok(SymbolicResolution::Object(*object))
                    }
                    Some(GitRawTarget::Symbolic { target }) => current = target.clone(),
                    None => return Ok(SymbolicResolution::Missing(current)),
                }
            }
        }
    }
}

fn derive_material_head(
    raw_refs: &[GitRawRef],
    raw_head: &GitRawTarget,
    decoded: &BTreeMap<ExternalObjectId, DecodedGitObject>,
) -> std::result::Result<GitMaterialHead, GitExternalAuthorityError> {
    let refs = raw_refs
        .iter()
        .map(|raw_ref| (raw_ref.name.clone(), raw_ref.target.clone()))
        .collect::<BTreeMap<_, _>>();
    let direct_target = match resolve_target(raw_head, &refs)? {
        SymbolicResolution::Missing(missing_ref) => {
            return Ok(GitMaterialHead::Unborn { missing_ref })
        }
        SymbolicResolution::Object(target) => target,
    };

    let mut current = direct_target;
    let mut tag_chain = Vec::new();
    let mut seen = BTreeSet::new();
    while current.kind == ExternalObjectKind::Tag {
        if !seen.insert(current) {
            return Err(GitExternalAuthorityError::TagCycle { object: current });
        }
        tag_chain.push(current);
        let object = decoded
            .get(&current)
            .ok_or(GitExternalAuthorityError::MissingDependency {
                source_object: direct_target,
                target: current,
            })?;
        let dependency = object
            .dependencies
            .first()
            .ok_or(GitExternalAuthorityError::NonCanonicalDependencies { object: current })?;
        current = dependency.target;
    }

    if current.kind == ExternalObjectKind::Commit {
        let projection = decoded
            .get(&current)
            .and_then(|object| object.commit_projection.as_ref())
            .ok_or(GitExternalAuthorityError::NonCanonicalCommitProjections)?;
        Ok(GitMaterialHead::Commit {
            direct_target,
            tag_chain,
            commit_oid: current.oid,
            raw_tree_oid: projection.raw_tree_oid,
        })
    } else {
        Ok(GitMaterialHead::NonMaterializable {
            direct_target,
            tag_chain,
            peeled_target: current,
        })
    }
}

fn validate_raw_ref_order(
    raw_refs: &[GitRawRef],
) -> std::result::Result<(), GitExternalAuthorityError> {
    for pair in raw_refs.windows(2) {
        match pair[0].name.cmp(&pair[1].name) {
            Ordering::Less => {}
            Ordering::Equal => {
                return Err(GitExternalAuthorityError::DuplicateRawRef {
                    name: pair[0].name.clone(),
                })
            }
            Ordering::Greater => return Err(GitExternalAuthorityError::NonCanonicalRawRefs),
        }
    }
    Ok(())
}

fn ensure_no_duplicate_raw_refs(
    raw_refs: &[GitRawRef],
) -> std::result::Result<(), GitExternalAuthorityError> {
    let mut names = BTreeSet::new();
    for raw_ref in raw_refs {
        if !names.insert(raw_ref.name.clone()) {
            return Err(GitExternalAuthorityError::DuplicateRawRef {
                name: raw_ref.name.clone(),
            });
        }
    }
    Ok(())
}

fn validate_target_format(
    expected: GitObjectFormat,
    target: &GitRawTarget,
    context: &str,
) -> std::result::Result<(), GitExternalAuthorityError> {
    if let GitRawTarget::Direct { object } = target {
        ensure_oid_format(expected, object.oid, context.to_string())?;
    }
    Ok(())
}

fn ensure_oid_format(
    expected: GitObjectFormat,
    oid: GitObjectId,
    context: String,
) -> std::result::Result<(), GitExternalAuthorityError> {
    if expected.matches(oid) {
        return Ok(());
    }
    Err(GitExternalAuthorityError::MixedObjectFormat {
        context,
        expected,
        actual: GitObjectFormat::from_oid(oid),
    })
}

fn ensure_non_null_dependency(
    object: ExternalObjectId,
    oid: GitObjectId,
    field: &str,
) -> std::result::Result<(), GitExternalAuthorityError> {
    if oid.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(GitExternalAuthorityError::InvalidObject {
            object,
            reason: format!("{field} uses the null object ID"),
        });
    }
    Ok(())
}

fn ensure_lower_hex(
    object: ExternalObjectId,
    field: &str,
    value: &[u8],
) -> std::result::Result<(), GitExternalAuthorityError> {
    if value.iter().any(u8::is_ascii_uppercase) {
        return Err(GitExternalAuthorityError::InvalidObject {
            object,
            reason: format!("{field} OID is not canonical lowercase hex"),
        });
    }
    Ok(())
}

/// The exact mode encodings of one tree body's entries, in body order.
///
/// A tree entry is `<mode> <name>\0<oid>`, so the encodings are recoverable
/// from the body without reparsing the objects. They are read back here rather
/// than re-encoded from the decoded mode, because a decoded mode cannot
/// represent every spelling Git tolerates: `gix` collapses a zero-padded file
/// mode onto its canonical value, and represents a zero-padded directory with
/// the same value it gives the literal `140000` that Git rejects.
fn raw_tree_entry_modes(
    object: ExternalObjectId,
    body: &[u8],
    oid_len: usize,
) -> std::result::Result<Vec<&[u8]>, GitExternalAuthorityError> {
    let malformed = |reason: &str| GitExternalAuthorityError::InvalidObject {
        object,
        reason: format!("malformed tree body: {reason}"),
    };
    let mut modes = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| malformed("tree entry has no mode terminator"))?;
        let (mode, after_mode) = rest.split_at(space);
        let nul = after_mode
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| malformed("tree entry has no name terminator"))?;
        let entry_len = nul
            .checked_add(1)
            .and_then(|len| len.checked_add(oid_len))
            .ok_or_else(|| malformed("tree entry length overflows"))?;
        if after_mode.len() < entry_len {
            return Err(malformed("tree entry is truncated"));
        }
        modes.push(mode);
        rest = &after_mode[entry_len..];
    }
    Ok(modes)
}

fn exact_tree_mode(
    object: ExternalObjectId,
    mode: gix_object::tree::EntryMode,
    raw_mode: &[u8],
) -> std::result::Result<GitTreeEntryMode, GitExternalAuthorityError> {
    let exact = match mode.value() {
        0o040000 => GitTreeEntryMode::Tree,
        0o100644 => GitTreeEntryMode::Blob,
        0o100755 => GitTreeEntryMode::BlobExecutable,
        0o120000 => GitTreeEntryMode::Symlink,
        0o160000 => GitTreeEntryMode::Gitlink,
        other => {
            return Err(GitExternalAuthorityError::InvalidObject {
                object,
                reason: format!("unsupported tree-entry mode {other:o}"),
            })
        }
    };
    // Git's own parser tolerates leading zeros, so history written by pre-2010
    // tooling and CVS/SVN imports carries `040000` where canonical Git writes
    // `40000`. Such an encoding still names exactly one legal mode, and the
    // admitted body is stored and replayed verbatim, so accepting it costs no
    // fidelity: an object is bound to its raw bytes by the Git object ID that
    // `ExternalObjectRecord::validate_raw` recomputes over them. Any other
    // spelling stays refused, so a mode whose digits differ from the canonical
    // ones can never be admitted as that mode.
    let significant = raw_mode
        .iter()
        .position(|digit| *digit != b'0')
        .map_or(raw_mode, |first| &raw_mode[first..]);
    if significant != exact.canonical_mode() {
        return Err(GitExternalAuthorityError::InvalidObject {
            object,
            reason: "noncanonical tree-entry mode encoding".to_string(),
        });
    }
    Ok(exact)
}

fn model_oid(
    source_object: ExternalObjectId,
    oid: gix_hash::ObjectId,
) -> std::result::Result<GitObjectId, GitExternalAuthorityError> {
    match oid.as_slice() {
        bytes if bytes.len() == 20 => {
            let mut value = [0_u8; 20];
            value.copy_from_slice(bytes);
            Ok(GitObjectId::sha1(value))
        }
        bytes if bytes.len() == 32 => {
            let mut value = [0_u8; 32];
            value.copy_from_slice(bytes);
            Ok(GitObjectId::sha256(value))
        }
        bytes => Err(GitExternalAuthorityError::InvalidObject {
            object: source_object,
            reason: format!("gix returned unsupported {}-byte OID", bytes.len()),
        }),
    }
}

const fn external_kind(kind: gix_object::Kind) -> ExternalObjectKind {
    match kind {
        gix_object::Kind::Commit => ExternalObjectKind::Commit,
        gix_object::Kind::Tree => ExternalObjectKind::Tree,
        gix_object::Kind::Blob => ExternalObjectKind::Blob,
        gix_object::Kind::Tag => ExternalObjectKind::Tag,
    }
}

fn compute_commit_identity(
    object_format: GitObjectFormat,
    record: &ExternalObjectRecord,
    raw_tree_oid: GitObjectId,
    parent_oids: &[GitObjectId],
) -> std::result::Result<GitCommitCanonicalIdentity, GitExternalAuthorityError> {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-git-commit-projection-v2\0");
    hasher.update([object_format.identity_tag()]);
    append_identity_field(&mut hasher, record.object.oid.as_bytes())?;
    append_identity_field(&mut hasher, record.body_hash.as_bytes())?;
    append_identity_field(&mut hasher, raw_tree_oid.as_bytes())?;
    hasher.update(
        u64::try_from(parent_oids.len())
            .map_err(|_| GitExternalAuthorityError::IdentityOverflow)?
            .to_le_bytes(),
    );
    for parent in parent_oids {
        append_identity_field(&mut hasher, parent.as_bytes())?;
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(GitCommitCanonicalIdentity::from_hash(Hash256::from_bytes(
        bytes,
    )))
}

fn append_identity_field(
    hasher: &mut Sha256,
    field: &[u8],
) -> std::result::Result<(), GitExternalAuthorityError> {
    hasher.update(
        u64::try_from(field.len())
            .map_err(|_| GitExternalAuthorityError::IdentityOverflow)?
            .to_le_bytes(),
    );
    hasher.update(field);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use sha1::Sha1;

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct MemoryBodies {
        bodies: BTreeMap<Hash256, Vec<u8>>,
    }

    impl MemoryBodies {
        fn insert(
            &mut self,
            format: GitObjectFormat,
            kind: ExternalObjectKind,
            body: impl Into<Vec<u8>>,
        ) -> ExternalObjectRecord {
            let body = body.into();
            let oid = hash_object(format, kind, &body);
            let record = ExternalObjectRecord::from_raw(kind, oid, &body).unwrap();
            self.bodies.insert(record.body_hash, body);
            record
        }
    }

    impl GitObjectBodyLoader for MemoryBodies {
        type Error = Infallible;

        fn load_body(
            &mut self,
            body_hash: &Hash256,
        ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.bodies.get(body_hash).cloned())
        }
    }

    #[derive(Clone)]
    struct Fixture {
        authority: GitExternalAuthority,
        bodies: MemoryBodies,
        records: Vec<ExternalObjectRecord>,
        tree: ExternalObjectRecord,
        parent: ExternalObjectRecord,
        head: ExternalObjectRecord,
        gitlink_oid: GitObjectId,
    }

    fn fixture(format: GitObjectFormat) -> Fixture {
        let mut bodies = MemoryBodies::default();
        let compose = bodies.insert(
            format,
            ExternalObjectKind::Blob,
            b"services:\n  api:\n    build: .\n".to_vec(),
        );
        let binary = bodies.insert(format, ExternalObjectKind::Blob, vec![0, 0xff, 0x80, b'\n']);
        let gitlink_oid = repeated_oid(format, 0x77);
        let tree = bodies.insert(
            format,
            ExternalObjectKind::Tree,
            tree_body(&[
                (b"compose.yaml", b"100644", compose.object.oid),
                (b"payload.bin", b"100755", binary.object.oid),
                (b"vendor", b"160000", gitlink_oid),
                (&[0xff], b"100644", binary.object.oid),
            ]),
        );
        let parent = bodies.insert(
            format,
            ExternalObjectKind::Commit,
            commit_body(tree.object.oid, &[], b"parent"),
        );
        let head = bodies.insert(
            format,
            ExternalObjectKind::Commit,
            commit_body(tree.object.oid, &[parent.object.oid], b"head"),
        );
        let records = vec![
            binary.clone(),
            head.clone(),
            tree.clone(),
            compose,
            parent.clone(),
        ];
        let main = RefName::branch(b"main").unwrap();
        let mut loader = bodies.clone();
        let authority = GitExternalAuthority::from_raw_parts(
            RepositoryId::new("repo").unwrap(),
            format,
            vec![
                GitRawRef {
                    name: main.clone(),
                    target: direct(head.object),
                },
                GitRawRef {
                    name: RefName::from_bytes(b"refs/aliases/stable".to_vec()).unwrap(),
                    target: GitRawTarget::Symbolic {
                        target: main.clone(),
                    },
                },
            ],
            GitRawTarget::Symbolic { target: main },
            records.clone(),
            &mut loader,
        )
        .unwrap();
        Fixture {
            authority,
            bodies,
            records,
            tree,
            parent,
            head,
            gitlink_oid,
        }
    }

    fn direct(object: ExternalObjectId) -> GitRawTarget {
        GitRawTarget::Direct { object }
    }

    fn repeated_oid(format: GitObjectFormat, byte: u8) -> GitObjectId {
        match format {
            GitObjectFormat::Sha1 => GitObjectId::sha1([byte; 20]),
            GitObjectFormat::Sha256 => GitObjectId::sha256([byte; 32]),
        }
    }

    fn hash_object(format: GitObjectFormat, kind: ExternalObjectKind, body: &[u8]) -> GitObjectId {
        let mut envelope = Vec::new();
        envelope.extend_from_slice(kind.git_header());
        envelope.push(b' ');
        envelope.extend_from_slice(body.len().to_string().as_bytes());
        envelope.push(0);
        envelope.extend_from_slice(body);
        match format {
            GitObjectFormat::Sha1 => {
                let digest = Sha1::digest(&envelope);
                let mut bytes = [0_u8; 20];
                bytes.copy_from_slice(&digest);
                GitObjectId::sha1(bytes)
            }
            GitObjectFormat::Sha256 => {
                let digest = Sha256::digest(&envelope);
                let mut bytes = [0_u8; 32];
                bytes.copy_from_slice(&digest);
                GitObjectId::sha256(bytes)
            }
        }
    }

    fn tree_body(entries: &[(&[u8], &[u8], GitObjectId)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, mode, oid) in entries {
            body.extend_from_slice(mode);
            body.push(b' ');
            body.extend_from_slice(name);
            body.push(0);
            body.extend_from_slice(oid.as_bytes());
        }
        body
    }

    fn commit_body(tree: GitObjectId, parents: &[GitObjectId], message: &[u8]) -> Vec<u8> {
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

    fn tag_body(target: ExternalObjectId, name: &[u8]) -> Vec<u8> {
        let mut body = format!(
            "object {}\ntype {}\ntag ",
            target.oid,
            std::str::from_utf8(target.kind.git_header()).unwrap()
        )
        .into_bytes();
        body.extend_from_slice(name);
        body.extend_from_slice(b"\n\nexact tag");
        body
    }

    fn direct_authority(
        format: GitObjectFormat,
        records: Vec<ExternalObjectRecord>,
        target: ExternalObjectId,
        bodies: &MemoryBodies,
    ) -> std::result::Result<GitExternalAuthority, GitExternalAuthorityError> {
        let mut loader = bodies.clone();
        GitExternalAuthority::from_raw_parts(
            RepositoryId::new("direct").unwrap(),
            format,
            Vec::new(),
            direct(target),
            records,
            &mut loader,
        )
    }

    fn validation_error(
        authority: &GitExternalAuthority,
        bodies: &MemoryBodies,
    ) -> GitExternalAuthorityError {
        let mut loader = bodies.clone();
        authority
            .validate_with_body_loader(&mut loader)
            .unwrap_err()
    }

    #[test]
    fn sha1_and_sha256_authority_roundtrip_exact_objects_and_gitlink_leaf() {
        for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
            let fixture = fixture(format);
            let mut loader = fixture.bodies.clone();
            fixture
                .authority
                .validate_with_body_loader(&mut loader)
                .unwrap();
            assert_eq!(
                fixture.authority.schema_version,
                GIT_EXTERNAL_AUTHORITY_SCHEMA_VERSION
            );
            assert_eq!(fixture.authority.object_format, format);
            assert_eq!(fixture.authority.raw_refs.len(), 2);
            assert_eq!(fixture.authority.closure.roots.len(), 3);
            assert_eq!(
                fixture.authority.closure.objects.len(),
                fixture.records.len()
            );
            assert!(!fixture
                .authority
                .closure
                .objects
                .iter()
                .any(|entry| entry.record.object.oid == fixture.gitlink_oid));

            let tree = fixture
                .authority
                .closure
                .objects
                .iter()
                .find(|entry| entry.record.object == fixture.tree.object)
                .unwrap();
            assert!(tree.dependencies.iter().any(|dependency| {
                matches!(
                    dependency.kind,
                    GitObjectDependencyKind::TreeEntry {
                        mode: GitTreeEntryMode::Gitlink,
                        ..
                    }
                ) && dependency.target.oid == fixture.gitlink_oid
                    && !dependency.requires_closure_object()
            }));
            assert!(tree.dependencies.iter().any(|dependency| {
                matches!(
                    &dependency.kind,
                    GitObjectDependencyKind::TreeEntry { name, .. }
                        if name.as_bytes() == [0xff]
                )
            }));

            assert!(matches!(
                fixture.authority.material_head,
                GitMaterialHead::Commit {
                    direct_target,
                    ref tag_chain,
                    commit_oid,
                    raw_tree_oid,
                } if direct_target == fixture.head.object
                    && tag_chain.is_empty()
                    && commit_oid == fixture.head.object.oid
                    && raw_tree_oid == fixture.tree.object.oid
            ));

            let encoded = serde_json::to_vec(&fixture.authority).unwrap();
            let decoded: GitExternalAuthority = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(decoded, fixture.authority);
            let mut loader = fixture.bodies.clone();
            decoded.validate_with_body_loader(&mut loader).unwrap();
        }
    }

    #[test]
    fn tag_chain_keeps_raw_detached_head_distinct_from_material_commit() {
        for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
            let mut fixture = fixture(format);
            let inner = fixture.bodies.insert(
                format,
                ExternalObjectKind::Tag,
                tag_body(fixture.head.object, b"inner"),
            );
            let outer = fixture.bodies.insert(
                format,
                ExternalObjectKind::Tag,
                tag_body(inner.object, b"outer"),
            );
            fixture.records.extend([inner.clone(), outer.clone()]);
            let tag_ref = RefName::tag(b"release").unwrap();
            let mut loader = fixture.bodies.clone();
            let authority = GitExternalAuthority::from_raw_parts(
                RepositoryId::new("tags").unwrap(),
                format,
                vec![GitRawRef {
                    name: tag_ref,
                    target: direct(outer.object),
                }],
                direct(outer.object),
                fixture.records,
                &mut loader,
            )
            .unwrap();

            assert_eq!(authority.raw_head, direct(outer.object));
            assert!(matches!(
                authority.material_head,
                GitMaterialHead::Commit {
                    direct_target,
                    ref tag_chain,
                    commit_oid,
                    raw_tree_oid,
                } if direct_target == outer.object
                    && tag_chain == &[outer.object, inner.object]
                    && commit_oid == fixture.head.object.oid
                    && raw_tree_oid == fixture.tree.object.oid
            ));
            authority.validate_with_body_loader(&mut loader).unwrap();
        }
    }

    #[test]
    fn detached_tag_to_blob_remains_explicitly_non_materializable() {
        let format = GitObjectFormat::Sha256;
        let mut bodies = MemoryBodies::default();
        let blob = bodies.insert(
            format,
            ExternalObjectKind::Blob,
            b"not a workspace".to_vec(),
        );
        let tag = bodies.insert(
            format,
            ExternalObjectKind::Tag,
            tag_body(blob.object, b"blob-tag"),
        );
        let authority =
            direct_authority(format, vec![tag.clone(), blob.clone()], tag.object, &bodies).unwrap();

        assert_eq!(authority.raw_head, direct(tag.object));
        assert_eq!(authority.commit_projections, Vec::new());
        assert_eq!(
            authority.material_head,
            GitMaterialHead::NonMaterializable {
                direct_target: tag.object,
                tag_chain: vec![tag.object],
                peeled_target: blob.object,
            }
        );
        let mut loader = bodies;
        authority.validate_with_body_loader(&mut loader).unwrap();
    }

    #[test]
    fn symbolic_unborn_head_has_no_object_or_workspace_claim() {
        let main = RefName::branch(b"future").unwrap();
        let mut bodies = MemoryBodies::default();
        let authority = GitExternalAuthority::from_raw_parts(
            RepositoryId::new("unborn").unwrap(),
            GitObjectFormat::Sha1,
            Vec::new(),
            GitRawTarget::Symbolic {
                target: main.clone(),
            },
            Vec::new(),
            &mut bodies,
        )
        .unwrap();
        assert_eq!(
            authority.material_head,
            GitMaterialHead::Unborn { missing_ref: main }
        );
        assert!(authority.closure.roots.is_empty());
        assert!(authority.closure.objects.is_empty());
        assert!(authority.commit_projections.is_empty());
    }

    #[test]
    fn missing_commit_tree_parent_and_tree_blob_fail_closed() {
        let format = GitObjectFormat::Sha1;

        let mut missing_tree_bodies = MemoryBodies::default();
        let missing_tree = repeated_oid(format, 0x31);
        let commit = missing_tree_bodies.insert(
            format,
            ExternalObjectKind::Commit,
            commit_body(missing_tree, &[], b"missing tree"),
        );
        let error = direct_authority(
            format,
            vec![commit.clone()],
            commit.object,
            &missing_tree_bodies,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            GitExternalAuthorityError::MissingDependency {
                target: ExternalObjectId {
                    kind: ExternalObjectKind::Tree,
                    oid,
                },
                ..
            } if oid == missing_tree
        ));

        let mut missing_parent_bodies = MemoryBodies::default();
        let tree = missing_parent_bodies.insert(format, ExternalObjectKind::Tree, Vec::<u8>::new());
        let missing_parent = repeated_oid(format, 0x32);
        let commit = missing_parent_bodies.insert(
            format,
            ExternalObjectKind::Commit,
            commit_body(tree.object.oid, &[missing_parent], b"missing parent"),
        );
        let error = direct_authority(
            format,
            vec![tree, commit.clone()],
            commit.object,
            &missing_parent_bodies,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            GitExternalAuthorityError::MissingDependency {
                target: ExternalObjectId {
                    kind: ExternalObjectKind::Commit,
                    oid,
                },
                ..
            } if oid == missing_parent
        ));

        let mut missing_blob_bodies = MemoryBodies::default();
        let missing_blob = repeated_oid(format, 0x33);
        let tree = missing_blob_bodies.insert(
            format,
            ExternalObjectKind::Tree,
            tree_body(&[(b"compose.yaml", b"100644", missing_blob)]),
        );
        let commit = missing_blob_bodies.insert(
            format,
            ExternalObjectKind::Commit,
            commit_body(tree.object.oid, &[], b"missing blob"),
        );
        let error = direct_authority(
            format,
            vec![commit.clone(), tree],
            commit.object,
            &missing_blob_bodies,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            GitExternalAuthorityError::MissingDependency {
                target: ExternalObjectId {
                    kind: ExternalObjectKind::Blob,
                    oid,
                },
                ..
            } if oid == missing_blob
        ));
    }

    #[test]
    fn wrong_dependency_kind_and_mixed_hash_format_fail_before_body_use() {
        let format = GitObjectFormat::Sha1;
        let mut bodies = MemoryBodies::default();
        let tree = bodies.insert(format, ExternalObjectKind::Tree, Vec::<u8>::new());
        let commit = bodies.insert(
            format,
            ExternalObjectKind::Commit,
            commit_body(tree.object.oid, &[], b"wrong kind"),
        );
        let mut authority = direct_authority(
            format,
            vec![tree.clone(), commit.clone()],
            commit.object,
            &bodies,
        )
        .unwrap();
        authority
            .closure
            .objects
            .iter_mut()
            .find(|entry| entry.record.object == tree.object)
            .unwrap()
            .record
            .object
            .kind = ExternalObjectKind::Blob;
        assert!(matches!(
            validation_error(&authority, &bodies),
            GitExternalAuthorityError::WrongDependencyKind {
                expected: ExternalObjectKind::Tree,
                actual: ExternalObjectKind::Blob,
                ..
            }
        ));

        let mut authority = fixture(format).authority;
        authority
            .closure
            .objects
            .iter_mut()
            .find(|entry| entry.record.object.kind == ExternalObjectKind::Commit)
            .unwrap()
            .dependencies[0]
            .target
            .oid = repeated_oid(GitObjectFormat::Sha256, 0x44);
        assert!(matches!(
            validation_error(&authority, &fixture(format).bodies),
            GitExternalAuthorityError::MixedObjectFormat { .. }
        ));
    }

    #[test]
    fn zero_padded_tree_modes_are_admitted_without_rewriting_the_body() {
        for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
            let mut bodies = MemoryBodies::default();
            let leaf = bodies.insert(format, ExternalObjectKind::Blob, b"legacy\n".to_vec());
            let child = bodies.insert(
                format,
                ExternalObjectKind::Tree,
                tree_body(&[(b"page.txt", b"100644", leaf.object.oid)]),
            );
            // Pre-2010 and CVS/SVN-imported history spells directories "040000"
            // where canonical Git spells "40000", and pads file modes likewise.
            // Git admits both and reports them only under `fsck --strict`.
            let padded_body = tree_body(&[
                (b"docs", b"040000", child.object.oid),
                (b"setup.py", b"0100644", leaf.object.oid),
            ]);
            let padded = bodies.insert(format, ExternalObjectKind::Tree, padded_body.clone());

            let decoded = decode_git_external_object(format, &padded, &padded_body).unwrap();
            assert_eq!(
                decoded.dependencies,
                vec![
                    GitObjectDependency {
                        kind: GitObjectDependencyKind::TreeEntry {
                            position: 0,
                            mode: GitTreeEntryMode::Tree,
                            name: GitTreeEntryName::from_bytes(b"docs".to_vec()).unwrap(),
                        },
                        target: ExternalObjectId::new(ExternalObjectKind::Tree, child.object.oid),
                    },
                    GitObjectDependency {
                        kind: GitObjectDependencyKind::TreeEntry {
                            position: 1,
                            mode: GitTreeEntryMode::Blob,
                            name: GitTreeEntryName::from_bytes(b"setup.py".to_vec()).unwrap(),
                        },
                        target: ExternalObjectId::new(ExternalObjectKind::Blob, leaf.object.oid),
                    },
                ]
            );

            // Admission binds the exact admitted bytes and nothing else: the
            // canonically respelled tree is a different object, so a rewrite on
            // the way in could never pass the record's own identity check.
            assert_eq!(usize::try_from(padded.body_len).unwrap(), padded_body.len());
            let canonical_body = tree_body(&[
                (b"docs", b"40000", child.object.oid),
                (b"setup.py", b"100644", leaf.object.oid),
            ]);
            assert_ne!(canonical_body, padded_body);
            assert!(ExternalObjectRecord::from_raw(
                ExternalObjectKind::Tree,
                padded.object.oid,
                &canonical_body,
            )
            .is_err());

            // The whole authority admits, which is the path `kin init` takes.
            let commit = bodies.insert(
                format,
                ExternalObjectKind::Commit,
                commit_body(padded.object.oid, &[], b"legacy import"),
            );
            let authority = direct_authority(
                format,
                vec![leaf, child, padded, commit.clone()],
                commit.object,
                &bodies,
            )
            .unwrap();
            let mut loader = bodies.clone();
            authority.validate_with_body_loader(&mut loader).unwrap();
        }
    }

    #[test]
    fn malformed_tree_modes_names_duplicates_and_order_fail_closed() {
        let format = GitObjectFormat::Sha1;
        let target = repeated_oid(format, 0x51);
        let cases = [
            tree_body(&[(b"file", b"100664", target)]),
            tree_body(&[(b"file", b"100645", target)]),
            tree_body(&[(b"file", b"999999", target)]),
            // gix parses this to the same value it uses for a padded "040000",
            // so only the admitted bytes can tell the two apart.
            tree_body(&[(b"dir", b"140000", target)]),
            tree_body(&[(b"", b"100644", target)]),
            tree_body(&[(b"a/b", b"100644", target)]),
            tree_body(&[(b".", b"100644", target)]),
            tree_body(&[(b".GIT", b"100644", target)]),
            tree_body(&[(b"vendor", b"160000", repeated_oid(GitObjectFormat::Sha1, 0))]),
            [
                tree_body(&[(b"file", b"100644", target)]),
                b"100644 truncated".to_vec(),
            ]
            .concat(),
        ];
        for body in cases {
            let mut bodies = MemoryBodies::default();
            let record = bodies.insert(format, ExternalObjectKind::Tree, body.clone());
            assert!(
                decode_git_external_object(format, &record, &body).is_err(),
                "malformed tree body unexpectedly decoded: {body:?}"
            );
        }

        // A literal `140000` decodes to the same mode value as a zero-padded
        // directory, so its refusal has to come from the admitted bytes rather
        // than from the decoded mode.
        let literal_body = tree_body(&[(b"dir", b"140000", target)]);
        let mut literal_bodies = MemoryBodies::default();
        let literal = literal_bodies.insert(format, ExternalObjectKind::Tree, literal_body.clone());
        assert!(matches!(
            decode_git_external_object(format, &literal, &literal_body),
            Err(GitExternalAuthorityError::InvalidObject { reason, .. })
                if reason == "noncanonical tree-entry mode encoding"
        ));

        let duplicate_body = tree_body(&[
            (b"same", b"100644", target),
            (b"same", b"100755", repeated_oid(format, 0x52)),
        ]);
        let mut bodies = MemoryBodies::default();
        let duplicate = bodies.insert(format, ExternalObjectKind::Tree, duplicate_body.clone());
        assert!(matches!(
            decode_git_external_object(format, &duplicate, &duplicate_body),
            Err(GitExternalAuthorityError::DuplicateTreeEntryName { .. })
        ));

        let unordered_body = tree_body(&[
            (b"z", b"100644", target),
            (b"a", b"100644", repeated_oid(format, 0x53)),
        ]);
        let unordered = bodies.insert(format, ExternalObjectKind::Tree, unordered_body.clone());
        assert!(matches!(
            decode_git_external_object(format, &unordered, &unordered_body),
            Err(GitExternalAuthorityError::NonCanonicalTreeOrder { .. })
        ));
    }

    #[test]
    fn declared_tag_cycles_fail_before_noncanonical_bodies_can_hide_them() {
        let mut fixture = fixture(GitObjectFormat::Sha1);
        let inner = fixture.bodies.insert(
            GitObjectFormat::Sha1,
            ExternalObjectKind::Tag,
            tag_body(fixture.head.object, b"inner"),
        );
        let outer = fixture.bodies.insert(
            GitObjectFormat::Sha1,
            ExternalObjectKind::Tag,
            tag_body(inner.object, b"outer"),
        );
        fixture.records.extend([inner.clone(), outer.clone()]);
        let mut authority = direct_authority(
            GitObjectFormat::Sha1,
            fixture.records,
            outer.object,
            &fixture.bodies,
        )
        .unwrap();
        authority
            .closure
            .objects
            .iter_mut()
            .find(|entry| entry.record.object == inner.object)
            .unwrap()
            .dependencies[0]
            .target = outer.object;
        assert!(matches!(
            validation_error(&authority, &fixture.bodies),
            GitExternalAuthorityError::TagCycle { .. }
        ));
    }

    #[test]
    fn duplicate_refs_objects_kinds_paths_and_positions_fail_closed() {
        let fixture = fixture(GitObjectFormat::Sha1);
        let duplicated_ref = fixture.authority.raw_refs[0].clone();
        let mut loader = fixture.bodies.clone();
        assert!(matches!(
            GitExternalAuthority::from_raw_parts(
                RepositoryId::new("duplicate-ref").unwrap(),
                GitObjectFormat::Sha1,
                vec![duplicated_ref.clone(), duplicated_ref],
                fixture.authority.raw_head.clone(),
                fixture.records.clone(),
                &mut loader,
            ),
            Err(GitExternalAuthorityError::DuplicateRawRef { .. })
        ));

        let mut duplicate_records = fixture.records.clone();
        duplicate_records.push(fixture.head.clone());
        assert!(matches!(
            direct_authority(
                GitObjectFormat::Sha1,
                duplicate_records,
                fixture.head.object,
                &fixture.bodies,
            ),
            Err(GitExternalAuthorityError::DuplicateObject { .. })
        ));

        let mut kind_collision = fixture.head.clone();
        kind_collision.object.kind = ExternalObjectKind::Tree;
        let mut collision_records = fixture.records.clone();
        collision_records.push(kind_collision);
        assert!(matches!(
            direct_authority(
                GitObjectFormat::Sha1,
                collision_records,
                fixture.head.object,
                &fixture.bodies,
            ),
            Err(GitExternalAuthorityError::DuplicateObjectKind { .. })
        ));

        let mut duplicate_path = fixture.authority.clone();
        let tree = duplicate_path
            .closure
            .objects
            .iter_mut()
            .find(|entry| entry.record.object == fixture.tree.object)
            .unwrap();
        let first_name = match &tree.dependencies[0].kind {
            GitObjectDependencyKind::TreeEntry { name, .. } => name.clone(),
            _ => unreachable!(),
        };
        match &mut tree.dependencies[1].kind {
            GitObjectDependencyKind::TreeEntry { name, .. } => *name = first_name,
            _ => unreachable!(),
        }
        assert!(matches!(
            validation_error(&duplicate_path, &fixture.bodies),
            GitExternalAuthorityError::NonCanonicalDependencies { .. }
        ));

        let mut duplicate_position = fixture.authority;
        let tree = duplicate_position
            .closure
            .objects
            .iter_mut()
            .find(|entry| entry.record.object == fixture.tree.object)
            .unwrap();
        match &mut tree.dependencies[1].kind {
            GitObjectDependencyKind::TreeEntry { position, .. } => *position = 0,
            _ => unreachable!(),
        }
        assert!(matches!(
            validation_error(&duplicate_position, &fixture.bodies),
            GitExternalAuthorityError::NonCanonicalDependencies { .. }
        ));
    }

    #[test]
    fn missing_extra_and_noncanonical_closure_state_fail_closed() {
        let fixture = fixture(GitObjectFormat::Sha1);

        let mut extra_bodies = fixture.bodies.clone();
        let extra = extra_bodies.insert(
            GitObjectFormat::Sha1,
            ExternalObjectKind::Blob,
            b"unreachable".to_vec(),
        );
        let mut extra_records = fixture.records.clone();
        extra_records.push(extra);
        assert!(matches!(
            direct_authority(
                GitObjectFormat::Sha1,
                extra_records,
                fixture.head.object,
                &extra_bodies,
            ),
            Err(GitExternalAuthorityError::ExtraObject { .. })
        ));

        let mut raw_refs = fixture.authority.clone();
        raw_refs.raw_refs.reverse();
        assert!(matches!(
            validation_error(&raw_refs, &fixture.bodies),
            GitExternalAuthorityError::NonCanonicalRawRefs
        ));

        let mut roots = fixture.authority.clone();
        roots.closure.roots.reverse();
        assert!(matches!(
            validation_error(&roots, &fixture.bodies),
            GitExternalAuthorityError::NonCanonicalRoots
        ));

        let mut objects = fixture.authority.clone();
        objects.closure.objects.reverse();
        assert!(matches!(
            validation_error(&objects, &fixture.bodies),
            GitExternalAuthorityError::NonCanonicalObjects
        ));

        let mut dependencies = fixture.authority.clone();
        dependencies
            .closure
            .objects
            .iter_mut()
            .find(|entry| entry.record.object.kind == ExternalObjectKind::Blob)
            .unwrap()
            .dependencies
            .push(GitObjectDependency {
                kind: GitObjectDependencyKind::TagTarget,
                target: fixture.head.object,
            });
        assert!(matches!(
            validation_error(&dependencies, &fixture.bodies),
            GitExternalAuthorityError::NonCanonicalDependencies { .. }
        ));

        let mut projections = fixture.authority;
        projections.commit_projections.reverse();
        assert!(matches!(
            validation_error(&projections, &fixture.bodies),
            GitExternalAuthorityError::NonCanonicalCommitProjections
        ));
    }

    #[test]
    fn exact_ordered_and_repeated_commit_parents_bind_canonical_identity() {
        let format = GitObjectFormat::Sha256;
        let mut bodies = MemoryBodies::default();
        let tree = bodies.insert(format, ExternalObjectKind::Tree, Vec::<u8>::new());
        let first = bodies.insert(
            format,
            ExternalObjectKind::Commit,
            commit_body(tree.object.oid, &[], b"first"),
        );
        let second = bodies.insert(
            format,
            ExternalObjectKind::Commit,
            commit_body(tree.object.oid, &[], b"second"),
        );
        let expected_parents = vec![second.object.oid, first.object.oid, second.object.oid];
        let merge = bodies.insert(
            format,
            ExternalObjectKind::Commit,
            commit_body(tree.object.oid, &expected_parents, b"octopus"),
        );
        let mut authority = direct_authority(
            format,
            vec![tree, first, second, merge.clone()],
            merge.object,
            &bodies,
        )
        .unwrap();
        let projection = authority
            .commit_projections
            .iter()
            .find(|projection| projection.commit_oid == merge.object.oid)
            .unwrap();
        assert_eq!(projection.parent_oids, expected_parents);
        let original_identity = projection.canonical_identity;
        assert_eq!(
            original_identity.to_string(),
            "819ce93898f4f2f1dd76bce1139631b36499fb1d3055383f9022c16d7488f2bd",
            "v2 commit projection identity is schema-pinned"
        );

        let projection = authority
            .commit_projections
            .iter_mut()
            .find(|projection| projection.commit_oid == merge.object.oid)
            .unwrap();
        projection.parent_oids.swap(0, 1);
        assert_eq!(projection.canonical_identity, original_identity);
        assert!(matches!(
            validation_error(&authority, &bodies),
            GitExternalAuthorityError::NonCanonicalCommitProjections
        ));
    }

    #[test]
    fn material_head_commit_fields_and_identity_are_independently_checked() {
        let fixture = fixture(GitObjectFormat::Sha1);
        let mut material = fixture.authority.clone();
        match &mut material.material_head {
            GitMaterialHead::Commit { raw_tree_oid, .. } => {
                *raw_tree_oid = repeated_oid(GitObjectFormat::Sha1, 0x99)
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            validation_error(&material, &fixture.bodies),
            GitExternalAuthorityError::NonCanonicalMaterialHead
        ));

        let mut identity = fixture.authority;
        identity.commit_projections[0].canonical_identity =
            GitCommitCanonicalIdentity::from_hash(Hash256::from_bytes([0xff; 32]));
        assert!(matches!(
            validation_error(&identity, &fixture.bodies),
            GitExternalAuthorityError::NonCanonicalCommitProjections
        ));
    }

    #[test]
    fn authority_delta_initial_update_removal_and_inverse_are_exact() {
        let fixture = fixture(GitObjectFormat::Sha1);
        let old = fixture.authority;
        let mut loader = fixture.bodies.clone();
        let new = GitExternalAuthority::from_raw_parts(
            old.repository_id.clone(),
            old.object_format,
            old.raw_refs.clone(),
            direct(fixture.head.object),
            fixture.records,
            &mut loader,
        )
        .unwrap();
        assert_ne!(old, new);

        let initialize = GitExternalAuthorityDelta::initialize(old.clone());
        initialize.validate().unwrap();
        assert_eq!(
            initialize.repository_id(),
            Some(&RepositoryId::new("repo").unwrap())
        );
        let removal = initialize.inverse();
        assert_eq!(removal, GitExternalAuthorityDelta::remove(old.clone()));
        removal.validate().unwrap();
        assert_eq!(removal.inverse(), initialize);

        let update = GitExternalAuthorityDelta::update(old.clone(), new.clone());
        update.validate().unwrap();
        update
            .validate_for_repository(&RepositoryId::new("repo").unwrap())
            .unwrap();
        let inverse = update.inverse();
        inverse.validate().unwrap();
        assert_eq!(
            inverse,
            GitExternalAuthorityDelta::update(new.clone(), old.clone())
        );
        assert_eq!(inverse.inverse(), update);

        let encoded = serde_json::to_vec(&update).unwrap();
        assert_eq!(
            serde_json::from_slice::<GitExternalAuthorityDelta>(&encoded).unwrap(),
            update
        );
    }

    #[test]
    fn authority_delta_rejects_empty_noop_mixed_identity_and_malformed_sides() {
        let sha1 = fixture(GitObjectFormat::Sha1).authority;
        let sha256 = fixture(GitObjectFormat::Sha256).authority;

        assert!(matches!(
            GitExternalAuthorityDelta {
                old: None,
                new: None,
            }
            .validate(),
            Err(GitExternalAuthorityError::EmptyDelta)
        ));
        assert!(matches!(
            GitExternalAuthorityDelta::update(sha1.clone(), sha1.clone()).validate(),
            Err(GitExternalAuthorityError::NoOpDelta)
        ));

        let mut other_repository = sha1.clone();
        other_repository.repository_id = RepositoryId::new("other").unwrap();
        assert!(matches!(
            GitExternalAuthorityDelta::update(sha1.clone(), other_repository).validate(),
            Err(GitExternalAuthorityError::DeltaRepositoryMismatch { .. })
        ));
        assert!(matches!(
            GitExternalAuthorityDelta::update(sha1.clone(), sha256).validate(),
            Err(GitExternalAuthorityError::DeltaObjectFormatMismatch { .. })
        ));
        assert!(matches!(
            GitExternalAuthorityDelta::initialize(sha1.clone())
                .validate_for_repository(&RepositoryId::new("other").unwrap()),
            Err(GitExternalAuthorityError::EnclosingRepositoryMismatch { .. })
        ));

        let mut malformed = sha1;
        malformed.commit_projections[0].canonical_identity =
            GitCommitCanonicalIdentity::from_hash(Hash256::from_bytes([0xee; 32]));
        assert!(matches!(
            GitExternalAuthorityDelta::initialize(malformed).validate(),
            Err(GitExternalAuthorityError::NonCanonicalCommitProjections)
        ));
    }

    #[test]
    fn schema_v2_rejects_v1_and_unknown_fields_without_compatibility() {
        let fixture = fixture(GitObjectFormat::Sha1);
        let mut v1 = fixture.authority.clone();
        v1.schema_version = 1;
        assert!(matches!(
            validation_error(&v1, &fixture.bodies),
            GitExternalAuthorityError::UnsupportedSchema {
                actual: 1,
                expected: GIT_EXTERNAL_AUTHORITY_SCHEMA_VERSION,
            }
        ));

        let mut value = serde_json::to_value(&fixture.authority).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("legacy_head".to_string(), serde_json::json!(null));
        assert!(serde_json::from_value::<GitExternalAuthority>(value).is_err());
    }

    #[test]
    fn missing_or_tampered_cas_body_is_rejected() {
        let fixture = fixture(GitObjectFormat::Sha1);
        let mut missing = fixture.bodies.clone();
        missing.bodies.remove(&fixture.head.body_hash);
        assert!(matches!(
            validation_error(&fixture.authority, &missing),
            GitExternalAuthorityError::MissingBody { object }
                if object == fixture.head.object
        ));

        let mut tampered = fixture.bodies;
        tampered
            .bodies
            .insert(fixture.parent.body_hash, b"not the commit".to_vec());
        assert!(matches!(
            validation_error(&fixture.authority, &tampered),
            GitExternalAuthorityError::InvalidObject { object, .. }
                if object == fixture.parent.object
        ));
    }
}
