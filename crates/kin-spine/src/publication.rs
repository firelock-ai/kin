// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cursor-bound durable spine publications.
//!
//! A publication is immutable and content addressed. Durable stores stage its
//! rows before one repository head compare-and-swap makes them visible. The
//! source cursor is deliberately independent of `kin-db` so the spine storage
//! crate does not absorb the graph database's full API surface.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::backend::SpineError;
use crate::index::{CrossRepoEdge, EntityEntry};

/// Version of the durable publication manifest and its canonical hash domain.
pub const REPO_PUBLICATION_SCHEMA_VERSION: u32 = 2;
pub const SPINE_ROLLOUT_FENCE_SCHEMA: &str = "kin.spine-rollout-fence.v1";
pub const LEGACY_SPINE_WRITER_DRAIN_SCHEMA: &str = "kin.spine-legacy-writer-drain.v1";
const SPINE_ROLLOUT_TOKEN_HASH_DOMAIN: &[u8] = b"kin.spine-rollout-token.v1\0";
const SPINE_ROLLOUT_FENCE_PAYLOAD_HASH_DOMAIN: &[u8] = b"kin.spine-rollout-fence-payload.v1\0";

/// The exact backend generation from which one spine publication was derived.
///
/// This mirrors `kin_db::SnapshotCursor::backend_generation()` without making
/// `kin-spine` depend on the database crate. Generation zero is KinDB's
/// authoritative initial cursor, including a proved-empty initial snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpineSourceCursor(u64);

impl SpineSourceCursor {
    pub const fn from_backend_generation(value: u64) -> Self {
        Self(value)
    }

    pub const fn backend_generation(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SpineSourceCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Exact same-bytes GCS rewrite evidence for one repository in a hosted
/// rollout. The vector containing these rows is canonical by repository id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpineRolloutRepositoryFence {
    pub repo_id: String,
    pub pre_fence_generation: u64,
    pub fenced_generation: u64,
    pub snapshot_schema: u32,
    pub e_tag: Option<String>,
}

/// Durable fleet fence shared by rollout and every spine publication CAS.
///
/// `payload_sha256` is computed over a separate canonical tuple that excludes
/// the digest field itself. `rollout_token_sha256` hashes the exact UTF-8 lease
/// token bytes under its own domain, so neither digest is self-referential or
/// ambiguous with another Kin hash domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpineRolloutFence {
    pub schema: String,
    pub scope: String,
    pub rollout_fence: u64,
    pub rollout_token_sha256: String,
    pub repositories: Vec<SpineRolloutRepositoryFence>,
    pub payload_sha256: String,
}

impl SpineRolloutFence {
    /// Build one canonical fence and require the GCS evidence to cover the exact
    /// expected fleet. Callers pass the full hosted registry, currently five
    /// repositories; a missing, duplicate, or unrelated row fails closed.
    pub fn new_exact(
        scope: String,
        rollout_fence: u64,
        rollout_token: &str,
        expected_repository_ids: &[String],
        mut repositories: Vec<SpineRolloutRepositoryFence>,
    ) -> Result<Self, SpineError> {
        validate_identifier("rollout scope", &scope)?;
        if rollout_fence == 0 {
            return Err(SpineError::Serialization(
                "rollout fence must be positive".to_string(),
            ));
        }
        if rollout_token.is_empty() {
            return Err(SpineError::Serialization(
                "rollout token must be non-empty".to_string(),
            ));
        }
        let mut expected = expected_repository_ids.to_vec();
        for repo_id in &expected {
            validate_identifier("expected rollout repository id", repo_id)?;
        }
        expected.sort();
        if expected.is_empty() || expected.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(SpineError::Serialization(
                "expected rollout repository fleet must be non-empty and unique".to_string(),
            ));
        }
        repositories.sort_by(|left, right| left.repo_id.cmp(&right.repo_id));
        let actual = repositories
            .iter()
            .map(|row| row.repo_id.clone())
            .collect::<Vec<_>>();
        if actual != expected {
            return Err(SpineError::Serialization(format!(
                "rollout fence repository vector does not exactly match the expected fleet: expected {}, observed {}",
                expected.join(", "),
                actual.join(", ")
            )));
        }
        for row in &repositories {
            validate_rollout_repository_fence(row)?;
        }

        let mut token_hasher = Sha256::new();
        token_hasher.update(SPINE_ROLLOUT_TOKEN_HASH_DOMAIN);
        token_hasher.update(rollout_token.as_bytes());
        let rollout_token_sha256 = format!("sha256:{}", hex::encode(token_hasher.finalize()));
        let payload_sha256 = hash_rollout_fence_payload(
            &scope,
            rollout_fence,
            &rollout_token_sha256,
            &repositories,
        )?;
        let fence = Self {
            schema: SPINE_ROLLOUT_FENCE_SCHEMA.to_string(),
            scope,
            rollout_fence,
            rollout_token_sha256,
            repositories,
            payload_sha256,
        };
        fence.validate()?;
        Ok(fence)
    }

    pub(crate) fn validate(&self) -> Result<(), SpineError> {
        if self.schema != SPINE_ROLLOUT_FENCE_SCHEMA {
            return Err(SpineError::Serialization(format!(
                "unsupported spine rollout fence schema {}",
                self.schema
            )));
        }
        validate_identifier("rollout scope", &self.scope)?;
        if self.rollout_fence == 0 || self.repositories.is_empty() {
            return Err(SpineError::Serialization(
                "spine rollout fence must carry a positive fence and non-empty fleet".to_string(),
            ));
        }
        validate_sha256("rollout token digest", "fleet", &self.rollout_token_sha256)?;
        validate_sha256("rollout payload digest", "fleet", &self.payload_sha256)?;
        for row in &self.repositories {
            validate_rollout_repository_fence(row)?;
        }
        if self
            .repositories
            .windows(2)
            .any(|pair| pair[0].repo_id >= pair[1].repo_id)
        {
            return Err(SpineError::Serialization(
                "spine rollout repository vector must be strictly sorted and unique".to_string(),
            ));
        }
        let expected = hash_rollout_fence_payload(
            &self.scope,
            self.rollout_fence,
            &self.rollout_token_sha256,
            &self.repositories,
        )?;
        if self.payload_sha256 != expected {
            return Err(SpineError::Serialization(
                "spine rollout fence payload digest does not match its canonical fields"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn repository(&self, repo_id: &str) -> Option<&SpineRolloutRepositoryFence> {
        self.repositories
            .binary_search_by(|row| row.repo_id.as_str().cmp(repo_id))
            .ok()
            .map(|index| &self.repositories[index])
    }

    /// Revalidate a loaded durable fence against the configured hosted scope
    /// and complete registry. Generic schema validation cannot know that
    /// deployment-specific authority set, so readiness must call this method.
    pub fn validate_exact_fleet(
        &self,
        expected_scope: &str,
        expected_repository_ids: &[String],
    ) -> Result<(), SpineError> {
        self.validate()?;
        if self.scope != expected_scope {
            return Err(SpineError::Backend(format!(
                "active spine rollout scope {} does not match configured scope {expected_scope}",
                self.scope
            )));
        }
        let mut expected = expected_repository_ids.to_vec();
        for repo_id in &expected {
            validate_identifier("expected rollout repository id", repo_id)?;
        }
        expected.sort();
        if expected.is_empty() || expected.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(SpineError::Serialization(
                "configured rollout repository fleet must be non-empty and unique".to_string(),
            ));
        }
        let observed = self
            .repositories
            .iter()
            .map(|row| row.repo_id.clone())
            .collect::<Vec<_>>();
        if observed != expected {
            return Err(SpineError::Backend(format!(
                "active spine rollout fence does not exactly cover configured fleet: expected {}, observed {}",
                expected.join(", "),
                observed.join(", ")
            )));
        }
        Ok(())
    }

    /// Require a publication repository to belong to the exact fenced fleet.
    /// KinDB source cursors and GCS object generations are distinct numeric
    /// domains and must never be compared. The daemon separately re-probes the
    /// KinDB cursor and content root before and after this storage CAS.
    pub(crate) fn validate_publication_repo(&self, repo_id: &str) -> Result<(), SpineError> {
        self.repository(repo_id).ok_or_else(|| {
            SpineError::Backend(format!(
                "repo {repo_id} is absent from active spine rollout fence {}",
                self.payload_sha256
            ))
        })?;
        Ok(())
    }
}

fn validate_rollout_repository_fence(row: &SpineRolloutRepositoryFence) -> Result<(), SpineError> {
    validate_identifier("rollout repository id", &row.repo_id)?;
    if row.snapshot_schema == 0 {
        return Err(SpineError::Serialization(format!(
            "repo {} rollout snapshot schema must be positive",
            row.repo_id
        )));
    }
    if row.pre_fence_generation == 0 || row.fenced_generation == 0 {
        return Err(SpineError::Serialization(format!(
            "repo {} rollout generations must both be nonzero",
            row.repo_id
        )));
    }
    if row.fenced_generation <= row.pre_fence_generation {
        return Err(SpineError::Serialization(format!(
            "repo {} rollout fenced generation {} must advance pre-fence generation {}",
            row.repo_id, row.fenced_generation, row.pre_fence_generation
        )));
    }
    if row
        .e_tag
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.trim() != value)
    {
        return Err(SpineError::Serialization(format!(
            "repo {} rollout e-tag must be canonical when present",
            row.repo_id
        )));
    }
    Ok(())
}

fn hash_rollout_fence_payload(
    scope: &str,
    rollout_fence: u64,
    rollout_token_sha256: &str,
    repositories: &[SpineRolloutRepositoryFence],
) -> Result<String, SpineError> {
    let canonical = serde_json::to_vec(&(
        SPINE_ROLLOUT_FENCE_SCHEMA,
        scope,
        rollout_fence,
        rollout_token_sha256,
        repositories,
    ))
    .map_err(|error| {
        SpineError::Serialization(format!(
            "failed to serialize canonical spine rollout fence payload: {error}"
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(SPINE_ROLLOUT_FENCE_PAYLOAD_HASH_DOMAIN);
    hasher.update(canonical);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Durable evidence persisted into the GCS publication-control record after a
/// Firestore fleet-fence CAS succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpineRolloutFenceEvidence {
    pub rollout_fence: u64,
    pub payload_sha256: String,
    pub update_time: String,
}

/// Trusted deployment evidence required before the one-way legacy migration
/// seal can be created. A fleet fence alone cannot stop an older cursorless
/// binary from writing the legacy collections, so the rollout owner must bind
/// an externally produced old-revision drain proof and the exact deployed
/// daemon image digest to the Firestore fence it admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacySpineWriterDrainAttestation {
    pub schema: String,
    pub rollout_fence_evidence: SpineRolloutFenceEvidence,
    pub daemon_image_sha256: String,
    pub drain_proof_sha256: String,
}

impl LegacySpineWriterDrainAttestation {
    /// Validate the portable drain attestation before a storage backend uses
    /// it to create or verify the durable one-way migration seal.
    pub fn validate(&self) -> Result<(), SpineError> {
        if self.schema != LEGACY_SPINE_WRITER_DRAIN_SCHEMA {
            return Err(SpineError::Serialization(format!(
                "unsupported legacy spine writer-drain schema {}",
                self.schema
            )));
        }
        if self.rollout_fence_evidence.rollout_fence == 0
            || self.rollout_fence_evidence.update_time.is_empty()
        {
            return Err(SpineError::Serialization(
                "legacy spine writer-drain attestation has incomplete rollout evidence".to_string(),
            ));
        }
        validate_sha256(
            "legacy writer-drain rollout payload digest",
            "fleet",
            &self.rollout_fence_evidence.payload_sha256,
        )?;
        validate_sha256(
            "legacy writer-drain daemon image digest",
            "fleet",
            &self.daemon_image_sha256,
        )?;
        validate_sha256(
            "legacy writer-drain proof digest",
            "fleet",
            &self.drain_proof_sha256,
        )?;
        Ok(())
    }
}

/// Outcome of advancing the shared rollout fence.
#[must_use = "rollout fence conflicts must be classified before completing acquisition"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpineRolloutFenceCommit {
    Advanced(SpineRolloutFenceEvidence),
    AlreadyCurrent(SpineRolloutFenceEvidence),
    Conflict {
        attempted_rollout_fence: u64,
        observed: Option<SpineRolloutFenceEvidence>,
    },
}

/// Strength of the durable publication for one source repository.
///
/// Metadata makes entity resolution possible but keeps cross-repo topology
/// incomplete. Edges is a same-cursor upgrade whose outgoing edge set was
/// resolved against the recorded repository roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoPublicationPhase {
    Metadata,
    Edges,
}

/// Complete candidate for one cursor-bound repository publication.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoSpinePublication {
    pub repo_id: String,
    pub source_cursor: SpineSourceCursor,
    pub root_hash: String,
    pub entries: Vec<EntityEntry>,
    /// `None` means metadata-only and therefore explicitly incomplete.
    /// `Some(vec![])` is a complete observed zero for the recorded roots.
    pub outgoing_edges: Option<Vec<CrossRepoEdge>>,
    /// Exact roots against which `outgoing_edges` was resolved.
    pub resolution_roots: Option<BTreeMap<String, String>>,
}

impl RepoSpinePublication {
    pub fn phase(&self) -> RepoPublicationPhase {
        if self.outgoing_edges.is_some() {
            RepoPublicationPhase::Edges
        } else {
            RepoPublicationPhase::Metadata
        }
    }

    pub(crate) fn canonicalize(mut self) -> Result<CanonicalRepoPublication, SpineError> {
        validate_identifier("repository id", &self.repo_id)?;
        validate_identifier("root hash", &self.root_hash)?;

        let mut entity_ids = HashSet::with_capacity(self.entries.len());
        for entry in &self.entries {
            if entry.repo_id != self.repo_id {
                return Err(SpineError::Serialization(format!(
                    "publication for repo {} contains entity {} owned by repo {}",
                    self.repo_id, entry.entity_id, entry.repo_id
                )));
            }
            if !entity_ids.insert(entry.entity_id) {
                return Err(SpineError::Serialization(format!(
                    "publication for repo {} contains duplicate entity {}",
                    self.repo_id, entry.entity_id
                )));
            }
            if !entry.fingerprint.stability_score.is_finite()
                || !(0.0..=1.0).contains(&entry.fingerprint.stability_score)
            {
                return Err(SpineError::Serialization(format!(
                    "publication for repo {} contains entity {} with invalid fingerprint stability {}",
                    self.repo_id, entry.entity_id, entry.fingerprint.stability_score
                )));
            }
        }
        self.entries.sort_by(|left, right| {
            left.entity_id
                .cmp(&right.entity_id)
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.signature.cmp(&right.signature))
        });

        match (&mut self.outgoing_edges, &self.resolution_roots) {
            (None, None) => {}
            (None, Some(_)) => {
                return Err(SpineError::Serialization(format!(
                    "metadata publication for repo {} must not claim resolution roots",
                    self.repo_id
                )));
            }
            (Some(_), None) => {
                return Err(SpineError::Serialization(format!(
                    "edge publication for repo {} is missing resolution roots",
                    self.repo_id
                )));
            }
            (Some(edges), Some(roots)) => {
                if roots.is_empty() || !roots.contains_key(&self.repo_id) {
                    return Err(SpineError::Serialization(format!(
                        "edge publication for repo {} must include its source root",
                        self.repo_id
                    )));
                }
                if roots.get(&self.repo_id) != Some(&self.root_hash) {
                    return Err(SpineError::Serialization(format!(
                        "edge publication for repo {} resolved against a source root different from its entity root",
                        self.repo_id
                    )));
                }
                for (repo_id, root_hash) in roots {
                    validate_identifier("resolution repository id", repo_id)?;
                    validate_identifier("resolution root hash", root_hash)?;
                }

                let mut identities = HashSet::with_capacity(edges.len());
                for edge in edges.iter() {
                    if edge.src_repo != self.repo_id {
                        return Err(SpineError::Serialization(format!(
                            "publication for repo {} contains outgoing edge owned by {}",
                            self.repo_id, edge.src_repo
                        )));
                    }
                    if edge.src_repo == edge.dst_repo {
                        return Err(SpineError::Serialization(format!(
                            "publication for repo {} contains a same-repository edge",
                            self.repo_id
                        )));
                    }
                    if !entity_ids.contains(&edge.src_entity) {
                        return Err(SpineError::Serialization(format!(
                            "publication for repo {} contains edge from unknown source entity {}",
                            self.repo_id, edge.src_entity
                        )));
                    }
                    if !roots.contains_key(&edge.dst_repo) {
                        return Err(SpineError::Serialization(format!(
                            "publication for repo {} contains edge to unwatermarked repo {}",
                            self.repo_id, edge.dst_repo
                        )));
                    }
                    if !edge.confidence.is_finite() || !(0.0..=1.0).contains(&edge.confidence) {
                        return Err(SpineError::Serialization(format!(
                            "publication for repo {} contains invalid edge confidence {}",
                            self.repo_id, edge.confidence
                        )));
                    }
                    let identity = (
                        edge.src_repo.clone(),
                        edge.src_entity,
                        edge.dst_repo.clone(),
                        edge.dst_entity,
                    );
                    if !identities.insert(identity) {
                        return Err(SpineError::Serialization(format!(
                            "publication for repo {} contains a duplicate cross-repo edge",
                            self.repo_id
                        )));
                    }
                }
                edges.sort_by(|left, right| {
                    left.src_repo
                        .cmp(&right.src_repo)
                        .then_with(|| left.src_entity.cmp(&right.src_entity))
                        .then_with(|| left.dst_repo.cmp(&right.dst_repo))
                        .then_with(|| left.dst_entity.cmp(&right.dst_entity))
                        .then_with(|| left.confidence.total_cmp(&right.confidence))
                });
            }
        }

        let metadata_bytes = serde_json::to_vec(&(
            REPO_PUBLICATION_SCHEMA_VERSION,
            &self.repo_id,
            self.source_cursor,
            &self.root_hash,
            &self.entries,
        ))
        .map_err(|error| {
            SpineError::Serialization(format!(
                "failed to serialize spine publication metadata: {error}"
            ))
        })?;
        let metadata_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&metadata_bytes)));
        let manifest_bytes = serde_json::to_vec(&(REPO_PUBLICATION_SCHEMA_VERSION, &self))
            .map_err(|error| {
                SpineError::Serialization(format!("failed to serialize spine publication: {error}"))
            })?;
        let digest = hex::encode(Sha256::digest(&manifest_bytes));
        let head = RepoPublicationHead {
            schema_version: REPO_PUBLICATION_SCHEMA_VERSION,
            repo_id: self.repo_id.clone(),
            source_cursor: self.source_cursor,
            root_hash: self.root_hash.clone(),
            phase: self.phase(),
            publication_id: digest.clone(),
            manifest_sha256: format!("sha256:{digest}"),
            metadata_sha256,
            entity_count: self.entries.len() as u64,
            edge_count: self
                .outgoing_edges
                .as_ref()
                .map_or(0, |edges| edges.len() as u64),
            resolution_roots: self.resolution_roots.clone().unwrap_or_default(),
        };
        Ok(CanonicalRepoPublication {
            publication: self,
            head,
        })
    }
}

fn validate_identifier(what: &str, value: &str) -> Result<(), SpineError> {
    if value.is_empty() || value.trim() != value {
        return Err(SpineError::Serialization(format!(
            "{what} must be non-empty and canonical"
        )));
    }
    Ok(())
}

/// Durable head payload. Only a head reached through the store's CAS is
/// readable authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoPublicationHead {
    pub schema_version: u32,
    pub repo_id: String,
    pub source_cursor: SpineSourceCursor,
    pub root_hash: String,
    pub phase: RepoPublicationPhase,
    pub publication_id: String,
    pub manifest_sha256: String,
    /// Digest of the cursor-bound repo/root/entity domain, independent of the
    /// metadata or edge phase. A same-cursor edge upgrade must retain it.
    pub metadata_sha256: String,
    pub entity_count: u64,
    pub edge_count: u64,
    #[serde(default)]
    pub resolution_roots: BTreeMap<String, String>,
}

impl RepoPublicationHead {
    pub(crate) fn validate(&self) -> Result<(), SpineError> {
        if self.schema_version != REPO_PUBLICATION_SCHEMA_VERSION {
            return Err(SpineError::Serialization(format!(
                "repo {} publication uses unsupported schema version {} instead of {}",
                self.repo_id, self.schema_version, REPO_PUBLICATION_SCHEMA_VERSION
            )));
        }
        validate_identifier("repository id", &self.repo_id)?;
        validate_identifier("root hash", &self.root_hash)?;
        if !is_canonical_sha256_digest(&self.publication_id) {
            return Err(SpineError::Serialization(format!(
                "repo {} has malformed publication id",
                self.repo_id
            )));
        }
        if self.manifest_sha256 != format!("sha256:{}", self.publication_id) {
            return Err(SpineError::Serialization(format!(
                "repo {} publication id and manifest digest disagree",
                self.repo_id
            )));
        }
        validate_sha256("metadata digest", &self.repo_id, &self.metadata_sha256)?;
        match self.phase {
            RepoPublicationPhase::Metadata => {
                if self.edge_count != 0 || !self.resolution_roots.is_empty() {
                    return Err(SpineError::Serialization(format!(
                        "repo {} metadata head claims edge authority",
                        self.repo_id
                    )));
                }
            }
            RepoPublicationPhase::Edges => {
                if self.resolution_roots.is_empty()
                    || !self.resolution_roots.contains_key(&self.repo_id)
                {
                    return Err(SpineError::Serialization(format!(
                        "repo {} edge head is missing resolution roots",
                        self.repo_id
                    )));
                }
                if self.resolution_roots.get(&self.repo_id) != Some(&self.root_hash) {
                    return Err(SpineError::Serialization(format!(
                        "repo {} edge head source root disagrees with its resolution watermark",
                        self.repo_id
                    )));
                }
                for (repo_id, root_hash) in &self.resolution_roots {
                    validate_identifier("resolution repository id", repo_id)?;
                    validate_identifier("resolution root hash", root_hash)?;
                }
            }
        }
        Ok(())
    }
}

fn validate_sha256(what: &str, repo_id: &str, value: &str) -> Result<(), SpineError> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(SpineError::Serialization(format!(
            "repo {repo_id} has malformed {what}"
        )));
    };
    if !is_canonical_sha256_digest(digest) {
        return Err(SpineError::Serialization(format!(
            "repo {repo_id} has malformed {what}"
        )));
    }
    Ok(())
}

fn is_canonical_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone)]
pub(crate) struct CanonicalRepoPublication {
    pub(crate) publication: RepoSpinePublication,
    pub(crate) head: RepoPublicationHead,
}

impl CanonicalRepoPublication {
    pub(crate) fn validate_loaded(
        head: RepoPublicationHead,
        entries: Vec<EntityEntry>,
        outgoing_edges: Vec<CrossRepoEdge>,
    ) -> Result<Self, SpineError> {
        head.validate()?;
        if entries.len() as u64 != head.entity_count {
            return Err(SpineError::Serialization(format!(
                "repo {} publication {} expected {} entities but loaded {}",
                head.repo_id,
                head.publication_id,
                head.entity_count,
                entries.len()
            )));
        }
        if outgoing_edges.len() as u64 != head.edge_count {
            return Err(SpineError::Serialization(format!(
                "repo {} publication {} expected {} edges but loaded {}",
                head.repo_id,
                head.publication_id,
                head.edge_count,
                outgoing_edges.len()
            )));
        }
        let candidate = RepoSpinePublication {
            repo_id: head.repo_id.clone(),
            source_cursor: head.source_cursor,
            root_hash: head.root_hash.clone(),
            entries,
            outgoing_edges: match head.phase {
                RepoPublicationPhase::Metadata => None,
                RepoPublicationPhase::Edges => Some(outgoing_edges),
            },
            resolution_roots: match head.phase {
                RepoPublicationPhase::Metadata => None,
                RepoPublicationPhase::Edges => Some(head.resolution_roots.clone()),
            },
        }
        .canonicalize()?;
        if candidate.head != head {
            return Err(SpineError::Serialization(format!(
                "repo {} publication {} failed manifest validation",
                head.repo_id, head.publication_id
            )));
        }
        Ok(candidate)
    }
}

/// A typed lost-CAS result. The winner's observed cursor is always surfaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoPublicationConflict {
    pub attempted_cursor: SpineSourceCursor,
    pub observed_cursor: Option<SpineSourceCursor>,
    pub observed_publication_id: Option<String>,
    pub observed_phase: Option<RepoPublicationPhase>,
    pub attempted_rollout_fence: Option<u64>,
    pub observed_rollout_fence: Option<u64>,
    pub observed_rollout_payload_sha256: Option<String>,
    pub observed_dependency_repo: Option<String>,
    pub observed_dependency_cursor: Option<SpineSourceCursor>,
    pub observed_dependency_publication_id: Option<String>,
}

impl RepoPublicationConflict {
    /// Classify a failed head compare-and-swap against the store's current
    /// observed head. Public store implementations use this constructor so the
    /// typed result always carries the winner cursor and phase consistently.
    pub fn against(
        attempted_cursor: SpineSourceCursor,
        observed: Option<&RepoPublicationHead>,
    ) -> Self {
        Self {
            attempted_cursor,
            observed_cursor: observed.map(|head| head.source_cursor),
            observed_publication_id: observed.map(|head| head.publication_id.clone()),
            observed_phase: observed.map(|head| head.phase),
            attempted_rollout_fence: None,
            observed_rollout_fence: None,
            observed_rollout_payload_sha256: None,
            observed_dependency_repo: None,
            observed_dependency_cursor: None,
            observed_dependency_publication_id: None,
        }
    }

    pub fn against_dependency(
        attempted_cursor: SpineSourceCursor,
        dependency_repo: &str,
        observed: Option<&RepoPublicationHead>,
    ) -> Self {
        let mut conflict = Self::against(attempted_cursor, None);
        conflict.observed_dependency_repo = Some(dependency_repo.to_string());
        conflict.observed_dependency_cursor = observed.map(|head| head.source_cursor);
        conflict.observed_dependency_publication_id =
            observed.map(|head| head.publication_id.clone());
        conflict
    }

    pub fn against_rollout_fence(
        attempted_cursor: SpineSourceCursor,
        attempted_rollout_fence: u64,
        observed_head: Option<&RepoPublicationHead>,
        observed_fence: Option<&SpineRolloutFence>,
    ) -> Self {
        let mut conflict = Self::against(attempted_cursor, observed_head);
        conflict.attempted_rollout_fence = Some(attempted_rollout_fence);
        conflict.observed_rollout_fence = observed_fence.map(|fence| fence.rollout_fence);
        conflict.observed_rollout_payload_sha256 =
            observed_fence.map(|fence| fence.payload_sha256.clone());
        conflict
    }
}

/// Result of the one atomic repository-head transition.
#[must_use = "a spine publication commit outcome must be classified before reporting success"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoPublicationCommit {
    Committed { source_cursor: SpineSourceCursor },
    AlreadyCommitted { source_cursor: SpineSourceCursor },
    Conflict(RepoPublicationConflict),
}
