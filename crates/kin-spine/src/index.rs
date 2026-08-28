// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-repo entity metadata index.
//!
//! Indexes entity metadata (name, kind, signature, fingerprint) across all
//! registered repos. Provides name-based resolution with fingerprint
//! disambiguation for common names like Config, Error, init.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use hashbrown::HashMap;
use kin_model::{Entity, EntityId, EntityKind, EntityRole, Relation, SemanticFingerprint};
use parking_lot::{Mutex, RwLock};
use sha2::{Digest, Sha256};

use crate::publication::SpineSourceCursor;

/// A repo identifier (matches registry.toml entries).
pub type RepoId = String;

/// Metadata for a single entity in the spine index.
/// Does NOT include entity content/body — just enough for resolution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntityEntry {
    pub repo_id: RepoId,
    pub entity_id: EntityId,
    pub name: String,
    pub kind: EntityKind,
    pub signature: String,
    pub fingerprint: SemanticFingerprint,
    pub file_path: Option<String>,
    /// Entity role (Source, Test, External, etc.). Enables role-based
    /// filtering in federated queries without loading the full entity.
    #[serde(default)]
    pub role: Option<EntityRole>,
}

/// One fully validated durable repository publication ready for an atomic
/// cache-generation replacement.
#[derive(Debug, Clone)]
pub(crate) struct CommittedRepoIndexPublication {
    pub repo_id: String,
    pub entries: Vec<EntityEntry>,
    pub root_hash: String,
    pub source_cursor: SpineSourceCursor,
    pub outgoing_edges: Option<Vec<CrossRepoEdge>>,
    pub resolution_roots: Option<BTreeMap<String, String>>,
}

impl PartialEq for EntityEntry {
    fn eq(&self, other: &Self) -> bool {
        self.repo_id == other.repo_id
            && self.entity_id == other.entity_id
            && self.name == other.name
            && self.kind == other.kind
            && self.signature == other.signature
            && self.fingerprint.algorithm == other.fingerprint.algorithm
            && self.fingerprint.ast_hash == other.fingerprint.ast_hash
            && self.fingerprint.signature_hash == other.fingerprint.signature_hash
            && self.fingerprint.behavior_hash == other.fingerprint.behavior_hash
            && self.fingerprint.equivalence_hash == other.fingerprint.equivalence_hash
            && self.fingerprint.stability_score.to_bits()
                == other.fingerprint.stability_score.to_bits()
            && self.file_path == other.file_path
            && self.role == other.role
    }
}

/// Cross-repo edge linking two entities across repo boundaries.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CrossRepoEdge {
    pub src_repo: RepoId,
    pub src_entity: EntityId,
    pub dst_repo: RepoId,
    pub dst_entity: EntityId,
    /// Confidence in the edge (0.0 - 1.0). Name-only matches get lower
    /// confidence than fingerprint-verified matches.
    pub confidence: f32,
}

/// The exact repository/entity pair for which an xref response was projected.
///
/// Xref payloads may legitimately be empty, so clients cannot infer this anchor
/// from the returned edges. Echoing it prevents a stale or mis-keyed response
/// from certifying absence for a different entity in the same repository.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpineXrefAuthorityAnchor {
    pub repo_id: RepoId,
    pub entity_id: EntityId,
}

/// Versioned wire response for `GET /spine/xref`.
///
/// `edges` remains the canonical topology payload. `entities` is an additive,
/// metadata-only sidecar that lets clients render useful cross-repo references
/// without inventing field names or reading another repository's files.
/// `authority_*` carries the exact graph-authority watermark against which the
/// topology was answered. Older version-1 daemons omitted the additive sidecar
/// and authority fields, so they decode conservatively as incomplete.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpineXrefResponse {
    version: u32,
    pub edges: Vec<CrossRepoEdge>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities: Vec<EntityEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_anchor: Option<SpineXrefAuthorityAnchor>,
    #[serde(default)]
    pub authority_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_revision: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub authority_roots: BTreeMap<RepoId, String>,
}

/// How a spine response's watermark for one repository relates to the caller's
/// live graph root.
///
/// The three cases are separate because they are separate facts about the
/// deployment, and only one of them is a mismatch of anything: an unregistered
/// repository is the ordinary state of a single-repo install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRootState<'a> {
    /// The registered root is exactly the caller's live graph root.
    Matches,
    /// The repository is registered at a root the live graph has advanced past.
    Stale { registered: &'a str },
    /// The spine holds no root for the repository at all.
    Unregistered,
}

impl SpineXrefResponse {
    /// Construct an unwatermarked response.
    ///
    /// This remains available for patch-compatible callers that only have an
    /// edge collection, but it deliberately cannot certify an empty result.
    /// Production daemon routes should use [`Self::from_snapshot`].
    pub fn new(edges: Vec<CrossRepoEdge>, entities: Vec<EntityEntry>) -> Self {
        Self {
            version: crate::SPINE_PAYLOAD_VERSION,
            edges,
            entities,
            authority_anchor: None,
            authority_complete: false,
            authority_revision: None,
            authority_roots: BTreeMap::new(),
        }
    }

    /// Project one entity's xrefs from a single atomic authority snapshot.
    ///
    /// Both topology and the metadata sidecar come from the same spine read.
    /// Completeness also requires that the requested repository belongs to the
    /// snapshot's root watermark; a typo or stale binding must not certify an
    /// empty result against some unrelated repository universe.
    pub fn from_snapshot(
        snapshot: CrossRepoEdgesSnapshot,
        repo_id: &str,
        entity_id: &EntityId,
    ) -> Self {
        let CrossRepoEdgesSnapshot {
            complete,
            revision,
            roots,
            edges,
            entities,
            covered_entities,
            ..
        } = snapshot;
        let edges = edges
            .into_iter()
            .filter(|edge| {
                (edge.src_repo == repo_id && edge.src_entity == *entity_id)
                    || (edge.dst_repo == repo_id && edge.dst_entity == *entity_id)
            })
            .collect::<Vec<_>>();
        let entity_keys = edges
            .iter()
            .flat_map(|edge| {
                [
                    (edge.src_repo.clone(), edge.src_entity),
                    (edge.dst_repo.clone(), edge.dst_entity),
                ]
            })
            .collect::<std::collections::BTreeSet<_>>();
        let entities = entities
            .into_iter()
            .filter(|entity| entity_keys.contains(&(entity.repo_id.clone(), entity.entity_id)))
            .collect();

        Self {
            version: crate::SPINE_PAYLOAD_VERSION,
            edges,
            entities,
            authority_anchor: Some(SpineXrefAuthorityAnchor {
                repo_id: repo_id.to_string(),
                entity_id: *entity_id,
            }),
            authority_complete: complete
                && roots.contains_key(repo_id)
                && covered_entities
                    .get(repo_id)
                    .is_some_and(|entities| entities.contains(entity_id)),
            authority_revision: Some(revision),
            authority_roots: roots,
        }
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    /// Whether this payload can certify an answer for the requested anchor.
    ///
    /// This is intentionally stricter than the wire-level boolean so callers
    /// cannot accidentally ignore the response's query binding.
    pub fn authority_complete_for(&self, repo_id: &str, entity_id: &EntityId) -> bool {
        self.authority_complete
            && self
                .authority_anchor
                .as_ref()
                .is_some_and(|anchor| anchor.repo_id == repo_id && anchor.entity_id == *entity_id)
            && self.authority_roots.contains_key(repo_id)
    }

    /// Whether the response's primary-repo watermark is the exact graph root
    /// held by the caller. A complete spine rooted at an older live/session
    /// graph is stale authority, including for positive rows.
    ///
    /// True only for [`AuthorityRootState::Matches`]. A caller that reports WHY
    /// the spine cannot answer must use [`Self::authority_root_state`] instead:
    /// this boolean collapses "registered at an older root" and "never
    /// registered" into one false, and a caller that then invents a message for
    /// it describes a root mismatch on a repository that has no root to
    /// mismatch.
    pub fn authority_root_matches(&self, repo_id: &str, expected_root: &str) -> bool {
        matches!(
            self.authority_root_state(repo_id, expected_root),
            AuthorityRootState::Matches
        )
    }

    /// How the response's watermark for `repo_id` relates to the caller's live
    /// graph root: the same root, an older one, or no registration at all.
    ///
    /// One implementation of the rule, because two callers (`find_references` on
    /// the MCP surface and `kin xref` on the CLI) each report it to a user, and
    /// two hand-rolled copies of a three-way distinction drift into disagreeing
    /// about what a single-repo install is.
    pub fn authority_root_state<'a>(
        &'a self,
        repo_id: &str,
        expected_root: &str,
    ) -> AuthorityRootState<'a> {
        match self.authority_roots.get(repo_id) {
            Some(root) if root == expected_root => AuthorityRootState::Matches,
            Some(registered) => AuthorityRootState::Stale { registered },
            None => AuthorityRootState::Unregistered,
        }
    }

    /// Decode and version-check an xref response as one shared contract.
    ///
    /// Callers must not index ad-hoc JSON fields: required topology fields and
    /// entity IDs are validated by Serde, while an unsupported version fails
    /// explicitly instead of degrading to an empty cross-repo result.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SpineXrefDecodeError> {
        let response: Self = serde_json::from_slice(bytes)?;
        if response.version != crate::SPINE_PAYLOAD_VERSION {
            return Err(SpineXrefDecodeError::UnsupportedVersion {
                actual: response.version,
                supported: crate::SPINE_PAYLOAD_VERSION,
            });
        }
        if response.authority_complete {
            let valid_anchor = response.authority_anchor.as_ref().is_some_and(|anchor| {
                !anchor.repo_id.is_empty()
                    && anchor.repo_id.trim() == anchor.repo_id
                    && response.authority_roots.contains_key(&anchor.repo_id)
            });
            let valid_revision = response
                .authority_revision
                .as_deref()
                .is_some_and(|revision| {
                    revision.len() == 71
                        && revision.strip_prefix("sha256:").is_some_and(|digest| {
                            digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
                });
            let valid_roots = !response.authority_roots.is_empty()
                && response.authority_roots.iter().all(|(repo, root)| {
                    !repo.is_empty()
                        && repo.trim() == repo
                        && !root.is_empty()
                        && root.trim() == root
                });
            let endpoints_are_watermarked = response.edges.iter().all(|edge| {
                response.authority_roots.contains_key(&edge.src_repo)
                    && response.authority_roots.contains_key(&edge.dst_repo)
            });
            if !valid_anchor || !valid_revision || !valid_roots || !endpoints_are_watermarked {
                return Err(SpineXrefDecodeError::InvalidAuthority(
                    "complete xref authority requires a query anchor, canonical revision, non-empty roots, and watermarked edge endpoints"
                        .to_string(),
                ));
            }
        }
        Ok(response)
    }

    /// Decode an xref response and bind it to the request that produced it.
    ///
    /// Every transport consumer should use this method. Empty responses must
    /// echo the requested anchor; the sole compatibility exception is a
    /// pre-authority v1 payload with non-empty typed edges, which is accepted
    /// only when every edge is incident to the requested anchor and is forced
    /// incomplete. Any unrelated edge is internally inconsistent.
    pub fn from_slice_for(
        bytes: &[u8],
        repo_id: &str,
        entity_id: &EntityId,
    ) -> Result<Self, SpineXrefDecodeError> {
        let mut response = Self::from_slice(bytes)?;
        let anchor_matches = response
            .authority_anchor
            .as_ref()
            .is_some_and(|anchor| anchor.repo_id == repo_id && anchor.entity_id == *entity_id);
        let legacy_incident_positive = response.authority_anchor.is_none()
            && !response.edges.is_empty()
            && !response.authority_complete;
        if !anchor_matches && !legacy_incident_positive {
            return Err(SpineXrefDecodeError::InvalidAuthority(format!(
                "xref response anchor does not match requested repository/entity {repo_id}/{entity_id}"
            )));
        }

        let edges_are_incident = response.edges.iter().all(|edge| {
            (edge.src_repo == repo_id && edge.src_entity == *entity_id)
                || (edge.dst_repo == repo_id && edge.dst_entity == *entity_id)
        });
        if !edges_are_incident {
            return Err(SpineXrefDecodeError::InvalidAuthority(format!(
                "xref response contains an edge unrelated to requested repository/entity {repo_id}/{entity_id}"
            )));
        }

        // Pre-authority v1 payloads can still carry a useful typed positive.
        // Preserve only non-empty incident edges and force them incomplete;
        // an unanchored empty can never certify which query it answered.
        if legacy_incident_positive {
            response.authority_complete = false;
        }

        Ok(response)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpineXrefDecodeError {
    #[error("malformed spine xref response: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("unsupported spine xref response version {actual}; supported version is {supported}")]
    UnsupportedVersion { actual: u32, supported: u32 },
    #[error("invalid spine xref authority: {0}")]
    InvalidAuthority(String),
}

/// One atomic, graph-authoritative view of every cross-repo edge in the spine.
///
/// `roots` is the graph-root watermark for the exact registered repo set and
/// `revision` is a deterministic SHA-256 digest over those roots plus the
/// canonical edge set. `complete` says whether every registered authority root
/// and every returned edge endpoint is covered by a completed graph-native
/// refresh. Durable-store hydration alone never establishes that authority.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CrossRepoEdgesSnapshot {
    pub complete: bool,
    pub revision: String,
    pub repos: Vec<RepoId>,
    pub roots: BTreeMap<RepoId, String>,
    pub edges: Vec<CrossRepoEdge>,
    /// Metadata for the returned edge endpoints, captured under the same lock.
    /// This is an internal authority sidecar; the bulk edge route intentionally
    /// projects only topology and watermarks onto its public wire response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities: Vec<EntityEntry>,
    /// Entity IDs covered by the same registered root snapshot. Kept off the
    /// serialized bulk payload; xref projection uses it to ensure the queried
    /// anchor itself belongs to the watermarked graph before certifying absence.
    #[serde(skip)]
    covered_entities: BTreeMap<RepoId, BTreeSet<EntityId>>,
}

impl Default for CrossRepoEdgesSnapshot {
    fn default() -> Self {
        let roots = BTreeMap::new();
        let edges = Vec::new();
        Self {
            complete: false,
            revision: cross_repo_snapshot_revision(&roots, &edges),
            repos: Vec::new(),
            roots,
            edges,
            entities: Vec::new(),
            covered_entities: BTreeMap::new(),
        }
    }
}

/// The spine's in-memory cross-repo metadata index.
///
/// Thread-safe via RwLock — multiple readers, exclusive writer.
/// Rebuilt from daemon queries on startup. Updated via SSE events.
pub struct SpineIndex {
    inner: RwLock<SpineInner>,
    /// Serialize the full replace operation for outgoing edge sets. Authority
    /// registration deliberately does not take this lock: it must be able to
    /// invalidate an in-flight refresh, which the epoch CAS below detects.
    edge_refresh_serialization: Mutex<()>,
}

struct SpineInner {
    /// All known entities across all repos.
    /// Key: (lowercased name, kind) → Vec<EntityEntry>
    by_name: HashMap<(String, EntityKind), Vec<EntityEntry>>,

    /// Entity lookup by (repo_id, entity_id) for direct resolution.
    by_id: HashMap<(RepoId, EntityId), EntityEntry>,

    /// Cross-repo edges (precomputed from import analysis).
    cross_repo_edges: Vec<CrossRepoEdge>,

    /// Incident-edge index for bounded single-anchor xref reads. The full edge
    /// vector remains the canonical bulk topology, while this projection lets
    /// one entity query avoid cloning or scanning the entire organization.
    cross_repo_edges_by_anchor: HashMap<(RepoId, EntityId), Vec<CrossRepoEdge>>,

    /// Cached validation/revision metadata maintained on the write path. Xref
    /// reads use these values under the same read lock as the incident-edge
    /// projection, so certifying one anchor never requires a global edge scan.
    edge_authority_is_closed: bool,
    authority_revision: String,

    /// Graph root hash per repo (for cache coherence).
    root_hashes: HashMap<RepoId, String>,

    /// Source publication cursor installed atomically with each durable repo
    /// head. Legacy/local registrations deliberately have no cursor.
    source_cursors: HashMap<RepoId, SpineSourceCursor>,

    /// Repos whose registered entity/root authority has changed since their
    /// outgoing cross-repo edges were last fully materialized.
    dirty_edge_repos: HashSet<RepoId>,

    /// Monotonic generation for the registered repo/entity/root authority.
    /// A refresh may clear its dirty bit only when this value is unchanged
    /// from the start of that refresh.
    authority_epoch: u64,

    /// Number of edge refreshes currently replacing a repo's outgoing set.
    /// A snapshot taken while this is non-zero is atomic but not complete.
    active_edge_refreshes: usize,

    /// Epoch of the one all-repo refresh pass currently in flight. Per-source
    /// refreshes may install topology during this lease, but they cannot clear
    /// dirty authority or expose completeness; only the pass-wide final CAS can
    /// publish the captured root set atomically.
    active_full_refresh_epoch: Option<u64>,
}

struct EdgeRefreshGuard<'a> {
    index: &'a SpineIndex,
    repo_id: RepoId,
    authority_epoch: u64,
    succeeded: bool,
}

impl EdgeRefreshGuard<'_> {
    fn mark_succeeded(&mut self) {
        self.succeeded = true;
    }
}

impl Drop for EdgeRefreshGuard<'_> {
    fn drop(&mut self) {
        let mut inner = self.index.inner.write();
        if self.succeeded
            && inner.authority_epoch == self.authority_epoch
            && inner.active_full_refresh_epoch.is_none()
        {
            inner.dirty_edge_repos.remove(&self.repo_id);
        }
        inner.active_edge_refreshes = inner
            .active_edge_refreshes
            .checked_sub(1)
            .expect("edge refresh guard count underflow");
    }
}

impl Default for SpineIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl SpineIndex {
    fn empty_inner() -> SpineInner {
        SpineInner {
            by_name: HashMap::new(),
            by_id: HashMap::new(),
            cross_repo_edges: Vec::new(),
            cross_repo_edges_by_anchor: HashMap::new(),
            edge_authority_is_closed: true,
            authority_revision: cross_repo_snapshot_revision(&BTreeMap::new(), &[]),
            root_hashes: HashMap::new(),
            source_cursors: HashMap::new(),
            dirty_edge_repos: HashSet::new(),
            authority_epoch: 0,
            active_edge_refreshes: 0,
            active_full_refresh_epoch: None,
        }
    }

    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Self::empty_inner()),
            edge_refresh_serialization: Mutex::new(()),
        }
    }

    /// Replace a complete durable head set as one reader-visible generation.
    ///
    /// All maps and edge completeness metadata are built off-lock. The final
    /// swap takes the index write lock once, so resolve/xref readers observe
    /// either the prior stable committed fleet or the complete replacement,
    /// never a prefix installed repo by repo.
    pub(crate) fn replace_committed_repo_publications<F>(
        &self,
        publications: Vec<CommittedRepoIndexPublication>,
        mut after_staged_repo: F,
    ) where
        F: FnMut(usize),
    {
        let mut next = Self::empty_inner();
        let complete_roots = publications
            .iter()
            .map(|publication| (publication.repo_id.clone(), publication.root_hash.clone()))
            .collect::<BTreeMap<_, _>>();

        for (index, publication) in publications.iter().enumerate() {
            for entry in &publication.entries {
                let key = (entry.name.to_lowercase(), entry.kind);
                next.by_name.entry(key).or_default().push(entry.clone());
                next.by_id
                    .insert((entry.repo_id.clone(), entry.entity_id), entry.clone());
            }
            next.root_hashes
                .insert(publication.repo_id.clone(), publication.root_hash.clone());
            next.source_cursors
                .insert(publication.repo_id.clone(), publication.source_cursor);
            after_staged_repo(index + 1);
        }

        for publication in publications {
            let complete_edge_head = publication.outgoing_edges.is_some()
                && publication.resolution_roots.as_ref() == Some(&complete_roots);
            if let Some(edges) = publication.outgoing_edges {
                next.cross_repo_edges
                    .extend(edges.into_iter().filter(|edge| {
                        edge.src_repo == publication.repo_id && edge.src_repo != edge.dst_repo
                    }));
            }
            if !complete_edge_head {
                next.dirty_edge_repos.insert(publication.repo_id);
            }
        }
        Self::recompute_cross_repo_metadata(&mut next);

        let mut current = self.inner.write();
        next.authority_epoch = current
            .authority_epoch
            .checked_add(1)
            .expect("spine authority epoch exhausted");
        *current = next;
    }

    /// Register entities from a repo into the index.
    pub fn register_repo(&self, repo_id: &str, entities: Vec<EntityEntry>, root_hash: &str) {
        let mut inner = self.inner.write();

        Self::register_repo_locked(&mut inner, repo_id, entities, root_hash);
        inner.source_cursors.remove(repo_id);
    }

    /// Install one committed durable publication under a single write lock.
    ///
    /// Metadata, root, cursor and the complete outgoing-edge replacement are
    /// one reader-visible fact. A metadata-only head removes older outgoing
    /// edges and stays dirty; an edge head may clear its source dirty bit only
    /// when it was resolved against the exact roots currently resident.
    pub(crate) fn install_repo_publication(
        &self,
        repo_id: &str,
        entities: Vec<EntityEntry>,
        root_hash: &str,
        source_cursor: SpineSourceCursor,
        outgoing_edges: Option<Vec<CrossRepoEdge>>,
        resolution_roots: Option<&BTreeMap<String, String>>,
    ) {
        let mut inner = self.inner.write();
        let root_changed = inner.root_hashes.get(repo_id).map(String::as_str) != Some(root_hash);
        let has_edge_publication = outgoing_edges.is_some();

        inner.by_name.values_mut().for_each(|entries| {
            entries.retain(|entry| entry.repo_id != repo_id);
        });
        inner.by_id.retain(|(owner, _), _| owner != repo_id);
        for entry in entities {
            let key = (entry.name.to_lowercase(), entry.kind);
            inner.by_name.entry(key).or_default().push(entry.clone());
            inner
                .by_id
                .insert((entry.repo_id.clone(), entry.entity_id), entry);
        }
        inner
            .root_hashes
            .insert(repo_id.to_string(), root_hash.to_string());
        inner
            .source_cursors
            .insert(repo_id.to_string(), source_cursor);
        inner
            .cross_repo_edges
            .retain(|edge| edge.src_repo != repo_id);
        if let Some(edges) = outgoing_edges {
            inner.cross_repo_edges.extend(
                edges
                    .into_iter()
                    .filter(|edge| edge.src_repo == repo_id && edge.src_repo != edge.dst_repo),
            );
        }

        inner.authority_epoch = inner
            .authority_epoch
            .checked_add(1)
            .expect("spine authority epoch exhausted");
        if root_changed {
            inner.dirty_edge_repos = inner.root_hashes.keys().cloned().collect();
        }
        let resolved_against_current_roots = has_edge_publication
            && resolution_roots.is_some_and(|expected| {
                inner
                    .root_hashes
                    .iter()
                    .map(|(repo, root)| (repo.clone(), root.clone()))
                    .collect::<BTreeMap<_, _>>()
                    == *expected
            });
        if resolved_against_current_roots {
            inner.dirty_edge_repos.remove(repo_id);
        } else {
            inner.dirty_edge_repos.insert(repo_id.to_string());
        }
        Self::recompute_cross_repo_metadata(&mut inner);
    }

    fn register_repo_locked(
        inner: &mut SpineInner,
        repo_id: &str,
        entities: Vec<EntityEntry>,
        root_hash: &str,
    ) {
        // Remove existing entries for this repo (full refresh)
        inner.by_name.values_mut().for_each(|entries| {
            entries.retain(|e| e.repo_id != repo_id);
        });
        inner.by_id.retain(|(rid, _), _| rid != repo_id);

        // Insert new entries
        for entry in entities {
            let key = (entry.name.to_lowercase(), entry.kind);
            inner.by_name.entry(key).or_default().push(entry.clone());
            inner
                .by_id
                .insert((entry.repo_id.clone(), entry.entity_id), entry);
        }

        inner
            .root_hashes
            .insert(repo_id.to_string(), root_hash.to_string());
        inner.authority_epoch = inner
            .authority_epoch
            .checked_add(1)
            .expect("spine authority epoch exhausted");

        // Any registered repo can be the target of any source repo's outgoing
        // resolution. Adding or changing one target therefore invalidates every
        // registered source, not just the repo whose metadata changed.
        inner.dirty_edge_repos = inner.root_hashes.keys().cloned().collect();
        Self::recompute_cross_repo_metadata(inner);
    }

    /// Rebuild the bounded xref projection and global authority metadata after
    /// a topology/root mutation. This deliberately runs on the write path;
    /// read-side single-anchor queries stay proportional to repo roots plus the
    /// queried entity's incident edges.
    fn recompute_cross_repo_metadata(inner: &mut SpineInner) {
        let mut by_anchor = HashMap::<(RepoId, EntityId), Vec<CrossRepoEdge>>::new();
        let mut closed = true;
        for edge in &inner.cross_repo_edges {
            closed &= inner.root_hashes.contains_key(&edge.src_repo)
                && inner.root_hashes.contains_key(&edge.dst_repo)
                && inner
                    .by_id
                    .contains_key(&(edge.src_repo.clone(), edge.src_entity))
                && inner
                    .by_id
                    .contains_key(&(edge.dst_repo.clone(), edge.dst_entity));
            by_anchor
                .entry((edge.src_repo.clone(), edge.src_entity))
                .or_default()
                .push(edge.clone());
            by_anchor
                .entry((edge.dst_repo.clone(), edge.dst_entity))
                .or_default()
                .push(edge.clone());
        }
        for edges in by_anchor.values_mut() {
            edges.sort_by(cross_repo_edge_order);
            edges.dedup_by(|left, right| cross_repo_edge_identity_order(left, right).is_eq());
        }

        let roots = inner
            .root_hashes
            .iter()
            .map(|(repo, root)| (repo.clone(), root.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut canonical_edges = inner.cross_repo_edges.clone();
        canonical_edges.sort_by(cross_repo_edge_order);
        canonical_edges.dedup_by(|left, right| cross_repo_edge_identity_order(left, right).is_eq());

        inner.cross_repo_edges_by_anchor = by_anchor;
        inner.edge_authority_is_closed = closed;
        inner.authority_revision = cross_repo_snapshot_revision(&roots, &canonical_edges);
    }

    /// This index's own cross-repo authority completeness, read without
    /// materializing the edge set.
    ///
    /// `cross_repo_edges_snapshot().complete` answers the same question and
    /// clones every edge and entity to do it, which is the wrong price for a
    /// health endpoint that wants one boolean.
    ///
    /// What it means is narrow on purpose: the edge authority this index is
    /// currently serving is closed and nothing is dirty. It goes false for a
    /// refresh in flight as readily as for an authority that is genuinely short,
    /// so a caller reporting WHY cross-repo answers are empty needs the startup
    /// pin's own reading beside it, not this alone.
    pub fn authority_is_complete(&self) -> bool {
        let inner = self.inner.read();
        let roots = inner
            .root_hashes
            .iter()
            .map(|(repo, root)| (repo.clone(), root.clone()))
            .collect::<BTreeMap<_, _>>();
        Self::authority_complete(&inner, &roots)
    }

    fn authority_complete(inner: &SpineInner, roots: &BTreeMap<RepoId, String>) -> bool {
        inner.active_edge_refreshes == 0
            && inner.active_full_refresh_epoch.is_none()
            && inner.dirty_edge_repos.is_empty()
            && !roots.is_empty()
            && roots
                .values()
                .all(|root| !root.is_empty() && root.trim() == root)
            && inner.edge_authority_is_closed
    }

    /// Resolve an entity by name and kind across all repos.
    /// Returns matches sorted by fingerprint similarity if a reference fingerprint is provided.
    ///
    /// External reference targets are never returned. Such an entry stands for a
    /// symbol its repository references without owning, which is what a graph
    /// binds for an unresolved import, so returning one would answer "where is
    /// this defined" with another repository's import and hand back a definition
    /// site that does not exist.
    ///
    /// The test is the conjunction of [`EntityRole::External`] and the absent
    /// path, because neither half identifies the shape alone. That role is also
    /// carried by real entities a repository vendors under `third_party/` and its
    /// siblings, which own their source and are legitimate targets, while an
    /// absent path on its own only means no path was recorded.
    pub fn resolve(
        &self,
        name: &str,
        kind: Option<EntityKind>,
        reference_fingerprint: Option<&SemanticFingerprint>,
    ) -> Vec<EntityEntry> {
        let inner = self.inner.read();

        let mut results = Vec::new();

        let owns_definition = |entry: &&EntityEntry| {
            entry.role != Some(EntityRole::External) || entry.file_path.is_some()
        };
        if let Some(kind) = kind {
            let key = (name.to_lowercase(), kind);
            if let Some(entries) = inner.by_name.get(&key) {
                results.extend(entries.iter().filter(owns_definition).cloned());
            }
        } else {
            // Search across all kinds
            let name_lower = name.to_lowercase();
            for ((n, _), entries) in &inner.by_name {
                if *n == name_lower {
                    results.extend(entries.iter().filter(owns_definition).cloned());
                }
            }
        }

        // If a reference fingerprint is provided, sort by similarity
        // (exact match first, then partial matches, then the rest)
        if let Some(ref_fp) = reference_fingerprint {
            results.sort_by(|a, b| {
                let a_match = fingerprint_match_score(&a.fingerprint, ref_fp);
                let b_match = fingerprint_match_score(&b.fingerprint, ref_fp);
                b_match
                    .partial_cmp(&a_match)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }

        results
    }

    /// Get cross-repo edges originating from or targeting a specific entity.
    pub fn cross_repo_edges_for(&self, repo_id: &str, entity_id: &EntityId) -> Vec<CrossRepoEdge> {
        let inner = self.inner.read();
        inner
            .cross_repo_edges
            .iter()
            .filter(|e| {
                (e.src_repo == repo_id && e.src_entity == *entity_id)
                    || (e.dst_repo == repo_id && e.dst_entity == *entity_id)
            })
            .cloned()
            .collect()
    }

    /// Get all cross-repo edges whose source repo is `repo_id`.
    ///
    /// `refresh_cross_repo_edges` replaces a repo's edges by source repo, so this
    /// returns the exact set a persistence layer must mirror after a refresh.
    pub fn cross_repo_edges_from(&self, repo_id: &str) -> Vec<CrossRepoEdge> {
        let inner = self.inner.read();
        inner
            .cross_repo_edges
            .iter()
            .filter(|e| e.src_repo == repo_id)
            .cloned()
            .collect()
    }

    /// Capture every registered root and cross-repo edge under one read lock.
    ///
    /// The returned edge set is sorted and deduplicated by topology (keeping
    /// the highest-confidence copy), so repeated reads of unchanged graph
    /// authority serialize to identical bytes. No projection or filesystem
    /// surface participates in this read.
    pub fn cross_repo_edges_snapshot(&self) -> CrossRepoEdgesSnapshot {
        let (complete, revision, roots, mut edges, mut entities, covered_entities) = {
            let inner = self.inner.read();
            let roots = inner
                .root_hashes
                .iter()
                .map(|(repo, root)| (repo.clone(), root.clone()))
                .collect::<BTreeMap<_, _>>();
            let entities = inner
                .cross_repo_edges
                .iter()
                .flat_map(|edge| {
                    [
                        (edge.src_repo.clone(), edge.src_entity),
                        (edge.dst_repo.clone(), edge.dst_entity),
                    ]
                })
                .filter_map(|key| inner.by_id.get(&key).cloned())
                .collect::<Vec<_>>();
            let mut covered_entities = BTreeMap::<RepoId, BTreeSet<EntityId>>::new();
            for (repo_id, entity_id) in inner.by_id.keys() {
                covered_entities
                    .entry(repo_id.clone())
                    .or_default()
                    .insert(*entity_id);
            }
            (
                Self::authority_complete(&inner, &roots),
                inner.authority_revision.clone(),
                roots,
                inner.cross_repo_edges.clone(),
                entities,
                covered_entities,
            )
        };

        edges.sort_by(cross_repo_edge_order);
        edges.dedup_by(|a, b| cross_repo_edge_identity_order(a, b).is_eq());
        entities.sort_by(|left, right| {
            left.repo_id
                .cmp(&right.repo_id)
                .then_with(|| left.entity_id.cmp(&right.entity_id))
        });
        entities.dedup_by(|left, right| {
            left.repo_id == right.repo_id && left.entity_id == right.entity_id
        });

        let repos = roots.keys().cloned().collect::<Vec<_>>();
        CrossRepoEdgesSnapshot {
            complete,
            revision,
            repos,
            roots,
            edges,
            entities,
            covered_entities,
        }
    }

    /// Atomically project one entity's xref response without cloning/scanning
    /// the global edge and entity collections. Roots, completeness, incident
    /// edges, endpoint metadata, and direct anchor coverage all come from one
    /// read-lock acquisition.
    pub fn cross_repo_xref_response(
        &self,
        repo_id: &str,
        entity_id: &EntityId,
    ) -> SpineXrefResponse {
        let inner = self.inner.read();
        let roots = inner
            .root_hashes
            .iter()
            .map(|(repo, root)| (repo.clone(), root.clone()))
            .collect::<BTreeMap<_, _>>();
        let edges = inner
            .cross_repo_edges_by_anchor
            .get(&(repo_id.to_string(), *entity_id))
            .cloned()
            .unwrap_or_default();
        let endpoint_keys = edges
            .iter()
            .flat_map(|edge| {
                [
                    (edge.src_repo.clone(), edge.src_entity),
                    (edge.dst_repo.clone(), edge.dst_entity),
                ]
            })
            .collect::<BTreeSet<_>>();
        let entities = endpoint_keys
            .into_iter()
            .filter_map(|key| inner.by_id.get(&key).cloned())
            .collect();
        let anchor_covered = inner.by_id.contains_key(&(repo_id.to_string(), *entity_id));

        SpineXrefResponse {
            version: crate::SPINE_PAYLOAD_VERSION,
            edges,
            entities,
            authority_anchor: Some(SpineXrefAuthorityAnchor {
                repo_id: repo_id.to_string(),
                entity_id: *entity_id,
            }),
            authority_complete: Self::authority_complete(&inner, &roots)
                && roots.contains_key(repo_id)
                && anchor_covered,
            authority_revision: Some(inner.authority_revision.clone()),
            authority_roots: roots,
        }
    }

    /// Add a cross-repo edge to the index.
    ///
    /// Returns `false` when the candidate does not cross a repository
    /// boundary. Keeping this invariant at the storage boundary prevents a
    /// resolver bug or stale durable row from making an intra-repo reference
    /// look like hosted cross-repo proof.
    pub fn add_cross_repo_edge(&self, edge: CrossRepoEdge) -> bool {
        self.add_cross_repo_edges(std::iter::once(edge)) == 1
    }

    /// Install a batch of cross-repo edges with one metadata rebuild.
    ///
    /// Durable-cache hydration can contain thousands of rows. Recomputing the
    /// global anchor projection and canonical revision after every row turns
    /// that linear load into O(E^2 log E). This path validates every candidate
    /// but defers the projection/revision rebuild until the full batch is in
    /// memory. Incremental callers can continue using `add_cross_repo_edge`.
    pub fn add_cross_repo_edges<I>(&self, edges: I) -> usize
    where
        I: IntoIterator<Item = CrossRepoEdge>,
    {
        let mut inner = self.inner.write();
        let mut accepted = 0usize;
        for edge in edges {
            if edge.src_repo == edge.dst_repo {
                continue;
            }
            inner.source_cursors.remove(&edge.src_repo);
            inner.cross_repo_edges.push(edge);
            accepted += 1;
        }
        if accepted == 0 {
            return 0;
        }
        Self::recompute_cross_repo_metadata(&mut inner);
        accepted
    }

    /// Mark one source repo's cross-repo materialization stale without
    /// discarding its last known positive edges. The authority epoch bump also
    /// prevents an older in-flight refresh from clearing this invalidation.
    pub fn invalidate_cross_repo_edges(&self, repo_id: &str) {
        let mut inner = self.inner.write();
        inner.dirty_edge_repos.insert(repo_id.to_string());
        inner.authority_epoch = inner
            .authority_epoch
            .checked_add(1)
            .expect("spine authority epoch exhausted");
    }

    /// Start the one pass-wide cross-repo refresh lease.
    ///
    /// Returns `None` when another full pass is already active or the caller's
    /// captured root set no longer matches registered spine authority. Either
    /// failure leaves all registered sources dirty and therefore incomplete.
    pub fn begin_cross_repo_refresh_pass(
        &self,
        authority_roots: &BTreeMap<RepoId, String>,
    ) -> Option<u64> {
        let mut inner = self.inner.write();
        let registered_roots = inner
            .root_hashes
            .iter()
            .map(|(repo, root)| (repo.clone(), root.clone()))
            .collect::<BTreeMap<_, _>>();
        if inner.active_full_refresh_epoch.is_some() || registered_roots != *authority_roots {
            inner.dirty_edge_repos = inner.root_hashes.keys().cloned().collect();
            return None;
        }

        inner.authority_epoch = inner
            .authority_epoch
            .checked_add(1)
            .expect("spine authority epoch exhausted");
        let token = inner.authority_epoch;
        inner.active_full_refresh_epoch = Some(token);
        inner.dirty_edge_repos = authority_roots.keys().cloned().collect();
        Some(token)
    }

    /// Finish a full refresh and publish completeness with one authority CAS.
    ///
    /// The dirty set and pass lease are cleared under the same write lock only
    /// when no registration/invalidation advanced the epoch and the registered
    /// repo/root map still exactly equals the caller's captured authority.
    pub fn finish_cross_repo_refresh_pass(
        &self,
        token: u64,
        authority_roots: &BTreeMap<RepoId, String>,
        success: bool,
    ) -> bool {
        let mut inner = self.inner.write();
        if inner.active_full_refresh_epoch != Some(token) {
            return false;
        }

        let registered_roots = inner
            .root_hashes
            .iter()
            .map(|(repo, root)| (repo.clone(), root.clone()))
            .collect::<BTreeMap<_, _>>();
        let committed = success
            && inner.authority_epoch == token
            && registered_roots == *authority_roots
            && inner.active_edge_refreshes == 0;
        if committed {
            inner.dirty_edge_repos.clear();
        }
        inner.active_full_refresh_epoch = None;
        committed
    }

    /// Look up an entity by (repo_id, entity_id).
    pub fn lookup_by_id(&self, repo_id: &str, entity_id: &EntityId) -> Option<EntityEntry> {
        let inner = self.inner.read();
        inner.by_id.get(&(repo_id.to_string(), *entity_id)).cloned()
    }

    /// Get the root hash for a repo (for cache coherence checks).
    pub fn root_hash(&self, repo_id: &str) -> Option<String> {
        let inner = self.inner.read();
        inner.root_hashes.get(repo_id).cloned()
    }

    /// Exact durable source cursor installed with this repo's committed head.
    pub fn source_cursor(&self, repo_id: &str) -> Option<SpineSourceCursor> {
        let inner = self.inner.read();
        inner.source_cursors.get(repo_id).copied()
    }

    /// Total number of indexed entities across all repos.
    pub fn entity_count(&self) -> usize {
        let inner = self.inner.read();
        inner.by_id.len()
    }

    /// Number of registered repos.
    pub fn repo_count(&self) -> usize {
        let inner = self.inner.read();
        inner.root_hashes.len()
    }

    /// Number of cross-repo edges.
    pub fn edge_count(&self) -> usize {
        let inner = self.inner.read();
        inner.cross_repo_edges.len()
    }

    /// Get the set of all registered repo IDs.
    pub fn registered_repo_ids(&self) -> HashSet<String> {
        let inner = self.inner.read();
        inner.root_hashes.keys().cloned().collect()
    }

    /// Refresh cross-repo edges for a repo by collecting unresolved imports,
    /// resolving them, and materializing edges.
    ///
    /// Removes existing edges originating from this repo before adding new ones.
    pub fn refresh_cross_repo_edges(
        &self,
        repo_id: &str,
        entities: &[Entity],
        relations: &[Relation],
        registry_repo_ids: &[String],
    ) {
        self.refresh_cross_repo_edges_with_hook(
            repo_id,
            entities,
            relations,
            registry_repo_ids,
            || {},
        );
    }

    /// Resolve one repository's complete outgoing cross-repo edge set without
    /// mutating the index.
    ///
    /// Durable publishers use this between metadata and edge phases: all
    /// candidate rows remain detached until the repository head CAS commits
    /// them, so readers continue to observe only the previous committed head.
    pub fn derive_cross_repo_edges(
        &self,
        repo_id: &str,
        entities: &[Entity],
        relations: &[Relation],
        registry_repo_ids: &[String],
    ) -> Vec<CrossRepoEdge> {
        use crate::xref::{collect_unresolved_imports, materialized_edges, resolve_imports};

        let unresolved =
            collect_unresolved_imports(entities, relations, repo_id, registry_repo_ids);
        if unresolved.is_empty() {
            return Vec::new();
        }
        let resolutions = resolve_imports(self, &unresolved);
        materialized_edges(&unresolved, &resolutions)
    }

    fn refresh_cross_repo_edges_with_hook<F>(
        &self,
        repo_id: &str,
        entities: &[Entity],
        relations: &[Relation],
        registry_repo_ids: &[String],
        after_start: F,
    ) where
        F: FnOnce(),
    {
        let _serialized = self.edge_refresh_serialization.lock();
        let mut refresh = self.begin_edge_refresh(repo_id, entities);
        after_start();

        // Resolve into a detached replacement before taking the mutation lock.
        // Installing the full outgoing set in one write prevents readers from
        // seeing a partial or interleaved union.
        let replacement =
            self.derive_cross_repo_edges(repo_id, entities, relations, registry_repo_ids);
        let mut inner = self.inner.write();
        inner.cross_repo_edges.retain(|e| e.src_repo != repo_id);
        inner.cross_repo_edges.extend(replacement);
        inner.source_cursors.remove(repo_id);
        Self::recompute_cross_repo_metadata(&mut inner);
        drop(inner);
        refresh.mark_succeeded();
    }

    fn begin_edge_refresh(&self, repo_id: &str, entities: &[Entity]) -> EdgeRefreshGuard<'_> {
        let mut inner = self.inner.write();
        // Normal production callers register graph authority before refreshing.
        // Preserve the direct-refresh compatibility path only for a genuinely
        // absent repo; re-registering every normal refresh would globally dirty
        // all repos and make a complete multi-repo pass impossible.
        if !inner.root_hashes.contains_key(repo_id) {
            Self::register_repo_locked(
                &mut inner,
                repo_id,
                entries_from_entities(repo_id, entities),
                "",
            );
        }
        inner.active_edge_refreshes += 1;
        EdgeRefreshGuard {
            index: self,
            repo_id: repo_id.to_string(),
            authority_epoch: inner.authority_epoch,
            succeeded: false,
        }
    }
}

fn cross_repo_edge_order(a: &CrossRepoEdge, b: &CrossRepoEdge) -> std::cmp::Ordering {
    cross_repo_edge_identity_order(a, b).then_with(|| b.confidence.total_cmp(&a.confidence))
}

fn cross_repo_edge_identity_order(a: &CrossRepoEdge, b: &CrossRepoEdge) -> std::cmp::Ordering {
    a.src_repo
        .cmp(&b.src_repo)
        .then_with(|| a.src_entity.cmp(&b.src_entity))
        .then_with(|| a.dst_repo.cmp(&b.dst_repo))
        .then_with(|| a.dst_entity.cmp(&b.dst_entity))
}

fn cross_repo_snapshot_revision(
    roots: &BTreeMap<RepoId, String>,
    edges: &[CrossRepoEdge],
) -> String {
    fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"kin-spine-cross-repo-edges-v1\0");
    hasher.update((roots.len() as u64).to_be_bytes());
    for (repo, root) in roots {
        hash_bytes(&mut hasher, repo.as_bytes());
        hash_bytes(&mut hasher, root.as_bytes());
    }
    hasher.update((edges.len() as u64).to_be_bytes());
    for edge in edges {
        hash_bytes(&mut hasher, edge.src_repo.as_bytes());
        hasher.update(edge.src_entity.0.as_bytes());
        hash_bytes(&mut hasher, edge.dst_repo.as_bytes());
        hasher.update(edge.dst_entity.0.as_bytes());
        hasher.update(edge.confidence.to_bits().to_be_bytes());
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Project a repo's graph entities into the metadata-only [`EntityEntry`] rows
/// the index resolves against — the same mapping the daemon uses when it
/// registers a repo. Bodies are never stored; just name/kind/signature/
/// fingerprint/role, enough for cross-repo resolution.
fn entries_from_entities(repo_id: &str, entities: &[Entity]) -> Vec<EntityEntry> {
    entities
        .iter()
        .map(|e| EntityEntry {
            repo_id: repo_id.to_string(),
            entity_id: e.id,
            name: e.name.clone(),
            kind: e.kind,
            signature: e.signature.clone(),
            fingerprint: e.fingerprint.clone(),
            file_path: e.file_origin.as_ref().map(|f| f.0.clone()),
            role: Some(e.role),
        })
        .collect()
}

/// Score how well two fingerprints match (0.0 = no match, 3.0 = exact match).
pub fn fingerprint_match_score(a: &SemanticFingerprint, b: &SemanticFingerprint) -> f32 {
    let mut score = 0.0f32;
    if a.ast_hash == b.ast_hash {
        score += 1.0;
    }
    if a.signature_hash == b.signature_hash {
        score += 1.0;
    }
    if a.behavior_hash == b.behavior_hash {
        score += 1.0;
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        EntityMetadata, FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, RelationEvidence,
        RelationId, RelationKind, RelationOrigin, Visibility,
    };
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;

    /// The watermark rule separates three deployments that a boolean collapsed
    /// into two: same root, older root, and no registration. The third is the
    /// ordinary state of a single-repo install, and reporting it as a mismatch
    /// described a misconfiguration that did not exist.
    #[test]
    fn the_watermark_rule_separates_a_stale_root_from_no_registration() {
        let mut response = SpineXrefResponse::new(Vec::new(), Vec::new());
        assert_eq!(
            response.authority_root_state("nk", "live"),
            AuthorityRootState::Unregistered
        );
        assert!(!response.authority_root_matches("nk", "live"));

        response
            .authority_roots
            .insert("nk".to_string(), "older".to_string());
        assert_eq!(
            response.authority_root_state("nk", "live"),
            AuthorityRootState::Stale {
                registered: "older"
            }
        );
        assert!(!response.authority_root_matches("nk", "live"));

        response
            .authority_roots
            .insert("nk".to_string(), "live".to_string());
        assert_eq!(
            response.authority_root_state("nk", "live"),
            AuthorityRootState::Matches
        );
        assert!(response.authority_root_matches("nk", "live"));

        // And the state is per repository: another repo's registration answers
        // nothing about this one.
        assert_eq!(
            response.authority_root_state("other", "live"),
            AuthorityRootState::Unregistered
        );
    }

    fn test_fp() -> SemanticFingerprint {
        SemanticFingerprint {
            ast_hash: Hash256::from_bytes([1; 32]),
            signature_hash: Hash256::from_bytes([2; 32]),
            behavior_hash: Hash256::from_bytes([3; 32]),
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        }
    }

    fn test_entry(repo: &str, name: &str, kind: EntityKind) -> EntityEntry {
        EntityEntry {
            repo_id: repo.to_string(),
            entity_id: EntityId::new(),
            name: name.to_string(),
            kind,
            signature: format!("fn {name}()"),
            fingerprint: test_fp(),
            file_path: Some("src/lib.rs".to_string()),
            role: Some(EntityRole::Source),
        }
    }

    /// The shape admission binds for a symbol another repository owns: the
    /// imported name, no file, and the uniform kind that says only that the
    /// symbol is reached through a module this repository does not own.
    fn external_target_entry(repo: &str, name: &str) -> EntityEntry {
        let mut entry = test_entry(repo, name, EntityKind::Module);
        entry.file_path = None;
        entry.signature = String::new();
        entry.role = Some(EntityRole::External);
        entry
    }

    fn test_entry_with_id(repo: &str, id: EntityId, name: &str) -> EntityEntry {
        let mut entry = test_entry(repo, name, EntityKind::Function);
        entry.entity_id = id;
        entry
    }

    fn committed_pair(version: &str, cursor: u64) -> Vec<CommittedRepoIndexPublication> {
        let roots = [
            ("alpha".to_string(), format!("alpha-{version}")),
            ("beta".to_string(), format!("beta-{version}")),
        ]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
        ["alpha", "beta"]
            .into_iter()
            .map(|repo_id| CommittedRepoIndexPublication {
                repo_id: repo_id.to_string(),
                entries: vec![test_entry(
                    repo_id,
                    &format!("{repo_id}_{version}"),
                    EntityKind::Function,
                )],
                root_hash: roots[repo_id].clone(),
                source_cursor: SpineSourceCursor::from_backend_generation(cursor),
                outgoing_edges: Some(Vec::new()),
                resolution_roots: Some(roots.clone()),
            })
            .collect()
    }

    #[test]
    fn committed_fleet_replacement_is_one_reader_visible_generation() {
        let index = Arc::new(SpineIndex::new());
        index.replace_committed_repo_publications(committed_pair("old", 1), |_| {});
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let worker_index = Arc::clone(&index);
        let worker_barrier = Arc::clone(&barrier);
        let worker = thread::spawn(move || {
            worker_index.replace_committed_repo_publications(committed_pair("new", 2), |staged| {
                if staged == 1 {
                    worker_barrier.wait();
                    worker_barrier.wait();
                }
            });
        });

        barrier.wait();
        assert_eq!(index.root_hash("alpha").as_deref(), Some("alpha-old"));
        assert_eq!(index.root_hash("beta").as_deref(), Some("beta-old"));
        assert_eq!(index.resolve("alpha_old", None, None).len(), 1);
        assert!(index.resolve("alpha_new", None, None).is_empty());
        barrier.wait();
        worker.join().unwrap();

        assert_eq!(index.root_hash("alpha").as_deref(), Some("alpha-new"));
        assert_eq!(index.root_hash("beta").as_deref(), Some("beta-new"));
        assert_eq!(index.resolve("alpha_new", None, None).len(), 1);
        assert!(index.resolve("alpha_old", None, None).is_empty());
        assert!(index.authority_is_complete());
    }

    #[test]
    fn sequential_hydration_falsification_exposes_a_mixed_fleet() {
        let index = Arc::new(SpineIndex::new());
        index.replace_committed_repo_publications(committed_pair("old", 1), |_| {});
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let worker_index = Arc::clone(&index);
        let worker_barrier = Arc::clone(&barrier);
        let worker = thread::spawn(move || {
            let mut replacements = committed_pair("new", 2).into_iter();
            let alpha = replacements.next().unwrap();
            worker_index.install_repo_publication(
                &alpha.repo_id,
                alpha.entries,
                &alpha.root_hash,
                alpha.source_cursor,
                alpha.outgoing_edges,
                alpha.resolution_roots.as_ref(),
            );
            worker_barrier.wait();
            worker_barrier.wait();
            let beta = replacements.next().unwrap();
            worker_index.install_repo_publication(
                &beta.repo_id,
                beta.entries,
                &beta.root_hash,
                beta.source_cursor,
                beta.outgoing_edges,
                beta.resolution_roots.as_ref(),
            );
        });

        barrier.wait();
        assert_eq!(index.root_hash("alpha").as_deref(), Some("alpha-new"));
        assert_eq!(index.root_hash("beta").as_deref(), Some("beta-old"));
        assert_eq!(index.resolve("alpha_new", None, None).len(), 1);
        assert_eq!(index.resolve("beta_old", None, None).len(), 1);
        barrier.wait();
        worker.join().unwrap();
    }

    #[test]
    fn xref_wire_response_round_trips_typed_edges_and_metadata() {
        let src = EntityId::new();
        let dst = EntityId::new();
        let response = SpineXrefResponse::new(
            vec![CrossRepoEdge {
                src_repo: "consumer".to_string(),
                src_entity: src,
                dst_repo: "provider".to_string(),
                dst_entity: dst,
                confidence: 0.9,
            }],
            vec![test_entry_with_id("consumer", src, "run_task")],
        );

        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded = SpineXrefResponse::from_slice(&bytes).unwrap();
        assert_eq!(decoded.version(), crate::SPINE_PAYLOAD_VERSION);
        assert_eq!(decoded.edges.len(), 1);
        assert_eq!(decoded.edges[0].src_repo, "consumer");
        assert_eq!(decoded.entities.len(), 1);
        assert_eq!(decoded.entities[0].name, "run_task");
        assert!(!decoded.authority_complete);
        assert!(decoded.authority_anchor.is_none());
        assert!(decoded.authority_revision.is_none());
        assert!(decoded.authority_roots.is_empty());
    }

    #[test]
    fn xref_wire_response_accepts_legacy_version_one_as_incomplete() {
        let src = EntityId::new();
        let dst = EntityId::new();
        let bytes = serde_json::to_vec(&serde_json::json!({
            "version": crate::SPINE_PAYLOAD_VERSION,
            "edges": [{
                "src_repo": "consumer",
                "src_entity": src,
                "dst_repo": "provider",
                "dst_entity": dst,
                "confidence": 0.9,
            }],
        }))
        .unwrap();

        let decoded = SpineXrefResponse::from_slice(&bytes).unwrap();
        assert_eq!(decoded.edges.len(), 1);
        assert!(decoded.entities.is_empty());
        assert!(!decoded.authority_complete);
        assert!(decoded.authority_anchor.is_none());
        assert!(decoded.authority_revision.is_none());
        assert!(decoded.authority_roots.is_empty());
        let bound = SpineXrefResponse::from_slice_for(&bytes, "provider", &dst).unwrap();
        assert_eq!(bound.edges.len(), 1);
        assert!(!bound.authority_complete);
        assert!(bound.authority_anchor.is_none());

        let empty_unanchored = serde_json::to_vec(&serde_json::json!({
            "version": crate::SPINE_PAYLOAD_VERSION,
            "edges": [],
        }))
        .unwrap();
        assert!(matches!(
            SpineXrefResponse::from_slice_for(&empty_unanchored, "provider", &dst),
            Err(SpineXrefDecodeError::InvalidAuthority(_))
        ));
    }

    #[test]
    fn xref_wire_response_projects_complete_atomic_snapshot() {
        let src = EntityId::new();
        let dst = EntityId::new();
        let no_refs = EntityId::new();
        let consumer = test_entry_with_id("consumer", src, "run_task");
        let provider = test_entry_with_id("provider", dst, "do_work");
        let unused = test_entry_with_id("provider", no_refs, "unused");
        let index = SpineIndex::new();
        index.register_repo("consumer", vec![consumer], "consumer-root");
        index.register_repo("provider", vec![provider, unused], "provider-root");
        let repos = vec!["consumer".to_string(), "provider".to_string()];
        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        index.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "consumer".to_string(),
            src_entity: src,
            dst_repo: "provider".to_string(),
            dst_entity: dst,
            confidence: 0.9,
        });

        let response = index.cross_repo_xref_response("provider", &dst);
        assert!(response.authority_complete);
        assert!(response
            .authority_revision
            .as_deref()
            .is_some_and(|revision| revision.starts_with("sha256:")));
        assert_eq!(response.authority_roots["consumer"], "consumer-root");
        assert_eq!(response.authority_roots["provider"], "provider-root");
        assert_eq!(
            response.authority_anchor,
            Some(SpineXrefAuthorityAnchor {
                repo_id: "provider".to_string(),
                entity_id: dst,
            })
        );
        assert!(response.authority_complete_for("provider", &dst));
        assert!(!response.authority_complete_for("provider", &no_refs));
        assert_eq!(response.edges.len(), 1);
        assert_eq!(response.entities.len(), 2);
        assert_eq!(response.entities[0].repo_id, "consumer");
        assert_eq!(response.entities[1].repo_id, "provider");

        let response_bytes = serde_json::to_vec(&response).unwrap();
        let decoded = SpineXrefResponse::from_slice_for(&response_bytes, "provider", &dst).unwrap();
        assert!(decoded.authority_complete);
        assert_eq!(decoded.authority_revision, response.authority_revision);

        let wrong_repo = index.cross_repo_xref_response("unknown", &dst);
        assert!(!wrong_repo.authority_complete);

        let covered_empty = index.cross_repo_xref_response("provider", &no_refs);
        assert!(covered_empty.authority_complete);
        assert!(covered_empty.edges.is_empty());
        let covered_empty_bytes = serde_json::to_vec(&covered_empty).unwrap();
        assert!(matches!(
            SpineXrefResponse::from_slice_for(&covered_empty_bytes, "provider", &dst),
            Err(SpineXrefDecodeError::InvalidAuthority(_))
        ));

        let unknown_entity = index.cross_repo_xref_response("provider", &EntityId::new());
        assert!(!unknown_entity.authority_complete);
    }

    #[test]
    fn anchor_xref_projection_excludes_unrelated_topology() {
        let index = SpineIndex::new();
        let target = EntityId::new();
        let caller = EntityId::new();
        let unrelated_target = EntityId::new();
        let unrelated_caller = EntityId::new();
        index.register_repo(
            "provider",
            vec![
                test_entry_with_id("provider", target, "target"),
                test_entry_with_id("provider", unrelated_target, "other_target"),
            ],
            "provider-root",
        );
        index.register_repo(
            "consumer",
            vec![
                test_entry_with_id("consumer", caller, "caller"),
                test_entry_with_id("consumer", unrelated_caller, "other_caller"),
            ],
            "consumer-root",
        );
        let repos = vec!["consumer".to_string(), "provider".to_string()];
        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        for (src_entity, dst_entity) in [(caller, target), (unrelated_caller, unrelated_target)] {
            index.add_cross_repo_edge(CrossRepoEdge {
                src_repo: "consumer".to_string(),
                src_entity,
                dst_repo: "provider".to_string(),
                dst_entity,
                confidence: 0.9,
            });
        }

        let response = index.cross_repo_xref_response("provider", &target);
        assert!(response.authority_complete);
        assert_eq!(response.edges.len(), 1);
        assert_eq!(response.edges[0].src_entity, caller);
        assert_eq!(response.entities.len(), 2);
        assert!(response
            .entities
            .iter()
            .all(|entity| entity.entity_id != unrelated_caller
                && entity.entity_id != unrelated_target));
    }

    #[test]
    fn xref_bound_decode_rejects_non_incident_edges() {
        let requested = EntityId::new();
        let unrelated_src = EntityId::new();
        let unrelated_dst = EntityId::new();
        let mut response = SpineXrefResponse::new(
            vec![CrossRepoEdge {
                src_repo: "consumer".to_string(),
                src_entity: unrelated_src,
                dst_repo: "provider".to_string(),
                dst_entity: unrelated_dst,
                confidence: 0.9,
            }],
            Vec::new(),
        );
        response.authority_anchor = Some(SpineXrefAuthorityAnchor {
            repo_id: "provider".to_string(),
            entity_id: requested,
        });

        let bytes = serde_json::to_vec(&response).unwrap();
        assert!(matches!(
            SpineXrefResponse::from_slice_for(&bytes, "provider", &requested),
            Err(SpineXrefDecodeError::InvalidAuthority(_))
        ));
    }

    #[test]
    fn xref_wire_response_rejects_legacy_field_names_and_versions() {
        let legacy = serde_json::to_vec(&serde_json::json!({
            "version": crate::SPINE_PAYLOAD_VERSION,
            "edges": [{
                "repo_id": "consumer",
                "from_name": "run_task",
                "to_repo_id": "provider",
                "kind": "calls",
            }],
        }))
        .unwrap();
        assert!(matches!(
            SpineXrefResponse::from_slice(&legacy),
            Err(SpineXrefDecodeError::Malformed(_))
        ));

        let unsupported = serde_json::to_vec(&serde_json::json!({
            "version": crate::SPINE_PAYLOAD_VERSION + 1,
            "edges": [],
        }))
        .unwrap();
        assert!(matches!(
            SpineXrefResponse::from_slice(&unsupported),
            Err(SpineXrefDecodeError::UnsupportedVersion { .. })
        ));

        let unwatermarked_complete = serde_json::to_vec(&serde_json::json!({
            "version": crate::SPINE_PAYLOAD_VERSION,
            "edges": [],
            "authority_complete": true,
        }))
        .unwrap();
        assert!(matches!(
            SpineXrefResponse::from_slice(&unwatermarked_complete),
            Err(SpineXrefDecodeError::InvalidAuthority(_))
        ));
    }

    fn test_entity(id: EntityId, name: &str) -> Entity {
        Entity {
            id,
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: test_fp(),
            file_origin: None,
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn external_call(src: EntityId, import_source: &str, token: &str) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(EntityId::new()),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: Some(import_source.to_string()),
            evidence: vec![RelationEvidence {
                token: Some(token.to_string()),
                ..RelationEvidence::default()
            }],
        }
    }

    #[test]
    fn resolve_by_name_and_kind() {
        let index = SpineIndex::new();
        index.register_repo(
            "repo-a",
            vec![
                test_entry("repo-a", "Config", EntityKind::Class),
                test_entry("repo-a", "parse", EntityKind::Function),
            ],
            "hash-a",
        );
        index.register_repo(
            "repo-b",
            vec![test_entry("repo-b", "Config", EntityKind::Class)],
            "hash-b",
        );

        // Resolve Config class — should find both repos
        let results = index.resolve("Config", Some(EntityKind::Class), None);
        assert_eq!(results.len(), 2);

        // Resolve parse function — only in repo-a
        let results = index.resolve("parse", Some(EntityKind::Function), None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].repo_id, "repo-a");
    }

    /// An external reference target is registered under the repository that
    /// imports the symbol, not the one that defines it. Two repositories
    /// importing the same symbol from the same third party is the ordinary case,
    /// `useState` from `react` being the obvious one, and neither repository is
    /// the registry entry the other should resolve against: binding one would
    /// assert the symbol is defined in a repository that only references it.
    ///
    /// Nothing else narrows this. Named-repo resolution never reaches it,
    /// because the import source is not a registered repository, so resolution
    /// falls through to name matching across every candidate repo, where the two
    /// importers see each other.
    #[test]
    fn resolve_refuses_entries_that_hold_no_definition() {
        let index = SpineIndex::new();
        index.register_repo(
            "repo-a",
            vec![external_target_entry("repo-a", "useState")],
            "hash-a",
        );
        index.register_repo(
            "repo-b",
            vec![external_target_entry("repo-b", "useState")],
            "hash-b",
        );

        assert!(
            index.resolve("useState", None, None).is_empty(),
            "a repository that only imports a symbol is not where it is defined"
        );
        assert!(
            index
                .resolve("useState", Some(EntityKind::Module), None)
                .is_empty(),
            "the kind-narrowed path must refuse it too"
        );

        // The repository that owns the declaration is still resolved, and is the
        // only result even though two other repositories carry the name.
        index.register_repo(
            "repo-c",
            vec![test_entry("repo-c", "useState", EntityKind::Function)],
            "hash-c",
        );
        let results = index.resolve("useState", None, None);
        assert_eq!(results.len(), 1, "{results:?}");
        assert_eq!(results[0].repo_id, "repo-c");
    }

    #[test]
    fn resolve_disambiguates_by_fingerprint() {
        let index = SpineIndex::new();

        let mut entry_a = test_entry("repo-a", "Config", EntityKind::Class);
        entry_a.fingerprint.ast_hash = Hash256::from_bytes([10; 32]);

        let mut entry_b = test_entry("repo-b", "Config", EntityKind::Class);
        entry_b.fingerprint.ast_hash = Hash256::from_bytes([20; 32]);

        index.register_repo("repo-a", vec![entry_a], "hash-a");
        index.register_repo("repo-b", vec![entry_b], "hash-b");

        // Resolve with a reference fingerprint matching repo-b
        let ref_fp = SemanticFingerprint {
            ast_hash: Hash256::from_bytes([20; 32]),
            signature_hash: Hash256::from_bytes([2; 32]),
            behavior_hash: Hash256::from_bytes([3; 32]),
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        };

        let results = index.resolve("Config", Some(EntityKind::Class), Some(&ref_fp));
        assert_eq!(results.len(), 2);
        // repo-b should be first (better fingerprint match)
        assert_eq!(results[0].repo_id, "repo-b");
    }

    #[test]
    fn repo_refresh_replaces_entries() {
        let index = SpineIndex::new();

        index.register_repo(
            "repo-a",
            vec![test_entry("repo-a", "old_fn", EntityKind::Function)],
            "hash-1",
        );
        assert_eq!(index.entity_count(), 1);

        // Re-register with different entities
        index.register_repo(
            "repo-a",
            vec![
                test_entry("repo-a", "new_fn", EntityKind::Function),
                test_entry("repo-a", "other_fn", EntityKind::Function),
            ],
            "hash-2",
        );
        assert_eq!(index.entity_count(), 2);

        // Old entity should be gone
        let results = index.resolve("old_fn", Some(EntityKind::Function), None);
        assert!(results.is_empty());
    }

    #[test]
    fn cross_repo_edges() {
        let index = SpineIndex::new();

        let entry_a = test_entry("repo-a", "caller", EntityKind::Function);
        let entry_b = test_entry("repo-b", "callee", EntityKind::Function);

        index.register_repo("repo-a", vec![entry_a.clone()], "hash-a");
        index.register_repo("repo-b", vec![entry_b.clone()], "hash-b");

        index.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "repo-a".to_string(),
            src_entity: entry_a.entity_id,
            dst_repo: "repo-b".to_string(),
            dst_entity: entry_b.entity_id,
            confidence: 0.95,
        });

        let edges = index.cross_repo_edges_for("repo-a", &entry_a.entity_id);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].dst_repo, "repo-b");

        assert_eq!(index.edge_count(), 1);
    }

    #[test]
    fn bulk_edge_install_filters_invalid_rows_and_builds_anchor_projection() {
        let index = SpineIndex::new();
        let caller = test_entry("repo-a", "caller", EntityKind::Function);
        let callee = test_entry("repo-b", "callee", EntityKind::Function);
        index.register_repo("repo-a", vec![caller.clone()], "hash-a");
        index.register_repo("repo-b", vec![callee.clone()], "hash-b");
        let repos = vec!["repo-a".to_string(), "repo-b".to_string()];
        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }

        let accepted = index.add_cross_repo_edges([
            CrossRepoEdge {
                src_repo: "repo-a".to_string(),
                src_entity: caller.entity_id,
                dst_repo: "repo-b".to_string(),
                dst_entity: callee.entity_id,
                confidence: 0.95,
            },
            CrossRepoEdge {
                src_repo: "repo-a".to_string(),
                src_entity: caller.entity_id,
                dst_repo: "repo-a".to_string(),
                dst_entity: caller.entity_id,
                confidence: 0.5,
            },
        ]);

        assert_eq!(accepted, 1);
        assert_eq!(index.edge_count(), 1);
        let response = index.cross_repo_xref_response("repo-b", &callee.entity_id);
        assert_eq!(response.edges.len(), 1);
        assert_eq!(response.edges[0].src_entity, caller.entity_id);
        assert!(response.authority_complete_for("repo-b", &callee.entity_id));
        assert!(response
            .authority_revision
            .as_deref()
            .is_some_and(|revision| revision.starts_with("sha256:")));
    }

    #[test]
    fn rejects_intra_repo_edges_at_the_index_boundary() {
        let index = SpineIndex::new();
        let caller = test_entry("repo-a", "caller", EntityKind::Function);
        let callee = test_entry("repo-a", "callee", EntityKind::Function);

        assert!(!index.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "repo-a".to_string(),
            src_entity: caller.entity_id,
            dst_repo: "repo-a".to_string(),
            dst_entity: callee.entity_id,
            confidence: 0.95,
        }));
        assert_eq!(index.edge_count(), 0);
        assert!(index
            .cross_repo_edges_for("repo-a", &caller.entity_id)
            .is_empty());
    }

    #[test]
    fn edge_snapshot_is_complete_canonical_and_revisioned() {
        let a = EntityId::from_content("src/a.rs", "a", "function", 1);
        let b = EntityId::from_content("src/b.rs", "b", "function", 1);
        let c = EntityId::from_content("src/c.rs", "c", "function", 1);
        let edge_ab = CrossRepoEdge {
            src_repo: "alpha".to_string(),
            src_entity: a,
            dst_repo: "beta".to_string(),
            dst_entity: b,
            confidence: 0.9,
        };
        let edge_bc = CrossRepoEdge {
            src_repo: "beta".to_string(),
            src_entity: b,
            dst_repo: "gamma".to_string(),
            dst_entity: c,
            confidence: 0.8,
        };

        let first = SpineIndex::new();
        first.register_repo(
            "gamma",
            vec![test_entry_with_id("gamma", c, "gamma")],
            "root-c",
        );
        first.register_repo(
            "alpha",
            vec![test_entry_with_id("alpha", a, "alpha")],
            "root-a",
        );
        first.register_repo(
            "beta",
            vec![test_entry_with_id("beta", b, "beta")],
            "root-b",
        );
        let repos = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
        for repo in &repos {
            first.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        first.add_cross_repo_edge(edge_bc.clone());
        first.add_cross_repo_edge(edge_ab.clone());
        first.add_cross_repo_edge(edge_ab.clone());
        first.add_cross_repo_edge(CrossRepoEdge {
            confidence: 0.4,
            ..edge_ab.clone()
        });

        let second = SpineIndex::new();
        second.register_repo(
            "beta",
            vec![test_entry_with_id("beta", b, "beta")],
            "root-b",
        );
        second.register_repo(
            "gamma",
            vec![test_entry_with_id("gamma", c, "gamma")],
            "root-c",
        );
        second.register_repo(
            "alpha",
            vec![test_entry_with_id("alpha", a, "alpha")],
            "root-a",
        );
        for repo in &repos {
            second.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        second.add_cross_repo_edge(edge_ab.clone());
        second.add_cross_repo_edge(edge_bc.clone());

        let first_snapshot = first.cross_repo_edges_snapshot();
        let second_snapshot = second.cross_repo_edges_snapshot();
        assert!(first_snapshot.complete);
        assert_eq!(
            first_snapshot.repos,
            vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()]
        );
        assert_eq!(first_snapshot.edges, vec![edge_ab, edge_bc]);
        assert_eq!(first_snapshot, second_snapshot);
        assert_eq!(
            serde_json::to_vec(&first_snapshot).unwrap(),
            serde_json::to_vec(&second_snapshot).unwrap(),
            "equivalent authority must produce stable snapshot bytes"
        );
        assert!(first_snapshot.revision.starts_with("sha256:"));
        assert_eq!(first_snapshot.revision.len(), 71);

        second.register_repo(
            "gamma",
            vec![test_entry_with_id("gamma", c, "gamma")],
            "root-c-next",
        );
        assert_ne!(
            first_snapshot.revision,
            second.cross_repo_edges_snapshot().revision,
            "changing a graph root must advance the deterministic watermark"
        );
    }

    #[test]
    fn edge_snapshot_fails_closed_while_refresh_is_in_flight() {
        let index = SpineIndex::new();
        index.register_repo("alpha", vec![], "root-a");
        index.refresh_cross_repo_edges("alpha", &[], &[], &["alpha".to_string()]);
        let before = index.cross_repo_edges_snapshot();
        assert!(before.complete);

        let refresh = index.begin_edge_refresh("alpha", &[]);
        let during = index.cross_repo_edges_snapshot();
        assert!(!during.complete);
        assert_eq!(during.revision, before.revision);

        drop(refresh);
        assert!(index.cross_repo_edges_snapshot().complete);
    }

    #[test]
    fn edge_snapshot_stays_incomplete_until_every_registered_repo_is_refreshed() {
        let index = SpineIndex::new();
        let repos = vec!["alpha".to_string(), "beta".to_string()];

        index.register_repo("alpha", vec![], "root-a");
        assert!(
            !index.cross_repo_edges_snapshot().complete,
            "registering authority must dirty that repo's edge set"
        );
        index.register_repo("beta", vec![], "root-b");

        index.refresh_cross_repo_edges("alpha", &[], &[], &repos);
        assert!(
            !index.cross_repo_edges_snapshot().complete,
            "refreshing one repo must not clear another repo's dirty state"
        );

        index.refresh_cross_repo_edges("beta", &[], &[], &repos);
        assert!(
            index.cross_repo_edges_snapshot().complete,
            "the snapshot becomes complete only after every dirty repo refreshes"
        );
    }

    #[test]
    fn all_repo_pass_stays_incomplete_through_the_final_validation_window() {
        let index = SpineIndex::new();
        let repos = vec!["alpha".to_string(), "beta".to_string()];
        index.register_repo("alpha", vec![], "root-a");
        index.register_repo("beta", vec![], "root-b");
        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        assert!(index.cross_repo_edges_snapshot().complete);

        let roots = BTreeMap::from([
            ("alpha".to_string(), "root-a".to_string()),
            ("beta".to_string(), "root-b".to_string()),
        ]);
        let token = index
            .begin_cross_repo_refresh_pass(&roots)
            .expect("first full pass owns the lease");
        assert!(
            index.begin_cross_repo_refresh_pass(&roots).is_none(),
            "a concurrent full pass must not overlap the active lease"
        );

        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        assert!(
            !index.cross_repo_edges_snapshot().complete,
            "the last source install must not expose completeness before final validation"
        );

        assert!(index.finish_cross_repo_refresh_pass(token, &roots, true));
        assert!(index.cross_repo_edges_snapshot().complete);
    }

    #[test]
    fn all_repo_pass_cannot_commit_after_concurrent_authority_change() {
        let index = SpineIndex::new();
        let repos = vec!["alpha".to_string(), "beta".to_string()];
        index.register_repo("alpha", vec![], "root-a");
        index.register_repo("beta", vec![], "root-b");
        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }

        let roots = BTreeMap::from([
            ("alpha".to_string(), "root-a".to_string()),
            ("beta".to_string(), "root-b".to_string()),
        ]);
        let token = index.begin_cross_repo_refresh_pass(&roots).unwrap();
        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        index.register_repo("beta", vec![], "root-b-next");

        assert!(!index.finish_cross_repo_refresh_pass(token, &roots, true));
        assert!(
            !index.cross_repo_edges_snapshot().complete,
            "a newer root registration must win the pass epoch CAS"
        );
    }

    #[test]
    fn explicit_refresh_invalidation_preserves_edges_but_revokes_completeness() {
        let index = SpineIndex::new();
        let source = test_entry("consumer", "caller", EntityKind::Function);
        let target = test_entry("provider", "target", EntityKind::Function);
        index.register_repo("consumer", vec![source.clone()], "consumer-root");
        index.register_repo("provider", vec![target.clone()], "provider-root");
        let repos = vec!["consumer".to_string(), "provider".to_string()];
        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        index.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "consumer".to_string(),
            src_entity: source.entity_id,
            dst_repo: "provider".to_string(),
            dst_entity: target.entity_id,
            confidence: 0.9,
        });
        assert!(index.cross_repo_edges_snapshot().complete);

        index.invalidate_cross_repo_edges("consumer");
        let invalidated = index.cross_repo_xref_response("provider", &target.entity_id);
        assert!(!invalidated.authority_complete);
        assert_eq!(
            invalidated.edges.len(),
            1,
            "known positives remain advisory"
        );

        index.refresh_cross_repo_edges("consumer", &[], &[], &repos);
        assert!(index.cross_repo_edges_snapshot().complete);
    }

    #[test]
    fn edge_snapshot_requires_nonempty_canonical_root_watermarks() {
        assert!(
            !SpineIndex::new().cross_repo_edges_snapshot().complete,
            "an empty authority root set cannot be proof-complete"
        );

        let index = SpineIndex::new();
        let repos = vec!["alpha".to_string(), "beta".to_string()];
        index.register_repo("alpha", vec![], "root-a");
        index.register_repo("beta", vec![], "");
        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        assert!(
            !index.cross_repo_edges_snapshot().complete,
            "a refreshed repo set with an empty root cannot be proof-complete"
        );

        index.register_repo("beta", vec![], "root-b");
        assert!(
            !index.cross_repo_edges_snapshot().complete,
            "replacing one target must dirty every source until all edges refresh"
        );
        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        assert!(index.cross_repo_edges_snapshot().complete);

        index.register_repo("beta", vec![], " root-b ");
        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        assert!(
            !index.cross_repo_edges_snapshot().complete,
            "a non-canonical whitespace-padded root must fail closed"
        );
    }

    #[test]
    fn registering_a_new_repo_invalidates_every_existing_source_repo() {
        let index = SpineIndex::new();
        let mut repos = vec!["alpha".to_string(), "beta".to_string()];
        index.register_repo("alpha", vec![], "root-a");
        index.register_repo("beta", vec![], "root-b");
        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        assert!(index.cross_repo_edges_snapshot().complete);

        index.register_repo("gamma", vec![], "root-c");
        repos.push("gamma".to_string());
        index.refresh_cross_repo_edges("gamma", &[], &[], &repos);
        assert!(
            !index.cross_repo_edges_snapshot().complete,
            "a new target may change every existing source repo's resolution"
        );

        index.refresh_cross_repo_edges("alpha", &[], &[], &repos);
        assert!(!index.cross_repo_edges_snapshot().complete);
        index.refresh_cross_repo_edges("beta", &[], &[], &repos);
        assert!(index.cross_repo_edges_snapshot().complete);
    }

    #[test]
    fn changing_one_repo_requires_every_other_source_to_refresh() {
        let index = SpineIndex::new();
        let repos = vec!["alpha".to_string(), "beta".to_string()];
        index.register_repo("alpha", vec![], "root-a");
        index.register_repo("beta", vec![], "root-b");
        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        assert!(index.cross_repo_edges_snapshot().complete);

        index.register_repo("alpha", vec![], "root-a-next");
        index.refresh_cross_repo_edges("alpha", &[], &[], &repos);
        assert!(
            !index.cross_repo_edges_snapshot().complete,
            "beta's prior outgoing resolution predates alpha's new authority"
        );
        index.refresh_cross_repo_edges("beta", &[], &[], &repos);
        assert!(index.cross_repo_edges_snapshot().complete);
    }

    #[test]
    fn register_during_refresh_cannot_clear_newer_global_invalidation() {
        let index = Arc::new(SpineIndex::new());
        let repos = vec!["alpha".to_string(), "beta".to_string()];
        index.register_repo("alpha", vec![], "root-a");
        index.register_repo("beta", vec![], "root-b");
        for repo in &repos {
            index.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        assert!(index.cross_repo_edges_snapshot().complete);

        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_index = Arc::clone(&index);
        let worker_repos = repos.clone();
        let worker = thread::spawn(move || {
            worker_index.refresh_cross_repo_edges_with_hook(
                "alpha",
                &[],
                &[],
                &worker_repos,
                || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                },
            );
        });

        started_rx.recv().unwrap();
        index.register_repo("beta", vec![], "root-b-next");
        release_tx.send(()).unwrap();
        worker.join().unwrap();

        assert!(
            !index.cross_repo_edges_snapshot().complete,
            "the old alpha refresh epoch must not clear beta's newer invalidation"
        );
        index.refresh_cross_repo_edges("beta", &[], &[], &repos);
        assert!(
            !index.cross_repo_edges_snapshot().complete,
            "alpha must remain dirty after its stale refresh loses the epoch CAS"
        );
        index.refresh_cross_repo_edges("alpha", &[], &[], &repos);
        assert!(index.cross_repo_edges_snapshot().complete);
    }

    #[test]
    fn concurrent_same_repo_refreshes_are_serialized_and_replace_not_union() {
        let index = Arc::new(SpineIndex::new());
        let source_id = EntityId::from_content("src/a.rs", "source", "function", 1);
        let beta_id = EntityId::from_content("src/b.rs", "beta_target", "function", 1);
        let gamma_id = EntityId::from_content("src/c.rs", "gamma_target", "function", 1);
        let source = test_entity(source_id, "source");
        let repos = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];

        index.register_repo(
            "alpha",
            vec![test_entry_with_id("alpha", source_id, "source")],
            "root-a",
        );
        index.register_repo(
            "beta",
            vec![test_entry_with_id("beta", beta_id, "beta_target")],
            "root-b",
        );
        index.register_repo(
            "gamma",
            vec![test_entry_with_id("gamma", gamma_id, "gamma_target")],
            "root-c",
        );
        index.refresh_cross_repo_edges("beta", &[], &[], &repos);
        index.refresh_cross_repo_edges("gamma", &[], &[], &repos);

        let (first_started_tx, first_started_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first_index = Arc::clone(&index);
        let first_repos = repos.clone();
        let first_source = source.clone();
        let first = thread::spawn(move || {
            let relation = external_call(source_id, "beta", "beta_target");
            first_index.refresh_cross_repo_edges_with_hook(
                "alpha",
                &[first_source],
                &[relation],
                &first_repos,
                || {
                    first_started_tx.send(()).unwrap();
                    release_first_rx.recv().unwrap();
                },
            );
        });
        first_started_rx.recv().unwrap();

        let (second_attempt_tx, second_attempt_rx) = mpsc::channel();
        let (second_done_tx, second_done_rx) = mpsc::channel();
        let second_index = Arc::clone(&index);
        let second_repos = repos.clone();
        let second = thread::spawn(move || {
            second_attempt_tx.send(()).unwrap();
            let relation = external_call(source_id, "gamma", "gamma_target");
            second_index.refresh_cross_repo_edges("alpha", &[source], &[relation], &second_repos);
            second_done_tx.send(()).unwrap();
        });
        second_attempt_rx.recv().unwrap();
        assert!(
            second_done_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "a second refresh must block while the first owns the global serializer"
        );

        release_first_tx.send(()).unwrap();
        first.join().unwrap();
        second.join().unwrap();
        second_done_rx.recv().unwrap();

        let outgoing = index.cross_repo_edges_from("alpha");
        assert_eq!(outgoing.len(), 1, "refreshes must replace, never union");
        assert_eq!(outgoing[0].dst_repo, "gamma");
        assert_eq!(outgoing[0].dst_entity, gamma_id);
        assert!(index.cross_repo_edges_snapshot().complete);
    }

    #[test]
    fn edge_snapshot_rejects_orphan_repos_and_entities() {
        let source_id = EntityId::from_content("src/a.rs", "source", "function", 1);
        let target_id = EntityId::from_content("src/b.rs", "target", "function", 1);
        let repos = vec!["alpha".to_string(), "beta".to_string()];

        let build_index = || {
            let index = SpineIndex::new();
            index.register_repo(
                "alpha",
                vec![test_entry_with_id("alpha", source_id, "source")],
                "root-a",
            );
            index.register_repo(
                "beta",
                vec![test_entry_with_id("beta", target_id, "target")],
                "root-b",
            );
            for repo in &repos {
                index.refresh_cross_repo_edges(repo, &[], &[], &repos);
            }
            index
        };

        let orphan_repo = build_index();
        orphan_repo.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "alpha".to_string(),
            src_entity: source_id,
            dst_repo: "missing".to_string(),
            dst_entity: EntityId::new(),
            confidence: 0.9,
        });
        assert!(!orphan_repo.cross_repo_edges_snapshot().complete);

        let orphan_entity = build_index();
        orphan_entity.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "alpha".to_string(),
            src_entity: source_id,
            dst_repo: "beta".to_string(),
            dst_entity: EntityId::new(),
            confidence: 0.9,
        });
        assert!(!orphan_entity.cross_repo_edges_snapshot().complete);
    }
}
