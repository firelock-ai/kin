// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-repo entity metadata index.
//!
//! Indexes entity metadata (name, kind, signature, fingerprint) across all
//! registered repos. Provides name-based resolution with fingerprint
//! disambiguation for common names like Config, Error, init.

use std::collections::{BTreeMap, HashSet};

use hashbrown::HashMap;
use kin_model::{Entity, EntityId, EntityKind, EntityRole, Relation, SemanticFingerprint};
use parking_lot::{Mutex, RwLock};
use sha2::{Digest, Sha256};

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

/// Versioned wire response for `GET /v1/spine/xref`.
///
/// `edges` remains the canonical topology payload. `entities` is an additive,
/// metadata-only sidecar that lets clients render useful cross-repo references
/// without inventing field names or reading another repository's files. Older
/// version-1 daemons omitted the sidecar, so it defaults to empty on decode.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpineXrefResponse {
    version: u32,
    pub edges: Vec<CrossRepoEdge>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities: Vec<EntityEntry>,
}

impl SpineXrefResponse {
    pub fn new(edges: Vec<CrossRepoEdge>, entities: Vec<EntityEntry>) -> Self {
        Self {
            version: crate::SPINE_PAYLOAD_VERSION,
            edges,
            entities,
        }
    }

    pub fn version(&self) -> u32 {
        self.version
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
        Ok(response)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpineXrefDecodeError {
    #[error("malformed spine xref response: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("unsupported spine xref response version {actual}; supported version is {supported}")]
    UnsupportedVersion { actual: u32, supported: u32 },
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

    /// Graph root hash per repo (for cache coherence).
    root_hashes: HashMap<RepoId, String>,

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
        if self.succeeded && inner.authority_epoch == self.authority_epoch {
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
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(SpineInner {
                by_name: HashMap::new(),
                by_id: HashMap::new(),
                cross_repo_edges: Vec::new(),
                root_hashes: HashMap::new(),
                dirty_edge_repos: HashSet::new(),
                authority_epoch: 0,
                active_edge_refreshes: 0,
            }),
            edge_refresh_serialization: Mutex::new(()),
        }
    }

    /// Register entities from a repo into the index.
    pub fn register_repo(&self, repo_id: &str, entities: Vec<EntityEntry>, root_hash: &str) {
        let mut inner = self.inner.write();

        Self::register_repo_locked(&mut inner, repo_id, entities, root_hash);
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
    }

    /// Resolve an entity by name and kind across all repos.
    /// Returns matches sorted by fingerprint similarity if a reference fingerprint is provided.
    pub fn resolve(
        &self,
        name: &str,
        kind: Option<EntityKind>,
        reference_fingerprint: Option<&SemanticFingerprint>,
    ) -> Vec<EntityEntry> {
        let inner = self.inner.read();

        let mut results = Vec::new();

        if let Some(kind) = kind {
            let key = (name.to_lowercase(), kind);
            if let Some(entries) = inner.by_name.get(&key) {
                results.extend(entries.iter().cloned());
            }
        } else {
            // Search across all kinds
            let name_lower = name.to_lowercase();
            for ((n, _), entries) in &inner.by_name {
                if *n == name_lower {
                    results.extend(entries.iter().cloned());
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
        let (complete, roots, mut edges) = {
            let inner = self.inner.read();
            let roots = inner
                .root_hashes
                .iter()
                .map(|(repo, root)| (repo.clone(), root.clone()))
                .collect::<BTreeMap<_, _>>();
            let edge_authority_is_closed = inner.cross_repo_edges.iter().all(|edge| {
                inner.root_hashes.contains_key(&edge.src_repo)
                    && inner.root_hashes.contains_key(&edge.dst_repo)
                    && inner
                        .by_id
                        .contains_key(&(edge.src_repo.clone(), edge.src_entity))
                    && inner
                        .by_id
                        .contains_key(&(edge.dst_repo.clone(), edge.dst_entity))
            });
            (
                inner.active_edge_refreshes == 0
                    && inner.dirty_edge_repos.is_empty()
                    && !roots.is_empty()
                    && roots
                        .values()
                        .all(|root| !root.is_empty() && root.trim() == root)
                    && edge_authority_is_closed,
                roots,
                inner.cross_repo_edges.clone(),
            )
        };

        edges.sort_by(cross_repo_edge_order);
        edges.dedup_by(|a, b| cross_repo_edge_identity_order(a, b).is_eq());

        let repos = roots.keys().cloned().collect::<Vec<_>>();
        let revision = cross_repo_snapshot_revision(&roots, &edges);
        CrossRepoEdgesSnapshot {
            complete,
            revision,
            repos,
            roots,
            edges,
        }
    }

    /// Add a cross-repo edge to the index.
    ///
    /// Returns `false` when the candidate does not cross a repository
    /// boundary. Keeping this invariant at the storage boundary prevents a
    /// resolver bug or stale durable row from making an intra-repo reference
    /// look like hosted cross-repo proof.
    pub fn add_cross_repo_edge(&self, edge: CrossRepoEdge) -> bool {
        if edge.src_repo == edge.dst_repo {
            return false;
        }
        let mut inner = self.inner.write();
        inner.cross_repo_edges.push(edge);
        true
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
        use crate::xref::{collect_unresolved_imports, materialized_edges, resolve_imports};

        let _serialized = self.edge_refresh_serialization.lock();
        let mut refresh = self.begin_edge_refresh(repo_id, entities);
        after_start();

        // Resolve into a detached replacement before taking the mutation lock.
        // Installing the full outgoing set in one write prevents readers from
        // seeing a partial or interleaved union.
        let unresolved =
            collect_unresolved_imports(entities, relations, repo_id, registry_repo_ids);
        let replacement = if unresolved.is_empty() {
            Vec::new()
        } else {
            let resolutions = resolve_imports(self, &unresolved);
            materialized_edges(&unresolved, &resolutions)
        };
        let mut inner = self.inner.write();
        inner.cross_repo_edges.retain(|e| e.src_repo != repo_id);
        inner.cross_repo_edges.extend(replacement);
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

    fn test_entry_with_id(repo: &str, id: EntityId, name: &str) -> EntityEntry {
        let mut entry = test_entry(repo, name, EntityKind::Function);
        entry.entity_id = id;
        entry
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
    }

    #[test]
    fn xref_wire_response_accepts_version_one_without_metadata_sidecar() {
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
