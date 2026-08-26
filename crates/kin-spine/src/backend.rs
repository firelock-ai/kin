// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! SpineBackend trait — abstraction over spine metadata storage.
//!
//! Backends:
//! - `InMemorySpineBackend`: wraps the existing `SpineIndex` (default, local dev)
//! - `FirestoreSpineBackend`: Firestore REST API (cloud, stateless daemon pool)
//! - `CachedSpineBackend<B>`: LRU cache wrapper for any backend

use std::collections::{BTreeMap, HashSet};

use kin_model::{Entity, EntityId, EntityKind, Relation, SemanticFingerprint};

use crate::federation::{self, FederatedImpact};
use crate::index::{
    CrossRepoEdge, CrossRepoEdgesSnapshot, EntityEntry, SpineIndex, SpineXrefResponse,
};

/// Error type for spine backend operations.
#[derive(Debug, thiserror::Error)]
pub enum SpineError {
    #[error("backend error: {0}")]
    Backend(String),

    #[error("entity not found: {0}")]
    NotFound(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("authentication error: {0}")]
    Auth(String),
}

/// Abstraction over spine metadata storage.
///
/// All methods are synchronous (blocking) for compatibility with the existing
/// SpineIndex call sites. The FirestoreSpineBackend uses `tokio::runtime::Handle`
/// internally to bridge async HTTP calls.
pub trait SpineBackend: Send + Sync {
    /// Register all entities from a repo, replacing any previous entries.
    fn register_repo(&self, repo_id: &str, entries: Vec<EntityEntry>, root_hash: &str);

    /// Resolve an entity by name and optional kind across all repos.
    fn resolve(
        &self,
        name: &str,
        kind: Option<EntityKind>,
        reference_fingerprint: Option<&SemanticFingerprint>,
    ) -> Vec<EntityEntry>;

    /// Look up an entity by (repo_id, entity_id).
    fn lookup_by_id(&self, repo_id: &str, entity_id: &EntityId) -> Option<EntityEntry>;

    /// Get cross-repo edges involving a specific entity.
    fn cross_repo_edges_for(&self, repo_id: &str, entity_id: &EntityId) -> Vec<CrossRepoEdge>;

    /// Atomically capture the complete graph-authoritative cross-repo edge set.
    ///
    /// The fail-closed default preserves source compatibility for external
    /// patch-release implementers of this trait. Backends must override it only
    /// when they can provide one atomic authority capture.
    fn cross_repo_edges_snapshot(&self) -> CrossRepoEdgesSnapshot {
        CrossRepoEdgesSnapshot::default()
    }

    /// Atomically project xrefs for one repository/entity anchor.
    ///
    /// The compatibility default remains fail-closed because the default bulk
    /// snapshot is incomplete. Built-in backends override this with a bounded
    /// incident-edge projection that does not clone the organization graph.
    fn cross_repo_xref_response(&self, repo_id: &str, entity_id: &EntityId) -> SpineXrefResponse {
        SpineXrefResponse::from_snapshot(self.cross_repo_edges_snapshot(), repo_id, entity_id)
    }

    /// Add a cross-repo edge.
    fn add_cross_repo_edge(&self, edge: CrossRepoEdge);

    /// Get the root hash for a repo (for cache coherence).
    fn root_hash(&self, repo_id: &str) -> Option<String>;

    /// Total number of indexed entities.
    fn entity_count(&self) -> usize;

    /// Number of registered repos.
    fn repo_count(&self) -> usize;

    /// Number of cross-repo edges.
    fn edge_count(&self) -> usize;

    /// Set of all registered repo IDs.
    fn registered_repo_ids(&self) -> HashSet<String>;

    /// Refresh cross-repo edges for a repo from its entities and relations.
    fn refresh_cross_repo_edges(
        &self,
        repo_id: &str,
        entities: &[Entity],
        relations: &[Relation],
        registry_repo_ids: &[String],
    );

    /// Fail closed after a refresh/load failure while preserving last-known
    /// positive edges for advisory use. This is required rather than a no-op
    /// default so a backend cannot advertise complete snapshots while silently
    /// ignoring a failed refresh.
    fn invalidate_cross_repo_edges(&self, repo_id: &str);

    /// Whether the cross-repo edge authority this backend is serving is
    /// complete.
    ///
    /// The default derives it from the snapshot, which is correct for any
    /// backend and costs a full materialization; a backend that can answer
    /// cheaply should override. Reported so an empty cross-repo answer can say
    /// whether it is an observed zero or an unbuilt authority.
    fn authority_complete(&self) -> bool {
        self.cross_repo_edges_snapshot().complete
    }

    /// Acquire one all-repo refresh lease against an exact registered root set.
    /// While active, per-source refreshes cannot advertise completeness.
    fn begin_cross_repo_refresh_pass(
        &self,
        authority_roots: &BTreeMap<String, String>,
    ) -> Option<u64>;

    /// Atomically publish (or abort) the all-repo pass after final validation.
    fn finish_cross_repo_refresh_pass(
        &self,
        token: u64,
        authority_roots: &BTreeMap<String, String>,
        success: bool,
    ) -> bool;

    /// Compute federated impact by BFS through cross-repo edges.
    fn federated_impact(
        &self,
        start_repo: &str,
        start_entity: &EntityId,
        max_depth: u32,
    ) -> FederatedImpact;
}

/// In-memory spine backend — wraps the existing `SpineIndex`.
///
/// This is the default backend for local development and single-daemon mode.
/// All data is held in memory with no external dependencies.
pub struct InMemorySpineBackend {
    index: SpineIndex,
}

impl InMemorySpineBackend {
    pub fn new() -> Self {
        Self {
            index: SpineIndex::new(),
        }
    }

    /// Get a reference to the underlying SpineIndex.
    /// Useful for callers that need direct access (e.g., xref resolution).
    pub fn index(&self) -> &SpineIndex {
        &self.index
    }
}

impl Default for InMemorySpineBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SpineBackend for InMemorySpineBackend {
    fn authority_complete(&self) -> bool {
        self.index.authority_is_complete()
    }

    fn register_repo(&self, repo_id: &str, entries: Vec<EntityEntry>, root_hash: &str) {
        self.index.register_repo(repo_id, entries, root_hash);
    }

    fn resolve(
        &self,
        name: &str,
        kind: Option<EntityKind>,
        reference_fingerprint: Option<&SemanticFingerprint>,
    ) -> Vec<EntityEntry> {
        self.index.resolve(name, kind, reference_fingerprint)
    }

    fn lookup_by_id(&self, repo_id: &str, entity_id: &EntityId) -> Option<EntityEntry> {
        self.index.lookup_by_id(repo_id, entity_id)
    }

    fn cross_repo_edges_for(&self, repo_id: &str, entity_id: &EntityId) -> Vec<CrossRepoEdge> {
        self.index.cross_repo_edges_for(repo_id, entity_id)
    }

    fn cross_repo_edges_snapshot(&self) -> CrossRepoEdgesSnapshot {
        self.index.cross_repo_edges_snapshot()
    }

    fn cross_repo_xref_response(&self, repo_id: &str, entity_id: &EntityId) -> SpineXrefResponse {
        self.index.cross_repo_xref_response(repo_id, entity_id)
    }

    fn add_cross_repo_edge(&self, edge: CrossRepoEdge) {
        self.index.add_cross_repo_edge(edge);
    }

    fn root_hash(&self, repo_id: &str) -> Option<String> {
        self.index.root_hash(repo_id)
    }

    fn entity_count(&self) -> usize {
        self.index.entity_count()
    }

    fn repo_count(&self) -> usize {
        self.index.repo_count()
    }

    fn edge_count(&self) -> usize {
        self.index.edge_count()
    }

    fn registered_repo_ids(&self) -> HashSet<String> {
        self.index.registered_repo_ids()
    }

    fn refresh_cross_repo_edges(
        &self,
        repo_id: &str,
        entities: &[Entity],
        relations: &[Relation],
        registry_repo_ids: &[String],
    ) {
        self.index
            .refresh_cross_repo_edges(repo_id, entities, relations, registry_repo_ids);
    }

    fn invalidate_cross_repo_edges(&self, repo_id: &str) {
        self.index.invalidate_cross_repo_edges(repo_id);
    }

    fn begin_cross_repo_refresh_pass(
        &self,
        authority_roots: &BTreeMap<String, String>,
    ) -> Option<u64> {
        self.index.begin_cross_repo_refresh_pass(authority_roots)
    }

    fn finish_cross_repo_refresh_pass(
        &self,
        token: u64,
        authority_roots: &BTreeMap<String, String>,
        success: bool,
    ) -> bool {
        self.index
            .finish_cross_repo_refresh_pass(token, authority_roots, success)
    }

    fn federated_impact(
        &self,
        start_repo: &str,
        start_entity: &EntityId,
        max_depth: u32,
    ) -> FederatedImpact {
        federation::federated_impact(&self.index, start_repo, start_entity, max_depth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{FingerprintAlgorithm, Hash256, SemanticFingerprint};

    struct PatchCompatibleBackend;

    impl SpineBackend for PatchCompatibleBackend {
        fn register_repo(&self, _: &str, _: Vec<EntityEntry>, _: &str) {}

        fn resolve(
            &self,
            _: &str,
            _: Option<EntityKind>,
            _: Option<&SemanticFingerprint>,
        ) -> Vec<EntityEntry> {
            Vec::new()
        }

        fn lookup_by_id(&self, _: &str, _: &EntityId) -> Option<EntityEntry> {
            None
        }

        fn cross_repo_edges_for(&self, _: &str, _: &EntityId) -> Vec<CrossRepoEdge> {
            Vec::new()
        }

        fn add_cross_repo_edge(&self, _: CrossRepoEdge) {}

        fn root_hash(&self, _: &str) -> Option<String> {
            None
        }

        fn entity_count(&self) -> usize {
            0
        }

        fn repo_count(&self) -> usize {
            0
        }

        fn edge_count(&self) -> usize {
            0
        }

        fn registered_repo_ids(&self) -> HashSet<String> {
            HashSet::new()
        }

        fn refresh_cross_repo_edges(&self, _: &str, _: &[Entity], _: &[Relation], _: &[String]) {}

        fn invalidate_cross_repo_edges(&self, _: &str) {}

        fn begin_cross_repo_refresh_pass(&self, _: &BTreeMap<String, String>) -> Option<u64> {
            None
        }

        fn finish_cross_repo_refresh_pass(
            &self,
            _: u64,
            _: &BTreeMap<String, String>,
            _: bool,
        ) -> bool {
            false
        }

        fn federated_impact(&self, _: &str, _: &EntityId, _: u32) -> FederatedImpact {
            panic!("not used by compatibility test")
        }
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

    #[test]
    fn snapshot_method_default_is_patch_compatible_and_fail_closed() {
        let snapshot = PatchCompatibleBackend.cross_repo_edges_snapshot();
        assert!(!snapshot.complete);
        assert!(snapshot.repos.is_empty());
        assert!(snapshot.roots.is_empty());
        assert!(snapshot.edges.is_empty());
        assert!(snapshot.revision.starts_with("sha256:"));
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
            role: Some(kin_model::EntityRole::Source),
        }
    }

    #[test]
    fn in_memory_backend_basic_ops() {
        let backend = InMemorySpineBackend::new();

        backend.register_repo(
            "repo-a",
            vec![
                test_entry("repo-a", "Config", EntityKind::Class),
                test_entry("repo-a", "parse", EntityKind::Function),
            ],
            "hash-a",
        );

        assert_eq!(backend.entity_count(), 2);
        assert_eq!(backend.repo_count(), 1);

        let results = backend.resolve("Config", Some(EntityKind::Class), None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].repo_id, "repo-a");

        assert_eq!(backend.root_hash("repo-a"), Some("hash-a".to_string()));
    }

    #[test]
    fn in_memory_backend_cross_repo_edges() {
        let backend = InMemorySpineBackend::new();

        let entry_a = test_entry("repo-a", "caller", EntityKind::Function);
        let entry_b = test_entry("repo-b", "callee", EntityKind::Function);

        backend.register_repo("repo-a", vec![entry_a.clone()], "hash-a");
        backend.register_repo("repo-b", vec![entry_b.clone()], "hash-b");

        backend.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "repo-a".to_string(),
            src_entity: entry_a.entity_id,
            dst_repo: "repo-b".to_string(),
            dst_entity: entry_b.entity_id,
            confidence: 0.95,
        });

        let edges = backend.cross_repo_edges_for("repo-a", &entry_a.entity_id);
        assert_eq!(edges.len(), 1);
        assert_eq!(backend.edge_count(), 1);
    }

    #[test]
    fn in_memory_backend_federated_impact() {
        let backend = InMemorySpineBackend::new();

        let a = test_entry("repo-a", "fn_a", EntityKind::Function);
        let b = test_entry("repo-b", "fn_b", EntityKind::Function);

        backend.register_repo("repo-a", vec![a.clone()], "h1");
        backend.register_repo("repo-b", vec![b.clone()], "h2");

        // b depends on a (b calls a)
        backend.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "repo-b".to_string(),
            src_entity: b.entity_id,
            dst_repo: "repo-a".to_string(),
            dst_entity: a.entity_id,
            confidence: 0.9,
        });

        let impact = backend.federated_impact("repo-a", &a.entity_id, 5);
        assert!(impact.repos_involved.contains(&"repo-b".to_string()));
    }
}
