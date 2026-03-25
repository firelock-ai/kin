// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-repo entity metadata index.
//!
//! Indexes entity metadata (name, kind, signature, fingerprint) across all
//! registered repos. Provides name-based resolution with fingerprint
//! disambiguation for common names like Config, Error, init.

use hashbrown::HashMap;
use kin_model::{EntityId, EntityKind, SemanticFingerprint};
use parking_lot::RwLock;

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
}

/// Cross-repo edge linking two entities across repo boundaries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrossRepoEdge {
    pub src_repo: RepoId,
    pub src_entity: EntityId,
    pub dst_repo: RepoId,
    pub dst_entity: EntityId,
    /// Confidence in the edge (0.0 - 1.0). Name-only matches get lower
    /// confidence than fingerprint-verified matches.
    pub confidence: f32,
}

/// The spine's in-memory cross-repo metadata index.
///
/// Thread-safe via RwLock — multiple readers, exclusive writer.
/// Rebuilt from daemon queries on startup. Updated via SSE events.
pub struct SpineIndex {
    inner: RwLock<SpineInner>,
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
}

impl SpineIndex {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(SpineInner {
                by_name: HashMap::new(),
                by_id: HashMap::new(),
                cross_repo_edges: Vec::new(),
                root_hashes: HashMap::new(),
            }),
        }
    }

    /// Register entities from a repo into the index.
    pub fn register_repo(&self, repo_id: &str, entities: Vec<EntityEntry>, root_hash: &str) {
        let mut inner = self.inner.write();

        // Remove existing entries for this repo (full refresh)
        inner.by_name.values_mut().for_each(|entries| {
            entries.retain(|e| e.repo_id != repo_id);
        });
        inner.by_id.retain(|(rid, _), _| rid != repo_id);

        // Insert new entries
        for entry in entities {
            let key = (entry.name.to_lowercase(), entry.kind);
            inner
                .by_name
                .entry(key)
                .or_default()
                .push(entry.clone());
            inner
                .by_id
                .insert((entry.repo_id.clone(), entry.entity_id), entry);
        }

        inner.root_hashes.insert(repo_id.to_string(), root_hash.to_string());
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
                b_match.partial_cmp(&a_match).unwrap_or(std::cmp::Ordering::Equal)
            });
        }

        results
    }

    /// Get cross-repo edges originating from or targeting a specific entity.
    pub fn cross_repo_edges_for(
        &self,
        repo_id: &str,
        entity_id: &EntityId,
    ) -> Vec<CrossRepoEdge> {
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

    /// Add a cross-repo edge to the index.
    pub fn add_cross_repo_edge(&self, edge: CrossRepoEdge) {
        let mut inner = self.inner.write();
        inner.cross_repo_edges.push(edge);
    }

    /// Look up an entity by (repo_id, entity_id).
    pub fn lookup_by_id(&self, repo_id: &str, entity_id: &EntityId) -> Option<EntityEntry> {
        let inner = self.inner.read();
        inner
            .by_id
            .get(&(repo_id.to_string(), *entity_id))
            .cloned()
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
    use kin_model::{FingerprintAlgorithm, Hash256};

    fn test_fp() -> SemanticFingerprint {
        SemanticFingerprint {
            ast_hash: Hash256::from_bytes([1; 32]),
            signature_hash: Hash256::from_bytes([2; 32]),
            behavior_hash: Hash256::from_bytes([3; 32]),
            algorithm: FingerprintAlgorithm::V1TreeSitter,
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
}
