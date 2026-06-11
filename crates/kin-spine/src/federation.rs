// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Federated BFS across repo boundaries.
//!
//! The query that proves federation works:
//! "What breaks across all repos if I change this function?"
//!
//! The BFS starts in one repo's daemon and uses the spine's precomputed
//! cross-repo edge topology for routing. Only content fetches (entity
//! details) go over the network — topology traversal is local.

use std::collections::{HashSet, VecDeque};

use crate::index::SpineIndex;
use kin_model::EntityId;

/// A node in the federated impact subgraph.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FederatedNode {
    pub repo_id: String,
    pub entity_id: EntityId,
    pub name: String,
    pub kind: String,
    pub file_path: Option<String>,
    /// How many hops from the start entity.
    pub depth: u32,
}

/// An edge in the federated impact subgraph.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FederatedEdge {
    pub src_repo: String,
    pub src_entity: EntityId,
    pub dst_repo: String,
    pub dst_entity: EntityId,
    pub confidence: f32,
    /// Whether this edge crosses a repo boundary.
    pub cross_repo: bool,
}

/// Result of a federated impact query.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FederatedImpact {
    /// Start point of the query.
    pub start_repo: String,
    pub start_entity: EntityId,
    pub max_depth: u32,
    /// All impacted entities across repos.
    pub nodes: Vec<FederatedNode>,
    /// All edges in the impact subgraph (including cross-repo).
    pub edges: Vec<FederatedEdge>,
    /// Repos involved in the impact.
    pub repos_involved: Vec<String>,
}

/// Compute federated impact by BFS-ing through cross-repo edges.
///
/// This performs the BFS entirely within the spine's precomputed edge topology.
/// For intra-repo edges, the caller must provide a `local_neighbors` callback
/// that queries the appropriate daemon for a given entity's outgoing relations.
///
/// In the simplest case (cross-repo only), this BFS uses only the spine's
/// CrossRepoEdge graph — no daemon calls needed.
pub fn federated_impact(
    index: &SpineIndex,
    start_repo: &str,
    start_entity: &EntityId,
    max_depth: u32,
) -> FederatedImpact {
    let mut visited: HashSet<(String, EntityId)> = HashSet::new();
    let mut queue: VecDeque<(String, EntityId, u32)> = VecDeque::new();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut repos: HashSet<String> = HashSet::new();

    // Seed the BFS with the start entity
    visited.insert((start_repo.to_string(), *start_entity));
    queue.push_back((start_repo.to_string(), *start_entity, 0));
    repos.insert(start_repo.to_string());

    // Look up start entity metadata from the index
    let start_meta = index.lookup_by_id(start_repo, start_entity);
    nodes.push(FederatedNode {
        repo_id: start_repo.to_string(),
        entity_id: *start_entity,
        name: start_meta
            .as_ref()
            .map(|e| e.name.clone())
            .unwrap_or_default(),
        kind: start_meta
            .as_ref()
            .map(|e| format!("{:?}", e.kind))
            .unwrap_or_default(),
        file_path: start_meta.as_ref().and_then(|e| e.file_path.clone()),
        depth: 0,
    });

    while let Some((repo_id, entity_id, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }

        // Get all cross-repo edges involving this entity
        let cross_edges = index.cross_repo_edges_for(&repo_id, &entity_id);

        for edge in &cross_edges {
            // Impact analysis: only follow edges where we are the DESTINATION
            // (i.e., someone depends on us). Traverse to the SOURCE (the caller).
            if edge.dst_repo != repo_id || edge.dst_entity != entity_id {
                continue;
            }
            let (target_repo, target_entity) = (&edge.src_repo, &edge.src_entity);

            let key = (target_repo.clone(), *target_entity);
            if visited.contains(&key) {
                continue;
            }
            visited.insert(key);

            repos.insert(target_repo.clone());

            nodes.push(FederatedNode {
                repo_id: target_repo.clone(),
                entity_id: *target_entity,
                name: String::new(), // Resolved later from index
                kind: String::new(),
                file_path: None,
                depth: depth + 1,
            });

            edges.push(FederatedEdge {
                src_repo: repo_id.clone(),
                src_entity: entity_id,
                dst_repo: target_repo.clone(),
                dst_entity: *target_entity,
                confidence: edge.confidence,
                cross_repo: edge.src_repo != edge.dst_repo,
            });

            queue.push_back((target_repo.clone(), *target_entity, depth + 1));
        }
    }

    FederatedImpact {
        start_repo: start_repo.to_string(),
        start_entity: *start_entity,
        max_depth,
        nodes,
        edges,
        repos_involved: repos.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{CrossRepoEdge, EntityEntry};
    use kin_model::{EntityKind, FingerprintAlgorithm, Hash256, SemanticFingerprint};

    fn test_fp() -> SemanticFingerprint {
        SemanticFingerprint {
            ast_hash: Hash256::from_bytes([1; 32]),
            signature_hash: Hash256::from_bytes([2; 32]),
            behavior_hash: Hash256::from_bytes([3; 32]),
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            stability_score: 1.0,
        }
    }

    fn test_entry(repo: &str, name: &str) -> EntityEntry {
        EntityEntry {
            repo_id: repo.to_string(),
            entity_id: EntityId::new(),
            name: name.to_string(),
            kind: EntityKind::Function,
            signature: format!("fn {name}()"),
            fingerprint: test_fp(),
            file_path: Some("src/lib.rs".to_string()),
            role: Some(kin_model::EntityRole::Source),
        }
    }

    #[test]
    fn federated_bfs_follows_cross_repo_edges() {
        let index = SpineIndex::new();

        let a = test_entry("kin-db", "query_entities");
        let b = test_entry("kin", "run_search");
        let c = test_entry("kin-editor", "search_panel");

        index.register_repo("kin-db", vec![a.clone()], "h1");
        index.register_repo("kin", vec![b.clone()], "h2");
        index.register_repo("kin-editor", vec![c.clone()], "h3");

        // kin → kin-db (imports query_entities)
        index.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "kin".to_string(),
            src_entity: b.entity_id,
            dst_repo: "kin-db".to_string(),
            dst_entity: a.entity_id,
            confidence: 0.9,
        });

        // kin-editor → kin (imports run_search)
        index.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "kin-editor".to_string(),
            src_entity: c.entity_id,
            dst_repo: "kin".to_string(),
            dst_entity: b.entity_id,
            confidence: 0.8,
        });

        // Start BFS from query_entities in kin-db — should reach kin and kin-editor
        let result = federated_impact(&index, "kin-db", &a.entity_id, 5);

        assert!(
            result.repos_involved.len() >= 2,
            "should span multiple repos"
        );
        assert!(!result.edges.is_empty(), "should have cross-repo edges");

        // The BFS should find the path: kin-db ← kin ← kin-editor
        let repo_set: HashSet<&str> = result.repos_involved.iter().map(|s| s.as_str()).collect();
        assert!(repo_set.contains("kin-db"));
        assert!(repo_set.contains("kin"));

        // Start node should have real metadata, not placeholders
        assert_eq!(result.nodes[0].name, "query_entities");
        assert!(!result.nodes[0].kind.is_empty());
        assert_eq!(result.nodes[0].file_path.as_deref(), Some("src/lib.rs"));
    }

    #[test]
    fn federated_bfs_only_follows_incoming_edges() {
        // Impact analysis should only follow edges where we are the destination
        // (someone depends on us), NOT edges where we are the source.
        let index = SpineIndex::new();

        let a = test_entry("repo-a", "fn_a");
        let b = test_entry("repo-b", "fn_b");
        let c = test_entry("repo-c", "fn_c");

        index.register_repo("repo-a", vec![a.clone()], "h1");
        index.register_repo("repo-b", vec![b.clone()], "h2");
        index.register_repo("repo-c", vec![c.clone()], "h3");

        // a depends on b (a is src, b is dst) — a calls b
        index.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "repo-a".to_string(),
            src_entity: a.entity_id,
            dst_repo: "repo-b".to_string(),
            dst_entity: b.entity_id,
            confidence: 0.9,
        });
        // c depends on a (c is src, a is dst) — c calls a
        index.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "repo-c".to_string(),
            src_entity: c.entity_id,
            dst_repo: "repo-a".to_string(),
            dst_entity: a.entity_id,
            confidence: 0.9,
        });

        // Impact of changing a: only c should be affected (c depends on a).
        // b should NOT appear (a depends on b, not the other way).
        let result = federated_impact(&index, "repo-a", &a.entity_id, 5);

        let repo_set: HashSet<&str> = result.repos_involved.iter().map(|s| s.as_str()).collect();
        assert!(
            repo_set.contains("repo-c"),
            "c depends on a, should be impacted"
        );
        assert!(
            !repo_set.contains("repo-b"),
            "a depends on b, b should NOT be impacted"
        );
    }

    #[test]
    fn federated_bfs_respects_depth_limit() {
        let index = SpineIndex::new();

        let a = test_entry("repo-a", "fn_a");
        let b = test_entry("repo-b", "fn_b");
        let c = test_entry("repo-c", "fn_c");

        index.register_repo("repo-a", vec![a.clone()], "h1");
        index.register_repo("repo-b", vec![b.clone()], "h2");
        index.register_repo("repo-c", vec![c.clone()], "h3");

        // Chain: a → b → c
        index.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "repo-b".to_string(),
            src_entity: b.entity_id,
            dst_repo: "repo-a".to_string(),
            dst_entity: a.entity_id,
            confidence: 0.9,
        });
        index.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "repo-c".to_string(),
            src_entity: c.entity_id,
            dst_repo: "repo-b".to_string(),
            dst_entity: b.entity_id,
            confidence: 0.9,
        });

        // Depth 1: should reach repo-b but not repo-c
        let result = federated_impact(&index, "repo-a", &a.entity_id, 1);
        assert!(
            result.nodes.len() <= 2,
            "depth 1 should not reach repo-c (3 hops away)"
        );
    }
}
