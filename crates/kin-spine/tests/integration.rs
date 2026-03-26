// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Integration tests for kin-spine federation layer.
//!
//! These tests exercise the full spine stack: SpineIndex registration,
//! cross-repo edge resolution, federated BFS traversal, and routing.

use std::collections::HashSet;

use kin_model::{EntityId, EntityKind, FingerprintAlgorithm, Hash256, SemanticFingerprint};
use kin_spine::index::{CrossRepoEdge, EntityEntry, SpineIndex};
use kin_spine::federation::federated_impact;
use kin_spine::routing::{RepoEndpoint, RoutingTable};

// ── Helpers ─────────────────────────────────────────────────────────────

fn make_fp(seed: u8) -> SemanticFingerprint {
    SemanticFingerprint {
        ast_hash: Hash256::from_bytes([seed; 32]),
        signature_hash: Hash256::from_bytes([seed.wrapping_add(1); 32]),
        behavior_hash: Hash256::from_bytes([seed.wrapping_add(2); 32]),
        algorithm: FingerprintAlgorithm::V1TreeSitter,
        stability_score: 1.0,
    }
}

fn entry(repo: &str, name: &str, kind: EntityKind, fp_seed: u8) -> EntityEntry {
    EntityEntry {
        repo_id: repo.to_string(),
        entity_id: EntityId::new(),
        name: name.to_string(),
        kind,
        signature: format!("fn {name}()"),
        fingerprint: make_fp(fp_seed),
        file_path: Some(format!("src/{name}.rs")),
    }
}

fn fn_entry(repo: &str, name: &str) -> EntityEntry {
    entry(repo, name, EntityKind::Function, 1)
}

// ── Test 1: Resolve entity by name across repos ────────────────────────

#[test]
fn resolve_entity_by_name_finds_across_repos() {
    let index = SpineIndex::new();

    let e_a = fn_entry("repo-a", "process");
    let e_b = fn_entry("repo-b", "process");
    let e_c = fn_entry("repo-c", "unrelated");

    index.register_repo("repo-a", vec![e_a], "h1");
    index.register_repo("repo-b", vec![e_b], "h2");
    index.register_repo("repo-c", vec![e_c], "h3");

    let results = index.resolve("process", Some(EntityKind::Function), None);
    assert_eq!(results.len(), 2, "should find 'process' in both repo-a and repo-b");

    let repos: HashSet<&str> = results.iter().map(|e| e.repo_id.as_str()).collect();
    assert!(repos.contains("repo-a"));
    assert!(repos.contains("repo-b"));
    assert!(!repos.contains("repo-c"));
}

// ── Test 2: Resolve entity by fingerprint disambiguates correctly ──────

#[test]
fn resolve_entity_by_fingerprint_disambiguates() {
    let index = SpineIndex::new();

    let e_a = entry("repo-a", "Config", EntityKind::Class, 10);
    let e_b = entry("repo-b", "Config", EntityKind::Class, 20);

    index.register_repo("repo-a", vec![e_a], "h1");
    index.register_repo("repo-b", vec![e_b], "h2");

    // Reference fingerprint matches repo-b's seed=20
    let ref_fp = make_fp(20);

    let results = index.resolve("Config", Some(EntityKind::Class), Some(&ref_fp));
    assert_eq!(results.len(), 2);
    // repo-b should rank first due to exact fingerprint match
    assert_eq!(
        results[0].repo_id, "repo-b",
        "repo-b should rank first due to fingerprint match"
    );
}

// ── Test 3: Federated impact traverses across repo boundaries ──────────

#[test]
fn federated_impact_traverses_cross_repo() {
    let index = SpineIndex::new();

    let db_entity = fn_entry("kin-db", "query_entities");
    let core_entity = fn_entry("kin", "run_search");
    let editor_entity = fn_entry("kin-editor", "search_panel");

    index.register_repo("kin-db", vec![db_entity.clone()], "h1");
    index.register_repo("kin", vec![core_entity.clone()], "h2");
    index.register_repo("kin-editor", vec![editor_entity.clone()], "h3");

    // kin depends on kin-db (kin calls query_entities)
    index.add_cross_repo_edge(CrossRepoEdge {
        src_repo: "kin".to_string(),
        src_entity: core_entity.entity_id,
        dst_repo: "kin-db".to_string(),
        dst_entity: db_entity.entity_id,
        confidence: 0.9,
    });

    // kin-editor depends on kin (kin-editor calls run_search)
    index.add_cross_repo_edge(CrossRepoEdge {
        src_repo: "kin-editor".to_string(),
        src_entity: editor_entity.entity_id,
        dst_repo: "kin".to_string(),
        dst_entity: core_entity.entity_id,
        confidence: 0.85,
    });

    // Impact of changing query_entities in kin-db
    let result = federated_impact(&index, "kin-db", &db_entity.entity_id, 5);

    let repos: HashSet<&str> = result.repos_involved.iter().map(|s| s.as_str()).collect();
    assert!(repos.contains("kin-db"), "start repo should be included");
    assert!(repos.contains("kin"), "kin depends on kin-db");
    assert!(repos.contains("kin-editor"), "kin-editor transitively depends on kin-db");
    assert!(result.edges.len() >= 2, "should have at least 2 cross-repo edges");
}

// ── Test 4: Cross-repo BFS finds transitive dependencies ───────────────

#[test]
fn cross_repo_bfs_finds_transitive_dependencies() {
    let index = SpineIndex::new();

    // Chain: A <- B <- C <- D (D depends on C depends on B depends on A)
    let a = fn_entry("repo-a", "base_fn");
    let b = fn_entry("repo-b", "mid_fn");
    let c = fn_entry("repo-c", "upper_fn");
    let d = fn_entry("repo-d", "top_fn");

    index.register_repo("repo-a", vec![a.clone()], "h1");
    index.register_repo("repo-b", vec![b.clone()], "h2");
    index.register_repo("repo-c", vec![c.clone()], "h3");
    index.register_repo("repo-d", vec![d.clone()], "h4");

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
    index.add_cross_repo_edge(CrossRepoEdge {
        src_repo: "repo-d".to_string(),
        src_entity: d.entity_id,
        dst_repo: "repo-c".to_string(),
        dst_entity: c.entity_id,
        confidence: 0.9,
    });

    // Impact of changing A: should reach B, C, D (depth 10 is plenty)
    let result = federated_impact(&index, "repo-a", &a.entity_id, 10);

    assert_eq!(result.nodes.len(), 4, "should find all 4 entities in the chain");
    let repos: HashSet<&str> = result.repos_involved.iter().map(|s| s.as_str()).collect();
    assert!(repos.contains("repo-a"));
    assert!(repos.contains("repo-b"));
    assert!(repos.contains("repo-c"));
    assert!(repos.contains("repo-d"));
}

// ── Test 5: RoutingTable routes to correct repo endpoints ──────────────

#[test]
fn routing_table_routes_to_correct_endpoints() {
    let table = RoutingTable::new();

    table.register_endpoint(RepoEndpoint {
        url: "http://daemon-0:4219".to_string(),
        repos: vec!["kin".to_string(), "kin-db".to_string()],
        healthy: true,
        last_check: None,
    });
    table.register_endpoint(RepoEndpoint {
        url: "http://daemon-1:4219".to_string(),
        repos: vec!["kin-editor".to_string(), "kin-vfs".to_string()],
        healthy: true,
        last_check: None,
    });

    assert_eq!(table.route("kin"), Some("http://daemon-0:4219".to_string()));
    assert_eq!(table.route("kin-db"), Some("http://daemon-0:4219".to_string()));
    assert_eq!(table.route("kin-editor"), Some("http://daemon-1:4219".to_string()));
    assert_eq!(table.route("kin-vfs"), Some("http://daemon-1:4219".to_string()));
    assert_eq!(table.route("nonexistent"), None);
    assert_eq!(table.endpoint_count(), 2);
}

// ── Test 6: SpineIndex handles duplicate entity names across repos ─────

#[test]
fn spine_handles_duplicate_names_across_repos() {
    let index = SpineIndex::new();

    // Three repos, each with a "Config" class — common in real codebases
    let c1 = entry("repo-a", "Config", EntityKind::Class, 10);
    let c2 = entry("repo-b", "Config", EntityKind::Class, 20);
    let c3 = entry("repo-c", "Config", EntityKind::Class, 30);

    index.register_repo("repo-a", vec![c1.clone()], "h1");
    index.register_repo("repo-b", vec![c2.clone()], "h2");
    index.register_repo("repo-c", vec![c3.clone()], "h3");

    // All three should be found
    let results = index.resolve("Config", Some(EntityKind::Class), None);
    assert_eq!(results.len(), 3, "all three Config classes should be found");

    // Case-insensitive resolution
    let results_lower = index.resolve("config", Some(EntityKind::Class), None);
    assert_eq!(results_lower.len(), 3, "case-insensitive should also find all three");

    // Each entity should be individually addressable by ID
    assert!(index.lookup_by_id("repo-a", &c1.entity_id).is_some());
    assert!(index.lookup_by_id("repo-b", &c2.entity_id).is_some());
    assert!(index.lookup_by_id("repo-c", &c3.entity_id).is_some());
}

// ── Test 7: Empty index returns empty results ──────────────────────────

#[test]
fn empty_index_returns_empty_results() {
    let index = SpineIndex::new();

    assert_eq!(index.entity_count(), 0);
    assert_eq!(index.repo_count(), 0);
    assert_eq!(index.edge_count(), 0);

    let results = index.resolve("anything", Some(EntityKind::Function), None);
    assert!(results.is_empty());

    let edges = index.cross_repo_edges_for("repo", &EntityId::new());
    assert!(edges.is_empty());

    assert!(index.lookup_by_id("repo", &EntityId::new()).is_none());
    assert!(index.root_hash("repo").is_none());

    // Federated impact on empty index should return just the start node
    let start_id = EntityId::new();
    let result = federated_impact(&index, "repo", &start_id, 5);
    assert_eq!(result.nodes.len(), 1, "only the start node");
    assert!(result.edges.is_empty());
}

// ── Test 8: Single-repo index works same as direct graph query ─────────

#[test]
fn single_repo_index_works_like_direct_query() {
    let index = SpineIndex::new();

    let e1 = fn_entry("my-repo", "handler");
    let e2 = entry("my-repo", "AppConfig", EntityKind::Class, 5);
    let e3 = entry("my-repo", "handler", EntityKind::Method, 6);

    index.register_repo("my-repo", vec![e1.clone(), e2.clone(), e3.clone()], "h1");

    assert_eq!(index.entity_count(), 3);
    assert_eq!(index.repo_count(), 1);

    // Resolve by name returns both handler (function) and handler (method)
    let handlers = index.resolve("handler", None, None);
    assert_eq!(handlers.len(), 2);

    // Resolve by name+kind is specific
    let fns = index.resolve("handler", Some(EntityKind::Function), None);
    assert_eq!(fns.len(), 1);
    assert_eq!(fns[0].entity_id, e1.entity_id);

    let methods = index.resolve("handler", Some(EntityKind::Method), None);
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0].entity_id, e3.entity_id);

    // Root hash is accessible
    assert_eq!(index.root_hash("my-repo"), Some("h1".to_string()));
}

// ── Test 9: Federated BFS respects depth limit ─────────────────────────

#[test]
fn federated_bfs_depth_limit_is_strict() {
    let index = SpineIndex::new();

    let a = fn_entry("repo-a", "fn_a");
    let b = fn_entry("repo-b", "fn_b");
    let c = fn_entry("repo-c", "fn_c");
    let d = fn_entry("repo-d", "fn_d");

    index.register_repo("repo-a", vec![a.clone()], "h1");
    index.register_repo("repo-b", vec![b.clone()], "h2");
    index.register_repo("repo-c", vec![c.clone()], "h3");
    index.register_repo("repo-d", vec![d.clone()], "h4");

    // Chain: a <- b <- c <- d
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
    index.add_cross_repo_edge(CrossRepoEdge {
        src_repo: "repo-d".to_string(),
        src_entity: d.entity_id,
        dst_repo: "repo-c".to_string(),
        dst_entity: c.entity_id,
        confidence: 0.9,
    });

    // Depth 0: only start node
    let r0 = federated_impact(&index, "repo-a", &a.entity_id, 0);
    assert_eq!(r0.nodes.len(), 1, "depth 0 should only return start node");

    // Depth 1: start + repo-b
    let r1 = federated_impact(&index, "repo-a", &a.entity_id, 1);
    assert_eq!(r1.nodes.len(), 2, "depth 1 should reach repo-b only");

    // Depth 2: start + repo-b + repo-c
    let r2 = federated_impact(&index, "repo-a", &a.entity_id, 2);
    assert_eq!(r2.nodes.len(), 3, "depth 2 should reach repo-b and repo-c");

    // Depth 3: all four
    let r3 = federated_impact(&index, "repo-a", &a.entity_id, 3);
    assert_eq!(r3.nodes.len(), 4, "depth 3 should reach all repos");
}

// ── Test 10: Register repo replaces previous entries ───────────────────

#[test]
fn register_repo_replaces_previous_entries() {
    let index = SpineIndex::new();

    let v1 = fn_entry("my-repo", "old_function");
    index.register_repo("my-repo", vec![v1.clone()], "hash-v1");
    assert_eq!(index.entity_count(), 1);
    assert_eq!(index.root_hash("my-repo"), Some("hash-v1".to_string()));

    // Re-register with completely different entities
    let v2a = fn_entry("my-repo", "new_fn_a");
    let v2b = fn_entry("my-repo", "new_fn_b");
    index.register_repo("my-repo", vec![v2a.clone(), v2b.clone()], "hash-v2");

    assert_eq!(index.entity_count(), 2);
    assert_eq!(index.root_hash("my-repo"), Some("hash-v2".to_string()));

    // Old entity should be gone
    let old = index.resolve("old_function", Some(EntityKind::Function), None);
    assert!(old.is_empty(), "old entity should be removed after re-registration");

    // New entities should be present
    let new_a = index.resolve("new_fn_a", Some(EntityKind::Function), None);
    assert_eq!(new_a.len(), 1);
    let new_b = index.resolve("new_fn_b", Some(EntityKind::Function), None);
    assert_eq!(new_b.len(), 1);
}

// ── Test 11: Routing with health status ────────────────────────────────

#[test]
fn routing_table_health_tracking() {
    let table = RoutingTable::new();

    table.register_endpoint(RepoEndpoint {
        url: "http://daemon-0:4219".to_string(),
        repos: vec!["kin".to_string()],
        healthy: true,
        last_check: None,
    });

    let endpoints = table.endpoints();
    assert_eq!(endpoints.len(), 1);
    assert!(endpoints[0].healthy);

    table.mark_unhealthy("http://daemon-0:4219");

    let endpoints = table.endpoints();
    assert!(!endpoints[0].healthy, "endpoint should be marked unhealthy");

    // Routing still works even for unhealthy endpoints (routing != availability)
    assert_eq!(table.route("kin"), Some("http://daemon-0:4219".to_string()));
}

// ── Test 12: Cross-repo edges bidirectional lookup ─────────────────────

#[test]
fn cross_repo_edges_bidirectional_lookup() {
    let index = SpineIndex::new();

    let a = fn_entry("repo-a", "caller");
    let b = fn_entry("repo-b", "callee");

    index.register_repo("repo-a", vec![a.clone()], "h1");
    index.register_repo("repo-b", vec![b.clone()], "h2");

    index.add_cross_repo_edge(CrossRepoEdge {
        src_repo: "repo-a".to_string(),
        src_entity: a.entity_id,
        dst_repo: "repo-b".to_string(),
        dst_entity: b.entity_id,
        confidence: 0.95,
    });

    // Edge should be found from either side
    let from_a = index.cross_repo_edges_for("repo-a", &a.entity_id);
    assert_eq!(from_a.len(), 1);
    assert_eq!(from_a[0].confidence, 0.95);

    let from_b = index.cross_repo_edges_for("repo-b", &b.entity_id);
    assert_eq!(from_b.len(), 1, "edge should be found from destination side too");
    assert_eq!(from_b[0].src_repo, "repo-a");
}

// ── Test 13: Federated impact does not follow outgoing edges ───────────

#[test]
fn federated_impact_only_follows_incoming() {
    let index = SpineIndex::new();

    let a = fn_entry("repo-a", "fn_a");
    let b = fn_entry("repo-b", "fn_b");
    let c = fn_entry("repo-c", "fn_c");

    index.register_repo("repo-a", vec![a.clone()], "h1");
    index.register_repo("repo-b", vec![b.clone()], "h2");
    index.register_repo("repo-c", vec![c.clone()], "h3");

    // a calls b (a is src, b is dst) — a depends on b
    index.add_cross_repo_edge(CrossRepoEdge {
        src_repo: "repo-a".to_string(),
        src_entity: a.entity_id,
        dst_repo: "repo-b".to_string(),
        dst_entity: b.entity_id,
        confidence: 0.9,
    });
    // c calls a (c is src, a is dst) — c depends on a
    index.add_cross_repo_edge(CrossRepoEdge {
        src_repo: "repo-c".to_string(),
        src_entity: c.entity_id,
        dst_repo: "repo-a".to_string(),
        dst_entity: a.entity_id,
        confidence: 0.9,
    });

    // Impact of changing a: c is impacted (c depends on a), b is NOT (a depends on b)
    let result = federated_impact(&index, "repo-a", &a.entity_id, 5);

    let repos: HashSet<&str> = result.repos_involved.iter().map(|s| s.as_str()).collect();
    assert!(repos.contains("repo-c"), "c depends on a → impacted");
    assert!(!repos.contains("repo-b"), "a depends on b → b not impacted");
}

// ── Test 14: Multiple entities per repo with mixed kinds ───────────────

#[test]
fn multiple_entities_per_repo_with_mixed_kinds() {
    let index = SpineIndex::new();

    let entities = vec![
        entry("big-repo", "Config", EntityKind::Class, 1),
        entry("big-repo", "parse", EntityKind::Function, 2),
        entry("big-repo", "Config", EntityKind::Interface, 3),
        entry("big-repo", "TIMEOUT", EntityKind::Constant, 4),
        entry("big-repo", "parse", EntityKind::Method, 5),
    ];

    index.register_repo("big-repo", entities, "h1");
    assert_eq!(index.entity_count(), 5);

    // "Config" matches Class and Interface
    let configs = index.resolve("Config", None, None);
    assert_eq!(configs.len(), 2);

    // "Config" with Class filter returns only the class
    let config_class = index.resolve("Config", Some(EntityKind::Class), None);
    assert_eq!(config_class.len(), 1);
    assert_eq!(config_class[0].kind, EntityKind::Class);

    // "parse" with no kind filter returns both Function and Method
    let parses = index.resolve("parse", None, None);
    assert_eq!(parses.len(), 2);
}
