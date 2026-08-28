// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Integration tests for kin-spine federation layer.
//!
//! These tests exercise the full spine stack: SpineIndex registration,
//! cross-repo edge resolution, federated BFS traversal, and routing.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;

use kin_model::{
    Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, GraphNodeId,
    Hash256, LanguageId, Relation, RelationEvidence, RelationId, RelationKind, RelationOrigin,
    SemanticFingerprint, Visibility,
};
use kin_spine::backend::SpineBackend;
use kin_spine::federation::federated_impact;
use kin_spine::index::{CrossRepoEdge, EntityEntry, SpineIndex};
use kin_spine::routing::{RepoEndpoint, RoutingTable};
use kin_spine::{
    FirestoreSpineBackend, LegacySpineWriterDrainAttestation, LoadedRepo,
    LoadedRepoPublication, LoadedSpineRolloutFence, PreparedStorePublication,
    RepoPublicationCleanupProgress, RepoPublicationCommit, RepoPublicationConflict,
    RepoPublicationHead, RepoSpinePublication, SpineError, SpineRolloutFence,
    SpineRolloutFenceCommit, SpineRolloutFenceEvidence, SpineRolloutRepositoryFence,
    SpineSourceCursor, SpineStore, StoreHeadPrecondition, StorePublicationStageGuard,
    StoreRepoHeadGuard, LEGACY_SPINE_WRITER_DRAIN_SCHEMA,
};

// ── Helpers ─────────────────────────────────────────────────────────────

fn make_fp(seed: u8) -> SemanticFingerprint {
    SemanticFingerprint {
        ast_hash: Hash256::from_bytes([seed; 32]),
        signature_hash: Hash256::from_bytes([seed.wrapping_add(1); 32]),
        behavior_hash: Hash256::from_bytes([seed.wrapping_add(2); 32]),
        algorithm: FingerprintAlgorithm::V1TreeSitter,
        equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
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
        role: Some(kin_model::EntityRole::Source),
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
    assert_eq!(
        results.len(),
        2,
        "should find 'process' in both repo-a and repo-b"
    );

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
    assert!(
        repos.contains("kin-editor"),
        "kin-editor transitively depends on kin-db"
    );
    assert!(
        result.edges.len() >= 2,
        "should have at least 2 cross-repo edges"
    );
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

    assert_eq!(
        result.nodes.len(),
        4,
        "should find all 4 entities in the chain"
    );
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
    assert_eq!(
        table.route("kin-db"),
        Some("http://daemon-0:4219".to_string())
    );
    assert_eq!(
        table.route("kin-editor"),
        Some("http://daemon-1:4219".to_string())
    );
    assert_eq!(
        table.route("kin-vfs"),
        Some("http://daemon-1:4219".to_string())
    );
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
    assert_eq!(
        results_lower.len(),
        3,
        "case-insensitive should also find all three"
    );

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
    assert!(
        old.is_empty(),
        "old entity should be removed after re-registration"
    );

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
    assert_eq!(
        from_b.len(),
        1,
        "edge should be found from destination side too"
    );
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

// ── Hosted-shaped multi-repo xref (no local disk, no network) ──────────
//
// The hosted daemon runs one repo per pod and owns no local sibling
// checkouts: the cross-repo index has to come from the durable spine store,
// not from on-disk sibling `.kndb` graphs. These tests stand up the exact
// store-backed backend a cloud pod builds (`FirestoreSpineBackend` over a
// `SpineStore`), hydrate it from a store seeded by a separate writer, drive
// the cross-repo edge refresh over the primary repo's relations, and assert
// the per-entity edge contract that backs `GET /spine/xref` returns
// non-empty cross-repo edges. The store seam is in-memory here so the whole
// pipeline runs with no Firestore and no filesystem siblings.

/// In-memory [`SpineStore`] standing in for Firestore: immutable staged
/// publications plus one revision-checked head per repository. Shared between
/// a writer backend and a freshly started pod via `Arc`.
struct HostedFakeStore {
    repos: Mutex<HashMap<String, (String, Vec<EntityEntry>)>>,
    edges: Mutex<Vec<CrossRepoEdge>>,
    publications: Mutex<HostedPublicationState>,
    rollout_fence: Mutex<Option<(u64, SpineRolloutFence)>>,
    legacy_migration_seal: Mutex<
        Option<(
            SpineRolloutFenceEvidence,
            LegacySpineWriterDrainAttestation,
            Vec<RepoPublicationHead>,
        )>,
    >,
}

#[derive(Default)]
struct HostedPublicationState {
    heads: HashMap<String, (u64, RepoPublicationHead)>,
    staged: HashMap<String, LoadedRepoPublication>,
    stage_revisions: HashMap<String, u64>,
}

impl Default for HostedFakeStore {
    fn default() -> Self {
        let expected = vec!["kin".to_string(), "kin-db".to_string()];
        let fence = SpineRolloutFence::new_exact(
            "gcs://test-bucket/test-prefix".to_string(),
            1,
            "hosted-integration-rollout",
            &expected,
            vec![
                SpineRolloutRepositoryFence {
                    repo_id: "kin".to_string(),
                    pre_fence_generation: 10,
                    fenced_generation: 11,
                    snapshot_schema: 4,
                    e_tag: Some("kin-etag".to_string()),
                },
                SpineRolloutRepositoryFence {
                    repo_id: "kin-db".to_string(),
                    pre_fence_generation: 20,
                    fenced_generation: 21,
                    snapshot_schema: 4,
                    e_tag: Some("kin-db-etag".to_string()),
                },
            ],
        )
        .expect("valid hosted test rollout fence");
        Self {
            repos: Mutex::new(HashMap::new()),
            edges: Mutex::new(Vec::new()),
            publications: Mutex::new(HostedPublicationState::default()),
            rollout_fence: Mutex::new(Some((1, fence))),
            legacy_migration_seal: Mutex::new(None),
        }
    }
}

impl SpineStore for HostedFakeStore {
    fn load_rollout_fence(&self) -> Result<Option<LoadedSpineRolloutFence>, SpineError> {
        Ok(self
            .rollout_fence
            .lock()
            .unwrap()
            .as_ref()
            .map(|(revision, fence)| LoadedSpineRolloutFence {
                fence: fence.clone(),
                update_time: revision.to_string(),
            }))
    }

    fn advance_rollout_fence(
        &self,
        candidate: SpineRolloutFence,
    ) -> Result<SpineRolloutFenceCommit, SpineError> {
        let mut state = self.rollout_fence.lock().unwrap();
        if let Some((revision, current)) = state.as_ref() {
            if current.payload_sha256 == candidate.payload_sha256 {
                return Ok(SpineRolloutFenceCommit::AlreadyCurrent(
                    SpineRolloutFenceEvidence {
                        rollout_fence: current.rollout_fence,
                        payload_sha256: current.payload_sha256.clone(),
                        update_time: revision.to_string(),
                    },
                ));
            }
            if current.scope != candidate.scope || current.rollout_fence >= candidate.rollout_fence
            {
                return Ok(SpineRolloutFenceCommit::Conflict {
                    attempted_rollout_fence: candidate.rollout_fence,
                    observed: Some(SpineRolloutFenceEvidence {
                        rollout_fence: current.rollout_fence,
                        payload_sha256: current.payload_sha256.clone(),
                        update_time: revision.to_string(),
                    }),
                });
            }
        }
        let revision = state
            .as_ref()
            .map_or(1, |(revision, _)| revision.saturating_add(1));
        *state = Some((revision, candidate.clone()));
        Ok(SpineRolloutFenceCommit::Advanced(
            SpineRolloutFenceEvidence {
                rollout_fence: candidate.rollout_fence,
                payload_sha256: candidate.payload_sha256,
                update_time: revision.to_string(),
            },
        ))
    }

    fn legacy_migration_complete(&self) -> Result<bool, SpineError> {
        let seal = self.legacy_migration_seal.lock().unwrap();
        let Some((sealed_evidence, writer_drain, sealed_heads)) = seal.as_ref() else {
            return Ok(false);
        };
        writer_drain.validate()?;
        let active = self.load_rollout_fence()?.ok_or_else(|| {
            SpineError::Backend(
                "hosted integration migration seal has no rollout fence".to_string(),
            )
        })?;
        let expected_ids = active
            .fence
            .repositories
            .iter()
            .map(|row| row.repo_id.as_str())
            .collect::<Vec<_>>();
        let sealed_ids = sealed_heads
            .iter()
            .map(|head| head.repo_id.as_str())
            .collect::<Vec<_>>();
        if sealed_evidence != &active.evidence()
            || writer_drain.rollout_fence_evidence != *sealed_evidence
            || sealed_ids != expected_ids
        {
            return Err(SpineError::Backend(
                "hosted integration migration seal does not match active authority"
                    .to_string(),
            ));
        }
        Ok(true)
    }

    fn complete_legacy_migration(
        &self,
        rollout_fence: &LoadedSpineRolloutFence,
        writer_drain: &LegacySpineWriterDrainAttestation,
    ) -> Result<(), SpineError> {
        writer_drain.validate()?;
        if writer_drain.rollout_fence_evidence != rollout_fence.evidence() {
            return Err(SpineError::Backend(
                "hosted integration writer-drain evidence does not match rollout fence"
                    .to_string(),
            ));
        }
        let state = self.publications.lock().unwrap();
        let mut heads = state
            .heads
            .values()
            .map(|(_, head)| head.clone())
            .collect::<Vec<_>>();
        heads.sort_by(|left, right| left.repo_id.cmp(&right.repo_id));
        let expected_ids = rollout_fence
            .fence
            .repositories
            .iter()
            .map(|row| row.repo_id.as_str())
            .collect::<Vec<_>>();
        let observed_ids = heads
            .iter()
            .map(|head| head.repo_id.as_str())
            .collect::<Vec<_>>();
        if observed_ids != expected_ids {
            return Err(SpineError::Backend(
                "hosted integration migration seal requires exact fleet heads"
                    .to_string(),
            ));
        }
        drop(state);
        let candidate = (rollout_fence.evidence(), writer_drain.clone(), heads);
        let mut seal = self.legacy_migration_seal.lock().unwrap();
        if let Some(existing) = seal.as_ref() {
            if existing != &candidate {
                return Err(SpineError::Backend(
                    "a different hosted integration migration seal already exists"
                        .to_string(),
                ));
            }
            return Ok(());
        }
        *seal = Some(candidate);
        Ok(())
    }

    fn prepare_repo_publication(
        &self,
        publication: RepoSpinePublication,
    ) -> Result<PreparedStorePublication, SpineError> {
        let rollout_fence = self.load_rollout_fence()?.ok_or_else(|| {
            SpineError::Backend("hosted integration rollout fence is missing".to_string())
        })?;
        let mut state = self.publications.lock().unwrap();
        let observed = state.heads.get(&publication.repo_id).cloned();
        let (precondition, observed_head) = match observed {
            Some((revision, head)) => (
                StoreHeadPrecondition::Revision(revision.to_string()),
                Some(head),
            ),
            None => (StoreHeadPrecondition::Missing, None),
        };
        let mut dependency_heads = BTreeMap::new();
        for (repo_id, expected_root) in publication
            .resolution_roots
            .as_ref()
            .into_iter()
            .flat_map(|roots| roots.iter())
        {
            if repo_id == &publication.repo_id {
                continue;
            }
            let (revision, head) = state.heads.get(repo_id).cloned().ok_or_else(|| {
                SpineError::Backend(format!(
                    "hosted integration edge publication is missing dependency head {repo_id}"
                ))
            })?;
            if head.root_hash != *expected_root {
                return Err(SpineError::Backend(format!(
                    "hosted integration edge publication resolved {repo_id} at {expected_root}, but head is at {}",
                    head.root_hash
                )));
            }
            dependency_heads.insert(
                repo_id.clone(),
                StoreRepoHeadGuard {
                    head,
                    precondition: StoreHeadPrecondition::Revision(revision.to_string()),
                },
            );
        }
        let mut prepared = PreparedStorePublication::new_fenced(
            publication,
            observed_head,
            precondition,
            dependency_heads,
            rollout_fence,
        )?;
        if prepared.requires_staging() {
            let candidate = prepared.publication();
            state.staged.insert(
                prepared.candidate_head().publication_id.clone(),
                LoadedRepoPublication {
                    head: prepared.candidate_head().clone(),
                    entries: candidate.entries.clone(),
                    outgoing_edges: candidate.outgoing_edges.clone().unwrap_or_default(),
                },
            );
            let publication_id = prepared.candidate_head().publication_id.clone();
            let revision = state
                .stage_revisions
                .entry(publication_id)
                .or_insert(1);
            prepared = prepared.bind_stage_guard(StorePublicationStageGuard {
                stage_sequence: 1,
                revision_sha256: format!("hosted-integration-stage-{revision}"),
                update_time: revision.to_string(),
            })?;
        }
        Ok(prepared)
    }

    fn commit_repo_publication(
        &self,
        prepared: &PreparedStorePublication,
    ) -> Result<RepoPublicationCommit, SpineError> {
        let candidate = prepared.candidate_head().clone();
        if let Some(RepoPublicationCommit::Conflict(conflict)) = prepared.terminal_result() {
            return Ok(RepoPublicationCommit::Conflict(conflict));
        }
        let prepared_fence = prepared.rollout_fence().ok_or_else(|| {
            SpineError::Backend(
                "hosted integration publication has no rollout fence".to_string(),
            )
        })?;
        let fence_state = self.rollout_fence.lock().unwrap();
        let mut state = self.publications.lock().unwrap();
        let current = state.heads.get(&candidate.repo_id).cloned();
        if !fence_state.as_ref().is_some_and(|(revision, fence)| {
            revision.to_string() == prepared_fence.update_time
                && fence.payload_sha256 == prepared_fence.fence.payload_sha256
        }) {
            return Ok(RepoPublicationCommit::Conflict(
                RepoPublicationConflict::against_rollout_fence(
                    candidate.source_cursor,
                    prepared_fence.fence.rollout_fence,
                    current.as_ref().map(|(_, head)| head),
                    fence_state.as_ref().map(|(_, fence)| fence),
                ),
            ));
        }
        if prepared.requires_staging() {
            let stage_guard = prepared.stage_guard().ok_or_else(|| {
                SpineError::Backend(
                    "hosted integration publication has no stage guard".to_string(),
                )
            })?;
            let stage_matches = state
                .stage_revisions
                .get(&candidate.publication_id)
                .is_some_and(|revision| revision.to_string() == stage_guard.update_time);
            if !stage_matches {
                return Ok(RepoPublicationCommit::Conflict(
                    RepoPublicationConflict::against(
                        candidate.source_cursor,
                        current.as_ref().map(|(_, head)| head),
                    ),
                ));
            }
        }
        for (repo_id, guard) in prepared.dependency_heads() {
            let observed_dependency = state.heads.get(repo_id).cloned();
            let dependency_matches = match (&guard.precondition, &observed_dependency) {
                (StoreHeadPrecondition::Revision(expected), Some((revision, head))) => {
                    expected == &revision.to_string() && head == &guard.head
                }
                _ => false,
            };
            if !dependency_matches {
                return Ok(RepoPublicationCommit::Conflict(
                    RepoPublicationConflict::against_dependency(
                        candidate.source_cursor,
                        repo_id,
                        observed_dependency.as_ref().map(|(_, head)| head),
                    ),
                ));
            }
        }
        let precondition_matches = match (prepared.head_precondition(), &current) {
            (StoreHeadPrecondition::Missing, None) => true,
            (StoreHeadPrecondition::Revision(expected), Some((revision, _))) => {
                expected == &revision.to_string()
            }
            _ => false,
        };
        if !precondition_matches {
            if current
                .as_ref()
                .is_some_and(|(_, head)| head.publication_id == candidate.publication_id)
            {
                return Ok(RepoPublicationCommit::AlreadyCommitted {
                    source_cursor: candidate.source_cursor,
                });
            }
            return Ok(RepoPublicationCommit::Conflict(
                RepoPublicationConflict::against(
                    candidate.source_cursor,
                    current.as_ref().map(|(_, head)| head),
                ),
            ));
        }
        if matches!(
            prepared.terminal_result(),
            Some(RepoPublicationCommit::AlreadyCommitted { .. })
        ) {
            if current
                .as_ref()
                .is_some_and(|(_, head)| head.publication_id == candidate.publication_id)
            {
                return Ok(RepoPublicationCommit::AlreadyCommitted {
                    source_cursor: candidate.source_cursor,
                });
            }
            return Ok(RepoPublicationCommit::Conflict(
                RepoPublicationConflict::against(
                    candidate.source_cursor,
                    current.as_ref().map(|(_, head)| head),
                ),
            ));
        }
        if !state.staged.contains_key(&candidate.publication_id) {
            return Err(SpineError::Backend(
                "staged hosted publication is missing".to_string(),
            ));
        }
        let revision = match current.as_ref() {
            Some((revision, _)) => revision.checked_add(1).ok_or_else(|| {
                SpineError::Backend("hosted fake head revision exhausted".to_string())
            })?,
            None => 1,
        };
        state
            .heads
            .insert(candidate.repo_id.clone(), (revision, candidate.clone()));
        Ok(RepoPublicationCommit::Committed {
            source_cursor: candidate.source_cursor,
        })
    }

    fn load_repo_publications(&self) -> Result<Vec<LoadedRepoPublication>, SpineError> {
        let state = self.publications.lock().unwrap();
        state
            .heads
            .values()
            .map(|(_, head)| {
                state
                    .staged
                    .get(&head.publication_id)
                    .cloned()
                    .ok_or_else(|| {
                        SpineError::Serialization(format!(
                            "head references missing staged publication {}",
                            head.publication_id
                        ))
                    })
            })
            .collect()
    }

    fn cleanup_repo_publications(
        &self,
        _active_head: &RepoPublicationHead,
        _max_rows: usize,
    ) -> Result<RepoPublicationCleanupProgress, SpineError> {
        Ok(RepoPublicationCleanupProgress::default())
    }

    fn load_repos(&self) -> Result<Vec<LoadedRepo>, SpineError> {
        Ok(self
            .repos
            .lock()
            .unwrap()
            .iter()
            .map(|(repo_id, (root_hash, entries))| LoadedRepo {
                repo_id: repo_id.clone(),
                root_hash: root_hash.clone(),
                entries: entries.clone(),
            })
            .collect())
    }

    fn load_edges(&self) -> Result<Vec<CrossRepoEdge>, SpineError> {
        Ok(self.edges.lock().unwrap().clone())
    }

    fn write_entity(&self, entry: &EntityEntry, root_hash: &str) -> Result<(), SpineError> {
        let mut repos = self.repos.lock().unwrap();
        let bucket = repos
            .entry(entry.repo_id.clone())
            .or_insert_with(|| (root_hash.to_string(), Vec::new()));
        bucket.0 = root_hash.to_string();
        bucket.1.push(entry.clone());
        Ok(())
    }

    fn delete_repo_entities(&self, repo_id: &str) -> Result<(), SpineError> {
        self.repos.lock().unwrap().remove(repo_id);
        Ok(())
    }

    fn write_edge(&self, edge: &CrossRepoEdge) -> Result<(), SpineError> {
        self.edges.lock().unwrap().push(edge.clone());
        Ok(())
    }

    fn delete_repo_edges(&self, repo_id: &str) -> Result<(), SpineError> {
        self.edges.lock().unwrap().retain(|e| e.src_repo != repo_id);
        Ok(())
    }
}

/// A source-side function entity (the caller that references a sibling repo).
fn source_entity(id: EntityId, name: &str, language: LanguageId) -> Entity {
    Entity {
        id,
        kind: EntityKind::Function,
        name: name.to_string(),
        language,
        fingerprint: make_fp(1),
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

/// A `Calls`/`References` relation from a local entity to an out-of-repo
/// target, carrying the `import_source` module and the imported-symbol token
/// the cross-repo resolver keys on. `dst` is a fresh id deliberately absent
/// from the local entity set so the reference is treated as external.
fn cross_repo_call(
    src: EntityId,
    import_source: &str,
    symbol_token: &str,
    kind: RelationKind,
) -> Relation {
    Relation {
        id: RelationId::new(),
        kind,
        src: GraphNodeId::Entity(src),
        dst: GraphNodeId::Entity(EntityId::new()),
        confidence: 1.0,
        origin: RelationOrigin::Parsed,
        created_in: None,
        import_source: Some(import_source.to_string()),
        evidence: vec![RelationEvidence {
            token: Some(symbol_token.to_string()),
            ..RelationEvidence::default()
        }],
    }
}

// ── Test 15: hosted pod serves non-empty /spine/xref from the store ────
//
// This is the cross-repo demo blocker in miniature: a single-repo pod with
// no on-disk siblings must still answer cross-repo xref. It proves the spine
// pipeline (store hydrate → cross-repo edge refresh → per-entity edge read)
// produces non-empty edges purely from store-resident sibling metadata.

#[test]
fn hosted_pod_serves_non_empty_xref_from_store_only() {
    // Shared durable store standing in for Firestore — no disk, no network.
    let store = Arc::new(HostedFakeStore::default());

    // ── Ingestion side ────────────────────────────────────────────────
    // Two repos land in the store the way cloud ingestion would: the sibling
    // `kin-db` (which exports `InMemoryGraph`) and the primary `kin`. The
    // sibling is registered through a *separate* backend instance to model a
    // different ingestion actor; only its metadata reaches the store, never a
    // local `.kndb`.
    let graph_entity = entry("kin-db", "InMemoryGraph", EntityKind::Class, 7);
    let caller = EntityId::new();
    let primary_entities = vec![source_entity(caller, "open_graph", LanguageId::Rust)];
    let primary_entries = vec![EntityEntry {
        repo_id: "kin".to_string(),
        entity_id: caller,
        name: "open_graph".to_string(),
        kind: EntityKind::Function,
        signature: "fn open_graph()".to_string(),
        fingerprint: make_fp(1),
        file_path: Some("src/graph.rs".to_string()),
        role: Some(EntityRole::Source),
    }];
    {
        let ingest = FirestoreSpineBackend::with_store(store.clone());
        ingest_repo(&ingest, "kin-db", vec![graph_entity.clone()], "db-hash");
        ingest_repo(&ingest, "kin", primary_entries.clone(), "kin-hash");
    }
    seal_hosted_store(&store);

    // ── Pod startup side (the bug surface) ────────────────────────────
    // A freshly started pod builds the same store-backed backend the cloud
    // path constructs and hydrates its cache from the store — the cache is
    // empty until then because the pod has no local siblings.
    let pod = FirestoreSpineBackend::with_store(store.clone());
    assert_eq!(
        pod.entity_count(),
        0,
        "pod cache must be empty before hydrate (no local-disk siblings)"
    );
    pod.hydrate().expect("hydrate cache from store");
    assert_eq!(
        pod.repo_count(),
        2,
        "the exact sealed fleet is visible purely from the store after hydrate"
    );

    // The pod publishes its own primary metadata and then derives a detached
    // edge-phase candidate. The primary `kin` has a function
    // that calls `kin_db::InMemoryGraph`; the relation carries the
    // `import_source` and the imported symbol, so the resolver can bind it to
    // the store-resident `kin-db` entity.
    let relations = vec![cross_repo_call(
        caller,
        "kin_db",
        "kin_db::InMemoryGraph",
        RelationKind::Calls,
    )];
    let registry: Vec<String> = pod.registered_repo_ids().into_iter().collect();
    let edges = pod
        .derive_cross_repo_edges("kin", &primary_entities, &relations, &registry)
        .expect("derive edge publication");
    publish_repo(
        &pod,
        RepoSpinePublication {
            repo_id: "kin".to_string(),
            source_cursor: SpineSourceCursor::from_backend_generation(1),
            root_hash: "kin-hash".to_string(),
            entries: primary_entries,
            outgoing_edges: Some(edges),
            resolution_roots: Some(BTreeMap::from([
                ("kin".to_string(), "kin-hash".to_string()),
                ("kin-db".to_string(), "db-hash".to_string()),
            ])),
        },
    );

    // ── The contract the demo needs: non-empty cross-repo xref ────────
    // This is exactly what `GET /spine/xref?repo=kin&entity=<caller>` reads.
    assert!(
        pod.edge_count() >= 1,
        "spine must hold at least one cross-repo edge after refresh, got {}",
        pod.edge_count()
    );
    let xref = pod.cross_repo_edges_for("kin", &caller);
    assert!(
        !xref.is_empty(),
        "/spine/xref for the primary caller must be non-empty with store-only siblings"
    );
    let edge = &xref[0];
    assert_eq!(edge.src_repo, "kin");
    assert_eq!(
        edge.dst_repo, "kin-db",
        "edge must cross into the sibling repo"
    );
    assert_eq!(
        edge.dst_entity, graph_entity.entity_id,
        "edge must bind to the store-resident sibling entity, not a local guess"
    );

    // The same edge is reachable from the sibling side, and federated impact
    // crosses the boundary — the cross-repo reachability the demo shows.
    let from_db = pod.cross_repo_edges_for("kin-db", &graph_entity.entity_id);
    assert_eq!(from_db.len(), 1, "edge is bidirectional from the dst side");
    let impact = pod.federated_impact("kin-db", &graph_entity.entity_id, 5);
    assert!(
        impact.repos_involved.contains(&"kin".to_string()),
        "changing the sibling entity must impact the primary repo across the boundary"
    );
}

// ── Test 16: edges survive a cold pod restart (store is the source) ────
//
// A second pod that only ever hydrates from the store — never touching the
// primary repo's relations — must still see the materialized cross-repo
// edges, because the cursor-bound edge head committed them.
// This proves the edge state is owned by the store, not by an ephemeral
// in-pod refresh.

#[test]
fn cross_repo_edges_survive_cold_pod_restart_via_store() {
    let store = Arc::new(HostedFakeStore::default());

    let graph_entity = entry("kin-db", "InMemoryGraph", EntityKind::Class, 7);
    let caller = EntityId::new();

    // First pod: publish sibling metadata, primary metadata, then an edge head.
    {
        let pod = FirestoreSpineBackend::with_store(store.clone());
        ingest_repo(&pod, "kin-db", vec![graph_entity.clone()], "db-hash");

        let primary_entries = vec![EntityEntry {
            repo_id: "kin".to_string(),
            entity_id: caller,
            name: "open_graph".to_string(),
            kind: EntityKind::Function,
            signature: "fn open_graph()".to_string(),
            fingerprint: make_fp(1),
            file_path: Some("src/graph.rs".to_string()),
            role: Some(EntityRole::Source),
        }];
        let primary_entities = vec![source_entity(caller, "open_graph", LanguageId::Rust)];
        ingest_repo(&pod, "kin", primary_entries.clone(), "kin-hash");

        let relations = vec![cross_repo_call(
            caller,
            "kin_db",
            "kin_db::InMemoryGraph",
            RelationKind::Calls,
        )];
        let registry: Vec<String> = pod.registered_repo_ids().into_iter().collect();
        let edges = pod
            .derive_cross_repo_edges("kin", &primary_entities, &relations, &registry)
            .expect("derive edge publication");
        publish_repo(
            &pod,
            RepoSpinePublication {
                repo_id: "kin".to_string(),
                source_cursor: SpineSourceCursor::from_backend_generation(1),
                root_hash: "kin-hash".to_string(),
                entries: primary_entries,
                outgoing_edges: Some(edges),
                resolution_roots: Some(BTreeMap::from([
                    ("kin".to_string(), "kin-hash".to_string()),
                    ("kin-db".to_string(), "db-hash".to_string()),
                ])),
            },
        );
        assert_eq!(pod.edge_count(), 1);
    }

    seal_hosted_store(&store);

    // Second (cold) pod: hydrate only — no access to the primary's relations.
    let cold = FirestoreSpineBackend::with_store(store.clone());
    cold.hydrate().expect("cold hydrate");

    assert_eq!(
        cold.edge_count(),
        1,
        "materialized cross-repo edge must rehydrate from the store on a cold pod"
    );
    let xref = cold.cross_repo_edges_for("kin", &caller);
    assert_eq!(
        xref.len(),
        1,
        "/spine/xref non-empty on a pod that only hydrated"
    );
    assert_eq!(xref[0].dst_repo, "kin-db");
}

// ── Test 17: transitive (2-hop) + multi-consumer edges form through
// refresh_cross_repo_edges alone, without a separate register_repo ─────────
//
// Chain: prov ← consumer ← downstream, plus a second consumer2 ← prov. Each
// repo is ONLY ever passed to refresh_cross_repo_edges (never an explicit
// register_repo), exactly as a direct/store refresh does. The downstream→
// consumer edge can only materialize if consumer's own entities became
// name-resolution targets during consumer's refresh — the behavior this fix
// adds. Before it, consumer indexed as an impact node but not a resolution
// target, so the 2nd hop never resolved.
#[test]
fn transitive_and_multi_consumer_edges_via_refresh_only() {
    let index = SpineIndex::new();
    let registry: Vec<String> = vec![
        "prov".to_string(),
        "consumer".to_string(),
        "consumer2".to_string(),
        "downstream".to_string(),
    ];

    // prov exports `target_fn` (a leaf; no outgoing imports).
    let target = source_entity(EntityId::new(), "target_fn", LanguageId::Rust);
    index.refresh_cross_repo_edges("prov", std::slice::from_ref(&target), &[], &registry);

    // consumer imports prov::target_fn via its own `run_task`.
    let run_task = source_entity(EntityId::new(), "run_task", LanguageId::Rust);
    let consumer_rels = vec![cross_repo_call(
        run_task.id,
        "prov",
        "prov::target_fn",
        RelationKind::Calls,
    )];
    index.refresh_cross_repo_edges(
        "consumer",
        std::slice::from_ref(&run_task),
        &consumer_rels,
        &registry,
    );

    // consumer2 also imports prov::target_fn (the multi-consumer case).
    let other_task = source_entity(EntityId::new(), "other_task", LanguageId::Rust);
    let consumer2_rels = vec![cross_repo_call(
        other_task.id,
        "prov",
        "prov::target_fn",
        RelationKind::Calls,
    )];
    index.refresh_cross_repo_edges(
        "consumer2",
        std::slice::from_ref(&other_task),
        &consumer2_rels,
        &registry,
    );

    // downstream imports consumer::run_task — the 2nd hop.
    let down_fn = source_entity(EntityId::new(), "orchestrate", LanguageId::Rust);
    let downstream_rels = vec![cross_repo_call(
        down_fn.id,
        "consumer",
        "consumer::run_task",
        RelationKind::Calls,
    )];
    index.refresh_cross_repo_edges(
        "downstream",
        std::slice::from_ref(&down_fn),
        &downstream_rels,
        &registry,
    );

    // 1-hop (unchanged): consumer → prov outgoing edge bound to prov's entity.
    let consumer_out: Vec<_> = index
        .cross_repo_edges_for("consumer", &run_task.id)
        .into_iter()
        .filter(|e| e.src_repo == "consumer")
        .collect();
    assert_eq!(
        consumer_out.len(),
        1,
        "consumer must have exactly one outgoing 1-hop edge"
    );
    assert_eq!(consumer_out[0].dst_repo, "prov");
    assert_eq!(consumer_out[0].dst_entity, target.id);

    // 2-hop (the fix): downstream → consumer outgoing edge. ABSENT without
    // registering consumer's entities during its own refresh.
    let downstream_out: Vec<_> = index
        .cross_repo_edges_for("downstream", &down_fn.id)
        .into_iter()
        .filter(|e| e.src_repo == "downstream")
        .collect();
    assert_eq!(
        downstream_out.len(),
        1,
        "downstream must resolve the 2nd hop into consumer (transitive edge)"
    );
    assert_eq!(downstream_out[0].dst_repo, "consumer");
    assert_eq!(downstream_out[0].dst_entity, run_task.id);

    // multi-consumer: prov's target_fn has incoming edges from both consumers.
    let into_prov: Vec<_> = index
        .cross_repo_edges_for("prov", &target.id)
        .into_iter()
        .filter(|e| e.dst_repo == "prov")
        .collect();
    let mut src_repos: Vec<String> = into_prov.iter().map(|e| e.src_repo.clone()).collect();
    src_repos.sort();
    assert_eq!(
        src_repos,
        vec!["consumer".to_string(), "consumer2".to_string()],
        "prov's exported entity must show both consumers as incoming edges"
    );

    // Registering each repo's own entities during refresh must not create
    // self-edges (src_repo == dst_repo).
    assert!(
        index
            .cross_repo_edges_for("prov", &target.id)
            .iter()
            .all(|e| e.src_repo != e.dst_repo),
        "refresh must not introduce self-edges"
    );
}

// ── Test 18: refresh alone registers the repo as a resolution target ────────
//
// Regression guard for the register-on-refresh weld: refresh_cross_repo_edges
// must register a repo's own entities, not just index its imports. Before it, a
// repo indexed as an impact node but never became a name-resolution target, so
// the registry the cross-repo traversal consults came up empty. This asserts the
// weld directly — a repo that is ONLY ever passed to refresh_cross_repo_edges
// (never an explicit register_repo) must afterward be both present in
// registered_repo_ids() and resolvable by name.
#[test]
fn refresh_alone_registers_repo_as_resolution_target() {
    let index = SpineIndex::new();
    let leaf = source_entity(EntityId::new(), "open_graph", LanguageId::Rust);

    index.refresh_cross_repo_edges("libgraph", std::slice::from_ref(&leaf), &[], &[]);

    assert!(
        index.registered_repo_ids().contains("libgraph"),
        "refresh must register the repo in the registry the traversal consults"
    );
    let resolved = index.resolve("open_graph", Some(EntityKind::Function), None);
    assert!(
        resolved.iter().any(|e| e.repo_id == "libgraph"),
        "the refreshed repo's own entities must become name-resolution targets"
    );
}

// ── Test 19: a 2-hop chain resolves regardless of refresh order ─────────────
//
// The production daemon registers every sibling's metadata first, then refreshes
// each repo's edges. This mirrors that shape: with all repos pre-registered, a
// leaf ← mid ← top chain resolves even when edges are materialized in
// dependent-first (adversarial) order — proving the fix does not depend on a
// lucky dependency-ordered refresh, only on every repo being a resolution target
// before edges are bound.
#[test]
fn two_hop_resolves_independent_of_refresh_order_when_prewired() {
    let registry: Vec<String> = vec!["leaf".to_string(), "mid".to_string(), "top".to_string()];

    let leaf_fn = source_entity(EntityId::new(), "leaf_fn", LanguageId::Rust);
    let mid_fn = source_entity(EntityId::new(), "mid_fn", LanguageId::Rust);
    let top_fn = source_entity(EntityId::new(), "top_fn", LanguageId::Rust);

    // mid calls leaf::leaf_fn (2nd hop); top calls mid::mid_fn (1st hop).
    let mid_rels = vec![cross_repo_call(
        mid_fn.id,
        "leaf",
        "leaf::leaf_fn",
        RelationKind::Calls,
    )];
    let top_rels = vec![cross_repo_call(
        top_fn.id,
        "mid",
        "mid::mid_fn",
        RelationKind::Calls,
    )];

    let index = SpineIndex::new();

    // Pass 1 — register every repo's entities (edges deferred: empty relations),
    // exactly as the daemon registers all siblings before resolving any edges.
    index.refresh_cross_repo_edges("leaf", std::slice::from_ref(&leaf_fn), &[], &registry);
    index.refresh_cross_repo_edges("mid", std::slice::from_ref(&mid_fn), &[], &registry);
    index.refresh_cross_repo_edges("top", std::slice::from_ref(&top_fn), &[], &registry);

    // Pass 2 — materialize edges in DEPENDENT-FIRST (adversarial) order.
    index.refresh_cross_repo_edges("top", std::slice::from_ref(&top_fn), &top_rels, &registry);
    index.refresh_cross_repo_edges("mid", std::slice::from_ref(&mid_fn), &mid_rels, &registry);

    // 1st hop: top → mid, bound to mid's registered entity.
    let top_out: Vec<_> = index
        .cross_repo_edges_for("top", &top_fn.id)
        .into_iter()
        .filter(|e| e.src_repo == "top")
        .collect();
    assert_eq!(top_out.len(), 1, "top must resolve its edge into mid");
    assert_eq!(top_out[0].dst_repo, "mid");
    assert_eq!(top_out[0].dst_entity, mid_fn.id);

    // 2nd hop: mid → leaf, bound to leaf's registered entity.
    let mid_out: Vec<_> = index
        .cross_repo_edges_for("mid", &mid_fn.id)
        .into_iter()
        .filter(|e| e.src_repo == "mid")
        .collect();
    assert_eq!(mid_out.len(), 1, "mid must resolve the 2nd hop into leaf");
    assert_eq!(mid_out[0].dst_repo, "leaf");
    assert_eq!(mid_out[0].dst_entity, leaf_fn.id);

    // End to end: changing leaf_fn impacts top across both hops.
    let impact = federated_impact(&index, "leaf", &leaf_fn.id, 5);
    assert!(
        impact.repos_involved.contains(&"top".to_string()),
        "transitive blast radius from leaf must reach top, got {:?}",
        impact.repos_involved
    );
}

fn publish_repo(backend: &FirestoreSpineBackend, publication: RepoSpinePublication) {
    let prepared = backend
        .prepare_repo_publication(publication)
        .expect("prepare hosted publication");
    assert!(matches!(
        backend
            .commit_repo_publication(prepared)
            .expect("commit hosted publication"),
        RepoPublicationCommit::Committed { .. }
            | RepoPublicationCommit::AlreadyCommitted { .. }
    ));
}

fn seal_hosted_store(store: &Arc<HostedFakeStore>) {
    let active = store
        .load_rollout_fence()
        .expect("load hosted rollout fence")
        .expect("hosted rollout fence");
    let writer_drain = LegacySpineWriterDrainAttestation {
        schema: LEGACY_SPINE_WRITER_DRAIN_SCHEMA.to_string(),
        rollout_fence_evidence: active.evidence(),
        daemon_image_sha256: format!("sha256:{}", "a".repeat(64)),
        drain_proof_sha256: format!("sha256:{}", "b".repeat(64)),
    };
    FirestoreSpineBackend::with_store(store.clone())
        .complete_legacy_migration(writer_drain)
        .expect("seal hosted integration fleet after trusted old-writer drain");
}

/// Publish a repo's cursor-bound entity metadata through the store-backed
/// backend, mirroring the daemon's first publication phase.
fn ingest_repo(
    backend: &FirestoreSpineBackend,
    repo_id: &str,
    entries: Vec<EntityEntry>,
    root_hash: &str,
) {
    publish_repo(
        backend,
        RepoSpinePublication {
            repo_id: repo_id.to_string(),
            source_cursor: SpineSourceCursor::from_backend_generation(1),
            root_hash: root_hash.to_string(),
            entries,
            outgoing_edges: None,
            resolution_roots: None,
        },
    );
}
