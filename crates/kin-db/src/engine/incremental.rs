// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use hashbrown::HashSet;

use super::graph::InMemoryGraph;
use crate::types::{RepoPath, TreeEntry};

/// The result of comparing an imported tree against graph-owned tree truth.
#[derive(Debug, Clone, Default)]
pub struct IncrementalDiff {
    /// Files present on disk but not in the graph.
    pub added_files: Vec<RepoPath>,
    /// Files present in both but with different content identity or mode.
    pub modified_files: Vec<RepoPath>,
    /// Files in the graph but no longer on disk.
    pub removed_files: Vec<RepoPath>,
}

impl IncrementalDiff {
    /// Returns true if no files changed.
    pub fn is_empty(&self) -> bool {
        self.added_files.is_empty()
            && self.modified_files.is_empty()
            && self.removed_files.is_empty()
    }

    /// Total number of changed files.
    pub fn changed_count(&self) -> usize {
        self.added_files.len() + self.modified_files.len() + self.removed_files.len()
    }
}

/// Compare exact imported tree entries against the graph-owned repository tree.
///
/// - Files in `current_files` but not in the graph → `added_files`
/// - Files in both but with different content or mode → `modified_files`
/// - Files in the graph but not in `current_files` → `removed_files`
pub fn compute_diff(
    graph: &InMemoryGraph,
    current_files: &[(RepoPath, TreeEntry)],
) -> IncrementalDiff {
    let tree = graph.resolved_tree();
    let indexed_paths: HashSet<RepoPath> = tree
        .artifacts_by_path()
        .map(|artifact| artifact.path.clone())
        .collect();
    let current_paths: HashSet<&RepoPath> = current_files.iter().map(|(path, _)| path).collect();

    let mut diff = IncrementalDiff::default();

    for (path, entry) in current_files {
        match tree.artifact_at_path(path).map(|artifact| artifact.entry) {
            None => {
                diff.added_files.push(path.clone());
            }
            Some(stored_entry) if stored_entry != *entry => {
                diff.modified_files.push(path.clone());
            }
            _ => {
                // Exact entry matches — no change.
            }
        }
    }

    for path in &indexed_paths {
        if !current_paths.contains(path) {
            diff.removed_files.push(path.clone());
        }
    }

    // Sort for deterministic output.
    diff.added_files.sort();
    diff.modified_files.sort();
    diff.removed_files.sort();

    diff
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::InMemoryGraph;
    use crate::store::EntityStore;
    use crate::types::*;

    fn make_entry(byte: u8) -> TreeEntry {
        regular_tree_entry(byte)
    }

    fn path(value: &str) -> RepoPath {
        RepoPath::from_utf8(value).unwrap()
    }

    fn test_entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
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

    fn test_relation(src: EntityId, dst: EntityId, kind: RelationKind) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // compute_diff tests
    // -----------------------------------------------------------------------

    #[test]
    fn diff_all_new_files() {
        let graph = InMemoryGraph::new();
        let current = vec![(path("a.rs"), make_entry(1)), (path("b.rs"), make_entry(2))];

        let diff = compute_diff(&graph, &current);
        assert_eq!(diff.added_files, vec![path("a.rs"), path("b.rs")]);
        assert!(diff.modified_files.is_empty());
        assert!(diff.removed_files.is_empty());
    }

    #[test]
    fn diff_no_changes() {
        let graph = InMemoryGraph::new();
        graph.admit_artifact_for_test("a.rs", make_entry(1));
        graph.admit_artifact_for_test("b.rs", make_entry(2));

        let current = vec![(path("a.rs"), make_entry(1)), (path("b.rs"), make_entry(2))];

        let diff = compute_diff(&graph, &current);
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_modified_file() {
        let graph = InMemoryGraph::new();
        graph.admit_artifact_for_test("a.rs", make_entry(1));

        let current = vec![(path("a.rs"), make_entry(99))];

        let diff = compute_diff(&graph, &current);
        assert!(diff.added_files.is_empty());
        assert_eq!(diff.modified_files, vec![path("a.rs")]);
        assert!(diff.removed_files.is_empty());
    }

    #[test]
    fn diff_removed_file() {
        let graph = InMemoryGraph::new();
        graph.admit_artifact_for_test("a.rs", make_entry(1));
        graph.admit_artifact_for_test("b.rs", make_entry(2));

        let current = vec![(path("a.rs"), make_entry(1))];

        let diff = compute_diff(&graph, &current);
        assert!(diff.added_files.is_empty());
        assert!(diff.modified_files.is_empty());
        assert_eq!(diff.removed_files, vec![path("b.rs")]);
    }

    #[test]
    fn diff_mixed_add_modify_remove() {
        let graph = InMemoryGraph::new();
        graph.admit_artifact_for_test("existing.rs", make_entry(1));
        graph.admit_artifact_for_test("modified.rs", make_entry(2));
        graph.admit_artifact_for_test("deleted.rs", make_entry(3));

        let current = vec![
            (path("existing.rs"), make_entry(1)),  // unchanged
            (path("modified.rs"), make_entry(99)), // modified
            (path("new.rs"), make_entry(4)),       // added
        ];

        let diff = compute_diff(&graph, &current);
        assert_eq!(diff.added_files, vec![path("new.rs")]);
        assert_eq!(diff.modified_files, vec![path("modified.rs")]);
        assert_eq!(diff.removed_files, vec![path("deleted.rs")]);
        assert_eq!(diff.changed_count(), 3);
    }

    // -----------------------------------------------------------------------
    // remove_entities_for_file tests
    // -----------------------------------------------------------------------

    #[test]
    fn remove_entities_for_file_basic() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("fn_a", "src/a.rs");
        let e2 = test_entity("fn_b", "src/a.rs");
        let e3 = test_entity("fn_c", "src/b.rs");

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();
        graph.admit_artifact_for_test("src/a.rs", make_entry(1));
        graph.admit_artifact_for_test("src/b.rs", make_entry(2));

        assert_eq!(graph.entity_count(), 3);

        let removed = graph.remove_entities_for_file("src/a.rs");
        assert_eq!(removed.len(), 2);
        assert_eq!(graph.entity_count(), 1);
        // e3 should still be there
        assert!(graph.get_entity(&e3.id).unwrap().is_some());
        // e1/e2 should be gone
        assert!(graph.get_entity(&e1.id).unwrap().is_none());
        assert!(graph.get_entity(&e2.id).unwrap().is_none());
        // Semantic enrichment removal must not erase exact tree truth.
        assert_eq!(graph.tree_entry_for_test("src/a.rs"), Some(make_entry(1)));
        // The unrelated tree entry remains as well.
        assert!(graph.tree_entry_for_test("src/b.rs").is_some());
    }

    #[test]
    fn remove_entities_removes_outgoing_relations() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("caller", "src/a.rs");
        let e2 = test_entity("callee", "src/b.rs");
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();
        graph.admit_artifact_for_test("src/a.rs", make_entry(1));

        assert_eq!(graph.relation_count(), 1);

        graph.remove_entities_for_file("src/a.rs");

        // The outgoing relation from e1 should be gone.
        assert_eq!(graph.relation_count(), 0);
        // e2 should still exist.
        assert!(graph.get_entity(&e2.id).unwrap().is_some());
    }

    #[test]
    fn remove_entities_keeps_incoming_from_other_files() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("caller", "src/a.rs"); // external caller
        let e2 = test_entity("callee", "src/b.rs"); // will be removed
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();
        graph.admit_artifact_for_test("src/b.rs", make_entry(2));

        // Remove entities for b.rs (the callee's file).
        graph.remove_entities_for_file("src/b.rs");

        // e2 is gone.
        assert!(graph.get_entity(&e2.id).unwrap().is_none());
        // e1 is still there.
        assert!(graph.get_entity(&e1.id).unwrap().is_some());
        // The relation from e1→e2 is kept (dangling dst) — it's an incoming relation
        // from another file.
        assert_eq!(graph.relation_count(), 1);
    }

    #[test]
    fn remove_entities_cleans_intra_file_relations() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("fn_a", "src/a.rs");
        let e2 = test_entity("fn_b", "src/a.rs");
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();
        graph.admit_artifact_for_test("src/a.rs", make_entry(1));

        graph.remove_entities_for_file("src/a.rs");

        assert_eq!(graph.entity_count(), 0);
        assert_eq!(graph.relation_count(), 0);
    }

    #[test]
    fn remove_then_reinsert_produces_correct_graph() {
        let graph = InMemoryGraph::new();

        // Initial state: a.rs has fn_a calling fn_c in c.rs.
        let e_a = test_entity("fn_a", "src/a.rs");
        let e_c = test_entity("fn_c", "src/c.rs");
        let rel1 = test_relation(e_a.id, e_c.id, RelationKind::Calls);

        graph.upsert_entity(&e_a).unwrap();
        graph.upsert_entity(&e_c).unwrap();
        graph.upsert_relation(&rel1).unwrap();
        graph.admit_artifact_for_test("src/a.rs", make_entry(1));
        graph.admit_artifact_for_test("src/c.rs", make_entry(3));

        // Remove a.rs entities (simulating re-index of modified file).
        graph.remove_entities_for_file("src/a.rs");

        assert_eq!(graph.entity_count(), 1); // only e_c remains
        assert_eq!(graph.relation_count(), 0); // outgoing from e_a is gone

        // Re-insert updated entities for a.rs.
        let e_a2 = test_entity("fn_a_v2", "src/a.rs");
        let rel2 = test_relation(e_a2.id, e_c.id, RelationKind::Calls);
        let artifact_id = graph
            .artifact_id_at_path(&path("src/a.rs"))
            .expect("the old exact artifact remains admitted");
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![EntityDelta::Added { new: e_a2.clone() }],
                relation_deltas: vec![RelationDelta::Added { new: rel2 }],
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: LocatedEntry::new(path("src/a.rs"), make_entry(1)),
                    new: LocatedEntry::new(path("src/a.rs"), make_entry(10)),
                }],
                admission_policy_delta: None,
            })
            .unwrap();

        assert_eq!(graph.entity_count(), 2);
        assert_eq!(graph.relation_count(), 1);

        // Verify the new entity is queryable.
        let filter = EntityFilter {
            file_path: Some(FilePathId::new("src/a.rs")),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "fn_a_v2");
    }

    #[test]
    fn remove_nonexistent_file_is_noop() {
        let graph = InMemoryGraph::new();
        let removed = graph.remove_entities_for_file("no_such_file.rs");
        assert!(removed.is_empty());
    }

    #[test]
    fn remove_entities_for_file_preserves_tree_even_without_entities() {
        let graph = InMemoryGraph::new();
        graph.admit_artifact_for_test("stale.rs", make_entry(7));

        let removed = graph.remove_entities_for_file("stale.rs");
        assert!(removed.is_empty());
        assert_eq!(graph.tree_entry_for_test("stale.rs"), Some(make_entry(7)));

        assert_eq!(
            graph.remove_admitted_artifact_for_test("stale.rs"),
            Some(make_entry(7))
        );
        assert!(graph.tree_entry_for_test("stale.rs").is_none());
    }

    // -----------------------------------------------------------------------
    // Exact repository-tree round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn repository_tree_entry_transaction_roundtrip() {
        let graph = InMemoryGraph::new();
        assert!(graph.tree_entry_for_test("foo.rs").is_none());

        graph.admit_artifact_for_test("foo.rs", make_entry(42));
        assert_eq!(graph.tree_entry_for_test("foo.rs"), Some(make_entry(42)));
    }

    #[test]
    fn repository_paths_returns_all() {
        let graph = InMemoryGraph::new();
        graph.admit_artifact_for_test("a.rs", make_entry(1));
        graph.admit_artifact_for_test("b.rs", make_entry(2));
        graph.admit_artifact_for_test("c.rs", make_entry(3));

        let mut paths = graph.repository_paths();
        paths.sort();
        assert_eq!(paths, vec![path("a.rs"), path("b.rs"), path("c.rs")]);
    }
}
