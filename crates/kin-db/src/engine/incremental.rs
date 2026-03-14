use hashbrown::HashSet;

use super::graph::InMemoryGraph;

/// The result of comparing current file state against the graph's recorded hashes.
#[derive(Debug, Clone, Default)]
pub struct IncrementalDiff {
    /// Files present on disk but not in the graph.
    pub added_files: Vec<String>,
    /// Files present in both but with different content hashes.
    pub modified_files: Vec<String>,
    /// Files in the graph but no longer on disk.
    pub removed_files: Vec<String>,
}

impl IncrementalDiff {
    /// Returns true if no files changed.
    pub fn is_empty(&self) -> bool {
        self.added_files.is_empty() && self.modified_files.is_empty() && self.removed_files.is_empty()
    }

    /// Total number of changed files.
    pub fn changed_count(&self) -> usize {
        self.added_files.len() + self.modified_files.len() + self.removed_files.len()
    }
}

/// Compare current file hashes against the graph's recorded hashes.
///
/// - Files in `current_files` but not in the graph → `added_files`
/// - Files in both but with different hashes → `modified_files`
/// - Files in the graph but not in `current_files` → `removed_files`
pub fn compute_diff(
    graph: &InMemoryGraph,
    current_files: &[(String, [u8; 32])],
) -> IncrementalDiff {
    let indexed_paths: HashSet<String> = graph.indexed_file_paths().into_iter().collect();
    let current_paths: HashSet<&String> = current_files.iter().map(|(p, _)| p).collect();

    let mut diff = IncrementalDiff::default();

    for (path, hash) in current_files {
        match graph.get_file_hash(path) {
            None => {
                diff.added_files.push(path.clone());
            }
            Some(stored_hash) if stored_hash != *hash => {
                diff.modified_files.push(path.clone());
            }
            _ => {
                // Hash matches — no change.
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
    use crate::store::GraphStore;
    use crate::types::*;

    fn make_hash(byte: u8) -> [u8; 32] {
        [byte; 32]
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
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
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
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
        }
    }

    // -----------------------------------------------------------------------
    // compute_diff tests
    // -----------------------------------------------------------------------

    #[test]
    fn diff_all_new_files() {
        let graph = InMemoryGraph::new();
        let current = vec![
            ("a.rs".to_string(), make_hash(1)),
            ("b.rs".to_string(), make_hash(2)),
        ];

        let diff = compute_diff(&graph, &current);
        assert_eq!(diff.added_files, vec!["a.rs", "b.rs"]);
        assert!(diff.modified_files.is_empty());
        assert!(diff.removed_files.is_empty());
    }

    #[test]
    fn diff_no_changes() {
        let graph = InMemoryGraph::new();
        graph.set_file_hash("a.rs", make_hash(1));
        graph.set_file_hash("b.rs", make_hash(2));

        let current = vec![
            ("a.rs".to_string(), make_hash(1)),
            ("b.rs".to_string(), make_hash(2)),
        ];

        let diff = compute_diff(&graph, &current);
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_modified_file() {
        let graph = InMemoryGraph::new();
        graph.set_file_hash("a.rs", make_hash(1));

        let current = vec![("a.rs".to_string(), make_hash(99))];

        let diff = compute_diff(&graph, &current);
        assert!(diff.added_files.is_empty());
        assert_eq!(diff.modified_files, vec!["a.rs"]);
        assert!(diff.removed_files.is_empty());
    }

    #[test]
    fn diff_removed_file() {
        let graph = InMemoryGraph::new();
        graph.set_file_hash("a.rs", make_hash(1));
        graph.set_file_hash("b.rs", make_hash(2));

        let current = vec![("a.rs".to_string(), make_hash(1))];

        let diff = compute_diff(&graph, &current);
        assert!(diff.added_files.is_empty());
        assert!(diff.modified_files.is_empty());
        assert_eq!(diff.removed_files, vec!["b.rs"]);
    }

    #[test]
    fn diff_mixed_add_modify_remove() {
        let graph = InMemoryGraph::new();
        graph.set_file_hash("existing.rs", make_hash(1));
        graph.set_file_hash("modified.rs", make_hash(2));
        graph.set_file_hash("deleted.rs", make_hash(3));

        let current = vec![
            ("existing.rs".to_string(), make_hash(1)),  // unchanged
            ("modified.rs".to_string(), make_hash(99)),  // modified
            ("new.rs".to_string(), make_hash(4)),        // added
        ];

        let diff = compute_diff(&graph, &current);
        assert_eq!(diff.added_files, vec!["new.rs"]);
        assert_eq!(diff.modified_files, vec!["modified.rs"]);
        assert_eq!(diff.removed_files, vec!["deleted.rs"]);
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
        graph.set_file_hash("src/a.rs", make_hash(1));
        graph.set_file_hash("src/b.rs", make_hash(2));

        assert_eq!(graph.entity_count(), 3);

        let removed = graph.remove_entities_for_file("src/a.rs");
        assert_eq!(removed.len(), 2);
        assert_eq!(graph.entity_count(), 1);
        // e3 should still be there
        assert!(graph.get_entity(&e3.id).unwrap().is_some());
        // e1/e2 should be gone
        assert!(graph.get_entity(&e1.id).unwrap().is_none());
        assert!(graph.get_entity(&e2.id).unwrap().is_none());
        // File hash for a.rs should be cleared
        assert!(graph.get_file_hash("src/a.rs").is_none());
        // File hash for b.rs should remain
        assert!(graph.get_file_hash("src/b.rs").is_some());
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
        graph.set_file_hash("src/a.rs", make_hash(1));

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
        let e1 = test_entity("caller", "src/a.rs");    // external caller
        let e2 = test_entity("callee", "src/b.rs");    // will be removed
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();
        graph.set_file_hash("src/b.rs", make_hash(2));

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
        graph.set_file_hash("src/a.rs", make_hash(1));

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
        graph.set_file_hash("src/a.rs", make_hash(1));
        graph.set_file_hash("src/c.rs", make_hash(3));

        // Remove a.rs entities (simulating re-index of modified file).
        graph.remove_entities_for_file("src/a.rs");

        assert_eq!(graph.entity_count(), 1); // only e_c remains
        assert_eq!(graph.relation_count(), 0); // outgoing from e_a is gone

        // Re-insert updated entities for a.rs.
        let e_a2 = test_entity("fn_a_v2", "src/a.rs");
        let rel2 = test_relation(e_a2.id, e_c.id, RelationKind::Calls);

        graph.upsert_entity(&e_a2).unwrap();
        graph.upsert_relation(&rel2).unwrap();
        graph.set_file_hash("src/a.rs", make_hash(10));

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

    // -----------------------------------------------------------------------
    // file_hash round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn file_hash_set_get_roundtrip() {
        let graph = InMemoryGraph::new();
        assert!(graph.get_file_hash("foo.rs").is_none());

        graph.set_file_hash("foo.rs", make_hash(42));
        assert_eq!(graph.get_file_hash("foo.rs"), Some(make_hash(42)));
    }

    #[test]
    fn indexed_file_paths_returns_all() {
        let graph = InMemoryGraph::new();
        graph.set_file_hash("a.rs", make_hash(1));
        graph.set_file_hash("b.rs", make_hash(2));
        graph.set_file_hash("c.rs", make_hash(3));

        let mut paths = graph.indexed_file_paths();
        paths.sort();
        assert_eq!(paths, vec!["a.rs", "b.rs", "c.rs"]);
    }
}
