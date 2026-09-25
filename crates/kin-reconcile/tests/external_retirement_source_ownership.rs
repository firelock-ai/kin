// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::sync::Arc;

use kin_blobs::BlobStore;
use kin_db::{InMemoryGraph, SnapshotManager};
use kin_index::IndexPipeline;
use kin_model::{
    ArtifactId, EntityStore, FilePathId, Hash256, LocatedEntry, RelationKind, RepoPath,
    TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;

const CALLER: &str = "from local import remote\n\ndef same():\n    return remote()\n\ndef same():\n    return remote()\n";

struct Repo {
    root: tempfile::TempDir,
    graph: Arc<InMemoryGraph>,
    blobs: BlobStore,
    reconciler: Reconciler,
}

impl Repo {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(root.path().join("blobs")).unwrap();
        let graph = Arc::new(InMemoryGraph::new());
        let reconciler = Reconciler::new(root.path().to_owned());
        Self {
            root,
            graph,
            blobs,
            reconciler,
        }
    }

    fn admit(&mut self, file: &str, source: &str) -> TransactionDelta {
        let blob = self.blobs.write(source.as_bytes()).unwrap();
        let path = RepoPath::from_utf8(file).unwrap();
        assert!(self.graph.artifact_id_at_path(&path).is_none());
        self.graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: LocatedEntry::new(
                        path,
                        TreeEntry::blob(Hash256::from_bytes(blob.0), false),
                    ),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        let indexed = IndexPipeline::new()
            .index_file_content_with_tests(&FilePathId::new(file), source.as_bytes(), blob)
            .unwrap()
            .indexed_file;
        let result = self
            .reconciler
            .reconcile_indexed_observation(&indexed, &self.blobs, self.graph.as_ref())
            .expect("real admitted target/source reconciliation");
        self.graph.apply_transaction_delta(&result.delta).unwrap();
        result.delta
    }

    fn reopen(&mut self) {
        let path = self.root.path().join("graph.kindb");
        SnapshotManager::save_graph(&path, self.graph.as_ref()).unwrap();
        self.graph = SnapshotManager::open_without_text_index(&path)
            .unwrap()
            .graph();
        self.reconciler = Reconciler::new(self.root.path().to_owned());
        self.reconciler
            .seed_lkg_entities_from_graph(self.graph.as_ref());
        self.reconciler
            .restore_cross_file_dependencies(self.graph.as_ref(), &self.blobs)
            .expect("restore real admitted source dependencies after cold reopen");
    }
}

fn target_arrival(cold: bool) {
    let mut repo = Repo::new();
    repo.admit("caller.py", CALLER);
    let callers: Vec<_> = repo
        .graph
        .list_all_entities()
        .unwrap()
        .into_iter()
        .filter(|entity| entity.name == "same")
        .collect();
    assert_eq!(callers.len(), 2);
    let mut old_edges = Vec::new();
    for caller in &callers {
        let edges: Vec<_> = repo
            .graph
            .get_all_relations_for_entity(&caller.id)
            .unwrap()
            .into_iter()
            .filter(|edge| {
                edge.src.as_entity() == Some(caller.id) && edge.kind == RelationKind::Calls
            })
            .collect();
        assert_eq!(edges.len(), 1);
        assert!(kin_index::is_external_import_placeholder(&edges[0]));
        assert_eq!(edges[0].evidence[0].occurrence_count, 1);
        old_edges.push(edges[0].id);
    }
    if cold {
        repo.reopen();
    }
    let delta = repo.admit("local.py", "def remote():\n    return 42\n");
    let removed: Vec<_> = delta
        .relation_deltas
        .iter()
        .filter_map(|change| match change {
            kin_model::RelationDelta::Removed { old } if old_edges.contains(&old.id) => {
                Some(old.id)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        removed.len(),
        2,
        "target-only arrival must retire both exact old external bindings: {delta:#?}"
    );
    for reopen in [false, true] {
        if reopen {
            repo.reopen();
        }
        for caller in &callers {
            let held = repo.graph.get_entity(&caller.id).unwrap().unwrap();
            assert_eq!(held.fingerprint, caller.fingerprint);
            assert_eq!(held.span, caller.span);
            assert_eq!(
                held.metadata.extra.get("blob_hash"),
                caller.metadata.extra.get("blob_hash")
            );
            let edges: Vec<_> = repo
                .graph
                .get_all_relations_for_entity(&caller.id)
                .unwrap()
                .into_iter()
                .filter(|edge| {
                    edge.src.as_entity() == Some(caller.id) && edge.kind == RelationKind::Calls
                })
                .collect();
            assert_eq!(edges.len(), 1);
            assert!(!kin_index::is_external_import_placeholder(&edges[0]));
            let target = repo
                .graph
                .get_entity(&edges[0].dst.as_entity().unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(target.file_origin, Some(FilePathId::new("local.py")));
            assert_eq!(target.name, "remote");
            assert_eq!(
                edges[0]
                    .evidence
                    .iter()
                    .map(|row| row.occurrence_count)
                    .sum::<u32>(),
                1
            );
            let site = edges[0]
                .evidence
                .iter()
                .find_map(|row| row.source_span.as_ref())
                .unwrap();
            let span = caller.span.as_ref().unwrap();
            assert!(span.start_byte <= site.start_byte && site.end_byte <= span.end_byte);
        }
    }
}

#[test]
fn warm_target_arrival_retires_each_same_name_callers_own_occurrence() {
    target_arrival(false);
}

#[test]
fn cold_target_arrival_retires_each_same_name_callers_own_occurrence() {
    target_arrival(true);
}

#[test]
fn immutable_external_predecessor_requires_exact_source_tree_occurrence_and_target() {
    let mut repo = Repo::new();
    repo.admit("caller.py", CALLER);
    let snapshot = repo.graph.to_snapshot();
    let prior = kin_model::graph::ResolvedGraphState {
        entities: snapshot.entities.clone(),
        relations: snapshot.relations.clone(),
        tree: snapshot.resolved_tree.clone(),
        external_references: snapshot.external_references.clone(),
        ..Default::default()
    };
    let relation = prior
        .relations
        .values()
        .find(|relation| kin_index::is_external_import_placeholder(relation))
        .unwrap()
        .clone();
    kin_reconcile::verify_external_import_predecessor(&prior, &relation, &repo.blobs)
        .expect("actual stored relation and original source are sufficient");

    let mut wrong_count = prior.clone();
    let mut altered = relation.clone();
    altered.evidence[0].occurrence_count += 1;
    wrong_count.relations.insert(altered.id, altered.clone());
    assert!(
        kin_reconcile::verify_external_import_predecessor(&wrong_count, &altered, &repo.blobs)
            .is_err()
    );

    let mut wrong_origin = prior.clone();
    let mut altered = relation.clone();
    altered.origin = kin_model::RelationOrigin::Manual;
    wrong_origin.relations.insert(altered.id, altered.clone());
    assert!(kin_reconcile::verify_external_import_predecessor(
        &wrong_origin,
        &altered,
        &repo.blobs
    )
    .is_err());

    let mut missing_target = prior.clone();
    missing_target
        .entities
        .remove(&relation.dst.as_entity().unwrap());
    assert!(kin_reconcile::verify_external_import_predecessor(
        &missing_target,
        &relation,
        &repo.blobs
    )
    .is_err());

    let mut wrong_target = prior.clone();
    wrong_target
        .entities
        .get_mut(&relation.dst.as_entity().unwrap())
        .unwrap()
        .name = "foreign occupant".into();
    assert!(kin_reconcile::verify_external_import_predecessor(
        &wrong_target,
        &relation,
        &repo.blobs
    )
    .is_err());

    let mut wrong_body = prior.clone();
    let blob = repo.blobs.write(b"def same():\n    return 1\n").unwrap();
    wrong_body
        .entities
        .get_mut(&relation.src.as_entity().unwrap())
        .unwrap()
        .metadata
        .extra
        .insert("blob_hash".into(), blob.to_string().into());
    assert!(
        kin_reconcile::verify_external_import_predecessor(&wrong_body, &relation, &repo.blobs)
            .is_err()
    );

    let mut changed_record = relation.clone();
    changed_record.evidence[0].token = Some("some_other_import".into());
    assert!(kin_reconcile::verify_external_import_predecessor(
        &prior,
        &changed_record,
        &repo.blobs
    )
    .is_err());
    let absent_blobs = BlobStore::new(repo.root.path().join("empty-cas")).unwrap();
    assert!(
        kin_reconcile::verify_external_import_predecessor(&prior, &relation, &absent_blobs)
            .is_err()
    );
    assert_eq!(repo.graph.to_snapshot().entities, snapshot.entities);
    assert_eq!(repo.graph.to_snapshot().relations, snapshot.relations);
}
