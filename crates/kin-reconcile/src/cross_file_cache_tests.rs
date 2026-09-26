// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;
use kin_model::{
    EntityStore, FilePathId, LocatedEntry, RelationDelta, TransactionDelta, TreeDelta, TreeEntry,
};

struct Fixture {
    _root: tempfile::TempDir,
    blobs: kin_blobs::BlobStore,
    graph: kin_db::InMemoryGraph,
    live: LiveCrossFileLinker,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let blobs = kin_blobs::BlobStore::new(root.path().join("blobs")).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        for (file, body) in [
            (
                "gone.py",
                "from keep import kept\ndef departed():\n    return kept()\n",
            ),
            (
                "waiting.py",
                "from gone import departed\ndef waiting():\n    return departed()\n",
            ),
            ("keep.py", "def kept():\n    return 1\n"),
        ] {
            let hash = blobs.write(body.as_bytes()).unwrap();
            graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![TreeDelta::Added {
                        artifact_id: ArtifactId::new(),
                        new: LocatedEntry::new(
                            RepoPath::from_utf8(file).unwrap(),
                            TreeEntry::blob(kin_model::Hash256::from_bytes(hash.0), false),
                        ),
                    }],
                    ..Default::default()
                })
                .unwrap();
        }
        let prepared = crate::Reconciler::prepare_admitted_source_batch(
            graph.to_snapshot(),
            &[
                FilePathId::new("gone.py"),
                FilePathId::new("keep.py"),
                FilePathId::new("waiting.py"),
            ],
            &blobs,
            &[],
        )
        .unwrap();
        let graph = kin_db::InMemoryGraph::from_snapshot(prepared.snapshot().clone()).unwrap();
        let mut live = LiveCrossFileLinker::new();
        live.seed_from_graph_checked(&graph).unwrap();
        live.restore_dependencies(&graph, &blobs, None).unwrap();
        assert!(live.pending.contains_key("gone.py"));
        assert!(live.waiting_on_paths["gone.py"].contains("waiting.py"));
        Self {
            _root: root,
            blobs,
            graph,
            live,
        }
    }

    // Model the already-admitted graph removal; the real daemon route tests
    // independently exercise the production retirement and debt planner.
    fn remove_gone_from_graph(&self) {
        let snapshot = self.graph.to_snapshot();
        let artifact = snapshot
            .resolved_tree
            .artifact_at_path(&RepoPath::from_utf8("gone.py").unwrap())
            .unwrap();
        let removed: Vec<_> = snapshot
            .entities
            .values()
            .filter(|entity| {
                entity
                    .file_origin
                    .as_ref()
                    .is_some_and(|file| file.0 == "gone.py")
            })
            .map(|entity| entity.id)
            .collect();
        self.graph.remove_entities_batch(&removed).unwrap();
        let relations = self
            .graph
            .get_all_relations_for_node(&GraphNodeId::Artifact(artifact.artifact_id))
            .unwrap();
        self.graph
            .apply_transaction_delta(&TransactionDelta {
                relation_deltas: relations
                    .into_iter()
                    .map(|old| RelationDelta::Removed { old })
                    .collect(),
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id: artifact.artifact_id,
                    old: artifact.located_entry(),
                }],
                ..Default::default()
            })
            .unwrap();
    }
}

#[test]
fn restore_census_retains_cache_on_missing_admitted_cas_then_retries() {
    let mut fixture = Fixture::new();
    fixture.remove_gone_from_graph();
    fixture.live.dependencies_restored = false;
    let keep =
        crate::admitted_source::load(&fixture.graph, &fixture.blobs, &FilePathId::new("keep.py"))
            .unwrap()
            .unwrap();
    let bytes = fixture.blobs.read(&keep.blob_hash).unwrap();
    fixture.blobs.delete(&keep.blob_hash).unwrap();
    let before = serde_json::to_vec(&fixture.live.linker.to_checkpoint_v1()).unwrap();
    assert!(fixture
        .live
        .restore_dependencies(&fixture.graph, &fixture.blobs, None)
        .is_err());
    assert_eq!(
        serde_json::to_vec(&fixture.live.linker.to_checkpoint_v1()).unwrap(),
        before
    );
    assert!(fixture.live.pending.contains_key("gone.py"));
    fixture.blobs.write(&bytes).unwrap();
    fixture
        .live
        .restore_dependencies(&fixture.graph, &fixture.blobs, None)
        .unwrap();
    assert!(!fixture.live.knows_file("gone.py"));
    assert!(!fixture.live.pending.contains_key("gone.py"));
    assert!(
        fixture.live.waiting_on_paths["gone.py"].contains("waiting.py"),
        "a surviving importer must remain eligible for target recovery"
    );
}

#[test]
fn nominated_sources_retire_only_after_all_admitted_reads_succeed() {
    let mut fixture = Fixture::new();
    // The normal transitive importer index nominates gone and then waiting,
    // placing absent and unreadable admitted sources in one dependent pass.
    fixture.remove_gone_from_graph();
    let keep =
        crate::admitted_source::load(&fixture.graph, &fixture.blobs, &FilePathId::new("keep.py"))
            .unwrap()
            .unwrap();
    let waiting = crate::admitted_source::load(
        &fixture.graph,
        &fixture.blobs,
        &FilePathId::new("waiting.py"),
    )
    .unwrap()
    .unwrap();
    let bytes = fixture.blobs.read(&waiting.blob_hash).unwrap();
    fixture.blobs.delete(&waiting.blob_hash).unwrap();
    assert!(fixture
        .live
        .resolve_after_edit_checked(
            &fixture.graph,
            &fixture.blobs,
            "keep.py",
            &keep.entities,
            &keep.extracted_relations,
            &keep.imports,
            ParseCompleteness::Full
        )
        .is_err());
    assert!(fixture.live.knows_file("gone.py"));
    assert!(fixture.live.pending.contains_key("gone.py"));
    fixture.blobs.write(&bytes).unwrap();
    let pass = fixture
        .live
        .resolve_after_edit_checked(
            &fixture.graph,
            &fixture.blobs,
            "keep.py",
            &keep.entities,
            &keep.extracted_relations,
            &keep.imports,
            ParseCompleteness::Full,
        )
        .unwrap();
    assert!(pass.failure.is_none(), "{:?}", pass.failure);
    assert!(!fixture.live.knows_file("gone.py"));
    assert!(fixture.live.knows_file("waiting.py"));
}

#[test]
fn batch_retirement_stays_private_until_successful_adoption() {
    let fixture = Fixture::new();
    fixture.remove_gone_from_graph();
    let keep =
        crate::admitted_source::load(&fixture.graph, &fixture.blobs, &FilePathId::new("keep.py"))
            .unwrap()
            .unwrap();
    let mut invalid =
        crate::admitted_source::load(&fixture.graph, &fixture.blobs, &FilePathId::new("keep.py"))
            .unwrap()
            .unwrap();
    invalid.file_id = FilePathId::new("never-admitted.py");
    assert!(fixture
        .live
        .fork_for_admitted_batch(&fixture.graph, &fixture.blobs, &[invalid])
        .is_err());
    assert!(fixture.live.knows_file("gone.py"));
    assert!(fixture.live.pending.contains_key("gone.py"));
    let (candidate, retired) = fixture
        .live
        .fork_for_admitted_batch(&fixture.graph, &fixture.blobs, &[keep])
        .unwrap();
    assert_eq!(retired, vec![FilePathId::new("gone.py")]);
    assert!(!candidate.knows_file("gone.py"));
    assert!(
        fixture.live.knows_file("gone.py"),
        "successful preparation is still not adoption"
    );
    assert!(candidate.waiting_on_paths["gone.py"].contains("waiting.py"));
}
