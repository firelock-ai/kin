// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_blobs::BlobStore;
use kin_db::{InMemoryGraph, SnapshotManager};
use kin_model::{
    ArtifactId, Entity, EntityDelta, EntityStore, FilePathId, Hash256, LocatedEntry, RepoPath,
    SourceRegion, TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;

struct Fixture {
    root: tempfile::TempDir,
    blobs: BlobStore,
    graph: InMemoryGraph,
}

impl Fixture {
    fn new(files: &[(&str, &str)]) -> Self {
        let root = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(root.path().join("blobs")).unwrap();
        let mut fixture = Self {
            root,
            blobs,
            graph: InMemoryGraph::new(),
        };
        fixture.publish(files);
        fixture
    }

    fn publish(&mut self, files: &[(&str, &str)]) {
        let old = self.graph.to_snapshot();
        for (file, body) in files {
            let path = RepoPath::from_utf8(*file).unwrap();
            let hash = self.blobs.write(body.as_bytes()).unwrap();
            let next = LocatedEntry::new(
                path.clone(),
                TreeEntry::blob(Hash256::from_bytes(hash.0), false),
            );
            let change = match self.graph.get_tree_entry(&FilePathId::new(*file)).unwrap() {
                Some(entry) => TreeDelta::Updated {
                    artifact_id: self.graph.artifact_id_at_path(&path).unwrap(),
                    old: LocatedEntry::new(path, entry),
                    new: next,
                },
                None => TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: next,
                },
            };
            self.graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![change],
                    ..Default::default()
                })
                .unwrap();
            std::fs::write(self.root.path().join(file), body).unwrap();
        }
        let prior = kin_model::graph::ResolvedGraphState {
            entities: old.entities,
            relations: old.relations,
            tree: old.resolved_tree,
            external_references: old.external_references,
            ..Default::default()
        };
        let prepared = Reconciler::prepare_admitted_source_batch(
            self.graph.to_snapshot(),
            &files
                .iter()
                .map(|(f, _)| FilePathId::new(*f))
                .collect::<Vec<_>>(),
            &self.blobs,
            &[prior],
        )
        .unwrap();
        self.graph = InMemoryGraph::from_snapshot(prepared.snapshot().clone()).unwrap();
        for source in prepared.sources() {
            self.graph.upsert_file_layout(&source.layout).unwrap();
        }
    }

    fn entity(&self, name: &str) -> Entity {
        self.graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|e| e.name == name && e.kind == kin_model::EntityKind::Function)
            .unwrap()
    }

    fn cold_graph(&self) -> InMemoryGraph {
        let path = self.root.path().join("snapshot.json");
        SnapshotManager::save_graph(&path, &self.graph).unwrap();
        let reopened = SnapshotManager::open_without_text_index(&path).unwrap();
        InMemoryGraph::from_snapshot_without_text_index(reopened.graph().to_snapshot()).unwrap()
    }

    fn cold_reconciler(&self, graph: &InMemoryGraph) -> Reconciler {
        let mut reconciler = Reconciler::new(self.root.path().to_path_buf());
        reconciler.seed_lkg_entities_from_graph(graph);
        reconciler.seed_cross_file_linker_from_graph(graph);
        reconciler.set_traffic_checker(Box::new(Clear));
        reconciler
    }
}

struct Clear;
impl kin_reconcile::TrafficChecker for Clear {
    fn check_collisions(
        &self,
        _: &kin_model::IntentScope,
        _: Option<&kin_model::SessionId>,
    ) -> std::result::Result<kin_reconcile::CollisionCheck, String> {
        Ok(kin_reconcile::CollisionCheck::Clear)
    }
}

#[test]
fn cold_checked_source_state_drives_metadata_only_projection_with_preserved_identity() {
    let mut fixture = Fixture::new(&[("work.py", "def work(value):\n    return value\n")]);
    let id = fixture.entity("work").id;
    let body = "# moved declaration\n\ndef work(value):\n    return value + 2\n";
    fixture.publish(&[("work.py", body)]);
    assert_eq!(fixture.entity("work").id, id);
    let parsed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("work.py"),
            body.as_bytes(),
            kin_blobs::digest(body.as_bytes()),
        )
        .unwrap()
        .indexed_file;
    let raw_id = parsed
        .entities
        .iter()
        .find(|entity| entity.name == "work" && entity.kind == kin_model::EntityKind::Function)
        .unwrap()
        .id;
    assert_ne!(
        raw_id, id,
        "control must exercise canonical layout ID remapping"
    );
    let graph = fixture.cold_graph();
    let mut reconciler = fixture.cold_reconciler(&graph);
    reconciler
        .restore_canonical_source_state(&graph, &fixture.blobs)
        .unwrap();
    let current = graph.get_entity(&id).unwrap().unwrap();
    let mut updated = current.clone();
    updated
        .metadata
        .extra
        .insert("projection-control".into(), serde_json::json!(true));
    let (files, _) = reconciler
        .project_transaction_to_files(
            &TransactionDelta {
                entity_deltas: vec![EntityDelta::Modified {
                    old: current,
                    new: updated,
                }],
                ..Default::default()
            },
            &HashMap::new(),
        )
        .unwrap();
    assert_eq!(files, vec![FilePathId::new("work.py")]);
    assert_eq!(
        std::fs::read(fixture.root.path().join("work.py")).unwrap(),
        body.as_bytes()
    );
    assert!(reconciler
        .projection()
        .get_layout(&FilePathId::new("work.py"))
        .unwrap()
        .regions
        .iter()
        .any(
            |region| matches!(region, SourceRegion::EntityRef { entity_id, .. } if *entity_id == id)
        ));
}

#[test]
fn cold_checked_source_state_includes_complete_entity_free_source_without_a_layout() {
    let fixture = Fixture::new(&[("empty.c", "// no declarations\n")]);
    assert!(
        fixture.graph.list_all_entities().unwrap().is_empty(),
        "fixture must actually have no declaration anchors"
    );
    fixture
        .graph
        .delete_file_layout(&FilePathId::new("empty.c"))
        .unwrap();
    let graph = fixture.cold_graph();
    let mut reconciler = fixture.cold_reconciler(&graph);
    reconciler
        .restore_canonical_source_state(&graph, &fixture.blobs)
        .unwrap();
    let file = FilePathId::new("empty.c");
    assert_eq!(
        reconciler.projection().get_content(&file),
        Some(&b"// no declarations\n"[..])
    );
    assert_eq!(
        reconciler
            .projection()
            .get_layout(&file)
            .unwrap()
            .parse_completeness,
        kin_model::ParseCompleteness::Full
    );
}

#[test]
fn cold_checked_source_state_refuses_foreign_ids_ranges_and_import_claims() {
    for corruption in ["foreign-id", "range", "import"] {
        let fixture = Fixture::new(&[("work.py", "def work(value):\n    return value\n")]);
        let file = FilePathId::new("work.py");
        let mut layout = fixture.graph.get_file_layout(&file).unwrap().unwrap();
        if corruption == "import" {
            layout.imports.items.push(kin_model::ImportItem {
                source: "unrelated".into(),
                symbols: vec!["work".into()],
                byte_range: 0..1,
            });
        } else {
            let region = layout
                .regions
                .iter_mut()
                .find(|region| matches!(region, SourceRegion::EntityRef { .. }))
                .unwrap();
            let SourceRegion::EntityRef {
                entity_id,
                byte_range,
            } = region
            else {
                unreachable!()
            };
            if corruption == "foreign-id" {
                *entity_id = kin_model::EntityId::new();
            } else {
                byte_range.start += 1;
            }
        }
        fixture.graph.upsert_file_layout(&layout).unwrap();
        let graph = fixture.cold_graph();
        let before = serde_json::to_value(graph.get_file_layout(&file).unwrap()).unwrap();
        let mut reconciler = fixture.cold_reconciler(&graph);
        let error = reconciler
            .restore_canonical_source_state(&graph, &fixture.blobs)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("projection layout differs from verified source"),
            "{corruption}: {error}"
        );
        assert!(reconciler.projection().get_content(&file).is_none());
        assert_eq!(
            serde_json::to_value(graph.get_file_layout(&file).unwrap()).unwrap(),
            before
        );
    }
}

#[test]
fn cold_checked_source_state_missing_cas_does_not_partially_adopt_then_retry_succeeds() {
    let mut fixture = Fixture::new(&[
        ("a.py", "def first():\n    return 1\n"),
        (
            "z.py",
            "from a import first\ndef last():\n    return first()\n",
        ),
    ]);
    let mut reconciler = fixture.cold_reconciler(&fixture.graph);
    reconciler
        .restore_canonical_source_state(&fixture.graph, &fixture.blobs)
        .unwrap();
    let a = FilePathId::new("a.py");
    let z = FilePathId::new("z.py");
    let before = reconciler.projection().get_content(&a).unwrap().to_vec();
    let before_layout = serde_json::to_value(reconciler.projection().get_layout(&a)).unwrap();
    let pending = reconciler.cross_file_linker().pending_file_count();
    let original = fixture.entity("first");
    let lkg = reconciler
        .lkg()
        .get(&original.id)
        .unwrap()
        .fingerprint
        .clone();
    fixture.publish(&[("a.py", "def first():\n    return 9\n")]);
    let hash = fixture
        .graph
        .get_tree_entry(&z)
        .unwrap()
        .unwrap()
        .blob_identity()
        .unwrap();
    let hash = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
    let saved = fixture.blobs.read(&hash).unwrap();
    fixture.blobs.delete(&hash).unwrap();
    assert!(reconciler
        .restore_canonical_source_state(&fixture.graph, &fixture.blobs)
        .is_err());
    assert_eq!(
        reconciler.projection().get_content(&a),
        Some(before.as_slice())
    );
    assert_eq!(
        serde_json::to_value(reconciler.projection().get_layout(&a)).unwrap(),
        before_layout
    );
    assert_eq!(reconciler.cross_file_linker().pending_file_count(), pending);
    assert_eq!(reconciler.lkg().get(&original.id).unwrap().fingerprint, lkg);
    assert_eq!(fixture.blobs.write(&saved).unwrap(), hash);
    reconciler
        .restore_canonical_source_state(&fixture.graph, &fixture.blobs)
        .unwrap();
    assert_eq!(
        reconciler.projection().get_content(&a),
        Some(&b"def first():\n    return 9\n"[..])
    );
}

#[test]
fn cold_checked_source_state_refuses_source_identity_mismatch_without_host_fallback() {
    let fixture = Fixture::new(&[("work.py", "def work(value):\n    return value\n")]);
    let mut entity = fixture.entity("work");
    entity.metadata.extra.insert(
        "blob_hash".into(),
        serde_json::json!(kin_blobs::digest(b"unrelated").to_string()),
    );
    fixture.graph.upsert_entity(&entity).unwrap();
    let graph = fixture.cold_graph();
    let mut reconciler = fixture.cold_reconciler(&graph);
    let error = reconciler
        .restore_canonical_source_state(&graph, &fixture.blobs)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("metadata differs from its admitted blob"),
        "{error}"
    );
    assert!(reconciler.projection().file_ids().is_empty());
    assert_eq!(
        std::fs::read(fixture.root.path().join("work.py")).unwrap(),
        b"def work(value):\n    return value\n"
    );
}

#[test]
fn cold_checked_source_state_partial_neighbor_retains_lkg_without_blocking_complete_source() {
    let fixture = Fixture::new(&[
        ("work.py", "def work(value):\n    return value\n"),
        ("broken.py", "def broken():\n    return 7\n"),
    ]);
    let old = fixture.entity("broken");
    let path = RepoPath::from_utf8("broken.py").unwrap();
    let previous = fixture
        .graph
        .get_tree_entry(&FilePathId::new("broken.py"))
        .unwrap()
        .unwrap();
    let bad = b"def broken(:\n    return 7\n";
    let hash = fixture.blobs.write(bad).unwrap();
    let parsed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(&FilePathId::new("broken.py"), bad, hash)
        .unwrap()
        .indexed_file;
    assert!(
        !matches!(parsed.parse_state, kin_model::ParseState::Valid),
        "fixture must actually be incomplete"
    );
    std::fs::write(fixture.root.path().join("broken.py"), bad).unwrap();
    fixture
        .graph
        .apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Updated {
                artifact_id: fixture.graph.artifact_id_at_path(&path).unwrap(),
                old: LocatedEntry::new(path.clone(), previous),
                new: LocatedEntry::new(path, TreeEntry::blob(Hash256::from_bytes(hash.0), false)),
            }],
            ..Default::default()
        })
        .unwrap();
    let graph = fixture.cold_graph();
    let mut reconciler = fixture.cold_reconciler(&graph);
    reconciler
        .restore_canonical_source_state(&graph, &fixture.blobs)
        .unwrap();
    assert!(reconciler.lkg().get(&old.id).is_some());
    assert!(reconciler
        .projection()
        .get_content(&FilePathId::new("broken.py"))
        .is_none());
    assert!(reconciler
        .projection()
        .get_content(&FilePathId::new("work.py"))
        .is_some());
    assert_eq!(graph.get_entity(&old.id).unwrap(), Some(old));
    assert_eq!(
        std::fs::read(fixture.root.path().join("broken.py")).unwrap(),
        bad
    );
}

#[test]
fn cold_checked_source_state_retains_waiting_caller_for_actual_followup_edit() {
    let mut fixture = Fixture::new(&[(
        "caller.py",
        "from local import work\ndef run():\n    return work(value=1)\n",
    )]);
    let caller = fixture.entity("run").id;
    let graph = fixture.cold_graph();
    let mut reconciler = fixture.cold_reconciler(&graph);
    reconciler
        .restore_canonical_source_state(&graph, &fixture.blobs)
        .unwrap();
    assert_eq!(reconciler.cross_file_linker().pending_file_count(), 1);
    let body = "def work(value):\n    return value\n";
    let hash = fixture.blobs.write(body.as_bytes()).unwrap();
    graph
        .apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("local.py").unwrap(),
                    TreeEntry::blob(Hash256::from_bytes(hash.0), false),
                ),
            }],
            ..Default::default()
        })
        .unwrap();
    std::fs::write(fixture.root.path().join("local.py"), body).unwrap();
    let result = reconciler
        .reconcile_file_change(
            &kin_index::FileEvent::Changed(fixture.root.path().join("local.py")),
            &fixture.blobs,
            &graph,
        )
        .unwrap();
    graph.apply_transaction_delta(&result.delta).unwrap();
    let target = graph
        .list_all_entities()
        .unwrap()
        .into_iter()
        .find(|entity| {
            entity.name == "work" && entity.file_origin == Some(FilePathId::new("local.py"))
        })
        .unwrap();
    assert!(
        graph
            .get_relations(&caller, &[kin_model::RelationKind::Calls])
            .unwrap()
            .iter()
            .any(|edge| edge.dst.as_entity() == Some(target.id) && edge.confidence >= 0.9),
        "target={target:#?}, caller relations={:#?}, delta={:#?}",
        graph
            .get_relations(&caller, &[kin_model::RelationKind::Calls])
            .unwrap(),
        result.delta
    );
    assert_eq!(graph.get_entity(&caller).unwrap().unwrap().id, caller);
    fixture.graph = graph;
    let cold = fixture.cold_graph();
    let mut reopened = fixture.cold_reconciler(&cold);
    reopened
        .restore_canonical_source_state(&cold, &fixture.blobs)
        .unwrap();
    assert!(reopened
        .projection()
        .get_content(&FilePathId::new("caller.py"))
        .is_some());
}

#[test]
fn cold_checked_source_state_preserves_opaque_facet_with_source_extension() {
    let fixture = Fixture::new(&[("work.py", "def work():\n    return 1\n")]);
    let file = FilePathId::new("opaque.py");
    let content = b"\0\xff\0\xff";
    let hash = fixture.blobs.write(content).unwrap();
    let indexed = kin_index::IndexPipeline::new()
        .index_any_content(&file, content, hash)
        .unwrap();
    let kin_index::IndexedAny::OpaqueArtifact(opaque) = indexed else {
        panic!("control must use real byte-classified opaque content");
    };
    fixture
        .graph
        .apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(
                    RepoPath::from_utf8(&file.0).unwrap(),
                    TreeEntry::blob(Hash256::from_bytes(hash.0), false),
                ),
            }],
            ..Default::default()
        })
        .unwrap();
    fixture.graph.upsert_opaque_artifact(&opaque).unwrap();
    let graph = fixture.cold_graph();
    let mut reconciler = fixture.cold_reconciler(&graph);
    reconciler
        .restore_canonical_source_state(&graph, &fixture.blobs)
        .unwrap();
    assert!(reconciler.projection().get_content(&file).is_none());
    assert!(graph.get_file_layout(&file).unwrap().is_none());
    assert_eq!(
        serde_json::to_value(graph.get_opaque_artifact(&file).unwrap().unwrap()).unwrap(),
        serde_json::to_value(opaque).unwrap()
    );
    assert!(reconciler
        .projection()
        .get_content(&FilePathId::new("work.py"))
        .is_some());
}
