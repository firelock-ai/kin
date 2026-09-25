// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_blobs::BlobStore;
use kin_db::{InMemoryGraph, SnapshotManager};
use kin_index::IndexPipeline;
use kin_model::{
    ArtifactId, EntityStore, FilePathId, Hash256, LocatedEntry, Relation, RepoPath,
    TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;
use std::sync::Arc;

const SOURCE: &str = "var Channel = require('external-wire');\n\
var service = {};\n\
service.initialize = function() {\n\
 var held = null;\n\
 Object.defineProperty(this, 'transport', { get: function() {\n\
  if (held === null) { held = new Channel(); }\n\
  return held;\n\
 }});\n\
};\n\
service.dispatch = function(request) { this.transport.send(request); this.transport.send(request); };\n";
const FILE: &str = "src/service.js";

fn edit(graph: &InMemoryGraph, reconciler: &mut Reconciler, blobs: &BlobStore, source: &str) {
    edit_at(graph, reconciler, blobs, FILE, source);
}
fn edit_at(
    graph: &InMemoryGraph,
    reconciler: &mut Reconciler,
    blobs: &BlobStore,
    file: &str,
    source: &str,
) {
    let blob = blobs.write(source.as_bytes()).unwrap();
    let path = RepoPath::from_utf8(file.to_string()).unwrap();
    let new = LocatedEntry::new(
        path.clone(),
        TreeEntry::blob(Hash256::from_bytes(blob.0), false),
    );
    let tree_delta = match graph.get_tree_entry(&FilePathId::new(file)).unwrap() {
        Some(old) => TreeDelta::Updated {
            artifact_id: graph.artifact_id_at_path(&path).unwrap(),
            old: LocatedEntry::new(path, old),
            new,
        },
        None => TreeDelta::Added {
            artifact_id: ArtifactId::new(),
            new,
        },
    };
    graph
        .apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![tree_delta],
            ..Default::default()
        })
        .unwrap();
    let indexed = IndexPipeline::new()
        .index_file_content_with_tests(&FilePathId::new(file), source.as_bytes(), blob)
        .unwrap()
        .indexed_file;
    let result = reconciler
        .reconcile_indexed_observation(&indexed, blobs, graph)
        .unwrap();
    graph.apply_transaction_delta(&result.delta).unwrap();
}
fn edges(graph: &InMemoryGraph) -> Vec<Relation> {
    let caller = graph
        .list_all_entities()
        .unwrap()
        .into_iter()
        .find(|e| e.name == "service.dispatch" && e.file_origin == Some(FilePathId::new(FILE)))
        .unwrap();
    graph
        .get_all_relations_for_entity(&caller.id)
        .unwrap()
        .into_iter()
        .filter(|r| {
            r.src.as_entity() == Some(caller.id) && kin_index::is_external_import_placeholder(r)
        })
        .collect()
}

#[test]
fn imported_getter_live_source_retarget_withdrawal_recovery_and_reopen() {
    let root = tempfile::tempdir().unwrap();
    let blobs = BlobStore::new(root.path().join("blobs")).unwrap();
    let mut graph = Arc::new(InMemoryGraph::new());
    let mut reconciler = Reconciler::new(root.path().to_owned());
    let sources = [
        (SOURCE.to_owned(), Some("external-wire")),
        (
            SOURCE.replace("external-wire", "another-wire"),
            Some("another-wire"),
        ),
        (
            SOURCE.replace("held = new Channel();", "held = unknown;"),
            None,
        ),
        (SOURCE.to_owned(), Some("external-wire")),
        (format!("{SOURCE}\nservice.transport = other;"), None),
        (SOURCE.to_owned(), Some("external-wire")),
        (format!("{SOURCE}\nconst alias = service; Object.defineProperty(alias, 'transport', {{value: replacement}});"), None),
        (SOURCE.to_owned(), Some("external-wire")),
        (format!("{SOURCE}\nconst first = service; const second = first; Reflect.defineProperty(second, 'transport', {{value: replacement}});"), None),
        (SOURCE.to_owned(), Some("external-wire")),
    ];
    let mut caller_identity = None;
    for (step, (source, expected)) in sources.into_iter().enumerate() {
        edit(graph.as_ref(), &mut reconciler, &blobs, &source);
        let caller = graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|entity| {
                entity.name == "service.dispatch"
                    && entity.file_origin == Some(FilePathId::new(FILE))
            })
            .unwrap();
        if let Some(id) = caller_identity {
            assert_eq!(
                caller.id, id,
                "supporting-source edits preserve the caller identity"
            );
        } else {
            caller_identity = Some(caller.id);
        }
        let current = edges(graph.as_ref());
        assert_eq!(
            current.len(),
            usize::from(expected.is_some()),
            "step {step}: {current:?}"
        );
        if let Some(module) = expected {
            let edge = &current[0];
            assert_eq!(edge.import_source.as_deref(), Some(module));
            assert_eq!(edge.evidence.len(), 2);
            let target = graph
                .get_entity(&edge.dst.as_entity().unwrap())
                .unwrap()
                .unwrap();
            assert!(target.file_origin.is_none() && target.span.is_none());
            assert_eq!(target.role, kin_model::EntityRole::External);
            assert_eq!(
                kin_index::trace_crossing_for(&target, Some(edge))
                    .unwrap()
                    .specifier
                    .as_deref(),
                Some(module)
            );
        }
        let snapshot = root.path().join(format!("generation-{step}.kindb"));
        SnapshotManager::save_graph(&snapshot, graph.as_ref()).unwrap();
        graph = SnapshotManager::open_without_text_index(&snapshot)
            .unwrap()
            .graph();
        assert_eq!(edges(graph.as_ref()), current);
        // A fresh reconciler must reconstruct its authority from this admitted
        // graph/CAS state; no synthetic linker or coverage inputs are injected.
        reconciler = Reconciler::new(root.path().to_owned());
    }
    let result = reconciler
        .reconcile_file_change(
            &kin_index::FileEvent::Removed(root.path().join(FILE)),
            &blobs,
            graph.as_ref(),
        )
        .unwrap();
    graph.apply_transaction_delta(&result.delta).unwrap();
    assert!(graph
        .list_all_entities()
        .unwrap()
        .iter()
        .all(|e| e.file_origin != Some(FilePathId::new(FILE))));
}
