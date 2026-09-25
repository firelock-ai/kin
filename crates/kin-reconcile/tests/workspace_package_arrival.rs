// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::sync::Arc;

use kin_blobs::BlobStore;
use kin_db::{InMemoryGraph, SnapshotManager};
use kin_index::IndexPipeline;
use kin_model::{
    ArtifactId, Entity, EntityStore, FilePathId, GraphNodeId, Hash256, LocatedEntry, Relation,
    RelationKind, RepoPath, TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;

const CALLER_FILE: &str = "src/caller.js";
const TARGET_FILE: &str = "packages/wire/src/index.js";
const CALLER: &str = "import invoke from 'wire';\nexport function run() { return invoke(); }\n";
const NAMED: &str = "module.exports = function invoke() { return 42; };\n";
const DIFFERENT: &str = "module.exports = function implementation() { return 42; };\n";
const ANONYMOUS: &str = "module.exports = function () { return 42; };\n";

struct Repo {
    root: tempfile::TempDir,
    graph: Arc<InMemoryGraph>,
    blobs: BlobStore,
    reconciler: Reconciler,
    generation: usize,
}

impl Repo {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(root.path().join("blobs")).unwrap();
        let graph = Arc::new(InMemoryGraph::new());
        let mut reconciler = Reconciler::new(root.path().to_owned());
        reconciler
            .restore_cross_file_dependencies(graph.as_ref(), &blobs)
            .unwrap();
        Self {
            root,
            graph,
            blobs,
            reconciler,
            generation: 0,
        }
    }

    fn admit(&mut self, file: &str, source: &str) {
        let blob = self.blobs.write(source.as_bytes()).unwrap();
        let path = RepoPath::from_utf8(file).unwrap();
        let new = TreeEntry::blob(Hash256::from_bytes(blob.0), false);
        match self.graph.get_tree_entry(&FilePathId::new(file)).unwrap() {
            Some(held) if held == new => {}
            Some(held) => self
                .graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![TreeDelta::Updated {
                        artifact_id: self.graph.artifact_id_at_path(&path).unwrap(),
                        old: LocatedEntry::new(path.clone(), held),
                        new: LocatedEntry::new(path, new),
                    }],
                    ..Default::default()
                })
                .unwrap(),
            None => self
                .graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![TreeDelta::Added {
                        artifact_id: ArtifactId::new(),
                        new: LocatedEntry::new(path, new),
                    }],
                    ..Default::default()
                })
                .unwrap(),
        }
        let indexed = IndexPipeline::new()
            .index_file_content_with_tests(&FilePathId::new(file), source.as_bytes(), blob)
            .unwrap()
            .indexed_file;
        let result = self
            .reconciler
            .reconcile_indexed_observation(&indexed, &self.blobs, self.graph.as_ref())
            .expect("real admitted observation reconciles");
        self.graph.apply_transaction_delta(&result.delta).unwrap();
    }

    fn reopen(&mut self) {
        self.generation += 1;
        let path = self
            .root
            .path()
            .join(format!("graph-{}.kindb", self.generation));
        SnapshotManager::save_graph(&path, self.graph.as_ref()).unwrap();
        self.graph = SnapshotManager::open_without_text_index(&path)
            .unwrap()
            .graph();
        self.reconciler = Reconciler::new(self.root.path().to_owned());
        self.reconciler
            .seed_lkg_entities_from_graph(self.graph.as_ref());
        self.reconciler
            .restore_cross_file_dependencies(self.graph.as_ref(), &self.blobs)
            .expect("restore dependencies from real persisted graph and CAS");
    }

    fn caller(&self) -> Entity {
        self.graph
            .query_entities(&kin_model::EntityFilter {
                file_path: Some(FilePathId::new(CALLER_FILE)),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .find(|entity| entity.name == "run")
            .unwrap()
    }

    fn calls(&self) -> Vec<Relation> {
        let id = self.caller().id;
        self.graph
            .get_all_relations_for_entity(&id)
            .unwrap()
            .into_iter()
            .filter(|edge| edge.src.as_entity() == Some(id) && edge.kind == RelationKind::Calls)
            .collect()
    }

    fn assert_local_binding(&self, expected_name: &str, prior: &Entity) {
        self.assert_local_binding_at(TARGET_FILE, expected_name, prior);
    }

    fn assert_local_binding_at(&self, target_file: &str, expected_name: &str, prior: &Entity) {
        let caller = self.caller();
        assert_eq!(caller.id, prior.id);
        assert_eq!(caller.span, prior.span);
        assert_eq!(caller.fingerprint, prior.fingerprint);
        assert_eq!(
            caller.metadata.extra.get("blob_hash"),
            prior.metadata.extra.get("blob_hash")
        );
        let calls = self.calls();
        println!(
            "package arrival expected={expected_name} files_resolved={} calls={calls:?}",
            self.reconciler.cross_file_linker().last_files_resolved()
        );
        assert_eq!(calls.len(), 1);
        assert!(
            !kin_index::is_external_import_placeholder(&calls[0]),
            "package path must rebind the unchanged importer: {calls:?}"
        );
        let target = self
            .graph
            .get_entity(&calls[0].dst.as_entity().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(target.file_origin, Some(FilePathId::new(target_file)));
        assert_eq!(target.name, expected_name);
        assert_eq!(
            calls[0]
                .evidence
                .iter()
                .map(|row| row.occurrence_count)
                .sum::<u32>(),
            1
        );
        let site = calls[0]
            .evidence
            .iter()
            .find_map(|row| row.source_span.as_ref())
            .unwrap();
        assert_eq!(site.file, FilePathId::new(CALLER_FILE));
        let span = caller.span.as_ref().unwrap();
        assert!(span.start_byte <= site.start_byte && site.end_byte <= span.end_byte);

        self.assert_import_target(target_file);
    }

    fn assert_import_target(&self, target_file: &str) {
        let artifact = |file| {
            self.graph
                .artifact_id_at_path(&RepoPath::from_utf8(file).unwrap())
                .unwrap()
        };
        let source_node = GraphNodeId::Artifact(artifact(CALLER_FILE));
        let target_node = GraphNodeId::Artifact(artifact(target_file));
        let imports = self
            .graph
            .traverse(&source_node, &[RelationKind::Imports], 1)
            .unwrap();
        assert!(
            imports
                .relations
                .iter()
                .any(|edge| edge.src == source_node && edge.dst == target_node),
            "the actual package import must bind the admitted target artifact"
        );
    }
}

fn target_first(source: &str, name: &str) {
    let mut repo = Repo::new();
    repo.admit(TARGET_FILE, source);
    repo.admit(CALLER_FILE, CALLER);
    let caller = repo.caller();
    repo.assert_local_binding(name, &caller);
    repo.reopen();
    repo.assert_local_binding(name, &caller);
}

fn target_arrives(source: &str, name: &str, cold: bool) {
    target_arrives_at("wire", TARGET_FILE, source, name, cold);
}

fn target_arrives_at(module: &str, target_file: &str, source: &str, name: &str, cold: bool) {
    let mut repo = Repo::new();
    repo.admit(
        CALLER_FILE,
        &CALLER.replace("'wire'", &format!("'{module}'")),
    );
    let caller = repo.caller();
    let original = repo.calls();
    assert_eq!(original.len(), 1);
    assert!(kin_index::is_external_import_placeholder(&original[0]));
    if cold {
        repo.reopen();
    }
    repo.admit(target_file, source);
    assert_eq!(repo.reconciler.cross_file_linker().last_files_resolved(), 2);
    repo.assert_local_binding_at(target_file, name, &caller);
    assert!(repo.calls().iter().all(|edge| edge.id != original[0].id));
    repo.reopen();
    repo.assert_local_binding_at(target_file, name, &caller);
}

#[test]
fn target_first_named_export_proves_resolver_support() {
    target_first(NAMED, "invoke");
}
#[test]
fn target_first_different_export_proves_resolver_support() {
    target_first(DIFFERENT, "implementation");
}
#[test]
fn target_first_anonymous_export_proves_resolver_support() {
    target_first(ANONYMOUS, "module.exports");
}
#[test]
fn warm_named_package_arrival_rebinds_unchanged_importer() {
    target_arrives(NAMED, "invoke", false);
}
#[test]
fn cold_named_package_arrival_rebinds_unchanged_importer() {
    target_arrives(NAMED, "invoke", true);
}
#[test]
fn warm_different_package_arrival_rebinds_unchanged_importer() {
    target_arrives(DIFFERENT, "implementation", false);
}
#[test]
fn cold_different_package_arrival_rebinds_unchanged_importer() {
    target_arrives(DIFFERENT, "implementation", true);
}
#[test]
fn warm_anonymous_package_arrival_rebinds_unchanged_importer() {
    target_arrives(ANONYMOUS, "module.exports", false);
}
#[test]
fn cold_anonymous_package_arrival_rebinds_unchanged_importer() {
    target_arrives(ANONYMOUS, "module.exports", true);
}

#[test]
fn scoped_and_subpath_arrivals_rebind_after_warm_and_cold_startup() {
    for (module, target) in [
        ("@scope/wire", "packages/wire/src/index.js"),
        ("@scope/wire", "packages/scope-wire/src/index.js"),
        ("wire/feature", "packages/wire/src/feature/index.js"),
        (
            "@scope/wire/feature",
            "packages/scope-wire/src/feature/index.js",
        ),
    ] {
        for cold in [false, true] {
            target_arrives_at(module, target, ANONYMOUS, "module.exports", cold);
        }
    }
}

#[test]
fn import_retarget_clears_old_package_candidates_warm_and_after_reopen() {
    for cold in [false, true] {
        let mut repo = Repo::new();
        repo.admit(CALLER_FILE, CALLER);
        repo.admit(CALLER_FILE, &CALLER.replace("'wire'", "'other-wire'"));
        let caller = repo.caller();
        if cold {
            repo.reopen();
        }
        repo.admit(TARGET_FILE, ANONYMOUS);
        assert_eq!(
            repo.reconciler.cross_file_linker().last_files_resolved(),
            1,
            "retired package keys must not nominate the caller"
        );
        assert!(kin_index::is_external_import_placeholder(&repo.calls()[0]));
        let current = "packages/other-wire/src/index.js";
        repo.admit(current, ANONYMOUS);
        assert_eq!(repo.reconciler.cross_file_linker().last_files_resolved(), 2);
        repo.assert_local_binding_at(current, "module.exports", &caller);
    }
}

#[test]
fn unrelated_packages_do_not_expand_the_resolution_batch() {
    let mut repo = Repo::new();
    repo.admit(CALLER_FILE, CALLER);
    let caller = repo.caller();
    for index in 0..24 {
        repo.admit(
            &format!("packages/unrelated-{index}/src/index.js"),
            ANONYMOUS,
        );
        assert_eq!(repo.reconciler.cross_file_linker().last_files_resolved(), 1);
        assert!(kin_index::is_external_import_placeholder(&repo.calls()[0]));
    }
    repo.admit(TARGET_FILE, ANONYMOUS);
    assert_eq!(repo.reconciler.cross_file_linker().last_files_resolved(), 2);
    repo.assert_local_binding("module.exports", &caller);
}

#[test]
fn side_effect_import_without_symbol_keys_rebinds_after_cold_startup() {
    let mut repo = Repo::new();
    repo.admit(CALLER_FILE, "import 'wire';\n");
    repo.reopen();
    repo.admit(TARGET_FILE, ANONYMOUS);
    assert_eq!(repo.reconciler.cross_file_linker().last_files_resolved(), 2);
    repo.assert_import_target(TARGET_FILE);
    repo.reopen();
    repo.assert_import_target(TARGET_FILE);
}
