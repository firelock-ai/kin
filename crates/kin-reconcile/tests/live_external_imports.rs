// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! External import targets and their source-owned edges share one live delta.

use kin_blobs::BlobStore;
use kin_db::{InMemoryGraph, SnapshotManager};
use kin_index::IndexPipeline;
use kin_model::{
    ArtifactId, Entity, EntityDelta, EntityStore, FilePathId, Hash256, LocatedEntry, Relation,
    RelationDelta, RepoPath, TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::{ReconcileOutcome, Reconciler};
use std::sync::Arc;

const ONE: &str = "const remote = require('external-one');\nfunction run() { return remote(); }\n";
const TWO: &str = "const remote = require('external-two');\nfunction run() { return remote(); }\n";
const NONE: &str = "function run() { return 1; }\n";

struct Repo {
    root: tempfile::TempDir,
    blobs: BlobStore,
    graph: Arc<InMemoryGraph>,
    reconciler: Reconciler,
    generation: usize,
}
impl Repo {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(root.path().join("blobs")).unwrap();
        let graph = Arc::new(InMemoryGraph::new());
        let mut reconciler = Reconciler::new(root.path().to_owned());
        reconciler.seed_cross_file_linker_from_graph(graph.as_ref());
        Self {
            root,
            blobs,
            graph,
            reconciler,
            generation: 0,
        }
    }
    fn plan(
        &mut self,
        file: &str,
        source: &str,
    ) -> kin_reconcile::Result<kin_reconcile::ReconcileResult> {
        let blob = self.blobs.write(source.as_bytes()).unwrap();
        let path = RepoPath::from_utf8(file.to_owned()).unwrap();
        let new = LocatedEntry::new(
            path.clone(),
            TreeEntry::blob(Hash256::from_bytes(blob.0), false),
        );
        let change = match self.graph.get_tree_entry(&FilePathId::new(file)).unwrap() {
            Some(old) if old == new.entry => return self.plan_admitted(file, source, blob),
            Some(old) => TreeDelta::Updated {
                artifact_id: self.graph.artifact_id_at_path(&path).unwrap(),
                old: LocatedEntry::new(path, old),
                new,
            },
            None => TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new,
            },
        };
        self.graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![change],
                ..Default::default()
            })
            .unwrap();
        self.plan_admitted(file, source, blob)
    }
    fn plan_admitted(
        &mut self,
        file: &str,
        source: &str,
        blob: kin_blobs::Hash256,
    ) -> kin_reconcile::Result<kin_reconcile::ReconcileResult> {
        let indexed = IndexPipeline::new()
            .index_file_content_with_tests(&FilePathId::new(file), source.as_bytes(), blob)
            .unwrap()
            .indexed_file;
        self.reconciler
            .reconcile_indexed_observation(&indexed, &self.blobs, self.graph.as_ref())
    }
    fn edit(&mut self, file: &str, source: &str) -> TransactionDelta {
        let result = self.plan(file, source).unwrap();
        self.graph.apply_transaction_delta(&result.delta).unwrap();
        result.delta
    }
    fn reopen(&mut self) {
        self.generation += 1;
        let path = self
            .root
            .path()
            .join(format!("state-{}.kindb", self.generation));
        SnapshotManager::save_graph(&path, self.graph.as_ref()).unwrap();
        self.graph = SnapshotManager::open_without_text_index(&path)
            .unwrap()
            .graph();
        self.reconciler = Reconciler::new(self.root.path().to_owned());
        self.reconciler
            .seed_lkg_entities_from_graph(self.graph.as_ref());
        self.reconciler
            .seed_cross_file_linker_from_graph(self.graph.as_ref());
    }
    fn source(&self, file: &str) -> Entity {
        self.graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|entity| {
                entity.name == "run"
                    && entity
                        .file_origin
                        .as_ref()
                        .is_some_and(|origin| origin.0 == file)
            })
            .unwrap()
    }
    fn edges(&self, file: &str) -> Vec<Relation> {
        let source = self.source(file).id;
        self.graph
            .get_all_relations_for_entity(&source)
            .unwrap()
            .into_iter()
            .filter(|relation| {
                relation.src.as_entity() == Some(source)
                    && kin_index::is_external_import_placeholder(relation)
            })
            .collect()
    }
    fn target(&self, relation: &Relation) -> Entity {
        self.graph
            .get_entity(&relation.dst.as_entity().unwrap())
            .unwrap()
            .unwrap()
    }
    fn outgoing_calls(&self, file: &str) -> Vec<Relation> {
        let source = self.source(file).id;
        self.graph
            .get_all_relations_for_entity(&source)
            .unwrap()
            .into_iter()
            .filter(|relation| {
                relation.src.as_entity() == Some(source)
                    && relation.kind == kin_model::RelationKind::Calls
            })
            .collect()
    }
    fn remove(&mut self, file: &str) {
        let result = self
            .reconciler
            .reconcile_file_change(
                &kin_index::FileEvent::Removed(self.root.path().join(file)),
                &self.blobs,
                self.graph.as_ref(),
            )
            .unwrap();
        self.graph.apply_transaction_delta(&result.delta).unwrap();
        let path = RepoPath::from_utf8(file.to_owned()).unwrap();
        let old = self
            .graph
            .get_tree_entry(&FilePathId::new(file))
            .unwrap()
            .unwrap();
        let artifact_id = self.graph.artifact_id_at_path(&path).unwrap();
        let node = kin_model::GraphNodeId::Artifact(artifact_id);
        let relation_deltas = self
            .graph
            .traverse(&node, &[kin_model::RelationKind::Imports], 1)
            .unwrap()
            .relations
            .into_iter()
            .filter(|edge| edge.src == node || edge.dst == node)
            .map(|old| RelationDelta::Removed { old })
            .collect();
        self.graph
            .apply_transaction_delta(&TransactionDelta {
                relation_deltas,
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id,
                    old: LocatedEntry::new(path, old),
                }],
                ..Default::default()
            })
            .unwrap();
    }
}

#[test]
fn cold_live_external_import_admits_target_and_edge_together_without_workspace_source() {
    let mut repo = Repo::new();
    let result = repo.plan("caller.js", ONE).unwrap();
    let edge = result
        .delta
        .relation_deltas
        .iter()
        .find_map(|delta| match delta {
            RelationDelta::Added { new } if kin_index::is_external_import_placeholder(new) => {
                Some(new)
            }
            _ => None,
        })
        .expect("live external edge");
    let target = edge.dst.as_entity().unwrap();
    assert!(result.delta.entity_deltas.iter().any(|delta| matches!(delta, EntityDelta::Added { new } if new.id == target && kin_index::is_external_reference_target(new))));
    assert!(
        repo.graph.get_entity(&target).unwrap().is_none(),
        "planning cannot mutate graph"
    );
    let mut incomplete = result.delta.clone();
    incomplete
        .entity_deltas
        .retain(|delta| delta.target_id() != target);
    assert!(
        repo.graph.apply_transaction_delta(&incomplete).is_err(),
        "an edge without its target must fail atomically"
    );
    assert!(repo.graph.list_all_entities().unwrap().is_empty());
    repo.graph.apply_transaction_delta(&result.delta).unwrap();
    assert!(!repo.root.path().join("caller.js").exists());
    repo.reopen();
    let edges = repo.edges("caller.js");
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].import_source.as_deref(), Some("external-one"));
    assert_eq!(
        kin_index::RelationResolution::of(&edges[0]),
        kin_index::RelationResolution::NameOnly
    );
    assert!(kin_index::is_external_reference_target(
        &repo.target(&edges[0])
    ));
}

#[test]
fn import_only_retarget_and_removal_survive_warm_and_cold_reopen_and_preserve_shared_target() {
    for cold in [false, true] {
        let mut repo = Repo::new();
        repo.edit("caller.js", ONE);
        repo.edit("other.js", ONE);
        let old = repo.edges("caller.js")[0].clone();
        let other = repo.edges("other.js")[0].clone();
        assert_eq!(old.dst, other.dst);
        let target = repo.target(&old);
        if cold {
            repo.reopen();
        }
        let delta = repo.edit("caller.js", TWO);
        assert!(delta.relation_deltas.iter().any(
            |delta| matches!(delta, RelationDelta::Removed { old: removed } if removed.id == old.id)
        ));
        assert_eq!(
            repo.edges("caller.js")[0].import_source.as_deref(),
            Some("external-two")
        );
        assert_eq!(repo.edges("other.js"), vec![other.clone()]);
        assert_eq!(
            repo.graph.get_entity(&target.id).unwrap(),
            Some(target.clone())
        );
        repo.reopen();
        repo.edit("caller.js", NONE);
        assert!(repo.edges("caller.js").is_empty());
        assert_eq!(repo.edges("other.js"), vec![other]);
        repo.edit("other.js", NONE);
        repo.reopen();
        assert_eq!(
            repo.graph.get_entity(&target.id).unwrap(),
            Some(target),
            "orphan target records are retained"
        );
    }
}

#[test]
fn full_edit_replaces_occurrence_count_and_preserves_stable_relation_identity() {
    let mut repo = Repo::new();
    repo.edit("caller.js", ONE);
    let original = repo.edges("caller.js")[0].clone();
    let twice = ONE.replace("return remote();", "remote(); return remote();");
    repo.edit("caller.js", &twice);
    let changed = repo.edges("caller.js")[0].clone();
    assert_eq!(original.id, changed.id);
    assert_eq!(changed.evidence[0].occurrence_count, 2);
    repo.reopen();
    repo.edit("caller.js", &format!("// shifted\n{ONE}"));
    let shifted = repo.edges("caller.js")[0].clone();
    assert_eq!(original.id, shifted.id);
    assert_eq!(shifted.evidence[0].occurrence_count, 1);
}

#[test]
fn occupied_external_target_identity_refuses_without_changing_source_or_edges() {
    let mut repo = Repo::new();
    let proposed = repo.plan("caller.js", ONE).unwrap();
    let mut target = proposed
        .delta
        .entity_deltas
        .iter()
        .find_map(|delta| match delta {
            EntityDelta::Added { new } if kin_index::is_external_reference_target(new) => {
                Some(new.clone())
            }
            _ => None,
        })
        .unwrap();
    target.name = "unrelated".into();
    repo.graph.upsert_entity(&target).unwrap();
    let error = repo.plan("caller.js", ONE).unwrap_err().to_string();
    assert!(error.contains("identity collision"), "{error}");
    assert_eq!(repo.graph.list_all_entities().unwrap(), vec![target]);
}

#[test]
fn malformed_stored_external_proof_refuses_and_preserves_the_graph() {
    let mut repo = Repo::new();
    repo.edit("caller.js", ONE);
    let mut edge = repo.edges("caller.js")[0].clone();
    edge.evidence[0].occurrence_count = 0;
    repo.graph.upsert_relation(&edge).unwrap();
    let error = repo.plan("caller.js", NONE).unwrap_err().to_string();
    assert!(error.contains("malformed stored external proof"), "{error}");
    assert!(repo
        .graph
        .get_all_relations_for_entity(&repo.source("caller.js").id)
        .unwrap()
        .contains(&edge));
}

#[test]
fn absent_or_wrong_old_blob_cannot_authorize_retirement_from_a_same_name() {
    for wrong in [false, true] {
        let mut repo = Repo::new();
        repo.edit("caller.js", ONE);
        let edge = repo.edges("caller.js")[0].clone();
        let mut source = repo.source("caller.js");
        if wrong {
            let hash = repo.blobs.write(NONE.as_bytes()).unwrap();
            source.metadata.extra.insert(
                "blob_hash".into(),
                serde_json::Value::String(hash.to_string()),
            );
        } else {
            source.metadata.extra.remove("blob_hash");
        }
        repo.graph.upsert_entity(&source).unwrap();
        assert!(repo.plan("caller.js", TWO).is_err());
        assert_eq!(repo.edges("caller.js"), vec![edge]);
    }
}

#[test]
fn incomplete_edit_retains_last_known_external_evidence_until_valid_recovery() {
    let mut repo = Repo::new();
    repo.edit("caller.js", ONE);
    let original = repo.edges("caller.js")[0].clone();
    let result = repo
        .plan(
            "caller.js",
            "const remote = require('external-two');\nfunction run( {",
        )
        .unwrap();
    assert!(matches!(
        result.outcome,
        ReconcileOutcome::BrokenAst { .. } | ReconcileOutcome::PartiallyUpdated { .. }
    ));
    repo.graph.apply_transaction_delta(&result.delta).unwrap();
    assert_eq!(repo.edges("caller.js"), vec![original]);
    repo.reopen();
    repo.edit("caller.js", TWO);
    assert_eq!(
        repo.edges("caller.js")[0].import_source.as_deref(),
        Some("external-two")
    );
}

#[test]
fn removed_caller_drops_only_its_edges_and_keeps_other_importer() {
    let mut repo = Repo::new();
    repo.edit("caller.js", ONE);
    repo.edit("other.js", ONE);
    let other = repo.edges("other.js")[0].clone();
    let target = repo.target(&other);
    let old_source = repo.source("caller.js").id;
    repo.edit("caller.js", "const value = 1;\n");
    assert!(repo.graph.get_entity(&old_source).unwrap().is_none());
    assert_eq!(repo.edges("other.js"), vec![other]);
    assert_eq!(repo.graph.get_entity(&target.id).unwrap(), Some(target));
}

#[test]
fn changed_bytes_without_exact_tree_admission_cannot_publish_external_evidence() {
    let mut repo = Repo::new();
    repo.edit("caller.js", ONE);
    let old = repo.edges("caller.js")[0].clone();
    let blob = repo.blobs.write(TWO.as_bytes()).unwrap();
    let error = repo
        .plan_admitted("caller.js", TWO, blob)
        .unwrap_err()
        .to_string();
    assert!(error.contains("not the admitted file version"), "{error}");
    assert_eq!(repo.edges("caller.js"), vec![old]);
}

#[test]
fn occupied_relation_identity_is_not_overwritten_with_external_evidence() {
    let mut repo = Repo::new();
    repo.edit("caller.js", ONE);
    let mut held = repo.edges("caller.js")[0].clone();
    held.origin = kin_model::RelationOrigin::Manual;
    held.evidence.clear();
    repo.graph.upsert_relation(&held).unwrap();
    let error = repo.plan("caller.js", ONE).unwrap_err().to_string();
    assert!(error.contains("occupied by other evidence"), "{error}");
    assert!(repo
        .graph
        .get_all_relations_for_entity(&repo.source("caller.js").id)
        .unwrap()
        .contains(&held));
}

const WAITING: &str = "from local import work\n\ndef run():\n    return work()\n";
const LOCAL: &str = "def work():\n    return 1\n";

#[test]
fn arriving_local_definition_atomically_retires_only_its_proven_external_edge() {
    let mut repo = Repo::new();
    let two_imports = "from local import work\nfrom another_external import other\n\ndef run():\n    return work() + other()\n";
    repo.edit("caller.py", two_imports);
    repo.edit("unrelated.py", WAITING);
    let old = repo.edges("caller.py");
    assert_eq!(old.len(), 2);
    let removed = old
        .iter()
        .find(|edge| edge.import_source.as_deref() == Some("local"))
        .unwrap();
    let retained = old
        .iter()
        .find(|edge| edge.import_source.as_deref() == Some("another_external"))
        .unwrap();
    let orphan = repo.target(removed);
    let result = repo.plan("local.py", LOCAL).unwrap();
    assert_eq!(repo.edges("caller.py"), old);
    assert!(!repo
        .graph
        .list_all_entities()
        .unwrap()
        .iter()
        .any(|entity| entity.name == "work"
            && entity
                .file_origin
                .as_ref()
                .is_some_and(|file| file.0 == "local.py")));
    assert!(result
        .delta
        .relation_deltas
        .iter()
        .any(|delta| matches!(delta, RelationDelta::Removed { old } if old.id == removed.id)));
    repo.graph.apply_transaction_delta(&result.delta).unwrap();
    assert_eq!(repo.edges("caller.py"), vec![retained.clone()]);
    assert!(repo.edges("unrelated.py").is_empty());
    assert_eq!(repo.outgoing_calls("caller.py").len(), 2);
    assert_eq!(repo.outgoing_calls("unrelated.py").len(), 1);
    assert_eq!(repo.graph.get_entity(&orphan.id).unwrap(), Some(orphan));
    let again = repo.edit("local.py", LOCAL);
    assert!(!again
        .relation_deltas
        .iter()
        .any(|delta| matches!(delta, RelationDelta::Removed { old } if old.id == removed.id)));
    repo.reopen();
    assert_eq!(repo.edges("caller.py"), vec![retained.clone()]);
    assert_eq!(repo.outgoing_calls("caller.py").len(), 2);
}

#[test]
fn invalid_waiting_source_refuses_whole_replacement_and_same_linker_can_retry() {
    for missing in [false, true] {
        let mut repo = Repo::new();
        repo.edit("caller.py", WAITING);
        let old = repo.edges("caller.py")[0].clone();
        let original = repo.source("caller.py");
        let mut invalid = original.clone();
        if missing {
            invalid.metadata.extra.remove("blob_hash");
        } else {
            let wrong = repo.blobs.write(b"def run():\n    return 0\n").unwrap();
            invalid.metadata.extra.insert(
                "blob_hash".into(),
                serde_json::Value::String(wrong.to_string()),
            );
        }
        repo.graph.upsert_entity(&invalid).unwrap();
        let error = repo.plan("local.py", LOCAL).unwrap_err().to_string();
        assert!(
            error.contains("metadata differs from its admitted blob"),
            "{error}"
        );
        assert_eq!(repo.edges("caller.py"), vec![old.clone()]);
        assert_eq!(repo.outgoing_calls("caller.py"), vec![old.clone()]);
        assert!(!repo
            .graph
            .list_all_entities()
            .unwrap()
            .iter()
            .any(|entity| entity.name == "work"
                && entity
                    .file_origin
                    .as_ref()
                    .is_some_and(|file| file.0 == "local.py")));
        repo.graph.upsert_entity(&original).unwrap();
        repo.edit("local.py", LOCAL);
        assert!(repo.edges("caller.py").is_empty());
        let calls = repo.outgoing_calls("caller.py");
        assert_eq!(calls.len(), 1);
        assert_eq!(repo.target(&calls[0]).name, "work");
        repo.reopen();
        assert_eq!(repo.outgoing_calls("caller.py"), calls);
    }
}

#[test]
fn caller_refresh_after_local_removal_readmits_boundary_then_recreation_rebinds() {
    let mut repo = Repo::new();
    repo.edit("local.py", LOCAL);
    repo.edit("caller.py", WAITING);
    assert!(repo.edges("caller.py").is_empty());
    assert_eq!(repo.outgoing_calls("caller.py").len(), 1);
    repo.remove("local.py");
    assert!(repo.outgoing_calls("caller.py").is_empty());
    repo.reopen();
    // Existing restart/deletion logic does not rebuild waiting sources. This
    // control deliberately refreshes the caller to prove only that recovery.
    repo.edit("caller.py", WAITING);
    assert_eq!(repo.edges("caller.py").len(), 1);
    repo.edit("local.py", LOCAL);
    assert!(repo.edges("caller.py").is_empty());
    let calls = repo.outgoing_calls("caller.py");
    assert_eq!(calls.len(), 1);
    assert_eq!(repo.target(&calls[0]).name, "work");
    repo.reopen();
    assert_eq!(repo.outgoing_calls("caller.py"), calls);
}

#[test]
fn new_reconciler_lazily_seeds_external_admission_and_old_boundary_retirement() {
    let mut repo = Repo::new();
    repo.reconciler = Reconciler::new(repo.root.path().to_owned());
    repo.edit("caller.js", ONE);
    assert!(repo.reconciler.cross_file_linker().is_seeded());
    assert_eq!(repo.edges("caller.js").len(), 1);
    repo.reconciler = Reconciler::new(repo.root.path().to_owned());
    repo.edit("caller.js", NONE);
    assert!(repo.reconciler.cross_file_linker().is_seeded());
    assert!(repo.edges("caller.js").is_empty());
}

#[test]
fn new_reconciler_seeds_known_local_import_instead_of_inventing_an_external_target() {
    let mut repo = Repo::new();
    repo.edit("local.py", LOCAL);
    repo.reconciler = Reconciler::new(repo.root.path().to_owned());
    repo.edit("caller.py", WAITING);
    assert!(repo.edges("caller.py").is_empty());
    let calls = repo.outgoing_calls("caller.py");
    assert_eq!(calls.len(), 1);
    assert_eq!(
        repo.target(&calls[0]).file_origin,
        Some(FilePathId::new("local.py"))
    );
    repo.reopen();
    assert_eq!(repo.outgoing_calls("caller.py"), calls);
}

#[test]
fn lazy_seed_cannot_authorize_an_unadmitted_source() {
    let mut repo = Repo::new();
    repo.reconciler = Reconciler::new(repo.root.path().to_owned());
    let blob = repo.blobs.write(ONE.as_bytes()).unwrap();
    let error = repo
        .plan_admitted("caller.js", ONE, blob)
        .unwrap_err()
        .to_string();
    assert!(error.contains("no admitted live linker pass"), "{error}");
    assert!(repo.graph.list_all_entities().unwrap().is_empty());
}

#[test]
fn source_without_import_owned_evidence_does_not_require_a_seed() {
    let mut repo = Repo::new();
    repo.reconciler = Reconciler::new(repo.root.path().to_owned());
    repo.edit("caller.js", NONE);
    assert!(!repo.reconciler.cross_file_linker().is_seeded());
    assert!(repo.edges("caller.js").is_empty());
}

#[test]
fn first_call_to_an_existing_import_adds_only_the_external_target_identity() {
    let mut repo = Repo::new();
    repo.edit(
        "caller.js",
        "const remote = require('external-one');\nfunction run() { return 1; }\n",
    );
    let source = repo.source("caller.js").id;
    assert!(repo.edges("caller.js").is_empty());
    repo.reconciler = Reconciler::new(repo.root.path().to_owned());
    let delta = repo.edit("caller.js", ONE);
    assert_eq!(repo.source("caller.js").id, source);
    assert_eq!(repo.edges("caller.js").len(), 1);
    let added: Vec<_> = delta
        .entity_deltas
        .iter()
        .filter_map(|change| match change {
            EntityDelta::Added { new } => Some(new),
            _ => None,
        })
        .collect();
    assert_eq!(added.len(), 1);
    assert!(kin_index::is_external_reference_target(added[0]));
    assert!(added[0].created_in.is_none());
    assert!(!delta
        .entity_deltas
        .iter()
        .any(|change| matches!(change, EntityDelta::Removed { .. })));
}

#[test]
fn failed_destination_plan_keeps_its_boundary_while_another_destination_arrives() {
    let mut repo = Repo::new();
    let caller = "from first import a\nfrom second import b\n\ndef run():\n    return a() + b()\n";
    repo.edit("caller.py", caller);
    let original = repo.source("caller.py");
    let mut invalid = original.clone();
    invalid.metadata.extra.remove("blob_hash");
    repo.graph.upsert_entity(&invalid).unwrap();
    assert!(repo.plan("first.py", "def a():\n    return 1\n").is_err());
    repo.graph.upsert_entity(&original).unwrap();
    let first = repo
        .edges("caller.py")
        .into_iter()
        .find(|edge| edge.import_source.as_deref() == Some("first"))
        .unwrap();
    repo.edit("second.py", "def b():\n    return 2\n");
    assert_eq!(repo.edges("caller.py"), vec![first]);
    assert_eq!(repo.outgoing_calls("caller.py").len(), 2);
    repo.edit("first.py", "def a():\n    return 1\n");
    assert!(repo.edges("caller.py").is_empty());
    assert_eq!(repo.outgoing_calls("caller.py").len(), 2);
}

#[test]
fn rejected_destination_application_cannot_erase_its_boundary_when_another_arrives() {
    let mut repo = Repo::new();
    let caller = "from first import a\nfrom second import b\n\ndef run():\n    return a() + b()\n";
    repo.edit("caller.py", caller);
    let old = repo.edges("caller.py");
    let mut rejected = repo
        .plan("first.py", "def a():\n    return 1\n")
        .unwrap()
        .delta;
    rejected.entity_deltas.clear();
    assert!(repo.graph.apply_transaction_delta(&rejected).is_err());
    assert_eq!(repo.edges("caller.py"), old);
    let error = repo
        .plan("second.py", "def b():\n    return 2\n")
        .unwrap_err()
        .to_string();
    assert!(error.contains("unadmitted cached target"), "{error}");
    assert_eq!(repo.edges("caller.py"), old);
    assert!(!repo
        .graph
        .list_all_entities()
        .unwrap()
        .iter()
        .any(|entity| {
            entity
                .file_origin
                .as_ref()
                .is_some_and(|file| file.0 == "first.py" || file.0 == "second.py")
        }));
    // The failed B plan forgets B; retrying A can then publish its exact delta.
    repo.edit("first.py", "def a():\n    return 1\n");
    repo.edit("second.py", "def b():\n    return 2\n");
    assert!(repo.edges("caller.py").is_empty());
    assert_eq!(repo.outgoing_calls("caller.py").len(), 2);
}

fn named_function(repo: &Repo, file: &str, name: &str) -> Entity {
    let matches: Vec<_> = repo
        .graph
        .list_all_entities()
        .unwrap()
        .into_iter()
        .filter(|entity| {
            entity.name == name
                && entity.kind == kin_model::EntityKind::Function
                && entity
                    .file_origin
                    .as_ref()
                    .is_some_and(|origin| origin.0 == file)
        })
        .collect();
    assert_eq!(matches.len(), 1);
    matches[0].clone()
}

fn named_external_edges(repo: &Repo, file: &str, name: &str) -> Vec<Relation> {
    let id = named_function(repo, file, name).id;
    repo.graph
        .get_all_relations_for_entity(&id)
        .unwrap()
        .into_iter()
        .filter(|edge| {
            edge.src.as_entity() == Some(id) && kin_index::is_external_import_placeholder(edge)
        })
        .collect()
}

#[test]
fn owner_module_and_function_with_same_basename_support_first_use_and_retirement() {
    for cold in [false, true] {
        let mut repo = Repo::new();
        let initial = "const remote = require('external-one');\nfunction shared() { return 1; }\n";
        let first =
            "const remote = require('external-one');\nfunction shared() { return remote(); }\n";
        repo.edit("src/shared.js", initial);
        let source = named_function(&repo, "src/shared.js", "shared");
        assert_eq!(
            repo.graph
                .list_all_entities()
                .unwrap()
                .iter()
                .filter(|entity| entity.name == "shared")
                .count(),
            2,
            "module and function are distinct declarations"
        );
        repo.edit("src/shared.js", first);
        assert_eq!(
            named_function(&repo, "src/shared.js", "shared").id,
            source.id
        );
        let old = named_external_edges(&repo, "src/shared.js", "shared")[0].clone();
        let target = repo.target(&old);
        if cold {
            repo.reopen();
        }
        let delta = repo.edit(
            "src/shared.js",
            &first.replace("external-one", "external-two"),
        );
        assert!(delta.relation_deltas.iter().any(
            |change| matches!(change, RelationDelta::Removed { old: edge } if edge.id == old.id)
        ));
        let edges = named_external_edges(&repo, "src/shared.js", "shared");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].import_source.as_deref(), Some("external-two"));
        repo.edit("src/shared.js", initial);
        assert!(named_external_edges(&repo, "src/shared.js", "shared").is_empty());
        assert_eq!(repo.graph.get_entity(&target.id).unwrap(), Some(target));
    }
}

#[test]
fn owner_local_arrival_retires_boundary_from_same_basename_function() {
    let mut repo = Repo::new();
    repo.edit(
        "shared.py",
        "from local import work\n\ndef shared():\n    return work()\n",
    );
    let source = named_function(&repo, "shared.py", "shared");
    let old = named_external_edges(&repo, "shared.py", "shared")[0].clone();
    let delta = repo.edit("local.py", LOCAL);
    assert!(delta
        .relation_deltas
        .iter()
        .any(|change| matches!(change, RelationDelta::Removed { old: edge } if edge.id == old.id)));
    assert!(named_external_edges(&repo, "shared.py", "shared").is_empty());
    let calls: Vec<_> = repo
        .graph
        .get_all_relations_for_entity(&source.id)
        .unwrap()
        .into_iter()
        .filter(|edge| {
            edge.src.as_entity() == Some(source.id) && edge.kind == kin_model::RelationKind::Calls
        })
        .collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        repo.target(&calls[0]).file_origin,
        Some(FilePathId::new("local.py"))
    );
    repo.reopen();
    assert!(repo
        .graph
        .get_all_relations_for_entity(&source.id)
        .unwrap()
        .contains(&calls[0]));
}

#[test]
fn distinct_same_name_call_sites_keep_exact_source_ownership() {
    let mut repo = Repo::new();
    let source = "from external import remote\n\ndef same():\n    return remote()\n\ndef same():\n    return remote()\n";
    repo.edit("caller.py", source);
    let blob = repo.blobs.write(source.as_bytes()).unwrap();
    let indexed = IndexPipeline::new()
        .index_file_content_with_tests(&FilePathId::new("caller.py"), source.as_bytes(), blob)
        .unwrap()
        .indexed_file;
    let owners: Vec<_> = indexed
        .entities
        .iter()
        .filter(|entity| entity.name == "same")
        .collect();
    assert_eq!(owners.len(), 2);
    for reopen in [false, true] {
        if reopen {
            repo.reopen();
        }
        let mut site_lines = Vec::new();
        for owner in &owners {
            let edges: Vec<_> = repo
                .graph
                .get_all_relations_for_entity(&owner.id)
                .unwrap()
                .into_iter()
                .filter(|edge| {
                    edge.src.as_entity() == Some(owner.id)
                        && edge.kind == kin_model::RelationKind::Calls
                })
                .collect();
            assert_eq!(edges.len(), 1);
            assert!(kin_index::is_external_import_placeholder(&edges[0]));
            assert_eq!(edges[0].evidence[0].occurrence_count, 1);
            assert_eq!(repo.target(&edges[0]).name, "remote");
            let raw: Vec<_> = indexed
                .extracted_relations
                .iter()
                .filter(|raw| {
                    raw.dst_name == "remote"
                        && kin_index::relation_source_entity(raw, &indexed.entities)
                            .is_some_and(|source| source.id == owner.id)
                })
                .collect();
            assert_eq!(raw.len(), 1);
            site_lines.push(raw[0].site.as_ref().unwrap().start_line);
        }
        site_lines.sort();
        assert_eq!(site_lines, vec![3, 6]);
    }
}

/// A stored external edge an older parser minted can carry an occurrence count
/// this build's parser does not reproduce from the same bytes. A live edit still
/// refuses to retire it on that proof. A daemon's startup re-derivation of the
/// file retires it and derives the file's edges afresh, because the fresh
/// derivation of the same bytes replaces what the older parser described.
#[test]
fn startup_rederivation_retires_an_external_edge_an_older_parser_counted_differently() {
    let mut repo = Repo::new();
    repo.edit("caller.js", ONE);
    let mut edge = repo.edges("caller.js")[0].clone();
    edge.evidence[0].occurrence_count = 2;
    repo.graph.upsert_relation(&edge).unwrap();

    let error = repo.plan("caller.js", NONE).unwrap_err().to_string();
    assert!(error.contains("unverified import occurrences"), "{error}");
    assert_eq!(
        repo.edges("caller.js"),
        vec![edge.clone()],
        "a refused live edit changes nothing"
    );

    let prepared = Reconciler::prepare_admitted_source_rederivation(
        repo.graph.to_snapshot(),
        &[FilePathId::new("caller.js")],
        &repo.blobs,
    )
    .unwrap();
    assert!(
        !prepared.snapshot().relations.contains_key(&edge.id),
        "the re-derivation retires the edge the fresh parse does not reproduce"
    );
    assert_eq!(
        prepared.external_edges_retired_unreproduced(),
        1,
        "the start counts the edge it retired without an exact recount"
    );
    let run = repo.source("caller.js");
    assert!(
        prepared.snapshot().entities.contains_key(&run.id),
        "the declaration keeps its identity"
    );
}

/// A stored edge whose recorded bytes still recount exactly is retired the way
/// a live edit retires it, and is not counted as one the start could not prove.
#[test]
fn startup_rederivation_counts_only_the_external_edges_it_could_not_recount() {
    let (repo, edge) = startup_with_stored_external_edge();
    let prepared = Reconciler::prepare_admitted_source_rederivation(
        repo.graph.to_snapshot(),
        &[FilePathId::new("caller.js")],
        &repo.blobs,
    )
    .unwrap();
    assert!(!prepared.snapshot().relations.contains_key(&edge.id));
    assert_eq!(prepared.external_edges_retired_unreproduced(), 0);
}

/// Admit the new bytes but leave the old graph payload in place, as startup
/// encounters after an interrupted observation. The valid live plan is not applied.
fn startup_with_stored_external_edge() -> (Repo, Relation) {
    let mut repo = Repo::new();
    repo.edit("caller.js", ONE);
    let edge = repo.edges("caller.js")[0].clone();
    repo.plan("caller.js", NONE).unwrap();
    (repo, edge)
}

fn assert_startup_rejects_stored_external(repo: &Repo, edge: &Relation) {
    let before = repo.graph.to_snapshot();
    let result = Reconciler::prepare_admitted_source_rederivation(
        before.clone(),
        &[FilePathId::new("caller.js")],
        &repo.blobs,
    );
    assert!(
        result.is_err(),
        "startup must refuse unproved retirement of {}",
        edge.id
    );
    assert_eq!(repo.graph.to_snapshot().relations, before.relations);
    assert_eq!(repo.graph.to_snapshot().entities, before.entities);
}

#[test]
fn startup_rederivation_refuses_manual_edge_with_external_parser_label() {
    let (repo, mut edge) = startup_with_stored_external_edge();
    edge.origin = kin_model::RelationOrigin::Manual;
    repo.graph.upsert_relation(&edge).unwrap();
    assert_startup_rejects_stored_external(&repo, &edge);
}

#[test]
fn startup_rederivation_refuses_lsp_edge_with_external_parser_label() {
    let (repo, mut edge) = startup_with_stored_external_edge();
    edge.origin = kin_model::RelationOrigin::Lsp;
    repo.graph.upsert_relation(&edge).unwrap();
    assert_startup_rejects_stored_external(&repo, &edge);
}

#[test]
fn startup_rederivation_refuses_nonfactory_external_relation_identity() {
    let (repo, mut edge) = startup_with_stored_external_edge();
    repo.graph.remove_relation(&edge.id).unwrap();
    edge.id = kin_model::RelationId::new();
    repo.graph.upsert_relation(&edge).unwrap();
    assert_startup_rejects_stored_external(&repo, &edge);
}

#[test]
fn startup_rederivation_refuses_corrupted_external_target() {
    let (repo, edge) = startup_with_stored_external_edge();
    let mut target = repo.target(&edge);
    target.name = "occupied_by_different_target".to_owned();
    repo.graph.upsert_entity(&target).unwrap();
    assert_startup_rejects_stored_external(&repo, &edge);
}

#[test]
fn startup_rederivation_refuses_missing_old_external_source_blob() {
    let (repo, edge) = startup_with_stored_external_edge();
    repo.blobs
        .delete(&kin_blobs::digest(ONE.as_bytes()))
        .unwrap();
    assert_startup_rejects_stored_external(&repo, &edge);
}

#[test]
fn startup_rederivation_refuses_corrupted_old_external_source_blob() {
    let (repo, edge) = startup_with_stored_external_edge();
    let hash = kin_blobs::digest(ONE.as_bytes()).to_string();
    let old_blob = repo.blobs.root().join(&hash[..2]).join(&hash[2..]);
    assert!(old_blob.is_file());
    std::fs::write(old_blob, b"corrupted immutable source").unwrap();
    assert_startup_rejects_stored_external(&repo, &edge);
}

#[test]
fn startup_rederivation_refuses_incomplete_old_external_source_parse() {
    let (repo, edge) = startup_with_stored_external_edge();
    let bytes = b"function {";
    let digest = repo.blobs.write(bytes).unwrap();
    let indexed = IndexPipeline::new()
        .index_file_content_with_tests(&FilePathId::new("caller.js"), bytes, digest)
        .unwrap()
        .indexed_file;
    assert!(!matches!(indexed.parse_state, kin_model::ParseState::Valid));
    let mut source = repo.source("caller.js");
    source
        .metadata
        .extra
        .insert("blob_hash".into(), digest.to_string().into());
    repo.graph.upsert_entity(&source).unwrap();
    assert_startup_rejects_stored_external(&repo, &edge);
}

#[test]
fn startup_rederivation_refuses_nonfactory_edge_even_when_source_is_removed() {
    let (mut repo, mut edge) = startup_with_stored_external_edge();
    repo.plan("caller.js", "").unwrap();
    edge.origin = kin_model::RelationOrigin::Manual;
    repo.graph.upsert_relation(&edge).unwrap();
    assert_startup_rejects_stored_external(&repo, &edge);
}

/// Every external-import edge a file's declarations own.
fn file_external_edges(repo: &Repo, file: &str) -> Vec<Relation> {
    let mut edges = Vec::new();
    for entity in repo.graph.list_all_entities().unwrap() {
        if entity.file_origin.as_ref().map(|origin| origin.0.as_str()) != Some(file) {
            continue;
        }
        for relation in repo.graph.get_all_relations_for_entity(&entity.id).unwrap() {
            if relation.src.as_entity() == Some(entity.id)
                && kin_index::is_external_import_placeholder(&relation)
            {
                edges.push(relation);
            }
        }
    }
    edges.sort_by_key(|relation| relation.id);
    edges
}

fn external_tokens(edges: &[Relation]) -> Vec<String> {
    let mut tokens: Vec<_> = edges
        .iter()
        .filter_map(|edge| edge.evidence[0].token.clone())
        .collect();
    tokens.sort();
    tokens
}

const METHOD_NAMED_LIKE_AN_IMPORT: &str = "use std::env;\n\
\n\
pub fn forward(cmd: &mut std::process::Command) {\n\
    if let Ok(current_exe) = env::current_exe() {\n\
        cmd.env(\"KIN_BINARY_PATH\", current_exe);\n\
    }\n\
}\n";

/// `cmd.env(..)` beside `use std::env;` is `Command::env`, never the `std::env`
/// module. Counted as an occurrence of the import, it minted an external edge
/// whose own proof could not reproduce the count, so the file's first live
/// observation and every edit after it were refused.
#[test]
fn a_method_named_like_an_import_is_not_an_external_reference_and_its_file_admits_edits() {
    let mut repo = Repo::new();
    repo.edit("src/probe.rs", METHOD_NAMED_LIKE_AN_IMPORT);
    assert!(
        !external_tokens(&file_external_edges(&repo, "src/probe.rs")).contains(&"env".to_string()),
        "a receiver call is not a use of the import it shares a name with"
    );
    let edited = format!("{METHOD_NAMED_LIKE_AN_IMPORT}\n// a trailing comment\n");
    repo.edit("src/probe.rs", &edited);
    assert!(
        !external_tokens(&file_external_edges(&repo, "src/probe.rs")).contains(&"env".to_string())
    );
}

/// The same shape inside a test module that reuses the file's imports through
/// `use super::*`, beside an imported free-function call the parser does record.
/// Keep the constant syntax too; this adapter does not emit a constant-use edge.
#[test]
fn a_test_module_reusing_the_file_imports_keeps_its_real_occurrences_and_admits_edits() {
    let source = "use std::env;\n\
use outside::{NOTICE, render};\n\
\n\
pub fn notice() -> &'static str {\n\
    render(NOTICE)\n\
}\n\
\n\
#[cfg(test)]\n\
mod tests {\n\
    use super::*;\n\
\n\
    #[test]\n\
    fn forwards_the_notice() {\n\
        let mut cmd = std::process::Command::new(\"true\");\n\
        cmd.env(\"KIN_NOTICE\", NOTICE);\n\
        assert_eq!(notice(), NOTICE);\n\
    }\n\
}\n";
    let mut repo = Repo::new();
    repo.edit("src/probe.rs", source);
    let tokens = external_tokens(&file_external_edges(&repo, "src/probe.rs"));
    assert!(tokens.contains(&"render".to_string()), "{tokens:?}");
    assert!(!tokens.contains(&"env".to_string()), "{tokens:?}");
    repo.edit(
        "src/probe.rs",
        &format!("{source}\n// a trailing comment\n"),
    );
    let tokens = external_tokens(&file_external_edges(&repo, "src/probe.rs"));
    assert!(tokens.contains(&"render".to_string()), "{tokens:?}");
}

const COUNTED_BOTH: &str = "use std::process::exit;\n\
\n\
pub fn stop(worker: &mut Worker) -> ! {\n\
    worker.exit();\n\
    exit(1)\n\
}\n";
const CALLS_NEITHER: &str = "use std::process::exit;\n\
\n\
pub fn stop(worker: &mut Worker) {\n\
    worker.flush();\n\
}\n";

/// An edge an earlier linker stored counted the receiver call too. The next
/// edit retires it on an exact re-count under that earlier rule. A count that
/// neither rule reproduces from the recorded bytes is still refused.
#[test]
fn a_stored_edge_that_counted_a_receiver_call_is_retired_only_on_an_exact_recount() {
    for (stored, retires) in [(2, true), (3, false)] {
        let mut repo = Repo::new();
        repo.edit("src/probe.rs", COUNTED_BOTH);
        let mut edges = file_external_edges(&repo, "src/probe.rs");
        edges.retain(|edge| edge.evidence[0].token.as_deref() == Some("exit"));
        assert_eq!(edges.len(), 1, "the receiverless exit(1) is one occurrence");
        let mut edge = edges.remove(0);
        assert_eq!(edge.evidence[0].occurrence_count, 1);
        edge.evidence[0].occurrence_count = stored;
        repo.graph.upsert_relation(&edge).unwrap();

        let result = repo.plan("src/probe.rs", CALLS_NEITHER);
        if retires {
            let result = result.unwrap();
            assert!(result.delta.relation_deltas.iter().any(|delta| matches!(
                delta,
                RelationDelta::Removed { old } if old.id == edge.id
            )));
        } else {
            let error = result.unwrap_err().to_string();
            assert!(error.contains("unverified import occurrences"), "{error}");
        }
    }
}

/// The real source file that refused old-store startup combines receiver calls,
/// imported constants in format arguments, and test-module imports. Preserve
/// its actual bytes through initial admission, a saved graph, and a later edit.
#[test]
fn kin_bench_command_source_admits_and_reopens_without_receiver_import_edges() {
    let source = include_str!("../../kin-cli/src/commands/bench.rs");
    let file = "crates/kin-cli/src/commands/bench.rs";
    let mut repo = Repo::new();
    repo.edit(file, source);
    repo.reopen();
    let tokens = external_tokens(&file_external_edges(&repo, file));
    assert!(tokens.contains(&"exit".to_string()), "{tokens:?}");
    assert!(!tokens.contains(&"env".to_string()), "{tokens:?}");
    repo.edit(
        file,
        &format!("{source}\n// edited after reopening the saved graph\n"),
    );
    repo.reopen();
    let tokens = external_tokens(&file_external_edges(&repo, file));
    assert!(tokens.contains(&"exit".to_string()), "{tokens:?}");
    assert!(!tokens.contains(&"env".to_string()), "{tokens:?}");
}

const ANNOTATED_WITH_AN_IMPORTED_TYPE: &str =
    "from requests import Session\n\n\nclass Client:\n    session: Session\n";
const ANNOTATION_REMOVED: &str = "from requests import Session\n\n\nclass Client:\n    pass\n";

/// A Python class-body field annotated with an imported type keeps the field in
/// the edge's receiver and names the import itself, so it is an external
/// reference and not a member call. The live proof counts it: the file admits
/// its first observation and later edits, and dropping the annotation retires
/// the edge on an exact recount of the bytes it was minted from.
#[test]
fn a_python_field_annotation_naming_an_imported_type_keeps_its_external_edge_and_admits_edits() {
    let mut repo = Repo::new();
    repo.edit("client.py", ANNOTATED_WITH_AN_IMPORTED_TYPE);
    let edges = file_external_edges(&repo, "client.py");
    assert_eq!(external_tokens(&edges), vec!["Session".to_string()]);
    assert_eq!(edges[0].kind, kin_model::RelationKind::References);
    assert_eq!(edges[0].import_source.as_deref(), Some("requests"));
    assert_eq!(edges[0].evidence[0].occurrence_count, 1);

    repo.edit(
        "client.py",
        &format!("{ANNOTATED_WITH_AN_IMPORTED_TYPE}\n# a trailing comment\n"),
    );
    let kept: Vec<_> = file_external_edges(&repo, "client.py")
        .iter()
        .map(|edge| edge.id)
        .collect();
    assert_eq!(kept, vec![edges[0].id], "an edit keeps the reference");

    repo.reopen();
    let result = repo.plan("client.py", ANNOTATION_REMOVED).unwrap();
    assert!(result.delta.relation_deltas.iter().any(|delta| matches!(
        delta,
        RelationDelta::Removed { old } if old.id == edges[0].id
    )));
    repo.graph.apply_transaction_delta(&result.delta).unwrap();
    assert!(file_external_edges(&repo, "client.py").is_empty());
}
