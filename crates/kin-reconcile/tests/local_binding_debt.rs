// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_blobs::BlobStore;
use kin_db::{InMemoryGraph, SnapshotManager};
use kin_index::{binding_debt::*, IndexPipeline};
use kin_model::{
    ArtifactId, Entity, EntityStore, FilePathId, Hash256, LocatedEntry, Relation, RelationDelta,
    RelationKind, RepoPath, TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;
use std::sync::Arc;

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

const CALLER: &str = "from local import work\n\ndef run():\n    return work(value=1)\n";
const TARGET: &str = "def work(value):\n    return value\n";

impl Repo {
    fn obligation_relation(&self) -> Option<Relation> {
        let path = RepoPath::from_utf8("caller.py").unwrap();
        let artifact = self.graph.artifact_id_at_path(&path).unwrap();
        self.graph
            .get_all_relations_for_node(&kin_model::GraphNodeId::Artifact(artifact))
            .unwrap()
            .into_iter()
            .find(|relation| relation.id == local_binding_debt_id(artifact))
    }
    fn debt(&self) -> Option<LocalBindingDebt> {
        let file = FilePathId::new("caller.py");
        let path = RepoPath::from_utf8(file.0.clone()).unwrap();
        let artifact = self.graph.artifact_id_at_path(&path).unwrap();
        let Some(TreeEntry::Blob { hash, .. }) = self.graph.get_tree_entry(&file).unwrap() else {
            panic!("source blob");
        };
        let relations = self
            .graph
            .get_all_relations_for_node(&kin_model::GraphNodeId::Artifact(artifact))
            .unwrap();
        inspect_local_binding_debt(&file, artifact, hash, &relations.iter().collect::<Vec<_>>())
            .unwrap()
    }
    fn full_parse_is_independent(&self) {
        let artifact = self
            .graph
            .artifact_id_at_path(&RepoPath::from_utf8("caller.py").unwrap())
            .unwrap();
        let relations = self
            .graph
            .get_all_relations_for_node(&kin_model::GraphNodeId::Artifact(artifact))
            .unwrap();
        assert!(relations
            .iter()
            .any(|relation| kin_index::is_parse_coverage_relation(
                relation,
                "caller.py",
                artifact
            ) && relation
                .evidence
                .iter()
                .any(|e| e.parser_rule.as_deref()
                    == Some(kin_index::CALL_SHAPE_PARSE_COVERAGE_FULL_V1))));
    }
}

fn resolved() -> Repo {
    let mut repo = Repo::new();
    repo.edit("local.py", TARGET);
    repo.edit("caller.py", CALLER);
    assert!(repo.debt().is_none());
    repo
}

#[test]
fn local_binding_debt_survives_reopen_and_distraction_then_real_recreation_clears_it() {
    let mut repo = resolved();
    let source_id = repo.source("caller.py").id;
    repo.remove("local.py");
    let missing = repo.debt().unwrap();
    assert!(missing
        .obligations
        .iter()
        .any(|o| o.retired_relation.kind == RelationKind::Calls));
    repo.full_parse_is_independent();
    repo.reopen();
    assert_eq!(repo.debt(), Some(missing.clone()));
    repo.edit("unrelated.py", TARGET);
    assert_eq!(repo.debt(), Some(missing));
    repo.full_parse_is_independent();
    repo.edit("local.py", TARGET);
    assert!(repo.debt().is_none());
    assert_eq!(repo.source("caller.py").id, source_id);
    repo.reopen();
    assert!(repo.debt().is_none());
}

#[test]
fn recreated_module_missing_member_keeps_obligation_until_member_returns() {
    let mut repo = resolved();
    repo.remove("local.py");
    repo.edit("local.py", "def other():\n    return 1\n");
    assert!(repo.debt().is_some());
    repo.edit("unrelated.py", TARGET);
    assert!(repo.debt().is_some());
    repo.edit("local.py", TARGET);
    assert!(repo.debt().is_none());
}

#[test]
fn separate_removed_targets_clear_only_their_own_obligations() {
    let mut repo = resolved();
    repo.edit("second.py", "def other(value):\n    return value\n");
    repo.edit("caller.py", "from local import work\nfrom second import other\n\ndef run():\n    return work(value=1) + other(value=2)\n");
    repo.remove("local.py");
    repo.remove("second.py");
    let debt = repo.debt().unwrap();
    assert!(debt
        .obligations
        .iter()
        .any(|o| o.target_file.0 == "local.py"));
    assert!(debt
        .obligations
        .iter()
        .any(|o| o.target_file.0 == "second.py"));
    repo.reopen();
    repo.edit("local.py", TARGET);
    let debt = repo.debt().unwrap();
    assert!(debt
        .obligations
        .iter()
        .all(|o| o.target_file.0 == "second.py"));
    repo.edit("second.py", "def other(value):\n    return value\n");
    assert!(repo.debt().is_none());
}

#[test]
fn admitted_source_removing_old_import_and_call_clears_the_obligation() {
    let mut repo = resolved();
    repo.remove("local.py");
    repo.edit("caller.py", "def run():\n    return 1\n");
    assert!(repo.debt().is_none());
    repo.reopen();
    assert!(repo.debt().is_none());
}

#[test]
fn initial_external_import_has_no_prior_local_binding_debt() {
    let mut repo = Repo::new();
    repo.edit(
        "caller.py",
        "from third_party import work\n\ndef run():\n    return work(value=1)\n",
    );
    assert!(repo.debt().is_none());
    repo.full_parse_is_independent();
    repo.reopen();
    assert!(repo.debt().is_none());
}

#[test]
fn canonical_debt_decoder_rejects_wrong_id_marker_digest_and_payload_without_erasure() {
    let mut repo = resolved();
    repo.remove("local.py");
    let relation = repo.obligation_relation().unwrap();
    let file = FilePathId::new("caller.py");
    let artifact = repo
        .graph
        .artifact_id_at_path(&RepoPath::from_utf8(file.0.clone()).unwrap())
        .unwrap();
    let debt = repo.debt().unwrap();
    for variant in 0..5 {
        let mut bad = relation.clone();
        match variant {
            0 => bad.id = kin_model::RelationId::new(),
            1 => bad.evidence[0].parser_rule = None,
            2 => bad.confidence = 0.2,
            3 => bad.evidence[0].token = Some("{}".into()),
            _ => bad.evidence[0].token.as_mut().unwrap().push(' '),
        }
        assert!(
            inspect_local_binding_debt(&file, artifact, debt.observed_source_digest, &[&bad])
                .is_err()
        );
    }
    assert!(inspect_local_binding_debt(
        &file,
        artifact,
        Hash256::from_bytes([0; 32]),
        &[&relation]
    )
    .is_err());
    assert_eq!(repo.obligation_relation(), Some(relation));
}

#[test]
fn failed_dependent_proof_retains_obligation_and_retry_clears_it() {
    let mut repo = resolved();
    repo.remove("local.py");
    let before = repo.obligation_relation().unwrap();
    let source = repo.source("caller.py");
    let mut bad = source.clone();
    bad.metadata.extra.remove("blob_hash");
    repo.graph.upsert_entity(&bad).unwrap();
    assert!(repo.plan("local.py", TARGET).is_err());
    assert_eq!(repo.obligation_relation(), Some(before));
    repo.graph.upsert_entity(&source).unwrap();
    repo.edit("local.py", TARGET);
    assert!(repo.debt().is_none());
}

#[test]
fn alias_spelling_change_does_not_remove_the_same_imported_dependency() {
    let mut repo = Repo::new();
    repo.edit("local.py", TARGET);
    repo.edit(
        "caller.py",
        "from local import work as w\n\ndef run():\n    return w(value=1)\n",
    );
    repo.remove("local.py");
    assert!(repo.debt().is_some());
    repo.edit(
        "caller.py",
        "from local import work as renamed\n\ndef run():\n    return renamed(value=1)\n",
    );
    assert!(
        repo.debt().is_some(),
        "renaming an alias does not discharge the missing binding"
    );
    repo.reopen();
    assert!(repo.debt().is_some());
    repo.edit("local.py", TARGET);
    assert!(repo.debt().is_none());
}

#[test]
fn changed_imported_symbol_with_same_local_alias_removes_only_the_prior_reference() {
    let mut repo = Repo::new();
    repo.edit("local.py", TARGET);
    repo.edit(
        "caller.py",
        "from local import work as w\n\ndef run():\n    return w(value=1)\n",
    );
    repo.remove("local.py");
    repo.edit("local.py", "def other(value):\n    return value + 1\n");
    assert!(repo.debt().is_some());
    repo.edit(
        "caller.py",
        "from local import other as w\n\ndef run():\n    return w(value=1)\n",
    );
    assert!(
        repo.debt().is_none(),
        "the old exported work reference was actually removed"
    );
    repo.reopen();
    assert!(repo.debt().is_none());
}

#[test]
fn changed_import_module_with_same_alias_clears_only_after_old_reference_is_removed() {
    let mut repo = Repo::new();
    repo.edit("local.py", TARGET);
    repo.edit("other.py", TARGET);
    repo.edit(
        "caller.py",
        "from local import work as w\n\ndef run():\n    return w(value=1)\n",
    );
    repo.remove("local.py");
    assert!(repo.debt().is_some());
    repo.edit(
        "caller.py",
        "from other import work as w\n\ndef run():\n    return w(value=1)\n",
    );
    assert!(repo.debt().is_none());
    let calls = repo
        .graph
        .get_all_relations_for_node(&kin_model::GraphNodeId::Entity(repo.source("caller.py").id))
        .unwrap();
    let intended = calls
        .iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .filter_map(|r| r.dst.as_entity())
        .filter_map(|id| repo.graph.get_entity(&id).unwrap())
        .any(|e| e.file_origin == Some(FilePathId::new("other.py")) && e.name == "work");
    assert!(
        intended,
        "the new alias must actually resolve to other.work"
    );
    repo.reopen();
    assert!(repo.debt().is_none());
}

#[test]
fn removing_the_obligated_source_retires_its_fact_with_source_semantics() {
    let mut repo = resolved();
    repo.remove("local.py");
    let debt = repo.obligation_relation().unwrap();
    let result = repo
        .reconciler
        .reconcile_file_change(
            &kin_index::FileEvent::Removed(repo.root.path().join("caller.py")),
            &repo.blobs,
            repo.graph.as_ref(),
        )
        .unwrap();
    assert!(
        result
            .delta
            .relation_deltas
            .iter()
            .any(|change| matches!(change,
        RelationDelta::Removed { old } if old.id == debt.id)),
        "the departing source must withdraw its own obligation atomically"
    );
    repo.graph.apply_transaction_delta(&result.delta).unwrap();
    assert!(repo.obligation_relation().is_none());
}

fn occupy_debt_identity(repo: &mut Repo) -> Relation {
    repo.edit("unrelated.py", "def unrelated():\n    return 0\n");
    let source = repo
        .graph
        .list_all_entities()
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == "unrelated" && entity.kind == kin_model::EntityKind::Function)
        .unwrap();
    let artifact = repo
        .graph
        .artifact_id_at_path(&RepoPath::from_utf8("caller.py").unwrap())
        .unwrap();
    let foreign = Relation {
        id: local_binding_debt_id(artifact),
        kind: RelationKind::References,
        src: kin_model::GraphNodeId::Entity(source.id),
        dst: kin_model::GraphNodeId::Entity(repo.source("caller.py").id),
        confidence: 1.0,
        origin: kin_model::RelationOrigin::Manual,
        created_in: None,
        import_source: None,
        evidence: vec![],
    };
    repo.graph
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas: vec![RelationDelta::Added {
                new: foreign.clone(),
            }],
            ..Default::default()
        })
        .unwrap();
    foreign
}

#[test]
fn direct_target_removal_refuses_foreign_debt_identity_before_publishing() {
    let mut repo = resolved();
    let foreign = occupy_debt_identity(&mut repo);
    let result = repo.reconciler.reconcile_file_change(
        &kin_index::FileEvent::Removed(repo.root.path().join("local.py")),
        &repo.blobs,
        repo.graph.as_ref(),
    );
    assert!(result.is_err());
    assert_eq!(repo.graph.get_relation_by_id(&foreign.id), Some(foreign));
}

#[test]
fn source_revalidation_refuses_foreign_debt_identity_without_erasing_it() {
    let mut repo = resolved();
    let foreign = occupy_debt_identity(&mut repo);
    let blob = kin_blobs::digest(CALLER.as_bytes());
    assert!(repo.plan_admitted("caller.py", CALLER, blob).is_err());
    assert_eq!(repo.graph.get_relation_by_id(&foreign.id), Some(foreign));
}

#[test]
fn exact_lookup_through_reference_retains_foreign_endpoints_and_distinguishes_absence() {
    let mut repo = resolved();
    let foreign = occupy_debt_identity(&mut repo);
    let graph = repo.graph.as_ref();
    assert_eq!(
        <&InMemoryGraph as EntityStore>::lookup_relation_by_id(&graph, &foreign.id).unwrap(),
        kin_model::RelationLookup::Present(foreign)
    );
    assert_eq!(
        <&InMemoryGraph as EntityStore>::lookup_relation_by_id(
            &graph,
            &kin_model::RelationId::new()
        )
        .unwrap(),
        kin_model::RelationLookup::Absent
    );
}

#[test]
fn malformed_owned_debt_with_wrong_id_and_kind_refuses_revalidation() {
    let mut repo = resolved();
    repo.remove("local.py");
    let old = repo.obligation_relation().unwrap();
    let mut bad = old.clone();
    bad.id = kin_model::RelationId::new();
    bad.kind = RelationKind::References;
    repo.graph
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas: vec![
                RelationDelta::Removed { old },
                RelationDelta::Added { new: bad.clone() },
            ],
            ..Default::default()
        })
        .unwrap();
    assert!(
        repo.plan_admitted("caller.py", CALLER, kin_blobs::digest(CALLER.as_bytes()))
            .is_err(),
        "a claimed source-owned obligation with wrong ID and kind must not disappear from the read"
    );
    assert_eq!(repo.graph.get_relation_by_id(&bad.id), Some(bad));
}

#[test]
fn binding_debt_v1_roundtrip_and_v2_moves_preserve_original_occurrences() {
    let mut repo = resolved();
    repo.remove("local.py");
    let relation = repo.obligation_relation().unwrap();
    let file = FilePathId::new("caller.py");
    let artifact = repo
        .graph
        .artifact_id_at_path(&RepoPath::from_utf8("caller.py").unwrap())
        .unwrap();
    let debt = decode_local_binding_debt(&file, artifact, &relation)
        .unwrap()
        .unwrap();
    assert_eq!(
        relation.evidence[0].parser_rule.as_deref(),
        Some(LOCAL_BINDING_DEBT_V1)
    );
    assert!(!relation.evidence[0]
        .token
        .as_ref()
        .unwrap()
        .contains("prior_source_file"));
    let mut rebuilt = build_local_binding_debt(artifact, debt.clone()).unwrap();
    rebuilt.created_in = relation.created_in;
    assert_eq!(
        serde_json::to_vec(&relation).unwrap(),
        serde_json::to_vec(&rebuilt).unwrap()
    );
    let moved = FilePathId::new("nested/renamed.py");
    let new = relocate_local_binding_debt(
        &file,
        &moved,
        artifact,
        debt.observed_source_digest,
        &relation,
    )
    .unwrap()
    .unwrap();
    let parsed = decode_local_binding_debt(&moved, artifact, &new)
        .unwrap()
        .unwrap();
    assert_eq!(new.id, relation.id);
    assert_eq!(new.src, relation.src);
    assert_eq!(new.created_in, relation.created_in);
    assert_eq!(
        new.evidence[0].parser_rule.as_deref(),
        Some(LOCAL_BINDING_DEBT_V2)
    );
    for (before, after) in debt.obligations.iter().zip(&parsed.obligations) {
        assert_eq!(before.retired_relation, after.retired_relation);
        assert_eq!(before.source_digest, after.source_digest);
        assert_eq!(after.prior_source_file.as_ref(), Some(&file));
    }
    let twice = FilePathId::new("third.py");
    let second =
        relocate_local_binding_debt(&moved, &twice, artifact, debt.observed_source_digest, &new)
            .unwrap()
            .unwrap();
    assert_eq!(
        decode_local_binding_debt(&twice, artifact, &second)
            .unwrap()
            .unwrap()
            .obligations,
        parsed.obligations
    );
    assert!(relocate_local_binding_debt(
        &file,
        &moved,
        artifact,
        Hash256::from_bytes([9; 32]),
        &relation
    )
    .is_err());
}

#[test]
fn binding_debt_versions_reject_missing_mixed_and_fabricated_original_locations() {
    let mut repo = resolved();
    repo.remove("local.py");
    let relation = repo.obligation_relation().unwrap();
    let file = FilePathId::new("caller.py");
    let artifact = repo
        .graph
        .artifact_id_at_path(&RepoPath::from_utf8("caller.py").unwrap())
        .unwrap();
    let debt = repo.debt().unwrap();
    let moved = FilePathId::new("renamed.py");
    let v2 = relocate_local_binding_debt(
        &file,
        &moved,
        artifact,
        debt.observed_source_digest,
        &relation,
    )
    .unwrap()
    .unwrap();
    let mut missing = v2.clone();
    let mut payload: serde_json::Value =
        serde_json::from_str(missing.evidence[0].token.as_ref().unwrap()).unwrap();
    payload["obligations"][0]
        .as_object_mut()
        .unwrap()
        .remove("prior_source_file");
    missing.evidence[0].token = Some(serde_json::to_string(&payload).unwrap());
    assert!(decode_local_binding_debt(&moved, artifact, &missing).is_err());
    let mut mislabeled = v2.clone();
    mislabeled.evidence[0].parser_rule = Some(LOCAL_BINDING_DEBT_V1.into());
    assert!(decode_local_binding_debt(&moved, artifact, &mislabeled).is_err());
    let mut unknown = relation.clone();
    unknown.id = kin_model::RelationId::new();
    unknown.evidence[0].parser_rule = Some("local_binding_debt_v999".into());
    assert!(claims_local_binding_debt(&unknown));
    assert!(decode_local_binding_debt(&file, artifact, &unknown).is_err());
    let mut fabricated = decode_local_binding_debt(&moved, artifact, &v2)
        .unwrap()
        .unwrap();
    fabricated.obligations[0].prior_source_file = Some(moved.clone());
    assert!(build_local_binding_debt(artifact, fabricated).is_err());
    assert!(
        inspect_local_binding_debt(&moved, artifact, debt.observed_source_digest, &[&v2, &v2])
            .is_err()
    );
}
