// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_blobs::BlobStore;
use kin_db::{GraphSnapshot, InMemoryGraph, SnapshotManager};
use kin_model::{
    ArtifactId, Entity, EntityStore, FilePathId, GraphNodeId, Hash256, LocatedEntry, Relation,
    RelationDelta, RelationKind, RelationOrigin, RepoPath, TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;

struct Repo {
    root: tempfile::TempDir,
    blobs: BlobStore,
    graph: InMemoryGraph,
    previous: kin_model::graph::ResolvedGraphState,
}

impl Repo {
    fn new(files: &[(&str, &str)]) -> Self {
        let root = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(root.path().join("blobs")).unwrap();
        let mut repo = Self {
            root,
            blobs,
            graph: InMemoryGraph::new(),
            previous: Default::default(),
        };
        for (file, body) in files {
            repo.admit(file, body);
        }
        repo.batch(&files.iter().map(|(file, _)| *file).collect::<Vec<_>>());
        repo
    }

    fn admit(&self, file: &str, body: &str) {
        let blob = self.blobs.write(body.as_bytes()).unwrap();
        self.admit_hash(file, Hash256::from_bytes(blob.0));
    }

    fn admit_hash(&self, file: &str, hash: Hash256) {
        let path = RepoPath::from_utf8(file).unwrap();
        let new = LocatedEntry::new(path.clone(), TreeEntry::blob(hash, false));
        let change = match self.graph.get_tree_entry(&FilePathId::new(file)).unwrap() {
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
    }

    fn plan(&self, files: &[&str]) -> kin_reconcile::Result<GraphSnapshot> {
        Reconciler::reconcile_admitted_source_batch(
            self.graph.to_snapshot(),
            &files
                .iter()
                .map(|file| FilePathId::new(*file))
                .collect::<Vec<_>>(),
            &self.blobs,
            std::slice::from_ref(&self.previous),
        )
    }

    fn batch(&mut self, files: &[&str]) {
        self.graph = InMemoryGraph::from_snapshot(self.plan(files).unwrap()).unwrap();
        let snapshot = self.graph.to_snapshot();
        self.previous = kin_model::graph::ResolvedGraphState {
            entities: snapshot.entities,
            relations: snapshot.relations,
            tree: snapshot.resolved_tree,
            external_references: snapshot.external_references,
            ..Default::default()
        };
    }

    fn entity(&self, name: &str) -> Entity {
        self.graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|e| e.name == name)
            .unwrap()
    }

    fn calls(&self, source: &str, target: &str) -> bool {
        let source = self.entity(source).id;
        let target = self.entity(target).id;
        self.graph.to_snapshot().relations.values().any(|r| {
            r.kind == RelationKind::Calls
                && r.src == GraphNodeId::Entity(source)
                && r.dst == GraphNodeId::Entity(target)
        })
    }

    fn debt(&self, file: &str) -> Option<kin_index::binding_debt::LocalBindingDebt> {
        let source = FilePathId::new(file);
        let artifact = self
            .graph
            .artifact_id_at_path(&RepoPath::from_utf8(file).unwrap())
            .unwrap();
        let Some(TreeEntry::Blob { hash, .. }) = self.graph.get_tree_entry(&source).unwrap() else {
            panic!("admitted source")
        };
        let relations = self
            .graph
            .get_all_relations_for_node(&GraphNodeId::Artifact(artifact))
            .unwrap();
        kin_index::binding_debt::inspect_local_binding_debt(
            &source,
            artifact,
            hash,
            &relations.iter().collect::<Vec<_>>(),
        )
        .unwrap()
    }
}

#[test]
fn a_private_batch_preserves_identities_manual_edges_and_cycles_in_either_path_order() {
    for (a, b) in [("a.py", "z.py"), ("z.py", "a.py")] {
        let am = a.trim_end_matches(".py");
        let bm = b.trim_end_matches(".py");
        let old_a = format!("from {bm} import beta\n\ndef run(value):\n    return beta(value)\n\ndef helper(value):\n    return value\n");
        let old_b =
            format!("from {am} import helper\n\ndef beta(value):\n    return helper(value)\n");
        let mut repo = Repo::new(&[(a, &old_a), (b, &old_b)]);
        assert!(repo.calls("run", "beta"));
        assert!(repo.calls("beta", "helper"));
        let caller = repo.entity("run").id;
        let helper = repo.entity("helper").id;
        let old_target = repo.entity("beta").id;
        let manual = Relation {
            id: kin_model::RelationId::new(),
            src: GraphNodeId::Entity(caller),
            dst: GraphNodeId::Entity(helper),
            kind: RelationKind::Calls,
            origin: RelationOrigin::Manual,
            confidence: 1.0,
            evidence: vec![],
            created_in: None,
            import_source: None,
        };
        repo.graph
            .apply_transaction_delta(&TransactionDelta {
                relation_deltas: vec![RelationDelta::Added {
                    new: manual.clone(),
                }],
                ..Default::default()
            })
            .unwrap();
        repo.admit(a, &format!("from {bm} import gamma\n\ndef run(value):\n    return gamma(value) + 3\n\ndef helper(value):\n    return value + 4\n"));
        repo.admit(
            b,
            &format!(
                "from {am} import helper\n\ndef gamma(value):\n    return helper(value) * 2\n"
            ),
        );
        repo.batch(&[b, a]);
        assert_eq!(repo.entity("run").id, caller);
        assert_eq!(repo.entity("helper").id, helper);
        assert!(repo.graph.get_entity(&old_target).unwrap().is_none());
        assert!(repo.calls("run", "gamma"));
        assert!(repo.calls("gamma", "helper"));
        assert_eq!(
            repo.graph.to_snapshot().relations.get(&manual.id),
            Some(&manual)
        );
        let snapshot = repo.root.path().join("cold.kindb");
        SnapshotManager::save_graph(&snapshot, &repo.graph).unwrap();
        let cold = SnapshotManager::open_without_text_index(&snapshot).unwrap();
        assert_eq!(
            cold.graph().to_snapshot().relations,
            repo.graph.to_snapshot().relations
        );
    }
}

#[test]
fn removing_one_declaration_records_the_unchanged_callers_lost_binding() {
    let mut repo = Repo::new(&[
        ("b.py", "def beta(value):\n    return value\n"),
        (
            "c.py",
            "from b import beta\n\ndef run(value):\n    return beta(value)\n",
        ),
    ]);
    assert!(repo.calls("run", "beta"));
    let source_id = repo.entity("run").id;
    repo.admit("b.py", "def gamma(value):\n    return value * 2\n");
    repo.batch(&["b.py"]);
    assert_eq!(repo.entity("run").id, source_id);
    let source = FilePathId::new("c.py");
    let artifact = repo
        .graph
        .artifact_id_at_path(&RepoPath::from_utf8("c.py").unwrap())
        .unwrap();
    let Some(TreeEntry::Blob { hash, .. }) = repo.graph.get_tree_entry(&source).unwrap() else {
        panic!("admitted source")
    };
    let relations = repo
        .graph
        .get_all_relations_for_node(&GraphNodeId::Artifact(artifact))
        .unwrap();
    let debt = kin_index::binding_debt::inspect_local_binding_debt(
        &source,
        artifact,
        hash,
        &relations.iter().collect::<Vec<_>>(),
    )
    .unwrap()
    .expect("retiring a declaration must not silently erase the old caller binding");
    assert!(debt
        .obligations
        .iter()
        .any(|o| o.retired_relation.kind == RelationKind::Calls && o.target_file.0 == "b.py"));
}

#[test]
fn authored_callers_keep_prior_debt_in_either_order_until_occurrence_removal_or_real_rebinding() {
    for (source, target) in [("a.py", "z.py"), ("z.py", "a.py")] {
        for remove_occurrence in [false, true] {
            let module = target.trim_end_matches(".py");
            let caller =
                format!("from {module} import beta\n\ndef run(value):\n    return beta(value)\n");
            let mut repo = Repo::new(&[
                (target, "def beta(value):\n    return value\n"),
                (source, &caller),
            ]);
            let prior_call = repo
                .graph
                .to_snapshot()
                .relations
                .values()
                .find(|r| {
                    r.kind == RelationKind::Calls
                        && r.src.as_entity() == Some(repo.entity("run").id)
                })
                .unwrap()
                .clone();
            let original_digest =
                kin_model::Hash256::from_bytes(repo.blobs.write(caller.as_bytes()).unwrap().0);
            repo.admit(target, "def gamma(value):\n    return value * 2\n");
            repo.admit(
                source,
                &format!(
                    "from {module} import beta\n\ndef run(value):\n    return beta(value) + 1\n"
                ),
            );
            repo.batch(&[source, target]);
            let debt = repo
                .debt(source)
                .expect("edited caller still requires the removed local binding");
            assert!(debt.obligations.iter().any(|o| o.retired_relation == prior_call
                && o.source_digest == original_digest), "immutable predecessor call/digest survive the current re-observation");
            let path = repo.root.path().join("debt.kindb");
            SnapshotManager::save_graph(&path, &repo.graph).unwrap();
            let cold = SnapshotManager::open_without_text_index(&path).unwrap();
            repo.graph = InMemoryGraph::from_snapshot(cold.graph().to_snapshot()).unwrap();
            assert_eq!(repo.debt(source), Some(debt));
            if remove_occurrence {
                repo.admit(source, "def run(value):\n    return value + 1\n");
                repo.batch(&[source]);
            } else {
                repo.admit(target, "def beta(value):\n    return value + 3\n");
                repo.batch(&[target]);
                assert!(repo.calls("run", "beta"));
            }
            assert!(repo.debt(source).is_none());
        }
    }
}

/// An obligation minted before import edges carried specifier spans still
/// discharges.
///
/// `held` comes out of the STORE and `old` is re-parsed here and now, so the
/// first reconcile after an upgrade compares an obligation written by the old
/// binary against imports read by the new one. The old binary recorded the
/// whole import statement; the new one records the specifier. Without a
/// statement-span fallback those never match, the obligation is never
/// satisfied, and a caller edited after the upgrade carries binding debt that
/// nothing can clear. This ages the stored obligation back to the statement's
/// span on purpose and asserts the debt still clears.
#[test]
fn an_obligation_recorded_against_the_whole_import_statement_still_discharges() {
    let caller = "from z import beta\n\ndef run(value):\n    return beta(value)\n";
    let mut repo = Repo::new(&[
        ("z.py", "def beta(value):\n    return value\n"),
        ("a.py", caller),
    ]);
    repo.admit("z.py", "def gamma(value):\n    return value * 2\n");
    repo.admit(
        "a.py",
        "from z import beta\n\ndef run(value):\n    return beta(value) + 1\n",
    );
    repo.batch(&["a.py", "z.py"]);
    assert!(
        repo.debt("a.py").is_some(),
        "the edited caller must hold debt before this test can age it"
    );

    // The whole `from z import beta` statement, which is what the store held
    // before an import edge cited its specifier. Derived from the fixture
    // rather than pinned, so editing the source cannot leave it behind.
    let statement = caller.lines().next().expect("the import line");
    let statement_span = kin_model::SourceSpan {
        file: FilePathId::new("a.py"),
        start_byte: 0,
        end_byte: statement.len(),
        start_line: 0,
        start_col: 0,
        end_line: 0,
        end_col: statement.len() as u32,
    };
    age_import_obligations(&mut repo, "a.py", &statement_span);

    repo.admit("z.py", "def beta(value):\n    return value + 3\n");
    repo.batch(&["z.py"]);
    assert!(repo.calls("run", "beta"));
    assert!(
        repo.debt("a.py").is_none(),
        "a rebound caller must clear debt an older binary recorded against the statement"
    );
}

/// Rewrite every `Imports` obligation the store holds for `file` so its
/// evidence names `statement` instead of the specifier, which is the shape a
/// pre-upgrade store carries.
fn age_import_obligations(repo: &mut Repo, file: &str, statement: &kin_model::SourceSpan) {
    let source = FilePathId::new(file);
    let artifact = repo
        .graph
        .artifact_id_at_path(&RepoPath::from_utf8(file).unwrap())
        .unwrap();
    let relations = repo
        .graph
        .get_all_relations_for_node(&GraphNodeId::Artifact(artifact))
        .unwrap();
    let (record, mut debt) = relations
        .iter()
        .find_map(|relation| {
            kin_index::binding_debt::decode_local_binding_debt(&source, artifact, relation)
                .unwrap()
                .map(|debt| (relation.clone(), debt))
        })
        .expect("a binding debt record to age");
    let mut aged = 0_usize;
    for obligation in &mut debt.obligations {
        if obligation.retired_relation.kind != RelationKind::Imports {
            continue;
        }
        for evidence in &mut obligation.retired_relation.evidence {
            if evidence.source_span.is_some() {
                evidence.source_span = Some(statement.clone());
                aged += 1;
            }
        }
    }
    assert!(
        aged > 0,
        "the fixture must hold an import obligation with a span, or it ages nothing"
    );
    let rebuilt = kin_index::binding_debt::build_local_binding_debt(artifact, debt).unwrap();
    assert_eq!(rebuilt.id, record.id, "the debt record keeps its identity");
    repo.graph.upsert_relation(&rebuilt).unwrap();
    let snapshot = repo.graph.to_snapshot();
    repo.previous.relations = snapshot.relations;
}

#[test]
fn missing_or_mismatched_predecessors_cannot_authorize_a_withdrawn_binding() {
    for missing in [false, true] {
        let mut repo = Repo::new(&[
            ("b.py", "def beta(value):\n    return value\n"),
            (
                "c.py",
                "from b import beta\n\ndef run(value):\n    return beta(value)\n",
            ),
        ]);
        repo.admit("b.py", "def gamma(value):\n    return value * 2\n");
        if missing {
            repo.previous.relations.clear();
        } else {
            for entity in repo.previous.entities.values_mut().filter(|entity| {
                entity
                    .file_origin
                    .as_ref()
                    .is_some_and(|file| file.0 == "c.py")
            }) {
                entity
                    .metadata
                    .extra
                    .insert("blob_hash".into(), serde_json::json!("wrong"));
            }
        }
        let before = repo.graph.to_snapshot();
        assert!(repo.plan(&["b.py"]).is_err());
        assert_eq!(before.entities, repo.graph.to_snapshot().entities);
        assert_eq!(before.relations, repo.graph.to_snapshot().relations);
    }
}

#[test]
fn replacing_the_callers_identity_does_not_erase_its_files_old_binding() {
    let mut repo = Repo::new(&[
        ("b.py", "def beta(value):\n    return value\n"),
        (
            "c.py",
            "from b import beta\n\ndef run(value):\n    return beta(value)\n",
        ),
    ]);
    let old = repo.entity("run").id;
    repo.admit("b.py", "def gamma(value):\n    return value * 2\n");
    repo.admit("c.py", "from b import beta\n\nclass NewOwner:\n    def renamed(self, other):\n        changed = beta(other)\n        return changed + 17\n");
    repo.batch(&["b.py", "c.py"]);
    assert!(
        repo.graph.get_entity(&old).unwrap().is_none(),
        "this control must replace the source identity"
    );
    assert!(
        repo.debt("c.py").is_some(),
        "the file still calls the removed beta"
    );
}

#[test]
fn composed_call_spans_use_the_exact_predecessor_selected_by_source_body() {
    let mut repo = Repo::new(&[
        ("b.py", "def beta(value):\n    return value\n"),
        (
            "c.py",
            "from b import beta\n\ndef run(value):\n    return beta(value)\n",
        ),
    ]);
    let mut snapshot = repo.graph.to_snapshot();
    let held = snapshot
        .relations
        .values_mut()
        .find(|relation| relation.kind == RelationKind::Calls)
        .unwrap();
    for evidence in &mut held.evidence {
        if let Some(span) = &mut evidence.source_span {
            span.start_line += 7;
            span.end_line += 7;
        }
    }
    let original = repo.previous.relations[&held.id].clone();
    assert_ne!(
        *held, original,
        "composition control must change the recorded span"
    );
    repo.graph = InMemoryGraph::from_snapshot(snapshot).unwrap();
    repo.admit("b.py", "def gamma(value):\n    return value * 2\n");
    repo.batch(&["b.py"]);
    assert!(repo
        .debt("c.py")
        .unwrap()
        .obligations
        .iter()
        .any(|obligation| obligation.retired_relation == original));
}

#[test]
fn replacing_a_target_with_non_source_bytes_keeps_the_surviving_callers_debt() {
    let mut repo = Repo::new(&[
        ("b.py", "def beta(value):\n    return value\n"),
        (
            "c.py",
            "from b import beta\n\ndef run(value):\n    return beta(value)\n",
        ),
    ]);
    let blob = repo.blobs.write(&[0, 255, 0, 255]).unwrap();
    repo.admit_hash("b.py", Hash256::from_bytes(blob.0));
    repo.batch(&["b.py"]);
    assert!(!repo
        .graph
        .list_all_entities()
        .unwrap()
        .iter()
        .any(|entity| entity
            .file_origin
            .as_ref()
            .is_some_and(|file| file.0 == "b.py")));
    assert!(repo.debt("c.py").is_some());
}

#[test]
fn invalid_missing_and_unlisted_stale_sources_cannot_escape_the_private_candidate() {
    for control in ["invalid", "missing", "unlisted-stale", "duplicate"] {
        let repo = Repo::new(&[
            ("b.py", "def beta(value):\n    return value\n"),
            (
                "a.py",
                "from b import beta\n\ndef run(value):\n    return beta(value)\n",
            ),
        ]);
        match control {
            "invalid" => repo.admit("a.py", "def run(\n"),
            "missing" => repo.admit_hash("a.py", Hash256::from_bytes([17; 32])),
            "unlisted-stale" => repo.admit("b.py", "def beta(value):\n    return value + 7\n"),
            "duplicate" => {}
            _ => unreachable!(),
        }
        let before = repo.graph.to_snapshot();
        let files = if control == "duplicate" {
            vec!["a.py", "a.py"]
        } else {
            vec!["a.py"]
        };
        assert!(repo.plan(&files).is_err(), "{control} must refuse");
        let after = repo.graph.to_snapshot();
        assert_eq!(before.entities, after.entities);
        assert_eq!(before.relations, after.relations);
        assert_eq!(before.resolved_tree, after.resolved_tree);
    }
}

/// A daemon's startup re-derivation has one observation from before it: the
/// store as it loaded it. A caller that store certifies keeps the record of the
/// binding the re-derivation withdrew. A caller whose own derivation is stale,
/// because its bytes moved without a parse, has nothing to ground a record in,
/// so its binding is dropped and counted rather than refusing the whole batch.
#[test]
fn a_startup_rederivation_keeps_certified_callers_records_and_counts_stale_ones() {
    let repo = Repo::new(&[
        ("b.py", "def beta(value):\n    return value\n"),
        (
            "c.py",
            "from b import beta\n\ndef run(value):\n    return beta(value)\n",
        ),
        (
            "d.py",
            "from b import beta\n\ndef keep(value):\n    return beta(value)\n",
        ),
    ]);
    repo.admit("b.py", "def gamma(value):\n    return value * 2\n");
    repo.admit("d.py", "def keep(value):\n    return value\n");
    let files = [FilePathId::new("b.py"), FilePathId::new("d.py")];

    assert!(
        Reconciler::prepare_admitted_source_batch(
            repo.graph.to_snapshot(),
            &files,
            &repo.blobs,
            &[]
        )
        .is_err(),
        "without a predecessor an ordinary batch still refuses a withdrawn binding"
    );

    let prepared = Reconciler::prepare_admitted_source_rederivation(
        repo.graph.to_snapshot(),
        &files,
        &repo.blobs,
    )
    .unwrap();
    assert!(
        prepared.withdrawn_bindings_unrecorded() > 0,
        "the stale caller's binding is dropped and counted"
    );
    let graph = InMemoryGraph::from_snapshot(prepared.snapshot().clone()).unwrap();
    let source = FilePathId::new("c.py");
    let artifact = graph
        .artifact_id_at_path(&RepoPath::from_utf8("c.py").unwrap())
        .unwrap();
    let Some(TreeEntry::Blob { hash, .. }) = graph.get_tree_entry(&source).unwrap() else {
        panic!("admitted source")
    };
    let relations = graph
        .get_all_relations_for_node(&GraphNodeId::Artifact(artifact))
        .unwrap();
    let debt = kin_index::binding_debt::inspect_local_binding_debt(
        &source,
        artifact,
        hash,
        &relations.iter().collect::<Vec<_>>(),
    )
    .unwrap()
    .expect("the certified caller keeps the record that it still calls the retired name");
    assert!(debt
        .obligations
        .iter()
        .any(|o| o.retired_relation.kind == RelationKind::Calls && o.target_file.0 == "b.py"));
}

fn semantic_delta(before: &GraphSnapshot, after: &GraphSnapshot) -> TransactionDelta {
    use kin_model::{EntityDelta, ExternalReferenceDelta};
    let mut delta = TransactionDelta::default();
    for (id, old) in &before.entities {
        match after.entities.get(id) {
            None => delta
                .entity_deltas
                .push(EntityDelta::Removed { old: old.clone() }),
            Some(new) if new != old => delta.entity_deltas.push(EntityDelta::Modified {
                old: old.clone(),
                new: new.clone(),
            }),
            _ => {}
        }
    }
    for (id, new) in &after.entities {
        if !before.entities.contains_key(id) {
            delta
                .entity_deltas
                .push(EntityDelta::Added { new: new.clone() });
        }
    }
    for (id, old) in &before.relations {
        match after.relations.get(id) {
            None => delta
                .relation_deltas
                .push(RelationDelta::Removed { old: old.clone() }),
            Some(new) if new != old => delta.relation_deltas.push(RelationDelta::Modified {
                old: old.clone(),
                new: new.clone(),
            }),
            _ => {}
        }
    }
    for (id, new) in &after.relations {
        if !before.relations.contains_key(id) {
            delta
                .relation_deltas
                .push(RelationDelta::Added { new: new.clone() });
        }
    }
    for (id, old) in &before.external_references {
        match after.external_references.get(id) {
            None => delta
                .external_reference_deltas
                .push(ExternalReferenceDelta::Removed { old: old.clone() }),
            Some(new) => assert_eq!(old, new, "external reference identity is immutable"),
        }
    }
    for (id, new) in &after.external_references {
        if !before.external_references.contains_key(id) {
            delta
                .external_reference_deltas
                .push(ExternalReferenceDelta::Added { new: new.clone() });
        }
    }
    delta
}

// New live-adoption controls distinguish a same-named module from its function.
fn function(repo: &Repo, file: &str, name: &str) -> Entity {
    let matches: Vec<_> = repo
        .graph
        .list_all_entities()
        .unwrap()
        .into_iter()
        .filter(|entity| {
            entity.kind == kin_model::EntityKind::Function
                && entity.file_origin.as_ref() == Some(&FilePathId::new(file))
                && entity.name == name
        })
        .collect();
    assert_eq!(matches.len(), 1, "exact function {file}::{name}");
    matches.into_iter().next().unwrap()
}

fn calls_ids(repo: &Repo, source: kin_model::EntityId, target: kin_model::EntityId) -> bool {
    repo.graph.to_snapshot().relations.values().any(|relation| {
        relation.kind == RelationKind::Calls
            && relation.src == GraphNodeId::Entity(source)
            && relation.dst == GraphNodeId::Entity(target)
    })
}

fn prepare(repo: &Repo, files: &[&str]) -> kin_reconcile::PreparedAdmittedSourceBatch {
    Reconciler::prepare_admitted_source_batch(
        repo.graph.to_snapshot(),
        &files
            .iter()
            .map(|file| FilePathId::new(*file))
            .collect::<Vec<_>>(),
        &repo.blobs,
        std::slice::from_ref(&repo.previous),
    )
    .unwrap()
}

fn live_reconciler(repo: &Repo) -> Reconciler {
    let mut live = Reconciler::new(repo.root.path().to_path_buf());
    live.seed_lkg_entities_from_graph(&repo.graph);
    live.seed_cross_file_linker_from_graph(&repo.graph);
    live.restore_cross_file_dependencies(&repo.graph, &repo.blobs)
        .unwrap();
    live.set_traffic_checker(Box::new(ClearBatchTraffic));
    live
}

struct ClearBatchTraffic;
impl kin_reconcile::TrafficChecker for ClearBatchTraffic {
    fn check_collisions(
        &self,
        _: &kin_model::IntentScope,
        _: Option<&kin_model::SessionId>,
    ) -> std::result::Result<kin_reconcile::CollisionCheck, String> {
        Ok(kin_reconcile::CollisionCheck::Clear)
    }
}

#[test]
fn prepared_layout_uses_preserved_ids_and_drives_the_next_real_entity_edit() {
    let repo = Repo::new(&[("work.py", "def work(value):\n    return value\n")]);
    let old = function(&repo, "work.py", "work");
    let body = "# an actual source prepend\n\ndef work(value):\n    return value + 2\n";
    let mut live = live_reconciler(&repo);
    repo.admit("work.py", body);
    let prepared = prepare(&repo, &["work.py"]);
    let source = &prepared.sources()[0];
    assert_eq!(source.content, body.as_bytes());
    assert!(source.layout.regions.iter().any(|region| matches!(region,
        kin_model::SourceRegion::EntityRef { entity_id, .. } if *entity_id == old.id)));
    assert!(prepared.snapshot().entities.contains_key(&old.id));
    let delta = semantic_delta(&repo.graph.to_snapshot(), prepared.snapshot());
    let adoption = live
        .preflight_admitted_source_batch(&prepared, &repo.graph, &delta, &repo.blobs)
        .unwrap();
    assert!(
        live.projection()
            .get_layout(&FilePathId::new("work.py"))
            .is_none(),
        "preflight cannot install projection state"
    );
    repo.graph.apply_transaction_delta(&delta).unwrap();
    live.adopt_admitted_source_batch(adoption);
    let current = repo.graph.get_entity(&old.id).unwrap().unwrap();
    let new_body = b"def work(value):\n    return value + 77".to_vec();
    let mut updated = current.clone();
    updated.signature = "def work(value):".into();
    live.project_transaction_to_files(
        &TransactionDelta {
            entity_deltas: vec![kin_model::EntityDelta::Modified {
                old: current,
                new: updated,
            }],
            ..Default::default()
        },
        &std::collections::HashMap::from([(old.id, new_body.clone())]),
    )
    .unwrap();
    let expected = format!(
        "# an actual source prepend\n\n{}\n",
        String::from_utf8(new_body).unwrap()
    );
    assert_eq!(
        std::fs::read(repo.root.path().join("work.py")).unwrap(),
        expected.as_bytes()
    );
}

struct BatchTraffic {
    blocked: kin_model::IntentScope,
    seen: std::sync::Arc<std::sync::Mutex<Vec<kin_model::IntentScope>>>,
}
impl kin_reconcile::TrafficChecker for BatchTraffic {
    fn check_collisions(
        &self,
        scope: &kin_model::IntentScope,
        _: Option<&kin_model::SessionId>,
    ) -> std::result::Result<kin_reconcile::CollisionCheck, String> {
        self.seen.lock().unwrap().push(scope.clone());
        Ok(if scope == &self.blocked {
            kin_reconcile::CollisionCheck::Blocked {
                conflict: kin_model::IntentConflict::HardCollision,
                blocking_intents: vec![],
            }
        } else {
            kin_reconcile::CollisionCheck::Clear
        })
    }
}

#[test]
fn prepared_batch_checks_unchanged_dependent_scope_before_any_cache_or_graph_change() {
    let repo = Repo::new(&[(
        "caller.py",
        "from b import work\n\ndef run():\n    return work()\n",
    )]);
    let mut live = live_reconciler(&repo);
    let caller = function(&repo, "caller.py", "run");
    let pending = live.cross_file_linker().pending_file_count();
    repo.admit("b.py", "def work():\n    return 2\n");
    let prepared = prepare(&repo, &["b.py"]);
    assert!(
        prepared
            .sources()
            .iter()
            .any(|source| source.file_id.0 == "caller.py"),
        "rederived dependent gets exact current projection"
    );
    let before = repo.graph.to_snapshot();
    let delta = semantic_delta(&before, prepared.snapshot());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
    live.set_traffic_checker(Box::new(BatchTraffic {
        blocked: kin_model::IntentScope::Entity(caller.id),
        seen: seen.clone(),
    }));
    assert!(matches!(
        live.preflight_admitted_source_batch(&prepared, &repo.graph, &delta, &repo.blobs),
        Err(kin_reconcile::ReconcileError::CollisionBlocked { .. })
    ));
    assert!(seen
        .lock()
        .unwrap()
        .contains(&kin_model::IntentScope::Entity(caller.id)));
    assert_eq!(repo.graph.to_snapshot().relations, before.relations);
    assert_eq!(repo.graph.to_snapshot().entities, before.entities);
    assert!(live.projection().file_ids().is_empty());
    assert_eq!(live.cross_file_linker().pending_file_count(), pending);
    assert!(!live.cross_file_linker().knows_file("b.py"));
    assert_eq!(
        live.lkg().get(&caller.id).unwrap().fingerprint,
        caller.fingerprint
    );
}

#[test]
fn prepared_adoption_keeps_dependent_import_cache_current_for_the_next_target_edit() {
    let repo = Repo::new(&[(
        "caller.py",
        "from b import work\n\ndef run():\n    return work()\n",
    )]);
    let mut live = live_reconciler(&repo);
    let caller = function(&repo, "caller.py", "run").id;
    repo.admit("b.py", "def work():\n    return 2\n");
    let prepared = prepare(&repo, &["b.py"]);
    let delta = semantic_delta(&repo.graph.to_snapshot(), prepared.snapshot());
    let adoption = live
        .preflight_admitted_source_batch(&prepared, &repo.graph, &delta, &repo.blobs)
        .unwrap();
    repo.graph.apply_transaction_delta(&delta).unwrap();
    live.adopt_admitted_source_batch(adoption);
    let target = function(&repo, "b.py", "work").id;
    assert!(calls_ids(&repo, caller, target));
    repo.admit("b.py", "def work():\n    return 44\n");
    let hash = repo.blobs.write(b"def work():\n    return 44\n").unwrap();
    let indexed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("b.py"),
            b"def work():\n    return 44\n",
            hash,
        )
        .unwrap()
        .indexed_file;
    let result = live
        .reconcile_indexed_content(&indexed, &repo.blobs, &repo.graph)
        .unwrap();
    repo.graph.apply_transaction_delta(&result.delta).unwrap();
    assert!(
        live.cross_file_linker().last_files_resolved() >= 2,
        "the unchanged imported caller remains nominated"
    );
    assert_eq!(function(&repo, "caller.py", "run").id, caller);
    assert_eq!(function(&repo, "b.py", "work").id, target);
    assert!(calls_ids(&repo, caller, target));
}

#[test]
fn prepared_batch_rejects_stale_graph_wrong_delta_and_missing_cas_before_adoption() {
    for control in [
        "stale-graph",
        "wrong-delta",
        "missing-cas",
        "missing-checker",
    ] {
        let repo = Repo::new(&[("work.py", "def work():\n    return 1\n")]);
        let mut live = live_reconciler(&repo);
        repo.admit("work.py", "def work():\n    return 2\n");
        let prepared = prepare(&repo, &["work.py"]);
        let mut delta = semantic_delta(&repo.graph.to_snapshot(), prepared.snapshot());
        match control {
            "stale-graph" => repo.admit("work.py", "def work():\n    return 3\n"),
            "missing-checker" => live = Reconciler::new(repo.root.path().to_path_buf()),
            "wrong-delta" => delta.entity_deltas.clear(),
            "missing-cas" => {
                repo.blobs
                    .delete(&kin_blobs::Hash256::from_bytes(
                        *prepared.sources()[0].blob_hash.as_bytes(),
                    ))
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let before = repo.graph.to_snapshot();
        assert!(
            live.preflight_admitted_source_batch(&prepared, &repo.graph, &delta, &repo.blobs)
                .is_err(),
            "{control}"
        );
        assert_eq!(repo.graph.to_snapshot().entities, before.entities);
        assert_eq!(repo.graph.to_snapshot().relations, before.relations);
        assert!(live.projection().file_ids().is_empty());
        // A failed preflight does not poison ordinary serving state.
        live.clear_session_id();
    }
}

#[test]
fn prepared_cycles_are_order_independent_and_adopt_exact_current_sources() {
    let repo = Repo::new(&[
        (
            "a.py",
            "from b import beta\n\ndef alpha(n):\n    return beta(n)\n",
        ),
        (
            "b.py",
            "from a import alpha\n\ndef beta(n):\n    return alpha(n)\n",
        ),
    ]);
    let mut live = live_reconciler(&repo);
    repo.admit(
        "a.py",
        "from b import beta\n\ndef alpha(n):\n    return beta(n + 1)\n",
    );
    repo.admit(
        "b.py",
        "from a import alpha\n\ndef beta(n):\n    return alpha(n + 2)\n",
    );
    let forward = prepare(&repo, &["a.py", "b.py"]);
    let reverse = prepare(&repo, &["b.py", "a.py"]);
    assert_eq!(forward.snapshot().entities, reverse.snapshot().entities);
    assert_eq!(forward.snapshot().relations, reverse.snapshot().relations);
    let delta = semantic_delta(&repo.graph.to_snapshot(), forward.snapshot());
    let adoption = live
        .preflight_admitted_source_batch(&forward, &repo.graph, &delta, &repo.blobs)
        .unwrap();
    repo.graph.apply_transaction_delta(&delta).unwrap();
    live.adopt_admitted_source_batch(adoption);
    let alpha = function(&repo, "a.py", "alpha").id;
    let beta = function(&repo, "b.py", "beta").id;
    assert!(calls_ids(&repo, alpha, beta));
    assert!(calls_ids(&repo, beta, alpha));
    for source in forward.sources() {
        assert_eq!(
            live.projection().get_content(&source.file_id),
            Some(source.content.as_slice())
        );
    }
}

#[test]
fn prepared_adoption_preserves_unrelated_partial_lkg_projection_and_pending_observation() {
    let old = "int keep(void) { return missing(); }\n";
    let partial = "int keep(void) { return missing(); }\nint broken(\n";
    let repo = Repo::new(&[
        ("pending.c", old),
        ("good.py", "def good():\n    return 1\n"),
    ]);
    let mut live = live_reconciler(&repo);
    let index = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("pending.c"),
            old.as_bytes(),
            repo.blobs.write(old.as_bytes()).unwrap(),
        )
        .unwrap()
        .indexed_file;
    let initial = live
        .reconcile_indexed_content(&index, &repo.blobs, &repo.graph)
        .unwrap();
    repo.graph.apply_transaction_delta(&initial.delta).unwrap();
    repo.admit("pending.c", partial);
    let index = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("pending.c"),
            partial.as_bytes(),
            repo.blobs.write(partial.as_bytes()).unwrap(),
        )
        .unwrap()
        .indexed_file;
    let partial_result = live
        .reconcile_indexed_observation(&index, &repo.blobs, &repo.graph)
        .unwrap();
    assert!(matches!(
        partial_result.outcome,
        kin_reconcile::ReconcileOutcome::PartiallyUpdated { .. }
    ));
    repo.graph
        .apply_transaction_delta(&partial_result.delta)
        .unwrap();
    let keep = function(&repo, "pending.c", "keep");
    let before_fingerprint = live.lkg().get(&keep.id).unwrap().fingerprint.clone();
    let before_projection = live
        .projection()
        .get_content(&FilePathId::new("pending.c"))
        .unwrap()
        .to_vec();
    let before_pending = live.cross_file_linker().pending_file_count();
    assert!(
        before_pending > 0,
        "a real unresolved source nomination must exist"
    );
    repo.admit("good.py", "def good():\n    return 2\n");
    let prepared = prepare(&repo, &["good.py"]);
    assert!(!prepared
        .sources()
        .iter()
        .any(|source| source.file_id.0 == "pending.c"));
    let delta = semantic_delta(&repo.graph.to_snapshot(), prepared.snapshot());
    let adoption = live
        .preflight_admitted_source_batch(&prepared, &repo.graph, &delta, &repo.blobs)
        .unwrap();
    repo.graph.apply_transaction_delta(&delta).unwrap();
    live.adopt_admitted_source_batch(adoption);
    assert_eq!(
        live.lkg().get(&keep.id).unwrap().fingerprint,
        before_fingerprint
    );
    assert_eq!(
        live.projection().get_content(&FilePathId::new("pending.c")),
        Some(before_projection.as_slice())
    );
    assert_eq!(
        live.cross_file_linker().pending_file_count(),
        before_pending
    );
    assert_eq!(repo.graph.get_entity(&keep.id).unwrap().unwrap(), keep);
}

#[test]
fn prepared_adoption_retains_unchanged_imported_base_alias_for_later_override_resolution() {
    let child = "from base import Base as Alias\n\nclass Child(Alias):\n    def extra(self):\n        return 3\n";
    let repo = Repo::new(&[
        (
            "base.py",
            "class Base:\n    def send(self):\n        return 1\n",
        ),
        ("child.py", child),
        ("good.py", "def good():\n    return 1\n"),
    ]);
    let child_id = repo.entity("Child.extra").id;
    let mut live = live_reconciler(&repo);
    repo.admit("good.py", "def good():\n    return 2\n");
    let prepared = prepare(&repo, &["good.py"]);
    assert!(!prepared
        .sources()
        .iter()
        .any(|source| source.file_id.0 == "child.py"));
    let delta = semantic_delta(&repo.graph.to_snapshot(), prepared.snapshot());
    let adoption = live
        .preflight_admitted_source_batch(&prepared, &repo.graph, &delta, &repo.blobs)
        .unwrap();
    repo.graph.apply_transaction_delta(&delta).unwrap();
    live.adopt_admitted_source_batch(adoption);
    let body = "class Base:\n    def send(self):\n        return 1\n    def extra(self):\n        return 2\n";
    repo.admit("base.py", body);
    let indexed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("base.py"),
            body.as_bytes(),
            repo.blobs.write(body.as_bytes()).unwrap(),
        )
        .unwrap()
        .indexed_file;
    let result = live
        .reconcile_indexed_content(&indexed, &repo.blobs, &repo.graph)
        .unwrap();
    repo.graph.apply_transaction_delta(&result.delta).unwrap();
    let base_id = repo.entity("Base.extra").id;
    assert_eq!(repo.entity("Child.extra").id, child_id);
    assert!(
        repo.graph
            .to_snapshot()
            .relations
            .values()
            .any(|relation| relation.kind == RelationKind::Overrides
                && relation.src == GraphNodeId::Entity(child_id)
                && relation.dst == GraphNodeId::Entity(base_id)),
        "unchanged imported alias must resolve against the newly added base method"
    );
    let child_hash = repo
        .graph
        .get_tree_entry(&FilePathId::new("child.py"))
        .unwrap()
        .unwrap();
    assert_eq!(
        child_hash,
        TreeEntry::blob(
            Hash256::from_bytes(repo.blobs.write(child.as_bytes()).unwrap().0),
            false
        )
    );
}

#[test]
fn prepared_noop_still_checks_every_adopted_entity_reservation() {
    let repo = Repo::new(&[("good.py", "def good():\n    return 1\n")]);
    let mut live = live_reconciler(&repo);
    let prepared = prepare(&repo, &["good.py"]);
    let before = repo.graph.to_snapshot();
    let delta = semantic_delta(&before, prepared.snapshot());
    assert!(delta.entity_deltas.is_empty());
    assert!(delta.relation_deltas.is_empty());
    let entity = function(&repo, "good.py", "good");
    live.set_traffic_checker(Box::new(BatchTraffic {
        blocked: kin_model::IntentScope::Entity(entity.id),
        seen: Default::default(),
    }));
    assert!(matches!(
        live.preflight_admitted_source_batch(&prepared, &repo.graph, &delta, &repo.blobs),
        Err(kin_reconcile::ReconcileError::CollisionBlocked { .. })
    ));
    assert!(live.projection().file_ids().is_empty());
    assert_eq!(repo.graph.to_snapshot().entities, before.entities);
    assert_eq!(repo.graph.to_snapshot().relations, before.relations);
}

// Exercise the committed graph move boundary independently of the daemon's
// projection/cache cleanup. The tree keeps the same artifact; declarations
// keep identity and move their actual location, and the old parse certificate
// is withdrawn just as the ordinary source-move publisher requires.
fn move_admitted_artifact(repo: &mut Repo, from: &str, to: &str) -> ArtifactId {
    let from_file = FilePathId::new(from);
    let to_file = FilePathId::new(to);
    let from_path = RepoPath::from_utf8(from).unwrap();
    let artifact = repo.graph.artifact_id_at_path(&from_path).unwrap();
    let entry = repo.graph.get_tree_entry(&from_file).unwrap().unwrap();
    let entities = repo
        .graph
        .query_entities(&kin_model::EntityFilter {
            file_path: Some(from_file.clone()),
            ..Default::default()
        })
        .unwrap();
    let mut relations: Vec<_> = repo
        .graph
        .get_all_relations_for_node(&GraphNodeId::Artifact(artifact))
        .unwrap()
        .into_iter()
        .filter(|r| kin_index::is_parse_coverage_relation(r, from, artifact))
        .map(|old| RelationDelta::Removed { old })
        .collect();
    kin_reconcile::plan_moved_import_bindings(
        &repo.graph,
        &[(from_file, to_file.clone())],
        &mut relations,
        |hash| {
            repo.blobs
                .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
                .map_err(Into::into)
        },
    )
    .unwrap();
    repo.graph
        .apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Updated {
                artifact_id: artifact,
                old: LocatedEntry::new(from_path, entry.clone()),
                new: LocatedEntry::new(RepoPath::from_utf8(to).unwrap(), entry),
            }],
            entity_deltas: entities
                .into_iter()
                .map(|old| {
                    let mut new = old.clone();
                    new.file_origin = Some(to_file.clone());
                    if let Some(span) = &mut new.span {
                        span.file = to_file.clone();
                    }
                    kin_model::EntityDelta::Modified { old, new }
                })
                .collect(),
            relation_deltas: relations,
            ..Default::default()
        })
        .unwrap();
    let path = repo.root.path().join("admitted-move.kindb");
    SnapshotManager::save_graph(&path, &repo.graph).unwrap();
    let reopened = SnapshotManager::open_without_text_index(&path).unwrap();
    repo.graph = InMemoryGraph::from_snapshot(reopened.graph().to_snapshot()).unwrap();
    assert_eq!(
        repo.graph
            .artifact_id_at_path(&RepoPath::from_utf8(to).unwrap()),
        Some(artifact)
    );
    artifact
}

fn apply_prepared(repo: &Repo, live: &mut Reconciler, files: &[&str]) {
    let prepared = prepare(repo, files);
    let delta = semantic_delta(&repo.graph.to_snapshot(), prepared.snapshot());
    let adoption = live
        .preflight_admitted_source_batch(&prepared, &repo.graph, &delta, &repo.blobs)
        .unwrap();
    repo.graph.apply_transaction_delta(&delta).unwrap();
    live.adopt_admitted_source_batch(adoption);
}

#[test]
fn prepared_moved_artifact_retires_old_cache_and_projection_before_future_caller_edit() {
    let mut repo = Repo::new(&[
        ("old.py", "def work():\n    return 1\n"),
        (
            "caller.py",
            "from new import work\n\ndef run():\n    return work()\n",
        ),
    ]);
    let mut live = live_reconciler(&repo);
    apply_prepared(&repo, &mut live, &["old.py", "caller.py"]);
    let target = function(&repo, "old.py", "work").id;
    let caller = function(&repo, "caller.py", "run").id;
    let artifact = move_admitted_artifact(&mut repo, "old.py", "new.py");
    assert!(live.cross_file_linker().knows_file("old.py"));
    assert!(live
        .projection()
        .get_layout(&FilePathId::new("old.py"))
        .is_some());
    apply_prepared(&repo, &mut live, &["new.py"]);
    assert_eq!(function(&repo, "new.py", "work").id, target);
    assert!(calls_ids(&repo, caller, target));
    assert!(
        !live.cross_file_linker().knows_file("old.py"),
        "moved artifact cannot retain its old module cache"
    );
    assert_eq!(
        live.cross_file_linker()
            .path_of_artifact(&artifact)
            .as_deref(),
        Some("new.py")
    );
    assert!(
        live.projection()
            .get_layout(&FilePathId::new("old.py"))
            .is_none(),
        "old layout cannot remain an editable path"
    );
    assert!(live
        .projection()
        .get_content(&FilePathId::new("old.py"))
        .is_none());
    let current = repo.graph.get_entity(&target).unwrap().unwrap();
    let body = b"def work():\n    return 44".to_vec();
    let authored = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("new.py"),
            &body,
            repo.blobs.write(&body).unwrap(),
        )
        .unwrap()
        .indexed_file;
    let mut updated = current.clone();
    updated.fingerprint = authored
        .entities
        .iter()
        .find(|entity| entity.name == "work" && entity.kind == kin_model::EntityKind::Function)
        .unwrap()
        .fingerprint
        .clone();
    live.project_transaction_to_files(
        &TransactionDelta {
            entity_deltas: vec![kin_model::EntityDelta::Modified {
                old: current,
                new: updated,
            }],
            ..Default::default()
        },
        &std::collections::HashMap::from([(target, body)]),
    )
    .unwrap();
    let actual = std::fs::read(repo.root.path().join("new.py")).unwrap();
    assert_eq!(actual, b"def work():\n    return 44\n");
    assert!(!repo.root.path().join("old.py").exists());
    repo.admit("new.py", std::str::from_utf8(&actual).unwrap());
    let indexed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("new.py"),
            &actual,
            repo.blobs.write(&actual).unwrap(),
        )
        .unwrap()
        .indexed_file;
    let result = live
        .reconcile_indexed_content(&indexed, &repo.blobs, &repo.graph)
        .unwrap();
    repo.graph.apply_transaction_delta(&result.delta).unwrap();
    assert!(live.cross_file_linker().last_files_resolved() >= 2);
    assert_eq!(function(&repo, "caller.py", "run").id, caller);
    assert_eq!(function(&repo, "new.py", "work").id, target);
    assert!(calls_ids(&repo, caller, target));
}

#[test]
fn prepared_moved_artifact_preserves_a_different_artifact_reusing_the_old_path() {
    let mut repo = Repo::new(&[
        ("old.py", "def work():\n    return 1\n"),
        (
            "caller.py",
            "from new import work\n\ndef run():\n    return work()\n",
        ),
    ]);
    let mut live = live_reconciler(&repo);
    apply_prepared(&repo, &mut live, &["old.py", "caller.py"]);
    let target = function(&repo, "old.py", "work").id;
    let moved = move_admitted_artifact(&mut repo, "old.py", "new.py");
    let replacement = "def work():\n    return 99\n";
    repo.admit("old.py", replacement);
    let replacement_artifact = repo
        .graph
        .artifact_id_at_path(&RepoPath::from_utf8("old.py").unwrap())
        .unwrap();
    assert_ne!(moved, replacement_artifact);
    // Sorted preparation installs old.py first; cleanup must not subsequently
    // erase that replacement when it sees the moved artifact's former path.
    apply_prepared(&repo, &mut live, &["old.py", "new.py"]);
    assert_ne!(function(&repo, "old.py", "work").id, target);
    assert_eq!(function(&repo, "new.py", "work").id, target);
    assert_eq!(
        live.cross_file_linker().path_of_artifact(&moved).as_deref(),
        Some("new.py")
    );
    assert_eq!(
        live.cross_file_linker()
            .path_of_artifact(&replacement_artifact)
            .as_deref(),
        Some("old.py")
    );
    assert_eq!(
        live.projection().get_content(&FilePathId::new("old.py")),
        Some(replacement.as_bytes())
    );
    assert!(live
        .projection()
        .get_layout(&FilePathId::new("new.py"))
        .is_some());
    assert!(calls_ids(
        &repo,
        function(&repo, "caller.py", "run").id,
        target
    ));
}

#[test]
fn prepared_moved_artifact_checks_old_path_traffic_and_preserves_unrelated_partial_state() {
    let pending = "int keep(void) { return missing(); }\n";
    let mut repo = Repo::new(&[
        ("old.py", "def work():\n    return 1\n"),
        (
            "caller.py",
            "from new import work\n\ndef run():\n    return work()\n",
        ),
        ("pending.c", pending),
    ]);
    let mut live = live_reconciler(&repo);
    apply_prepared(&repo, &mut live, &["old.py", "caller.py", "pending.c"]);
    let keep = function(&repo, "pending.c", "keep");
    let partial = "int keep(void) { return missing(); }\nint broken(\n";
    repo.admit("pending.c", partial);
    let indexed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("pending.c"),
            partial.as_bytes(),
            repo.blobs.write(partial.as_bytes()).unwrap(),
        )
        .unwrap()
        .indexed_file;
    let result = live
        .reconcile_indexed_observation(&indexed, &repo.blobs, &repo.graph)
        .unwrap();
    assert!(matches!(
        result.outcome,
        kin_reconcile::ReconcileOutcome::PartiallyUpdated { .. }
    ));
    repo.graph.apply_transaction_delta(&result.delta).unwrap();
    let held = live.lkg().get(&keep.id).unwrap().fingerprint.clone();
    let count = live.cross_file_linker().pending_file_count();
    move_admitted_artifact(&mut repo, "old.py", "new.py");
    let prepared = prepare(&repo, &["new.py"]);
    let before = repo.graph.to_snapshot();
    let delta = semantic_delta(&before, prepared.snapshot());
    live.set_traffic_checker(Box::new(BatchTraffic {
        blocked: kin_model::IntentScope::Artifact(FilePathId::new("old.py")),
        seen: Default::default(),
    }));
    assert!(matches!(
        live.preflight_admitted_source_batch(&prepared, &repo.graph, &delta, &repo.blobs),
        Err(kin_reconcile::ReconcileError::CollisionBlocked { .. })
    ));
    assert!(live.cross_file_linker().knows_file("old.py"));
    assert!(live
        .projection()
        .get_layout(&FilePathId::new("old.py"))
        .is_some());
    assert!(live
        .projection()
        .get_layout(&FilePathId::new("new.py"))
        .is_none());
    assert_eq!(repo.graph.to_snapshot().entities, before.entities);
    assert_eq!(repo.graph.to_snapshot().relations, before.relations);
    assert_eq!(live.cross_file_linker().pending_file_count(), count);
    live.set_traffic_checker(Box::new(ClearBatchTraffic));
    apply_prepared(&repo, &mut live, &["new.py"]);
    assert_eq!(live.lkg().get(&keep.id).unwrap().fingerprint, held);
    assert_eq!(
        live.projection().get_content(&FilePathId::new("pending.c")),
        Some(pending.as_bytes())
    );
    assert!(live.cross_file_linker().knows_file("pending.c"));
    assert!(!live.cross_file_linker().knows_file("old.py"));
}

#[test]
fn prepared_moved_artifact_refuses_unobserved_old_path_reuse_then_accepts_checked_retry() {
    let mut repo = Repo::new(&[("old.py", "def work():\n    return 1\n")]);
    let mut live = live_reconciler(&repo);
    apply_prepared(&repo, &mut live, &["old.py"]);
    let artifact = move_admitted_artifact(&mut repo, "old.py", "new.py");
    repo.admit("old.py", "def broken(\n");
    let prepared = prepare(&repo, &["new.py"]);
    let before = repo.graph.to_snapshot();
    let delta = semantic_delta(&before, prepared.snapshot());
    let error = live
        .preflight_admitted_source_batch(&prepared, &repo.graph, &delta, &repo.blobs)
        .err()
        .expect("unobserved replacement refuses");
    assert!(
        error.to_string().contains("checked replacement source"),
        "{error}"
    );
    assert_eq!(repo.graph.to_snapshot().entities, before.entities);
    assert_eq!(repo.graph.to_snapshot().relations, before.relations);
    assert_eq!(
        live.cross_file_linker()
            .path_of_artifact(&artifact)
            .as_deref(),
        Some("old.py")
    );
    assert!(live
        .projection()
        .get_layout(&FilePathId::new("old.py"))
        .is_some());
    repo.admit("old.py", "def replacement():\n    return 9\n");
    apply_prepared(&repo, &mut live, &["new.py", "old.py"]);
    assert_eq!(
        live.cross_file_linker()
            .path_of_artifact(&artifact)
            .as_deref(),
        Some("new.py")
    );
    assert_eq!(
        live.projection().get_content(&FilePathId::new("old.py")),
        Some(b"def replacement():\n    return 9\n".as_slice())
    );
}

#[test]
fn prepared_moved_artifact_preserves_already_observed_partial_replacement_at_old_path() {
    let mut repo = Repo::new(&[
        ("old.py", "def work():\n    return 1\n"),
        (
            "caller.py",
            "from new import work\n\ndef run():\n    return work()\n",
        ),
    ]);
    let mut live = live_reconciler(&repo);
    apply_prepared(&repo, &mut live, &["old.py", "caller.py"]);
    let target = function(&repo, "old.py", "work").id;
    let moved = move_admitted_artifact(&mut repo, "old.py", "new.py");
    let replacement = "def spare():\n    return 7\n";
    repo.admit("old.py", replacement);
    let replacement_artifact = repo
        .graph
        .artifact_id_at_path(&RepoPath::from_utf8("old.py").unwrap())
        .unwrap();
    let indexed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("old.py"),
            replacement.as_bytes(),
            repo.blobs.write(replacement.as_bytes()).unwrap(),
        )
        .unwrap()
        .indexed_file;
    let result = live
        .reconcile_indexed_content(&indexed, &repo.blobs, &repo.graph)
        .unwrap();
    repo.graph.apply_transaction_delta(&result.delta).unwrap();
    let spare = function(&repo, "old.py", "spare");
    assert_ne!(spare.id, target);
    assert_eq!(
        live.cross_file_linker()
            .path_of_artifact(&replacement_artifact)
            .as_deref(),
        Some("old.py")
    );
    assert_eq!(live.cross_file_linker().path_of_artifact(&moved), None);
    let partial = "def spare():\n    return 7\ndef broken(\n";
    repo.admit("old.py", partial);
    let indexed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("old.py"),
            partial.as_bytes(),
            repo.blobs.write(partial.as_bytes()).unwrap(),
        )
        .unwrap()
        .indexed_file;
    let result = live
        .reconcile_indexed_observation(&indexed, &repo.blobs, &repo.graph)
        .unwrap();
    assert!(matches!(
        result.outcome,
        kin_reconcile::ReconcileOutcome::PartiallyUpdated { .. }
    ));
    repo.graph.apply_transaction_delta(&result.delta).unwrap();
    let held = live.lkg().get(&spare.id).unwrap().fingerprint.clone();
    apply_prepared(&repo, &mut live, &["new.py"]);
    assert_eq!(
        live.cross_file_linker().path_of_artifact(&moved).as_deref(),
        Some("new.py")
    );
    assert_eq!(
        live.cross_file_linker()
            .path_of_artifact(&replacement_artifact)
            .as_deref(),
        Some("old.py")
    );
    assert_eq!(
        live.projection().get_content(&FilePathId::new("old.py")),
        Some(replacement.as_bytes())
    );
    assert_eq!(live.lkg().get(&spare.id).unwrap().fingerprint, held);
    assert_eq!(repo.graph.get_entity(&spare.id).unwrap().unwrap(), spare);
    assert!(calls_ids(
        &repo,
        function(&repo, "caller.py", "run").id,
        target
    ));
}
