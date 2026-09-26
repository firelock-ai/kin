// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Re-export dependencies must invalidate unchanged consumers through the
//! admitted live path. Initial parser Calls always come from real source;
//! only explicit provenance and collision controls install injected relations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use kin_blobs::BlobStore;
use kin_db::{InMemoryGraph, SnapshotManager};
use kin_index::{
    binding_debt::inspect_local_binding_debt, binding_debt::LocalBindingDebt, IndexPipeline,
};
use kin_model::{
    ArtifactId, Entity, EntityId, EntityKind, EntityStore, FilePathId, GraphNodeId, Hash256,
    LocatedEntry, Relation, RelationDelta, RelationId, RelationKind, RelationOrigin, RepoPath,
    TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;

const APP: &str = "from pkg import public\ndef run():\n    return public()\n";
const PACKAGE: &str = "from .bridge import forward as public\n";
const OLD_BRIDGE: &str = "from .old_impl import execute as forward\n";
const NEW_BRIDGE: &str = "from .new_impl import execute as forward\n";

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

    fn admit(&mut self, file: &str, source: &str) -> kin_index::IndexedFile {
        let blob = self.blobs.write(source.as_bytes()).unwrap();
        let path = RepoPath::from_utf8(file).unwrap();
        let new = LocatedEntry::new(
            path.clone(),
            TreeEntry::blob(Hash256::from_bytes(blob.0), false),
        );
        let tree_delta = match self.graph.get_tree_entry(&FilePathId::new(file)).unwrap() {
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
                tree_deltas: vec![tree_delta],
                ..Default::default()
            })
            .unwrap();
        IndexPipeline::new()
            .index_file_content_with_tests(&FilePathId::new(file), source.as_bytes(), blob)
            .expect("real source indexing")
            .indexed_file
    }

    fn plan_admitted(
        &mut self,
        indexed: &kin_index::IndexedFile,
    ) -> kin_reconcile::Result<kin_reconcile::ReconcileResult> {
        self.reconciler
            .reconcile_indexed_observation(indexed, &self.blobs, self.graph.as_ref())
    }

    fn apply(&self, result: &kin_reconcile::ReconcileResult) {
        self.graph.apply_transaction_delta(&result.delta).unwrap();
    }

    fn edit(&mut self, file: &str, source: &str) {
        let indexed = self.admit(file, source);
        let result = self
            .plan_admitted(&indexed)
            .expect("real admitted source reconciliation");
        self.apply(&result);
    }

    fn reparse_admitted(&self, file: &str) -> kin_index::IndexedFile {
        let file = FilePathId::new(file);
        let Some(TreeEntry::Blob { hash, .. }) = self.graph.get_tree_entry(&file).unwrap() else {
            panic!("expected current admitted source: {file}");
        };
        let blob = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
        let source = self.blobs.read(&blob).unwrap();
        IndexPipeline::new()
            .index_file_content_with_tests(&file, &source, blob)
            .expect("reparse exact admitted CAS bytes")
            .indexed_file
    }

    /// Canonical admission can retire a target before semantic readmission.
    /// Keep the reconciler alive so the next read must refresh its old universe.
    fn remove_canonically_with_binding_debt(&mut self, file: &str) -> ArtifactId {
        let file_id = FilePathId::new(file);
        let path = RepoPath::from_utf8(file).unwrap();
        let artifact = self.graph.artifact_id_at_path(&path).unwrap();
        let entry = self.graph.get_tree_entry(&file_id).unwrap().unwrap();
        let entities: Vec<_> = self
            .graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .filter(|entity| entity.file_origin.as_ref() == Some(&file_id))
            .collect();
        assert!(!entities.is_empty(), "remove actual admitted declarations");
        let departing = entities.iter().map(|entity| entity.id).collect();
        let mut incident = BTreeMap::new();
        for entity in &entities {
            for relation in self.graph.get_all_relations_for_entity(&entity.id).unwrap() {
                incident.insert(relation.id, relation);
            }
        }
        for relation in self
            .graph
            .get_all_relations_for_node(&GraphNodeId::Artifact(artifact))
            .unwrap()
        {
            incident.insert(relation.id, relation);
        }
        let incident: Vec<_> = incident.into_values().collect();
        let mut relations = kin_reconcile::plan_local_binding_obligations(
            &departing,
            &incident,
            |id| Ok(self.graph.get_entity(&id).unwrap()),
            |file| {
                let path = RepoPath::from_utf8(file.0.clone()).unwrap();
                let Some(artifact) = self.graph.artifact_id_at_path(&path) else {
                    return Ok(None);
                };
                Ok(match self.graph.get_tree_entry(file).unwrap() {
                    Some(TreeEntry::Blob { hash, .. }) => Some((artifact, hash)),
                    _ => None,
                })
            },
            |id| {
                Ok(self
                    .graph
                    .get_all_relations_for_node(&GraphNodeId::Artifact(id))
                    .unwrap())
            },
            |id| Ok(self.graph.get_relation_by_id(&id)),
        )
        .expect("derive debt from the actual prior local bindings before deletion");
        assert!(relations.iter().any(|change| {
            matches!(change, RelationDelta::Added { new }
                if kin_index::binding_debt::claims_local_binding_debt(new))
        }));
        relations.extend(
            incident
                .into_iter()
                .map(|old| RelationDelta::Removed { old }),
        );
        self.graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id: artifact,
                    old: LocatedEntry::new(path, entry),
                }],
                entity_deltas: entities
                    .into_iter()
                    .map(|old| kin_model::EntityDelta::Removed { old })
                    .collect(),
                relation_deltas: relations,
                ..Default::default()
            })
            .expect("atomically publish canonical deletion and retained binding debt");
        artifact
    }

    fn function(&self, file: &str, name: &str) -> Entity {
        self.graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|entity| {
                entity.kind == EntityKind::Function
                    && entity.name == name
                    && entity
                        .file_origin
                        .as_ref()
                        .is_some_and(|origin| origin.0 == file)
            })
            .unwrap_or_else(|| panic!("missing function {file}:{name}"))
    }

    fn calls(&self, source: EntityId) -> Vec<Relation> {
        self.graph
            .get_all_relations_for_entity(&source)
            .unwrap()
            .into_iter()
            .filter(|edge| edge.src.as_entity() == Some(source) && edge.kind == RelationKind::Calls)
            .collect()
    }

    fn reopen(&mut self) {
        self.generation += 1;
        let snapshot = self
            .root
            .path()
            .join(format!("reexport-{}.kindb", self.generation));
        SnapshotManager::save_graph(&snapshot, self.graph.as_ref()).unwrap();
        self.graph = SnapshotManager::open_without_text_index(&snapshot)
            .unwrap()
            .graph();
        self.reconciler = Reconciler::new(self.root.path().to_owned());
        self.reconciler
            .seed_lkg_entities_from_graph(self.graph.as_ref());
        self.reconciler
            .restore_cross_file_dependencies(self.graph.as_ref(), &self.blobs)
            .expect("restore dependencies from admitted CAS after cold reopen");
    }

    fn debt(&self, source: &str) -> Option<LocalBindingDebt> {
        let file = FilePathId::new(source);
        let path = RepoPath::from_utf8(source).unwrap();
        let artifact = self.graph.artifact_id_at_path(&path).unwrap();
        let Some(TreeEntry::Blob { hash, .. }) = self.graph.get_tree_entry(&file).unwrap() else {
            panic!("source must have an admitted blob: {source}");
        };
        let relations = self
            .graph
            .get_all_relations_for_node(&GraphNodeId::Artifact(artifact))
            .unwrap();
        inspect_local_binding_debt(&file, artifact, hash, &relations.iter().collect::<Vec<_>>())
            .expect("persisted debt must decode canonically against the current admitted source")
    }
}

fn intermediate_edit(cold: bool) {
    let mut repo = Repo::new();
    // Both destinations precede the first caller. This is a re-export edit,
    // not target arrival/deletion or a matching-name repair.
    repo.edit("pkg/old_impl.py", "def execute():\n    return 'old'\n");
    repo.edit("pkg/new_impl.py", "def execute():\n    return 'new'\n");
    repo.edit("pkg/bridge.py", OLD_BRIDGE);
    repo.edit("pkg/__init__.py", PACKAGE);
    repo.edit("app.py", APP);

    let caller = repo.function("app.py", "run");
    let old = repo.function("pkg/old_impl.py", "execute");
    let new = repo.function("pkg/new_impl.py", "execute");
    assert_ne!(old.id, new.id);
    let initial = repo.calls(caller.id);
    assert_eq!(
        initial.len(),
        1,
        "initial live route must publish exactly one call: {initial:#?}"
    );
    assert_eq!(
        initial[0].dst.as_entity(),
        Some(old.id),
        "initial live re-export resolution is a separate prerequisite: {initial:#?}"
    );
    assert!(!kin_index::is_external_import_placeholder(&initial[0]));
    assert!(initial[0].confidence >= 0.9);
    assert!(
        !repo.root.path().join("app.py").exists(),
        "the source lives in admitted CAS, not a working-tree fixture"
    );
    let caller_tree = repo
        .graph
        .get_tree_entry(&FilePathId::new("app.py"))
        .unwrap();
    let package_tree = repo
        .graph
        .get_tree_entry(&FilePathId::new("pkg/__init__.py"))
        .unwrap();

    if cold {
        repo.reopen();
        assert_eq!(
            repo.calls(caller.id)[0].dst.as_entity(),
            Some(old.id),
            "initial actual edge survives reopen"
        );
    }
    repo.edit("pkg/bridge.py", NEW_BRIDGE);

    let held_caller = repo.function("app.py", "run");
    assert_eq!(held_caller.id, caller.id);
    assert_eq!(held_caller.fingerprint, caller.fingerprint);
    assert_eq!(held_caller.span, caller.span);
    assert_eq!(
        held_caller.metadata.extra.get("blob_hash"),
        caller.metadata.extra.get("blob_hash")
    );
    assert_eq!(
        repo.graph
            .get_tree_entry(&FilePathId::new("app.py"))
            .unwrap(),
        caller_tree
    );
    assert_eq!(
        repo.graph
            .get_tree_entry(&FilePathId::new("pkg/__init__.py"))
            .unwrap(),
        package_tree
    );
    for (path, expected) in [("pkg/old_impl.py", old), ("pkg/new_impl.py", new.clone())] {
        let held = repo.function(path, "execute");
        assert_eq!(held.id, expected.id, "both implementations retain identity");
        assert_eq!(
            held.fingerprint, expected.fingerprint,
            "neither implementation changed"
        );
    }
    let actual = repo.calls(caller.id);
    assert_eq!(
        actual.len(),
        1,
        "intermediate-only edit must leave one current call, cold={cold}: {actual:#?}"
    );
    assert_eq!(actual[0].dst.as_entity(), Some(new.id),
        "intermediate-only re-export edit must retarget the unchanged consumer; cold={cold}, files_resolved={}: {actual:#?}",
        repo.reconciler.cross_file_linker().last_files_resolved());
    assert!(!kin_index::is_external_import_placeholder(&actual[0]));
    assert!(actual[0].confidence >= 0.9);
}

#[test]
fn an_intermediate_reexport_edit_retargets_the_unchanged_live_consumer() {
    intermediate_edit(false);
}

#[test]
fn an_intermediate_reexport_edit_retargets_the_unchanged_consumer_after_reopen() {
    intermediate_edit(true);
}

fn chain() -> (Repo, Entity, Entity, Entity, Relation) {
    let mut repo = Repo::new();
    repo.edit("pkg/old_impl.py", "def execute():\n    return 'old'\n");
    repo.edit("pkg/new_impl.py", "def execute():\n    return 'new'\n");
    repo.edit("pkg/bridge.py", OLD_BRIDGE);
    repo.edit("pkg/__init__.py", PACKAGE);
    repo.edit("app.py", APP);
    let caller = repo.function("app.py", "run");
    let old = repo.function("pkg/old_impl.py", "execute");
    let new = repo.function("pkg/new_impl.py", "execute");
    let initial = single_call(&repo, caller.id, old.id);
    assert!(repo.debt("app.py").is_none());
    assert!(!repo.root.path().join("app.py").exists());
    (repo, caller, old, new, initial)
}

fn single_call(repo: &Repo, caller: EntityId, target: EntityId) -> Relation {
    let calls = repo.calls(caller);
    assert_eq!(
        calls.len(),
        1,
        "expected exactly one actual live call: {calls:#?}"
    );
    assert_eq!(calls[0].dst.as_entity(), Some(target), "{calls:#?}");
    assert!(!kin_index::is_external_import_placeholder(&calls[0]));
    assert!(matches!(
        calls[0].origin,
        RelationOrigin::Parsed | RelationOrigin::Inferred
    ));
    assert!(calls[0].confidence >= 0.9);
    calls[0].clone()
}

const DIRECT_CALLER: &str = "from local import work\ndef run():\n    return work(value=1)\n";
const DIRECT_TARGET: &str = "def work(value):\n    return value + 1\n";

fn direct_local_binding() -> (Repo, Entity, Entity, Relation) {
    let mut repo = Repo::new();
    repo.edit("local.py", DIRECT_TARGET);
    repo.edit("caller.py", DIRECT_CALLER);
    let caller = repo.function("caller.py", "run");
    let target = repo.function("local.py", "work");
    let relation = single_call(&repo, caller.id, target.id);
    assert!(repo.debt("caller.py").is_none());
    assert!(!repo.root.path().join("caller.py").exists());
    (repo, caller, target, relation)
}

#[test]
fn canonical_deletion_readmits_an_unchanged_caller_and_retains_debt_through_recovery() {
    let (mut repo, caller, target, initial) = direct_local_binding();
    let caller_tree = repo
        .graph
        .get_tree_entry(&FilePathId::new("caller.py"))
        .unwrap();
    let old_artifact = repo.remove_canonically_with_binding_debt("local.py");
    assert!(repo.graph.get_entity(&target.id).unwrap().is_none());
    assert!(repo
        .graph
        .get_tree_entry(&FilePathId::new("local.py"))
        .unwrap()
        .is_none());
    assert!(repo.calls(caller.id).is_empty());
    let debt = repo
        .debt("caller.py")
        .expect("canonical removal retains real prior-local debt");
    assert!(debt.obligations.iter().any(|obligation| {
        obligation.retired_relation == initial && obligation.target_artifact == old_artifact
    }));
    let assert_only_unresolved_calls = |repo: &Repo| {
        let calls = repo.calls(caller.id);
        assert!(
            calls.iter().all(|relation| {
                kin_index::is_external_import_placeholder(relation)
                    && relation.confidence.to_bits() == 0.2_f32.to_bits()
                    && !kin_index::RelationResolution::of(relation).is_proven()
                    && relation.dst.as_entity() != Some(target.id)
                    && relation.import_source.as_deref() == Some("local")
                    && relation.evidence.iter().all(|evidence| {
                        evidence.token.as_deref() == Some("work") && evidence.occurrence_count == 1
                    })
                    && relation.dst.as_entity().is_some_and(|id| {
                        repo.graph
                            .get_entity(&id)
                            .unwrap()
                            .is_some_and(|entity| entity.file_origin.is_none())
                    })
            }),
            "removed local target permits only canonical unresolved external Calls: {calls:#?}"
        );
        assert!(
            repo.graph.get_entity(&target.id).unwrap().is_none(),
            "the removed local target must not be recreated: {calls:#?}"
        );
    };

    // No commit, restart, reseed, or reconcile removal occurred. This is the
    // first unchanged caller readmission with the same warm reconciler.
    let indexed = repo.reparse_admitted("caller.py");
    let refreshed = repo.plan_admitted(&indexed).expect(
        "canonical deletion must not leave a cached target that prevents caller readmission",
    );
    repo.apply(&refreshed);
    assert_only_unresolved_calls(&repo);
    assert_eq!(repo.function("caller.py", "run"), caller);
    assert_eq!(repo.debt("caller.py"), Some(debt.clone()));
    assert_eq!(
        repo.graph
            .get_tree_entry(&FilePathId::new("caller.py"))
            .unwrap(),
        caller_tree
    );

    repo.reopen();
    assert_only_unresolved_calls(&repo);
    assert_eq!(repo.debt("caller.py"), Some(debt));
    assert_eq!(repo.function("caller.py", "run"), caller);
    repo.edit("local.py", DIRECT_TARGET);
    let restored = repo.function("local.py", "work");
    assert_ne!(
        repo.graph
            .artifact_id_at_path(&RepoPath::from_utf8("local.py").unwrap()),
        Some(old_artifact),
        "a deleted path returns as a newly admitted artifact"
    );
    single_call(&repo, caller.id, restored.id);
    assert!(
        repo.debt("caller.py").is_none(),
        "actual restored Calls discharge the prior debt"
    );
    repo.reopen();
    single_call(&repo, caller.id, restored.id);
    assert!(repo.debt("caller.py").is_none());
    assert_eq!(repo.function("caller.py", "run"), caller);
}

#[test]
fn canonical_deletion_then_unindexed_path_replacement_cannot_reuse_the_old_target() {
    const REPLACEMENT: &str = "def other(value):\n    return value + 100\n";
    let (mut repo, caller, target, initial) = direct_local_binding();
    let old_artifact = repo.remove_canonically_with_binding_debt("local.py");
    let debt = repo
        .debt("caller.py")
        .expect("real deletion creates prior-local debt");
    assert!(debt
        .obligations
        .iter()
        .any(|obligation| obligation.retired_relation == initial));

    // Membership has returned with a different artifact and body, but neither
    // it nor the old target has current semantic declarations in the graph.
    let replacement = repo.admit("local.py", REPLACEMENT);
    let new_artifact = repo
        .graph
        .artifact_id_at_path(&RepoPath::from_utf8("local.py").unwrap())
        .unwrap();
    assert_ne!(new_artifact, old_artifact);
    assert!(repo.graph.get_entity(&target.id).unwrap().is_none());
    assert!(repo
        .graph
        .list_all_entities()
        .unwrap()
        .iter()
        .all(|entity| { entity.file_origin.as_ref() != Some(&FilePathId::new("local.py")) }));
    let caller_observation = repo.reparse_admitted("caller.py");
    let refreshed = repo.plan_admitted(&caller_observation).expect(
        "a different admitted artifact must invalidate the old cached target before readmission",
    );
    repo.apply(&refreshed);
    assert!(
        repo.calls(caller.id).is_empty(),
        "old work must not reappear from a stale witness"
    );
    assert_eq!(repo.debt("caller.py"), Some(debt.clone()));
    assert_eq!(repo.function("caller.py", "run"), caller);

    let replacement_result = repo
        .plan_admitted(&replacement)
        .expect("derive the actual replacement body");
    repo.apply(&replacement_result);
    repo.function("local.py", "other");
    assert!(repo.calls(caller.id).is_empty());
    assert_eq!(repo.debt("caller.py"), Some(debt.clone()));
    repo.reopen();
    assert!(repo.calls(caller.id).is_empty());
    assert_eq!(repo.debt("caller.py"), Some(debt));

    repo.edit("local.py", DIRECT_TARGET);
    let restored = repo.function("local.py", "work");
    assert_eq!(
        repo.graph
            .artifact_id_at_path(&RepoPath::from_utf8("local.py").unwrap()),
        Some(new_artifact)
    );
    single_call(&repo, caller.id, restored.id);
    assert!(repo.debt("caller.py").is_none());
    assert_eq!(repo.function("caller.py", "run"), caller);
    repo.reopen();
    single_call(&repo, caller.id, restored.id);
    assert!(repo.debt("caller.py").is_none());
}

fn invalid_bridge_withdrawal_and_recovery(invalid_bridge: &str, cold: bool) {
    let (mut repo, caller, old, new, initial) = chain();
    if cold {
        repo.reopen();
        single_call(&repo, caller.id, old.id);
    }

    repo.edit("pkg/bridge.py", invalid_bridge);
    let calls = repo.calls(caller.id);
    assert!(
        calls.is_empty(),
        "an unproven chain must withdraw its previous local Calls, cold={cold}: {calls:#?}"
    );
    assert_eq!(
        repo.function("app.py", "run"),
        caller,
        "the consumer was not edited"
    );
    let debt = repo
        .debt("app.py")
        .expect("withdrawal must leave persistent source-owned binding debt");
    assert_eq!(debt.obligations.len(), 1, "{debt:#?}");
    assert_eq!(debt.obligations[0].retired_relation, initial);
    assert_eq!(
        debt.obligations[0].target_file,
        FilePathId::new("pkg/old_impl.py")
    );

    // Both warm and cold invalidations must persist the unproven interval.
    // Recovery is deliberately performed by a newly seeded reconciler.
    repo.reopen();
    assert!(repo.calls(caller.id).is_empty());
    assert_eq!(repo.debt("app.py"), Some(debt));
    assert_eq!(repo.function("app.py", "run"), caller);

    repo.edit("pkg/bridge.py", NEW_BRIDGE);
    single_call(&repo, caller.id, new.id);
    assert!(
        repo.debt("app.py").is_none(),
        "a valid different-target replacement must discharge the prior obligation"
    );
    assert_eq!(repo.function("app.py", "run"), caller);
    assert_eq!(repo.function("pkg/old_impl.py", "execute"), old);
    assert_eq!(repo.function("pkg/new_impl.py", "execute"), new);
    repo.reopen();
    single_call(&repo, caller.id, new.id);
    assert!(repo.debt("app.py").is_none());
}

#[test]
fn a_guarded_bridge_withdraws_and_recovers_with_persisted_debt() {
    invalid_bridge_withdrawal_and_recovery(
        "if True:\n    from .old_impl import execute as forward\n",
        false,
    );
}

#[test]
fn a_guarded_bridge_withdraws_after_reopen_and_recovers_with_persisted_debt() {
    invalid_bridge_withdrawal_and_recovery(
        "if True:\n    from .old_impl import execute as forward\n",
        true,
    );
}

#[test]
fn a_cyclic_bridge_withdraws_and_recovers_with_persisted_debt() {
    invalid_bridge_withdrawal_and_recovery("from pkg import public as forward\n", false);
}

#[test]
fn a_cyclic_bridge_withdraws_after_reopen_and_recovers_with_persisted_debt() {
    invalid_bridge_withdrawal_and_recovery("from pkg import public as forward\n", true);
}

#[test]
fn a_duplicate_bridge_binding_withdraws_and_recovers_with_persisted_debt() {
    invalid_bridge_withdrawal_and_recovery(
        "from .old_impl import execute as forward\nfrom .new_impl import execute as forward\n",
        false,
    );
}

#[test]
fn a_duplicate_bridge_binding_withdraws_after_reopen_and_recovers_with_persisted_debt() {
    invalid_bridge_withdrawal_and_recovery(
        "from .old_impl import execute as forward\nfrom .new_impl import execute as forward\n",
        true,
    );
}

fn occurrence_texts<'a>(relation: &Relation, source: &'a str) -> BTreeSet<&'a str> {
    relation
        .evidence
        .iter()
        .filter_map(|evidence| evidence.source_span.as_ref())
        .map(|span| {
            assert_eq!(span.file, FilePathId::new("app.py"));
            source
                .get(span.start_byte..span.end_byte)
                .expect("exact caller occurrence bytes")
        })
        .collect()
}

#[test]
fn retargeting_one_alias_preserves_the_other_occurrence_of_the_old_target() {
    const TWO_CALLS: &str =
        "from pkg import moving, fixed\ndef run():\n    return moving() + fixed()\n";
    let mut repo = Repo::new();
    repo.edit("pkg/old_impl.py", "def execute():\n    return 1\n");
    repo.edit("pkg/new_impl.py", "def execute():\n    return 2\n");
    repo.edit(
        "pkg/bridge.py",
        "from .old_impl import execute as forward\nfrom .old_impl import execute as stationary\n",
    );
    repo.edit(
        "pkg/__init__.py",
        "from .bridge import forward as moving\nfrom .bridge import stationary as fixed\n",
    );
    repo.edit("app.py", TWO_CALLS);
    let caller = repo.function("app.py", "run");
    let old = repo.function("pkg/old_impl.py", "execute");
    let new = repo.function("pkg/new_impl.py", "execute");
    let initial = single_call(&repo, caller.id, old.id);
    assert_eq!(
        occurrence_texts(&initial, TWO_CALLS),
        BTreeSet::from(["moving()", "fixed()"])
    );

    repo.edit(
        "pkg/bridge.py",
        "from .new_impl import execute as forward\nfrom .old_impl import execute as stationary\n",
    );
    let assert_split = |repo: &Repo| {
        let calls = repo.calls(caller.id);
        assert_eq!(
            calls.len(),
            2,
            "one current edge per distinct target: {calls:#?}"
        );
        let kept = calls
            .iter()
            .find(|edge| edge.dst.as_entity() == Some(old.id))
            .expect("unaffected alias must retain the old target");
        let moved = calls
            .iter()
            .find(|edge| edge.dst.as_entity() == Some(new.id))
            .expect("changed alias must bind the new target");
        assert_eq!(kept.id, initial.id);
        assert_eq!(
            occurrence_texts(kept, TWO_CALLS),
            BTreeSet::from(["fixed()"])
        );
        assert_eq!(
            occurrence_texts(moved, TWO_CALLS),
            BTreeSet::from(["moving()"])
        );
        assert!(repo.debt("app.py").is_none());
        assert_eq!(repo.function("app.py", "run"), caller);
    };
    assert_split(&repo);
    repo.reopen();
    assert_split(&repo);
}

#[test]
fn retargeting_preserves_manual_and_lsp_outgoing_proof() {
    let (mut repo, caller, old, new, initial) = chain();
    repo.edit("unrelated.py", "def audit():\n    return 0\n");
    let unrelated = repo.function("unrelated.py", "audit");
    // Even a same-site Manual edge to the old target is outside the parser's
    // authority. The LSP edge tests an unrelated outgoing destination too.
    let mut manual = initial.clone();
    manual.id = RelationId::new();
    manual.origin = RelationOrigin::Manual;
    let mut lsp = initial.clone();
    lsp.id = RelationId::new();
    lsp.origin = RelationOrigin::Lsp;
    lsp.dst = GraphNodeId::Entity(unrelated.id);
    repo.graph
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas: vec![
                RelationDelta::Added {
                    new: manual.clone(),
                },
                RelationDelta::Added { new: lsp.clone() },
            ],
            ..Default::default()
        })
        .unwrap();
    repo.edit("pkg/bridge.py", NEW_BRIDGE);
    let assert_preserved = |repo: &Repo| {
        assert_eq!(
            repo.graph.get_relation_by_id(&manual.id),
            Some(manual.clone())
        );
        assert_eq!(repo.graph.get_relation_by_id(&lsp.id), Some(lsp.clone()));
        let calls = repo.calls(caller.id);
        let parser_calls: Vec<_> = calls
            .iter()
            .filter(|edge| {
                matches!(
                    edge.origin,
                    RelationOrigin::Parsed | RelationOrigin::Inferred
                )
            })
            .collect();
        assert_eq!(parser_calls.len(), 1, "{calls:#?}");
        assert_eq!(parser_calls[0].dst.as_entity(), Some(new.id));
        assert!(!parser_calls
            .iter()
            .any(|edge| edge.dst.as_entity() == Some(old.id)));
        assert!(repo.debt("app.py").is_none());
    };
    assert_preserved(&repo);
    repo.reopen();
    assert_preserved(&repo);
}

#[test]
fn a_new_caller_after_cold_graph_seed_resolves_the_admitted_reexport_chain() {
    let (mut repo, existing, old, _, _) = chain();
    repo.reopen();
    single_call(&repo, existing.id, old.id);
    repo.edit(
        "late.py",
        "from pkg import public as invoke\ndef later():\n    return invoke()\n",
    );
    let late = repo.function("late.py", "later");
    assert_ne!(late.id, existing.id);
    single_call(&repo, late.id, old.id);
    assert!(repo.debt("late.py").is_none());
    assert!(!repo.root.path().join("late.py").exists());
    repo.reopen();
    single_call(&repo, late.id, old.id);
}

#[test]
fn a_foreign_inferred_identity_with_copied_factory_evidence_is_preserved() {
    let (mut repo, caller, old, new, initial) = chain();
    let mut foreign = initial.clone();
    foreign.id = RelationId::new();
    assert_ne!(foreign.id, initial.id);
    assert_eq!(foreign.origin, RelationOrigin::Inferred);
    repo.graph
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas: vec![RelationDelta::Added {
                new: foreign.clone(),
            }],
            ..Default::default()
        })
        .unwrap();

    repo.edit("pkg/bridge.py", NEW_BRIDGE);
    let assert_owned_only = |repo: &Repo| {
        assert_eq!(
            repo.graph.get_relation_by_id(&foreign.id),
            Some(foreign.clone()),
            "matching occurrence fields do not enroll a foreign relation identity"
        );
        assert!(repo.graph.get_relation_by_id(&initial.id).is_none());
        let calls = repo.calls(caller.id);
        assert_eq!(
            calls.len(),
            2,
            "foreign old edge plus the actual new derivation: {calls:#?}"
        );
        assert!(calls
            .iter()
            .any(|edge| edge.id == foreign.id && edge.dst.as_entity() == Some(old.id)));
        assert_eq!(
            calls
                .iter()
                .filter(|edge| edge.id != foreign.id && edge.dst.as_entity() == Some(new.id))
                .count(),
            1
        );
        assert!(
            repo.debt("app.py").is_none(),
            "foreign evidence must not become factory-owned debt"
        );
    };
    assert_owned_only(&repo);
    repo.reopen();
    assert_owned_only(&repo);
}

const TWO_ALIAS_APP: &str =
    "from pkg import moving, fixed\ndef run():\n    return moving() + fixed()\n";
const BOTH_OLD: &str =
    "from .old_impl import execute as forward\nfrom .old_impl import execute as stationary\n";
const BOTH_MISSING: &str =
    "from .missing import execute as forward\nfrom .missing import execute as stationary\n";
const MOVING_NEW_FIXED_MISSING: &str =
    "from .new_impl import execute as forward\nfrom .missing import execute as stationary\n";
const MOVING_NEW_FIXED_OLD: &str =
    "from .new_impl import execute as forward\nfrom .old_impl import execute as stationary\n";

fn two_alias_chain(bridge: &str) -> (Repo, Entity, Entity, Entity) {
    let mut repo = Repo::new();
    repo.edit("pkg/old_impl.py", "def execute():\n    return 1\n");
    repo.edit("pkg/new_impl.py", "def execute():\n    return 2\n");
    repo.edit("pkg/bridge.py", bridge);
    repo.edit(
        "pkg/__init__.py",
        "from .bridge import forward as moving\nfrom .bridge import stationary as fixed\n",
    );
    repo.edit("app.py", TWO_ALIAS_APP);
    let caller = repo.function("app.py", "run");
    let old = repo.function("pkg/old_impl.py", "execute");
    let new = repo.function("pkg/new_impl.py", "execute");
    assert!(repo.debt("app.py").is_none());
    (repo, caller, old, new)
}

fn assert_alias_sites(repo: &Repo, caller: EntityId, expected: &[(EntityId, &[&str])]) {
    let calls = repo.calls(caller);
    assert_eq!(
        calls.len(),
        expected.len(),
        "one current relation per expected target: {calls:#?}"
    );
    for (target, texts) in expected {
        let matching: Vec<_> = calls
            .iter()
            .filter(|edge| edge.dst.as_entity() == Some(*target))
            .collect();
        assert_eq!(matching.len(), 1, "{calls:#?}");
        assert!(matches!(
            matching[0].origin,
            RelationOrigin::Parsed | RelationOrigin::Inferred
        ));
        assert!(!kin_index::is_external_import_placeholder(matching[0]));
        assert!(matching[0].confidence >= 0.9);
        assert_eq!(
            occurrence_texts(matching[0], TWO_ALIAS_APP),
            texts.iter().copied().collect()
        );
    }
}

#[test]
fn swapping_alias_targets_preserves_both_newly_accepted_occurrences() {
    let (mut repo, caller, old, new) = two_alias_chain(MOVING_NEW_FIXED_OLD);
    assert_alias_sites(
        &repo,
        caller.id,
        &[(new.id, &["moving()"]), (old.id, &["fixed()"])],
    );
    let original_ids: BTreeSet<_> = repo.calls(caller.id).iter().map(|edge| edge.id).collect();

    repo.edit(
        "pkg/bridge.py",
        "from .old_impl import execute as forward\nfrom .new_impl import execute as stationary\n",
    );
    assert_alias_sites(
        &repo,
        caller.id,
        &[(old.id, &["moving()"]), (new.id, &["fixed()"])],
    );
    assert_eq!(
        repo.calls(caller.id)
            .iter()
            .map(|edge| edge.id)
            .collect::<BTreeSet<_>>(),
        original_ids
    );
    assert!(repo.debt("app.py").is_none());
    assert_eq!(repo.function("app.py", "run"), caller);
    repo.reopen();
    assert_alias_sites(
        &repo,
        caller.id,
        &[(old.id, &["moving()"]), (new.id, &["fixed()"])],
    );
    assert!(repo.debt("app.py").is_none());
}

fn mixed_debt_partial_recovery(cold: bool) {
    let (mut repo, caller, old, new) = two_alias_chain(BOTH_OLD);
    assert_alias_sites(&repo, caller.id, &[(old.id, &["moving()", "fixed()"])]);
    let initial = repo.calls(caller.id).pop().unwrap();
    if cold {
        repo.reopen();
    }
    repo.edit("pkg/bridge.py", BOTH_MISSING);
    assert_alias_sites(&repo, caller.id, &[]);
    let debt = repo
        .debt("app.py")
        .expect("both lost sites require persistent prior-local debt");
    assert_eq!(debt.obligations.len(), 1);
    assert_eq!(debt.obligations[0].retired_relation, initial);
    repo.reopen();
    assert_eq!(repo.debt("app.py"), Some(debt));
    assert_alias_sites(&repo, caller.id, &[]);

    repo.edit("pkg/bridge.py", MOVING_NEW_FIXED_MISSING);
    assert_alias_sites(&repo, caller.id, &[(new.id, &["moving()"])]);
    let partial = repo
        .debt("app.py")
        .expect("one proven occurrence cannot discharge the other unresolved site");
    assert!(partial
        .obligations
        .iter()
        .any(
            |obligation| occurrence_texts(&obligation.retired_relation, TWO_ALIAS_APP)
                .contains("fixed()")
        ));
    repo.reopen();
    assert_eq!(repo.debt("app.py"), Some(partial));
    assert_alias_sites(&repo, caller.id, &[(new.id, &["moving()"])]);

    repo.edit("pkg/bridge.py", MOVING_NEW_FIXED_OLD);
    assert_alias_sites(
        &repo,
        caller.id,
        &[(new.id, &["moving()"]), (old.id, &["fixed()"])],
    );
    assert!(repo.debt("app.py").is_none());
    assert_eq!(repo.function("app.py", "run"), caller);
    repo.reopen();
    assert_alias_sites(
        &repo,
        caller.id,
        &[(new.id, &["moving()"]), (old.id, &["fixed()"])],
    );
    assert!(repo.debt("app.py").is_none());
}

#[test]
fn mixed_two_site_debt_survives_partial_recovery_until_both_sites_are_proven() {
    mixed_debt_partial_recovery(false);
}

#[test]
fn mixed_two_site_debt_after_reopen_survives_partial_recovery_until_both_sites_are_proven() {
    mixed_debt_partial_recovery(true);
}

#[test]
fn progressive_withdrawal_of_two_sites_preserves_all_prior_occurrence_debt() {
    let (mut repo, caller, old, new) = two_alias_chain(BOTH_OLD);
    assert_alias_sites(&repo, caller.id, &[(old.id, &["moving()", "fixed()"])]);
    repo.edit(
        "pkg/bridge.py",
        "from .missing import execute as forward\nfrom .old_impl import execute as stationary\n",
    );
    assert_alias_sites(&repo, caller.id, &[(old.id, &["fixed()"])]);
    let first = repo
        .debt("app.py")
        .expect("the first withdrawn site needs debt");
    assert!(first.obligations.iter().any(|obligation| occurrence_texts(
        &obligation.retired_relation,
        TWO_ALIAS_APP
    )
    .contains("moving()")));
    repo.reopen();
    assert_eq!(repo.debt("app.py"), Some(first));

    repo.edit("pkg/bridge.py", BOTH_MISSING);
    assert_alias_sites(&repo, caller.id, &[]);
    let second = repo
        .debt("app.py")
        .expect("both prior occurrences must survive sequential withdrawal");
    let sites: BTreeSet<_> = second
        .obligations
        .iter()
        .flat_map(|obligation| occurrence_texts(&obligation.retired_relation, TWO_ALIAS_APP))
        .collect();
    assert_eq!(sites, BTreeSet::from(["moving()", "fixed()"]));
    repo.reopen();
    assert_eq!(repo.debt("app.py"), Some(second));

    repo.edit("pkg/bridge.py", MOVING_NEW_FIXED_OLD);
    assert_alias_sites(
        &repo,
        caller.id,
        &[(new.id, &["moving()"]), (old.id, &["fixed()"])],
    );
    assert!(repo.debt("app.py").is_none());
    assert_eq!(repo.function("app.py", "run"), caller);
}

fn entity_snapshot(repo: &Repo) -> BTreeMap<EntityId, Entity> {
    repo.graph
        .list_all_entities()
        .unwrap()
        .into_iter()
        .map(|entity| (entity.id, entity))
        .collect()
}

#[test]
fn an_unapplied_retarget_proposal_can_be_retried_by_the_same_reconciler() {
    let (mut repo, caller, old, new, initial) = chain();
    let semantic_entities = entity_snapshot(&repo);
    let indexed = repo.admit("pkg/bridge.py", NEW_BRIDGE);
    let admitted_bridge = repo
        .graph
        .get_tree_entry(&FilePathId::new("pkg/bridge.py"))
        .unwrap();
    assert_eq!(
        admitted_bridge,
        Some(TreeEntry::blob(indexed.blob_hash, false))
    );

    let proposed = repo
        .plan_admitted(&indexed)
        .expect("first genuine derived proposal");
    assert!(
        proposed
            .delta
            .relation_deltas
            .iter()
            .any(|change| matches!(change, RelationDelta::Removed { old } if old == &initial)),
        "the rejected proposal must really intend to retire the old call"
    );
    let replacement = proposed
        .delta
        .relation_deltas
        .iter()
        .find_map(|change| {
            let relation = match change {
                RelationDelta::Added { new } | RelationDelta::Modified { new, .. } => new,
                RelationDelta::Removed { .. } => return None,
            };
            (relation.src.as_entity() == Some(caller.id)
                && relation.dst.as_entity() == Some(new.id)
                && relation.kind == RelationKind::Calls)
                .then(|| relation.clone())
        })
        .expect("the rejected proposal must really intend to publish the new call");
    // Simulate the authority declining the unpublished semantic proposal. The
    // newly admitted tree remains, while no proposed entity/relation is applied.
    drop(proposed);
    assert_eq!(entity_snapshot(&repo), semantic_entities);
    assert_eq!(single_call(&repo, caller.id, old.id), initial);
    assert!(repo.debt("app.py").is_none());

    let retry = repo
        .plan_admitted(&indexed)
        .expect("same reconciler retries the same admitted bytes");
    assert_eq!(
        repo.graph
            .get_tree_entry(&FilePathId::new("pkg/bridge.py"))
            .unwrap(),
        admitted_bridge
    );
    assert_eq!(entity_snapshot(&repo), semantic_entities);
    assert_eq!(single_call(&repo, caller.id, old.id), initial);
    repo.apply(&retry);
    assert_eq!(single_call(&repo, caller.id, new.id), replacement);
    assert!(repo.graph.get_relation_by_id(&initial.id).is_none());
    assert!(repo.debt("app.py").is_none());
    assert_eq!(repo.function("app.py", "run"), caller);
    repo.reopen();
    assert_eq!(single_call(&repo, caller.id, new.id), replacement);
    assert!(repo.debt("app.py").is_none());
}

#[test]
fn a_foreign_debt_identity_refuses_the_whole_change_and_same_reconciler_can_retry() {
    let (mut repo, caller, old, new, initial) = chain();
    repo.edit(
        "unrelated.py",
        "def first():\n    return 1\ndef second():\n    return 2\n",
    );
    let unrelated_source = repo.function("unrelated.py", "first");
    let unrelated_target = repo.function("unrelated.py", "second");
    let artifact = repo
        .graph
        .artifact_id_at_path(&RepoPath::from_utf8("app.py").unwrap())
        .unwrap();
    let foreign = Relation {
        id: kin_index::binding_debt::local_binding_debt_id(artifact),
        kind: RelationKind::References,
        src: GraphNodeId::Entity(unrelated_source.id),
        dst: GraphNodeId::Entity(unrelated_target.id),
        confidence: 1.0,
        origin: RelationOrigin::Manual,
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
    let semantic_entities = entity_snapshot(&repo);
    let indexed = repo.admit("pkg/bridge.py", "from pkg import public as forward\n");
    let admitted_bridge = repo
        .graph
        .get_tree_entry(&FilePathId::new("pkg/bridge.py"))
        .unwrap();
    let error = repo
        .plan_admitted(&indexed)
        .expect_err("foreign debt identity must refuse the whole semantic proposal")
        .to_string();
    assert!(
        error.contains("binding debt"),
        "the actual refusal must identify debt authority: {error}"
    );
    assert_eq!(
        repo.graph.get_relation_by_id(&foreign.id),
        Some(foreign.clone())
    );
    assert_eq!(single_call(&repo, caller.id, old.id), initial);
    assert_eq!(entity_snapshot(&repo), semantic_entities);

    // Remove only the row installed by this control. Retry with the same
    // reconciler, indexed observation, and already admitted cyclic bridge.
    repo.graph
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas: vec![RelationDelta::Removed {
                old: foreign.clone(),
            }],
            ..Default::default()
        })
        .unwrap();
    let retry = repo
        .plan_admitted(&indexed)
        .expect("debt authority repair permits the same source observation to retry");
    assert_eq!(
        repo.graph
            .get_tree_entry(&FilePathId::new("pkg/bridge.py"))
            .unwrap(),
        admitted_bridge
    );
    assert_eq!(single_call(&repo, caller.id, old.id), initial);
    assert!(repo.graph.get_relation_by_id(&foreign.id).is_none());
    repo.apply(&retry);
    assert!(repo.calls(caller.id).is_empty());
    let debt = repo
        .debt("app.py")
        .expect("successful retry atomically records the withdrawn local binding");
    assert_eq!(debt.obligations.len(), 1);
    assert_eq!(debt.obligations[0].retired_relation, initial);
    assert_ne!(repo.graph.get_relation_by_id(&foreign.id), Some(foreign));
    assert_eq!(repo.function("app.py", "run"), caller);
    repo.reopen();
    assert!(repo.calls(caller.id).is_empty());
    assert_eq!(repo.debt("app.py"), Some(debt));
    repo.edit("pkg/bridge.py", NEW_BRIDGE);
    single_call(&repo, caller.id, new.id);
    assert!(repo.debt("app.py").is_none());
}

#[test]
fn an_admitted_unindexed_competing_module_blocks_a_new_exact_caller() {
    let (mut repo, caller, old, _, initial) = chain();
    let semantic_entities = entity_snapshot(&repo);

    // Admission precedes semantic publication. The competing module is real
    // repository tree/CAS truth even when its indexing delta never publishes.
    let competitor = repo.admit("pkg.py", "def public():\n    return 99\n");
    assert_eq!(
        repo.graph
            .get_tree_entry(&FilePathId::new("pkg.py"))
            .unwrap(),
        Some(TreeEntry::blob(competitor.blob_hash, false))
    );
    assert!(!competitor.entities.is_empty());
    drop(competitor);
    assert_eq!(entity_snapshot(&repo), semantic_entities);
    assert!(!repo
        .graph
        .list_all_entities()
        .unwrap()
        .iter()
        .any(|entity| entity.file_origin.as_ref() == Some(&FilePathId::new("pkg.py"))));

    // A fresh caller exercises actual live resolution after the competitor's
    // admission, without refreshing or hand-editing the linker's file set.
    let late = repo.admit(
        "late.py",
        "from pkg import public\ndef later():\n    return public()\n",
    );
    let late_caller = late
        .entities
        .iter()
        .find(|entity| entity.kind == EntityKind::Function && entity.name == "later")
        .unwrap()
        .id;
    repo.plan_admitted(&late)
        .expect_err("an unindexed competing tree path must refuse exact package resolution");

    assert_eq!(entity_snapshot(&repo), semantic_entities);
    assert_eq!(single_call(&repo, caller.id, old.id), initial);
    assert!(repo.graph.get_entity(&late_caller).unwrap().is_none());
    assert!(repo.calls(late_caller).is_empty());
    assert!(repo.debt("app.py").is_none());
    assert!(repo
        .graph
        .get_tree_entry(&FilePathId::new("pkg.py"))
        .unwrap()
        .is_some());
    assert!(repo
        .graph
        .get_tree_entry(&FilePathId::new("late.py"))
        .unwrap()
        .is_some());
    assert!(!repo.root.path().join("pkg.py").exists());
}
