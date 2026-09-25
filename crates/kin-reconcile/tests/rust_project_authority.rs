// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_blobs::BlobStore;
use kin_db::{GraphSnapshot, InMemoryGraph, SnapshotManager};
use kin_model::{
    ArtifactId, Entity, EntityStore, FilePathId, GraphNodeId, Hash256, LocatedEntry, RelationKind,
    RepoPath, TransactionDelta, TreeDelta, TreeEntry,
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
        let matches: Vec<_> = self
            .graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .filter(|entity| {
                entity.name == name
                    && entity.file_origin.is_some()
                    && entity.kind != kin_model::EntityKind::Module
            })
            .collect();
        assert_eq!(matches.len(), 1, "exact local declaration {name}");
        matches.into_iter().next().unwrap()
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

const MANIFEST: &str = "[package]\nname='fixture'\nedition='2021'\nautolib=false\nautobins=false\n[lib]\npath='app.rs'\n";
const CALLER: &str = "use crate::owner::work; pub fn run() { work(); }";

fn project() -> Repo {
    Repo::new(&[
        ("Cargo.toml", MANIFEST),
        ("app.rs", "pub mod owner; pub mod caller;"),
        ("owner.rs", "pub fn work() {}"),
        ("caller.rs", CALLER),
        ("other.rs", "pub fn unrelated() {}"),
    ])
}

#[test]
fn canonical_cargo_authority_binds_real_calls_and_retires_external_boundary() {
    let repo = project();
    assert!(repo.calls("run", "work"));
    let caller = repo.entity("run").id;
    let outgoing: Vec<_> = repo
        .graph
        .get_all_relations_for_entity(&caller)
        .unwrap()
        .into_iter()
        .filter(|r| r.src.as_entity() == Some(caller) && r.kind == RelationKind::Calls)
        .collect();
    assert_eq!(outgoing.len(), 1, "{:?}", outgoing);
    assert_eq!(outgoing[0].confidence, 0.95);
    assert_eq!(
        outgoing[0].evidence[0].source_path.as_deref(),
        Some("crate::owner")
    );
    assert_eq!(
        outgoing[0].evidence[0].resolved_path.as_deref(),
        Some("owner.rs")
    );
    assert!(repo.debt("caller.rs").is_none());
}

#[test]
fn manifest_only_retarget_withdraws_owned_call_and_persists_debt_until_repaired() {
    let mut repo = project();
    let caller = repo.entity("run").id;
    let target = repo.entity("work").id;
    let replacement = MANIFEST.replace("app.rs", "other.rs");
    repo.admit("Cargo.toml", &replacement);
    repo.batch(&["Cargo.toml"]);
    assert_eq!(repo.entity("run").id, caller);
    assert_eq!(repo.entity("work").id, target);
    assert!(!repo.calls("run", "work"));
    let debt = repo.debt("caller.rs").unwrap();
    assert_eq!(debt.obligations.len(), 1);
    let saved = repo.root.path().join("snapshot");
    SnapshotManager::save_graph(&saved, &repo.graph).unwrap();
    repo.graph = InMemoryGraph::from_snapshot(
        SnapshotManager::open_without_text_index(&saved)
            .unwrap()
            .graph()
            .to_snapshot(),
    )
    .unwrap();
    assert!(!repo.calls("run", "work"));
    assert_eq!(repo.debt("caller.rs").unwrap(), debt);
    repo.admit("Cargo.toml", MANIFEST);
    repo.batch(&["Cargo.toml"]);
    assert!(repo.calls("run", "work"));
    assert!(repo.debt("caller.rs").is_none());
    assert_eq!(repo.entity("run").id, caller);
    assert_eq!(repo.entity("work").id, target);
}

#[test]
fn supported_to_conditional_manifest_is_unknown_and_does_not_keep_old_exact_call() {
    let mut repo = project();
    repo.admit(
        "Cargo.toml",
        &format!("{MANIFEST}required-features=['runtime-choice']\n"),
    );
    repo.batch(&["Cargo.toml"]);
    assert!(!repo.calls("run", "work"));
    assert!(repo.debt("caller.rs").is_some());
}

#[test]
fn root_module_membership_change_rechecks_unchanged_callers_without_a_manifest_edit() {
    let mut repo = project();
    let caller = repo.entity("run").id;
    let target = repo.entity("work").id;
    repo.admit("app.rs", "pub mod caller;");
    repo.batch(&["app.rs"]);
    assert!(!repo.calls("run", "work"));
    assert_eq!(repo.debt("caller.rs").unwrap().obligations.len(), 1);
    repo.admit("app.rs", "pub mod owner; pub mod caller;");
    repo.batch(&["app.rs"]);
    assert!(repo.calls("run", "work"));
    assert!(repo.debt("caller.rs").is_none());
    assert_eq!(repo.entity("run").id, caller);
    assert_eq!(repo.entity("work").id, target);
}

#[test]
fn missing_project_cas_refuses_candidate_and_keeps_prior_graph_unchanged() {
    let repo = project();
    repo.admit_hash("owner.rs", Hash256::from_bytes([77; 32]));
    let before = repo.graph.to_snapshot();
    let error = repo.plan(&["Cargo.toml"]).unwrap_err();
    assert!(error.to_string().contains("owner.rs"), "{error}");
    let after = repo.graph.to_snapshot();
    assert_eq!(before.entities, after.entities);
    assert_eq!(before.relations, after.relations);
    assert_eq!(before.resolved_tree, after.resolved_tree);
    assert!(repo.calls("run", "work"));
}

#[test]
fn foreign_provenance_is_never_retired_or_overwritten_by_project_rederivation() {
    let mut repo = project();
    let caller = repo.entity("run").id;
    let target = repo.entity("work").id;
    let old = repo
        .graph
        .get_all_relations_for_entity(&caller)
        .unwrap()
        .into_iter()
        .find(|r| {
            r.kind == RelationKind::Calls
                && r.src.as_entity() == Some(caller)
                && r.dst.as_entity() == Some(target)
        })
        .unwrap();
    let mut manual = old.clone();
    manual.origin = kin_model::RelationOrigin::Manual;
    repo.graph
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas: vec![kin_model::RelationDelta::Modified {
                old,
                new: manual.clone(),
            }],
            ..Default::default()
        })
        .unwrap();
    repo.admit("Cargo.toml", &MANIFEST.replace("app.rs", "other.rs"));
    repo.batch(&["Cargo.toml"]);
    assert_eq!(
        repo.graph.to_snapshot().relations.get(&manual.id),
        Some(&manual)
    );
    assert!(repo.debt("caller.rs").is_none());
    repo.admit("Cargo.toml", MANIFEST);
    let error = repo.plan(&["Cargo.toml"]).unwrap_err();
    assert!(
        error.to_string().contains("unrecognized held provenance"),
        "{error}"
    );
    assert_eq!(
        repo.graph.to_snapshot().relations.get(&manual.id),
        Some(&manual)
    );
}

#[test]
fn independent_same_file_self_import_survives_without_any_cargo_manifest() {
    let mut repo = Repo::new(&[(
        "standalone.rs",
        "enum Width { Narrow(u8) } use self::Width::Narrow; fn run() { Narrow(1); }",
    )]);
    assert!(repo.calls("run", "Width::Narrow"));
    repo.batch(&[]);
    assert!(repo.calls("run", "Width::Narrow"));
    assert!(repo.debt("standalone.rs").is_none());
}

#[test]
fn non_rs_root_transition_withdraws_prior_authority_instead_of_guessing_membership() {
    let mut repo = project();
    assert!(repo.calls("run", "work"));
    repo.admit("root.inc", "pub mod owner; pub mod caller;");
    repo.admit("Cargo.toml", &MANIFEST.replace("app.rs", "root.inc"));
    repo.batch(&["Cargo.toml"]);
    assert!(!repo.calls("run", "work"));
    assert!(repo.debt("caller.rs").is_some());
}

#[test]
fn inline_single_source_cargo_call_has_exact_project_binding() {
    const BODY: &str =
        "pub mod owner { pub fn work() {} } use crate::owner::work; pub fn run() { work(); }";
    let repo = Repo::new(&[("Cargo.toml", MANIFEST), ("app.rs", BODY)]);
    let mut authority = kin_index::rust_project::RustProjectAuthority::from_admitted_tree(
        &repo.graph.resolved_tree(),
        Default::default(),
        |hash| {
            repo.blobs
                .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
                .map_err(|e| e.to_string())
        },
    )
    .unwrap();
    let entities = repo.graph.list_all_entities().unwrap();
    authority.bind_entities(&entities).unwrap();
    assert_eq!(
        authority.resolve_entity(
            "app.rs",
            BODY.find("work();").unwrap(),
            "crate::owner",
            "work"
        ),
        Some((repo.entity("work").id, "app.rs".to_owned())),
    );
    assert!(
        repo.calls("run", "work"),
        "inline source must resolve through Cargo authority"
    );
}
