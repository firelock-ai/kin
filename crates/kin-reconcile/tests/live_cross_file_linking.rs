// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-file relations on the live reconcile path, one file at a time.
//!
//! This is the shape a stranger produces: `kin init` in an empty directory,
//! then modules written and committed one after another. Before the live path
//! ran a cross-file linker, that repository held `Contains` and same-file
//! `Calls` and nothing else, whatever the imports said.
//!
//! Every test here drives the real reconciler against a real graph through the
//! same admit-then-reconcile order the daemon uses, and both write orders are
//! exercised deliberately. Writing the callee first and the caller second is
//! the easy direction; a fix that only handles it passes a naive test and fails
//! a real build, where the module you are working in usually exists before the
//! module it will call.

use std::path::PathBuf;

use kin_blobs::BlobStore;
use kin_db::InMemoryGraph;
use kin_index::FileEvent;
use kin_model::{
    ArtifactId, EntityId, EntityStore, GraphNodeId, Hash256, LocatedEntry, Relation, RelationKind,
    RepoPath, TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;
use tempfile::TempDir;

/// A repository built the way a user builds one: file by file, each one
/// admitted and reconciled before the next is written.
struct LiveRepo {
    dir: TempDir,
    graph: InMemoryGraph,
    blobs: BlobStore,
    reconciler: Reconciler,
    /// Files this repo resolved on its most recent commit, as the cross-file
    /// pass counted them. The cost assertion reads this.
    last_files_resolved: usize,
    /// Every path this repo has committed, so artifact edges can be read back
    /// by walking out of each artifact node.
    committed: Vec<String>,
}

impl LiveRepo {
    fn new() -> Self {
        let dir = TempDir::new().expect("temp repo");
        let blobs = BlobStore::new(dir.path().join("blobs")).expect("blob store");
        let graph = InMemoryGraph::new();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        // The daemon does exactly this at startup. An unseeded linker resolves
        // against an empty universe and reports every destination missing.
        reconciler.seed_cross_file_linker_from_graph(&graph);
        Self {
            dir,
            graph,
            blobs,
            reconciler,
            last_files_resolved: 0,
            committed: Vec::new(),
        }
    }

    fn abs(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    /// Write, admit, reconcile, apply. The admit-before-reconcile order is the
    /// daemon's: `exact_tree_admission` runs before the reconcile in both the
    /// watch loop and the commit sync, and a file with no admitted artifact
    /// identity cannot carry artifact-level import edges.
    fn commit(&mut self, rel: &str, source: &str) {
        let path = self.abs(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(&path, source).expect("write source");
        if !self.committed.iter().any(|known| known == rel) {
            self.committed.push(rel.to_string());
        }

        let blob_hash = self.blobs.write(source.as_bytes()).expect("store blob");
        let repo_path = RepoPath::from_utf8(rel.to_string()).expect("repo path");
        let entry = TreeEntry::blob(Hash256::from_bytes(blob_hash.0), false);
        let tree_delta = match self.graph.artifact_id_at_path(&repo_path) {
            Some(artifact_id) => {
                let old_entry = self
                    .graph
                    .get_tree_entry(&kin_model::FilePathId::new(rel))
                    .ok()
                    .flatten();
                match old_entry {
                    Some(old) if old == entry => None,
                    Some(old) => Some(TreeDelta::Updated {
                        artifact_id,
                        old: LocatedEntry::new(repo_path.clone(), old),
                        new: LocatedEntry::new(repo_path, entry),
                    }),
                    None => Some(TreeDelta::Added {
                        artifact_id,
                        new: LocatedEntry::new(repo_path, entry),
                    }),
                }
            }
            None => Some(TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(repo_path, entry),
            }),
        };
        if let Some(tree_delta) = tree_delta {
            self.graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![tree_delta],
                    ..TransactionDelta::default()
                })
                .expect("admit artifact");
        }

        let result = self
            .reconciler
            .reconcile_file_change(&FileEvent::Changed(path), &self.blobs, &self.graph)
            .expect("reconcile succeeds");
        let (_, delta) = result.into_parts();
        if let Err(error) = self.graph.apply_transaction_delta(&delta) {
            panic!("apply reconciled delta for {rel}: {error}\ndelta = {delta:#?}");
        }
        self.last_files_resolved = self.reconciler.cross_file_linker().last_files_resolved();
    }

    fn remove(&mut self, rel: &str) {
        let path = self.abs(rel);
        std::fs::remove_file(&path).expect("remove source");
        self.committed.retain(|known| known != rel);
        let result = self
            .reconciler
            .reconcile_file_change(&FileEvent::Removed(path), &self.blobs, &self.graph)
            .expect("reconcile removal");
        let (_, delta) = result.into_parts();
        self.graph
            .apply_transaction_delta(&delta)
            .expect("apply removal delta");
    }

    fn entity(&self, file: &str, name: &str) -> EntityId {
        self.graph
            .list_all_entities()
            .expect("list entities")
            .into_iter()
            .find(|entity| {
                entity.name == name
                    && entity.file_origin.as_ref().map(|f| f.0.as_str()) == Some(file)
            })
            .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
            .id
    }

    /// The file's own module surface, absent when the file declared nothing.
    ///
    /// Looked up by kind rather than by name, because a file whose package
    /// clause and whose top-level declaration share a name holds two entities
    /// the name cannot tell apart.
    fn module_surface(&self, file: &str) -> Option<EntityId> {
        self.graph
            .list_all_entities()
            .expect("list entities")
            .into_iter()
            .find(|entity| {
                entity.kind == kin_model::EntityKind::Module
                    && entity.file_origin.as_ref().map(|f| f.0.as_str()) == Some(file)
            })
            .map(|entity| entity.id)
    }

    /// Every entity the graph still holds for one file, named for an assertion
    /// that has to print what survived.
    fn entities_in(&self, file: &str) -> Vec<String> {
        let mut found: Vec<String> = self
            .graph
            .list_all_entities()
            .expect("list entities")
            .into_iter()
            .filter(|entity| entity.file_origin.as_ref().map(|f| f.0.as_str()) == Some(file))
            .map(|entity| format!("{:?} {}", entity.kind, entity.name))
            .collect();
        found.sort();
        found
    }

    fn relations_of(&self, id: EntityId) -> Vec<Relation> {
        self.graph
            .get_all_relations_for_entity(&id)
            .expect("relations for entity")
    }

    /// Every caller of `id`, the way `find_references` asks the question.
    fn callers_of(&self, id: EntityId) -> Vec<EntityId> {
        let mut callers: Vec<EntityId> = self
            .relations_of(id)
            .into_iter()
            .filter(|relation| relation.kind == RelationKind::Calls)
            .filter(|relation| relation.dst == GraphNodeId::Entity(id))
            .filter_map(|relation| relation.src.as_entity())
            .collect();
        callers.sort_by_key(|id| id.0);
        callers.dedup();
        callers
    }

    fn call_edge(&self, src: EntityId, dst: EntityId) -> Option<Relation> {
        self.relations_of(src).into_iter().find(|relation| {
            relation.kind == RelationKind::Calls
                && relation.src == GraphNodeId::Entity(src)
                && relation.dst == GraphNodeId::Entity(dst)
        })
    }

    /// The entity-rooted `Imports` edge between two entities, which is the one
    /// `find_references` can read. The artifact edge beside it hangs off no
    /// entity and answers a different question.
    fn entity_import_edge(&self, src: EntityId, dst: EntityId) -> Option<Relation> {
        self.relations_of(src).into_iter().find(|relation| {
            relation.kind == RelationKind::Imports
                && relation.src == GraphNodeId::Entity(src)
                && relation.dst == GraphNodeId::Entity(dst)
        })
    }

    /// Artifact-level import edges, resolved back to paths so the assertion can
    /// name files rather than opaque identities.
    ///
    /// Artifact edges hang off no entity, so `get_all_relations_for_entity`
    /// cannot see them; they are read by walking out of each artifact node.
    fn artifact_imports(&self) -> Vec<(String, String)> {
        let ids: Vec<(String, ArtifactId)> = self
            .committed
            .iter()
            .filter_map(|path| {
                let repo_path = RepoPath::from_utf8(path.clone()).ok()?;
                let id = self.graph.artifact_id_at_path(&repo_path)?;
                Some((path.clone(), id))
            })
            .collect();
        let path_of = |id: ArtifactId| -> Option<String> {
            ids.iter()
                .find(|(_, candidate)| *candidate == id)
                .map(|(path, _)| path.clone())
        };

        let mut edges: Vec<(String, String)> = Vec::new();
        for (path, id) in &ids {
            let node = GraphNodeId::Artifact(*id);
            let sub = self
                .graph
                .traverse(&node, &[RelationKind::Imports, RelationKind::Includes], 1)
                .expect("traverse artifact node");
            for relation in sub.relations {
                if relation.src != node {
                    continue;
                }
                if let GraphNodeId::Artifact(dst) = relation.dst {
                    if let Some(dst) = path_of(dst) {
                        edges.push((path.clone(), dst));
                    }
                }
            }
        }
        edges.sort();
        edges.dedup();
        edges
    }

    fn cross_file_call_count(&self) -> usize {
        let entities = self.graph.list_all_entities().expect("list entities");
        let file_of = |id: EntityId| -> Option<String> {
            entities
                .iter()
                .find(|entity| entity.id == id)
                .and_then(|entity| entity.file_origin.as_ref())
                .map(|file| file.0.clone())
        };
        let mut seen: Vec<(EntityId, EntityId)> = Vec::new();
        for entity in &entities {
            for relation in self.relations_of(entity.id) {
                if relation.kind != RelationKind::Calls {
                    continue;
                }
                let (Some(src), Some(dst)) = (relation.src.as_entity(), relation.dst.as_entity())
                else {
                    continue;
                };
                if file_of(src) == file_of(dst) {
                    continue;
                }
                if !seen.contains(&(src, dst)) {
                    seen.push((src, dst));
                }
            }
        }
        seen.len()
    }
}

fn go_receiver_owners(repo: &LiveRepo, method: EntityId) -> Vec<EntityId> {
    let mut owners: Vec<_> = repo
        .relations_of(method)
        .iter()
        .filter(|r| r.kind == RelationKind::Contains && r.dst.as_entity() == Some(method))
        .filter_map(|r| r.src.as_entity())
        .collect();
    owners.sort();
    owners.dedup();
    owners
}

#[test]
fn go_cross_file_receiver_owner_follows_type_edits_with_method_unchanged() {
    for type_first in [false, true] {
        let mut repo = LiveRepo::new();
        let files = [
            ("api/type.go", "package api\ntype Issue struct{}\n"),
            (
                "api/export.go",
                "package api\nfunc (i *Issue) ExportData() {}\n",
            ),
        ];
        for index in if type_first { [0, 1] } else { [1, 0] } {
            repo.commit(files[index].0, files[index].1);
        }
        let method = repo.entity("api/export.go", "Issue.ExportData");
        assert_eq!(
            go_receiver_owners(&repo, method),
            vec![repo.entity("api/type.go", "Issue")]
        );

        // A process restart must recover the receiver dependency from admitted
        // bytes, even after it was successfully bound on the previous pass.
        repo.reconciler = Reconciler::new(repo.dir.path().to_path_buf());
        repo.reconciler
            .seed_cross_file_linker_from_graph(&repo.graph);
        repo.commit("api/type.go", "package api\ntype Renamed struct{}\n");
        assert!(go_receiver_owners(&repo, method).is_empty());
        repo.commit(
            "api/type.go",
            "package api\ntype Issue struct{ Number int }\n",
        );
        assert_eq!(
            go_receiver_owners(&repo, method),
            vec![repo.entity("api/type.go", "Issue")]
        );
        repo.remove("api/type.go");
        assert!(go_receiver_owners(&repo, method).is_empty());
        repo.commit("other/type.go", "package api\ntype Issue struct{}\n");
        repo.commit(
            "api/type_test.go",
            "package api_test\ntype Issue struct{}\n",
        );
        assert!(go_receiver_owners(&repo, method).is_empty());
        assert_eq!(repo.entity("api/export.go", "Issue.ExportData"), method);
        assert_eq!(
            std::fs::read_to_string(repo.abs("api/export.go")).unwrap(),
            files[1].1
        );
    }
}

#[test]
fn go_cross_file_receiver_owner_withdraws_when_a_competing_type_is_admitted() {
    let mut repo = LiveRepo::new();
    repo.commit("api/type.go", "package api\ntype Issue struct{}\n");
    repo.commit(
        "api/export.go",
        "package api\nfunc (i *Issue) ExportData() {}\n",
    );
    let method = repo.entity("api/export.go", "Issue.ExportData");
    assert_eq!(
        go_receiver_owners(&repo, method),
        vec![repo.entity("api/type.go", "Issue")]
    );
    repo.commit("api/duplicate.go", "package api\ntype Issue struct{}\n");
    assert!(
        go_receiver_owners(&repo, method).is_empty(),
        "two declarations cannot pick whichever type the method linked to first"
    );
    repo.remove("api/duplicate.go");
    assert_eq!(
        go_receiver_owners(&repo, method),
        vec![repo.entity("api/type.go", "Issue")],
        "removing the competing type restores the only remaining owner"
    );
    assert_eq!(repo.entity("api/export.go", "Issue.ExportData"), method);
    assert_eq!(
        std::fs::read_to_string(repo.abs("api/export.go")).unwrap(),
        "package api\nfunc (i *Issue) ExportData() {}\n"
    );
}

#[test]
fn go_cross_file_receiver_owner_incomplete_method_cannot_withdraw_last_good_owner() {
    let mut repo = LiveRepo::new();
    repo.commit("api/type.go", "package api\ntype Issue struct{}\n");
    repo.commit(
        "api/export.go",
        "package api\nfunc (i *Issue) ExportData() {}\n",
    );
    let method = repo.entity("api/export.go", "Issue.ExportData");
    let owner = repo.entity("api/type.go", "Issue");
    repo.commit(
        "api/export.go",
        "package api\nfunc (i *Issue) ExportData() {\n",
    );
    assert_eq!(go_receiver_owners(&repo, method), vec![owner]);
    // A valid edit of another file nominates this method again, but its
    // incomplete admitted bytes cannot authorize withdrawing last-good edges.
    repo.commit("api/duplicate.go", "package api\ntype Issue struct{}\n");
    assert_eq!(go_receiver_owners(&repo, method), vec![owner]);
    repo.remove("api/duplicate.go");
    assert_eq!(go_receiver_owners(&repo, method), vec![owner]);
}

#[test]
fn go_receiver_removal_keeps_held_parser_identity_and_foreign_evidence() {
    let mut repo = LiveRepo::new();
    let source = "package api\ntype Issue struct{}\nfunc (i Issue) ExportData() {}\n";
    repo.commit("api/export.go", source);
    repo.commit("other/type.go", "package other\ntype Issue struct{}\n");
    repo.commit(
        "unrelated.py",
        "class Issue:\n    def ExportData(self):\n        pass\n",
    );
    let method = repo.entity("api/export.go", "Issue.ExportData");
    let owner = repo.entity("api/export.go", "Issue");
    let mut held: Vec<_> = repo
        .relations_of(method)
        .into_iter()
        .filter(|relation| {
            relation.kind == RelationKind::Contains && relation.dst.as_entity() == Some(method)
        })
        .collect();
    assert_eq!(held.len(), 1);
    let mut parsed = held.remove(0);
    assert_eq!(
        parsed.id,
        kin_model::RelationId::from_content(&owner.to_string(), &method.to_string(), "Contains"),
        "fixture holds the actual pipeline identity"
    );

    // Establish the real alternate producer identity, without inventing one.
    let indexed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(
            &kin_model::FilePathId::new("api/export.go"),
            source.as_bytes(),
            kin_blobs::digest(source.as_bytes()),
        )
        .unwrap()
        .indexed_file;
    let linked = kin_index::link_cross_file(
        &[kin_index::FileParseData {
            file_path: "api/export.go".into(),
            entities: indexed.entities,
            relations: indexed.extracted_relations,
            imports: indexed.imports,
        }],
        &std::collections::HashMap::from([("api/export.go".to_owned(), ArtifactId::new())]),
    )
    .unwrap();
    let alternate = linked
        .iter()
        .find(|relation| {
            relation.kind == RelationKind::Contains
                && relation.src.as_entity() == Some(owner)
                && relation.dst.as_entity() == Some(method)
        })
        .unwrap();
    assert_ne!(
        parsed.id, alternate.id,
        "the real pipeline and linker identities differ"
    );

    parsed.created_in = Some(kin_model::SemanticChangeId(Hash256::from_bytes([7; 32])));
    repo.graph.upsert_relation(&parsed).unwrap();
    let mut expected = vec![parsed.clone()];
    for origin in [
        kin_model::RelationOrigin::Manual,
        kin_model::RelationOrigin::Lsp,
    ] {
        let mut foreign = parsed.clone();
        foreign.id = kin_model::RelationId::new();
        foreign.origin = origin;
        repo.graph.upsert_relation(&foreign).unwrap();
        expected.push(foreign);
    }
    expected.sort_by_key(|relation| relation.id);
    let python_owner = repo.entity("unrelated.py", "Issue");
    let mut python_before = repo.relations_of(python_owner);
    python_before.sort_by_key(|relation| relation.id);

    repo.remove("other/type.go");
    let mut actual: Vec<_> = repo
        .relations_of(method)
        .into_iter()
        .filter(|relation| {
            relation.kind == RelationKind::Contains && relation.dst.as_entity() == Some(method)
        })
        .collect();
    actual.sort_by_key(|relation| relation.id);
    assert_eq!(
        actual, expected,
        "unrelated removal must retain the parser identity and all foreign evidence exactly"
    );
    let mut python_after = repo.relations_of(python_owner);
    python_after.sort_by_key(|relation| relation.id);
    assert_eq!(
        python_after, python_before,
        "non-Go ownership is unaffected"
    );
    assert_eq!(
        std::fs::read_to_string(repo.abs("api/export.go")).unwrap(),
        source
    );
}

#[test]
fn go_cross_file_receiver_owner_does_not_publish_a_local_type_when_ambiguous() {
    let mut repo = LiveRepo::new();
    repo.commit("api/duplicate.go", "package api\ntype Issue struct{}\n");
    repo.commit(
        "api/export.go",
        "package api\ntype Issue struct{}\nfunc (i *Issue) ExportData() {}\n",
    );
    let method = repo.entity("api/export.go", "Issue.ExportData");
    assert!(
        go_receiver_owners(&repo, method).is_empty(),
        "the per-file parse must not bypass the complete package's refusal"
    );
}

const PARSING: &str = "def parse_note(raw):\n    return {\"raw\": raw}\n";

const STORAGE: &str = "from parsing import parse_note\n\n\
                       def save_note(raw):\n    return parse_note(raw)\n";

const API: &str = "from storage import save_note\n\n\
                   def handle(raw):\n    return save_note(raw)\n";

/// Confidence the linker records when a call resolves through the importing
/// file's own import declaration. Asserting the tier, not merely the edge,
/// keeps this falsifiable: the blind cross-file name fallback reaches the same
/// entity at 0.7 in a single-definition fixture, so an edge alone cannot tell
/// import resolution apart from a lucky name match. An incrementally linked
/// edge must be indistinguishable in kind from a batch-linked one.
const IMPORT_RESOLVED_CONFIDENCE: f32 = 0.95;

fn assert_chain_is_linked(repo: &LiveRepo) {
    let parse_note = repo.entity("parsing.py", "parse_note");
    let save_note = repo.entity("storage.py", "save_note");
    let handle = repo.entity("api.py", "handle");

    let storage_call = repo
        .call_edge(save_note, parse_note)
        .expect("storage.save_note must call parsing.parse_note across the file boundary");
    let api_call = repo
        .call_edge(handle, save_note)
        .expect("api.handle must call storage.save_note across the file boundary");

    assert_eq!(
        storage_call.confidence, IMPORT_RESOLVED_CONFIDENCE,
        "an incrementally linked import-bound call must carry the import tier, \
         not the blind name-match tier"
    );
    assert_eq!(
        api_call.confidence, IMPORT_RESOLVED_CONFIDENCE,
        "an incrementally linked import-bound call must carry the import tier, \
         not the blind name-match tier"
    );

    assert_eq!(
        repo.callers_of(parse_note),
        vec![save_note],
        "find_references on parse_note must reach its caller in another file"
    );
    assert_eq!(
        repo.callers_of(save_note),
        vec![handle],
        "find_references on save_note must reach its caller in another file"
    );

    let imports = repo.artifact_imports();
    assert!(
        imports.contains(&("storage.py".to_string(), "parsing.py".to_string())),
        "storage.py must hold an artifact Imports edge to parsing.py; got {imports:?}"
    );
    assert!(
        imports.contains(&("api.py".to_string(), "storage.py".to_string())),
        "api.py must hold an artifact Imports edge to storage.py; got {imports:?}"
    );
}

#[test]
fn three_modules_written_callee_first_end_up_cross_linked() {
    let mut repo = LiveRepo::new();
    repo.commit("parsing.py", PARSING);
    repo.commit("storage.py", STORAGE);
    repo.commit("api.py", API);
    assert_chain_is_linked(&repo);
}

#[test]
fn three_modules_written_caller_first_end_up_cross_linked() {
    // The order that matters. Every destination is missing when its referring
    // file is indexed, so every edge here exists only because a later arrival
    // re-bound an earlier file's unresolved reference.
    let mut repo = LiveRepo::new();
    repo.commit("api.py", API);
    repo.commit("storage.py", STORAGE);
    repo.commit("parsing.py", PARSING);
    assert_chain_is_linked(&repo);
}

#[test]
fn a_middle_module_arriving_last_binds_both_of_its_neighbours() {
    // Neither end can bind until the middle exists: api waits on save_note and
    // storage waits on parse_note, and one arrival has to satisfy both.
    let mut repo = LiveRepo::new();
    repo.commit("api.py", API);
    repo.commit("parsing.py", PARSING);
    repo.commit("storage.py", STORAGE);
    assert_chain_is_linked(&repo);
}

#[test]
fn a_trace_crosses_a_file_boundary() {
    let mut repo = LiveRepo::new();
    repo.commit("api.py", API);
    repo.commit("storage.py", STORAGE);
    repo.commit("parsing.py", PARSING);

    // What `trace_data_flow` walks: expand outward from the entry point and
    // require the walk to leave the file it started in.
    let handle = repo.entity("api.py", "handle");
    let reached = repo
        .graph
        .expand_neighborhood(&[handle], &[RelationKind::Calls], 3)
        .expect("expand neighborhood");
    let files: Vec<String> = reached
        .entities
        .values()
        .filter_map(|entity| entity.file_origin.as_ref().map(|file| file.0.clone()))
        .collect();
    assert!(
        files.contains(&"storage.py".to_string()) && files.contains(&"parsing.py".to_string()),
        "a call walk from api.handle must reach both other modules; reached {files:?}"
    );
}

#[test]
fn deleting_a_call_site_removes_only_that_edge() {
    let mut repo = LiveRepo::new();
    repo.commit("parsing.py", PARSING);
    repo.commit("storage.py", STORAGE);
    repo.commit("api.py", API);

    let parse_note = repo.entity("parsing.py", "parse_note");
    let save_note = repo.entity("storage.py", "save_note");
    let handle = repo.entity("api.py", "handle");
    assert!(repo.call_edge(save_note, parse_note).is_some());
    assert!(repo.call_edge(handle, save_note).is_some());

    // Drop the call site in storage.py, keeping the import and the function.
    repo.commit(
        "storage.py",
        "from parsing import parse_note\n\n\
         def save_note(raw):\n    return raw\n",
    );

    let save_note = repo.entity("storage.py", "save_note");
    assert!(
        repo.call_edge(save_note, parse_note).is_none(),
        "the deleted call site's cross-file edge must be retired"
    );
    assert!(
        repo.call_edge(handle, save_note).is_some(),
        "an edge this reconcile did not author and did not contradict must survive"
    );
    let imports = repo.artifact_imports();
    assert!(
        imports.contains(&("storage.py".to_string(), "parsing.py".to_string())),
        "the import declaration is still there, so its artifact edge stays; got {imports:?}"
    );
}

#[test]
fn moving_a_cross_file_call_into_a_wrapper_retires_its_former_source() {
    let mut repo = LiveRepo::new();
    repo.commit("parsing.py", PARSING);
    repo.commit("storage.py", STORAGE);
    let callee = repo.entity("parsing.py", "parse_note");
    let original = repo.entity("storage.py", "save_note");
    assert!(repo.call_edge(original, callee).is_some());

    repo.commit(
        "storage.py",
        "from parsing import parse_note\n\n\
         def save_note(raw):\n    return _validate(raw)\n\n\
         def _validate(raw):\n    return parse_note(raw)\n",
    );
    assert_eq!(repo.entity("storage.py", "save_note"), original);
    let wrapper = repo.entity("storage.py", "_validate");
    assert!(repo.call_edge(original, wrapper).is_some());
    assert_eq!(
        repo.callers_of(callee),
        vec![wrapper],
        "the wrapper's reference cannot preserve a removed call from another entity"
    );
}

#[test]
fn requests_shaped_wrapper_retires_only_its_old_direct_call() {
    let mut repo = LiveRepo::new();
    repo.commit(
        "utils.py",
        "def check_header_validity(header):\n    return header\n",
    );
    let original_source = "from utils import check_header_validity\n\nclass PreparedRequest:\n    def prepare_headers(self, headers):\n        for header in headers.items():\n            check_header_validity(header)\n\n    def other(self, dispatch):\n        return dispatch['dynamic']()\n\nAT_MODULE = object()\n";
    repo.commit("models.py", original_source);
    let caller = repo.entity("models.py", "PreparedRequest.prepare_headers");
    let target = repo.entity("utils.py", "check_header_validity");
    assert!(repo.call_edge(caller, target).is_some());
    let changed = original_source.replace(
        "            check_header_validity(header)",
        "            _wrapper(header)",
    ) + "\ndef _wrapper(header):\n    return check_header_validity(header)\n";
    repo.commit("models.py", &changed);
    assert_eq!(
        repo.entity("models.py", "PreparedRequest.prepare_headers"),
        caller
    );
    let wrapper = repo.entity("models.py", "_wrapper");
    assert!(repo.call_edge(caller, wrapper).is_some());
    assert_eq!(repo.callers_of(target), vec![wrapper]);
    repo.commit("models.py", original_source);
    assert_eq!(repo.callers_of(target), vec![caller]);
}

#[test]
fn deleting_the_import_retires_its_artifact_edge() {
    let mut repo = LiveRepo::new();
    repo.commit("parsing.py", PARSING);
    repo.commit("storage.py", STORAGE);
    assert!(repo
        .artifact_imports()
        .contains(&("storage.py".to_string(), "parsing.py".to_string())));

    repo.commit("storage.py", "def save_note(raw):\n    return raw\n");
    assert!(
        !repo
            .artifact_imports()
            .contains(&("storage.py".to_string(), "parsing.py".to_string())),
        "an artifact import edge this process authored must be retired once the \
         declaration is gone"
    );
}

#[test]
fn an_edge_this_reconcile_did_not_author_survives_an_unrelated_edit() {
    let mut repo = LiveRepo::new();
    repo.commit("parsing.py", PARSING);
    repo.commit("storage.py", STORAGE);

    let parse_note = repo.entity("parsing.py", "parse_note");
    let save_note = repo.entity("storage.py", "save_note");
    assert!(repo.call_edge(save_note, parse_note).is_some());

    // Edit the callee's file. Nothing in parsing.py sources the cross-file
    // edge, so the reconcile of parsing.py has no authority over it.
    repo.commit(
        "parsing.py",
        "def parse_note(raw):\n    return {\"raw\": raw, \"len\": len(raw)}\n",
    );

    let parse_note = repo.entity("parsing.py", "parse_note");
    assert_eq!(
        repo.callers_of(parse_note),
        vec![save_note],
        "reconciling the destination's own file must not retire an edge it does not source"
    );
}

#[test]
fn removing_the_destination_file_retires_its_edges_and_a_replacement_rebinds() {
    let mut repo = LiveRepo::new();
    repo.commit("parsing.py", PARSING);
    repo.commit("storage.py", STORAGE);
    let save_note = repo.entity("storage.py", "save_note");
    assert_eq!(repo.cross_file_call_count(), 1);

    repo.remove("parsing.py");
    assert_eq!(
        repo.cross_file_call_count(),
        0,
        "removing the destination file must take its edges with it"
    );

    // Re-creating the destination and touching the importer must bind again.
    // The importer is touched on purpose and the assertion is written to match:
    // deleting a destination does not put its dependents back on the waiting
    // index, so the destination's return alone does not rebind them. The report
    // states that limit.
    repo.commit("parsing.py", PARSING);
    repo.commit("storage.py", STORAGE);
    let parse_note = repo.entity("parsing.py", "parse_note");
    let save_note_again = repo.entity("storage.py", "save_note");
    assert_eq!(save_note_again, save_note);
    assert!(
        repo.call_edge(save_note_again, parse_note).is_some(),
        "a re-created destination must bind again"
    );
}

#[test]
fn a_third_party_import_names_an_external_boundary_without_a_local_definition() {
    let mut repo = LiveRepo::new();
    repo.commit(
        "client.py",
        "from requests import get\n\ndef fetch(url):\n    return get(url)\n",
    );
    let fetch = repo.entity("client.py", "fetch");
    let edges: Vec<_> = repo
        .relations_of(fetch)
        .into_iter()
        .filter(kin_index::is_external_import_placeholder)
        .collect();
    assert_eq!(
        edges.len(),
        1,
        "the imported symbol has an explicit external boundary"
    );
    assert_eq!(edges[0].import_source.as_deref(), Some("requests"));
    assert_eq!(
        kin_index::RelationResolution::of(&edges[0]),
        kin_index::RelationResolution::NameOnly
    );
    let target = repo
        .graph
        .get_entity(&edges[0].dst.as_entity().unwrap())
        .unwrap()
        .unwrap();
    assert!(kin_index::is_external_reference_target(&target));
    assert!(target.file_origin.is_none() && target.signature.is_empty());
    assert!(
        repo.artifact_imports().is_empty(),
        "a third-party module path resolves to no repository file"
    );
}

#[test]
fn resolving_one_file_does_not_touch_the_repository() {
    // The cost bound, asserted rather than asserted about: a write resolves the
    // edited file plus the files waiting on a name it defines. Nothing here
    // makes that set grow with repository size.
    let mut repo = LiveRepo::new();
    const FILLER: usize = 12;
    for index in 0..FILLER {
        repo.commit(
            &format!("unrelated_{index}.py"),
            &format!("def unrelated_{index}():\n    return {index}\n"),
        );
        assert_eq!(
            repo.last_files_resolved, 1,
            "a file nothing waits on resolves only itself"
        );
    }

    repo.commit("storage.py", STORAGE);
    assert_eq!(
        repo.last_files_resolved, 1,
        "a file whose destination does not exist yet still resolves only itself"
    );

    repo.commit("parsing.py", PARSING);
    assert_eq!(
        repo.last_files_resolved,
        2,
        "the arrival that unblocks storage.py resolves itself plus that one file, \
         not the {} files in the repository",
        FILLER + 2
    );
    assert!(
        repo.last_files_resolved < FILLER,
        "per-write cost must not scale with repository size"
    );
}

#[test]
fn a_repository_written_one_file_at_a_time_reports_cross_file_relations() {
    // The isolation container's exact shape, stated as one assertion.
    let mut repo = LiveRepo::new();
    repo.commit("api.py", API);
    repo.commit("storage.py", STORAGE);
    repo.commit("parsing.py", PARSING);

    assert_eq!(
        repo.cross_file_call_count(),
        2,
        "a three-module chain written one file at a time holds two cross-file Calls"
    );
    assert_eq!(
        repo.artifact_imports().len(),
        2,
        "and two artifact Imports edges"
    );
}

#[test]
fn derived_member_candidates_and_generator_evidence_survive_live_edit_and_reopen() {
    use kin_model::derivation::generator_relation_matches;
    let mut repo = LiveRepo::new();
    let source =
        "export const app = {}; for (const key of ['get','post']) { app[key] = () => {}; }";
    repo.commit("members.js", source);
    repo.commit(
        "caller.js",
        "import { app } from './members'; export function run() { app.get(); }",
    );
    let verify = |repo: &LiveRepo| {
        let id = repo.entity("members.js", "app.get");
        let member = repo.graph.get_entity(&id).unwrap().unwrap();
        assert!(member.span.is_none());
        let artifact = repo
            .graph
            .artifact_id_at_path(&RepoPath::from_utf8("members.js").unwrap())
            .unwrap();
        let hash = match repo
            .graph
            .get_tree_entry(&kin_model::FilePathId::new("members.js"))
            .unwrap()
            .unwrap()
        {
            TreeEntry::Blob { hash, .. } => hash.to_string(),
            _ => panic!("blob"),
        };
        let edges = repo
            .graph
            .traverse(&GraphNodeId::Entity(id), &[], 1)
            .unwrap()
            .relations;
        assert!(
            edges
                .iter()
                .any(|r| generator_relation_matches(&member, r, artifact, &hash)),
            "{edges:?}"
        );
        let calls: Vec<_> = edges
            .iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .collect();
        assert!(!calls.is_empty(), "candidate remains useful to callers");
        assert!(calls.iter().all(
            |r| kin_index::RelationResolution::of(r) == kin_index::RelationResolution::NameOnly
        ));
        assert!(kin_model::require_independent_source(&member).is_err());
        id
    };
    let previous = verify(&repo);
    // Restored graph + fresh linker seed, then caller-only edit.
    repo.graph = InMemoryGraph::from_snapshot_without_text_index(repo.graph.to_snapshot()).unwrap();
    repo.reconciler = Reconciler::new(repo.dir.path().to_path_buf());
    repo.reconciler
        .seed_cross_file_linker_from_graph(&repo.graph);
    repo.commit(
        "caller.js",
        "import { app } from './members'; export function run() { app.get(); app.post(); }",
    );
    verify(&repo);
    // Generator-only source movement and new RHS; provenance must bind new bytes.
    repo.commit(
        "members.js",
        &format!(
            "// moved generator\n{}",
            source.replace("() => {}", "() => 1")
        ),
    );
    verify(&repo);
    repo.commit(
        "members.js",
        "export const app = {}; app.ready = () => true;",
    );
    assert!(repo.graph.get_entity(&previous).unwrap().is_none());
    assert!(!repo
        .graph
        .list_all_entities()
        .unwrap()
        .iter()
        .any(|e| e.name == "app.get"));
}

#[test]
fn derived_member_file_removal_collects_generator_edges_and_projection_refuses_metadata_stripping()
{
    let mut repo = LiveRepo::new();
    repo.commit(
        "members.js",
        "export const app={}; for(const key of ['get']) { app[key]=()=>1; }",
    );
    let candidate = repo
        .graph
        .get_entity(&repo.entity("members.js", "app.get"))
        .unwrap()
        .unwrap();
    let mut stripped = candidate.clone();
    stripped.metadata.extra.clear();
    let delta = TransactionDelta {
        entity_deltas: vec![kin_model::EntityDelta::Modified {
            old: candidate.clone(),
            new: stripped,
        }],
        ..Default::default()
    };
    let error = repo
        .reconciler
        .project_transaction_to_files(
            &delta,
            &std::collections::HashMap::from([(candidate.id, b"() => 2".to_vec())]),
        )
        .unwrap_err();
    assert!(error.to_string().contains("generator"), "{error}");
    repo.remove("members.js");
    assert!(repo.graph.get_entity(&candidate.id).unwrap().is_none());
    assert!(repo
        .graph
        .traverse(&GraphNodeId::Entity(candidate.id), &[], 1)
        .unwrap()
        .relations
        .is_empty());
}

/// A Python base written `module.Class` has to be decided by the import the
/// declaring file wrote, on this path as much as on a cold index. A class
/// merely sharing the base's leaf name in the SAME file used to outrank it, and
/// the resulting `Overrides` edge was minted at full parser confidence onto the
/// wrong class.
///
/// Commit order is the hard direction on purpose: the subclass is written
/// before the module it imports, so the base binding has to survive until the
/// base file arrives.
#[test]
fn a_qualified_python_base_resolves_through_the_import_on_the_live_path() {
    let mut repo = LiveRepo::new();
    repo.commit(
        "pkg/rows.py",
        "import pkg.models as models\n\n\nclass Model:\n    def save(self):\n        return 'decoy'\n\n\nclass Row(models.Model):\n    def save(self):\n        return 'row'\n",
    );
    repo.commit(
        "pkg/models.py",
        "class Model:\n    def save(self):\n        return 'real'\n",
    );
    // The subclass is relinked once its base exists, which is the step where
    // the binding is read back.
    repo.commit(
        "pkg/rows.py",
        "import pkg.models as models\n\n\nclass Model:\n    def save(self):\n        return 'decoy'\n\n\nclass Row(models.Model):\n    def save(self):\n        return 'row'\n",
    );

    let row_save = repo.entity("pkg/rows.py", "Row.save");
    let real_save = repo.entity("pkg/models.py", "Model.save");
    let decoy_save = repo.entity("pkg/rows.py", "Model.save");

    let overrides: Vec<Relation> = repo
        .relations_of(row_save)
        .into_iter()
        .filter(|relation| {
            relation.kind == RelationKind::Overrides
                && relation.src == GraphNodeId::Entity(row_save)
        })
        .collect();
    assert!(
        overrides
            .iter()
            .any(|relation| relation.dst == GraphNodeId::Entity(real_save)),
        "the live path must reach the `Model` the import named: {overrides:#?}"
    );
    assert!(
        !overrides
            .iter()
            .any(|relation| relation.dst == GraphNodeId::Entity(decoy_save)),
        "and must not reach the same-file class that only shares its leaf name: {overrides:#?}"
    );
}

/// A base a third-party module owns reaches the linker's external-import
/// placeholder, whose destination is deliberately absent from this repository's
/// entity set. The live path publishes no half-bound endpoint: it withholds the
/// edge the same way it withholds an external call or reference, rather than
/// admitting an edge into a node the graph does not hold.
///
/// This is the documented divergence between the batch path, which binds the
/// placeholder target in the same transaction, and this one. It is asserted
/// here so the divergence is a stated contract rather than something a reader
/// discovers from a missing row.
#[test]
fn an_external_python_base_is_withheld_rather_than_half_bound_on_the_live_path() {
    let mut repo = LiveRepo::new();
    repo.commit(
        "pkg/cli.py",
        "from click import Group\n\n\nclass AppGroup(Group):\n    def get_command(self, ctx, name):\n        return None\n",
    );

    let get_command = repo.entity("pkg/cli.py", "AppGroup.get_command");
    let published: Vec<Relation> = repo
        .relations_of(get_command)
        .into_iter()
        .filter(|relation| relation.kind == RelationKind::Overrides)
        .collect();
    assert!(
        published.is_empty(),
        "an unbound external endpoint must not be published: {published:#?}"
    );

    // Nothing was published, so nothing dangles: every relation this repository
    // holds names endpoints it also holds.
    let known: Vec<EntityId> = repo
        .graph
        .list_all_entities()
        .expect("list entities")
        .into_iter()
        .map(|entity| entity.id)
        .collect();
    for entity_id in &known {
        for relation in repo.relations_of(*entity_id) {
            if let Some(dst) = relation.dst.as_entity() {
                assert!(
                    known.contains(&dst),
                    "relation {:?} names a destination the graph does not hold",
                    relation.id
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entity-level import edges, on the live path
// ---------------------------------------------------------------------------

const GO_STORE_LIVE: &str = "package store\n\nfunc Open() int {\n\treturn 1\n}\n";

const GO_MAIN_LIVE: &str = "package main\n\nimport \"example.com/app/internal/store\"\n\n\
                            func Run() int {\n\treturn store.Open()\n}\n";

const RUST_STORE_LIVE: &str = "pub struct Store;\n\npub fn open() -> usize {\n    1\n}\n";

const RUST_APP_LIVE: &str = "use crate::store::Store;\n\npub fn run(_: Store) -> usize {\n    \
                             crate::store::open()\n}\n";

/// The easy write order: the imported package exists before the file that
/// imports it.
///
/// Go minted no entity-level import edge at all before this, so `find_references`
/// on a Go package had nothing to walk. The daemon path has to mint it too, or
/// a repository that grew one file at a time holds what a cold `kin init` would
/// not.
#[test]
fn a_go_package_import_reaches_the_package_entity_on_the_live_path() {
    let mut repo = LiveRepo::new();
    repo.commit("internal/store/store.go", GO_STORE_LIVE);
    repo.commit("cmd/app/main.go", GO_MAIN_LIVE);

    let importer = repo.entity("cmd/app/main.go", "main");
    let package = repo.entity("internal/store/store.go", "store");
    let edge = repo
        .entity_import_edge(importer, package)
        .unwrap_or_else(|| {
            panic!(
                "no entity-level Imports edge from the importing file's module surface to the \
                 package it named; relations = {:?}",
                repo.relations_of(importer)
                    .iter()
                    .map(|relation| (relation.kind, relation.dst))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        kin_index::RelationResolution::of(&edge).as_str(),
        "import_scoped",
        "a package representative is a settled scope, not a proven destination"
    );
    // The artifact edge is unaffected and still answers "which file imports
    // which file". Both exist; neither stands in for the other.
    assert!(
        repo.artifact_imports().contains(&(
            "cmd/app/main.go".to_string(),
            "internal/store/store.go".to_string()
        )),
        "the artifact edge must survive beside the entity one: {:?}",
        repo.artifact_imports()
    );
}

/// The hard write order: the importing file is committed before the module it
/// names exists.
///
/// This is the direction a real build takes, because the module you are working
/// in usually exists before the one it will reach for. A linker that binds
/// imports only at the importer's own commit leaves the edge missing forever.
#[test]
fn a_rust_use_reaches_its_module_when_the_importer_is_committed_first() {
    let mut repo = LiveRepo::new();
    repo.commit("src/app.rs", RUST_APP_LIVE);
    repo.commit("src/store.rs", RUST_STORE_LIVE);
    // Re-committing the importer is what the daemon does when a dependency
    // lands: the watch loop reconciles the file whose unresolved import now has
    // a destination. Without it this case would be asserting that a commit of
    // one file rewrites another file's edges, which the live path does not do.
    repo.commit("src/app.rs", RUST_APP_LIVE);

    let importer = repo.entity("src/app.rs", "app");
    let imported = repo.entity("src/store.rs", "Store");
    let edge = repo
        .entity_import_edge(importer, imported)
        .unwrap_or_else(|| {
            panic!(
                "no entity-level Imports edge from `src/app.rs`'s module surface to `Store`; \
                 relations = {:?}",
                repo.relations_of(importer)
                    .iter()
                    .map(|relation| (relation.kind, relation.dst))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        kin_index::RelationResolution::of(&edge).as_str(),
        "import_scoped"
    );
}

/// An import of a crate this repository does not hold mints nothing on the live
/// path either, and mints nothing dangling in particular.
///
/// The live path withholds an edge whose endpoint the graph does not hold, the
/// same way it already withholds an external call. This walks every relation in
/// the store afterwards to show nothing dangles, because a dangling endpoint is
/// what admission fails closed on.
#[test]
fn a_rust_use_of_a_crate_outside_the_repository_leaves_no_dangling_edge() {
    let mut repo = LiveRepo::new();
    repo.commit(
        "src/app.rs",
        "use serde::Deserialize;\n\npub fn run() -> usize {\n    1\n}\n",
    );

    let known: Vec<EntityId> = repo
        .graph
        .list_all_entities()
        .expect("list entities")
        .into_iter()
        .map(|entity| entity.id)
        .collect();
    for id in &known {
        for relation in repo.relations_of(*id) {
            if let Some(dst) = relation.dst.as_entity() {
                assert!(
                    known.contains(&dst),
                    "relation {:?} names a destination the store does not hold",
                    relation.kind
                );
            }
            if let Some(src) = relation.src.as_entity() {
                assert!(
                    known.contains(&src),
                    "relation {:?} is sourced at an entity the store does not hold",
                    relation.kind
                );
            }
        }
    }
}

/// A file that stops declaring anything retires its module surface, and the
/// entity-level import edge sourced there goes with it.
///
/// The surface is minted only for a file that produced a declaration or an
/// import, so an edit that empties a file has to remove it rather than leave a
/// module standing for bytes that declare nothing. Nothing else in this suite
/// drives a file from entities to zero, and a surface that survived would keep
/// answering "who imports this" from a file that imports nothing.
#[test]
fn emptying_a_file_retires_its_module_surface_and_the_edge_it_sourced() {
    let mut repo = LiveRepo::new();
    repo.commit("internal/store/store.go", GO_STORE_LIVE);
    repo.commit("cmd/app/main.go", GO_MAIN_LIVE);

    let importer = repo
        .module_surface("cmd/app/main.go")
        .expect("the importing file carries a module surface");
    let package = repo
        .module_surface("internal/store/store.go")
        .expect("the imported package carries a module surface");
    assert!(
        repo.entity_import_edge(importer, package).is_some(),
        "the case starts from a real entity-level import edge"
    );

    // The same path, holding a comment and nothing else.
    repo.commit("cmd/app/main.go", "// nothing is declared here\n");

    assert!(
        repo.module_surface("cmd/app/main.go").is_none(),
        "the module surface survived a file that declares nothing: {:?}",
        repo.entities_in("cmd/app/main.go")
    );
    assert_eq!(
        repo.entities_in("cmd/app/main.go"),
        Vec::<String>::new(),
        "an emptied file must hold no entity at all"
    );
    assert!(
        repo.entity_import_edge(importer, package).is_none(),
        "the import edge sourced at the retired module surface survived it: {:?}",
        repo.relations_of(importer)
            .iter()
            .map(|relation| (relation.kind, relation.src, relation.dst))
            .collect::<Vec<_>>()
    );
    // The destination is untouched: retiring the importer is not a reason to
    // retire what it named.
    assert!(
        repo.module_surface("internal/store/store.go").is_some(),
        "the imported package's own surface must survive the importer emptying"
    );
}
