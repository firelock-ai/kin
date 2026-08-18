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
fn a_third_party_import_binds_to_nothing() {
    let mut repo = LiveRepo::new();
    repo.commit(
        "client.py",
        "from requests import get\n\ndef fetch(url):\n    return get(url)\n",
    );
    assert_eq!(
        repo.cross_file_call_count(),
        0,
        "a name no file in the repository defines must not acquire a cross-file edge"
    );
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
