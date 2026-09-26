// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A file edit re-derives the files that bind against it only when it changed
//! something they bind against.
//!
//! The live cross-file pass resolves the edited file and every file waiting on
//! a name it defines or importing it. Those files did not change. When the edit
//! leaves the edited file's declarations, imports and structural relations
//! exactly as they were, re-deriving them reproduces the linker's first answer
//! for each of their calls, including a name-only guess that something more
//! exact has since retired, such as a language server's answer at the call
//! site. These tests pin both halves: a body edit leaves the other files alone,
//! and an edit that changes what they bind against still re-derives them.

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

struct LiveRepo {
    dir: TempDir,
    graph: InMemoryGraph,
    blobs: BlobStore,
    reconciler: Reconciler,
}

impl LiveRepo {
    fn new() -> Self {
        let dir = TempDir::new().expect("temp repo");
        let blobs = BlobStore::new(dir.path().join("blobs")).expect("blob store");
        let graph = InMemoryGraph::new();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        reconciler.seed_cross_file_linker_from_graph(&graph);
        Self {
            dir,
            graph,
            blobs,
            reconciler,
        }
    }

    fn abs(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    /// Write, admit, reconcile and apply one file, the daemon's order. Returns
    /// how many files the cross-file pass resolved.
    fn commit(&mut self, rel: &str, source: &str) -> usize {
        let path = self.abs(rel);
        std::fs::create_dir_all(path.parent().unwrap()).expect("create parent");
        std::fs::write(&path, source).expect("write source");
        let blob_hash = self.blobs.write(source.as_bytes()).expect("store blob");
        let repo_path = RepoPath::from_utf8(rel.to_string()).expect("repo path");
        let entry = TreeEntry::blob(Hash256::from_bytes(blob_hash.0), false);
        let tree_delta = match self.graph.artifact_id_at_path(&repo_path) {
            Some(artifact_id) => {
                let old = self
                    .graph
                    .get_tree_entry(&kin_model::FilePathId::new(rel))
                    .unwrap()
                    .expect("an admitted artifact has a tree entry");
                TreeDelta::Updated {
                    artifact_id,
                    old: LocatedEntry::new(repo_path.clone(), old),
                    new: LocatedEntry::new(repo_path, entry),
                }
            }
            None => TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(repo_path, entry),
            },
        };
        self.graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![tree_delta],
                ..TransactionDelta::default()
            })
            .expect("admit artifact");
        let result = self
            .reconciler
            .reconcile_file_change(&FileEvent::Changed(path), &self.blobs, &self.graph)
            .expect("reconcile succeeds");
        let (_, delta) = result.into_parts();
        self.graph
            .apply_transaction_delta(&delta)
            .unwrap_or_else(|error| panic!("apply reconciled delta for {rel}: {error}"));
        self.reconciler.cross_file_linker().last_files_resolved()
    }

    fn entity(&self, file: &str, name: &str) -> EntityId {
        self.graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|entity| {
                entity.name == name
                    && entity.file_origin.as_ref().map(|f| f.0.as_str()) == Some(file)
            })
            .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
            .id
    }

    fn call_edge(&self, src: EntityId, dst: EntityId) -> Option<Relation> {
        self.graph
            .get_all_relations_for_entity(&src)
            .unwrap()
            .into_iter()
            .find(|relation| {
                relation.kind == RelationKind::Calls
                    && relation.src == GraphNodeId::Entity(src)
                    && relation.dst == GraphNodeId::Entity(dst)
            })
    }
}

const HELPER: &str = "export function y(): number {\n    return 1;\n}\n";
const EDITED: &str = "import { y } from \"./y\";\nexport class B {\n    remove(): number {\n        return y();\n    }\n}\n";
const OTHER: &str = "export class C {\n    remove(): number {\n        return 2;\n    }\n}\n";
/// `.remove()` on a receiver nothing types binds to both `remove` methods by
/// name alone.
const CALLER: &str = "import { y } from \"./y\";\nexport function run(target: any) {\n    return target.make().remove() + y();\n}\n";

/// The repository after `run`'s name-only guess into `C.remove` was retired,
/// the way a language server's answer at the call site retires it. Returns
/// `run`, `B.remove`, `C.remove` and the retired guess.
fn settled_repo() -> (LiveRepo, EntityId, EntityId, EntityId, Relation) {
    let mut repo = LiveRepo::new();
    repo.commit("src/y.ts", HELPER);
    repo.commit("src/b.ts", EDITED);
    repo.commit("src/c.ts", OTHER);
    repo.commit("src/a.ts", CALLER);
    let run = repo.entity("src/a.ts", "run");
    let b_remove = repo.entity("src/b.ts", "B.remove");
    let c_remove = repo.entity("src/c.ts", "C.remove");
    assert!(
        repo.call_edge(run, b_remove).is_some(),
        "the fixture needs the guess into B.remove"
    );
    let guess = repo
        .call_edge(run, c_remove)
        .expect("the fixture needs the guess into C.remove");
    assert_eq!(
        kin_index::RelationResolution::of(&guess),
        kin_index::RelationResolution::NameOnly
    );
    repo.graph
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas: vec![kin_model::RelationDelta::Removed { old: guess.clone() }],
            ..TransactionDelta::default()
        })
        .expect("retire the guess");
    (repo, run, b_remove, c_remove, guess)
}

#[test]
fn a_body_edit_resolves_only_the_edited_file_and_keeps_a_retired_guess_retired() {
    let (mut repo, run, b_remove, c_remove, _) = settled_repo();
    let resolved = repo.commit(
        "src/b.ts",
        "import { y } from \"./y\";\nexport class B {\n    remove(): number {\n        return y() + 1;\n    }\n}\n",
    );
    assert_eq!(
        resolved, 1,
        "a change inside a method body changes nothing another file binds against"
    );
    assert!(
        repo.call_edge(run, c_remove).is_none(),
        "the edit brought back a guess nothing about it invalidated"
    );
    assert!(
        repo.call_edge(run, b_remove).is_some(),
        "and it leaves the other file's edges as they were"
    );
}

#[test]
fn moving_every_declaration_down_a_line_is_still_a_body_edit() {
    let (mut repo, run, _, c_remove, _) = settled_repo();
    let resolved = repo.commit(
        "src/b.ts",
        "// a comment above everything moves every position in the file\nimport { y } from \"./y\";\nexport class B {\n    remove(): number {\n        return y();\n    }\n}\n",
    );
    assert_eq!(
        resolved, 1,
        "positions are not something another file binds against"
    );
    assert!(repo.call_edge(run, c_remove).is_none());
}

#[test]
fn a_changed_signature_still_rebinds_the_files_that_call_it() {
    let (mut repo, _, _, _, _) = settled_repo();
    let resolved = repo.commit(
        "src/b.ts",
        "import { y } from \"./y\";\nexport class B {\n    remove(force?: boolean): number {\n        return force ? y() : 0;\n    }\n}\n",
    );
    assert!(
        resolved >= 2,
        "a declaration's signature is what a caller binds against, so the caller is \
         re-derived: resolved {resolved}"
    );
}

#[test]
fn an_added_declaration_still_rebinds_the_files_waiting_on_its_name() {
    let (mut repo, _, _, _, _) = settled_repo();
    let resolved = repo.commit(
        "src/b.ts",
        "import { y } from \"./y\";\nexport class B {\n    remove(): number {\n        return y();\n    }\n}\nexport class D {\n    remove(): number {\n        return 3;\n    }\n}\n",
    );
    assert!(
        resolved >= 2,
        "a new declaration named `remove` is something `run` may now bind to: resolved {resolved}"
    );
    let run = repo.entity("src/a.ts", "run");
    let d_remove = repo.entity("src/b.ts", "D.remove");
    assert!(
        repo.call_edge(run, d_remove).is_some(),
        "the caller waiting on `remove` binds to the new one once it exists"
    );
}

#[test]
fn a_changed_import_still_rebinds_the_files_that_import_it() {
    let (mut repo, _, _, _, _) = settled_repo();
    let resolved = repo.commit(
        "src/b.ts",
        "import { y } from \"./y\";\nexport { y as helper } from \"./y\";\nexport class B {\n    remove(): number {\n        return y();\n    }\n}\n",
    );
    assert!(
        resolved >= 2,
        "a re-export changes what an importer can bind through this file: resolved {resolved}"
    );
}
