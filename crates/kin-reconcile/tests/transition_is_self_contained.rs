// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A reconcile delta has to be a transition kin-db will take.
//!
//! FIR-2838. Renaming one function wedged a repository for writes. The rename
//! commit reported success in 448 ms while its own delta was refused and
//! dropped, and every later commit, including one blank line appended to
//! `README.md`, failed with HTTP 500. Two rules kin-db enforces on every
//! transaction were not enforced where the delta is built:
//!
//! * a delta may not ADD a relation identity the store already holds
//!   (`transaction adds existing relation <id>`), and
//! * a delta may not leave a relation naming an entity it removes
//!   (`transaction relation <id> has unadmitted destination endpoint
//!   entity:<id>`), which poisons every later transition until the daemon
//!   restarts.
//!
//! Both are asserted here against a real reconciler and a real graph, each with
//! the control that separates the fix from a pass that simply stopped emitting
//! things.

use std::path::PathBuf;

use kin_blobs::BlobStore;
use kin_db::InMemoryGraph;
use kin_index::FileEvent;
use kin_model::{
    ArtifactId, Entity, EntityStore, GraphNodeId, Hash256, LocatedEntry, Relation, RelationDelta,
    RelationId, RelationKind, RelationOrigin, RepoPath, TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;
use tempfile::TempDir;

const NOTES_PY: &str = r#"# Note storage.


def resolve_key(raw):
    return raw.strip().lower()


def forget_notes_outside(store, roots):
    return {k: v for k, v in store.items() if v in roots}
"#;

/// The same file with `forget_notes_outside` gone.
///
/// The ticket is a rename, and a rename reaches the graph as a removal plus an
/// addition whenever the pass cannot pair the new declaration with the old one,
/// which is what the rc061a store recorded: `added=1 modified=18 removed=1`. A
/// deletion is the same departure with none of that ambiguity, so the assertion
/// below is about the invariant rather than about which way the pairing fell.
const NOTES_PY_WITHOUT_IT: &str = r#"# Note storage.


def resolve_key(raw):
    return raw.strip().lower()
"#;

const INGEST_PY: &str = r#"# Ingest notes.

from notes import forget_notes_outside


def run_ingest(store, roots):
    return forget_notes_outside(store, roots)
"#;

/// A repository built the way a user builds one: write the file, admit its
/// artifact, reconcile, apply.
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

    /// Reconcile one file and hand back the delta WITHOUT applying it, so a
    /// test can grade what the pass produced before the store gets a say.
    fn plan(&mut self, rel: &str, source: &str) -> TransactionDelta {
        let path = self.abs(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(&path, source).expect("write source");

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
        delta
    }

    /// Plan and apply, which is what the daemon does. The store's refusal is
    /// the failure this file is about, so it is reported with the delta that
    /// earned it rather than swallowed.
    fn commit(&mut self, rel: &str, source: &str) -> TransactionDelta {
        let delta = self.plan(rel, source);
        if let Err(error) = self.graph.apply_transaction_delta(&delta) {
            panic!("kin-db refused the reconciled delta for {rel}: {error}");
        }
        delta
    }

    /// The one FUNCTION with this name.
    ///
    /// A Python file also declares a module entity carrying the file's stem, so
    /// a lookup by name alone is ambiguous for any function named after its own
    /// module. Naming the kind is what keeps the assertion about the
    /// declaration the test means.
    fn entity(&self, name: &str) -> Entity {
        let mut matches: Vec<Entity> = self
            .graph
            .list_all_entities()
            .expect("list entities")
            .into_iter()
            .filter(|entity| entity.name == name && entity.kind == kin_model::EntityKind::Function)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one entity named {name}, found {}",
            matches.len()
        );
        matches.pop().expect("checked above")
    }

    fn artifact(&self, rel: &str) -> ArtifactId {
        let repo_path = RepoPath::from_utf8(rel.to_string()).expect("repo path");
        self.graph
            .artifact_id_at_path(&repo_path)
            .unwrap_or_else(|| panic!("no admitted artifact for {rel}"))
    }

    /// Every relation the store holds at one node, of every kind and in both
    /// directions, which is the read `get_all_relations_for_entity` cannot do.
    fn relations_at(&self, node: GraphNodeId) -> Vec<Relation> {
        self.graph
            .traverse(&node, &[], 1)
            .expect("traverse node")
            .relations
            .into_iter()
            .filter(|relation| relation.src == node || relation.dst == node)
            .collect()
    }
}

/// Retiring an entity has to take the edges bound to it, including the ones
/// `get_all_relations_for_entity` cannot see.
///
/// That reader filters to entity-to-entity edges, so an edge with one
/// non-entity endpoint was invisible to the retire loop. kin-db's transaction
/// gate is not so selective: one surviving edge into a removed entity makes it
/// refuse EVERY later transition on the store, which is the repository-wide
/// write wedge a user meets as "500: unadmitted destination endpoint" on a
/// commit that touched an unrelated file.
///
/// Arm two is the control. Without it, a pass that retired every edge at every
/// node it looked at would satisfy arm one and quietly delete live enrichment.
#[test]
fn a_departing_entity_takes_its_mixed_node_edges_with_it() {
    let mut repo = LiveRepo::new();
    repo.commit("notes.py", NOTES_PY);

    let departing = repo.entity("forget_notes_outside");
    let surviving = repo.entity("resolve_key");
    let artifact = GraphNodeId::Artifact(repo.artifact("notes.py"));

    // Two edges of the shape the entity-only reader is blind to: one into the
    // entity this edit retires, one into an entity it keeps. kin-db admits both
    // writes; its transaction gate is what refuses the strand later.
    let into_departing = Relation {
        id: RelationId::new(),
        kind: RelationKind::References,
        src: artifact,
        dst: GraphNodeId::Entity(departing.id),
        confidence: 1.0,
        origin: RelationOrigin::Manual,
        created_in: None,
        import_source: None,
        evidence: Vec::new(),
    };
    let into_surviving = Relation {
        id: RelationId::new(),
        dst: GraphNodeId::Entity(surviving.id),
        ..into_departing.clone()
    };
    repo.graph
        .upsert_relation(&into_departing)
        .expect("seed the edge into the departing entity");
    repo.graph
        .upsert_relation(&into_surviving)
        .expect("seed the edge into the surviving entity");

    // The entity leaves. Pre-fix this apply is refused outright and the panic
    // names the stranded endpoint.
    let delta = repo.commit("notes.py", NOTES_PY_WITHOUT_IT);

    assert!(
        delta.relation_deltas.iter().any(|relation_delta| matches!(
            relation_delta,
            RelationDelta::Removed { old } if old.id == into_departing.id
        )),
        "the delta that removes an entity must carry the removal of the edge naming it; \
         relation deltas were {:?}",
        delta
            .relation_deltas
            .iter()
            .map(|d| d.target_id())
            .collect::<Vec<_>>()
    );
    assert!(
        repo.relations_at(GraphNodeId::Entity(departing.id))
            .is_empty(),
        "no edge may still name the retired entity, or every later commit is refused"
    );

    // Arm two, the control: the edge into the entity this edit KEPT is still
    // there. A fix that collected everything would fail here.
    assert!(
        repo.relations_at(GraphNodeId::Entity(surviving.id))
            .iter()
            .any(|relation| relation.id == into_surviving.id),
        "an edge into an entity this pass did not remove must survive it"
    );

    // And the consequence the ticket is actually about: the store still takes a
    // transition afterwards. This is the commit that returned 500.
    repo.commit(
        "unrelated.py",
        "\"\"\"Unrelated.\"\"\"\n\n\ndef untouched():\n    return 1\n",
    );
}

/// A re-derived edge whose identity the store already holds is a modification,
/// never an addition.
///
/// kin-db refuses `transaction adds existing relation <id>` and the daemon logs
/// that and drops the whole delta, so a rename's entities never land while the
/// other file's pass does: the graph then serves the old name, the new name
/// resolves to nothing, and the census reports edges lost with no entity
/// removed. The reconciler could not see the identity because
/// `existing_relations` is gathered from the entities of the file being
/// reconciled and matched by `(src, dst, kind)`, and a bucket holding only
/// non-parser-derived edges yields no identity to keep.
///
/// Arm two is the control: a genuinely new edge must still arrive as an
/// addition, so this is not satisfied by a pass that stopped adding anything.
#[test]
fn a_rederived_edge_keeps_the_identity_the_store_already_holds() {
    let mut repo = LiveRepo::new();
    repo.commit("notes.py", NOTES_PY);
    repo.commit("ingest.py", INGEST_PY);

    let caller = repo.entity("run_ingest");
    let callee = repo.entity("forget_notes_outside");
    let held = repo
        .relations_at(GraphNodeId::Entity(caller.id))
        .into_iter()
        .find(|relation| {
            relation.kind == RelationKind::Calls
                && relation.src == GraphNodeId::Entity(caller.id)
                && relation.dst == GraphNodeId::Entity(callee.id)
        })
        .expect("the cross-file call edge the linker minted");

    // Relabel that exact identity as enrichment. The pass will re-derive the
    // same edge and find no parser-derived identity to keep, which is the state
    // that produced `transaction adds existing relation` on the rc061a run.
    repo.graph
        .upsert_relation(&Relation {
            origin: RelationOrigin::Lsp,
            ..held.clone()
        })
        .expect("relabel the held edge as enrichment");

    // Touch the caller. Pre-fix its delta adds an identity the store holds and
    // kin-db refuses the whole transition, so `commit` panics here.
    let delta = repo.commit(
        "ingest.py",
        &format!("{INGEST_PY}\n\n# a trailing comment\n"),
    );

    assert!(
        !delta.relation_deltas.iter().any(|relation_delta| matches!(
            relation_delta,
            RelationDelta::Added { new } if new.id == held.id
        )),
        "the pass re-derived an identity the store already holds and offered it as an addition"
    );
    assert!(
        repo.relations_at(GraphNodeId::Entity(caller.id))
            .iter()
            .any(|relation| relation.id == held.id),
        "and the edge itself must survive: carrying it as a modification is the point, \
         dropping it would lose the caller"
    );

    // Arm two, the control. A file that names something new still produces an
    // addition, so the rule above is not "stop adding edges".
    let before = repo
        .graph
        .list_all_entities()
        .expect("list entities")
        .into_iter()
        .filter(|entity| entity.name == "second_hop")
        .count();
    assert_eq!(before, 0, "the control symbol must not exist yet");
    let delta = repo.commit(
        "ingest.py",
        &format!(
            "{INGEST_PY}\n\ndef second_hop(store, roots):\n    return run_ingest(store, roots)\n"
        ),
    );
    assert!(
        delta
            .relation_deltas
            .iter()
            .any(|relation_delta| matches!(relation_delta, RelationDelta::Added { .. })),
        "a call site this pass met for the first time must still arrive as an addition"
    );
}
