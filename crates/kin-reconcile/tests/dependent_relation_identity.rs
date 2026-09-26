// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A later caller refreshes complete admitted dependencies without minting a
//! second parser identity for their unchanged same-file facts.
use kin_blobs::BlobStore;
use kin_db::{InMemoryGraph, SnapshotManager};
use kin_index::FileEvent;
use kin_model::{
    ArtifactId, Entity, EntityStore, FilePathId, GraphNodeId, Hash256, LocatedEntry, Relation,
    RelationDelta, RelationId, RelationKind, RelationOrigin, RepoPath, TransactionDelta, TreeDelta,
    TreeEntry,
};
use kin_reconcile::Reconciler;

struct Repo {
    root: tempfile::TempDir,
    blobs: BlobStore,
    graph: InMemoryGraph,
    reconciler: Reconciler,
}
impl Repo {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(root.path().join("cas")).unwrap();
        let graph = InMemoryGraph::new();
        let mut reconciler = Reconciler::new(root.path().to_path_buf());
        reconciler.seed_cross_file_linker_from_graph(&graph);
        Self {
            root,
            blobs,
            graph,
            reconciler,
        }
    }
    fn commit(&mut self, file: &str, body: &str) {
        let host = self.root.path().join(file);
        std::fs::create_dir_all(host.parent().unwrap()).unwrap();
        std::fs::write(&host, body).unwrap();
        let digest = self.blobs.write(body.as_bytes()).unwrap();
        let path = RepoPath::from_utf8(file).unwrap();
        let new = LocatedEntry::new(
            path.clone(),
            TreeEntry::blob(Hash256::from_bytes(digest.0), false),
        );
        let delta = match self.graph.resolved_tree().artifact_at_path(&path).cloned() {
            Some(old) if old.entry == new.entry => None,
            Some(old) => Some(TreeDelta::Updated {
                artifact_id: old.artifact_id,
                old: LocatedEntry::new(old.path, old.entry),
                new,
            }),
            None => Some(TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new,
            }),
        };
        if let Some(delta) = delta {
            self.graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![delta],
                    ..Default::default()
                })
                .unwrap();
        }
        let result = self
            .reconciler
            .reconcile_file_change(&FileEvent::Changed(host), &self.blobs, &self.graph)
            .unwrap();
        let (_, delta) = result.into_parts();
        kin_model::validate_transaction_delta(&delta).unwrap();
        self.graph.apply_transaction_delta(&delta).unwrap();
    }
    fn reopen(&mut self) {
        let path = self.root.path().join("snapshot.kindb");
        SnapshotManager::save_graph(&path, &self.graph).unwrap();
        let cold = SnapshotManager::open_without_text_index(&path).unwrap();
        self.graph = InMemoryGraph::from_snapshot(cold.graph().to_snapshot()).unwrap();
        self.reconciler = Reconciler::new(self.root.path().to_path_buf());
        self.reconciler.seed_lkg_entities_from_graph(&self.graph);
        self.reconciler
            .seed_cross_file_linker_from_graph(&self.graph);
        self.reconciler
            .restore_cross_file_dependencies(&self.graph, &self.blobs)
            .unwrap();
    }
    fn entity(&self, name: &str) -> Entity {
        self.graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|e| e.name == name)
            .unwrap()
    }
    fn storage_parser_relations(&self) -> Vec<Relation> {
        let snapshot = self.graph.to_snapshot();
        let mut result: Vec<_> = snapshot
            .relations
            .into_values()
            .filter(|r| {
                r.origin == RelationOrigin::Parsed
                    && matches!(r.kind, RelationKind::Calls | RelationKind::Contains)
                    && [r.src, r.dst].iter().all(|n| {
                        n.as_entity()
                            .and_then(|id| snapshot.entities.get(&id))
                            .is_some_and(|e| {
                                e.file_origin == Some(FilePathId::new("pkg/storage.py"))
                            })
                    })
            })
            .collect();
        result.sort_by_key(|r| r.id);
        result
    }
}

fn fixture() -> Repo {
    let mut repo = Repo::new();
    repo.commit("pkg/__init__.py", "");
    repo.commit("pkg/parsing.py", PARSING_PY);
    repo.commit("pkg/storage.py", STORAGE_PY);
    repo
}

fn arrival_preserves_internal_identity(cold: bool) {
    let mut repo = fixture();
    let caller = repo.entity("Database.ingest_dir");
    let before = repo.storage_parser_relations();
    assert_eq!(
        before
            .iter()
            .filter(|r| r.kind == RelationKind::Contains)
            .count(),
        4
    );
    assert_eq!(
        before
            .iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .count(),
        1
    );
    let call = before
        .iter()
        .find(|r| r.kind == RelationKind::Calls)
        .unwrap();
    assert_eq!(call.src, GraphNodeId::Entity(caller.id));
    assert_eq!(
        call.dst,
        GraphNodeId::Entity(repo.entity("Database.ingest_note").id)
    );
    let records = kin_index::occurrence::original_evidence(call).unwrap();
    assert_eq!(records.len(), 1);
    assert!(!kin_index::occurrence::proven_sites(call).0.is_empty());
    let site = records[0].source_span.as_ref().unwrap();
    assert_eq!(
        &STORAGE_PY[site.start_byte..site.end_byte],
        "self.ingest_note(parse_note(text, name))"
    );
    if cold {
        repo.reopen();
    }
    repo.commit("pkg/linkgraph.py", LINKGRAPH_PY);
    assert!(
        repo.reconciler.cross_file_linker().last_files_resolved() > 1,
        "real arriving caller must refresh an admitted dependency"
    );
    assert_eq!(repo.entity("Database.ingest_dir"), caller);
    assert_eq!(
        std::fs::read_to_string(repo.root.path().join("pkg/storage.py")).unwrap(),
        STORAGE_PY
    );
    assert_eq!(repo.storage_parser_relations(), before,
        "unchanged dependency must keep one exact parser fact, identity and occurrence; never a second linker ID");
    let complete = repo.graph.to_snapshot().relations;
    repo.commit("pkg/linkgraph.py", LINKGRAPH_PY);
    assert_eq!(
        repo.graph.to_snapshot().relations,
        complete,
        "unchanged repeat is idempotent"
    );
    repo.reopen();
    assert_eq!(
        repo.storage_parser_relations(),
        before,
        "exact facts survive persisted cold replay"
    );
    repo.commit("pkg/linkgraph.py", LINKGRAPH_PY);
    assert_eq!(
        repo.graph.to_snapshot().relations,
        complete,
        "restored dependency refresh is idempotent"
    );
}

#[test]
fn arriving_caller_keeps_unchanged_dependency_relation_ids_warm() {
    arrival_preserves_internal_identity(false);
}
#[test]
fn arriving_caller_keeps_unchanged_dependency_relation_ids_cold() {
    arrival_preserves_internal_identity(true);
}

#[test]
fn dependent_parser_refresh_preserves_separate_manual_and_lsp_facts() {
    let mut repo = fixture();
    let before = repo.storage_parser_relations();
    let parsed = before
        .iter()
        .find(|r| r.kind == RelationKind::Calls)
        .unwrap();
    let foreign: Vec<_> = [RelationOrigin::Manual, RelationOrigin::Lsp]
        .into_iter()
        .enumerate()
        .map(|(index, origin)| {
            let mut r = parsed.clone();
            r.id = RelationId::from_bytes([index as u8; 16]);
            r.origin = origin;
            r.confidence = 0.75;
            r.evidence.clear();
            r
        })
        .collect();
    repo.graph
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas: foreign
                .iter()
                .cloned()
                .map(|new| RelationDelta::Added { new })
                .collect(),
            ..Default::default()
        })
        .unwrap();
    repo.commit("pkg/linkgraph.py", LINKGRAPH_PY);
    assert_eq!(repo.storage_parser_relations(), before);
    for r in foreign {
        assert_eq!(repo.graph.get_relation_by_id(&r.id).as_ref(), Some(&r));
    }
}

#[test]
fn dependent_parser_refresh_never_steals_an_lsp_only_identity() {
    let mut repo = fixture();
    let parsed = repo
        .storage_parser_relations()
        .into_iter()
        .find(|r| r.kind == RelationKind::Calls)
        .unwrap();
    let mut lsp = parsed.clone();
    lsp.id = RelationId::from_bytes([0; 16]);
    lsp.origin = RelationOrigin::Lsp;
    lsp.confidence = 0.75;
    lsp.evidence.clear();
    repo.graph
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas: vec![
                RelationDelta::Removed {
                    old: parsed.clone(),
                },
                RelationDelta::Added { new: lsp.clone() },
            ],
            ..Default::default()
        })
        .unwrap();
    repo.commit("pkg/linkgraph.py", LINKGRAPH_PY);
    assert_eq!(repo.graph.get_relation_by_id(&lsp.id).as_ref(), Some(&lsp));
    let calls: Vec<_> = repo
        .storage_parser_relations()
        .into_iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .collect();
    assert_eq!(calls.len(), 1);
    assert_ne!(calls[0].id, lsp.id);
    assert_eq!(calls[0].src, parsed.src);
    assert_eq!(calls[0].dst, parsed.dst);
    assert_eq!(
        kin_index::occurrence::original_evidence(&calls[0]),
        kin_index::occurrence::original_evidence(&parsed)
    );
    assert_eq!(
        kin_index::occurrence::proven_sites(&calls[0]),
        kin_index::occurrence::proven_sites(&parsed)
    );
    assert!(kin_index::occurrence::groups(&calls[0])
        .iter()
        .all(|group| !group.qualification_missing));
}

const PARSING_PY: &str = r###"import re

TAG_RE = re.compile(r"(?<![\w#])#([A-Za-z][\w/-]*)")


def normalize_title(title):
    return title.strip().lower()


def strip_code(text):
    return text.replace("`", "")


def extract_tags(text):
    return TAG_RE.findall(strip_code(text))


def extract_links(text):
    return [normalize_title(part) for part in text.split("|")]


def parse_note(text, path):
    return {"path": str(path), "tags": extract_tags(text), "links": extract_links(text)}
"###;

const STORAGE_PY: &str = r###"from .parsing import parse_note, normalize_title


class Database:
    def __init__(self, path):
        self.path = path
        self.notes = {}

    def ingest_note(self, note):
        key = normalize_title(note["path"])
        self.notes[key] = note
        return normalize_title(key)

    def ingest_dir(self, root):
        for name, text in root.items():
            self.ingest_note(parse_note(text, name))
        return len(self.notes)

    def all_notes(self):
        return list(self.notes.values())
"###;

const LINKGRAPH_PY: &str = r###"from .parsing import normalize_title
from .storage import Database


class LinkGraph:
    def __init__(self, edges):
        self.edges = edges

    @staticmethod
    def from_db(db: Database):
        edges = {}
        for note in db.all_notes():
            edges[normalize_title(note["path"])] = [normalize_title(link)
                                                    for link in note["links"]]
        return LinkGraph(edges)

    def backlinks(self, title):
        return [src for src, dsts in self.edges.items() if title in dsts]
"###;
