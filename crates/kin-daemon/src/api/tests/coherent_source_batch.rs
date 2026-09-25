// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[tokio::test]
async fn coherent_source_batch_rename_lands_in_one_commit_and_survives_restart() {
    let (repo, state) = mcp_lifecycle_fixture();
    let files = [
        ("a.py", "def normalize_title(value):\n    return value.strip()\n"),
        ("b.py", "from a import normalize_title\n\ndef first(value):\n    return normalize_title(value)\n"),
        ("c.py", "from a import normalize_title\n\ndef second(value):\n    return normalize_title(value)\n"),
    ];
    // Real separate admissions establish the old bindings before the rename.
    for (file, body) in files {
        std::fs::write(repo.path().join(file), body).unwrap();
        waiting_admit(&state, file).await;
    }
    waiting_commit(&state, "batch baseline").await;
    println!("coherent source batch: baseline native commit published");
    let old = waiting_entity(&state, "a.py", "normalize_title");
    for (file, name) in [("b.py", "first"), ("c.py", "second")] {
        let caller = waiting_entity(&state, file, name);
        assert!(state.graph.get_relations(&caller.id, &[kin_model::RelationKind::Calls])
            .unwrap().iter().any(|relation| relation.dst.as_entity() == Some(old.id)),
            "baseline must contain the actual cross-file call");
    }
    for (file, body) in files {
        std::fs::write(repo.path().join(file), body.replace("normalize_title", "canonical_title")).unwrap();
    }
    // This must be the first and only commit after editing all three files.
    waiting_commit(&state, "rename three source files coherently").await;
    println!("coherent source batch: first rename commit published");
    let layout = state.layout.clone();
    let mut view = state;
    for phase in 0..2 {
        if phase == 1 {
            // Reopen only after the warm state's publication has completed.
            drop(view);
            view = waiting_cold_start(layout.clone()).await;
        }
        let target = waiting_entity(&view, "a.py", "canonical_title");
        assert!(view.graph.list_all_entities().unwrap().iter()
            .all(|entity| entity.name != "normalize_title"));
        for (file, name) in [("b.py", "first"), ("c.py", "second")] {
            let caller = waiting_entity(&view, file, name);
            let calls = view.graph.get_relations(&caller.id, &[kin_model::RelationKind::Calls]).unwrap();
            assert_eq!(calls.iter().filter(|relation| relation.dst.as_entity() == Some(target.id)).count(), 1,
                "the renamed target retains each actual caller: {calls:?}");
        }
        for (file, body) in files {
            let expected = body.replace("normalize_title", "canonical_title");
            let digest = kin_model::Hash256::from_bytes(kin_blobs::digest(expected.as_bytes()).0);
            let entities = view.graph.query_entities(&kin_db::EntityFilter {
                file_path: Some(kin_model::FilePathId::new(file)), ..Default::default()
            }).unwrap();
            assert!(!entities.is_empty());
            assert!(entities.iter().all(|entity| entity.metadata.extra["blob_hash"] == digest.to_string()));
            let stored = view.graph.get_file_layout(&kin_model::FilePathId::new(file)).unwrap();
            assert!(stored.is_some(), "current projection layout survives publication and reopen");
        }
        std::fs::write(repo.path().join("unrelated.txt"), format!("unrelated change {phase}\n")).unwrap();
        waiting_commit(&view, "unrelated write after coherent rename").await;
        println!("coherent source batch: unrelated phase {phase} commit published");
    }
}

#[tokio::test]
async fn coherent_source_batch_acceptance_rename_keeps_class_method_callers() {
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
    const CLI_PY: &str = r###"from .linkgraph import LinkGraph
from .storage import Database


def main():
    db = Database(":memory:")
    db.ingest_dir({"a.md": "hello #tag b|c"})
    return LinkGraph.from_db(db).backlinks("b")
"###;
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::create_dir(repo.path().join("pkg")).unwrap();
    std::fs::write(repo.path().join("README.md"), "# nk\n\nA note keeper.\n").unwrap();
    std::fs::write(repo.path().join("pyproject.toml"), "[project]\nname = \"nk\"\nversion = \"0.1.0\"\n\n[project.scripts]\nnk = \"pkg.cli:main\"\n").unwrap();
    std::fs::write(repo.path().join("pkg/__init__.py"), "").unwrap();
    for (path, body) in [("pkg/parsing.py", PARSING_PY), ("pkg/storage.py", STORAGE_PY), ("pkg/linkgraph.py", LINKGRAPH_PY), ("pkg/cli.py", CLI_PY)] {
        std::fs::write(repo.path().join(path), body).unwrap();
        waiting_commit(&state, path).await;
    }
    let prior = waiting_entity(&state, "pkg/parsing.py", "normalize_title");
    for (path, name) in [("pkg/storage.py", "Database.ingest_note"), ("pkg/linkgraph.py", "LinkGraph.from_db")] {
        let caller = waiting_entity(&state, path, name);
        assert!(state.graph.get_relations(&caller.id, &[kin_model::RelationKind::Calls]).unwrap().iter().any(|r| r.dst.as_entity() == Some(prior.id)), "baseline must contain both actual callers");
    }
    for (path, body) in [("pkg/parsing.py", PARSING_PY), ("pkg/storage.py", STORAGE_PY), ("pkg/linkgraph.py", LINKGRAPH_PY)] {
        std::fs::write(repo.path().join(path), body.replace("normalize_title", "canonical_title")).unwrap();
    }
    waiting_commit(&state, "Rename normalize_title to canonical_title").await;
    println!("acceptance rename first commit published");
    let layout = state.layout.clone();
    let mut view = state;
    for phase in 0..2 {
        if phase == 1 {
            drop(view);
            view = waiting_cold_start(layout.clone()).await;
        }
        let target = waiting_entity(&view, "pkg/parsing.py", "canonical_title");
        assert!(view.graph.list_all_entities().unwrap().iter().all(|e| e.name != "normalize_title"));
        for (path, name) in [("pkg/storage.py", "Database.ingest_note"), ("pkg/linkgraph.py", "LinkGraph.from_db")] {
            let caller = waiting_entity(&view, path, name);
            assert!(view.graph.get_relations(&caller.id, &[kin_model::RelationKind::Calls]).unwrap().iter().any(|r| r.dst.as_entity() == Some(target.id)), "actual renamed callers survive phase {phase}");
        }
        std::fs::write(repo.path().join("README.md"), format!("# nk\n\nA note keeper.\nphase {phase}\n")).unwrap();
        waiting_commit(&view, "unrelated README after rename").await;
    }
}
