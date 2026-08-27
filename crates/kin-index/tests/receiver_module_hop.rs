// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A call whose receiver is bound to a module one hop short of the callee.
//!
//! Tier (a0) binds an attribute call's receiver to the file its import names,
//! and two shapes put that file one hop away from where the callee is defined:
//!
//! - `from pkg import mod` records `pkg` as the module path and `mod` as a
//!   separate specifier, so the receiver lands on `pkg/__init__.py` while the
//!   callee lives in the sibling `pkg/mod.py`.
//! - `module.exports = require('./lib/express')` makes the package entry point
//!   the receiver's file while every export lives one module away.
//!
//! Before the hop existed, tier (a0) missed and `continue`d past every lower
//! tier, so the call produced no edge and no placeholder at all: on the shipped
//! 0.6.0 bytes `kin refs note_body` answered "no incoming relations" and the
//! envelope certified that absence as authoritative, while the test that calls
//! it sat one grep away.
//!
//! The controls matter as much as the arms. The hop offers exactly one
//! candidate, named by a statement the source actually wrote; handing the call
//! to the name-matching tiers instead would bind the bare leaf to any same-named
//! symbol in the repository, which is a false consumer nothing downstream can
//! catch. `a_submodule_that_does_not_define_the_callee_reaches_nothing` is that
//! property, and it is the arm that fails if anyone reaches for a fallthrough.

use std::collections::HashMap;

use kin_index::{
    link_cross_file as link_cross_file_with_identities, link_cross_file_incremental,
    FileParseData, IncrementalLinker,
};
use kin_model::{ArtifactId, Entity, EntityId, FilePathId, GraphNodeId, Relation, RelationKind};
use kin_parser::{JavaScriptAdapter, LanguageAdapter, PythonAdapter};

fn parse_with(adapter: &dyn LanguageAdapter, file_path: &str, source: &str) -> FileParseData {
    let file_id = FilePathId::new(file_path);
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse");
    let output = adapter.extract(&tree, bytes, &file_id).expect("extract");
    let entities: Vec<Entity> = output
        .entities
        .into_iter()
        .map(|e| e.into_entity_with_source(adapter.language_id(), &file_id, Some(bytes)))
        .collect();
    FileParseData {
        file_path: file_path.to_string(),
        entities,
        relations: output.relations,
        imports: output.imports,
    }
}

fn py(file_path: &str, source: &str) -> FileParseData {
    parse_with(&PythonAdapter, file_path, source)
}

fn js(file_path: &str, source: &str) -> FileParseData {
    parse_with(&JavaScriptAdapter, file_path, source)
}

fn entity_id(files: &[FileParseData], file: &str, name: &str) -> EntityId {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
        .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
        .id
}

fn link(files: &[FileParseData]) -> Vec<Relation> {
    let artifact_ids: HashMap<String, ArtifactId> = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    link_cross_file_with_identities(files, &artifact_ids)
        .expect("every fixture file has an explicitly assigned artifact identity")
}

fn link_incremental(files: &[FileParseData]) -> Vec<Relation> {
    let mut linker = IncrementalLinker::new();
    for file in files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker.record_class_bases(files);
    link_cross_file_incremental(files, &linker)
        .expect("every fixture file has an explicitly assigned artifact identity")
}

fn has_call(relations: &[Relation], src: EntityId, dst: EntityId) -> bool {
    relations.iter().any(|r| {
        r.kind == RelationKind::Calls
            && r.src == GraphNodeId::Entity(src)
            && r.dst == GraphNodeId::Entity(dst)
    })
}

/// Every `Calls` destination this source reaches, resolved or not.
///
/// Read rather than `has_call` wherever an arm has to say that NOTHING was
/// produced: an unresolved-receiver placeholder is a `Calls` edge to a
/// synthesized destination, so "no edge to the right target" and "no edge at
/// all" are different findings and only this separates them.
fn call_destinations(relations: &[Relation], src: EntityId) -> Vec<GraphNodeId> {
    relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls && r.src == GraphNodeId::Entity(src))
        .map(|r| r.dst.clone())
        .collect()
}

/// The stranger's own shape, trimmed: `from notekeeper import storage` in a
/// test, then `storage.note_body(...)`. The package index defines nothing the
/// call names, exactly as the real `src/notekeeper/__init__.py` defines only a
/// docstring and `__version__`.
fn notekeeper_shape() -> Vec<FileParseData> {
    vec![
        py(
            "src/notekeeper/__init__.py",
            "\"\"\"notekeeper: a local markdown knowledge base.\"\"\"\n\n__version__ = \"0.1.0\"\n",
        ),
        py(
            "src/notekeeper/storage.py",
            "def note_body(conn, note_id):\n    return \"\"\n",
        ),
        py(
            "tests/test_storage.py",
            "from notekeeper import storage\n\n\ndef test_bodies_round_trip(db):\n    assert storage.note_body(db, 1)\n",
        ),
    ]
}

#[test]
fn a_submodule_receiver_resolves_through_the_package_index() {
    let files = notekeeper_shape();
    let caller = entity_id(&files, "tests/test_storage.py", "test_bodies_round_trip");
    let target = entity_id(&files, "src/notekeeper/storage.py", "note_body");

    let relations = link(&files);
    assert!(
        has_call(&relations, caller, target),
        "`from notekeeper import storage` then `storage.note_body(...)` must reach \
         src/notekeeper/storage.py::note_body; the receiver resolves to the package \
         __init__, which defines nothing the call names, and before the hop existed \
         tier (a0) dropped the call whole"
    );
}

#[test]
fn an_incremental_submodule_receiver_resolves_with_batch_parity() {
    // The incremental linker carries its own copy of tier (a0). A hop that
    // lands only in the batch path means the live-edit graph and the cold graph
    // answer one call differently, which is drift no other arm here can see.
    let files = notekeeper_shape();
    let caller = entity_id(&files, "tests/test_storage.py", "test_bodies_round_trip");
    let target = entity_id(&files, "src/notekeeper/storage.py", "note_body");

    let relations = link_incremental(&files);
    assert!(
        has_call(&relations, caller, target),
        "the incremental linker must resolve the submodule receiver exactly as the \
         batch linker does"
    );
}

#[test]
fn a_relative_submodule_receiver_resolves_through_the_package_index() {
    // `from . import storage` inside the package, the real shape at
    // src/notekeeper/cli.py:19. It takes the same path to the same __init__.
    let files = vec![
        py("src/notekeeper/__init__.py", "__version__ = \"0.1.0\"\n"),
        py(
            "src/notekeeper/storage.py",
            "def ingest_directory(path):\n    return 0\n",
        ),
        py(
            "src/notekeeper/cli.py",
            "from . import storage\n\n\ndef main(path):\n    return storage.ingest_directory(path)\n",
        ),
    ];
    let caller = entity_id(&files, "src/notekeeper/cli.py", "main");
    let target = entity_id(&files, "src/notekeeper/storage.py", "ingest_directory");

    let relations = link(&files);
    assert!(
        has_call(&relations, caller, target),
        "`from . import storage` then `storage.ingest_directory(...)` must reach the \
         sibling module, not stop at the package __init__"
    );
}

#[test]
fn an_aliased_submodule_receiver_resolves_through_its_original_name() {
    // `from notekeeper import storage as st` binds the receiver root to `st`
    // while the module is still `storage`. The import map records the pair, and
    // only the ORIGINAL half names a file. A hop that joined the receiver root
    // instead would look for notekeeper/st.py, find nothing, and be silently
    // right on every unaliased call in the fleet.
    let files = vec![
        py("src/notekeeper/__init__.py", "__version__ = \"0.1.0\"\n"),
        py(
            "src/notekeeper/storage.py",
            "def note_body(conn, note_id):\n    return \"\"\n",
        ),
        py(
            "tests/test_alias.py",
            "from notekeeper import storage as st\n\n\ndef test_alias(db):\n    assert st.note_body(db, 1)\n",
        ),
    ];
    let caller = entity_id(&files, "tests/test_alias.py", "test_alias");
    let target = entity_id(&files, "src/notekeeper/storage.py", "note_body");

    let relations = link(&files);
    assert!(
        has_call(&relations, caller, target),
        "`from notekeeper import storage as st` then `st.note_body(...)` must reach \
         storage.py: the hop names the module by the import's original name, not by \
         the local name the receiver was written with"
    );
}

#[test]
fn a_submodule_that_does_not_define_the_callee_reaches_nothing() {
    // THE CONTROL THAT SEPARATES THIS FIX FROM A TIER FALLTHROUGH.
    //
    // The hop lands on pkg/mod.py, which does not define `note_body`. A same
    // named function exists in a file this caller never imports. Letting the
    // call fall through to the name-matching tiers would bind it there and mint
    // a consumer the source never had, which is the whole reason tier (a0)
    // `continue`s. Nothing downstream can catch that, so it is caught here.
    let files = vec![
        py("pkg/__init__.py", "__version__ = \"1\"\n"),
        py("pkg/mod.py", "def unrelated_helper():\n    return 1\n"),
        py("elsewhere.py", "def note_body(conn, note_id):\n    return \"\"\n"),
        py(
            "caller.py",
            "from pkg import mod\n\n\ndef run(db):\n    return mod.note_body(db, 1)\n",
        ),
    ];
    let caller = entity_id(&files, "caller.py", "run");
    let decoy = entity_id(&files, "elsewhere.py", "note_body");

    let relations = link(&files);
    assert!(
        !has_call(&relations, caller, decoy),
        "`mod.note_body(...)` must not bind to a same-named function in a file this \
         caller never imports; the receiver names pkg/mod.py and that is the only \
         file that can answer"
    );
}

#[test]
fn a_receiver_naming_a_class_rather_than_a_submodule_is_unchanged() {
    // CONTROL THAT MUST STAY GREEN UNDER EVERY MUTATION OF THE HOP.
    //
    // `from pkg import Session` names a class the package index defines, and no
    // pkg/Session.py exists. The hop must not fire, and the pre-existing
    // resolution through the package index must be untouched.
    let files = vec![
        py(
            "pkg/__init__.py",
            "class Session:\n    def send(self, request):\n        return request\n",
        ),
        py(
            "caller.py",
            "from pkg import Session\n\n\ndef run(session):\n    return Session.send(session, 1)\n",
        ),
    ];
    let caller = entity_id(&files, "caller.py", "run");
    let target = entity_id(&files, "pkg/__init__.py", "Session.send");

    let relations = link(&files);
    assert!(
        has_call(&relations, caller, target),
        "a receiver bound to a class the package index itself defines must keep \
         resolving there; the hop is additive and must not displace it"
    );
}

#[test]
fn a_whole_module_reexport_receiver_reaches_the_real_export() {
    // The express shape. `require('..')` resolves to the repo-root index.js,
    // which is `module.exports = require('./lib/express')` and defines nothing,
    // so every `express.static(...)` call site reached nothing even once
    // lib/express.js carried the entity.
    let files = vec![
        js("index.js", "module.exports = require('./lib/express');\n"),
        js(
            "lib/express.js",
            "exports.static = require('serve-static');\nexports.json = function json() { return 1; };\n",
        ),
        js(
            "test/app.js",
            "var express = require('..');\n\nfunction mount(app) {\n  return app.use(express.json());\n}\n",
        ),
    ];
    let caller = entity_id(&files, "test/app.js", "mount");
    let target = entity_id(&files, "lib/express.js", "json");

    let relations = link(&files);
    assert!(
        has_call(&relations, caller, target),
        "`var express = require('..')` then `express.json()` must reach \
         lib/express.js::json through the root index's whole-module re-export"
    );
}

#[test]
fn the_hop_resolves_the_call_rather_than_minting_a_placeholder() {
    // An unresolved-receiver placeholder is itself a `Calls` edge, and the
    // arrival gate counts them to decide whether a file's calls were accounted
    // for. Minting one here would move the file from unaccounted to accounted
    // and re-certify exactly the absences that gate exists to refuse, so this
    // arm reads the destination set rather than asking whether the right edge
    // is somewhere in it.
    let files = notekeeper_shape();
    let caller = entity_id(&files, "tests/test_storage.py", "test_bodies_round_trip");
    let target = entity_id(&files, "src/notekeeper/storage.py", "note_body");

    let relations = link(&files);
    let destinations = call_destinations(&relations, caller);
    assert_eq!(
        destinations,
        vec![GraphNodeId::Entity(target)],
        "the call must resolve to exactly the real target: no second edge, and no \
         unresolved-receiver placeholder beside it"
    );
}

/// The same class against a real repository rather than a trimmed fixture.
///
/// Ignored by default and driven by `KIN_RECEIVER_HOP_CORPUS`, because the
/// corpora that carry this shape are not in the tree. A fixture written by the
/// same hand as the fix cannot say what the real adapters emit over real source,
/// so this runs the real parser over every `.py` file under the named root and
/// reports how many calls through a package-index receiver the hop recovered.
///
///     KIN_RECEIVER_HOP_CORPUS=/path/to/repo cargo test -p kin-index \
///         --test receiver_module_hop -- --ignored --nocapture
#[test]
#[ignore]
fn a_real_repository_recovers_calls_through_a_package_index_receiver() {
    let root = std::env::var("KIN_RECEIVER_HOP_CORPUS")
        .expect("KIN_RECEIVER_HOP_CORPUS must name a repository root");
    let root = std::path::PathBuf::from(root);

    let mut sources: Vec<std::path::PathBuf> = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if name != ".kin" && name != ".git" && name != "node_modules" && name != "__pycache__"
                {
                    stack.push(path);
                }
            } else if path.extension().and_then(|e| e.to_str()) == Some("py") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    assert!(
        !sources.is_empty(),
        "corpus {} holds no .py files, so this arm measured nothing",
        root.display()
    );

    let files: Vec<FileParseData> = sources
        .iter()
        .filter_map(|path| {
            let rel = path.strip_prefix(&root).ok()?.to_string_lossy().to_string();
            let source = std::fs::read_to_string(path).ok()?;
            Some(py(&rel, &source))
        })
        .collect();

    let relations = link(&files);
    let entity_files: HashMap<EntityId, String> = files
        .iter()
        .flat_map(|f| f.entities.iter().map(|e| (e.id, f.file_path.clone())))
        .collect();

    // Every call whose destination is an entity in a file OTHER than the one
    // the caller's receiver import named. Reported, not asserted on a number:
    // the count is corpus-specific and a hardcoded one would be a check that
    // passes for the wrong reason on the next corpus.
    let mut cross_file = 0usize;
    for relation in &relations {
        if relation.kind != RelationKind::Calls {
            continue;
        }
        let (GraphNodeId::Entity(src), GraphNodeId::Entity(dst)) =
            (&relation.src, &relation.dst)
        else {
            continue;
        };
        match (entity_files.get(src), entity_files.get(dst)) {
            (Some(src_file), Some(dst_file)) if src_file != dst_file => cross_file += 1,
            _ => {}
        }
    }

    println!("RECEIVER_HOP_CORPUS {}", root.display());
    println!("RECEIVER_HOP_FILES {}", files.len());
    println!("RECEIVER_HOP_CROSS_FILE_CALLS {cross_file}");
    assert!(
        cross_file > 0,
        "a real Python repository must produce at least one cross-file call edge; \
         zero means the run parsed nothing rather than that the hop found nothing"
    );
}
