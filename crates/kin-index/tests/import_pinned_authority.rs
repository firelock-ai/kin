// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Parser-recorded imports constrain lookup even when their module is missing.

use kin_index::{FileParseData, IncrementalLinker, IndexPipeline};
use kin_model::{ArtifactId, EntityId, FilePathId, Relation, RelationKind};

fn parse(path: &str, body: &str) -> FileParseData {
    let indexed = IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new(path),
            body.as_bytes(),
            kin_blobs::digest(body.as_bytes()),
        )
        .unwrap()
        .indexed_file;
    FileParseData {
        file_path: path.into(),
        entities: indexed.entities,
        relations: indexed.extracted_relations,
        imports: indexed.imports,
    }
}

fn id(file: &FileParseData, name: &str) -> EntityId {
    file.entities
        .iter()
        .find(|entity| entity.name == name)
        .unwrap()
        .id
}

fn all_routes(files: &[FileParseData]) -> Vec<(&'static str, Vec<Relation>)> {
    let artifacts: std::collections::HashMap<String, ArtifactId> = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let mut linker = IncrementalLinker::new();
    for file in files {
        linker.add_file(&file.file_path, artifacts[&file.file_path], &file.entities);
    }
    let bytes = serde_json::to_vec(&linker.to_checkpoint_v1()).unwrap();
    let restored =
        IncrementalLinker::from_checkpoint_v1(serde_json::from_slice(&bytes).unwrap()).unwrap();
    vec![
        (
            "batch",
            kin_index::link_cross_file(files, &artifacts).unwrap(),
        ),
        (
            "incremental",
            kin_index::link_cross_file_incremental(files, &linker).unwrap(),
        ),
        (
            "checkpoint",
            kin_index::link_cross_file_incremental(files, &restored).unwrap(),
        ),
    ]
}

fn missing_module(source: &str) {
    let files = [
        parse("caller.py", source),
        parse("unrelated.py", "def work(value):\n    return value\n"),
    ];
    let caller = id(&files[0], "run");
    let unrelated = id(&files[1], "work");
    assert!(files[0]
        .relations
        .iter()
        .any(|raw| raw.kind == RelationKind::Calls && raw.import_source.is_some()));
    for (route, relations) in all_routes(&files) {
        let calls: Vec<_> = relations
            .iter()
            .filter(|relation| {
                relation.kind == RelationKind::Calls && relation.src.as_entity() == Some(caller)
            })
            .collect();
        assert!(
            calls
                .iter()
                .all(|relation| relation.dst.as_entity() != Some(unrelated)),
            "{route}: {calls:?}"
        );
        assert_eq!(
            calls.len(),
            1,
            "{route}: explicit external boundary is retained"
        );
        assert!(
            kin_index::is_external_import_placeholder(calls[0]),
            "{route}: {calls:?}"
        );
    }
}

#[test]
fn missing_bare_python_module_never_captures_global_name() {
    missing_module("from local import work\n\ndef run():\n    return work(value=1)\n");
}

#[test]
fn missing_aliased_python_module_never_captures_global_name() {
    missing_module("from local import work as invoke\n\ndef run():\n    return invoke(value=1)\n");
}

#[test]
fn missing_dotted_python_module_never_captures_global_name() {
    missing_module("from missing.local import work\n\ndef run():\n    return work(value=1)\n");
}

#[test]
fn legitimate_external_python_import_keeps_named_boundary() {
    missing_module("from third_party.client import work\n\ndef run():\n    return work(value=1)\n");
}

#[test]
fn present_python_module_without_symbol_never_captures_sibling() {
    let files = [
        parse(
            "caller.py",
            "from local import work\n\ndef run():\n    return work(value=1)\n",
        ),
        parse("local.py", "def other():\n    return 0\n"),
        parse("unrelated.py", "def work(value):\n    return value\n"),
    ];
    let caller = id(&files[0], "run");
    for (route, relations) in all_routes(&files) {
        assert!(
            !relations
                .iter()
                .any(|relation| relation.kind == RelationKind::Calls
                    && relation.src.as_entity() == Some(caller)),
            "{route}: absent member stays unresolved: {relations:?}"
        );
    }
}

#[test]
fn actual_local_plain_alias_and_dotted_imports_still_bind() {
    for (module, target, local_name) in [
        ("local", "local.py", "work"),
        ("local", "local.py", "invoke"),
        ("pkg.local", "pkg/local.py", "work"),
    ] {
        let alias = if local_name == "work" {
            String::new()
        } else {
            format!(" as {local_name}")
        };
        let files = [parse("caller.py", &format!("from {module} import work{alias}\n\ndef run():\n    return {local_name}(value=1)\n")),
            parse(target, "def work(value):\n    return value\n"),
            parse("unrelated.py", "def work(value):\n    return value\n")];
        let caller = id(&files[0], "run");
        let expected = id(&files[1], "work");
        for (route, relations) in all_routes(&files) {
            let calls: Vec<_> = relations
                .iter()
                .filter(|relation| {
                    relation.kind == RelationKind::Calls && relation.src.as_entity() == Some(caller)
                })
                .collect();
            assert_eq!(calls.len(), 1, "{module}/{local_name}/{route}: {calls:?}");
            assert_eq!(calls[0].dst.as_entity(), Some(expected));
            assert_eq!(calls[0].confidence, 0.95);
        }
    }
}

#[test]
fn proven_go_caller_can_resolve_an_imported_package_sibling() {
    let files = [
        parse(
            "cmd/main.go",
            "package main\nimport \"github.com/acme/repo/pkg/wire\"\nfunc run() { wire.Work() }\n",
        ),
        parse("pkg/wire/a.go", "package wire\nfunc Other() {}\n"),
        parse("pkg/wire/z.go", "package wire\nfunc Work() {}\n"),
        parse("unrelated/work.go", "package unrelated\nfunc Work() {}\n"),
    ];
    let caller = id(&files[0], "run");
    let expected = id(&files[2], "Work");
    for (route, relations) in all_routes(&files) {
        let calls: Vec<_> = relations
            .iter()
            .filter(|relation| {
                relation.kind == RelationKind::Calls && relation.src.as_entity() == Some(caller)
            })
            .collect();
        assert_eq!(calls.len(), 1, "{route}: {calls:?}");
        assert_eq!(calls[0].dst.as_entity(), Some(expected), "{route}");
    }
}
