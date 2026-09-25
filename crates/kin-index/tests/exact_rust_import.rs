// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Source-bound same-file `self::` imports, with root-dependent paths refused.
//! The audit retains the causal counterexamples to a filename-root heuristic.
use std::collections::HashMap;

use kin_index::{FileParseData, IncrementalLinker, IndexPipeline};
use kin_model::{ArtifactId, EntityId, EntityKind, FilePathId, Relation, RelationKind};

fn parse(path: &str, source: &str) -> FileParseData {
    let file = IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new(path),
            source.as_bytes(),
            kin_blobs::digest(source.as_bytes()),
        )
        .unwrap()
        .indexed_file;
    FileParseData {
        file_path: path.into(),
        entities: file.entities,
        relations: file.extracted_relations,
        imports: file.imports,
    }
}
fn fixture(root: &str, caller: &str) -> Vec<FileParseData> {
    vec![
        parse("one/src/lib.rs", root),
        parse("one/src/use_it.rs", caller),
        parse(
            "one/src/defs.rs",
            "pub fn work() -> u32 { 1 }\npub enum Status { Ready(u32) }\n",
        ),
        parse("two/src/lib.rs", "pub mod defs;\n"),
        parse(
            "two/src/defs.rs",
            "pub fn work() -> u32 { 2 }\npub enum Status { Ready(u32) }\n",
        ),
    ]
}
fn id(files: &[FileParseData], path: &str, name: &str) -> EntityId {
    files
        .iter()
        .find(|f| f.file_path == path)
        .unwrap()
        .entities
        .iter()
        .find(|e| e.name == name && e.kind != EntityKind::Module)
        .unwrap()
        .id
}
fn calls(relations: &[Relation], source: EntityId) -> Vec<EntityId> {
    relations
        .iter()
        .filter(|r| {
            r.kind == RelationKind::Calls
                && r.src.as_entity() == Some(source)
                && !kin_index::is_external_import_placeholder(r)
        })
        .filter_map(|r| r.dst.as_entity())
        .collect()
}
fn assert_routes(files: &[FileParseData], expected: Option<EntityId>) {
    let source = id(files, "one/src/use_it.rs", "run");
    let artifacts: HashMap<_, _> = files
        .iter()
        .map(|f| (f.file_path.clone(), ArtifactId::new()))
        .collect();
    let mut linker = IncrementalLinker::new();
    for file in files {
        linker.add_file(&file.file_path, artifacts[&file.file_path], &file.entities);
    }
    linker.record_class_bases(files);
    let checkpoint = serde_json::to_vec(&linker.to_checkpoint_v1()).unwrap();
    let restored =
        IncrementalLinker::from_checkpoint_v1(serde_json::from_slice(&checkpoint).unwrap())
            .unwrap();
    let caller_only: Vec<_> = files
        .iter()
        .filter(|f| f.file_path == "one/src/use_it.rs")
        .cloned()
        .collect();
    for (route, relations) in [
        (
            "batch",
            kin_index::link_cross_file(files, &artifacts).unwrap(),
        ),
        (
            "warm caller-only",
            kin_index::link_cross_file_incremental(&caller_only, &linker).unwrap(),
        ),
        (
            "checkpoint caller-only",
            kin_index::link_cross_file_incremental(&caller_only, &restored).unwrap(),
        ),
    ] {
        let actual = calls(&relations, source);
        match expected {
            Some(target) => assert_eq!(actual, vec![target], "{route}: {relations:?}"),
            None => assert!(actual.is_empty(), "{route}: {relations:?}"),
        }
    }
}

#[test]
fn same_file_self_use_resolves_an_alias_and_owned_variant() {
    for (use_path, call, expected) in [
        ("work as invoke", "invoke()", "work"),
        (
            "Status::Ready as make_ready",
            "make_ready(1)",
            "Status::Ready",
        ),
    ] {
        let files = fixture("pub mod defs; pub mod use_it;", &format!("use self::{use_path};\npub fn work() -> u32 {{ 3 }}\npub enum Status {{ Ready(u32) }}\npub fn run() {{ {call}; }}\n"));
        let target = id(&files, "one/src/use_it.rs", expected);
        assert_routes(&files, Some(target));
    }
}

#[test]
fn exact_named_use_refuses_undeclared_or_attributed_modules_and_ambiguous_roots() {
    for root in [
        "pub mod use_it;",
        "#[path=\"defs.rs\"] pub mod defs; pub mod use_it;",
        "#[cfg(any())] pub mod defs; pub mod use_it;",
        "pub mod defs { pub fn work() {} } pub mod use_it;",
    ] {
        let files = fixture(root, "use crate::defs::work; pub fn run() { work(); }");
        assert_routes(&files, None);
    }
    let mut files = fixture(
        "pub mod defs; pub mod use_it;",
        "use crate::defs::work; pub fn run() { work(); }",
    );
    files.push(parse("one/src/main.rs", "pub mod defs; pub mod use_it;"));
    assert_routes(&files, None);
}

#[test]
fn exact_named_use_refuses_missing_or_ambiguous_module_bodies() {
    let mut files = fixture(
        "pub mod defs; pub mod use_it;",
        "use crate::defs::work; pub fn run() { work(); }",
    );
    files.retain(|f| f.file_path != "one/src/defs.rs");
    assert_routes(&files, None);
    files.push(parse("one/src/defs.rs", "pub fn work() {}"));
    files.push(parse("one/src/defs/mod.rs", "pub fn work() {}"));
    assert_routes(&files, None);
}

#[test]
fn exact_named_use_does_not_promote_a_shadowed_or_nested_caller_pin() {
    for source in [
        "use self::work as invoke; pub fn work() {} pub fn run(invoke: fn()) { invoke(); }",
        "use self::work as invoke; pub fn work() {} pub fn run() { let invoke = || {}; invoke(); }",
        "use self::work as invoke; pub fn work() {} pub fn run() { fn invoke() {} invoke(); }",
    ] {
        let files = fixture("pub mod defs; pub mod use_it;", source);
        let target = id(&files, "one/src/use_it.rs", "work");
        let artifacts = files
            .iter()
            .map(|f| (f.file_path.clone(), ArtifactId::new()))
            .collect();
        let relations = kin_index::link_cross_file(&files, &artifacts).unwrap();
        assert!(
            !calls(&relations, id(&files, "one/src/use_it.rs", "run")).contains(&target),
            "{source}: {relations:?}"
        );
    }
}

#[test]
fn exact_import_witness_requires_unique_current_source_binding() {
    for mutation in ["missing_digest", "stale_digest", "duplicate", "malformed"] {
        let mut files = fixture(
            "pub mod defs; pub mod use_it;",
            "use self::work as invoke; pub fn work() {} pub fn run() { invoke(); }",
        );
        let root = &mut files[1];
        match mutation {
            "missing_digest" => {
                for entity in &mut root.entities {
                    entity.metadata.extra.remove("blob_hash");
                }
            }
            "stale_digest" => {
                for entity in &mut root.entities {
                    entity.metadata.extra.insert(
                        "blob_hash".into(),
                        serde_json::Value::String("0".repeat(64)),
                    );
                }
            }
            "duplicate" => {
                let record = root
                    .relations
                    .iter()
                    .find(|r| kin_parser::import_witness::claims_import_witness(r))
                    .unwrap()
                    .clone();
                root.relations.push(record);
            }
            "malformed" => {
                root.relations
                    .iter_mut()
                    .find(|r| kin_parser::import_witness::claims_import_witness(r))
                    .unwrap()
                    .dst_name = "{}".into();
            }
            _ => unreachable!(),
        }
        assert_routes(&files, None);
    }
}

#[test]
fn a_custom_target_root_does_not_turn_its_nested_lib_rs_into_a_crate_root() {
    // The actual package target is [lib] path="custom.rs". A nested module's
    // filename does not override Cargo's target. The current linker input has
    // no slot for that admitted manifest fact: this is the causal gap.
    let files = vec![
        parse(
            "custom.rs",
            "#[path=\"src/lib.rs\"] pub mod nested; pub mod target;",
        ),
        parse("target.rs", "pub fn work() {}"),
        parse("src/lib.rs", "pub mod target; pub mod use_it;"),
        parse("src/target.rs", "pub fn work() {}"),
        parse(
            "src/use_it.rs",
            "use crate::target::work; pub fn run() { work(); }",
        ),
    ];
    let source = id(&files, "src/use_it.rs", "run");
    let wrong = id(&files, "src/target.rs", "work");
    let artifacts = files
        .iter()
        .map(|f| (f.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = kin_index::link_cross_file(&files, &artifacts).unwrap();
    assert!(
        !calls(&relations, source).contains(&wrong),
        "a filename cannot establish target root: {relations:?}"
    );
}

#[test]
fn a_nested_main_module_uses_its_own_module_directory() {
    let files = vec![
        parse("src/lib.rs", "pub mod outer; pub mod use_it;"),
        parse("src/outer.rs", "pub mod main;"),
        parse("src/outer/main.rs", "pub mod target;"),
        parse("src/outer/main/target.rs", "pub fn work() {}"),
        parse("src/outer/target.rs", "pub fn work() {}"),
        parse(
            "src/use_it.rs",
            "use crate::outer::main::target::work; pub fn run() { work(); }",
        ),
    ];
    let source = id(&files, "src/use_it.rs", "run");
    let wrong = id(&files, "src/outer/target.rs", "work");
    let artifacts = files
        .iter()
        .map(|f| (f.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = kin_index::link_cross_file(&files, &artifacts).unwrap();
    assert!(
        !calls(&relations, source).contains(&wrong),
        "main.rs inside a module is not a root: {relations:?}"
    );
}
