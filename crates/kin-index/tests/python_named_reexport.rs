// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A named Python package import follows its declared re-export chain, never a
//! same-name sibling. Every fixture uses real parsing and both linker paths;
//! checkpoint controls restore the entity inventory before relinking the same
//! admitted parses. No filesystem module resolution is involved.

use std::collections::HashMap;

use kin_index::{FileParseData, IncrementalLinker, IndexPipeline};
use kin_model::{ArtifactId, EntityId, EntityKind, FilePathId, Relation, RelationKind};

fn parse(path: &str, source: &str) -> FileParseData {
    let indexed = IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new(path),
            source.as_bytes(),
            kin_blobs::digest(source.as_bytes()),
        )
        .expect("fixture source indexes")
        .indexed_file;
    FileParseData {
        file_path: path.into(),
        entities: indexed.entities,
        relations: indexed.extracted_relations,
        imports: indexed.imports,
    }
}

fn entity(files: &[FileParseData], path: &str, name: &str, kind: EntityKind) -> EntityId {
    files
        .iter()
        .find(|file| file.file_path == path)
        .unwrap()
        .entities
        .iter()
        .find(|entity| entity.name == name && entity.kind == kind)
        .unwrap_or_else(|| panic!("missing {kind:?} {path}:{name}"))
        .id
}

fn routes(files: &[FileParseData]) -> Vec<(&'static str, Vec<Relation>)> {
    let artifacts: HashMap<_, _> = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let mut linker = IncrementalLinker::new();
    for file in files {
        linker.add_file(&file.file_path, artifacts[&file.file_path], &file.entities);
    }
    let checkpoint = serde_json::to_vec(&linker.to_checkpoint_v1()).unwrap();
    let restored =
        IncrementalLinker::from_checkpoint_v1(serde_json::from_slice(&checkpoint).unwrap())
            .unwrap();
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

fn caller(files: &[FileParseData]) -> EntityId {
    let caller = entity(files, "app.py", "run", EntityKind::Function);
    assert!(
        files
            .iter()
            .find(|file| file.file_path == "app.py")
            .unwrap()
            .relations
            .iter()
            .any(|relation| relation.src_name == "run"
                && relation.import_source.as_deref() == Some("pkg")),
        "the caller must carry the package import pin that forbids blind name fallback"
    );
    caller
}

fn assert_exact_target(files: &[FileParseData], target: EntityId, kind: RelationKind) {
    let caller = caller(files);
    for (route, relations) in routes(files) {
        let edges: Vec<_> = relations
            .iter()
            .filter(|edge| edge.src.as_entity() == Some(caller) && edge.kind == kind)
            .collect();
        assert_eq!(edges.len(), 1, "{route}: {edges:?}");
        assert_eq!(edges[0].dst.as_entity(), Some(target), "{route}: {edges:?}");
        assert!(
            edges[0].confidence >= 0.9,
            "{route}: an explicit import chain must not pass as blind-name confidence: {edges:?}"
        );
        assert!(
            !kin_index::is_external_import_placeholder(edges[0]),
            "{route}: the declared target is local"
        );
    }
}

fn assert_no_caller_calls(files: &[FileParseData]) {
    let caller = caller(files);
    for (route, relations) in routes(files) {
        let calls: Vec<_> = relations
            .iter()
            .filter(|edge| edge.src.as_entity() == Some(caller) && edge.kind == RelationKind::Calls)
            .collect();
        assert!(
            calls.is_empty(),
            "{route}: unresolved members of an admitted local package must not acquire a local or external substitute: {calls:?}"
        );
    }
}

#[test]
fn named_reexport_selects_the_declared_function_past_module_and_sibling_twins() {
    let files = [
        parse(
            "app.py",
            "from pkg import search\ndef run():\n    return search()\n",
        ),
        parse("pkg/__init__.py", "from pkg.search import search\n"),
        parse("pkg/search.py", "def search():\n    return 'selected'\n"),
        parse("pkg/decoy.py", "def search():\n    return 'sibling'\n"),
        parse("elsewhere.py", "def search():\n    return 'unrelated'\n"),
    ];
    let target = entity(&files, "pkg/search.py", "search", EntityKind::Function);
    let module = entity(&files, "pkg/search.py", "search", EntityKind::Module);
    assert_ne!(target, module);
    assert_exact_target(&files, target, RelationKind::Calls);
}

#[test]
fn named_reexport_keeps_aliases_at_each_relative_hop_and_at_the_caller() {
    let files = [
        parse("app.py", "from pkg import public as invoke\ndef run():\n    return invoke()\n"),
        parse("pkg/__init__.py", "from .bridge import forward as public\n"),
        parse("pkg/bridge.py", "from .implementation import execute as forward\n"),
        parse("pkg/implementation.py", "def execute():\n    return 'selected'\n"),
        parse("pkg/decoy.py", "def execute():\n    return 'wrong'\ndef public():\n    return 'wrong'\ndef invoke():\n    return 'wrong'\n"),
    ];
    let target = entity(
        &files,
        "pkg/implementation.py",
        "execute",
        EntityKind::Function,
    );
    assert_exact_target(&files, target, RelationKind::Calls);
}

#[test]
fn named_reexport_value_reference_keeps_the_same_declared_function_target() {
    let files = [
        parse(
            "app.py",
            "from pkg import public as invoke\ndef run():\n    return invoke\n",
        ),
        parse(
            "pkg/__init__.py",
            "from .implementation import execute as public\n",
        ),
        parse("pkg/implementation.py", "def execute():\n    return 1\n"),
        parse("elsewhere.py", "def execute():\n    return 2\n"),
    ];
    let target = entity(
        &files,
        "pkg/implementation.py",
        "execute",
        EntityKind::Function,
    );
    assert_exact_target(&files, target, RelationKind::References);
}

#[test]
fn a_same_named_package_sibling_is_not_an_undeclared_reexport() {
    let files = [
        parse(
            "app.py",
            "from pkg import search\ndef run():\n    return search()\n",
        ),
        parse("pkg/__init__.py", "pass\n"),
        parse("pkg/search.py", "def search():\n    return 1\n"),
    ];
    assert_no_caller_calls(&files);
}

#[test]
fn a_missing_reexport_target_does_not_capture_a_same_named_sibling() {
    let files = [
        parse(
            "app.py",
            "from pkg import work\ndef run():\n    return work()\n",
        ),
        parse("pkg/__init__.py", "from .missing import work\n"),
        parse("pkg/decoy.py", "def work():\n    return 1\n"),
    ];
    assert_no_caller_calls(&files);
}

#[test]
fn a_named_reexport_cycle_remains_unresolved_despite_a_matching_declaration() {
    let files = [
        parse(
            "app.py",
            "from pkg import work\ndef run():\n    return work()\n",
        ),
        parse("pkg/__init__.py", "from .bridge import work\n"),
        parse("pkg/bridge.py", "from pkg import work\n"),
        parse("pkg/decoy.py", "def work():\n    return 1\n"),
    ];
    assert_no_caller_calls(&files);
}

#[test]
fn competing_named_reexports_do_not_use_the_flat_maps_last_entry_as_proof() {
    // The bounded helper does not model rebinding order. Keep both source
    // declarations visible and decline this new inference rather than treating
    // HashMap insertion order as an exact export-ownership proof.
    let files = [
        parse(
            "app.py",
            "from pkg import work\ndef run():\n    return work()\n",
        ),
        parse(
            "pkg/__init__.py",
            "from .left import work\nfrom .right import work\n",
        ),
        parse("pkg/left.py", "def work():\n    return 1\n"),
        parse("pkg/right.py", "def work():\n    return 2\n"),
    ];
    assert_no_caller_calls(&files);
}

#[test]
fn guarded_and_function_local_imports_are_not_module_reexports() {
    for package in [
        "if enabled:\n    from .implementation import work\n",
        "def configure():\n    from .implementation import work\n",
    ] {
        let files = [
            parse(
                "app.py",
                "from pkg import work\ndef run():\n    return work()\n",
            ),
            parse("pkg/__init__.py", package),
            parse("pkg/implementation.py", "def work():\n    return 1\n"),
        ];
        assert_no_caller_calls(&files);
    }
}

#[test]
fn a_reexported_module_is_not_its_same_named_callable_declaration() {
    // `import search` and `from search import search` share today's flattened
    // tuple. The new helper must refuse that ambiguity unless richer admitted
    // import-form evidence can establish which value is exported.
    let files = [
        parse(
            "app.py",
            "from pkg import search\ndef run():\n    return search()\n",
        ),
        parse("pkg/__init__.py", "import search\n"),
        parse(
            "search.py",
            "def search():\n    return 'not the module object'\n",
        ),
    ];
    assert_no_caller_calls(&files);
}

#[test]
fn a_named_reexport_overwritten_without_a_graph_entity_does_not_keep_its_old_target() {
    // FileImport records the declaration, not the final Python module binding.
    // These writes are deliberately absent from today's entity inventory. A
    // new re-export inference must therefore require source-derived evidence
    // rather than infer stability from the absence of a competing entity.
    for mutation in [
        "work = None\n",
        "work = replacement\n",
        "work = lambda: 'replacement'\n",
        "work, other = (None, None)\n",
        "del work\n",
        "if enabled:\n    work = None\n",
        "globals()['work'] = None\n",
    ] {
        let package = format!("from .implementation import work\n{mutation}");
        let files = [
            parse(
                "app.py",
                "from pkg import work\ndef run():\n    return work()\n",
            ),
            parse("pkg/__init__.py", &package),
            parse("pkg/implementation.py", "def work():\n    return 'old'\n"),
        ];
        assert!(
            files[1].imports.iter().any(|import| import
                .specifiers
                .iter()
                .any(|specifier| specifier.local_name == "work")),
            "fixture must retain the original import: {mutation}"
        );
        assert!(
            files[1].entities.iter().all(|entity| entity.name != "work"),
            "fixture must exercise a mutation lost by the entity projection: {mutation}"
        );
        assert_no_caller_calls(&files);
    }
}

#[test]
fn reexport_witness_survives_checkpoint_but_is_withdrawn_when_the_slice_changes() {
    let mut files = vec![
        parse(
            "app.py",
            "from pkg import work\ndef run():\n    return work()\n",
        ),
        parse("pkg/__init__.py", "from .impl import work\n"),
        parse("pkg/impl.py", "def work():\n    return 1\n"),
    ];
    let target = entity(&files, "pkg/impl.py", "work", EntityKind::Function);
    let caller = caller(&files);
    let mut linker = IncrementalLinker::new();
    let artifacts: HashMap<_, _> = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    for file in &files {
        linker.add_file(&file.file_path, artifacts[&file.file_path], &file.entities);
    }
    linker.record_class_bases(&files);
    let bytes = serde_json::to_vec(&linker.to_checkpoint_v1()).unwrap();
    let mut linker =
        IncrementalLinker::from_checkpoint_v1(serde_json::from_slice(&bytes).unwrap()).unwrap();
    let calls_target = |linker: &IncrementalLinker, caller_file: &FileParseData| {
        kin_index::link_cross_file_incremental(std::slice::from_ref(caller_file), linker)
            .unwrap()
            .iter()
            .any(|relation| {
                relation.kind == RelationKind::Calls
                    && relation.src.as_entity() == Some(caller)
                    && relation.dst.as_entity() == Some(target)
            })
    };
    assert!(
        calls_target(&linker, &files[0]),
        "unchanged reexport proof must be restored from checkpoint"
    );
    files[1] = parse("pkg/__init__.py", "from .impl import work\nwork = None\n");
    linker.add_file(
        &files[1].file_path,
        artifacts[&files[1].file_path],
        &files[1].entities,
    );
    linker.record_class_bases(&files[1..2]);
    assert!(
        !calls_target(&linker, &files[0]),
        "new bytes retire the old reexport witness"
    );
    files[1] = parse("pkg/__init__.py", "from .impl import work\n");
    linker.add_file(
        &files[1].file_path,
        artifacts[&files[1].file_path],
        &files[1].entities,
    );
    linker.record_class_bases(&files[1..2]);
    assert!(
        calls_target(&linker, &files[0]),
        "new exact proof restores the named binding"
    );
    linker.remove_file("pkg/__init__.py");
    assert!(
        !calls_target(&linker, &files[0]),
        "removed source never retains its witness"
    );
}

#[test]
fn new_reexport_resolution_refuses_caller_parameter_and_module_rebinding() {
    for source in [
        "from pkg import work\ndef run(work):\n    return work()\n",
        "from pkg import work\ndef run():\n    work = lambda: 2\n    return work()\n",
        "from pkg import work\nwork = None\ndef run():\n    return work()\n",
        "from pkg import work\ndel work\ndef run():\n    return work()\n",
    ] {
        let files = [
            parse("app.py", source),
            parse("pkg/__init__.py", "from .impl import work\n"),
            parse("pkg/impl.py", "def work():\n    return 1\n"),
        ];
        assert_no_caller_calls(&files);
    }
}

#[test]
fn exact_reexports_refuse_competing_module_package_and_stub_bodies() {
    for extra in ["pkg.py", "pkg/__init__.pyi", "src/pkg/__init__.py"] {
        let files = vec![
            parse(
                "app.py",
                "from pkg import public\ndef run():\n    return public()\n",
            ),
            parse("pkg/__init__.py", "from chosen import execute as public\n"),
            parse(extra, "from wrong import execute as public\n"),
            parse("chosen.py", "def execute():\n    return 1\n"),
            parse("wrong.py", "def execute():\n    return 2\n"),
        ];
        let source = caller(&files);
        for (route, relations) in routes(&files) {
            let calls: Vec<_> = relations
                .iter()
                .filter(|relation| {
                    relation.kind == RelationKind::Calls && relation.src.as_entity() == Some(source)
                })
                .collect();
            assert!(
                calls.iter().all(
                    |relation| kin_index::is_external_import_placeholder(relation)
                        && relation.confidence == 0.2
                ),
                "{route}: ambiguity must not produce an exact local target: {calls:?}"
            );
        }
    }
}

#[test]
fn synthetic_modules_do_not_capture_exact_named_value_reexports() {
    let files = vec![
        parse(
            "app.py",
            "from pkg import public\ndef run():\n    return public\n",
        ),
        parse("pkg/__init__.py", "from .public import public\n"),
        parse("pkg/public.py", "from .search import search as public\n"),
        parse("pkg/search.py", "def search():\n    return 1\n"),
    ];
    let target = entity(&files, "pkg/search.py", "search", EntityKind::Function);
    assert_exact_target(&files, target, RelationKind::References);
}

#[test]
fn duplicate_source_slices_cannot_restore_witness_authority_by_input_order() {
    let mut files = vec![
        parse(
            "app.py",
            "from pkg import work\ndef run():\n    return work()\n",
        ),
        parse("pkg/__init__.py", "from .impl import work\n"),
        parse("pkg/impl.py", "def work():\n    return 1\n"),
    ];
    files.push(files[1].clone());
    assert_no_caller_calls(&files);
    let mut linker = IncrementalLinker::new();
    let artifacts: HashMap<_, _> = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    for file in &files {
        linker.add_file(&file.file_path, artifacts[&file.file_path], &file.entities);
    }
    linker.record_class_bases(&files);
    let checkpoint = serde_json::to_vec(&linker.to_checkpoint_v1()).unwrap();
    let linker =
        IncrementalLinker::from_checkpoint_v1(serde_json::from_slice(&checkpoint).unwrap())
            .unwrap();
    let relations = kin_index::link_cross_file_incremental(&files[..1], &linker).unwrap();
    let caller = caller(&files);
    assert!(!relations
        .iter()
        .any(|relation| relation.kind == RelationKind::Calls
            && relation.src.as_entity() == Some(caller)));
}

#[test]
fn a_nonpackage_parent_cannot_authorize_a_nested_module_reexport() {
    let files = vec![
        parse(
            "app.py",
            "from pkg import public\ndef run():\n    return public()\n",
        ),
        parse(
            "pkg/__init__.py",
            "from shadow.child import execute as public\n",
        ),
        parse("shadow.py", "pass\n"),
        parse("shadow/child.py", "def execute():\n    return 1\n"),
    ];
    assert_no_caller_calls(&files);
}

#[test]
fn checkpoint_refuses_noncanonical_duplicate_and_unbound_import_witnesses() {
    let files = [
        parse(
            "app.py",
            "from pkg import work\ndef run():\n    return work()\n",
        ),
        parse("pkg/__init__.py", "from .impl import work\n"),
        parse("pkg/impl.py", "def work():\n    return 1\n"),
    ];
    let mut linker = IncrementalLinker::new();
    for file in &files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker.record_class_bases(&files);
    let clean = serde_json::to_value(linker.to_checkpoint_v1()).unwrap();
    assert!(
        IncrementalLinker::from_checkpoint_v1(serde_json::from_value(clean.clone()).unwrap())
            .is_ok()
    );
    for case in [
        "duplicate-payload-key",
        "noncanonical-payload",
        "duplicate-record",
        "stale-digest",
        "unbound-digest",
    ] {
        let mut corrupt = clean.clone();
        match case {
            "duplicate-payload-key" | "noncanonical-payload" => {
                let entry = corrupt["exact_import_witnesses"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|entry| entry[0] == "pkg/__init__.py")
                    .unwrap();
                let payload = entry[1].as_str().unwrap();
                let rewritten = if case == "noncanonical-payload" {
                    format!(" {payload}")
                } else {
                    let pair = "\"work\":{\"module\":\".impl\",\"original\":\"work\"}";
                    assert!(payload.contains(pair));
                    payload.replace(pair, &format!("{pair},{pair}"))
                };
                entry[1] = serde_json::Value::String(rewritten);
            }
            "duplicate-record" => {
                let records = corrupt["exact_import_witnesses"].as_array_mut().unwrap();
                records.push(records[0].clone());
            }
            "stale-digest" => {
                corrupt["source_digests_by_file"][0][1] = serde_json::json!("0".repeat(64))
            }
            "unbound-digest" => corrupt["source_digests_by_file"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!(["unadmitted.py", "0".repeat(64)])),
            _ => unreachable!(),
        }
        let checkpoint = serde_json::from_value(corrupt).unwrap();
        assert!(
            IncrementalLinker::from_checkpoint_v1(checkpoint).is_err(),
            "{case} must not restore usable authority"
        );
    }
}
