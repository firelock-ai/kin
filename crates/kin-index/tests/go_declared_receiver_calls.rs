// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_index::{
    link_cross_file, link_cross_file_incremental, FileParseData, IncrementalLinker, IndexPipeline,
    RelationResolution,
};
use kin_model::{ArtifactId, Entity, EntityId, EntityKind, FilePathId, Relation, RelationKind};
use kin_parser::{attach_go_package_metadata, GoAdapter, LanguageAdapter};

fn parse(path: &str, source: &str) -> FileParseData {
    let adapter = GoAdapter;
    let file_id = FilePathId::new(path);
    let tree = adapter.parse(source.as_bytes()).unwrap();
    let output = adapter.extract(&tree, source.as_bytes(), &file_id).unwrap();
    let mut entities: Vec<Entity> = output
        .entities
        .into_iter()
        .map(|entity| {
            entity.into_entity_with_source(adapter.language_id(), &file_id, Some(source.as_bytes()))
        })
        .collect();
    attach_go_package_metadata(&tree, source.as_bytes(), &mut entities);
    FileParseData {
        file_path: path.into(),
        entities,
        relations: output.relations,
        imports: output.imports,
    }
}

fn entity(file: &FileParseData, name: &str) -> EntityId {
    file.entities
        .iter()
        .find(|entity| entity.name == name)
        .unwrap()
        .id
}

fn call_targets(relations: &[Relation], caller: EntityId) -> Vec<EntityId> {
    let mut targets: Vec<_> = relations
        .iter()
        .filter(|relation| {
            relation.kind == RelationKind::Calls && relation.src.as_entity() == Some(caller)
        })
        .filter_map(|relation| relation.dst.as_entity())
        .collect();
    targets.sort();
    targets.dedup();
    targets
}

fn batch(files: &[FileParseData]) -> Vec<Relation> {
    let identities = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    link_cross_file(files, &identities).unwrap()
}

fn incremental(files: &[FileParseData]) -> IncrementalLinker {
    let mut linker = IncrementalLinker::new();
    for file in files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker
}

#[test]
fn same_file_receiver_calls_keep_each_site_and_do_not_capture_a_free_function() {
    let source = "package app\ntype App struct{}\nfunc (a *App) Run() { a.prepare(); a.prepare(); prepare() }\nfunc (a *App) prepare() {}\nfunc prepare() {}\n";
    let files = [parse("app.go", source)];
    let caller = entity(&files[0], "App.Run");
    let method = entity(&files[0], "App.prepare");
    let free = entity(&files[0], "prepare");
    for relations in [
        batch(&files),
        link_cross_file_incremental(&files, &incremental(&files)).unwrap(),
    ] {
        let mut expected = vec![method, free];
        expected.sort();
        assert_eq!(call_targets(&relations, caller), expected);
        let edge = relations
            .iter()
            .find(|r| {
                r.src.as_entity() == Some(caller)
                    && r.dst.as_entity() == Some(method)
                    && r.kind == RelationKind::Calls
            })
            .unwrap();
        assert_eq!(
            RelationResolution::of(edge),
            RelationResolution::TypeResolved
        );
        assert_eq!(edge.evidence.len(), 2);
        assert!(edge
            .evidence
            .iter()
            .all(|evidence| evidence.source_span.is_some()));
    }

    let indexed = IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("app.go"),
            source.as_bytes(),
            kin_blobs::digest(source.as_bytes()),
        )
        .unwrap()
        .indexed_file;
    assert!(indexed.entities.iter().all(|e| e
        .metadata
        .extra
        .get("go_package")
        .and_then(|v| v.as_str())
        == Some("app")));
    let method = indexed
        .entities
        .iter()
        .find(|e| e.name == "App.prepare")
        .unwrap()
        .id;
    let caller = indexed
        .entities
        .iter()
        .find(|e| e.name == "App.Run")
        .unwrap()
        .id;
    assert!(call_targets(&indexed.relations, caller).contains(&method));
}

fn package_fixture() -> Vec<FileParseData> {
    vec![
        parse("pkg/types.go", "package app\ntype App struct{}\n"),
        parse(
            "pkg/run.go",
            "package app\nfunc (a *App) Run() { a.prepare() }\n",
        ),
        parse(
            "pkg/prepare.go",
            "package app\nfunc (a *App) prepare() {}\n",
        ),
        parse(
            "other/app.go",
            "package app\ntype App struct{}\nfunc (a *App) prepare() {}\n",
        ),
        parse(
            "pkg/external_test.go",
            "package app_test\ntype App struct{}\nfunc (a *App) prepare() {}\n",
        ),
        parse(
            "pkg/other.go",
            "package app\ntype Other struct{}\nfunc (o *Other) prepare() {}\n",
        ),
    ]
}

#[test]
fn cross_file_dispatch_uses_package_and_receiver_through_incremental_checkpoint() {
    let files = package_fixture();
    let caller = entity(&files[1], "App.Run");
    let target = entity(&files[2], "App.prepare");
    let linker = incremental(&files);
    let encoded = serde_json::to_vec(&linker.to_checkpoint_v1()).unwrap();
    let restored =
        IncrementalLinker::from_checkpoint_v1(serde_json::from_slice(&encoded).unwrap()).unwrap();
    assert_eq!(
        encoded,
        serde_json::to_vec(&restored.to_checkpoint_v1()).unwrap()
    );
    for relations in [
        batch(&files),
        link_cross_file_incremental(&files[1..2], &linker).unwrap(),
        link_cross_file_incremental(&files[1..2], &restored).unwrap(),
    ] {
        assert_eq!(call_targets(&relations, caller), vec![target]);
        let edge = relations
            .iter()
            .find(|r| r.src.as_entity() == Some(caller) && r.dst.as_entity() == Some(target))
            .unwrap();
        assert_eq!(
            RelationResolution::of(edge),
            RelationResolution::TypeResolved
        );
    }
}

#[test]
fn named_scalar_receiver_does_not_require_a_struct_entity() {
    let files = [
        parse(
            "pkg/app.go",
            "package app\ntype App string\nfunc (a App) Run() { a.prepare() }\n",
        ),
        parse("pkg/prepare.go", "package app\nfunc (a App) prepare() {}\n"),
    ];
    let caller = entity(&files[0], "App.Run");
    let target = entity(&files[1], "App.prepare");
    assert_eq!(
        files[0]
            .entities
            .iter()
            .find(|e| e.name == "App")
            .unwrap()
            .kind,
        EntityKind::TypeAlias
    );
    assert_eq!(call_targets(&batch(&files), caller), vec![target]);
}

#[test]
fn a_removed_method_never_rebinds_to_another_package() {
    let files = package_fixture();
    let caller = entity(&files[1], "App.Run");
    let mut linker = incremental(&files);
    linker.remove_file(&files[2].file_path);
    assert!(call_targets(
        &link_cross_file_incremental(&files[1..2], &linker).unwrap(),
        caller
    )
    .is_empty());
    let remaining: Vec<_> = files
        .into_iter()
        .enumerate()
        .filter_map(|(i, file)| (i != 2).then_some(file))
        .collect();
    assert!(call_targets(&batch(&remaining), caller).is_empty());
}

#[test]
fn missing_or_ambiguous_package_evidence_does_not_become_dispatch_proof() {
    let mut files = package_fixture();
    let caller = entity(&files[1], "App.Run");
    files[2].entities.iter_mut().for_each(|e| {
        e.metadata.extra.remove("go_package");
    });
    assert!(call_targets(&batch(&files), caller).is_empty());
    let mut files = package_fixture();
    files.push(parse(
        "pkg/duplicate.go",
        "package app\nfunc (a *App) prepare() {}\n",
    ));
    let caller = entity(&files[1], "App.Run");
    assert!(call_targets(&batch(&files), caller).is_empty());
}

#[test]
fn receiver_binding_respects_nested_scopes_and_initializer_order() {
    let source = r#"package app
type App struct{}
type Other struct{}
func (a *App) Run(ch chan Other, value interface{}) {
    a.before()
    { a := a.makeOther(); a.local() }
    a.after()
    if a := a.makeOther(); a.valid() { a.branch() }
    a.afterIf()
    for _, a := range a.values() { a.ranged() }
    func(a Other) { a.parameter() }(Other{})
    func() { a.captured() }()
    switch a := value.(type) { default: a.switched() }
    select { case a := <-ch: a.received(); default: a.defaulted() }
    { var a Other; a.variable() }
    a.final()
}
"#;
    let file = parse("pkg/app.go", source);
    let names: Vec<_> = file
        .relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .map(|r| r.dst_name.as_str())
        .collect();
    for name in [
        "before",
        "makeOther",
        "after",
        "afterIf",
        "values",
        "captured",
        "defaulted",
        "final",
    ] {
        assert!(
            names.contains(&format!("App.{name}").as_str()),
            "missing bound receiver {name}: {names:?}"
        );
    }
    for name in [
        "local",
        "valid",
        "branch",
        "ranged",
        "parameter",
        "switched",
        "received",
        "variable",
    ] {
        assert!(
            names.contains(&name),
            "missing shadowed receiver {name}: {names:?}"
        );
        assert!(
            !names.contains(&format!("App.{name}").as_str()),
            "incorrect owner for {name}: {names:?}"
        );
    }
}

#[test]
fn a_receiver_binding_wins_over_a_same_named_file_import() {
    let files = [parse("app.go", "package app\nimport a \"external/decoy\"\ntype App struct{}\nfunc (a *App) Run() { a.prepare() }\nfunc (a *App) prepare() {}\n")];
    let caller = entity(&files[0], "App.Run");
    assert_eq!(
        call_targets(&batch(&files), caller),
        vec![entity(&files[0], "App.prepare")]
    );
    let call = files[0]
        .relations
        .iter()
        .find(|r| r.kind == RelationKind::Calls)
        .unwrap();
    assert!(call.import_source.is_none());
}

#[test]
fn a_shadowed_receiver_cannot_become_an_import_or_free_function() {
    let source = "package app\nimport a \"external/decoy\"\ntype App struct{}\ntype Other struct{}\nfunc (a *App) Run() { { a := Other{}; a.prepare() }; a.prepare() }\nfunc (a *App) prepare() {}\nfunc (a *Other) prepare() {}\nfunc prepare() {}\n";
    let files = [parse("app.go", source)];
    let caller = entity(&files[0], "App.Run");
    let free = entity(&files[0], "prepare");
    let calls: Vec<_> = files[0]
        .relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls && r.src_name == "App.Run")
        .collect();
    assert_eq!(calls.len(), 2);
    assert!(calls
        .iter()
        .all(|r| r.receiver.as_deref() == Some("a") && r.import_source.is_none()));
    assert_eq!(calls[0].dst_name, "prepare");
    assert_eq!(calls[1].dst_name, "App.prepare");
    for relations in [
        batch(&files),
        link_cross_file_incremental(&files, &incremental(&files)).unwrap(),
    ] {
        assert!(!call_targets(&relations, caller).contains(&free));
    }
    let indexed = IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("app.go"),
            source.as_bytes(),
            kin_blobs::digest(source.as_bytes()),
        )
        .unwrap()
        .indexed_file;
    let free = indexed
        .entities
        .iter()
        .find(|e| e.name == "prepare")
        .unwrap()
        .id;
    assert!(!indexed
        .relations
        .iter()
        .any(|r| r.dst.as_entity() == Some(free)));
}
