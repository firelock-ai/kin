// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Go declares a receiver's type and methods anywhere in one package.
//! Ownership must survive that layout without borrowing a namesake elsewhere.

use kin_db::InMemoryGraph;
use kin_index::{
    interface_implementations, link_cross_file, link_cross_file_incremental, FileParseData,
    IncrementalLinker, IndexPipeline,
};
use kin_model::{ArtifactId, EntityId, EntityStore, FilePathId, Relation, RelationKind};

fn parse(path: &str, source: &str) -> FileParseData {
    let indexed = IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new(path),
            source.as_bytes(),
            kin_blobs::digest(source.as_bytes()),
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

fn id(files: &[FileParseData], path: &str, name: &str) -> EntityId {
    files
        .iter()
        .find(|f| f.file_path == path)
        .unwrap()
        .entities
        .iter()
        .find(|e| e.name == name)
        .unwrap()
        .id
}

fn linker(files: &[FileParseData]) -> IncrementalLinker {
    let mut linker = IncrementalLinker::new();
    for file in files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker
}

fn modes(files: &[FileParseData]) -> [Vec<Relation>; 3] {
    let artifacts = files
        .iter()
        .map(|f| (f.file_path.clone(), ArtifactId::new()))
        .collect();
    let linker = linker(files);
    let encoded = serde_json::to_vec(&linker.to_checkpoint_v1()).unwrap();
    let restored =
        IncrementalLinker::from_checkpoint_v1(serde_json::from_slice(&encoded).unwrap()).unwrap();
    [
        link_cross_file(files, &artifacts).unwrap(),
        link_cross_file_incremental(files, &linker).unwrap(),
        link_cross_file_incremental(files, &restored).unwrap(),
    ]
}

fn owners(relations: &[Relation], method: EntityId) -> Vec<EntityId> {
    let mut owners: Vec<_> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Contains && r.dst.as_entity() == Some(method))
        .filter_map(|r| r.src.as_entity())
        .collect();
    owners.sort();
    owners.dedup();
    owners
}

#[test]
fn cross_file_go_receivers_keep_their_own_types_and_interface_implementations() {
    let files = vec![
        parse("api/types.go", "package api\ntype Issue struct{}\ntype PullRequest struct{}\ntype Repository struct{}\n"),
        parse("api/export.go", "package api\nfunc (i *Issue) ExportData() string { return \"\" }\nfunc (p PullRequest) ExportData() string { return \"\" }\nfunc (r *Repository) ExportData() string { return \"\" }\n"),
        parse("search/result.go", "package search\ntype Issue struct{}\nfunc (i Issue) ExportData() string { return \"\" }\n"),
        parse("api/external_test.go", "package api_test\ntype Issue struct{}\nfunc (i Issue) ExportData() string { return \"\" }\n"),
        parse("app/common.go", "package app\ntype App struct{}\n"),
        parse("app/create.go", "package app\nfunc (a *App) Create() {}\n"),
        parse("contract/export.go", "package contract\ntype Exportable interface { ExportData() string }\n"),
    ];
    for relations in modes(&files) {
        for name in ["Issue", "PullRequest", "Repository"] {
            assert_eq!(
                owners(
                    &relations,
                    id(&files, "api/export.go", &format!("{name}.ExportData"))
                ),
                vec![id(&files, "api/types.go", name)],
                "{name}'s owner is declared in another file of the same package"
            );
        }
        assert_eq!(
            owners(&relations, id(&files, "app/create.go", "App.Create")),
            vec![id(&files, "app/common.go", "App")]
        );
        for (path, name) in [
            ("search/result.go", "Issue"),
            ("api/external_test.go", "Issue"),
        ] {
            assert_eq!(
                owners(&relations, id(&files, path, "Issue.ExportData")),
                vec![id(&files, path, name)]
            );
        }
        let graph = InMemoryGraph::new();
        for entity in files.iter().flat_map(|f| &f.entities) {
            graph.upsert_entity(entity).unwrap();
        }
        for relation in &relations {
            graph.upsert_relation(relation).unwrap();
        }
        let focal = graph
            .get_entity(&id(&files, "contract/export.go", "Exportable.ExportData"))
            .unwrap()
            .unwrap();
        let found = interface_implementations(&graph, &focal).unwrap();
        assert_eq!(
            found.len(),
            5,
            "three split owners plus the two independent same-file controls"
        );
        for name in ["Issue", "PullRequest", "Repository"] {
            assert!(found.iter().any(|row| row.method_id
                == id(&files, "api/export.go", &format!("{name}.ExportData"))
                && row.receiver_id == id(&files, "api/types.go", name)));
        }
    }
}

#[test]
fn cross_file_go_receiver_requires_directory_clause_type_and_unique_owner() {
    let method = "package api\nfunc (i *Issue) ExportData() {}\n";
    for decoys in [
        vec![parse("other/type.go", "package api\ntype Issue struct{}\n")],
        vec![parse(
            "api/type_test.go",
            "package api_test\ntype Issue struct{}\n",
        )],
        vec![parse("api/function.go", "package api\nfunc Issue() {}\n")],
        vec![
            parse("api/one.go", "package api\ntype Issue struct{}\n"),
            parse("api/two.go", "package api\ntype Issue struct{}\n"),
        ],
    ] {
        let mut files = vec![parse("api/export.go", method)];
        files.extend(decoys);
        for relations in modes(&files) {
            assert!(owners(&relations, id(&files, "api/export.go", "Issue.ExportData")).is_empty());
        }
    }
    // A same-file declaration cannot hide a duplicate owner in its package.
    let files = [
        parse(
            "api/export.go",
            "package api\ntype Issue struct{}\nfunc (i Issue) ExportData() {}\n",
        ),
        parse("api/duplicate.go", "package api\ntype Issue struct{}\n"),
    ];
    for relations in modes(&files) {
        assert!(owners(&relations, id(&files, "api/export.go", "Issue.ExportData")).is_empty());
    }
}

#[test]
fn cross_file_go_receiver_never_guesses_missing_package_metadata() {
    for missing in [0, 1] {
        let mut files = [
            parse("api/types.go", "package api\ntype Issue struct{}\n"),
            parse(
                "api/export.go",
                "package api\nfunc (i *Issue) ExportData() {}\n",
            ),
        ];
        for entity in &mut files[missing].entities {
            entity.metadata.extra.remove("go_package");
        }
        for relations in modes(&files) {
            assert!(owners(&relations, id(&files, "api/export.go", "Issue.ExportData")).is_empty());
        }
    }
}

#[test]
fn cross_file_go_named_scalar_and_generic_receivers_have_owners() {
    let files = [parse("api/types.go", "package api\ntype Key string\ntype Box[T any] struct { value T }\n"), parse("api/methods.go", "package api\nfunc (k Key) String() string { return string(k) }\nfunc (b *Box[T]) Value() T { return b.value }\n")];
    for relations in modes(&files) {
        for (owner, method) in [("Key", "Key.String"), ("Box", "Box.Value")] {
            assert_eq!(
                owners(&relations, id(&files, "api/methods.go", method)),
                vec![id(&files, "api/types.go", owner)]
            );
        }
    }
}

#[test]
fn cross_file_go_owner_removal_and_replacement_relink_an_unchanged_method() {
    let files = [
        parse("api/types.go", "package api\ntype Issue struct{}\n"),
        parse(
            "api/export.go",
            "package api\nfunc (i *Issue) ExportData() {}\n",
        ),
    ];
    let method = id(&files, "api/export.go", "Issue.ExportData");
    let mut linker = linker(&files);
    assert_eq!(
        owners(
            &link_cross_file_incremental(&files[1..], &linker).unwrap(),
            method
        ),
        vec![id(&files, "api/types.go", "Issue")]
    );
    linker.remove_file("api/types.go");
    assert!(owners(
        &link_cross_file_incremental(&files[1..], &linker).unwrap(),
        method
    )
    .is_empty());
    let renamed = parse("api/types.go", "package api\ntype Renamed struct{}\n");
    linker.add_file(&renamed.file_path, ArtifactId::new(), &renamed.entities);
    assert!(owners(
        &link_cross_file_incremental(&files[1..], &linker).unwrap(),
        method
    )
    .is_empty());
    let restored = parse(
        "api/types.go",
        "package api\ntype Issue struct{ Number int }\n",
    );
    linker.add_file(&restored.file_path, ArtifactId::new(), &restored.entities);
    assert_eq!(
        owners(
            &link_cross_file_incremental(&files[1..], &linker).unwrap(),
            method
        ),
        vec![
            restored
                .entities
                .iter()
                .find(|e| e.name == "Issue")
                .unwrap()
                .id
        ]
    );
}
