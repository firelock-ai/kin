// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A selector's member name must never capture a free global of that name.
//! Exercise extraction, initial indexing, full linking, and staged relinking.

use kin_index::{
    link_cross_file, link_cross_file_incremental, FileParseData, IncrementalLinker, IndexPipeline,
    RelationResolution,
};
use kin_model::{ArtifactId, EntityId, FilePathId, Relation, RelationKind};
use kin_parser::{GoAdapter, LanguageAdapter};

const TASK: &str = r#"package task
var Name string

type Task struct { Name string }
type Other struct { Name string }
func Read(t Task) string { return t.Name }
func Write(t *Task, next string) { t.Name = next }
func Bare() string { return Name }
"#;
const CLIENT: &str = r#"package client
import "example/task"
import pkg "example/remote"
var Name string
func CrossRead(t task.Task) string { return t.Name }
func CrossWrite(t *task.Task, next string) { t.Name = next }
func External() string { return pkg.Name }
func CrossBare() string { return Name }
"#;

fn parse(path: &str, source: &str) -> FileParseData {
    let adapter = GoAdapter;
    let file = FilePathId::new(path);
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).unwrap();
    let output = adapter.extract(&tree, bytes, &file).unwrap();
    FileParseData {
        file_path: path.to_string(),
        entities: output
            .entities
            .into_iter()
            .map(|entity| entity.into_entity_with_source(adapter.language_id(), &file, Some(bytes)))
            .collect(),
        relations: output.relations,
        imports: output.imports,
    }
}

fn id(files: &[FileParseData], path: &str, name: &str) -> EntityId {
    files
        .iter()
        .find(|file| file.file_path == path)
        .unwrap()
        .entities
        .iter()
        .find(|entity| entity.name == name)
        .unwrap()
        .id
}

fn reference(relations: &[Relation], src: EntityId, dst: EntityId) -> Option<&Relation> {
    relations.iter().find(|relation| {
        relation.kind == RelationKind::References
            && relation.src.as_entity() == Some(src)
            && relation.dst.as_entity() == Some(dst)
    })
}

fn assert_selector_targets(
    files: &[FileParseData],
    relations: &[Relation],
    callers: &[(&str, &str)],
) {
    let fields = [
        id(files, "task.go", "Task.Name"),
        id(files, "task.go", "Other.Name"),
    ];
    let globals = [id(files, "task.go", "Name"), id(files, "client.go", "Name")];
    for &(path, name) in callers {
        let src = id(files, path, name);
        for field in fields {
            let candidate = reference(relations, src, field).expect("field candidate retained");
            assert_eq!(candidate.confidence, 0.3);
            assert_eq!(
                RelationResolution::of(candidate),
                RelationResolution::NameOnly
            );
            assert!(!RelationResolution::of(candidate).is_proven());
            assert!(candidate
                .evidence
                .iter()
                .any(|evidence| evidence.token.as_deref() == Some("t.Name")
                    && evidence.source_span.is_some()));
        }
        for global in globals {
            assert!(
                reference(relations, src, global).is_none(),
                "{path}:{name} must not reference a free Name through t.Name"
            );
        }
    }
}

#[test]
fn selector_provenance_distinguishes_fields_from_imported_names() {
    let file = parse(
        "selectors.go",
        r#"package task
import Name "example/unrelated"
import pkg "example/remote"
type Task struct { Name string }
func Read(t Task) { consume(t.Name, t.Inner.Name, makeTask().Name, pkg.Name) }
"#,
    );
    let selectors: Vec<_> = file
        .relations
        .iter()
        .filter(|rel| rel.kind == RelationKind::References && rel.dst_name == "Name")
        .collect();
    for receiver in ["t", "t.Inner", "makeTask()", "pkg"] {
        let relation = selectors
            .iter()
            .find(|rel| rel.src_name == "Read" && rel.receiver.as_deref() == Some(receiver))
            .expect("receiver preserved");
        assert_eq!(
            relation.import_source.as_deref(),
            (receiver == "pkg").then_some("example/remote")
        );
    }
    let same_name = parse("same_name.go", "package task\ntype Task struct { Name string }\nfunc Name(t Task) string { return t.Name }");
    assert!(
        same_name
            .relations
            .iter()
            .any(|rel| rel.kind == RelationKind::References
                && rel.src_name == "Name"
                && rel.dst_name == "Name"
                && rel.receiver.as_deref() == Some("t")),
        "a member sharing its enclosing function's name is still a reference"
    );
}

#[test]
fn batch_keeps_field_reads_and_writes_as_candidates_and_free_values_as_values() {
    let files = vec![parse("task.go", TASK), parse("client.go", CLIENT)];
    let artifacts = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = link_cross_file(&files, &artifacts).unwrap();
    assert_selector_targets(
        &files,
        &relations,
        &[
            ("task.go", "Read"),
            ("task.go", "Write"),
            ("client.go", "CrossRead"),
            ("client.go", "CrossWrite"),
        ],
    );
    for (path, caller) in [("task.go", "Bare"), ("client.go", "CrossBare")] {
        let src = id(&files, path, caller);
        assert_eq!(
            reference(&relations, src, id(&files, path, "Name"))
                .unwrap()
                .confidence,
            1.0
        );
        assert!(reference(&relations, src, id(&files, "task.go", "Task.Name")).is_none());
    }
    let external = id(&files, "client.go", "External");
    for (path, target) in [
        ("task.go", "Task.Name"),
        ("task.go", "Other.Name"),
        ("task.go", "Name"),
        ("client.go", "Name"),
    ] {
        assert!(
            reference(&relations, external, id(&files, path, target)).is_none(),
            "an imported package selector must not capture a local field or global"
        );
    }
}

#[test]
fn initial_indexing_defers_selector_leaves_instead_of_binding_same_file_globals() {
    let indexed = IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new("task.go"),
            TASK.as_bytes(),
            kin_blobs::digest(TASK.as_bytes()),
        )
        .unwrap()
        .indexed_file;
    let global = indexed
        .entities
        .iter()
        .find(|entity| entity.name == "Name")
        .unwrap()
        .id;
    for name in ["Read", "Write"] {
        let src = indexed
            .entities
            .iter()
            .find(|entity| entity.name == name)
            .unwrap()
            .id;
        assert!(reference(&indexed.relations, src, global).is_none());
        assert!(indexed
            .extracted_relations
            .iter()
            .any(|rel| rel.src_name == name
                && rel.dst_name == "Name"
                && rel.receiver.as_deref() == Some("t")));
    }
}

#[test]
fn incremental_caller_only_edit_keeps_field_candidates_and_import_gaps() {
    let mut files = vec![parse("task.go", TASK), parse("client.go", CLIENT)];
    let mut linker = IncrementalLinker::new();
    for file in &files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    let initial = link_cross_file_incremental(&files, &linker).unwrap();
    assert_selector_targets(
        &files,
        &initial,
        &[("client.go", "CrossRead"), ("client.go", "CrossWrite")],
    );
    let artifact = ArtifactId::new();
    files[1] = parse("client.go", &format!("{CLIENT}\n// comment-only edit\n"));
    linker.remove_file("client.go");
    linker.add_file("client.go", artifact, &files[1].entities);
    let relations = link_cross_file_incremental(&files[1..], &linker).unwrap();
    assert_selector_targets(
        &files,
        &relations,
        &[("client.go", "CrossRead"), ("client.go", "CrossWrite")],
    );
    let external = id(&files, "client.go", "External");
    for name in ["Task.Name", "Other.Name", "Name"] {
        assert!(reference(&relations, external, id(&files, "task.go", name)).is_none());
    }
}

#[test]
fn a_bare_identifier_does_not_fan_out_to_a_struct_field() {
    let files = vec![
        parse("task.go", "package task\ntype Task struct { Name string }"),
        parse(
            "client.go",
            "package task\nfunc Read(Name string) string { return Name }",
        ),
    ];
    let artifacts = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = link_cross_file(&files, &artifacts).unwrap();
    assert!(reference(
        &relations,
        id(&files, "client.go", "Read"),
        id(&files, "task.go", "Task.Name")
    )
    .is_none());
}
