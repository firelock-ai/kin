// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_index::{
    link_cross_file_incremental, FileParseData, IncrementalLinker, IndexPipeline,
    RelationResolution,
};
use kin_model::{ArtifactId, EntityId, FilePathId, Relation, RelationKind};

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

fn entity(file: &FileParseData, name: &str) -> EntityId {
    file.entities
        .iter()
        .find(|entity| entity.name == name)
        .unwrap()
        .id
}

fn call(relations: &[Relation], source: EntityId, target: EntityId) -> &Relation {
    relations
        .iter()
        .find(|relation| {
            relation.kind == RelationKind::Calls
                && relation.src.as_entity() == Some(source)
                && relation.dst.as_entity() == Some(target)
        })
        .expect("expected call survives retained-state linking")
}

#[test]
fn mixed_language_checkpoint_keeps_call_evidence_through_restart_and_removal() {
    let files = vec![
        parse("pkg/run.go", "package app\ntype App struct{}\nfunc (a *App) Run() { a.prepare() }\n"),
        parse("pkg/prepare.go", "package app\nfunc (a *App) prepare() {}\n"),
        parse("other/prepare.go", "package app\ntype App struct{}\nfunc (a *App) prepare() {}\n"),
        parse("base.py", "class Base:\n    def send(self, request):\n        return request\n    def resolve(self, request):\n        return self.send(request)\n"),
        parse("child.py", "from base import Base as Alias\nclass Child(Alias):\n    def send(self, request):\n        return request\n"),
        parse("members.js", "export const app = {}; for (const key of ['get', 'post']) { app[key] = () => {}; }"),
        parse("caller.js", "import { app } from './members'; export function run() { app.get(); }"),
    ];
    let mut linker = IncrementalLinker::new();
    for file in &files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker.record_class_bases(&files);
    let callers = [files[0].clone(), files[3].clone(), files[6].clone()];
    let go_caller = entity(&files[0], "App.Run");
    let go_target = entity(&files[1], "App.prepare");
    let foreign_go_target = entity(&files[2], "App.prepare");
    let python_caller = entity(&files[3], "Base.resolve");
    let python_target = entity(&files[3], "Base.send");
    let js_caller = entity(&files[6], "run");
    let js_target = entity(&files[5], "app.get");

    let check = |linker: &IncrementalLinker| {
        let relations = link_cross_file_incremental(&callers, linker).unwrap();
        assert_eq!(
            RelationResolution::of(call(&relations, go_caller, go_target)),
            RelationResolution::TypeResolved
        );
        assert!(!relations
            .iter()
            .any(|relation| relation.src.as_entity() == Some(go_caller)
                && relation.dst.as_entity() == Some(foreign_go_target)));
        let python_call = call(&relations, python_caller, python_target);
        assert_eq!(
            python_call.confidence,
            kin_index::resolution::DISPATCH_CANDIDATE_CONFIDENCE
        );
        assert_eq!(
            RelationResolution::of(python_call),
            RelationResolution::ImportScoped
        );
        assert_eq!(
            RelationResolution::of(call(&relations, js_caller, js_target)),
            RelationResolution::NameOnly
        );
    };
    check(&linker);
    let encoded = serde_json::to_vec(&linker.to_checkpoint_v1()).unwrap();
    let mut restored =
        IncrementalLinker::from_checkpoint_v1(serde_json::from_slice(&encoded).unwrap()).unwrap();
    check(&restored);

    // Unchanged callers are re-linked from retained parse fragments after the
    // corresponding declarations disappear. A restart must not make retired
    // evidence authoritative, or allow a same-named foreign Go method through.
    for path in ["pkg/prepare.go", "child.py", "members.js"] {
        restored.remove_file(path);
    }
    let encoded = serde_json::to_vec(&restored.to_checkpoint_v1()).unwrap();
    let restored =
        IncrementalLinker::from_checkpoint_v1(serde_json::from_slice(&encoded).unwrap()).unwrap();
    let relations = link_cross_file_incremental(&callers, &restored).unwrap();
    assert!(!relations
        .iter()
        .any(|relation| relation.dst.as_entity().is_some_and(|id| [
            go_target,
            foreign_go_target,
            js_target
        ]
        .contains(&id))));
    assert_eq!(
        call(&relations, python_caller, python_target).confidence,
        1.0
    );
}
