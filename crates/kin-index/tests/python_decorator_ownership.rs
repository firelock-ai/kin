// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_index::{
    link_cross_file, link_cross_file_incremental, relation_source_entity, FileParseData,
    IncrementalLinker,
};
use kin_model::{ArtifactId, FilePathId, RelationKind};
use kin_parser::{LanguageAdapter, PythonAdapter};

fn parsed(source: &str) -> FileParseData {
    let adapter = PythonAdapter;
    let path = FilePathId::new("calls.py");
    let tree = adapter.parse(source.as_bytes()).unwrap();
    let output = adapter.extract(&tree, source.as_bytes(), &path).unwrap();
    FileParseData {
        file_path: path.to_string(),
        entities: output
            .entities
            .into_iter()
            .map(|entity| entity.into_entity(adapter.language_id(), &path))
            .collect(),
        relations: output.relations,
        imports: output.imports,
    }
}

#[test]
fn repeated_decorators_keep_their_callers_in_batch_incremental_and_reopened_linkers() {
    let file = parsed("from foreign import wrap, step\n\n@wrap\ndef run():\n    return step(1)\n\n@wrap\ndef run():\n    return step(2)\n");
    let artifact = ArtifactId::new();
    let ids = [(file.file_path.clone(), artifact)].into_iter().collect();
    let mut linker = IncrementalLinker::new();
    linker.add_file(&file.file_path, artifact, &file.entities);
    let reopened = IncrementalLinker::from_checkpoint_v1(linker.to_checkpoint_v1()).unwrap();
    let batch = link_cross_file(std::slice::from_ref(&file), &ids).unwrap();
    for relations in [
        batch,
        link_cross_file_incremental(std::slice::from_ref(&file), &linker).unwrap(),
        link_cross_file_incremental(std::slice::from_ref(&file), &reopened).unwrap(),
    ] {
        for owner in file.entities.iter().filter(|entity| entity.name == "run") {
            let calls: Vec<_> = relations
                .iter()
                .filter(|relation| {
                    relation.src.as_entity() == Some(owner.id)
                        && relation.kind == RelationKind::Calls
                })
                .collect();
            assert_eq!(calls.len(), 2);
            assert!(calls.iter().all(|relation| relation
                .evidence
                .iter()
                .map(|row| row.occurrence_count)
                .sum::<u32>()
                == 1));
        }
    }
    let mut fragment = file.clone();
    fragment.entities.clear();
    assert!(
        !link_cross_file_incremental(&[fragment], &reopened)
            .unwrap()
            .iter()
            .any(|edge| edge.kind == RelationKind::Calls),
        "a fragment without declaration spans cannot guess between same-name sources"
    );
}

#[test]
fn source_sites_choose_only_a_unique_innermost_declaration() {
    let mut file = parsed("from foreign import step\ndef run():\n    return step(1)\ndef run():\n    return step(2)\n");
    let call = file
        .relations
        .iter()
        .rfind(|relation| relation.dst_name == "step")
        .unwrap()
        .clone();
    let mut owners: Vec<_> = file
        .entities
        .drain(..)
        .filter(|entity| entity.name == "run")
        .collect();
    owners.sort_by_key(|entity| entity.span.as_ref().unwrap().start_byte);
    let expected = owners[1].id;
    owners[0].span.as_mut().unwrap().end_byte = owners[1].span.as_ref().unwrap().end_byte;
    assert_eq!(relation_source_entity(&call, &owners).unwrap().id, expected);
    owners[1].span.as_mut().unwrap().end_byte += 1;
    assert!(
        relation_source_entity(&call, &owners).is_none(),
        "overlap alone is not lexical nesting"
    );
    owners[0].span = owners[1].span.clone();
    assert!(
        relation_source_entity(&call, &owners).is_none(),
        "equal spans are not lexical ownership"
    );
    let mut missing = call.clone();
    missing.site = None;
    assert!(relation_source_entity(&missing, &owners).is_none());
    let mut outside = call;
    outside.site.as_mut().unwrap().start_byte = 0;
    assert!(relation_source_entity(&outside, &owners).is_none());
}

#[test]
fn nested_decorated_classes_do_not_borrow_the_enclosing_same_name() {
    let file = parsed("from foreign import wrap\n@wrap\nclass Box:\n    @wrap\n    class Box:\n        def run(self):\n            return 1\n");
    let ids = [(file.file_path.clone(), ArtifactId::new())]
        .into_iter()
        .collect();
    let relations = link_cross_file(std::slice::from_ref(&file), &ids).unwrap();
    let owners: Vec<_> = file
        .entities
        .iter()
        .filter(|entity| entity.name == "Box")
        .collect();
    assert_eq!(owners.len(), 2);
    for owner in owners {
        let calls: Vec<_> = relations
            .iter()
            .filter(|edge| {
                edge.src.as_entity() == Some(owner.id)
                    && edge.kind == RelationKind::Calls
                    && edge.import_source.as_deref() == Some("foreign")
            })
            .collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].evidence[0].occurrence_count, 1);
    }
}
