use std::collections::HashMap;
use kin_index::{link_cross_file as link_it, FileParseData};
use kin_model::{ArtifactId, Entity, FilePathId, GraphNodeId, Relation, RelationKind};
use kin_parser::{LanguageAdapter, RustAdapter};

fn parse_with(adapter: &dyn LanguageAdapter, path: &str, src: &str) -> FileParseData {
    let file_id = FilePathId::new(path);
    let bytes = src.as_bytes();
    let tree = adapter.parse(bytes).expect("parse");
    let output = adapter.extract(&tree, bytes, &file_id).expect("extract");
    println!("--- {path} imports: {:?}", output.imports);
    for r in &output.relations {
        println!("--- {path} rel {:?} {} -> {} src={:?}", r.kind, r.src_name, r.dst_name, r.import_source);
    }
    let entities: Vec<Entity> = output.entities.into_iter()
        .map(|e| e.into_entity_with_source(adapter.language_id(), &file_id, Some(bytes)))
        .collect();
    FileParseData { file_path: path.to_string(), entities, relations: output.relations, imports: output.imports }
}

#[test]
fn rust_cross_file() {
    let files = vec![
        parse_with(&RustAdapter, "src/storage.rs",
            "use crate::parsing::parse_note;\n\npub fn ingest_note(p: &str) -> String { parse_note(p) }\n"),
        parse_with(&RustAdapter, "src/parsing.rs",
            "pub fn parse_note(p: &str) -> String { p.to_string() }\n"),
    ];
    let ids: HashMap<String, ArtifactId> = files.iter().map(|f| (f.file_path.clone(), ArtifactId::new())).collect();
    let rels: Vec<Relation> = link_it(&files, &ids).expect("link");
    for r in &rels {
        let name = |n: &GraphNodeId| match n {
            GraphNodeId::Entity(id) => files.iter().flat_map(|f| f.entities.iter()).find(|e| e.id == *id)
                .map(|e| format!("{}::{}", e.file_origin.as_ref().map(|p| p.0.clone()).unwrap_or_default(), e.name))
                .unwrap_or_else(|| "?ext".into()),
            GraphNodeId::Artifact(a) => ids.iter().find(|(_, i)| *i == a).map(|(p, _)| format!("artifact:{p}")).unwrap_or("artifact:?".into()),
            o => format!("{o:?}"),
        };
        println!("REL {:?} {} -> {} conf={} origin={:?}", r.kind, name(&r.src), name(&r.dst), r.confidence, r.origin);
    }
    assert!(rels.iter().any(|r| r.kind == RelationKind::Imports), "rust artifact Imports edge");
}
