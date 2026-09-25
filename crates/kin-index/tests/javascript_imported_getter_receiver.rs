// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_index::{
    link_cross_file, link_cross_file_incremental, FileParseData, IncrementalLinker, IndexPipeline,
};
use kin_model::{ArtifactId, EntityId, FilePathId, LanguageId, Relation, RelationKind};
use std::collections::HashMap;

const SOURCE: &str = "var Channel = require('external-wire');\n\
var service = {};\n\
service.initialize = function() {\n\
  var held = null;\n\
  Object.defineProperty(this, 'transport', { get: function() {\n\
    if (held === null) { held = new Channel(); }\n\
    return held;\n\
  }});\n\
};\n\
service.dispatch = function(request) { this.transport.send(request); this.transport.send(request); };\n";

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
fn caller_id(file: &FileParseData) -> EntityId {
    file.entities
        .iter()
        .find(|e| e.name == "service.dispatch")
        .unwrap()
        .id
}
fn calls(edges: Vec<Relation>, caller: EntityId) -> Vec<Relation> {
    edges
        .into_iter()
        .filter(|r| r.src.as_entity() == Some(caller) && r.kind == RelationKind::Calls)
        .collect()
}
fn both(files: &[FileParseData]) -> [Vec<Relation>; 3] {
    let artifacts: HashMap<_, _> = files
        .iter()
        .map(|f| (f.file_path.clone(), ArtifactId::new()))
        .collect();
    let mut linker = IncrementalLinker::new();
    for file in files {
        linker.add_file(&file.file_path, artifacts[&file.file_path], &file.entities);
    }
    let encoded = serde_json::to_vec(&linker.to_checkpoint_v1()).unwrap();
    let restored =
        IncrementalLinker::from_checkpoint_v1(serde_json::from_slice(&encoded).unwrap()).unwrap();
    [
        link_cross_file(files, &artifacts).unwrap(),
        link_cross_file_incremental(files, &linker).unwrap(),
        link_cross_file_incremental(files, &restored).unwrap(),
    ]
}

#[test]
fn imported_getter_boundary_survives_batch_incremental_checkpoint_and_local_decoys() {
    let source = format!("{SOURCE}\nvar transport = {{}}; transport.send = function() {{}};\n");
    let file = parse("src/service.js", &source);
    let caller = caller_id(&file);
    let decoy = parse(
        "src/decoy.js",
        "var transport = {}; transport.send = function() {};\n",
    );
    for edges in both(&[file, decoy]) {
        let outgoing = calls(edges, caller);
        assert_eq!(outgoing.len(), 1, "{outgoing:?}");
        let edge = &outgoing[0];
        assert!(kin_index::is_external_import_placeholder(edge), "{edge:?}");
        assert_eq!(edge.import_source.as_deref(), Some("external-wire"));
        assert_eq!(edge.confidence, 0.2);
        assert_eq!(edge.origin, kin_model::RelationOrigin::Inferred);
        assert_eq!(edge.evidence.len(), 2, "two calls keep two exact sites");
        for evidence in &edge.evidence {
            assert_eq!(
                evidence.parser_rule.as_deref(),
                Some(kin_index::JS_IMPORTED_GETTER_REFERENCE_RULE)
            );
            assert_eq!(evidence.token.as_deref(), Some("transport.send"));
            assert_eq!(evidence.occurrence_count, 1);
            let span = evidence.source_span.as_ref().unwrap();
            assert_eq!(
                &source[span.start_byte..span.end_byte],
                "this.transport.send(request)"
            );
        }
        let target = kin_index::placeholder_target_entity(edge, LanguageId::JavaScript).unwrap();
        assert_eq!(target.name, "transport.send");
        assert_eq!(target.role, kin_model::EntityRole::External);
        assert!(
            target.file_origin.is_none() && target.span.is_none() && target.signature.is_empty()
        );
        let crossing = kin_index::trace_crossing_for(&target, Some(edge)).unwrap();
        assert_eq!(crossing.status, "named");
        assert_eq!(crossing.specifier.as_deref(), Some("external-wire"));
    }
}

#[test]
fn imported_getter_local_or_malformed_proof_never_falls_back_to_local_names() {
    let source = SOURCE.replace("external-wire", "wire");
    let file = parse("src/service.js", &source);
    let caller = caller_id(&file);
    let local = parse(
        "packages/wire/src/index.js",
        "module.exports = function Channel() {};\n",
    );
    let decoy = parse(
        "src/decoy.js",
        "var transport = {}; transport.send = function() {};\n",
    );
    for edges in both(&[file, local, decoy.clone()]) {
        assert!(calls(edges, caller).is_empty());
    }
    let mut file = parse("src/service.js", SOURCE);
    let caller = caller_id(&file);
    for raw in &mut file.relations {
        if raw.src_name == "service.dispatch" {
            raw.receiver = Some("other.transport".into());
        }
    }
    for edges in both(&[file, decoy]) {
        assert!(calls(edges, caller).is_empty());
    }
}

#[test]
fn imported_getter_canonical_evidence_refuses_missing_forged_and_duplicate_sites() {
    let file = parse("src/service.js", SOURCE);
    let caller = caller_id(&file);
    let edge = calls(both(&[file]).into_iter().next().unwrap(), caller).remove(0);
    let mut cases = Vec::new();
    let mut broken = edge.clone();
    broken.evidence[1].source_span.as_mut().unwrap().file = FilePathId::new("src/foreign.js");
    cases.push(broken);
    let mut broken = edge.clone();
    broken.evidence[0].source_span = None;
    cases.push(broken);
    let mut broken = edge.clone();
    broken.evidence[0].parser_rule = Some(kin_index::EXTERNAL_IMPORT_REFERENCE_RULE.into());
    cases.push(broken);
    let mut broken = edge.clone();
    broken.evidence[0].source_span.as_mut().unwrap().end_byte = 0;
    cases.push(broken);
    let mut broken = edge.clone();
    broken.evidence[0].token = Some("foreign.send".into());
    cases.push(broken);
    let mut broken = edge.clone();
    broken.evidence.push(broken.evidence[0].clone());
    cases.push(broken);
    for broken in cases {
        assert!(
            !kin_index::is_external_import_placeholder(&broken),
            "{broken:?}"
        );
    }
}
