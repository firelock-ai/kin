// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end: real parser -> real linker -> real spine cross-repo resolver.
//!
//! A consumer repo calls a symbol imported from an external crate. The parser
//! records the import source, the linker preserves the otherwise-unresolved
//! reference as a cross-repo edge carrying the real symbol, and the spine
//! resolver matches it to the providing repo by that real symbol name. This
//! exercises the full production chain, not hand-injected evidence.

use std::collections::HashSet;

use kin_index::{link_cross_file, FileParseData};
use kin_model::{
    Entity, EntityId, EntityKind, EntityRole, FilePathId, FingerprintAlgorithm, Hash256,
    SemanticFingerprint,
};
use kin_parser::AdapterRegistry;
use kin_spine::{
    collect_unresolved_imports, materialize_edges, resolve_imports, EntityEntry, SpineIndex,
};

fn parse_consumer(file_path: &str, source: &str) -> FileParseData {
    let registry = AdapterRegistry::new();
    let ext = std::path::Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .expect("file extension");
    let adapter = registry
        .get_by_extension(ext)
        .expect("language adapter for extension");
    let language = adapter.language_id();
    let file_id = FilePathId::new(file_path);
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse");
    let output = adapter.extract(&tree, bytes, &file_id).expect("extract");

    let entities: Vec<Entity> = output
        .entities
        .into_iter()
        .map(|e| e.into_entity_with_source(language, &file_id, Some(bytes)))
        .collect();

    FileParseData {
        file_path: file_path.to_string(),
        entities,
        relations: output.relations,
        imports: output.imports,
    }
}

fn fingerprint() -> SemanticFingerprint {
    let zero = Hash256::from_bytes([0u8; 32]);
    SemanticFingerprint {
        algorithm: FingerprintAlgorithm::V1TreeSitter,
        ast_hash: zero,
        signature_hash: zero,
        behavior_hash: zero,
        equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
        stability_score: 1.0,
    }
}

#[test]
fn parser_linker_spine_resolves_cross_repo_reference_with_real_symbol() {
    // Consumer repo: a function that calls a free function imported from an
    // external crate. `do_work` is defined in another repo, so the linker cannot
    // resolve it locally.
    let consumer = parse_consumer(
        "src/app.rs",
        "use external_dep::do_work;\n\npub fn run_task() {\n    do_work();\n}\n",
    );
    let consumer_entities = consumer.entities.clone();

    let relations = link_cross_file(&[consumer]);

    // The linker preserved the cross-repo reference: an edge whose destination is
    // not a local entity.
    let local_ids: HashSet<EntityId> = consumer_entities.iter().map(|e| e.id).collect();
    let has_external_edge = relations.iter().any(|r| {
        r.dst
            .as_entity()
            .map(|id| !local_ids.contains(&id))
            .unwrap_or(false)
    });
    assert!(
        has_external_edge,
        "linker should emit a cross-repo reference edge for the external call"
    );

    // Drive the real spine collector over the linker's real output.
    let unresolved = collect_unresolved_imports(&consumer_entities, &relations, "consumer", &[]);
    assert!(
        !unresolved.is_empty(),
        "spine should collect the linker-emitted cross-repo reference"
    );
    let imp = &unresolved[0];
    let dep = imp
        .import_source
        .clone()
        .expect("import source from parser");
    let symbol = imp.imported_name.clone();
    assert_eq!(dep, "external_dep");
    assert_eq!(
        symbol, "do_work",
        "the real symbol name flows parser -> linker -> spine"
    );

    // Provider repo named after the real import source, holding the real symbol.
    let index = SpineIndex::new();
    let target = EntityEntry {
        repo_id: dep.clone(),
        entity_id: EntityId::new(),
        name: symbol.clone(),
        kind: EntityKind::Function,
        signature: format!("fn {symbol}()"),
        fingerprint: fingerprint(),
        file_path: Some("src/lib.rs".to_string()),
        role: Some(EntityRole::Source),
    };
    index.register_repo(&dep, vec![target.clone()], "");

    let resolutions = resolve_imports(&index, &unresolved);
    let materialized = materialize_edges(&index, &unresolved, &resolutions);
    assert!(materialized >= 1, "expected a materialized cross-repo edge");

    let edges = index.cross_repo_edges_from("consumer");
    assert!(
        edges
            .iter()
            .any(|e| e.dst_repo == dep && e.dst_entity == target.entity_id),
        "cross-repo edge should resolve to the providing repo's real symbol"
    );
}
