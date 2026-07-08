// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-file arm of the C++ call-resolution regression net.
//!
//! The extractor resolves a method call's receiver static type and emits it as
//! `Type::method`, so the linker binds `recv.method()` to the receiver's own
//! class instead of fanning the bare method name out to every same-named method
//! in the graph — the phantom-consumer defect that inflated review impact on
//! partially-migrated C++ APIs.
//! These tests drive the real parser -> real linker pipeline (both the batch and
//! incremental linkers, asserting parity) to prove: a typed receiver binds only
//! to its class; a call through a derived receiver reaches the base-declared
//! method and nothing else; and an unresolvable receiver still fans out weakly.

use kin_index::{link_cross_file, link_cross_file_incremental, FileParseData, IncrementalLinker};
use kin_model::{Entity, EntityId, FilePathId, Relation, RelationKind};
use kin_parser::{CppAdapter, LanguageAdapter};

fn parse_cpp(file_path: &str, source: &str) -> FileParseData {
    let adapter = CppAdapter;
    let file_id = FilePathId::new(file_path);
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse");
    let output = adapter.extract(&tree, bytes, &file_id).expect("extract");
    let entities: Vec<Entity> = output
        .entities
        .into_iter()
        .map(|e| e.into_entity_with_source(adapter.language_id(), &file_id, Some(bytes)))
        .collect();
    FileParseData {
        file_path: file_path.to_string(),
        entities,
        relations: output.relations,
        imports: output.imports,
    }
}

fn entity_id(files: &[FileParseData], file: &str, name: &str) -> EntityId {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
        .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
        .id
}

fn has_call(relations: &[Relation], src: EntityId, dst: EntityId) -> bool {
    relations.iter().any(|r| {
        r.kind == RelationKind::Calls
            && r.src.as_entity() == Some(src)
            && r.dst.as_entity() == Some(dst)
    })
}

fn call_confidence(relations: &[Relation], src: EntityId, dst: EntityId) -> Option<f32> {
    relations
        .iter()
        .find(|r| {
            r.kind == RelationKind::Calls
                && r.src.as_entity() == Some(src)
                && r.dst.as_entity() == Some(dst)
        })
        .map(|r| r.confidence)
}

/// Link `files` through both the batch and incremental linkers, assert the two
/// agree on every `Calls` edge, and return the batch edges. Receiver-scoped
/// resolution has a batch tier and an incremental twin, so every scenario is
/// proved on both paths at once.
fn link_both(files: &[FileParseData]) -> Vec<Relation> {
    let batch = link_cross_file(files);

    let mut linker = IncrementalLinker::new();
    for f in files {
        linker.add_file(&f.file_path, &f.entities);
    }
    let incremental = link_cross_file_incremental(files, &linker);

    let call_set = |rels: &[Relation]| -> std::collections::HashSet<(EntityId, EntityId)> {
        rels.iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .filter_map(|r| Some((r.src.as_entity()?, r.dst.as_entity()?)))
            .collect()
    };
    assert_eq!(
        call_set(&batch),
        call_set(&incremental),
        "batch and incremental linkers must resolve the same C++ call edges"
    );
    batch
}

#[test]
fn typed_receiver_binds_to_own_class_not_same_named_sibling() {
    // A factory builds typed generator locals and calls `.add()` / `->add()` on
    // them. An unrelated `MultipleReporters::add` in another file shares the bare
    // leaf `add` — the phantom consumer the pre-fix bare-name fan-out minted onto
    // every same-named method regardless of receiver class.
    let files = vec![
        parse_cpp(
            "generators.hpp",
            r#"
namespace Catch {
    struct ValuesGenerator {
        void add( int value ) {}
    };
    struct CompositeGenerator {
        void add( int g ) {}
    };
    CompositeGenerator values( int v1 ) {
        CompositeGenerator generators;
        ValuesGenerator* valuesGen = new ValuesGenerator();
        valuesGen->add( v1 );
        generators.add( 0 );
        return generators;
    }
}
"#,
        ),
        parse_cpp(
            "reporters.hpp",
            r#"
namespace Catch {
    struct MultipleReporters {
        void add( int reporter ) {}
    };
}
"#,
        ),
    ];

    let relations = link_both(&files);
    let values = entity_id(&files, "generators.hpp", "values");
    let vg_add = entity_id(&files, "generators.hpp", "ValuesGenerator::add");
    let cg_add = entity_id(&files, "generators.hpp", "CompositeGenerator::add");
    let mr_add = entity_id(&files, "reporters.hpp", "MultipleReporters::add");

    assert!(
        has_call(&relations, values, vg_add),
        "`valuesGen->add` must bind to ValuesGenerator::add"
    );
    assert!(
        has_call(&relations, values, cg_add),
        "`generators.add` must bind to CompositeGenerator::add"
    );
    assert!(
        !has_call(&relations, values, mr_add),
        "the bare-name fan-out phantom `values -> MultipleReporters::add` must be gone"
    );
    // Same-file, receiver-pinned binding is parser-certain.
    assert_eq!(call_confidence(&relations, values, vg_add), Some(1.0));
}

#[test]
fn derived_receiver_resolves_to_base_method_only() {
    // A call through a derived-typed local must reach the base-declared method by
    // walking the Extends chain — not fan out to an unrelated same-named method.
    let files = vec![
        parse_cpp(
            "base.hpp",
            r#"
struct Base {
    void poll() {}
};
"#,
        ),
        parse_cpp(
            "other.hpp",
            r#"
struct Other {
    void poll() {}
};
"#,
        ),
        parse_cpp(
            "use.hpp",
            r#"
struct Derived : Base {};
void use_it() {
    Derived d;
    d.poll();
}
"#,
        ),
    ];

    let relations = link_both(&files);
    let use_it = entity_id(&files, "use.hpp", "use_it");
    let base_poll = entity_id(&files, "base.hpp", "Base::poll");
    let other_poll = entity_id(&files, "other.hpp", "Other::poll");

    assert!(
        has_call(&relations, use_it, base_poll),
        "`d.poll()` through `Derived : Base` must resolve to Base::poll"
    );
    assert!(
        !has_call(&relations, use_it, other_poll),
        "inheritance resolution must not reach the unrelated Other::poll"
    );
    assert_eq!(
        call_confidence(&relations, use_it, base_poll),
        Some(0.85),
        "an inherited receiver-method edge carries INHERITED_METHOD_CONFIDENCE"
    );
}

#[test]
fn unresolvable_receiver_fans_out_weakly() {
    // `sink.flush()` with no visible declaration of `sink`: the receiver type is
    // unknown, so the call keeps its bare leaf and the ambiguous receiver-method
    // tier fans out to same-named implementors at low confidence — never as
    // strong truth.
    let files = vec![
        parse_cpp(
            "writer.hpp",
            r#"
struct Writer {
    void flush() {}
};
"#,
        ),
        parse_cpp(
            "logger.hpp",
            r#"
struct Logger {
    void flush() {}
};
"#,
        ),
        parse_cpp(
            "drain.hpp",
            r#"
void drain() {
    sink.flush();
}
"#,
        ),
    ];

    let relations = link_both(&files);
    let drain = entity_id(&files, "drain.hpp", "drain");
    let writer_flush = entity_id(&files, "writer.hpp", "Writer::flush");
    let logger_flush = entity_id(&files, "logger.hpp", "Logger::flush");

    assert!(
        has_call(&relations, drain, writer_flush),
        "unresolvable receiver keeps its bare leaf and fans out to Writer::flush"
    );
    assert!(
        has_call(&relations, drain, logger_flush),
        "unresolvable receiver keeps its bare leaf and fans out to Logger::flush"
    );
    assert_eq!(
        call_confidence(&relations, drain, writer_flush),
        Some(0.3),
        "an unresolvable receiver-method fan-out stays at the weak ambiguous confidence"
    );
}
