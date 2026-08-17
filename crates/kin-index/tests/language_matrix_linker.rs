// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-file linker arm of the language matrix.
//!
//! The parser adapters narrow callees to simple names; this file drives the
//! real linker (`link_cross_file`) to prove those names resolve across files and
//! to pin the ambiguity behaviors that matter to the matrix:
//!
//!  * a name-based cross-file call resolves (real parser -> real linker);
//!  * two same-named free functions resolve to a single deterministic target
//!    (the linker picks one, it does not fan out for exact free-function names);
//!  * a receiver-method name defined in several classes fans out to every
//!    implementor, bounded by the fan-out cap;
//!  * a dotted `obj.execute` callee (what a non-narrowing adapter would emit)
//!    does NOT resolve — narrowing belongs in the adapters, not the linker. This
//!    test encodes that contract: simple names resolve, dotted ones do not.
//!
//! The linker is language-agnostic (it matches `dst_name` against entity
//! `name`), so these behaviors hold for every language once the adapter hands it
//! a simple name.

use kin_index::{link_cross_file as link_cross_file_with_identities, FileParseData};
use kin_model::{
    ArtifactId, Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId,
    FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, Relation, RelationKind,
    SemanticFingerprint, SourceSpan, Visibility,
};
use kin_parser::{
    CSharpAdapter, ExtractedRelation, JavaAdapter, LanguageAdapter, TypeScriptAdapter,
};

// ---- helpers: direct entity construction (mirrors linker.rs unit-test idiom) ----

fn zero_fp() -> SemanticFingerprint {
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

fn entity(name: &str, file_path: &str, kind: EntityKind) -> Entity {
    let file_id = FilePathId::new(file_path);
    Entity {
        id: EntityId::new(),
        kind,
        name: name.to_string(),
        language: LanguageId::Rust,
        fingerprint: zero_fp(),
        file_origin: Some(file_id.clone()),
        span: Some(SourceSpan {
            file: file_id,
            start_byte: 0,
            end_byte: 10,
            start_line: 1,
            start_col: 0,
            end_line: 1,
            end_col: 10,
        }),
        signature: name.to_string(),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

fn func(name: &str, file_path: &str) -> Entity {
    entity(name, file_path, EntityKind::Function)
}

fn method(name: &str, file_path: &str) -> Entity {
    entity(name, file_path, EntityKind::Method)
}

fn calls_relation(src: &str, dst: &str) -> ExtractedRelation {
    ExtractedRelation {
        receiver: None,
        call_shape: None,
        kind: RelationKind::Calls,
        src_name: src.to_string(),
        dst_name: dst.to_string(),
        import_source: None,
    }
}

fn count_calls(rels: &[Relation]) -> usize {
    rels.iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .count()
}

fn has_call(rels: &[Relation], src: EntityId, dst: EntityId) -> bool {
    rels.iter().any(|r| {
        r.kind == RelationKind::Calls
            && r.src == GraphNodeId::Entity(src)
            && r.dst == GraphNodeId::Entity(dst)
    })
}

fn link_cross_file(files: &[FileParseData]) -> Vec<Relation> {
    let artifact_ids = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    link_cross_file_with_identities(files, &artifact_ids)
        .expect("every fixture file has an explicitly assigned artifact identity")
}

/// The fan-out cap mirrors `linker::AMBIGUOUS_CALL_FANOUT_CAP` (private). If the
/// cap changes, update this constant; the boundary test below documents it.
const FANOUT_CAP: usize = 8;

// ---- (A) name-based cross-file resolution through the real parser ----

fn parse_with(adapter: &dyn LanguageAdapter, path: &str, src: &str) -> FileParseData {
    let file_id = FilePathId::new(path);
    let bytes = src.as_bytes();
    let tree = adapter.parse(bytes).expect("parse");
    let output = adapter.extract(&tree, bytes, &file_id).expect("extract");
    let entities: Vec<Entity> = output
        .entities
        .into_iter()
        .map(|e| e.into_entity_with_source(adapter.language_id(), &file_id, Some(bytes)))
        .collect();
    FileParseData {
        file_path: path.to_string(),
        entities,
        relations: output.relations,
        imports: output.imports,
    }
}

fn entity_id_in(files: &[FileParseData], file: &str, name: &str) -> EntityId {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
        .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
        .id
}

#[test]
fn name_based_cross_file_call_resolves() {
    // caller.ts imports and calls a function defined in m.ts; the simple-name
    // call must resolve to the real cross-file target.
    let files = vec![
        parse_with(
            &TypeScriptAdapter,
            "caller.ts",
            "import { compute } from \"./m\";\nfunction run() { compute(); }\n",
        ),
        parse_with(
            &TypeScriptAdapter,
            "m.ts",
            "export function compute() { return 1; }\n",
        ),
    ];
    let run = entity_id_in(&files, "caller.ts", "run");
    let compute = entity_id_in(&files, "m.ts", "compute");

    let rels = link_cross_file(&files);
    assert!(
        has_call(&rels, run, compute),
        "imported call `compute()` should resolve run -> m.ts::compute"
    );
}

#[test]
fn java_and_csharp_narrowed_method_calls_resolve_cross_file() {
    // The Java and C# adapters narrow `w.execute()` / `w.Execute()` to the
    // rightmost simple name; the linker resolves that leaf to the method
    // defined in the other file.
    let java = vec![
        parse_with(
            &JavaAdapter,
            "Caller.java",
            "class Caller { void run() { w.execute(); } }",
        ),
        parse_with(
            &JavaAdapter,
            "Worker.java",
            "class Worker { public void execute() {} }",
        ),
    ];
    let run = entity_id_in(&java, "Caller.java", "Caller.run");
    let execute = entity_id_in(&java, "Worker.java", "Worker.execute");
    assert!(
        has_call(&link_cross_file(&java), run, execute),
        "narrowed Java method call should resolve Caller.run -> Worker.execute"
    );

    let csharp = vec![
        parse_with(
            &CSharpAdapter,
            "Caller.cs",
            "namespace N { class C { void Run() { w.Execute(); } } }",
        ),
        parse_with(
            &CSharpAdapter,
            "Worker.cs",
            "namespace N { class Worker { public void Execute() {} } }",
        ),
    ];
    let run = entity_id_in(&csharp, "Caller.cs", "N.C.Run");
    let execute = entity_id_in(&csharp, "Worker.cs", "N.Worker.Execute");
    assert!(
        has_call(&link_cross_file(&csharp), run, execute),
        "narrowed C# method call should resolve N.C.Run -> N.Worker.Execute"
    );
}

// ---- (B) same-name free functions: no signal, no edge ----

#[test]
fn same_name_free_functions_without_signal_resolve_to_nothing() {
    // A bare `shared()` call with two same-named free-function targets and no
    // disambiguating locality signal names no reachable definition: neither a
    // bucket-order pick nor a fan-out, because the callee's name is the only
    // evidence and it proves nothing. This is distinct from the
    // receiver-method path, where every implementor is a plausible dispatch.
    let caller = func("run", "c.rs");
    let files = vec![
        FileParseData {
            file_path: "c.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![calls_relation("run", "shared")],
            imports: vec![],
        },
        FileParseData {
            file_path: "a.rs".to_string(),
            entities: vec![func("shared", "a.rs")],
            relations: vec![],
            imports: vec![],
        },
        FileParseData {
            file_path: "b.rs".to_string(),
            entities: vec![func("shared", "b.rs")],
            relations: vec![],
            imports: vec![],
        },
    ];

    let rels = link_cross_file(&files);
    assert_eq!(
        count_calls(&rels),
        0,
        "two same-named free functions with no scope signal must leave the call unlinked"
    );
}

// ---- (C) receiver-method fan-out to every implementor, bounded by the cap ----

fn receiver_fanout_call_count(n: usize) -> usize {
    let caller = method("build", "caller.rs");
    let mut files = vec![FileParseData {
        file_path: "caller.rs".to_string(),
        entities: vec![caller],
        relations: vec![calls_relation("build", "make")],
        imports: vec![],
    }];
    for i in 0..n {
        let path = format!("impl{i}.rs");
        files.push(FileParseData {
            file_path: path.clone(),
            entities: vec![method(&format!("Impl{i}::make"), &path)],
            relations: vec![],
            imports: vec![],
        });
    }
    count_calls(&link_cross_file(&files))
}

#[test]
fn receiver_method_call_fans_out_to_all_implementors() {
    // Three classes define `make`; a bare `make()` call has an unknowable
    // receiver type, so it fans out to every implementor.
    assert_eq!(receiver_fanout_call_count(3), 3);
}

#[test]
fn receiver_method_fanout_respects_cap() {
    // At the cap every implementor links; one beyond it, the name is too
    // ubiquitous to guess and none link.
    assert_eq!(
        receiver_fanout_call_count(FANOUT_CAP),
        FANOUT_CAP,
        "at the cap every implementor links"
    );
    assert_eq!(
        receiver_fanout_call_count(FANOUT_CAP + 1),
        0,
        "above the cap the receiver-method call stays unresolved"
    );
}

// ---- (D) dotted-callee contract: simple names resolve, dotted ones do not ----

#[test]
fn simple_name_resolves_but_dotted_receiver_name_does_not() {
    // The linker matches `dst_name` against entity `name`. A simple `execute`
    // resolves cross-file; a dotted `obj.execute` resolves to nothing — which
    // is why every adapter narrows callees to the rightmost simple name rather
    // than the linker splitting dotted text.
    let target = func("execute", "target.rs");

    let simple = vec![
        FileParseData {
            file_path: "caller.rs".to_string(),
            entities: vec![func("run", "caller.rs")],
            relations: vec![calls_relation("run", "execute")],
            imports: vec![],
        },
        FileParseData {
            file_path: "target.rs".to_string(),
            entities: vec![target.clone()],
            relations: vec![],
            imports: vec![],
        },
    ];
    assert_eq!(
        count_calls(&link_cross_file(&simple)),
        1,
        "a simple-name call must resolve cross-file"
    );

    let dotted = vec![
        FileParseData {
            file_path: "caller.rs".to_string(),
            entities: vec![func("run", "caller.rs")],
            relations: vec![calls_relation("run", "obj.execute")],
            imports: vec![],
        },
        FileParseData {
            file_path: "target.rs".to_string(),
            entities: vec![target],
            relations: vec![],
            imports: vec![],
        },
    ];
    assert_eq!(
        count_calls(&link_cross_file(&dotted)),
        0,
        "a dotted `obj.execute` callee must not resolve — the adapter must narrow it first"
    );
}
