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
    CSharpAdapter, ExtractedRelation, FileImport, JavaAdapter, JavaScriptAdapter, LanguageAdapter,
    PythonAdapter, TypeScriptAdapter,
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
        // Load-bearing. These entities are Rust, and a bare Rust `make()` reaches
        // the owner-qualified `Impl0::make` only from a file whose import list
        // cannot answer whether it binds that name. An empty list is
        // name-complete, so the call would be refused before it could fan out at
        // all, and this helper would measure the FIR-1581 gate instead of the cap
        // it exists to measure. A glob import is the stand-down that gate documents.
        imports: vec![FileImport {
            module_path: "crate::impls".to_string(),
            specifiers: vec![],
        }],
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

// ---- (E) same-file receiver-qualified calls ----
//
// Every linker tier that matches a BARE method leaf considers cross-file
// candidates only: the exact-name bucket filters out the calling file, and so
// does the bare-name receiver tier. Only the same-file exact tier can bind
// within one file, and it needs the qualified name. So a JavaScript adapter
// that narrowed `helpers.normalize()` to `normalize` made a sibling call inside
// one object literal permanently unresolvable, while the SAME call from another
// file resolved.

/// A call between two methods of the same object literal, in one file, must
/// produce exactly one edge to the sibling.
#[test]
fn javascript_object_literal_sibling_call_resolves_in_one_file() {
    let files = vec![parse_with(
        &JavaScriptAdapter,
        "helpers.js",
        "const helpers = {\n  normalize(p) { return String(p).trim(); },\n  join(a, b) { return helpers.normalize(a) + '/' + helpers.normalize(b); },\n};\nmodule.exports = helpers;\n",
    )];
    let join = entity_id_in(&files, "helpers.js", "helpers.join");
    let normalize = entity_id_in(&files, "helpers.js", "helpers.normalize");

    let rels = link_cross_file(&files);
    assert!(
        has_call(&rels, join, normalize),
        "`helpers.join` calls `helpers.normalize` in the same file and must link to it"
    );
    let sibling_edges = rels
        .iter()
        .filter(|r| {
            r.kind == RelationKind::Calls
                && r.src == GraphNodeId::Entity(join)
                && r.dst == GraphNodeId::Entity(normalize)
        })
        .count();
    assert_eq!(
        sibling_edges, 1,
        "exactly one edge to the sibling, not one per call site"
    );
}

/// The same contract for a `this.` call inside an ES class body, which had the
/// identical blind spot and no test.
#[test]
fn javascript_class_this_call_resolves_in_one_file() {
    let files = vec![parse_with(
        &JavaScriptAdapter,
        "helpers.js",
        "class Helpers {\n  normalize(p) { return String(p).trim(); }\n  join(a, b) { return this.normalize(a) + this.normalize(b); }\n}\n",
    )];
    let join = entity_id_in(&files, "helpers.js", "Helpers.join");
    let normalize = entity_id_in(&files, "helpers.js", "Helpers.normalize");
    assert!(
        has_call(&link_cross_file(&files), join, normalize),
        "`this.normalize()` inside `Helpers.join` must link to `Helpers.normalize`"
    );
}

/// A receiver that is NOT the enclosing owner keeps its bare leaf, so nothing
/// claims a resolution the syntax does not settle. `this.router.handle(...)` is
/// a call through a property whose type is unknown; it must not bind to a
/// same-named method of the enclosing object.
#[test]
fn javascript_foreign_receiver_does_not_bind_to_the_enclosing_owner() {
    let files = vec![parse_with(
        &JavaScriptAdapter,
        "application.js",
        "app.handle = function handle(req, res) {\n  this.router.handle(req, res);\n};\n",
    )];
    let handle = entity_id_in(&files, "application.js", "app.handle");
    let rels = link_cross_file(&files);
    assert!(
        !has_call(&rels, handle, handle),
        "`this.router.handle()` must not be read as `app.handle` calling itself"
    );
}

// ---- (F) receiver-method fan-out narrowed by what the calling file can reach ----
//
// A call through an object dispatches on the receiver's static type. The
// bare-name fan-out cannot know that type, so it once linked EVERY same-named
// method in the repository, minting inbound callers a method provably never
// had. Narrowing to the candidates the calling file's own imports account for
// removes those without collapsing a genuine ambiguity to a guess.

fn python_call_fixture(files: &[(&str, &str)]) -> Vec<FileParseData> {
    files
        .iter()
        .map(|(path, src)| parse_with(&PythonAdapter, path, src))
        .collect()
}

const ADAPTER_PY: &str = "class Adapter:\n    def send(self, request):\n        return request\n";
const SESSION_PY: &str = "from .adapter import Adapter\n\n\nclass Session:\n    def __init__(self):\n        self.adapter = Adapter()\n\n    def send(self, request):\n        return self.adapter.send(request)\n";

/// A call through an object must not reach a same-named method whose owning
/// type the calling file neither binds by name nor imports the module of.
#[test]
fn receiver_call_does_not_reach_an_unimportable_owner() {
    let files = python_call_fixture(&[
        ("app/adapter.py", ADAPTER_PY),
        ("app/session.py", SESSION_PY),
        (
            "app/pipeline.py",
            "from .session import Session\n\n\ndef run_all(session):\n    return session.send({})\n",
        ),
    ]);
    let run_all = entity_id_in(&files, "app/pipeline.py", "run_all");
    let session_send = entity_id_in(&files, "app/session.py", "Session.send");
    let adapter_send = entity_id_in(&files, "app/adapter.py", "Adapter.send");

    let rels = link_cross_file(&files);
    assert!(
        has_call(&rels, run_all, session_send),
        "`session.send(...)` must still reach `Session.send`, whose type this file imports"
    );
    assert!(
        !has_call(&rels, run_all, adapter_send),
        "`app/pipeline.py` never names `Adapter`, so `Adapter.send` cannot be this receiver"
    );
}

/// A caller whose imports account for none of the candidates has no type
/// evidence at all, and must keep the whole fan-out rather than lose every
/// candidate to a rule that could not see any of them.
#[test]
fn receiver_call_with_no_import_evidence_still_fans_out() {
    let files = python_call_fixture(&[
        (
            "app/a.py",
            "class A:\n    def run(self):\n        return 1\n",
        ),
        (
            "app/b.py",
            "class B:\n    def run(self):\n        return 2\n",
        ),
        ("app/c.py", "def go(thing):\n    return thing.run()\n"),
    ]);
    let go = entity_id_in(&files, "app/c.py", "go");
    let a_run = entity_id_in(&files, "app/a.py", "A.run");
    let b_run = entity_id_in(&files, "app/b.py", "B.run");

    let rels = link_cross_file(&files);
    assert!(
        has_call(&rels, go, a_run) && has_call(&rels, go, b_run),
        "a file naming no candidate owner keeps every dispatch target"
    );
}

/// A caller that CAN name both candidate owners is genuinely ambiguous, and the
/// fan-out must stay ambiguous rather than pick one.
#[test]
fn receiver_call_naming_both_owners_keeps_both() {
    let files = python_call_fixture(&[
        (
            "app/a.py",
            "class A:\n    def run(self):\n        return 1\n",
        ),
        (
            "app/b.py",
            "class B:\n    def run(self):\n        return 2\n",
        ),
        (
            "app/c.py",
            "from .a import A\nfrom .b import B\n\n\ndef go(thing):\n    return thing.run()\n",
        ),
    ]);
    let go = entity_id_in(&files, "app/c.py", "go");
    let a_run = entity_id_in(&files, "app/a.py", "A.run");
    let b_run = entity_id_in(&files, "app/b.py", "B.run");

    let rels = link_cross_file(&files);
    assert!(
        has_call(&rels, go, a_run) && has_call(&rels, go, b_run),
        "both owners are nameable here, so both stay dispatch candidates"
    );
}
