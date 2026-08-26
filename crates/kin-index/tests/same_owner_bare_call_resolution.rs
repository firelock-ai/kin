// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! FIR-1826: a bare call to a same-file sibling under the caller's own owner.
//!
//! `void Foo::a() { b(); }` in a file that also defines `Foo::b` reached no
//! linker tier at all. Tier (a) and tier (c) key on the full entity name, and
//! `Foo::b` is not `b`. Tier (c2) does hold `Foo::b` under its bare leaf and
//! drops every candidate in the caller's own file. So the call site existed in
//! the source and in no edge, which is strictly worse than a low-confidence or
//! mis-ranked edge: `find_references`, blast radius and every rename built on
//! the graph omitted the site with nothing on any surface to say so.
//!
//! Whether that bare call reaches the sibling is a question only the language
//! answers, and this file is where that judgement is recorded per language.
//! Every adapter emits the identical relation for `b()` inside `Foo.a`: a
//! `Calls` with `dst_name = "b"` and no receiver. The relation cannot tell Java,
//! where the call is `this.b()`, from Go, where it names a package-level
//! function.
//!
//! So each negative here carries a control that the parser DID emit the bare
//! call. Without it a language whose adapter simply records no call for the
//! shape reads exactly like a language the linker correctly refused, and the
//! two are different answers. Ruby is that language today, which is why it is
//! absent rather than listed as a negative.
//!
//! One measurement in this file constrains the whole rule, and it is why the
//! tier is narrower than "the sibling exists". None of Java, C#, Kotlin, Swift
//! or C++ records a receiver for `h.b()` either: every one of them emits the
//! same relation for an object call as for a bare call. Only Python and Rust
//! separate the two shapes at extraction time, and neither is a language where
//! a bare call reaches a sibling. So the linker cannot ask whether a receiver
//! was written, and the tier stands on uniqueness instead: it binds only when
//! the leaf names exactly one owner-qualified entity in the whole universe and
//! no unqualified one, which is the ticket's own framing of a bare call whose
//! only candidate is a same-file qualified-name entity.
//!
//! The bound that leaves is stated rather than hidden. A receiver call whose
//! receiver type the graph does not hold at all still binds to the caller's own
//! sibling. Closing it needs the adapters to record receivers for these
//! languages, which is a parser change; this file's job is to make sure nobody
//! reads the current rule as more than it is.
//!
//! Every case runs through the real parser and both linkers, batch and
//! incremental, and asserts they agree, because a rule that holds only on a cold
//! link is a rule a warm store loses.

use std::collections::HashSet;

use kin_index::{
    link_cross_file as link_cross_file_with_identities, link_cross_file_incremental, FileParseData,
    IncrementalLinker,
};
use kin_model::{
    ArtifactId, Entity, EntityId, FilePathId, Relation, RelationKind, RelationOrigin,
};
use kin_parser::{
    CSharpAdapter, CppAdapter, GoAdapter, JavaAdapter, JavaScriptAdapter, KotlinAdapter,
    LanguageAdapter, PhpAdapter, PythonAdapter, RustAdapter, SwiftAdapter, TypeScriptAdapter,
};

fn adapter_for(language: &str) -> Box<dyn LanguageAdapter> {
    match language {
        "java" => Box::new(JavaAdapter),
        "csharp" => Box::new(CSharpAdapter),
        "cpp" => Box::new(CppAdapter),
        "kotlin" => Box::new(KotlinAdapter),
        "swift" => Box::new(SwiftAdapter),
        "go" => Box::new(GoAdapter),
        "php" => Box::new(PhpAdapter),
        "python" => Box::new(PythonAdapter),
        "rust" => Box::new(RustAdapter),
        "typescript" => Box::new(TypeScriptAdapter),
        "javascript" => Box::new(JavaScriptAdapter),
        other => panic!("no adapter wired for `{other}` in this suite"),
    }
}

fn parse(language: &str, file_path: &str, source: &str) -> FileParseData {
    let adapter = adapter_for(language);
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
        .unwrap_or_else(|| {
            let known: Vec<&str> = files
                .iter()
                .flat_map(|f| f.entities.iter())
                .map(|e| e.name.as_str())
                .collect();
            panic!("entity `{name}` in `{file}` not found; the file holds {known:?}")
        })
        .id
}

fn link_cross_file(files: &[FileParseData]) -> Vec<Relation> {
    let artifact_ids = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    link_cross_file_with_identities(files, &artifact_ids)
        .expect("every fixture file has an explicitly assigned artifact identity")
}

/// Link through both linkers, assert they agree on every `Calls` edge, and
/// return the batch edges. The tier has a batch site and an incremental twin;
/// proving only one leaves a warm relink free to drop what a cold link found.
fn link_both(files: &[FileParseData]) -> Vec<Relation> {
    let batch = link_cross_file(files);

    let mut linker = IncrementalLinker::new();
    for f in files {
        linker.add_file(&f.file_path, ArtifactId::new(), &f.entities);
    }
    let incremental = link_cross_file_incremental(files, &linker)
        .expect("every fixture file has an explicitly assigned artifact identity");

    let call_set = |rels: &[Relation]| -> HashSet<(EntityId, EntityId)> {
        rels.iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .filter_map(|r| Some((r.src.as_entity()?, r.dst.as_entity()?)))
            .collect()
    };
    assert_eq!(
        call_set(&batch),
        call_set(&incremental),
        "the batch and incremental linkers disagree on this file's Calls edges"
    );
    batch
}

fn calls_from(relations: &[Relation], src: EntityId) -> Vec<EntityId> {
    let mut out: Vec<EntityId> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls && r.src.as_entity() == Some(src))
        .filter_map(|r| r.dst.as_entity())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The control every negative needs. A language whose adapter records no call
/// for the bare shape produces zero edges for a reason that has nothing to do
/// with the rule under test, and reads identically to a refusal.
fn assert_parser_emitted_bare_call(file: &FileParseData, caller: &str, leaf: &str) {
    let emitted = file.relations.iter().any(|r| {
        r.kind == RelationKind::Calls
            && r.src_name == caller
            && r.dst_name == leaf
            && r.receiver.is_none()
    });
    assert!(
        emitted,
        "the `{}` adapter recorded no bare `{leaf}()` call from `{caller}`, so this case would \
         grade a linker rule it never reached. Fix the fixture, not the assertion",
        file.file_path,
    );
}

// ── The per-language judgement ──
//
// One row per language, the source that spells the shape, and whether that
// language's bare call reaches the sibling. A row is not a preference: it is
// what the language does, and the reason is written beside it.

struct Case {
    language: &'static str,
    path: &'static str,
    source: &'static str,
    caller: &'static str,
    callee: &'static str,
    leaf: &'static str,
    binds: bool,
    why: &'static str,
}

const CASES: &[Case] = &[
    Case {
        language: "java",
        path: "Sample.java",
        source: "class Foo {\n    void a() { b(); }\n    void b() { }\n}\n",
        caller: "Foo.a",
        callee: "Foo.b",
        leaf: "b",
        binds: true,
        why: "Java gives a member call an implicit `this`, so `b()` is `this.b()`",
    },
    Case {
        language: "csharp",
        path: "Sample.cs",
        source: "class Foo {\n    void A() { B(); }\n    void B() { }\n}\n",
        caller: "Foo.A",
        callee: "Foo.B",
        leaf: "B",
        binds: true,
        why: "C# gives a member call an implicit `this`",
    },
    Case {
        language: "cpp",
        path: "sample.cpp",
        source: "struct Foo {\n    void a();\n    void b();\n};\nvoid Foo::a() { b(); }\nvoid Foo::b() { }\n",
        caller: "Foo::a",
        callee: "Foo::b",
        leaf: "b",
        binds: true,
        why: "C++ gives a member call an implicit `this->`",
    },
    Case {
        language: "kotlin",
        path: "Sample.kt",
        source: "class Foo {\n    fun a() { b() }\n    fun b() { }\n}\n",
        caller: "Foo.a",
        callee: "Foo.b",
        leaf: "b",
        binds: true,
        why: "Kotlin gives a member call an implicit `this`",
    },
    Case {
        language: "swift",
        path: "Sample.swift",
        source: "class Foo {\n    func a() { b() }\n    func b() { }\n}\n",
        caller: "Foo.a",
        callee: "Foo.b",
        leaf: "b",
        binds: true,
        why: "Swift gives a member call an implicit `self`",
    },
    Case {
        language: "go",
        path: "sample.go",
        source: "package main\ntype Foo struct{}\nfunc (f Foo) a() { b() }\nfunc (f Foo) b() { }\n",
        caller: "Foo.a",
        callee: "Foo.b",
        leaf: "b",
        binds: false,
        why: "Go has no implicit receiver; a bare `b()` inside a method names a package-level function",
    },
    Case {
        language: "php",
        path: "sample.php",
        source: "<?php\nclass Foo {\n    function a() { b(); }\n    function b() { }\n}\n",
        caller: "Foo.a",
        callee: "Foo.b",
        leaf: "b",
        binds: false,
        why: "PHP needs `$this->b()`; a bare `b()` inside a method names a global function",
    },
    Case {
        language: "python",
        path: "sample.py",
        source: "class Foo:\n    def a(self):\n        b()\n    def b(self):\n        pass\n",
        caller: "Foo.a",
        callee: "Foo.b",
        leaf: "b",
        binds: false,
        why: "Python needs `self.b()`; this is the gate that keeps `open(path)` off a same-named method",
    },
    Case {
        language: "rust",
        path: "sample.rs",
        source: "struct Foo;\nimpl Foo {\n    fn a(&self) { width(); }\n    fn width(&self) -> u32 { 1 }\n}\n",
        caller: "Foo::a",
        callee: "Foo::width",
        leaf: "width",
        binds: false,
        why: "Rust needs `self.width()` or `Self::width()`; this is the gate that keeps `Ok(..)` off a repo `ParseResult::Ok`",
    },
    Case {
        language: "typescript",
        path: "sample.ts",
        source: "class Foo {\n  a(): void { b(); }\n  b(): void { }\n}\n",
        caller: "Foo.a",
        callee: "Foo.b",
        leaf: "b",
        binds: false,
        why: "TypeScript needs `this.b()`",
    },
    Case {
        language: "javascript",
        path: "sample.js",
        source: "class Foo {\n  a() { b(); }\n  b() { }\n}\n",
        caller: "Foo.a",
        callee: "Foo.b",
        leaf: "b",
        binds: false,
        why: "JavaScript needs `this.b()`",
    },
];

#[test]
fn bare_call_reaches_the_same_owner_sibling_exactly_where_the_language_says_so() {
    for case in CASES {
        let files = vec![parse(case.language, case.path, case.source)];
        assert_parser_emitted_bare_call(&files[0], case.caller, case.leaf);

        let relations = link_both(&files);
        let caller = entity_id(&files, case.path, case.caller);
        let callee = entity_id(&files, case.path, case.callee);
        let targets = calls_from(&relations, caller);

        if case.binds {
            assert_eq!(
                targets,
                vec![callee],
                "`{}`: {} , so `{}` must call `{}` and nothing else",
                case.language,
                case.why,
                case.caller,
                case.callee,
            );
        } else {
            assert!(
                !targets.contains(&callee),
                "`{}`: {} , so `{}` must not reach `{}`; it did",
                case.language,
                case.why,
                case.caller,
                case.callee,
            );
        }
    }
}

#[test]
fn the_bound_edge_is_inferred_and_not_parser_certain() {
    // 1.0 would stamp RelationOrigin::Parsed and let find_references report a
    // name-derived edge as proven. The tier is locality plus a unique
    // owner-qualified leaf, which is stronger than a cross-file name guess and
    // weaker than what the parser saw.
    let files = vec![parse(
        "cpp",
        "sample.cpp",
        "struct Foo {\n    void a();\n    void b();\n};\nvoid Foo::a() { b(); }\nvoid Foo::b() { }\n",
    )];
    let relations = link_both(&files);
    let caller = entity_id(&files, "sample.cpp", "Foo::a");
    let callee = entity_id(&files, "sample.cpp", "Foo::b");
    let edge = relations
        .iter()
        .find(|r| {
            r.kind == RelationKind::Calls
                && r.src.as_entity() == Some(caller)
                && r.dst.as_entity() == Some(callee)
        })
        .expect("the same-owner sibling edge");
    assert_eq!(edge.origin, RelationOrigin::Inferred);
    assert!(
        (edge.confidence - 0.8).abs() < f32::EPSILON,
        "expected the locality-disambiguated confidence, got {}",
        edge.confidence
    );
}

#[test]
fn a_sibling_under_another_owner_in_the_same_file_is_not_reached() {
    // The bare-leaf index would offer `Bar::b` too. A bare call in none of these
    // languages reaches another class's method, and the caller's own file is
    // where such a decoy is most likely to sit.
    for (language, path, source, caller, decoy) in [
        (
            "java",
            "Sample.java",
            "class Foo {\n    void a() { b(); }\n}\nclass Bar {\n    void b() { }\n}\n",
            "Foo.a",
            "Bar.b",
        ),
        (
            "cpp",
            "sample.cpp",
            "struct Foo { void a(); };\nstruct Bar { void b(); };\nvoid Foo::a() { b(); }\nvoid Bar::b() { }\n",
            "Foo::a",
            "Bar::b",
        ),
    ] {
        let files = vec![parse(language, path, source)];
        assert_parser_emitted_bare_call(&files[0], caller, "b");
        let relations = link_both(&files);
        let caller_id = entity_id(&files, path, caller);
        let decoy_id = entity_id(&files, path, decoy);
        assert!(
            !calls_from(&relations, caller_id).contains(&decoy_id),
            "`{language}`: `{caller}` must not reach `{decoy}`, which belongs to another owner"
        );
    }
}

#[test]
fn an_object_call_does_not_bind_to_the_callers_own_member() {
    // The measurement this suite's header records: the Java adapter emits `h.b()`
    // as `Calls dst="b" receiver=None`, byte for byte what a bare `b()` emits, so
    // the linker cannot tell them apart. What keeps the object call off `Foo.b`
    // is that `Helper.b` is in the graph, which makes the leaf mean more than one
    // thing. That is the whole load the uniqueness rule carries, and this is the
    // case that proves it carries it.
    let source = "class Helper {\n    void b() { }\n}\nclass Foo {\n    Helper h;\n    void a() { h.b(); }\n    void b() { }\n}\n";
    let files = vec![parse("java", "Sample.java", source)];
    // The control. If the adapter had recorded a receiver, this case would be
    // graded by a different rule than the one it names.
    assert_parser_emitted_bare_call(&files[0], "Foo.a", "b");

    let relations = link_both(&files);
    let caller = entity_id(&files, "Sample.java", "Foo.a");
    let own_b = entity_id(&files, "Sample.java", "Foo.b");
    assert!(
        !calls_from(&relations, caller).contains(&own_b),
        "`h.b()` must not bind to the caller's own `Foo.b`; `Helper.b` shares the leaf, so the \
         call names more than one thing and this tier has to stand down"
    );
}

#[test]
fn a_second_holder_of_the_leaf_anywhere_stands_the_tier_down() {
    // Same shape as the positive, plus one unrelated class in another file that
    // happens to define a method with the same leaf. The sibling is still there
    // and still the likeliest target, and the tier still refuses, because with a
    // receiver it cannot see it has no way to know the call meant the sibling.
    let source_a = "class Foo {\n    void a() { b(); }\n    void b() { }\n}\n";
    let source_b = "class Unrelated {\n    void b() { }\n}\n";
    let files = vec![
        parse("java", "Foo.java", source_a),
        parse("java", "Unrelated.java", source_b),
    ];
    assert_parser_emitted_bare_call(&files[0], "Foo.a", "b");

    let relations = link_both(&files);
    let caller = entity_id(&files, "Foo.java", "Foo.a");
    let sibling = entity_id(&files, "Foo.java", "Foo.b");
    assert!(
        !calls_from(&relations, caller).contains(&sibling),
        "a second holder of the leaf anywhere in the universe must stand this tier down"
    );

    // And the control that the case is about the second holder rather than about
    // the fixture: with that file removed, the same call binds.
    let alone = vec![parse("java", "Foo.java", source_a)];
    let relations = link_both(&alone);
    let caller = entity_id(&alone, "Foo.java", "Foo.a");
    let sibling = entity_id(&alone, "Foo.java", "Foo.b");
    assert_eq!(
        calls_from(&relations, caller),
        vec![sibling],
        "CONTROL: with the second holder gone the tier must bind, or the case above proves nothing"
    );
}

#[test]
fn a_bare_call_naming_the_caller_itself_mints_no_self_edge() {
    let files = vec![parse(
        "java",
        "Sample.java",
        "class Foo {\n    void a() { a(); }\n}\n",
    )];
    let relations = link_both(&files);
    let caller = entity_id(&files, "Sample.java", "Foo.a");
    assert!(
        !calls_from(&relations, caller).contains(&caller),
        "recursion must not mint a self-edge; every consumer that walks Calls would carry it"
    );
}

/// The Rust half of the same question, cross-file, which had no test anywhere.
///
/// `rust_bare_call_may_reach_owned` is one of the two gates the same-owner tier
/// had to leave standing, and a mutation that made it always answer true
/// survived every suite in this crate: nothing exercised it. That is the defect
/// class this repository keeps finding, a guard whose absence looks exactly like
/// its success, so the gate gets its own case here in both directions.
///
/// The refusal is the `Ok(self.width())` shape: a bare Rust call reaching a
/// repository entity spelled with the same leaf, in a module the caller never
/// names. The control beside it is the binding Rust does allow, a `use` of that
/// exact name, and without it the refusal would be indistinguishable from a tier
/// that had stopped resolving Rust calls at all.
#[test]
fn a_bare_rust_call_reaches_an_owned_entity_only_through_a_use() {
    const DEFS: &str =
        "pub enum Status { Ready(u32) }\npub struct S;\nimpl S { pub fn width(&self) -> u32 { 1 } }\n";

    // Refusal: no `use` binds `width` here, and `width()` in Rust is not
    // `self.width()`.
    let files = vec![
        parse("rust", "shapes.rs", DEFS),
        parse("rust", "caller.rs", "pub fn run() -> u32 { width() }\n"),
    ];
    assert_parser_emitted_bare_call(&files[1], "run", "width");
    let relations = link_both(&files);
    let caller = entity_id(&files, "caller.rs", "run");
    let owned = entity_id(&files, "shapes.rs", "S::width");
    assert!(
        !calls_from(&relations, caller).contains(&owned),
        "a bare Rust call must not reach an owner-qualified entity this file never names"
    );

    // CONTROL: the binding Rust does allow. Without this the refusal above would
    // pass just as well on a build that had stopped resolving Rust entirely.
    let files = vec![
        parse("rust", "shapes.rs", DEFS),
        parse(
            "rust",
            "user.rs",
            "use crate::shapes::Status::Ready;\npub fn run() -> u32 { Ready(1); 0 }\n",
        ),
    ];
    assert_parser_emitted_bare_call(&files[1], "run", "Ready");
    let relations = link_both(&files);
    let caller = entity_id(&files, "user.rs", "run");
    let variant = entity_id(&files, "shapes.rs", "Status::Ready");
    assert!(
        calls_from(&relations, caller).contains(&variant),
        "CONTROL: a `use` of the exact name is what Rust does bind, and it must still resolve, \
         or the refusal above proves nothing"
    );
}

#[test]
fn a_free_function_in_the_file_is_not_treated_as_an_owner_sibling() {
    // The caller has no owner, so there is no sibling to compose. C++ free
    // functions already resolve through tier (a); this pins that the new tier
    // adds nothing there and cannot start guessing for unqualified callers.
    let files = vec![parse(
        "cpp",
        "sample.cpp",
        "struct Foo { void b(); };\nvoid Foo::b() { }\nvoid a() { b(); }\n",
    )];
    let relations = link_both(&files);
    let caller = entity_id(&files, "sample.cpp", "a");
    let member = entity_id(&files, "sample.cpp", "Foo::b");
    assert!(
        !calls_from(&relations, caller).contains(&member),
        "a free function's bare call must not reach a class member it never named"
    );
}
