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

use kin_index::{
    link_cross_file as link_cross_file_with_identities, link_cross_file_incremental, FileParseData,
    IncrementalLinker,
};
use kin_model::{ArtifactId, Entity, EntityId, FilePathId, Relation, RelationKind};
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

fn link_cross_file(files: &[FileParseData]) -> Vec<Relation> {
    let artifact_ids = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    link_cross_file_with_identities(files, &artifact_ids)
        .expect("every fixture file has an explicitly assigned artifact identity")
}

/// Link `files` through both the batch and incremental linkers, assert the two
/// agree on every `Calls` edge, and return the batch edges. Receiver-scoped
/// resolution has a batch tier and an incremental twin, so every scenario is
/// proved on both paths at once.
fn link_both(files: &[FileParseData]) -> Vec<Relation> {
    let batch = link_cross_file(files);

    let mut linker = IncrementalLinker::new();
    for f in files {
        linker.add_file(&f.file_path, ArtifactId::new(), &f.entities);
    }
    let incremental = link_cross_file_incremental(files, &linker)
        .expect("every fixture file has an explicitly assigned artifact identity");

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

// ── Arity-aware overload binding ─────────────────────────────────────────────
//
// Overloaded free functions and methods share one entity name, so the linker
// cannot tell them apart by name. Each of these scenarios binds a call to the
// overload its call-site argument count admits and drops the arity-incompatible
// siblings the pre-fix bare-leaf / same-name fan-out phantom-attached. On the
// old linker the argument count is ignored, so the asserted `!has_call` (or the
// mismatched single pick) fails — every test here is red before the fix.

/// Resolve the id of the overload of `name` in `file` whose signature contains
/// `sig_needle`. Overloads share a name, so a signature fragment is the only way
/// to name one of them from a test.
fn overload_id(files: &[FileParseData], file: &str, name: &str, sig_needle: &str) -> EntityId {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| {
            e.name == name
                && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file)
                && e.signature.contains(sig_needle)
        })
        .unwrap_or_else(|| {
            panic!("overload `{name}` matching `{sig_needle}` in `{file}` not found")
        })
        .id
}

fn call_edges(relations: &[Relation]) -> std::collections::HashSet<(EntityId, EntityId)> {
    relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .filter_map(|r| Some((r.src.as_entity()?, r.dst.as_entity()?)))
        .collect()
}

#[test]
fn namespaced_overload_binds_only_the_arity_compatible_overload() {
    // The Catch2 two-overload shape: `Catch::Main` has two overloads, and the
    // untouched caller invokes the two-argument one. The qualifier `Catch` is a
    // namespace, so the receiver-scope fix (#265) does not apply; only call-site
    // arity keeps the two-argument caller off the signature-changed one-arg
    // overload that the bare-leaf `Main` fan-out otherwise phantom-attaches.
    let files = vec![
        parse_cpp(
            "runner.hpp",
            r#"
namespace Catch {
    int Main( int argc, char* const argv[] ) { return 0; }
    int Main( Config const& config ) { return 1; }
}
"#,
        ),
        parse_cpp(
            "main.hpp",
            r#"
namespace Catch {
    int defaultMain( int argc, char* const argv[] ) {
        return Catch::Main( argc, argv );
    }
}
"#,
        ),
    ];

    let relations = link_both(&files);
    let caller = entity_id(&files, "main.hpp", "defaultMain");
    let main_two = overload_id(&files, "runner.hpp", "Main", "argv");
    let main_one = overload_id(&files, "runner.hpp", "Main", "Config");

    assert!(
        has_call(&relations, caller, main_two),
        "the two-argument caller must bind the two-argument Catch::Main"
    );
    assert!(
        !has_call(&relations, caller, main_one),
        "the phantom `defaultMain -> Main(Config const&)` (arity 1) must be gone"
    );
}

#[test]
fn bare_free_function_overloads_bind_by_call_arity() {
    // Bare (unqualified) calls to overloaded free functions: each caller's
    // argument count must select its matching overload. The old linker picks one
    // bucket-order overload for BOTH callers regardless of arity, so one caller
    // is always mis-bound.
    let files = vec![
        parse_cpp(
            "shapes.hpp",
            r#"
void render( int only ) {}
void render( int width, int height ) {}
"#,
        ),
        parse_cpp(
            "canvas.hpp",
            r#"
void draw_one() { render( a ); }
void draw_two() { render( a, b ); }
"#,
        ),
    ];

    let relations = link_both(&files);
    let draw_one = entity_id(&files, "canvas.hpp", "draw_one");
    let draw_two = entity_id(&files, "canvas.hpp", "draw_two");
    let render_one = overload_id(&files, "shapes.hpp", "render", "only");
    let render_two = overload_id(&files, "shapes.hpp", "render", "height");

    assert!(has_call(&relations, draw_one, render_one));
    assert!(
        !has_call(&relations, draw_one, render_two),
        "a one-argument call must not bind the two-argument render"
    );
    assert!(has_call(&relations, draw_two, render_two));
    assert!(
        !has_call(&relations, draw_two, render_one),
        "a two-argument call must not bind the one-argument render"
    );
}

#[test]
fn default_parameters_widen_the_accepted_arity() {
    // A defaulted parameter makes one overload accept a range of arities; the
    // strict sibling accepts only its exact count. Both a one-arg and a two-arg
    // caller must reach the defaulted overload and neither the strict three-arg
    // one — proving `min`/`max` (not just an exact match) drives compatibility.
    let files = vec![
        parse_cpp(
            "cfg.hpp",
            r#"
namespace Cfg {
    void configure( int mode, int retries = 0 ) {}
    void configure( int mode, int lo, int hi ) {}
}
"#,
        ),
        parse_cpp(
            "boot.hpp",
            r#"
namespace Cfg {
    void boot_one() { Cfg::configure( m ); }
    void boot_two() { Cfg::configure( m, r ); }
}
"#,
        ),
    ];

    let relations = link_both(&files);
    let boot_one = entity_id(&files, "boot.hpp", "boot_one");
    let boot_two = entity_id(&files, "boot.hpp", "boot_two");
    let defaulted = overload_id(&files, "cfg.hpp", "configure", "retries");
    let strict = overload_id(&files, "cfg.hpp", "configure", "hi");

    assert!(
        has_call(&relations, boot_one, defaulted),
        "a one-argument call fits `configure(int, int = 0)`"
    );
    assert!(
        has_call(&relations, boot_two, defaulted),
        "a two-argument call fits `configure(int, int = 0)`"
    );
    assert!(
        !has_call(&relations, boot_one, strict),
        "a one-argument call cannot reach `configure(int, int, int)`"
    );
    assert!(
        !has_call(&relations, boot_two, strict),
        "a two-argument call cannot reach `configure(int, int, int)`"
    );
}

#[test]
fn method_overloads_combine_receiver_scope_and_arity() {
    // Receiver scoping (#265) pins the class; arity pins the overload. A typed
    // receiver whose class declares `run(int)` and `run(int, int)` must bind the
    // overload matching each call's argument count — the two fixes composing.
    let files = vec![
        parse_cpp(
            "widget.hpp",
            r#"
struct Widget {
    void run( int once ) {}
    void run( int lhs, int rhs ) {}
};
"#,
        ),
        parse_cpp(
            "driver.hpp",
            r#"
void use_one() {
    Widget w;
    w.run( x );
}
void use_two() {
    Widget w;
    w.run( x, y );
}
"#,
        ),
    ];

    let relations = link_both(&files);
    let use_one = entity_id(&files, "driver.hpp", "use_one");
    let use_two = entity_id(&files, "driver.hpp", "use_two");
    let run_one = overload_id(&files, "widget.hpp", "Widget::run", "once");
    let run_two = overload_id(&files, "widget.hpp", "Widget::run", "rhs");

    assert!(has_call(&relations, use_one, run_one));
    assert!(
        !has_call(&relations, use_one, run_two),
        "receiver-scoped one-arg call must bind Widget::run(int), not the 2-arg overload"
    );
    assert!(has_call(&relations, use_two, run_two));
    assert!(
        !has_call(&relations, use_two, run_one),
        "receiver-scoped two-arg call must bind Widget::run(int, int), not the 1-arg overload"
    );
}

#[test]
fn no_compatible_overload_keeps_the_existing_fan_out() {
    // Fail-open guard: when the call's argument count matches NO overload's known
    // arity, arity pruning must not erase the edge. The call keeps the existing
    // fan-out to every same-named overload rather than dropping to a silent miss.
    let files = vec![
        parse_cpp(
            "probe.hpp",
            r#"
namespace Diag {
    void probe( int solo ) {}
    void probe( int pair_a, int pair_b ) {}
}
"#,
        ),
        parse_cpp(
            "trace.hpp",
            r#"
namespace Diag {
    void trace() { Diag::probe( a, b, c ); }
}
"#,
        ),
    ];

    let relations = link_both(&files);
    let trace = entity_id(&files, "trace.hpp", "trace");
    let probe_one = overload_id(&files, "probe.hpp", "probe", "solo");
    let probe_two = overload_id(&files, "probe.hpp", "probe", "pair_b");

    assert!(
        has_call(&relations, trace, probe_one) && has_call(&relations, trace, probe_two),
        "an all-incompatible arity read must keep the fan-out, not erase the edge"
    );
}

#[test]
fn arity_pruned_binding_is_deterministic() {
    // Determinism: re-linking identical input yields an identical Calls edge set,
    // and (via `link_both`) the batch and incremental linkers already agree. The
    // prune is a set operation and emission stays ordered by content-derived
    // EntityId, so no HashMap iteration order can leak into the result.
    let build = || {
        vec![
            parse_cpp(
                "over.hpp",
                r#"
namespace N {
    int dispatch( int solo ) { return 0; }
    int dispatch( int pair_a, int pair_b ) { return 1; }
    int dispatch( int trio_a, int trio_b, int trio_c ) { return 2; }
}
"#,
            ),
            parse_cpp(
                "call.hpp",
                r#"
namespace N {
    int go() { return N::dispatch( a, b ); }
}
"#,
            ),
        ]
    };

    let first = call_edges(&link_both(&build()));
    let second = call_edges(&link_both(&build()));
    assert_eq!(
        first, second,
        "arity-pruned overload binding must be byte-stable across runs"
    );
    let go = entity_id(&build(), "call.hpp", "go");
    let dispatch_two = overload_id(&build(), "over.hpp", "dispatch", "pair_b");
    assert!(
        first.contains(&(go, dispatch_two)),
        "the two-argument call binds the two-argument dispatch overload"
    );
}

#[test]
fn pack_expansion_call_is_arity_unknown_and_keeps_all_overloads() {
    // A variadic forwarder spreads a pack (`dispatch(args...)`): the call shape
    // is splat-widened, so its positional count is a lower bound and pins no
    // arity. The call must stay bound to every overload (arity-unknown → prune
    // nothing), not be narrowed to the literal expanded count.
    let files = vec![
        parse_cpp(
            "over.hpp",
            r#"
namespace N {
    int dispatch( int solo ) { return 0; }
    int dispatch( int pair_a, int pair_b ) { return 1; }
}
"#,
        ),
        parse_cpp(
            "fwd.hpp",
            r#"
namespace N {
    template<typename... A>
    int forward_all( A... args ) { return N::dispatch( args... ); }
}
"#,
        ),
    ];

    let relations = link_both(&files);
    let forward_all = entity_id(&files, "fwd.hpp", "forward_all");
    let dispatch_one = overload_id(&files, "over.hpp", "dispatch", "solo");
    let dispatch_two = overload_id(&files, "over.hpp", "dispatch", "pair_b");

    assert!(
        has_call(&relations, forward_all, dispatch_one)
            && has_call(&relations, forward_all, dispatch_two),
        "a pack-expansion call is arity-unknown and must keep every overload"
    );
}
