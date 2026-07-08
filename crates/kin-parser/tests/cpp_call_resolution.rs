// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Regression tests for C++ call-reference extraction.
//!
//! Callee names must reach the linker in instantiation-free, index-matchable
//! form: template-argument lists are stripped from qualified callee paths
//! (`ratio_string<Ratio>::symbol` → `ratio_string::symbol`), and calls inside
//! template-struct member bodies and preprocessor-guarded blocks must emit
//! References at all — the merge-trust Catch2 misses traced back to callee
//! names no name index could match.

use kin_model::{FilePathId, RelationKind};
use kin_parser::{CallArgShape, CppAdapter, ExtractedRelation, LanguageAdapter};

fn parse_and_extract(source: &str) -> Vec<ExtractedRelation> {
    let adapter = CppAdapter;
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse should succeed");
    let file_id = FilePathId("test/calls.hpp".to_string());
    let output = adapter
        .extract(&tree, bytes, &file_id)
        .expect("extract should succeed");
    output.relations
}

fn calls_named<'a>(rels: &'a [ExtractedRelation], name: &str) -> Vec<&'a ExtractedRelation> {
    rels.iter()
        .filter(|r| r.kind == RelationKind::Calls && r.dst_name == name)
        .collect()
}

#[test]
fn template_member_call_strips_template_args_from_qualified_callee() {
    let source = r#"
namespace Catch {
    template<class Ratio>
    struct ratio_string {
        static std::string symbol();
    };

    template<class Value, class Ratio>
    struct StringMaker {
        static std::string convert(Value const& duration) {
            return ratio_string<Ratio>::symbol();
        }
    };
}
"#;
    let rels = parse_and_extract(source);
    assert!(
        !calls_named(&rels, "ratio_string::symbol").is_empty(),
        "template-arg-laden callee must be emitted instantiation-free, got: {:?}",
        rels.iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .map(|r| &r.dst_name)
            .collect::<Vec<_>>()
    );
    assert!(
        calls_named(&rels, "ratio_string<Ratio>::symbol").is_empty(),
        "raw template-arg callee name must not leak into references"
    );
}

#[test]
fn call_in_template_member_body_emits_plain_callee() {
    let source = r#"
namespace Catch {
    std::string time_t_toString(time_t const& toConvert);

    template<typename Duration>
    struct StringMaker {
        static std::string convert(time_t const& value) {
            return time_t_toString(value);
        }
    };
}
"#;
    let rels = parse_and_extract(source);
    assert!(
        !calls_named(&rels, "time_t_toString").is_empty(),
        "plain call inside a template member body must emit a Calls reference"
    );
}

#[test]
fn preproc_guarded_qualified_call_emits_reference() {
    let source = r#"
#ifndef TWOBLUECUBES_CATCH_DEFAULT_MAIN_HPP_INCLUDED
#define TWOBLUECUBES_CATCH_DEFAULT_MAIN_HPP_INCLUDED

#ifndef __OBJC__
int main(int argc, char* const argv[]) {
    return Catch::Main(argc, argv);
}
#endif

#endif
"#;
    let rels = parse_and_extract(source);
    assert!(
        !calls_named(&rels, "Catch::Main").is_empty(),
        "qualified call inside nested preprocessor guards must emit a Calls reference"
    );
}

#[test]
fn free_function_template_call_reduces_to_bare_name() {
    let source = r#"
void caller() {
    process<int>(42);
}
"#;
    let rels = parse_and_extract(source);
    assert!(
        !calls_named(&rels, "process").is_empty(),
        "free-function template instantiation must emit the bare callee name"
    );
}

fn calls_from<'a>(rels: &'a [ExtractedRelation], src: &str) -> Vec<&'a str> {
    rels.iter()
        .filter(|r| r.kind == RelationKind::Calls && r.src_name == src)
        .map(|r| r.dst_name.as_str())
        .collect()
}

#[test]
fn typed_local_receiver_binds_call_to_its_class() {
    // Local generators whose `.add()`/`->add()` must resolve to their own class,
    // never fan out to every same-named `add` across unrelated classes.
    let source = r#"
namespace Catch {
    template<typename T>
    struct ValuesGenerator {
        void add( T value ) {}
    };
    template<typename T>
    struct CompositeGenerator {
        void add( const T* g ) {}
    };
    template<typename T>
    CompositeGenerator<T> values( T v1, T v2 ) {
        CompositeGenerator<T> generators;
        ValuesGenerator<T>* valuesGen = new ValuesGenerator<T>();
        valuesGen->add( v1 );
        generators.add( valuesGen );
        return generators;
    }
}
"#;
    let rels = parse_and_extract(source);
    let calls = calls_from(&rels, "values");
    assert!(
        calls.contains(&"ValuesGenerator::add"),
        "pointer-local `valuesGen->add` must bind to ValuesGenerator, got: {calls:?}"
    );
    assert!(
        calls.contains(&"CompositeGenerator::add"),
        "value-local `generators.add` must bind to CompositeGenerator, got: {calls:?}"
    );
    assert!(
        !calls.contains(&"add"),
        "no bare `add` may survive when both receivers are typed, got: {calls:?}"
    );
}

#[test]
fn this_receiver_binds_call_to_enclosing_class() {
    let source = r#"
struct Widget {
    void run() { this->helper(); }
    void helper() {}
};
"#;
    let rels = parse_and_extract(source);
    let calls = calls_from(&rels, "Widget::run");
    assert!(
        calls.contains(&"Widget::helper"),
        "`this->helper()` must bind to the enclosing class, got: {calls:?}"
    );
}

#[test]
fn member_field_receiver_binds_call_to_field_class() {
    let source = r#"
struct Engine { void start() {} };
struct Car {
    Engine m_engine;
    void drive() { m_engine.start(); }
};
"#;
    let rels = parse_and_extract(source);
    let calls = calls_from(&rels, "Car::drive");
    assert!(
        calls.contains(&"Engine::start"),
        "member-field receiver `m_engine.start()` must bind to Engine, got: {calls:?}"
    );
}

#[test]
fn parameter_receiver_binds_call_to_parameter_class() {
    let source = r#"
struct Sink { void write() {} };
void pump( Sink& out ) { out.write(); }
"#;
    let rels = parse_and_extract(source);
    let calls = calls_from(&rels, "pump");
    assert!(
        calls.contains(&"Sink::write"),
        "parameter receiver `out.write()` must bind to Sink, got: {calls:?}"
    );
}

#[test]
fn unresolvable_receiver_keeps_bare_method_name() {
    // No declaration for `obj`: the receiver type is unknown, so the call keeps
    // its bare rightmost name for the linker's weak ambiguous-fanout tier.
    let source = r#"
struct S {
    void run() { obj.execute(); }
};
"#;
    let rels = parse_and_extract(source);
    let calls = calls_from(&rels, "S::run");
    assert!(
        calls.contains(&"execute"),
        "unresolvable receiver must keep the bare method name, got: {calls:?}"
    );
    assert!(
        !calls.iter().any(|c| c.contains("::execute")),
        "unresolvable receiver must not invent a class qualifier, got: {calls:?}"
    );
}

#[test]
fn explicit_scope_qualified_static_call_is_preserved() {
    let source = r#"
namespace Catch {
    int helper() { return 0; }
    int caller() { return Catch::helper(); }
}
"#;
    let rels = parse_and_extract(source);
    let calls = calls_from(&rels, "caller");
    assert!(
        calls.contains(&"Catch::helper"),
        "explicit `Catch::helper()` must keep its qualified callee, got: {calls:?}"
    );
}

/// The call shape of the one call named `name`; panics if the callee was emitted
/// zero or multiple times so a test never reads a stale duplicate.
fn call_shape_of<'a>(rels: &'a [ExtractedRelation], name: &str) -> &'a CallArgShape {
    let matches = calls_named(rels, name);
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one `{name}` call, got {}",
        matches.len()
    );
    matches[0]
        .call_shape
        .as_ref()
        .unwrap_or_else(|| panic!("`{name}` call recorded no call shape"))
}

fn call_arg_count(rels: &[ExtractedRelation], name: &str) -> u32 {
    call_shape_of(rels, name).positional
}

#[test]
fn call_site_records_positional_argument_count() {
    // The extractor must record each call's positional argument count so the
    // linker can keep an overloaded callee's arity-incompatible overloads out of
    // the binding set. Counts come from the argument list, so a nested call is
    // counted by its own arguments, not folded into the outer call's.
    let source = r#"
void driver() {
    two_args( a, b );
    zero_args();
    one_arg( x );
    outer( inner( p ), q );
}
"#;
    let rels = parse_and_extract(source);
    assert_eq!(call_arg_count(&rels, "two_args"), 2);
    assert_eq!(call_arg_count(&rels, "zero_args"), 0);
    assert_eq!(call_arg_count(&rels, "one_arg"), 1);
    // `outer(inner(p), q)`: two arguments to outer, one to the nested inner.
    assert_eq!(call_arg_count(&rels, "outer"), 2);
    assert_eq!(call_arg_count(&rels, "inner"), 1);
    // No keyword args and no splats in plain C++ calls.
    let two = call_shape_of(&rels, "two_args");
    assert!(two.keywords.is_empty() && !two.has_var_positional && !two.has_var_keyword);
}

#[test]
fn call_arg_count_is_not_inflated_by_callee_template_arguments() {
    // A template-instantiated callee carries a comma-bearing `<...>` list. That
    // list is part of the callee, not the call's arguments, so it must not lift
    // the recorded argument count.
    let source = r#"
void driver() {
    make< int, long >( only );
}
"#;
    let rels = parse_and_extract(source);
    assert_eq!(
        call_arg_count(&rels, "make"),
        1,
        "callee template args (`<int, long>`) are not call arguments"
    );
}

#[test]
fn pack_expansion_argument_marks_shape_var_positional() {
    // A forwarding call spreads a parameter pack (`args...`). The positional
    // count is then a lower bound, so the shape must flag `has_var_positional`
    // and the linker treats the call as arity-unknown (prunes no overload).
    let source = r#"
void driver() {
    forward( first, rest... );
}
"#;
    let rels = parse_and_extract(source);
    let shape = call_shape_of(&rels, "forward");
    assert!(
        shape.has_var_positional,
        "a `rest...` pack-expansion argument must set has_var_positional"
    );
    assert!(!shape.has_var_keyword, "C++ has no keyword splats");
}
