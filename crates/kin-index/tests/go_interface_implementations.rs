// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Where a Go interface method is implemented.
//!
//! The other direction of the gap `go_interface_dispatch_candidates.rs` covers,
//! and the one a reader asks about more often. A pre-registered,
//! compiler-graded measurement on the gh CLI at commit `14d339d9` put Kin at
//! **zero correct implementation sites out of 142** across 75 interface
//! methods, against a one-line grep that returned every one of them. The cause
//! is the same as that file's: Go writes no `implements` clause, the adapter's
//! own satisfaction inference is same-file and type-to-type, and nothing binds
//! a concrete method to the spec it satisfies.
//!
//! The fixture is the same shape for the same reason: the contract and its
//! implementations are in separate files, because a struct in one package and
//! its interface in another is the ordinary Go arrangement and is the
//! arrangement that produced the zero.

use kin_db::InMemoryGraph;
use kin_index::dispatch::{
    implementations_apply, interface_dispatch_targets, interface_implementations,
};
use kin_index::{apply_to_graph, IndexPipeline};
use kin_model::graph::EntityStore;
use kin_model::{
    ArtifactId, Entity, EntityFilter, EntityKind, Hash256, LocatedEntry, RelationKind, RepoPath,
    TransactionDelta, TreeDelta, TreeEntry,
};

/// The contract. Declared alone, so no same-file inference can see an
/// implementation of it.
const CONTRACT: &str = r#"
package gh

type Writer interface {
	Write(p []byte) (int, error)
	Close() error
}
"#;

/// One implementation, in its own file and its own package.
const BUFFER: &str = r#"
package buf

type Buffer struct {
	data []byte
}

func (b *Buffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *Buffer) Close() error {
	return nil
}
"#;

/// A second implementation, so the answer is a set rather than a single row.
const DISCARD: &str = r#"
package discard

type Discard struct{}

func (d *Discard) Write(p []byte) (int, error) {
	return len(p), nil
}

func (d *Discard) Close() error {
	return nil
}
"#;

/// Has `Write` and no `Close`, so it does not satisfy `Writer`. The control
/// this whole answer is worth nothing without: a method-name match alone must
/// not make a type an implementation, which is exactly the mistake the text
/// baseline makes and pays for in precision.
const COUNTER: &str = r#"
package count

type Counter struct {
	n int
}

func (c *Counter) Write(p []byte) (int, error) {
	c.n += len(p)
	return len(p), nil
}
"#;

/// Satisfies `Writer` by name on both methods and takes two parameters where
/// the contract takes one. The arity filter is what removes it.
const WIDE: &str = r#"
package wide

type Wide struct{}

func (w *Wide) Write(p []byte, flush bool) (int, error) {
	return len(p), nil
}

func (w *Wide) Close() error {
	return nil
}
"#;

/// A second contract that declares the same two methods. An interface is not an
/// implementation of another interface, however well its method set lines up.
const SINK: &str = r#"
package sink

type Sink interface {
	Write(p []byte) (int, error)
	Close() error
}
"#;

fn admit(graph: &InMemoryGraph, path: &str) {
    let repo_path = RepoPath::from_utf8(path.to_string()).expect("a usable repository path");
    if graph.artifact_id_at_path(&repo_path).is_some() {
        return;
    }
    graph
        .apply_transaction_delta(&TransactionDelta {
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(
                    repo_path,
                    TreeEntry::blob(Hash256::from_bytes([7; 32]), false),
                ),
            }],
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        })
        .expect("admission goes through the repository tree transaction");
}

fn ingest(graph: &InMemoryGraph, path: &str, source: &str) {
    let pipeline = IndexPipeline::new();
    let file_id = kin_model::FilePathId::new(path.to_string());
    let indexed = pipeline
        .index_file_content_with_tests(
            &file_id,
            source.as_bytes(),
            kin_blobs::digest(source.as_bytes()),
        )
        .expect("indexing succeeds")
        .indexed_file;
    admit(graph, &indexed.file_id.0);
    apply_to_graph(graph, &indexed).expect("apply succeeds");
}

fn entity_named(graph: &InMemoryGraph, name: &str) -> Entity {
    graph
        .query_entities(&EntityFilter::default())
        .expect("the store answers")
        .into_iter()
        .find(|entity| entity.name == name)
        .unwrap_or_else(|| panic!("the graph holds an entity named {name}"))
}

/// Five packages, one contract, two implementations of it and three near
/// misses. No call edge is needed: the implementations question is answered
/// from declarations alone, which is why it is answerable on a bare install.
fn repository() -> InMemoryGraph {
    let graph = InMemoryGraph::new();
    ingest(&graph, "internal/gh/contract.go", CONTRACT);
    ingest(&graph, "internal/buf/buffer.go", BUFFER);
    ingest(&graph, "internal/discard/discard.go", DISCARD);
    ingest(&graph, "internal/count/counter.go", COUNTER);
    ingest(&graph, "internal/wide/wide.go", WIDE);
    ingest(&graph, "internal/sink/sink.go", SINK);
    graph
}

/// The finding, stated as a fact about today's graph rather than about the fix.
/// If this starts failing, the answer below can read an edge instead of
/// computing a method set.
#[test]
fn no_edge_binds_the_contract_to_a_concrete_method_that_satisfies_it() {
    let graph = repository();
    let spec = entity_named(&graph, "Writer.Write");

    let bound: Vec<_> = graph
        .get_all_relations_for_entity(&spec.id)
        .expect("the store answers")
        .into_iter()
        .filter(|relation| relation.kind == RelationKind::Implements)
        .collect();
    assert!(
        bound.is_empty(),
        "the Go adapter's Implements inference is same-file and type-to-type, so a contract \
         and its implementations in different files produce no binding at all: {bound:?}"
    );
}

/// What a caller receives when they ask where an interface method is
/// implemented: the concrete methods, both of them, and neither of the near
/// misses.
#[test]
fn an_interface_method_names_every_concrete_method_that_satisfies_it() {
    let graph = repository();
    let spec = entity_named(&graph, "Writer.Write");

    let found = interface_implementations(&graph, &spec).expect("the walk answers");
    assert_eq!(
        found
            .iter()
            .map(|row| row.method_name.as_str())
            .collect::<Vec<_>>(),
        vec!["Buffer.Write", "Discard.Write"],
        "both implementations, and nothing that only shares the name: {found:?}"
    );
}

/// The line is the answer. A file-granularity reply to "where is this
/// implemented" is what scored zero on the site axis, so the row has to carry a
/// position a reader can open.
#[test]
fn an_implementation_row_carries_the_declaration_it_points_at() {
    let graph = repository();
    let spec = entity_named(&graph, "Writer.Write");

    let found = interface_implementations(&graph, &spec).expect("the walk answers");
    let buffer = found
        .iter()
        .find(|row| row.method_name == "Buffer.Write")
        .expect("Buffer.Write is one of the implementations");

    let method = graph
        .get_entity(&buffer.method_id)
        .expect("the store answers")
        .expect("the row points at an entity the graph holds");
    assert_eq!(
        method
            .file_origin
            .as_ref()
            .map(|origin| origin.0.as_str())
            .unwrap_or_default(),
        "internal/buf/buffer.go"
    );
    let span = method.span.expect("a parsed declaration carries a span");
    let source_line = BUFFER
        .lines()
        .nth(span.start_line as usize)
        .expect("the span points inside the file");
    assert!(
        source_line.contains("func (b *Buffer) Write("),
        "the row must point at the declaration itself, not at its type: {source_line:?}"
    );
    assert_eq!(buffer.receiver_name, "Buffer");
}

/// The control. `Counter` has a `Write` and no `Close`, so it satisfies no
/// `Writer`, and the one-line grep that returns every implementation returns
/// this one too.
#[test]
fn a_type_that_misses_one_contract_method_is_not_an_implementation() {
    let graph = repository();
    let spec = entity_named(&graph, "Writer.Write");

    let found = interface_implementations(&graph, &spec).expect("the walk answers");
    assert!(
        !found.iter().any(|row| row.method_name == "Counter.Write"),
        "Counter has no Close, so it implements nothing here: {found:?}"
    );
}

/// The second control, and the one a method-name match cannot catch: `Wide`
/// offers both names and the wrong signature.
#[test]
fn a_method_with_the_wrong_arity_is_not_an_implementation() {
    let graph = repository();
    let spec = entity_named(&graph, "Writer.Write");

    let found = interface_implementations(&graph, &spec).expect("the walk answers");
    assert!(
        !found.iter().any(|row| row.method_name == "Wide.Write"),
        "Wide.Write takes two parameters where the contract takes one: {found:?}"
    );
}

/// A contract is not an implementation of another contract. Go lets one
/// interface embed another, so an interface's own spec would otherwise read as
/// satisfying every interface with a compatible method set.
#[test]
fn a_second_interface_is_not_an_implementation_of_the_first() {
    let graph = repository();
    let spec = entity_named(&graph, "Writer.Write");

    let found = interface_implementations(&graph, &spec).expect("the walk answers");
    assert!(
        !found.iter().any(|row| row.method_name == "Sink.Write"),
        "Sink is a contract, not something that implements one: {found:?}"
    );
}

/// The two directions read the same satisfaction rule, so they must agree about
/// which types satisfy which contract. Asserted rather than assumed, because a
/// drift here would let one surface name a type the other denies.
#[test]
fn the_two_directions_agree_about_who_satisfies_the_contract() {
    let graph = repository();
    let spec = entity_named(&graph, "Writer.Write");

    let implementations = interface_implementations(&graph, &spec).expect("the walk answers");
    for row in &implementations {
        let concrete = graph
            .get_entity(&row.method_id)
            .expect("the store answers")
            .expect("the row points at an entity the graph holds");
        let targets = interface_dispatch_targets(&graph, &concrete).expect("the walk answers");
        assert!(
            targets
                .iter()
                .any(|target| target.interface_method_id == spec.id),
            "{} reaches Writer.Write in the implementations direction and not in the dispatch \
             direction: {targets:?}",
            row.method_name
        );
    }
}

/// The question does not apply to a concrete method, and the two empty answers
/// are different facts. Asking what implements `Buffer.Write` is asking what
/// implements an implementation, and a surface that answered "nothing" would be
/// describing an implementation as a dead contract.
#[test]
fn a_concrete_method_has_no_implementations_question() {
    let graph = repository();
    let concrete = entity_named(&graph, "Buffer.Write");

    assert!(!implementations_apply(&graph, &concrete).expect("the gate answers"));
    assert!(interface_implementations(&graph, &concrete)
        .expect("the walk answers")
        .is_empty());

    let spec = entity_named(&graph, "Writer.Write");
    assert!(implementations_apply(&graph, &spec).expect("the gate answers"));
}

/// A contract nothing satisfies answers none, which is a different fact from
/// having no implementations question at all.
#[test]
fn a_contract_nothing_satisfies_answers_none_rather_than_nothing() {
    let graph = InMemoryGraph::new();
    ingest(&graph, "internal/gh/contract.go", CONTRACT);
    ingest(&graph, "internal/count/counter.go", COUNTER);
    let spec = entity_named(&graph, "Writer.Write");

    assert!(
        implementations_apply(&graph, &spec).expect("the gate answers"),
        "the question applies: this is a contract"
    );
    assert!(
        interface_implementations(&graph, &spec)
            .expect("the walk answers")
            .is_empty(),
        "and the answer to it is none"
    );
}

/// The gh arrangement that makes owner resolution load-bearing.
///
/// `internal/gh` declares the interface `AuthConfig` and `internal/config`
/// declares a struct of the same name that satisfies it. Both produce a method
/// entity named `AuthConfig.TokenForUser`, so a `Contains` edge the linker
/// resolved by name alone can land on the wrong one: on the measured store the
/// interface's spec carried an incoming `Contains` from the CONCRETE struct,
/// resolved `name_only`. Reading whichever edge the store listed first would
/// make this answer depend on adjacency order, and for this query it would
/// answer nothing at all.
mod name_collision {
    use super::*;

    const GH: &str = r#"
package gh

type AuthConfig interface {
	TokenForUser(hostname, user string) (string, string, error)
	ActiveUser(hostname string) string
}
"#;

    const CONFIG: &str = r#"
package config

type AuthConfig struct {
	cfg *Config
}

func (c *AuthConfig) TokenForUser(hostname, user string) (string, string, error) {
	return "", "", nil
}

func (c *AuthConfig) ActiveUser(hostname string) string {
	return ""
}
"#;

    #[test]
    fn a_contract_and_a_struct_sharing_a_name_resolve_to_their_own_owners() {
        let graph = InMemoryGraph::new();
        ingest(&graph, "internal/gh/gh.go", GH);
        ingest(&graph, "internal/config/config.go", CONFIG);

        // Both the interface and the struct are named AuthConfig, which is the
        // arrangement under test. Stated rather than assumed: if the adapter
        // starts qualifying these names the collision is gone and so is the
        // point of this test.
        let types: Vec<EntityKind> = graph
            .query_entities(&EntityFilter::default())
            .expect("the store answers")
            .into_iter()
            .filter(|entity| entity.name == "AuthConfig")
            .map(|entity| entity.kind)
            .collect();
        assert_eq!(types.len(), 2, "two types share the name: {types:?}");

        let spec = graph
            .query_entities(&EntityFilter::default())
            .expect("the store answers")
            .into_iter()
            .find(|entity| {
                entity.name == "AuthConfig.TokenForUser"
                    && entity.file_origin.as_ref().map(|origin| origin.0.as_str())
                        == Some("internal/gh/gh.go")
            })
            .expect("the contract's own spec");

        assert!(
            implementations_apply(&graph, &spec).expect("the gate answers"),
            "the spec in internal/gh is a contract, whatever else Contains it"
        );
        let found = interface_implementations(&graph, &spec).expect("the walk answers");
        assert_eq!(found.len(), 1, "{found:?}");
        let method = graph
            .get_entity(&found[0].method_id)
            .expect("the store answers")
            .expect("the row points at an entity the graph holds");
        assert_eq!(
            method
                .file_origin
                .as_ref()
                .map(|origin| origin.0.as_str())
                .unwrap_or_default(),
            "internal/config/config.go",
            "the implementation is the struct's method, not the contract's own spec"
        );
    }
}

/// The shape the answer reads, asserted against real tree-sitter output. If the
/// adapter stops containing an interface's method specs, every assertion above
/// would still pass on a graph built by hand and the answer would be empty on a
/// real repository.
#[test]
fn a_contract_contains_its_method_specs_as_methods() {
    let graph = InMemoryGraph::new();
    ingest(&graph, "internal/gh/contract.go", CONTRACT);

    let interface = entity_named(&graph, "Writer");
    assert_eq!(interface.kind, EntityKind::Interface);
    let spec = entity_named(&graph, "Writer.Write");
    assert_eq!(spec.kind, EntityKind::Method);

    let contained = graph
        .get_relations(&interface.id, &[RelationKind::Contains])
        .expect("the store answers")
        .into_iter()
        .any(|relation| {
            relation.src.as_entity() == Some(interface.id)
                && relation.dst.as_entity() == Some(spec.id)
        });
    assert!(
        contained,
        "the interface must Contain its method spec, which is how the contract is read"
    );
}
