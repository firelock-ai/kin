// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Callers of a Go concrete method that only a dynamic dispatch can reach.
//!
//! The pre-registered callers protocol's interface class, in miniature: one
//! interface, two implementations, one call written against the interface
//! value. On the gh CLI that class is 184 call sites over 15 declarations and
//! Kin returned 0 of them, because the call resolves to the interface's method
//! object and nothing in the graph binds that back to a concrete method.
//!
//! The files are separate on purpose. The Go adapter already infers implicit
//! satisfaction from method sets, but it does so inside one `extract` call over
//! one tree, so it only ever sees a struct and an interface declared in the
//! SAME file, and it emits the result as a type-to-type `Implements` edge
//! rather than a method-to-method one. A struct in one package and its
//! interface in another is the ordinary Go arrangement and the gh arrangement,
//! and it is the arrangement this file asserts against.

use kin_db::InMemoryGraph;
use kin_index::dispatch::{dispatch_candidate_callers, interface_dispatch_targets};
use kin_index::{apply_to_graph, IndexPipeline};
use kin_model::graph::EntityStore;
use kin_model::{
    ArtifactId, Entity, EntityFilter, EntityKind, GraphNodeId, Hash256, LocatedEntry, Relation,
    RelationKind, RelationOrigin, RepoPath, TransactionDelta, TreeDelta, TreeEntry,
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

/// One implementation, in its own file.
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

/// A second implementation, so one call site is a candidate for two concrete
/// methods and therefore proves neither.
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

/// Has Write and no Close, so it does not satisfy Writer. The control: a
/// method-name match alone must not make this a candidate.
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

/// The caller. Its only call is through the interface value.
const CALLER: &str = r#"
package app

func emit(sink Writer, payload []byte) error {
	if _, err := sink.Write(payload); err != nil {
		return err
	}
	return sink.Close()
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

/// The graph a repository with a Go language server has.
///
/// The one edge added by hand is the call site's own resolution. `sink.Write(p)`
/// reaches the graph as a `Calls` relation whose `dst_name` is the bare
/// `Write`, and gopls is what binds it to the interface's method object, which
/// is exactly what the protocol says the Go compiler does too. Without a
/// language server the bare-name fan-out either spreads that call across every
/// same-named method or, past its cap of eight, emits nothing; neither is the
/// state this feature reads, and the bare-install tier of the proof returned no
/// call sites at all. Stating the edge here rather than simulating an LSP keeps
/// the assumption visible instead of buried in a fixture.
fn gopls_shaped_graph() -> InMemoryGraph {
    let graph = InMemoryGraph::new();
    ingest(&graph, "internal/gh/contract.go", CONTRACT);
    ingest(&graph, "internal/buf/buffer.go", BUFFER);
    ingest(&graph, "internal/discard/discard.go", DISCARD);
    ingest(&graph, "internal/count/counter.go", COUNTER);
    ingest(&graph, "cmd/app/emit.go", CALLER);

    let emit = entity_named(&graph, "emit");
    for contract_method in ["Writer.Write", "Writer.Close"] {
        let spec = entity_named(&graph, contract_method);
        graph
            .upsert_relation(&Relation {
                id: kin_model::ids::RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(emit.id),
                dst: GraphNodeId::Entity(spec.id),
                confidence: 1.0,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .expect("the call edge lands");
    }
    graph
}

/// The shape the feature reads, asserted against real tree-sitter output rather
/// than assumed. If the adapter stops making an interface's method specs
/// first-class entities, every assertion below would still pass on a graph
/// built by hand and the feature would return nothing on a real repository.
#[test]
fn an_interface_method_spec_is_an_entity_its_interface_contains() {
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
        "the interface must Contain its method spec, which is how the method set is read"
    );
}

/// The gap, stated as a fact about today's graph rather than about the feature.
#[test]
fn no_edge_binds_a_concrete_method_to_the_contract_it_satisfies() {
    let graph = gopls_shaped_graph();
    let concrete = entity_named(&graph, "Buffer.Write");

    let bound = graph
        .get_all_relations_for_entity(&concrete.id)
        .expect("the store answers")
        .into_iter()
        .any(|relation| relation.kind == RelationKind::Implements);
    assert!(
        !bound,
        "the Go adapter's Implements inference is same-file and type-to-type, so a struct \
         and its interface in different files produce no binding at all; if this starts \
         failing the feature can read the edge instead of computing the method set"
    );
}

#[test]
fn a_call_through_the_interface_is_a_candidate_for_every_implementation() {
    let graph = gopls_shaped_graph();
    let emit = entity_named(&graph, "emit");

    for concrete in ["Buffer.Write", "Discard.Write"] {
        let focal = entity_named(&graph, concrete);
        let targets = interface_dispatch_targets(&graph, &focal).expect("the walk answers");
        assert_eq!(
            targets
                .iter()
                .map(|target| target.interface_method_name.as_str())
                .collect::<Vec<_>>(),
            vec!["Writer.Write"],
            "{concrete} satisfies Writer, so Writer.Write is the method a call through the \
             interface reaches"
        );

        let callers =
            dispatch_candidate_callers(&graph, &focal, &targets).expect("the walk answers");
        assert_eq!(
            callers,
            vec![(emit.id, vec!["Writer.Write".to_string()])],
            "{concrete} must reach the call site written against the interface"
        );
    }
}

/// The control the feature is worth nothing without. `Counter` has a `Write`
/// and no `Close`, so it satisfies no contract the call site names, and a
/// method-name match alone must not carry it.
#[test]
fn a_type_that_misses_one_contract_method_is_not_a_candidate() {
    let graph = gopls_shaped_graph();
    let focal = entity_named(&graph, "Counter.Write");

    let targets = interface_dispatch_targets(&graph, &focal).expect("the walk answers");
    assert!(
        targets.is_empty(),
        "Counter has no Close, so it satisfies no Writer and nothing may reach it: {targets:?}"
    );
}

/// An interface method's own callers are already direct callers. Widening one
/// contract's method to another contract's would invent dispatch between two
/// things nothing implements.
#[test]
fn an_interface_method_is_not_dispatched_to_another_interface() {
    let graph = gopls_shaped_graph();
    let focal = entity_named(&graph, "Writer.Write");

    let targets = interface_dispatch_targets(&graph, &focal).expect("the walk answers");
    assert!(
        targets.is_empty(),
        "the focal is already the method a call site resolves to: {targets:?}"
    );
}

/// A candidate is never presented as a proven caller, so the direct caller set
/// must not change. `emit` calls the contract and nothing calls `Buffer.Write`
/// directly, which is the whole reason the count was zero.
#[test]
fn the_proven_caller_set_is_unchanged_by_the_candidate_walk() {
    let graph = gopls_shaped_graph();
    let focal = entity_named(&graph, "Buffer.Write");

    // The whole edge set, not `get_relations`, which answers with a node's
    // OUTGOING edges only. A caller is on the incoming side, so the narrow read
    // would return an empty list here whatever the graph held and this
    // assertion would pass without testing anything.
    let direct: Vec<_> = graph
        .get_all_relations_for_entity(&focal.id)
        .expect("the store answers")
        .into_iter()
        .filter(|relation| {
            relation.kind == RelationKind::Calls && relation.dst.as_entity() == Some(focal.id)
        })
        .collect();
    assert!(
        direct.is_empty(),
        "nothing calls the concrete method by name, which is the finding: {direct:?}"
    );

    let targets = interface_dispatch_targets(&graph, &focal).expect("the walk answers");
    let callers = dispatch_candidate_callers(&graph, &focal, &targets).expect("the walk answers");
    assert_eq!(
        callers.len(),
        1,
        "the candidate travels beside the proven set and never inside it"
    );
}
