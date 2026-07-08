// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end proof for call-site argument-shape gating.
//!
//! A fresh mini-graph is built by the real Python parser and the real linker;
//! the resolved `Calls` edges carry the persisted call-site argument shape; and
//! the review gate reads that shape from the stored graph to judge an
//! arity-preserving parameter rename. This exercises the whole chain —
//! parse -> link -> persist -> review — not the review logic in isolation.
//!
//! It mirrors the cdc7e13067 `Testdir._makefile` defect: a parameter is renamed
//! with arity preserved and every call site passes positionally, so the rename
//! strands no caller and must not gate as a breaking change. The keyword-caller
//! and `**kwargs` variants prove the gate still blocks a rename that a call site
//! actually names.

use kin_db::{EntityStore, InMemoryGraph};
use kin_index::{link_cross_file, FileParseData};
use kin_model::{Entity, FilePathId, GraphNodeId, RelationKind};
use kin_parser::{LanguageAdapter, PythonAdapter};
use kin_review::{
    analyze_impact, collect_inline_comments, EntityChange, EntityChangeKind, InlineCommentKind,
    SemanticDiff,
};

fn parse_python(file_path: &str, source: &str) -> FileParseData {
    let adapter = PythonAdapter;
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

fn find_entity(files: &[FileParseData], name: &str) -> Entity {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("entity `{name}` not found"))
        .clone()
}

/// Parse `source`, link it into a fresh graph (persisting each call site's
/// argument shape onto its `Calls` edge), then run the review gate over a
/// rename of `target` from `old_sig` to `new_sig`. Returns the emitted comment
/// kinds and the linked relations (so the caller can also assert on the
/// persisted shape directly).
fn link_and_review(
    source: &str,
    old_sig: &str,
    new_sig: &str,
) -> (Vec<InlineCommentKind>, Vec<kin_model::Relation>) {
    let files = vec![parse_python("mod.py", source)];

    // Real linker: resolves calls and persists each Calls edge's argument shape.
    let relations = link_cross_file(&files);

    // Persist entities and edges into a real graph store, exactly as ingest does.
    let graph = InMemoryGraph::new();
    for file in &files {
        for entity in &file.entities {
            graph.upsert_entity(entity).expect("upsert entity");
        }
    }
    for rel in &relations {
        graph.upsert_relation(rel).expect("upsert relation");
    }

    // The rename diff: same entity id, signature old -> new.
    let target = find_entity(&files, "target");
    let mut old = target.clone();
    old.signature = old_sig.to_string();
    let mut new = target.clone();
    new.signature = new_sig.to_string();
    let diff = SemanticDiff {
        entity_changes: vec![EntityChange {
            entity_id: new.id,
            kind: EntityChangeKind::Modified { old, new },
        }],
        ..Default::default()
    };

    let report = analyze_impact(&graph, &diff).expect("analyze impact");
    let kinds = collect_inline_comments(&diff, &report)
        .into_iter()
        .map(|c| c.kind)
        .collect();
    (kinds, relations)
}

const POSITIONAL_CALLERS: &str = "\
def target(ext, args):
    return ext, args


def caller_one():
    return target(1, 2)


def caller_two():
    return target(3, 4)


def caller_three():
    return target(5, 6)
";

const KEYWORD_CALLER: &str = "\
def target(ext, args):
    return ext, args


def caller_one():
    return target(1, 2)


def caller_two():
    return target(3, args=4)
";

const VAR_KEYWORD_CALLER: &str = "\
def target(ext, args):
    return ext, args


def caller_one():
    return target(1, 2)


def caller_two(**opts):
    return target(**opts)
";

#[test]
fn linker_persists_positional_call_shape_on_calls_edges() {
    // Persist proof: the real linker attaches the call-site shape to the target's
    // inbound Calls edges — three positional callers, no keywords.
    let (_kinds, relations) = link_and_review(
        POSITIONAL_CALLERS,
        "def target(ext, args)",
        "def target(ext, lines)",
    );
    let target = find_entity(&[parse_python("mod.py", POSITIONAL_CALLERS)], "target");
    let inbound_shapes: Vec<_> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls && r.dst == GraphNodeId::Entity(target.id))
        .filter_map(|r| r.evidence.iter().find_map(|e| e.call_shape.as_ref()))
        .collect();
    assert_eq!(inbound_shapes.len(), 3, "three call sites carry a shape");
    for shape in inbound_shapes {
        assert_eq!(shape.positional, 2);
        assert!(shape.keywords.is_empty());
        assert!(!shape.has_var_keyword);
    }
}

#[test]
fn e2e_positional_rename_is_not_breaking() {
    // The _makefile shape: rename with every call site positional -> the gate
    // records the signature change but does not block.
    let (kinds, _relations) = link_and_review(
        POSITIONAL_CALLERS,
        "def target(ext, args)",
        "def target(ext, lines)",
    );
    assert!(
        kinds.contains(&InlineCommentKind::SignatureChange),
        "signature evidence is preserved: {kinds:?}"
    );
    assert!(
        !kinds.contains(&InlineCommentKind::Breaking),
        "positional-only callers -> no breaking finding: {kinds:?}"
    );
}

#[test]
fn e2e_keyword_caller_rename_is_breaking() {
    // A caller names the renamed parameter -> the rename strands it -> breaking.
    let (kinds, _relations) = link_and_review(
        KEYWORD_CALLER,
        "def target(ext, args)",
        "def target(ext, lines)",
    );
    assert!(
        kinds.contains(&InlineCommentKind::Breaking),
        "keyword caller of the renamed param must break: {kinds:?}"
    );
}

#[test]
fn e2e_var_keyword_caller_rename_is_breaking() {
    // A `**kwargs` caller could forward the renamed key -> unknown -> breaking.
    let (kinds, _relations) = link_and_review(
        VAR_KEYWORD_CALLER,
        "def target(ext, args)",
        "def target(ext, lines)",
    );
    assert!(
        kinds.contains(&InlineCommentKind::Breaking),
        "**kwargs caller keeps the rename breaking: {kinds:?}"
    );
}

#[test]
fn e2e_review_output_is_deterministic() {
    // The whole chain — shape capture, persistence, harvest, and gate — sorts
    // its intermediate sets, so the same input yields byte-identical output.
    let run = || {
        link_and_review(
            POSITIONAL_CALLERS,
            "def target(ext, args)",
            "def target(ext, lines)",
        )
        .0
    };
    assert_eq!(run(), run(), "review output must be stable across runs");
}
