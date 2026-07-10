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
//!
//! Both gate channels are exercised: the inline `signature_change`/`Breaking`
//! channel (`collect_inline_comments`) AND the SHADOW `downstream_risk` channel
//! (`derive_shadow_policy`). FIR-1440 shipped because only the inline channel had
//! e2e coverage — the shadow gate, which is the real merge-trust verdict,
//! re-blocked the positional-safe rename with no test to catch it.

use kin_db::{EntityStore, InMemoryGraph};
use kin_index::{
    link_cross_file, link_cross_file_with_completeness, FileParseCompletenessMap, FileParseData,
    CALL_SHAPE_EVIDENCE_AGGREGATION_V1, CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1,
};
use kin_model::review::{RiskLevel, RiskSummary};
use kin_model::{
    Entity, FileLayout, FilePathId, GraphNodeId, ImportSection, ParseCompleteness, RelationKind,
};
use kin_parser::{LanguageAdapter, PythonAdapter};
use kin_review::{
    analyze_impact, collect_inline_comments, derive_shadow_policy, EntityChange, EntityChangeKind,
    InlineCommentKind, Review, SemanticDiff, ShadowGateVerdict,
};

fn parse_python_bytes_allow_incomplete(
    file_path: &str,
    bytes: &[u8],
) -> (FileParseData, ParseCompleteness) {
    let adapter = PythonAdapter;
    let file_id = FilePathId::new(file_path);
    let tree = adapter.parse(bytes).expect("parse");
    let output = adapter.extract(&tree, bytes, &file_id).expect("extract");
    let parse_completeness = ParseCompleteness::from_parse_state(&output.parse_state);
    let entities: Vec<Entity> = output
        .entities
        .into_iter()
        .map(|e| e.into_entity_with_source(adapter.language_id(), &file_id, Some(bytes)))
        .collect();
    (
        FileParseData {
            file_path: file_path.to_string(),
            entities,
            relations: output.relations,
            imports: output.imports,
        },
        parse_completeness,
    )
}

fn parse_python_bytes(file_path: &str, bytes: &[u8]) -> FileParseData {
    let (parsed, parse_completeness) = parse_python_bytes_allow_incomplete(file_path, bytes);
    assert!(
        matches!(&parse_completeness, ParseCompleteness::Full),
        "call-shape fixture must exercise a valid Python parse: {:?}",
        parse_completeness
    );
    parsed
}

fn parse_python(file_path: &str, source: &str) -> FileParseData {
    parse_python_bytes(file_path, source.as_bytes())
}

fn find_entity(files: &[FileParseData], name: &str) -> Entity {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("entity `{name}` not found"))
        .clone()
}

/// Parse `source` and link it into a fresh persisted graph, exactly as ingest
/// does — each `Calls` edge carries its call-site argument shape. Returns the
/// parsed files (for entity lookup), the linked relations, and the graph store.
fn link_into_graph(source: &str) -> (Vec<FileParseData>, Vec<kin_model::Relation>, InMemoryGraph) {
    link_into_graph_bytes(source.as_bytes())
}

fn link_into_graph_bytes(
    source: &[u8],
) -> (Vec<FileParseData>, Vec<kin_model::Relation>, InMemoryGraph) {
    let files = vec![parse_python_bytes("mod.py", source)];
    link_parsed_files_into_graph(files)
}

fn link_parsed_files_into_graph(
    files: Vec<FileParseData>,
) -> (Vec<FileParseData>, Vec<kin_model::Relation>, InMemoryGraph) {
    let completeness = files
        .iter()
        .map(|file| (file.file_path.clone(), ParseCompleteness::Full))
        .collect();
    link_parsed_files_into_graph_with_completeness(files, completeness)
}

fn link_parsed_files_into_graph_with_completeness(
    files: Vec<FileParseData>,
    completeness: FileParseCompletenessMap,
) -> (Vec<FileParseData>, Vec<kin_model::Relation>, InMemoryGraph) {
    // Real linker: resolves calls and persists each Calls edge's argument shape.
    let relations = link_cross_file_with_completeness(&files, &completeness);

    // Persist entities and edges into a real graph store, exactly as ingest does.
    let graph = InMemoryGraph::new();
    for file in &files {
        graph
            .upsert_file_layout(&FileLayout {
                file_id: FilePathId::new(&file.file_path),
                parse_completeness: completeness.get(&file.file_path).cloned().unwrap_or_else(
                    || ParseCompleteness::Failed("missing test parse coverage".to_string()),
                ),
                imports: ImportSection {
                    byte_range: 0..0,
                    items: Vec::new(),
                },
                regions: Vec::new(),
            })
            .expect("upsert file layout");
        for entity in &file.entities {
            graph.upsert_entity(entity).expect("upsert entity");
        }
    }
    for rel in &relations {
        graph.upsert_relation(rel).expect("upsert relation");
    }
    (files, relations, graph)
}

fn shadow_verdict(graph: &InMemoryGraph, diff: SemanticDiff) -> ShadowGateVerdict {
    let report = analyze_impact(graph, &diff).expect("analyze impact");
    let inline_comments = collect_inline_comments(&diff, &report);
    let review = Review {
        base: None,
        head: None,
        diff,
        impact: report,
        risk: RiskSummary {
            overall_risk: RiskLevel::Low,
            breaking_changes: vec![],
            test_coverage_gaps: vec![],
            contract_violations: vec![],
            work_risks: vec![],
            notes: vec![],
        },
        inline_comments,
    };
    derive_shadow_policy(&review, &[], &[]).verdict
}

/// The rename diff for `target`: same entity id, signature `old_sig` -> `new_sig`.
fn rename_diff(files: &[FileParseData], old_sig: &str, new_sig: &str) -> SemanticDiff {
    let target = find_entity(files, "target");
    let mut old = target.clone();
    old.signature = old_sig.to_string();
    let mut new = target.clone();
    new.signature = new_sig.to_string();
    SemanticDiff {
        entity_changes: vec![EntityChange {
            entity_id: new.id,
            kind: EntityChangeKind::Modified { old, new },
        }],
        ..Default::default()
    }
}

/// Parse, link, persist, and run the INLINE review gate over a rename of
/// `target` from `old_sig` to `new_sig`. Returns the emitted comment kinds and
/// the linked relations (so the caller can also assert on the persisted shape).
fn link_and_review(
    source: &str,
    old_sig: &str,
    new_sig: &str,
) -> (Vec<InlineCommentKind>, Vec<kin_model::Relation>) {
    let (files, relations, graph) = link_into_graph(source);
    let diff = rename_diff(&files, old_sig, new_sig);
    let report = analyze_impact(&graph, &diff).expect("analyze impact");
    let kinds = collect_inline_comments(&diff, &report)
        .into_iter()
        .map(|c| c.kind)
        .collect();
    (kinds, relations)
}

/// Drive the SHADOW gate (the `downstream_risk` channel) over the same real
/// mini-graph. This is the merge-trust verdict the shipped FIR-1440 bug slipped
/// through: the inline-only assertions above never exercised it. Builds a
/// `Review` from the real diff + impact + inline comments — reproducing the
/// exact production seam — and returns the gate verdict with the graph inputs
/// so evidence-level regressions can inspect the persisted logical edges.
fn link_and_shadow_analysis(
    source: &str,
    old_sig: &str,
    new_sig: &str,
) -> (
    ShadowGateVerdict,
    Vec<FileParseData>,
    Vec<kin_model::Relation>,
) {
    let (files, relations, graph) = link_into_graph(source);
    let diff = rename_diff(&files, old_sig, new_sig);
    (shadow_verdict(&graph, diff), files, relations)
}

fn link_and_shadow_verdict(source: &str, old_sig: &str, new_sig: &str) -> ShadowGateVerdict {
    link_and_shadow_analysis(source, old_sig, new_sig).0
}

fn same_caller_shadow_evidence(
    source: &str,
    old_sig: &str,
    new_sig: &str,
) -> (ShadowGateVerdict, Vec<kin_model::RelationEvidence>) {
    let (verdict, files, relations) = link_and_shadow_analysis(source, old_sig, new_sig);
    let target = find_entity(&files, "target");
    let inbound: Vec<_> = relations
        .iter()
        .filter(|relation| {
            relation.kind == RelationKind::Calls && relation.dst == GraphNodeId::Entity(target.id)
        })
        .collect();
    assert_eq!(
        inbound.len(),
        1,
        "one caller entity must produce one logical Calls edge"
    );
    (verdict, inbound[0].evidence.clone())
}

/// Build old and new entities from their real source declarations, rather than
/// overwriting a parsed entity's signature with hand-authored strings. This
/// covers the production declaration canonicalizer as well as parse, link,
/// persist, impact, inline, and shadow policy.
fn link_and_shadow_verdict_from_sources(
    old_source: &str,
    new_source: &str,
) -> (ShadowGateVerdict, String, String) {
    link_and_shadow_verdict_from_source_bytes(old_source.as_bytes(), new_source.as_bytes())
}

fn link_and_shadow_verdict_from_source_bytes(
    old_source: &[u8],
    new_source: &[u8],
) -> (ShadowGateVerdict, String, String) {
    let (old_files, _relations, graph) = link_into_graph_bytes(old_source);
    let new_files = vec![parse_python_bytes("mod.py", new_source)];
    let old = find_entity(&old_files, "target");
    let new = find_entity(&new_files, "target");
    assert_eq!(
        old.id, new.id,
        "the same declaration path/name must retain graph identity"
    );
    let old_signature = old.signature.clone();
    let new_signature = new.signature.clone();
    let diff = SemanticDiff {
        entity_changes: vec![EntityChange {
            entity_id: new.id,
            kind: EntityChangeKind::Modified { old, new },
        }],
        ..Default::default()
    };
    (shadow_verdict(&graph, diff), old_signature, new_signature)
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

const SAME_CALLER_POSITIONAL_THEN_KEYWORD: &str = "\
def target(ext, args):
    return ext, args


def caller():
    target(1, 2)
    return target(3, args=4)
";

const SAME_CALLER_KEYWORD_THEN_POSITIONAL: &str = "\
def target(ext, args):
    return ext, args


def caller():
    target(3, args=4)
    return target(1, 2)
";

const SAME_CALLER_POSITIONAL_THEN_VAR_KEYWORD: &str = "\
def target(ext, args):
    return ext, args


def caller(opts):
    target(1, 2)
    return target(**opts)
";

const SAME_CALLER_VAR_KEYWORD_THEN_POSITIONAL: &str = "\
def target(ext, args):
    return ext, args


def caller(opts):
    target(**opts)
    return target(1, 2)
";

const SAME_CALLER_ALL_POSITIONAL: &str = "\
def target(ext, args=1):
    return ext, args


def caller(values):
    target(1)
    target(2, 3)
    target(4, 5)
    return target(*values)
";

const SAME_CALLER_ALL_POSITIONAL_REVERSED: &str = "\
def target(ext, args=1):
    return ext, args


def caller(values):
    target(*values)
    target(4, 5)
    target(2, 3)
    return target(1)
";

const POSITIONAL_DEFAULT_CALLERS: &str = "\
def target(ext, args=1):
    return ext, args


def caller_one():
    return target(1)


def caller_two():
    return target(2, 3)
";

const PARSED_DEFAULT_CHANGE_OLD: &str = r#"def target(ext, args="x  y"):
    return ext, args


def caller_one():
    return target(1)


def caller_two():
    return target(2, "explicit")
"#;

const PARSED_DEFAULT_CHANGE_NEW: &str = r#"def target(ext, lines="xy"):
    return ext, lines


def caller_one():
    return target(1)


def caller_two():
    return target(2, "explicit")
"#;

const PARSED_NONE_TYPE_STRING_DEFAULT_OLD: &str = r#"def target(value="type(None)"):
    return value


def caller():
    return target("explicit")
"#;

const PARSED_NONE_TYPE_STRING_DEFAULT_NEW: &str = r#"def target(value="types.NoneType"):
    return value


def caller():
    return target("explicit")
"#;

const PARSED_LARGER_IDENTIFIER_DEFAULT_OLD: &str = r#"def target(value=mytype(None)):
    return value


def caller():
    return target("explicit")
"#;

const PARSED_LARGER_IDENTIFIER_DEFAULT_NEW: &str = r#"def target(value=mytypes.NoneType):
    return value


def caller():
    return target("explicit")
"#;

const PARSED_LINE_CONTINUED_ATTRIBUTE_DEFAULT_OLD: &str = r#"def target(value=obj.\
 type(None)):
    return value


def caller():
    return target("explicit")
"#;

const PARSED_LINE_CONTINUED_ATTRIBUTE_DEFAULT_NEW: &str = r#"def target(value=obj.\
 types.NoneType):
    return value


def caller():
    return target("explicit")
"#;

const INCOMPLETE_TARGET_DEFINITION: &str = "\
def target(ext, args):
    return ext, args
";

const COMPLETE_POSITIONAL_CALLER: &str = "\
def caller():
    return target(1, 2)
";

const INCOMPLETE_ONLY_KEYWORD_CALLER: &str = "\
def broken():
    return target(3, args=4
";

const PARSED_SYNC_RENAME: &str = "\
def target(ext, args):
    return ext, args


def caller():
    return target(1, 2)
";

const PARSED_ASYNC_RENAME: &str = "\
async def target(ext, lines):
    return ext, lines


def caller():
    return target(1, 2)
";

const LATIN1_DEFAULT_CHANGE_OLD: &[u8] = b"# coding: latin-1\ndef target(ext, args=\"x  \xff y\"):\n    return ext, args\n\n\ndef caller_one():\n    return target(1)\n\n\ndef caller_two():\n    return target(2, \"explicit\")\n";

const LATIN1_DEFAULT_WHITESPACE_CHANGE_NEW: &[u8] = b"# coding: latin-1\ndef target(ext, lines=\"x \xff y\"):\n    return ext, lines\n\n\ndef caller_one():\n    return target(1)\n\n\ndef caller_two():\n    return target(2, \"explicit\")\n";

const LATIN1_DEFAULT_BYTE_CHANGE_NEW: &[u8] = b"# coding: latin-1\ndef target(ext, lines=\"x  \xfe y\"):\n    return ext, lines\n\n\ndef caller_one():\n    return target(1)\n\n\ndef caller_two():\n    return target(2, \"explicit\")\n";

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

#[test]
fn e2e_shadow_gate_positional_rename_needs_attention_not_would_block() {
    // FIR-1440, the shipped blind spot: the inline assertions above pass for this
    // rename, but the real merge-trust verdict is the SHADOW gate. Pre-fix the
    // shadow `downstream_risk` channel re-blocked the positional-safe rename
    // (WouldBlock); post-fix it demotes to attention, matching the inline channel.
    let verdict = link_and_shadow_verdict(
        POSITIONAL_CALLERS,
        "def target(ext, args)",
        "def target(ext, lines)",
    );
    assert_eq!(
        verdict,
        ShadowGateVerdict::NeedsAttention,
        "positional-safe rename must not block the shadow gate"
    );
    assert_ne!(verdict, ShadowGateVerdict::WouldBlock);
}

#[test]
fn e2e_shadow_gate_keyword_caller_rename_would_block() {
    // A caller names the renamed parameter -> the rename strands it -> the shadow
    // gate must still block (no over-suppression from the FIR-1440 fix).
    let verdict = link_and_shadow_verdict(
        KEYWORD_CALLER,
        "def target(ext, args)",
        "def target(ext, lines)",
    );
    assert_eq!(
        verdict,
        ShadowGateVerdict::WouldBlock,
        "keyword caller of the renamed param keeps the shadow gate blocking"
    );
}

#[test]
fn e2e_shadow_gate_var_keyword_caller_rename_would_block() {
    // A `**kwargs` caller could forward the renamed key -> unknown -> the shadow
    // gate must still block.
    let verdict = link_and_shadow_verdict(
        VAR_KEYWORD_CALLER,
        "def target(ext, args)",
        "def target(ext, lines)",
    );
    assert_eq!(
        verdict,
        ShadowGateVerdict::WouldBlock,
        "**kwargs caller keeps the shadow gate blocking"
    );
}

#[test]
fn e2e_same_caller_keyword_shape_blocks_independent_of_source_order() {
    let old = "def target(ext, args)";
    let new = "def target(ext, lines)";
    let (forward_verdict, forward_evidence) =
        same_caller_shadow_evidence(SAME_CALLER_POSITIONAL_THEN_KEYWORD, old, new);
    let (reverse_verdict, reverse_evidence) =
        same_caller_shadow_evidence(SAME_CALLER_KEYWORD_THEN_POSITIONAL, old, new);

    assert_eq!(forward_verdict, ShadowGateVerdict::WouldBlock);
    assert_eq!(reverse_verdict, ShadowGateVerdict::WouldBlock);
    assert_eq!(
        forward_evidence, reverse_evidence,
        "logical call evidence must be byte-stable across source-order reversal"
    );
    assert_eq!(forward_evidence.len(), 2, "both distinct shapes survive");
    assert!(forward_evidence.iter().any(|evidence| {
        evidence
            .call_shape
            .as_ref()
            .is_some_and(|shape| shape.keywords == ["args"])
    }));
    assert!(forward_evidence.iter().any(|evidence| {
        evidence.call_shape.as_ref().is_some_and(|shape| {
            shape.positional == 2 && shape.keywords.is_empty() && !shape.has_var_keyword
        })
    }));
}

#[test]
fn e2e_same_caller_var_keyword_shape_blocks_independent_of_source_order() {
    let old = "def target(ext, args)";
    let new = "def target(ext, lines)";
    let (forward_verdict, forward_evidence) =
        same_caller_shadow_evidence(SAME_CALLER_POSITIONAL_THEN_VAR_KEYWORD, old, new);
    let (reverse_verdict, reverse_evidence) =
        same_caller_shadow_evidence(SAME_CALLER_VAR_KEYWORD_THEN_POSITIONAL, old, new);

    assert_eq!(forward_verdict, ShadowGateVerdict::WouldBlock);
    assert_eq!(reverse_verdict, ShadowGateVerdict::WouldBlock);
    assert_eq!(
        forward_evidence, reverse_evidence,
        "`**kwargs` evidence must not depend on which call appears first"
    );
    assert_eq!(forward_evidence.len(), 2, "both distinct shapes survive");
    assert!(forward_evidence.iter().any(|evidence| {
        evidence
            .call_shape
            .as_ref()
            .is_some_and(|shape| shape.has_var_keyword)
    }));
}

#[test]
fn e2e_same_caller_all_positional_shapes_remain_neutral_and_deterministic() {
    let old = "def target(ext, args=1)";
    let new = "def target(ext, lines=1)";
    let (forward_verdict, forward_evidence) =
        same_caller_shadow_evidence(SAME_CALLER_ALL_POSITIONAL, old, new);
    let (reverse_verdict, reverse_evidence) =
        same_caller_shadow_evidence(SAME_CALLER_ALL_POSITIONAL_REVERSED, old, new);

    assert_eq!(forward_verdict, ShadowGateVerdict::NeedsAttention);
    assert_eq!(reverse_verdict, ShadowGateVerdict::NeedsAttention);
    assert_eq!(
        forward_evidence, reverse_evidence,
        "all-positional evidence must sort and deduplicate deterministically"
    );
    assert_eq!(
        forward_evidence.len(),
        3,
        "four calls collapse to three distinct shapes"
    );
    assert_eq!(
        forward_evidence
            .iter()
            .map(|evidence| evidence.occurrence_count)
            .sum::<u32>(),
        4,
        "occurrence counts retain every call site"
    );
    assert!(forward_evidence.iter().all(|evidence| {
        evidence.parser_rule.as_deref() == Some(CALL_SHAPE_EVIDENCE_AGGREGATION_V1)
    }));
    assert!(forward_evidence.iter().all(|evidence| {
        evidence
            .call_shape
            .as_ref()
            .is_some_and(|shape| shape.keywords.is_empty() && !shape.has_var_keyword)
    }));
    assert!(forward_evidence.iter().any(|evidence| {
        evidence
            .call_shape
            .as_ref()
            .is_some_and(|shape| shape.has_var_positional)
    }));
    assert!(forward_evidence.iter().any(|evidence| {
        evidence.occurrence_count == 2
            && evidence
                .call_shape
                .as_ref()
                .is_some_and(|shape| shape.positional == 2 && !shape.has_var_positional)
    }));
}

#[test]
fn e2e_legacy_serialized_single_shape_evidence_stays_blocking() {
    let files = vec![parse_python("mod.py", SAME_CALLER_POSITIONAL_THEN_KEYWORD)];
    let target = find_entity(&files, "target");
    let relations = link_cross_file(&files);
    let mut legacy_edge = relations
        .iter()
        .find(|relation| {
            relation.kind == RelationKind::Calls && relation.dst == GraphNodeId::Entity(target.id)
        })
        .expect("fresh logical caller-target edge")
        .clone();
    let first_positional = legacy_edge
        .evidence
        .iter()
        .find(|evidence| {
            evidence.call_shape.as_ref().is_some_and(|shape| {
                shape.positional == 2 && shape.keywords.is_empty() && !shape.has_var_keyword
            })
        })
        .expect("positional occurrence")
        .clone();
    legacy_edge.evidence = vec![first_positional];

    // v0.2.15 stored this shaped first occurrence without any completeness
    // provenance. Round-trip the edge with that field absent to exercise the
    // same backward-compatible serde path an upgraded graph takes.
    let mut serialized = serde_json::to_value(&legacy_edge).expect("serialize relation");
    let records = serialized
        .get_mut("evidence")
        .and_then(serde_json::Value::as_array_mut)
        .expect("serialized evidence array");
    records[0]
        .as_object_mut()
        .expect("serialized evidence record")
        .remove("parser_rule");
    let legacy_edge: kin_model::Relation =
        serde_json::from_value(serialized).expect("deserialize legacy relation");
    assert!(legacy_edge.evidence[0].call_shape.is_some());
    assert!(legacy_edge.evidence[0].parser_rule.is_none());

    let graph = InMemoryGraph::new();
    for entity in files.iter().flat_map(|file| file.entities.iter()) {
        graph.upsert_entity(entity).expect("upsert entity");
    }
    graph
        .upsert_relation(&legacy_edge)
        .expect("upsert legacy relation");
    let diff = rename_diff(&files, "def target(ext, args)", "def target(ext, lines)");
    let impact = analyze_impact(&graph, &diff).expect("analyze legacy impact");
    assert!(
        !impact
            .entity_impact(&target.id)
            .expect("target impact")
            .call_shapes
            .all_consumers_shaped_calls,
        "legacy first-occurrence evidence is shaped but not complete"
    );
    let inline_comments = collect_inline_comments(&diff, &impact);
    assert!(inline_comments
        .iter()
        .any(|comment| comment.kind == InlineCommentKind::Breaking));
    let review = Review {
        base: None,
        head: None,
        diff,
        impact,
        risk: RiskSummary {
            overall_risk: RiskLevel::Low,
            breaking_changes: vec![],
            test_coverage_gaps: vec![],
            contract_violations: vec![],
            work_risks: vec![],
            notes: vec![],
        },
        inline_comments,
    };
    assert_eq!(
        derive_shadow_policy(&review, &[], &[]).verdict,
        ShadowGateVerdict::WouldBlock,
        "an upgraded v0.2.15 edge must fail closed until it is re-linked"
    );
}

#[test]
fn e2e_shadow_gate_rename_with_default_change_would_block() {
    // Full negative-control chain: parse the real defaulted declaration and
    // positional callers, link and persist their call shapes, harvest impact,
    // then drive the shadow merge-trust verdict. Complete positional evidence
    // must not demote a simultaneous default-value change.
    let verdict = link_and_shadow_verdict(
        POSITIONAL_DEFAULT_CALLERS,
        "def target(ext, args=1)",
        "def target(ext, lines=2)",
    );
    assert_eq!(
        verdict,
        ShadowGateVerdict::WouldBlock,
        "a rename with a changed default must stay blocking after the full graph path"
    );
}

#[test]
fn e2e_parsed_sources_preserve_and_block_changed_string_default() {
    let (verdict, old_signature, new_signature) =
        link_and_shadow_verdict_from_sources(PARSED_DEFAULT_CHANGE_OLD, PARSED_DEFAULT_CHANGE_NEW);
    assert!(
        old_signature.contains(r#"args="x  y""#),
        "the production declaration signature must preserve both literal spaces: {old_signature}"
    );
    assert!(
        new_signature.contains(r#"lines="xy""#),
        "new declaration signature comes from parsed source: {new_signature}"
    );
    assert_eq!(
        verdict,
        ShadowGateVerdict::WouldBlock,
        "a parsed rename plus semantic string-default change must stay blocking"
    );
}

#[test]
fn e2e_parsed_none_type_text_and_larger_identifier_defaults_stay_blocking() {
    for (label, old_source, new_source, old_fragment, new_fragment) in [
        (
            "quoted text",
            PARSED_NONE_TYPE_STRING_DEFAULT_OLD,
            PARSED_NONE_TYPE_STRING_DEFAULT_NEW,
            r#"value="type(None)""#,
            r#"value="types.NoneType""#,
        ),
        (
            "larger identifier",
            PARSED_LARGER_IDENTIFIER_DEFAULT_OLD,
            PARSED_LARGER_IDENTIFIER_DEFAULT_NEW,
            "value=mytype(None)",
            "value=mytypes.NoneType",
        ),
    ] {
        let (verdict, old_signature, new_signature) =
            link_and_shadow_verdict_from_sources(old_source, new_source);
        assert!(
            old_signature.contains(old_fragment),
            "old {label} default must come from parsed source: {old_signature}"
        );
        assert!(
            new_signature.contains(new_fragment),
            "new {label} default must come from parsed source: {new_signature}"
        );
        assert_eq!(
            verdict,
            ShadowGateVerdict::WouldBlock,
            "NoneType spelling normalization must not rewrite {label}"
        );
    }
}

#[test]
fn e2e_line_continued_attribute_none_type_change_stays_blocking() {
    let (verdict, old_signature, new_signature) = link_and_shadow_verdict_from_sources(
        PARSED_LINE_CONTINUED_ATTRIBUTE_DEFAULT_OLD,
        PARSED_LINE_CONTINUED_ATTRIBUTE_DEFAULT_NEW,
    );
    assert!(
        old_signature.contains('\\') && new_signature.contains('\\'),
        "production signatures must retain the explicit continuation: {old_signature:?} -> {new_signature:?}"
    );
    assert_eq!(
        verdict,
        ShadowGateVerdict::WouldBlock,
        "NoneType normalization must not cross an explicit continuation after attribute access"
    );
}

#[test]
fn e2e_fully_omitted_call_in_incomplete_file_cannot_neutralize_rename() {
    let target = parse_python("defs.py", INCOMPLETE_TARGET_DEFINITION);
    let positional = parse_python("good.py", COMPLETE_POSITIONAL_CALLER);
    let (incomplete, incomplete_state) =
        parse_python_bytes_allow_incomplete("bad.py", INCOMPLETE_ONLY_KEYWORD_CALLER.as_bytes());
    assert!(
        matches!(
            &incomplete_state,
            ParseCompleteness::Partial(_) | ParseCompleteness::Failed(_)
        ),
        "fixture must exercise tree-sitter recovery: {:?}",
        incomplete_state
    );
    let extracted_target_calls = incomplete
        .relations
        .iter()
        .filter(|relation| relation.kind == RelationKind::Calls && relation.dst_name == "target")
        .count();
    assert_eq!(
        extracted_target_calls, 0,
        "the recovered parse must fully omit its only malformed keyword call"
    );

    let files = vec![target, positional, incomplete];
    let completeness = FileParseCompletenessMap::from([
        ("defs.py".to_string(), ParseCompleteness::Full),
        ("good.py".to_string(), ParseCompleteness::Full),
        ("bad.py".to_string(), incomplete_state),
    ]);
    let (files, relations, graph) =
        link_parsed_files_into_graph_with_completeness(files, completeness);
    let target = find_entity(&files, "target");
    let inbound = relations
        .iter()
        .find(|relation| {
            relation.kind == RelationKind::Calls && relation.dst == GraphNodeId::Entity(target.id)
        })
        .expect("the complete positional caller still links");
    assert!(inbound.evidence.iter().all(|evidence| {
        evidence.parser_rule.as_deref() == Some(CALL_SHAPE_EVIDENCE_AGGREGATION_V1)
            && evidence.call_shape.is_some()
    }));
    assert!(relations
        .iter()
        .any(|relation| relation.evidence.iter().any(|evidence| {
            evidence.parser_rule.as_deref() == Some(CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1)
                && evidence.source_path.as_deref() == Some("bad.py")
        })));

    let diff = rename_diff(&files, "def target(ext, args)", "def target(ext, lines)");
    let impact = analyze_impact(&graph, &diff).expect("analyze incomplete-parse impact");
    assert!(
        !impact
            .entity_impact(&target.id)
            .expect("target impact")
            .call_shapes
            .all_consumers_shaped_calls,
        "file-level incomplete-parse evidence must remain unknown even when no call edge survived"
    );
    assert_eq!(
        shadow_verdict(&graph, diff),
        ShadowGateVerdict::WouldBlock,
        "an omitted call from recovered syntax cannot be neutralized by the surviving positional call"
    );
}

#[test]
fn e2e_parsed_sync_async_rename_stays_blocking_in_both_directions() {
    for (label, old_source, new_source) in [
        ("sync-to-async", PARSED_SYNC_RENAME, PARSED_ASYNC_RENAME),
        ("async-to-sync", PARSED_ASYNC_RENAME, PARSED_SYNC_RENAME),
    ] {
        let (verdict, old_signature, new_signature) =
            link_and_shadow_verdict_from_sources(old_source, new_source);
        assert_ne!(
            old_signature.starts_with("async def"),
            new_signature.starts_with("async def")
        );
        assert_eq!(
            verdict,
            ShadowGateVerdict::WouldBlock,
            "{label} changes the callable runtime mode and cannot be neutralized by positional call evidence"
        );
    }
}

#[test]
fn e2e_invalid_utf8_defaults_are_opaque_and_fail_closed() {
    for (label, changed_source) in [
        (
            "semantic whitespace around an invalid byte",
            LATIN1_DEFAULT_WHITESPACE_CHANGE_NEW,
        ),
        (
            "a distinct invalid byte value",
            LATIN1_DEFAULT_BYTE_CHANGE_NEW,
        ),
    ] {
        let (verdict, old_signature, new_signature) =
            link_and_shadow_verdict_from_source_bytes(LATIN1_DEFAULT_CHANGE_OLD, changed_source);
        assert!(
            old_signature.starts_with("non_utf8_hex:"),
            "old invalid-UTF-8 declaration must be opaque: {old_signature}"
        );
        assert!(
            new_signature.starts_with("non_utf8_hex:"),
            "new invalid-UTF-8 declaration must be opaque: {new_signature}"
        );
        assert_ne!(
            old_signature, new_signature,
            "raw declaration changes must remain visible for {label}"
        );
        assert_eq!(
            verdict,
            ShadowGateVerdict::WouldBlock,
            "rename analysis must fail closed for {label}"
        );
    }
}

#[test]
fn e2e_shadow_gate_verdict_is_deterministic() {
    // The demoted shadow verdict reads only counts and sorted call_shapes, so the
    // same input yields the same verdict across runs (citable-gate determinism).
    let run = || {
        link_and_shadow_verdict(
            POSITIONAL_CALLERS,
            "def target(ext, args)",
            "def target(ext, lines)",
        )
    };
    assert_eq!(run(), run(), "shadow verdict must be stable across runs");
}
