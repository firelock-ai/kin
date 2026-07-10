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
use kin_index::{link_cross_file, FileParseData};
use kin_model::review::{RiskLevel, RiskSummary};
use kin_model::{Entity, FilePathId, GraphNodeId, RelationKind};
use kin_parser::{LanguageAdapter, PythonAdapter};
use kin_review::{
    analyze_impact, collect_inline_comments, derive_shadow_policy, EntityChange, EntityChangeKind,
    InlineCommentKind, Review, SemanticDiff, ShadowGateVerdict,
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

/// Parse `source` and link it into a fresh persisted graph, exactly as ingest
/// does — each `Calls` edge carries its call-site argument shape. Returns the
/// parsed files (for entity lookup), the linked relations, and the graph store.
fn link_into_graph(source: &str) -> (Vec<FileParseData>, Vec<kin_model::Relation>, InMemoryGraph) {
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
    (files, relations, graph)
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
/// exact production seam — and returns the gate verdict.
fn link_and_shadow_verdict(source: &str, old_sig: &str, new_sig: &str) -> ShadowGateVerdict {
    let (files, _relations, graph) = link_into_graph(source);
    let diff = rename_diff(&files, old_sig, new_sig);
    let report = analyze_impact(&graph, &diff).expect("analyze impact");
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

/// Build old and new entities from their real source declarations, rather than
/// overwriting a parsed entity's signature with hand-authored strings. This
/// covers the production declaration canonicalizer as well as parse, link,
/// persist, impact, inline, and shadow policy.
fn link_and_shadow_verdict_from_sources(
    old_source: &str,
    new_source: &str,
) -> (ShadowGateVerdict, String, String) {
    let (old_files, _relations, graph) = link_into_graph(old_source);
    let new_files = vec![parse_python("mod.py", new_source)];
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
    let report = analyze_impact(&graph, &diff).expect("analyze impact");
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
    (
        derive_shadow_policy(&review, &[], &[]).verdict,
        old_signature,
        new_signature,
    )
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
