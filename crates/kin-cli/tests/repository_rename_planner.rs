// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Adversarial evidence for repository-v6 rename planning.
//!
//! Production relation evidence currently carries occurrence counts but no
//! source spans. These tests prove the bounded replacement contract: Kin uses
//! the graph-owned source entity span plus the relation occurrence count to
//! account for exact identifier sites in repository CAS, and refuses any case
//! where one-to-one accounting cannot be established.

use std::collections::{BTreeSet, HashMap};

use kin_cli::commands::rename::{plan_rename, RenamePlan, RenameRequest};
use kin_db::InMemoryGraph;
use kin_index::linker::ArtifactIdentityMap;
use kin_model::{
    ArtifactId, AuthorId, Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore,
    FileLayout, FilePathId, FingerprintAlgorithm, GraphNodeId, Hash256, ImportSection, LanguageId,
    LocatedEntry, OperationId, ParseCompleteness, Relation, RelationEvidence, RelationId,
    RelationKind, RelationOrigin, RepoPath, SemanticFingerprint, SourceSpan, TransactionDelta,
    TreeDelta, TreeEntry, Visibility,
};

struct PlannerHarness {
    graph: InMemoryGraph,
    bodies: HashMap<String, Vec<u8>>,
}

impl PlannerHarness {
    fn new() -> Self {
        Self {
            graph: InMemoryGraph::new(),
            bodies: HashMap::new(),
        }
    }

    fn add_tree_blob(&mut self, path: &str, body: &str) -> ArtifactId {
        let artifact_id = ArtifactId::new();
        let digest = kin_blobs::digest(body.as_bytes());
        self.graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: LocatedEntry::new(
                        RepoPath::from_utf8(path).unwrap(),
                        TreeEntry::blob(Hash256::from_bytes(digest.0), false),
                    ),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        self.bodies
            .insert(path.to_string(), body.as_bytes().to_vec());
        artifact_id
    }

    /// Returns the artifact this file was admitted as, so a test that needs
    /// to name it in a relation uses the admitted identity rather than
    /// minting a fresh one the tree does not carry.
    fn add_file(&mut self, path: &str, body: &str, completeness: ParseCompleteness) -> ArtifactId {
        let artifact_id = self.add_tree_blob(path, body);
        let parser_rule = if completeness == ParseCompleteness::Full {
            kin_index::CALL_SHAPE_PARSE_COVERAGE_FULL_V1
        } else {
            kin_index::CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1
        };
        self.graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::DependsOn,
                src: GraphNodeId::Artifact(artifact_id),
                dst: GraphNodeId::Artifact(artifact_id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: vec![RelationEvidence {
                    parser_rule: Some(parser_rule.to_string()),
                    source_path: Some(path.to_string()),
                    occurrence_count: 1,
                    ..RelationEvidence::default()
                }],
            })
            .unwrap();
        self.graph
            .upsert_file_layout(&FileLayout {
                file_id: FilePathId::new(path),
                parse_completeness: completeness,
                imports: ImportSection {
                    byte_range: 0..0,
                    items: Vec::new(),
                },
                regions: Vec::new(),
            })
            .unwrap();
        artifact_id
    }

    fn add_entity(&self, name: &str, path: &str, start_byte: usize, end_byte: usize) -> Entity {
        let entity = test_entity(name, path, start_byte, end_byte);
        self.graph.upsert_entity(&entity).unwrap();
        entity
    }

    fn add_entity_at(
        &self,
        name: &str,
        path: &str,
        start_byte: usize,
        end_byte: usize,
        start_line: u32,
        end_line: u32,
        language: LanguageId,
    ) -> Entity {
        let mut entity = test_entity(name, path, start_byte, end_byte);
        entity.language = language;
        entity.span = Some(SourceSpan {
            file: FilePathId::new(path),
            start_byte,
            end_byte,
            start_line,
            start_col: 0,
            end_line,
            end_col: u32::try_from(end_byte.saturating_sub(start_byte)).unwrap(),
        });
        self.graph.upsert_entity(&entity).unwrap();
        entity
    }

    fn add_reference(&self, source: &Entity, target: &Entity, occurrence_count: u32) -> RelationId {
        let relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(source.id),
            dst: GraphNodeId::Entity(target.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![RelationEvidence {
                occurrence_count,
                source_span: None,
                ..RelationEvidence::default()
            }],
        };
        let id = relation.id;
        self.graph.upsert_relation(&relation).unwrap();
        id
    }

    fn plan(&self, symbol: &str, new_name: &str, file: &str) -> anyhow::Result<RenamePlan> {
        plan_rename(
            &self.graph,
            &request(symbol, new_name, Some(file)),
            |path, _hash| {
                let path = path.as_utf8().expect("fixture paths are UTF-8");
                self.bodies
                    .get(path)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("missing fixture body {path}"))
            },
        )
    }
}

fn request(symbol: &str, new_name: &str, file: Option<&str>) -> RenameRequest {
    RenameRequest {
        symbol: symbol.to_string(),
        new_name: new_name.to_string(),
        file: file.map(ToString::to_string),
        line: None,
        column: None,
        json: true,
        operation_id: OperationId::new(),
        actor: AuthorId::new("rename-planner-test"),
    }
}

fn test_entity(name: &str, path: &str, start_byte: usize, end_byte: usize) -> Entity {
    Entity {
        id: EntityId::new(),
        kind: EntityKind::Function,
        name: name.to_string(),
        language: LanguageId::Rust,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0x11; 32]),
            signature_hash: Hash256::from_bytes([0x22; 32]),
            behavior_hash: Hash256::from_bytes([0x33; 32]),
            equivalence_hash: Hash256::from_bytes([0x44; 32]),
            stability_score: 1.0,
        },
        file_origin: Some(FilePathId::new(path)),
        span: Some(SourceSpan {
            file: FilePathId::new(path),
            start_byte,
            end_byte,
            start_line: 0,
            start_col: u32::try_from(start_byte).unwrap(),
            end_line: 0,
            end_col: u32::try_from(end_byte).unwrap(),
        }),
        signature: format!("fn {name}()"),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

#[test]
fn occurrence_count_without_relation_spans_accounts_for_every_site() {
    let mut harness = PlannerHarness::new();
    let target_body = "pub fn target() {}\n";
    let caller_body = "pub fn caller() { target(); target(); }\n";
    harness.add_file("src/target.rs", target_body, ParseCompleteness::Full);
    harness.add_file("src/caller.rs", caller_body, ParseCompleteness::Full);
    let target = harness.add_entity("target", "src/target.rs", 0, target_body.len());
    let caller = harness.add_entity("caller", "src/caller.rs", 0, caller_body.len());
    let relation_id = harness.add_reference(&caller, &target, 2);

    let plan = harness.plan("target", "renamed", "src/target.rs").unwrap();
    assert_eq!(plan.edits.len(), 3);
    assert_eq!(plan.relation_ids, vec![relation_id]);
    assert_eq!(
        plan.edits
            .iter()
            .map(|edit| edit.file.0.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["src/caller.rs", "src/target.rs"])
    );
}

#[test]
fn occurrence_count_mismatch_refuses_instead_of_skipping_or_guessing() {
    let mut harness = PlannerHarness::new();
    let target_body = "pub fn target() {}\n";
    let caller_body = "pub fn caller() { target(); target(); }\n";
    harness.add_file("src/target.rs", target_body, ParseCompleteness::Full);
    harness.add_file("src/caller.rs", caller_body, ParseCompleteness::Full);
    let target = harness.add_entity("target", "src/target.rs", 0, target_body.len());
    let caller = harness.add_entity("caller", "src/caller.rs", 0, caller_body.len());
    harness.add_reference(&caller, &target, 3);

    let error = harness
        .plan("target", "renamed", "src/target.rs")
        .unwrap_err();
    assert!(error.to_string().contains("require 3 'target' occurrence"));
}

#[test]
fn overlapping_entity_spans_cannot_double_claim_one_occurrence() {
    let mut harness = PlannerHarness::new();
    let target_body = "pub fn target() {}\n";
    let caller_body = "pub fn outer() { target(); }\n";
    harness.add_file("src/target.rs", target_body, ParseCompleteness::Full);
    harness.add_file("src/caller.rs", caller_body, ParseCompleteness::Full);
    let target = harness.add_entity("target", "src/target.rs", 0, target_body.len());
    let outer = harness.add_entity("outer", "src/caller.rs", 0, caller_body.len());
    let token_start = caller_body.find("target").unwrap();
    let nested = harness.add_entity(
        "nested",
        "src/caller.rs",
        token_start,
        token_start + "target".len(),
    );
    harness.add_reference(&outer, &target, 1);
    harness.add_reference(&nested, &target, 1);

    let error = harness
        .plan("target", "renamed", "src/target.rs")
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("overlapping graph source entities"));
}

#[test]
fn same_spelling_different_target_only_follows_the_selected_identity() {
    let mut harness = PlannerHarness::new();
    let declaration = "pub fn target() {}\n";
    let caller_a_body = "pub fn caller_a() { target(); }\n";
    let caller_b_body = "pub fn caller_b() { target(); }\n";
    for (path, body) in [
        ("src/a.rs", declaration),
        ("src/b.rs", declaration),
        ("src/caller_a.rs", caller_a_body),
        ("src/caller_b.rs", caller_b_body),
    ] {
        harness.add_file(path, body, ParseCompleteness::Full);
    }
    let target_a = harness.add_entity("target", "src/a.rs", 0, declaration.len());
    let target_b = harness.add_entity("target", "src/b.rs", 0, declaration.len());
    let caller_a = harness.add_entity("caller_a", "src/caller_a.rs", 0, caller_a_body.len());
    let caller_b = harness.add_entity("caller_b", "src/caller_b.rs", 0, caller_b_body.len());
    harness.add_reference(&caller_a, &target_a, 1);
    harness.add_reference(&caller_b, &target_b, 1);

    let plan = harness.plan("target", "renamed", "src/a.rs").unwrap();
    let edited = plan
        .edits
        .iter()
        .map(|edit| edit.file.0.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(edited, BTreeSet::from(["src/a.rs", "src/caller_a.rs"]));
    assert!(!edited.contains("src/b.rs"));
    assert!(!edited.contains("src/caller_b.rs"));
}

#[test]
fn same_spelling_shadowing_inside_one_source_entity_refuses_ambiguous_sites() {
    let mut harness = PlannerHarness::new();
    let declaration = "pub fn target() {}\n";
    let caller_body = "pub fn caller() { target(); target(); }\n";
    harness.add_file("src/a.rs", declaration, ParseCompleteness::Full);
    harness.add_file("src/b.rs", declaration, ParseCompleteness::Full);
    harness.add_file("src/caller.rs", caller_body, ParseCompleteness::Full);
    let target_a = harness.add_entity("target", "src/a.rs", 0, declaration.len());
    let target_b = harness.add_entity("target", "src/b.rs", 0, declaration.len());
    let caller = harness.add_entity("caller", "src/caller.rs", 0, caller_body.len());
    harness.add_reference(&caller, &target_a, 1);
    harness.add_reference(&caller, &target_b, 1);

    let error = harness.plan("target", "renamed", "src/a.rs").unwrap_err();
    assert!(
        error.to_string().contains("require 1 'target' occurrence"),
        "same-spelling shadow sites must not be guessed: {error:#}"
    );
}

#[test]
fn cross_file_new_name_collision_refuses_unproven_namespaces() {
    let mut harness = PlannerHarness::new();
    let target_body = "pub fn target() {}\n";
    let collision_body = "pub fn renamed() {}\n";
    harness.add_file("src/target.rs", target_body, ParseCompleteness::Full);
    harness.add_file("src/collision.rs", collision_body, ParseCompleteness::Full);
    harness.add_entity("target", "src/target.rs", 0, target_body.len());
    harness.add_entity("renamed", "src/collision.rs", 0, collision_body.len());

    let error = harness
        .plan("target", "renamed", "src/target.rs")
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cross-file namespace equivalence is unproven"),
        "collision must fail closed: {error:#}"
    );
}

#[test]
fn one_unsupported_reference_file_refuses_the_whole_plan() {
    let mut harness = PlannerHarness::new();
    let target_body = "pub fn target() {}\n";
    let supported = "pub fn supported() { target(); }\n";
    let unsupported = "pub fn unsupported() { target(); }\n";
    harness.add_file("src/target.rs", target_body, ParseCompleteness::Full);
    harness.add_file("src/supported.rs", supported, ParseCompleteness::Full);
    harness.add_file(
        "src/unsupported.rs",
        unsupported,
        ParseCompleteness::Partial("fixture parser gap".to_string()),
    );
    let target = harness.add_entity("target", "src/target.rs", 0, target_body.len());
    let supported_entity = harness.add_entity("supported", "src/supported.rs", 0, supported.len());
    let unsupported_entity =
        harness.add_entity("unsupported", "src/unsupported.rs", 0, unsupported.len());
    harness.add_reference(&supported_entity, &target, 1);
    harness.add_reference(&unsupported_entity, &target, 1);

    let error = harness
        .plan("target", "renamed", "src/target.rs")
        .unwrap_err();
    assert!(error.to_string().contains("partial parse coverage"));
}

#[test]
fn graph_tree_source_without_a_layout_refuses_repository_wide_coverage() {
    let mut harness = PlannerHarness::new();
    let target_body = "pub fn target() {}\n";
    let caller_body = "pub fn caller() { target(); }\n";
    harness.add_file("src/target.rs", target_body, ParseCompleteness::Full);
    harness.add_file("src/caller.rs", caller_body, ParseCompleteness::Full);
    harness.add_tree_blob("src/uncovered.rs", "use crate::target;\n");
    let target = harness.add_entity("target", "src/target.rs", 0, target_body.len());
    let caller = harness.add_entity("caller", "src/caller.rs", 0, caller_body.len());
    harness.add_reference(&caller, &target, 1);

    let error = harness
        .plan("target", "renamed", "src/target.rs")
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("src/uncovered.rs has no graph-owned file layout"),
        "uncovered source must fail closed: {error:#}"
    );
}

#[test]
fn one_based_line_cursor_selects_graph_row_zero_not_the_adjacent_identity() {
    let mut harness = PlannerHarness::new();
    let body = "fn target() {}\nfn target() {}\n";
    harness.add_file("src/two.rs", body, ParseCompleteness::Full);
    let split = body.find('\n').unwrap() + 1;
    let first = harness.add_entity_at("target", "src/two.rs", 0, split - 1, 0, 0, LanguageId::Rust);
    harness.add_entity_at(
        "target",
        "src/two.rs",
        split,
        body.len() - 1,
        1,
        1,
        LanguageId::Rust,
    );

    let mut cursor = request("target", "renamed", Some("src/two.rs"));
    cursor.line = Some(1);
    let plan = plan_rename(&harness.graph, &cursor, |path, _| {
        Ok(harness.bodies[path.as_utf8().unwrap()].clone())
    })
    .unwrap();
    assert_eq!(plan.entity_id, first.id);
    assert_eq!(plan.edits.len(), 1);
    assert_eq!(plan.edits[0].start_line, 1);
}

#[test]
fn reference_cursor_beats_an_unrelated_same_named_declaration_in_the_file() {
    let mut harness = PlannerHarness::new();
    let remote_body = "fn target() {}\n";
    let caller_body = "fn target() {}\nfn caller() { target(); }\n";
    harness.add_file("src/remote.rs", remote_body, ParseCompleteness::Full);
    harness.add_file("src/caller.rs", caller_body, ParseCompleteness::Full);
    let remote = harness.add_entity_at(
        "target",
        "src/remote.rs",
        0,
        remote_body.len(),
        0,
        0,
        LanguageId::Rust,
    );
    let split = caller_body.find('\n').unwrap() + 1;
    harness.add_entity_at(
        "target",
        "src/caller.rs",
        0,
        split - 1,
        0,
        0,
        LanguageId::Rust,
    );
    let caller = harness.add_entity_at(
        "caller",
        "src/caller.rs",
        split,
        caller_body.len(),
        1,
        1,
        LanguageId::Rust,
    );
    harness.add_reference(&caller, &remote, 1);
    let mut cursor = request("target", "renamed", Some("src/caller.rs"));
    cursor.line = Some(2);

    let plan = plan_rename(&harness.graph, &cursor, |path, _| {
        Ok(harness.bodies[path.as_utf8().unwrap()].clone())
    })
    .unwrap();
    assert_eq!(plan.entity_id, remote.id);
    assert_eq!(
        plan.edits
            .iter()
            .map(|edit| edit.file.0.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["src/caller.rs", "src/remote.rs"])
    );
}

#[test]
fn extraction_incomplete_certificate_refuses_a_syntax_full_partial_refactor() {
    let mut harness = PlannerHarness::new();
    let target_body = "def target():\n    return 1\n";
    let caller_body =
        "def other():\n    return 2\n\ndef caller(flag):\n    return (target if flag else other)()\n";
    let target_artifact = harness.add_file("target.py", target_body, ParseCompleteness::Full);
    let caller_artifact = harness.add_file("caller.py", caller_body, ParseCompleteness::Full);
    harness.add_entity_at(
        "target",
        "target.py",
        0,
        target_body.len(),
        0,
        1,
        LanguageId::Python,
    );
    harness
        .graph
        .upsert_relation(&Relation {
            id: RelationId::new(),
            kind: RelationKind::DependsOn,
            // The certificate is about caller.py depending on target.py, so
            // it names the artifacts the harness actually admitted. Minting
            // fresh ids here described a dependency between two files the
            // repository does not contain.
            src: GraphNodeId::Artifact(caller_artifact),
            dst: GraphNodeId::Artifact(target_artifact),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![RelationEvidence {
                parser_rule: Some(
                    kin_index::CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1.to_string(),
                ),
                source_path: Some("caller.py".to_string()),
                occurrence_count: 1,
                ..RelationEvidence::default()
            }],
        })
        .unwrap();

    let error = harness.plan("target", "renamed", "target.py").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("extraction-incomplete certificate")
            || error
                .to_string()
                .contains("incomplete named-reference extraction"),
        "syntax-full extraction gaps must fail closed: {error:#}"
    );
}

#[test]
fn unicode_prefix_cannot_turn_a_spanless_edge_into_an_ascii_substring_edit() {
    let mut harness = PlannerHarness::new();
    let target_body = "def foo():\n    return 1\n";
    let caller_body = "def caller():\n    return éfoo()\n";
    harness.add_file("target.py", target_body, ParseCompleteness::Full);
    harness.add_file("caller.py", caller_body, ParseCompleteness::Full);
    let target = harness.add_entity_at(
        "foo",
        "target.py",
        0,
        target_body.len(),
        0,
        1,
        LanguageId::Python,
    );
    let caller = harness.add_entity_at(
        "caller",
        "caller.py",
        0,
        caller_body.len(),
        0,
        1,
        LanguageId::Python,
    );
    harness.add_reference(&caller, &target, 1);

    let error = harness.plan("foo", "renamed", "target.py").unwrap_err();
    assert!(
        error.to_string().contains("require 1 'foo' occurrence"),
        "Unicode identifier neighbors must not be spliced: {error:#}"
    );
}

struct LanguageFixture {
    name: &'static str,
    target_path: &'static str,
    target_source: &'static str,
    caller_path: &'static str,
    caller_source: &'static str,
    /// This language's fixture imports the target by name.
    ///
    /// It used to be `has_named_import_without_span`, and the refusal it drove
    /// was correct while `FileImport` carried no span. FIR-2690 gave every
    /// adapter one, so a named import is now a renameable SITE rather than a
    /// reason to refuse, and these fixtures assert the edit instead of the
    /// error. The spanless case still has a test: a hand-built graph whose
    /// import evidence names no span, below, which must still refuse.
    has_named_import: bool,
    /// This language emits a MODULE entity for an ordinary source file.
    ///
    /// An entity-level import edge is sourced at the importing file's module
    /// entity. JavaScript and TypeScript emit one only for index files
    /// (FIR-2675), so for them there is no source entity to hang the edge on,
    /// no edge, and therefore no spanned evidence however good the parser's
    /// span is. Their refusal is real and is asserted below rather than hidden,
    /// because a suite that quietly skips the languages it cannot serve reports
    /// coverage it does not have.
    emits_module_entity_per_file: bool,
    /// Whether this language's adapter records a call site, so its `Calls`
    /// evidence carries a `source_span` (FIR-1825). The planner does not read
    /// spans, so its behavior below is the same either way; this keeps the
    /// fixture honest about what the linker actually produced instead of
    /// asserting one blanket answer for every language.
    records_call_sites: bool,
}

fn entity_leaf(name: &str) -> &str {
    name.rsplit(|character| character == '.' || character == ':')
        .find(|part| !part.is_empty())
        .unwrap_or(name)
}

const LANGUAGE_FIXTURES: &[LanguageFixture] = &[
    LanguageFixture {
        name: "Rust",
        target_path: "defs.rs",
        target_source: "pub fn target() -> u32 { 1 }\n",
        caller_path: "caller.rs",
        caller_source: "pub fn caller() -> u32 { target() + target() }\n",
        has_named_import: false,
        emits_module_entity_per_file: true,
        records_call_sites: false,
    },
    LanguageFixture {
        name: "TypeScript",
        target_path: "defs.ts",
        target_source: "export function target(): number { return 1; }\n",
        caller_path: "caller.ts",
        caller_source: "import { target } from './defs';\nexport function caller(): number { return target() + target(); }\n",
        has_named_import: true,
        emits_module_entity_per_file: false,
        records_call_sites: true,
    },
    LanguageFixture {
        name: "JavaScript",
        target_path: "defs.js",
        target_source: "export function target() { return 1; }\n",
        caller_path: "caller.js",
        caller_source: "import { target } from './defs';\nexport function caller() { return target() + target(); }\n",
        has_named_import: true,
        emits_module_entity_per_file: false,
        records_call_sites: true,
    },
    LanguageFixture {
        name: "Python",
        target_path: "defs.py",
        target_source: "def target():\n    return 1\n",
        caller_path: "caller.py",
        caller_source: "from defs import target\n\ndef caller():\n    return target() + target()\n",
        has_named_import: true,
        emits_module_entity_per_file: true,
        records_call_sites: true,
    },
    LanguageFixture {
        name: "Go",
        target_path: "defs.go",
        target_source: "package main\n\nfunc target() int { return 1 }\n",
        caller_path: "caller.go",
        caller_source: "package main\n\nfunc caller() int { return target() + target() }\n",
        has_named_import: false,
        emits_module_entity_per_file: true,
        records_call_sites: false,
    },
    LanguageFixture {
        name: "Java",
        target_path: "Defs.java",
        target_source: "class Defs { static int target() { return 1; } }\n",
        caller_path: "Caller.java",
        caller_source: "class Caller { int caller() { return target() + target(); } }\n",
        has_named_import: false,
        emits_module_entity_per_file: true,
        records_call_sites: false,
    },
    LanguageFixture {
        name: "C",
        target_path: "defs.c",
        target_source: "int target(void) { return 1; }\n",
        caller_path: "caller.c",
        caller_source: "int caller(void) { return target() + target(); }\n",
        has_named_import: false,
        emits_module_entity_per_file: true,
        records_call_sites: false,
    },
    LanguageFixture {
        name: "Cpp",
        target_path: "defs.cpp",
        target_source: "int target() { return 1; }\n",
        caller_path: "caller.cpp",
        caller_source: "int caller() { return target() + target(); }\n",
        has_named_import: false,
        emits_module_entity_per_file: true,
        records_call_sites: false,
    },
];

#[test]
fn real_linker_spanless_relations_are_exact_or_refused_across_eight_languages() {
    for fixture in LANGUAGE_FIXTURES {
        let pipeline = kin_index::IndexPipeline::new();
        let graph = InMemoryGraph::new();
        let mut bodies = HashMap::new();
        let mut parse_data = Vec::new();
        let mut artifact_ids = ArtifactIdentityMap::new();
        let mut indexed_files = Vec::new();

        for (path, source) in [
            (fixture.target_path, fixture.target_source),
            (fixture.caller_path, fixture.caller_source),
        ] {
            let digest = kin_blobs::digest(source.as_bytes());
            let indexed = pipeline
                .index_file_content_with_tests(&FilePathId::new(path), source.as_bytes(), digest)
                .unwrap_or_else(|error| panic!("{} index {path}: {error}", fixture.name))
                .indexed_file;
            let artifact_id = ArtifactId::new();
            graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![TreeDelta::Added {
                        artifact_id,
                        new: LocatedEntry::new(
                            RepoPath::from_utf8(path).unwrap(),
                            TreeEntry::blob(Hash256::from_bytes(digest.0), false),
                        ),
                    }],
                    ..TransactionDelta::default()
                })
                .unwrap();
            graph.upsert_file_layout(&indexed.file_layout).unwrap();
            for entity in &indexed.entities {
                graph.upsert_entity(entity).unwrap();
            }
            artifact_ids.insert(path.to_string(), artifact_id);
            bodies.insert(path.to_string(), source.as_bytes().to_vec());
            parse_data.push(kin_index::FileParseData {
                file_path: path.to_string(),
                entities: indexed.entities.clone(),
                relations: indexed.extracted_relations.clone(),
                imports: indexed.imports.clone(),
            });
            indexed_files.push(indexed);
        }

        let completeness = indexed_files
            .iter()
            .map(|indexed| {
                (
                    indexed.file_id.0.clone(),
                    indexed.file_layout.parse_completeness.clone(),
                )
            })
            .collect::<kin_index::FileParseCompletenessMap>();
        let linked =
            kin_index::link_cross_file_with_completeness(&parse_data, &artifact_ids, &completeness)
                .unwrap_or_else(|error| panic!("{} link: {error}", fixture.name));
        for relation in &linked {
            graph.upsert_relation(relation).unwrap();
        }
        let target = indexed_files[0]
            .entities
            .iter()
            .find(|entity| entity_leaf(&entity.name) == "target")
            .unwrap_or_else(|| {
                panic!(
                    "{} target entity; found {:?}",
                    fixture.name,
                    indexed_files[0]
                        .entities
                        .iter()
                        .map(|entity| (&entity.name, entity.kind))
                        .collect::<Vec<_>>()
                )
            });
        let caller = indexed_files[1]
            .entities
            .iter()
            .find(|entity| entity_leaf(&entity.name) == "caller")
            .unwrap_or_else(|| panic!("{} caller entity", fixture.name));
        let call = linked
            .iter()
            .find(|relation| {
                relation.kind == RelationKind::Calls
                    && relation.src == GraphNodeId::Entity(caller.id)
                    && relation.dst == GraphNodeId::Entity(target.id)
            })
            .unwrap_or_else(|| panic!("{} repeated call edge", fixture.name));
        let spanned = call
            .evidence
            .iter()
            .filter(|evidence| evidence.source_span.is_some())
            .count();
        if fixture.records_call_sites {
            assert_eq!(
                spanned, 2,
                "{} records call sites, so both of its occurrences must carry one; a \
                 reference row for this language reports them as its site lines",
                fixture.name
            );
        } else {
            assert_eq!(
                spanned, 0,
                "{} unexpectedly gained a relation span; update the bounded planner proof",
                fixture.name
            );
        }
        assert_eq!(
            call.evidence
                .iter()
                .map(|evidence| evidence.occurrence_count)
                .sum::<u32>(),
            2,
            "{} must retain both sites through occurrence_count",
            fixture.name
        );

        let result = plan_rename(
            &graph,
            &request("target", "renamed", Some(fixture.target_path)),
            |path, _hash| {
                let path = path.as_utf8().unwrap();
                Ok(bodies.get(path).unwrap().clone())
            },
        );
        if fixture.has_named_import && !fixture.emits_module_entity_per_file {
            // FIR-2675, not FIR-2690. The parser records this language's import
            // span correctly; there is simply no module entity to source the
            // edge at, so no entity-level import edge exists and no evidence
            // carries the span. The refusal is right and stays asserted, so
            // this suite says out loud which languages the import fix does not
            // reach yet.
            let error = result.unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("graph import evidence has no exact source span"),
                "{} has no per-file module entity, so its import edge cannot exist yet: {error:#}",
                fixture.name
            );
        } else if fixture.has_named_import {
            // FIR-2690. This branch asserted the refusal until every adapter
            // recorded an import span. It now asserts the thing the refusal was
            // standing in for: the import statement is edited like any other
            // reference site.
            let plan = result.unwrap_or_else(|error| {
                panic!(
                    "{} imports the target by name and every adapter now records the site, so \
                     the rename must reach it: {error:#}",
                    fixture.name
                )
            });
            let import_edits: Vec<&_> = plan
                .edits
                .iter()
                .filter(|edit| edit.reason.contains("imports"))
                .collect();
            assert_eq!(
                import_edits.len(),
                1,
                "{} must edit its import site exactly once, got {:?}",
                fixture.name,
                plan.edits
            );
            // The count is the assertion that matters. Three edits is what this
            // fixture produced while the import site was unreachable, so a plan
            // that still holds three is one where the span changed nothing.
            assert_eq!(
                plan.edits.len(),
                4,
                "{} expects the declaration, two call sites and the import site",
                fixture.name
            );
        } else if target.name != "target" {
            let error = result.unwrap_err();
            assert!(
                error.to_string().contains("cannot be proven")
                    || error
                        .to_string()
                        .contains("not found in repository-v6 graph authority")
                    || error.to_string().contains("is not declared in graph file"),
                "{} must fail closed for its qualified declaration name: {error:#}",
                fixture.name
            );
        } else {
            let plan = result.unwrap_or_else(|error| {
                panic!(
                    "{} exact spanless plan should succeed: {error:#}",
                    fixture.name
                )
            });
            assert_eq!(plan.edits.len(), 3, "{} exact edit count", fixture.name);
        }
    }
}

// ---------------------------------------------------------------------------
// Import evidence has no source span, so the planner refuses. FIR-2690.
//
// `plan_rename` calls `require_repository_reference_coverage` at :184, ahead of
// the grouping loop at :192, and that function refuses at :472 whenever a
// reparse of the importing file names the target among its import specifiers.
// `FileImport` carries no span (`kin-parser/src/extract.rs:318`), so the
// evidence has nothing to offer and the guard fails closed rather than editing
// a site it cannot locate.
//
// These pin the CURRENT refusal. Each is written to fail the day FIR-2690 lands
// and the span exists, which is the signal to convert it to a positive
// assertion rather than delete it. That is the same pattern the JavaScript
// module-entity limitation uses in `entity_level_import_edges.rs`.
//
// They are not `#[ignore]`d on purpose: an ignored test is a test nobody runs.
// ---------------------------------------------------------------------------

const IMPORT_SPAN_REFUSAL: &str = "graph import evidence has no exact source span";

/// The shape kin#1123's entity-level import edges produce: a module entity
/// sourcing an `Imports` edge into a symbol another file defines.
#[test]
fn a_module_sourced_import_edge_still_refuses_for_want_of_a_span() {
    let mut harness = PlannerHarness::new();
    let importer_body = "from .parsing import parse_note\n\n\ndef build():\n    return parse_note(1)\n\n\ndef again():\n    return parse_note(2)\n";
    let target_body = "def parse_note(x):\n    return x\n";
    harness.add_file("app/parsing.py", target_body, ParseCompleteness::Full);
    harness.add_file("app/main.py", importer_body, ParseCompleteness::Full);

    let target = harness.add_entity_at(
        "parse_note",
        "app/parsing.py",
        0,
        target_body.len(),
        0,
        1,
        LanguageId::Python,
    );
    // A Python module entity's span is the whole file, which is what
    // `python.rs` emits for every Python source file.
    let module = harness.add_entity_at(
        "main",
        "app/main.py",
        0,
        importer_body.len(),
        0,
        8,
        LanguageId::Python,
    );
    harness
        .graph
        .upsert_relation(&Relation {
            id: RelationId::new(),
            kind: RelationKind::Imports,
            src: GraphNodeId::Entity(module.id),
            dst: GraphNodeId::Entity(target.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: Some(".parsing".to_string()),
            evidence: vec![RelationEvidence {
                token: Some("parse_note".to_string()),
                source_path: Some(".parsing".to_string()),
                resolved_path: Some("app/parsing.py".to_string()),
                parser_rule: Some("import_specifier_binding".to_string()),
                occurrence_count: 1,
                source_span: None,
                ..RelationEvidence::default()
            }],
        })
        .unwrap();

    let err = harness
        .plan("parse_note", "mask_code_spans", "app/parsing.py")
        .expect_err(
            "the planner must refuse while import evidence carries no span; if this now \
             SUCCEEDS, FIR-2690 has landed and this test should assert the edits instead",
        );
    assert!(
        err.to_string().contains(IMPORT_SPAN_REFUSAL),
        "expected the FIR-2690 import-span refusal, got: {err}"
    );
}

/// CONTROL, and the reason it exists is worth more than the assertion.
///
/// The same fixture with NO import edge in the graph at all refuses identically.
/// That is what proves the refusal is a property of the planner meeting an
/// imported symbol, and NOT of the entity-level import edges kin#1123 adds. A
/// diagnosis attributing it to those edges was written and verified twice before
/// this control was run.
///
/// Keep it. The day someone reads the refusal beside the new edges and blames
/// them again, this test answers in one run.
#[test]
fn the_import_span_refusal_is_not_caused_by_entity_level_import_edges() {
    let mut harness = PlannerHarness::new();
    let importer_body = "from .parsing import parse_note\n\n\ndef build():\n    return parse_note(1)\n\n\ndef again():\n    return parse_note(2)\n";
    let target_body = "def parse_note(x):\n    return x\n";
    harness.add_file("app/parsing.py", target_body, ParseCompleteness::Full);
    harness.add_file("app/main.py", importer_body, ParseCompleteness::Full);

    harness.add_entity_at(
        "parse_note",
        "app/parsing.py",
        0,
        target_body.len(),
        0,
        1,
        LanguageId::Python,
    );
    harness.add_entity_at(
        "main",
        "app/main.py",
        0,
        importer_body.len(),
        0,
        8,
        LanguageId::Python,
    );
    // Deliberately no Imports relation of any kind.

    let err = harness
        .plan("parse_note", "mask_code_spans", "app/parsing.py")
        .expect_err("the planner refuses an imported symbol with no import edge present");
    assert!(
        err.to_string().contains(IMPORT_SPAN_REFUSAL),
        "the refusal must be the import-span one, proving it is independent of any import \
         edge, got: {err}"
    );
}
