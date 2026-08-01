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

    fn add_tree_blob(&mut self, path: &str, body: &str) {
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
    }

    fn add_file(&mut self, path: &str, body: &str, completeness: ParseCompleteness) {
        self.add_tree_blob(path, body);
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
    }

    fn add_entity(&self, name: &str, path: &str, start_byte: usize, end_byte: usize) -> Entity {
        let entity = test_entity(name, path, start_byte, end_byte);
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
        line: Some(1),
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
            start_line: 1,
            start_col: u32::try_from(start_byte).unwrap(),
            end_line: 1,
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

struct LanguageFixture {
    name: &'static str,
    target_path: &'static str,
    target_source: &'static str,
    caller_path: &'static str,
    caller_source: &'static str,
    has_named_import_without_span: bool,
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
        has_named_import_without_span: false,
    },
    LanguageFixture {
        name: "TypeScript",
        target_path: "defs.ts",
        target_source: "export function target(): number { return 1; }\n",
        caller_path: "caller.ts",
        caller_source: "import { target } from './defs';\nexport function caller(): number { return target() + target(); }\n",
        has_named_import_without_span: true,
    },
    LanguageFixture {
        name: "JavaScript",
        target_path: "defs.js",
        target_source: "export function target() { return 1; }\n",
        caller_path: "caller.js",
        caller_source: "import { target } from './defs';\nexport function caller() { return target() + target(); }\n",
        has_named_import_without_span: true,
    },
    LanguageFixture {
        name: "Python",
        target_path: "defs.py",
        target_source: "def target():\n    return 1\n",
        caller_path: "caller.py",
        caller_source: "from defs import target\n\ndef caller():\n    return target() + target()\n",
        has_named_import_without_span: true,
    },
    LanguageFixture {
        name: "Go",
        target_path: "defs.go",
        target_source: "package main\n\nfunc target() int { return 1 }\n",
        caller_path: "caller.go",
        caller_source: "package main\n\nfunc caller() int { return target() + target() }\n",
        has_named_import_without_span: false,
    },
    LanguageFixture {
        name: "Java",
        target_path: "Defs.java",
        target_source: "class Defs { static int target() { return 1; } }\n",
        caller_path: "Caller.java",
        caller_source: "class Caller { int caller() { return target() + target(); } }\n",
        has_named_import_without_span: false,
    },
    LanguageFixture {
        name: "C",
        target_path: "defs.c",
        target_source: "int target(void) { return 1; }\n",
        caller_path: "caller.c",
        caller_source: "int caller(void) { return target() + target(); }\n",
        has_named_import_without_span: false,
    },
    LanguageFixture {
        name: "Cpp",
        target_path: "defs.cpp",
        target_source: "int target() { return 1; }\n",
        caller_path: "caller.cpp",
        caller_source: "int caller() { return target() + target(); }\n",
        has_named_import_without_span: false,
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

        let linked = pipeline
            .resolve_cross_file(&parse_data, &artifact_ids)
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
        assert!(
            call.evidence
                .iter()
                .all(|evidence| evidence.source_span.is_none()),
            "{} unexpectedly gained a relation span; update the bounded planner proof",
            fixture.name
        );
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
        if fixture.has_named_import_without_span {
            let error = result.unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("graph import evidence has no exact source span"),
                "{} must refuse its unspanned named import: {error:#}",
                fixture.name
            );
        } else if target.name != "target" {
            let error = result.unwrap_err();
            assert!(
                error.to_string().contains("cannot be proven")
                    || error
                        .to_string()
                        .contains("not found in repository-v6 graph authority"),
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
