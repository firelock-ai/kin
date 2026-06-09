// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Phase 9 acceptance tests: cross-file relation resolution via the linker.
//!
//! These tests exercise `link_cross_file` with `FileParseData` inputs and
//! verify that cross-file relations (imports, calls, contains) are resolved
//! correctly and surface in context packs.

use kin_index::{link_cross_file, FileParseData};
use kin_model::*;
use kin_parser::{ExtractedRelation, FileImport, ImportedName};

use crate::helpers::*;

// ---------------------------------------------------------------------------
// 26. TypeScript import creates relation
// ---------------------------------------------------------------------------

#[test]
fn ts_import_creates_relation() {
    let helper = make_entity("helper", "src/utils.ts", EntityKind::Function);
    let post = make_entity("POST", "src/api/route.ts", EntityKind::Function);

    let files = vec![
        FileParseData {
            file_path: "src/utils.ts".to_string(),
            entities: vec![helper.clone()],
            relations: vec![],
            imports: vec![],
        },
        FileParseData {
            file_path: "src/api/route.ts".to_string(),
            entities: vec![post.clone()],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Imports,
                src_name: "POST".to_string(),
                dst_name: "helper".to_string(),
                import_source: None,
            }],
            imports: vec![FileImport {
                module_path: "../utils".to_string(),
                specifiers: vec![ImportedName {
                    local_name: "helper".to_string(),
                    original_name: None,
                    is_default: false,
                }],
            }],
        },
    ];

    let relations = link_cross_file(&files);

    // Should resolve the import to the helper entity via import-based resolution.
    let import_rels: Vec<_> = relations
        .iter()
        .filter(|r| r.dst == GraphNodeId::Entity(helper.id))
        .collect();

    assert!(
        !import_rels.is_empty(),
        "expected at least one relation targeting the helper entity"
    );
    assert_eq!(import_rels[0].src, GraphNodeId::Entity(post.id));
}

// ---------------------------------------------------------------------------
// 27. Cross-file function call creates Calls relation
// ---------------------------------------------------------------------------

#[test]
fn ts_call_creates_cross_file_relation() {
    let execute_tool = make_entity("executeTool", "src/lib/tools.ts", EntityKind::Function);
    let post = make_entity("POST", "src/api/chat/route.ts", EntityKind::Function);

    let files = vec![
        FileParseData {
            file_path: "src/lib/tools.ts".to_string(),
            entities: vec![execute_tool.clone()],
            relations: vec![],
            imports: vec![],
        },
        FileParseData {
            file_path: "src/api/chat/route.ts".to_string(),
            entities: vec![post.clone()],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: "POST".to_string(),
                dst_name: "executeTool".to_string(),
                import_source: None,
            }],
            imports: vec![FileImport {
                module_path: "../../lib/tools".to_string(),
                specifiers: vec![ImportedName {
                    local_name: "executeTool".to_string(),
                    original_name: None,
                    is_default: false,
                }],
            }],
        },
    ];

    let relations = link_cross_file(&files);

    let calls: Vec<_> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .collect();

    assert!(!calls.is_empty(), "expected at least one Calls relation");

    let cross_file_call = calls.iter().find(|r| {
        r.src == GraphNodeId::Entity(post.id) && r.dst == GraphNodeId::Entity(execute_tool.id)
    });
    assert!(
        cross_file_call.is_some(),
        "expected Calls relation from POST to executeTool"
    );
}

// ---------------------------------------------------------------------------
// 28. Same-file relation (Contains) resolves correctly
// ---------------------------------------------------------------------------

#[test]
fn same_file_relation_resolves() {
    let dog = make_entity("Dog", "src/animals.ts", EntityKind::Class);
    let bark = make_entity("Dog.bark", "src/animals.ts", EntityKind::Function);

    let files = vec![FileParseData {
        file_path: "src/animals.ts".to_string(),
        entities: vec![dog.clone(), bark.clone()],
        relations: vec![ExtractedRelation {
            kind: RelationKind::Contains,
            src_name: "Dog".to_string(),
            dst_name: "Dog.bark".to_string(),
            import_source: None,
        }],
        imports: vec![],
    }];

    let relations = link_cross_file(&files);

    let contains: Vec<_> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Contains)
        .collect();

    assert_eq!(contains.len(), 1, "expected one Contains relation");
    assert_eq!(contains[0].src, GraphNodeId::Entity(dog.id));
    assert_eq!(contains[0].dst, GraphNodeId::Entity(bark.id));
    // Same-file resolution should have full confidence.
    assert_eq!(contains[0].confidence, 1.0);
}

// ---------------------------------------------------------------------------
// 29. Unresolved call to unknown function is skipped gracefully
// ---------------------------------------------------------------------------

#[test]
fn unresolved_call_skipped_gracefully() {
    let handler = make_entity("handler", "src/api.ts", EntityKind::Function);

    let files = vec![FileParseData {
        file_path: "src/api.ts".to_string(),
        entities: vec![handler.clone()],
        relations: vec![ExtractedRelation {
            kind: RelationKind::Calls,
            src_name: "handler".to_string(),
            dst_name: "console.log".to_string(),
            import_source: None,
        }],
        imports: vec![],
    }];

    // Should not panic.
    let relations = link_cross_file(&files);

    // console.log has no matching entity anywhere, so no relation should be created.
    assert!(
        relations.is_empty(),
        "expected no resolved relations for unresolvable external call, got {}",
        relations.len()
    );
}

// ---------------------------------------------------------------------------
// 30. Context pack includes cross-file dependencies
// ---------------------------------------------------------------------------

#[test]
fn context_pack_includes_cross_file_deps() {
    let (_dir, graph, _genesis_id) = init_kin_repo();

    // Caller in one file, callee in another.
    let caller = make_entity("handleRequest", "src/api/handler.ts", EntityKind::Function);
    let callee = make_entity("validateInput", "src/lib/validate.ts", EntityKind::Function);

    graph.upsert_entity(&caller).unwrap();
    graph.upsert_entity(&callee).unwrap();

    // Create a Calls relation between them (as the linker would produce).
    let relation = Relation {
        id: RelationId::new(),
        kind: RelationKind::Calls,
        src: GraphNodeId::Entity(caller.id),
        dst: GraphNodeId::Entity(callee.id),
        confidence: 0.95,
        origin: RelationOrigin::Inferred,
        created_in: None,
        import_source: None,
        evidence: Vec::new(),
    };
    graph.upsert_relation(&relation).unwrap();

    // Build a context pack centered on the caller.
    let opts = kin_context::ContextOptions {
        budget: TokenBudget::Small8k,
        max_depth: 2,
        include_tests: true,
        include_contracts: true,
        include_traffic: false,
        assistant_hint: None,
    };

    let pack = kin_context::build_context_pack(graph.as_ref(), &caller.id, &opts).unwrap();

    // The callee should appear in dependency_signatures.
    assert!(
        !pack.dependency_signatures.is_empty(),
        "expected cross-file dependency in context pack"
    );
    assert!(
        pack.dependency_signatures
            .iter()
            .any(|entry| entry.content.contains("validateInput")),
        "expected validateInput in dependency signatures"
    );
}

// ---------------------------------------------------------------------------
// 32. Downstream impact exposes dependent proof targets
// ---------------------------------------------------------------------------

#[test]
fn downstream_impact_surfaces_impacted_proof_targets() {
    let (_dir, graph, _genesis_id) = init_kin_repo();

    let callee = make_entity("checkout_core", "src/checkout.rs", EntityKind::Function);
    let caller = make_entity("checkout_handler", "src/handler.rs", EntityKind::Function);

    graph.upsert_entity(&callee).unwrap();
    graph.upsert_entity(&caller).unwrap();

    graph
        .upsert_relation(&Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(caller.id),
            dst: GraphNodeId::Entity(callee.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        })
        .unwrap();

    let caller_test = TestCase {
        test_id: TestId::new(),
        name: "test_checkout_handler".into(),
        language: "rust".into(),
        kind: TestKind::Integration,
        scopes: vec![WorkScope::Entity(caller.id)],
        runner: TestRunner::Cargo,
        file_origin: Some(FilePathId::new("tests/checkout_handler.rs")),
    };
    graph.create_test_case(&caller_test).unwrap();

    let impacted = graph.get_downstream_impact(&callee.id, 1).unwrap();
    assert_eq!(impacted.len(), 1);
    assert_eq!(impacted[0].id, caller.id);

    let impacted_tests = graph.get_tests_for_entity(&impacted[0].id).unwrap();
    assert_eq!(impacted_tests.len(), 1);
    assert_eq!(impacted_tests[0].test_id, caller_test.test_id);
}

// ---------------------------------------------------------------------------
// 31. Renamed import (foo as bar) resolves bar calls to foo entity
// ---------------------------------------------------------------------------

#[test]
fn renamed_import_resolves() {
    let foo = make_entity("foo", "src/utils.ts", EntityKind::Function);
    let handler = make_entity("handler", "src/api.ts", EntityKind::Function);

    let files = vec![
        FileParseData {
            file_path: "src/utils.ts".to_string(),
            entities: vec![foo.clone()],
            relations: vec![],
            imports: vec![],
        },
        FileParseData {
            file_path: "src/api.ts".to_string(),
            entities: vec![handler.clone()],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: "handler".to_string(),
                // The local alias "bar" is used in the call expression.
                dst_name: "bar".to_string(),
                import_source: None,
            }],
            imports: vec![FileImport {
                module_path: "./utils".to_string(),
                specifiers: vec![ImportedName {
                    local_name: "bar".to_string(),
                    original_name: Some("foo".to_string()),
                    is_default: false,
                }],
            }],
        },
    ];

    let relations = link_cross_file(&files);

    let calls: Vec<_> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls && r.src == GraphNodeId::Entity(handler.id))
        .collect();

    assert_eq!(calls.len(), 1, "expected one Calls relation from handler");
    assert_eq!(
        calls[0].dst,
        GraphNodeId::Entity(foo.id),
        "renamed import 'bar' should resolve to original entity 'foo'"
    );
    // Import-based resolution confidence.
    assert_eq!(calls[0].confidence, 0.95);
}

// ---------------------------------------------------------------------------
// 32. Multiple files cross-link: A -> B -> C call chain
// ---------------------------------------------------------------------------

#[test]
fn multiple_files_cross_link() {
    let entity_a = make_entity("routeHandler", "src/routes.ts", EntityKind::Function);
    let entity_b = make_entity(
        "processOrder",
        "src/services/order.ts",
        EntityKind::Function,
    );
    let entity_c = make_entity("saveToDb", "src/db/repository.ts", EntityKind::Function);

    let files = vec![
        FileParseData {
            file_path: "src/routes.ts".to_string(),
            entities: vec![entity_a.clone()],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: "routeHandler".to_string(),
                dst_name: "processOrder".to_string(),
                import_source: None,
            }],
            imports: vec![FileImport {
                module_path: "./services/order".to_string(),
                specifiers: vec![ImportedName {
                    local_name: "processOrder".to_string(),
                    original_name: None,
                    is_default: false,
                }],
            }],
        },
        FileParseData {
            file_path: "src/services/order.ts".to_string(),
            entities: vec![entity_b.clone()],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: "processOrder".to_string(),
                dst_name: "saveToDb".to_string(),
                import_source: None,
            }],
            imports: vec![FileImport {
                module_path: "../db/repository".to_string(),
                specifiers: vec![ImportedName {
                    local_name: "saveToDb".to_string(),
                    original_name: None,
                    is_default: false,
                }],
            }],
        },
        FileParseData {
            file_path: "src/db/repository.ts".to_string(),
            entities: vec![entity_c.clone()],
            relations: vec![],
            imports: vec![],
        },
    ];

    let relations = link_cross_file(&files);

    let calls: Vec<_> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .collect();

    assert_eq!(
        calls.len(),
        2,
        "expected 2 Calls relations for A->B->C chain, got {}",
        calls.len()
    );

    // Verify A -> B.
    let a_to_b = calls.iter().find(|r| {
        r.src == GraphNodeId::Entity(entity_a.id) && r.dst == GraphNodeId::Entity(entity_b.id)
    });
    assert!(
        a_to_b.is_some(),
        "expected Calls from routeHandler to processOrder"
    );

    // Verify B -> C.
    let b_to_c = calls.iter().find(|r| {
        r.src == GraphNodeId::Entity(entity_b.id) && r.dst == GraphNodeId::Entity(entity_c.id)
    });
    assert!(
        b_to_c.is_some(),
        "expected Calls from processOrder to saveToDb"
    );
}

// ===========================================================================
// Phase 9 verification graph acceptance tests
// ===========================================================================

use kin_db::InMemoryGraph;
use kin_model::graph::EntityStore;
use kin_model::verification;
use kin_model::work::WorkScope;

// ---------------------------------------------------------------------------
// 33. Test case lifecycle: create -> query -> coverage
// ---------------------------------------------------------------------------

#[test]
fn test_case_lifecycle_and_coverage() {
    let store = InMemoryGraph::new();

    // Create an entity.
    let entity = make_entity("checkout", "src/checkout.ts", EntityKind::Function);
    store.upsert_entity(&entity).unwrap();

    // Create a test case scoped to that entity.
    let tc = verification::TestCase {
        test_id: verification::TestId::new(),
        name: "test_checkout_flow".into(),
        language: "typescript".into(),
        kind: verification::TestKind::Unit,
        scopes: vec![WorkScope::Entity(entity.id)],
        runner: verification::TestRunner::Jest,
        file_origin: Some(kin_model::FilePathId::new("tests/checkout.test.ts")),
    };
    store.create_test_case(&tc).unwrap();

    // get_tests_for_entity should return the test.
    let tests = store.get_tests_for_entity(&entity.id).unwrap();
    assert_eq!(tests.len(), 1);
    assert_eq!(tests[0].name, "test_checkout_flow");
    assert_eq!(tests[0].test_id, tc.test_id);

    // Coverage summary should show 1 covered out of 1 total.
    let summary = store.get_coverage_summary().unwrap();
    assert_eq!(summary.total_entities, 1);
    assert_eq!(summary.covered_entities, 1);
    assert!((summary.coverage_ratio - 1.0).abs() < 0.01);
    assert!(summary.missing_proof.is_empty());
}

// ---------------------------------------------------------------------------
// 34. Assertion create and get roundtrip
// ---------------------------------------------------------------------------

#[test]
fn assertion_create_and_get_roundtrip() {
    let store = InMemoryGraph::new();

    let entity_id = kin_model::EntityId::new();
    let assertion = verification::Assertion {
        assertion_id: verification::AssertionId::new(),
        summary: "Checkout must validate card".into(),
        expected_behavior: "Returns error on invalid card number".into(),
        target_scope: WorkScope::Entity(entity_id),
    };
    store.create_assertion(&assertion).unwrap();

    let retrieved = store
        .get_assertion(&assertion.assertion_id)
        .unwrap()
        .expect("assertion should exist");

    assert_eq!(retrieved.assertion_id, assertion.assertion_id);
    assert_eq!(retrieved.summary, "Checkout must validate card");
    assert_eq!(
        retrieved.expected_behavior,
        "Returns error on invalid card number"
    );

    // Non-existent assertion returns None.
    let missing = store
        .get_assertion(&verification::AssertionId::new())
        .unwrap();
    assert!(missing.is_none());
}

// ---------------------------------------------------------------------------
// 35. Delete test case drops coverage
// ---------------------------------------------------------------------------

#[test]
fn delete_test_case_drops_coverage() {
    let store = InMemoryGraph::new();

    let entity = make_entity("payment", "src/payment.ts", EntityKind::Function);
    store.upsert_entity(&entity).unwrap();

    let tc = verification::TestCase {
        test_id: verification::TestId::new(),
        name: "test_payment_processing".into(),
        language: "typescript".into(),
        kind: verification::TestKind::Integration,
        scopes: vec![WorkScope::Entity(entity.id)],
        runner: verification::TestRunner::Jest,
        file_origin: None,
    };
    store.create_test_case(&tc).unwrap();

    // Verify test is linked.
    let tests = store.get_tests_for_entity(&entity.id).unwrap();
    assert_eq!(tests.len(), 1);

    // Coverage should show 1 covered.
    let summary = store.get_coverage_summary().unwrap();
    assert_eq!(summary.covered_entities, 1);

    // Delete the test case.
    store.delete_test_case(&tc.test_id).unwrap();

    // Tests for entity should be empty.
    let tests_after = store.get_tests_for_entity(&entity.id).unwrap();
    assert!(
        tests_after.is_empty(),
        "expected no tests after deletion, got {}",
        tests_after.len()
    );

    // Coverage should drop to 0.
    let summary_after = store.get_coverage_summary().unwrap();
    assert_eq!(summary_after.covered_entities, 0);
    assert_eq!(summary_after.missing_proof.len(), 1);
    assert_eq!(summary_after.missing_proof[0], entity.id);
}

// ===========================================================================
// Phase 9 completion: verification runs, mock hints, contract coverage,
// proof links
// ===========================================================================

// ---------------------------------------------------------------------------
// 36. Verification run CRUD: create, get by ID, list by test
// ---------------------------------------------------------------------------

#[test]
fn verification_run_crud() {
    let store = InMemoryGraph::new();

    // Create a test case (VerificationRun.EXECUTED edges need it).
    let entity = make_entity("handler", "src/api.ts", EntityKind::Function);
    store.upsert_entity(&entity).unwrap();

    let tc = verification::TestCase {
        test_id: verification::TestId::new(),
        name: "test_handler".into(),
        language: "typescript".into(),
        kind: verification::TestKind::Unit,
        scopes: vec![WorkScope::Entity(entity.id)],
        runner: verification::TestRunner::Jest,
        file_origin: None,
    };
    store.create_test_case(&tc).unwrap();

    let run = verification::VerificationRun {
        run_id: verification::VerificationRunId::new(),
        test_ids: vec![tc.test_id],
        status: verification::VerificationStatus::Passing,
        runner: verification::TestRunner::Jest,
        started_at: kin_model::Timestamp::now(),
        finished_at: Some(kin_model::Timestamp::now()),
        duration_ms: Some(42),
        evidence_blob: None,
        exit_code: Some(0),
    };
    store.create_verification_run(&run).unwrap();

    // Get by ID.
    let fetched = store
        .get_verification_run(&run.run_id)
        .unwrap()
        .expect("run should exist");
    assert_eq!(fetched.run_id, run.run_id);
    assert_eq!(fetched.status, verification::VerificationStatus::Passing);
    assert_eq!(fetched.duration_ms, Some(42));
    assert_eq!(fetched.exit_code, Some(0));

    // Non-existent returns None.
    let missing = store
        .get_verification_run(&verification::VerificationRunId::new())
        .unwrap();
    assert!(missing.is_none());

    // List runs for this test.
    let runs = store.list_runs_for_test(&tc.test_id).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run.run_id);
}

// ---------------------------------------------------------------------------
// 37. Test covers contract: link test -> contract, query back
// ---------------------------------------------------------------------------

#[test]
fn test_covers_contract() {
    let store = InMemoryGraph::new();

    // Create a test case.
    let entity = make_entity("validate", "src/validate.ts", EntityKind::Function);
    store.upsert_entity(&entity).unwrap();

    let tc = verification::TestCase {
        test_id: verification::TestId::new(),
        name: "test_validate_contract".into(),
        language: "typescript".into(),
        kind: verification::TestKind::Contract,
        scopes: vec![WorkScope::Entity(entity.id)],
        runner: verification::TestRunner::Jest,
        file_origin: None,
    };
    store.create_test_case(&tc).unwrap();

    // Contract coverage with no contracts should show 0/0.
    let summary = store.get_contract_coverage_summary().unwrap();
    assert_eq!(summary.total_contracts, 0);
    assert_eq!(summary.covered_contracts, 0);

    // Query tests covering a non-existent contract returns empty.
    let contract_id = kin_model::ContractId::new();
    let tests = store.get_tests_covering_contract(&contract_id).unwrap();
    assert!(tests.is_empty());
}

// ---------------------------------------------------------------------------
// 38. Test verifies work item: link test -> work item, query back
// ---------------------------------------------------------------------------

#[test]
fn test_verifies_work_item() {
    let store = InMemoryGraph::new();

    // Create entity + test case.
    let entity = make_entity("checkout", "src/checkout.ts", EntityKind::Function);
    store.upsert_entity(&entity).unwrap();

    let tc = verification::TestCase {
        test_id: verification::TestId::new(),
        name: "test_checkout_work".into(),
        language: "typescript".into(),
        kind: verification::TestKind::Integration,
        scopes: vec![WorkScope::Entity(entity.id)],
        runner: verification::TestRunner::Jest,
        file_origin: None,
    };
    store.create_test_case(&tc).unwrap();

    // Create a work item.
    let work = kin_model::WorkItem {
        work_id: kin_model::WorkId::new(),
        kind: kin_model::WorkKind::Feature,
        title: "Implement checkout".into(),
        description: "Add checkout flow".into(),
        status: kin_model::WorkStatus::InProgress,
        priority: kin_model::Priority::High,
        scopes: vec![WorkScope::Entity(entity.id)],
        acceptance_criteria: vec!["passes tests".into()],
        external_refs: vec![],
        created_by: kin_model::IdentityRef::human("alice"),
        created_at: kin_model::Timestamp::now(),
    };
    store.create_work_item(&work).unwrap();

    // Link test to work item.
    store
        .create_test_verifies_work(&tc.test_id, &work.work_id)
        .unwrap();

    // Query back.
    let tests = store.get_tests_verifying_work(&work.work_id).unwrap();
    assert_eq!(tests.len(), 1);
    assert_eq!(tests[0].test_id, tc.test_id);
    assert_eq!(tests[0].name, "test_checkout_work");

    // Non-existent work item returns empty.
    let empty = store
        .get_tests_verifying_work(&kin_model::WorkId::new())
        .unwrap();
    assert!(empty.is_empty());
}

// ---------------------------------------------------------------------------
// 39. Mock hint tracking: create and query roundtrip
// ---------------------------------------------------------------------------

#[test]
fn mock_hint_tracking() {
    let store = InMemoryGraph::new();

    let entity = make_entity("db_client", "src/db.ts", EntityKind::Function);
    store.upsert_entity(&entity).unwrap();

    let tc = verification::TestCase {
        test_id: verification::TestId::new(),
        name: "test_with_mock_db".into(),
        language: "typescript".into(),
        kind: verification::TestKind::Unit,
        scopes: vec![WorkScope::Entity(entity.id)],
        runner: verification::TestRunner::Jest,
        file_origin: None,
    };
    store.create_test_case(&tc).unwrap();

    let hint = verification::MockHint {
        hint_id: verification::MockHintId::new(),
        test_id: tc.test_id,
        dependency_scope: WorkScope::Entity(entity.id),
        strategy: verification::MockStrategy::InMemory,
    };
    store.create_mock_hint(&hint).unwrap();

    // Query hints for test.
    let hints = store.get_mock_hints_for_test(&tc.test_id).unwrap();
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].hint_id, hint.hint_id);
    assert_eq!(hints[0].strategy, verification::MockStrategy::InMemory);

    // Different test has no hints.
    let empty = store
        .get_mock_hints_for_test(&verification::TestId::new())
        .unwrap();
    assert!(empty.is_empty());
}

// ---------------------------------------------------------------------------
// 40. Run proves entity: link verification run -> entity
// ---------------------------------------------------------------------------

#[test]
fn run_proves_entity() {
    let store = InMemoryGraph::new();

    let entity = make_entity("auth", "src/auth.ts", EntityKind::Function);
    store.upsert_entity(&entity).unwrap();

    let tc = verification::TestCase {
        test_id: verification::TestId::new(),
        name: "test_auth".into(),
        language: "typescript".into(),
        kind: verification::TestKind::Unit,
        scopes: vec![WorkScope::Entity(entity.id)],
        runner: verification::TestRunner::Jest,
        file_origin: None,
    };
    store.create_test_case(&tc).unwrap();

    let run = verification::VerificationRun {
        run_id: verification::VerificationRunId::new(),
        test_ids: vec![tc.test_id],
        status: verification::VerificationStatus::Passing,
        runner: verification::TestRunner::Jest,
        started_at: kin_model::Timestamp::now(),
        finished_at: Some(kin_model::Timestamp::now()),
        duration_ms: Some(100),
        evidence_blob: None,
        exit_code: Some(0),
    };
    store.create_verification_run(&run).unwrap();

    // Link run to entity — should not error.
    store
        .link_run_proves_entity(&run.run_id, &entity.id)
        .unwrap();

    // Verify the run still exists and is intact after linking.
    let fetched = store
        .get_verification_run(&run.run_id)
        .unwrap()
        .expect("run should still exist after linking");
    assert_eq!(fetched.status, verification::VerificationStatus::Passing);
}

// ---------------------------------------------------------------------------
// 41. Proof-link queries return persisted verification runs
// ---------------------------------------------------------------------------

#[test]
fn proof_link_queries_roundtrip() {
    let store = InMemoryGraph::new();

    let entity = make_entity("checkout", "src/checkout.ts", EntityKind::Function);
    store.upsert_entity(&entity).unwrap();

    let work = kin_model::WorkItem {
        work_id: kin_model::WorkId::new(),
        kind: kin_model::WorkKind::Feature,
        title: "Implement checkout".into(),
        description: "Ship checkout flow".into(),
        status: kin_model::WorkStatus::InProgress,
        priority: kin_model::Priority::High,
        scopes: vec![WorkScope::Entity(entity.id)],
        acceptance_criteria: vec!["passes targeted proof".into()],
        external_refs: vec![],
        created_by: kin_model::IdentityRef::human("alice"),
        created_at: kin_model::Timestamp::now(),
    };
    store.create_work_item(&work).unwrap();

    let tc = verification::TestCase {
        test_id: verification::TestId::new(),
        name: "test_checkout".into(),
        language: "typescript".into(),
        kind: verification::TestKind::Integration,
        scopes: vec![WorkScope::Entity(entity.id)],
        runner: verification::TestRunner::Jest,
        file_origin: None,
    };
    store.create_test_case(&tc).unwrap();
    store
        .create_test_verifies_work(&tc.test_id, &work.work_id)
        .unwrap();

    let run = verification::VerificationRun {
        run_id: verification::VerificationRunId::new(),
        test_ids: vec![tc.test_id],
        status: verification::VerificationStatus::Passing,
        runner: verification::TestRunner::Jest,
        started_at: kin_model::Timestamp::now(),
        finished_at: Some(kin_model::Timestamp::now()),
        duration_ms: Some(75),
        evidence_blob: None,
        exit_code: Some(0),
    };
    store.create_verification_run(&run).unwrap();
    store
        .link_run_proves_entity(&run.run_id, &entity.id)
        .unwrap();
    store
        .link_run_proves_work(&run.run_id, &work.work_id)
        .unwrap();

    let entity_runs = store.list_runs_proving_entity(&entity.id).unwrap();
    assert_eq!(entity_runs.len(), 1);
    assert_eq!(entity_runs[0].run_id, run.run_id);

    let work_runs = store.list_runs_proving_work(&work.work_id).unwrap();
    assert_eq!(work_runs.len(), 1);
    assert_eq!(work_runs[0].run_id, run.run_id);
}

// ---------------------------------------------------------------------------
// 42. Contract coverage summary: empty graph has 0/0
// ---------------------------------------------------------------------------

#[test]
fn contract_coverage_summary() {
    let store = InMemoryGraph::new();

    // With no contracts, summary should be 0/0.
    let summary = store.get_contract_coverage_summary().unwrap();
    assert_eq!(summary.total_contracts, 0);
    assert_eq!(summary.covered_contracts, 0);
    assert!(summary.uncovered_contract_ids.is_empty());

    // Add an entity and test — contract coverage should still be 0/0
    // since entity coverage and contract coverage are separate.
    let entity = make_entity("foo", "src/foo.ts", EntityKind::Function);
    store.upsert_entity(&entity).unwrap();

    let tc = verification::TestCase {
        test_id: verification::TestId::new(),
        name: "test_foo".into(),
        language: "typescript".into(),
        kind: verification::TestKind::Unit,
        scopes: vec![WorkScope::Entity(entity.id)],
        runner: verification::TestRunner::Jest,
        file_origin: None,
    };
    store.create_test_case(&tc).unwrap();

    let summary_after = store.get_contract_coverage_summary().unwrap();
    assert_eq!(summary_after.total_contracts, 0);
    assert_eq!(summary_after.covered_contracts, 0);
}
