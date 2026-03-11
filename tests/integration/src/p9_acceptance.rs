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
    let import_rels: Vec<_> = relations.iter().filter(|r| r.dst == helper.id).collect();

    assert!(
        !import_rels.is_empty(),
        "expected at least one relation targeting the helper entity"
    );
    assert_eq!(import_rels[0].src, post.id);
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

    let cross_file_call = calls
        .iter()
        .find(|r| r.src == post.id && r.dst == execute_tool.id);
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
        }],
        imports: vec![],
    }];

    let relations = link_cross_file(&files);

    let contains: Vec<_> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Contains)
        .collect();

    assert_eq!(contains.len(), 1, "expected one Contains relation");
    assert_eq!(contains[0].src, dog.id);
    assert_eq!(contains[0].dst, bark.id);
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
        src: caller.id,
        dst: callee.id,
        confidence: 0.95,
        origin: RelationOrigin::Inferred,
        created_in: None,
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
        .filter(|r| r.kind == RelationKind::Calls && r.src == handler.id)
        .collect();

    assert_eq!(calls.len(), 1, "expected one Calls relation from handler");
    assert_eq!(
        calls[0].dst, foo.id,
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
    let a_to_b = calls
        .iter()
        .find(|r| r.src == entity_a.id && r.dst == entity_b.id);
    assert!(
        a_to_b.is_some(),
        "expected Calls from routeHandler to processOrder"
    );

    // Verify B -> C.
    let b_to_c = calls
        .iter()
        .find(|r| r.src == entity_b.id && r.dst == entity_c.id);
    assert!(
        b_to_c.is_some(),
        "expected Calls from processOrder to saveToDb"
    );
}

// ===========================================================================
// Phase 9 verification graph acceptance tests
// ===========================================================================

use kin_graph::KuzuGraphStore;
use kin_model::graph::GraphStore;
use kin_model::verification;
use kin_model::work::WorkScope;

// ---------------------------------------------------------------------------
// 33. Test case lifecycle: create -> query -> coverage
// ---------------------------------------------------------------------------

#[test]
fn test_case_lifecycle_and_coverage() {
    let store = KuzuGraphStore::in_memory().unwrap();

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
    let store = KuzuGraphStore::in_memory().unwrap();

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
    let store = KuzuGraphStore::in_memory().unwrap();

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
