//! Phase 8 acceptance tests: semantic work graph, annotations, context pack
//! integration, review integration, TODO import, and staleness detection.

use kin_model::*;

use crate::helpers::*;

// ---------------------------------------------------------------------------
// Helper: create a WorkItem scoped to an entity
// ---------------------------------------------------------------------------

fn make_work(title: &str, kind: WorkKind, entity_id: EntityId) -> WorkItem {
    WorkItem {
        work_id: WorkId::new(),
        kind,
        title: title.to_string(),
        description: format!("Test work item: {title}"),
        status: WorkStatus::InProgress,
        priority: Priority::Medium,
        scopes: vec![WorkScope::Entity(entity_id)],
        acceptance_criteria: vec!["Tests pass".to_string()],
        external_refs: vec![],
        created_by: IdentityRef::human("test"),
        created_at: Timestamp::now(),
    }
}

fn make_annotation(
    body: &str,
    kind: AnnotationKind,
    entity: &Entity,
) -> Annotation {
    Annotation {
        annotation_id: AnnotationId::new(),
        kind,
        body: body.to_string(),
        scopes: vec![WorkScope::Entity(entity.id)],
        anchored_fingerprint: Some(SemanticAnchor {
            ast_hash: entity.fingerprint.ast_hash,
            signature_hash: entity.fingerprint.signature_hash,
        }),
        authored_by: IdentityRef::human("test"),
        created_at: Timestamp::now(),
        staleness: StalenessState::Fresh,
    }
}

// -----------------------------------------------------------------------
// 16. Work item CRUD: create -> get -> list -> update status -> verify
// -----------------------------------------------------------------------

#[test]
fn work_item_crud_lifecycle() {
    let (_dir, graph, _genesis_id) = init_kin_repo();

    // Create an entity to scope work to.
    let entity = make_entity("payment_handler", "src/payment.rs", EntityKind::Function);
    graph.upsert_entity(&entity).unwrap();

    // Create a work item.
    let work = make_work("Add retry logic", WorkKind::Task, entity.id);
    let work_id = work.work_id;
    graph.create_work_item(&work).unwrap();

    // Get the work item back.
    let fetched = graph.get_work_item(&work_id).unwrap();
    assert!(fetched.is_some());
    let fetched = fetched.unwrap();
    assert_eq!(fetched.title, "Add retry logic");
    assert_eq!(fetched.kind, WorkKind::Task);
    assert_eq!(fetched.status, WorkStatus::InProgress);

    // List work items with filter.
    let all = graph
        .list_work_items(&WorkFilter::default())
        .unwrap();
    assert!(!all.is_empty());
    assert!(all.iter().any(|w| w.work_id == work_id));

    // Update status to Done.
    graph.update_work_status(&work_id, WorkStatus::Done).unwrap();
    let updated = graph.get_work_item(&work_id).unwrap().unwrap();
    assert_eq!(updated.status, WorkStatus::Done);
    assert!(updated.is_closed());

    // Delete the work item.
    graph.delete_work_item(&work_id).unwrap();
    let deleted = graph.get_work_item(&work_id).unwrap();
    assert!(deleted.is_none());
}

// -----------------------------------------------------------------------
// 17. Annotation CRUD: create -> get -> list -> update staleness -> verify
// -----------------------------------------------------------------------

#[test]
fn annotation_crud_lifecycle() {
    let (_dir, graph, _genesis_id) = init_kin_repo();

    let entity = make_entity("auth_service", "src/auth.rs", EntityKind::Function);
    graph.upsert_entity(&entity).unwrap();

    // Create a fresh annotation.
    let ann = make_annotation(
        "Never call external tax API in this path",
        AnnotationKind::Instruction,
        &entity,
    );
    let ann_id = ann.annotation_id;
    graph.create_annotation(&ann).unwrap();

    // Fetch it back.
    let fetched = graph.get_annotation(&ann_id).unwrap();
    assert!(fetched.is_some());
    let fetched = fetched.unwrap();
    assert_eq!(fetched.kind, AnnotationKind::Instruction);
    assert_eq!(fetched.staleness, StalenessState::Fresh);

    // Mark it suspect.
    graph
        .update_annotation_staleness(&ann_id, StalenessState::Suspect)
        .unwrap();
    let suspect = graph.get_annotation(&ann_id).unwrap().unwrap();
    assert_eq!(suspect.staleness, StalenessState::Suspect);

    // Mark it stale.
    graph
        .update_annotation_staleness(&ann_id, StalenessState::Stale)
        .unwrap();
    let stale = graph.get_annotation(&ann_id).unwrap().unwrap();
    assert_eq!(stale.staleness, StalenessState::Stale);

    // Delete it.
    graph.delete_annotation(&ann_id).unwrap();
    let gone = graph.get_annotation(&ann_id).unwrap();
    assert!(gone.is_none());
}

// -----------------------------------------------------------------------
// 18. Work scoped to entities: create work -> query by scope -> verify
// -----------------------------------------------------------------------

#[test]
fn work_scoped_to_entity_is_queryable() {
    let (_dir, graph, _genesis_id) = init_kin_repo();

    let e1 = make_entity("handler_a", "src/a.rs", EntityKind::Function);
    let e2 = make_entity("handler_b", "src/b.rs", EntityKind::Function);
    graph.upsert_entity(&e1).unwrap();
    graph.upsert_entity(&e2).unwrap();

    // Work item scoped to e1 only.
    let work = make_work("Fix handler A", WorkKind::Issue, e1.id);
    graph.create_work_item(&work).unwrap();

    // Query by e1 scope — should find it.
    let for_e1 = graph
        .get_work_for_scope(&WorkScope::Entity(e1.id))
        .unwrap();
    assert_eq!(for_e1.len(), 1);
    assert_eq!(for_e1[0].title, "Fix handler A");

    // Query by e2 scope — should be empty.
    let for_e2 = graph
        .get_work_for_scope(&WorkScope::Entity(e2.id))
        .unwrap();
    assert!(for_e2.is_empty());
}

// -----------------------------------------------------------------------
// 19. Context pack includes work items and annotations
// -----------------------------------------------------------------------

#[test]
fn context_pack_includes_work_and_annotations() {
    let (_dir, graph, _genesis_id) = init_kin_repo();

    let entity = make_entity("checkout_flow", "src/checkout.rs", EntityKind::Function);
    graph.upsert_entity(&entity).unwrap();

    // Create an in-progress work item.
    let work = make_work("Implement checkout", WorkKind::Feature, entity.id);
    graph.create_work_item(&work).unwrap();

    // Create a fresh annotation.
    let ann = make_annotation(
        "Validate card before charging",
        AnnotationKind::Warning,
        &entity,
    );
    graph.create_annotation(&ann).unwrap();

    // Build context pack.
    let opts = kin_context::ContextOptions {
        budget: TokenBudget::Small8k,
        max_depth: 2,
        include_tests: true,
        include_contracts: true,
        include_traffic: false,
    };

    let pack = kin_context::build_context_pack(graph.as_ref(), &entity.id, &opts).unwrap();

    // Verify focal entity present.
    assert_eq!(pack.focal_entities.len(), 1);
    assert!(pack.focal_entities[0].content.contains("checkout_flow"));

    // Verify work item present.
    assert!(
        !pack.work_items.is_empty(),
        "expected work items in context pack"
    );
    assert!(pack.work_items[0].content.contains("Implement checkout"));

    // Verify annotation present.
    assert!(
        !pack.annotations.is_empty(),
        "expected annotations in context pack"
    );
    assert!(
        pack.annotations[0]
            .content
            .contains("Validate card before charging")
    );

    // Verify token budget is respected.
    assert!(pack.actual_tokens <= opts.budget.max_tokens());
}

// -----------------------------------------------------------------------
// 20. Context pack excludes closed work items and stale annotations
// -----------------------------------------------------------------------

#[test]
fn context_pack_excludes_closed_work_and_stale_annotations() {
    let (_dir, graph, _genesis_id) = init_kin_repo();

    let entity = make_entity("data_sync", "src/sync.rs", EntityKind::Function);
    graph.upsert_entity(&entity).unwrap();

    // Create a Done work item — should be excluded.
    let mut work = make_work("Old task", WorkKind::Task, entity.id);
    work.status = WorkStatus::Done;
    graph.create_work_item(&work).unwrap();

    // Create a stale annotation — should be excluded.
    let mut ann = make_annotation("Outdated note", AnnotationKind::Comment, &entity);
    ann.staleness = StalenessState::Stale;
    graph.create_annotation(&ann).unwrap();

    let opts = kin_context::ContextOptions {
        budget: TokenBudget::Small8k,
        max_depth: 2,
        include_tests: true,
        include_contracts: true,
        include_traffic: false,
    };

    let pack = kin_context::build_context_pack(graph.as_ref(), &entity.id, &opts).unwrap();

    // Both should be excluded.
    assert!(
        pack.work_items.is_empty(),
        "closed work items should not appear in context pack"
    );
    assert!(
        pack.annotations.is_empty(),
        "stale annotations should not appear in context pack"
    );
}

// -----------------------------------------------------------------------
// 21. TODO import: write files with TODOs -> extract -> verify structured data
// -----------------------------------------------------------------------

#[test]
fn todo_import_extracts_markers() {
    let dir = tempfile::tempdir().unwrap();

    write_rust_file(
        dir.path(),
        "src/lib.rs",
        "// TODO: add retry logic\nfn process() {}\n// FIXME: race condition\n// HACK: temporary\n",
    );

    let todos = kin_parser::extract_todos(dir.path()).unwrap();
    assert_eq!(todos.len(), 3);
    assert_eq!(todos[0].kind, "TODO");
    assert!(todos[0].body.contains("retry logic"));
    assert_eq!(todos[1].kind, "FIXME");
    assert!(todos[1].body.contains("race condition"));
    assert_eq!(todos[2].kind, "HACK");
    assert!(todos[2].body.contains("temporary"));
}

// -----------------------------------------------------------------------
// 22. Work links: decompose feature -> tasks -> verify parent-child
// -----------------------------------------------------------------------

#[test]
fn work_decomposition_parent_child() {
    let (_dir, graph, _genesis_id) = init_kin_repo();

    let entity = make_entity("api_gateway", "src/gateway.rs", EntityKind::Module);
    graph.upsert_entity(&entity).unwrap();

    // Create a feature and two subtasks.
    let feature = make_work("API Gateway", WorkKind::Feature, entity.id);
    let task1 = make_work("Implement routing", WorkKind::Task, entity.id);
    let task2 = make_work("Add rate limiting", WorkKind::Task, entity.id);

    graph.create_work_item(&feature).unwrap();
    graph.create_work_item(&task1).unwrap();
    graph.create_work_item(&task2).unwrap();

    // Link: feature decomposes into task1 and task2.
    graph
        .create_work_link(&WorkLink::DecomposesTo {
            parent: feature.work_id,
            child: task1.work_id,
        })
        .unwrap();
    graph
        .create_work_link(&WorkLink::DecomposesTo {
            parent: feature.work_id,
            child: task2.work_id,
        })
        .unwrap();

    // Query children.
    let children = graph.get_child_work_items(&feature.work_id).unwrap();
    assert_eq!(children.len(), 2);
    let child_ids: Vec<WorkId> = children.iter().map(|c| c.work_id).collect();
    assert!(child_ids.contains(&task1.work_id));
    assert!(child_ids.contains(&task2.work_id));
}

// -----------------------------------------------------------------------
// 23. Annotation staleness detection: fresh -> entity changes -> suspect
// -----------------------------------------------------------------------

#[test]
fn annotation_staleness_after_entity_modification() {
    let (_dir, graph, _genesis_id) = init_kin_repo();

    let entity = make_entity("validator", "src/validate.rs", EntityKind::Function);
    graph.upsert_entity(&entity).unwrap();

    // Create a fresh annotation anchored to the entity's current fingerprint.
    let ann = make_annotation(
        "Must validate input length before parsing",
        AnnotationKind::Instruction,
        &entity,
    );
    let ann_id = ann.annotation_id;
    graph.create_annotation(&ann).unwrap();

    // Verify initially fresh.
    let fresh = graph.get_annotation(&ann_id).unwrap().unwrap();
    assert_eq!(fresh.staleness, StalenessState::Fresh);

    // Simulate entity modification by updating staleness (as the reconciler would).
    graph
        .update_annotation_staleness(&ann_id, StalenessState::Suspect)
        .unwrap();

    let suspect = graph.get_annotation(&ann_id).unwrap().unwrap();
    assert_eq!(suspect.staleness, StalenessState::Suspect);

    // Query annotations for scope — should include the suspect annotation.
    let scope_anns = graph
        .get_annotations_for_scope(&WorkScope::Entity(entity.id))
        .unwrap();
    assert_eq!(scope_anns.len(), 1);
    assert_eq!(scope_anns[0].staleness, StalenessState::Suspect);
}

// -----------------------------------------------------------------------
// 24. Multiple work kinds and status transitions
// -----------------------------------------------------------------------

#[test]
fn work_item_status_transitions() {
    let (_dir, graph, _genesis_id) = init_kin_repo();

    let entity = make_entity("scheduler", "src/scheduler.rs", EntityKind::Function);
    graph.upsert_entity(&entity).unwrap();

    let work = make_work("Investigate scheduling bug", WorkKind::Investigation, entity.id);
    let work_id = work.work_id;
    graph.create_work_item(&work).unwrap();

    // Proposed -> Planned -> InProgress -> Blocked -> InProgress -> Done -> Verified
    let transitions = [
        WorkStatus::Planned,
        WorkStatus::InProgress,
        WorkStatus::Blocked,
        WorkStatus::InProgress,
        WorkStatus::Done,
        WorkStatus::Verified,
    ];

    for status in transitions {
        graph.update_work_status(&work_id, status).unwrap();
        let current = graph.get_work_item(&work_id).unwrap().unwrap();
        assert_eq!(current.status, status);
    }
}

// -----------------------------------------------------------------------
// 25. Annotations for work item scope (work:id queries)
// -----------------------------------------------------------------------

#[test]
fn annotations_scoped_to_entity_queryable_by_scope() {
    let (_dir, graph, _genesis_id) = init_kin_repo();

    let entity = make_entity("cache_manager", "src/cache.rs", EntityKind::Module);
    graph.upsert_entity(&entity).unwrap();

    // Create multiple annotations on the same entity.
    let a1 = make_annotation("Consider LRU eviction", AnnotationKind::Comment, &entity);
    let a2 = make_annotation("Must handle concurrent access", AnnotationKind::Warning, &entity);
    let a3 = make_annotation(
        "Agent explored Redis alternative",
        AnnotationKind::Reasoning,
        &entity,
    );

    graph.create_annotation(&a1).unwrap();
    graph.create_annotation(&a2).unwrap();
    graph.create_annotation(&a3).unwrap();

    // Query all annotations for the entity.
    let anns = graph
        .get_annotations_for_scope(&WorkScope::Entity(entity.id))
        .unwrap();
    assert_eq!(anns.len(), 3);

    let kinds: Vec<AnnotationKind> = anns.iter().map(|a| a.kind).collect();
    assert!(kinds.contains(&AnnotationKind::Comment));
    assert!(kinds.contains(&AnnotationKind::Warning));
    assert!(kinds.contains(&AnnotationKind::Reasoning));
}
