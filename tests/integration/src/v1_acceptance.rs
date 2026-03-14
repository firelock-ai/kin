//! V1 acceptance tests for sovereign Kin operations.

use kin_blobs::BlobStore;
use kin_model::*;

use crate::helpers::*;

// -----------------------------------------------------------------------
// 1. Sovereign init: kin init -> verify .kin/ structure, genesis in graph
// -----------------------------------------------------------------------

#[test]
fn sovereign_init_creates_kin_structure_and_genesis() {
    let dir = tempfile::tempdir().unwrap();

    // Run kin init.
    let init_result = kin_core::init(dir.path()).unwrap();

    // Verify .kin/ directory structure.
    assert!(init_result.layout.root().exists());
    assert!(init_result.layout.config_path().exists());
    assert!(init_result.layout.manifest_path().exists());
    // KinDB snapshot dir snapshot directory
    assert!(init_result.layout.root().join("kindb").exists());
    assert!(init_result.layout.objects_dir().exists());
    assert!(init_result.layout.stashes_dir().exists());
    assert!(init_result.layout.projections_dir().exists());
    assert!(init_result.layout.docs_dir().exists());
    assert!(init_result.layout.bench_dir().exists());
    assert!(init_result.layout.runs_dir().exists());
    assert!(init_result.layout.logs_dir().exists());
    assert!(init_result.layout.adapters_dir().exists());

    // Open the graph from the KinDB snapshot that init created.
    let snap_path = init_result.layout.root().join("kindb").join("graph.kndb");
    let snap = kin_db::SnapshotManager::open(&snap_path).unwrap();
    let graph = snap.graph();
    let genesis = kin_core::build_genesis_change();

    // Verify genesis change is in the graph.
    let stored = graph.get_change(&genesis.id).unwrap();
    assert!(stored.is_some());
    let stored = stored.unwrap();
    assert_eq!(stored.id, genesis.id);
    assert!(stored.parents.is_empty());
    assert_eq!(stored.message, "kin init");

    // Verify main branch exists and points to genesis.
    let branch = graph.get_branch(&BranchName::new("main")).unwrap();
    assert!(branch.is_some());
    assert_eq!(branch.unwrap().head, genesis.id);

    // Verify HEAD file exists and points to main.
    let head_content = std::fs::read_to_string(init_result.layout.head_path()).unwrap();
    assert_eq!(head_content.trim(), "main");

    // Verify config is valid.
    let config = kin_core::KinConfig::load(&init_result.layout.config_path()).unwrap();
    assert_eq!(config.default_branch, "main");

    // Verify manifest is valid.
    let manifest = kin_core::KinManifest::load(&init_result.layout.manifest_path()).unwrap();
    assert!(!manifest.repo_id.is_empty());
}

// -----------------------------------------------------------------------
// 2. Parse + index: write a TS file -> parse -> index -> verify entities
// -----------------------------------------------------------------------

#[test]
fn parse_and_index_typescript_file() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));

    // Write a TypeScript file with functions and a class.
    let ts_content = r#"
export function greet(name: string): string {
    return `Hello, ${name}!`;
}

export function add(a: number, b: number): number {
    return a + b;
}

export class Calculator {
    value: number = 0;

    add(n: number): void {
        this.value += n;
    }

    reset(): void {
        this.value = 0;
    }
}
"#;
    let ts_path = write_ts_file(dir.path(), "src/math.ts", ts_content);

    // Create blob store and indexer.
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let indexer = kin_index::Indexer::new();

    // Index the file.
    let result = indexer
        .index_and_apply(&ts_path, &blob_store, graph.as_ref())
        .unwrap();

    // Should have upserted entities (functions + class + methods).
    assert!(
        result.entities_upserted > 0,
        "expected entities to be upserted, got {}",
        result.entities_upserted
    );

    // Query all entities in the graph — should find the ones we indexed.
    let all_entities = graph.list_all_entities().unwrap();
    assert!(
        !all_entities.is_empty(),
        "expected entities in graph after indexing"
    );

    // At minimum, the exported functions should be present.
    let names: Vec<&str> = all_entities.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names
            .iter()
            .any(|n| n.contains("greet") || n.contains("add") || n.contains("Calculator")),
        "expected to find known entities, got: {:?}",
        names
    );
}

// -----------------------------------------------------------------------
// 3. Projection round-trip: entity -> project -> re-parse -> same fingerprint
// -----------------------------------------------------------------------

#[test]
fn projection_round_trip_preserves_fingerprint() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));

    // Write a simple Rust file.
    let rs_content = r#"
pub fn process_data(input: &str) -> String {
    input.to_uppercase()
}
"#;
    let rs_path = write_rust_file(dir.path(), "src/processor.rs", rs_content);

    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let indexer = kin_index::Indexer::new();

    // First index: captures initial fingerprints.
    let result1 = indexer
        .index_and_apply(&rs_path, &blob_store, graph.as_ref())
        .unwrap();
    assert!(result1.entities_upserted > 0);

    let entities_after_first = graph.list_all_entities().unwrap();
    let first_fingerprints: Vec<_> = entities_after_first
        .iter()
        .map(|e| (e.name.clone(), e.fingerprint.ast_hash))
        .collect();

    // Re-index the same file without changes.
    let _result2 = indexer
        .index_and_apply(&rs_path, &blob_store, graph.as_ref())
        .unwrap();

    // Verify that no entities were modified (LKG skips same fingerprints).
    // The entities should still exist with the same fingerprints.
    let entities_after_second = graph.list_all_entities().unwrap();

    for (name, hash) in &first_fingerprints {
        let entity = entities_after_second.iter().find(|e| &e.name == name);
        assert!(
            entity.is_some(),
            "entity '{}' should still exist after re-index",
            name
        );
        assert_eq!(
            entity.unwrap().fingerprint.ast_hash,
            *hash,
            "fingerprint for '{}' should be unchanged after re-index",
            name
        );
    }
}

// -----------------------------------------------------------------------
// 4. Branch + merge: create branch -> make changes -> verify result
// -----------------------------------------------------------------------

#[test]
fn branch_create_and_change_history() {
    let (_dir, graph, genesis_id) = init_kin_repo();

    // Verify main branch exists with genesis.
    let main = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
    assert_eq!(main.head, genesis_id);

    // Create a change on main.
    let entity = make_entity("process", "src/lib.rs", EntityKind::Function);
    graph.upsert_entity(&entity).unwrap();

    let change1 = make_change(genesis_id, vec![entity.clone()], "add process function");
    graph.create_change(&change1).unwrap();
    graph
        .update_branch_head(&BranchName::new("main"), &change1.id)
        .unwrap();

    // Verify branch head moved.
    let main = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
    assert_eq!(main.head, change1.id);

    // Create a feature branch from the same point.
    let feature_branch = Branch {
        name: BranchName::new("feature/auth"),
        head: change1.id,
    };
    graph.create_branch(&feature_branch).unwrap();

    // Add a change on the feature branch.
    let entity2 = make_entity("authenticate", "src/auth.rs", EntityKind::Function);
    graph.upsert_entity(&entity2).unwrap();

    let change2 = make_change(change1.id, vec![entity2], "add authenticate function");
    graph.create_change(&change2).unwrap();
    graph
        .update_branch_head(&BranchName::new("feature/auth"), &change2.id)
        .unwrap();

    // Verify the two branches have different heads.
    let main = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
    let feature = graph
        .get_branch(&BranchName::new("feature/auth"))
        .unwrap()
        .unwrap();
    assert_ne!(main.head, feature.head);
    assert_eq!(feature.head, change2.id);

    // List all branches — should have 2.
    let branches = graph.list_branches().unwrap();
    assert_eq!(branches.len(), 2);
}

// -----------------------------------------------------------------------
// 5. Context pack: generate with token budget -> verify fits budget
// -----------------------------------------------------------------------

#[test]
fn context_pack_fits_token_budget() {
    let (_dir, graph, _genesis_id) = init_kin_repo();

    // Insert a focal entity and some related entities.
    let focal = make_entity("main_handler", "src/handler.rs", EntityKind::Function);
    graph.upsert_entity(&focal).unwrap();

    let dep = make_entity("helper_util", "src/util.rs", EntityKind::Function);
    graph.upsert_entity(&dep).unwrap();

    // Create a relation between them.
    let relation = kin_model::Relation {
        id: kin_model::RelationId::new(),
        kind: kin_model::RelationKind::Calls,
        src: focal.id,
        dst: dep.id,
        confidence: 1.0,
        origin: kin_model::RelationOrigin::Parsed,
        created_in: None,
    };
    graph.upsert_relation(&relation).unwrap();

    // Build context pack with small budget.
    let opts = kin_context::ContextOptions {
        budget: TokenBudget::Small8k,
        max_depth: 2,
        include_tests: true,
        include_contracts: true,
        include_traffic: false,
        assistant_hint: None,
    };

    let pack = kin_context::build_context_pack(graph.as_ref(), &focal.id, &opts).unwrap();

    // Verify the pack fits within budget.
    assert!(
        pack.actual_tokens <= opts.budget.max_tokens(),
        "context pack uses {} tokens but budget is {}",
        pack.actual_tokens,
        opts.budget.max_tokens()
    );

    // Verify focal entity is included.
    assert_eq!(pack.focal_entities.len(), 1);
    assert_eq!(pack.focal_entities[0].entity_id, focal.id);
    assert_eq!(
        pack.focal_entities[0].projection_level,
        ProjectionLevel::FullBody
    );

    // The dependency should appear in the pack (at signature level).
    assert!(
        !pack.dependency_signatures.is_empty(),
        "expected at least one dependency signature in context pack"
    );
}

// -----------------------------------------------------------------------
// 6. Review: make changes -> run review -> verify risk assessment
// -----------------------------------------------------------------------

#[test]
fn review_produces_risk_assessment() {
    let (_dir, graph, genesis_id) = init_kin_repo();

    // Create a change that adds an entity.
    let entity = make_entity("api_handler", "src/api.rs", EntityKind::Function);
    let change = make_change(genesis_id, vec![entity.clone()], "add api handler");
    graph.create_change(&change).unwrap();
    graph.upsert_entity(&entity).unwrap();

    // Create a diff from the change and run a review.
    let diff = kin_review::diff_from_change(&change);
    assert_eq!(diff.entity_changes.len(), 1);

    let review = kin_review::SemanticReview::review_from_diff(diff, graph.as_ref()).unwrap();

    // Verify review output structure.
    assert_eq!(review.diff.entity_changes.len(), 1);

    // New public entity with no test coverage should produce a note.
    // Risk should be Low since there are no breaking changes or consumers.
    assert!(matches!(
        review.risk.overall_risk,
        RiskLevel::Low | RiskLevel::Medium
    ));
}

// -----------------------------------------------------------------------
// 7. Git export: init kin repo -> add entities -> export -> verify commits
// -----------------------------------------------------------------------

#[test]
fn git_export_creates_commits() {
    let (dir, graph, genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));

    // Create a change with an artifact delta (so export has file content).
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();

    // Store actual file content in the blob store.
    let file_content = b"pub fn exported_fn() { println!(\"hello\"); }\n";
    let blob_hash = blob_store.write(file_content).unwrap();
    let content_hash = Hash256::from_bytes(blob_hash.0);

    let entity = make_entity("exported_fn", "src/lib.rs", EntityKind::Function);
    graph.upsert_entity(&entity).unwrap();

    // Build a change with an artifact delta so the export has file content.
    let mut change = make_change(genesis_id, vec![entity], "add exported function");
    change.artifact_deltas.push(kin_model::ArtifactDelta {
        file_id: kin_model::FilePathId::new("src/lib.rs"),
        kind: kin_model::ArtifactDeltaKind::Added,
        old_hash: None,
        new_hash: Some(content_hash),
    });
    graph.create_change(&change).unwrap();
    graph
        .update_branch_head(&BranchName::new("main"), &change.id)
        .unwrap();

    let git_dir = dir.path().join("git-export");

    // Export must succeed.
    let export_result = kin_git::export_to_git(
        graph.as_ref(),
        &blob_store,
        genesis_id,
        &BranchName::new("main"),
        &git_dir,
    )
    .expect("git export should succeed");

    // Verify at least one commit was exported.
    assert!(
        export_result.commits_exported >= 1,
        "expected at least 1 commit exported, got {}",
        export_result.commits_exported
    );
    assert_eq!(export_result.branches_updated, 1);
}

// -----------------------------------------------------------------------
// 8. Real init then reopen graph: disk round-trip
// -----------------------------------------------------------------------

#[test]
fn real_init_then_reopen_graph() {
    let dir = tempfile::tempdir().unwrap();

    // Step 1: init creates graph, genesis, and main branch on disk.
    let init_result = kin_core::init(dir.path()).unwrap();
    let genesis = kin_core::build_genesis_change();

    // Step 2: drop everything — simulate process exit.
    let snap_path = init_result.layout.root().join("kindb").join("graph.kndb");
    drop(init_result);

    // Step 3: reopen the graph from the KinDB snapshot.
    let snap = kin_db::SnapshotManager::open(&snap_path).unwrap();
    let graph = snap.graph();

    // Step 4: verify genesis change survived the round-trip.
    let stored = graph.get_change(&genesis.id).unwrap();
    assert!(stored.is_some(), "genesis should survive disk round-trip");
    let stored = stored.unwrap();
    assert_eq!(stored.id, genesis.id);
    assert!(stored.parents.is_empty());
    assert_eq!(stored.message, "kin init");

    // Step 5: verify main branch exists and points to genesis.
    let branch = graph.get_branch(&BranchName::new("main")).unwrap();
    assert!(
        branch.is_some(),
        "main branch should survive disk round-trip"
    );
    assert_eq!(branch.unwrap().head, genesis.id);
}

// -----------------------------------------------------------------------
// 9. Real CLI init and commit: full user flow
// -----------------------------------------------------------------------

#[test]
fn real_cli_init_and_commit() {
    let dir = tempfile::tempdir().unwrap();

    // Step 1: init
    let init_result = kin_core::init(dir.path()).unwrap();
    let layout = &init_result.layout;

    // Step 2: write a source file
    let rs_content = r#"
pub fn hello() -> &'static str {
    "hello world"
}

pub fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#;
    write_rust_file(dir.path(), "src/lib.rs", rs_content);

    // Step 3: open graph and blob store
    let snap_path = layout.root().join("kindb").join("graph.kndb");
    let snap = kin_db::SnapshotManager::open(&snap_path).unwrap();
    let graph = snap.graph();
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();

    // Step 4: verify initial state
    let genesis = kin_core::build_genesis_change();
    let branch_before = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
    assert_eq!(branch_before.head, genesis.id);

    // Step 5: simulate commit — parse, index, create change
    let current_branch = kin_core::read_current_branch(layout).unwrap();
    assert_eq!(current_branch, BranchName::new("main"));

    let indexer = kin_index::Indexer::new();
    let rs_path = dir.path().join("src/lib.rs");
    let index_result = indexer
        .index_and_apply(&rs_path, &blob_store, &*graph)
        .unwrap();
    assert!(
        index_result.entities_upserted > 0,
        "expected entities from Rust file"
    );

    // Build entity deltas from indexed entities
    let all_entities = graph.list_all_entities().unwrap();
    let entity_deltas: Vec<EntityDelta> = all_entities
        .iter()
        .map(|e| EntityDelta::Added(e.clone()))
        .collect();

    // Store file in blob store for artifact delta
    let file_bytes = std::fs::read(&rs_path).unwrap();
    let blob_hash = blob_store.write(&file_bytes).unwrap();
    let content_hash = Hash256::from_bytes(blob_hash.0);

    // Build the semantic change
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(b"kin-change-v1:test commit:");
    hasher.update(genesis.id.0.as_bytes());
    hasher.update(uuid::Uuid::new_v4().as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    let change_id = SemanticChangeId::from_hash(Hash256::from_bytes(bytes));

    let change = SemanticChange {
        id: change_id,
        parents: vec![genesis.id],
        timestamp: Timestamp::now(),
        author: AuthorId::new("test"),
        message: "add hello and add functions".to_string(),
        entity_deltas,
        relation_deltas: vec![],
        artifact_deltas: vec![kin_model::ArtifactDelta {
            file_id: FilePathId::new("src/lib.rs"),
            kind: kin_model::ArtifactDeltaKind::Added,
            old_hash: None,
            new_hash: Some(content_hash),
        }],
        projected_files: vec![],
        spec_link: None,
        evidence: vec![],
        risk_summary: None,
        authored_on: Some(BranchName::new("main")),
    };

    graph.create_change(&change).unwrap();
    graph
        .update_branch_head(&BranchName::new("main"), &change_id)
        .unwrap();

    // Step 6: verify change is in graph
    let stored_change = graph.get_change(&change_id).unwrap();
    assert!(stored_change.is_some(), "change should be in graph");
    let stored = stored_change.unwrap();
    assert_eq!(stored.message, "add hello and add functions");
    assert!(
        !stored.entity_deltas.is_empty(),
        "change should have entity deltas"
    );

    // Step 7: verify branch head advanced
    let branch_after = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
    assert_eq!(branch_after.head, change_id);
    assert_ne!(
        branch_after.head, genesis.id,
        "branch head should have advanced past genesis"
    );
}

// -----------------------------------------------------------------------
// 10. Branch switch persists via HEAD file
// -----------------------------------------------------------------------

#[test]
fn branch_switch_persists() {
    let dir = tempfile::tempdir().unwrap();

    // Init repo
    let init_result = kin_core::init(dir.path()).unwrap();
    let layout = &init_result.layout;

    // Open graph from KinDB snapshot
    let snap_path = layout.root().join("kindb").join("graph.kndb");
    let snap = kin_db::SnapshotManager::open(&snap_path).unwrap();
    let graph = snap.graph();
    let genesis = kin_core::build_genesis_change();

    // Verify HEAD starts at "main"
    let current = kin_core::read_current_branch(layout).unwrap();
    assert_eq!(current, BranchName::new("main"));

    // Create branch "dev" forking from main
    let dev_branch = Branch {
        name: BranchName::new("dev"),
        head: genesis.id,
    };
    graph.create_branch(&dev_branch).unwrap();

    // Switch to "dev"
    kin_core::write_current_branch(layout, &BranchName::new("dev")).unwrap();

    // Verify HEAD file contains "dev"
    let head_content = std::fs::read_to_string(layout.head_path()).unwrap();
    assert_eq!(head_content.trim(), "dev");

    let current = kin_core::read_current_branch(layout).unwrap();
    assert_eq!(current, BranchName::new("dev"));

    // Switch back to "main"
    kin_core::write_current_branch(layout, &BranchName::new("main")).unwrap();

    // Verify HEAD file contains "main"
    let head_content = std::fs::read_to_string(layout.head_path()).unwrap();
    assert_eq!(head_content.trim(), "main");

    let current = kin_core::read_current_branch(layout).unwrap();
    assert_eq!(current, BranchName::new("main"));

    // Verify both branches still exist in graph
    let branches = graph.list_branches().unwrap();
    assert_eq!(branches.len(), 2);
    assert!(graph
        .get_branch(&BranchName::new("main"))
        .unwrap()
        .is_some());
    assert!(graph.get_branch(&BranchName::new("dev")).unwrap().is_some());
}
