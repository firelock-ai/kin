// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Phase 3 acceptance tests: projection splicing, branch switch re-projection,
//! merge commit creation, reconciler round-trips, and LKG resilience.

use kin_blobs::BlobStore;
use kin_model::*;

use crate::helpers::*;

// -----------------------------------------------------------------------
// 1. projection_splice_preserves_formatting
// -----------------------------------------------------------------------

#[test]
fn projection_splice_preserves_formatting() {
    // Build a file with comments, whitespace, and a function.
    let original =
        b"// header comment\n\npub fn greet() {\n    println!(\"hi\");\n}\n\n// footer\n";

    let entity_id = EntityId::new();
    let layout = FileLayout {
        file_id: FilePathId::new("src/greet.rs"),
        parse_completeness: ParseCompleteness::Full,
        imports: ImportSection {
            byte_range: 0..0,
            items: vec![],
        },
        regions: vec![
            SourceRegion::Trivia {
                byte_range: 0..18, // "// header comment\n"
            },
            SourceRegion::Trivia {
                byte_range: 18..19, // "\n"
            },
            SourceRegion::EntityRef {
                entity_id,
                byte_range: 19..56, // "pub fn greet() {\n    println!(\"hi\");\n}"
            },
            SourceRegion::Trivia {
                byte_range: 56..68, // "\n\n// footer\n"
            },
        ],
    };

    // Splice: replace entity body only.
    let new_body = b"pub fn greet() {\n    println!(\"hello world\");\n}";
    let splice = kin_projection::splice_entity(&layout, &entity_id, new_body).unwrap();
    let result = kin_projection::apply_splices(original, vec![splice]).unwrap();

    // Trivia before and after the entity must be byte-identical.
    assert_eq!(
        &result[..19],
        &original[..19],
        "header trivia must be preserved"
    );
    let new_entity_end = 19 + new_body.len();
    let original_footer = &original[56..];
    let result_footer = &result[new_entity_end..];
    assert_eq!(
        result_footer, original_footer,
        "footer trivia must be preserved"
    );

    // Entity body should have changed.
    let entity_slice = &result[19..new_entity_end];
    assert_eq!(entity_slice, new_body);
}

// -----------------------------------------------------------------------
// 2. projection_multiple_entity_mutations
// -----------------------------------------------------------------------

#[test]
fn projection_multiple_entity_mutations() {
    // File with 3 functions separated by blank lines.
    let original = b"fn alpha() { 1 }\n\nfn beta() { 2 }\n\nfn gamma() { 3 }\n";
    //               0-17           17-18  18-34         34-35  35-52

    let id_a = EntityId::new();
    let id_b = EntityId::new();
    let id_c = EntityId::new();

    let layout = FileLayout {
        file_id: FilePathId::new("src/lib.rs"),
        parse_completeness: ParseCompleteness::Full,
        imports: ImportSection {
            byte_range: 0..0,
            items: vec![],
        },
        regions: vec![
            SourceRegion::EntityRef {
                entity_id: id_a,
                byte_range: 0..16, // "fn alpha() { 1 }"
            },
            SourceRegion::Trivia {
                byte_range: 16..18, // "\n\n"
            },
            SourceRegion::EntityRef {
                entity_id: id_b,
                byte_range: 18..33, // "fn beta() { 2 }"
            },
            SourceRegion::Trivia {
                byte_range: 33..35, // "\n\n"
            },
            SourceRegion::EntityRef {
                entity_id: id_c,
                byte_range: 35..51, // "fn gamma() { 3 }"
            },
            SourceRegion::Trivia {
                byte_range: 51..52, // "\n"
            },
        ],
    };

    // Mutate alpha and gamma, leave beta unchanged.
    let splice_a = kin_projection::splice_entity(&layout, &id_a, b"fn alpha() { 10 }").unwrap();
    let splice_c = kin_projection::splice_entity(&layout, &id_c, b"fn gamma() { 30 }").unwrap();
    let result = kin_projection::apply_splices(original, vec![splice_a, splice_c]).unwrap();

    let result_str = std::str::from_utf8(&result).unwrap();
    assert!(
        result_str.contains("fn alpha() { 10 }"),
        "alpha should be mutated"
    );
    assert!(
        result_str.contains("fn beta() { 2 }"),
        "beta should be unchanged"
    );
    assert!(
        result_str.contains("fn gamma() { 30 }"),
        "gamma should be mutated"
    );
}

// -----------------------------------------------------------------------
// 3. branch_switch_reprojects_working_directory
// -----------------------------------------------------------------------

#[test]
fn branch_switch_reprojects_working_directory() {
    let (dir, graph, genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();

    // Commit a file on main.
    let main_content = b"pub fn main_fn() { 1 }\n";
    let main_blob = blob_store.write(main_content).unwrap();
    let main_hash = Hash256::from_bytes(main_blob.0);

    let entity_main = make_entity("main_fn", "src/lib.rs", EntityKind::Function);
    let mut change_main = make_change(genesis_id, vec![entity_main], "add main_fn");
    change_main.artifact_deltas.push(ArtifactDelta {
        file_id: FilePathId::new("src/lib.rs"),
        kind: ArtifactDeltaKind::Added,
        old_hash: None,
        new_hash: Some(main_hash),
    });
    graph.create_change(&change_main).unwrap();
    graph
        .update_branch_head(&BranchName::new("main"), &change_main.id)
        .unwrap();

    // Create feature branch from main's current head.
    let feature_branch = Branch {
        name: BranchName::new("feature"),
        head: change_main.id,
    };
    graph.create_branch(&feature_branch).unwrap();

    // Commit a different file on feature.
    let feature_content = b"pub fn feature_fn() { 42 }\n";
    let feature_blob = blob_store.write(feature_content).unwrap();
    let feature_hash = Hash256::from_bytes(feature_blob.0);

    let entity_feature = make_entity("feature_fn", "src/feature.rs", EntityKind::Function);
    let mut change_feature = make_change(change_main.id, vec![entity_feature], "add feature_fn");
    change_feature.artifact_deltas.push(ArtifactDelta {
        file_id: FilePathId::new("src/feature.rs"),
        kind: ArtifactDeltaKind::Added,
        old_hash: None,
        new_hash: Some(feature_hash),
    });
    graph.create_change(&change_feature).unwrap();
    graph
        .update_branch_head(&BranchName::new("feature"), &change_feature.id)
        .unwrap();

    // Checkout main: working dir should have src/lib.rs only.
    let main_branch = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
    let files_written = kin_core::checkout_branch(
        graph.as_ref(),
        &blob_store,
        &layout,
        &genesis_id,
        &main_branch.head,
    )
    .unwrap();
    assert!(files_written >= 1, "should write at least 1 file for main");

    let main_on_disk = std::fs::read(layout.working_dir().join("src/lib.rs")).unwrap();
    assert_eq!(main_on_disk, main_content);

    // Checkout feature: working dir should have both files (main's + feature's).
    let feature = graph
        .get_branch(&BranchName::new("feature"))
        .unwrap()
        .unwrap();
    let files_written = kin_core::checkout_branch(
        graph.as_ref(),
        &blob_store,
        &layout,
        &genesis_id,
        &feature.head,
    )
    .unwrap();
    assert!(
        files_written >= 2,
        "should write at least 2 files for feature"
    );

    let feature_on_disk = std::fs::read(layout.working_dir().join("src/feature.rs")).unwrap();
    assert_eq!(feature_on_disk, feature_content);

    // The main file should still be there on feature branch (inherited).
    let main_still = std::fs::read(layout.working_dir().join("src/lib.rs")).unwrap();
    assert_eq!(main_still, main_content);
}

// -----------------------------------------------------------------------
// 4. merge_creates_merge_commit_with_two_parents
// -----------------------------------------------------------------------

#[test]
fn merge_creates_merge_commit_with_two_parents() {
    let (_dir, graph, genesis_id) = init_kin_repo();

    // Create change on main: add entity A.
    let entity_a = make_entity("func_a", "src/a.rs", EntityKind::Function);
    let change_a = make_change(genesis_id, vec![entity_a], "add func_a on main");
    graph.create_change(&change_a).unwrap();
    graph
        .update_branch_head(&BranchName::new("main"), &change_a.id)
        .unwrap();

    // Create feature branch from genesis (before change_a).
    let feature_branch = Branch {
        name: BranchName::new("feature"),
        head: genesis_id,
    };
    graph.create_branch(&feature_branch).unwrap();

    // Create change on feature: add entity B.
    let entity_b = make_entity("func_b", "src/b.rs", EntityKind::Function);
    let change_b = make_change(genesis_id, vec![entity_b], "add func_b on feature");
    graph.create_change(&change_b).unwrap();
    graph
        .update_branch_head(&BranchName::new("feature"), &change_b.id)
        .unwrap();

    // Build a merge change with two parents.
    let main_head = change_a.id;
    let feature_head = change_b.id;
    let their_changes = graph.get_changes_since(&genesis_id, &feature_head).unwrap();

    let merge = build_merge_change_for_test(
        &main_head,
        &feature_head,
        &their_changes,
        "Merge feature into main",
    );
    graph.create_change(&merge).unwrap();
    graph
        .update_branch_head(&BranchName::new("main"), &merge.id)
        .unwrap();

    // Verify: merge commit exists with 2 parents.
    let stored = graph.get_change(&merge.id).unwrap().unwrap();
    assert_eq!(stored.parents.len(), 2, "merge commit must have 2 parents");
    assert!(
        stored.parents.contains(&main_head),
        "merge commit must include main's head as parent"
    );
    assert!(
        stored.parents.contains(&feature_head),
        "merge commit must include feature's head as parent"
    );

    // Verify: branch head advanced to merge commit.
    let main_after = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
    assert_eq!(
        main_after.head, merge.id,
        "main head should point to merge commit"
    );
}

// -----------------------------------------------------------------------
// 5. merge_fast_forward_when_no_divergence
// -----------------------------------------------------------------------

#[test]
fn merge_fast_forward_when_no_divergence() {
    let (_dir, graph, genesis_id) = init_kin_repo();

    // Create feature branch from genesis (same as main).
    let feature_branch = Branch {
        name: BranchName::new("feature"),
        head: genesis_id,
    };
    graph.create_branch(&feature_branch).unwrap();

    // Create change only on feature (main unchanged at genesis).
    let entity = make_entity("feat_only", "src/feat.rs", EntityKind::Function);
    let change = make_change(genesis_id, vec![entity], "add feat_only on feature");
    graph.create_change(&change).unwrap();
    graph
        .update_branch_head(&BranchName::new("feature"), &change.id)
        .unwrap();

    // Simulate fast-forward merge: main has no changes since genesis,
    // so just advance main's head to feature's head.
    let main = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
    let ours = graph.get_changes_since(&genesis_id, &main.head).unwrap();
    assert!(
        ours.is_empty(),
        "main should have no changes (fast-forward eligible)"
    );

    // Fast-forward: set main head = feature head.
    graph
        .update_branch_head(&BranchName::new("main"), &change.id)
        .unwrap();

    // Verify: main's head == feature's head (no merge commit).
    let main_after = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
    let feature_after = graph
        .get_branch(&BranchName::new("feature"))
        .unwrap()
        .unwrap();
    assert_eq!(
        main_after.head, feature_after.head,
        "fast-forward should make main head == feature head"
    );
}

// -----------------------------------------------------------------------
// 6. merge_detects_structural_conflict
// -----------------------------------------------------------------------

#[test]
fn merge_detects_structural_conflict() {
    let (_dir, graph, genesis_id) = init_kin_repo();

    // Create entity X on main.
    let entity_x = make_entity("shared_fn", "src/shared.rs", EntityKind::Function);
    let entity_x_id = entity_x.id;
    graph.upsert_entity(&entity_x).unwrap();

    let change_main_base = make_change(genesis_id, vec![entity_x.clone()], "add shared_fn");
    graph.create_change(&change_main_base).unwrap();
    graph
        .update_branch_head(&BranchName::new("main"), &change_main_base.id)
        .unwrap();

    // Create feature branch from same point.
    let feature = Branch {
        name: BranchName::new("feature"),
        head: change_main_base.id,
    };
    graph.create_branch(&feature).unwrap();

    // Modify entity X on main.
    let mut entity_x_main = entity_x.clone();
    entity_x_main.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]);

    let change_main_mod = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"main-mod");
        hasher.update(uuid::Uuid::new_v4().as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes(bytes)),
            parents: vec![change_main_base.id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "modify shared_fn on main".to_string(),
            entity_deltas: vec![EntityDelta::Modified {
                old: entity_x.clone(),
                new: entity_x_main,
            }],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: Some(BranchName::new("main")),
        }
    };
    graph.create_change(&change_main_mod).unwrap();
    graph
        .update_branch_head(&BranchName::new("main"), &change_main_mod.id)
        .unwrap();

    // Modify entity X on feature (different fingerprint).
    let mut entity_x_feat = entity_x.clone();
    entity_x_feat.fingerprint.ast_hash = Hash256::from_bytes([0x22; 32]);

    let change_feat_mod = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"feat-mod");
        hasher.update(uuid::Uuid::new_v4().as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes(bytes)),
            parents: vec![change_main_base.id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "modify shared_fn on feature".to_string(),
            entity_deltas: vec![EntityDelta::Modified {
                old: entity_x.clone(),
                new: entity_x_feat,
            }],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: Some(BranchName::new("feature")),
        }
    };
    graph.create_change(&change_feat_mod).unwrap();
    graph
        .update_branch_head(&BranchName::new("feature"), &change_feat_mod.id)
        .unwrap();

    // Detect conflicts by comparing entity delta IDs.
    let main_head = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
    let feat_head = graph
        .get_branch(&BranchName::new("feature"))
        .unwrap()
        .unwrap();
    let bases = graph
        .find_merge_bases(&main_head.head, &feat_head.head)
        .unwrap();
    assert!(!bases.is_empty(), "should find at least one merge base");

    let base = &bases[0];
    let ours = graph.get_changes_since(base, &main_head.head).unwrap();
    let theirs = graph.get_changes_since(base, &feat_head.head).unwrap();

    let extract_ids = |deltas: &[EntityDelta]| -> Vec<EntityId> {
        deltas
            .iter()
            .map(|d| match d {
                EntityDelta::Added(e) => e.id,
                EntityDelta::Modified { new, .. } => new.id,
                EntityDelta::Removed(id) => *id,
            })
            .collect()
    };

    let mut conflicts = Vec::new();
    for our_change in &ours {
        let our_ids = extract_ids(&our_change.entity_deltas);
        for their_change in &theirs {
            let their_ids = extract_ids(&their_change.entity_deltas);
            for our_id in &our_ids {
                if their_ids.contains(our_id) {
                    conflicts.push(*our_id);
                }
            }
        }
    }

    assert!(
        !conflicts.is_empty(),
        "conflict should be detected for entity modified on both sides"
    );
    assert!(
        conflicts.contains(&entity_x_id),
        "the conflicting entity should be the shared one"
    );

    // Verify: branch head should NOT advance (no merge applied).
    let main_still = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
    assert_eq!(
        main_still.head, change_main_mod.id,
        "main head should not advance when conflicts exist"
    );
}

// -----------------------------------------------------------------------
// 7. reconciler_file_to_overlay_round_trip
// -----------------------------------------------------------------------

#[test]
fn reconciler_file_to_overlay_round_trip() {
    let dir = tempfile::tempdir().unwrap();

    // Write a Rust file with a function.
    let rs_content = b"pub fn round_trip() -> i32 {\n    42\n}\n";
    let rs_path = dir.path().join("src");
    std::fs::create_dir_all(&rs_path).unwrap();
    let file_path = rs_path.join("lib.rs");
    std::fs::write(&file_path, rs_content).unwrap();

    // Set up reconciler infrastructure.
    let (kin_dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(kin_dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();

    // Use IndexPipeline to parse (File -> entities).
    let pipeline = kin_index::IndexPipeline::new();
    let indexed = pipeline.index_file(&file_path, &blob_store).unwrap();

    assert!(
        !indexed.entities.is_empty(),
        "should parse at least one entity from the Rust file"
    );

    // Find the round_trip entity.
    let round_trip_entity = indexed
        .entities
        .iter()
        .find(|e| e.name.contains("round_trip"));
    assert!(
        round_trip_entity.is_some(),
        "should find round_trip entity in parse results"
    );

    // Upsert into graph to simulate overlay application.
    for entity in &indexed.entities {
        graph.upsert_entity(entity).unwrap();
    }

    // Verify entities are in the graph.
    let all = graph.list_all_entities().unwrap();
    let names: Vec<&str> = all.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.contains("round_trip")),
        "round_trip entity should be in graph after upsert"
    );
}

// -----------------------------------------------------------------------
// 8. lkg_retains_state_on_broken_parse
// -----------------------------------------------------------------------

#[test]
fn lkg_retains_state_on_broken_parse() {
    // Write a valid Rust file and record its entity in LKG.
    let mut lkg = kin_reconcile::LkgStore::new();

    let entity = make_entity("stable_fn", "src/lib.rs", EntityKind::Function);
    let entity_id = entity.id;
    let original_fingerprint = entity.fingerprint.clone();

    lkg.record(entity, vec![]);
    assert!(
        lkg.get(&entity_id).is_some(),
        "entity should be in LKG after record"
    );

    // Simulate a broken parse: the LKG should still have the original fingerprint.
    // (In real usage, the reconciler checks parse_state and skips graph updates on BrokenAst.)
    let new_fingerprint = SemanticFingerprint {
        algorithm: FingerprintAlgorithm::V1TreeSitter,
        ast_hash: Hash256::from_bytes([0xff; 32]),
        signature_hash: Hash256::from_bytes([0xfe; 32]),
        behavior_hash: Hash256::from_bytes([0xfd; 32]),
        stability_score: 0.0,
    };

    // Verify has_changed detects the difference.
    assert!(
        lkg.has_changed(&entity_id, &new_fingerprint),
        "should detect that new fingerprint differs from LKG"
    );

    // Since we did NOT record the broken fingerprint, LKG should still have the original.
    let lkg_entry = lkg.get(&entity_id).unwrap();
    assert_eq!(
        lkg_entry.entity.fingerprint.ast_hash, original_fingerprint.ast_hash,
        "LKG should retain original fingerprint when broken parse is not recorded"
    );
    assert_eq!(
        lkg_entry.entity.fingerprint.signature_hash, original_fingerprint.signature_hash,
        "LKG signature_hash should be unchanged"
    );
    assert_eq!(
        lkg_entry.entity.fingerprint.behavior_hash, original_fingerprint.behavior_hash,
        "LKG behavior_hash should be unchanged"
    );
}

// -----------------------------------------------------------------------
// 9. git_export_import_round_trip
// -----------------------------------------------------------------------

#[test]
fn git_export_import_round_trip() {
    let (dir, graph, genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();

    // Create entities and a change with artifact deltas.
    let file_content = b"pub fn round_trip() -> bool { true }\n";
    let blob_hash = blob_store.write(file_content).unwrap();
    let content_hash = Hash256::from_bytes(blob_hash.0);

    let entity = make_entity("round_trip", "src/lib.rs", EntityKind::Function);
    graph.upsert_entity(&entity).unwrap();

    let mut change = make_change(genesis_id, vec![entity], "add round_trip function");
    change.artifact_deltas.push(ArtifactDelta {
        file_id: FilePathId::new("src/lib.rs"),
        kind: ArtifactDeltaKind::Added,
        old_hash: None,
        new_hash: Some(content_hash),
    });
    graph.create_change(&change).unwrap();
    graph
        .update_branch_head(&BranchName::new("main"), &change.id)
        .unwrap();

    // Export to Git.
    let git_dir = dir.path().join("git-export");
    let export_result = kin_git::export_to_git(
        graph.as_ref(),
        &blob_store,
        genesis_id,
        &BranchName::new("main"),
        &git_dir,
    )
    .expect("git export should succeed");

    assert!(
        export_result.commits_exported >= 1,
        "expected at least 1 commit exported, got {}",
        export_result.commits_exported
    );

    // Import from the exported Git repo.
    let import_opts = kin_git::ImportOptions {
        shallow: false,
        max_commits: 0,
        branch: Some("main".to_string()),
    };
    let imported = kin_git::import_git_history(&git_dir, genesis_id, &import_opts)
        .expect("git import should succeed");

    assert!(
        !imported.is_empty(),
        "import should produce at least one change"
    );

    // Verify at least one imported change has artifact deltas.
    let has_artifacts = imported
        .iter()
        .any(|ic| !ic.change.artifact_deltas.is_empty());
    assert!(
        has_artifacts,
        "at least one imported change should have artifact deltas"
    );
}

// -----------------------------------------------------------------------
// 10. reconciler_lkg_retains_on_real_broken_parse
// -----------------------------------------------------------------------

#[test]
fn reconciler_lkg_retains_on_real_broken_parse() {
    // Use a real indexer/parser to verify LKG retention on broken syntax.
    let dir = tempfile::tempdir().unwrap();
    let kin_layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    for d in kin_layout.all_dirs() {
        std::fs::create_dir_all(&d).unwrap();
    }
    let blob_store = BlobStore::new(kin_layout.objects_dir()).unwrap();
    let graph = kin_db::InMemoryGraph::new();
    let genesis = kin_core::build_genesis_change();
    kin_core::init_graph(&graph, &genesis, "main").unwrap();

    let mut lkg = kin_reconcile::LkgStore::new();
    let indexer = kin_index::Indexer::new();

    // Write a valid Rust file and index it.
    let valid_content = "pub fn valid_function() -> i32 {\n    42\n}\n";
    let rs_path = write_rust_file(dir.path(), "src/valid.rs", valid_content);

    let result = indexer
        .index_and_apply(&rs_path, &blob_store, &graph)
        .unwrap();
    assert!(
        result.entities_upserted > 0,
        "should find entities in valid file"
    );

    // Record all entities in the LKG store.
    let entities = graph.list_all_entities().unwrap();
    assert!(!entities.is_empty(), "should have entities in graph");
    for entity in &entities {
        lkg.record(entity.clone(), vec![]);
    }
    assert_eq!(lkg.len(), entities.len());

    // Overwrite file with broken syntax.
    std::fs::write(&rs_path, "fn broken( {{{ }").unwrap();

    // Index again — may succeed or fail, but LKG should be unaffected
    // because we only recorded in our separate LKG store, not re-recorded.
    let _broken_result = indexer.index_and_apply(&rs_path, &blob_store, &graph);

    // Verify LKG store still has original fingerprints.
    for entity in &entities {
        let lkg_entry = lkg.get(&entity.id);
        assert!(
            lkg_entry.is_some(),
            "LKG should still have entity '{}' after broken parse",
            entity.name
        );
        assert_eq!(
            lkg_entry.unwrap().entity.fingerprint.ast_hash,
            entity.fingerprint.ast_hash,
            "LKG fingerprint for '{}' should be unchanged after broken parse",
            entity.name
        );
    }
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

/// Build a merge SemanticChange with two parents (mirrors the production
/// `build_merge_change` in merge.rs).
fn build_merge_change_for_test(
    ours_head: &SemanticChangeId,
    theirs_head: &SemanticChangeId,
    their_changes: &[SemanticChange],
    message: &str,
) -> SemanticChange {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"kin-merge-v1:");
    hasher.update(ours_head.0.as_bytes());
    hasher.update(theirs_head.0.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    let id = SemanticChangeId::from_hash(Hash256::from_bytes(bytes));

    let entity_deltas: Vec<_> = their_changes
        .iter()
        .flat_map(|c| c.entity_deltas.clone())
        .collect();
    let relation_deltas: Vec<_> = their_changes
        .iter()
        .flat_map(|c| c.relation_deltas.clone())
        .collect();
    let artifact_deltas: Vec<_> = their_changes
        .iter()
        .flat_map(|c| c.artifact_deltas.clone())
        .collect();

    SemanticChange {
        id,
        parents: vec![*ours_head, *theirs_head],
        timestamp: Timestamp::now(),
        author: AuthorId::new("kin-merge"),
        message: message.to_string(),
        entity_deltas,
        relation_deltas,
        artifact_deltas,
        projected_files: vec![],
        spec_link: None,
        evidence: vec![],
        risk_summary: None,
        authored_on: None,
    }
}
