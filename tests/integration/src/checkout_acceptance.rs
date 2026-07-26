// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Checkout acceptance tests: verify file-level restore from semantic history.

use kin_blobs::BlobStore;
use kin_model::*;

use crate::helpers::*;

/// Convert a kin_blobs::Hash256 to a kin_model::Hash256 for use in a TreeEntry.
fn blob_to_model_hash(h: &kin_blobs::Hash256) -> Hash256 {
    Hash256::from_bytes(h.0)
}

/// Convert a kin_model::Hash256 to a kin_blobs::Hash256 for blob store lookup.
fn model_to_blob_hash(h: &Hash256) -> kin_blobs::Hash256 {
    kin_blobs::Hash256(*h.as_bytes())
}

// -----------------------------------------------------------------------
// 1. Checkout restores a file from the current branch HEAD
// -----------------------------------------------------------------------

#[test]
fn checkout_restores_file_from_branch_head() {
    let (dir, graph, genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();

    // Write a file and store its content in the blob store
    let content = b"fn main() { println!(\"hello\"); }";
    let blob_hash = blob_store.write(content).unwrap();

    // Create a SemanticChange with a tree delta for this file
    let file_id = FilePathId::new("src/main.rs");
    let entry = TreeEntry::regular(blob_to_model_hash(&blob_hash), false);
    let change = {
        let mut c = make_change(genesis_id, vec![], "add main.rs");
        c.tree_deltas.push(TreeDelta::Added {
            file_id: file_id.clone(),
            new_entry: entry,
        });
        c
    };

    graph.create_change(&change).unwrap();
    graph
        .update_branch_head(&BranchName::new("main"), &change.id)
        .unwrap();

    // Build the file tree and verify the file is present
    let tree = kin_core::build_file_tree(graph.as_ref(), &genesis_id, &change.id).unwrap();
    assert!(tree.contains_key(&file_id), "file should be in tree");

    // Read back the blob content using the entry from the tree
    let stored = tree.get(&file_id).unwrap();
    assert_eq!(
        *stored, entry,
        "tree entry should match the exact entry the change recorded"
    );
    let stored_blob = model_to_blob_hash(&stored.blob_hash);
    let restored = blob_store.read(&stored_blob).unwrap();
    assert_eq!(restored, content, "blob content should match original");

    // Write a different version to disk (simulating a dirty working copy)
    let dest = dir.path().join("src/main.rs");
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    std::fs::write(&dest, b"fn main() { println!(\"MODIFIED\"); }").unwrap();

    // Now simulate what `kin checkout` does: restore from the graph
    let tree = kin_core::build_file_tree(graph.as_ref(), &genesis_id, &change.id).unwrap();
    let head_entry = tree.get(&file_id).unwrap();
    let head_blob = model_to_blob_hash(&head_entry.blob_hash);
    let original_content = blob_store.read(&head_blob).unwrap();
    std::fs::write(&dest, &original_content).unwrap();

    // Verify the file was restored
    let on_disk = std::fs::read(&dest).unwrap();
    assert_eq!(on_disk, content, "checkout should restore original content");
}

// -----------------------------------------------------------------------
// 2. Checkout restores from a specific change (not HEAD)
// -----------------------------------------------------------------------

#[test]
fn checkout_restores_from_specific_change() {
    let (dir, graph, genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();

    let file_id = FilePathId::new("src/lib.rs");

    // Version 1
    let content_v1 = b"pub fn version() -> u32 { 1 }";
    let hash_v1 = blob_store.write(content_v1).unwrap();
    let entry_v1 = TreeEntry::regular(blob_to_model_hash(&hash_v1), false);
    let change_v1 = {
        let mut c = make_change(genesis_id, vec![], "v1");
        c.tree_deltas.push(TreeDelta::Added {
            file_id: file_id.clone(),
            new_entry: entry_v1,
        });
        c
    };
    graph.create_change(&change_v1).unwrap();

    // Version 2
    let content_v2 = b"pub fn version() -> u32 { 2 }";
    let hash_v2 = blob_store.write(content_v2).unwrap();
    let entry_v2 = TreeEntry::regular(blob_to_model_hash(&hash_v2), false);
    let change_v2 = {
        let mut c = make_change(change_v1.id, vec![], "v2");
        c.tree_deltas.push(TreeDelta::Modified {
            file_id: file_id.clone(),
            old_entry: entry_v1,
            new_entry: entry_v2,
        });
        c
    };
    graph.create_change(&change_v2).unwrap();
    graph
        .update_branch_head(&BranchName::new("main"), &change_v2.id)
        .unwrap();

    // HEAD points to v2, but checkout from change_v1 should give v1
    let tree_v1 = kin_core::build_file_tree(graph.as_ref(), &genesis_id, &change_v1.id).unwrap();
    let entry = tree_v1.get(&file_id).unwrap();
    assert_eq!(*entry, entry_v1, "tree at v1 should hold the v1 entry");
    let blob = model_to_blob_hash(&entry.blob_hash);
    let restored = blob_store.read(&blob).unwrap();
    assert_eq!(
        restored, content_v1,
        "checkout at v1 should return v1 content"
    );

    // And checkout at HEAD (v2) gives v2
    let tree_v2 = kin_core::build_file_tree(graph.as_ref(), &genesis_id, &change_v2.id).unwrap();
    let entry = tree_v2.get(&file_id).unwrap();
    assert_eq!(*entry, entry_v2, "tree at v2 should hold the v2 entry");
    let blob = model_to_blob_hash(&entry.blob_hash);
    let restored = blob_store.read(&blob).unwrap();
    assert_eq!(
        restored, content_v2,
        "checkout at v2 should return v2 content"
    );
}

// -----------------------------------------------------------------------
// 3. Checkout handles removed files correctly
// -----------------------------------------------------------------------

#[test]
fn checkout_removed_file_not_in_tree() {
    let (dir, graph, genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();

    let file_id = FilePathId::new("src/temp.rs");

    // Add file
    let content = b"// temporary file";
    let hash = blob_store.write(content).unwrap();
    let entry = TreeEntry::regular(blob_to_model_hash(&hash), false);
    let change_add = {
        let mut c = make_change(genesis_id, vec![], "add temp");
        c.tree_deltas.push(TreeDelta::Added {
            file_id: file_id.clone(),
            new_entry: entry,
        });
        c
    };
    graph.create_change(&change_add).unwrap();

    // Remove file
    let change_rm = {
        let mut c = make_change(change_add.id, vec![], "remove temp");
        c.tree_deltas.push(TreeDelta::Removed {
            file_id: file_id.clone(),
            old_entry: entry,
        });
        c
    };
    graph.create_change(&change_rm).unwrap();
    graph
        .update_branch_head(&BranchName::new("main"), &change_rm.id)
        .unwrap();

    // At HEAD, the file should NOT be in the tree
    let tree = kin_core::build_file_tree(graph.as_ref(), &genesis_id, &change_rm.id).unwrap();
    assert!(
        !tree.contains_key(&file_id),
        "removed file should not be in tree at HEAD"
    );

    // But at the add-change, it should be
    let tree_before =
        kin_core::build_file_tree(graph.as_ref(), &genesis_id, &change_add.id).unwrap();
    assert_eq!(
        tree_before.get(&file_id),
        Some(&entry),
        "file should be in tree at the change that added it"
    );
}

// -----------------------------------------------------------------------
// 4. Build file tree with multiple files
// -----------------------------------------------------------------------

#[test]
fn checkout_multiple_files_in_tree() {
    let (dir, graph, genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();

    let files: Vec<(&str, &[u8])> = vec![
        ("src/a.rs", b"fn a() {}"),
        ("src/b.rs", b"fn b() {}"),
        ("src/nested/c.rs", b"fn c() {}"),
    ];

    let mut deltas = vec![];
    for (path, content) in &files {
        let hash = blob_store.write(content).unwrap();
        deltas.push(TreeDelta::Added {
            file_id: FilePathId::new(*path),
            new_entry: TreeEntry::regular(blob_to_model_hash(&hash), false),
        });
    }

    let change = {
        let mut c = make_change(genesis_id, vec![], "add three files");
        c.tree_deltas = deltas;
        c
    };
    graph.create_change(&change).unwrap();
    graph
        .update_branch_head(&BranchName::new("main"), &change.id)
        .unwrap();

    let tree = kin_core::build_file_tree(graph.as_ref(), &genesis_id, &change.id).unwrap();
    assert_eq!(tree.len(), 3);
    assert!(tree.contains_key(&FilePathId::new("src/a.rs")));
    assert!(tree.contains_key(&FilePathId::new("src/b.rs")));
    assert!(tree.contains_key(&FilePathId::new("src/nested/c.rs")));

    // Verify content and exact mode roundtrip
    for (path, expected_content) in &files {
        let entry = tree.get(&FilePathId::new(*path)).unwrap();
        assert_eq!(
            entry.kind,
            TreeEntryKind::Regular { executable: false },
            "mode mismatch for {path}"
        );
        let blob = model_to_blob_hash(&entry.blob_hash);
        let actual = blob_store.read(&blob).unwrap();
        assert_eq!(actual, *expected_content, "content mismatch for {}", path);
    }
}
