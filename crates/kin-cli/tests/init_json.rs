// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_db::EntityStore;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn find_cache_graph_path(cache_dir: &Path) -> std::path::PathBuf {
    let mut stack = vec![cache_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read cache dir") {
            let entry = entry.expect("cache entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().and_then(|name| name.to_str()) == Some("graph.kndb") {
                return path;
            }
        }
    }
    panic!("graph.kndb not found under {}", cache_dir.display());
}

fn find_cache_manifest_path(cache_dir: &Path) -> std::path::PathBuf {
    let mut stack = vec![cache_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read cache dir") {
            let entry = entry.expect("cache entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().and_then(|name| name.to_str()) == Some("manifest.json") {
                return path;
            }
        }
    }
    panic!("manifest.json not found under {}", cache_dir.display());
}

fn git_head(path: &Path) -> String {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(path)
        .output()
        .expect("git rev-parse HEAD");
    assert!(
        output.status.success(),
        "git rev-parse HEAD failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8 git head")
        .trim()
        .to_string()
}

fn seed_cached_vectors(cache_graph_path: &Path) {
    let snapshot = kin_db::SnapshotManager::open(cache_graph_path).expect("open cache graph");
    let graph = snapshot.graph();
    let entities = graph
        .query_entities(&kin_model::EntityFilter::default())
        .expect("query cache entities");
    assert!(!entities.is_empty(), "cache graph should contain entities");

    let vector_path = cache_graph_path.with_extension("kvec.seed");
    let vectors = kin_db::VectorIndex::new(4).expect("create vector index");
    for (idx, entity) in entities.iter().enumerate() {
        let embedding = match idx % 3 {
            0 => [1.0, 0.0, 0.0, 0.0],
            1 => [0.0, 1.0, 0.0, 0.0],
            _ => [0.0, 0.0, 1.0, 0.0],
        };
        vectors
            .upsert(entity.id, &embedding)
            .expect("upsert cache vector");
    }
    vectors.save(&vector_path).expect("save cache vectors");
    graph
        .load_vector_index(&vector_path)
        .expect("load cache vectors into graph");
    snapshot.save().expect("persist cache vectors");
    fs::remove_file(&vector_path).expect("remove temp vector file");
}

fn init_git_repo(path: &Path, remote: &str) {
    fs::create_dir_all(path).expect("create repo dir");
    fs::write(path.join("README.md"), "hello\n").expect("write repo file");

    let init = Command::new("git")
        .args(["init"])
        .current_dir(path)
        .output()
        .expect("git init");
    assert!(init.status.success(), "git init failed");

    let commands: &[&[&str]] = &[
        &["config", "user.email", "kin@example.com"],
        &["config", "user.name", "Kin"],
        &["remote", "add", "origin", remote],
        &["add", "README.md"],
        &["commit", "-m", "init"],
    ];
    for args in commands {
        let output = Command::new("git")
            .args(*args)
            .current_dir(path)
            .output()
            .expect("git command");
        assert!(
            output.status.success(),
            "git {:?} failed: stdout={} stderr={}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn add_rust_source_and_commit(path: &Path) {
    fs::create_dir_all(path.join("src")).expect("create src dir");
    fs::write(
        path.join("src/lib.rs"),
        "pub fn retained_symbol() -> &'static str { \"retained\" }\n",
    )
    .expect("write rust source");
    let commands: &[&[&str]] = &[&["add", "src/lib.rs"], &["commit", "-m", "add source"]];
    for args in commands {
        let output = Command::new("git")
            .args(*args)
            .current_dir(path)
            .output()
            .expect("git command");
        assert!(
            output.status.success(),
            "git {:?} failed: stdout={} stderr={}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn checkout_branch_and_add_empty_commit(path: &Path, branch: &str) {
    let commands: &[&[&str]] = &[
        &["checkout", "-b", branch],
        &["commit", "--allow-empty", "-m", "branch marker"],
    ];
    for args in commands {
        let output = Command::new("git")
            .args(*args)
            .current_dir(path)
            .output()
            .expect("git command");
        assert!(
            output.status.success(),
            "git {:?} failed: stdout={} stderr={}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn init_json_reports_warm_cache_hits_for_same_repo_identity() {
    let root = tempdir().expect("temp root");
    let home_dir = root.path().join("home");
    let cache_dir = root.path().join("warm-cache");
    fs::create_dir_all(&home_dir).expect("create home");
    fs::create_dir_all(&cache_dir).expect("create cache");

    let remote = "https://example.com/acme/demo.git";
    let repo1 = root.path().join("repo1");
    let repo2 = root.path().join("repo2");
    init_git_repo(&repo1, remote);
    init_git_repo(&repo2, remote);

    let first = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["init", "--json", "."])
        .current_dir(&repo1)
        .env("HOME", &home_dir)
        .env("KIN_INIT_CACHE_DIR", &cache_dir)
        .output()
        .expect("run first kin init --json");
    assert!(
        first.status.success(),
        "first kin init --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let first_payload: Value =
        serde_json::from_slice(&first.stdout).expect("first init stdout should be json");
    assert_eq!(first_payload["schema"], "kin.init-result.v1");
    assert_eq!(first_payload["warm_cache_hit"], false);
    assert_eq!(first_payload["warm_text_index_reused"], false);
    assert_eq!(first_payload["warm_vector_index_reused"], false);
    assert_eq!(first_payload["warm_requeued_embeddings"], 0);
    assert!(first_payload["total_files"].as_u64().unwrap_or(0) >= 1);

    let second = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["init", "--json", "."])
        .current_dir(&repo2)
        .env("HOME", &home_dir)
        .env("KIN_INIT_CACHE_DIR", &cache_dir)
        .output()
        .expect("run second kin init --json");
    assert!(
        second.status.success(),
        "second kin init --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    let second_payload: Value =
        serde_json::from_slice(&second.stdout).expect("second init stdout should be json");
    assert_eq!(second_payload["schema"], "kin.init-result.v1");
    assert_eq!(second_payload["warm_cache_hit"], true);
    assert_eq!(second_payload["warm_text_index_reused"], true);
    assert_eq!(second_payload["warm_vector_index_reused"], false);
    assert_eq!(second_payload["warm_requeued_embeddings"], 0);
    assert_eq!(second_payload["warm_changed_files"], 0);
    assert_eq!(second_payload["warm_reparsed_files"], 0);
    assert!(second_payload["indexed_embeddings"].is_u64());
    assert!(second_payload["pending_embeddings"].is_u64());
}

#[test]
fn init_json_reports_vector_reuse_for_non_entity_warm_deltas() {
    let root = tempdir().expect("temp root");
    let home_dir = root.path().join("home");
    let cache_dir = root.path().join("warm-cache");
    fs::create_dir_all(&home_dir).expect("create home");
    fs::create_dir_all(&cache_dir).expect("create cache");

    let remote = "https://example.com/acme/demo-vector.git";
    let repo1 = root.path().join("repo1");
    let repo2 = root.path().join("repo2");
    init_git_repo(&repo1, remote);
    init_git_repo(&repo2, remote);
    add_rust_source_and_commit(&repo1);
    add_rust_source_and_commit(&repo2);
    fs::write(repo2.join("README.md"), "hello from feature branch\n").expect("update readme");

    let first = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["init", "--json", "."])
        .current_dir(&repo1)
        .env("HOME", &home_dir)
        .env("KIN_INIT_CACHE_DIR", &cache_dir)
        .output()
        .expect("run first kin init --json");
    assert!(
        first.status.success(),
        "first kin init --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );

    let cache_graph_path = find_cache_graph_path(&cache_dir);
    seed_cached_vectors(&cache_graph_path);

    let second = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["init", "--json", "."])
        .current_dir(&repo2)
        .env("HOME", &home_dir)
        .env("KIN_INIT_CACHE_DIR", &cache_dir)
        .output()
        .expect("run second kin init --json");
    assert!(
        second.status.success(),
        "second kin init --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );

    let second_payload: Value =
        serde_json::from_slice(&second.stdout).expect("second init stdout should be json");
    assert_eq!(second_payload["schema"], "kin.init-result.v1");
    assert_eq!(second_payload["warm_cache_hit"], true);
    assert_eq!(second_payload["warm_text_index_reused"], true);
    assert_eq!(second_payload["warm_vector_index_reused"], true);
    assert_eq!(second_payload["warm_requeued_embeddings"], 0);
    assert_eq!(second_payload["warm_changed_files"], 1);
    assert_eq!(second_payload["warm_reparsed_files"], 1);
    assert!(second_payload["indexed_embeddings"].as_u64().unwrap_or(0) >= 1);
    assert_eq!(second_payload["pending_embeddings"], 0);

    let support = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["support", "--json"])
        .current_dir(&repo2)
        .env("HOME", &home_dir)
        .output()
        .expect("run kin support --json");
    assert!(
        support.status.success(),
        "kin support --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&support.stdout),
        String::from_utf8_lossy(&support.stderr)
    );
    let support_payload: Value =
        serde_json::from_slice(&support.stdout).expect("support stdout should be json");
    assert!(
        support_payload["indexed_embedding_count"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );
    assert_eq!(support_payload["pending_embedding_count"], 0);

    let proof_dir = std::path::PathBuf::from("/tmp/workstreamA-vector-reuse-proof");
    fs::create_dir_all(&proof_dir).expect("create proof dir");
    let summary = serde_json::json!({
        "second_init": {
            "warm_cache_hit": second_payload["warm_cache_hit"],
            "warm_text_index_reused": second_payload["warm_text_index_reused"],
            "warm_vector_index_reused": second_payload["warm_vector_index_reused"],
            "warm_requeued_embeddings": second_payload["warm_requeued_embeddings"],
            "warm_changed_files": second_payload["warm_changed_files"],
            "warm_reparsed_files": second_payload["warm_reparsed_files"],
            "indexed_embeddings": second_payload["indexed_embeddings"],
            "pending_embeddings": second_payload["pending_embeddings"],
        },
        "reopened_support": {
            "indexed_embedding_count": support_payload["indexed_embedding_count"],
            "pending_embedding_count": support_payload["pending_embedding_count"],
            "total_entities": support_payload["total_entities"],
        }
    });
    fs::write(
        proof_dir.join("summary.json"),
        serde_json::to_string_pretty(&summary).expect("encode proof summary"),
    )
    .expect("write proof summary");
}

#[test]
fn init_json_reuses_immutable_bundle_for_identical_graph_truth() {
    let root = tempdir().expect("temp root");
    let home_dir = root.path().join("home");
    let cache_dir = root.path().join("warm-cache");
    fs::create_dir_all(&home_dir).expect("create home");
    fs::create_dir_all(&cache_dir).expect("create cache");

    let remote = "https://example.com/acme/demo-manifest.git";
    let repo1 = root.path().join("repo1");
    let repo2 = root.path().join("repo2");
    init_git_repo(&repo1, remote);
    init_git_repo(&repo2, remote);
    add_rust_source_and_commit(&repo1);
    add_rust_source_and_commit(&repo2);
    checkout_branch_and_add_empty_commit(&repo2, "feature");

    let first = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["init", "--json", "."])
        .current_dir(&repo1)
        .env("HOME", &home_dir)
        .env("KIN_INIT_CACHE_DIR", &cache_dir)
        .output()
        .expect("run first kin init --json");
    assert!(
        first.status.success(),
        "first kin init --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );

    let second = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["init", "--json", "."])
        .current_dir(&repo2)
        .env("HOME", &home_dir)
        .env("KIN_INIT_CACHE_DIR", &cache_dir)
        .output()
        .expect("run second kin init --json");
    assert!(
        second.status.success(),
        "second kin init --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );

    let second_payload: Value =
        serde_json::from_slice(&second.stdout).expect("second init stdout should be json");
    assert_eq!(second_payload["warm_cache_hit"], true);
    assert_eq!(second_payload["warm_changed_files"], 0);
    assert_eq!(second_payload["warm_reparsed_files"], 0);

    let manifest_path = find_cache_manifest_path(&cache_dir);
    let manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read cache manifest"))
            .expect("decode cache manifest");
    let current_bundle_id = manifest["current_bundle_id"]
        .as_str()
        .expect("current bundle id")
        .to_string();
    let repo1_head = git_head(&repo1);
    let repo2_head = git_head(&repo2);
    assert_ne!(repo1_head, repo2_head);
    assert_eq!(manifest["heads"][&repo1_head], current_bundle_id);
    assert_eq!(manifest["heads"][&repo2_head], current_bundle_id);

    let bundle_root = manifest_path
        .parent()
        .expect("manifest parent")
        .join("bundles");
    let bundle_dirs: Vec<_> = fs::read_dir(&bundle_root)
        .expect("read bundle root")
        .map(|entry| entry.expect("bundle entry").path())
        .collect();
    assert_eq!(bundle_dirs.len(), 1);
    assert_eq!(
        bundle_dirs[0].file_name().and_then(|name| name.to_str()),
        Some(current_bundle_id.as_str())
    );

    let proof_dir = std::path::PathBuf::from("/tmp/workstreamA-manifest-reuse-proof");
    fs::create_dir_all(&proof_dir).expect("create proof dir");
    let summary = serde_json::json!({
        "bundle_id": current_bundle_id,
        "repo1_head": repo1_head,
        "repo2_head": repo2_head,
        "bundle_dir_count": bundle_dirs.len(),
        "second_init": {
            "warm_cache_hit": second_payload["warm_cache_hit"],
            "warm_changed_files": second_payload["warm_changed_files"],
            "warm_reparsed_files": second_payload["warm_reparsed_files"],
        }
    });
    fs::write(
        proof_dir.join("summary.json"),
        serde_json::to_string_pretty(&summary).expect("encode proof summary"),
    )
    .expect("write proof summary");
}
