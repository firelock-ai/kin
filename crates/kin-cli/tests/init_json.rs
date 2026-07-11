// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[cfg(feature = "vector")]
use kin_db::EntityStore;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

#[cfg(feature = "vector")]
mod common;

#[cfg(feature = "vector")]
fn find_cache_graph_path(cache_dir: &Path) -> std::path::PathBuf {
    let manifest_path = find_cache_manifest_path(cache_dir);
    let manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read cache manifest"))
            .expect("decode cache manifest");
    if let Some(bundle_id) = manifest["current_bundle_id"].as_str() {
        let bundle_graph = manifest_path
            .parent()
            .expect("manifest parent")
            .join("bundles")
            .join(bundle_id)
            .join("graph.kndb");
        if bundle_graph.exists() {
            return bundle_graph;
        }
    }

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

#[cfg(feature = "vector")]
fn seed_cached_vectors(cache_graph_path: &Path) {
    let snapshot = kin_db::SnapshotManager::open(cache_graph_path).expect("open cache graph");
    let graph = snapshot.graph();
    let entities = graph
        .query_entities(&kin_model::EntityFilter::default())
        .expect("query cache entities");
    assert!(!entities.is_empty(), "cache graph should contain entities");
    let graph_snapshot = graph.to_snapshot();
    let entity_revision_ids = graph_snapshot
        .entity_revisions
        .values()
        .flat_map(|revisions| revisions.iter().map(|revision| revision.revision_id))
        .collect::<Vec<_>>();

    let artifact_ids = graph_snapshot
        .artifact_index
        .values()
        .copied()
        .collect::<Vec<_>>();

    let vector_path = cache_graph_path.with_extension("kvec");
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
    for (idx, artifact_id) in artifact_ids.iter().enumerate() {
        let embedding = match (idx + entities.len() + entity_revision_ids.len()) % 3 {
            0 => [1.0, 0.0, 0.0, 0.0],
            1 => [0.0, 1.0, 0.0, 0.0],
            _ => [0.0, 0.0, 1.0, 0.0],
        };
        vectors
            .upsert_retrievable(kin_model::RetrievalKey::Artifact(*artifact_id), &embedding)
            .expect("upsert cache artifact vector");
    }
    for (idx, revision_id) in entity_revision_ids.iter().enumerate() {
        let embedding = match (idx + entities.len()) % 3 {
            0 => [1.0, 0.0, 0.0, 0.0],
            1 => [0.0, 1.0, 0.0, 0.0],
            _ => [0.0, 0.0, 1.0, 0.0],
        };
        vectors
            .upsert_retrievable(
                kin_model::RetrievalKey::EntityRevision(*revision_id),
                &embedding,
            )
            .expect("upsert cache entity revision vector");
    }
    vectors.save(&vector_path).expect("save cache vectors");
    graph
        .load_vector_index(&vector_path)
        .expect("load cache vectors into graph");
    graph
        .save_vector_index(&cache_graph_path.with_extension("kvec"))
        .expect("persist cache vector index sidecar");
    snapshot.save().expect("persist cache vectors");
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
        let mut cmd = Command::new("git");
        cmd.args(*args);
        // Explicit increasing commit timestamps: order-sensitive fixtures must
        // not depend on wall-clock second granularity.
        if args.first() == Some(&"commit") {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COMMIT_EPOCH: AtomicU64 = AtomicU64::new(1_000_000_000);
            let date = format!("{} +0000", COMMIT_EPOCH.fetch_add(100, Ordering::Relaxed));
            cmd.env("GIT_AUTHOR_DATE", &date)
                .env("GIT_COMMITTER_DATE", &date);
        }
        let output = cmd.current_dir(path).output().expect("git command");
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
        let mut cmd = Command::new("git");
        cmd.args(*args);
        // Explicit increasing commit timestamps: order-sensitive fixtures must
        // not depend on wall-clock second granularity.
        if args.first() == Some(&"commit") {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COMMIT_EPOCH: AtomicU64 = AtomicU64::new(1_000_000_000);
            let date = format!("{} +0000", COMMIT_EPOCH.fetch_add(100, Ordering::Relaxed));
            cmd.env("GIT_AUTHOR_DATE", &date)
                .env("GIT_COMMITTER_DATE", &date);
        }
        let output = cmd.current_dir(path).output().expect("git command");
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
        let mut cmd = Command::new("git");
        cmd.args(*args);
        // Explicit increasing commit timestamps: order-sensitive fixtures must
        // not depend on wall-clock second granularity.
        if args.first() == Some(&"commit") {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COMMIT_EPOCH: AtomicU64 = AtomicU64::new(1_000_000_000);
            let date = format!("{} +0000", COMMIT_EPOCH.fetch_add(100, Ordering::Relaxed));
            cmd.env("GIT_AUTHOR_DATE", &date)
                .env("GIT_COMMITTER_DATE", &date);
        }
        let output = cmd.current_dir(path).output().expect("git command");
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
fn fresh_native_init_bootstraps_agent_docs_and_next_steps() {
    let root = tempdir().expect("temp root");
    let home_dir = root.path().join("home");
    let repo = root.path().join("native");
    fs::create_dir_all(&home_dir).expect("create home");

    let output = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(&repo)
        .args(["--git-history", "off"])
        .env("HOME", &home_dir)
        .output()
        .expect("run fresh native kin init");
    assert!(
        output.status.success(),
        "fresh native kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Fresh Kin-native repository ready."));
    assert!(stdout.contains("kin with --session codex"));
    assert!(stdout.contains("kin exec -- <command>"));
    assert!(stdout.contains("kin git export --output <path>"));

    let agents = fs::read_to_string(repo.join("AGENTS.md")).expect("read generated AGENTS.md");
    assert!(agents.contains("This repository is Kin-native."));
    assert!(agents.contains("Agent Coding Workflow"));
    assert!(agents.contains("semantic_locate"));
    assert!(agents.contains("get_context_pack"));
    assert!(agents.contains("trace_data_flow"));
    assert!(agents.contains("kin commit -m \"message\""));
    assert!(agents.contains("kin git export --output <path>"));
    assert!(repo.join(".kin/assistant-sync.toml").exists());

    let config = fs::read_to_string(repo.join(".kin/config.toml")).expect("read kin config");
    assert!(config.contains("mode = \"native\""));
    assert!(!repo.join(".git").exists());
}

#[test]
fn fresh_native_init_json_stays_machine_readable_and_bootstraps_docs() {
    let root = tempdir().expect("temp root");
    let home_dir = root.path().join("home");
    let repo = root.path().join("native-json");
    fs::create_dir_all(&home_dir).expect("create home");

    let output = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(&repo)
        .args(["--json", "--git-history", "off"])
        .env("HOME", &home_dir)
        .output()
        .expect("run fresh native kin init --json");
    assert!(
        output.status.success(),
        "fresh native kin init --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("fresh native init stdout should be json");
    assert_eq!(payload["schema"], "kin.init-result.v1");
    assert_eq!(payload["warm_cache_hit"], false);
    assert!(payload["total_files"].as_u64().unwrap_or(0) >= 1);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Fresh Kin-native repository ready."));
    assert!(!stdout.contains("kin with --session codex"));
    assert!(repo.join("AGENTS.md").exists());
    assert!(repo.join(".kin/assistant-sync.toml").exists());
}

#[test]
fn git_backed_init_does_not_emit_fresh_native_bootstrap() {
    let root = tempdir().expect("temp root");
    let home_dir = root.path().join("home");
    let repo = root.path().join("git-backed");
    fs::create_dir_all(&home_dir).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");

    let init = Command::new("git")
        .arg("init")
        .current_dir(&repo)
        .output()
        .expect("git init");
    assert!(
        init.status.success(),
        "git init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(&repo)
        .args(["--git-history", "off"])
        .env("HOME", &home_dir)
        .output()
        .expect("run git-backed kin init");
    assert!(
        output.status.success(),
        "git-backed kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Fresh Kin-native repository ready."));
    assert!(!stdout.contains("kin with --session codex"));
    assert!(!repo.join("AGENTS.md").exists());
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
    assert!(second_payload["warm_requeued_embeddings"].is_u64());
    assert_eq!(second_payload["warm_changed_files"], 0);
    assert_eq!(second_payload["warm_reparsed_files"], 0);
    assert!(second_payload["indexed_embeddings"].is_u64());
    assert!(second_payload["pending_embeddings"].is_u64());
}

#[cfg(feature = "vector")]
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
    assert_eq!(second_payload["warm_text_index_reused"], false);
    assert_eq!(second_payload["warm_vector_index_reused"], true);
    assert_eq!(second_payload["warm_requeued_embeddings"], 0);
    assert_eq!(second_payload["warm_changed_files"], 1);
    assert_eq!(second_payload["warm_reparsed_files"], 1);
    assert!(second_payload["indexed_embeddings"].as_u64().unwrap_or(0) >= 1);
    assert!(second_payload["pending_embeddings"].as_u64().unwrap_or(0) >= 1);

    let support = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["support", "--json"])
        .current_dir(&repo2)
        .env("HOME", &home_dir)
        .env("KIN_DAEMON_BIN", common::fresh_daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "30")
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
    assert!(
        support_payload["pending_embedding_count"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );

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
