// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#![cfg(feature = "vector")]

use kin_db::EntityStore;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::tempdir;

mod common;

fn git(path: &Path, args: &[&str]) -> Output {
    let output = Command::new("git")
        .args(args)
        .current_dir(path)
        .output()
        .expect("run git command");
    assert!(
        output.status.success(),
        "git {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn init_seed_repo(repo: &Path, remote: &str) {
    fs::create_dir_all(repo).expect("create repo dir");
    let init = Command::new("git")
        .args(["init"])
        .current_dir(repo)
        .output()
        .expect("git init");
    assert!(
        init.status.success(),
        "git init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    git(repo, &["config", "user.email", "kin@example.com"]);
    git(repo, &["config", "user.name", "Kin"]);
    git(repo, &["remote", "add", "origin", remote]);

    fs::write(repo.join("README.md"), "hello\n").expect("write README");
    fs::create_dir_all(repo.join("src")).expect("create src dir");
    fs::write(
        repo.join("src/lib.rs"),
        "pub fn retained_symbol() -> &'static str { \"retained\" }\n",
    )
    .expect("write source");
    git(repo, &["add", "README.md", "src/lib.rs"]);
    git(repo, &["commit", "-m", "seed repo"]);
    git(repo, &["branch", "-M", "main"]);
}

fn clone_same_repo_identity(source_repo: &Path, repo: &Path, remote: &str) {
    let clone = Command::new("git")
        .args([
            "clone",
            source_repo.to_str().expect("source repo path"),
            repo.to_str().expect("repo path"),
        ])
        .output()
        .expect("git clone");
    assert!(
        clone.status.success(),
        "git clone failed: stdout={} stderr={}",
        String::from_utf8_lossy(&clone.stdout),
        String::from_utf8_lossy(&clone.stderr)
    );
    git(repo, &["remote", "set-url", "origin", remote]);
}

fn seed_local_vectors(cache_graph_path: &Path) {
    let snapshot = kin_db::SnapshotManager::open(cache_graph_path).expect("open graph");
    let graph = snapshot.graph();
    let entities = graph
        .query_entities(&kin_model::EntityFilter::default())
        .expect("query entities");
    assert!(!entities.is_empty(), "graph should contain entities");
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
            .expect("upsert vector");
    }
    for (idx, artifact_id) in artifact_ids.iter().enumerate() {
        let embedding = match (idx + entities.len() + entity_revision_ids.len()) % 3 {
            0 => [1.0, 0.0, 0.0, 0.0],
            1 => [0.0, 1.0, 0.0, 0.0],
            _ => [0.0, 0.0, 1.0, 0.0],
        };
        vectors
            .upsert_retrievable(kin_model::RetrievalKey::Artifact(*artifact_id), &embedding)
            .expect("upsert artifact vector");
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
            .expect("upsert entity revision vector");
    }
    vectors.save(&vector_path).expect("save vector index");
    graph
        .load_vector_index(&vector_path)
        .expect("load vector index into graph");
    snapshot.save().expect("persist seeded vectors");
    fs::remove_file(vector_path).expect("remove temp vector file");
}

fn parse_json_output(output: &Output, context: &str) -> Value {
    assert!(
        output.status.success(),
        "{} failed: stdout={} stderr={}",
        context,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout should be valid json")
}

fn kin(repo: &Path, kin_home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
    command
        .current_dir(repo)
        .env("KIN_HOME", kin_home)
        .env("KIN_REGISTRY_PATH", kin_home.join("registry.toml"))
        .env_remove("KIN_DAEMON_URL")
        .env_remove("KIN_SUPERVISOR_URL")
        .env_remove("KIN_SESSION_ID");
    command
}

#[test]
fn prepared_state_publish_and_materialize_preserve_indexed_state() {
    let root = tempdir().expect("temp root");
    let repo1 = root.path().join("repo1");
    let repo2 = root.path().join("repo2");
    let prepared_dir = root.path().join("prepared");
    let kin_home = root.path().join("kin-home");
    let remote = "https://example.com/acme/prepared-state.git";

    init_seed_repo(&repo1, remote);
    clone_same_repo_identity(&repo1, &repo2, remote);

    let init = kin(&repo1, &kin_home)
        .args(["init", "--json", "."])
        .output()
        .expect("run kin init");
    let init_payload = parse_json_output(&init, "kin init --json");
    assert_eq!(init_payload["schema"], "kin.init-result.v1");

    seed_local_vectors(&repo1.join(".kin/kindb/graph.kndb"));

    let publish = kin(&repo1, &kin_home)
        .args([
            "prepared-state",
            "publish",
            "--json",
            "--target",
            prepared_dir.to_str().expect("prepared dir"),
        ])
        .output()
        .expect("run kin prepared-state publish");
    let publish_payload = parse_json_output(&publish, "kin prepared-state publish --json");
    assert_eq!(publish_payload["schema"], "kin.prepared-state.publish.v1");
    assert_eq!(publish_payload["text_index_present"], true);
    assert_eq!(publish_payload["vector_index_present"], true);

    let materialize = kin(&repo2, &kin_home)
        .args([
            "prepared-state",
            "materialize",
            "--json",
            "--source",
            prepared_dir.to_str().expect("prepared dir"),
        ])
        .output()
        .expect("run kin prepared-state materialize");
    let materialize_payload =
        parse_json_output(&materialize, "kin prepared-state materialize --json");
    assert_eq!(
        materialize_payload["schema"],
        "kin.prepared-state.materialize.v1"
    );
    assert_eq!(materialize_payload["validated"], true);
    assert_eq!(
        materialize_payload["cache_key"],
        publish_payload["cache_key"]
    );

    let support = kin(&repo2, &kin_home)
        .args(["support", "--json"])
        .env("KIN_DAEMON_BIN", common::fresh_daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "30")
        .output()
        .expect("run kin support --json");
    let support_payload = parse_json_output(&support, "kin support --json");
    assert!(
        support_payload["text_indexed_entity_count"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert!(
        support_payload["indexed_embedding_count"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert_eq!(support_payload["pending_embedding_count"], 0);

    let artifact_dir = root.path().join("proof-artifact");
    fs::create_dir_all(&artifact_dir).expect("create proof artifact dir");
    fs::write(
        artifact_dir.join("publish.json"),
        serde_json::to_string_pretty(&publish_payload).expect("serialize publish payload"),
    )
    .expect("write publish artifact");
    fs::write(
        artifact_dir.join("materialize.json"),
        serde_json::to_string_pretty(&materialize_payload).expect("serialize materialize payload"),
    )
    .expect("write materialize artifact");
    fs::write(
        artifact_dir.join("support.json"),
        serde_json::to_string_pretty(&support_payload).expect("serialize support payload"),
    )
    .expect("write support artifact");
    let summary = serde_json::json!({
        "publish": {
            "schema": publish_payload["schema"].clone(),
            "cache_key": publish_payload["cache_key"].clone(),
            "text_index_present": publish_payload["text_index_present"].clone(),
            "vector_index_present": publish_payload["vector_index_present"].clone(),
        },
        "materialize": {
            "schema": materialize_payload["schema"].clone(),
            "cache_key": materialize_payload["cache_key"].clone(),
            "validated": materialize_payload["validated"].clone(),
        },
        "reopened_support": {
            "text_indexed_entity_count": support_payload["text_indexed_entity_count"].clone(),
            "indexed_embedding_count": support_payload["indexed_embedding_count"].clone(),
            "pending_embedding_count": support_payload["pending_embedding_count"].clone(),
        }
    });
    fs::write(
        artifact_dir.join("summary.json"),
        serde_json::to_string_pretty(&summary).expect("serialize summary"),
    )
    .expect("write summary artifact");
}

#[test]
fn prepared_state_materialize_rejects_repo_state_mismatch() {
    let root = tempdir().expect("temp root");
    let repo1 = root.path().join("repo1");
    let repo2 = root.path().join("repo2");
    let prepared_dir = root.path().join("prepared");
    let kin_home = root.path().join("kin-home");
    let remote = "https://example.com/acme/prepared-state.git";

    init_seed_repo(&repo1, remote);
    clone_same_repo_identity(&repo1, &repo2, remote);

    let init = kin(&repo1, &kin_home)
        .args(["init", "--json", "."])
        .output()
        .expect("run kin init");
    let _ = parse_json_output(&init, "kin init --json");

    seed_local_vectors(&repo1.join(".kin/kindb/graph.kndb"));

    let publish = kin(&repo1, &kin_home)
        .args([
            "prepared-state",
            "publish",
            "--json",
            "--target",
            prepared_dir.to_str().expect("prepared dir"),
        ])
        .output()
        .expect("run kin prepared-state publish");
    let _ = parse_json_output(&publish, "kin prepared-state publish --json");

    git(&repo2, &["config", "user.email", "kin@example.com"]);
    git(&repo2, &["config", "user.name", "Kin"]);
    git(&repo2, &["commit", "--allow-empty", "-m", "drift"]);

    let materialize = kin(&repo2, &kin_home)
        .args([
            "prepared-state",
            "materialize",
            "--json",
            "--source",
            prepared_dir.to_str().expect("prepared dir"),
        ])
        .output()
        .expect("run kin prepared-state materialize");
    assert!(
        !materialize.status.success(),
        "materialize unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&materialize.stdout),
        String::from_utf8_lossy(&materialize.stderr)
    );
    let stderr = String::from_utf8_lossy(&materialize.stderr);
    assert!(
        stderr.contains("cache key mismatch") || stderr.contains("git head mismatch"),
        "unexpected materialize stderr: {stderr}"
    );
}
