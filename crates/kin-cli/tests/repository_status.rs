// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Every case here drives the retained no-follow projection, which only Unix
// implements, so the whole binary is scoped to that platform.
#![cfg(unix)]

use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

fn run_git(path: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .current_dir(path)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_kin(repo: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(args)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("KIN_DAEMON_URL")
        .env_remove("KIN_VFS_WORKSPACE")
        .current_dir(repo)
        .output()
        .expect("run kin")
}

#[cfg(unix)]
#[test]
fn status_is_one_exact_authority_lease_and_ignores_checkout_and_git_drift() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");

    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::write(
        repo.join("compose.yaml"),
        b"services:\n  api:\n    build: .\n",
    )
    .expect("write Compose file");
    fs::write(repo.join("Dockerfile"), b"FROM scratch\n").expect("write Dockerfile");
    fs::write(repo.join("payload.bin"), [0_u8, 255, 17, 0, 128, 42]).expect("write opaque payload");
    fs::write(repo.join("tool"), b"#!/bin/sh\nexit 0\n").expect("write tool");
    let mut permissions = fs::metadata(repo.join("tool")).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(repo.join("tool"), permissions).expect("mark executable");
    symlink("compose.yaml", repo.join("compose-link")).expect("create symlink");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "exact mixed tree"]);

    let init = run_kin(&repo, &home, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let before = run_kin(&repo, &home, &["status", "--json"]);
    // A canonical authority read succeeds independently of projection drift
    // or daemon availability.
    assert!(
        before.status.success(),
        "status answered {:?}: stdout={} stderr={}",
        before.status.code(),
        String::from_utf8_lossy(&before.stdout),
        String::from_utf8_lossy(&before.stderr)
    );
    let before_report: Value =
        serde_json::from_slice(&before.stdout).expect("status stdout should be JSON");
    assert_eq!(before_report["schema"], "kin.status.v3");
    assert_eq!(before_report["authority"], "repository-v6");
    assert_eq!(before_report["repository"]["generation"], 1);
    assert_eq!(before_report["repository"]["source_cas_verified"], true);
    assert_eq!(before_report["repository"]["ref_count"], 1);
    assert_eq!(
        before_report["repository"]["default_ref"]["bytes_hex"],
        "726566732f68656164732f6d61696e"
    );
    assert_eq!(before_report["workspace"]["head"]["type"], "symbolic");
    assert_eq!(before_report["workspace"]["dirty"], false);
    assert_eq!(before_report["workspace"]["artifact_count"], 5);
    assert_eq!(
        before_report["semantic_enrichment"]["view"],
        "durable_repository_authority"
    );
    assert_eq!(
        before_report["semantic_enrichment"]["authority_generation"],
        before_report["repository"]["generation"]
    );
    assert_eq!(
        before_report["semantic_enrichment"]["workspace_generation"],
        before_report["workspace"]["generation"]
    );
    assert_eq!(before_report["semantic_enrichment"]["presence"], "absent");
    assert_eq!(
        before_report["semantic_enrichment"]["completion_attested"],
        false
    );
    assert_eq!(
        before_report["semantic_enrichment"]["semantic_change_count"],
        1
    );
    // No daemon holds this repository, so there is no live graph to sample and
    // no vector index behind it. Status has to say that rather than publish the
    // zero an unindexed graph would produce, which is the reading a fully
    // embedded repository would be indistinguishable from.
    assert_eq!(
        before_report["embedding_coverage"]["state"], "unobserved",
        "coverage cannot be observed with no daemon running: {}",
        before_report["embedding_coverage"]
    );
    assert_eq!(
        before_report["embedding_coverage"]["reason"],
        "no_running_daemon"
    );
    assert!(
        before_report["embedding_coverage"].get("indexed").is_none(),
        "an unobserved coverage must carry no count: {}",
        before_report["embedding_coverage"]
    );

    // Make the checkout and Git metadata maximally misleading. Status must
    // remain byte-for-byte authority-derived: no raw file walk, Git query, or
    // repair from these surfaces is permitted.
    fs::rename(repo.join(".git"), repo.join("git-authority-disabled")).expect("hide Git metadata");
    fs::write(repo.join("compose.yaml"), b"services: {}\n").expect("drift Compose file");
    fs::remove_file(repo.join("Dockerfile")).expect("delete Dockerfile");
    fs::remove_file(repo.join("payload.bin")).expect("delete opaque payload");
    fs::remove_file(repo.join("compose-link")).expect("delete symlink");
    let mut permissions = fs::metadata(repo.join("tool")).unwrap().permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(repo.join("tool"), permissions).expect("remove executable bit");
    fs::write(
        repo.join("unrelated.unsupported"),
        b"not repository truth\n",
    )
    .expect("add unrelated file");

    let after = run_kin(&repo, &home, &["status", "--json"]);
    // A canonical authority read succeeds independently of projection drift
    // or daemon availability.
    assert!(
        after.status.success(),
        "status answered {:?}: stdout={} stderr={}",
        after.status.code(),
        String::from_utf8_lossy(&after.stdout),
        String::from_utf8_lossy(&after.stderr)
    );
    let after_report: Value =
        serde_json::from_slice(&after.stdout).expect("status stdout should remain JSON");
    assert_eq!(
        after_report, before_report,
        "checkout or Git drift influenced repository-v6 status"
    );
}

fn seeded_status_repository(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let home = root.join("home");
    let repo = root.join("repo");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repo).unwrap();
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "status@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Status fixture"]);
    fs::write(repo.join("source.rs"), "pub fn canonical() -> u32 { 7 }\n").unwrap();
    run_git(&repo, &["add", "."]);
    run_git(&repo, &["commit", "-m", "Canonical source"]);
    let initialized = run_kin(&repo, &home, &["init", "--no-enrich", "--json"]);
    assert!(
        matches!(initialized.status.code(), Some(0) | Some(7) | Some(8)),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    (repo, home)
}

fn inspect_canonical_status(repo: &Path) -> kin_cli::commands::status::StatusReport {
    let layout = kin_core::KinLayout::discover(repo).unwrap();
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap();
    kin_cli::commands::status::inspect(
        &layout,
        &binding,
        kin_cli::commands::status::EmbeddingCoverage::unobserved(
            kin_cli::commands::status::EmbeddingCoverageUnobserved::NoRunningDaemon,
        ),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_status_crosses_only_read_http_boundaries_and_keeps_persisted_authority() {
    use std::sync::{Arc, Mutex};
    let root = tempdir().unwrap();
    let (repo, home) = seeded_status_repository(root.path());
    let before = inspect_canonical_status(&repo);
    let projection = "pub fn unadmitted() -> u32 { 999 }\n";
    fs::write(repo.join("source.rs"), projection).unwrap();
    fs::write(repo.join("untracked.rs"), "pub fn untracked() {}\n").unwrap();
    let marker = repo.join(".kin/last-admission.json");
    let marker_before = fs::read(&marker).ok();
    let response = serde_json::to_value(kin_cli::commands::status::CommandStatusResponse {
        report: before.clone(),
        build: None,
        text: String::new(),
        json: None,
        merge: None,
        workspace_tip: None,
        authority_readings_taken: false,
    })
    .unwrap();
    let health = serde_json::json!({
        "status": "ok", "version": "fixture", "uptime_seconds": 1,
        "graph_loaded": true, "reconciliation_status": "idle",
        "repo_id": before.repository.repository_id, "repo_root": before.repo_root,
    });
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&requests);
    let app = axum::Router::new().fallback(axum::routing::any(move |method: axum::http::Method, uri: axum::http::Uri| {
        captured.lock().unwrap().push(format!("{method} {}", uri.path()));
        let response = response.clone();
        let health = health.clone();
        async move {
            match (method.as_str(), uri.path()) {
                ("GET", "/readiness") => (axum::http::StatusCode::OK, axum::Json(serde_json::json!({"ready": true, "warming": false}))),
                ("GET", "/health") => (axum::http::StatusCode::OK, axum::Json(health)),
                ("POST", "/commands/status") => (axum::http::StatusCode::OK, axum::Json(response)),
                _ => (axum::http::StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "status must not request admission or any mutation"}))),
            }
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    for json in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
        command
            .arg("status")
            .env("HOME", &home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("KIN_DAEMON_URL", format!("http://127.0.0.1:{port}"))
            .current_dir(&repo);
        if json {
            command.arg("--json");
        }
        let output = command.output().unwrap();
        assert!(
            !requests
                .lock()
                .unwrap()
                .iter()
                .any(|path| path == "POST /commands/admit"),
            "default status requested admission: {:?}",
            requests.lock().unwrap()
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if json {
            let report: kin_cli::commands::status::StatusReport =
                serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report, before, "strict v3 JSON remains canonical authority");
        } else {
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(
                text.contains("Read-only status: canonical repository/workspace authority"),
                "{text}"
            );
            assert!(
                text.contains("working-copy contents were not inspected or admitted"),
                "{text}"
            );
            assert!(text.contains("Admission freshness:"), "{text}");
            assert!(!text.contains("Exit 9"), "{text}");
        }
    }
    server.abort();
    assert!(requests
        .lock()
        .unwrap()
        .iter()
        .any(|path| path == "POST /commands/status"));
    assert!(
        requests.lock().unwrap().iter().all(|path| matches!(
            path.as_str(),
            "GET /health" | "GET /readiness" | "POST /commands/status"
        )),
        "{:?}",
        requests.lock().unwrap()
    );
    assert_eq!(
        inspect_canonical_status(&repo),
        before,
        "canonical roots and generations changed"
    );
    assert_eq!(
        fs::read_to_string(repo.join("source.rs")).unwrap(),
        projection
    );
    assert!(repo.join("untracked.rs").exists());
    assert_eq!(
        fs::read(&marker).ok(),
        marker_before,
        "status rewrote admission freshness"
    );
}

#[test]
fn read_only_status_needs_no_author_or_daemon_and_real_authority_errors_still_fail() {
    let root = tempdir().unwrap();
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repo).unwrap();
    let initialized = kin_core::init(&repo).unwrap();
    {
        let _identity_env = kin_core::test_env::EnvVarGuard::new()
            .with("GIT_CONFIG_NOSYSTEM", "1")
            .with("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
            .with("HOME", &home)
            .without("XDG_CONFIG_HOME");
        assert!(
            kin_core::resolve_commit_identity(&initialized.layout).is_err(),
            "the fixture unexpectedly has a commit author"
        );
    }
    fs::write(repo.join("unadmitted.rs"), "pub fn unadmitted() {}\n").unwrap();
    let before = inspect_canonical_status(&repo);
    for args in [
        vec!["status"],
        vec!["status", "--json", "--wait-quiesce", "1"],
    ] {
        let output = run_kin(&repo, &home, &args);
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !repo.join(".kin/daemon.pid").exists(),
            "status started a daemon"
        );
    }
    assert_eq!(inspect_canonical_status(&repo), before);
    let outside = root.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let invalid = run_kin(&outside, &home, &["status", "--json"]);
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("not a Kin repository"));
}

#[test]
fn read_only_status_refuses_corrupt_canonical_source_without_repairing_from_projection() {
    let root = tempdir().unwrap();
    let (repo, home) = seeded_status_repository(root.path());
    let before = inspect_canonical_status(&repo);
    let layout = kin_core::KinLayout::discover(&repo).unwrap();
    let hash = kin_blobs::digest(b"pub fn canonical() -> u32 { 7 }\n").to_string();
    let blob = layout
        .kindb_namespace_path(before.repository.repository_id.as_str())
        .join("source-blobs/sha256")
        .join(&hash[..2])
        .join(&hash);
    assert!(
        blob.is_file(),
        "the fixture must corrupt the actual repository-owned body"
    );
    fs::write(&blob, b"corrupt canonical body").unwrap();
    let output = run_kin(&repo, &home, &["status", "--json"]);
    assert!(
        !output.status.success(),
        "a corrupt authority read cannot report success"
    );
    assert!(
        !output.stderr.is_empty(),
        "the canonical refusal must have a cause"
    );
    assert_eq!(fs::read(&blob).unwrap(), b"corrupt canonical body");
    assert_eq!(
        fs::read(repo.join("source.rs")).unwrap(),
        b"pub fn canonical() -> u32 { 7 }\n"
    );
}
