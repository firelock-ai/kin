// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Phase 7 acceptance tests: sessions, intents, traffic-aware context,
//! collision enforcement, contract/artifact scopes, orphan sweep.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kin_daemon::session_registry::SessionCoordinator;
use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::*;

use crate::helpers::*;

fn writable_capabilities() -> SessionCapabilities {
    SessionCapabilities {
        can_write: true,
        ..SessionCapabilities::default()
    }
}

// -----------------------------------------------------------------------
// 8. Session lifecycle: register -> heartbeat -> verify active -> end -> gone
// -----------------------------------------------------------------------

#[test]
fn session_full_lifecycle() {
    let (_dir, graph, _genesis_id) = init_kin_repo();
    let coord = SessionCoordinator::new(graph.clone());

    // Register a session.
    let sid = coord
        .register_session(
            "claude-code",
            "test-session",
            SessionTransport::Mcp,
            Some(std::process::id()),
            PathBuf::from("/project"),
            SessionCapabilities::default(),
        )
        .unwrap();

    // Verify the session is active.
    let session = coord.get_session(&sid).unwrap();
    assert!(session.is_some());
    let session = session.unwrap();
    assert_eq!(session.vendor, "claude-code");
    assert_eq!(session.transport, SessionTransport::Mcp);

    // Send a heartbeat.
    coord.heartbeat(&sid).unwrap();

    // Verify session is still active.
    let session = coord.get_session(&sid).unwrap();
    assert!(session.is_some());

    // Deregister the session.
    coord.deregister_session(&sid).unwrap();

    // Verify the session is gone.
    let session = coord.get_session(&sid).unwrap();
    assert!(session.is_none());
}

// -----------------------------------------------------------------------
// 9. Intent registration: hard lock -> conflicting intent -> HardCollision
// -----------------------------------------------------------------------

#[test]
fn intent_hard_collision_blocks_second_agent() {
    let (_dir, graph, _genesis_id) = init_kin_repo();
    let coord = SessionCoordinator::new(graph.clone());

    // Create a test entity in the graph.
    let entity = make_entity("payment_handler", "src/payment.rs", EntityKind::Function);
    graph.upsert_entity(&entity).unwrap();

    // Register two sessions (simulating two AI agents).
    let s1 = coord
        .register_session(
            "claude-code",
            "agent-1",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/project"),
            writable_capabilities(),
        )
        .unwrap();

    let s2 = coord
        .register_session(
            "codex",
            "agent-2",
            SessionTransport::Cli,
            None,
            PathBuf::from("/project"),
            writable_capabilities(),
        )
        .unwrap();

    // Agent 1 registers a hard lock on the entity.
    let r1 = coord
        .register_intent(
            &s1,
            vec![IntentScope::Entity(entity.id)],
            LockType::Hard,
            "refactoring payment handler",
            None,
        )
        .unwrap();

    match r1 {
        kin_daemon::session_registry::IntentRegistrationResult::Registered {
            intent_id, ..
        } => {
            // Good, agent 1's intent registered.
            assert!(!intent_id.to_string().is_empty());
        }
        _ => panic!("expected agent 1's intent to register successfully"),
    }

    // Agent 2 attempts a hard lock on the same entity — should be blocked.
    let r2 = coord
        .register_intent(
            &s2,
            vec![IntentScope::Entity(entity.id)],
            LockType::Hard,
            "also editing payment handler",
            None,
        )
        .unwrap();

    match r2 {
        kin_daemon::session_registry::IntentRegistrationResult::Blocked { conflicts, .. } => {
            assert!(!conflicts.is_empty());
            assert_eq!(conflicts[0].vendor, "claude-code");
        }
        _ => panic!("expected agent 2's intent to be blocked by hard collision"),
    }
}

// -----------------------------------------------------------------------
// 10. Traffic-aware context: register intent -> request context with traffic
// -----------------------------------------------------------------------

#[test]
fn traffic_aware_context_pack_includes_traffic() {
    let (_dir, graph, _genesis_id) = init_kin_repo();
    let coord = SessionCoordinator::new(graph.clone());

    // Create entities.
    let focal = make_entity("auth_service", "src/auth.rs", EntityKind::Function);
    graph.upsert_entity(&focal).unwrap();

    // Register a session with an intent on the focal entity.
    let sid = coord
        .register_session(
            "codex",
            "nearby-agent",
            SessionTransport::Cli,
            None,
            PathBuf::from("/project"),
            SessionCapabilities::default(),
        )
        .unwrap();

    let _reg = coord
        .register_intent(
            &sid,
            vec![IntentScope::Entity(focal.id)],
            LockType::Soft,
            "reviewing auth module",
            None,
        )
        .unwrap();

    // Build the nearby_intents list from the session coordinator.
    let intents = coord.list_intents(&sid).unwrap();
    let nearby: Vec<IntentSummary> = intents
        .iter()
        .map(|i| IntentSummary {
            intent_id: i.intent_id,
            session_id: i.session_id,
            vendor: "codex".to_string(),
            task_description: i.task_description.clone(),
            lock_type: i.lock_type,
            registered_at: i.registered_at.clone(),
        })
        .collect();

    // Build context pack with traffic included.
    let opts = kin_context::ContextOptions {
        budget: TokenBudget::Small8k,
        max_depth: 2,
        include_tests: true,
        include_contracts: true,
        include_traffic: true,
        assistant_hint: None,
    };

    let pack =
        kin_context::build_context_pack_with_traffic(graph.as_ref(), &focal.id, &opts, &nearby)
            .unwrap();

    // Verify the pack includes traffic entries.
    assert!(
        !pack.traffic.is_empty(),
        "expected traffic entries in context pack when include_traffic=true and intents exist"
    );
    assert_eq!(pack.traffic[0].intent.vendor, "codex");
    assert_eq!(pack.traffic[0].intent.lock_type, LockType::Soft);

    // Verify pack still fits budget.
    assert!(pack.actual_tokens <= opts.budget.max_tokens());
}

// -----------------------------------------------------------------------
// 11. Brownfield Git admission: exact full history, refs, membership and bytes
// -----------------------------------------------------------------------

fn run_git(repo: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .current_dir(repo)
        .output()
        .expect("run Git");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn open_migrated_authority(root: &Path) -> RepositoryAuthorityManager<LocalFileBackend> {
    let layout = kin_core::KinLayout::discover(root).expect("discover migrated Kin repository");
    let manifest =
        kin_core::KinManifest::load(&layout.manifest_path()).expect("load migrated manifest");
    let repository_id =
        RepositoryId::new(manifest.repo_id).expect("manifest repository identity is valid");
    RepositoryAuthorityManager::open(
        repository_id,
        Arc::new(LocalFileBackend::new(layout.kindb_dir())),
    )
    .expect("reopen repository authority")
}

fn assert_workspace_blob(
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    path: &str,
    expected: &[u8],
) {
    let lease = authority.read_authority();
    let workspace = lease
        .metadata()
        .workspaces
        .first()
        .expect("migrated workspace");
    let repo_path = RepoPath::from_utf8(path).expect("test path");
    let artifact = workspace
        .tree
        .artifact_at_path(&repo_path)
        .unwrap_or_else(|| panic!("{path} is absent from exact workspace authority"));
    let digest = artifact
        .entry
        .blob_identity()
        .unwrap_or_else(|| panic!("{path} is not backed by immutable source bytes"));
    drop(lease);
    assert_eq!(
        authority
            .load_source_blob(digest)
            .expect("load source body")
            .unwrap_or_else(|| panic!("{path} body is absent from immutable source CAS")),
        expected
    );
}

#[test]
fn brownfield_full_migration_publishes_repository_authority() {
    let dir = tempfile::tempdir().unwrap();
    run_git(dir.path(), &["init", "-b", "main"]);
    run_git(dir.path(), &["config", "user.email", "test@test.com"]);
    run_git(dir.path(), &["config", "user.name", "Test"]);

    let source = b"pub fn hello() -> &'static str { \"hello\" }\n";
    write_rust_file(
        dir.path(),
        "src/lib.rs",
        std::str::from_utf8(source).unwrap(),
    );
    run_git(dir.path(), &["add", "--all"]);
    run_git(dir.path(), &["commit", "-m", "initial commit"]);

    let scan = kin_migrate::scan_repo(dir.path()).expect("scan Git repository");
    let plan = kin_migrate::plan_migration(&scan, kin_migrate::MigrationStrategy::Full, None);
    let result =
        kin_migrate::execute_migration_persisted(&plan).expect("admit exact Git repository");

    assert_eq!(result.strategy, kin_migrate::MigrationStrategy::Full);
    assert_eq!(result.commits_imported, 1);
    assert_eq!(result.artifacts_admitted, 1);
    assert_eq!(
        result.files_indexed, 0,
        "semantic enrichment is a later phase"
    );
    assert_eq!(result.default_branch.as_deref(), Some("main"));
    assert!(result.authority_generation > 0);

    let authority = open_migrated_authority(dir.path());
    let lease = authority.read_authority();
    assert_eq!(
        lease.metadata().ref_state.default_ref,
        Some(RefName::branch(b"main").unwrap())
    );
    assert_eq!(lease.metadata().workspaces[0].tree.len(), 1);
    drop(lease);
    assert_workspace_blob(&authority, "src/lib.rs", source);
}

#[test]
fn brownfield_full_migration_preserves_mixed_repo_shape_and_bytes() {
    let dir = tempfile::tempdir().unwrap();
    run_git(dir.path(), &["init", "-b", "main"]);
    run_git(dir.path(), &["config", "user.email", "test@test.com"]);
    run_git(dir.path(), &["config", "user.name", "Test"]);

    let files: &[(&str, &[u8])] = &[
        (
            "src/lib.rs",
            b"pub fn hello() -> &'static str { \"hello\" }\n",
        ),
        ("frontend/app.tsx", b"export const App = () => 'hello';\n"),
        ("package.json", br#"{"name":"mixed-repo","private":true}"#),
        ("README.md", b"# Mixed Repo\n"),
        ("Dockerfile", b"FROM rust:1.89\nWORKDIR /app\nCOPY . .\n"),
        (
            "compose.yaml",
            b"services:\n  api:\n    build: .\n    command: ./run-tool\n",
        ),
        ("notes.mystery", b"unsupported-language bytes\n"),
        ("assets/data.bin", &[0_u8, 0xff, 0x10, 0x00]),
    ];
    for (path, bytes) in files {
        let full_path = dir.path().join(path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(full_path, bytes).unwrap();
    }

    let mut expected_artifacts = files.len();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(dir.path().join("run-tool"), b"#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(dir.path().join("run-tool"))
            .unwrap()
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(dir.path().join("run-tool"), permissions).unwrap();
        std::os::unix::fs::symlink("compose.yaml", dir.path().join("compose-link")).unwrap();
        expected_artifacts += 2;
    }

    run_git(dir.path(), &["add", "--all"]);
    run_git(dir.path(), &["commit", "-m", "initial mixed commit"]);

    let scan = kin_migrate::scan_repo(dir.path()).expect("scan mixed Git repository");
    let plan = kin_migrate::plan_migration(&scan, kin_migrate::MigrationStrategy::Full, None);
    let result =
        kin_migrate::execute_migration_persisted(&plan).expect("admit mixed Git repository");

    assert_eq!(result.commits_imported, 1);
    assert_eq!(result.artifacts_admitted, expected_artifacts);
    assert_eq!(result.files_indexed, 0, "authority is language-independent");
    let authority = open_migrated_authority(dir.path());
    for (path, bytes) in files {
        assert_workspace_blob(&authority, path, bytes);
    }

    #[cfg(unix)]
    {
        assert_workspace_blob(&authority, "run-tool", b"#!/bin/sh\nexit 0\n");
        assert_workspace_blob(&authority, "compose-link", b"compose.yaml");
        let lease = authority.read_authority();
        let workspace = &lease.metadata().workspaces[0];
        let executable = workspace
            .tree
            .artifact_at_path(&RepoPath::from_utf8("run-tool").unwrap())
            .unwrap();
        assert!(matches!(
            executable.entry,
            TreeEntry::Blob {
                executable: true,
                ..
            }
        ));
        let symlink = workspace
            .tree
            .artifact_at_path(&RepoPath::from_utf8("compose-link").unwrap())
            .unwrap();
        assert!(matches!(symlink.entry, TreeEntry::Symlink { .. }));
    }
}

// -----------------------------------------------------------------------
// 12. Orphan sweep: register session -> skip heartbeats -> swept after timeout
// -----------------------------------------------------------------------

#[test]
fn orphan_sweep_reaps_stale_sessions() {
    let (_dir, graph, _genesis_id) = init_kin_repo();

    // Create coordinator with a very short heartbeat interval.
    let coord =
        SessionCoordinator::with_heartbeat_interval(graph.clone(), Duration::from_millis(1));

    // Register a session with a PID that definitely doesn't exist.
    // Use PID 999999999 which almost certainly isn't a real process.
    let sid = coord
        .register_session(
            "stale-agent",
            "will-be-reaped",
            SessionTransport::Cli,
            Some(999_999_999), // Non-existent PID
            PathBuf::from("/project"),
            SessionCapabilities::default(),
        )
        .unwrap();

    // Verify the session is active.
    let session = coord.get_session(&sid).unwrap();
    assert!(session.is_some());

    // Wait just long enough for the heartbeat to be considered stale.
    // With 1ms interval, 2x threshold = 2ms, so 10ms sleep is plenty.
    std::thread::sleep(Duration::from_millis(10));

    // Run the orphan sweeper.
    let reaped = coord.sweep_stale_sessions().unwrap();

    // The session should have been reaped (either by stale heartbeat or dead PID).
    assert!(
        reaped > 0,
        "expected at least one stale session to be reaped"
    );

    // Verify the session is gone.
    let session = coord.get_session(&sid).unwrap();
    assert!(
        session.is_none(),
        "stale session should be gone after sweep"
    );
}

// -----------------------------------------------------------------------
// 14. Contract scope collision: register intent on Contract scope ->
//     second agent on same contract -> verify collision
// -----------------------------------------------------------------------

#[test]
fn contract_scope_collision() {
    let (_dir, graph, _genesis_id) = init_kin_repo();
    let coord = SessionCoordinator::new(graph.clone());

    // Register two sessions.
    let s1 = coord
        .register_session(
            "claude-code",
            "agent-1",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/project"),
            writable_capabilities(),
        )
        .unwrap();

    let s2 = coord
        .register_session(
            "codex",
            "agent-2",
            SessionTransport::Cli,
            None,
            PathBuf::from("/project"),
            writable_capabilities(),
        )
        .unwrap();

    // Agent 1 registers a hard lock on a contract scope.
    let contract_id = ContractId::new();
    let r1 = coord
        .register_intent(
            &s1,
            vec![IntentScope::Contract(contract_id)],
            LockType::Hard,
            "refactoring contract",
            None,
        )
        .unwrap();

    match &r1 {
        kin_daemon::session_registry::IntentRegistrationResult::Registered { .. } => {}
        _ => panic!("expected agent 1's contract intent to register"),
    }

    // Agent 2 attempts a hard lock on the same contract -> blocked.
    let r2 = coord
        .register_intent(
            &s2,
            vec![IntentScope::Contract(contract_id)],
            LockType::Hard,
            "also editing contract",
            None,
        )
        .unwrap();

    match r2 {
        kin_daemon::session_registry::IntentRegistrationResult::Blocked { conflicts, .. } => {
            assert!(!conflicts.is_empty(), "expected at least one conflict");
            assert_eq!(conflicts[0].vendor, "claude-code");
        }
        _ => panic!("expected agent 2's contract intent to be blocked"),
    }
}

// -----------------------------------------------------------------------
// 15. Artifact scope collision: register intent on Artifact scope ->
//     second agent on same file -> verify collision
// -----------------------------------------------------------------------

#[test]
fn artifact_scope_collision() {
    let (_dir, graph, _genesis_id) = init_kin_repo();
    let coord = SessionCoordinator::new(graph.clone());

    // Register two sessions.
    let s1 = coord
        .register_session(
            "claude-code",
            "agent-1",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/project"),
            writable_capabilities(),
        )
        .unwrap();

    let s2 = coord
        .register_session(
            "cursor",
            "agent-2",
            SessionTransport::Cli,
            None,
            PathBuf::from("/project"),
            writable_capabilities(),
        )
        .unwrap();

    // Agent 1 registers a hard lock on a file artifact.
    let file_id = FilePathId::new("src/important.rs");
    let r1 = coord
        .register_intent(
            &s1,
            vec![IntentScope::Artifact(file_id.clone())],
            LockType::Hard,
            "rewriting important.rs",
            None,
        )
        .unwrap();

    match &r1 {
        kin_daemon::session_registry::IntentRegistrationResult::Registered { .. } => {}
        _ => panic!("expected agent 1's artifact intent to register"),
    }

    // Agent 2 attempts a hard lock on the same file -> blocked.
    let r2 = coord
        .register_intent(
            &s2,
            vec![IntentScope::Artifact(file_id)],
            LockType::Hard,
            "also editing important.rs",
            None,
        )
        .unwrap();

    match r2 {
        kin_daemon::session_registry::IntentRegistrationResult::Blocked { conflicts, .. } => {
            assert!(!conflicts.is_empty(), "expected at least one conflict");
            assert_eq!(conflicts[0].vendor, "claude-code");
        }
        _ => panic!("expected agent 2's artifact intent to be blocked"),
    }

    // Verify a different file is NOT blocked.
    let other_file = FilePathId::new("src/other.rs");
    let r3 = coord
        .register_intent(
            &s2,
            vec![IntentScope::Artifact(other_file)],
            LockType::Hard,
            "editing a different file",
            None,
        )
        .unwrap();

    match r3 {
        kin_daemon::session_registry::IntentRegistrationResult::Registered { .. } => {}
        _ => panic!("expected different file intent to register without conflict"),
    }
}
