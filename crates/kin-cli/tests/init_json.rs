// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

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

fn seed_git_repo(path: &Path) {
    fs::create_dir_all(path).expect("create repo dir");
    run_git(path, &["init", "--initial-branch=main"]);
    run_git(path, &["config", "user.email", "kin@example.invalid"]);
    run_git(path, &["config", "user.name", "Kin"]);
    fs::write(path.join("README.md"), "first\n").expect("write first revision");
    run_git(path, &["add", "--all"]);
    run_git(path, &["commit", "-m", "first"]);
    fs::write(path.join("README.md"), "second\n").expect("write second revision");
    fs::write(
        path.join("compose.yaml"),
        "services:\n  api:\n    build: .\n",
    )
    .expect("write Compose file");
    run_git(path, &["add", "--all"]);
    run_git(path, &["commit", "-m", "second"]);
}

fn kin_init(repo: &Path, home: &Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(repo)
        .args(extra)
        .env("HOME", home)
        .output()
        .expect("run kin init")
}

fn kin_graph_materialize(repo: &Path, home: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["graph", "materialize", "--json"])
        .env("HOME", home)
        .env("KIN_EMBED_BACKEND", "cpu")
        .env("KIN_NO_DAEMON", "1")
        .env("KIN_SESSION_ID", uuid::Uuid::new_v4().to_string())
        .current_dir(repo)
        .output()
        .expect("run kin graph materialize")
}

fn git_stdout(path: &Path, args: &[&str]) -> String {
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
    String::from_utf8(output.stdout).expect("utf8 git stdout")
}

/// A converted repository's `git status` must not name the store.
///
/// `.kin/` runs from hundreds of megabytes to over a gigabyte, and Kin authors
/// no ignore rules of its own, so the store stood in `git status` as untracked
/// for the life of the checkout and one careless `git add -A` staged all of it.
/// The exclusion belongs to this checkout, so it goes in `.git/info/exclude` and
/// never in the tracked `.gitignore`, where it would enter the user's diff.
///
/// Driven through the binary, because the exclusion writer being correct and
/// `kin init` never calling it look identical from a unit test.
#[test]
fn git_init_keeps_the_store_out_of_git_status() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("excluded");
    fs::create_dir_all(&home).expect("create home");
    seed_git_repo(&repo);

    let output = kin_init(&repo, &home, &[]);
    assert!(
        output.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(repo.join(".kin").is_dir(), "init published no store");

    let status = git_stdout(&repo, &["status", "--porcelain"]);
    assert!(
        !status.contains(".kin"),
        "git status must not name the store after init: {status}"
    );
    assert!(
        !repo.join(".gitignore").exists(),
        "the exclusion must stay local rather than entering the tracked ignore file"
    );
    let exclude = fs::read_to_string(repo.join(".git/info/exclude")).expect("read local exclude");
    assert!(
        exclude.lines().any(|line| line.trim() == "/.kin/"),
        "the local exclude must carry the anchored store pattern: {exclude}"
    );
}

#[test]
fn fresh_native_init_creates_unborn_repository_authority() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("native");
    fs::create_dir_all(&home).expect("create home");

    let output = kin_init(&repo, &home, &[]);
    assert!(
        output.status.success(),
        "fresh native init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Authority: repository-v6 (graph-owned)"));
    assert!(stdout.contains("History: unborn (no synthetic commit)"));
    assert!(repo.join(".kin/manifest.json").is_file());
    assert!(!repo.join(".git").exists());
    assert!(!repo.join("AGENTS.md").exists());
}

#[test]
fn fresh_native_init_json_reports_exact_unborn_authority() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("native-json");
    fs::create_dir_all(&home).expect("create home");

    let output = kin_init(&repo, &home, &["--json"]);
    assert!(
        output.status.success(),
        "fresh native init --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("native init stdout should be JSON");
    assert_eq!(payload["schema"], "kin.init-result.v6");
    assert_eq!(payload["authority"], "repository-v6");
    assert_eq!(payload["source_boundary"], "native-unborn");
    assert_eq!(payload["history"], "unborn");
    assert_eq!(
        payload["semantic_enrichment"]["view"],
        "durable_repository_authority"
    );
    assert_eq!(payload["semantic_enrichment"]["authority_generation"], 1);
    assert_eq!(payload["semantic_enrichment"]["workspace_generation"], 0);
    assert_eq!(payload["semantic_enrichment"]["presence"], "absent");
    assert_eq!(payload["semantic_enrichment"]["entity_count"], 0);
    assert_eq!(payload["semantic_enrichment"]["relation_count"], 0);
    assert_eq!(payload["exact_reachable_git_history"], false);
    assert_eq!(payload["authority_generation"], 1);
    assert_eq!(payload["workspace_generation"], 0);
    assert!(payload["initial_change_id"].is_null());
    assert_eq!(
        payload["graph_section_materialization"]["schema"],
        "kin.graph-section-materialization.v1"
    );
    assert_eq!(
        payload["graph_section_materialization"]["state"],
        "no_base_target"
    );
    assert_eq!(
        payload["graph_section_materialization"]["scope"],
        "workspace_base"
    );
    assert!(payload["graph_section_materialization"]["resolved_at"].is_null());
}

#[test]
fn fresh_git_init_json_reports_exact_reachable_authority() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("git-backed");
    fs::create_dir_all(&home).expect("create home");
    seed_git_repo(&repo);

    let output = kin_init(&repo, &home, &["--json"]);
    assert!(
        output.status.success(),
        "fresh Git init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("Git init stdout should be JSON");
    assert_eq!(payload["schema"], "kin.init-result.v6");
    assert_eq!(payload["authority"], "repository-v6");
    assert_eq!(payload["source_boundary"], "git-exact-reachable-history");
    assert_eq!(payload["history"], "exact-reachable");
    assert_eq!(
        payload["semantic_enrichment"]["view"],
        "durable_repository_authority"
    );
    assert_eq!(payload["semantic_enrichment"]["authority_generation"], 1);
    assert_eq!(payload["semantic_enrichment"]["workspace_generation"], 0);
    assert_eq!(payload["semantic_enrichment"]["presence"], "absent");
    assert_eq!(payload["semantic_enrichment"]["entity_count"], 0);
    assert!(payload["semantic_enrichment"]["semantic_change_count"]
        .as_u64()
        .is_some_and(|changes| changes >= 2));
    assert_eq!(payload["exact_reachable_git_history"], true);
    assert_eq!(payload["authority_generation"], 1);
    assert_eq!(payload["workspace_generation"], 0);
    assert!(!payload["initial_change_id"].is_null());
    assert!(repo.join(".kin/manifest.json").is_file());
    assert!(!repo.join("AGENTS.md").exists());
    assert!(
        payload["uncommitted_worktree"].is_null(),
        "a source that matched carries no disclosure: {payload}"
    );
    assert_eq!(
        payload["graph_section_materialization"]["state"],
        "persisted"
    );
    assert_eq!(
        payload["graph_section_materialization"]["authority_generation"],
        payload["authority_generation"]
    );
    assert!(!payload["graph_section_materialization"]["resolved_at"].is_null());
}

/// The automatic phase must persist before enrichment can start a daemon, and
/// the explicit operator verb must observe that same durable section through
/// the direct offline reopen path without starting or targeting a daemon.
#[test]
fn init_materializes_before_the_first_daemon_reopen() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("materialized");
    fs::create_dir_all(&home).expect("create home");
    seed_git_repo(&repo);

    let init = kin_init(&repo, &home, &["--json", "--no-enrich"]);
    assert!(
        init.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    let initialized: Value =
        serde_json::from_slice(&init.stdout).expect("init stdout should be JSON");
    let automatic = &initialized["graph_section_materialization"];
    assert_eq!(automatic["state"], "persisted", "{initialized}");
    assert_eq!(automatic["scope"], "workspace_base", "{initialized}");
    assert!(!repo.join(".kin/daemon.pid").exists());
    assert!(!repo.join(".kin/daemon.port").exists());

    let explicit = kin_graph_materialize(&repo, &home);
    assert!(
        explicit.status.success(),
        "explicit materialization failed: stdout={} stderr={}",
        String::from_utf8_lossy(&explicit.stdout),
        String::from_utf8_lossy(&explicit.stderr)
    );
    let reopened: Value =
        serde_json::from_slice(&explicit.stdout).expect("graph materialize stdout should be JSON");
    assert_eq!(reopened["schema"], "kin.graph-section-materialization.v1");
    assert_eq!(reopened["state"], "already_current", "{reopened}");
    assert_eq!(reopened["scope"], "workspace_base", "{reopened}");
    assert_eq!(
        reopened["authority_generation"],
        automatic["authority_generation"]
    );
    assert_eq!(reopened["resolved_at"], automatic["resolved_at"]);
    assert!(
        !repo.join(".kin/daemon.pid").exists() && !repo.join(".kin/daemon.port").exists(),
        "an offline representation rewrite must not leave a daemon endpoint behind"
    );
}

/// A repository someone has been working in initializes and says what it saw.
///
/// The first repository a new adopter points `kin init` at has untracked files
/// and unstaged edits in it, so this is the shape that decides whether adoption
/// starts at all. Both halves are asserted: init succeeds, and the delta it did
/// not admit is named on the surface the operator is looking at.
#[test]
fn a_worked_in_git_repository_initializes_and_discloses_the_delta() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("worked-in");
    fs::create_dir_all(&home).expect("create home");
    seed_git_repo(&repo);
    fs::write(repo.join("README.md"), "edited after the commit\n").expect("unstaged edit");
    fs::write(repo.join("scratch.log"), "log\n").expect("untracked file");
    fs::write(repo.join("staged.txt"), "staged\n").expect("staged file");
    run_git(&repo, &["add", "staged.txt"]);

    let output = kin_init(&repo, &home, &["--json"]);
    assert!(
        output.status.success(),
        "a worked-in repository must initialize: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("init stdout should be JSON");
    let disclosed = &payload["uncommitted_worktree"];
    assert_eq!(disclosed["observed_paths"], 3, "{payload}");
    assert_eq!(disclosed["unlisted_paths"], 0, "{payload}");
    let states = disclosed["paths"]
        .as_array()
        .expect("disclosed paths")
        .iter()
        .map(|entry| {
            (
                entry["path"].as_str().expect("path").to_string(),
                entry["state"].as_str().expect("state").to_string(),
            )
        })
        .collect::<Vec<_>>();
    assert!(
        states.contains(&("README.md".to_string(), "modified".to_string())),
        "{states:?}"
    );
    assert!(
        states.contains(&("staged.txt".to_string(), "staged".to_string())),
        "{states:?}"
    );
    assert!(
        states.contains(&("scratch.log".to_string(), "untracked".to_string())),
        "{states:?}"
    );

    // The worktree keeps everything it had, and the admitted state is the
    // commit rather than what is on disk.
    assert_eq!(
        fs::read_to_string(repo.join("README.md")).expect("read README"),
        "edited after the commit\n"
    );
    assert!(repo.join("scratch.log").is_file());
    assert_eq!(payload["workspace_generation"], 0);
}

/// The same repository through the human surface.
#[test]
fn a_worked_in_git_repository_names_the_delta_in_human_output() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("worked-in-human");
    fs::create_dir_all(&home).expect("create home");
    seed_git_repo(&repo);
    fs::write(repo.join("scratch.log"), "log\n").expect("untracked file");

    let output = kin_init(&repo, &home, &[]);
    assert!(output.status.success(), "init must succeed");
    let printed = String::from_utf8_lossy(&output.stdout);
    assert!(
        printed.contains("Uncommitted worktree state: 1 path(s) differ"),
        "{printed}"
    );
    assert!(printed.contains("untracked (1): scratch.log"), "{printed}");
    assert!(
        printed.contains("None of it entered repository authority"),
        "{printed}"
    );
}

#[test]
fn init_and_status_report_the_same_admission_enrichment() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("enriched");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::write(
        repo.join("src/lib.rs"),
        "pub fn helper() -> u32 {\n    7\n}\n\npub fn caller() -> u32 {\n    helper() + 1\n}\n",
    )
    .expect("write entity source");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "entity source"]);

    let init = kin_init(&repo, &home, &["--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    let admitted: Value = serde_json::from_slice(&init.stdout).expect("init stdout should be JSON");

    assert_eq!(admitted["semantic_enrichment"]["presence"], "present");
    assert!(
        admitted["semantic_enrichment"]["entity_count"]
            .as_u64()
            .is_some_and(|entities| entities >= 2),
        "admission enriches the supported source it imported: {}",
        admitted["semantic_enrichment"]
    );

    let status = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["status", "--json"])
        .env("HOME", &home)
        .env_remove("KIN_DAEMON_URL")
        .current_dir(&repo)
        .output()
        .expect("run kin status");
    assert!(
        status.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    let reported: Value =
        serde_json::from_slice(&status.stdout).expect("status stdout should be JSON");

    assert_eq!(
        reported["semantic_enrichment"], admitted["semantic_enrichment"],
        "init and status report the same generation-bound durable authority view"
    );
}

#[test]
fn exact_git_remote_mapping_is_sealed_during_admission() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("remote-backed");
    fs::create_dir_all(&home).expect("create home");
    seed_git_repo(&repo);
    run_git(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/acme/repository.git",
        ],
    );

    let output = kin_init(&repo, &home, &[]);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let config = fs::read_to_string(repo.join(".kin/config.toml")).expect("read Kin config");
    assert!(config.contains("name = \"origin\""), "{config}");
    assert!(
        config.contains("https://example.invalid/acme/repository.git"),
        "{config}"
    );
}

#[test]
fn existing_repository_is_not_rebuilt_from_the_working_tree() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("native");
    fs::create_dir_all(&home).expect("create home");

    let first = kin_init(&repo, &home, &[]);
    assert!(first.status.success());
    let manifest_before = fs::read(repo.join(".kin/manifest.json")).expect("read initial manifest");

    let second = kin_init(&repo, &home, &[]);
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr)
        .contains("never rebuilds graph authority from the working tree"));
    assert_eq!(
        fs::read(repo.join(".kin/manifest.json")).expect("read unchanged manifest"),
        manifest_before
    );
}

#[test]
fn pre_release_init_flags_are_not_accepted() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    fs::create_dir_all(&home).expect("create home");

    for flag in ["--git-history", "--no-lsp", "--force", "--verbose"] {
        let repo = root.path().join(flag.trim_start_matches('-'));
        let mut command = Command::new(env!("CARGO_BIN_EXE_kin"));
        command.arg("init").arg(&repo).arg(flag).env("HOME", &home);
        if flag == "--git-history" {
            command.arg("full");
        }
        let output = command.output().expect("run rejected kin init flag");
        assert!(!output.status.success(), "{flag} unexpectedly succeeded");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unexpected argument"),
            "{flag}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!repo.join(".kin").exists());
    }
}

#[test]
fn non_git_existing_files_fail_instead_of_becoming_implicit_authority() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("files");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");
    fs::write(repo.join("compose.yaml"), "services: {}\n").expect("write source");

    let output = kin_init(&repo, &home, &[]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("will not silently ignore or derive authority"));
    assert!(!repo.join(".kin").exists());
}

/// Sum the file bytes under `path`, independently of the implementation under
/// test.
///
/// The point of re-walking here is that the printed ratio has to be checkable
/// against the disk rather than against the same code that produced it. A test
/// that asserted the CLI agrees with itself would pass on any arithmetic.
fn tree_bytes(path: &Path) -> u64 {
    let mut total = 0_u64;
    let mut pending = vec![path.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                total += metadata.len();
            }
        }
    }
    total
}

fn printed_ratio(stdout: &str) -> f64 {
    let line = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("Store size:"))
        .unwrap_or_else(|| panic!("no store size line in init output:\n{stdout}"));
    let multiple = line
        .split(", ")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .unwrap_or_else(|| panic!("store size line states no multiple: {line}"));
    multiple
        .trim_end_matches('x')
        .parse::<f64>()
        .unwrap_or_else(|error| panic!("unparsable multiple {multiple:?} in {line}: {error}"))
}

/// `kin init` must state what the store cost and what it cost relative to the
/// Git object store it was admitted from.
///
/// Before this, the number existed only on disk. A user learned their store
/// size from `du` after the fact and had nothing to compare it against, which
/// is what let a two-orders-of-magnitude expansion ship undisclosed.
#[test]
fn git_init_states_the_store_size_and_its_ratio_to_the_git_object_store() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("sized");
    fs::create_dir_all(&home).expect("create home");
    seed_git_repo(&repo);

    let output = kin_init(&repo, &home, &[]);
    assert!(output.status.success(), "init failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("Store size:") && stdout.contains("under .kin/"),
        "init must report the store size: {stdout}"
    );
    assert!(
        stdout.contains("Git object store"),
        "init must name what the ratio is against: {stdout}"
    );
    assert!(
        stdout.contains("grows with history depth") && stdout.contains("docs/store-size.md"),
        "init must say what drives store size and where the measured range lives: {stdout}"
    );

    // The printed multiple must describe the disk, not merely be present.
    let store = tree_bytes(&repo.join(".kin"));
    let git = tree_bytes(&repo.join(".git").join("objects"));
    assert!(store > 0 && git > 0, "fixture measured {store} over {git}");
    let expected = store as f64 / git as f64;
    let printed = printed_ratio(&stdout);
    assert!(
        (printed - expected).abs() < 0.05 * expected.max(1.0),
        "init printed {printed}x for a store of {store} bytes over {git} Git object bytes \
         (expected about {expected:.2}x): {stdout}"
    );
}

/// The two-sided case, and the falsification of the test above.
///
/// A repository can produce a store SMALLER than its Git object store, and the
/// disclosure has to report that truthfully rather than describe every
/// repository as inflated. A renderer that only ever printed a multiple above
/// one, or that rounded a fraction to `1.0x` or to `0x`, passes the test above
/// and fails this one.
///
/// The construction is a real distinction rather than a contrived one. Git's
/// object store keeps unreachable objects until it is garbage collected; Kin
/// admits exact REACHABLE history and never seals what no ref can reach. A
/// repository that has reset away a large commit therefore carries megabytes in
/// `.git/objects` that are legitimately absent from `.kin/`.
///
/// Note what this test does NOT claim. A short history alone does not put a
/// store below its Git object store: a two-commit repository measures well
/// ABOVE it, because a nearly empty store still carries fixed authority
/// scaffolding while a nearly empty object store carries almost nothing.
#[test]
fn a_store_below_its_git_object_store_prints_a_fraction() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("orphaned");
    fs::create_dir_all(&home).expect("create home");
    seed_git_repo(&repo);

    // A blob that does not compress, so the object it becomes is about as large
    // as the bytes written. Generated rather than random, so the fixture is the
    // same size on every run.
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut incompressible = Vec::with_capacity(400_000);
    while incompressible.len() < 400_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        incompressible.extend_from_slice(&state.to_le_bytes());
    }
    fs::write(repo.join("payload.bin"), &incompressible).expect("write payload");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "payload"]);
    // Unreachable from here on, and still on disk.
    run_git(&repo, &["reset", "--hard", "HEAD~1"]);

    let output = kin_init(&repo, &home, &[]);
    assert!(
        output.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    let store = tree_bytes(&repo.join(".kin"));
    let git = tree_bytes(&repo.join(".git").join("objects"));
    assert!(
        store < git,
        "the fixture did not produce a store ({store} bytes) below its Git object store \
         ({git} bytes), so this test is not exercising the case it names"
    );

    let printed = printed_ratio(&stdout);
    assert!(
        printed < 1.0 && printed > 0.0,
        "a store below its Git object store must print a fraction, not {printed}x: {stdout}"
    );
    let expected = store as f64 / git as f64;
    // 0.005 is half the quantum of the two-decimal print; for small ratios the
    // 5% band alone is narrower than print rounding, which makes the assertion
    // fail on formatting rather than on the measured ratio.
    assert!(
        (printed - expected).abs() < 0.005 + 0.05 * expected.max(0.01),
        "init printed {printed}x for {store} store bytes over {git} Git object bytes \
         (expected about {expected:.2}x): {stdout}"
    );
}

/// The JSON surface must carry the raw counts, so a consumer can track store
/// growth over time instead of parsing a rendered sentence.
#[test]
fn init_json_carries_the_measured_store_and_git_object_bytes() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("sized-json");
    fs::create_dir_all(&home).expect("create home");
    seed_git_repo(&repo);

    let output = kin_init(&repo, &home, &["--json"]);
    assert!(output.status.success(), "init --json failed");
    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("init stdout should be JSON");

    let store = payload["store_footprint"]["store"]["bytes"]
        .as_u64()
        .expect("the payload must carry measured store bytes");
    let git = payload["store_footprint"]["git_objects"]["bytes"]
        .as_u64()
        .expect("the payload must carry measured Git object bytes");
    assert_eq!(
        store,
        tree_bytes(&repo.join(".kin")),
        "the reported store bytes must be the bytes on disk"
    );
    assert_eq!(
        git,
        tree_bytes(&repo.join(".git").join("objects")),
        "the reported Git object bytes must be the bytes on disk"
    );
    assert_eq!(
        payload["store_footprint"]["store"]["unreadable_entries"], 0,
        "a complete walk must report no unreadable entries, or the size is a floor"
    );
}

/// A Kin-native repository has no Git object store, and must say there is
/// nothing to compare against rather than print a ratio it cannot compute.
#[test]
fn native_init_reports_a_store_size_with_no_comparison() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("native-size");
    fs::create_dir_all(&home).expect("create home");

    let output = kin_init(&repo, &home, &[]);
    assert!(output.status.success(), "native init failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Store size:") && stdout.contains("no Git object store"),
        "a native repository must report its size and name the missing comparison: {stdout}"
    );
}
