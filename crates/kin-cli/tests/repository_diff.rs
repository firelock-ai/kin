// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Every case here drives the retained no-follow projection, which only Unix
// implements, so the whole binary is scoped to that platform.
#![cfg(unix)]

use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

fn run_git(path: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .current_dir(path)
        .output()
        .expect("run git")
}

fn require_git(path: &Path, args: &[&str]) {
    let output = run_git(path, args);
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_stdout(path: &Path, args: &[&str]) -> String {
    let output = run_git(path, args);
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Git stdout should be UTF-8")
        .trim()
        .to_string()
}

fn run_kin(repo: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(args)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        // This test asserts an exact authority generation, which means "this
        // repository was written once, by init". Language-server enrichment is
        // durable authority now, so a host that has a server for the polyglot
        // fixture writes a second time and the number moves. Nothing here is
        // about enrichment, so the writer is switched off rather than the
        // assertion loosened, which also stops the result depending on which
        // servers the host happens to have installed.
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env_remove("KIN_DAEMON_URL")
        .env_remove("KIN_VFS_WORKSPACE")
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn require_kin_json(repo: &Path, home: &Path, args: &[&str]) -> Value {
    let output = run_kin(repo, home, args);
    assert!(
        output.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("Kin stdout should be JSON")
}

fn path_hex(path: &[u8]) -> String {
    path.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn delta_path<'a>(delta: &'a Value, side: &str) -> Option<&'a str> {
    delta[side]["path"]["bytes_hex"].as_str()
}

fn deltas_by_representative_path(report: &Value) -> BTreeMap<String, &Value> {
    report["artifact_deltas"]
        .as_array()
        .expect("artifact deltas")
        .iter()
        .map(|delta| {
            let path = delta_path(delta, "new")
                .or_else(|| delta_path(delta, "old"))
                .expect("artifact delta has an old or new path");
            (path.to_string(), delta)
        })
        .collect()
}

fn git_oid_json(oid: &str) -> Value {
    Value::Array(
        hex::decode(oid)
            .expect("Git object ID should be hex")
            .into_iter()
            .map(|byte| Value::from(u64::from(byte)))
            .collect(),
    )
}

#[cfg(unix)]
#[test]
fn diff_is_exact_for_polyglot_non_code_binary_modes_symlinks_gitlinks_and_raw_paths() {
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{symlink, PermissionsExt};

    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");

    require_git(&repo, &["init", "--initial-branch=main"]);
    require_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    require_git(&repo, &["config", "user.name", "Kin"]);
    require_git(&repo, &["config", "commit.gpgsign", "false"]);

    // Two real commit objects provide exact, distinct gitlink targets without
    // requiring any external repository or network.
    fs::write(repo.join(".subtarget"), b"one\n").expect("write first submodule target");
    require_git(&repo, &["add", ".subtarget"]);
    require_git(&repo, &["commit", "-m", "submodule target one"]);
    let gitlink_one = git_stdout(&repo, &["rev-parse", "HEAD"]);
    fs::write(repo.join(".subtarget"), b"two\n").expect("write second submodule target");
    require_git(&repo, &["add", ".subtarget"]);
    require_git(&repo, &["commit", "-m", "submodule target two"]);
    let gitlink_two = git_stdout(&repo, &["rev-parse", "HEAD"]);
    require_git(&repo, &["branch", "-m", "sub-targets"]);
    require_git(&repo, &["switch", "--orphan", "main"]);
    if repo.join(".subtarget").exists() {
        fs::remove_file(repo.join(".subtarget")).expect("remove target fixture from main");
    }
    require_git(&repo, &["add", "--all"]);

    fs::create_dir_all(repo.join("src")).expect("create Rust source directory");
    fs::create_dir_all(repo.join("scripts")).expect("create Python source directory");
    fs::write(
        repo.join("compose.yaml"),
        b"services:\n  api:\n    build: .\n",
    )
    .expect("write Compose file");
    fs::write(repo.join("Dockerfile"), b"FROM scratch\n").expect("write Dockerfile");
    fs::write(repo.join("src/lib.rs"), b"pub fn answer() -> u8 { 1 }\n")
        .expect("write Rust source");
    fs::write(
        repo.join("scripts/tool.py"),
        b"def answer():\n    return 1\n",
    )
    .expect("write Python source");
    fs::write(repo.join("policy.unsupported"), b"allow = one\n")
        .expect("write unsupported-language artifact");
    fs::write(repo.join("payload.bin"), [0_u8, 255, 17, 0, 128, 42])
        .expect("write binary artifact");
    fs::write(repo.join("tool"), b"#!/bin/sh\nexit 0\n").expect("write executable");
    let mut tool_permissions = fs::metadata(repo.join("tool")).unwrap().permissions();
    tool_permissions.set_mode(0o755);
    fs::set_permissions(repo.join("tool"), tool_permissions).expect("mark executable");
    symlink("compose.yaml", repo.join("config-link")).expect("create symlink");
    fs::write(repo.join("unchanged.data"), b"not semantically related\n")
        .expect("write unrelated unchanged artifact");
    // Darwin rejects ill-formed UTF-8 at the filesystem syscall boundary.
    // Other Unix targets exercise truly non-UTF-8 names; Darwin still proves
    // byte-exact path transitions here, while the platform-independent unit
    // test covers ill-formed bytes directly in repository authority.
    #[cfg(target_vendor = "apple")]
    let (raw_old_bytes, raw_new_bytes): (&[u8], &[u8]) =
        (b"raw-\xf0\x9f\xa7\xac.dat", b"renamed-\xf0\x9f\xa7\xaa.dat");
    #[cfg(not(target_vendor = "apple"))]
    let (raw_old_bytes, raw_new_bytes): (&[u8], &[u8]) = (b"raw-\xff.dat", b"renamed-\xfe.dat");
    let raw_old = OsString::from_vec(raw_old_bytes.to_vec());
    let raw_new = OsString::from_vec(raw_new_bytes.to_vec());
    fs::write(repo.join(&raw_old), b"byte-exact path\n").expect("write raw path");
    fs::create_dir_all(repo.join("vendor/submodule"))
        .expect("materialize the gitlink workspace boundary");
    require_git(&repo, &["add", "--all"]);
    require_git(
        &repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{gitlink_one},vendor/submodule"),
        ],
    );
    require_git(&repo, &["commit", "-m", "exact mixed base tree"]);
    let base_oid = git_stdout(&repo, &["rev-parse", "HEAD"]);

    fs::write(
        repo.join("compose.yaml"),
        b"services:\n  api:\n    build: .\n  worker:\n    image: scratch\n",
    )
    .expect("modify Compose file");
    fs::remove_file(repo.join("Dockerfile")).expect("remove Dockerfile");
    fs::write(repo.join("src/lib.rs"), b"pub fn answer() -> u8 { 2 }\n")
        .expect("modify Rust source");
    fs::write(
        repo.join("scripts/tool.py"),
        b"def answer():\n    return 2\n",
    )
    .expect("modify Python source");
    fs::write(repo.join("policy.unsupported"), b"allow = two\n")
        .expect("modify unsupported-language artifact");
    fs::write(repo.join("payload.bin"), [0_u8, 254, 17, 0, 129, 42])
        .expect("modify binary artifact");
    let mut tool_permissions = fs::metadata(repo.join("tool")).unwrap().permissions();
    tool_permissions.set_mode(0o644);
    fs::set_permissions(repo.join("tool"), tool_permissions).expect("clear executable bit");
    fs::remove_file(repo.join("config-link")).expect("replace symlink");
    symlink("policy.unsupported", repo.join("config-link")).expect("change symlink target");
    fs::rename(repo.join(&raw_old), repo.join(&raw_new)).expect("rename byte-exact path");
    fs::write(repo.join("notes.random"), b"unrelated new artifact\n")
        .expect("write unrelated added artifact");
    require_git(&repo, &["add", "--all"]);
    require_git(
        &repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{gitlink_two},vendor/submodule"),
        ],
    );
    require_git(&repo, &["commit", "-m", "exact mixed head tree"]);
    let head_oid = git_stdout(&repo, &["rev-parse", "HEAD"]);

    let init = run_kin(&repo, &home, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let report = require_kin_json(&repo, &home, &["diff", &base_oid, &head_oid, "--json"]);
    assert_eq!(report["schema"], "kin.diff.v1");
    assert_eq!(report["authority"], "repository-v6");
    assert_eq!(report["authority_generation"], 1);
    assert_eq!(report["base"]["source"], "git_object");
    assert_eq!(report["head"]["source"], "git_object");
    assert_eq!(report["summary"]["artifacts_added"], 2);
    assert_eq!(report["summary"]["artifacts_updated"], 8);
    assert_eq!(report["summary"]["artifacts_removed"], 2);
    // Admission binds the semantics of every imported change, so a diff across
    // imported history carries entity deltas as well as the exact tree. Both
    // edited supported-language files keep their declaration set and change one
    // body each: the Rust `answer`, the Python `answer`, and the Python module
    // that contains it. The unsupported-language, binary, symlink, gitlink, and
    // raw-path artifacts contribute none.
    assert_eq!(report["summary"]["entities_added"], 0);
    assert_eq!(report["summary"]["entities_modified"], 3);
    assert_eq!(report["summary"]["entities_removed"], 0);
    assert_eq!(report["summary"]["relations_added"], 0);
    assert_eq!(report["summary"]["relations_modified"], 0);
    assert_eq!(report["summary"]["relations_removed"], 0);

    let deltas = deltas_by_representative_path(&report);
    assert_eq!(deltas.len(), 12);
    assert!(!deltas.contains_key(&path_hex(b"unchanged.data")));

    for path in [
        b"compose.yaml".as_slice(),
        b"src/lib.rs".as_slice(),
        b"scripts/tool.py".as_slice(),
        b"policy.unsupported".as_slice(),
        b"payload.bin".as_slice(),
    ] {
        let delta = deltas.get(&path_hex(path)).expect("updated artifact");
        assert_eq!(delta["operation"], "updated");
        assert_eq!(delta["old"]["entry"]["type"], "blob");
        assert_eq!(delta["new"]["entry"]["type"], "blob");
        assert_ne!(
            delta["old"]["entry"]["hash"],
            delta["new"]["entry"]["hash"],
            "content identity did not change for {}",
            String::from_utf8_lossy(path)
        );
    }

    let dockerfile = deltas
        .get(&path_hex(b"Dockerfile"))
        .expect("removed Dockerfile");
    assert_eq!(dockerfile["operation"], "removed");
    assert_eq!(dockerfile["old"]["entry"]["type"], "blob");

    let added = deltas
        .get(&path_hex(b"notes.random"))
        .expect("unrelated artifact addition");
    assert_eq!(added["operation"], "added");
    assert_eq!(added["new"]["entry"]["type"], "blob");

    let executable = deltas.get(&path_hex(b"tool")).expect("mode-only update");
    assert_eq!(executable["operation"], "updated");
    assert_eq!(
        executable["old"]["entry"]["hash"], executable["new"]["entry"]["hash"],
        "mode-only transition unexpectedly changed the blob identity"
    );
    assert_eq!(executable["old"]["entry"]["executable"], true);
    assert_eq!(executable["new"]["entry"]["executable"], false);

    let symlink_delta = deltas
        .get(&path_hex(b"config-link"))
        .expect("symlink target update");
    assert_eq!(symlink_delta["operation"], "updated");
    assert_eq!(symlink_delta["old"]["entry"]["type"], "symlink");
    assert_eq!(symlink_delta["new"]["entry"]["type"], "symlink");
    assert_ne!(
        symlink_delta["old"]["entry"]["target_blob"],
        symlink_delta["new"]["entry"]["target_blob"]
    );

    // Imported Git history intentionally does not invent rename identity from
    // similarity: the exact raw tree records one removal and one addition.
    // The unit-level exact-tree fixture separately proves that a graph-native
    // stable artifact ID is rendered as one byte-exact move.
    let raw_removed = deltas
        .get(&path_hex(raw_old_bytes))
        .expect("byte-exact removal");
    let raw_added = deltas
        .get(&path_hex(raw_new_bytes))
        .expect("byte-exact addition");
    assert_eq!(raw_removed["operation"], "removed");
    assert_eq!(raw_added["operation"], "added");
    assert_eq!(
        raw_removed["old"]["path"]["bytes_hex"],
        path_hex(raw_old_bytes)
    );
    assert_eq!(
        raw_added["new"]["path"]["bytes_hex"],
        path_hex(raw_new_bytes)
    );
    assert_eq!(
        raw_removed["old"]["entry"], raw_added["new"]["entry"],
        "raw Git rename did not preserve exact material identity"
    );

    let gitlink = deltas
        .get(&path_hex(b"vendor/submodule"))
        .expect("gitlink update");
    assert_eq!(gitlink["operation"], "updated");
    assert_eq!(gitlink["old"]["entry"]["type"], "gitlink");
    assert_eq!(gitlink["new"]["entry"]["type"], "gitlink");
    assert_eq!(gitlink["old"]["entry"]["target"]["algorithm"], "sha1");
    assert_eq!(
        gitlink["old"]["entry"]["target"]["bytes"],
        git_oid_json(&gitlink_one)
    );
    assert_eq!(
        gitlink["new"]["entry"]["target"]["bytes"],
        git_oid_json(&gitlink_two)
    );

    // A single endpoint compares that immutable authority target to the exact
    // graph-owned workspace, not to checkout files.
    let workspace_report = require_kin_json(&repo, &home, &["diff", &base_oid, "--json"]);
    assert_eq!(workspace_report["head"]["source"], "workspace");
    assert_eq!(
        workspace_report["artifact_deltas"],
        report["artifact_deltas"]
    );

    // Both ordinary and byte-exact ref selectors resolve from the same lease.
    let main_hex = path_hex(b"refs/heads/main");
    let ref_report = require_kin_json(
        &repo,
        &home,
        &["diff", &base_oid, &format!("ref-hex:{main_hex}"), "--json"],
    );
    assert_eq!(ref_report["head"]["source"], "ref");
    assert_eq!(ref_report["artifact_deltas"], report["artifact_deltas"]);

    let clean = require_kin_json(&repo, &home, &["diff", "--json"]);
    assert_eq!(clean["base"]["source"], "head");
    assert_eq!(clean["head"]["source"], "workspace");
    assert!(clean["artifact_deltas"].as_array().unwrap().is_empty());

    let human = run_kin(&repo, &home, &["diff", &base_oid, &head_oid]);
    assert!(human.status.success());
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    assert!(human_stdout.contains("Kin repository-v6 diff"));
    #[cfg(target_vendor = "apple")]
    {
        assert!(human_stdout.contains("raw-🧬.dat"));
        assert!(human_stdout.contains("renamed-🧪.dat"));
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        assert!(human_stdout.contains(r"raw-\xff.dat"));
        assert!(human_stdout.contains(r"renamed-\xfe.dat"));
    }
    assert!(human_stdout.contains("mode=160000"));

    // Disable every file-first compatibility surface and make the checkout
    // contradict authority. The exact report must remain byte-for-byte stable.
    fs::rename(repo.join(".git"), repo.join("git-authority-disabled"))
        .expect("hide admitted Git metadata");
    fs::write(repo.join("compose.yaml"), b"services: {}\n").expect("drift Compose checkout");
    fs::remove_file(repo.join("payload.bin")).expect("remove binary checkout");
    fs::remove_file(repo.join("config-link")).expect("remove symlink checkout");
    fs::write(repo.join("checkout-only.tmp"), b"not authority\n").expect("add checkout-only file");
    let after = require_kin_json(&repo, &home, &["diff", &base_oid, &head_oid, "--json"]);
    assert_eq!(
        after, report,
        "Git metadata or checkout drift influenced repository-v6 diff"
    );
}
