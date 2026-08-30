// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const SHA_OVERRIDE_ENV: &str = "KIN_BUILD_GIT_SHA_OVERRIDE";
const DIRTY_OVERRIDE_ENV: &str = "KIN_BUILD_DIRTY_OVERRIDE";
const BRANCH_OVERRIDE_ENV: &str = "KIN_BUILD_BRANCH_OVERRIDE";

#[derive(Debug)]
struct ExplicitBuildIdentity {
    sha: String,
    dirty: bool,
    branch: String,
}

fn main() {
    for name in [SHA_OVERRIDE_ENV, DIRTY_OVERRIDE_ENV, BRANCH_OVERRIDE_ENV] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = git(&manifest_dir, &["rev-parse", "--show-toplevel"])
        .map(PathBuf::from)
        // Docker and source archives intentionally omit `.git`; retain the
        // workspace Cargo.lock authority by walking to the nearest ancestor
        // that carries both workspace files instead of falling back to this
        // crate directory (which would make dependency provenance unknown).
        .or_else(|| find_workspace_root(&manifest_dir))
        .unwrap_or_else(|| manifest_dir.clone());

    // `git rev-parse --git-path` answers RELATIVE to the repository in a normal
    // checkout and ABSOLUTE in a linked worktree, and cargo resolves a relative
    // `rerun-if-changed` against the PACKAGE manifest directory rather than the
    // repository root. So a bare `.git/HEAD` here registers
    // `crates/kin-buildinfo/.git/HEAD`, which does not exist, and a
    // rerun-if-changed on a missing file makes cargo treat this unit as dirty on
    // every invocation.
    //
    // Measured on CI before this was joined: cargo said
    //   stale: missing ".../crates/kin-buildinfo/.git/HEAD"
    //   dirty: FsStatusOutdated(StaleItem(MissingFile { path: ... }))
    // and kin-cli, kin-daemon and kin-integration-tests followed as
    // StaleDepFingerprint on this build script's unit. That is a whole recompile
    // of four crates in every cargo invocation after the first, measured at 108
    // seconds per fast-gate shard.
    //
    // It is invisible in a linked worktree, where the path comes back absolute
    // and resolves, which is every lane checkout in the fleet and is why this
    // survived so long.
    let watch = |path: String| {
        let path = PathBuf::from(path);
        let path = if path.is_absolute() { path } else { root.join(path) };
        println!("cargo:rerun-if-changed={}", path.display());
    };

    if let Some(head) = git(&root, &["rev-parse", "--git-path", "HEAD"]) {
        watch(head);
    }
    if let Some(index) = git(&root, &["rev-parse", "--git-path", "index"]) {
        watch(index);
    }
    if let Some(reference) = git(&root, &["symbolic-ref", "-q", "HEAD"]) {
        if let Some(path) = git(&root, &["rev-parse", "--git-path", &reference]) {
            watch(path);
        }
    }

    // The build identity is an authority input for persisted semantic caches.
    // Watching only HEAD/reference files can leave KIN_BUILD_DIRTY stale when
    // another workspace crate changes without touching kin-buildinfo. Watch
    // every tracked top-level source subtree (but never target/) so any source
    // edit, newly created file below a tracked subtree, stage, commit, or
    // checkout reruns this build script before a binary is linked.
    if let Some(files) = git(&root, &["ls-files"]) {
        let mut watched = BTreeSet::new();
        for file in files.lines().filter(|line| !line.is_empty()) {
            let path = Path::new(file);
            let top = path.components().next().map(|part| part.as_os_str());
            if let Some(top) = top {
                watched.insert(root.join(top));
            }
        }
        for path in watched {
            if path.file_name().and_then(|name| name.to_str()) != Some("target") {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }

    // Container build contexts intentionally exclude `.git`, so release image
    // builders must provide the source identity explicitly. Treat the three
    // values as one atomic input: a partial or malformed identity fails the
    // build instead of silently producing a clean-looking `unknown` binary.
    let explicit_identity = explicit_build_identity();
    let (sha, dirty, branch, source_identity_known) = if let Some(identity) = explicit_identity {
        (identity.sha, identity.dirty, identity.branch, true)
    } else {
        let sha = git(&root, &["rev-parse", "HEAD"]);
        let branch = git(&root, &["branch", "--show-current"])
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "detached".into());
        // A clean status is valid empty output, so use the variant that
        // preserves empty stdout. Any execution/status/UTF-8 failure is an
        // unknown source identity and must fail closed for persisted caches.
        let status = git_allow_empty(&root, &["status", "--porcelain"]);
        let source_identity_known = sha.is_some() && status.is_some();
        let dirty = status
            .as_ref()
            .map(|value| !value.is_empty())
            .unwrap_or(true);
        (
            sha.unwrap_or_else(|| "unknown".into()),
            dirty,
            branch,
            source_identity_known,
        )
    };
    let dependency_provenance = dependency_provenance(&root);
    let source_known = source_identity_known && dependency_provenance.is_some();
    let dependency_provenance = dependency_provenance.unwrap_or_else(|| "unknown".to_string());
    let built_at = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into());
    let sha_display = if dirty && sha != "unknown" {
        format!("{sha}-dirty")
    } else {
        sha.clone()
    };
    let package_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let version = format!("{package_version} ({sha_display} {branch} {built_at})");

    println!("cargo:rustc-env=KIN_BUILD_GIT_SHA={sha}");
    println!("cargo:rustc-env=KIN_BUILD_DIRTY={dirty}");
    println!("cargo:rustc-env=KIN_BUILD_SOURCE_KNOWN={source_known}");
    println!("cargo:rustc-env=KIN_BUILD_DEPENDENCY_PROVENANCE={dependency_provenance}");
    println!("cargo:rustc-env=KIN_BUILD_BRANCH={branch}");
    println!("cargo:rustc-env=KIN_BUILD_TIME={built_at}");
    println!("cargo:rustc-env=KIN_BUILD_VERSION={version}");
}

fn explicit_build_identity() -> Option<ExplicitBuildIdentity> {
    let sha = std::env::var(SHA_OVERRIDE_ENV).ok();
    let dirty = std::env::var(DIRTY_OVERRIDE_ENV).ok();
    let branch = std::env::var(BRANCH_OVERRIDE_ENV).ok();

    if sha.is_none() && dirty.is_none() && branch.is_none() {
        return None;
    }

    let sha = sha.unwrap_or_else(|| panic!("{SHA_OVERRIDE_ENV} is required with build overrides"));
    let dirty =
        dirty.unwrap_or_else(|| panic!("{DIRTY_OVERRIDE_ENV} is required with build overrides"));
    let branch =
        branch.unwrap_or_else(|| panic!("{BRANCH_OVERRIDE_ENV} is required with build overrides"));

    assert!(
        sha.len() == 40
            && sha
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{SHA_OVERRIDE_ENV} must be a full lowercase 40-hex commit id"
    );
    let dirty = match dirty.as_str() {
        "true" => true,
        "false" => false,
        _ => panic!("{DIRTY_OVERRIDE_ENV} must be exactly true or false"),
    };
    assert!(
        !branch.is_empty()
            && branch.len() <= 255
            && !branch.chars().any(|character| character.is_control()),
        "{BRANCH_OVERRIDE_ENV} must be a non-empty branch/ref label without control characters"
    );

    Some(ExplicitBuildIdentity { sha, dirty, branch })
}

fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|candidate| {
            candidate.join("Cargo.toml").is_file() && candidate.join("Cargo.lock").is_file()
        })
        .map(Path::to_path_buf)
}

fn git(cwd: &Path, args: &[&str]) -> Option<String> {
    git_allow_empty(cwd, args).filter(|value| !value.is_empty())
}

fn git_allow_empty(cwd: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        // Every git call this script makes goes through here, which is why the
        // switch is set once at the chokepoint rather than per subcommand.
        //
        // `git status` performs an OPTIONAL index refresh: when the cached stat
        // data is stale it rewrites `.git/index` as a side effect of reporting.
        // This script declares that same index as one of its own
        // `rerun-if-changed` inputs, so a plain status makes the build script
        // invalidate itself for the next cargo invocation in the same job.
        //
        // Measured on CI: the fast-gate shard's `cargo nextest list` compiled 24
        // crates, and the `cargo nextest run` that followed recompiled exactly
        // four, kin-buildinfo and its three dependents, for 1m48s. That is 108
        // seconds per shard per run buying nothing.
        //
        // GIT_OPTIONAL_LOCKS=0 is git's own switch for exactly this: it skips
        // the optional write while returning the identical answer. Measured
        // locally against a deliberately staled index, a plain status rewrote
        // it and this one did not, with both reporting the same porcelain.
        //
        // It is set for every subcommand rather than only `status` so a future
        // call that also takes an optional lock cannot reintroduce this.
        // Acceptance for the line above is a CI reading, not a local one:
        // the shard's `cargo nextest run` step must compile ZERO crates,
        // against the four it recompiled before. This comment is the no-op
        // commit that takes that reading.
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    Some(value.trim().to_string())
}

fn dependency_provenance(root: &Path) -> Option<String> {
    let lock_path = root.join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    let bytes = fs::read(lock_path).ok()?;
    Some(hex_sha256(&bytes))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("write to String cannot fail");
    }
    output
}
