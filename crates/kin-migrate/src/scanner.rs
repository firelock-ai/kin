// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::{MigrateError, Result};
use crate::MigrationProcessHost;

const MIGRATION_GIT_TIMEOUT: Duration = Duration::from_secs(30);
const MIGRATION_GIT_CAPTURE_LIMIT: u64 = 1024 * 1024;

/// Metadata about a scanned Git repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoScan {
    /// Path to the repository root.
    pub root: PathBuf,
    /// Default branch name (e.g., "main", "master").
    pub default_branch: Option<String>,
}

/// Scan a Git repository to gather metadata for migration planning.
///
/// This phase deliberately does not walk the working tree. Repository
/// membership comes from the imported Git tree; scanning only identifies the
/// repository root and selected branch.
///
/// `process_host` makes the bounded-probe containment authority explicit. On
/// Unix, a product host must satisfy the entrypoint contract documented by
/// [`MigrationProcessHost::product`].
pub fn scan_repo(repo_path: &Path, process_host: &MigrationProcessHost) -> Result<RepoScan> {
    if !repo_path.exists() {
        return Err(MigrateError::SourceNotFound(
            repo_path.display().to_string(),
        ));
    }

    let root = repo_path
        .canonicalize()
        .map_err(|error| MigrateError::io(repo_path, error))?;
    let mut git_probe = git_command(&root)?;
    git_probe.args(["rev-parse", "--git-dir"]);
    let git_probe = run_git_metadata(process_host, git_probe, "migration repository probe")
        .map_err(|error| MigrateError::io(&root, error))?;
    if !git_probe.status.success() {
        return Err(MigrateError::NotAGitRepo(repo_path.display().to_string()));
    }

    info!(
        path = %root.display(),
        "scanned repository"
    );

    Ok(RepoScan {
        default_branch: detect_default_branch(&root, process_host),
        root,
    })
}

/// Detect the checked-out branch without interpreting `.git` internals. This
/// also works for linked worktrees where `.git` is a file.
fn detect_default_branch(repo_path: &Path, process_host: &MigrationProcessHost) -> Option<String> {
    let mut command = git_command(repo_path).ok()?;
    command.args(["symbolic-ref", "--quiet", "--short", "HEAD"]);
    let output = run_git_metadata(process_host, command, "migration branch probe").ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Construct the product Git boundary for a repository selected explicitly by
/// `repo_path`.
///
/// Migration scanning asks Git only for repository metadata. Ambient Git
/// selectors, Kin/VFS projection authority, and loader injection must not be
/// able to redirect that query to a different repository or executable
/// context. Local repository configuration remains visible; system/global and
/// command-scope configuration do not.
struct ProductGitCommand {
    inner: Command,
    host_path: OsString,
}

impl ProductGitCommand {
    fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.inner.args(args);
        self
    }
}

fn git_command(repo_path: &Path) -> Result<ProductGitCommand> {
    let resolution_cwd = std::env::current_dir().map_err(|error| {
        MigrateError::GitImport(format!("capture host Git resolution directory: {error}"))
    })?;
    let host_path = absolute_host_search_path(kin_core::shims::unshimmed_path(), &resolution_cwd)?;
    let git = which::which_in("git", Some(&host_path), &resolution_cwd).map_err(|error| {
        MigrateError::GitImport(format!(
            "locate host Git executable for {}: {error}",
            repo_path.display()
        ))
    })?;
    let git = if git.is_absolute() {
        git
    } else {
        resolution_cwd.join(git)
    };
    let mut command = Command::new(git);
    command.arg("-C").arg(repo_path);
    Ok(ProductGitCommand {
        inner: command,
        host_path,
    })
}

fn absolute_host_search_path(
    host_path: impl AsRef<OsStr>,
    resolution_cwd: &Path,
) -> Result<OsString> {
    let entries = std::env::split_paths(host_path.as_ref())
        .map(|entry| {
            if entry.is_absolute() {
                entry
            } else {
                resolution_cwd.join(entry)
            }
        })
        .collect::<Vec<_>>();
    std::env::join_paths(entries).map_err(|error| {
        MigrateError::GitImport(format!(
            "normalize host Git PATH against {}: {error}",
            resolution_cwd.display()
        ))
    })
}

fn run_git_metadata(
    process_host: &MigrationProcessHost,
    mut command: ProductGitCommand,
    label: &str,
) -> std::io::Result<Output> {
    // This is the final command mutation before the bounded helper attaches
    // owned stdio and spawns the process.
    isolate_git_process(&mut command.inner, &command.host_path);
    crate::bounded_process::output_finalized_with_timeout_and_limit(
        process_host,
        command.inner,
        label,
        MIGRATION_GIT_TIMEOUT,
        MIGRATION_GIT_CAPTURE_LIMIT,
    )
}

fn isolate_git_process(command: &mut Command, host_path: &OsStr) {
    let explicit_authority = command
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .filter(|key| is_git_process_authority(key))
        .collect::<Vec<_>>();
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_git_process_authority(key))
        .chain(explicit_authority)
    {
        command.env_remove(key);
    }
    command
        .env("PATH", host_path)
        .env("KIN_VFS_DISABLE", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0");
}

fn is_git_process_authority(key: &std::ffi::OsStr) -> bool {
    let label = key.to_string_lossy();
    env_name_starts_with(&label, "GIT_")
        || env_name_starts_with(&label, "KIN_")
        || env_name_starts_with(&label, "_KIN_")
        || env_name_starts_with(&label, "DYLD_")
        || env_name_starts_with(&label, "LD_")
}

#[cfg(windows)]
fn env_name_starts_with(actual: &str, expected: &str) -> bool {
    actual
        .get(..expected.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(expected))
}

#[cfg(not(windows))]
fn env_name_starts_with(actual: &str, expected: &str) -> bool {
    actual.starts_with(expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_process_host() -> MigrationProcessHost {
        MigrationProcessHost::exact_test(
            std::env::current_exe().expect("resolve migration unit-test executable"),
            "kin_process_group_guardian_worker",
        )
    }

    fn make_git_repo() -> Option<tempfile::TempDir> {
        let dir = tempfile::tempdir().unwrap();
        let mut command = git_command(dir.path()).ok()?;
        command.args(["init", "-b", "main"]);
        let output = run_git_metadata(
            &test_process_host(),
            command,
            "migration test repository init",
        )
        .ok()?;
        output.status.success().then_some(dir)
    }

    #[test]
    fn product_git_boundary_scrubs_command_local_authority() {
        let mut command = Command::new("git");
        for (key, value) in [
            ("GIT_DIR", "/hostile/repository"),
            ("GIT_CONFIG_COUNT", "1"),
            ("KIN_VFS_WORKSPACE", "/hostile/projection"),
            ("_KIN_VFS_LAST_DIR", "/hostile/projection/src"),
            ("DYLD_INSERT_LIBRARIES", "/hostile/interpose.dylib"),
            ("LD_PRELOAD", "/hostile/interpose.so"),
        ] {
            command.env(key, value);
        }
        let resolution_cwd = std::env::current_dir().unwrap();
        let host_path =
            absolute_host_search_path(kin_core::shims::unshimmed_path(), &resolution_cwd).unwrap();
        isolate_git_process(&mut command, &host_path);

        let envs = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for removed in [
            "GIT_DIR",
            "GIT_CONFIG_COUNT",
            "KIN_VFS_WORKSPACE",
            "_KIN_VFS_LAST_DIR",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
        ] {
            assert_eq!(
                envs.get(removed),
                Some(&None),
                "{removed} retained product Git authority"
            );
        }
        assert_eq!(
            envs.get("GIT_CONFIG_GLOBAL"),
            Some(&Some(
                kin_git::empty_global_git_config()
                    .to_string_lossy()
                    .into_owned()
            ))
        );
        assert_eq!(envs.get("KIN_VFS_DISABLE"), Some(&Some("1".to_string())));
        assert!(envs.get("PATH").is_some_and(Option::is_some));
    }

    /// `kin migrate` shells out to Git through this boundary, so the global
    /// config it binds has to be a path Git can actually open. Binding the
    /// reserved Windows device name `NUL` made Git fail with
    /// `fatal: unable to access 'NUL': Invalid argument` on a real Windows
    /// host, which failed the scan rather than isolating it.
    #[test]
    fn product_git_boundary_binds_an_openable_empty_global_config() {
        let mut command = Command::new("git");
        let resolution_cwd = std::env::current_dir().unwrap();
        let host_path =
            absolute_host_search_path(kin_core::shims::unshimmed_path(), &resolution_cwd).unwrap();
        isolate_git_process(&mut command, &host_path);

        let bound = command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new("GIT_CONFIG_GLOBAL"))
            .and_then(|(_, value)| value)
            .expect("the migration Git boundary bound a global config");
        assert_eq!(
            bound,
            kin_git::empty_global_git_config(),
            "the migration Git boundary stopped routing through the shared helper"
        );
        assert!(
            Path::new(bound).is_absolute(),
            "bound global Git config {bound:?} is a bare name, not an absolute path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn relative_host_path_is_bound_absolutely_before_child_cwd_changes() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let resolution_cwd = root.path().join("resolution");
        let child_cwd = root.path().join("child");
        let host_bin = resolution_cwd.join("bin");
        let hostile_bin = child_cwd.join("bin");
        std::fs::create_dir_all(&host_bin).unwrap();
        std::fs::create_dir_all(&hostile_bin).unwrap();
        let trusted = host_bin.join("git");
        let hostile = hostile_bin.join("git");
        std::fs::write(&trusted, "#!/bin/sh\nprintf trusted\n").unwrap();
        std::fs::write(&hostile, "#!/bin/sh\nprintf hostile\n").unwrap();
        for executable in [&trusted, &hostile] {
            let mut permissions = std::fs::metadata(executable).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(executable, permissions).unwrap();
        }

        let host_path = absolute_host_search_path("bin", &resolution_cwd).unwrap();
        let git = which::which_in("git", Some(&host_path), &resolution_cwd).unwrap();
        assert!(git.is_absolute(), "host Git binding remained relative");
        let output = Command::new(git).current_dir(&child_cwd).output().unwrap();
        assert_eq!(output.stdout, b"trusted");
    }

    #[cfg(windows)]
    #[test]
    fn product_git_boundary_is_case_insensitive_on_windows() {
        for hostile in [
            "git_dir",
            "Kin_Vfs_Workspace",
            "_kin_vfs_last_dir",
            "Dyld_Insert_Libraries",
            "ld_preload",
        ] {
            assert!(
                is_git_process_authority(std::ffi::OsStr::new(hostile)),
                "{hostile} bypassed Windows product Git isolation"
            );
        }
    }

    #[test]
    fn scan_valid_repo() {
        let Some(dir) = make_git_repo() else {
            return;
        };
        std::fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.path().join("readme.md"), "# Hello").unwrap();

        let scan = scan_repo(dir.path(), &test_process_host()).unwrap();
        assert_eq!(scan.root, dir.path().canonicalize().unwrap());
        assert_eq!(scan.default_branch, Some("main".to_string()));
    }

    #[test]
    fn scan_missing_dir_fails() {
        let err = scan_repo(Path::new("/nonexistent/repo"), &test_process_host()).unwrap_err();
        assert!(matches!(err, MigrateError::SourceNotFound(_)));
    }

    #[test]
    fn scan_non_git_dir_fails() {
        let dir = tempfile::tempdir().unwrap();
        let err = scan_repo(dir.path(), &test_process_host()).unwrap_err();
        assert!(matches!(err, MigrateError::NotAGitRepo(_)));
    }

    #[test]
    fn scan_does_not_derive_membership_from_worktree_files() {
        let Some(dir) = make_git_repo() else {
            return;
        };
        std::fs::write(dir.path().join("untracked.rs"), "fn untracked() {}").unwrap();
        let scan = scan_repo(dir.path(), &test_process_host()).unwrap();
        assert_eq!(scan.root, dir.path().canonicalize().unwrap());
    }

    #[test]
    fn detect_default_branch_name() {
        let Some(dir) = make_git_repo() else {
            return;
        };
        let branch = detect_default_branch(dir.path(), &test_process_host());
        assert_eq!(branch, Some("main".to_string()));
    }

    #[test]
    fn repo_scan_serializes() {
        let scan = RepoScan {
            root: PathBuf::from("/project"),
            default_branch: Some("main".into()),
        };
        let json = serde_json::to_string(&scan).unwrap();
        let parsed: RepoScan = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.default_branch.as_deref(), Some("main"));
    }
}
