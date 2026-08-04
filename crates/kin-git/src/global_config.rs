// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Empty global Git configuration for Kin's Git-process authority boundaries.
//!
//! Every Kin surface that shells out to Git binds `GIT_CONFIG_GLOBAL` so the
//! ambient global configuration scope cannot steer the child. This module owns
//! the single answer to "what path means no global configuration", because the
//! answer is not the same on every target and getting it wrong either disables
//! Git entirely or turns a loud failure into a silent one.

use std::ffi::OsStr;

/// Path to bind to `GIT_CONFIG_GLOBAL` so Git resolves the global configuration
/// scope to no configuration at all.
///
/// `GIT_CONFIG_GLOBAL` *replaces* the global scope rather than adding to it, so
/// binding a path Git reads as empty is what silences `$HOME/.gitconfig` and its
/// XDG sibling.
///
/// Unix names `/dev/null`. It reads as empty, and a `--global` write to it fails
/// loudly (`error: could not lock config file /dev/null`) rather than being
/// swallowed.
///
/// No other target has that path, and Windows in particular does not. `NUL` is a
/// reserved device name rather than a file; Git refuses it outright with
/// `fatal: unable to access 'NUL': Invalid argument`, so a boundary that bound
/// it failed the very Git commands it existed to isolate.
///
/// Off Unix the binding is instead **a path inside a directory that does not
/// exist**, which reproduces both halves of `/dev/null`'s behavior:
///
/// - Reads are clean. Git tolerates an absent global config and resolves the
///   scope to nothing, so the ambient global scope is fully suppressed.
/// - Writes fail loudly. Git cannot create its lockfile beneath a missing
///   parent, so `git config --global ...` errors instead of silently persisting.
///
/// That second half is the reason this is not simply a real empty file. A shared
/// empty file is *writable*: a stray `--global` write succeeds, persists, and is
/// then read by every later Git launch in the process, silently poisoning on
/// Windows the exact isolation this function provides, where Unix would have
/// failed loudly. Both behaviors were falsified against Git 2.55.0 on a native
/// Windows 11 ARM64 host, including a control proving the probe could see an
/// ambient `[user] name` when `GIT_CONFIG_GLOBAL` was unset.
///
/// Nothing is created, so this performs no filesystem operation, leaks no
/// temporary directory, and cannot fail. The path is deterministic; on Windows
/// `%TEMP%` is per-user, so pre-creating it requires already being that user,
/// who could edit `$HOME/.gitconfig` directly and gains nothing. Every caller
/// also binds `GIT_CONFIG_NOSYSTEM=1`.
#[cfg(unix)]
pub fn empty_global_git_config() -> &'static OsStr {
    OsStr::new("/dev/null")
}

#[cfg(not(unix))]
pub fn empty_global_git_config() -> &'static OsStr {
    use std::path::PathBuf;
    use std::sync::OnceLock;

    static EMPTY_GLOBAL_GIT_CONFIG: OnceLock<PathBuf> = OnceLock::new();
    EMPTY_GLOBAL_GIT_CONFIG
        .get_or_init(|| {
            // The intermediate directory is deliberately never created: its
            // absence is what makes a `--global` write fail instead of persist.
            std::env::temp_dir()
                .join("kin-absent-global-gitconfig")
                .join("gitconfig")
        })
        .as_os_str()
}

#[cfg(test)]
mod tests {
    use super::empty_global_git_config;
    use std::path::Path;

    /// Asserted on every target, and the reason it is worth asserting: `NUL` is
    /// a bare reserved device name, so it is not absolute anywhere. This single
    /// property fails against the defect on Unix and Windows alike.
    #[test]
    fn bound_path_is_absolute() {
        let path = Path::new(empty_global_git_config());
        assert!(
            path.is_absolute(),
            "global Git config {path:?} is not an absolute path, so it is a bare \
             name Git resolves against its own working directory"
        );
    }

    /// The binding outlives any one command, so repeated boundary applications
    /// in a process agree rather than racing to derive different paths.
    #[test]
    fn bound_path_is_stable_within_the_process() {
        assert_eq!(empty_global_git_config(), empty_global_git_config());
    }

    /// Unix keeps the device Git already reads as an empty config and refuses
    /// to lock for writing.
    #[cfg(unix)]
    #[test]
    fn unix_binds_the_null_device() {
        assert_eq!(
            empty_global_git_config(),
            std::ffi::OsStr::new("/dev/null"),
            "Unix lost the path Git reads as empty and refuses to lock"
        );
        let contents = std::fs::read("/dev/null").expect("read /dev/null");
        assert!(contents.is_empty(), "/dev/null did not read as empty");
    }

    /// Off Unix the guarantee is structural: the config path is absent, and so
    /// is its parent. The absent parent is what makes `git config --global`
    /// fail to take a lockfile instead of silently persisting.
    #[cfg(not(unix))]
    #[test]
    fn non_unix_binds_an_absent_path_under_an_absent_parent() {
        let path = Path::new(empty_global_git_config());
        assert!(
            !path.exists(),
            "global Git config {path:?} exists, so Git would read it"
        );
        let parent = path.parent().expect("bound path has a parent directory");
        assert!(
            !parent.exists(),
            "parent {parent:?} exists, so a --global write could create the \
             config there and silently poison every later Git launch"
        );
        assert!(
            parent
                .parent()
                .is_some_and(|grandparent| grandparent == std::env::temp_dir()),
            "bound path {path:?} is not anchored in the per-user temp directory"
        );
    }
}
