// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Where Kin installs the tools it provisions for itself, and how the processes
//! that look for them find them.
//!
//! Language-server discovery is `which` over `PATH` and nothing else
//! (`kin_lsp::discovery::discover_servers`), so a server Kin installs is
//! reachable only if the directory it landed in is on the `PATH` of the process
//! that starts the enrichment. That process is the repo daemon, which inherits
//! the environment of whichever `kin` command spawned it. Both binaries
//! therefore call [`augment_path_with_managed_tools`] at process start, while
//! they are still single-threaded, exactly as they both call
//! `resource_profile::apply_product_default`.
//!
//! Two directories, because two installers write in different shapes. A binary
//! Kin downloads and verifies itself lands in [`managed_tool_bin_dir`]. A
//! package installed with `npm install --prefix` lands under
//! [`managed_node_prefix`], whose executables npm links into
//! [`managed_node_bin_dir`]; that is the same prefix shape
//! `scripts/ci-install-language-servers.sh` already uses on hosted runners, and
//! it is what lets a provisioning run succeed on a host whose global npm prefix
//! is owned by root.
//!
//! These directories go on the END of `PATH`, never the front. A server the
//! operator installed themselves is the one their toolchain expects, and a
//! rustup `rust-analyzer` tracks the toolchain that compiled the code while
//! Kin's pinned copy does not. Kin's copy is a fallback for a host that has
//! none, so it must never shadow one that is already there.

use std::ffi::OsString;
use std::path::PathBuf;

/// The root Kin installs provisioned tools under.
pub fn managed_tool_root() -> PathBuf {
    crate::registry::managed_kin_home().join("tools")
}

/// Where a binary Kin downloaded and verified itself is installed.
pub fn managed_tool_bin_dir() -> PathBuf {
    managed_tool_root().join("bin")
}

/// The npm prefix Kin owns, for packages a shared global prefix refuses.
pub fn managed_node_prefix() -> PathBuf {
    managed_tool_root().join("node")
}

/// Where npm links the executables of packages installed into
/// [`managed_node_prefix`].
///
/// `npm install --prefix <dir> <pkg>` is a LOCAL install rooted at `<dir>`, so
/// its binaries land in `<dir>/node_modules/.bin` rather than in `<dir>/bin`.
/// Naming the wrong one of those two is a provisioning run that reports success
/// over a binary nothing can reach, which is the shape `kin doctor` already
/// re-probes `PATH` to catch.
pub fn managed_node_bin_dir() -> PathBuf {
    managed_node_prefix().join("node_modules").join(".bin")
}

/// Every directory Kin's own provisioning writes executables into.
pub fn managed_tool_dirs() -> Vec<PathBuf> {
    vec![managed_tool_bin_dir(), managed_node_bin_dir()]
}

/// `PATH` with Kin's tool directories appended, or `None` when it already
/// carries all of them.
///
/// Pure over its inputs so the composition is testable without touching the
/// process environment, and returning `None` for a no-op is what keeps a
/// repeated call from growing `PATH` once per invocation in a shell that
/// re-execs `kin`.
pub fn path_with_managed_tools(current: Option<&OsString>, dirs: &[PathBuf]) -> Option<OsString> {
    let existing: Vec<PathBuf> = current
        .map(|value| std::env::split_paths(value).collect())
        .unwrap_or_default();
    let missing: Vec<&PathBuf> = dirs.iter().filter(|dir| !existing.contains(dir)).collect();
    if missing.is_empty() {
        return None;
    }
    let mut joined: Vec<PathBuf> = existing;
    joined.extend(missing.into_iter().cloned());
    std::env::join_paths(joined).ok()
}

/// Put Kin's tool directories on this process's `PATH`.
///
/// Call while the process is still single-threaded. Mutating the environment
/// after threads exist is unsound, and both binaries already have a
/// single-threaded prologue for exactly this class of change.
///
/// Returns whether `PATH` was changed, so a caller can say so rather than
/// assert it.
pub fn augment_path_with_managed_tools() -> bool {
    let dirs = managed_tool_dirs();
    let current = std::env::var_os("PATH");
    match path_with_managed_tools(current.as_ref(), &dirs) {
        Some(updated) => {
            std::env::set_var("PATH", updated);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(value: &str) -> OsString {
        OsString::from(value)
    }

    fn parts(value: &OsString) -> Vec<PathBuf> {
        std::env::split_paths(value).collect()
    }

    /// The tool directories land at the END, behind whatever the operator has.
    ///
    /// The direction is the whole point. Kin's pinned `rust-analyzer` does not
    /// track the toolchain that compiled the repository and a rustup component
    /// does, so a host that has one must keep using it. A composition that put
    /// Kin's copy first would silently replace a working server with a
    /// different one and nothing downstream would report the swap.
    #[test]
    fn managed_directories_are_appended_rather_than_prepended() {
        let current = os("/usr/local/bin:/usr/bin");
        let dirs = vec![PathBuf::from("/home/u/.kin/tools/bin")];
        let updated = path_with_managed_tools(Some(&current), &dirs)
            .expect("a PATH without the tool dir must be rewritten");
        assert_eq!(
            parts(&updated),
            vec![
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/home/u/.kin/tools/bin"),
            ],
            "Kin's own tool directory must not shadow an operator's toolchain"
        );
    }

    /// A second call adds nothing, so a re-exec cannot grow `PATH` without end.
    #[test]
    fn a_path_that_already_carries_the_directories_is_left_alone() {
        let dirs = vec![
            PathBuf::from("/home/u/.kin/tools/bin"),
            PathBuf::from("/home/u/.kin/tools/node/node_modules/.bin"),
        ];
        let current =
            os("/usr/bin:/home/u/.kin/tools/bin:/home/u/.kin/tools/node/node_modules/.bin");
        assert_eq!(
            path_with_managed_tools(Some(&current), &dirs),
            None,
            "every directory was already present, so there is nothing to add"
        );
    }

    /// A partly-present `PATH` gains only what it is missing.
    #[test]
    fn only_the_missing_directories_are_added() {
        let dirs = vec![
            PathBuf::from("/home/u/.kin/tools/bin"),
            PathBuf::from("/home/u/.kin/tools/node/node_modules/.bin"),
        ];
        let current = os("/home/u/.kin/tools/bin:/usr/bin");
        let updated = path_with_managed_tools(Some(&current), &dirs)
            .expect("one directory is missing, so PATH must be rewritten");
        assert_eq!(
            parts(&updated),
            vec![
                PathBuf::from("/home/u/.kin/tools/bin"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/home/u/.kin/tools/node/node_modules/.bin"),
            ]
        );
    }

    /// An unset `PATH` still yields the tool directories rather than nothing.
    #[test]
    fn an_absent_path_becomes_the_tool_directories() {
        let dirs = vec![PathBuf::from("/home/u/.kin/tools/bin")];
        let updated =
            path_with_managed_tools(None, &dirs).expect("an unset PATH must still be composed");
        assert_eq!(
            parts(&updated),
            vec![PathBuf::from("/home/u/.kin/tools/bin")]
        );
    }

    /// The npm prefix and the directory npm links binaries into are different
    /// paths, and provisioning has to name the second one.
    #[test]
    fn the_node_bin_directory_is_the_local_install_link_directory() {
        let prefix = managed_node_prefix();
        let bin = managed_node_bin_dir();
        assert_eq!(
            bin,
            prefix.join("node_modules").join(".bin"),
            "`npm install --prefix` links binaries into node_modules/.bin, not into bin"
        );
        assert!(
            managed_tool_dirs().contains(&bin),
            "a directory provisioning writes into must be one PATH carries"
        );
    }

    /// The process mutation and the composition agree, asserted against the
    /// live environment rather than inferred from the pure half.
    ///
    /// Kept separate and behind the workspace's one sanctioned environment
    /// guard, because this is the only assertion here whose subject IS the
    /// environment read.
    #[test]
    fn the_process_path_gains_the_tool_directories() {
        let _guard = crate::test_env::EnvVarGuard::set("PATH", "/usr/bin");
        assert!(
            augment_path_with_managed_tools(),
            "a PATH of /usr/bin alone carries none of Kin's tool directories"
        );
        let after = std::env::var_os("PATH").expect("PATH must still be set");
        let entries = parts(&after);
        for dir in managed_tool_dirs() {
            assert!(
                entries.contains(&dir),
                "PATH must carry {} after augmentation, got {after:?}",
                dir.display()
            );
        }
        assert!(
            !augment_path_with_managed_tools(),
            "a second call must be a no-op rather than a second append"
        );
    }
}
