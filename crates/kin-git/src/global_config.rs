// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Empty global Git configuration for Kin's Git-process authority boundaries.
//!
//! Every Kin surface that shells out to Git binds `GIT_CONFIG_GLOBAL` so the
//! ambient global configuration scope cannot steer the child. This module owns
//! the single answer to "what path means no global configuration", because the
//! answer is not the same on every target and getting it wrong disables Git
//! entirely rather than degrading isolation.

use std::ffi::OsStr;

/// Path to bind to `GIT_CONFIG_GLOBAL` so Git resolves the global configuration
/// scope to no configuration at all.
///
/// `GIT_CONFIG_GLOBAL` *replaces* the global scope rather than adding to it, so
/// an empty file is exactly what silences `$HOME/.gitconfig` and its XDG
/// sibling.
///
/// Unix names `/dev/null`, which Git opens and reads as that empty file. No
/// other target has an equivalent path, and Windows in particular does not:
/// `NUL` is a reserved device name rather than a file, and Git refuses it with
/// `fatal: unable to access 'NUL': Invalid argument`. A boundary that bound
/// `NUL` therefore failed every Git command it was meant to isolate. Git
/// accepts any readable file, so the remaining targets share one real empty
/// file, created once per process.
///
/// The returned lifetime is deliberately `'static`. Callers mutate a
/// [`std::process::Command`] and return before that command is spawned, so a
/// file owned by the calling function would already be unlinked by the time Git
/// opened it. Tying the file to the process instead removes that failure mode
/// from the call sites rather than asking each of them to re-derive it.
///
/// The file is a freshly created temporary rather than a predictable path.
/// Callers are authority boundaries: a path another process can pre-create is a
/// path it can pre-fill with a hostile global configuration, which is the exact
/// authority the boundary exists to remove.
///
/// Creating that file is the only fallible step, and it fails loudly. Silently
/// leaving `GIT_CONFIG_GLOBAL` unbound would hand the child the ambient global
/// scope from inside the function whose whole purpose is to take it away.
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
            // `tempfile` creates the file already empty, so the config needs no
            // write of its own — there is no content to put in it.
            //
            // `keep` persists it past the command that first asked for it:
            // every later Git launch in this process reuses the same file.
            let (file, path) = tempfile::Builder::new()
                .prefix("kin-empty-global-gitconfig-")
                .tempfile()
                .expect("create empty global Git config")
                .keep()
                .expect("persist empty global Git config");
            // Closed before any child is spawned: Windows will not hand Git a
            // second handle to a file this process still holds open.
            drop(file);
            path
        })
        .as_os_str()
}

#[cfg(test)]
mod tests {
    use super::empty_global_git_config;

    /// The property Git actually needs, asserted on every target: the bound
    /// path opens and yields no configuration. `NUL` fails this on Windows,
    /// where it is a device rather than a file, and fails it on every other
    /// target, where nothing of that name exists at all.
    #[test]
    fn bound_path_opens_and_reads_as_empty() {
        let path = empty_global_git_config();
        let contents = std::fs::read(path).unwrap_or_else(|error| {
            panic!("global Git config {path:?} is not a readable path: {error}")
        });
        assert!(
            contents.is_empty(),
            "global Git config {path:?} carries {} bytes of configuration",
            contents.len()
        );
    }

    /// The path outlives any one command, so repeated boundary applications in
    /// a process bind the same file rather than racing to recreate it.
    #[test]
    fn bound_path_is_stable_within_the_process() {
        assert_eq!(empty_global_git_config(), empty_global_git_config());
    }

    #[cfg(unix)]
    #[test]
    fn unix_binds_the_null_device() {
        assert_eq!(
            empty_global_git_config(),
            std::ffi::OsStr::new("/dev/null"),
            "Unix lost the path Git already reads as an empty config"
        );
    }

    /// Off Unix there is no device Git will open, so the bound path has to be a
    /// real, empty, regular file.
    #[cfg(not(unix))]
    #[test]
    fn non_unix_binds_an_empty_regular_file() {
        let path = empty_global_git_config();
        let metadata = std::fs::metadata(path)
            .unwrap_or_else(|error| panic!("global Git config {path:?} is not a path: {error}"));
        assert!(
            metadata.is_file(),
            "global Git config {path:?} is not a regular file"
        );
        assert_eq!(metadata.len(), 0, "global Git config {path:?} is not empty");
    }
}
