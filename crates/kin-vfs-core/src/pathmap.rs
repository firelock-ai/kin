// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Pure, allocation-light path-mapping seams shared by the VFS shim's
//! interception hooks.
//!
//! These functions are the *security- and correctness-critical* string seams of
//! interposition: deciding whether a path is inside the workspace (and thus
//! eligible for graph-backed serving), synthesizing stable inode numbers, and
//! composing the temp/relative paths the `open`/`openat`/`fstatat` hooks build.
//!
//! They live in `kin-vfs-core` — a plain `rlib` with **no** libc interposition —
//! rather than in `kin-vfs-shim` on purpose:
//!
//! 1. They can be unit-tested on any host (no LD_PRELOAD/DYLD machinery needed).
//! 2. They can be **fuzzed** without linking the shim's `#[no_mangle]` libc
//!    overrides into the fuzz binary. Linking the shim would make the fuzz
//!    target self-interpose its own libc calls (`open`, `read`, …), breaking
//!    libFuzzer's corpus/crash file I/O. Keeping the fuzzable logic here means
//!    the fuzz crate depends on `kin-vfs-core` only and never pulls in a single
//!    interposing symbol.
//!
//! The shim delegates to these so there is exactly one definition of each seam
//! and no drift between the fuzzed/tested code and the production hot path.

/// Why a host path cannot be translated into a graph-owned, repo-relative key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspacePathError {
    /// The intercepted path or configured workspace root is not absolute.
    NotAbsolute,
    /// The intercepted path is outside the configured workspace root.
    OutsideRoot,
    /// A `..` component makes lexical containment ambiguous (especially through
    /// symlinks), so the path must not be presented to graph authority.
    ParentTraversal,
    /// More than one trusted workspace root contains the path but produces a
    /// different repo-relative key. Treat the alias configuration as invalid
    /// instead of guessing which graph identity should win.
    AliasAmbiguity,
}

/// Translate an absolute host path into the repo-relative key stored by Kin's
/// graph and returned by the daemon's `/vfs/tree` endpoint.
///
/// Both inputs use forward-slash semantics. Empty and `.` components are
/// normalized away, while `..` is rejected instead of being folded lexically:
/// resolving `link/../file` without consulting the host filesystem is ambiguous
/// when `link` is a symlink. This keeps an intercepted path from escaping (or
/// merely appearing to remain inside) the workspace through traversal syntax.
///
/// The workspace root itself maps to the empty graph key; descendants map to a
/// slash-separated relative key with no leading slash.
pub fn workspace_graph_key(path: &str, root: &str) -> Result<String, WorkspacePathError> {
    fn components(input: &str) -> Result<(Option<&str>, Vec<&str>), WorkspacePathError> {
        let (prefix, absolute) = if input.starts_with('/') {
            (None, input)
        } else if input.as_bytes().get(1) == Some(&b':') && input.as_bytes().get(2) == Some(&b'/') {
            (Some(&input[..2]), &input[2..])
        } else {
            return Err(WorkspacePathError::NotAbsolute);
        };

        let mut result = Vec::new();
        for component in absolute.split('/') {
            match component {
                "" | "." => {}
                ".." => return Err(WorkspacePathError::ParentTraversal),
                normal => result.push(normal),
            }
        }
        Ok((prefix, result))
    }

    let (path_prefix, path_components) = components(path)?;
    let (root_prefix, root_components) = components(root)?;
    if !match (path_prefix, root_prefix) {
        (Some(path), Some(root)) => path.eq_ignore_ascii_case(root),
        (None, None) => true,
        _ => false,
    } {
        return Err(WorkspacePathError::OutsideRoot);
    }

    let root_matches = if path_prefix.is_some() {
        path_components
            .iter()
            .zip(&root_components)
            .all(|(path, root)| path.eq_ignore_ascii_case(root))
    } else {
        path_components.starts_with(&root_components)
    };
    if path_components.len() < root_components.len() || !root_matches {
        return Err(WorkspacePathError::OutsideRoot);
    }

    Ok(path_components[root_components.len()..].join("/"))
}

/// Translate `path` through one canonical workspace root plus any launcher-
/// verified lexical aliases for that same root.
///
/// Intercepted paths cannot be canonicalized inside a libc hook: doing so would
/// re-enter the host filesystem and make raw disk part of the authority path.
/// The launcher can, however, resolve the workspace before injection and pass
/// the lexical spelling the child will use (for example macOS `/var/...` beside
/// canonical `/private/var/...`, or a user-provided symlink root). Each candidate
/// is still checked by [`workspace_graph_key`], including traversal and prefix-
/// sibling rejection. If overlapping aliases disagree about the relative key,
/// this fails closed with [`WorkspacePathError::AliasAmbiguity`].
pub fn workspace_graph_key_from_roots<'a>(
    path: &str,
    roots: impl IntoIterator<Item = &'a str>,
) -> Result<String, WorkspacePathError> {
    let mut key: Option<String> = None;
    let mut saw_not_absolute = false;

    for root in roots {
        match workspace_graph_key(path, root) {
            Ok(candidate) => {
                if key.as_ref().is_some_and(|existing| existing != &candidate) {
                    return Err(WorkspacePathError::AliasAmbiguity);
                }
                key = Some(candidate);
            }
            Err(WorkspacePathError::OutsideRoot) => {}
            Err(WorkspacePathError::NotAbsolute) => saw_not_absolute = true,
            Err(error @ WorkspacePathError::ParentTraversal)
            | Err(error @ WorkspacePathError::AliasAmbiguity) => return Err(error),
        }
    }

    key.ok_or(if saw_not_absolute {
        WorkspacePathError::NotAbsolute
    } else {
        WorkspacePathError::OutsideRoot
    })
}

/// FNV-1a 64-bit hash of `s`, used to synthesize a stable, low-collision inode
/// number for a virtual file or directory entry.
///
/// Tools like `find`, `tar`, and hardlink detectors key off `st_ino`, so two
/// distinct virtual paths must get distinct inodes. Deterministic and total:
/// never panics for any input, including empty or non-ASCII strings.
#[inline]
pub fn synthetic_inode(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
    for byte in s.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3); // FNV-1a prime
    }
    hash
}

/// `true` when `path` denotes an interposition temp artifact (`…​.kin_tmp_<pid>`).
///
/// `materialize_file` seeds a tool's write through `{target}.kin_tmp_{pid}` via
/// `std::fs::write`, which itself calls the hooked `open()`. Such temp paths must
/// be excluded from workspace interception so the shim does not re-enter the
/// daemon for a path that isn't in the tree (it would fall through to the real
/// syscall anyway). This is the exclusion half of [`atomic_temp_path`]'s
/// contract: every path produced by `atomic_temp_path` must satisfy this.
#[inline]
pub fn is_interpose_temp_artifact(path: &str) -> bool {
    path.contains(".kin_tmp_")
}

/// `true` when absolute `path` lies within `root`: either equal to `root`, or a
/// descendant separated by a `/` boundary.
///
/// This is the containment check that gates interception — a security boundary.
/// It is a prefix test **with a separator guard**, so a sibling that merely
/// shares a textual prefix is correctly rejected (`/ws/project` does NOT contain
/// `/ws/project2/file` nor `/ws/projectx`). Pure and total: never panics, never
/// indexes out of bounds (the boundary byte is read via `slice::get`).
///
/// Forward-slash semantics. Callers that may see OS-native separators (Windows
/// backslashes) must normalize both arguments to `/` before calling.
#[inline]
pub fn path_within_root(path: &str, root: &str) -> bool {
    path.starts_with(root)
        && (path.len() == root.len() || path.as_bytes().get(root.len()) == Some(&b'/'))
}

/// Compose the atomic-write temp path the shim opens before letting a tool write
/// to `target`; on `close` the temp is renamed onto `target`.
///
/// Format: `{target}.kin_tmp_{pid}`. Pure given `pid` (the caller passes
/// `libc::getpid()` from the hook). Every value it returns is, by construction,
/// recognized by [`is_interpose_temp_artifact`] — fuzzed as a round-trip
/// invariant so the exclusion can never silently drift out of sync.
#[inline]
pub fn atomic_temp_path(target: &str, pid: i32) -> String {
    format!("{target}.kin_tmp_{pid}")
}

/// Join a possibly-relative `rel` against directory `base` — the pure core of
/// `openat`/`fstatat`/`faccessat` path resolution once `base` (the dirfd's
/// directory, or the cwd) has been resolved to an absolute string.
///
/// An absolute `rel` (leading `/`) is authoritative and returned unchanged;
/// otherwise the result is `{base}/{rel}`. Pure and total: never panics.
#[inline]
pub fn join_at_path(base: &str, rel: &str) -> String {
    if rel.starts_with('/') {
        rel.to_string()
    } else {
        format!("{base}/{rel}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_inode_is_deterministic() {
        assert_eq!(synthetic_inode("/ws/a.rs"), synthetic_inode("/ws/a.rs"));
    }

    #[test]
    fn synthetic_inode_distinguishes_paths() {
        assert_ne!(synthetic_inode("/ws/a.rs"), synthetic_inode("/ws/b.rs"));
    }

    #[test]
    fn synthetic_inode_handles_empty_and_unicode() {
        // Must never panic on degenerate or multibyte input.
        let _ = synthetic_inode("");
        let _ = synthetic_inode("/ws/café/日本語.rs");
    }

    #[test]
    fn temp_artifact_detected() {
        assert!(is_interpose_temp_artifact("/ws/main.rs.kin_tmp_1234"));
        assert!(!is_interpose_temp_artifact("/ws/main.rs"));
    }

    #[test]
    fn path_within_root_matches_self_and_children() {
        assert!(path_within_root("/ws/project", "/ws/project"));
        assert!(path_within_root("/ws/project/src/main.rs", "/ws/project"));
        assert!(path_within_root("/ws/project/Cargo.toml", "/ws/project"));
    }

    #[test]
    fn path_within_root_rejects_prefix_siblings() {
        // The separator guard is the whole point: shared textual prefix is not
        // containment.
        assert!(!path_within_root("/ws/project2/file.rs", "/ws/project"));
        assert!(!path_within_root("/ws/projectx", "/ws/project"));
        assert!(!path_within_root("/etc/passwd", "/ws/project"));
        assert!(!path_within_root("relative/path", "/ws/project"));
    }

    #[test]
    fn path_within_root_total_on_multibyte_boundary() {
        // root.len() may land inside a multibyte char of `path`; `slice::get`
        // keeps this total instead of panicking on a non-char-boundary index.
        assert!(!path_within_root("/wséxtra", "/ws"));
    }

    #[test]
    fn workspace_graph_key_maps_host_absolute_path_to_repo_relative_key() {
        assert_eq!(
            workspace_graph_key("/ws/project/src/main.rs", "/ws/project"),
            Ok("src/main.rs".to_string())
        );
        assert_eq!(
            workspace_graph_key("/ws/project", "/ws/project"),
            Ok(String::new())
        );
    }

    #[test]
    fn workspace_graph_key_normalizes_safe_dot_and_separator_components() {
        assert_eq!(
            workspace_graph_key("/ws//project/./src/lib.rs", "/ws/project/"),
            Ok("src/lib.rs".to_string())
        );
    }

    #[test]
    fn workspace_graph_key_rejects_outside_and_prefix_sibling_paths() {
        assert_eq!(
            workspace_graph_key("/ws/project2/file.rs", "/ws/project"),
            Err(WorkspacePathError::OutsideRoot)
        );
        assert_eq!(
            workspace_graph_key("/etc/passwd", "/ws/project"),
            Err(WorkspacePathError::OutsideRoot)
        );
    }

    #[test]
    fn workspace_graph_key_rejects_relative_and_parent_traversal_paths() {
        assert_eq!(
            workspace_graph_key("src/main.rs", "/ws/project"),
            Err(WorkspacePathError::NotAbsolute)
        );
        assert_eq!(
            workspace_graph_key("/ws/project/src/../secret.rs", "/ws/project"),
            Err(WorkspacePathError::ParentTraversal)
        );
        assert_eq!(
            workspace_graph_key("/ws/project/src/main.rs", "/ws/../project"),
            Err(WorkspacePathError::ParentTraversal)
        );
    }

    #[test]
    fn workspace_graph_key_supports_normalized_windows_drive_paths() {
        assert_eq!(
            workspace_graph_key("C:/Users/Test/Project/src/Main.rs", "c:/users/test/project"),
            Ok("src/Main.rs".to_string())
        );
        assert_eq!(
            workspace_graph_key("D:/Users/Test/Project/src/Main.rs", "C:/Users/Test/Project"),
            Err(WorkspacePathError::OutsideRoot)
        );
    }

    #[test]
    fn workspace_graph_key_accepts_trusted_macos_and_symlink_aliases() {
        let macos_roots = ["/private/var/folders/xy/repo", "/var/folders/xy/repo"];
        assert_eq!(
            workspace_graph_key_from_roots(
                "/var/folders/xy/repo/probe.rs",
                macos_roots.iter().copied(),
            ),
            Ok("probe.rs".to_string())
        );
        assert_eq!(
            workspace_graph_key_from_roots(
                "/private/var/folders/xy/repo/src/lib.rs",
                macos_roots.iter().copied(),
            ),
            Ok("src/lib.rs".to_string())
        );

        let symlink_roots = ["/srv/repos/project", "/work/project-link"];
        assert_eq!(
            workspace_graph_key_from_roots(
                "/work/project-link/src/main.rs",
                symlink_roots.iter().copied(),
            ),
            Ok("src/main.rs".to_string())
        );
    }

    #[test]
    fn workspace_graph_key_aliases_still_fail_closed() {
        let roots = ["/ws/project", "/aliases/project"];
        assert_eq!(
            workspace_graph_key_from_roots("/etc/passwd", roots.iter().copied()),
            Err(WorkspacePathError::OutsideRoot)
        );
        assert_eq!(
            workspace_graph_key_from_roots(
                "/aliases/project/src/../secret.rs",
                roots.iter().copied(),
            ),
            Err(WorkspacePathError::ParentTraversal)
        );

        let overlapping = ["/ws", "/ws/project"];
        assert_eq!(
            workspace_graph_key_from_roots("/ws/project/src/main.rs", overlapping.iter().copied(),),
            Err(WorkspacePathError::AliasAmbiguity)
        );
    }

    #[test]
    fn atomic_temp_path_round_trips_exclusion() {
        let tmp = atomic_temp_path("/ws/project/src/main.rs", 4321);
        assert_eq!(tmp, "/ws/project/src/main.rs.kin_tmp_4321");
        // The exclusion MUST recognize anything this produces.
        assert!(is_interpose_temp_artifact(&tmp));
    }

    #[test]
    fn join_at_path_absolute_wins() {
        assert_eq!(join_at_path("/cwd", "/abs/path"), "/abs/path");
    }

    #[test]
    fn join_at_path_relative_is_joined() {
        assert_eq!(join_at_path("/cwd", "rel/file.rs"), "/cwd/rel/file.rs");
        assert_eq!(join_at_path("/cwd", ""), "/cwd/");
    }
}
