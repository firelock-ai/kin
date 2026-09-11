// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Pure, allocation-light path-mapping seams shared by the VFS shim's
//! interception hooks.
//!
//! These functions are the *security- and correctness-critical* byte seams of
//! interposition: deciding whether a path is inside the workspace (and thus
//! eligible for graph-backed serving), synthesizing stable inode numbers, and
//! composing the temp/relative paths the `open`/`openat`/`fstatat` hooks build.
//!
//! All inputs are exact host-path bytes (`&[u8]`). Unix paths are byte
//! sequences, not strings; interception must never require UTF-8 or apply a
//! lossy conversion — a non-UTF8 workspace path is served with full graph
//! authority, never passed through to raw disk.
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

use crate::path::VfsPath;

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
    /// The bytes cannot form a valid graph path (e.g. an embedded NUL).
    InvalidPath,
}

/// Translate an absolute host path into the byte-exact repo-relative key stored
/// by Kin's graph and served by the daemon's tree endpoint.
///
/// Both inputs use forward-slash semantics. Empty and `.` components are
/// normalized away, while `..` is rejected instead of being folded lexically:
/// resolving `link/../file` without consulting the host filesystem is ambiguous
/// when `link` is a symlink. This keeps an intercepted path from escaping (or
/// merely appearing to remain inside) the workspace through traversal syntax.
///
/// The workspace root itself maps to [`VfsPath::root`]; descendants map to a
/// slash-separated relative key with no leading slash.
pub fn workspace_graph_key(path: &[u8], root: &[u8]) -> Result<VfsPath, WorkspacePathError> {
    type Components<'a> = (Option<&'a [u8]>, Vec<&'a [u8]>);

    fn components(input: &[u8]) -> Result<Components<'_>, WorkspacePathError> {
        let (prefix, absolute): (Option<&[u8]>, &[u8]) = if input.first() == Some(&b'/') {
            (None, input)
        } else if input.get(1) == Some(&b':') && input.get(2) == Some(&b'/') {
            (Some(&input[..2]), &input[2..])
        } else {
            return Err(WorkspacePathError::NotAbsolute);
        };

        let mut result = Vec::new();
        for component in absolute.split(|byte| *byte == b'/') {
            match component {
                b"" | b"." => {}
                b".." => return Err(WorkspacePathError::ParentTraversal),
                normal => {
                    if normal.contains(&0) {
                        return Err(WorkspacePathError::InvalidPath);
                    }
                    result.push(normal);
                }
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

    let relative = &path_components[root_components.len()..];
    let mut key = Vec::with_capacity(
        relative
            .iter()
            .map(|component| component.len() + 1)
            .sum::<usize>()
            .saturating_sub(1),
    );
    for (index, component) in relative.iter().enumerate() {
        if index > 0 {
            key.push(b'/');
        }
        key.extend_from_slice(component);
    }
    VfsPath::from_bytes(key).map_err(|_| WorkspacePathError::InvalidPath)
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
    path: &[u8],
    roots: impl IntoIterator<Item = &'a [u8]>,
) -> Result<VfsPath, WorkspacePathError> {
    let mut key: Option<VfsPath> = None;
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
            Err(
                error @ (WorkspacePathError::ParentTraversal
                | WorkspacePathError::AliasAmbiguity
                | WorkspacePathError::InvalidPath),
            ) => return Err(error),
        }
    }

    key.ok_or(if saw_not_absolute {
        WorkspacePathError::NotAbsolute
    } else {
        WorkspacePathError::OutsideRoot
    })
}

/// FNV-1a 64-bit hash of `bytes`, used to synthesize a stable, low-collision
/// inode number for a virtual file or directory entry.
///
/// Tools like `find`, `tar`, and hardlink detectors key off `st_ino`, so two
/// distinct virtual paths must get distinct inodes. Deterministic and total:
/// never panics for any input, including empty or non-UTF8 bytes.
#[inline]
pub fn synthetic_inode(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
    for byte in bytes {
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
/// daemon for a path that isn't in the tree. They are explicit projection
/// artifacts served by the real syscall, not semantic answer paths. This is the
/// exclusion half of [`atomic_temp_path`]'s
/// contract: every path produced by `atomic_temp_path` must satisfy this.
#[inline]
pub fn is_interpose_temp_artifact(path: &[u8]) -> bool {
    const MARKER: &[u8] = b".kin_tmp_";
    path.len() >= MARKER.len() && path.windows(MARKER.len()).any(|window| window == MARKER)
}

/// `true` when absolute `path` lies within `root`: either equal to `root`, or a
/// descendant separated by a `/` boundary.
///
/// This is the containment check that gates interception — a security boundary.
/// It is a prefix test **with a separator guard**, so a sibling that merely
/// shares a byte prefix is correctly rejected (`/ws/project` does NOT contain
/// `/ws/project2/file` nor `/ws/projectx`). Pure and total: never panics, never
/// indexes out of bounds (the boundary byte is read via `slice::get`).
///
/// Forward-slash semantics. Callers that may see OS-native separators (Windows
/// backslashes) must normalize both arguments to `/` before calling.
#[inline]
pub fn path_within_root(path: &[u8], root: &[u8]) -> bool {
    path.starts_with(root) && (path.len() == root.len() || path.get(root.len()) == Some(&b'/'))
}

/// The file a Kin repository carries under its root to name itself, relative to
/// that root.
///
/// A directory is not a repository merely because it holds a `.kin` entry. The
/// Kin managed toolchain home is `$KIN_HOME` (default `$HOME/.kin`), a real
/// directory holding `bin/`, `lib/`, `shell/` and `config/`, so any marker walk
/// that asks only whether `.kin` is a directory binds the user's home as a
/// projection root and every path under it becomes graph-owned.
///
/// This file is the discriminator, and it is already the daemon's: the endpoint
/// reads it to bind repository and workspace identity before it constructs or
/// sends any request, so a root without it cannot be served at all. Refusing to
/// project such a root can only turn a failure into a pass-through; it can
/// never disable a projection that would otherwise have worked.
///
/// Spelled with `/` so it composes with [`join_at_path`] on Unix and with
/// `Path::join` on Windows, which accepts either separator.
pub const REPOSITORY_IDENTITY_MARKER: &str = ".kin/manifest.json";

/// Compose the atomic-write temp path the shim opens before letting a tool write
/// to `target`; on `close` the temp is renamed onto `target`.
///
/// Format: `{target}.kin_tmp_{pid}`. Pure given `pid` (the caller passes
/// `libc::getpid()` from the hook). Every value it returns is, by construction,
/// recognized by [`is_interpose_temp_artifact`] — fuzzed as a round-trip
/// invariant so the exclusion can never silently drift out of sync.
#[inline]
pub fn atomic_temp_path(target: &[u8], pid: i32) -> Vec<u8> {
    let suffix = format!(".kin_tmp_{pid}");
    let mut path = Vec::with_capacity(target.len() + suffix.len());
    path.extend_from_slice(target);
    path.extend_from_slice(suffix.as_bytes());
    path
}

/// Join a possibly-relative `rel` against directory `base` — the pure core of
/// `openat`/`fstatat`/`faccessat` path resolution once `base` (the dirfd's
/// directory, or the cwd) has been resolved to absolute bytes.
///
/// An absolute `rel` (leading `/`) is authoritative and returned unchanged;
/// otherwise the result is `{base}/{rel}`. Pure and total: never panics.
#[inline]
pub fn join_at_path(base: &[u8], rel: &[u8]) -> Vec<u8> {
    if rel.first() == Some(&b'/') {
        rel.to_vec()
    } else {
        let mut joined = Vec::with_capacity(base.len() + 1 + rel.len());
        joined.extend_from_slice(base);
        joined.push(b'/');
        joined.extend_from_slice(rel);
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(text: &str) -> VfsPath {
        VfsPath::from_utf8(text).unwrap()
    }

    #[test]
    fn synthetic_inode_is_deterministic() {
        assert_eq!(synthetic_inode(b"/ws/a.rs"), synthetic_inode(b"/ws/a.rs"));
    }

    #[test]
    fn synthetic_inode_distinguishes_paths() {
        assert_ne!(synthetic_inode(b"/ws/a.rs"), synthetic_inode(b"/ws/b.rs"));
    }

    #[test]
    fn synthetic_inode_handles_empty_and_raw_bytes() {
        // Must never panic on degenerate or non-UTF8 input.
        let _ = synthetic_inode(b"");
        let _ = synthetic_inode("/ws/café/日本語.rs".as_bytes());
        let _ = synthetic_inode(b"/ws/raw-\xff\xfe");
    }

    #[test]
    fn temp_artifact_detected() {
        assert!(is_interpose_temp_artifact(b"/ws/main.rs.kin_tmp_1234"));
        assert!(!is_interpose_temp_artifact(b"/ws/main.rs"));
        assert!(!is_interpose_temp_artifact(b""));
    }

    #[test]
    fn path_within_root_matches_self_and_children() {
        assert!(path_within_root(b"/ws/project", b"/ws/project"));
        assert!(path_within_root(b"/ws/project/src/main.rs", b"/ws/project"));
        assert!(path_within_root(b"/ws/project/Cargo.toml", b"/ws/project"));
    }

    #[test]
    fn path_within_root_rejects_prefix_siblings() {
        // The separator guard is the whole point: shared byte prefix is not
        // containment.
        assert!(!path_within_root(b"/ws/project2/file.rs", b"/ws/project"));
        assert!(!path_within_root(b"/ws/projectx", b"/ws/project"));
        assert!(!path_within_root(b"/etc/passwd", b"/ws/project"));
        assert!(!path_within_root(b"relative/path", b"/ws/project"));
    }

    #[test]
    fn path_within_root_total_on_arbitrary_boundary_bytes() {
        // root.len() may land on any byte of `path`; `slice::get` keeps this
        // total instead of panicking, including on non-UTF8 bytes.
        assert!(!path_within_root("/wséxtra".as_bytes(), b"/ws"));
        assert!(!path_within_root(b"/ws\xff", b"/ws"));
    }

    #[test]
    fn workspace_graph_key_maps_host_absolute_path_to_repo_relative_key() {
        assert_eq!(
            workspace_graph_key(b"/ws/project/src/main.rs", b"/ws/project"),
            Ok(key("src/main.rs"))
        );
        assert_eq!(
            workspace_graph_key(b"/ws/project", b"/ws/project"),
            Ok(VfsPath::root())
        );
    }

    #[test]
    fn workspace_graph_key_preserves_non_utf8_bytes_exactly() {
        let raw = b"/ws/project/logs/x-\xff\xfe.log";
        let mapped = workspace_graph_key(raw, b"/ws/project").unwrap();
        assert_eq!(mapped.as_bytes(), b"logs/x-\xff\xfe.log");
    }

    #[test]
    fn workspace_graph_key_normalizes_safe_dot_and_separator_components() {
        assert_eq!(
            workspace_graph_key(b"/ws//project/./src/lib.rs", b"/ws/project/"),
            Ok(key("src/lib.rs"))
        );
    }

    #[test]
    fn workspace_graph_key_rejects_outside_and_prefix_sibling_paths() {
        assert_eq!(
            workspace_graph_key(b"/ws/project2/file.rs", b"/ws/project"),
            Err(WorkspacePathError::OutsideRoot)
        );
        assert_eq!(
            workspace_graph_key(b"/etc/passwd", b"/ws/project"),
            Err(WorkspacePathError::OutsideRoot)
        );
    }

    #[test]
    fn workspace_graph_key_rejects_relative_traversal_and_nul_paths() {
        assert_eq!(
            workspace_graph_key(b"src/main.rs", b"/ws/project"),
            Err(WorkspacePathError::NotAbsolute)
        );
        assert_eq!(
            workspace_graph_key(b"/ws/project/src/../secret.rs", b"/ws/project"),
            Err(WorkspacePathError::ParentTraversal)
        );
        assert_eq!(
            workspace_graph_key(b"/ws/project/src/main.rs", b"/ws/../project"),
            Err(WorkspacePathError::ParentTraversal)
        );
        assert_eq!(
            workspace_graph_key(b"/ws/project/bad\0name", b"/ws/project"),
            Err(WorkspacePathError::InvalidPath)
        );
    }

    #[test]
    fn workspace_graph_key_supports_normalized_windows_drive_paths() {
        assert_eq!(
            workspace_graph_key(
                b"C:/Users/Test/Project/src/Main.rs",
                b"c:/users/test/project"
            ),
            Ok(key("src/Main.rs"))
        );
        assert_eq!(
            workspace_graph_key(
                b"D:/Users/Test/Project/src/Main.rs",
                b"C:/Users/Test/Project"
            ),
            Err(WorkspacePathError::OutsideRoot)
        );
    }

    #[test]
    fn workspace_graph_key_accepts_trusted_macos_and_symlink_aliases() {
        let macos_roots: [&[u8]; 2] = [b"/private/var/folders/xy/repo", b"/var/folders/xy/repo"];
        assert_eq!(
            workspace_graph_key_from_roots(
                b"/var/folders/xy/repo/probe.rs",
                macos_roots.iter().copied(),
            ),
            Ok(key("probe.rs"))
        );
        assert_eq!(
            workspace_graph_key_from_roots(
                b"/private/var/folders/xy/repo/src/lib.rs",
                macos_roots.iter().copied(),
            ),
            Ok(key("src/lib.rs"))
        );

        let symlink_roots: [&[u8]; 2] = [b"/srv/repos/project", b"/work/project-link"];
        assert_eq!(
            workspace_graph_key_from_roots(
                b"/work/project-link/src/main.rs",
                symlink_roots.iter().copied(),
            ),
            Ok(key("src/main.rs"))
        );
    }

    #[test]
    fn workspace_graph_key_aliases_still_fail_closed() {
        let roots: [&[u8]; 2] = [b"/ws/project", b"/aliases/project"];
        assert_eq!(
            workspace_graph_key_from_roots(b"/etc/passwd", roots.iter().copied()),
            Err(WorkspacePathError::OutsideRoot)
        );
        assert_eq!(
            workspace_graph_key_from_roots(
                b"/aliases/project/src/../secret.rs",
                roots.iter().copied(),
            ),
            Err(WorkspacePathError::ParentTraversal)
        );

        let overlapping: [&[u8]; 2] = [b"/ws", b"/ws/project"];
        assert_eq!(
            workspace_graph_key_from_roots(b"/ws/project/src/main.rs", overlapping.iter().copied()),
            Err(WorkspacePathError::AliasAmbiguity)
        );
    }

    #[test]
    fn atomic_temp_path_round_trips_exclusion() {
        let tmp = atomic_temp_path(b"/ws/project/src/main.rs", 4321);
        assert_eq!(tmp, b"/ws/project/src/main.rs.kin_tmp_4321");
        // The exclusion MUST recognize anything this produces.
        assert!(is_interpose_temp_artifact(&tmp));

        // Non-UTF8 targets round-trip byte-exactly.
        let raw = atomic_temp_path(b"/ws/x-\xff.bin", 7);
        assert_eq!(raw, b"/ws/x-\xff.bin.kin_tmp_7");
        assert!(is_interpose_temp_artifact(&raw));
    }

    #[test]
    fn join_at_path_absolute_wins() {
        assert_eq!(join_at_path(b"/cwd", b"/abs/path"), b"/abs/path");
    }

    #[test]
    fn join_at_path_relative_is_joined() {
        assert_eq!(join_at_path(b"/cwd", b"rel/file.rs"), b"/cwd/rel/file.rs");
        assert_eq!(join_at_path(b"/cwd", b""), b"/cwd/");
        assert_eq!(join_at_path(b"/cwd", b"raw-\xff"), b"/cwd/raw-\xff");
    }

    #[test]
    fn cwd_joined_relative_path_maps_to_its_absolute_twin() {
        // A relative path read from inside the workspace must reach exactly the
        // graph key its absolute spelling does; anything else lets the same file
        // be answered by two different authorities.
        let root: &[u8] = b"/ws/project";
        for (cwd, relative, absolute) in [
            (
                &b"/ws/project"[..],
                &b"src/main.rs"[..],
                &b"/ws/project/src/main.rs"[..],
            ),
            (b"/ws/project/src", b"main.rs", b"/ws/project/src/main.rs"),
            (b"/ws/project/src", b"./main.rs", b"/ws/project/src/main.rs"),
            (
                b"/ws/project",
                b"logs/x-\xff\xfe.log",
                b"/ws/project/logs/x-\xff\xfe.log",
            ),
        ] {
            assert_eq!(
                workspace_graph_key(&join_at_path(cwd, relative), root),
                workspace_graph_key(absolute, root)
            );
        }

        // Joining does not widen the boundary: a relative path from a cwd
        // outside the workspace stays outside it.
        assert_eq!(
            workspace_graph_key(&join_at_path(b"/etc", b"passwd"), root),
            Err(WorkspacePathError::OutsideRoot)
        );
        assert_eq!(
            workspace_graph_key(&join_at_path(b"/ws/project2", b"file.rs"), root),
            Err(WorkspacePathError::OutsideRoot)
        );
    }
}
