// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Where a projected write is allowed to land.
//!
//! Every mount that admits writes stages them in the served repository's
//! working copy, so the question "is this path inside the repository" decides
//! whether a save through the mount edits the repository or edits the machine.
//!
//! [`VfsPath`] answers the *lexical* half of that question at decode time: it
//! is relative, carries no `.` or `..` component, no empty component and no
//! NUL. That is a real invariant and it is not the whole answer, because
//! joining a clean relative path onto a clean root still traverses whatever
//! symlinks the working copy already holds. A repository that carries
//! `docs -> /etc` sends `docs/hosts` to `/etc/hosts` with no `..` anywhere in
//! sight, and lexical containment reports it contained.
//!
//! So containment here is resolved rather than spelled. Each component is
//! walked from the canonical root; a component that is a symlink is followed
//! only when the kernel resolves it to a path still under that root, and the
//! walk continues from the resolved location so the next component is judged
//! against where it actually lives. Nothing is repaired, guessed or normalized
//! by string arithmetic: a symlink the kernel cannot resolve at all, because it
//! dangles or loops, is refused rather than followed to a path that does not
//! exist yet, since creating that path is exactly the escape.
//!
//! What this does not carry: the resolution and the open that follows it are
//! two syscalls, so a symlink swapped between them is resolved as it was, not
//! as it became. Closing that needs `openat` with `O_NOFOLLOW` per component
//! against a retained directory descriptor, which is what kin-core's own
//! retained-directory writes do. The attacker who can win that race can already
//! write the working copy directly, which is the thing the race would buy.

use std::path::{Component, Path, PathBuf};

use crate::error::{VfsError, VfsResult};
use crate::path::VfsPath;

/// The host path a workspace-relative path names, with every component
/// resolved and the final one followed.
///
/// This is the form for operations on a file's *content*: open, write,
/// truncate, chmod, hash. Following the final component matches what those
/// calls do anyway, and the resolution is what makes the destination provably
/// inside `root`.
pub fn contained_target(root: &Path, path: &VfsPath) -> VfsResult<PathBuf> {
    resolve(root, path, true)
}

/// The host path a workspace-relative path names, with every component
/// resolved *except* the final one.
///
/// This is the form for operations on the directory entry itself: remove and
/// rename act on the link, not on what it points at, and resolving the final
/// component would make `rm link` delete the target instead.
pub fn contained_entry(root: &Path, path: &VfsPath) -> VfsResult<PathBuf> {
    resolve(root, path, false)
}

/// The refusal, carrying the path the caller named rather than the host path
/// it resolved to. A client that asked for `docs/hosts` is told about
/// `docs/hosts`; where the symlink pointed is the operator's business and
/// belongs in a log, not in an error handed back over a mount.
fn escapes(path: &VfsPath) -> VfsError {
    VfsError::EscapesRoot {
        path: path.to_string(),
    }
}

fn resolve(root: &Path, path: &VfsPath, follow_leaf: bool) -> VfsResult<PathBuf> {
    // The root itself is resolved once, so the comparison below is between two
    // paths the kernel produced rather than between one it produced and one a
    // caller spelled. On macOS `/tmp` is a symlink to `/private/tmp`, so a root
    // under either spelling would otherwise never match its own children.
    let root = std::fs::canonicalize(root)?;
    let relative = host_relative(path)?;

    let components: Vec<Component<'_>> = relative.components().collect();
    let mut current = root.clone();
    for (index, component) in components.iter().copied().enumerate() {
        // `Path::components` classifies `..` as `ParentDir` and `.` as
        // `CurDir`, so `Normal` cannot be either of them. Anything else here is
        // an absolute path or a Windows prefix, which a relative workspace path
        // cannot hold and which this refuses rather than reinterprets.
        let Component::Normal(name) = component else {
            return Err(VfsError::InvalidInput {
                path: path.to_string(),
            });
        };
        let candidate = current.join(name);

        if index + 1 == components.len() && !follow_leaf {
            current = candidate;
            break;
        }

        match std::fs::symlink_metadata(&candidate) {
            // Absent: nothing to follow, and the writer creates it under a
            // parent this walk has already proved is inside the root.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => current = candidate,
            Err(e) => return Err(VfsError::Io(e)),
            Ok(meta) if meta.file_type().is_symlink() => {
                let resolved = std::fs::canonicalize(&candidate).map_err(|_| escapes(path))?;
                if !resolved.starts_with(&root) {
                    return Err(escapes(path));
                }
                current = resolved;
            }
            Ok(_) => current = candidate,
        }
    }

    Ok(current)
}

/// The workspace-relative path as host bytes.
#[cfg(unix)]
fn host_relative(path: &VfsPath) -> VfsResult<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(path.as_bytes())))
}

/// Windows has no byte-exact path type, so a name that is not UTF-8 addresses
/// nothing there and is refused rather than lossily decoded into a different
/// file.
#[cfg(not(unix))]
fn host_relative(path: &VfsPath) -> VfsResult<PathBuf> {
    match std::str::from_utf8(path.as_bytes()) {
        Ok(text) => Ok(PathBuf::from(text)),
        Err(_) => Err(VfsError::InvalidInput {
            path: path.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vpath(text: &str) -> VfsPath {
        VfsPath::from_utf8(text).expect("valid test path")
    }

    /// The canonical form of a temporary directory. On macOS `TempDir` hands
    /// back a path under `/var/folders`, which is a symlink to
    /// `/private/var/folders`, so every expectation below is written against
    /// what the kernel resolves rather than what `TempDir` printed.
    fn canonical(dir: &tempfile::TempDir) -> PathBuf {
        std::fs::canonicalize(dir.path()).unwrap()
    }

    #[test]
    fn an_ordinary_path_resolves_under_the_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(&tmp);
        std::fs::create_dir_all(root.join("src")).unwrap();
        assert_eq!(
            contained_target(&root, &vpath("src/main.rs")).unwrap(),
            root.join("src").join("main.rs")
        );
    }

    #[test]
    fn a_path_whose_parents_do_not_exist_yet_resolves() {
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(&tmp);
        assert_eq!(
            contained_target(&root, &vpath("a/b/c.txt")).unwrap(),
            root.join("a").join("b").join("c.txt")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_pointing_outside_the_root_is_refused() {
        let outside = tempfile::tempdir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(&tmp);
        std::os::unix::fs::symlink(canonical(&outside), root.join("docs")).unwrap();

        // Positive control: the escape is reachable. Without the guard this
        // path resolves into the other directory, so the refusal below is
        // about the guard rather than about a path that never worked.
        assert_eq!(
            std::fs::canonicalize(root.join("docs")).unwrap(),
            canonical(&outside),
            "the fixture must actually redirect outside the root"
        );

        let err = contained_target(&root, &vpath("docs/hosts")).unwrap_err();
        assert!(
            matches!(err, VfsError::EscapesRoot { .. }),
            "expected a containment refusal, got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_file_pointing_outside_the_root_is_refused() {
        let outside = tempfile::tempdir().unwrap();
        let target = canonical(&outside).join("secret.txt");
        std::fs::write(&target, b"not yours").unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(&tmp);
        std::os::unix::fs::symlink(&target, root.join("notes.txt")).unwrap();

        let err = contained_target(&root, &vpath("notes.txt")).unwrap_err();
        assert!(
            matches!(err, VfsError::EscapesRoot { .. }),
            "expected a containment refusal, got {err:?}"
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"not yours",
            "the refusal must leave the outside file untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_that_stays_inside_the_root_is_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(&tmp);
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::fs::write(root.join("real").join("a.txt"), b"body").unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("linked")).unwrap();

        assert_eq!(
            contained_target(&root, &vpath("linked/a.txt")).unwrap(),
            root.join("real").join("a.txt"),
            "an in-repository symlink is ordinary and must keep working"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_is_refused_rather_than_created_through() {
        let outside = tempfile::tempdir().unwrap();
        let absent = canonical(&outside).join("does-not-exist-yet");
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(&tmp);
        std::os::unix::fs::symlink(&absent, root.join("bait")).unwrap();
        assert!(!absent.exists(), "the fixture must dangle");

        let err = contained_target(&root, &vpath("bait")).unwrap_err();
        assert!(
            matches!(err, VfsError::EscapesRoot { .. }),
            "expected a containment refusal, got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn removing_a_symlink_names_the_link_and_not_its_target() {
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(&tmp);
        std::fs::write(root.join("real.txt"), b"body").unwrap();
        std::os::unix::fs::symlink(root.join("real.txt"), root.join("alias")).unwrap();

        assert_eq!(
            contained_entry(&root, &vpath("alias")).unwrap(),
            root.join("alias"),
            "remove and rename act on the entry; resolving it would delete the target"
        );
        assert_eq!(
            contained_target(&root, &vpath("alias")).unwrap(),
            root.join("real.txt"),
            "content operations do follow it, which is what makes the pair worth having"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_entry_under_an_escaping_directory_is_still_refused() {
        let outside = tempfile::tempdir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(&tmp);
        std::os::unix::fs::symlink(canonical(&outside), root.join("docs")).unwrap();

        let err = contained_entry(&root, &vpath("docs/hosts")).unwrap_err();
        assert!(
            matches!(err, VfsError::EscapesRoot { .. }),
            "not following the leaf must not stop following the parents: got {err:?}"
        );
    }

    #[test]
    fn a_missing_root_is_an_io_error_rather_than_a_pass() {
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("no-such-root");
        let err = contained_target(&absent, &vpath("a.txt")).unwrap_err();
        assert!(
            matches!(err, VfsError::Io(_)),
            "a root that cannot be resolved must fail loud, got {err:?}"
        );
    }
}
