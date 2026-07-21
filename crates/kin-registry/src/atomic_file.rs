// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Crash-safe publication of registry artifacts.
//!
//! Registry readers must never observe a destination while it is being
//! rewritten. Stage bytes in the destination directory, durably flush them,
//! and only then replace the destination with one atomic rename.

use std::io::{self, Write};
use std::path::Path;

pub(crate) fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_with_pre_commit(path, bytes, |_| Ok(()))
}

fn write_with_pre_commit_impl<F>(path: &Path, bytes: &[u8], pre_commit: F) -> io::Result<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic registry destination has no parent directory",
        )
    })?;
    std::fs::create_dir_all(parent)?;

    // tempfile::NamedTempFile::persist performs an atomic, replacing rename on
    // Unix and Windows. Because the stage lives in `parent`, the rename cannot
    // cross filesystems. PersistError retains and cleans the stage on failure.
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(bytes)?;
    staged.flush()?;
    staged.as_file().sync_all()?;
    pre_commit(staged.path())?;

    let published = staged.persist(path).map_err(|error| error.error)?;
    published.sync_all()?;
    sync_parent(parent)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn write_with_pre_commit<F>(path: &Path, bytes: &[u8], pre_commit: F) -> io::Result<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    write_with_pre_commit_impl(path, bytes, pre_commit)
}

#[cfg(not(test))]
fn write_with_pre_commit<F>(path: &Path, bytes: &[u8], pre_commit: F) -> io::Result<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    write_with_pre_commit_impl(path, bytes, pre_commit)
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> io::Result<()> {
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> io::Result<()> {
    // The published file itself is flushed above. Opening directories for a
    // portable metadata fsync is not supported by std on non-Unix platforms.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_pre_commit_preserves_destination_and_cleans_stage() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("artifact");
        std::fs::write(&destination, b"old-complete-bytes").unwrap();

        let error = write_with_pre_commit(&destination, b"replacement", |_| {
            Err(io::Error::other("injected pre-rename failure"))
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(std::fs::read(&destination).unwrap(), b"old-complete-bytes");
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn successful_write_atomically_replaces_destination() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("artifact");
        std::fs::write(&destination, b"old").unwrap();

        write(&destination, b"new-complete-bytes").unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), b"new-complete-bytes");
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn fully_staged_bytes_are_not_visible_at_the_destination_before_commit() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("artifact");
        std::fs::write(&destination, b"old-complete-bytes").unwrap();

        write_with_pre_commit(&destination, b"new-complete-bytes", |stage| {
            assert_eq!(std::fs::read(&destination)?, b"old-complete-bytes");
            assert_eq!(std::fs::read(stage)?, b"new-complete-bytes");
            Ok(())
        })
        .unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), b"new-complete-bytes");
    }
}
